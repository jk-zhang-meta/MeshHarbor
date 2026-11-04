// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! The minter, against a Postgres that keeps its roles and signs a minted one
//! in by the verifier it was given (`testing::fake_issuer`).

use std::sync::atomic::Ordering::SeqCst;

use serde_json::json;

use super::super::testing::{FakeIssuer, FakeRole, fake_issuer, made};
use super::super::tls;
use super::*;

/// `host:port`, as the endpoint's own reader takes it, for these tests.
fn upstream_of(raw: &str) -> Result<(String, u16), String> {
    let (host, port) = raw.rsplit_once(':').ok_or("no port")?;
    Ok((host.to_string(), port.parse().map_err(|_| "a bad port")?))
}

/// A bundle as the vault seals one for `f`'s database.
fn bundle(f: &FakeIssuer, admin_password: &str, grants: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "audience": format!("localhost:{}", f.port),
        "fields": {
            "admin_user": "admin",
            "admin_password": admin_password,
            "database": "orders",
            "grants": grants,
            "ca": f.ca,
        },
    }))
    .unwrap()
}

/// A lease's id, made here.
fn lease() -> String {
    bson::oid::ObjectId::new().to_hex()
}

/// Every query the fake saw so far.
fn seen(f: &mut FakeIssuer) -> Vec<String> {
    let mut all = Vec::new();
    while let Ok(q) = f.saw.try_recv() {
        all.push(q);
    }
    all
}

/// The minted user, signed in by its own password over the issuer's TLS.
async fn signs_in_as(f: &FakeIssuer, user: &str, password: &str) -> Result<(), String> {
    let up = Upstream {
        host: "localhost".into(),
        port: f.port,
        user: user.into(),
        password: Zeroizing::new(password.into()),
        tls: tls::connector(Some(&f.ca)).unwrap(),
    };
    let s = pg::sign_in(&up, "orders").await?;
    pg::terminate(s).await;
    Ok(())
}

/// A user minted for a lease: its role named for the lease, its password
/// sent only as its verifier, valid until the lease's end, in the issuer's
/// roles (each quoted as a name), commented with the lease. And it signs in
/// with its password, which the database checked against that verifier
/// alone; the next lease's password is its own.
#[tokio::test]
async fn a_user_is_minted_with_a_verifier_and_signs_in_by_its_password() {
    let admin = made();
    let mut f = fake_issuer(&admin).await;
    let issuer =
        Issuer::from_bundle(&bundle(&f, &admin, "readonly\n reporting \n"), upstream_of).unwrap();
    assert_eq!(issuer.grants, ["readonly", "reporting"]);
    let id = lease();
    let until = "2099-01-01T00:00:00Z";
    let m = mint(&issuer, &id, until).await.unwrap();
    assert_eq!(m.user, format!("roomler_{id}"));
    assert_eq!(
        (m.host.as_str(), m.port, m.database.as_str()),
        ("localhost", f.port, "orders")
    );
    assert_eq!(m.password.len(), 43, "32 random bytes, base64url");

    let queries = seen(&mut f);
    let create = queries
        .iter()
        .find(|q| q.starts_with("CREATE ROLE"))
        .unwrap();
    assert!(create.contains("PASSWORD 'SCRAM-SHA-256$4096:"), "{create}");
    assert!(
        create.contains(" IN ROLE \"readonly\", \"reporting\""),
        "{create}"
    );
    assert!(
        !create.contains(m.password.as_str()),
        "the password never reaches the database"
    );
    assert!(!queries.iter().any(|q| q.contains(admin.as_str())));
    let role = f.roles.lock().unwrap().get(&m.user).cloned().unwrap();
    assert_eq!(
        (
            role.valid_until.as_str(),
            role.grants.as_slice(),
            role.comment.as_deref(),
            role.login
        ),
        (
            until,
            &["readonly".to_string(), "reporting".to_string()][..],
            Some(format!("roomler lease {id}").as_str()),
            true
        )
    );

    assert_eq!(signs_in_as(&f, &m.user, &m.password).await, Ok(()));
    let wrong = signs_in_as(&f, &m.user, &format!("{}x", m.password.as_str())).await;
    assert!(
        wrong
            .unwrap_err()
            .contains("password authentication failed")
    );
    assert_eq!(
        m.field("user").as_deref().map(String::as_str),
        Some(m.user.as_str())
    );
    assert_eq!(
        m.field("port").as_deref().map(String::as_str),
        Some(f.port.to_string().as_str())
    );
    assert_eq!(
        m.field("admin_password"),
        None,
        "an issuer's field is no minted credential's"
    );
    let next = mint(&issuer, &lease(), until).await.unwrap();
    assert!(next.password != m.password, "each lease its own password");
}

/// A revocation takes the role back, after which it signs in no more; and a
/// name no mint made is refused before anything is dialled.
#[tokio::test]
async fn a_revocation_drops_the_minted_role_and_nothing_else() {
    let admin = made();
    let mut f = fake_issuer(&admin).await;
    let issuer = Issuer::from_bundle(&bundle(&f, &admin, ""), upstream_of).unwrap();
    let m = mint(&issuer, &lease(), "2099-01-01T00:00:00Z")
        .await
        .unwrap();
    seen(&mut f);
    revoke(&issuer, &m.user).await.unwrap();
    let r = format!("\"{}\"", m.user);
    let queries = seen(&mut f);
    let order: Vec<&str> = queries
        .iter()
        .map(|q| q.split_whitespace().take(2).collect::<Vec<_>>().join(" "))
        .map(|q| match q.as_str() {
            "SELECT 1" => "exists",
            "ALTER ROLE" => "nologin",
            "SELECT pg_catalog.pg_terminate_backend(pid)" => "terminate",
            "REASSIGN OWNED" => "reassign",
            "DROP ROLE" => "drop",
            _ => "other",
        })
        .collect();
    assert_eq!(
        order,
        ["exists", "nologin", "terminate", "reassign", "drop"],
        "{queries:?}"
    );
    assert!(
        queries
            .iter()
            .all(|q| !q.contains("DROP ROLE") || q.contains(&r))
    );
    assert!(f.roles.lock().unwrap().get(&m.user).is_none());
    assert!(signs_in_as(&f, &m.user, &m.password).await.is_err());
    // Gone already: done, not an error.
    revoke(&issuer, &m.user).await.unwrap();

    for name in [
        "admin",
        "postgres",
        "roomler_",
        "roomler_1234",
        "roomler_zzzzzzzzzzzzzzzzzzzzzzzz",
    ] {
        let dialled = f.dialled.load(SeqCst);
        assert!(revoke(&issuer, name).await.is_err(), "{name}");
        assert_eq!(f.dialled.load(SeqCst), dialled, "{name}: nothing dialled");
    }
}

/// A revocation by an issuer that may not end the role's sessions, or take
/// back what it owns, still drops the role: each is best effort, and
/// `NOLOGIN` has already refused any new session.
#[tokio::test]
async fn a_revocation_drops_the_role_where_the_issuer_may_do_no_more() {
    let admin = made();
    let mut f = fake_issuer(&admin).await;
    let issuer = Issuer::from_bundle(&bundle(&f, &admin, ""), upstream_of).unwrap();
    let m = mint(&issuer, &lease(), "2099-01-01T00:00:00Z")
        .await
        .unwrap();
    f.refuse.terminate.store(true, SeqCst);
    f.refuse.reassign.store(true, SeqCst);
    seen(&mut f);
    revoke(&issuer, &m.user).await.unwrap();
    assert!(f.roles.lock().unwrap().get(&m.user).is_none());
    let queries = seen(&mut f);
    for refused in ["pg_terminate_backend", "REASSIGN OWNED"] {
        assert!(queries.iter().any(|q| q.contains(refused)), "{queries:?}");
    }
}

/// The issuer's next mint drops the minted roles whose `VALID UNTIL` has
/// passed, found by their comment; a role it did not mint, one still valid,
/// or one that carries the mark under a name no mint makes, stays.
#[tokio::test]
async fn the_expired_are_swept_at_the_next_mint() {
    let admin = made();
    let f = fake_issuer(&admin).await;
    let role = |until: &str, comment: Option<String>| FakeRole {
        verifier: String::new(),
        valid_until: until.to_string(),
        grants: Vec::new(),
        comment,
        login: true,
    };
    let (old, live, theirs) = (lease(), lease(), lease());
    {
        let mut roles = f.roles.lock().unwrap();
        roles.insert(
            format!("roomler_{old}"),
            role("2001-01-01T00:00:00Z", Some(format!("roomler lease {old}"))),
        );
        roles.insert(
            format!("roomler_{live}"),
            role(
                "2099-01-01T00:00:00Z",
                Some(format!("roomler lease {live}")),
            ),
        );
        roles.insert(
            format!("roomler_{theirs}"),
            role("2001-01-01T00:00:00Z", Some("someone else's".into())),
        );
        roles.insert(
            "roomler_admin".into(),
            role("2001-01-01T00:00:00Z", Some("roomler lease forged".into())),
        );
    }
    let issuer = Issuer::from_bundle(&bundle(&f, &admin, ""), upstream_of).unwrap();
    let m = mint(&issuer, &lease(), "2099-01-01T00:00:00Z")
        .await
        .unwrap();
    let roles = f.roles.lock().unwrap();
    assert!(
        !roles.contains_key(&format!("roomler_{old}")),
        "the expired one is swept"
    );
    for kept in [
        format!("roomler_{live}"),
        format!("roomler_{theirs}"),
        "roomler_admin".into(),
        m.user.clone(),
    ] {
        assert!(roles.contains_key(&kept), "{kept}");
    }
}

/// A mint the database refuses is refused in its own words; an issuer short
/// of a field, or a bundle that does not parse, is refused before anything
/// is sent, in words that name no value.
#[tokio::test]
async fn a_refused_mint_or_a_short_issuer_says_why() {
    let admin = made();
    let f = fake_issuer(&admin).await;
    f.refuse.create.store(true, SeqCst);
    let issuer = Issuer::from_bundle(&bundle(&f, &admin, ""), upstream_of).unwrap();
    let why = mint(&issuer, &lease(), "2099-01-01T00:00:00Z")
        .await
        .err()
        .unwrap();
    assert_eq!(
        why,
        "the database refused the mint: permission denied to create role"
    );
    assert!(f.roles.lock().unwrap().is_empty());

    let wrong = Issuer::from_bundle(&bundle(&f, &format!("{admin}x"), ""), upstream_of).unwrap();
    let why = mint(&wrong, &lease(), "2099-01-01T00:00:00Z")
        .await
        .err()
        .unwrap();
    assert!(why.contains("password authentication failed"), "{why}");
    assert!(!why.contains(admin.as_str()));

    for (fields, says) in [
        (
            json!({"admin_user": "admin", "database": "orders"}),
            "the issuer has no admin_password",
        ),
        (
            json!({"admin_password": admin, "database": "orders"}),
            "the issuer has no admin_user",
        ),
        (
            json!({"admin_user": "admin", "admin_password": admin}),
            "the issuer has no database",
        ),
    ] {
        let b = serde_json::to_vec(
            &json!({"audience": format!("localhost:{}", f.port), "fields": fields}),
        )
        .unwrap();
        let why = Issuer::from_bundle(&b, upstream_of).err().unwrap();
        assert_eq!(why, says);
        assert!(!why.contains(admin.as_str()));
    }
    let why = Issuer::from_bundle(b"not a bundle", upstream_of)
        .err()
        .unwrap();
    assert_eq!(why, "the bundle does not parse");
    assert!(
        mint(&issuer, "not-a-lease", "2099-01-01T00:00:00Z")
            .await
            .is_err()
    );
}

#[test]
fn names_are_identifiers_and_values_literals() {
    assert_eq!(ident("roomler_ab"), "\"roomler_ab\"");
    assert_eq!(ident("we\"ird"), "\"we\"\"ird\"");
    assert_eq!(literal("it's"), "'it''s'");
    assert_eq!(
        role_for("0123456789abcdef01234567"),
        Ok("roomler_0123456789abcdef01234567".into())
    );
    for bad in [
        "",
        "0123",
        "0123456789abcdef0123456g",
        "0123456789abcdef012345678",
    ] {
        assert!(role_for(bad).is_err(), "{bad}");
    }
}
