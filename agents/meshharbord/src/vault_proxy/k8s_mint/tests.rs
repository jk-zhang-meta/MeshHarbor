// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-6f-1 — the Kubernetes minter against a fake API server
//! (`crate::vault_proxy::testing::fake_k8s`): what it asks, in what order,
//! and what it takes back.

use serde_json::{Value, json};

use super::*;
use crate::vault_proxy::testing::{FakeK8s, fake_k8s};

/// The bearer the issuer signs in with: made at run time, a fixture shaped
/// like no real token.
fn bearer() -> String {
    ["issuer", "bearer", "for", "tests"].join("-")
}

fn lease() -> String {
    bson::oid::ObjectId::new().to_hex()
}

/// `secs` from now, in milliseconds.
fn in_ms(secs: i64) -> i64 {
    bson::DateTime::now().timestamp_millis() + secs * 1000
}

fn rfc3339(ms: i64) -> String {
    bson::DateTime::from_millis(ms)
        .try_to_rfc3339_string()
        .unwrap()
}

/// A bundle as the vault seals it, toward the fake's origin: its namespace,
/// its account, its CA, and `extra`.
fn bundle(k: &FakeK8s, extra: &[(&str, &str)]) -> Vec<u8> {
    let mut fields = serde_json::Map::new();
    fields.insert("namespace".into(), json!("hive-tokens"));
    fields.insert("service_account".into(), json!("session-runner"));
    fields.insert("ca".into(), json!(k.ca));
    for (name, value) in extra {
        fields.insert((*name).into(), json!(value));
    }
    json!({"audience": k.origin(), "fields": fields})
        .to_string()
        .into_bytes()
}

/// An issuer that signs in to the fake by the bearer.
fn issuer(k: &FakeK8s) -> Issuer {
    Issuer::from_bundle(&bundle(k, &[("admin_token", &bearer())])).unwrap()
}

/// The mint: the sweep's list, then the lease's Secret, then a token bound
/// to it by name and uid, for 600 s where the lease is shorter, each signed
/// in by the issuer's bearer. The credential names the token, the server,
/// the CA and the namespace, and no issuer field.
#[tokio::test]
async fn a_token_is_minted_bound_to_a_secret_made_for_its_lease() {
    let k = fake_k8s(false).await;
    let issuer = issuer(&k);
    let lease = lease();
    let until = in_ms(60);
    let m = mint(&issuer, &lease, 60, until).await.unwrap();
    let secret = format!("roomler-{lease}");
    assert_eq!(m.secret, secret);
    {
        let st = k.state();
        let held = st.secrets.get(&secret).expect("the lease's Secret is held");
        assert_eq!(m.uid, held.uid);
        assert_eq!(held.labels, json!({"roomler.ai/lease": lease}));
        assert_eq!(
            held.annotations,
            json!({"roomler.ai/until": rfc3339(until)})
        );
        let asked: Vec<(&str, &str)> = st
            .saw
            .iter()
            .map(|s| (s.method.as_str(), s.target.as_str()))
            .collect();
        assert_eq!(
            asked,
            [
                (
                    "GET",
                    "/api/v1/namespaces/hive-tokens/secrets?labelSelector=roomler.ai%2Flease"
                ),
                ("POST", "/api/v1/namespaces/hive-tokens/secrets"),
                (
                    "POST",
                    "/api/v1/namespaces/hive-tokens/serviceaccounts/session-runner/token"
                ),
            ]
        );
        let signed = format!("Bearer {}", bearer());
        assert!(
            st.saw
                .iter()
                .all(|s| s.authorization.as_deref() == Some(signed.as_str())),
            "every request is the issuer's"
        );
        let secret_body = &st.saw[1].body;
        assert_eq!(secret_body["kind"], "Secret");
        assert!(
            secret_body.get("data").is_none(),
            "the Secret holds nothing"
        );
        let spec = &st.saw[2].body["spec"];
        assert_eq!(
            spec["boundObjectRef"],
            json!({"apiVersion": "v1", "kind": "Secret", "name": secret, "uid": held.uid})
        );
        assert_eq!(
            spec["expirationSeconds"], 600,
            "Kubernetes mints nothing shorter"
        );
        assert!(
            spec.get("audiences").is_none(),
            "the API server's own, unless the issuer names some"
        );
    }
    assert_eq!(
        *m.field("token").unwrap(),
        format!("minted.session-runner.{secret}")
    );
    assert_eq!(*m.field("server").unwrap(), k.origin());
    assert_eq!(*m.field("ca").unwrap(), k.ca);
    assert_eq!(*m.field("namespace").unwrap(), "hive-tokens");
    for issuer_field in ["admin_token", "service_account", "audiences"] {
        assert!(m.field(issuer_field).is_none(), "{issuer_field}");
    }
}

/// A lease longer than ten minutes asks for its own TTL, and the token's
/// audiences are the issuer's where it names some, one per line.
#[tokio::test]
async fn a_long_lease_asks_its_own_ttl_toward_the_issuers_audiences() {
    let k = fake_k8s(false).await;
    let issuer = Issuer::from_bundle(&bundle(
        &k,
        &[
            ("admin_token", &bearer()),
            ("audiences", "https://kubernetes.default.svc\n\n vault "),
        ],
    ))
    .unwrap();
    mint(&issuer, &lease(), 900, in_ms(900)).await.unwrap();
    let st = k.state();
    let spec = &st.saw.last().unwrap().body["spec"];
    assert_eq!(spec["expirationSeconds"], 900);
    assert_eq!(
        spec["audiences"],
        json!(["https://kubernetes.default.svc", "vault"])
    );
}

/// A token the API server refuses takes the lease's Secret back, on its
/// uid, and the call is refused in the API server's words.
#[tokio::test]
async fn a_refused_token_takes_its_secret_back() {
    let k = fake_k8s(false).await;
    k.state().refuse_token = Some((403, "serviceaccounts is forbidden: no token".into()));
    let issuer = issuer(&k);
    let lease = lease();
    let refused = mint(&issuer, &lease, 60, in_ms(60)).await.err().unwrap();
    assert!(
        refused.contains("403") && refused.contains("is forbidden: no token"),
        "{refused}"
    );
    let st = k.state();
    assert!(st.secrets.is_empty(), "the Secret is taken back");
    let last = st.saw.last().unwrap();
    assert_eq!(last.method, "DELETE");
    assert_eq!(
        last.target,
        format!("/api/v1/namespaces/hive-tokens/secrets/roomler-{lease}")
    );
    assert!(last.body["preconditions"]["uid"].is_string(), "{last:?}");
}

/// The revocation deletes the Secret on the uid it was made with. One
/// already gone is done; another object under the name is left alone; a
/// name no mint made is refused before anything is asked.
#[tokio::test]
async fn the_revocation_deletes_the_secret_on_its_uid_and_nothing_else() {
    let k = fake_k8s(false).await;
    let issuer = issuer(&k);
    let m = mint(&issuer, &lease(), 60, in_ms(60)).await.unwrap();
    revoke(&issuer, &m.secret, &m.uid).await.unwrap();
    {
        let st = k.state();
        assert!(st.secrets.is_empty());
        let last = st.saw.last().unwrap();
        assert_eq!(last.method, "DELETE");
        assert_eq!(last.body["preconditions"]["uid"], m.uid.as_str());
    }
    revoke(&issuer, &m.secret, &m.uid)
        .await
        .expect("one already gone is a revocation done");
    let other = k.state().put(&m.secret, json!({}), json!({}));
    revoke(&issuer, &m.secret, &m.uid)
        .await
        .expect("another object under the name: ours is gone");
    assert_eq!(k.state().secrets[&m.secret].uid, other, "not ours: kept");
    let asked = k.state().saw.len();
    for name in [
        "app-config",
        "roomler-",
        "roomler-0123456789ABCDEF01234567",
        "roomler-0123456789abcdef0123456",
    ] {
        assert!(revoke(&issuer, name, "uid-1").await.is_err(), "{name}");
    }
    assert_eq!(
        k.state().saw.len(),
        asked,
        "nothing asked of the API server"
    );
}

/// The sweep, before each mint: every Secret a mint made whose end has
/// passed is deleted on its uid; one still live, one with no end, and a
/// name no mint made are kept, whatever they are labelled.
#[tokio::test]
async fn the_sweep_deletes_the_ended_secrets_a_mint_made_and_nothing_else() {
    let k = fake_k8s(false).await;
    let (ended, live, endless) = (
        format!("roomler-{}", lease()),
        format!("roomler-{}", lease()),
        format!("roomler-{}", lease()),
    );
    let label = json!({"roomler.ai/lease": "an-earlier-lease"});
    {
        let mut st = k.state();
        st.put(
            &ended,
            label.clone(),
            json!({"roomler.ai/until": rfc3339(in_ms(-60))}),
        );
        st.put(
            &live,
            label.clone(),
            json!({"roomler.ai/until": rfc3339(in_ms(600))}),
        );
        st.put(&endless, label.clone(), json!({}));
        st.put(
            "app-config",
            label.clone(),
            json!({"roomler.ai/until": rfc3339(in_ms(-60))}),
        );
    }
    let m = mint(&issuer(&k), &lease(), 60, in_ms(60)).await.unwrap();
    let st = k.state();
    assert!(!st.secrets.contains_key(&ended), "an ended one is deleted");
    for kept in [&live, &endless, &m.secret] {
        assert!(st.secrets.contains_key(kept), "{kept}");
    }
    assert!(
        st.secrets.contains_key("app-config"),
        "a name no mint made is kept"
    );
}

/// Where the issuer may not list its Secrets, nothing is swept, and the mint
/// goes on.
#[tokio::test]
async fn an_issuer_that_may_not_list_mints_with_no_sweep() {
    let k = fake_k8s(false).await;
    let ended = format!("roomler-{}", lease());
    {
        let mut st = k.state();
        st.refuse_list = true;
        st.put(
            &ended,
            json!({"roomler.ai/lease": "an-earlier-lease"}),
            json!({"roomler.ai/until": rfc3339(in_ms(-60))}),
        );
    }
    mint(&issuer(&k), &lease(), 60, in_ms(60)).await.unwrap();
    assert!(
        k.state().secrets.contains_key(&ended),
        "kept: nothing was listed"
    );
}

/// A client certificate signs the issuer in, in the handshake: no header
/// carries a credential. An API server that asks for one refuses a bearer
/// alone.
#[tokio::test]
async fn a_client_certificate_signs_the_issuer_in() {
    let k = fake_k8s(true).await;
    let (cert, key) = k.client.clone().unwrap();
    let issuer =
        Issuer::from_bundle(&bundle(&k, &[("admin_cert", &cert), ("admin_key", &key)])).unwrap();
    let m = mint(&issuer, &lease(), 60, in_ms(60)).await.unwrap();
    assert!(!m.token.is_empty());
    assert!(
        k.state().saw.iter().all(|s| s.authorization.is_none()),
        "no header carries a credential"
    );
    let bare = Issuer::from_bundle(&bundle(&k, &[("admin_token", &bearer())])).unwrap();
    assert!(mint(&bare, &lease(), 60, in_ms(60)).await.is_err());
}

/// An issuer is refused before anything is dialled: a namespace or an
/// account Kubernetes would not name (one that could leave its path among
/// them), a credential missing or given twice, a bearer that is not one, an
/// audience that is not an origin. No refusal names the bearer.
#[test]
fn an_issuer_whose_names_could_leave_its_path_is_refused() {
    let origin = "https://localhost:6443";
    let make = |fields: &Value, audience: &str| {
        Issuer::from_bundle(
            json!({"audience": audience, "fields": fields})
                .to_string()
                .as_bytes(),
        )
    };
    let ok = json!({
        "namespace": "hive-tokens",
        "service_account": "system.session-runner",
        "admin_token": bearer(),
    });
    assert!(make(&ok, origin).is_ok());
    let long = "a".repeat(64);
    let mut refusals = Vec::new();
    for (field, bad) in [
        ("namespace", "../kube-system"),
        ("namespace", "hive/tokens"),
        ("namespace", "Hive"),
        ("namespace", "-hive"),
        ("namespace", long.as_str()),
        ("service_account", "runner/../x"),
        ("service_account", "Runner"),
        ("service_account", "a..b"),
        ("service_account", "runner?x"),
        ("admin_token", "two words"),
    ] {
        let mut f = ok.clone();
        f[field] = json!(bad);
        refusals.push(
            make(&f, origin)
                .err()
                .unwrap_or_else(|| panic!("{field}={bad}")),
        );
    }
    for field in ["namespace", "service_account", "admin_token"] {
        let mut f = ok.clone();
        f.as_object_mut().unwrap().remove(field);
        refusals.push(
            make(&f, origin)
                .err()
                .unwrap_or_else(|| panic!("no {field}")),
        );
    }
    let mut both = ok.clone();
    both["admin_cert"] = json!("a certificate");
    both["admin_key"] = json!("its key");
    let twice = make(&both, origin).err().unwrap();
    assert!(twice.contains("one of the two"), "{twice}");
    refusals.push(twice);
    for audience in [
        "localhost:6443",
        "https://localhost:6443/api",
        "http://localhost:6443",
        "https://localhost:443",
    ] {
        refusals.push(
            make(&ok, audience)
                .err()
                .unwrap_or_else(|| panic!("{audience}")),
        );
    }
    for why in &refusals {
        assert!(
            !why.contains(&bearer()),
            "a refusal names the bearer: {why}"
        );
    }
}

/// A lease's id names one Secret, and only a name a mint made is ever
/// deleted.
#[test]
fn a_lease_names_one_secret_and_only_a_minted_name_is_deleted() {
    let lease = lease();
    assert_eq!(secret_for(&lease).unwrap(), format!("roomler-{lease}"));
    assert!(minted(&format!("roomler-{lease}")).is_ok());
    for bad in [
        "abc",
        "ABCDEF0123456789ABCDEF01",
        "0123456789abcdef0123456",
        "0123456789abcdef012345678",
        "0123456789abcdef0123456g",
    ] {
        assert!(secret_for(bad).is_err(), "{bad}");
    }
    for bad in [
        "app-config",
        "roomler-",
        "roomler_0123456789abcdef01234567",
        "x-roomler-0123456789abcdef01234567",
    ] {
        assert!(minted(bad).is_err(), "{bad}");
    }
}
