// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! The MySQL minter: against a MySQL that keeps its users and signs a minted
//! one in by the form it was given (`testing::fake_mysql`), and against a
//! real MySQL (ignored unless a run names one).

use std::sync::atomic::Ordering::SeqCst;

use serde_json::json;

use super::super::mysql;
use super::super::testing::{FakeMysql, FakeUser, fake_mysql, made, real_mysql};
use super::super::tls;
use super::*;

/// A bundle as the vault seals one for `f`'s database.
fn fake_bundle(f: &FakeMysql, admin_password: &str, grants: &str) -> Vec<u8> {
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

/// Every query the fake saw so far.
fn seen(f: &mut FakeMysql) -> Vec<String> {
    let mut all = Vec::new();
    while let Ok(q) = f.saw.try_recv() {
        all.push(q);
    }
    all
}

/// What each query was, by its first words.
fn kinds(queries: &[String]) -> Vec<&'static str> {
    queries
        .iter()
        .map(|q| match q {
            q if q.contains("USER_ATTRIBUTES WHERE USER LIKE") => "sweep",
            q if q.contains("USER_ATTRIBUTES WHERE USER =") => "exists",
            q if q.starts_with("CREATE USER") => "create",
            q if q.starts_with("GRANT") => "grant",
            q if q.starts_with("SET DEFAULT ROLE") => "default",
            q if q.starts_with("CREATE EVENT") => "event",
            q if q.starts_with("ALTER USER") => "lock",
            q if q.contains("PROCESSLIST") => "sessions",
            q if q.starts_with("KILL") => "kill",
            q if q.starts_with("DROP USER") => "drop",
            q if q.starts_with("DROP EVENT") => "drop-event",
            _ => "other",
        })
        .collect()
}

/// A user, signed in by its password over the fake's TLS.
async fn signs_in_as(f: &FakeMysql, user: &str, password: &str) -> Result<(), String> {
    let up = Upstream {
        host: "localhost".into(),
        port: f.port,
        user: user.into(),
        password: Zeroizing::new(password.into()),
        tls: tls::connector(Some(&f.ca)).unwrap(),
    };
    let s = mysql::sign_in(&up, "orders").await?;
    mysql::quit(s).await;
    Ok(())
}

/// A user minted for a lease: created from its password's form, never the
/// password, marked with its lease and its end, granted the issuer's roles
/// (each quoted as an account) as its defaults, its end scheduled; after the
/// sweep. It signs in by its password, which the database checks against the
/// form alone; the next lease's password is its own.
#[tokio::test]
async fn a_user_is_minted_from_its_form_with_its_grants_and_its_end() {
    let admin = made();
    let mut f = fake_mysql(&admin).await;
    let issuer = Issuer::from_bundle(
        &fake_bundle(&f, &admin, "reader\n auditor@localhost \n"),
        upstream_of,
    )
    .unwrap();
    assert_eq!(issuer.grants, ["reader", "auditor@localhost"]);
    let id = lease();
    let until = now() + 600;
    let m = mint(&issuer, &id, until).await.unwrap();
    assert_eq!(m.user, format!("roomler_{id}"));
    assert_eq!(
        (m.host.as_str(), m.port, m.database.as_str()),
        ("localhost", f.port, "orders")
    );
    let queries = seen(&mut f);
    assert_eq!(
        kinds(&queries),
        ["sweep", "create", "grant", "grant", "default", "event"],
        "{queries:?}"
    );
    let create = &queries[1];
    assert!(create.contains(" AS '$A$005$"), "{create}");
    assert!(
        !create.contains(m.password.as_str()),
        "the password never reaches the database"
    );
    assert!(
        create.ends_with(&format!(
            " ATTRIBUTE '{{\"roomler\": {{\"lease\": \"{id}\", \"until\": {until}}}}}'"
        )),
        "{create}"
    );
    assert!(
        queries[2].starts_with("GRANT 'reader'@'%' TO "),
        "{queries:?}"
    );
    assert!(queries[3].starts_with("GRANT 'auditor'@'localhost' TO "));
    assert_eq!(
        queries[5],
        format!(
            "CREATE EVENT `orders`.`roomler_end_{id}` ON SCHEDULE AT FROM_UNIXTIME({until}) \
             ON COMPLETION NOT PRESERVE DO DROP USER IF EXISTS 'roomler_{id}'@'%'"
        )
    );
    let u = f.users.lock().unwrap().get(&m.user).cloned().unwrap();
    assert_eq!(u.grants, ["reader", "auditor"]);
    assert!(u.default_roles);
    assert!(
        f.events
            .lock()
            .unwrap()
            .contains(&format!("roomler_end_{id}"))
    );

    assert_eq!(signs_in_as(&f, &m.user, &m.password).await, Ok(()));
    let wrong = signs_in_as(&f, &m.user, &format!("{}x", m.password.as_str())).await;
    assert!(wrong.unwrap_err().contains("1045 (28000)"));
    let next = mint(&issuer, &lease(), until).await.unwrap();
    assert!(next.password != m.password, "each lease its own password");
}

/// A step the database refuses after the user is made (its end, or a grant)
/// takes the user back, and the mint is refused in the database's words: no
/// user is left without its end.
#[tokio::test]
async fn a_refused_step_takes_the_user_back_and_the_mint_is_refused() {
    for (step, says) in [
        (
            "event",
            "the database refused the user's end: 1044 (42000): ",
        ),
        ("grant", "the database refused the mint: 1227 (42000): "),
    ] {
        let admin = made();
        let mut f = fake_mysql(&admin).await;
        match step {
            "event" => f.refuse.event.store(true, SeqCst),
            _ => f.refuse.grant.store(true, SeqCst),
        }
        let issuer = Issuer::from_bundle(&fake_bundle(&f, &admin, "reader"), upstream_of).unwrap();
        let why = mint(&issuer, &lease(), now() + 600).await.err().unwrap();
        assert!(why.starts_with(says), "{step}: {why}");
        assert!(f.users.lock().unwrap().is_empty(), "{step}: taken back");
        let queries = seen(&mut f);
        assert!(
            kinds(&queries).ends_with(&[
                "exists",
                "lock",
                "sessions",
                "kill",
                "drop",
                "drop-event"
            ]),
            "{step}: {queries:?}"
        );
    }
}

/// A revocation locks the user, ends its sessions, drops it and its event,
/// after which it signs in no more; a user already gone is done. A name no
/// mint made is refused before anything is dialled.
#[tokio::test]
async fn a_revocation_locks_ends_and_drops_the_user_and_nothing_else() {
    let admin = made();
    let mut f = fake_mysql(&admin).await;
    let issuer = Issuer::from_bundle(&fake_bundle(&f, &admin, ""), upstream_of).unwrap();
    let id = lease();
    let m = mint(&issuer, &id, now() + 600).await.unwrap();
    assert_eq!(
        kinds(&seen(&mut f)),
        ["sweep", "create", "event"],
        "no grants, no defaults"
    );
    revoke(&issuer, &m.user).await.unwrap();
    let queries = seen(&mut f);
    assert_eq!(
        kinds(&queries),
        ["exists", "lock", "sessions", "kill", "drop", "drop-event"],
        "{queries:?}"
    );
    assert_eq!(queries[3], "KILL 17");
    assert!(f.users.lock().unwrap().is_empty());
    assert!(f.events.lock().unwrap().is_empty());
    let gone = signs_in_as(&f, &m.user, &m.password).await.unwrap_err();
    assert!(gone.contains("1045 (28000)"), "{gone}");
    // Gone already: done, its event dropped all the same.
    revoke(&issuer, &m.user).await.unwrap();
    assert_eq!(kinds(&seen(&mut f)), ["exists", "drop-event"]);

    for name in [
        "admin",
        "root",
        "roomler_",
        "roomler_1234",
        "roomler_zzzzzzzzzzzzzzzzzzzzzzzz",
    ] {
        let dialled = f.dialled.load(SeqCst);
        assert!(revoke(&issuer, name).await.is_err(), "{name}");
        assert_eq!(f.dialled.load(SeqCst), dialled, "{name}: nothing dialled");
    }
}

/// An issuer that may not end a minted user's sessions still drops it: the
/// `KILL` is best effort, and the lock already refuses a new sign-in.
#[tokio::test]
async fn a_revocation_drops_the_user_where_the_issuer_may_not_end_its_sessions() {
    let admin = made();
    let f = fake_mysql(&admin).await;
    let issuer = Issuer::from_bundle(&fake_bundle(&f, &admin, ""), upstream_of).unwrap();
    let m = mint(&issuer, &lease(), now() + 600).await.unwrap();
    f.refuse.kill.store(true, SeqCst);
    revoke(&issuer, &m.user).await.unwrap();
    assert!(f.users.lock().unwrap().get(&m.user).is_none());
}

/// The issuer's next mint drops the minted users whose lease has ended by
/// their mark; a user still valid, one of another name, or one that carries
/// the mark under a name no mint makes, stays.
#[tokio::test]
async fn the_ended_are_swept_at_the_next_mint() {
    let admin = made();
    let f = fake_mysql(&admin).await;
    let marked = |id: &str, until: i64| FakeUser {
        attribute: Some(format!(
            "{{\"roomler\": {{\"lease\": \"{id}\", \"until\": {until}}}}}"
        )),
        ..FakeUser::default()
    };
    let (old, live) = (lease(), lease());
    {
        let mut users = f.users.lock().unwrap();
        users.insert(format!("roomler_{old}"), marked(&old, now() - 60));
        users.insert(format!("roomler_{live}"), marked(&live, now() + 600));
        users.insert("app_reader".into(), marked(&old, now() - 60));
        users.insert("roomler_admin".into(), marked("forged", now() - 60));
    }
    let issuer = Issuer::from_bundle(&fake_bundle(&f, &admin, ""), upstream_of).unwrap();
    let m = mint(&issuer, &lease(), now() + 600).await.unwrap();
    let users = f.users.lock().unwrap();
    assert!(
        !users.contains_key(&format!("roomler_{old}")),
        "the ended one is swept"
    );
    for kept in [
        format!("roomler_{live}"),
        "app_reader".into(),
        "roomler_admin".into(),
        m.user.clone(),
    ] {
        assert!(users.contains_key(&kept), "{kept}");
    }
}

/// An issuer short of a field, a bundle that does not parse, a grant or a
/// database that would be read as SQL: refused before anything is sent, in
/// words that name no value.
#[tokio::test]
async fn a_short_issuer_or_a_name_that_would_be_sql_is_refused() {
    let admin = made();
    let f = fake_mysql(&admin).await;
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
        (
            json!({"admin_user": "admin", "admin_password": admin, "database": "or`ders"}),
            "the issuer's database is not a name the minter quotes",
        ),
        (
            json!({"admin_user": "admin", "admin_password": admin, "database": "orders",
                   "grants": "reader'; DROP DATABASE orders; --"}),
            "a grant is not a role's name the minter quotes",
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
    assert_eq!(
        Issuer::from_bundle(b"not a bundle", upstream_of)
            .err()
            .unwrap(),
        "the bundle does not parse"
    );
    assert_eq!(f.dialled.load(SeqCst), 0, "nothing dialled");
}

fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

fn lease() -> String {
    bson::oid::ObjectId::new().to_hex()
}

/// `host:port`, as the endpoint's own reader takes it, for these tests.
fn upstream_of(raw: &str) -> Result<(String, u16), String> {
    let (host, port) = raw.rsplit_once(':').ok_or("no port")?;
    Ok((host.to_string(), port.parse().map_err(|_| "a bad port")?))
}

#[test]
fn names_are_quoted_and_a_name_that_would_be_sql_is_refused() {
    assert_eq!(ident("orders").unwrap(), "`orders`");
    assert!(ident("or`ders").is_err());
    assert!(ident("").is_err());
    assert_eq!(account("reader").unwrap(), "'reader'@'%'");
    assert_eq!(account("reader@localhost").unwrap(), "'reader'@'localhost'");
    for bad in ["read'er", "reader@lo'cal", "r\\eader", "@", "reader@"] {
        assert!(account(bad).is_err(), "{bad}");
    }
    assert_eq!(
        event_of("roomler_0123456789abcdef01234567"),
        "roomler_end_0123456789abcdef01234567"
    );
}

/// A real MySQL's issuer world, made by its `root`: a database and a table,
/// a role that reads it, and an issuer that may create users, schedule
/// events in that database, grant that role, see and end connections. Its
/// sign-in word is made for this run.
async fn issuer_world(root: &Upstream, word: &str) {
    let mut s = mysql::sign_in(root, "mysql").await.unwrap();
    for sql in [
        "CREATE DATABASE IF NOT EXISTS mintdb".to_string(),
        "CREATE TABLE IF NOT EXISTS mintdb.t (id INT PRIMARY KEY)".into(),
        "INSERT IGNORE INTO mintdb.t VALUES (1)".into(),
        "CREATE ROLE IF NOT EXISTS 'mint_reader'".into(),
        "GRANT SELECT ON mintdb.* TO 'mint_reader'".into(),
        format!("CREATE USER IF NOT EXISTS 'mint_issuer'@'%' IDENTIFIED BY '{word}'"),
        format!("ALTER USER 'mint_issuer'@'%' IDENTIFIED BY '{word}'"),
        "GRANT CREATE USER, PROCESS, CONNECTION_ADMIN ON *.* TO 'mint_issuer'@'%'".into(),
        "GRANT EVENT ON mintdb.* TO 'mint_issuer'@'%'".into(),
        "GRANT 'mint_reader' TO 'mint_issuer'@'%' WITH ADMIN OPTION".into(),
    ] {
        mysql::query(&mut s, &sql).await.unwrap();
    }
    mysql::quit(s).await;
}

/// The issuer, as a lease's bundle would carry it.
fn issuer(root: &Upstream, word: &str) -> Issuer {
    let ca = std::fs::read_to_string(std::env::var("ROOMLER_TEST_MYSQL_CA").unwrap()).unwrap();
    let bundle = serde_json::to_vec(&json!({
        "audience": format!("{}:{}", root.host, root.port),
        "fields": {
            "admin_user": "mint_issuer",
            "admin_password": word,
            "database": "mintdb",
            "grants": "mint_reader\n",
            "ca": ca,
        },
    }))
    .unwrap();
    Issuer::from_bundle(&bundle, upstream_of).unwrap()
}

/// Signs in as a minted user, and reads what its role may.
async fn reads_as(m: &Minted, root: &Upstream) -> Result<Vec<Vec<Option<String>>>, String> {
    let up = Upstream {
        host: m.host.clone(),
        port: m.port,
        user: m.user.clone(),
        password: m.password.clone(),
        tls: root.tls.clone(),
    };
    let mut s = mysql::sign_in(&up, &m.database).await?;
    let rows = mysql::query(&mut s, "SELECT CURRENT_ROLE(), (SELECT id FROM t)").await;
    mysql::quit(s).await;
    rows
}

async fn events(root: &Upstream, name: &str) -> usize {
    let mut s = mysql::sign_in(root, "mysql").await.unwrap();
    let n = mysql::query(
        &mut s,
        &format!("SELECT 1 FROM information_schema.EVENTS WHERE EVENT_NAME = '{name}'"),
    )
    .await
    .unwrap()
    .len();
    mysql::quit(s).await;
    n
}

/// Against a real MySQL: a user minted from its password's form, signing in
/// by its password over verified TLS, with its role; its end scheduled as an
/// event; taken back, after which it signs in no more and its event is gone;
/// an ended user swept at the next mint; a name no mint made refused.
#[tokio::test]
#[ignore = "needs a MySQL: ROOMLER_TEST_MYSQL, ROOMLER_TEST_MYSQL_CA, ROOMLER_TEST_MYSQL_AUTH_FILE"]
async fn a_real_mysql_user_is_minted_ended_and_taken_back() {
    let root = real_mysql().expect("a MySQL named by the environment");
    let word = made();
    issuer_world(&root, &word).await;
    let issuer = issuer(&root, &word);

    let id = lease();
    let m = mint(&issuer, &id, now() + 600).await.unwrap();
    assert_eq!(m.user, format!("roomler_{id}"));
    assert_eq!(m.password.len(), 43, "32 random bytes, base64url");
    assert_eq!(
        reads_as(&m, &root).await.unwrap(),
        [vec![
            Some("`mint_reader`@`%`".to_string()),
            Some("1".to_string())
        ]]
    );
    assert_eq!(events(&root, &format!("roomler_end_{id}")).await, 1);

    revoke(&issuer, &m.user).await.unwrap();
    let why = reads_as(&m, &root).await.unwrap_err();
    assert!(why.contains("1045 (28000)"), "{why}");
    assert_eq!(events(&root, &format!("roomler_end_{id}")).await, 0);
    revoke(&issuer, &m.user).await.unwrap();

    // Ended before its event could run (its time already past): the next
    // mint sweeps it.
    let old = mint(&issuer, &lease(), now() - 10).await.unwrap();
    assert!(
        reads_as(&old, &root).await.is_ok(),
        "it signs in until swept"
    );
    let fresh = mint(&issuer, &lease(), now() + 600).await.unwrap();
    assert!(reads_as(&old, &root).await.is_err(), "swept");
    revoke(&issuer, &fresh.user).await.unwrap();

    for name in ["root", "mint_issuer", "roomler_", "roomler_zz"] {
        assert!(revoke(&issuer, name).await.is_err(), "{name}");
    }
}
