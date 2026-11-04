// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! The MongoDB proxy's session, against a fake upstream over real TLS.

use bson::doc;
use tokio::io::DuplexStream;

use super::super::testing::{MongoSaw, MongoUpstreams, fake_mongo, made, op_query};
use super::*;

fn upstream(ca: Option<&str>, port: u16, password: &str) -> Upstream {
    Upstream {
        host: "localhost".into(),
        port,
        user: "app".into(),
        password: Zeroizing::new(password.into()),
        auth_source: "admin".into(),
        tls: tls::connector(ca).unwrap(),
    }
}

/// Serve one client of `up` over a pipe; the client's end, and the
/// session's result.
fn client_of(up: Upstream) -> (DuplexStream, tokio::task::JoinHandle<Result<(), String>>) {
    let (client, proxy) = tokio::io::duplex(64 * 1024);
    (client, tokio::spawn(async move { serve(proxy, &up).await }))
}

/// The next message to the client, within 10 s.
async fn reply(c: &mut DuplexStream) -> Message {
    tokio::time::timeout(Duration::from_secs(10), read_message(c, 1 << 20))
        .await
        .expect("an answer within 10 s")
        .expect("a message")
}

/// The document a reply carries, whichever kind it is.
fn reply_doc(m: &Message) -> Document {
    match m.op_code {
        OP_MSG => op_msg_document(m.body()).unwrap(),
        // Flags, a cursor, where it starts, how many: then the document.
        OP_REPLY => Document::from_reader(&mut &m.body()[20..]).unwrap(),
        other => panic!("a reply of op code {other}"),
    }
}

/// The legacy handshake a driver sends first, with its metadata.
fn handshake(id: i32) -> Vec<u8> {
    op_query(
        id,
        "admin.$cmd",
        &doc! { "isMaster": 1, "client": { "driver": { "name": "a-test", "version": "1" } } },
    )
}

/// Everything the fake has reported so far.
fn seen(saw: &mut tokio::sync::mpsc::UnboundedReceiver<MongoSaw>) -> Vec<MongoSaw> {
    std::iter::from_fn(|| saw.try_recv().ok()).collect()
}

/// The whole road. A client with no credentials gets its handshake answered
/// by a connection the proxy signed in as the secret's user: the upstream
/// sees the SCRAM exchange first, no `hello` of the proxy's own, then the
/// client's handshake with its metadata, then what the client asks.
#[tokio::test]
async fn a_client_without_credentials_gets_a_session_as_the_secrets_user() {
    let pw = made();
    let (ca, port, mut saw) = fake_mongo(MongoUpstreams::Scram(pw.clone())).await;
    let (mut c, session) = client_of(upstream(Some(&ca), port, &pw));
    c.write_all(&handshake(7)).await.unwrap();
    let m = reply(&mut c).await;
    assert_eq!((m.op_code, m.response_to), (OP_REPLY, 7));
    assert_eq!(reply_doc(&m).get_bool("ismaster"), Ok(true));
    let command = |name: &str, db: &str| MongoSaw::Command(name.into(), db.into());
    assert_eq!(
        seen(&mut saw),
        [
            command("saslStart", "admin"),
            MongoSaw::User("app".into()),
            command("saslContinue", "admin"),
            MongoSaw::Query("admin.$cmd".into(), "isMaster".into()),
            MongoSaw::Metadata(true),
        ],
        "signed in first, and the client's handshake the connection's first"
    );
    c.write_all(&op_msg(8, 0, &doc! { "ping": 1, "$db": "orders" }))
        .await
        .unwrap();
    let m = reply(&mut c).await;
    assert_eq!((m.op_code, m.response_to), (OP_MSG, 8));
    assert_eq!(reply_doc(&m).get_f64("ok"), Ok(1.0));
    assert_eq!(saw.recv().await.unwrap(), command("ping", "orders"));
    drop(c);
    assert!(session.await.unwrap().is_ok());
}

/// A wrong password: the upstream's refusal answers the client's first
/// message in the kind it was sent as, and that message never reaches the
/// upstream.
#[tokio::test]
async fn the_upstreams_refusal_answers_the_clients_first_message() {
    for (first, kind) in [
        (handshake(7), OP_REPLY),
        (op_msg(7, 0, &doc! { "hello": 1, "$db": "admin" }), OP_MSG),
    ] {
        let (ca, port, mut saw) = fake_mongo(MongoUpstreams::Scram(made())).await;
        let (mut c, session) = client_of(upstream(Some(&ca), port, &made()));
        c.write_all(&first).await.unwrap();
        let m = reply(&mut c).await;
        assert_eq!((m.op_code, m.response_to), (kind, 7));
        let answer = reply_doc(&m);
        assert_eq!(answer.get_f64("ok"), Ok(0.0));
        assert_eq!(
            answer.get_str("errmsg"),
            Ok("the upstream refused: Authentication failed.")
        );
        assert!(session.await.unwrap().is_err());
        let seen = seen(&mut saw);
        assert!(
            !seen.iter().any(|s| matches!(s, MongoSaw::Query(..))
                || matches!(s, MongoSaw::Command(n, _) if n == "hello")),
            "the client's first message never left: {seen:?}"
        );
    }
}

/// A server that cannot sign never held the password: refused before a byte
/// of the client's is sent to it.
#[tokio::test]
async fn a_server_that_cannot_sign_is_refused_before_the_clients_first_message() {
    let pw = made();
    let (ca, port, mut saw) = fake_mongo(MongoUpstreams::Forged(pw.clone())).await;
    let (mut c, session) = client_of(upstream(Some(&ca), port, &pw));
    c.write_all(&handshake(7)).await.unwrap();
    let answer = reply_doc(&reply(&mut c).await);
    assert!(
        answer
            .get_str("errmsg")
            .unwrap()
            .contains("does not hold the password"),
        "{answer}"
    );
    assert!(session.await.unwrap().is_err());
    let seen = seen(&mut saw);
    assert!(
        !seen.iter().any(|s| matches!(s, MongoSaw::Query(..))),
        "{seen:?}"
    );
}

/// A server before 4.4 does not skip the empty exchange: the proxy ends the
/// conversation with one, then the session runs.
#[tokio::test]
async fn an_upstream_that_asks_for_the_empty_exchange_is_given_it() {
    let pw = made();
    let (ca, port, mut saw) = fake_mongo(MongoUpstreams::NoSkip(pw.clone())).await;
    let (mut c, session) = client_of(upstream(Some(&ca), port, &pw));
    c.write_all(&handshake(7)).await.unwrap();
    assert_eq!(
        reply_doc(&reply(&mut c).await).get_bool("ismaster"),
        Ok(true)
    );
    let names: Vec<String> = seen(&mut saw)
        .into_iter()
        .filter_map(|s| match s {
            MongoSaw::Command(n, _) => Some(n),
            _ => None,
        })
        .collect();
    assert_eq!(names, ["saslStart", "saslContinue", "saslContinue"]);
    drop(c);
    assert!(session.await.unwrap().is_ok());
}

/// A first message past its bound is refused before any upstream is
/// dialled; and an upstream whose certificate no root vouches for is refused
/// at TLS, the client told why.
#[tokio::test]
async fn a_first_message_past_its_bound_and_an_unvouched_upstream_are_refused() {
    let (ca, port, mut saw) = fake_mongo(MongoUpstreams::Scram(made())).await;
    let (mut c, session) = client_of(upstream(Some(&ca), port, &made()));
    let mut head = ((1i32 << 20) + 1).to_le_bytes().to_vec();
    head.extend([0u8; 12]);
    c.write_all(&head).await.unwrap();
    let ended = tokio::time::timeout(Duration::from_secs(10), session).await;
    let why = ended.expect("refused at once").unwrap().unwrap_err();
    assert!(why.contains("a message of"), "{why}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(saw.try_recv().is_err(), "no upstream was dialled");

    let (mut c, session) = client_of(upstream(None, port, &made()));
    c.write_all(&handshake(9)).await.unwrap();
    let answer = reply_doc(&reply(&mut c).await);
    assert!(
        answer
            .get_str("errmsg")
            .unwrap()
            .starts_with("TLS to localhost"),
        "{answer}"
    );
    assert!(session.await.unwrap().is_err());
}

/// P3-5c-2 — a client the endpoint does not serve has its first message
/// answered with why, as a refusal answers it.
#[tokio::test]
async fn a_client_the_endpoint_does_not_serve_is_told_why() {
    let (mut c, mut proxy) = tokio::io::duplex(64 * 1024);
    c.write_all(&handshake(5)).await.unwrap();
    refuse(&mut proxy, "the endpoint's lease has ended")
        .await
        .unwrap();
    let m = reply(&mut c).await;
    assert_eq!((m.op_code, m.response_to), (OP_REPLY, 5));
    assert_eq!(
        reply_doc(&m).get_str("errmsg"),
        Ok("the endpoint's lease has ended")
    );
}
