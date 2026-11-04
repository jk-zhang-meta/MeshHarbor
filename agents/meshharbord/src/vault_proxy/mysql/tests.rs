// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! MySQL's client protocol: its codec, and (ignored unless a MySQL is named)
//! a sign-in and queries against a real server.

use zeroize::Zeroizing;

use super::super::testing::{LOCAL_FILE_PLEASE, fake_mysql, made, real_mysql};
use super::*;

/// The client never offers what would let a server read a local file, and
/// always asks for TLS.
#[test]
fn the_client_offers_no_local_files_and_asks_for_tls() {
    assert_eq!(CAPS & CLIENT_LOCAL_FILES, 0);
    assert_eq!(CAPS & CLIENT_SSL, CLIENT_SSL);
}

#[test]
fn length_encoded_integers_parse_and_null_is_none() {
    assert_eq!(lenenc(&[0x05]), Some((5, 1)));
    assert_eq!(lenenc(&[0xFA]), Some((250, 1)));
    assert_eq!(lenenc(&[0xFC, 0x34, 0x12]), Some((0x1234, 3)));
    assert_eq!(lenenc(&[0xFD, 0x56, 0x34, 0x12]), Some((0x12_3456, 4)));
    assert_eq!(lenenc(&[0xFE, 1, 0, 0, 0, 0, 0, 0, 0]), Some((1, 9)));
    assert_eq!(lenenc(&[0xFB]), None, "NULL is no integer");
    assert_eq!(lenenc(&[0xFC, 0x34]), None, "short");
    assert_eq!(lenenc(&[]), None);
}

#[test]
fn an_error_packet_reads_as_its_code_state_and_message() {
    let mut p = vec![0xFF];
    p.extend(1045u16.to_le_bytes());
    p.extend(b"#28000Access denied");
    assert_eq!(error_message(&p), "1045 (28000): Access denied");
    assert_eq!(error_message(&[0xFF, 0x15, 0x04]), "1045: ");
}

#[test]
fn a_row_reads_its_text_and_its_nulls() {
    let p = [1, b'1', 0xFB, 2, b'o', b'k'];
    assert_eq!(
        row(&p, 3).unwrap(),
        [Some("1".to_string()), None, Some("ok".to_string())]
    );
    assert!(row(&[5, b'x'], 1).is_err(), "a column past the packet");
}

/// A greeting as MySQL 8 sends it: protocol 10, its version, a connection
/// id, the scramble in two parts, its capabilities, its plugin.
fn greeting(caps: u32, nonce: &[u8]) -> Vec<u8> {
    let mut g = vec![10];
    g.extend(b"8.4.11\0");
    g.extend(7u32.to_le_bytes());
    g.extend(&nonce[..8]);
    g.push(0);
    g.extend((caps as u16).to_le_bytes());
    g.push(UTF8MB4);
    g.extend(2u16.to_le_bytes());
    g.extend(((caps >> 16) as u16).to_le_bytes());
    g.push(21);
    g.extend([0u8; 10]);
    g.extend(&nonce[8..]);
    g.push(0);
    g.extend(b"caching_sha2_password\0");
    g
}

#[test]
fn a_greeting_gives_its_capabilities_and_its_nonce() {
    let nonce: Vec<u8> = (1..=20).collect();
    let caps: u32 = CAPS | CLIENT_SSL;
    let g = greeting(caps, &nonce);
    let parsed = parse_greeting(&g).unwrap();
    assert_eq!(parsed.caps, caps);
    assert_eq!(parsed.nonce, nonce);
    assert!(parse_greeting(&g[..12]).is_err(), "short");
    assert!(parse_greeting(&[9]).is_err(), "not protocol 10");
}

/// A server that offers no TLS, or not the 4.1 protocol, is refused at its
/// greeting: the client sends it nothing at all, so neither the user's name
/// nor anything made from the password crosses the wire in the clear.
#[tokio::test]
async fn a_server_that_offers_no_tls_is_sent_no_byte_of_the_sign_in() {
    let ca = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .unwrap()
        .cert
        .pem();
    for (caps, says) in [
        (CAPS & !CLIENT_SSL, "the upstream does not offer TLS"),
        (
            (CAPS | CLIENT_SSL) & !CLIENT_PLUGIN_AUTH,
            "the upstream does not speak MySQL's 4.1 protocol",
        ),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            write_packet(&mut tcp, 0, &greeting(caps, &[7u8; 20]))
                .await
                .unwrap();
            // Everything the client sends until it hangs up.
            let mut got = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut got)).await;
            got
        });
        let up = Upstream {
            host: "localhost".into(),
            port,
            user: "admin".into(),
            password: Zeroizing::new(made()),
            tls: tls::connector(Some(&ca)).unwrap(),
        };
        let why = sign_in(&up, "orders").await.err().unwrap();
        let sent = server.await.unwrap();
        assert!(sent.is_empty(), "{says}: {} bytes sent", sent.len());
        assert!(why.starts_with(says), "{why}");
    }
}

/// A server that answers a query by asking for a local file is refused in
/// words, and sent nothing for it: the session's next query is answered as
/// the next command it reads.
#[tokio::test]
async fn a_server_that_asks_for_a_local_file_is_sent_none() {
    let admin = made();
    let f = fake_mysql(&admin).await;
    let up = Upstream {
        host: "localhost".into(),
        port: f.port,
        user: "admin".into(),
        password: Zeroizing::new(admin.clone()),
        tls: tls::connector(Some(&f.ca)).unwrap(),
    };
    let mut s = sign_in(&up, "orders").await.unwrap();
    let why = query(&mut s, LOCAL_FILE_PLEASE).await.unwrap_err();
    assert_eq!(
        why,
        "the upstream asked for a local file, which this client never sends"
    );
    let next = query(
        &mut s,
        "SELECT USER FROM information_schema.USER_ATTRIBUTES WHERE USER = 'nobody'",
    )
    .await;
    assert_eq!(next, Ok(Vec::new()), "the next command, in step");
    quit(s).await;
}

/// Against a real MySQL: the sign-in over verified TLS (the server's full
/// sign-in, then its cached one), a query's rows and NULLs, a refusal in
/// the server's words, and a wrong password refused.
#[tokio::test]
#[ignore = "needs a MySQL: ROOMLER_TEST_MYSQL, ROOMLER_TEST_MYSQL_CA, ROOMLER_TEST_MYSQL_AUTH_FILE"]
async fn a_real_mysql_is_signed_in_to_and_queried() {
    let up = real_mysql().expect("a MySQL named by the environment");
    for _ in 0..2 {
        let mut s = sign_in(&up, "mysql").await.unwrap();
        assert_eq!(
            query(&mut s, "SELECT 1, NULL, 'x'").await.unwrap(),
            [vec![Some("1".to_string()), None, Some("x".to_string())]]
        );
        assert_eq!(
            query(&mut s, "SELECT CURRENT_USER()").await.unwrap()[0][0].as_deref(),
            Some("root@%")
        );
        let tls = query(
            &mut s,
            "SELECT VARIABLE_VALUE FROM performance_schema.session_status WHERE VARIABLE_NAME = 'Ssl_version'",
        )
        .await
        .unwrap();
        assert!(
            tls[0][0].as_deref().unwrap().starts_with("TLSv1."),
            "{tls:?}"
        );
        let refused = query(&mut s, "SELEC 1").await.unwrap_err();
        assert!(refused.starts_with("1064 (42000): "), "{refused}");
        assert!(query(&mut s, "DO 1").await.unwrap().is_empty(), "an OK");
        quit(s).await;
    }
    let wrong = Upstream {
        password: Zeroizing::new(format!("{}x", up.password.as_str())),
        ..up
    };
    let why = sign_in(&wrong, "mysql").await.err().unwrap();
    assert!(why.contains("1045 (28000)"), "{why}");
}
