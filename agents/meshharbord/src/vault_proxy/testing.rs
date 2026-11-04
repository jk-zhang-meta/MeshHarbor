// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-5b — what the proxies' tests and the endpoint's share: a Postgres
//! upstream over real TLS, with a certificate made for each test, that
//! authenticates as it is told to and answers queries; and a client's half of
//! the wire.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{self, ServerConfig};

use super::pg::{CANCEL_REQUEST, SSL_REQUEST, frame, parse_params, read_message, read_startup};
use super::scram::server::ScramServer;
use super::ssh_agent::{LABEL, MAGIC, put_string, put_u32};

/// A message from the client's side: `tag`, then `body`.
pub(crate) fn message(tag: u8, body: &[u8]) -> Vec<u8> {
    frame(Some(tag), body)
}

/// How the fake upstream behaves.
#[derive(Clone, PartialEq)]
pub(crate) enum Upstreams {
    /// SCRAM with this password, then a session that answers queries.
    Scram(String),
    /// Declines TLS.
    NoTls,
    /// Asks for a cleartext password.
    Cleartext,
    /// Checks the proof for this password, then signs wrong: a server
    /// that never held it.
    Forged(String),
    /// Checks the proof, then lets the session in without signing at
    /// all.
    SkipFinal(String),
    /// Trusts the connection: `AuthenticationOk` at once.
    Trusting,
    /// SCRAM with this password, after a protocol negotiation and with a
    /// notice before its `AuthenticationOk`.
    Negotiates(String),
    /// P3-5b-3 — SCRAM with this password, bound to its own certificate,
    /// and the GS2 header it saw reported.
    Binds(String),
    /// Offers no `-PLUS`, and cannot bind: an older server, or a pooler.
    PlainOnly(String),
    /// Offers no `-PLUS`, though it binds: what a relay that strips `-PLUS`
    /// from the offer leaves.
    Stripped(String),
    /// Offers `-PLUS`, and binds to another certificate than the one the
    /// proxy saw: what the real upstream sees behind a TLS-terminating relay.
    BindsElsewhere(String),
}

/// What the fake upstream saw.
#[derive(Debug, PartialEq)]
pub(crate) enum Saw {
    Startup(Vec<(String, String)>),
    Query(String),
    Cancel(Vec<u8>),
    /// Bytes from the proxy after a refusal: what a password would be.
    After(Vec<u8>),
    /// P3-5b-3 — the SASL mechanism and the GS2 header the proxy chose.
    Sasl(String, String),
}

/// A TLS upstream on a random port of 127.0.0.1, with a certificate for
/// `localhost` made for this test; its CA's PEM, its port, and what it
/// saw.
pub(crate) async fn fake(how: Upstreams) -> (String, u16, mpsc::UnboundedReceiver<Saw>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let pem = cert.cert.pem();
    // P3-5b-3 — this channel's binding data, as Postgres computes its own.
    let own_binding = super::tls::server_end_point(cert.cert.der()).unwrap();
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into()),
            )
            .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let Ok((mut tcp, _)) = listener.accept().await else {
                return;
            };
            let (acceptor, tx, how) = (acceptor.clone(), tx.clone(), how.clone());
            let own_binding = own_binding.clone();
            tokio::spawn(async move {
                let Ok(packet) = read_startup(&mut tcp).await else {
                    return;
                };
                assert_eq!(&packet[..4], &SSL_REQUEST.to_be_bytes());
                if how == Upstreams::NoTls {
                    tcp.write_all(b"N").await.unwrap();
                    let rest = what_follows(&mut tcp).await;
                    let _ = tx.send(Saw::After(rest));
                    return;
                }
                tcp.write_all(b"S").await.unwrap();
                // A proxy that refused the certificate hangs up mid-handshake.
                let Ok(mut s) = acceptor.accept(tcp).await else {
                    return;
                };
                let Ok(packet) = read_startup(&mut s).await else {
                    return;
                };
                if packet[..4] == CANCEL_REQUEST.to_be_bytes() {
                    let _ = tx.send(Saw::Cancel(packet));
                    return;
                }
                let _ = tx.send(Saw::Startup(parse_params(&packet[4..]).unwrap()));
                let r = |code: u32, more: &[u8]| {
                    let mut b = code.to_be_bytes().to_vec();
                    b.extend(more);
                    frame(Some(b'R'), &b)
                };
                match how {
                    Upstreams::Cleartext => {
                        s.write_all(&r(3, &[])).await.unwrap();
                        let rest = what_follows(&mut s).await;
                        let _ = tx.send(Saw::After(rest));
                        return;
                    }
                    Upstreams::Trusting => s.write_all(&r(0, &[])).await.unwrap(),
                    Upstreams::Scram(ref password)
                    | Upstreams::Forged(ref password)
                    | Upstreams::SkipFinal(ref password)
                    | Upstreams::Negotiates(ref password)
                    | Upstreams::Binds(ref password)
                    | Upstreams::PlainOnly(ref password)
                    | Upstreams::Stripped(ref password)
                    | Upstreams::BindsElsewhere(ref password) => {
                        let negotiates = matches!(how, Upstreams::Negotiates(_));
                        if negotiates {
                            // Minor version 0, and one option it does not know.
                            let v = b"\0\0\0\0\0\0\0\x01_pq_.x\0";
                            s.write_all(&frame(Some(b'v'), v)).await.unwrap();
                        }
                        let offer: &[u8] = match how {
                            Upstreams::PlainOnly(_) | Upstreams::Stripped(_) => {
                                b"SCRAM-SHA-256\0\0"
                            }
                            _ => b"SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0",
                        };
                        s.write_all(&r(10, offer)).await.unwrap();
                        let (tag, body) = read_message(&mut s, 64 * 1024).await.unwrap();
                        assert_eq!(tag, b'p');
                        // SASLInitialResponse: the mechanism, its length, its data.
                        let nul = body.iter().position(|b| *b == 0).unwrap();
                        let mechanism = String::from_utf8(body[..nul].to_vec()).unwrap();
                        let first = &body[nul + 1 + 4..];
                        let mut srv = ScramServer::new(password, b"a-salt", 4096, "upnonce");
                        srv = match how {
                            Upstreams::PlainOnly(_) => srv,
                            Upstreams::BindsElsewhere(_) => {
                                srv.binding(b"the hash of a relay's own certificate".to_vec())
                            }
                            _ => srv.binding(own_binding.clone()),
                        };
                        let forged = matches!(how, Upstreams::Forged(_));
                        let server_first = srv.server_first(std::str::from_utf8(first).unwrap());
                        if matches!(
                            how,
                            Upstreams::Binds(_)
                                | Upstreams::PlainOnly(_)
                                | Upstreams::Stripped(_)
                                | Upstreams::BindsElsewhere(_)
                        ) {
                            let _ = tx.send(Saw::Sasl(mechanism, srv.gs2().to_string()));
                        }
                        s.write_all(&r(11, server_first.as_bytes())).await.unwrap();
                        let (_, fin) = read_message(&mut s, 64 * 1024).await.unwrap();
                        match srv.server_final(std::str::from_utf8(&fin).unwrap()) {
                            Ok(_) if forged => {
                                let forged = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";
                                s.write_all(&r(12, forged.as_bytes())).await.unwrap();
                                s.write_all(&r(0, &[])).await.unwrap();
                            }
                            Ok(_) if matches!(how, Upstreams::SkipFinal(_)) => {
                                s.write_all(&r(0, &[])).await.unwrap();
                            }
                            Ok(v) => {
                                s.write_all(&r(12, v.as_bytes())).await.unwrap();
                                if negotiates {
                                    let notice = b"SNOTICE\0Mheld\0\0";
                                    s.write_all(&frame(Some(b'N'), notice)).await.unwrap();
                                }
                                s.write_all(&r(0, &[])).await.unwrap();
                            }
                            Err(why) => {
                                // Postgres's own words for each refusal.
                                let (code, message) = match why.as_str() {
                                    "e=invalid-proof" => {
                                        ("28P01", "password authentication failed for user \"app\"")
                                    }
                                    "e=channel-bindings-dont-match" => {
                                        ("08P01", "SCRAM channel binding check failed")
                                    }
                                    "e=server-does-support-channel-binding" => {
                                        ("08P01", "SCRAM channel binding negotiation error")
                                    }
                                    _ => ("08P01", "malformed SCRAM message"),
                                };
                                let mut e = Vec::new();
                                for (c, t) in [(b'S', "FATAL"), (b'C', code), (b'M', message)] {
                                    e.push(c);
                                    e.extend(t.as_bytes());
                                    e.push(0);
                                }
                                e.push(0);
                                s.write_all(&frame(Some(b'E'), &e)).await.unwrap();
                                return;
                            }
                        }
                    }
                    Upstreams::NoTls => unreachable!(),
                }
                // The session: a parameter, the cancel key, ready.
                s.write_all(&frame(Some(b'S'), b"server_version\x0017.2\x00"))
                    .await
                    .unwrap();
                s.write_all(&frame(Some(b'K'), &[0, 0, 0, 7, 1, 2, 3, 4]))
                    .await
                    .unwrap();
                s.write_all(&frame(Some(b'Z'), b"I")).await.unwrap();
                while let Ok((tag, body)) = read_message(&mut s, 1 << 20).await {
                    if tag == b'X' {
                        return;
                    }
                    let q = String::from_utf8_lossy(&body[..body.len() - 1]).into_owned();
                    let _ = tx.send(Saw::Query(q));
                    s.write_all(&frame(Some(b'C'), b"SELECT 1\x00"))
                        .await
                        .unwrap();
                    s.write_all(&frame(Some(b'Z'), b"I")).await.unwrap();
                }
            });
        }
    });
    (pem, port, rx)
}

/// P3-6b-2 — one role the fake issuer's database holds.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FakeRole {
    pub(crate) verifier: String,
    pub(crate) valid_until: String,
    pub(crate) grants: Vec<String>,
    pub(crate) comment: Option<String>,
    pub(crate) login: bool,
}

/// The fake issuer's roles, by name.
pub(crate) type FakeRoles = Arc<std::sync::Mutex<std::collections::BTreeMap<String, FakeRole>>>;

/// What the fake issuer refuses, as Postgres refuses an issuer short of a
/// privilege: `CREATE ROLE` without `CREATEROLE`, ending another role's
/// session without `pg_signal_backend`, `REASSIGN OWNED` without the role's
/// privileges.
#[derive(Default)]
pub(crate) struct Refuse {
    pub(crate) create: std::sync::atomic::AtomicBool,
    pub(crate) terminate: std::sync::atomic::AtomicBool,
    pub(crate) reassign: std::sync::atomic::AtomicBool,
}

/// P3-6b-2 — a Postgres an issuer mints in, over real TLS with a
/// certificate made for the test. `admin` signs in with the password it was
/// made with; a role it made signs in by the verifier `CREATE ROLE` gave
/// it, as Postgres signs one in, while it may log in. The minter's
/// statements are answered as Postgres answers them, and every query kept.
pub(crate) struct FakeIssuer {
    pub(crate) ca: String,
    pub(crate) port: u16,
    pub(crate) saw: mpsc::UnboundedReceiver<String>,
    pub(crate) roles: FakeRoles,
    pub(crate) refuse: Arc<Refuse>,
    /// How many connections it took: zero for a call refused before
    /// anything is dialled.
    pub(crate) dialled: Arc<std::sync::atomic::AtomicUsize>,
    /// P3-6b-2b — while `hold_create` is set, a `CREATE ROLE` is kept
    /// unanswered until `let_create` is notified: a mint caught mid-flight.
    pub(crate) hold_create: Arc<std::sync::atomic::AtomicBool>,
    pub(crate) let_create: Arc<tokio::sync::Notify>,
}

pub(crate) async fn fake_issuer(password: &str) -> FakeIssuer {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let ca = cert.cert.pem();
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into()),
            )
            .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, saw) = mpsc::unbounded_channel();
    let roles: FakeRoles = Arc::default();
    let refuse: Arc<Refuse> = Arc::default();
    let dialled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let hold_create = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let let_create = Arc::new(tokio::sync::Notify::new());
    let password = password.to_string();
    let (r2, f2, d2) = (roles.clone(), refuse.clone(), dialled.clone());
    let (h2, l2) = (hold_create.clone(), let_create.clone());
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            d2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (acceptor, tx, roles, refuse) =
                (acceptor.clone(), tx.clone(), r2.clone(), f2.clone());
            let (hold, go) = (h2.clone(), l2.clone());
            let password = password.clone();
            tokio::spawn(async move {
                let Ok(packet) = read_startup(&mut tcp).await else {
                    return;
                };
                assert_eq!(&packet[..4], &SSL_REQUEST.to_be_bytes());
                tcp.write_all(b"S").await.unwrap();
                let Ok(mut s) = acceptor.accept(tcp).await else {
                    return;
                };
                let Ok(packet) = read_startup(&mut s).await else {
                    return;
                };
                let params = parse_params(&packet[4..]).unwrap();
                let user = params
                    .iter()
                    .find(|(k, _)| k == "user")
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();
                let server = if user == "admin" {
                    Some(ScramServer::new(&password, b"a-salt", 4096, "upnonce"))
                } else {
                    let role = roles
                        .lock()
                        .unwrap()
                        .get(&user)
                        .filter(|r| r.login)
                        .cloned();
                    // A password that is no verifier signs nobody in.
                    role.and_then(|r| ScramServer::from_verifier(&r.verifier, "upnonce").ok())
                };
                let r = |code: u32, more: &[u8]| {
                    let mut b = code.to_be_bytes().to_vec();
                    b.extend(more);
                    frame(Some(b'R'), &b)
                };
                let Some(mut srv) = server else {
                    let _ = s
                        .write_all(&pg_error(
                            "28P01",
                            &format!("password authentication failed for user \"{user}\""),
                        ))
                        .await;
                    return;
                };
                // Plain SCRAM-SHA-256 only: a server that cannot bind.
                s.write_all(&r(10, b"SCRAM-SHA-256\0\0")).await.unwrap();
                let Ok((_, body)) = read_message(&mut s, 64 * 1024).await else {
                    return;
                };
                let nul = body.iter().position(|b| *b == 0).unwrap();
                let first = std::str::from_utf8(&body[nul + 1 + 4..]).unwrap();
                let server_first = srv.server_first(first);
                s.write_all(&r(11, server_first.as_bytes())).await.unwrap();
                let Ok((_, fin)) = read_message(&mut s, 64 * 1024).await else {
                    return;
                };
                match srv.server_final(std::str::from_utf8(&fin).unwrap()) {
                    Ok(v) => {
                        s.write_all(&r(12, v.as_bytes())).await.unwrap();
                        s.write_all(&r(0, &[])).await.unwrap();
                    }
                    Err(_) => {
                        let _ = s
                            .write_all(&pg_error(
                                "28P01",
                                &format!("password authentication failed for user \"{user}\""),
                            ))
                            .await;
                        return;
                    }
                }
                s.write_all(&frame(Some(b'S'), b"server_version\x0017.2\x00"))
                    .await
                    .unwrap();
                s.write_all(&frame(Some(b'K'), &[0, 0, 0, 9, 1, 2, 3, 4]))
                    .await
                    .unwrap();
                s.write_all(&frame(Some(b'Z'), b"I")).await.unwrap();
                while let Ok((tag, body)) = read_message(&mut s, 1 << 20).await {
                    if tag != b'Q' {
                        return;
                    }
                    let sql = String::from_utf8_lossy(&body[..body.len() - 1]).into_owned();
                    let _ = tx.send(sql.clone());
                    if sql.starts_with("CREATE ROLE ")
                        && hold.load(std::sync::atomic::Ordering::SeqCst)
                    {
                        go.notified().await;
                    }
                    let reply = issuer_answer(&sql, &roles, &refuse);
                    s.write_all(&reply).await.unwrap();
                }
            });
        }
    });
    FakeIssuer {
        ca,
        port,
        saw,
        roles,
        refuse,
        dialled,
        hold_create,
        let_create,
    }
}

/// An `ErrorResponse`, `ERROR` with this SQLSTATE and message.
fn pg_error(code: &str, message: &str) -> Vec<u8> {
    let mut e = Vec::new();
    for (c, t) in [(b'S', "ERROR"), (b'C', code), (b'M', message)] {
        e.push(c);
        e.extend(t.as_bytes());
        e.push(0);
    }
    e.push(0);
    frame(Some(b'E'), &e)
}

/// A `DataRow` of text columns.
fn pg_row(columns: &[&str]) -> Vec<u8> {
    let mut d = (columns.len() as u16).to_be_bytes().to_vec();
    for c in columns {
        d.extend((c.len() as i32).to_be_bytes());
        d.extend(c.as_bytes());
    }
    frame(Some(b'D'), &d)
}

/// The text between `open` and the next `close` after it.
fn between<'a>(s: &'a str, open: &str, close: char) -> Option<&'a str> {
    let rest = &s[s.find(open)? + open.len()..];
    Some(&rest[..rest.find(close)?])
}

/// How the fake issuer's database answers one query: the statements the
/// minter sends, as Postgres answers them; anything else, a syntax error.
/// Each clause is read where it stands, and one that is absent leaves what it
/// sets empty, so a minter that drops a clause is caught by what its test
/// asserts, never by this fake.
fn issuer_answer(sql: &str, roles: &FakeRoles, refuse: &Refuse) -> Vec<u8> {
    use std::sync::atomic::Ordering::SeqCst;
    let done = |tags: &[&str]| {
        let mut out = Vec::new();
        for t in tags {
            out.extend(frame(Some(b'C'), format!("{t}\0").as_bytes()));
        }
        out
    };
    let missing = |name: &str| pg_error("42704", &format!("role \"{name}\" does not exist"));
    let mut out = if sql.starts_with("CREATE ROLE ") {
        let name = between(sql, "CREATE ROLE \"", '"')
            .unwrap_or_default()
            .to_string();
        if refuse.create.load(SeqCst) {
            pg_error("42501", "permission denied to create role")
        } else {
            let grants = sql
                .split_once(" IN ROLE ")
                .map(|(_, rest)| {
                    rest.split(';')
                        .next()
                        .unwrap()
                        .split(", ")
                        .map(|g| g.trim_matches('"').to_string())
                        .collect()
                })
                .unwrap_or_default();
            let role = FakeRole {
                verifier: between(sql, "PASSWORD '", '\'')
                    .unwrap_or_default()
                    .to_string(),
                valid_until: between(sql, "VALID UNTIL '", '\'')
                    .unwrap_or_default()
                    .to_string(),
                grants,
                comment: between(sql, "\" IS '", '\'').map(String::from),
                login: sql.contains(" LOGIN "),
            };
            match roles.lock().unwrap().entry(name) {
                // P3-6b-2b — as Postgres: a name is one role's, so a second
                // mint for one lease is refused, never a second credential.
                std::collections::btree_map::Entry::Occupied(taken) => {
                    pg_error("42710", &format!("role \"{}\" already exists", taken.key()))
                }
                std::collections::btree_map::Entry::Vacant(free) => {
                    free.insert(role);
                    done(&["CREATE ROLE", "COMMENT"])
                }
            }
        }
    } else if sql.starts_with("SELECT r.rolname FROM pg_catalog.pg_roles r WHERE r.rolname LIKE ") {
        // The sweep, each of its clauses applied as Postgres applies it: a
        // name's prefix (`\_` an underscore), `VALID UNTIL` past (a role
        // with none is never past it), the comment's prefix.
        let prefix = between(sql, "r.rolname LIKE '", '\'')
            .map(|p| p.trim_end_matches('%').replace("\\_", "_"));
        let expiry = sql.contains("r.rolvaliduntil < now()");
        let mark = between(sql, "'pg_authid') LIKE '", '\'').map(|m| m.trim_end_matches('%'));
        let now = bson::DateTime::now();
        let expired: Vec<String> = roles
            .lock()
            .unwrap()
            .iter()
            .filter(|(name, r)| {
                prefix.as_deref().is_none_or(|p| name.starts_with(p))
                    && (!expiry
                        || bson::DateTime::parse_rfc3339_str(&r.valid_until).is_ok_and(|t| t < now))
                    && mark.is_none_or(|m| r.comment.as_deref().is_some_and(|c| c.starts_with(m)))
            })
            .map(|(name, _)| name.clone())
            .collect();
        let mut out = Vec::new();
        for name in &expired {
            out.extend(pg_row(&[name]));
        }
        out.extend(done(&[&format!("SELECT {}", expired.len())]));
        out
    } else if let Some(name) = sql
        .strip_prefix("SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '")
        .and_then(|r| r.strip_suffix('\''))
    {
        if roles.lock().unwrap().contains_key(name) {
            let mut out = pg_row(&["1"]);
            out.extend(done(&["SELECT 1"]));
            out
        } else {
            done(&["SELECT 0"])
        }
    } else if sql.starts_with("ALTER ROLE ") && sql.ends_with(" NOLOGIN") {
        let name = between(sql, "ALTER ROLE \"", '"').unwrap_or_default();
        match roles.lock().unwrap().get_mut(name) {
            Some(r) => {
                r.login = false;
                done(&["ALTER ROLE"])
            }
            None => missing(name),
        }
    } else if sql.starts_with("SELECT pg_catalog.pg_terminate_backend(pid) ") {
        if refuse.terminate.load(SeqCst) {
            pg_error("42501", "permission denied to terminate process")
        } else {
            done(&["SELECT 0"])
        }
    } else if let Some(name) = between(sql, "REASSIGN OWNED BY \"", '"') {
        if refuse.reassign.load(SeqCst) {
            pg_error("42501", "permission denied to reassign objects")
        } else if roles.lock().unwrap().contains_key(name) {
            done(&["REASSIGN OWNED", "DROP OWNED"])
        } else {
            missing(name)
        }
    } else if let Some(name) = between(sql, "DROP ROLE IF EXISTS \"", '"') {
        roles.lock().unwrap().remove(name);
        done(&["DROP ROLE"])
    } else {
        pg_error("42601", "syntax error")
    };
    out.extend(frame(Some(b'Z'), b"I"));
    out
}

/// A password made for one test run, never written down.
pub(crate) fn made() -> String {
    format!("made-{:016x}", rand::random::<u64>())
}

/// P3-6d-1 — the real MySQL a run names, as its `root`'s upstream:
/// `ROOMLER_TEST_MYSQL` (`host:port`), its CA's PEM at
/// `ROOMLER_TEST_MYSQL_CA`, and `root`'s sign-in word in the file at
/// `ROOMLER_TEST_MYSQL_AUTH_FILE`. `None` when the run names none: the tests
/// that need one are ignored by default.
pub(crate) fn real_mysql() -> Option<super::pg::Upstream> {
    let at = std::env::var("ROOMLER_TEST_MYSQL").ok()?;
    let (host, port) = at.rsplit_once(':')?;
    let ca = std::fs::read_to_string(std::env::var("ROOMLER_TEST_MYSQL_CA").ok()?).ok()?;
    let word = std::fs::read_to_string(std::env::var("ROOMLER_TEST_MYSQL_AUTH_FILE").ok()?).ok()?;
    Some(super::pg::Upstream {
        host: host.to_string(),
        port: port.parse().ok()?,
        user: "root".into(),
        password: zeroize::Zeroizing::new(word.trim().to_string()),
        tls: super::tls::connector(Some(&ca)).ok()?,
    })
}

/// P3-6d-1 — one user the fake MySQL holds.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct FakeUser {
    /// `CREATE USER … AS`'s form: `$A$005$`, its salt, its digest.
    pub(crate) form: String,
    pub(crate) attribute: Option<String>,
    pub(crate) grants: Vec<String>,
    pub(crate) default_roles: bool,
    pub(crate) locked: bool,
}

/// The fake MySQL's users, by name.
pub(crate) type FakeUsers = Arc<std::sync::Mutex<std::collections::BTreeMap<String, FakeUser>>>;

/// What the fake MySQL refuses, as MySQL refuses an issuer short of a
/// privilege: an event without `EVENT` on the database, a grant without the
/// role's `ADMIN OPTION`, a `KILL` without `CONNECTION_ADMIN`.
#[derive(Default)]
pub(crate) struct MysqlRefuse {
    pub(crate) event: std::sync::atomic::AtomicBool,
    pub(crate) grant: std::sync::atomic::AtomicBool,
    pub(crate) kill: std::sync::atomic::AtomicBool,
}

/// P3-6d-1 — a MySQL an issuer mints in, over real TLS with a certificate
/// made for the test. `admin` signs in by the password it was made with; a
/// user it made, by the form `CREATE USER … AS` gave it, while it is not
/// locked; a user it does not hold is switched to `sha256_password` and
/// refused, as MySQL answers one. Every sign-in is the full one, the password
/// inside the TLS. The minter's statements are answered as MySQL answers
/// them, each clause read where it stands, and every query kept.
pub(crate) struct FakeMysql {
    pub(crate) ca: String,
    pub(crate) port: u16,
    pub(crate) saw: mpsc::UnboundedReceiver<String>,
    pub(crate) users: FakeUsers,
    pub(crate) events: Arc<std::sync::Mutex<std::collections::BTreeSet<String>>>,
    pub(crate) refuse: Arc<MysqlRefuse>,
    /// How many connections it took: zero for a call refused before
    /// anything is dialled.
    pub(crate) dialled: Arc<std::sync::atomic::AtomicUsize>,
}

pub(crate) async fn fake_mysql(password: &str) -> FakeMysql {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let ca = cert.cert.pem();
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into()),
            )
            .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, saw) = mpsc::unbounded_channel();
    let users: FakeUsers = Arc::default();
    let events: Arc<std::sync::Mutex<std::collections::BTreeSet<String>>> = Arc::default();
    let refuse: Arc<MysqlRefuse> = Arc::default();
    let dialled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mysql = MysqlState {
        password: password.to_string(),
        users: users.clone(),
        events: events.clone(),
        refuse: refuse.clone(),
    };
    let d2 = dialled.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            d2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (acceptor, tx, mysql) = (acceptor.clone(), tx.clone(), mysql.clone());
            tokio::spawn(async move {
                let _ = serve_mysql(tcp, acceptor, mysql, tx).await;
            });
        }
    });
    FakeMysql {
        ca,
        port,
        saw,
        users,
        events,
        refuse,
        dialled,
    }
}

/// The one query the fake MySQL answers as a hostile server would: by asking
/// for a local file (`LOCAL INFILE`'s request, `0xFB` and a path).
pub(crate) const LOCAL_FILE_PLEASE: &str = "SELECT 'a local file, please'";

/// What every connection of the fake MySQL shares.
#[derive(Clone)]
struct MysqlState {
    password: String,
    users: FakeUsers,
    events: Arc<std::sync::Mutex<std::collections::BTreeSet<String>>>,
    refuse: Arc<MysqlRefuse>,
}

/// How the fake MySQL checks one account's password: `admin`'s against the
/// password the fake was made with, a minted user's against its form.
type PasswordCheck = Box<dyn Fn(&[u8]) -> bool + Send>;

/// One connection of the fake MySQL: its greeting, TLS, the sign-in, then
/// queries until `COM_QUIT`.
async fn serve_mysql(
    mut tcp: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    mysql: MysqlState,
    tx: mpsc::UnboundedSender<String>,
) -> Result<(), String> {
    use super::mysql::{CACHING_SHA2, CAPS, CLIENT_SSL, SHA256, read_packet, write_packet};
    let nonce: Vec<u8> = (0..20).map(|_| b'a' + rand::random::<u8>() % 26).collect();
    let caps = CAPS | CLIENT_SSL;
    let mut g = vec![10];
    g.extend(b"8.4.11-fake\0");
    g.extend(9u32.to_le_bytes());
    g.extend(&nonce[..8]);
    g.push(0);
    g.extend((caps as u16).to_le_bytes());
    g.push(255);
    g.extend(2u16.to_le_bytes());
    g.extend(((caps >> 16) as u16).to_le_bytes());
    g.push(21);
    g.extend([0u8; 10]);
    g.extend(&nonce[8..]);
    g.push(0);
    g.extend(CACHING_SHA2.as_bytes());
    g.push(0);
    write_packet(&mut tcp, 0, &g).await?;
    let (_, ssl) = read_packet(&mut tcp, 1024).await?;
    let asked = u32::from_le_bytes(ssl.get(..4).ok_or("short")?.try_into().unwrap());
    assert_ne!(asked & CLIENT_SSL, 0, "the client asks for TLS first");
    let mut s = acceptor.accept(tcp).await.map_err(|e| e.to_string())?;
    let (got, hello) = read_packet(&mut s, 64 * 1024).await?;
    let user_end = 32 + hello[32..].iter().position(|b| *b == 0).ok_or("no user")?;
    let user = String::from_utf8_lossy(&hello[32..user_end]).into_owned();
    let mut seq = got.wrapping_add(1);
    let denied = |user: &str| {
        let mut e = vec![0xFF];
        e.extend(1045u16.to_le_bytes());
        e.extend(
            format!("#28000Access denied for user '{user}'@'localhost' (using password: YES)")
                .as_bytes(),
        );
        e
    };
    // The account's check: the password the fake was made with for
    // `admin`, the form for a user it made, nothing for any other.
    let check: Option<PasswordCheck> = if user == "admin" {
        let want = mysql.password.clone().into_bytes();
        Some(Box::new(move |pw: &[u8]| pw == want.as_slice()))
    } else {
        let form = mysql
            .users
            .lock()
            .unwrap()
            .get(&user)
            .filter(|u| !u.locked)
            .map(|u| u.form.clone());
        form.map(|form| {
            Box::new(move |pw: &[u8]| {
                form.len() == 70
                    && form.starts_with("$A$005$")
                    && super::sha_crypt::sha256_crypt(
                        pw,
                        &form.as_bytes()[7..27],
                        super::sha_crypt::MYSQL_ROUNDS,
                    ) == form[27..]
            }) as PasswordCheck
        })
    };
    let Some(check) = check else {
        // As MySQL answers a user it does not hold: a switch, then a refusal.
        let mut switch = vec![0xFE];
        switch.extend(SHA256.as_bytes());
        switch.push(0);
        switch.extend(&nonce);
        switch.push(0);
        write_packet(&mut s, seq, &switch).await?;
        let (got, _) = read_packet(&mut s, 1024).await?;
        write_packet(&mut s, got.wrapping_add(1), &denied(&user)).await?;
        return Ok(());
    };
    // The full sign-in: the password itself, inside the TLS.
    write_packet(&mut s, seq, &[0x01, 0x04]).await?;
    let (got, plain) = read_packet(&mut s, 1024).await?;
    seq = got.wrapping_add(1);
    let plain = plain.strip_suffix(&[0]).unwrap_or(&plain);
    if !check(plain) {
        write_packet(&mut s, seq, &denied(&user)).await?;
        return Ok(());
    }
    write_packet(&mut s, seq, &[0x00, 0, 0, 2, 0, 0, 0]).await?;
    loop {
        let Ok((_, cmd)) = read_packet(&mut s, 1 << 20).await else {
            return Ok(());
        };
        match cmd.first() {
            Some(0x01) => return Ok(()),
            Some(0x03) => {
                let sql = String::from_utf8_lossy(&cmd[1..]).into_owned();
                let _ = tx.send(sql.clone());
                for (i, p) in mysql_answer(&sql, &mysql).iter().enumerate() {
                    write_packet(&mut s, u8::try_from(i + 1).unwrap(), p).await?;
                }
            }
            _ => return Ok(()),
        }
    }
}

/// How the fake MySQL answers one query: the minter's statements, as MySQL
/// answers them, each clause read where it stands; anything else, a syntax
/// error. Packets, in order.
fn mysql_answer(sql: &str, mysql: &MysqlState) -> Vec<Vec<u8>> {
    use std::sync::atomic::Ordering::SeqCst;
    let ok = || vec![vec![0x00, 0, 0, 2, 0, 0, 0]];
    let err = |code: u16, state: &str, msg: &str| {
        let mut e = vec![0xFF];
        e.extend(code.to_le_bytes());
        e.push(b'#');
        e.extend(state.as_bytes());
        e.extend(msg.as_bytes());
        vec![e]
    };
    let rows = |column: &str, values: Vec<String>| {
        let eof = vec![0xFE, 0, 0, 2, 0];
        let mut def = Vec::new();
        for part in ["def", "", "", "", column, ""] {
            def.push(u8::try_from(part.len()).unwrap());
            def.extend(part.as_bytes());
        }
        def.extend([0x0c, 255, 0, 0, 1, 0, 0, 0xFD, 0, 0, 0, 0, 0]);
        let mut out = vec![vec![1], def, eof.clone()];
        for v in values {
            let mut r = vec![u8::try_from(v.len()).unwrap()];
            r.extend(v.as_bytes());
            out.push(r);
        }
        out.push(eof);
        out
    };
    let quoted_after = |marker: &str| between(sql, marker, '\'').map(String::from);
    if sql == LOCAL_FILE_PLEASE {
        let mut p = vec![0xFB];
        p.extend(b"/etc/hostname");
        return vec![p];
    }
    let mut users = mysql.users.lock().unwrap();
    if let Some(name) = quoted_after("CREATE USER '").filter(|_| sql.starts_with("CREATE USER '")) {
        let user = FakeUser {
            form: quoted_after(" AS '").unwrap_or_default(),
            attribute: quoted_after(" ATTRIBUTE '"),
            ..FakeUser::default()
        };
        match users.entry(name) {
            std::collections::btree_map::Entry::Occupied(taken) => err(
                1396,
                "HY000",
                &format!("Operation CREATE USER failed for '{}'@'%'", taken.key()),
            ),
            std::collections::btree_map::Entry::Vacant(free) => {
                free.insert(user);
                ok()
            }
        }
    } else if sql.starts_with("GRANT '") {
        if mysql.refuse.grant.load(SeqCst) {
            return err(
                1227,
                "42000",
                "Access denied; you need (at least one of) the WITH ADMIN OPTION privilege(s) for this operation",
            );
        }
        let role = quoted_after("GRANT '").unwrap_or_default();
        match quoted_after(" TO '").and_then(|t| users.get_mut(&t)) {
            Some(u) => {
                u.grants.push(role);
                ok()
            }
            None => err(3523, "HY000", "Unknown authorization ID"),
        }
    } else if sql.starts_with("SET DEFAULT ROLE ALL TO '") {
        match quoted_after(" TO '").and_then(|t| users.get_mut(&t)) {
            Some(u) => {
                u.default_roles = true;
                ok()
            }
            None => err(3523, "HY000", "Unknown authorization ID"),
        }
    } else if sql.starts_with("CREATE EVENT ") {
        if mysql.refuse.event.load(SeqCst) {
            return err(
                1044,
                "42000",
                "Access denied for user 'admin'@'%' to database 'orders'",
            );
        }
        let name = between(sql, ".`", '`').unwrap_or_default().to_string();
        mysql.events.lock().unwrap().insert(name);
        ok()
    } else if sql
        .starts_with("SELECT USER FROM information_schema.USER_ATTRIBUTES WHERE USER LIKE ")
    {
        // The sweep: a name's prefix (`\_` an underscore), an `until` past
        // (a user with none is never past it).
        let prefix = quoted_after("USER LIKE '")
            .map(|p| p.trim_end_matches('%').replace("\\_", "_"))
            .unwrap_or_default();
        let past = sql.contains("AS UNSIGNED) < UNIX_TIMESTAMP()");
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let until = |a: &Option<String>| {
            a.as_deref()
                .and_then(|a| serde_json::from_str::<serde_json::Value>(a).ok())
                .and_then(|v| v["roomler"]["until"].as_i64())
        };
        let ended = users
            .iter()
            .filter(|(name, u)| {
                name.starts_with(&prefix) && (!past || until(&u.attribute).is_some_and(|t| t < now))
            })
            .map(|(name, _)| name.clone())
            .collect();
        rows("USER", ended)
    } else if let Some(name) = sql
        .strip_prefix("SELECT USER FROM information_schema.USER_ATTRIBUTES WHERE USER = '")
        .and_then(|r| r.strip_suffix('\''))
    {
        rows(
            "USER",
            users
                .contains_key(name)
                .then(|| name.to_string())
                .into_iter()
                .collect(),
        )
    } else if sql.starts_with("ALTER USER '") && sql.ends_with(" ACCOUNT LOCK") {
        match quoted_after("ALTER USER '").and_then(|t| users.get_mut(&t)) {
            Some(u) => {
                u.locked = true;
                ok()
            }
            None => err(1396, "HY000", "Operation ALTER USER failed"),
        }
    } else if let Some(name) = sql
        .strip_prefix("SELECT ID FROM information_schema.PROCESSLIST WHERE USER = '")
        .and_then(|r| r.strip_suffix('\''))
    {
        // One open session for each user it holds, to end.
        rows(
            "ID",
            users
                .contains_key(name)
                .then(|| "17".to_string())
                .into_iter()
                .collect(),
        )
    } else if sql.starts_with("KILL ") {
        if mysql.refuse.kill.load(SeqCst) {
            return err(1095, "HY000", "You are not owner of thread 17");
        }
        ok()
    } else if sql.starts_with("DROP USER IF EXISTS '") {
        if let Some(name) = quoted_after("DROP USER IF EXISTS '") {
            users.remove(&name);
        }
        ok()
    } else if sql.starts_with("DROP EVENT IF EXISTS ") {
        let name = between(sql, ".`", '`').unwrap_or_default().to_string();
        mysql.events.lock().unwrap().remove(&name);
        ok()
    } else {
        err(1064, "42000", "You have an error in your SQL syntax")
    }
}

/// What the proxy sends in the two seconds after a refusal: nothing,
/// when it hangs up as it should.
async fn what_follows<S: AsyncRead + Unpin>(s: &mut S) -> Vec<u8> {
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await {
        if n == 0 {
            break;
        }
        got.extend(&buf[..n]);
    }
    got
}

/// A client's startup message with `params`, protocol 3.0.
pub(crate) fn startup(params: &[(&str, &str)]) -> Vec<u8> {
    let mut body = (3u32 << 16).to_be_bytes().to_vec();
    for (k, v) in params {
        body.extend(k.as_bytes());
        body.push(0);
        body.extend(v.as_bytes());
        body.push(0);
    }
    body.push(0);
    frame(None, &body)
}

/// The next message from `c`, within 10 s.
pub(crate) async fn next<R: AsyncRead + Unpin>(c: &mut R) -> (u8, Vec<u8>) {
    tokio::time::timeout(Duration::from_secs(10), read_message(c, 1 << 20))
        .await
        .expect("an answer within 10 s")
        .expect("a message")
}

// FR-90 P3-5c-1 — a MongoDB upstream, over TLS from its first byte.

/// A TLS listener on a random port of 127.0.0.1, with a certificate for
/// `localhost` made for this test: its CA's PEM, its acceptor, the listener,
/// and its port.
async fn tls_server() -> (String, TlsAcceptor, TcpListener, u16) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let pem = cert.cert.pem();
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into()),
            )
            .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    (pem, TlsAcceptor::from(Arc::new(config)), listener, port)
}

/// How the fake MongoDB upstream behaves.
#[derive(Clone, PartialEq)]
pub(crate) enum MongoUpstreams {
    /// SCRAM-SHA-256 with this password, the empty exchange skipped, then
    /// answering what it is asked.
    Scram(String),
    /// The same, without skipping the empty exchange: a server before 4.4.
    NoSkip(String),
    /// Checks the proof, then signs wrong: a server that never held the
    /// password.
    Forged(String),
}

/// What the fake MongoDB upstream saw, in order.
#[derive(Debug, PartialEq)]
pub(crate) enum MongoSaw {
    /// An `OP_MSG` command: its name and its `$db`.
    Command(String, String),
    /// The user a SCRAM exchange named.
    User(String),
    /// A legacy `OP_QUERY`: its collection, and its command's name.
    Query(String, String),
    /// Whether a handshake carried client metadata.
    Metadata(bool),
}

/// A MongoDB upstream on a random port of 127.0.0.1, TLS from its first
/// byte: its CA's PEM, its port, and what it saw.
pub(crate) async fn fake_mongo(
    how: MongoUpstreams,
) -> (String, u16, mpsc::UnboundedReceiver<MongoSaw>) {
    use base64::Engine;
    use bson::spec::BinarySubtype;
    use bson::{Binary, Bson, doc};

    use super::mongo::{OP_MSG, OP_QUERY, op_msg, op_msg_document, op_reply, read_message};

    let (pem, acceptor, listener, port) = tls_server().await;
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let (acceptor, tx, how) = (acceptor.clone(), tx.clone(), how.clone());
            tokio::spawn(async move {
                // A proxy that refused the certificate hangs up mid-handshake.
                let Ok(mut s) = acceptor.accept(tcp).await else {
                    return;
                };
                let (password, forged, skips) = match &how {
                    MongoUpstreams::Scram(p) => (p.clone(), false, true),
                    MongoUpstreams::NoSkip(p) => (p.clone(), false, false),
                    MongoUpstreams::Forged(p) => (p.clone(), true, true),
                };
                let mut srv = ScramServer::new(&password, b"a-salt", 4096, "upnonce");
                let mut continued = 0;
                let binary = |bytes: Vec<u8>| {
                    Bson::Binary(Binary {
                        subtype: BinarySubtype::Generic,
                        bytes,
                    })
                };
                while let Ok(m) = read_message(&mut s, 1 << 20).await {
                    let answer = match m.op_code {
                        OP_MSG => {
                            let Ok(doc) = op_msg_document(m.body()) else {
                                return;
                            };
                            let name = doc.keys().next().cloned().unwrap_or_default();
                            let db = doc.get_str("$db").unwrap_or("").to_string();
                            let _ = tx.send(MongoSaw::Command(name.clone(), db));
                            if name == "hello" {
                                let _ = tx.send(MongoSaw::Metadata(doc.contains_key("client")));
                            }
                            let payload = || match doc.get("payload") {
                                Some(Bson::Binary(b)) => {
                                    String::from_utf8(b.bytes.clone()).unwrap()
                                }
                                _ => String::new(),
                            };
                            let reply = match name.as_str() {
                                "saslStart" => {
                                    let first = payload();
                                    let user = first
                                        .split(',')
                                        .find_map(|a| a.strip_prefix("n="))
                                        .unwrap_or("")
                                        .to_string();
                                    let _ = tx.send(MongoSaw::User(user));
                                    let server_first = srv.server_first(&first);
                                    doc! {
                                        "conversationId": 1,
                                        "done": false,
                                        "payload": binary(server_first.into_bytes()),
                                        "ok": 1.0,
                                    }
                                }
                                "saslContinue" if continued == 0 => {
                                    continued += 1;
                                    match srv.server_final(&payload()) {
                                        Ok(v) => {
                                            let v = if forged {
                                                // A signature no server holding the
                                                // password would make.
                                                let wrong =
                                                    base64::engine::general_purpose::STANDARD
                                                        .encode([7u8; 32]);
                                                format!("v={wrong}")
                                            } else {
                                                v
                                            };
                                            doc! {
                                                "conversationId": 1,
                                                "done": skips,
                                                "payload": binary(v.into_bytes()),
                                                "ok": 1.0,
                                            }
                                        }
                                        Err(_) => doc! {
                                            "ok": 0.0,
                                            "errmsg": "Authentication failed.",
                                            "code": 18,
                                            "codeName": "AuthenticationFailed",
                                        },
                                    }
                                }
                                "saslContinue" => doc! {
                                    "conversationId": 1,
                                    "done": true,
                                    "payload": binary(Vec::new()),
                                    "ok": 1.0,
                                },
                                "hello" => doc! {
                                    "isWritablePrimary": true,
                                    "maxWireVersion": 21,
                                    "ok": 1.0,
                                },
                                _ => doc! { "ok": 1.0 },
                            };
                            op_msg(0, m.request_id, &reply)
                        }
                        OP_QUERY => {
                            // Flags, the collection's name, two counts, then
                            // the query.
                            let body = m.body();
                            let Some(nul) = body[4..].iter().position(|b| *b == 0) else {
                                return;
                            };
                            let collection =
                                String::from_utf8_lossy(&body[4..4 + nul]).into_owned();
                            let Ok(query) =
                                bson::Document::from_reader(&mut &body[4 + nul + 1 + 8..])
                            else {
                                return;
                            };
                            let name = query.keys().next().cloned().unwrap_or_default();
                            let _ = tx.send(MongoSaw::Query(collection, name));
                            let _ = tx.send(MongoSaw::Metadata(query.contains_key("client")));
                            op_reply(
                                m.request_id,
                                &doc! { "ismaster": true, "maxWireVersion": 21, "ok": 1.0 },
                            )
                        }
                        _ => return,
                    };
                    if s.write_all(&answer).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (pem, port, rx)
}

/// A client's legacy `OP_QUERY`: `query` against `collection`, as a driver
/// sends its first handshake.
pub(crate) fn op_query(request_id: i32, collection: &str, query: &bson::Document) -> Vec<u8> {
    let mut body = 0i32.to_le_bytes().to_vec();
    body.extend(collection.as_bytes());
    body.push(0);
    body.extend(0i32.to_le_bytes());
    body.extend((-1i32).to_le_bytes());
    query
        .to_writer(&mut body)
        .expect("a document writes into memory");
    let len = i32::try_from(16 + body.len()).unwrap();
    let mut out = len.to_le_bytes().to_vec();
    out.extend(request_id.to_le_bytes());
    out.extend(0i32.to_le_bytes());
    out.extend(super::mongo::OP_QUERY.to_le_bytes());
    out.extend(body);
    out
}

/// P3-5c-2 — a client's MongoDB command, as an `OP_MSG`.
pub(crate) fn mongo_command(request_id: i32, body: &bson::Document) -> Vec<u8> {
    super::mongo::op_msg(request_id, 0, body)
}

/// The next MongoDB reply on `r`, within 10 s: its op code, the request it
/// answers, and its document.
pub(crate) async fn mongo_reply<R: AsyncRead + Unpin>(r: &mut R) -> (i32, i32, bson::Document) {
    use super::mongo::{OP_MSG, OP_REPLY, op_msg_document, read_message};
    let m = tokio::time::timeout(Duration::from_secs(10), read_message(r, 1 << 20))
        .await
        .expect("an answer within 10 s")
        .expect("a message");
    let doc = match m.op_code {
        OP_MSG => op_msg_document(m.body()).unwrap(),
        // Flags, a cursor, where it starts, how many: then the document.
        OP_REPLY => bson::Document::from_reader(&mut &m.body()[20..]).unwrap(),
        other => panic!("a reply of op code {other}"),
    };
    (m.op_code, m.response_to, doc)
}

/// P3-5d-1 — one request the fake HTTPS upstream saw.
#[derive(Debug, Clone)]
pub(crate) struct HttpSaw {
    /// Which of the upstream's connections it came on, counted from 0.
    pub(crate) conn: usize,
    pub(crate) method: String,
    /// The request's target, as it came.
    pub(crate) target: String,
    pub(crate) headers: Vec<(String, String)>,
    /// How long its body was.
    pub(crate) body: usize,
}

impl HttpSaw {
    /// Every value of the header `name`, in order.
    pub(crate) fn values(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

/// P3-5d-1 — an HTTPS upstream on a random port of 127.0.0.1, with a
/// certificate for `localhost` made for this test: its CA's PEM, its port,
/// and each request it saw. It answers by path:
///
/// | Path | Answer |
/// |---|---|
/// | `/echo` | the request's body |
/// | `/redirect/here` | a 302 to itself, with a query and a fragment |
/// | `/redirect/case` | a 302 to itself, its scheme and host in capitals |
/// | `/redirect/port` | a 302 to the same host on another port |
/// | `/redirect/user` | a 302 to itself with a user in the authority |
/// | `/redirect/away` | a 302 to another host |
/// | `/headers` | its own hop-by-hop and origin headers, and one to keep |
/// | `/close` | `Connection: close`: the connection ends after it |
/// | anything else | `ok` |
pub(crate) async fn fake_http() -> (String, u16, mpsc::UnboundedReceiver<HttpSaw>) {
    let (pem, acceptor, listener, port) = tls_server().await;
    (pem, port, run_http(acceptor, listener, port))
}

/// The fake HTTPS upstream's answers, on `listener`, through `acceptor`. A
/// request for `/exec` that asks to upgrade is switched (`101`), and every
/// byte sent after is echoed (P3-5e-1).
fn run_http(
    acceptor: TlsAcceptor,
    listener: TcpListener,
    port: u16,
) -> mpsc::UnboundedReceiver<HttpSaw> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::body::Incoming;
    use hyper::{Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;

    let (tx, rx) = mpsc::unbounded_channel();
    let conns = Arc::new(AtomicUsize::new(0));
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let (acceptor, tx) = (acceptor.clone(), tx.clone());
            let conn = conns.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                // A proxy that refused the certificate hangs up mid-handshake.
                let Ok(s) = acceptor.accept(tcp).await else {
                    return;
                };
                let service = hyper::service::service_fn(move |mut req: Request<Incoming>| {
                    let tx = tx.clone();
                    // P3-5e-1 — an exec stream asked for: switch, then echo.
                    let upgrade = (req.uri().path() == "/exec")
                        .then(|| req.headers().get("upgrade").cloned())
                        .flatten();
                    let on = upgrade.is_some().then(|| hyper::upgrade::on(&mut req));
                    async move {
                        let (parts, body) = req.into_parts();
                        let body = body
                            .collect()
                            .await
                            .map(|b| b.to_bytes())
                            .unwrap_or_default();
                        let _ = tx.send(HttpSaw {
                            conn,
                            method: parts.method.to_string(),
                            target: parts.uri.to_string(),
                            headers: parts
                                .headers
                                .iter()
                                .map(|(n, v)| {
                                    let v = String::from_utf8_lossy(v.as_bytes()).into_owned();
                                    (n.as_str().to_string(), v)
                                })
                                .collect(),
                            body: body.len(),
                        });
                        let mut resp = Response::new(Full::new(Bytes::from_static(b"ok")));
                        let redirect = |resp: &mut Response<Full<Bytes>>, to: String| {
                            *resp.status_mut() = StatusCode::FOUND;
                            resp.headers_mut().insert("location", to.parse().unwrap());
                        };
                        let other = if port == 444 { 445 } else { 444 };
                        match parts.uri.path() {
                            "/echo" => *resp.body_mut() = Full::new(body),
                            "/redirect/here" => redirect(
                                &mut resp,
                                format!("https://localhost:{port}/landed?x=1#top"),
                            ),
                            "/redirect/case" => {
                                redirect(&mut resp, format!("HTTPS://LOCALHOST:{port}/case"))
                            }
                            "/redirect/port" => {
                                redirect(&mut resp, format!("https://localhost:{other}/x"))
                            }
                            "/redirect/user" => {
                                redirect(&mut resp, format!("https://someone@localhost:{port}/x"))
                            }
                            "/redirect/away" => {
                                redirect(&mut resp, "https://elsewhere.test/x".to_string())
                            }
                            "/headers" => {
                                let h = resp.headers_mut();
                                h.insert("alt-svc", "h3=\":443\"".parse().unwrap());
                                h.insert(
                                    "strict-transport-security",
                                    "max-age=60".parse().unwrap(),
                                );
                                h.insert("connection", "x-upstream-hop".parse().unwrap());
                                h.insert("x-upstream-hop", "1".parse().unwrap());
                                h.insert("x-kept", "yes".parse().unwrap());
                            }
                            "/close" => {
                                resp.headers_mut()
                                    .insert("connection", "close".parse().unwrap());
                            }
                            // P3-5d-2 — a git server's advertisement of one
                            // repository's refs (smart HTTP, protocol v0).
                            "/org/repo.git/info/refs" => {
                                let pkt = |s: &str| format!("{:04x}{s}", s.len() + 4);
                                let sha = "1".repeat(40);
                                let refs = format!(
                                    "{}0000{}{}0000",
                                    pkt("# service=git-upload-pack\n"),
                                    pkt(&format!(
                                        "{sha} HEAD\0symref=HEAD:refs/heads/main agent=git/fake\n"
                                    )),
                                    pkt(&format!("{sha} refs/heads/main\n")),
                                );
                                *resp.body_mut() = Full::new(Bytes::from(refs));
                                resp.headers_mut().insert(
                                    "content-type",
                                    "application/x-git-upload-pack-advertisement"
                                        .parse()
                                        .unwrap(),
                                );
                            }
                            _ => {}
                        }
                        if let (Some(protocol), Some(on)) = (upgrade, on) {
                            *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                            *resp.body_mut() = Full::new(Bytes::new());
                            resp.headers_mut().insert("upgrade", protocol);
                            resp.headers_mut()
                                .insert("connection", "Upgrade".parse().unwrap());
                            tokio::spawn(async move {
                                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                                let Ok(switched) = on.await else {
                                    return;
                                };
                                let mut io = TokioIo::new(switched);
                                let mut buf = [0u8; 4096];
                                while let Ok(n) = io.read(&mut buf).await {
                                    if n == 0 || io.write_all(&buf[..n]).await.is_err() {
                                        return;
                                    }
                                }
                            });
                        }
                        Ok::<_, std::convert::Infallible>(resp)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(s), service)
                    .with_upgrades()
                    .await;
            });
        }
    });
    rx
}

/// P3-5e-1 — an upstream that asks for a client certificate, as a
/// Kubernetes API server does: what it answers is the fake HTTPS
/// upstream's, and a connection that presents no certificate its client CA
/// made is refused in the handshake.
pub(crate) struct FakeMtls {
    /// The upstream's own CA, PEM.
    pub(crate) ca: String,
    pub(crate) port: u16,
    pub(crate) saw: mpsc::UnboundedReceiver<HttpSaw>,
    /// A client certificate its CA made, and its key: PEM, made for this
    /// test.
    pub(crate) cert: String,
    pub(crate) key: String,
}

pub(crate) async fn fake_http_mtls() -> FakeMtls {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    use tokio_rustls::rustls::RootCertStore;
    use tokio_rustls::rustls::server::WebPkiClientVerifier;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let issuer_key = KeyPair::generate().unwrap();
    let mut issuer = CertificateParams::new(Vec::<String>::new()).unwrap();
    issuer.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let issuer = issuer.self_signed(&issuer_key).unwrap();
    let client_key = KeyPair::generate().unwrap();
    let client = CertificateParams::new(vec!["hive-session".to_string()])
        .unwrap()
        .signed_by(&client_key, &issuer, &issuer_key)
        .unwrap();
    let mut client_roots = RootCertStore::empty();
    client_roots.add(issuer.der().clone()).unwrap();
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), Arc::clone(&provider))
            .build()
            .unwrap();
    let own = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![own.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(own.key_pair.serialize_der().into()),
        )
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let saw = run_http(TlsAcceptor::from(Arc::new(config)), listener, port);
    FakeMtls {
        ca: own.cert.pem(),
        port,
        saw,
        cert: client.pem(),
        key: client_key.serialize_pem(),
    }
}

/// P3-5d-1 — a CA's PEM that vouches for no upstream a test runs.
pub(crate) fn stranger() -> String {
    rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .unwrap()
        .cert
        .pem()
}

/// P3-5f — SSH strings, one after another (RFC 4251 §5).
pub(crate) fn strings(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        put_string(&mut out, part);
    }
    out
}

/// P3-5f — a PEM block: `raw` under `label`, in lines of 70 as `ssh-keygen`
/// writes. The armor is made here, so no whole header is ever written out.
pub(crate) fn armor(label: &str, raw: &[u8]) -> String {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for line in encoded.as_bytes().chunks(70) {
        pem.push_str(std::str::from_utf8(line).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

/// P3-5f — an OpenSSH private key file, laid out as `PROTOCOL.key` lays one
/// out, each part one a test may make wrong.
pub(crate) struct KeyFile {
    pub(crate) cipher: &'static str,
    pub(crate) kdf: &'static str,
    pub(crate) keys: u32,
    pub(crate) public: Vec<u8>,
    pub(crate) checks: (u32, u32),
    pub(crate) private: Vec<u8>,
    pub(crate) padding: Option<Vec<u8>>,
}

impl KeyFile {
    /// A key file as `ssh-keygen` writes one: unencrypted, one key.
    pub(crate) fn new(public: Vec<u8>, private: Vec<u8>) -> Self {
        let check = rand::random::<u32>();
        Self {
            cipher: "none",
            kdf: "none",
            keys: 1,
            public,
            checks: (check, check),
            private,
            padding: None,
        }
    }

    pub(crate) fn pem(&self) -> String {
        let mut list = Vec::new();
        put_u32(&mut list, self.checks.0);
        put_u32(&mut list, self.checks.1);
        list.extend_from_slice(&self.private);
        put_string(&mut list, b"made for the test");
        match &self.padding {
            Some(padding) => list.extend_from_slice(padding),
            None => {
                let mut i = 1u8;
                while list.len() % 8 != 0 {
                    list.push(i);
                    i += 1;
                }
            }
        }
        let mut body = MAGIC.to_vec();
        put_string(&mut body, self.cipher.as_bytes());
        put_string(&mut body, self.kdf.as_bytes());
        put_string(&mut body, b"");
        put_u32(&mut body, self.keys);
        put_string(&mut body, &self.public);
        put_string(&mut body, &list);
        armor(LABEL, &body)
    }
}

/// P3-5f-2 — an Ed25519 key made for the test, as a secret's `key` holds
/// one, and its public half as SSH writes it.
pub(crate) fn openssh_key() -> (String, Vec<u8>) {
    use ring::signature::KeyPair as _;
    let seed: [u8; 32] = rand::random();
    let pk = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed)
        .unwrap()
        .public_key()
        .as_ref()
        .to_vec();
    let public = strings(&[b"ssh-ed25519", &pk]);
    let private = strings(&[b"ssh-ed25519", &pk, &[&seed[..], &pk[..]].concat()]);
    (KeyFile::new(public.clone(), private).pem(), public)
}

/// P3-5f — whether `program` runs here. Under CI it must: a test that
/// stopped there would pass having proven nothing.
pub(crate) fn present(program: &str) -> bool {
    let runs = std::process::Command::new(program)
        .arg("-?")
        .output()
        .is_ok();
    if !runs {
        assert!(
            std::env::var_os("CI").is_none(),
            "{program} is not on this CI runner"
        );
        eprintln!("{program} is not on this system: the test stops here");
    }
    runs
}

/// P3-5f — an SSH host for the tests (russh): it lets `git` in with one key,
/// and answers any command with exit status 0.
#[cfg(feature = "ssh-server")]
pub(crate) struct Sshd {
    allowed: russh::keys::ssh_key::PublicKey,
}

#[cfg(feature = "ssh-server")]
impl russh::server::Handler for Sshd {
    type Error = russh::Error;

    // russh calls this once it has checked the sign-in's signature.
    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<russh::server::Auth, Self::Error> {
        Ok(
            if user == "git" && key.key_data() == self.allowed.key_data() {
                russh::server::Auth::Accept
            } else {
                russh::server::Auth::reject()
            },
        )
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<russh::server::Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: russh::ChannelId,
        _data: &[u8],
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

/// P3-5f — serve [`Sshd`] on a loopback port, with `host_key`: the port.
#[cfg(feature = "ssh-server")]
pub(crate) async fn sshd(
    host_key: russh::keys::ssh_key::PrivateKey,
    allowed: russh::keys::ssh_key::PublicKey,
) -> u16 {
    let config = Arc::new(russh::server::Config {
        keys: vec![host_key],
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..Default::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (config, allowed) = (config.clone(), allowed.clone());
            tokio::spawn(async move {
                if let Ok(session) =
                    russh::server::run_stream(config, stream, Sshd { allowed }).await
                {
                    let _ = session.await;
                }
            });
        }
    });
    port
}

/// P3-5f — OpenSSH's own `ssh` to `git@127.0.0.1:<port>`, `agent` its
/// agent's socket, checking the host by `known_hosts` alone. `-v`, so its
/// log says whether it bound the agent.
#[cfg(all(unix, feature = "ssh-server"))]
pub(crate) async fn run_ssh(
    agent: &std::path::Path,
    port: u16,
    known_hosts: &std::path::Path,
) -> std::process::Output {
    let ssh = tokio::process::Command::new("ssh")
        .args([
            "-v",
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
        ])
        .args([
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "PreferredAuthentications=publickey",
        ])
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", known_hosts.display()))
        .arg("-o")
        .arg(format!("IdentityAgent={}", agent.display()))
        .args(["-p", &port.to_string(), "git@127.0.0.1", "true"])
        .env_remove("SSH_AUTH_SOCK")
        .output();
    tokio::time::timeout(Duration::from_secs(30), ssh)
        .await
        .expect("ssh within 30 s")
        .unwrap()
}

/// P3-5f-3 — Windows' own `ssh.exe`, Win32-OpenSSH in System32 (9.5 on this
/// machine and on GitHub's runners): the `ssh` a Windows session has.
#[cfg(all(windows, feature = "ssh-server"))]
pub(crate) const WIN32_SSH: &str = r"C:\Windows\System32\OpenSSH\ssh.exe";

/// P3-5f-3 — [`WIN32_SSH`] to `git@127.0.0.1:<port>`, `agent` its agent's
/// pipe in `SSH_AUTH_SOCK`, checking the host by `known_hosts` alone, with
/// `empty` (an empty file) for its configuration. Paths go with forward
/// slashes, which Win32-OpenSSH takes and its option parser cannot misread as
/// escapes. `-v`, so its log says whether it bound the agent.
#[cfg(all(windows, feature = "ssh-server"))]
pub(crate) async fn run_win32_ssh(
    agent: &str,
    port: u16,
    known_hosts: &std::path::Path,
    empty: &std::path::Path,
) -> std::process::Output {
    let slashed = |p: &std::path::Path| p.display().to_string().replace('\\', "/");
    let ssh = tokio::process::Command::new(WIN32_SSH)
        .arg("-v")
        .arg("-F")
        .arg(slashed(empty))
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "PreferredAuthentications=publickey",
        ])
        .arg("-o")
        .arg(format!("GlobalKnownHostsFile={}", slashed(empty)))
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", slashed(known_hosts)))
        .args(["-p", &port.to_string(), "git@127.0.0.1", "true"])
        .env("SSH_AUTH_SOCK", agent)
        .output();
    tokio::time::timeout(Duration::from_secs(30), ssh)
        .await
        .expect("ssh.exe within 30 s")
        .unwrap()
}

/// P3-5f-2 — an SSH host made for the test: its key pair, its key as SSH
/// writes it, and its line as a secret's `host_keys` names it,
/// `ssh-ed25519 <base64>`.
pub(crate) fn ssh_host() -> (ring::signature::Ed25519KeyPair, Vec<u8>, String) {
    use base64::Engine as _;
    use ring::signature::KeyPair as _;
    let seed: [u8; 32] = rand::random();
    let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let key = strings(&[b"ssh-ed25519", pair.public_key().as_ref()]);
    let line = format!(
        "ssh-ed25519 {}",
        base64::engine::general_purpose::STANDARD.encode(&key)
    );
    (pair, key, line)
}

/// P3-5f-2 — an SSH host's key line made for the test, its pair let go.
pub(crate) fn ssh_host_line() -> String {
    ssh_host().2
}

/// P3-6f-1 — a Secret the fake API server holds.
#[derive(Debug, Clone)]
pub(crate) struct FakeSecret {
    pub(crate) uid: String,
    pub(crate) labels: serde_json::Value,
    pub(crate) annotations: serde_json::Value,
}

/// P3-6f-1 — one request the fake API server saw.
#[derive(Debug, Clone)]
pub(crate) struct K8sSaw {
    pub(crate) method: String,
    /// The request's target, as it came: its path and its query.
    pub(crate) target: String,
    pub(crate) authorization: Option<String>,
    /// Its body, as JSON; `Null` where it had none.
    pub(crate) body: serde_json::Value,
}

/// P3-6f-1 — what the fake API server holds, and how it answers.
#[derive(Default)]
pub(crate) struct K8sState {
    pub(crate) secrets: std::collections::BTreeMap<String, FakeSecret>,
    pub(crate) saw: Vec<K8sSaw>,
    /// Refuse the `TokenRequest` with this status and message.
    pub(crate) refuse_token: Option<(u16, String)>,
    /// Refuse to list Secrets, as for an issuer RBAC gives no `list`.
    pub(crate) refuse_list: bool,
    next: u64,
}

impl K8sState {
    /// A Secret the fake holds, made by the test, as an earlier mint or
    /// someone else would have left it.
    pub(crate) fn put(
        &mut self,
        name: &str,
        labels: serde_json::Value,
        annotations: serde_json::Value,
    ) -> String {
        self.next += 1;
        let uid = format!("uid-{}", self.next);
        self.secrets.insert(
            name.to_string(),
            FakeSecret {
                uid: uid.clone(),
                labels,
                annotations,
            },
        );
        uid
    }
}

/// P3-6f-1 — a fake Kubernetes API server on a random port of 127.0.0.1,
/// over TLS with a certificate for `localhost` made for the test, and (with
/// `mtls`) asking every client for a certificate its own client CA made.
pub(crate) struct FakeK8s {
    /// Its CA, PEM.
    pub(crate) ca: String,
    pub(crate) port: u16,
    pub(crate) state: Arc<std::sync::Mutex<K8sState>>,
    /// With `mtls`, a client certificate its client CA made, and its key.
    pub(crate) client: Option<(String, String)>,
}

impl FakeK8s {
    pub(crate) fn origin(&self) -> String {
        format!("https://localhost:{}", self.port)
    }

    pub(crate) fn state(&self) -> std::sync::MutexGuard<'_, K8sState> {
        self.state.lock().unwrap()
    }
}

/// P3-6f-1 — the fake answers what a Kubernetes issuer's minter asks of an
/// API server, by path:
///
/// | Request | Answer |
/// |---|---|
/// | `POST …/namespaces/<ns>/secrets` | the Secret held, with a uid of its own; 409 where one has its name |
/// | `POST …/serviceaccounts/<sa>/token` | a token, where its `boundObjectRef` names a Secret held, by name and uid; else 400 |
/// | `DELETE …/secrets/<name>` | 404 where none is held; 409 where its uid is not the precondition's; else deleted |
/// | `GET …/secrets?labelSelector=…` | the Secrets that carry the label (403 with `refuse_list`) |
pub(crate) async fn fake_k8s(mtls: bool) -> FakeK8s {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    use tokio_rustls::rustls::RootCertStore;
    use tokio_rustls::rustls::server::WebPkiClientVerifier;

    let state = Arc::new(std::sync::Mutex::new(K8sState::default()));
    let (ca, acceptor, listener, port, client) = if mtls {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let issuer_key = KeyPair::generate().unwrap();
        let mut issuer = CertificateParams::new(Vec::<String>::new()).unwrap();
        issuer.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let issuer = issuer.self_signed(&issuer_key).unwrap();
        let client_key = KeyPair::generate().unwrap();
        let client = CertificateParams::new(vec!["vault-issuer".to_string()])
            .unwrap()
            .signed_by(&client_key, &issuer, &issuer_key)
            .unwrap();
        let mut client_roots = RootCertStore::empty();
        client_roots.add(issuer.der().clone()).unwrap();
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(client_roots),
            Arc::clone(&provider),
        )
        .build()
        .unwrap();
        let own = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![own.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(own.key_pair.serialize_der().into()),
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        (
            own.cert.pem(),
            TlsAcceptor::from(Arc::new(config)),
            listener,
            port,
            Some((client.pem(), client_key.serialize_pem())),
        )
    } else {
        let (pem, acceptor, listener, port) = tls_server().await;
        (pem, acceptor, listener, port, None)
    };
    run_k8s(acceptor, listener, Arc::clone(&state));
    FakeK8s {
        ca,
        port,
        state,
        client,
    }
}

fn run_k8s(acceptor: TlsAcceptor, listener: TcpListener, state: Arc<std::sync::Mutex<K8sState>>) {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::body::Incoming;
    use hyper::{Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use serde_json::{Value, json};

    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let (acceptor, state) = (acceptor.clone(), Arc::clone(&state));
            tokio::spawn(async move {
                let Ok(s) = acceptor.accept(tcp).await else {
                    return;
                };
                let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let state = Arc::clone(&state);
                    async move {
                        let (parts, body) = req.into_parts();
                        let body = body
                            .collect()
                            .await
                            .map(|b| b.to_bytes())
                            .unwrap_or_default();
                        let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                        let target = parts.uri.to_string();
                        let path = parts.uri.path().to_string();
                        let mut st = state.lock().unwrap();
                        st.saw.push(K8sSaw {
                            method: parts.method.to_string(),
                            target: target.clone(),
                            authorization: parts
                                .headers
                                .get("authorization")
                                .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned()),
                            body: body.clone(),
                        });
                        let status_of = |code: u16, message: &str| {
                            (code, json!({"kind": "Status", "message": message}))
                        };
                        let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
                        let (code, answer) = match (parts.method.as_str(), segments.as_slice()) {
                            ("POST", ["api", "v1", "namespaces", _, "secrets"]) => {
                                let name = body["metadata"]["name"].as_str().unwrap_or_default();
                                if name.is_empty() || st.secrets.contains_key(name) {
                                    status_of(409, "secrets already exists")
                                } else {
                                    let (labels, annotations) = (
                                        body["metadata"]["labels"].clone(),
                                        body["metadata"]["annotations"].clone(),
                                    );
                                    let uid = st.put(name, labels, annotations);
                                    (201, json!({"metadata": {"name": name, "uid": uid}}))
                                }
                            }
                            (
                                "POST",
                                ["api", "v1", "namespaces", _, "serviceaccounts", sa, "token"],
                            ) => {
                                let bound = &body["spec"]["boundObjectRef"];
                                let held = bound["name"]
                                    .as_str()
                                    .and_then(|n| st.secrets.get(n))
                                    .is_some_and(|s| bound["uid"].as_str() == Some(s.uid.as_str()));
                                if let Some((code, message)) = st.refuse_token.clone() {
                                    status_of(code, &message)
                                } else if bound["kind"] != "Secret" || !held {
                                    status_of(400, "the bound object is not held")
                                } else {
                                    let token =
                                        ["minted", *sa, bound["name"].as_str().unwrap()].join(".");
                                    (201, json!({"status": {"token": token}}))
                                }
                            }
                            ("DELETE", ["api", "v1", "namespaces", _, "secrets", name]) => {
                                let want = body["preconditions"]["uid"].as_str().map(String::from);
                                match st.secrets.get(*name).map(|s| s.uid.clone()) {
                                    None => status_of(404, "secrets not found"),
                                    Some(uid) if Some(uid.as_str()) != want.as_deref() => {
                                        status_of(409, "the precondition's uid is not the object's")
                                    }
                                    Some(_) => {
                                        st.secrets.remove(*name);
                                        (200, json!({"kind": "Status", "status": "Success"}))
                                    }
                                }
                            }
                            ("GET", ["api", "v1", "namespaces", _, "secrets"]) => {
                                if st.refuse_list {
                                    status_of(403, "secrets is forbidden: cannot list")
                                } else {
                                    let items: Vec<Value> = st
                                        .secrets
                                        .iter()
                                        .filter(|(_, s)| s.labels.get("roomler.ai/lease").is_some())
                                        .map(|(name, s)| {
                                            json!({"metadata": {
                                                "name": name,
                                                "uid": s.uid,
                                                "labels": s.labels,
                                                "annotations": s.annotations,
                                            }})
                                        })
                                        .collect();
                                    (200, json!({"items": items}))
                                }
                            }
                            _ => status_of(404, "the fake answers no such request"),
                        };
                        drop(st);
                        let mut resp = Response::new(Full::new(Bytes::from(answer.to_string())));
                        *resp.status_mut() = StatusCode::from_u16(code).unwrap();
                        Ok::<_, std::convert::Infallible>(resp)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(s), service)
                    .await;
            });
        }
    });
}
