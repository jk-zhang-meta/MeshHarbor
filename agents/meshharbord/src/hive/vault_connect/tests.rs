// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! `vault_connect`'s checks. The endpoint itself is driven through the
//! toolbelt (`toolbelt/tests.rs`), against a Postgres upstream over real TLS.

use serde_json::json;

use super::*;

#[test]
fn an_upstream_is_a_host_and_a_port_as_an_audience_names_them() {
    for (raw, host, port) in [
        ("db.internal:5432", "db.internal", 5432),
        ("10.0.0.5:6432", "10.0.0.5", 6432),
        ("[fd00::5]:5432", "fd00::5", 5432),
        ("pg-1.example.com:65535", "pg-1.example.com", 65535),
        ("orders_db:5432", "orders_db", 5432),
    ] {
        assert_eq!(
            upstream_of(raw),
            Ok((host.to_string(), port)),
            "{raw} is an upstream"
        );
        #[cfg(unix)]
        assert!(
            crate::vault_proxy::tls::server_name(host).is_ok(),
            "{host} is a name TLS verifies"
        );
    }
    for bad in [
        "db.internal",
        "db.internal:",
        ":5432",
        "db.internal:0",
        "db.internal:65536",
        // One spelling per port: no sign, no leading zero.
        "db.internal:+5432",
        "db.internal:05432",
        // An IPv6 address is bracketed, and an address at all.
        "fd00::5:5432",
        "[fd00::zz]:5432",
        "[fe80::1%eth0]:5432",
        "-db:5432",
        ".db:5432",
        "db internal:5432",
        "db/x:5432",
        &format!("{}:5432", "a".repeat(254)),
        &format!("{}.internal:5432", "a".repeat(260)),
    ] {
        assert!(upstream_of(bad).is_err(), "{bad} is not an upstream");
    }
}

#[test]
fn a_call_names_a_secret_an_engine_and_an_upstream() {
    let req = parse(&json!({
        "handle": "db/main",
        "engine": "postgres",
        "upstream": "db.internal:5432",
    }))
    .unwrap();
    assert_eq!(
        req,
        ConnectRequest {
            secret: "db/main".into(),
            engine: Engine::Postgres,
            upstream: "db.internal:5432".into(),
            host: "db.internal".into(),
            port: 5432,
            database: None,
            ca: None,
            auth_source: None,
            auth: None,
            user: None,
            ttl: DEFAULT_TTL,
        }
    );
    let field = |s: &str, f: &str| Handle {
        secret: s.into(),
        field: f.into(),
    };
    assert_eq!(
        req.handles(),
        [field("db/main", "user"), field("db/main", "password")],
        "the endpoint signs in with the secret's user and password"
    );
    let full = parse(&json!({
        "handle": "rrn:grox:secret:db/main",
        "engine": "postgres",
        "upstream": "[fd00::5]:5432",
        "database": "orders",
        "ca": "pki/db-ca#pem",
        "ttl_s": 900,
    }))
    .unwrap();
    assert_eq!(full.database.as_deref(), Some("orders"));
    assert_eq!(full.ttl, 900);
    assert_eq!(
        full.handles(),
        [
            field("rrn:grox:secret:db/main", "user"),
            field("rrn:grox:secret:db/main", "password"),
            field("pki/db-ca", "pem"),
        ],
        "and the CA's value, where the call names one"
    );
    // P3-5c-2 — MongoDB, its auth database `admin` unless the call names one.
    let mongo = parse(&json!({
        "handle": "db/docs",
        "engine": "mongodb",
        "upstream": "mongo.internal:27017",
    }))
    .unwrap();
    assert_eq!(
        (mongo.engine, mongo.auth_source.as_deref()),
        (Engine::Mongodb, Some("admin"))
    );
    let named = parse(&json!({
        "handle": "db/docs",
        "engine": "mongodb",
        "upstream": "mongo.internal:27017",
        "auth_source": "users",
    }))
    .unwrap();
    assert_eq!(named.auth_source.as_deref(), Some("users"));
}

#[test]
fn a_call_no_endpoint_could_serve_is_refused() {
    let ok = json!({"handle": "db/main", "engine": "postgres", "upstream": "db.internal:5432"});
    let with = |k: &str, v: serde_json::Value| {
        let mut call = ok.clone();
        call[k] = v;
        call
    };
    for bad in [
        json!({"engine": "postgres", "upstream": "db.internal:5432"}),
        // The secret itself: the endpoint leases its fields.
        with("handle", json!("db/main#password")),
        with("handle", json!("")),
        with("engine", json!("mysql")),
        json!({"handle": "db/main", "upstream": "db.internal:5432"}),
        json!({"handle": "db/main", "engine": "postgres"}),
        with("upstream", json!("db.internal")),
        with("database", json!("")),
        with("database", json!("x".repeat(MAX_DATABASE + 1))),
        with("database", json!("a\nb")),
        with("database", json!(5)),
        with("ca", json!(true)),
        with("ca", json!("")),
        with("ttl_s", json!(29)),
        with("ttl_s", json!(901)),
        // P3-5c-2 — an auth database is MongoDB's, and a database's name.
        with("auth_source", json!("admin")),
        json!({"handle": "db/main", "engine": "mongodb", "upstream": "m:27017", "auth_source": "a/b"}),
        json!({"handle": "db/main", "engine": "mongodb", "upstream": "m:27017", "auth_source": ""}),
        json!({"handle": "db/main", "engine": "mongodb", "upstream": "m:27017", "auth_source": "x".repeat(64)}),
        json!({"handle": "db/main", "engine": "mongodb", "upstream": "m:27017", "auth_source": 7}),
    ] {
        assert!(parse(&bad).is_err(), "{bad}");
    }
}

/// P3-5d-2 — an HTTP upstream is an origin: `https`, a host, a port only
/// where it is not 443, and nothing after it. One spelling per origin.
#[test]
fn an_http_upstream_is_an_origin_as_an_audience_names_it() {
    for (raw, host, port) in [
        ("https://github.com", "github.com", 443),
        ("https://git.example:8443", "git.example", 8443),
        ("https://10.0.0.5:9443", "10.0.0.5", 9443),
        ("https://[fd00::5]", "fd00::5", 443),
        ("https://[fd00::5]:8443", "fd00::5", 8443),
    ] {
        assert_eq!(
            origin_of(raw),
            Ok((host.to_string(), port)),
            "{raw} is an origin"
        );
    }
    for bad in [
        // TLS always, spelled one way.
        "http://github.com",
        "HTTPS://github.com",
        "github.com",
        "github.com:443",
        // An origin, and nothing after it.
        "https://github.com/",
        "https://github.com/org/repo",
        "https://github.com?x=1",
        "https://github.com#top",
        "https://someone@github.com",
        // Its port only where it is not 443, written plainly.
        "https://github.com:443",
        "https://[fd00::5]:443",
        "https://github.com:0443",
        "https://github.com:0",
        "https://github.com:",
        "https://",
        // An IPv6 address in brackets.
        "https://fd00::5",
        &format!("https://{}.example", "a".repeat(260)),
    ] {
        assert!(origin_of(bad).is_err(), "{bad} is not an origin");
    }
    assert!(
        origin_of("https://github.com:443")
            .unwrap_err()
            .contains("write https://github.com"),
        "port 443 is left out, and the answer says how"
    );
}

/// P3-5d-2 — an `http` call names an origin and how the value is
/// presented; a database's fields are refused in it, and its own in a
/// database's call.
#[test]
fn an_http_call_names_an_origin_and_how_the_value_goes() {
    let field = |f: &str| Handle {
        secret: "git/bot".into(),
        field: f.into(),
    };
    let basic = parse(&json!({
        "handle": "git/bot",
        "engine": "http",
        "upstream": "https://github.com",
        "auth": "basic",
    }))
    .unwrap();
    assert_eq!(
        (
            basic.engine,
            basic.auth,
            basic.host.as_str(),
            basic.port,
            basic.upstream.as_str()
        ),
        (
            Engine::Http,
            Some(Auth::Basic),
            "github.com",
            443,
            "https://github.com"
        )
    );
    assert_eq!(basic.handles(), [field("user"), field("password")]);
    assert_eq!((basic.database, basic.auth_source), (None, None));
    let bearer = parse(&json!({
        "handle": "git/bot",
        "engine": "http",
        "upstream": "https://git.example:8443",
        "auth": "bearer",
        "ca": "pki/git-ca",
    }))
    .unwrap();
    assert_eq!(bearer.auth, Some(Auth::Bearer));
    assert_eq!(
        bearer.handles(),
        [
            field("token"),
            Handle {
                secret: "pki/git-ca".into(),
                field: String::new(),
            }
        ],
        "a token, then the CA"
    );
    let ok = json!({"handle": "git/bot", "engine": "http", "upstream": "https://github.com", "auth": "bearer"});
    let with = |k: &str, v: serde_json::Value| {
        let mut call = ok.clone();
        call[k] = v;
        call
    };
    for bad in [
        json!({"handle": "git/bot", "engine": "http", "upstream": "https://github.com"}),
        with("auth", json!("digest")),
        with("auth", json!("x-api-key")),
        with("auth", json!(true)),
        with("upstream", json!("github.com:443")),
        with("database", json!("orders")),
        with("auth_source", json!("admin")),
        json!({"handle": "db/main", "engine": "postgres", "upstream": "db.internal:5432", "auth": "basic"}),
        json!({"handle": "db/main", "engine": "postgres", "upstream": "https://db.internal"}),
        json!({"handle": "db/docs", "engine": "mongodb", "upstream": "m:27017", "auth": "bearer"}),
    ] {
        assert!(parse(&bad).is_err(), "{bad}");
    }
}

/// P3-5d-2 — a row's end, as Linux writes it: native words of an address
/// held in network order, and an IPv4 address mapped into IPv6 read as
/// IPv4.
#[cfg(target_os = "linux")]
#[test]
fn a_rows_end_reads_as_the_kernel_writes_it() {
    use std::net::{Ipv4Addr, SocketAddrV4};
    let word = |b: [u8; 4]| format!("{:08X}", u32::from_ne_bytes(b));
    let v4 = format!("{}:1F90", word([127, 0, 0, 1]));
    assert_eq!(
        proc_net::end(&v4),
        Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080))
    );
    let mapped = format!(
        "{}{}{}{}:0050",
        word([0; 4]),
        word([0; 4]),
        word([0, 0, 0xff, 0xff]),
        word([10, 0, 0, 5])
    );
    assert_eq!(
        proc_net::end(&mapped),
        Some(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 80))
    );
    let v6 = format!(
        "{}{}{}{}:0050",
        word([0xfd, 0, 0, 0]),
        word([0; 4]),
        word([0; 4]),
        word([0, 0, 0, 5])
    );
    assert_eq!(proc_net::end(&v6), None, "an IPv6 end is not one of ours");
    for bad in [
        "",
        "0100007F",
        "0100007F:",
        "0100007G:0050",
        "01007F:0050",
        "0100007F:10000",
    ] {
        assert_eq!(proc_net::end(bad), None, "{bad:?}");
    }
}

/// P3-5d-2 — the kernel names the account that owns a loopback
/// connection's client end, and nothing for a pair no connection is.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_loopback_connection_is_owned_by_whoever_opened_it() {
    use std::net::SocketAddr;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (accepted, _) = listener.accept().await.unwrap();
    let (SocketAddr::V4(from), SocketAddr::V4(to)) = (
        accepted.peer_addr().unwrap(),
        accepted.local_addr().unwrap(),
    ) else {
        panic!("IPv4 loopback");
    };
    // SAFETY: geteuid reads our own credentials.
    let me = unsafe { libc::geteuid() };
    assert_eq!(proc_net::owner(from, to), Some(me));
    let other = std::net::SocketAddrV4::new(*to.ip(), to.port().wrapping_add(1));
    assert_eq!(proc_net::owner(from, other), None, "no such connection");
    drop(client);
}

/// P3-5d-3 — macOS: a live loopback connection's client end is held by this
/// test's own process, and by processes of its uid alone. For another uid it
/// is not, since a process of this one holds it; and a pair no connection
/// is, nobody holds.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn a_loopback_connection_is_held_by_the_account_that_made_it() {
    use std::net::SocketAddr;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (accepted, _) = listener.accept().await.unwrap();
    let (SocketAddr::V4(from), SocketAddr::V4(to)) = (
        accepted.peer_addr().unwrap(),
        accepted.local_addr().unwrap(),
    ) else {
        panic!("IPv4 loopback");
    };
    // SAFETY: geteuid reads our own credentials.
    let me = unsafe { libc::geteuid() };
    let mine = libproc::ends_of(i32::try_from(std::process::id()).unwrap());
    assert!(
        libproc::held_by(from, to, me),
        "the test's own connection, {from} to {to}; this process's TCP ends, as libproc tells \
         them: {mine:?}"
    );
    assert!(
        !libproc::held_by(from, to, me.wrapping_add(4242)),
        "not another account's: this test's own process holds it"
    );
    let other = std::net::SocketAddrV4::new(*to.ip(), to.port().wrapping_add(1));
    assert!(!libproc::held_by(from, other, me), "no such connection");
    drop(client);
}

/// FR-90 P3-7-3b — a session's net listener admits a connection from its
/// account's processes and refuses one from any other account, asked as an
/// endpoint asks (`connection_is`).
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn a_session_listener_admits_its_account_alone() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = listener.local_addr().unwrap();
    let client = tokio::net::TcpStream::connect(local).await.unwrap();
    let (accepted, _) = listener.accept().await.unwrap();
    #[cfg(unix)]
    let (me, other) = {
        // SAFETY: geteuid reads our own credentials.
        let me = unsafe { libc::geteuid() };
        (me, me.wrapping_add(4242))
    };
    #[cfg(windows)]
    let (me, other) = (
        crate::hive_win::process_sid(std::process::id()).unwrap(),
        "S-1-5-21-1-2-3-4242".to_string(),
    );
    let ours = endpoint::loopback::session_admit(me).expect("this system says who connects");
    assert_eq!(ours(&accepted, local), Ok(()));
    let theirs = endpoint::loopback::session_admit(other).unwrap();
    assert!(theirs(&accepted, local).is_err(), "another account's");
    drop(client);
}

/// P3-5e-2 — a `kubernetes` call names an API server's origin, and `bearer`
/// or `client-cert`; `client-cert` leases the secret's `cert` and `key`, for
/// `http` too. A database's fields are refused in it, and so is `basic`,
/// which no API server takes.
#[test]
fn a_kubernetes_call_names_an_api_server_and_its_credential() {
    let field = |f: &str| Handle {
        secret: "k8s/prod".into(),
        field: f.into(),
    };
    let cert = parse(&json!({
        "handle": "k8s/prod",
        "engine": "kubernetes",
        "upstream": "https://k8s.internal:6443",
        "auth": "client-cert",
        "ca": "pki/k8s-ca",
    }))
    .unwrap();
    assert_eq!(
        (cert.engine, cert.auth, cert.host.as_str(), cert.port),
        (
            Engine::Kubernetes,
            Some(Auth::ClientCert),
            "k8s.internal",
            6443
        )
    );
    assert_eq!(
        cert.handles(),
        [
            field("cert"),
            field("key"),
            Handle {
                secret: "pki/k8s-ca".into(),
                field: String::new(),
            }
        ]
    );
    let bearer = parse(&json!({
        "handle": "k8s/prod",
        "engine": "kubernetes",
        "upstream": "https://k8s.internal:6443",
        "auth": "bearer",
    }))
    .unwrap();
    assert_eq!(bearer.handles(), [field("token")]);
    let mtls = parse(&json!({
        "handle": "k8s/prod",
        "engine": "http",
        "upstream": "https://mtls.example",
        "auth": "client-cert",
    }))
    .unwrap();
    assert_eq!(mtls.auth, Some(Auth::ClientCert));
    let ok = json!({"handle": "k8s/prod", "engine": "kubernetes", "upstream": "https://k8s.internal:6443", "auth": "bearer"});
    let with = |k: &str, v: serde_json::Value| {
        let mut call = ok.clone();
        call[k] = v;
        call
    };
    for bad in [
        json!({"handle": "k8s/prod", "engine": "kubernetes", "upstream": "https://k8s.internal:6443"}),
        with("auth", json!("basic")),
        with("upstream", json!("k8s.internal:6443")),
        with("database", json!("default")),
        with("auth_source", json!("admin")),
        json!({"handle": "db/main", "engine": "postgres", "upstream": "db.internal:5432", "auth": "client-cert"}),
    ] {
        assert!(parse(&bad).is_err(), "{bad}");
    }
}

/// P3-5f-2 — an SSH host, as an audience names one: `ssh://[user@]host`,
/// the port only where it is not 22, and no path; the user in it is the one
/// account the key signs in as.
#[test]
fn an_ssh_upstream_is_a_host_and_maybe_a_user_as_an_audience_names_them() {
    for (raw, user, host, port) in [
        ("ssh://github.com", None, "github.com", 22),
        ("ssh://git@github.com", Some("git"), "github.com", 22),
        (
            "ssh://deploy@build.internal:2222",
            Some("deploy"),
            "build.internal",
            2222,
        ),
        ("ssh://[fd00::5]", None, "fd00::5", 22),
        (
            "ssh://ops.svc@[fd00::5]:2200",
            Some("ops.svc"),
            "fd00::5",
            2200,
        ),
        ("ssh://10.0.0.7:2022", None, "10.0.0.7", 2022),
    ] {
        assert_eq!(
            ssh_of(raw),
            Ok((user.map(str::to_string), host.to_string(), port)),
            "{raw} is an ssh upstream"
        );
    }
    for raw in [
        "github.com",
        "github.com:22",
        "https://github.com",
        "ssh://",
        "ssh://github.com/org/repo",
        "ssh://github.com?x",
        "ssh://github.com#x",
        "ssh://@github.com",
        "ssh://a@b@github.com",
        "ssh://-root@github.com",
        "ssh://.hidden@github.com",
        "ssh://us er@github.com",
        "ssh://root;id@github.com",
        "ssh://github.com:",
        "ssh://github.com:0",
        "ssh://github.com:022",
        "ssh://github.com:65536",
        "ssh://[fd00::5",
        "ssh://-github.com",
    ] {
        assert!(ssh_of(raw).is_err(), "{raw} is no ssh upstream");
    }
    let named = ssh_of("ssh://git@github.com:22").unwrap_err();
    assert!(named.contains("write ssh://git@github.com"), "{named}");
    assert!(ssh_of(&format!("ssh://{}@github.com", "u".repeat(33))).is_err());
}

/// P3-5f-2 — an `ssh` call names an SSH host and leases the secret's `key`
/// and `host_keys`; what is a database's, TLS's or HTTP's is refused in it,
/// and a database never takes an `ssh://` upstream.
#[test]
fn an_ssh_call_names_a_host_and_leases_a_key_and_its_hosts() {
    let field = |f: &str| Handle {
        secret: "ssh/deploy".into(),
        field: f.into(),
    };
    let req = parse(&json!({
        "handle": "ssh/deploy",
        "engine": "ssh",
        "upstream": "ssh://git@github.com",
    }))
    .unwrap();
    assert_eq!(
        (
            req.engine,
            req.user.as_deref(),
            req.host.as_str(),
            req.port,
            req.auth
        ),
        (Engine::Ssh, Some("git"), "github.com", 22, None)
    );
    assert_eq!(req.handles(), [field("key"), field("host_keys")]);
    let ok = json!({"handle": "ssh/deploy", "engine": "ssh", "upstream": "ssh://git@github.com"});
    let with = |k: &str, v: serde_json::Value| {
        let mut call = ok.clone();
        call[k] = v;
        call
    };
    for (bad, says) in [
        (with("upstream", json!("github.com:22")), "ssh://"),
        (with("auth", json!("bearer")), "auth is http's"),
        (with("ca", json!("pki/ca")), "ca is TLS's"),
        (with("database", json!("main")), "database is a database's"),
        (
            with("auth_source", json!("admin")),
            "auth_source is MongoDB's",
        ),
        (
            json!({"handle": "db/main", "engine": "postgres", "upstream": "ssh://db.internal:5432"}),
            "host:port",
        ),
    ] {
        let refused = parse(&bad).unwrap_err();
        assert!(refused.contains(says), "{bad}: {refused}");
    }
}

/// P3-5f-3 — an SSH agent's pipe serves its peer's account alone. Granted to
/// this test's own account but admitting another's (SYSTEM's), the test's own
/// connection is refused by its SID, as any other account's would be; one
/// admitting this account takes it.
#[cfg(windows)]
#[tokio::test]
async fn a_pipe_serves_its_peers_account_alone() {
    use tokio::net::windows::named_pipe::ClientOptions;

    use super::endpoint::Place;
    let own = crate::hive_win::own_sid().unwrap();
    let elsewhere = super::endpoint::pipe::bind_as(&own, "S-1-5-18").unwrap();
    let _client = ClientOptions::new().open(elsewhere.name()).unwrap();
    let stream = elsewhere.accept().await.unwrap();
    let refused = elsewhere.admits(&stream).unwrap_err();
    assert!(refused.contains(&own), "refused by its SID: {refused}");

    let here = super::endpoint::pipe::bind_as(&own, &own).unwrap();
    let _client = ClientOptions::new().open(here.name()).unwrap();
    let stream = here.accept().await.unwrap();
    assert_eq!(here.admits(&stream), Ok(()));
}

/// P3-5f-3 — the agent pipe's grant lets the session's account open it as
/// Win32-OpenSSH opens an agent, `GENERIC_READ | GENERIC_WRITE` (tokio's
/// client asks for the same), where the toolbelt pipe's grant would refuse
/// it. Each pipe here grants this test's account alone, its SYSTEM and
/// Administrators grants taken out, so an elevated test cannot pass by them:
/// a session's own token has its Administrators group deny-only.
#[cfg(windows)]
#[tokio::test]
async fn the_agent_pipe_opens_as_win32_openssh_opens_it() {
    use tokio::net::windows::named_pipe::ClientOptions;

    let own = crate::hive_win::own_sid().unwrap();
    let alone = |sddl: String| sddl.replace("(A;;GA;;;SY)", "").replace("(A;;GA;;;BA)", "");
    for (sddl, opens) in [
        (alone(crate::hive_win::agent_pipe_sddl(&own)), true),
        (alone(crate::hive_win::toolbelt_pipe_sddl(&own)), false),
    ] {
        assert!(!sddl.contains(";BA)") && !sddl.contains(";SY)"), "{sddl}");
        let name = format!(
            r"\\.\pipe\meshharbor-vault-test-{:016x}",
            rand::random::<u64>()
        );
        let _server = super::super::toolbelt::pipe_instance(&name, &sddl, true).unwrap();
        let opened = ClientOptions::new().open(&name);
        match (opened, opens) {
            (Ok(_), true) => {}
            (Err(e), false) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{sddl}"),
            (got, _) => panic!("{sddl}: {got:?}"),
        }
    }
}

/// FR-90 P3-9-2 — why a person's lease was not given, in the person's words:
/// the vault's own word decides whether asking again could help, and no
/// connection or no answer always could. Decision 24's refusal says what it
/// means, and so does a server switch that lends nothing to people.
#[test]
fn a_persons_refusal_says_what_it_means_and_whether_to_ask_again() {
    use crate::vault::LeaseError;
    let refused = |word: &str| person_why(LeaseError::Refused(word.into()));
    let denied = refused("denied");
    assert!(!denied.again);
    assert!(denied.why.contains("the device's owner"), "{}", denied.why);
    let approval = refused("approval_unavailable");
    assert!(!approval.again);
    assert!(
        approval.why.contains("approval_unavailable"),
        "{}",
        approval.why
    );
    assert!(refused("not_served").why.contains("vault.people"));
    for word in ["unavailable", "undecided", "busy"] {
        assert!(refused(word).again, "{word}");
    }
    for word in ["no_secret", "disabled", "no_value", "bad_request"] {
        let r = refused(word);
        assert!(!r.again, "{word}");
        assert_eq!(r.why, format!("the vault refused: {word}"));
    }
    // A word a newer server sends is a refusal this build cannot name: not
    // asked again.
    assert!(!refused("from_a_newer_server").again);
    for (e, again) in [
        (LeaseError::NotConnected, true),
        (LeaseError::NoAnswer, true),
        (LeaseError::Unopenable, true),
        (LeaseError::AwaitingApproval("a1".into()), false),
        (LeaseError::NotAsked, false),
    ] {
        assert_eq!(person_why(e.clone()).again, again, "{e:?}");
    }
    // The daemon's own leases for a person let go of nothing an endpoint
    // that never held one would name.
    DaemonPersonLeases.drop_person(u64::MAX);
}

/// FR-90 P3-9-2 — the daemon renews a person's endpoint before its leases
/// end whatever TTL it asked for: even the shortest lease leaves a margin no
/// shorter than the floor between two renewals, and a sleeping clock is
/// looked at again well within the longest.
#[test]
fn the_daemon_renews_even_the_shortest_lease_in_time() {
    use meshharbor_remote_control::vault::lease_limits::{MAX_TTL_SECS, MIN_TTL_SECS};
    let t = Timing::DAEMON;
    let margin = std::time::Duration::from_secs(u64::from(MIN_TTL_SECS / t.margin_div));
    assert!(t.margin_div >= 2);
    assert!(margin >= t.floor, "{margin:?} < {:?}", t.floor);
    assert!(t.recheck < std::time::Duration::from_secs(u64::from(MAX_TTL_SECS / t.margin_div)));
}
