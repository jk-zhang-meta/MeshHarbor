// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-5d-1 — the HTTP engine, against a fake upstream over real TLS.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::client::conn::http1::SendRequest;
use hyper::header::HeaderValue;
use hyper::{HeaderMap, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use super::{Credential, Flavor, Upstream, point_back, refuse, serve};
use crate::vault_proxy::testing::{HttpSaw, fake_http, fake_http_mtls, made, stranger};
use crate::vault_proxy::tls;

type ClientBody = BoxBody<Bytes, Infallible>;

/// The endpoint's own origin, as the tests name it.
const FRONT: &str = "http://127.0.0.1:1";

fn bearer(token: &str) -> Credential {
    Credential::Bearer(Zeroizing::new(token.to_string()))
}

fn upstream(host: &str, port: u16, ca: &str, credential: Credential) -> Upstream {
    Upstream {
        host: host.to_string(),
        port,
        credential,
        tls: tls::connector(Some(ca)).unwrap(),
        front: FRONT.to_string(),
        flavor: Flavor::Plain,
    }
}

/// P3-5e-1 — the same, standing for a Kubernetes API server.
fn kube(host: &str, port: u16, ca: &str, credential: Credential) -> Upstream {
    Upstream {
        flavor: Flavor::Kubernetes,
        ..upstream(host, port, ca, credential)
    }
}

/// A connection the engine serves, and a client on it.
async fn client(up: Upstream) -> SendRequest<ClientBody> {
    let (near, far) = tokio::io::duplex(1 << 16);
    let up = Arc::new(up);
    tokio::spawn(async move {
        let _ = serve(far, &up).await;
    });
    let (send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(near))
        .await
        .unwrap();
    tokio::spawn(conn);
    send
}

fn empty() -> ClientBody {
    Full::new(Bytes::new()).boxed()
}

fn get(path: &str) -> Request<ClientBody> {
    Request::get(path)
        .header("host", "127.0.0.1:1")
        .body(empty())
        .unwrap()
}

/// `req` sent on `c`, within 10 s: the status, the headers and the body.
async fn ask(
    c: &mut SendRequest<ClientBody>,
    req: Request<ClientBody>,
) -> (StatusCode, HeaderMap, String) {
    let asked = async {
        c.ready().await.unwrap();
        let resp: Response<Incoming> = c.send_request(req).await.unwrap();
        let (status, headers) = (resp.status(), resp.headers().clone());
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, headers, String::from_utf8_lossy(&body).into_owned())
    };
    tokio::time::timeout(Duration::from_secs(10), asked)
        .await
        .expect("an answer within 10 s")
}

/// The next request the upstream saw, within 10 s.
async fn saw(rx: &mut mpsc::UnboundedReceiver<HttpSaw>) -> HttpSaw {
    tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("a request upstream within 10 s")
        .expect("the upstream is up")
}

/// Nothing more reaches the upstream in the next 2 s.
async fn nothing_more(rx: &mut mpsc::UnboundedReceiver<HttpSaw>) {
    if let Ok(Some(s)) = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
        panic!("a request reached the upstream: {s:?}");
    }
}

/// `request`, written as it is on a connection the engine serves: what came
/// back before the engine hung up.
async fn raw(up: Upstream, request: &str) -> String {
    let (mut near, far) = tokio::io::duplex(1 << 16);
    let up = Arc::new(up);
    tokio::spawn(async move {
        let _ = serve(far, &up).await;
    });
    near.write_all(request.as_bytes()).await.unwrap();
    let mut got = Vec::new();
    let read = near.read_to_end(&mut got);
    let _ = tokio::time::timeout(Duration::from_secs(10), read).await;
    String::from_utf8_lossy(&got).into_owned()
}

/// The secret's token goes upstream in `Authorization`, the path and query
/// as they came, `Host` the upstream's; the client's own credentials and
/// hop-by-hop headers never leave.
#[tokio::test]
async fn the_token_goes_upstream_and_nothing_of_the_clients_does() {
    let (ca, port, mut rx) = fake_http().await;
    let token = made();
    let mut c = client(upstream("localhost", port, &ca, bearer(&token))).await;
    let guess = made();
    let req = Request::get("/repos/x/y?per_page=1")
        .header("host", "127.0.0.1:1")
        .header("authorization", format!("Bearer {guess}"))
        .header("proxy-authorization", format!("Basic {guess}"))
        .header("connection", "x-client-hop")
        .header("x-client-hop", "1")
        .header("te", "trailers")
        .header("x-kept", "yes")
        .body(empty())
        .unwrap();
    let (status, _, body) = ask(&mut c, req).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "ok"));
    let s = saw(&mut rx).await;
    assert_eq!(
        (s.method.as_str(), s.target.as_str()),
        ("GET", "/repos/x/y?per_page=1")
    );
    assert_eq!(
        s.values("authorization"),
        [format!("Bearer {token}")],
        "one Authorization, the secret's"
    );
    assert_eq!(s.values("host"), [format!("localhost:{port}")]);
    for gone in ["proxy-authorization", "x-client-hop", "te", "connection"] {
        assert!(
            s.values(gone).is_empty(),
            "{gone} reached the upstream: {s:?}"
        );
    }
    assert!(
        !format!("{s:?}").contains(&guess),
        "the client's own credential reached the upstream: {s:?}"
    );
    assert_eq!(s.values("x-kept"), ["yes"]);
}

/// Basic carries the secret's user and password, a colon in the password
/// and all.
#[tokio::test]
async fn basic_is_the_secrets_user_and_password() {
    let (ca, port, mut rx) = fake_http().await;
    let (user, password) = (made(), format!("{}:{}", made(), made()));
    let credential = Credential::Basic {
        user: Zeroizing::new(user.clone()),
        password: Zeroizing::new(password.clone()),
    };
    let mut c = client(upstream("localhost", port, &ca, credential)).await;
    let (status, _, _) = ask(&mut c, get("/user")).await;
    assert_eq!(status, StatusCode::OK);
    let pair = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
    assert_eq!(
        saw(&mut rx).await.values("authorization"),
        [format!("Basic {pair}")]
    );
}

/// A value `Authorization` cannot carry is never sent: a user with a colon,
/// a token that is empty or holds a space or a line break.
#[tokio::test]
async fn a_value_a_header_cannot_carry_sends_nothing() {
    let (ca, port, mut rx) = fake_http().await;
    for credential in [
        Credential::Basic {
            user: Zeroizing::new(format!("{}:{}", made(), made())),
            password: Zeroizing::new(made()),
        },
        bearer(""),
        bearer(&format!("{} {}", made(), made())),
        bearer(&format!("{}\r\nx-injected: 1", made())),
    ] {
        let mut c = client(upstream("localhost", port, &ca, credential)).await;
        let (status, _, body) = ask(&mut c, get("/x")).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
        assert!(body.contains("Authorization header"), "{body}");
    }
    nothing_more(&mut rx).await;
}

/// The value is marked sensitive, so the HTTP stack never logs it.
#[test]
fn the_value_is_marked_sensitive() {
    assert!(bearer(&made()).header().unwrap().is_sensitive());
    let basic = Credential::Basic {
        user: Zeroizing::new(made()),
        password: Zeroizing::new(made()),
    };
    assert!(basic.header().unwrap().is_sensitive());
}

/// The endpoint stands for its upstream and nothing else: `CONNECT`, an
/// absolute form (even naming the upstream) and `*` are refused, and nothing
/// reaches the upstream.
#[tokio::test]
async fn the_endpoint_is_no_forward_proxy() {
    let (ca, port, mut rx) = fake_http().await;
    for (request, status) in [
        (
            "CONNECT elsewhere.test:443 HTTP/1.1\r\nHost: elsewhere.test:443\r\nConnection: \
             close\r\n\r\n"
                .to_string(),
            "405",
        ),
        (
            "GET https://elsewhere.test/x HTTP/1.1\r\nHost: elsewhere.test\r\nConnection: close\r\n\r\n"
                .to_string(),
            "400",
        ),
        (
            format!(
                "GET https://localhost:{port}/x HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: \
                 close\r\n\r\n"
            ),
            "400",
        ),
        (
            "OPTIONS * HTTP/1.1\r\nHost: 127.0.0.1:1\r\nConnection: close\r\n\r\n".to_string(),
            "400",
        ),
    ] {
        let got = raw(upstream("localhost", port, &ca, bearer(&made())), &request).await;
        assert!(
            got.starts_with(&format!("HTTP/1.1 {status} ")),
            "{request:?}: {got}"
        );
    }
    nothing_more(&mut rx).await;
}

/// A redirect to the upstream's own origin comes back pointed at the
/// endpoint, query and fragment kept; one anywhere else comes back as it
/// was, for the client to follow with no value.
#[tokio::test]
async fn a_redirect_to_the_upstream_comes_back_through_the_endpoint() {
    let (ca, port, _rx) = fake_http().await;
    let mut c = client(upstream("localhost", port, &ca, bearer(&made()))).await;
    let other = if port == 444 { 445 } else { 444 };
    for (path, location) in [
        ("/redirect/here", format!("{FRONT}/landed?x=1#top")),
        ("/redirect/case", format!("{FRONT}/case")),
        ("/redirect/port", format!("https://localhost:{other}/x")),
        (
            "/redirect/user",
            format!("https://someone@localhost:{port}/x"),
        ),
        ("/redirect/away", "https://elsewhere.test/x".to_string()),
    ] {
        let (status, headers, _) = ask(&mut c, get(path)).await;
        assert_eq!(status, StatusCode::FOUND, "{path}");
        assert_eq!(headers["location"].to_str().unwrap(), location, "{path}");
    }
}

/// The origin is matched whole: scheme, host and port, never a prefix.
#[test]
fn a_redirect_is_pointed_back_only_to_the_whole_origin() {
    let ca = stranger();
    let up = upstream("git.example", 443, &ca, bearer(&made()));
    let back = |location: &str| {
        point_back(&HeaderValue::from_str(location).unwrap(), &up)
            .map(|v| v.to_str().unwrap().to_string())
    };
    assert_eq!(
        back("https://git.example/a?b=1#c"),
        Some(format!("{FRONT}/a?b=1#c"))
    );
    assert_eq!(
        back("https://git.example:443/a"),
        Some(format!("{FRONT}/a"))
    );
    assert_eq!(back("https://Git.Example"), Some(format!("{FRONT}/")));
    for elsewhere in [
        "https://git.example.elsewhere.test/a",
        "https://git.example:8443/a",
        "http://git.example/a",
        "https://someone@git.example/a",
        "//git.example/a",
        "/a",
        "not a place",
    ] {
        assert_eq!(back(elsewhere), None, "{elsewhere}");
    }
    let v6 = upstream("fd00::5", 8443, &ca, bearer(&made()));
    let location = HeaderValue::from_static("https://[FD00::5]:8443/x");
    assert_eq!(
        point_back(&location, &v6).unwrap().to_str().unwrap(),
        format!("{FRONT}/x")
    );
}

/// `Host` names the port only where it is not 443, and an IPv6 address in
/// brackets.
#[test]
fn host_names_the_port_only_where_it_is_not_443() {
    let ca = stranger();
    let host = |h: &str, port| upstream(h, port, &ca, bearer(&made())).authority();
    assert_eq!(host("github.com", 443), "github.com");
    assert_eq!(host("git.example", 8443), "git.example:8443");
    assert_eq!(host("fd00::5", 443), "[fd00::5]");
    assert_eq!(host("fd00::5", 8443), "[fd00::5]:8443");
}

/// The upstream's hop-by-hop headers, those its `Connection` names, and the
/// headers that would describe it as if it were the endpoint stay behind.
#[tokio::test]
async fn the_upstreams_hop_and_origin_headers_stay_behind() {
    let (ca, port, _rx) = fake_http().await;
    let mut c = client(upstream("localhost", port, &ca, bearer(&made()))).await;
    let (status, headers, _) = ask(&mut c, get("/headers")).await;
    assert_eq!(status, StatusCode::OK);
    for gone in ["alt-svc", "strict-transport-security", "x-upstream-hop"] {
        assert!(headers.get(gone).is_none(), "{gone} came back: {headers:?}");
    }
    assert_eq!(headers["x-kept"].to_str().unwrap(), "yes");
}

/// A body streams to the upstream as it comes, with no length the client
/// did not give, and its answer streams back.
#[tokio::test]
async fn a_body_streams_both_ways() {
    let (ca, port, mut rx) = fake_http().await;
    let mut c = client(upstream("localhost", port, &ca, bearer(&made()))).await;
    let chunk = Bytes::from(vec![b'g'; 64 * 1024]);
    let frames: Vec<Result<Frame<Bytes>, Infallible>> =
        (0..17).map(|_| Ok(Frame::data(chunk.clone()))).collect();
    let body = StreamBody::new(futures::stream::iter(frames)).boxed();
    let req = Request::post("/echo")
        .header("host", "127.0.0.1:1")
        .body(body)
        .unwrap();
    let (status, _, echoed) = ask(&mut c, req).await;
    assert_eq!((status, echoed.len()), (StatusCode::OK, 17 * 64 * 1024));
    let s = saw(&mut rx).await;
    assert_eq!((s.method.as_str(), s.body), ("POST", 17 * 64 * 1024));
    assert_eq!(
        s.values("transfer-encoding"),
        ["chunked"],
        "streamed, never gathered into a length"
    );
}

/// An upstream whose certificate nobody vouches for gets no request at all.
#[tokio::test]
async fn an_upstream_nobody_verified_is_sent_nothing() {
    let (_, port, mut rx) = fake_http().await;
    let mut c = client(upstream("localhost", port, &stranger(), bearer(&made()))).await;
    let (status, _, body) = ask(&mut c, get("/x")).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert!(body.contains("TLS to localhost"), "{body}");
    nothing_more(&mut rx).await;
}

/// An upstream that answers in the clear never sees a request, let alone
/// the value.
#[tokio::test]
async fn a_cleartext_upstream_never_sees_the_value() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, mut got) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                let n = tcp.read(&mut buf).await.unwrap_or(0);
                let _ = tcp
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                    .await;
                let _ = tx.send(buf[..n].to_vec());
            });
        }
    });
    let token = made();
    let mut c = client(upstream("localhost", port, &stranger(), bearer(&token))).await;
    let (status, _, body) = ask(&mut c, get("/x")).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    let bytes = got.recv().await.unwrap();
    assert!(
        !bytes.windows(4).any(|w| w == b"GET "),
        "a request went out in the clear"
    );
    assert!(!String::from_utf8_lossy(&bytes).contains(&token));
}

/// One upstream connection carries a client connection's requests until
/// the upstream closes it; the next request goes on a new one.
#[tokio::test]
async fn requests_share_a_connection_until_the_upstream_closes_it() {
    let (ca, port, mut rx) = fake_http().await;
    let mut c = client(upstream("localhost", port, &ca, bearer(&made()))).await;
    for path in ["/a", "/b", "/close", "/c"] {
        let (status, _, _) = ask(&mut c, get(path)).await;
        assert_eq!(status, StatusCode::OK, "{path}");
    }
    let mut conns = Vec::new();
    for _ in 0..4 {
        conns.push(saw(&mut rx).await.conn);
    }
    assert_eq!(
        conns[0], conns[1],
        "two requests, one connection: {conns:?}"
    );
    assert_eq!(conns[1], conns[2], "{conns:?}");
    assert_ne!(
        conns[2], conns[3],
        "a new connection once the upstream closed its own: {conns:?}"
    );
}

/// A client the endpoint does not serve is told why, in HTTP.
#[tokio::test]
async fn a_refused_client_is_told_why() {
    let (near, far) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        let _ = refuse(far, "the endpoint's lease has ended").await;
    });
    let (mut c, conn) = hyper::client::conn::http1::handshake(TokioIo::new(near))
        .await
        .unwrap();
    tokio::spawn(conn);
    let (status, _, body) = ask(&mut c, get("/x")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("lease has ended"), "{body}");
}

/// P3-5e-1 — a client certificate is presented in the handshake, and no
/// header carries anything of it. Without one, an upstream that asks for
/// one refuses the handshake, and no request reaches it.
#[tokio::test]
async fn a_client_certificate_is_presented_in_the_handshake() {
    let mut f = fake_http_mtls().await;
    let identity = tls::identity(&f.cert, &f.key).unwrap();
    let presented = Upstream {
        tls: tls::connector_for(tls::roots(Some(&f.ca)).unwrap(), Some(identity)).unwrap(),
        ..kube("localhost", f.port, &f.ca, Credential::Handshake)
    };
    let mut c = client(presented).await;
    let (status, _, body) = ask(&mut c, get("/api/v1/namespaces")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let s = saw(&mut f.saw).await;
    assert_eq!(s.target, "/api/v1/namespaces");
    assert!(
        s.values("authorization").is_empty(),
        "no header carries a certificate: {s:?}"
    );
    let mut c = client(kube("localhost", f.port, &f.ca, Credential::Handshake)).await;
    let (status, _, body) = ask(&mut c, get("/api/v1/namespaces")).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    nothing_more(&mut f.saw).await;
}

/// P3-5e-1 — an identity is a certificate and a key, both PEM: anything
/// else is refused before a handshake.
#[test]
fn an_identity_that_is_not_one_is_refused() {
    let own = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let (cert, key) = (own.cert.pem(), own.key_pair.serialize_pem());
    assert!(tls::identity(&cert, &key).is_ok());
    for (cert, key) in [
        ("not a certificate", key.as_str()),
        ("", key.as_str()),
        (cert.as_str(), ""),
        (cert.as_str(), cert.as_str()),
    ] {
        assert!(
            tls::identity(cert, key).is_err(),
            "{cert:.20} with {key:.20}"
        );
    }
}

/// The head of one response on `s`, within 10 s: every byte to its blank
/// line, and none after.
async fn head_of(s: &mut tokio::io::DuplexStream) -> String {
    let read = async {
        let mut got = Vec::new();
        let mut byte = [0u8; 1];
        while !got.ends_with(b"\r\n\r\n") {
            let n = s.read(&mut byte).await.unwrap();
            assert_eq!(
                n,
                1,
                "the endpoint hung up: {:?}",
                String::from_utf8_lossy(&got)
            );
            got.push(byte[0]);
        }
        String::from_utf8_lossy(&got).into_owned()
    };
    tokio::time::timeout(Duration::from_secs(10), read)
        .await
        .expect("a response within 10 s")
}

/// P3-5e-1 — a Kubernetes endpoint carries an upgrade to the API server,
/// and on its `101` joins the two connections: what the client sends after
/// comes back from the upstream's end, the secret's token having gone with
/// the request.
#[tokio::test]
async fn kubernetes_relays_an_upgrade_and_joins_the_two_ends() {
    let (ca, port, mut rx) = fake_http().await;
    let token = made();
    let (mut near, far) = tokio::io::duplex(1 << 16);
    let up = Arc::new(kube("localhost", port, &ca, bearer(&token)));
    tokio::spawn(async move {
        let _ = serve(far, &up).await;
    });
    near.write_all(
        b"GET /exec HTTP/1.1\r\nHost: 127.0.0.1:1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
    )
    .await
    .unwrap();
    let head = head_of(&mut near).await;
    assert!(head.starts_with("HTTP/1.1 101 "), "{head}");
    assert!(
        head.to_ascii_lowercase().contains("upgrade: websocket"),
        "{head}"
    );
    let s = saw(&mut rx).await;
    assert_eq!(s.values("upgrade"), ["websocket"]);
    assert_eq!(s.values("authorization"), [format!("Bearer {token}")]);
    near.write_all(b"through the tunnel").await.unwrap();
    let mut echoed = [0u8; 18];
    tokio::time::timeout(Duration::from_secs(10), near.read_exact(&mut echoed))
        .await
        .expect("an echo within 10 s")
        .unwrap();
    assert_eq!(&echoed, b"through the tunnel");
}

/// P3-5e-1 — no upgrade is relayed where the endpoint is a plain HTTP one,
/// nor to a protocol `kubectl` does not stream over (`h2c`): the request
/// goes on as an ordinary one.
#[tokio::test]
async fn no_other_upgrade_is_relayed() {
    let (ca, port, mut rx) = fake_http().await;
    for (up, protocol) in [
        (
            upstream("localhost", port, &ca, bearer(&made())),
            "websocket",
        ),
        (kube("localhost", port, &ca, bearer(&made())), "h2c"),
    ] {
        let (mut near, far) = tokio::io::duplex(1 << 16);
        let up = Arc::new(up);
        tokio::spawn(async move {
            let _ = serve(far, &up).await;
        });
        let request = format!(
            "GET /exec HTTP/1.1\r\nHost: 127.0.0.1:1\r\nConnection: Upgrade\r\nUpgrade: \
             {protocol}\r\n\r\n"
        );
        near.write_all(request.as_bytes()).await.unwrap();
        let head = head_of(&mut near).await;
        assert!(head.starts_with("HTTP/1.1 200 "), "{protocol}: {head}");
        let s = saw(&mut rx).await;
        assert!(s.values("upgrade").is_empty(), "{protocol} relayed: {s:?}");
    }
}

/// P3-5e-1 — a Kubernetes endpoint drops every impersonation header, so the
/// session never acts through the secret's identity as another; a plain
/// HTTP one has no such header to mean anything, and passes them on.
#[tokio::test]
async fn kubernetes_drops_every_impersonation_header() {
    let (ca, port, mut rx) = fake_http().await;
    let impersonating = || {
        Request::get("/api/v1/secrets")
            .header("host", "127.0.0.1:1")
            .header("impersonate-user", "admin")
            .header("impersonate-group", "system:masters")
            .header("impersonate-uid", "0")
            .header("impersonate-extra-scopes", "all")
            .header("x-kept", "yes")
            .body(empty())
            .unwrap()
    };
    let mut c = client(kube("localhost", port, &ca, bearer(&made()))).await;
    let (status, _, _) = ask(&mut c, impersonating()).await;
    assert_eq!(status, StatusCode::OK);
    let s = saw(&mut rx).await;
    assert!(
        !s.headers.iter().any(|(n, _)| n.starts_with("impersonate-")),
        "impersonation reached the API server: {s:?}"
    );
    assert_eq!(s.values("x-kept"), ["yes"]);
    let mut c = client(upstream("localhost", port, &ca, bearer(&made()))).await;
    let (status, _, _) = ask(&mut c, impersonating()).await;
    assert_eq!(status, StatusCode::OK);
    let s = saw(&mut rx).await;
    assert_eq!(s.values("impersonate-user"), ["admin"]);
}

/// P3-5e-1 — a tunnel lives within its client connection's session: when
/// that ends (the endpoint's lease let go), the joined connection ends too.
#[tokio::test]
async fn a_tunnel_ends_with_its_session() {
    let (ca, port, _rx) = fake_http().await;
    let (mut near, far) = tokio::io::duplex(1 << 16);
    let up = Arc::new(kube("localhost", port, &ca, bearer(&made())));
    let session = tokio::spawn(async move {
        let _ = serve(far, &up).await;
    });
    near.write_all(
        b"GET /exec HTTP/1.1\r\nHost: 127.0.0.1:1\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n\r\n",
    )
    .await
    .unwrap();
    let head = head_of(&mut near).await;
    assert!(head.starts_with("HTTP/1.1 101 "), "{head}");
    near.write_all(b"once").await.unwrap();
    let mut echoed = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(10), near.read_exact(&mut echoed))
        .await
        .expect("an echo within 10 s")
        .unwrap();
    session.abort();
    let mut rest = Vec::new();
    let ended = tokio::time::timeout(Duration::from_secs(10), near.read_to_end(&mut rest)).await;
    assert!(ended.is_ok(), "the tunnel ended with its session");
}
