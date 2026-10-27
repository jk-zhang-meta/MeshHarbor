// SPDX-License-Identifier: MPL-2.0
//! v039 CTRL-03 — the control WS follows its server's address through a real
//! name lookup, and verifies that server's certificate, end to end through
//! [`roomlerd::ws_connect::connect`] (the dial the control WS and DERP use).
//!
//! The name is `localhost`, which the OS resolver answers from `/etc/hosts`
//! with both an A and an AAAA record, so the move below is a real
//! `getaddrinfo`, not a fake. The servers present certificates from a CA made
//! for this run, trusted through `SSL_CERT_FILE` (read by
//! `rustls-native-certs`, as on a device): this file is its own test binary,
//! so that variable reaches no other test.
//!
//! | Step | Server | Must show |
//! |---|---|---|
//! | AAAA | `[::1]:P`, the remembered answer | connects, the certificate verified for the NAME |
//! | moved | `[::1]:P` gone, now `127.0.0.1:P` | the failed dial drops the remembered answer, and a fresh lookup finds the new address |
//! | untrusted | `localhost` certificate from another CA | refused for its certificate; the server never sees a WS request |
//! | wrong name | the trusted CA, for `other.example` | refused for its certificate |
//! | redirect | a 302 to another origin | an HTTP error; the redirect is not followed |

use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{self, ServerConfig, pki_types::PrivateKeyDer};
use tokio_tungstenite::tungstenite::{self, Message};

struct Ca {
    cert: Certificate,
    key: KeyPair,
}

impl Ca {
    fn new() -> Self {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).unwrap();
        Self { cert, key }
    }

    fn leaf(&self, name: &str) -> Arc<ServerConfig> {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec![name.to_string()])
            .unwrap()
            .signed_by(&key, &self.cert, &self.key)
            .unwrap();
        let config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    PrivateKeyDer::Pkcs8(key.serialize_der().into()),
                )
                .unwrap();
        Arc::new(config)
    }
}

/// What a server does once TLS is up.
#[derive(Clone, Copy)]
enum Answer {
    /// A WS handshake, then one text frame naming this server.
    Ws(&'static str),
    /// A plain HTTP redirect to another origin.
    Redirect,
}

/// A TLS server on `listener`. `requests` counts the HTTP requests it read,
/// i.e. connections whose TLS handshake completed.
fn serve(
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    answer: Answer,
) -> (JoinHandle<()>, Arc<AtomicUsize>) {
    let requests = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&requests);
    let acceptor = TlsAcceptor::from(tls);
    let task = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, seen) = (acceptor.clone(), Arc::clone(&seen));
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                match answer {
                    Answer::Ws(tag) => {
                        let Ok(mut ws) = tokio_tungstenite::accept_async(tls).await else {
                            return;
                        };
                        seen.fetch_add(1, Ordering::SeqCst);
                        let _ = ws.send(Message::Text(tag.into())).await;
                        let _ = ws.next().await;
                    }
                    Answer::Redirect => {
                        let mut buf = [0u8; 4096];
                        if tls.read(&mut buf).await.unwrap_or(0) > 0 {
                            seen.fetch_add(1, Ordering::SeqCst);
                        }
                        let _ = tls
                            .write_all(
                                b"HTTP/1.1 302 Found\r\nLocation: wss://other.example/ws\r\nContent-Length: 0\r\n\r\n",
                            )
                            .await;
                        let _ = tls.shutdown().await;
                    }
                }
            });
        }
    });
    (task, requests)
}

/// A port free on both 127.0.0.1 and ::1, with its v4 and v6 listeners.
async fn dual_port() -> (u16, TcpListener, TcpListener) {
    for _ in 0..20 {
        let v4 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = v4.local_addr().unwrap().port();
        if let Ok(v6) = TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await {
            return (port, v4, v6);
        }
    }
    panic!("no port free on both loopbacks");
}

/// The text of the first frame, or the dial's error.
async fn dial(url: &str) -> Result<String, tungstenite::Error> {
    let (mut ws, _) =
        tokio::time::timeout(Duration::from_secs(15), roomlerd::ws_connect::connect(url))
            .await
            .expect("the dial is bounded")?;
    match ws.next().await {
        Some(Ok(Message::Text(t))) => Ok(t.to_string()),
        other => panic!("expected a text frame, got {other:?}"),
    }
}

#[tokio::test]
async fn the_control_dial_follows_its_server_and_verifies_it() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca = Ca::new();
    let roots = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(roots.path(), ca.cert.pem()).unwrap();
    // SAFETY: set before the first dial, in a test binary that runs this one
    // test; nothing else reads the environment concurrently.
    unsafe { std::env::set_var("SSL_CERT_FILE", roots.path()) };

    let (port, v4, v6) = dual_port().await;
    let hostport = tunnel_core::ctl_dns::hostport("localhost", port);
    let url = format!("wss://{hostport}/ws");
    let v6_addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));

    // AAAA: the remembered answer is the v6 address only.
    let (v6_task, _) = serve(v6, ca.leaf("localhost"), Answer::Ws("v6"));
    tunnel_core::ctl_dns::remember(&hostport, &[v6_addr]);
    assert_eq!(
        dial(&url)
            .await
            .expect("the AAAA address, verified for the name"),
        "v6"
    );

    // Moved: the v6 server is gone and the name's server answers on v4. The
    // first dial meets the stale address and drops it; a later one resolves
    // `localhost` afresh (A and AAAA) and reaches the server where it is now.
    v6_task.abort();
    let _ = v6_task.await;
    let (v4_task, _) = serve(v4, ca.leaf("localhost"), Answer::Ws("v4"));
    let mut moved = None;
    for _ in 0..50 {
        match dial(&url).await {
            Ok(tag) => {
                moved = Some(tag);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    assert_eq!(
        moved.as_deref(),
        Some("v4"),
        "a fresh lookup follows the server"
    );
    v4_task.abort();
    let _ = v4_task.await;

    let v4_addr = SocketAddr::from(([127, 0, 0, 1], port));
    for (step, tls) in [
        ("untrusted CA", Ca::new().leaf("localhost")),
        ("wrong name", ca.leaf("other.example")),
    ] {
        let listener = TcpListener::bind(v4_addr).await.unwrap();
        let (task, requests) = serve(listener, tls, Answer::Ws("impostor"));
        tunnel_core::ctl_dns::remember(&hostport, &[v4_addr]);
        let err = dial(&url).await.expect_err(step);
        // rustls' refusal surfaces as an I/O error carrying it.
        assert!(
            format!("{err:?}").contains("InvalidCertificate"),
            "{step}: refused for its certificate, got {err:?}"
        );
        assert_eq!(
            requests.load(Ordering::SeqCst),
            0,
            "{step}: no WS request reached it"
        );
        task.abort();
        let _ = task.await;
    }

    let listener = TcpListener::bind(v4_addr).await.unwrap();
    let (task, requests) = serve(listener, ca.leaf("localhost"), Answer::Redirect);
    tunnel_core::ctl_dns::remember(&hostport, &[v4_addr]);
    match dial(&url).await {
        Err(tungstenite::Error::Http(resp)) => assert_eq!(resp.status(), 302),
        other => panic!("a redirect is an HTTP error, not followed: {other:?}"),
    }
    assert_eq!(
        requests.load(Ordering::SeqCst),
        1,
        "one request, no second one to the target"
    );
    task.abort();
}
