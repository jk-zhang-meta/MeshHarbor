// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-5d-1 — the HTTP proxy's session: one client connection on the
//! endpoint, each of its requests sent on to one upstream origin with the
//! secret's credential added.
//!
//! | Step | What happens |
//! |---|---|
//! | a request | origin-form only (`/path?query`): `CONNECT`, an absolute or an authority form and `*` are refused, since the endpoint stands for one upstream and is no forward proxy |
//! | its headers | the client's own `Authorization` and `Proxy-Authorization` dropped, with every hop-by-hop header and those `Connection` names; `Host` made the upstream's; the secret's `Authorization` added, marked sensitive |
//! | the upstream | TCP, then TLS verified ([`super::tls`]), HTTP/1.1: dialled at the connection's first request, and again whenever the upstream has closed it |
//! | the response | streamed back, never buffered. A `Location` on the upstream's own origin is pointed back at the endpoint; one anywhere else goes back unchanged, and the client follows it with no value. `Alt-Svc` and `Strict-Transport-Security`, which would describe the upstream as if it were the endpoint, are dropped |
//! | a Kubernetes API server (P3-5e-1) | the same, and: a client certificate presented in the TLS handshake where the secret holds one (no header carries it); an upgrade to `websocket` or `SPDY/3.1` relayed, the two connections joined on the API server's `101` (`kubectl exec`, `attach`, `port-forward`), within the client connection's life; every `Impersonate-*` header dropped, so the session never acts through the secret's identity as another |
//!
//! ⚠️ The credential goes only in `Authorization`, in the form the call
//! named (`Basic` or `Bearer`), or in the handshake. A header the session
//! could name is a header an upstream might echo back in a response the
//! session reads.
//!
//! ⚠️ The proxy never follows a redirect itself. The client does, and only
//! one that stays on the upstream comes back through the endpoint.
//!
//! ⚠️ The value is on the wire here, inside the TLS the proxy verified, and
//! it passes through the HTTP stack's buffers, which are not zeroed: unlike
//! SCRAM, an `Authorization` header shows the upstream the value itself.

use std::convert::Infallible;
use std::sync::Mutex;
use std::time::Duration;

use base64::Engine as _;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tracing::debug;
use zeroize::Zeroizing;

use super::tls;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub(crate) type Body = BoxBody<Bytes, BoxError>;

/// How long the upstream may take to accept a connection and finish TLS.
const CONNECT_DEADLINE: Duration = Duration::from_secs(10);
/// How long a client has to send a request's headers.
const HEADER_DEADLINE: Duration = Duration::from_secs(30);
/// What a request that is not for a path on the upstream is told.
const NOT_A_PROXY: &str = "this endpoint stands for one upstream: send it a request for a path, as \
                           you would the upstream";

/// P3-5e-1 — what the endpoint stands for: an HTTP upstream (P3-5d), or a
/// Kubernetes API server, whose endpoint also relays an upgrade and drops
/// impersonation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flavor {
    Plain,
    Kubernetes,
}

/// How the secret's value is presented: in `Authorization`, in the form the
/// call named, or (P3-5e-1) as a client certificate in the TLS handshake.
pub(crate) enum Credential {
    /// RFC 7617: the secret's `user` and `password`.
    Basic {
        user: Zeroizing<String>,
        password: Zeroizing<String>,
    },
    /// RFC 6750: the secret's `token`.
    Bearer(Zeroizing<String>),
    /// P3-5e-1 — a client certificate, presented by the upstream's
    /// connector in the handshake: no header carries it, and TLS proves the
    /// key without sending it.
    Handshake,
}

impl Credential {
    /// What each request carries: `Authorization`'s value, or nothing for a
    /// certificate the handshake presents; `Err` for a value the header
    /// cannot carry.
    fn authorization(&self) -> Result<Option<HeaderValue>, ()> {
        match self {
            Self::Handshake => Ok(None),
            _ => self.header().map(Some).ok_or(()),
        }
    }

    /// `Authorization`'s value, marked sensitive: `None` for a value it
    /// cannot carry, and for a certificate. A user with a colon, which Basic
    /// cannot tell from the password; a token that is empty, or holds a
    /// space, a control character or a byte that is not ASCII.
    pub(crate) fn header(&self) -> Option<HeaderValue> {
        let raw = match self {
            Self::Handshake => return None,
            Self::Basic { user, password } => {
                if user.contains(':') {
                    return None;
                }
                let pair = Zeroizing::new(format!("{}:{}", user.as_str(), password.as_str()));
                let encoded = Zeroizing::new(
                    base64::engine::general_purpose::STANDARD.encode(pair.as_bytes()),
                );
                Zeroizing::new(format!("Basic {}", encoded.as_str()))
            }
            Self::Bearer(token) => {
                if token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic()) {
                    return None;
                }
                Zeroizing::new(format!("Bearer {}", token.as_str()))
            }
        };
        let mut value = HeaderValue::from_str(&raw).ok()?;
        value.set_sensitive(true);
        Some(value)
    }
}

/// Where the proxy sends a connection's requests, and with what.
pub(crate) struct Upstream {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) credential: Credential,
    pub(crate) tls: tokio_rustls::TlsConnector,
    /// The endpoint's own origin, such as `http://127.0.0.1:<port>`: where a
    /// redirect to the upstream is pointed back to.
    pub(crate) front: String,
    /// P3-5e-1 — what the endpoint stands for.
    pub(crate) flavor: Flavor,
}

impl Upstream {
    /// The upstream's authority, as `Host` names it: an IPv6 address in
    /// brackets, and the port only where it is not 443.
    fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == 443 {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

/// P3-5e-1 — a connection that switched protocols: the two ends joined,
/// carried by the client connection's own future so it ends with it.
type Tunnel = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

/// Serve one client connection until it ends: each request sent on to the
/// upstream with the credential, each response streamed back, and (P3-5e-1)
/// an upgraded connection carried as a tunnel until it closes. Whoever
/// drops this future ends both.
pub(crate) async fn serve<C>(client: C, up: &Upstream) -> Result<(), String>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let host = HeaderValue::from_str(&up.authority()).map_err(|e| e.to_string())?;
    let authorization = up.credential.authorization();
    // The connection's upstream leg, between its requests: hyper serves a
    // connection's requests one at a time, so it is taken out while one is
    // sent and put back with its response.
    let leg = Mutex::new(None::<Leg>);
    let tunnel = Mutex::new(None::<Tunnel>);
    let service = hyper::service::service_fn(|req| {
        let (host, authorization, leg, tunnel) = (&host, &authorization, &leg, &tunnel);
        async move { Ok::<_, Infallible>(forward(req, up, host, authorization, leg, tunnel).await) }
    });
    let served = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_DEADLINE)
        .serve_connection(TokioIo::new(client), service)
        .with_upgrades()
        .await;
    // The connection was handed over to an upgrade: carry it here.
    let switched = tunnel.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(switched) = switched {
        switched.await;
    }
    served.map_err(|e| e.to_string())
}

/// Tell a client why it is not served: its first request answered `503`
/// with the reason, and the connection closed.
pub(crate) async fn refuse<C>(client: C, why: &str) -> Result<(), String>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let service = hyper::service::service_fn(|_: Request<Incoming>| async move {
        Ok::<_, Infallible>(answer(StatusCode::SERVICE_UNAVAILABLE, why))
    });
    hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_DEADLINE)
        .keep_alive(false)
        .serve_connection(TokioIo::new(client), service)
        .await
        .map_err(|e| e.to_string())
}

/// One request, sent on and answered; or refused, with why.
async fn forward(
    mut req: Request<Incoming>,
    up: &Upstream,
    host: &HeaderValue,
    authorization: &Result<Option<HeaderValue>, ()>,
    leg: &Mutex<Option<Leg>>,
    tunnel: &Mutex<Option<Tunnel>>,
) -> Response<Body> {
    let Ok(authorization) = authorization else {
        return answer(
            StatusCode::BAD_GATEWAY,
            "the secret's value is not one an Authorization header can carry",
        );
    };
    // P3-5e-1 — an upgrade a Kubernetes endpoint relays, taken before the
    // request is rewritten.
    let upgrade = match up.flavor {
        Flavor::Kubernetes => upgrade_of(req.headers()),
        Flavor::Plain => None,
    };
    let near = upgrade.is_some().then(|| hyper::upgrade::on(&mut req));
    let mut req = match outbound(req, host, authorization.as_ref(), up.flavor) {
        Ok(req) => req,
        Err(status) => return answer(status, NOT_A_PROXY),
    };
    if let (Some(protocol), Some(near)) = (upgrade, near) {
        req.headers_mut().insert(header::UPGRADE, protocol);
        req.headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
        return switch(req, up, near, tunnel).await;
    }
    let held = leg.lock().unwrap_or_else(|e| e.into_inner()).take();
    match send(held, req, up).await {
        Ok((resp, kept)) => {
            *leg.lock().unwrap_or_else(|e| e.into_inner()) = Some(kept);
            inbound(resp, up)
        }
        Err(why) => answer(StatusCode::BAD_GATEWAY, &why),
    }
}

/// P3-5e-1 — send an upgrade on a connection of its own. Where the upstream
/// switches (`101`), the two ends are joined as the client connection's
/// tunnel and the response goes back with the upgrade's headers; any other
/// answer goes back as it came.
async fn switch(
    req: Request<Incoming>,
    up: &Upstream,
    near: hyper::upgrade::OnUpgrade,
    tunnel: &Mutex<Option<Tunnel>>,
) -> Response<Body> {
    let mut send = match dial_once(up).await {
        Ok(send) => send,
        Err(why) => return answer(StatusCode::BAD_GATEWAY, &why),
    };
    let mut resp = match send.send_request(req).await {
        Ok(resp) => resp,
        Err(e) => {
            return answer(StatusCode::BAD_GATEWAY, &format!("{}: {e}", up.authority()));
        }
    };
    if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        return inbound(resp, up);
    }
    let far = hyper::upgrade::on(&mut resp);
    let protocol = resp.headers().get(header::UPGRADE).cloned();
    let joined: Tunnel = Box::pin(async move {
        let (Ok(near), Ok(far)) = tokio::join!(near, far) else {
            return;
        };
        let (mut near, mut far) = (TokioIo::new(near), TokioIo::new(far));
        if let Err(e) = tokio::io::copy_bidirectional(&mut near, &mut far).await {
            debug!(%e, "vault: an upgraded proxy connection ended with an error");
        }
    });
    *tunnel.lock().unwrap_or_else(|e| e.into_inner()) = Some(joined);
    let mut out = inbound(resp, up);
    out.headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
    if let Some(protocol) = protocol {
        out.headers_mut().insert(header::UPGRADE, protocol);
    }
    out
}

/// P3-5e-1 — the protocol a request asks to switch to, where it is one
/// `kubectl` streams over: `SPDY/3.1`, or `websocket` (from Kubernetes
/// 1.30). Any other (`h2c` among them) is never relayed.
fn upgrade_of(headers: &HeaderMap) -> Option<HeaderValue> {
    let asked = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case("upgrade"));
    let protocol = headers.get(header::UPGRADE)?;
    let known = protocol
        .to_str()
        .is_ok_and(|p| p.eq_ignore_ascii_case("websocket") || p.eq_ignore_ascii_case("SPDY/3.1"));
    (asked && known).then(|| protocol.clone())
}

/// P3-5e-1 — drop every impersonation header: the session acts as the
/// secret's identity, never through it as another (`kubectl --as`),
/// whatever that identity's RBAC allows.
fn impersonation(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .keys()
        .filter(|n| {
            let n = n.as_str();
            matches!(
                n,
                "impersonate-user" | "impersonate-group" | "impersonate-uid"
            ) || n.starts_with("impersonate-extra-")
        })
        .cloned()
        .collect();
    for name in named {
        headers.remove(name);
    }
}

/// The request as the upstream gets it: or the status that refuses one
/// that is not for a path on the upstream.
fn outbound(
    req: Request<Incoming>,
    host: &HeaderValue,
    authorization: Option<&HeaderValue>,
    flavor: Flavor,
) -> Result<Request<Incoming>, StatusCode> {
    if req.method() == Method::CONNECT {
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }
    let uri = req.uri();
    let path = match (uri.scheme(), uri.authority(), uri.path_and_query()) {
        (None, None, Some(pq)) if pq.as_str().starts_with('/') => pq.clone(),
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    let (mut parts, body) = req.into_parts();
    parts.uri = Uri::from(path);
    parts.version = hyper::Version::HTTP_11;
    parts.extensions = Default::default();
    hop_by_hop(&mut parts.headers);
    // The client's own credentials never leave: the endpoint is its
    // credential, and the secret's goes in their place.
    for name in [header::AUTHORIZATION, header::HOST, header::EXPECT] {
        parts.headers.remove(name);
    }
    if flavor == Flavor::Kubernetes {
        impersonation(&mut parts.headers);
    }
    parts.headers.insert(header::HOST, host.clone());
    if let Some(authorization) = authorization {
        parts
            .headers
            .insert(header::AUTHORIZATION, authorization.clone());
    }
    Ok(Request::from_parts(parts, body))
}

/// The upstream's response as the client gets it.
fn inbound(resp: Response<Incoming>, up: &Upstream) -> Response<Body> {
    let (mut parts, body) = resp.into_parts();
    hop_by_hop(&mut parts.headers);
    parts.headers.remove(header::ALT_SVC);
    parts.headers.remove(header::STRICT_TRANSPORT_SECURITY);
    if let Some(back) = parts
        .headers
        .get(header::LOCATION)
        .and_then(|l| point_back(l, up))
    {
        parts.headers.insert(header::LOCATION, back);
    }
    Response::from_parts(parts, body.map_err(BoxError::from).boxed())
}

/// Drop the hop-by-hop headers, and those `Connection` names: they are one
/// leg's, never the next one's (RFC 9110 §7.6.1). `Proxy-Authorization`
/// among them, so a client's never leaves.
fn hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|n| HeaderName::from_bytes(n.trim().as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in [
        header::CONNECTION,
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-connection"),
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
        header::TE,
        header::TRAILER,
        header::TRANSFER_ENCODING,
        header::UPGRADE,
    ] {
        headers.remove(name);
    }
}

/// A redirect to the upstream's own origin, pointed back at the endpoint so
/// it stays authenticated: `None` for one anywhere else, which the client
/// follows with no value. The origin is matched whole (`https`, the host,
/// the port), never as a prefix: `https://host.elsewhere` is not `https://host`.
fn point_back(location: &HeaderValue, up: &Upstream) -> Option<HeaderValue> {
    let raw = location.to_str().ok()?;
    let (head, fragment) = raw.split_at(raw.find('#').unwrap_or(raw.len()));
    let uri: Uri = head.parse().ok()?;
    let authority = uri.authority()?;
    let host = authority.host();
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let ours = uri
        .scheme_str()
        .is_some_and(|s| s.eq_ignore_ascii_case("https"))
        && !authority.as_str().contains('@')
        && host.eq_ignore_ascii_case(&up.host)
        && authority.port_u16().unwrap_or(443) == up.port;
    if !ours {
        return None;
    }
    let path = uri.path_and_query().map_or("/", |p| p.as_str());
    let slash = if path.starts_with('/') { "" } else { "/" };
    HeaderValue::from_str(&format!("{}{slash}{path}{fragment}", up.front)).ok()
}

/// The endpoint's own answer: `status`, and why, as plain text.
fn answer(status: StatusCode, why: &str) -> Response<Body> {
    let body = Full::new(Bytes::from(format!("{why}\n")))
        .map_err(|never| match never {})
        .boxed();
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

/// One client connection's upstream leg.
struct Leg {
    send: SendRequest<Incoming>,
    /// The connection's own task, ended with the leg.
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Leg {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Send `req` on `held`, or on a new leg where there is none or the
/// upstream has closed it; once more on a new one if the upstream closed it
/// before the request went out. Answers the response and the leg to keep.
async fn send(
    mut held: Option<Leg>,
    mut req: Request<Incoming>,
    up: &Upstream,
) -> Result<(Response<Incoming>, Leg), String> {
    for _ in 0..2 {
        let mut leg = match held.take() {
            Some(mut leg) => match leg.send.ready().await {
                Ok(()) => leg,
                Err(_) => dial(up).await?,
            },
            None => dial(up).await?,
        };
        match leg.send.try_send_request(req).await {
            Ok(resp) => return Ok((resp, leg)),
            Err(mut e) => match e.take_message() {
                // Never written: the upstream closed the leg first.
                Some(back) => req = back,
                None => return Err(format!("{}: {}", up.authority(), e.into_error())),
            },
        }
    }
    Err(format!(
        "{} closed every connection before the request went out",
        up.authority()
    ))
}

/// TCP, then TLS verified, within the deadline.
async fn connect(up: &Upstream) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let name = tls::server_name(&up.host)?;
    let connected = async {
        let tcp = TcpStream::connect((up.host.as_str(), up.port))
            .await
            .map_err(|e| format!("{}: {e}", up.authority()))?;
        up.tls
            .connect(name, tcp)
            .await
            .map_err(|e| format!("TLS to {}: {e}", up.host))
    };
    tokio::time::timeout(CONNECT_DEADLINE, connected)
        .await
        .map_err(|_| {
            format!(
                "{} did not answer within {CONNECT_DEADLINE:?}",
                up.authority()
            )
        })?
}

/// A new leg: TCP, TLS verified, an HTTP/1.1 handshake.
async fn dial(up: &Upstream) -> Result<Leg, String> {
    let stream = connect(up).await?;
    let (send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| format!("{}: {e}", up.authority()))?;
    let task = tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!(%e, "vault: an HTTP proxy's upstream connection ended with an error");
        }
    });
    Ok(Leg { send, task })
}

/// P3-5e-1 — a connection for one upgrade. Its task runs until it hands the
/// connection over to the upgrade, or the connection ends; never kept as a
/// leg, since a switched connection carries no more requests.
async fn dial_once(up: &Upstream) -> Result<SendRequest<Incoming>, String> {
    let stream = connect(up).await?;
    let (send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| format!("{}: {e}", up.authority()))?;
    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            debug!(%e, "vault: an upgraded proxy's upstream connection ended with an error");
        }
    });
    Ok(send)
}

#[cfg(test)]
mod tests;
