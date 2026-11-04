// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! #2187 — the control WS and DERP dial through `tunnel_core::ctl_dns`.
//!
//! `connect_async(url)` resolves the URL's host on every attempt through the OS
//! resolver, and with an exit's DNS steer in force that means through the exit.
//! An exit whose DNS stops answering while its carrier stays up is never torn
//! down, so a control WS that dropped could not reconnect at all: every attempt
//! waited out the resolver and failed, and the device stayed offline for as long
//! as the exit's DNS did.
//!
//! [`connect`] dials the remembered address instead and hands the URL itself to
//! the handshake, so TLS still verifies the server's NAME (SNI and certificate)
//! and the `Host` header is unchanged. Only where the address comes from moves.

use std::net::IpAddr;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::{self, handshake::client::Response, http::Uri};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, client_async_tls_with_config, connect_async,
};

pub type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// One address's TCP connect; the caller's own timeout bounds the whole dial.
const PER_ADDR_CONNECT: Duration = Duration::from_secs(10);

/// `connect_async`, with the host's address from `ctl_dns`. An address literal,
/// or a name nothing knows, takes `connect_async`'s own path unchanged.
pub async fn connect(url: &str) -> Result<(Ws, Response), tungstenite::Error> {
    let Some((host, port)) = host_port(url) else {
        return connect_async(url).await;
    };
    if host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok() {
        return connect_async(url).await;
    }
    let hostport = tunnel_core::ctl_dns::hostport(&host, port);
    let addrs = tunnel_core::ctl_dns::resolve(&hostport).await;
    if addrs.is_empty() {
        return connect_async(url).await;
    }
    let mut last = None;
    for addr in &addrs {
        match tokio::time::timeout(PER_ADDR_CONNECT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let done = client_async_tls_with_config(url, stream, None, None).await;
                // An HTTP answer (a 401, say) proves the address; anything else
                // may be a server that moved, so look again behind the caller.
                if let Err(e) = &done
                    && !matches!(e, tungstenite::Error::Http(_))
                {
                    tunnel_core::ctl_dns::distrust(&hostport);
                }
                return done;
            }
            Ok(Err(e)) => last = Some(e),
            Err(_) => {
                last = Some(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("connect to {addr} timed out"),
                ))
            }
        }
    }
    // Every remembered address failed: the next attempt gets a fresh look.
    tunnel_core::ctl_dns::distrust(&hostport);
    Err(tungstenite::Error::Io(last.unwrap_or_else(|| {
        std::io::Error::other("no address to dial")
    })))
}

/// Host and port of a `ws(s)://` URL, the scheme's default port when it has none.
fn host_port(url: &str) -> Option<(String, u16)> {
    let uri: Uri = url.parse().ok()?;
    let host = uri.host()?.to_string();
    let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
        Some("wss") | Some("https") => 443,
        _ => 80,
    });
    Some((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    #[test]
    fn host_port_reads_the_url() {
        assert_eq!(
            host_port("wss://roomler.ai/ws?token=x&role=agent&tid=y"),
            Some(("roomler.ai".into(), 443))
        );
        assert_eq!(
            host_port("ws://relay.example:8080/derp"),
            Some(("relay.example".into(), 8080))
        );
        assert_eq!(host_port("not a url"), None);
    }

    /// #2187 — the field case in one process: a name the resolver can never
    /// answer (`.invalid`, RFC 2606), remembered from before. The dial goes to
    /// the remembered address and the handshake still carries the NAME, which
    /// the server sees in its `Host` header.
    #[tokio::test]
    // tungstenite's handshake `Callback` fixes the closure's error type.
    #[allow(clippy::result_large_err)]
    async fn a_remembered_name_connects_when_the_resolver_cannot_answer() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();
        let host_seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let seen = std::sync::Arc::clone(&host_seen);
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let cb = |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                      resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
                if let Some(h) = req.headers().get("host") {
                    *seen.lock().unwrap() = h.to_str().unwrap_or("").to_string();
                }
                Ok(resp)
            };
            let mut ws = tokio_tungstenite::accept_hdr_async(stream, cb)
                .await
                .unwrap();
            ws.send(Message::Text("hello".into())).await.unwrap();
        });

        let hostport = format!("ctl-dns-2187.invalid:{}", local.port());
        tunnel_core::ctl_dns::remember(&hostport, &[local]);
        let url = format!("ws://{hostport}/ws");
        let (mut ws, _) = tokio::time::timeout(Duration::from_secs(10), connect(&url))
            .await
            .expect("must not wait on the resolver")
            .expect("connects to the remembered address");
        let first = ws.next().await.unwrap().unwrap();
        assert_eq!(first, Message::Text("hello".into()));
        assert_eq!(*host_seen.lock().unwrap(), hostport, "Host keeps the name");
    }
}
