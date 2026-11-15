// SPDX-License-Identifier: MPL-2.0
//! GUI user identity is separate from a machine enrollment. Never persisted in
//! AgentConfig, never inferred from owner/tenant/device JWTs.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::time::Duration;
pub mod vault;

#[derive(Debug)]
pub struct SessionDenied(pub u16);
impl std::fmt::Display for SessionDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "User session is no longer valid (HTTP {}); sign in again",
            self.0
        )
    }
}
impl std::error::Error for SessionDenied {}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct UserProfile {
    pub id: String,
    pub email: String,
    pub email_verified: bool,
}
impl UserProfile {
    pub fn validate(&self) -> Result<()> {
        let Some((local, domain)) = self.email.rsplit_once('@') else {
            bail!("a verified account email is required");
        };
        if self.id.is_empty()
            || !self.email_verified
            || local.is_empty()
            || !domain.contains('.')
            || domain.eq_ignore_ascii_case("invalid")
            || domain.to_ascii_lowercase().ends_with(".invalid")
            || self
                .email
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
        {
            bail!("a genuine verified account email is required; sign in again");
        }
        Ok(())
    }
}

#[derive(Deserialize)]
pub struct NativeSession {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub user: UserProfile,
}
impl std::fmt::Debug for NativeSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSession")
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}
impl NativeSession {
    pub fn validate(&self) -> Result<()> {
        self.user.validate()?;
        if self.access_token.is_empty() || self.refresh_token.is_empty() || self.expires_in == 0 {
            bail!("invalid native user authorization");
        }
        Ok(())
    }
}

/// HTTPS origin and deployment-prefix scope. Literal loopback HTTP is reserved
/// for isolated tests/development, never a hostname merely resolving locally.
pub fn trusted_base(server: &str) -> Result<reqwest::Url> {
    let mut url: reqwest::Url = server.parse().context("invalid account server")?;
    let loopback = url
        .host_str()
        .and_then(|s| s.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback());
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
    {
        bail!("account authorization requires a trusted HTTPS server");
    }
    url.set_path(url.path().trim_end_matches('/').to_owned().as_str());
    Ok(url)
}

fn endpoint(server: &str, route: &str) -> Result<reqwest::Url> {
    let mut url = trusted_base(server)?;
    url.set_path(&format!("{}{}", url.path().trim_end_matches('/'), route));
    Ok(url)
}

fn http() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

pub async fn refresh(server: &str, refresh_token: &str) -> Result<NativeSession> {
    let reply = http()?
        .post(endpoint(server, "/api/auth/refresh")?)
        .json(&serde_json::json!({"refresh_token":refresh_token}))
        .send()
        .await
        .context("account server is unavailable; session state unknown")?;
    let status = reply.status();
    if matches!(status.as_u16(), 401 | 403) {
        return Err(SessionDenied(status.as_u16()).into());
    }
    if !status.is_success() {
        bail!(
            "user session refresh refused (HTTP {}); sign in again",
            status.as_u16()
        );
    }
    let session: NativeSession = reply
        .json()
        .await
        .context("invalid user session response")?;
    session.validate()?;
    Ok(session)
}

pub async fn revoke(server: &str, access_token: &str) -> Result<()> {
    let reply = http()?
        .post(endpoint(server, "/api/native/session/revoke")?)
        .bearer_auth(access_token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .context("cannot revoke session while account server is unavailable")?;
    if matches!(reply.status().as_u16(), 401 | 403) {
        return Err(SessionDenied(reply.status().as_u16()).into());
    }
    if reply.status().as_u16() != 204 {
        bail!(
            "session revocation not confirmed (HTTP {})",
            reply.status().as_u16()
        );
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "purpose", rename_all = "snake_case")]
pub enum WebTarget {
    Remote { tenant_id: String, agent_id: String },
    DeviceShareRemote { share_id: String },
    MyDevices,
    DeviceSharesSent,
    DeviceSharesReceived,
    Dashboard,
}
impl WebTarget {
    pub fn validate(&self) -> Result<()> {
        if let Self::DeviceShareRemote { share_id } = self
            && (share_id.len() != 24 || !share_id.bytes().all(|c| c.is_ascii_hexdigit()))
        {
            bail!("invalid shared device target identity");
        }
        if let Self::Remote {
            tenant_id,
            agent_id,
        } = self
        {
            let oid = |s: &str| s.len() == 24 && s.bytes().all(|c| c.is_ascii_hexdigit());
            if !oid(tenant_id) || !oid(agent_id) {
                bail!("invalid remote target identity");
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
pub struct Handoff {
    pub ticket: String,
    pub post_url: String,
    pub expires_in: u64,
}
impl std::fmt::Debug for Handoff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Handoff { credentials: <redacted> }")
    }
}

pub async fn handoff(
    server: &str,
    access_token: &str,
    target: &WebTarget,
    port: u16,
) -> Result<Handoff> {
    target.validate()?;
    if port == 0 {
        bail!("handoff listener is not bound");
    }
    let mut body = serde_json::to_value(target)?;
    body["form_origin"] = format!("http://127.0.0.1:{port}").into();
    let reply = http()?
        .post(endpoint(server, "/api/native/handoff")?)
        .bearer_auth(access_token)
        .json(&body)
        .send()
        .await
        .context("account handoff server unavailable")?;
    if !reply.status().is_success() {
        bail!("account handoff refused (HTTP {})", reply.status().as_u16());
    }
    let handoff: Handoff = reply.json().await.context("invalid account handoff")?;
    // Exact route, not starts_with: even a same-host path outside this
    // deployment prefix must not receive the one-use authorization ticket.
    if reqwest::Url::parse(&handoff.post_url)? != endpoint(server, "/api/native/handoff/consume")?
        || handoff.ticket.is_empty()
        || handoff.expires_in == 0
        || handoff.expires_in > 60
    {
        bail!("unsafe or expired account handoff response");
    }
    Ok(handoff)
}

/// A private listener is bound BEFORE the server authorizes this exact form
/// Origin. The launch URL contains no session credential or handoff ticket.
pub struct BrowserHandoff {
    listener: tokio::net::TcpListener,
    route: String,
    host: String,
}
impl BrowserHandoff {
    pub async fn bind() -> Result<Self> {
        use base64::Engine;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let host = listener.local_addr()?.to_string();
        let route = format!(
            "/open/{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
        );
        Ok(Self {
            listener,
            route,
            host,
        })
    }
    pub fn port(&self) -> Result<u16> {
        Ok(self.listener.local_addr()?.port())
    }
    pub fn launch_url(&self) -> String {
        format!("http://{}{}", self.host, self.route)
    }
    pub fn serve(self, handoff: Handoff) -> tokio::task::JoinHandle<Result<()>> {
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let deadline = tokio::time::Instant::now() + Duration::from_secs(handoff.expires_in);
            // Invalid probes cannot consume the ticket; all reads and the
            // listener itself are bounded, with no persistent HTTP framework.
            loop {
                let (mut stream, peer) = tokio::time::timeout_at(deadline, self.listener.accept())
                    .await
                    .context("account handoff expired before browser opened")??;
                if !peer.ip().is_loopback() {
                    continue;
                }
                let mut request = Vec::new();
                let read = tokio::time::timeout(Duration::from_secs(2), async {
                    while request.len() < 8192 && !request.ends_with(b"\r\n\r\n") {
                        request.push(stream.read_u8().await?);
                    }
                    Ok::<_, std::io::Error>(())
                })
                .await;
                let valid = matches!(read, Ok(Ok(())))
                    && valid_loopback_request(&request, &self.route, &self.host);
                if !valid {
                    let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                    continue;
                }
                let html = handoff_html(&handoff);
                // CSP permits the trusted server's fixed 303 landing. The
                // form action was separately validated against the exact
                // deployment-prefix consume endpoint before serving it.
                // Origin-only referrer policy hides the random launch path
                // while preserving the POST Origin binding. no-referrer makes
                // real Chromium form navigation send Origin:null and must NOT
                // be "fixed" by relaxing the server's Origin check.
                let form_origin = reqwest::Url::parse(&handoff.post_url)?
                    .origin()
                    .ascii_serialization();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nReferrer-Policy: origin\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; form-action {}; frame-ancestors 'none'; base-uri 'none'\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    form_origin,
                    html.len(),
                    html
                );
                stream.write_all(response.as_bytes()).await?;
                stream.shutdown().await?;
                return Ok(());
            }
        })
    }
}

fn valid_loopback_request(bytes: &[u8], route: &str, host: &str) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut lines = text.split("\r\n");
    if lines.next() != Some(format!("GET {route} HTTP/1.1").as_str()) {
        return false;
    }
    let mut hosts = 0;
    for line in lines.take_while(|s| !s.is_empty()) {
        let Some((key, value)) = line.split_once(':') else {
            return false;
        };
        if key.eq_ignore_ascii_case("host") {
            hosts += 1;
            if value.trim() != host {
                return false;
            }
        }
        if key.eq_ignore_ascii_case("origin") && value.trim() != format!("http://{host}") {
            return false;
        }
        if key.eq_ignore_ascii_case("sec-fetch-site") && value.trim() == "cross-site" {
            return false;
        }
    }
    hosts == 1 && text.ends_with("\r\n\r\n")
}
fn handoff_html(handoff: &Handoff) -> String {
    let escape = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
    };
    format!(
        "<!doctype html><meta charset=utf-8><meta name=referrer content=origin><title>Signing in to MeshHarbor</title><form method=post action=\"{}\"><input type=hidden name=ticket value=\"{}\"><noscript><button>Continue to MeshHarbor</button></noscript></form><script>document.forms[0].submit()</script>",
        escape(&handoff.post_url),
        escape(&handoff.ticket)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_never_treats_enrollment_or_placeholder_as_user_login() {
        assert!(
            UserProfile {
                id: "owner".into(),
                email: "owner@meshharbor.invalid".into(),
                email_verified: true
            }
            .validate()
            .is_err()
        );
        assert!(
            UserProfile {
                id: "user".into(),
                email: "person@example.com".into(),
                email_verified: false
            }
            .validate()
            .is_err()
        );
        assert!(
            UserProfile {
                id: "user".into(),
                email: "person@example.com".into(),
                email_verified: true
            }
            .validate()
            .is_ok()
        );
    }
    #[test]
    fn secret_debug_and_origin_prefix_are_bounded() {
        let session = NativeSession {
            access_token: "ACCESS_SECRET".into(),
            refresh_token: "REFRESH_SECRET".into(),
            expires_in: 60,
            user: UserProfile {
                id: "u".into(),
                email: "person@example.com".into(),
                email_verified: true,
            },
        };
        assert!(!format!("{session:?}").contains("SECRET"));
        for url in [
            "http://example.com",
            "https://u:p@example.com",
            "https://example.com?token=x",
            "https://example.com/#x",
        ] {
            assert!(trusted_base(url).is_err());
        }
        assert_eq!(
            endpoint("https://example.com/base", "/api/native/handoff/consume")
                .unwrap()
                .as_str(),
            "https://example.com/base/api/native/handoff/consume"
        );
    }

    #[tokio::test]
    async fn browser_handoff_is_single_use_strict_host_and_body_only() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = BrowserHandoff::bind().await.unwrap();
        let url = listener.launch_url();
        let parsed = reqwest::Url::parse(&url).unwrap();
        assert!(!url.contains("fixture_ticket"));
        let port = listener.port().unwrap();
        let handle = listener.serve(Handoff {
            ticket: "fixture_ticket<'\"&".into(),
            post_url: "https://example.com/base/api/native/handoff/consume".into(),
            expires_in: 5,
        });
        let request =
            |host: &str| format!("GET {} HTTP/1.1\r\nHost: {host}\r\n\r\n", parsed.path());
        let mut denied = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        denied
            .write_all(request("evil.test").as_bytes())
            .await
            .unwrap();
        let mut bytes = Vec::new();
        denied.read_to_end(&mut bytes).await.unwrap();
        assert!(
            String::from_utf8(bytes)
                .unwrap()
                .starts_with("HTTP/1.1 404")
        );
        let mut accepted = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        accepted
            .write_all(request(&format!("127.0.0.1:{port}")).as_bytes())
            .await
            .unwrap();
        let mut bytes = Vec::new();
        accepted.read_to_end(&mut bytes).await.unwrap();
        let html = String::from_utf8(bytes).unwrap();
        assert!(html.starts_with("HTTP/1.1 200"));
        assert!(html.contains("method=post"));
        assert!(html.contains("fixture_ticket&lt;&#39;&quot;&amp;"));
        assert!(!html.contains("access_token"));
        assert!(!html.contains("refresh_token"));
        handle.await.unwrap().unwrap();
        assert!(
            tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_err()
        );
    }

    #[test]
    fn loopback_rejects_rebinding_duplicate_host_foreign_origin_and_wrong_route() {
        for headers in [
            "Host: evil.test",
            "Host: 127.0.0.1:1\r\nHost: 127.0.0.1:1",
            "Host: 127.0.0.1:1\r\nOrigin: https://evil.test",
            "Host: 127.0.0.1:1\r\nSec-Fetch-Site: cross-site",
        ] {
            assert!(!valid_loopback_request(
                format!("GET /open/nonce HTTP/1.1\r\n{headers}\r\n\r\n").as_bytes(),
                "/open/nonce",
                "127.0.0.1:1"
            ));
        }
        assert!(!valid_loopback_request(
            b"GET /open/wrong HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n",
            "/open/nonce",
            "127.0.0.1:1"
        ));
    }

    async fn http_fixture(
        body: serde_json::Value,
        status: u16,
    ) -> (String, tokio::task::JoinHandle<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/base", listener.local_addr().unwrap());
        let body = body.to_string().replace(
            "FIXTURE_ORIGIN",
            &format!("http://{}", listener.local_addr().unwrap()),
        );
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            while !bytes.ends_with(b"\r\n\r\n") {
                bytes.push(stream.read_u8().await.unwrap());
            }
            let headers = String::from_utf8(bytes).unwrap();
            let length = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':')
                        .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                        .map(|(_, v)| v.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes).await.unwrap();
            stream.write_all(format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
            format!("{headers}{}", String::from_utf8(bytes).unwrap())
        });
        (url, task)
    }

    #[tokio::test]
    async fn refresh_denial_is_explicit_and_handoff_rejects_wrong_origin_or_prefix() {
        let (server, task) = http_fixture(serde_json::json!({"error":"revoked"}), 401).await;
        assert!(
            refresh(&server, "fixture_refresh")
                .await
                .unwrap_err()
                .downcast_ref::<SessionDenied>()
                .is_some()
        );
        let request = task.await.unwrap();
        assert!(request.starts_with("POST /base/api/auth/refresh "));
        assert!(request.contains("\"refresh_token\":\"fixture_refresh\""));
        for url in [
            "https://evil.example/api/native/handoff/consume",
            "FIXTURE_ORIGIN/base-evil/api/native/handoff/consume",
        ] {
            let (server, task) = http_fixture(
                serde_json::json!({"ticket":"fixture_ticket","post_url":url,"expires_in":60}),
                200,
            )
            .await;
            assert!(
                handoff(&server, "fixture_access", &WebTarget::Dashboard, 12345)
                    .await
                    .is_err()
            );
            let request = task.await.unwrap();
            assert!(request.contains("\"purpose\":\"dashboard\""));
            assert!(request.contains("\"form_origin\":\"http://127.0.0.1:12345\""));
            assert!(!request.lines().next().unwrap().contains("fixture_access"));
        }
    }

    /// Explicit opt-in harness only: fresh headless browser, synthetic ticket,
    /// loopback servers. Never attaches to the user's browser or OS vault.
    #[tokio::test]
    #[ignore = "requires isolated headless browser script in task runtime"]
    async fn browser_form_posts_origin_and_follows_cookie_landing() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let script = std::env::var("MESHHARBOR_HANDOFF_BROWSER_TEST_SCRIPT")
            .expect("explicit isolated browser harness required");
        let listener = BrowserHandoff::bind().await.unwrap();
        let expected_origin = format!("http://127.0.0.1:{}", listener.port().unwrap());
        let url = listener.launch_url();
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        let owner = listener.serve(Handoff {
            ticket: "synthetic-ticket".into(),
            post_url: format!("http://127.0.0.1:{port}/base/api/native/handoff/consume"),
            expires_in: 30,
        });
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = server.accept().await.unwrap();
            let mut bytes = Vec::new();
            while !bytes.ends_with(b"\r\n\r\n") {
                bytes.push(stream.read_u8().await.unwrap());
                assert!(bytes.len() < 8192);
            }
            let headers = String::from_utf8(bytes).unwrap();
            assert!(headers.starts_with("POST /base/api/native/handoff/consume HTTP/1.1"));
            println!(
                "Synthetic browser POST Origin: {:?}",
                headers
                    .lines()
                    .find(|line| line.to_ascii_lowercase().starts_with("origin:"))
            );
            assert!(
                headers
                    .lines()
                    .any(|line| line
                        .split_once(':')
                        .is_some_and(|(k, v)| k.eq_ignore_ascii_case("origin")
                            && v.trim() == expected_origin))
            );
            let length = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':')
                        .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                        .map(|(_, v)| v.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            let mut body = vec![0; length];
            stream.read_exact(&mut body).await.unwrap();
            assert_eq!(body, b"ticket=synthetic-ticket");
            stream.write_all(b"HTTP/1.1 303 See Other\r\nLocation: /base/native-session-complete?handoff_id=public-fixture\r\nSet-Cookie: fixture_session=accepted; HttpOnly; SameSite=Lax; Path=/base\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
            stream.shutdown().await.unwrap();
            let (mut stream, _) = server.accept().await.unwrap();
            let mut bytes = Vec::new();
            while !bytes.ends_with(b"\r\n\r\n") {
                bytes.push(stream.read_u8().await.unwrap());
                assert!(bytes.len() < 8192);
            }
            let headers = String::from_utf8(bytes).unwrap();
            assert!(headers.starts_with(
                "GET /base/native-session-complete?handoff_id=public-fixture HTTP/1.1"
            ));
            assert!(headers.contains("fixture_session=accepted"));
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\nConnection: close\r\n\r\nHANDOFF_READY").await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let output = tokio::process::Command::new("node")
            .arg(script)
            .env("HANDOFF_TEST_URL", url)
            .output()
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        tokio::time::timeout(Duration::from_secs(10), server_task)
            .await
            .unwrap()
            .unwrap();
        owner.await.unwrap().unwrap();
    }
}
