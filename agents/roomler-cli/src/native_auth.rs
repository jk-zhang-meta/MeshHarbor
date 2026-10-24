// SPDX-License-Identifier: MPL-2.0
//! One-shot native shared-SSH password proof. No browser session export, refresh,
//! storage or new audience: the in-memory Access JWT has general account powers.
use anyhow::{Result, bail};
use serde::{Deserialize, de::DeserializeOwned};
use std::time::Duration;
const MAX_BODY: usize = 32 * 1024;

pub(crate) fn server_base(raw: &str) -> Result<String> {
    let mut url = reqwest::Url::parse(raw).map_err(|_| anyhow::anyhow!("Invalid server URL"))?;
    // HTTP is test-only literal loopback, never a DNS name (even localhost).
    let loopback = url.host_str().is_some_and(|h| {
        h.trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    });
    if !matches!(url.scheme(), "https") && !(url.scheme() == "http" && loopback) {
        bail!("Native authentication requires HTTPS (only literal loopback IP HTTP is allowed)");
    }
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path().contains('%')
        || url.path().contains("//")
    {
        bail!("Server URL must have an unambiguous prefix and no userinfo/query/fragment");
    }
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(&path);
    Ok(url.to_string().trim_end_matches('/').to_owned())
}
/// Pure normalization: never log raw input before rejecting embedded secrets.
pub(crate) fn legacy_server_base(raw: &str) -> Result<String> {
    let secured = roomler_ai_remote_control::server_url::secure(raw, false);
    server_base(&secured.url)
}
pub(crate) fn http_client(server: &str) -> Result<reqwest::Client> {
    let server = server_base(server)?;
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(6));
    // A literal local HTTP request must not escape through HTTP_PROXY/ALL_PROXY.
    // Do not change HTTPS operators' configured proxy behavior.
    if server.starts_with("http://") {
        builder = builder.no_proxy();
    }
    Ok(builder.build()?)
}
pub(crate) async fn bounded_json<T: DeserializeOwned>(
    mut response: reqwest::Response,
) -> Result<T> {
    if response
        .content_length()
        .is_some_and(|n| n > MAX_BODY as u64)
    {
        bail!("Server response exceeds native authentication limit");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow::anyhow!("Reading bounded server response failed"))?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_BODY {
            bail!("Server response exceeds native authentication limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("Invalid bounded server response"))
}
#[derive(Deserialize)]
struct LoginResponse {
    access_token: String,
    expires_in: u64,
    user_id: String,
}
/// Caller supplies a secret in memory only. Never Debug/Serialize the response.
async fn login(server: &str, share: &str, username: &str, password: String) -> Result<String> {
    let server = server_base(server)?;
    let share = bson::oid::ObjectId::parse_str(share)
        .map_err(|_| anyhow::anyhow!("Exact share ID required"))?;
    if username.trim().is_empty()
        || username.len() > 254
        || password.is_empty()
        || password.len() > 4096
    {
        bail!("Bounded account name and nonempty password required");
    }
    let response=http_client(&server)?.post(format!("{server}/api/auth/native/share-ssh/login"))
        .json(&serde_json::json!({"username":username,"password":password,"share_grant_id":share.to_hex()}))
        .send().await.map_err(|_|anyhow::anyhow!("Native authentication request failed"))?;
    if !response.status().is_success() {
        bail!("Native authentication refused (HTTP {})", response.status());
    }
    let body: LoginResponse = bounded_json(response).await?;
    if body.access_token.is_empty()
        || body.access_token.len() > 16 * 1024
        || body.expires_in == 0
        || bson::oid::ObjectId::parse_str(&body.user_id).is_err()
    {
        bail!("Invalid native authentication response");
    }
    Ok(body.access_token)
}
pub async fn interactive(
    server: &str,
    share: &str,
    username: &str,
    session_secs: u64,
    args: &[String],
) -> Result<i32> {
    let server = server_base(server)?;
    bson::oid::ObjectId::parse_str(share)
        .map_err(|_| anyhow::anyhow!("Exact share ID required"))?;
    if username.trim().is_empty() || username.len() > 254 {
        bail!("Bounded account name required");
    }
    eprintln!(
        "One-shot account login: no credential is saved. Required MFA is unsupported and refused. SSH shell is not a sandbox."
    );
    let password =
        tokio::task::spawn_blocking(|| rpassword::prompt_password("MeshHarbor account password: "))
            .await
            .map_err(|_| anyhow::anyhow!("Password prompt failed"))?
            .map_err(|_| anyhow::anyhow!("Password terminal input failed"))?;
    let token = login(&server, share, username, password).await?;
    crate::share_sshcmd::run_with_token(&server, share, token, session_secs, args).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn one_response(response: Vec<u8>) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/meshharbor", listener.local_addr().unwrap());
        let worker = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                assert!(request.len() < 16384);
                if let Some(at) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..at]).to_ascii_lowercase();
                    let size = headers
                        .lines()
                        .find_map(|l| {
                            l.strip_prefix("content-length: ")
                                .and_then(|v| v.parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if request.len() >= at + 4 + size {
                        break;
                    }
                }
            }
            socket.write_all(&response).await.unwrap();
            request
        });
        (url, worker)
    }
    #[test]
    fn native_auth_url_prefix_and_transport_guards() {
        assert_eq!(
            server_base("https://www.itachi.fans/meshharbor/").unwrap(),
            "https://www.itachi.fans/meshharbor"
        );
        assert!(server_base("http://127.0.0.1:3000/meshharbor").is_ok());
        for url in [
            "http://remote.example/meshharbor",
            "http://localhost:3000/meshharbor",
            "https://u:p@example.com",
            "https://example.com/?token=x",
            "https://example.com/#x",
            "file:///tmp/a",
            "https://example.com/a%2fb",
            "https://example.com//a",
        ] {
            assert!(server_base(url).is_err(), "{url}");
        }
    }
    #[tokio::test]
    async fn native_auth_real_http_error_does_not_echo_secret_body() {
        let raw=b"HTTP/1.1 403 Forbidden\r\nContent-Length: 18\r\nConnection: close\r\n\r\nSECRET_MUST_NOT_LOG".to_vec();
        let (url, worker) = one_response(raw).await;
        let err = login(
            &url,
            "111111111111111111111111",
            "recipient",
            "fixture-password".into(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("403"));
        assert!(!err.contains("SECRET"));
        assert!(!err.contains("fixture-password"));
        let request = String::from_utf8(worker.await.unwrap()).unwrap();
        assert!(request.starts_with("POST /meshharbor/api/auth/native/share-ssh/login "));
        assert!(!request.to_ascii_lowercase().contains("cookie:"));
    }
    #[tokio::test]
    async fn native_auth_real_http_redirect_is_not_followed() {
        let trap = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let raw=format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{}/secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",trap.local_addr().unwrap()).into_bytes();
        let (url, worker) = one_response(raw).await;
        let err = login(
            &url,
            "111111111111111111111111",
            "recipient",
            "fixture-password".into(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("307"));
        worker.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(150), trap.accept())
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn native_auth_real_http_oversized_and_invalid_json_are_redacted() {
        for (size, body) in [
            (999999, ""),
            (
                "\"SECRET_INVALID_AUTH_BODY\"".len(),
                "\"SECRET_INVALID_AUTH_BODY\"",
            ),
        ] {
            let raw = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {size}\r\nConnection: close\r\n\r\n{body}"
            )
            .into_bytes();
            let (url, worker) = one_response(raw).await;
            let err = login(
                &url,
                "111111111111111111111111",
                "recipient",
                "fixture-password".into(),
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(!err.contains("SECRET"));
            worker.await.unwrap();
        }
    }
    #[tokio::test]
    async fn native_auth_real_http_valid_access_stays_in_memory() {
        let body=serde_json::json!({"access_token":"fixture-access-memory-only","expires_in":60,"user_id":"222222222222222222222222"}).to_string();
        let raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .into_bytes();
        let (url, worker) = one_response(raw).await;
        assert_eq!(
            login(
                &url,
                "111111111111111111111111",
                "recipient",
                "fixture-password".into()
            )
            .await
            .unwrap(),
            "fixture-access-memory-only"
        );
        let request = String::from_utf8(worker.await.unwrap()).unwrap();
        assert!(!request.contains("fixture-access-memory-only"));
        assert!(!request.to_ascii_lowercase().contains("cookie:"));
    }
    #[tokio::test]
    async fn native_auth_real_http_timeout_is_bounded_and_redacted() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let worker = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        let start = std::time::Instant::now();
        let err = login(
            &url,
            "111111111111111111111111",
            "recipient",
            "fixture-password".into(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(start.elapsed() < Duration::from_secs(8));
        assert!(!err.contains("fixture-password"));
        worker.abort();
    }
    #[tokio::test]
    #[ignore = "isolated child fixture invoked only by native_auth_proxy_bypass_real_child_process"]
    async fn native_auth_proxy_child_fixture() {
        assert_eq!(
            std::env::var("MH_NATIVE_AUTH_PROXY_CHILD").as_deref(),
            Ok("1")
        );
        let server = std::env::var("MH_NATIVE_AUTH_LOCAL_SERVER").unwrap();
        // Positive control: default reqwest really sees the child's hostile proxy.
        // It carries no credential. Patched login must use the actual local server.
        let control = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap()
            .post(format!("{server}/proxy-control"))
            .body("no-credential-proxy-control")
            .send()
            .await
            .unwrap();
        assert_eq!(control.status().as_u16(), 403);
        let token = login(
            &server,
            "111111111111111111111111",
            "recipient",
            "synthetic-loopback-password".into(),
        )
        .await
        .unwrap();
        assert_eq!(token, "fixture-memory-access");
    }
    #[tokio::test]
    async fn native_auth_proxy_bypass_real_child_process() {
        let body=serde_json::json!({"access_token":"fixture-memory-access","expires_in":60,"user_id":"222222222222222222222222"}).to_string();
        let (server, target) = one_response(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .into_bytes(),
        )
        .await;
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_url = format!("http://{}", proxy.local_addr().unwrap());
        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
        let proxy_task = tokio::spawn(async move {
            let mut requests = Vec::new();
            loop {
                let accepted = tokio::select! {_=&mut stop_rx=>break,r=proxy.accept()=>r.unwrap()};
                let (mut socket, _) = accepted;
                let mut bytes = Vec::new();
                let mut buf = [0u8; 1024];
                tokio::time::timeout(Duration::from_secs(2),async {
                    loop {let n=socket.read(&mut buf).await.unwrap();if n==0 {break;}bytes.extend_from_slice(&buf[..n]);assert!(bytes.len()<16384);
                        if let Some(at)=bytes.windows(4).position(|w|w==b"\r\n\r\n") {
                            let headers=String::from_utf8_lossy(&bytes[..at]).to_ascii_lowercase();
                            let len=headers.lines().find_map(|l|l.strip_prefix("content-length: ").and_then(|x|x.parse::<usize>().ok())).unwrap_or(0);
                            if bytes.len()>=at+4+len {break;}
                        }
                    }
                    socket.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                }).await.unwrap();
                requests.push(bytes);
            }
            requests
        });
        let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "native_auth::tests::native_auth_proxy_child_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env("MH_NATIVE_AUTH_PROXY_CHILD", "1")
            .env("MH_NATIVE_AUTH_LOCAL_SERVER", server)
            .env("HTTP_PROXY", &proxy_url)
            .env("http_proxy", &proxy_url)
            .env("ALL_PROXY", &proxy_url)
            .env("all_proxy", &proxy_url)
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .env_remove("HTTPS_PROXY")
            .env_remove("https_proxy")
            .kill_on_drop(true);
        let outcome = tokio::time::timeout(Duration::from_secs(8), command.output()).await;
        let _ = stop_tx.send(());
        let requests = proxy_task.await.unwrap();
        let ok = outcome
            .as_ref()
            .is_ok_and(|r| r.as_ref().is_ok_and(|o| o.status.success()));
        if !ok {
            target.abort();
        }
        assert!(
            ok,
            "isolated native login failed; no parent-process proxy environment was mutated"
        );
        assert_eq!(
            requests.len(),
            1,
            "only credential-free default-client control may reach proxy"
        );
        assert!(!String::from_utf8_lossy(&requests[0]).contains("synthetic-loopback-password"));
        let local = tokio::time::timeout(Duration::from_secs(1), target)
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&local).contains("synthetic-loopback-password"));
    }
    #[test]
    fn native_auth_invalid_legacy_url_never_reflects_into_real_log_sink() {
        #[derive(Clone)]
        struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Sink {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let output = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let capture = output.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .without_time()
            .with_ansi(false)
            .with_writer(move || Sink(capture.clone()))
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!("native-auth-sink-positive-control");
            for raw in [
                "http://SECRET_USER:SECRET_PASSWORD@example.com/meshharbor",
                "http://example.com/meshharbor?token=SECRET_QUERY",
            ] {
                let error = legacy_server_base(raw).unwrap_err();
                tracing::warn!(error=%error,"native URL refused");
            }
            assert_eq!(
                legacy_server_base("http://example.com/meshharbor").unwrap(),
                "https://example.com/meshharbor"
            );
        });
        let bytes = output.lock().unwrap();
        let logs = String::from_utf8_lossy(&bytes);
        assert!(logs.contains("native-auth-sink-positive-control"));
        assert!(!logs.contains("SECRET_"));
        assert!(!logs.contains("token="));
        assert!(!logs.contains("example.com"));
    }
}
