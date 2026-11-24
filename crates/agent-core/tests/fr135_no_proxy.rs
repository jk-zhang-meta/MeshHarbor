// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-135 AC1 + AC3 — a client from `http_client` ignores the proxy environment, and honours it
//! again once the device opts in (`MESHHARBOR_USE_SYSTEM_PROXY=1` or `use_system_proxy = true`).
//!
//! ONE test function in its own binary, on purpose: the proxy variables are process-wide, so no
//! other test may build a client while they point at a dead or recording proxy. Everything is
//! local — an axum server for "the centre", a raw listener recording what a proxy would see.

use std::sync::{Arc, Mutex};

use meshharbor_node_core::{config, http_client};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PROXY_VARS: [&str; 6] = [
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
];

/// SAFETY (every caller): the runtime is current-thread and no task runs between `block_on`
/// calls, so nothing reads the environment while it changes.
unsafe fn point_proxies_at(url: &str) {
    for v in PROXY_VARS {
        unsafe { std::env::set_var(v, url) };
    }
    for v in ["NO_PROXY", "no_proxy"] {
        unsafe { std::env::remove_var(v) };
    }
}

/// A listener that answers like a proxy and records each request line.
async fn recording_proxy() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let log = log.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&buf).to_string();
                let line = head.lines().next().unwrap_or("").to_string();
                let reply: &[u8] = if line.starts_with("CONNECT ") {
                    b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                } else {
                    b"HTTP/1.1 200 OK\r\ncontent-length: 9\r\nconnection: close\r\n\r\nvia-proxy"
                };
                log.lock().unwrap().push(line);
                let _ = sock.write_all(reply).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (url, seen)
}

/// "The centre": a local axum server.
async fn centre() -> String {
    let app = axum::Router::new().route("/ping", axum::routing::get(|| async { "direct" }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/ping", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    url
}

/// A local WebSocket echo server ("control socket / DERP").
async fn ws_centre() -> String {
    use futures::{SinkExt, StreamExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/ws", listener.local_addr().unwrap());
    tokio::spawn(async move {
        if let Ok((sock, _)) = listener.accept().await
            && let Ok(mut ws) = tokio_tungstenite::accept_async(sock).await
            && let Some(Ok(msg)) = ws.next().await
        {
            let _ = ws.send(msg).await;
        }
    });
    url
}

async fn get(url: &str) -> Result<String, String> {
    let client = http_client::builder()
        .timeout(std::time::Duration::from_secs(5))
        // A closed loopback port may drop rather than refuse (WSL); don't wait the whole budget.
        .connect_timeout(std::time::Duration::from_secs(1))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client.get(url).send().await.map_err(|e| format!("{e:?}"))?;
    resp.text().await.map_err(|e| e.to_string())
}

fn write_config(dir: &std::path::Path, opt_in: bool) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    std::fs::write(
        &path,
        format!(
            "server_url = \"https://example.invalid\"\nagent_token = \"\"\nagent_id = \"\"\n\
             tenant_id = \"\"\nmachine_id = \"\"\nmachine_name = \"\"\nuse_system_proxy = {opt_in}\n"
        ),
    )
    .unwrap();
    path
}

#[test]
fn fr135_proxies_are_skipped_unless_the_device_opts_in() {
    // SAFETY: no thread exists yet.
    unsafe {
        std::env::remove_var(http_client::OPT_IN_ENV);
        point_proxies_at("http://127.0.0.1:9");
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let centre = rt.block_on(centre());
    let ws_url = rt.block_on(ws_centre());
    let (proxy, seen) = rt.block_on(recording_proxy());
    assert!(!http_client::use_system_proxy());

    // ── AC1: every proxy variable names a dead proxy; the helper's HTTP client AND
    // tokio-tungstenite WebSocket client both reach the local centre directly.
    assert_eq!(rt.block_on(get(&centre)).as_deref(), Ok("direct"));
    let ws_echo = rt.block_on(async {
        use futures::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        // fr-134: allowed — loopback test WebSocket server for FR-135 no-proxy check.
        let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
        ws.send(Message::Text("ws-direct".into())).await.unwrap();
        match ws.next().await.unwrap().unwrap() {
            Message::Text(t) => t.to_string(),
            other => panic!("unexpected ws frame: {other:?}"),
        }
    });
    assert_eq!(ws_echo, "ws-direct");
    // Positive control: a proxy-honouring client in this same process DOES read them, and fails.
    let control = rt.block_on(async {
        http_client::builder_with(true)
            .timeout(std::time::Duration::from_secs(5))
            .connect_timeout(std::time::Duration::from_secs(1))
            .build()
            .unwrap()
            .get(&centre)
            .send()
            .await
    });
    assert!(
        control.is_err(),
        "the control must fail through the dead proxy, or this test proves nothing: {control:?}"
    );

    // ── The same with a proxy that records: the helper's client sends it nothing, http or https.
    unsafe { point_proxies_at(&proxy) };
    assert_eq!(rt.block_on(get(&centre)).as_deref(), Ok("direct"));
    let _ = rt.block_on(get("https://127.0.0.1:1/"));
    assert!(
        seen.lock().unwrap().is_empty(),
        "the proxy saw traffic it must not: {:?}",
        seen.lock().unwrap()
    );

    // ── AC3 (environment): MESHHARBOR_USE_SYSTEM_PROXY=1 — the proxy carries both again.
    unsafe { std::env::set_var(http_client::OPT_IN_ENV, "1") };
    assert!(http_client::use_system_proxy());
    assert_eq!(rt.block_on(get(&centre)).as_deref(), Ok("via-proxy"));
    let _ = rt.block_on(get("https://127.0.0.1:1/"));
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "{seen:?}");
        assert!(seen[0].starts_with(&format!("GET {centre} ")), "{seen:?}");
        assert!(seen[1].starts_with("CONNECT 127.0.0.1:1 "), "{seen:?}");
    }
    unsafe { std::env::remove_var(http_client::OPT_IN_ENV) };
    assert_eq!(rt.block_on(get(&centre)).as_deref(), Ok("direct"));

    // ── AC3 (device config): `use_system_proxy = true` in the file the process loads.
    let dir = tempfile::tempdir().unwrap();
    let cfg = config::load(&write_config(dir.path(), true)).unwrap();
    assert!(cfg.use_system_proxy);
    assert!(http_client::use_system_proxy());
    assert_eq!(rt.block_on(get(&centre)).as_deref(), Ok("via-proxy"));
    // And back off: the next load of a file without the opt-in is direct again.
    let cfg = config::load(&write_config(dir.path(), false)).unwrap();
    assert!(!cfg.use_system_proxy);
    assert_eq!(rt.block_on(get(&centre)).as_deref(), Ok("direct"));
    assert_eq!(seen.lock().unwrap().len(), 3);
}
