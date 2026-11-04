// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! The model sidecar against a mock provider: a session reaches the provider
//! only through it, with its own token, the device's key injected on the way
//! and the answer streamed — never buffered; and every call that is not this
//! session's, live, from a device that has not been offline past the grace,
//! is refused before anything leaves the host.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use futures::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;

use super::super::supervisor::tests::{Rig, next_state, order, rig_with};
use super::*;
use meshharbor_remote_control::hive::HiveRunState;

const WAIT: Duration = Duration::from_secs(10);
const DEVICE_KEY: &str = "sk-device-real";

/// A stand-in harness that writes the two variables the sidecar is about
/// into `env.out` in its folder, then speaks just enough stream-json.
const ENV_HARNESS: &str = r#"#!/bin/sh
printf '%s\n%s\n' "$ANTHROPIC_BASE_URL" "$ANTHROPIC_API_KEY" > env.out
while IFS= read -r line; do
  echo '{"type":"system","subtype":"init","session_id":"fake","model":"m","cwd":"'"$PWD"'","tools":[]}'
  echo '{"type":"assistant","message":{"content":[{"type":"text","text":"ok"}]}}'
  echo '{"type":"result","subtype":"success","is_error":false,"num_turns":1,"duration_ms":5,"total_cost_usd":0.0}'
done
"#;

/// What the mock provider saw of one request.
#[derive(Debug, Clone)]
struct Seen {
    head: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

struct Provider {
    url: String,
    hits: Arc<AtomicUsize>,
    seen: Arc<tokio::sync::Mutex<Vec<Seen>>>,
    /// The mock sends its second SSE chunk only once this is notified.
    go: Arc<Notify>,
    /// The next request is refused 401, as a provider refuses a stale key.
    fail_next: Arc<AtomicBool>,
}

/// A provider that answers every request with a two-chunk SSE stream — or
/// a 401 once `fail_next` is set.
async fn provider() -> Provider {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let go = Arc::new(Notify::new());
    let fail_next = Arc::new(AtomicBool::new(false));
    let (h, s, g, f) = (
        Arc::clone(&hits),
        Arc::clone(&seen),
        Arc::clone(&go),
        Arc::clone(&fail_next),
    );
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let (h, s, g, f) = (
                Arc::clone(&h),
                Arc::clone(&s),
                Arc::clone(&g),
                Arc::clone(&f),
            );
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                let head_end = loop {
                    let n = sock.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let mut lines = head.split("\r\n");
                let request_line = lines.next().unwrap_or("").to_string();
                let headers: HashMap<String, String> = lines
                    .filter_map(|l| l.split_once(':'))
                    .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
                    .collect();
                let len: usize = headers
                    .get("content-length")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                let mut body = buf[head_end + 4..].to_vec();
                while body.len() < len {
                    let n = sock.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&tmp[..n]);
                }
                h.fetch_add(1, Ordering::SeqCst);
                let fail = f.swap(false, Ordering::SeqCst);
                s.lock().await.push(Seen {
                    head: request_line,
                    headers,
                    body,
                });
                if fail {
                    let b = r#"{"type":"error","error":{"type":"authentication_error","message":"bad key"}}"#;
                    let _ = sock
                        .write_all(
                            format!(
                                "HTTP/1.1 401 Unauthorized\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{b}",
                                b.len()
                            )
                            .as_bytes(),
                        )
                        .await;
                    return;
                }
                let chunk = |data: &str| format!("{:x}\r\n{data}\r\n", data.len());
                let first = "event: message_start\ndata: {\"type\":\"message_start\"}\n\n";
                let second = "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nretry-after: 7\r\n\
                          anthropic-ratelimit-unified-status: allowed\r\ntransfer-encoding: chunked\r\n\
                          connection: close\r\n\r\n",
                    )
                    .await;
                let _ = sock.write_all(chunk(first).as_bytes()).await;
                let _ = sock.flush().await;
                // Not before the client has the first chunk: a sidecar that
                // buffered would never deliver it, and this would hang.
                g.notified().await;
                let _ = sock.write_all(chunk(second).as_bytes()).await;
                let _ = sock.write_all(b"0\r\n\r\n").await;
            });
        }
    });
    Provider {
        url,
        hits,
        seen,
        go,
        fail_next,
    }
}

/// A rig whose sessions reach `provider` through the sidecar, with a key
/// helper that counts its runs in `count`.
async fn sidecar_rig(provider: &Provider, grace: Duration) -> (Rig, tempfile::TempDir) {
    let count_dir = tempfile::tempdir().unwrap();
    let count = count_dir.path().join("helper-runs");
    let helper = format!(
        "echo run >> '{}'; printf '{DEVICE_KEY}\\n'",
        count.display()
    );
    let upstream = provider.url.clone();
    let r = rig_with(
        true,
        4,
        move |cfg| cfg.api_key_helper = Some(helper),
        move |sup| sup.with_sidecar(upstream, grace),
    );
    std::fs::write(r.root.path().join("claude"), ENV_HARNESS).unwrap();
    (r, count_dir)
}

/// Start a session and run one prompt, so its launch environment exists.
async fn started(r: &mut Rig) -> (ObjectId, String, String) {
    let o = order(r);
    started_with(r, o).await
}

/// [`started`], with `o` for the start.
async fn started_with(
    r: &mut Rig,
    o: super::super::supervisor::StartOrder,
) -> (ObjectId, String, String) {
    let sid = o.session_id;
    assert!(r.sup.start(o, true).await.refused.is_none());
    assert_eq!(next_state(r, sid).await.0, HiveRunState::Idle);
    r.sup.prompt(sid, None, "hi".into()).unwrap();
    assert_eq!(next_state(r, sid).await.0, HiveRunState::Running);
    assert_eq!(next_state(r, sid).await.0, HiveRunState::Idle);
    let env = std::fs::read_to_string(r.root.path().join("work").join("env.out")).unwrap();
    let mut lines = env.lines();
    let base = lines.next().unwrap_or("").to_string();
    let token = lines.next().unwrap_or("").to_string();
    (sid, base, token)
}

async fn call(url: &str, token: Option<&str>) -> reqwest::Response {
    let mut req = reqwest::Client::new()
        .post(url)
        .header("anthropic-version", "2023-06-01")
        .header("anthropic-beta", "test-beta")
        .header("content-type", "application/json")
        .body(r#"{"model":"m","messages":[]}"#);
    if let Some(t) = token {
        req = req.header("x-api-key", t);
    }
    tokio::time::timeout(WAIT, req.send())
        .await
        .expect("the sidecar answers in time")
        .expect("the sidecar is reachable")
}

async fn error_kind(resp: reqwest::Response) -> (u16, String) {
    let status = resp.status().as_u16();
    // Bounded: a call forwarded instead of refused waits on the mock's
    // withheld second chunk, and a test that hangs fails nobody.
    let v: serde_json::Value = tokio::time::timeout(WAIT, resp.json())
        .await
        .unwrap_or_else(|_| panic!("a {status} whose body never ended: forwarded, not refused?"))
        .unwrap();
    (
        status,
        v["error"]["type"].as_str().unwrap_or("").to_string(),
    )
}

#[tokio::test]
async fn a_session_reaches_the_provider_only_through_the_sidecar_with_its_own_token() {
    let p = provider().await;
    let (mut r, _count) = sidecar_rig(&p, OFFLINE_GRACE).await;
    let (sid, base, token) = started(&mut r).await;

    assert!(
        base.starts_with("http://127.0.0.1:") && base.ends_with(&format!("/s/{}", sid.to_hex())),
        "the harness points at the loopback sidecar: {base}"
    );
    assert!(token.starts_with("hive-"), "a session token: {token}");
    assert_ne!(
        token, DEVICE_KEY,
        "the provider's key never enters the session"
    );
    let settings = std::fs::read_to_string(
        r.root
            .path()
            .join("run")
            .join(sid.to_hex())
            .join("settings.json"),
    )
    .unwrap();
    assert!(
        !settings.contains("apiKeyHelper"),
        "nothing in the session can print the key: {settings}"
    );

    // Calling as the harness does: the key is swapped in, the rest is the
    // harness's own, and the answer streams.
    let resp = call(&format!("{base}/v1/messages?beta=true"), Some(&token)).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.headers()["retry-after"],
        "7",
        "provider headers pass through"
    );
    assert_eq!(
        resp.headers()["anthropic-ratelimit-unified-status"],
        "allowed"
    );
    let mut stream = resp.bytes_stream();
    let first = tokio::time::timeout(WAIT, stream.next())
        .await
        .expect("the first chunk arrives while the provider is still answering — not buffered")
        .unwrap()
        .unwrap();
    let first = String::from_utf8_lossy(&first).to_string();
    assert!(first.contains("message_start"), "{first}");
    assert!(!first.contains("message_stop"), "{first}");
    p.go.notify_one();
    let mut rest = String::new();
    while let Some(chunk) = tokio::time::timeout(WAIT, stream.next()).await.unwrap() {
        rest.push_str(&String::from_utf8_lossy(&chunk.unwrap()));
    }
    assert!(rest.contains("message_stop"), "{rest}");

    let seen = p.seen.lock().await.clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].head, "POST /v1/messages?beta=true HTTP/1.1");
    assert_eq!(seen[0].headers["x-api-key"], DEVICE_KEY);
    assert_eq!(seen[0].headers["anthropic-version"], "2023-06-01");
    assert_eq!(seen[0].headers["anthropic-beta"], "test-beta");
    assert_eq!(seen[0].body, br#"{"model":"m","messages":[]}"#);
    r.sup.stop(sid, 1, "owner".into());
}

#[tokio::test]
async fn a_call_that_is_not_this_live_session_s_never_reaches_the_provider() {
    let p = provider().await;
    let (mut r, _count) = sidecar_rig(&p, OFFLINE_GRACE).await;
    let (sid, base, token) = started(&mut r).await;
    let (other_sid, _other_base, other_token) = started(&mut r).await;
    let url = format!("{base}/v1/messages");

    for (token, why) in [
        (None, "no token"),
        (Some("hive-0000"), "a token this device never minted"),
        (Some(DEVICE_KEY), "the provider's own key"),
        (Some(other_token.as_str()), "another session's token"),
    ] {
        let (status, kind) = error_kind(call(&url, token).await).await;
        assert_eq!(
            (status, kind.as_str()),
            (401, "authentication_error"),
            "{why}"
        );
    }
    assert_eq!(
        p.hits.load(Ordering::SeqCst),
        0,
        "nothing reached the provider"
    );

    // Stopped: its token is dead with it (once the session has ended — until
    // then it is still the session's).
    r.sup.stop(sid, 1, "owner".into());
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        p.go.notify_one();
        let resp = call(&url, Some(&token)).await;
        if resp.status().as_u16() == 401 {
            let (_, kind) = error_kind(resp).await;
            assert_eq!(kind, "authentication_error");
            break;
        }
        drop(resp);
        assert!(
            tokio::time::Instant::now() < deadline,
            "the token outlived its session"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    r.sup.stop(other_sid, 1, "owner".into());
}

#[tokio::test]
async fn past_the_offline_grace_model_calls_stop() {
    let p = provider().await;
    let (mut r, _count) = sidecar_rig(&p, Duration::ZERO).await;
    let (sid, base, token) = started(&mut r).await;
    let url = format!("{base}/v1/messages");

    // Online: forwarded.
    p.go.notify_one();
    assert_eq!(call(&url, Some(&token)).await.status().as_u16(), 200);

    // The control connection goes: past the (zero) grace, nothing leaves.
    drop(std::mem::replace(
        &mut r.reports,
        tokio::sync::mpsc::channel(1).1,
    ));
    let deadline = tokio::time::Instant::now() + WAIT;
    while r.sup.offline_for().is_none() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the loss was never noticed"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(20)).await;
    let hits = p.hits.load(Ordering::SeqCst);
    let (status, kind) = error_kind(call(&url, Some(&token)).await).await;
    assert_eq!((status, kind.as_str()), (503, "overloaded_error"));
    assert_eq!(
        p.hits.load(Ordering::SeqCst),
        hits,
        "an offline device made a model call"
    );

    // Back online: calls flow again.
    let (tx, reports) = tokio::sync::mpsc::channel(64);
    r.reports = reports;
    r.sup.connected(tx);
    p.go.notify_one();
    assert_eq!(call(&url, Some(&token)).await.status().as_u16(), 200);
    r.sup.stop(sid, 1, "owner".into());
}

/// [`ENV_HARNESS`], but one that does not listen: it ignores both its stdin's
/// end and SIGTERM, so a stopped run of it holds on, its token still live,
/// until the supervisor's SIGKILL at the end of the stop grace.
const STUBBORN_HARNESS: &str = r#"#!/bin/sh
printf '%s\n%s\n' "$ANTHROPIC_BASE_URL" "$ANTHROPIC_API_KEY" > env.out
trap '' TERM
while IFS= read -r line; do
  echo '{"type":"system","subtype":"init","session_id":"fake","model":"m","cwd":"'"$PWD"'","tools":[]}'
  echo '{"type":"assistant","message":{"content":[{"type":"text","text":"ok"}]}}'
  echo '{"type":"result","subtype":"success","is_error":false,"num_turns":1,"duration_ms":5,"total_cost_usd":0.0}'
done
while :; do sleep 1; done
"#;

/// P2k-7 — AC4's stale-fence half, captured at the provider: a run demoted
/// to a newer fence makes no model call. Its harness does not listen, so the
/// run holds on through the stop grace with its token still live, and the
/// fence alone refuses the call before anything leaves the host. Once the run
/// has ended, its token is gone too.
#[tokio::test]
async fn a_demoted_run_makes_no_model_call() {
    let p = provider().await;
    let (mut r, _count) = sidecar_rig(&p, OFFLINE_GRACE).await;
    std::fs::write(r.root.path().join("claude"), STUBBORN_HARNESS).unwrap();
    let (sid, base, token) = started(&mut r).await;
    let url = format!("{base}/v1/messages");
    p.go.notify_one();
    assert_eq!(
        call(&url, Some(&token)).await.status().as_u16(),
        200,
        "at its own fence, it calls"
    );
    let hits = p.hits.load(Ordering::SeqCst);

    r.sup.demote(sid, 2, "not_location").await;
    assert!(r.sup.holds_live(sid), "the run has not let go yet");
    let resp = call(&url, Some(&token)).await;
    let status = resp.status().as_u16();
    let v: serde_json::Value = tokio::time::timeout(WAIT, resp.json())
        .await
        .expect("a body that ends: forwarded to the provider, not refused?")
        .unwrap();
    assert_eq!(
        (status, v["error"]["message"].as_str()),
        (
            401,
            Some("the session no longer runs on this device at this fence")
        ),
        "fenced out at once, by the fence: the run's token is still live"
    );
    assert!(r.sup.holds_live(sid), "refused while the run still held on");

    assert_eq!(next_state(&mut r, sid).await.0, HiveRunState::Ended);
    let (status, kind) = error_kind(call(&url, Some(&token)).await).await;
    assert_eq!(
        (status, kind.as_str()),
        (401, "authentication_error"),
        "and once it has ended"
    );
    assert_eq!(
        p.hits.load(Ordering::SeqCst),
        hits,
        "a run at a stale fence made a model call"
    );
}

/// P2e-2 — [`sidecar_rig`], whose leased runs give up on the server's word
/// after `wait`.
async fn leased_sidecar_rig(provider: &Provider, wait: Duration) -> (Rig, tempfile::TempDir) {
    let count_dir = tempfile::tempdir().unwrap();
    let count = count_dir.path().join("helper-runs");
    let helper = format!(
        "echo run >> '{}'; printf '{DEVICE_KEY}\\n'",
        count.display()
    );
    let upstream = provider.url.clone();
    let r = rig_with(
        true,
        4,
        move |cfg| cfg.api_key_helper = Some(helper),
        move |sup| {
            sup.with_sidecar(upstream, OFFLINE_GRACE)
                .with_lease_wait(wait)
        },
    );
    std::fs::write(r.root.path().join("claude"), ENV_HARNESS).unwrap();
    (r, count_dir)
}

/// P2e-2 — a leased run calls the model after a reconnect only on the
/// server's word on the NEW connection: without it the call is refused after
/// the wait, in the provider's "overloaded" shape, and nothing reaches the
/// provider; a call waiting when the word comes goes. Offline in between,
/// the closed connection is still the latest one, and its word counts, as
/// the grace does.
#[tokio::test]
async fn a_leased_run_calls_the_model_after_a_reconnect_only_on_the_servers_word() {
    let p = provider().await;
    let (mut r, _count) = leased_sidecar_rig(&p, Duration::from_millis(600)).await;
    let mut o = order(&r);
    o.lease = true;
    // The start is the word on its connection, as `handle_start` keeps it.
    let first = super::super::supervisor::tests::latest(&r);
    assert!(r.sup.record_word(o.session_id, 1, &first));
    let (sid, base, token) = started_with(&mut r, o).await;
    let url = format!("{base}/v1/messages");
    p.go.notify_one();
    assert_eq!(call(&url, Some(&token)).await.status().as_u16(), 200);

    // Offline: the closed connection's word, within the grace.
    drop(std::mem::replace(
        &mut r.reports,
        tokio::sync::mpsc::channel(1).1,
    ));
    let deadline = tokio::time::Instant::now() + WAIT;
    while r.sup.offline_for().is_none() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the loss was never noticed"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    p.go.notify_one();
    assert_eq!(
        call(&url, Some(&token)).await.status().as_u16(),
        200,
        "offline within the grace, on the last connection's word"
    );

    // A new connection, no word on it yet: refused, and nothing leaves.
    let (tx, reports) = tokio::sync::mpsc::channel(64);
    r.reports = reports;
    r.sup.connected(tx.clone());
    let hits = p.hits.load(Ordering::SeqCst);
    let (status, kind) = error_kind(call(&url, Some(&token)).await).await;
    assert_eq!((status, kind.as_str()), (503, "overloaded_error"));
    assert_eq!(
        p.hits.load(Ordering::SeqCst),
        hits,
        "a leased run called the model on no word"
    );

    // The word comes while a call waits: it goes.
    let waiting = {
        let (url, token) = (url.clone(), token.clone());
        tokio::spawn(async move { call(&url, Some(&token)).await.status().as_u16() })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(p.hits.load(Ordering::SeqCst), hits, "it waits for the word");
    r.sup.take_lease(sid, 1, &tx);
    p.go.notify_one();
    assert_eq!(waiting.await.unwrap(), 200);
    r.sup.stop(sid, 1, "owner".into());
}

/// P2e-2 — a run that is not leased keeps P1's behaviour: after a reconnect
/// it calls the model at once, on no word.
#[tokio::test]
async fn a_run_that_is_not_leased_calls_the_model_after_a_reconnect_on_no_word() {
    let p = provider().await;
    let (mut r, _count) = leased_sidecar_rig(&p, Duration::from_secs(5)).await;
    let (sid, base, token) = started(&mut r).await;
    let url = format!("{base}/v1/messages");
    let (tx, reports) = tokio::sync::mpsc::channel(64);
    r.reports = reports;
    r.sup.connected(tx);
    p.go.notify_one();
    let asked = tokio::time::Instant::now();
    assert_eq!(call(&url, Some(&token)).await.status().as_u16(), 200);
    assert!(
        asked.elapsed() < Duration::from_secs(2),
        "it waited for a word it does not need"
    );
    r.sup.stop(sid, 1, "owner".into());
}

#[tokio::test]
async fn the_device_key_is_fetched_once_and_again_after_the_provider_refuses_it() {
    let p = provider().await;
    let (mut r, count_dir) = sidecar_rig(&p, OFFLINE_GRACE).await;
    let (sid, base, token) = started(&mut r).await;
    let count = count_dir.path().join("helper-runs");
    let runs = || {
        std::fs::read_to_string(&count)
            .map(|s| s.lines().count())
            .unwrap_or(0)
    };

    for _ in 0..2 {
        p.go.notify_one();
        assert_eq!(
            call(&format!("{base}/v1/messages"), Some(&token))
                .await
                .status()
                .as_u16(),
            200
        );
    }
    assert_eq!(runs(), 1, "the helper ran once for two calls");

    // The provider refuses the key: the next call asks the helper again.
    p.fail_next.store(true, Ordering::SeqCst);
    let (status, _) = error_kind(call(&format!("{base}/v1/messages"), Some(&token)).await).await;
    assert_eq!(status, 401);
    p.go.notify_one();
    assert_eq!(
        call(&format!("{base}/v1/messages"), Some(&token))
            .await
            .status()
            .as_u16(),
        200
    );
    assert_eq!(runs(), 2, "a refused key is fetched again");
    r.sup.stop(sid, 1, "owner".into());
}

#[tokio::test]
async fn a_session_token_opens_inference_and_token_counting_and_nothing_else() {
    let p = provider().await;
    let (mut r, _count) = sidecar_rig(&p, OFFLINE_GRACE).await;
    let (sid, base, token) = started(&mut r).await;

    // What Claude Code calls besides inference: forwarded.
    p.go.notify_one();
    let resp = call(
        &format!("{base}/v1/messages/count_tokens?beta=true"),
        Some(&token),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);
    drop(resp);
    assert_eq!(p.hits.load(Ordering::SeqCst), 1);

    // What the device's key would open besides: not with a session token.
    let client = reqwest::Client::new();
    for (method, path) in [
        (reqwest::Method::POST, "/v1/files"),
        (reqwest::Method::GET, "/v1/files"),
        (reqwest::Method::POST, "/v1/messages/batches"),
        (reqwest::Method::GET, "/v1/models"),
        (reqwest::Method::GET, "/v1/messages"),
        (reqwest::Method::POST, "/v1/messages/"),
        (reqwest::Method::POST, "/v1/messages/count_tokens/x"),
        (reqwest::Method::POST, "/"),
    ] {
        let resp = tokio::time::timeout(
            WAIT,
            client
                .request(method.clone(), format!("{base}{path}"))
                .header("x-api-key", &token)
                .send(),
        )
        .await
        .unwrap()
        .unwrap();
        let (status, kind) = error_kind(resp).await;
        assert_eq!(
            (status, kind.as_str()),
            (404, "not_found_error"),
            "{method} {path}"
        );
    }
    // Claude Code's warm-up probe is refused too, harmlessly.
    let resp = tokio::time::timeout(
        WAIT,
        client
            .head(format!("{base}/api/hello"))
            .header("x-api-key", &token)
            .send(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(resp.status().as_u16(), 404);

    // A dot segment, sent raw: a URL library on the way up would fold
    // `/v1/messages/../files` into `/v1/files`.
    let addr = base
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap()
        .to_string();
    let mut sock = tokio::net::TcpStream::connect(&addr).await.unwrap();
    sock.write_all(
        format!(
            "POST /s/{}/v1/messages/../files HTTP/1.1\r\nhost: {addr}\r\nx-api-key: {token}\r\n\
             content-length: 2\r\nconnection: close\r\n\r\n{{}}",
            sid.to_hex()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut answer = String::new();
    tokio::time::timeout(WAIT, sock.read_to_string(&mut answer))
        .await
        .unwrap()
        .unwrap();
    assert!(answer.starts_with("HTTP/1.1 404"), "{answer}");

    assert_eq!(
        p.hits.load(Ordering::SeqCst),
        1,
        "nothing but the token count reached the provider"
    );
    r.sup.stop(sid, 1, "owner".into());
}

/// A key not scoped to a workspace needs `anthropic-workspace-id` on every
/// call (field, 2026-10-07: `400 This API key is not scoped to a
/// workspace`). The device's setting supplies it; whatever the session sent
/// is replaced, and without the setting nothing is added.
#[tokio::test]
async fn the_devices_workspace_travels_with_the_key_and_the_sessions_does_not() {
    for (configured, sent_by_session, expected) in [
        (
            Some("wrkspc_device"),
            Some("wrkspc_session"),
            Some("wrkspc_device"),
        ),
        (None, None, None),
    ] {
        let p = provider().await;
        let helper = format!("printf '{DEVICE_KEY}\\n'");
        let upstream = p.url.clone();
        let mut r = rig_with(
            true,
            4,
            move |cfg| {
                cfg.api_key_helper = Some(helper);
                cfg.api_workspace_id = configured.map(str::to_string);
            },
            move |sup| sup.with_sidecar(upstream, OFFLINE_GRACE),
        );
        std::fs::write(r.root.path().join("claude"), ENV_HARNESS).unwrap();
        let (sid, base, token) = started(&mut r).await;
        p.go.notify_one();
        let mut req = reqwest::Client::new()
            .post(format!("{base}/v1/messages"))
            .header("x-api-key", &token)
            .header("anthropic-version", "2023-06-01")
            .body("{}");
        if let Some(w) = sent_by_session {
            req = req.header("anthropic-workspace-id", w);
        }
        let resp = tokio::time::timeout(WAIT, req.send())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        drop(resp);
        let seen = p.seen.lock().await.clone();
        assert_eq!(
            seen[0]
                .headers
                .get("anthropic-workspace-id")
                .map(String::as_str),
            expected,
            "configured {configured:?}, sent by the session {sent_by_session:?}"
        );
        r.sup.stop(sid, 1, "owner".into());
    }
}

/// FR-90 P2k-1 — a Claude subscription's token (`claude setup-token`) goes
/// to the provider as a bearer token under the OAuth beta: the harness's own
/// betas kept and the OAuth one added once, no `x-api-key`, and no
/// workspace, the device's or the session's. A subscription has none.
#[tokio::test]
async fn a_subscription_token_goes_as_a_bearer_token_under_the_oauth_beta() {
    const SUBSCRIPTION: &str = "sk-ant-oat01-device-subscription";
    let p = provider().await;
    let helper = format!("printf '{SUBSCRIPTION}\\n'");
    let upstream = p.url.clone();
    let mut r = rig_with(
        true,
        4,
        move |cfg| {
            cfg.api_key_helper = Some(helper);
            cfg.api_workspace_id = Some("wrkspc_device".to_string());
        },
        move |sup| sup.with_sidecar(upstream, OFFLINE_GRACE),
    );
    std::fs::write(r.root.path().join("claude"), ENV_HARNESS).unwrap();
    let (sid, base, token) = started(&mut r).await;
    for betas in [
        "claude-code-20250219",
        "claude-code-20250219, oauth-2025-04-20",
    ] {
        p.go.notify_one();
        let resp = tokio::time::timeout(
            WAIT,
            reqwest::Client::new()
                .post(format!("{base}/v1/messages"))
                .header("x-api-key", &token)
                .header("anthropic-version", "2023-06-01")
                .header("anthropic-beta", betas)
                .header("anthropic-workspace-id", "wrkspc_session")
                .body("{}")
                .send(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        drop(resp);
    }
    let seen = p.seen.lock().await.clone();
    assert_eq!(seen.len(), 2);
    for s in &seen {
        assert_eq!(
            s.headers.get("authorization").map(String::as_str),
            Some(format!("Bearer {SUBSCRIPTION}").as_str()),
            "a bearer token"
        );
        assert!(
            !s.headers.contains_key("x-api-key"),
            "no x-api-key beside it: {:?}",
            s.headers
        );
        assert_eq!(
            s.headers.get("anthropic-beta").map(String::as_str),
            Some("claude-code-20250219,oauth-2025-04-20"),
            "the harness's betas kept, the OAuth beta once"
        );
        assert!(
            !s.headers.contains_key("anthropic-workspace-id"),
            "no workspace, the device's or the session's: {:?}",
            s.headers
        );
    }
    r.sup.stop(sid, 1, "owner".into());
}

/// P2k-1 — each form of the device's credential, on its own.
#[test]
fn the_devices_credential_goes_on_in_the_form_it_takes() {
    let headers_with = |pairs: &[(&'static str, &'static str)]| {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, HeaderValue::from_static(v));
        }
        h
    };
    let get = |h: &HeaderMap, name: &str| h.get(name).map(|v| v.to_str().unwrap().to_string());
    // An API key: `x-api-key`, the device's workspace over the session's,
    // the betas untouched.
    let mut h = headers_with(&[
        ("anthropic-beta", "claude-code-20250219"),
        ("anthropic-workspace-id", "wrkspc_session"),
    ]);
    assert!(put_credential(&mut h, "sk-ant-api03-key", Some("wrkspc_device")).is_ok());
    assert_eq!(
        get(&h, "x-api-key").as_deref(),
        Some("sk-ant-api03-key"),
        "an API key in x-api-key"
    );
    assert_eq!(
        get(&h, "anthropic-workspace-id").as_deref(),
        Some("wrkspc_device"),
        "the device's workspace over the session's"
    );
    assert_eq!(
        get(&h, "anthropic-beta").as_deref(),
        Some("claude-code-20250219"),
        "an API key's betas untouched"
    );
    assert_eq!(get(&h, "authorization"), None, "no bearer token for a key");

    // A subscription's token: the betas of every line, in order, once each,
    // and the OAuth one once.
    let mut h = headers_with(&[
        ("anthropic-beta", "a, b"),
        ("anthropic-beta", "b,oauth-2025-04-20"),
        ("anthropic-workspace-id", "wrkspc_session"),
    ]);
    assert!(put_credential(&mut h, "sk-ant-oat01-token", Some("wrkspc_device")).is_ok());
    assert_eq!(
        get(&h, "authorization").as_deref(),
        Some("Bearer sk-ant-oat01-token"),
        "a subscription's token as a bearer token"
    );
    assert_eq!(
        h.get_all("anthropic-beta").iter().count(),
        1,
        "one beta header"
    );
    assert_eq!(
        get(&h, "anthropic-beta").as_deref(),
        Some("a,b,oauth-2025-04-20"),
        "each beta once"
    );
    assert_eq!(
        get(&h, "x-api-key"),
        None,
        "no x-api-key for a subscription"
    );
    assert_eq!(
        get(&h, "anthropic-workspace-id"),
        None,
        "no workspace for a subscription"
    );

    // No betas asked for: the OAuth one alone.
    let mut h = HeaderMap::new();
    assert!(put_credential(&mut h, "sk-ant-oat01-token", None).is_ok());
    assert_eq!(
        get(&h, "anthropic-beta").as_deref(),
        Some(OAUTH_BETA),
        "the OAuth beta alone"
    );

    // A line no header can carry is no key, in either form.
    for bad in ["sk-ant-api03-\u{7}", "sk-ant-oat01-\u{7}"] {
        let refused = put_credential(&mut HeaderMap::new(), bad, None).unwrap_err();
        assert_eq!(refused.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(refused.message.contains("not a key"), "{}", refused.message);
    }
}

#[test]
fn only_inference_and_token_counting_are_forwarded() {
    use hyper::Method;
    assert!(forwarded(&Method::POST, "/v1/messages"));
    assert!(forwarded(&Method::POST, "/v1/messages/count_tokens"));
    for (method, path) in [
        (Method::GET, "/v1/messages"),
        (Method::POST, "/v1/files"),
        (Method::POST, "/v1/messages/batches"),
        (Method::POST, "/v1/messages/../files"),
        (Method::POST, "/v1/messages%2F..%2Ffiles"),
        (Method::POST, "/V1/messages"),
        (Method::HEAD, "/api/hello"),
        (Method::GET, "/v1/models"),
    ] {
        assert!(!forwarded(&method, path), "{method} {path}");
    }
}

#[test]
fn revoking_one_run_s_token_leaves_another_run_s_alone() {
    let tokens = Tokens::default();
    let session = ObjectId::new();
    let ended = tokens.mint(session, 1);
    let next = tokens.mint(session, 1);
    assert_ne!(ended, next);
    tokens.revoke(&ended);
    assert_eq!(tokens.resolve(&ended), None);
    assert_eq!(
        tokens.resolve(&next),
        Some((session, 1)),
        "the run that started as the other ended keeps its token"
    );
}

#[test]
fn a_session_path_splits_into_its_id_and_the_provider_path() {
    assert_eq!(
        split_session("/s/abc/v1/messages"),
        Some(("abc", "/v1/messages"))
    );
    assert_eq!(split_session("/s/abc"), Some(("abc", "/")));
    assert_eq!(split_session("/v1/messages"), None);
}

/// FR-90 P2e-6a — the server waits a primary out for `UNREACHABLE_SECS`
/// before it moves a session away from it with no drain. By then this device
/// must have stopped serving model calls: its own receive deadline to notice
/// the server is gone, then the grace it serves calls for after it last heard
/// from the server, then a margin. A shorter wait could move a session this
/// device still calls the model for.
#[test]
fn the_server_waits_a_primary_out_past_the_grace_it_serves_calls_for() {
    use meshharbor_remote_control::hive::promote_limits::UNREACHABLE_SECS;
    let serves = crate::signaling::WS_RX_DEADLINE + OFFLINE_GRACE + Duration::from_secs(30);
    assert_eq!(Duration::from_secs(UNREACHABLE_SECS), serves);
}
