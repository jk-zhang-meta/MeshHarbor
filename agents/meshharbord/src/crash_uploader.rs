// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Drain pending crash sidecars to the roomler.ai ingest endpoint.
//!
//! Phase 1C of the agent-crash-upload feature (Task 9). The recorder
//! (Phase 1A) wrote `*.json` sidecars to the Worker + Supervisor
//! crashes dirs at crash time; on next agent startup [`drain_and_
//! upload`] scans both dirs, POSTs each payload to roomler.ai with
//! Bearer auth, and deletes successfully-uploaded sidecars.
//!
//! ## Delete policy
//!
//! - **2xx** — server accepted, delete the sidecar.
//! - **4xx** — server rejected the payload shape (validation error);
//!   re-uploading the same bytes will loop forever. Delete + log.
//! - **5xx / network error** — transient. Keep the sidecar for the
//!   next agent startup retry.
//! - **A final verdict (2xx or 4xx) this process may not delete** — typically a
//!   sidecar another account wrote — is recorded in `<log dir>/crash-verdicts.txt`
//!   and never sent again (#1748). Before, it went out again on every drain:
//!   a 4xx forever, or a duplicate crash.
//!
//! ## Concurrency
//!
//! Single sequential POST per sidecar. A fleet of 100 hosts rebooting
//! simultaneously would burst the ingest endpoint with N parallel
//! posts per host otherwise; sequential keeps the host's outbound
//! HTTP behaviour predictable + maps onto the existing `reqwest::
//! Client::new()` (no connection pooling needed).
//!
//! ## Where this runs
//!
//! Spawned as a `tokio::task::spawn` from `main.rs` AFTER the first
//! successful WS connect — proves the agent JWT is valid + the
//! network can reach roomler.ai, so we're not hammering an offline
//! host with retry storms. Gated through `tokio::sync::Notify` from
//! the signaling loop's first `Ok(())` return.

use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use reqwest::StatusCode;

use crate::config::AgentConfig;
use crate::crash_recorder;

/// HTTP timeout for each individual crash-report POST. Sized
/// generously because the ingest endpoint may go through Cloudflare
/// + the K8s ingress before reaching the API pod.
const POST_TIMEOUT: Duration = Duration::from_secs(30);

/// rc.58: cadence for the periodic mid-session drain in `main.rs`.
/// Before rc.58 the drain ran ONLY at startup; long-running agents
/// that crashed once early (during, say, a flaky-network cold start
/// like the field-test host 2026-05-24 watchdog-loop) never got their
/// sidecars off disk because the next process restart was hours or
/// days away. 5 min keeps the loop cheap (one HTTP HEAD-equivalent
/// per drain when no sidecars are pending) while ensuring the admin
/// UI sees evidence within a single coffee break of the network
/// coming back. Pub so `main.rs` can import without re-defining.
pub const CRASH_DRAIN_INTERVAL_SECS: u64 = 5 * 60;

/// Minimum delay between consecutive sidecar POSTs. The backend's
/// `tower_governor` rate-limit is 60 req/min per IP = 1 req/sec
/// steady-state with a 60-burst budget. Field repro 2026-05-17
/// a third field-test host: agent drained 1317 sidecars at ~50/sec, exhausted the
/// burst budget in ~1.2 sec, then ~1267 of them got 429s. With a
/// 1.1-sec delay we stay safely under the steady-state limit; the
/// drain takes longer (1317 × 1.1s = ~24 min worst case) but every
/// sidecar lands. Backlogs that big are pathological anyway — the
/// recorder's 30-sec rate-limit prevents accumulation under normal
/// operation.
const INTER_REQUEST_DELAY: Duration = Duration::from_millis(1100);

/// Drain every pending crash sidecar to roomler.ai. Best-effort:
/// any IO / network / parse failure logs `warn!` and continues with
/// the next sidecar so a single poisoned file doesn't block the
/// fleet. Returns when the queue is empty.
///
/// FR-103 — `token` is the primary enrollment's LIVE slot, read once per
/// drain: this task runs for the life of the process, and the token it
/// started with may since have been renewed.
pub async fn drain_and_upload(cfg: &AgentConfig, token: &crate::token_slot::TokenSlot) {
    let ledger = verdicts_path();
    let settled = ledger.as_deref().map(load_settled).unwrap_or_default();
    let pending = without_settled(crash_recorder::pending_all(), &settled);
    if pending.is_empty() {
        tracing::debug!("crash_uploader: no pending sidecars");
        return;
    }
    tracing::info!(
        count = pending.len(),
        "crash_uploader: draining pending crash sidecars"
    );

    let client = match build_client() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "crash_uploader: client build failed; deferring uploads");
            return;
        }
    };
    let url = format!("{}/api/agent/crash", cfg.server_url.trim_end_matches('/'));
    let agent_token = token.get();

    let mut ok_count = 0u32;
    let mut keep_count = 0u32;
    let mut drop_count = 0u32;
    let mut first = true;
    for (path, payload) in pending {
        // Inter-request delay to stay under the backend's 60-req/min
        // rate-limit (tower_governor). Skipped for the first upload
        // so a single-sidecar drain is still instant.
        if !first {
            tokio::time::sleep(INTER_REQUEST_DELAY).await;
        }
        first = false;
        match upload_one(&client, &url, &agent_token, &payload).await {
            UploadOutcome::Accepted => {
                tracing::info!(file = %path.display(), "crash_uploader: uploaded + deleted");
                settle(&path, ledger.as_deref(), "uploaded", |p| {
                    std::fs::remove_file(p)
                });
                ok_count += 1;
            }
            UploadOutcome::Rejected { status, body } => {
                tracing::warn!(
                    file = %path.display(),
                    status = %status,
                    body = %body,
                    "crash_uploader: server rejected payload; deleting (4xx is permanent)"
                );
                settle(&path, ledger.as_deref(), "rejected (4xx)", |p| {
                    std::fs::remove_file(p)
                });
                drop_count += 1;
            }
            UploadOutcome::Transient { reason } => {
                tracing::warn!(
                    file = %path.display(),
                    reason = %reason,
                    "crash_uploader: transient failure; keeping sidecar for next startup"
                );
                keep_count += 1;
            }
        }
    }

    tracing::info!(
        uploaded = ok_count,
        kept = keep_count,
        dropped = drop_count,
        "crash_uploader: drain complete"
    );
}

/// Build the reqwest client with the same posture as
/// `enrollment.rs::enroll`'s plain `reqwest::Client::new()` —
/// system TLS roots, default timeouts, plus an explicit per-request
/// timeout via [`POST_TIMEOUT`].
fn build_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .user_agent(concat!(
            "roomlerd-crash-uploader/",
            env!("CARGO_PKG_VERSION")
        ))
        .timeout(POST_TIMEOUT)
        .build()?)
}

/// Categorisation of an upload attempt's outcome. Pure data — the
/// caller deletes or retains the sidecar based on the variant.
#[derive(Debug)]
enum UploadOutcome {
    /// 2xx — server accepted. Delete sidecar.
    Accepted,
    /// 4xx — server rejected. Delete sidecar (re-upload is useless).
    Rejected { status: StatusCode, body: String },
    /// 5xx, timeout, network error, etc. Keep sidecar for retry.
    Transient { reason: String },
}

async fn upload_one(
    client: &reqwest::Client,
    url: &str,
    agent_token: &str,
    payload: &meshharbor_remote_control::models::AgentCrashPayload,
) -> UploadOutcome {
    let req = client
        .post(url)
        .bearer_auth(agent_token)
        .json(payload)
        .send()
        .await;

    let resp = match req {
        Ok(r) => r,
        Err(e) => {
            return UploadOutcome::Transient {
                reason: format!("{e}"),
            };
        }
    };
    let status = resp.status();
    classify_status(status, || async { resp.text().await.unwrap_or_default() }).await
}

/// Categorise an HTTP response status into [`UploadOutcome`]. Pure
/// over `status` + body-resolver; tests use a stub body-resolver to
/// drive every branch without a real HTTP server.
async fn classify_status<F, Fut>(status: StatusCode, body_resolver: F) -> UploadOutcome
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = String>,
{
    if status.is_success() {
        UploadOutcome::Accepted
    } else if status == StatusCode::TOO_MANY_REQUESTS {
        // 429 is the BACKEND saying "slow down" — NOT permanent. Field
        // repro 2026-05-17 a third field-test host: storm of 1317 sidecars hit the
        // tower_governor 60-req/min IP limit; treating it as 4xx-
        // Rejected (the previous behaviour) deleted ~1267 of them
        // permanently. Now classified as Transient so the next agent
        // startup retries. The inter-request delay (see
        // INTER_REQUEST_DELAY) in `drain_and_upload` keeps the steady
        // state under the limit anyway; this is the safety net for
        // accumulated backlog.
        UploadOutcome::Transient {
            reason: format!("HTTP {status} — rate-limited"),
        }
    } else if status.is_client_error() {
        let body = body_resolver().await;
        UploadOutcome::Rejected { status, body }
    } else {
        // 5xx, 3xx unfollowed redirects, weird statuses → transient.
        UploadOutcome::Transient {
            reason: format!("HTTP {status}"),
        }
    }
}

/// Public helper for tests that want to drive the delete-vs-keep
/// decision without a network. Resolves the body lazily so 2xx
/// branches don't pay for an unused read.
#[cfg(test)]
async fn classify_status_for_test(status: StatusCode, body: &str) -> UploadOutcome {
    let owned = body.to_string();
    classify_status(status, || async move { owned }).await
}

/// Where the verdicts on undeletable sidecars are kept: this process's own
/// log folder, which it can always write. `None` without file logging.
///
/// A sidecar gets a FINAL verdict when it is uploaded, or rejected as
/// permanent. Normally it is then deleted. One this process may not delete is
/// one another account owns — measured: a report a root process wrote into
/// this user's log folder (`sudo` keeps `HOME` on macOS).
/// Without a record, every drain (at start AND every [`CRASH_DRAIN_INTERVAL_SECS`])
/// sent it again: a rejected report as another 4xx forever (field: the
/// supervised MacBook, one 2026-09-08 report re-sent every five minutes), and
/// an accepted one as a duplicate crash.
fn verdicts_path() -> Option<std::path::PathBuf> {
    crate::logging::log_dir().map(|d| d.join("crash-verdicts.txt"))
}

/// A sidecar's identity for the ledger: `<len>:<mtime> <file name>`. A file
/// nobody can delete does not change, and a new crash never reuses a name
/// (names carry the crash time and pid).
fn signature(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    let mtime = meta
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let name = path.file_name()?.to_str()?;
    Some(format!("{}:{} {}", meta.len(), mtime, name))
}

/// Every recorded signature. A missing or unreadable ledger is an empty one:
/// the cost is one more send, never a lost crash.
fn load_settled(ledger: &Path) -> std::collections::HashSet<String> {
    std::fs::read_to_string(ledger)
        .map(|s| {
            s.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn record_settled(ledger: &Path, sig: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(ledger)?;
    writeln!(f, "{sig}")
}

/// The queue less every sidecar that already has a final verdict.
fn without_settled<T>(
    pending: Vec<(std::path::PathBuf, T)>,
    settled: &std::collections::HashSet<String>,
) -> Vec<(std::path::PathBuf, T)> {
    if settled.is_empty() {
        return pending;
    }
    pending
        .into_iter()
        .filter(|(path, _)| !signature(path).is_some_and(|s| settled.contains(&s)))
        .collect()
}

/// A sidecar has its final verdict: delete it, or, when this process may not,
/// record the verdict so the sidecar is never sent again. `remove` is
/// `std::fs::remove_file` outside the tests.
fn settle(
    path: &Path,
    ledger: Option<&Path>,
    verdict: &str,
    remove: impl FnOnce(&Path) -> std::io::Result<()>,
) {
    let err = match remove(path) {
        Ok(()) => return,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => e,
    };
    match (ledger, signature(path)) {
        (Some(l), Some(sig)) if record_settled(l, &sig).is_ok() => tracing::warn!(
            file = %path.display(),
            error = %err,
            ledger = %l.display(),
            "crash_uploader: {verdict}, but this process may not delete the sidecar \
             (typically one another account wrote, e.g. a root process run with this \
             user's HOME); its verdict is recorded so it is not sent again. Remove it \
             as the account that owns it"
        ),
        _ => tracing::warn!(
            file = %path.display(),
            error = %err,
            "crash_uploader: {verdict}, but the sidecar could not be deleted and the \
             verdict could not be recorded; it will be sent again next drain"
        ),
    }
}

/// Delete a sidecar at `path` if it exists. Idempotent.
#[allow(dead_code)] // used by future Phase 2 + manual smoke tooling
pub fn delete_sidecar(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn denied(_: &Path) -> std::io::Result<()> {
        Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
    }

    /// The field bug: a rejected sidecar this process may not delete was sent
    /// again on every drain. Its verdict must be recorded, and the next drain
    /// must skip it.
    #[test]
    fn an_undeletable_verdict_is_recorded_and_never_sent_again() {
        let dir = tempfile::tempdir().unwrap();
        let sidecar = dir.path().join("1788894634-71069.json");
        std::fs::write(&sidecar, b"{}").unwrap();
        let ledger = dir.path().join("crash-verdicts.txt");

        settle(&sidecar, Some(&ledger), "rejected (4xx)", denied);

        assert!(sidecar.exists(), "the test's remove refused, so it stays");
        let left = without_settled(vec![(sidecar.clone(), ())], &load_settled(&ledger));
        assert!(
            left.is_empty(),
            "a settled sidecar must not be queued again: {left:?}"
        );
    }

    /// The control: a sidecar that WAS deleted leaves no record at all, so
    /// the ledger only ever holds what could not be cleaned up.
    #[test]
    fn a_deletable_sidecar_leaves_no_record() {
        let dir = tempfile::tempdir().unwrap();
        let sidecar = dir.path().join("1.json");
        std::fs::write(&sidecar, b"{}").unwrap();
        let ledger = dir.path().join("crash-verdicts.txt");

        settle(&sidecar, Some(&ledger), "uploaded", |p| {
            std::fs::remove_file(p)
        });

        assert!(!sidecar.exists());
        assert!(!ledger.exists(), "nothing to record for a deleted sidecar");
    }

    /// A new crash is never mistaken for a settled one: only the recorded
    /// sidecar is skipped, and a missing ledger skips nothing.
    #[test]
    fn only_the_settled_sidecar_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("100-1.json");
        let new = dir.path().join("200-2.json");
        std::fs::write(&old, b"{}").unwrap();
        std::fs::write(&new, b"{}").unwrap();
        let ledger = dir.path().join("crash-verdicts.txt");

        let none = without_settled(
            vec![(old.clone(), ()), (new.clone(), ())],
            &load_settled(&ledger),
        );
        assert_eq!(none.len(), 2, "no ledger yet: nothing is skipped");

        settle(&old, Some(&ledger), "rejected (4xx)", denied);
        let left = without_settled(
            vec![(old.clone(), ()), (new.clone(), ())],
            &load_settled(&ledger),
        );
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].0, new);
    }

    #[tokio::test]
    async fn classify_2xx_returns_accepted_delete() {
        let out = classify_status_for_test(StatusCode::CREATED, "ignored").await;
        assert!(matches!(out, UploadOutcome::Accepted));
        let out = classify_status_for_test(StatusCode::OK, "").await;
        assert!(matches!(out, UploadOutcome::Accepted));
    }

    #[tokio::test]
    async fn classify_4xx_returns_rejected_delete_with_body() {
        let out =
            classify_status_for_test(StatusCode::UNPROCESSABLE_ENTITY, "log_tail too big").await;
        match out {
            UploadOutcome::Rejected { status, body } => {
                assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
                assert_eq!(body, "log_tail too big");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn classify_401_returns_rejected_delete() {
        // 401 is a 4xx → delete. A persistently-invalid agent token
        // means re-uploading won't help; the sentinel system will
        // eventually surface the re-enrollment requirement.
        let out = classify_status_for_test(StatusCode::UNAUTHORIZED, "bad token").await;
        assert!(matches!(out, UploadOutcome::Rejected { .. }));
    }

    #[tokio::test]
    async fn classify_5xx_returns_transient_keep() {
        let out = classify_status_for_test(StatusCode::INTERNAL_SERVER_ERROR, "ignored").await;
        match out {
            UploadOutcome::Transient { reason } => {
                assert!(
                    reason.contains("500"),
                    "reason should include status code; got {reason:?}"
                );
            }
            other => panic!("expected Transient, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn classify_503_returns_transient_keep() {
        let out = classify_status_for_test(StatusCode::SERVICE_UNAVAILABLE, "ignored").await;
        assert!(matches!(out, UploadOutcome::Transient { .. }));
    }

    #[tokio::test]
    async fn classify_429_returns_transient_not_rejected() {
        // Field bug 2026-05-17 a third field-test host: 429 was being classified as
        // 4xx-Rejected → sidecar deleted permanently → ~1267 of 1317
        // crash reports lost when the backend rate-limited a drain
        // burst. 429 MUST be Transient so the next agent startup
        // retries.
        let out = classify_status_for_test(
            StatusCode::TOO_MANY_REQUESTS,
            "Too Many Requests! Wait for 0s",
        )
        .await;
        match out {
            UploadOutcome::Transient { reason } => {
                assert!(
                    reason.contains("429"),
                    "reason should mention 429; got {reason:?}"
                );
                assert!(
                    reason.contains("rate-limited"),
                    "reason should label as rate-limit; got {reason:?}"
                );
            }
            other => panic!("expected Transient (rate-limit retry), got {other:?}"),
        }
    }

    #[test]
    fn inter_request_delay_under_steady_state_rate_limit() {
        // Backend rate-limit is 60 req/min = 1 req/sec steady-state.
        // INTER_REQUEST_DELAY of 1100ms keeps us comfortably under
        // the limit even with clock drift / network jitter; a value
        // below 1000ms would silently trip the limiter once the
        // burst budget is exhausted.
        assert!(
            INTER_REQUEST_DELAY >= Duration::from_millis(1000),
            "inter-request delay must be >= 1s to stay under the 60 req/min limit"
        );
    }

    #[test]
    // Compile-time contract lock — the constant-ness IS the point.
    #[allow(clippy::assertions_on_constants)]
    fn crash_drain_interval_is_reasonable() {
        // Phase 4 pin: too short → wasted CPU + needless HTTP load on
        // long-running healthy agents. Too long → sidecars sit on
        // disk for hours after network repair, defeating the rc.58
        // periodic-drain motivation. 5 min hits the field-tuned
        // sweet spot: cheap when no sidecars are pending (empty
        // pending_all() returns immediately), responsive enough that
        // an operator opening the admin UI within a coffee break of
        // a network repair sees the evidence land.
        assert!(
            CRASH_DRAIN_INTERVAL_SECS >= 60,
            "CRASH_DRAIN_INTERVAL_SECS must be >= 60s to keep periodic \
             drain off the hot path; got {CRASH_DRAIN_INTERVAL_SECS}"
        );
        assert!(
            CRASH_DRAIN_INTERVAL_SECS <= 30 * 60,
            "CRASH_DRAIN_INTERVAL_SECS must be <= 30min so post-repair \
             sidecar surfacing stays operator-visible; got {CRASH_DRAIN_INTERVAL_SECS}"
        );
    }

    #[test]
    fn delete_sidecar_is_idempotent_when_file_missing() {
        let dir = std::env::temp_dir().join(format!(
            "crash_uploader_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = dir.join("nonexistent.json");
        // Don't create the dir — call delete on a path that
        // definitely doesn't exist. Must succeed (NotFound is mapped
        // to Ok).
        assert!(delete_sidecar(&path).is_ok());
    }

    #[test]
    fn delete_sidecar_removes_existing_file() {
        let dir = std::env::temp_dir().join(format!(
            "crash_uploader_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create_dir_all");
        let path = dir.join("present.json");
        std::fs::write(&path, b"{}").expect("write");
        assert!(path.exists());
        assert!(delete_sidecar(&path).is_ok());
        assert!(!path.exists());
        // Cleanup.
        let _ = std::fs::remove_dir_all(&dir);
    }
}
