//! Primary-scoped canonical names and one durable, CAS-based local proposal.
//! All mutations share the existing named-config write lock. Network work is
//! bounded and outside that lock; responses recheck the revision on entry.
use crate::config::{self, AgentConfig, DeviceNameJournal, DeviceNameProposal};
use anyhow::{Context, Result, bail};
use meshharbor_remote_control::signaling::ClientMsg;
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{Notify, mpsc};
use tunnel_core::localapi::DeviceNameStatus;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CanonicalName {
    pub agent_id: String,
    pub tenant_id: String,
    pub revision: String,
    pub name: String,
}

fn transient_http_error(error: &anyhow::Error) -> bool {
    error.downcast_ref::<reqwest::Error>().is_some_and(|e| {
        if let Some(status) = e.status() {
            status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS
        } else {
            !e.is_decode()
                && !e.is_builder()
                && (e.is_timeout() || e.is_connect() || e.is_body() || e.is_request())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, PathBuf, AgentConfig, Arc<DeviceNames>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("named-primary.toml");
        let cfg = config::test_fixture();
        config::save(&path, &cfg).unwrap();
        let names = Arc::new(DeviceNames::new(
            path.clone(),
            Arc::new(tokio::sync::Mutex::new(())),
        ));
        (dir, path, cfg, names)
    }
    fn canonical(cfg: &AgentConfig, revision: &str, name: &str) -> CanonicalName {
        CanonicalName {
            agent_id: cfg.agent_id.clone(),
            tenant_id: cfg.tenant_id.clone(),
            revision: revision.into(),
            name: name.into(),
        }
    }

    #[test]
    fn names_and_decimal_revisions_reject_ambiguous_inputs() {
        for bad in ["", "01", "-1", "9223372036854775808", "1.0"] {
            assert!(revision(bad).is_err());
        }
        assert_eq!(revision("9223372036854775807").unwrap(), i64::MAX as u64);
        for bad in ["", "\nnew", "ab\0cd", "a\tb"] {
            assert!(validate_name(bad).is_err());
        }
        assert!(validate_name(&"新".repeat(22)).is_err());
        assert_eq!(validate_name("  新名  ").unwrap(), "新名");
    }

    #[tokio::test]
    async fn durable_ack_idempotence_reorder_and_primary_scope() {
        let (_dir, path, cfg, names) = fixture();
        let (tx, mut rx) = mpsc::channel(8);
        names
            .apply_and_ack(&cfg, canonical(&cfg, "5", "new"), &tx)
            .await;
        let saved = config::load(&path).unwrap();
        assert_eq!(saved.machine_name, "new");
        assert_eq!(saved.agent_id, cfg.agent_id);
        assert_eq!(saved.exec_enabled, cfg.exec_enabled);
        assert!(
            matches!(rx.recv().await, Some(ClientMsg::DeviceNameAck {outcome, ..}) if outcome=="applied")
        );
        names
            .apply(&cfg, &canonical(&cfg, "5", "new"))
            .await
            .unwrap();
        assert!(
            names
                .apply(&cfg, &canonical(&cfg, "4", "stale"))
                .await
                .is_err()
        );
        assert!(
            names
                .apply(&cfg, &canonical(&cfg, "5", "collision"))
                .await
                .is_err()
        );
        let mut secondary = cfg.clone();
        secondary.tenant_id = "secondary".into();
        assert!(
            names
                .apply(&secondary, &canonical(&secondary, "9", "alien"))
                .await
                .is_err()
        );
        secondary = cfg.clone();
        secondary.server_url = "https://other.invalid".into();
        assert!(
            names
                .apply(&secondary, &canonical(&cfg, "9", "alien"))
                .await
                .is_err()
        );
        assert_eq!(config::load(&path).unwrap().machine_name, "new");
        // A legacy direct-file editor must not defeat authoritative rejoin.
        let mut externally_edited = config::load(&path).unwrap();
        externally_edited.machine_name = "legacy-local-cache".into();
        config::save(&path, &externally_edited).unwrap();
        names
            .apply(&cfg, &canonical(&cfg, "5", "new"))
            .await
            .unwrap();
        assert_eq!(config::load(&path).unwrap().machine_name, "new");
    }

    #[tokio::test]
    async fn offline_proposal_survives_restart_and_newer_web_name_wins() {
        let (_dir, path, cfg, names) = fixture();
        names
            .apply(&cfg, &canonical(&cfg, "3", "web-old"))
            .await
            .unwrap();
        let (actual, state) = names.propose("offline-choice").await.unwrap();
        assert_eq!(actual, "web-old");
        assert_eq!(state.state, "pending");
        let restarted = DeviceNames::new(path.clone(), Arc::new(tokio::sync::Mutex::new(())));
        assert_eq!(
            restarted.snapshot().unwrap().1.proposed_name.as_deref(),
            Some("offline-choice")
        );
        restarted
            .apply(&cfg, &canonical(&cfg, "4", "newer-web"))
            .await
            .unwrap();
        let (actual, state) = restarted.snapshot().unwrap();
        assert_eq!(actual, "newer-web");
        assert_eq!(state.error.as_deref(), Some("name_revision_conflict"));
        assert_eq!(state.proposed_name.as_deref(), Some("offline-choice"));
        assert_eq!(
            restarted.propose("explicit-retry").await.unwrap().1.state,
            "pending"
        );
        assert_eq!(
            config::load(&path)
                .unwrap()
                .name_sync
                .unwrap()
                .pending
                .unwrap()
                .base_revision,
            "4"
        );
    }

    #[tokio::test]
    async fn failed_atomic_save_does_not_publish_or_ack_applied() {
        let (_dir, path, cfg, names) = fixture();
        // Existing config remains readable, but its atomic-save temporary cannot be opened.
        let tmp = path.with_extension(format!("toml.tmp.{}", std::process::id()));
        std::fs::create_dir(&tmp).unwrap();
        let (tx, mut rx) = mpsc::channel(2);
        names
            .apply_and_ack(&cfg, canonical(&cfg, "1", "cannot-save"), &tx)
            .await;
        assert!(
            matches!(rx.recv().await, Some(ClientMsg::DeviceNameAck {outcome, ..}) if outcome=="failed")
        );
        assert_eq!(names.snapshot().unwrap().0, cfg.machine_name);
        assert_eq!(config::load(&path).unwrap().machine_name, cfg.machine_name);
    }

    #[tokio::test]
    async fn push_before_http_response_and_late_failure_cannot_replace_newer_proposal() {
        let (_dir, path, cfg, names) = fixture();
        names
            .apply(&cfg, &canonical(&cfg, "0", "host"))
            .await
            .unwrap();
        names.propose("accepted").await.unwrap();
        let old = config::load(&path).unwrap().name_sync.unwrap();
        names
            .apply(&cfg, &canonical(&cfg, "1", "accepted"))
            .await
            .unwrap(); // push before HTTP200
        names
            .apply(&cfg, &canonical(&cfg, "1", "accepted"))
            .await
            .unwrap(); // HTTP200 duplicate
        assert!(names.snapshot().unwrap().1.proposed_name.is_none());
        names.propose("newer-proposal").await.unwrap();
        names
            .fail_pending(&cfg, &old, "name_revision_conflict")
            .await
            .unwrap();
        assert_eq!(names.snapshot().unwrap().1.state, "pending");
        names
            .apply(&cfg, &canonical(&cfg, "2", "web-latest"))
            .await
            .unwrap();
        assert!(
            names
                .apply(&cfg, &canonical(&cfg, "1", "accepted"))
                .await
                .is_err()
        );
        assert_eq!(config::load(&path).unwrap().machine_name, "web-latest");
    }

    #[tokio::test]
    async fn real_http_cas_persists_then_acknowledges_without_reconnect() {
        http_cas_case(false, false).await;
    }

    #[tokio::test]
    async fn second_local_proposal_during_http_preserves_latest_intent_as_conflict() {
        http_cas_case(true, false).await;
    }

    #[tokio::test]
    async fn transient_http_transport_recovers_on_same_worker_without_ws_reconnect() {
        http_cas_case(false, true).await;
    }

    async fn http_cas_case(second_proposal: bool, transient_disconnect: bool) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (_dir, path, mut cfg, _) = fixture();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        cfg.server_url = format!("http://{}", listener.local_addr().unwrap());
        config::save(&path, &cfg).unwrap();
        let names = Arc::new(DeviceNames::new(
            path.clone(),
            Arc::new(tokio::sync::Mutex::new(())),
        ));
        names.propose("local-choice").await.unwrap();
        let server_cfg = cfg.clone();
        let server_names = names.clone();
        let server = tokio::spawn(async move {
            if transient_disconnect {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = [0; 4096];
                let n = stream.read(&mut buffer).await.unwrap();
                assert!(
                    String::from_utf8_lossy(&buffer[..n]).starts_with("GET /api/agent/self/name ")
                );
                drop(stream); // Real transport failure: no HTTP status/body.
            }
            for (verb, rev, name) in [("GET", "0", "host"), ("POST", "1", "local-choice")] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let mut buffer = [0; 2048];
                loop {
                    let n = stream.read(&mut buffer).await.unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&buffer[..n]);
                    let text = String::from_utf8_lossy(&bytes);
                    if let Some(end) = text.find("\r\n\r\n") {
                        let len = text[..end]
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .and_then(|v| v.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if bytes.len() >= end + 4 + len {
                            break;
                        }
                    }
                }
                let request = String::from_utf8(bytes).unwrap();
                assert!(request.starts_with(&format!("{verb} /api/agent/self/name ")));
                if verb == "POST" {
                    let body: serde_json::Value =
                        serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
                    assert_eq!(
                        body,
                        serde_json::json!({"expected_revision":"0", "name":"local-choice"})
                    );
                    if second_proposal {
                        server_names.propose("second-local-choice").await.unwrap();
                        // The accepted A push arrives while its HTTP response is still in flight.
                        server_names
                            .apply(&server_cfg, &canonical(&server_cfg, rev, name))
                            .await
                            .unwrap();
                    }
                }
                let body = serde_json::to_string(&canonical(&server_cfg, rev, name)).unwrap();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let (tx, mut rx) = mpsc::channel(4);
        let began = std::time::Instant::now();
        names
            .reconcile_bounded(&cfg, "fixture-token", &tx)
            .await
            .unwrap();
        if transient_disconnect {
            assert!(began.elapsed() >= Duration::from_millis(250));
        }
        server.await.unwrap();
        assert_eq!(config::load(&path).unwrap().machine_name, "local-choice");
        let status = names.snapshot().unwrap().1;
        if second_proposal {
            assert_eq!(status.proposed_name.as_deref(), Some("second-local-choice"));
            assert_eq!(status.error.as_deref(), Some("name_revision_conflict"));
        } else {
            assert!(status.proposed_name.is_none());
        }
        assert!(
            matches!(rx.recv().await, Some(ClientMsg::DeviceNameAck {revision, outcome, ..}) if revision=="0" && outcome=="applied")
        );
        assert!(
            matches!(rx.recv().await, Some(ClientMsg::DeviceNameAck {revision, outcome, ..}) if revision=="1" && outcome=="applied")
        );
    }

    #[tokio::test]
    async fn old_server_404_is_durable_unsupported_not_fake_synced_or_post_retry() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (_dir, path, mut cfg, _) = fixture();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        cfg.server_url = format!("http://{}", listener.local_addr().unwrap());
        config::save(&path, &cfg).unwrap();
        let names = DeviceNames::new(path.clone(), Arc::new(tokio::sync::Mutex::new(())));
        names.propose("queued-name").await.unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 4096];
            let n = stream.read(&mut buffer).await.unwrap();
            assert!(String::from_utf8_lossy(&buffer[..n]).starts_with("GET /api/agent/self/name "));
            stream
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            drop(stream);
            assert!(
                tokio::time::timeout(Duration::from_millis(100), listener.accept())
                    .await
                    .is_err(),
                "404 must not POST"
            );
        });
        let (tx, mut rx) = mpsc::channel(4);
        names
            .reconcile_bounded(&cfg, "fixture-token", &tx)
            .await
            .unwrap();
        server.await.unwrap();
        assert!(
            rx.try_recv().is_err(),
            "no successful ACK for unsupported server"
        );
        let reopened = DeviceNames::new(path.clone(), Arc::new(tokio::sync::Mutex::new(())));
        let (canonical, state) = reopened.snapshot().unwrap();
        assert_eq!(canonical, cfg.machine_name);
        assert_eq!(state.state, "unsupported");
        assert_eq!(state.proposed_name.as_deref(), Some("queued-name"));
        assert!(
            config::load(&path)
                .unwrap()
                .name_sync
                .unwrap()
                .pending
                .unwrap()
                .error
                .is_some()
        );
    }

    #[tokio::test]
    async fn transient_status_retries_are_bounded_to_five_attempts() {
        for status in [429, 503] {
            http_error_case(status, 0).await;
        }
    }

    #[tokio::test]
    async fn permanent_status_never_retries_and_new_intent_fences_old_backoff() {
        for status in [401, 403, 404, 409] {
            http_error_case(status, 0).await;
        }
        http_error_case(503, 1).await;
        http_error_case(503, 2).await;
    }

    #[tokio::test]
    async fn late_permanent_get_failure_cannot_poison_replacement_proposal() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for (status, initial_proposal) in [(403, true), (404, true), (404, false)] {
            let (_dir, path, mut cfg, _) = fixture();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            cfg.server_url = format!("http://{}", listener.local_addr().unwrap());
            config::save(&path, &cfg).unwrap();
            let names = Arc::new(DeviceNames::new(
                path.clone(),
                Arc::new(tokio::sync::Mutex::new(())),
            ));
            if initial_proposal {
                names.propose("intent-A").await.unwrap();
            }
            let server_names = names.clone();
            let server_cfg = cfg.clone();
            let server = tokio::spawn(async move {
                for step in 0..3 {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut bytes = [0; 4096];
                    let n = stream.read(&mut bytes).await.unwrap();
                    let request = String::from_utf8_lossy(&bytes[..n]);
                    assert!(request.starts_with(if step == 2 {
                        "POST /api/agent/self/name "
                    } else {
                        "GET /api/agent/self/name "
                    }));
                    if step == 0 {
                        server_names.propose("intent-B").await.unwrap();
                        stream.write_all(format!("HTTP/1.1 {status} Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
                    } else {
                        let body = serde_json::to_string(&canonical(
                            &server_cfg,
                            if step == 1 { "0" } else { "1" },
                            if step == 1 { "host" } else { "intent-B" },
                        ))
                        .unwrap();
                        stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).as_bytes()).await.unwrap();
                    }
                }
            });
            let (tx, mut rx) = mpsc::channel(4);
            names
                .reconcile_bounded(&cfg, "fixture-token", &tx)
                .await
                .unwrap();
            let pending = names.snapshot().unwrap().1;
            assert_eq!(pending.proposed_name.as_deref(), Some("intent-B"));
            assert_eq!(pending.state, "pending");
            assert!(pending.error.is_none());
            // The newer proposal's existing worker wakeup can now submit it.
            names
                .reconcile_bounded(&cfg, "fixture-token", &tx)
                .await
                .unwrap();
            server.await.unwrap();
            assert_eq!(names.snapshot().unwrap().0, "intent-B");
            assert!(names.snapshot().unwrap().1.proposed_name.is_none());
            assert!(
                matches!(rx.recv().await,Some(ClientMsg::DeviceNameAck {outcome,..}) if outcome=="applied")
            );
            assert!(
                matches!(rx.recv().await,Some(ClientMsg::DeviceNameAck {outcome,..}) if outcome=="applied")
            );
        }
    }

    async fn http_error_case(status: u16, change_intent: u8) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (_dir, path, mut cfg, _) = fixture();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        cfg.server_url = format!("http://{}", listener.local_addr().unwrap());
        config::save(&path, &cfg).unwrap();
        let names = Arc::new(DeviceNames::new(
            path.clone(),
            Arc::new(tokio::sync::Mutex::new(())),
        ));
        names.propose("intent-A").await.unwrap();
        let server_names = names.clone();
        let server_cfg = cfg.clone();
        let count = if [429, 503].contains(&status) && change_intent == 0 {
            5
        } else {
            1
        };
        let server = tokio::spawn(async move {
            for i in 0..count {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = [0; 4096];
                let n = stream.read(&mut bytes).await.unwrap();
                assert!(
                    String::from_utf8_lossy(&bytes[..n]).starts_with("GET /api/agent/self/name ")
                );
                if i == 0 && change_intent == 1 {
                    server_names.propose("intent-B").await.unwrap();
                }
                if i == 0 && change_intent == 2 {
                    server_names
                        .apply(&server_cfg, &canonical(&server_cfg, "4", "web-newer"))
                        .await
                        .unwrap();
                }
                stream.write_all(format!("HTTP/1.1 {status} Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(100), listener.accept())
                    .await
                    .is_err(),
                "unexpected replay beyond attempt fence"
            );
        });
        let (tx, mut rx) = mpsc::channel(4);
        let result = names.reconcile_bounded(&cfg, "fixture-token", &tx).await;
        if [429, 503].contains(&status) {
            assert!(result.is_err());
        } else {
            assert!(result.is_ok());
        }
        server.await.unwrap();
        assert!(rx.try_recv().is_err());
        let (name, state) = names.snapshot().unwrap();
        if change_intent == 1 {
            assert_eq!(state.proposed_name.as_deref(), Some("intent-B"));
            assert_eq!(state.state, "pending");
        }
        if change_intent == 2 {
            assert_eq!(name, "web-newer");
            assert_eq!(state.error.as_deref(), Some("name_revision_conflict"));
        }
        if change_intent == 0 && status == 404 {
            assert_eq!(state.state, "unsupported");
        }
    }
}

pub fn revision(value: &str) -> Result<u64> {
    let n: u64 = value.parse().context("invalid name revision")?;
    if n > i64::MAX as u64 || n.to_string() != value {
        bail!("invalid name revision");
    }
    Ok(n)
}

pub fn validate_name(name: &str) -> Result<String> {
    if name.chars().any(char::is_control) {
        bail!("device name contains a control character");
    }
    let name = name.trim();
    if name.is_empty() || name.len() > 64 || name.chars().any(char::is_control) {
        bail!("device name must be 1..64 UTF-8 bytes without control characters");
    }
    Ok(name.to_owned())
}

fn journal(cfg: &AgentConfig) -> DeviceNameJournal {
    cfg.name_sync
        .as_ref()
        .filter(|j| {
            j.server_url == cfg.server_url
                && j.tenant_id == cfg.tenant_id
                && j.agent_id == cfg.agent_id
        })
        .cloned()
        .unwrap_or_else(|| DeviceNameJournal {
            server_url: cfg.server_url.clone(),
            tenant_id: cfg.tenant_id.clone(),
            agent_id: cfg.agent_id.clone(),
            revision: None,
            canonical_name: None,
            error: None,
            pending: None,
        })
}

fn view(cfg: &AgentConfig) -> (String, DeviceNameStatus) {
    let j = journal(cfg);
    let error = j.pending.as_ref().and_then(|p| p.error.clone()).or(j.error);
    let state = if error.as_deref() == Some("unsupported") {
        "unsupported"
    } else if error.is_some() {
        "failed"
    } else if j.pending.is_some() {
        "pending"
    } else if j.revision.is_some() {
        "synced"
    } else {
        "unverified"
    };
    (
        cfg.machine_name.clone(),
        DeviceNameStatus {
            state: state.into(),
            revision: j.revision,
            proposed_name: j.pending.map(|p| p.name),
            error,
        },
    )
}

pub struct DeviceNames {
    path: PathBuf,
    lock: config::WriteLock,
    live: Mutex<Option<(String, DeviceNameStatus)>>,
    pub changed: Notify,
    network: Arc<tokio::sync::Mutex<()>>,
    rerun: std::sync::atomic::AtomicBool,
}

impl DeviceNames {
    pub fn new(path: PathBuf, lock: config::WriteLock) -> Self {
        // FR-43 P3 — an unenrolled GUI worker runs with no file at all; reading
        // one anyway would log "the host must be re-enrolled" at every start.
        let live = path
            .exists()
            .then(|| config::load(&path).ok())
            .flatten()
            .map(|c| view(&c));
        Self {
            path,
            lock,
            live: Mutex::new(live),
            changed: Notify::new(),
            network: Arc::new(tokio::sync::Mutex::new(())),
            rerun: false.into(),
        }
    }
    pub fn snapshot(&self) -> Option<(String, DeviceNameStatus)> {
        self.live.lock().ok()?.clone()
    }
    fn publish(&self, cfg: &AgentConfig) {
        *self.live.lock().expect("name snapshot lock") = Some(view(cfg));
    }

    pub async fn propose(&self, name: &str) -> Result<(String, DeviceNameStatus)> {
        let name = validate_name(name)?;
        let _guard = self.lock.lock().await;
        let mut cfg = config::load(&self.path)?;
        let mut j = journal(&cfg);
        let base_revision = j.revision.clone().unwrap_or_else(|| "0".into());
        j.error = None;
        j.pending = Some(DeviceNameProposal {
            name,
            base_revision,
            error: None,
        });
        cfg.name_sync = Some(j);
        config::save(&self.path, &cfg)?;
        self.publish(&cfg);
        self.changed.notify_one();
        Ok(view(&cfg))
    }

    /// The connection's identity is not interchangeable with frame fields.
    pub async fn apply(&self, connection: &AgentConfig, value: &CanonicalName) -> Result<()> {
        let n = revision(&value.revision)?;
        let name = validate_name(&value.name)?;
        if name != value.name {
            bail!("noncanonical device name");
        }
        let _guard = self.lock.lock().await;
        let mut cfg = config::load(&self.path)?;
        if cfg.server_url != connection.server_url
            || cfg.agent_id != connection.agent_id
            || cfg.tenant_id != connection.tenant_id
            || value.agent_id != cfg.agent_id
            || value.tenant_id != cfg.tenant_id
        {
            bail!("name scope is not current primary enrollment");
        }
        let mut j = journal(&cfg);
        if let Some(old) = &j.revision {
            let old = revision(old)?;
            if n < old {
                bail!("stale name revision");
            }
            if n == old && name != j.canonical_name.as_deref().unwrap_or(&cfg.machine_name) {
                bail!("same revision has conflicting name");
            }
        }
        if let Some(p) = &mut j.pending {
            if p.name == name {
                j.pending = None;
            } else if n > revision(&p.base_revision)? {
                p.error = Some("name_revision_conflict".into());
            }
        }
        j.revision = Some(value.revision.clone());
        j.canonical_name = Some(name.clone());
        j.error = None;
        cfg.name_sync = Some(j);
        cfg.machine_name = name;
        // save() atomically renames a fsynced temporary in the same directory.
        config::save(&self.path, &cfg)?;
        self.publish(&cfg);
        Ok(())
    }

    pub async fn apply_and_ack(
        &self,
        cfg: &AgentConfig,
        value: CanonicalName,
        tx: &mpsc::Sender<ClientMsg>,
    ) -> bool {
        let result = self.apply(cfg, &value).await;
        let applied = result.is_ok();
        let (outcome, detail) = match result {
            Ok(()) => ("applied", None),
            Err(error) => {
                tracing::warn!(error = %error, "device name persistence refused");
                // Do not expose filesystem paths or authentication material.
                (
                    "failed",
                    Some("name_persistence_or_revision_failed".to_owned()),
                )
            }
        };
        let _ = tx
            .send(ClientMsg::DeviceNameAck {
                agent_id: value.agent_id,
                tenant_id: value.tenant_id,
                revision: value.revision,
                name: value.name,
                outcome: outcome.into(),
                detail,
            })
            .await;
        applied
    }

    /// Single bounded worker shared by reconnect and local-proposal triggers.
    /// An old response never writes over a newer pushed revision.
    pub fn reconcile(
        self: &Arc<Self>,
        cfg: AgentConfig,
        token: String,
        tx: mpsc::Sender<ClientMsg>,
    ) {
        let Ok(guard) = self.network.clone().try_lock_owned() else {
            self.rerun.store(true, std::sync::atomic::Ordering::SeqCst);
            return;
        };
        let this = self.clone();
        tokio::spawn(async move {
            if let Err(error) = this.reconcile_bounded(&cfg, &token, &tx).await {
                tracing::debug!(error = %error, "name synchronization attempt stopped; inspect current proposal status");
            }
            drop(guard);
            if this.rerun.swap(false, std::sync::atomic::Ordering::SeqCst) {
                this.changed.notify_one();
            }
        });
    }

    async fn retry_state(&self, connection: &AgentConfig) -> Result<DeviceNameJournal> {
        let _guard = self.lock.lock().await;
        let cfg = config::load(&self.path)?;
        if cfg.server_url != connection.server_url
            || cfg.agent_id != connection.agent_id
            || cfg.tenant_id != connection.tenant_id
        {
            bail!("primary changed");
        }
        Ok(journal(&cfg))
    }

    /// At most five attempts, with no config lock held over network or backoff.
    /// A newer local proposal or server revision fences every delayed attempt.
    async fn reconcile_bounded(
        &self,
        cfg: &AgentConfig,
        token: &str,
        tx: &mpsc::Sender<ClientMsg>,
    ) -> Result<()> {
        let mut before = self.retry_state(cfg).await?;
        const DELAYS_MS: [u64; 4] = [250, 1000, 2000, 4000];
        for delay_ms in DELAYS_MS.into_iter().map(Some).chain(std::iter::once(None)) {
            let error = match self.reconcile_once(cfg, token, tx).await {
                Ok(()) => return Ok(()),
                Err(error) => error,
            };
            let Some(delay_ms) = delay_ms else {
                return Err(error);
            };
            if !transient_http_error(&error) {
                return Err(error);
            }
            let after = self.retry_state(cfg).await?;
            // GET may have established revision zero before POST failed. It is
            // safe to retry that SAME proposal, not a replacement/conflict.
            if before.pending != after.pending
                || after.pending.as_ref().is_some_and(|p| p.error.is_some())
                || (before.pending.is_none() && before.revision != after.revision)
            {
                return Err(error);
            }
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            if self.retry_state(cfg).await? != after {
                return Err(error);
            }
            before = after;
        }
        unreachable!("bounded retry loop returns on its final attempt")
    }

    async fn reconcile_once(
        &self,
        cfg: &AgentConfig,
        token: &str,
        tx: &mpsc::Sender<ClientMsg>,
    ) -> Result<()> {
        let get_attempt = self.retry_state(cfg).await?;
        // FR-128 — to the centre along the control socket's path.
        let client = meshharbor_node_core::management_path::route_http(meshharbor_node_core::http_client::builder())
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let url = format!(
            "{}/api/agent/self/name",
            cfg.server_url.trim_end_matches('/')
        );
        let response = client.get(&url).bearer_auth(token).send().await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return self.fail_pending(cfg, &get_attempt, "unsupported").await;
        }
        if response.status().is_client_error()
            && response.status() != reqwest::StatusCode::TOO_MANY_REQUESTS
        {
            return self
                .fail_pending(cfg, &get_attempt, "name_proposal_rejected")
                .await;
        }
        let canonical: CanonicalName = response.error_for_status()?.json().await?;
        if !self.apply_and_ack(cfg, canonical, tx).await {
            bail!("canonical name was not persisted; proposal was not submitted");
        }
        let post_attempt = self.retry_state(cfg).await?;
        let Some(proposal) = post_attempt.pending.as_ref().filter(|p| p.error.is_none()) else {
            return Ok(());
        };
        let response = client.post(&url).bearer_auth(token)
            .json(&serde_json::json!({"expected_revision": proposal.base_revision, "name": proposal.name}))
            .send().await?;
        let status = response.status();
        if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            response.error_for_status()?;
            unreachable!("transient HTTP status is an error");
        }
        if status.is_success() || status == reqwest::StatusCode::CONFLICT {
            let canonical: CanonicalName = response.json().await?;
            self.apply_and_ack(cfg, canonical, tx).await;
            if status == reqwest::StatusCode::CONFLICT {
                self.fail_pending(cfg, &post_attempt, "name_revision_conflict")
                    .await?;
            }
        } else {
            self.fail_pending(
                cfg,
                &post_attempt,
                if status == reqwest::StatusCode::NOT_FOUND {
                    "unsupported"
                } else {
                    "name_proposal_rejected"
                },
            )
            .await?;
        }
        Ok(())
    }

    async fn fail_pending(
        &self,
        connection: &AgentConfig,
        expected: &DeviceNameJournal,
        error: &str,
    ) -> Result<()> {
        let _guard = self.lock.lock().await;
        let mut cfg = config::load(&self.path)?;
        if cfg.server_url != connection.server_url
            || cfg.agent_id != connection.agent_id
            || cfg.tenant_id != connection.tenant_id
        {
            bail!("primary changed");
        }
        let mut j = journal(&cfg);
        // Late permanent failures belong only to the GET/POST that issued
        // them, never to a replacement proposal or a newer applied push.
        if &j != expected {
            return Ok(());
        }
        let mut changed = false;
        if error == "unsupported" {
            j.error = Some(error.into());
            changed = true;
        }
        if let Some(p) = &mut j.pending {
            p.error = Some(error.into());
            changed = true;
        }
        if changed {
            cfg.name_sync = Some(j);
            config::save(&self.path, &cfg)?;
            self.publish(&cfg);
        }
        Ok(())
    }
}
