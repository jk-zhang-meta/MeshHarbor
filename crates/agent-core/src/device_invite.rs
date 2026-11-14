// SPDX-License-Identifier: MPL-2.0
//! Temporary devices, the device's side: look at an invite code before
//! accepting it (who, which organization, until when), redeem it — for a
//! single-use enrollment token, or onto the enrollment this machine already
//! has in that organization (`mh join`) — ask the server whether an
//! enrollment is temporary and on whose invitations (a renewal reaches the
//! device this way), leave one invitation, and keep two small local files:
//!
//! - `temporary.json`, the marker: per enrollment (keyed by agent id), the
//!   invitations it holds, so the daemon knows, when the server says goodbye
//!   to that enrollment, that this was the planned end of its access rather
//!   than a fault to raise, and the tray can show each one;
//! - `invites.json`, the machine's history of accepted invitations with the
//!   private proof each redemption handed out. It outlives every enrollment:
//!   when the machine is (or later becomes) a device of its own owner's
//!   organization, that enrollment presents the proofs (`self/link`) and the
//!   owner's admins see what this machine accepted.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// `1234-5678`, `12345678` or `1234 5678` → the 8 digits; `None` otherwise.
pub fn normalize_code(raw: &str) -> Option<String> {
    let s: String = raw
        .trim()
        .chars()
        .filter(|c| !matches!(c, '-' | ' '))
        .collect();
    (s.len() == 8 && s.bytes().all(|b| b.is_ascii_digit())).then_some(s)
}

/// What a look at a code shows, before anything is spent.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Preview {
    pub tenant_id: String,
    #[serde(default)]
    pub org: String,
    #[serde(default)]
    pub inviter: String,
    pub access_until_ms: i64,
}

/// What a redemption hands back.
#[derive(Clone, Deserialize)]
pub struct Redeemed {
    /// Absent when the grant attached to an existing enrollment.
    #[serde(default)]
    pub enrollment_token: Option<String>,
    pub tenant_id: String,
    pub access_until_ms: i64,
    #[serde(default)]
    pub inviter: String,
    #[serde(default)]
    pub org: String,
    #[serde(default)]
    pub invite_id: String,
    #[serde(default)]
    pub device_proof: String,
    #[serde(default)]
    pub attached: bool,
}

impl std::fmt::Debug for Redeemed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redeemed")
            .field(
                "enrollment_token",
                &self.enrollment_token.as_ref().map(|_| "<redacted>"),
            )
            .field("tenant_id", &self.tenant_id)
            .field("access_until_ms", &self.access_until_ms)
            .field("inviter", &self.inviter)
            .field("org", &self.org)
            .field("invite_id", &self.invite_id)
            .field("device_proof", &"<redacted>")
            .field("attached", &self.attached)
            .finish()
    }
}

fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("meshharbor-join/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(20))
        .build()
        .context("building the HTTP client")
}

/// `https://host/x/` and `https://host/x` are the same server.
pub fn base(server: &str) -> String {
    server.trim().trim_end_matches('/').to_string()
}

fn os() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

async fn refusal(resp: reqwest::Response) -> anyhow::Error {
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    let err = body.get("error").and_then(|v| v.as_str());
    match (status.as_u16(), err) {
        (404, _) | (_, Some("invalid_code")) => anyhow::anyhow!(
            "this invite code is not valid (it may have expired, been revoked, or been used)"
        ),
        (409, Some("already_member")) => anyhow::anyhow!(
            "this device is already a regular device of that organization; it needs no invitation"
        ),
        (429, _) => {
            anyhow::anyhow!("too many wrong codes were tried; wait ten minutes and try again")
        }
        (503, _) => anyhow::anyhow!("this server does not accept invite codes"),
        _ => anyhow::anyhow!(
            "the server refused the code ({status}): {}",
            body.get("error")
                .or_else(|| body.get("message"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
        ),
    }
}

/// `POST /api/native/device-invite/preview` — spends nothing.
pub async fn preview(server: &str, code: &str) -> Result<Preview> {
    let Some(code) = normalize_code(code) else {
        bail!("an invite code is 8 digits, like 1234-5678");
    };
    let resp = client()?
        .post(format!("{}/api/native/device-invite/preview", base(server)))
        .json(&serde_json::json!({ "code": code }))
        .send()
        .await
        .context("could not reach the MeshHarbor server")?;
    if resp.status().is_success() {
        return resp
            .json()
            .await
            .context("unexpected answer from the server");
    }
    Err(refusal(resp).await)
}

/// `POST /api/native/device-invite/redeem`. `attach_token` is this machine's
/// own agent credential in the invitation's organization, when it has one.
pub async fn redeem(
    server: &str,
    code: &str,
    device_name: &str,
    attach_token: Option<&str>,
) -> Result<Redeemed> {
    let Some(code) = normalize_code(code) else {
        bail!("an invite code is 8 digits, like 1234-5678");
    };
    let mut body =
        serde_json::json!({ "code": code, "device_name": device_name, "device_os": os() });
    if let Some(t) = attach_token {
        body["attach_token"] = serde_json::json!(t);
    }
    let resp = client()?
        .post(format!("{}/api/native/device-invite/redeem", base(server)))
        .json(&body)
        .send()
        .await
        .context("could not reach the MeshHarbor server")?;
    if resp.status().is_success() {
        return resp
            .json()
            .await
            .context("unexpected answer from the server");
    }
    Err(refusal(resp).await)
}

/// One invitation an enrollment holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantInfo {
    #[serde(default)]
    pub invite_id: String,
    #[serde(default)]
    pub inviter: String,
    #[serde(default)]
    pub org: String,
    pub access_until_ms: i64,
}

/// The server's word on one enrollment of this machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporaryInfo {
    /// The latest deadline among its invitations.
    pub access_until_ms: i64,
    #[serde(default)]
    pub inviter: String,
    #[serde(default)]
    pub org: String,
    /// Each invitation (empty from a server older than several per device:
    /// then `access_until_ms` / `inviter` are the one).
    #[serde(default)]
    pub grants: Vec<GrantInfo>,
}

impl TemporaryInfo {
    /// The invitations, one per line in the tray — the legacy single one
    /// when the server listed none.
    pub fn each(&self) -> Vec<GrantInfo> {
        if self.grants.is_empty() {
            vec![GrantInfo {
                invite_id: String::new(),
                inviter: self.inviter.clone(),
                org: self.org.clone(),
                access_until_ms: self.access_until_ms,
            }]
        } else {
            self.grants.clone()
        }
    }
}

/// `GET /api/agent/self/temporary`. `Ok(None)` = an ordinary enrollment (or a
/// server without the feature); `Err` = no answer.
pub async fn self_status(server: &str, agent_token: &str) -> Result<Option<TemporaryInfo>> {
    let resp = client()?
        .get(format!("{}/api/agent/self/temporary", base(server)))
        .bearer_auth(agent_token)
        .send()
        .await
        .context("GET /api/agent/self/temporary")?;
    if resp.status().as_u16() == 404 {
        return Ok(None); // a server older than the feature
    }
    if !resp.status().is_success() {
        bail!("self/temporary answered {}", resp.status());
    }
    let v: serde_json::Value = resp.json().await.context("self/temporary body")?;
    if v.get("temporary").and_then(|t| t.as_bool()) != Some(true) {
        return Ok(None);
    }
    let s = |k: &str| v.get(k).and_then(|t| t.as_str()).unwrap_or("").to_string();
    let grants = v
        .get("grants")
        .cloned()
        .and_then(|g| serde_json::from_value::<Vec<GrantInfo>>(g).ok())
        .unwrap_or_default();
    Ok(Some(TemporaryInfo {
        access_until_ms: v
            .get("access_until_ms")
            .and_then(|t| t.as_i64())
            .unwrap_or(0),
        inviter: s("inviter"),
        org: s("org"),
        grants,
    }))
}

/// `POST /api/agent/self/temporary/{id}/leave` — leave ONE invitation.
/// `Ok(true)` = it was the enrollment's last, so the enrollment is gone.
pub async fn leave_one(server: &str, agent_token: &str, invite_id: &str) -> Result<bool> {
    if invite_id.is_empty() || !invite_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("not an invitation id: {invite_id:?}");
    }
    let resp = client()?
        .post(format!(
            "{}/api/agent/self/temporary/{invite_id}/leave",
            base(server)
        ))
        .bearer_auth(agent_token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .context("could not reach the MeshHarbor server")?;
    if !resp.status().is_success() {
        bail!("the server did not accept the leave ({})", resp.status());
    }
    let v: serde_json::Value = resp.json().await.unwrap_or_default();
    Ok(v.get("device_removed").and_then(|b| b.as_bool()) == Some(true))
}

/// `POST /api/agent/self/link` — present this machine's proofs from an
/// ordinary enrollment. Returns how many newly linked.
pub async fn link(server: &str, agent_token: &str, history: &[HistoryEntry]) -> Result<u64> {
    let proofs: Vec<_> = history
        .iter()
        .filter(|h| base(&h.server_url) == base(server) && !h.proof.is_empty())
        .take(200)
        .map(|h| serde_json::json!({ "invite_id": h.invite_id, "proof": h.proof }))
        .collect();
    if proofs.is_empty() {
        return Ok(0);
    }
    let resp = client()?
        .post(format!("{}/api/agent/self/link", base(server)))
        .bearer_auth(agent_token)
        .json(&serde_json::json!({ "proofs": proofs }))
        .send()
        .await
        .context("POST /api/agent/self/link")?;
    if !resp.status().is_success() {
        bail!("self/link answered {}", resp.status());
    }
    let v: serde_json::Value = resp.json().await.unwrap_or_default();
    Ok(v.get("linked").and_then(|n| n.as_u64()).unwrap_or(0))
}

// ─── the marker ─────────────────────────────────────────────────────────────

/// The key a pre-multi-invitation marker's one entry is read under: the
/// primary enrollment's.
pub const PRIMARY_KEY: &str = "primary";

#[derive(Debug, Default, Serialize, Deserialize)]
struct MarkerFile {
    #[serde(default)]
    enrollments: BTreeMap<String, TemporaryInfo>,
}

/// `<config dir>/temporary.json` — present while an enrollment is temporary.
pub fn marker_path(config_path: &Path) -> PathBuf {
    beside_config(config_path, "temporary.json")
}

fn beside_config(config_path: &Path, name: &str) -> PathBuf {
    config_path
        .parent()
        .map(|d| d.join(name))
        .unwrap_or_else(|| PathBuf::from(name))
}

/// Every temporary enrollment of this machine, keyed by agent id (an old
/// single-entry marker reads as [`PRIMARY_KEY`]).
pub fn read_markers(config_path: &Path) -> BTreeMap<String, TemporaryInfo> {
    let Ok(s) = std::fs::read_to_string(marker_path(config_path)) else {
        return BTreeMap::new();
    };
    if let Ok(f) = serde_json::from_str::<MarkerFile>(&s)
        && !f.enrollments.is_empty()
    {
        return f.enrollments;
    }
    match serde_json::from_str::<TemporaryInfo>(&s) {
        Ok(one) => BTreeMap::from([(PRIMARY_KEY.to_string(), one)]),
        Err(_) => BTreeMap::new(),
    }
}

/// The marker of one enrollment (`is_primary` also reads the legacy entry).
pub fn marker_for(config_path: &Path, agent_id: &str, is_primary: bool) -> Option<TemporaryInfo> {
    let mut all = read_markers(config_path);
    all.remove(agent_id)
        .or_else(|| is_primary.then(|| all.remove(PRIMARY_KEY)).flatten())
}

/// Is any enrollment of this machine temporary?
pub fn read_marker(config_path: &Path) -> Option<TemporaryInfo> {
    read_markers(config_path).into_values().next()
}

static MARKER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Record (or, with `None`, clear) what the server said about one
/// enrollment. Written only when it changes, through a rename, so a reader
/// never sees half a file; the file goes when no enrollment is temporary.
pub fn write_marker_for(
    config_path: &Path,
    agent_id: &str,
    is_primary: bool,
    info: Option<&TemporaryInfo>,
) -> Result<()> {
    let _g = MARKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let before = read_markers(config_path);
    let mut all = before.clone();
    if is_primary {
        all.remove(PRIMARY_KEY);
    }
    match info {
        Some(i) => {
            all.insert(agent_id.to_string(), i.clone());
        }
        None => {
            all.remove(agent_id);
        }
    }
    if all == before {
        return Ok(());
    }
    let path = marker_path(config_path);
    if all.is_empty() {
        if path.exists() {
            std::fs::remove_file(&path).context("removing temporary.json")?;
        }
        return Ok(());
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(&MarkerFile { enrollments: all })?)
        .context("writing temporary.json")?;
    std::fs::rename(&tmp, &path).context("placing temporary.json")?;
    Ok(())
}

// ─── the machine's history and proofs ───────────────────────────────────────

/// One invitation this machine accepted.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub invite_id: String,
    /// The private proof the redemption handed out.
    pub proof: String,
    pub server_url: String,
    pub tenant_id: String,
    #[serde(default)]
    pub org: String,
    #[serde(default)]
    pub inviter: String,
    pub access_until_ms: i64,
    pub accepted_at_ms: i64,
}

impl std::fmt::Debug for HistoryEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryEntry")
            .field("invite_id", &self.invite_id)
            .field("proof", &"<redacted>")
            .field("tenant_id", &self.tenant_id)
            .finish()
    }
}

/// `<config dir>/invites.json`.
pub fn history_path(config_path: &Path) -> PathBuf {
    beside_config(config_path, "invites.json")
}

pub fn read_history(config_path: &Path) -> Vec<HistoryEntry> {
    std::fs::read_to_string(history_path(config_path))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Add an accepted invitation (kept for good: it is the machine's record).
pub fn append_history(config_path: &Path, entry: HistoryEntry) -> Result<()> {
    let _g = MARKER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut all = read_history(config_path);
    if all.iter().any(|h| h.invite_id == entry.invite_id) {
        return Ok(());
    }
    all.push(entry);
    let path = history_path(config_path);
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&all)?).context("writing invites.json")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, &path).context("placing invites.json")?;
    Ok(())
}

// ─── the end of an enrollment's access ──────────────────────────────────────

/// The machine's last enrollment's access is over: set it aside (never
/// deleted — `config.toml.ended-<unix>` keeps what it was for a person to
/// look at), and clear the marker. The machine is then simply not signed in.
pub fn end_locally(config_path: &Path) -> Result<Option<PathBuf>> {
    let _ = std::fs::remove_file(marker_path(config_path));
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let beside = |suffix: &str| {
        let mut p = config_path.as_os_str().to_owned();
        p.push(suffix);
        PathBuf::from(p)
    };
    // The recovery copy FIRST: `config::load` restores a missing config from
    // `config.toml.prev` (field, Surface 2026-11-14: a load one second after
    // the end brought the ended enrollment back). With it gone first, no
    // load in between can resurrect anything.
    let prev = config_path.with_extension("toml.prev");
    if prev.exists() {
        std::fs::rename(&prev, beside(&format!(".ended-{secs}.prev")))
            .context("setting the previous config copy aside")?;
    }
    if !config_path.exists() {
        return Ok(None);
    }
    let aside = beside(&format!(".ended-{secs}"));
    std::fs::rename(config_path, &aside).context("setting the enrollment aside")?;
    Ok(Some(aside))
}

/// What ending one enrollment's access did to this machine's config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalEnd {
    /// It was the only enrollment: the machine is no longer signed in.
    SignedOut(Option<PathBuf>),
    /// It was the primary; another enrollment took the primary's place
    /// (the daemon must restart to run it as such).
    Promoted { label: String },
    /// A secondary enrollment, removed from `[[orgs]]`.
    OrgRemoved { label: String },
    /// No enrollment of the config has that agent id.
    NotFound,
}

/// End the access of the enrollment `agent_id` locally, keeping every other
/// enrollment of the machine. A primary with others beside it hands the
/// primary's place to one of them — an ordinary one first, so the owner's
/// own account drives the machine.
pub fn end_enrollment_locally(config_path: &Path, agent_id: &str) -> Result<LocalEnd> {
    let path = config_path.to_path_buf();
    let mut cfg = crate::config::load(&path).context("reading the config")?;
    let markers = read_markers(config_path);
    let outcome = if cfg.agent_id == agent_id {
        if cfg.orgs.is_empty() {
            return Ok(LocalEnd::SignedOut(end_locally(config_path)?));
        }
        let next = cfg
            .orgs
            .iter()
            .find(|o| !markers.contains_key(&o.agent_id))
            .or_else(|| cfg.orgs.first())
            .map(|o| o.label.clone())
            .expect("orgs is not empty");
        let demoted = format!("ended-{}", &agent_id[..agent_id.len().min(8)]);
        crate::config::promote_keeping_mesh(&mut cfg, &next, Some(&demoted))?;
        cfg.orgs.retain(|o| o.agent_id != agent_id);
        LocalEnd::Promoted { label: next }
    } else if let Some(o) = cfg.orgs.iter().find(|o| o.agent_id == agent_id) {
        let label = o.label.clone();
        cfg.orgs.retain(|o| o.agent_id != agent_id);
        LocalEnd::OrgRemoved { label }
    } else {
        return Ok(LocalEnd::NotFound);
    };
    crate::config::save(&path, &cfg).context("writing the config")?;
    let _ = write_marker_for(config_path, agent_id, false, None);
    Ok(outcome)
}

/// "2 d 3 h", "45 min" — what is left, for people.
pub fn remaining_words(until_ms: i64, now_ms: i64) -> String {
    let secs = (until_ms - now_ms).max(0) / 1000;
    let (d, h, m) = (secs / 86_400, (secs % 86_400) / 3600, (secs % 3600) / 60);
    if d >= 1 {
        format!("{d} d {h} h")
    } else if h >= 1 {
        format!("{h} h {m} min")
    } else {
        format!("{} min", m.max(if secs > 0 { 1 } else { 0 }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_normalize_leniently_and_nothing_else_passes() {
        assert_eq!(normalize_code("1234-5678").as_deref(), Some("12345678"));
        assert_eq!(normalize_code(" 1234 5678 ").as_deref(), Some("12345678"));
        for bad in ["", "1234-567", "1234-56789", "abcd-efgh", "1234_5678"] {
            assert_eq!(normalize_code(bad), None, "{bad}");
        }
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mh-temp-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn info(until: i64, who: &str) -> TemporaryInfo {
        TemporaryInfo {
            access_until_ms: until,
            inviter: who.into(),
            org: "Acme".into(),
            grants: vec![GrantInfo {
                invite_id: "aa".into(),
                inviter: who.into(),
                org: "Acme".into(),
                access_until_ms: until,
            }],
        }
    }

    #[test]
    fn the_marker_keeps_each_enrollment_and_reads_the_old_single_form() {
        let dir = tmpdir("marker");
        let cfg = dir.join("config.toml");
        // A marker written by a build that knew one invitation per device.
        std::fs::write(
            marker_path(&cfg),
            r#"{"access_until_ms":1800000000000,"inviter":"Alex"}"#,
        )
        .unwrap();
        let old = marker_for(&cfg, "p1", true).expect("legacy entry is the primary's");
        assert_eq!(old.each()[0].inviter, "Alex");
        assert!(marker_for(&cfg, "p1", false).is_none());

        write_marker_for(&cfg, "p1", true, Some(&info(1, "Alex"))).unwrap();
        write_marker_for(&cfg, "s2", false, Some(&info(2, "Bo"))).unwrap();
        let all = read_markers(&cfg);
        assert_eq!(all.len(), 2, "the legacy key is replaced: {all:?}");
        assert_eq!(all["s2"].inviter, "Bo");
        write_marker_for(&cfg, "p1", true, None).unwrap();
        write_marker_for(&cfg, "s2", false, None).unwrap();
        assert!(
            !marker_path(&cfg).exists(),
            "no temporary enrollment, no file"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_end_sets_the_enrollment_aside() {
        let dir = tmpdir("end");
        let cfg = dir.join("config.toml");
        std::fs::write(&cfg, "agent_id = \"x\"\n").unwrap();
        // The recovery copy a later `config::load` would restore from.
        std::fs::write(dir.join("config.toml.prev"), "agent_id = \"x\"\n").unwrap();
        write_marker_for(&cfg, "x", true, Some(&info(1, "Alex"))).unwrap();
        append_history(
            &cfg,
            HistoryEntry {
                invite_id: "aa".into(),
                proof: "p".repeat(64),
                server_url: "https://h/".into(),
                tenant_id: "t".into(),
                org: String::new(),
                inviter: String::new(),
                access_until_ms: 1,
                accepted_at_ms: 1,
            },
        )
        .unwrap();
        let aside = end_locally(&cfg).unwrap().expect("set aside");
        assert!(!cfg.exists() && aside.exists());
        assert!(
            !dir.join("config.toml.prev").exists(),
            "no recovery copy is left to bring the ended enrollment back"
        );
        assert!(read_markers(&cfg).is_empty());
        assert_eq!(
            read_history(&cfg).len(),
            1,
            "the machine's history outlives it"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remaining_time_reads_like_a_person_would_say_it() {
        let h = 3_600_000;
        assert_eq!(remaining_words(50 * h, 0), "2 d 2 h");
        assert_eq!(remaining_words(3 * h + 120_000, 0), "3 h 2 min");
        assert_eq!(remaining_words(30_000, 0), "1 min");
        assert_eq!(remaining_words(0, 5), "0 min");
    }
}
