// SPDX-License-Identifier: MPL-2.0
//! Temporary devices, the device's side: redeem an invite code for a
//! single-use enrollment token (`mh join`), ask the server whether this
//! device is temporary and until when (a renewal reaches the device this
//! way), and keep a small local marker so the daemon knows, when the server
//! says goodbye, that this was the planned end of a temporary device rather
//! than a fault to raise.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
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

/// What a redemption hands back.
#[derive(Clone, Deserialize)]
pub struct Redeemed {
    pub enrollment_token: String,
    pub tenant_id: String,
    pub access_until_ms: i64,
    #[serde(default)]
    pub inviter: String,
}

impl std::fmt::Debug for Redeemed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redeemed")
            .field("enrollment_token", &"<redacted>")
            .field("tenant_id", &self.tenant_id)
            .field("access_until_ms", &self.access_until_ms)
            .field("inviter", &self.inviter)
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

fn base(server: &str) -> String {
    server.trim().trim_end_matches('/').to_string()
}

/// `POST /api/native/device-invite/redeem`.
pub async fn redeem(server: &str, code: &str, device_name: &str) -> Result<Redeemed> {
    let Some(code) = normalize_code(code) else {
        bail!("an invite code is 8 digits, like 1234-5678");
    };
    let os = if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };
    let resp = client()?
        .post(format!("{}/api/native/device-invite/redeem", base(server)))
        .json(&serde_json::json!({ "code": code, "device_name": device_name, "device_os": os }))
        .send()
        .await
        .context("could not reach the MeshHarbor server")?;
    let status = resp.status();
    if status.is_success() {
        return resp
            .json()
            .await
            .context("unexpected answer from the server");
    }
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    match (status.as_u16(), body.get("error").and_then(|v| v.as_str())) {
        (404, _) | (_, Some("invalid_code")) => {
            bail!("this invite code is not valid (it may have expired, been revoked, or been used)")
        }
        (429, _) => bail!("too many wrong codes were tried; wait ten minutes and try again"),
        (503, _) => bail!("this server does not accept invite codes"),
        _ => bail!(
            "the server refused the code ({status}): {}",
            body.get("error")
                .or_else(|| body.get("message"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
        ),
    }
}

/// The server's word on this device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporaryInfo {
    pub access_until_ms: i64,
    #[serde(default)]
    pub inviter: String,
}

/// `GET /api/agent/self/temporary`. `Ok(None)` = an ordinary device (or a
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
    Ok(Some(TemporaryInfo {
        access_until_ms: v
            .get("access_until_ms")
            .and_then(|t| t.as_i64())
            .unwrap_or(0),
        inviter: v
            .get("inviter")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string(),
    }))
}

/// `<config dir>/temporary.json` — present while this device is temporary.
pub fn marker_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .map(|d| d.join("temporary.json"))
        .unwrap_or_else(|| PathBuf::from("temporary.json"))
}

pub fn read_marker(config_path: &Path) -> Option<TemporaryInfo> {
    let s = std::fs::read_to_string(marker_path(config_path)).ok()?;
    serde_json::from_str(&s).ok()
}

/// Record (or, with `None`, clear) what the server said. Written only when it
/// changes, through a rename, so a reader never sees half a file.
pub fn write_marker(config_path: &Path, info: Option<&TemporaryInfo>) -> Result<()> {
    let path = marker_path(config_path);
    match info {
        None => {
            if path.exists() {
                std::fs::remove_file(&path).context("removing temporary.json")?;
            }
            Ok(())
        }
        Some(i) => {
            if read_marker(config_path).as_ref() == Some(i) {
                return Ok(());
            }
            let tmp = path.with_extension("json.tmp");
            std::fs::write(&tmp, serde_json::to_vec(i)?).context("writing temporary.json")?;
            std::fs::rename(&tmp, &path).context("placing temporary.json")?;
            Ok(())
        }
    }
}

/// The temporary device's access is over: set its enrollment aside (never
/// deleted — `config.toml.ended-<unix>` keeps what it was for a person to
/// look at), and clear the marker. The machine is then simply not signed in.
pub fn end_locally(config_path: &Path) -> Result<Option<PathBuf>> {
    let _ = write_marker(config_path, None);
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

    #[test]
    fn the_marker_round_trips_and_the_end_sets_the_enrollment_aside() {
        let dir = std::env::temp_dir().join(format!("mh-temp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.toml");
        std::fs::write(&cfg, "agent_id = \"x\"\n").unwrap();
        // The recovery copy a later `config::load` would restore from.
        std::fs::write(dir.join("config.toml.prev"), "agent_id = \"x\"\n").unwrap();
        let info = TemporaryInfo {
            access_until_ms: 1_800_000_000_000,
            inviter: "Alex".into(),
        };
        write_marker(&cfg, Some(&info)).unwrap();
        assert_eq!(read_marker(&cfg), Some(info));
        let aside = end_locally(&cfg).unwrap().expect("set aside");
        assert!(!cfg.exists() && aside.exists());
        assert!(
            !dir.join("config.toml.prev").exists(),
            "no recovery copy is left to bring the ended enrollment back"
        );
        assert_eq!(read_marker(&cfg), None);
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
