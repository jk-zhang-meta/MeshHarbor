// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! `POST /api/tunnel-client/enroll` wrapper.
//!
//! Exchanges an admin-issued enrollment JWT for a long-lived
//! `TunnelClient` JWT, then hands the result back to the orchestrator
//! which pairs it with a config-save call so the freshly-installed
//! CLI binary finds its config on first run.
//!
//! Moved here (P4a) from the legacy tunnel wizard's enroll.rs (crate
//! retired in P4c-2). The `meshharbor_cli`-coupled `write_config`
//! half lives with the dep holders (the setup app's tunnel
//! orchestrator) — this crate stays free of the tunnel dep.
//! Original rationale for not calling
//! `meshharbor-cli`'s private `enroll_cmd`:
//!   - `enroll_cmd` is private to the CLI binary and prints to stdout
//!     with `println!` — bad for a wizard-driven flow that needs
//!     structured ProgressEvents on a channel.
//!   - The wizard sends the full request body the backend expects
//!     (`os` + `client_version` in addition to the three fields the
//!     CLI sends today); see crates/api/src/routes/tunnel.rs::
//!     `TunnelEnrollRequest`. The wizard's body shape is the
//!     canonical one going forward.
//!   - Tests mock the endpoint via `MESHHARBOR_TUNNEL_ENROLL_BASE_URL`.

use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Output of a successful enroll exchange. Mirrors the backend's
/// `TunnelEnrollResponse` plus the inputs the orchestrator needs to
/// emit a `config.toml` afterwards.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct EnrollResult {
    /// Hex `ObjectId` of the row in the server's `tunnel_clients`
    /// collection. Surfaced on the Done step.
    pub tunnel_client_id: String,
    /// Hex `ObjectId` of the tenant the client belongs to. Surfaced
    /// on the Done step so the operator can click straight into the
    /// admin UI.
    pub tenant_id: String,
    /// Long-lived TunnelClient JWT (`aud = tunnel-client`). Written
    /// into `config.toml` by the caller's `write_config`. NEVER
    /// logged or echoed in error messages.
    pub tunnel_client_token: String,
    /// Echoed back into config.toml so `meshharbor forward …`
    /// derives the same WS URL on first run.
    pub server_url: String,
    /// Echoed back into config.toml. Server-side `tunnel_clients`
    /// already has it; we keep a local copy for diagnostics.
    pub machine_name: String,
}

/// Wire shape the API returns. Field names match
/// `crates/api/src/routes/tunnel.rs::TunnelEnrollResponse`.
#[derive(Debug, Deserialize)]
struct EnrollResponse {
    tunnel_client_id: String,
    tenant_id: String,
    tunnel_client_token: String,
}

/// Convert this host's `std::env::consts::OS` into the snake_case
/// discriminant the backend's `OsKind` enum expects (`linux` /
/// `macos` / `windows`). Returns `None` for unsupported OSes so the
/// caller can surface a clear "tunnel client not supported on this
/// platform" message.
fn os_discriminant() -> Option<&'static str> {
    match std::env::consts::OS {
        "linux" => Some("linux"),
        "macos" => Some("macos"),
        "windows" => Some("windows"),
        _ => None,
    }
}

// RETIRED-NAME-ANCHOR(4): a UA string that ALREADY WENT OVER THE WIRE; the server has
// these rows.
/// POST the enrollment exchange and return the parsed result. Does
/// NOT touch the filesystem; the caller pairs this with its
/// `write_config` after surfacing `EnrollOk` to the SPA.
///
/// `user_agent` is caller-supplied so each wizard keeps its
/// historical wire-visible UA (`meshharbor-tunnel-installer/<v>` for the
/// legacy shim) and the unified app sends its own.
pub async fn enroll(
    server_url: &str,
    enrollment_token: &str,
    machine_name: &str,
    client_version: &str,
    user_agent: &str,
) -> Result<EnrollResult> {
    // Test mocks point the wizard at an in-process mock server via
    // MESHHARBOR_TUNNEL_ENROLL_BASE_URL. Production: env unset, fall
    // back to the operator-provided server URL.
    let base = std::env::var("MESHHARBOR_TUNNEL_ENROLL_BASE_URL")
        .ok()
        .unwrap_or_else(|| server_url.to_string());
    let base = base.trim_end_matches('/');
    let url = format!("{base}/api/tunnel-client/enroll");

    let os =
        os_discriminant().ok_or_else(|| anyhow!("unsupported OS {:?}", std::env::consts::OS))?;
    let machine_id = derive_machine_id(machine_name);
    let body = serde_json::json!({
        "enrollment_token": enrollment_token,
        "machine_name": machine_name,
        "machine_id": machine_id,
        "os": os,
        "client_version": client_version,
    });

    let client = reqwest::Client::builder()
        .user_agent(user_agent)
        .timeout(Duration::from_secs(30))
        .build()
        .context("building reqwest client")?;

    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!("enrollment failed (HTTP {status}): {body}"));
    }
    let parsed: EnrollResponse = resp
        .json()
        .await
        .context("parsing tunnel-client enroll response")?;

    Ok(EnrollResult {
        tunnel_client_id: parsed.tunnel_client_id,
        tenant_id: parsed.tenant_id,
        tunnel_client_token: parsed.tunnel_client_token,
        server_url: server_url.to_string(),
        machine_name: machine_name.to_string(),
    })
}

/// Derive a stable opaque `machine_id` from `machine_name` + the host's
/// `OS::HOSTNAME` env + OS/arch. Mirrors
/// `agents/meshharbor-cli/src/main.rs::derive_machine_id` exactly so
/// re-enrollments from the same wizard land on the same row in the
/// server's `tunnel_clients` collection (unique index on
/// `{tenant_id, machine_id}`).
fn derive_machine_id(machine_name: &str) -> String {
    let hostname = hostname_lossy();
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let mut h = Sha256::new();
    h.update(machine_name.as_bytes());
    h.update(b"\0");
    h.update(hostname.as_bytes());
    h.update(b"\0");
    h.update(os.as_bytes());
    h.update(b"\0");
    h.update(arch.as_bytes());
    let digest = h.finalize();
    hex::encode(&digest[..16])
}

fn hostname_lossy() -> String {
    #[cfg(unix)]
    {
        std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string())
    }
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string())
    }
    #[cfg(not(any(unix, windows)))]
    {
        "unknown".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_machine_id_is_deterministic() {
        let a = derive_machine_id("same-name");
        let b = derive_machine_id("same-name");
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn derive_machine_id_changes_with_name() {
        assert_ne!(derive_machine_id("a"), derive_machine_id("b"));
    }

    #[test]
    fn os_discriminant_returns_known_values() {
        // Test box is Win11 dev box → "windows" — but the assertion
        // is loose so the CI matrix's Linux/macOS jobs also pass.
        match os_discriminant() {
            Some(v) => assert!(matches!(v, "linux" | "macos" | "windows")),
            None => panic!("os_discriminant should return Some on supported platforms"),
        }
    }

    #[test]
    fn enroll_result_serialises_round_trip() {
        let r = EnrollResult {
            tunnel_client_id: "507f1f77bcf86cd799439011".to_string(),
            tenant_id: "507f191e810c19729de860ea".to_string(),
            // Opaque test-only fake-token: deliberately NOT in JWT
            // shape so GitGuardian's `eyJ...` JWT-prefix scanner
            // doesn't flag this fixture as a real secret leak.
            tunnel_client_token: "fake-tunnel-token-for-tests".to_string(),
            server_url: "https://roomler.ai".to_string(),
            machine_name: "field-laptop".to_string(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: EnrollResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}
