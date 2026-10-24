// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Tauri invoke handlers for the unified setup wizard.
//!
//! 11 handlers — the union of the two legacy wizards' surfaces
//! behind ONE command vocabulary. Each handler returns
//! `Result<T, String>` (or a plain value) so Tauri marshals errors as
//! rejected promises the SPA renders verbatim. The raw enrollment
//! token NEVER flows back from any command — only parsed metadata
//! (H5, inherited from both legacy wizards).
//!
//! All payload structs serialise camelCase so the SPA binds
//! `view.expiresAtUnix` / `report.principalId` etc. without a
//! translation layer.

use std::sync::atomic::Ordering;

use serde::{Deserialize, Serialize};

use crate::role::Role;

// ─── Probing / status ─────────────────────────────────────────────────────────

/// Output of `cmd_detect_install`: BOTH product probes in one round
/// trip, so the Welcome step renders the daemon and tunnel detection
/// summaries from a single invoke.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectResult {
    pub agent: AgentDetect,
    pub tunnel: TunnelDetect,
}

/// Daemon (MSI) probe half. Mirrors the legacy agent wizard's
/// `DetectResult` fields — flat string discriminator for JS
/// consumption — plus the `supported` flag the unified SPA uses to
/// hide the daemon role cards on non-Windows hosts.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentDetect {
    /// `false` on non-Windows: the daemon roles are MSI-only, so the
    /// SPA shows only the tunnel-client card.
    pub supported: bool,
    /// `"clean" | "peruser" | "permachine" | "ambiguous"`.
    pub kind: String,
    /// perUser version when present, else None.
    pub peruser_version: Option<String>,
    /// perMachine version when present, else None.
    pub permachine_version: Option<String>,
    /// Whether the host has BOTH flavours installed — should never
    /// happen post-rc.18 but is surfaced explicitly so the wizard
    /// can refuse to proceed until the operator cleans up.
    pub ambiguous: bool,
}

/// Tunnel-CLI probe half. Mirrors the legacy tunnel wizard's
/// `DetectResult` (config.toml probe at the platform-default path).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelDetect {
    pub installed: bool,
    /// When installed, the recorded machine_name from the
    /// config.toml. None for clean / unreadable.
    pub machine_name: Option<String>,
    /// When installed, the config.toml path (verbatim `display()`).
    pub config_path: Option<String>,
}

/// Probe the registry (daemon MSI flavours) + the tunnel CLI config
/// path. `detect_existing_install` is itself cfg-gated in the agent
/// crate (always `Clean` on non-Windows), so the call is
/// unconditional here — only the `supported` flag needs the
/// compile-time platform check.
#[tauri::command]
pub fn cmd_detect_install() -> Result<DetectResult, String> {
    use roomlerd::install_detect::{ExistingInstall, detect_existing_install};
    let agent = match detect_existing_install() {
        ExistingInstall::Clean => AgentDetect {
            supported: cfg!(target_os = "windows"),
            kind: "clean".to_string(),
            peruser_version: None,
            permachine_version: None,
            ambiguous: false,
        },
        ExistingInstall::PerUser(info) => AgentDetect {
            supported: cfg!(target_os = "windows"),
            kind: "peruser".to_string(),
            peruser_version: info.version,
            permachine_version: None,
            ambiguous: false,
        },
        ExistingInstall::PerMachine(info) => AgentDetect {
            supported: cfg!(target_os = "windows"),
            kind: "permachine".to_string(),
            peruser_version: None,
            permachine_version: info.version,
            ambiguous: false,
        },
        ExistingInstall::Ambiguous {
            peruser,
            permachine,
        } => AgentDetect {
            supported: cfg!(target_os = "windows"),
            kind: "ambiguous".to_string(),
            peruser_version: peruser.version,
            permachine_version: permachine.version,
            ambiguous: true,
        },
    };

    let tunnel = probe_tunnel_install();

    Ok(DetectResult { agent, tunnel })
}

/// The legacy tunnel wizard's config.toml probe, verbatim: resolve
/// the platform-default path, read + TOML-parse best-effort for the
/// machine_name.
fn probe_tunnel_install() -> TunnelDetect {
    let Ok(path) = roomler_cli::config::default_config_path() else {
        return TunnelDetect {
            installed: false,
            machine_name: None,
            config_path: None,
        };
    };
    if !path.exists() {
        return TunnelDetect {
            installed: false,
            machine_name: None,
            config_path: None,
        };
    }
    let machine_name = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| toml::from_str::<roomler_cli::config::TunnelConfig>(&s).ok())
        .map(|c| c.machine_name);
    TunnelDetect {
        installed: true,
        machine_name,
        config_path: Some(path.display().to_string()),
    }
}

/// Hostname (no domain) — the wizard pre-fills the device-name input
/// with this so the operator usually just hits Enter. Falls back to
/// `"roomler-device"` if the OS won't yield a name (rare).
#[tauri::command]
pub fn cmd_default_device_name() -> String {
    gethostname::gethostname()
        .into_string()
        .unwrap_or_else(|_| "roomler-device".to_string())
}

/// Default MeshHarbor center URL. Operators usually leave this as-is;
/// staging / on-prem deployments edit it.
#[tauri::command]
pub fn cmd_default_server_url() -> String {
    crate::proxy::DEFAULT_SERVER.to_string()
}

// ─── Token introspection ─────────────────────────────────────────────────────

/// Parsed view of an enrollment token. NEVER carries the raw token
/// bytes back (H5). The Roomler server's enrollment JWTs carry the
/// discriminant in a custom `token_type` claim (snake_case, e.g.
/// `"tunnel_enrollment"`) and NO `aud` claim — `audience` stays None
/// for them; the SPA renders `token_type` in the info card.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenValidation {
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub subject: Option<String>,
    pub jti: Option<String>,
    pub expires_at_unix: Option<i64>,
    /// `true` when `exp <= now` or `exp` is missing entirely.
    pub appears_expired: bool,
    /// Server-emitted `token_type` claim via
    /// `wizard_shared::token_peek`.
    pub token_type: Option<String>,
    /// `Some(token_type == "tunnel_enrollment")` ONLY when the
    /// operator picked the tunnel-client role — catches "wrong token
    /// copied" mistakes (agent-enrollment token from Admin → Agents
    /// pasted instead of the tunnel one from Admin → Tunnels) before
    /// the POST. `None` for daemon roles / no role: daemon tokens are
    /// not gated client-side, same as the legacy agent wizard.
    pub audience_matches: Option<bool>,
    /// FR-104 — the token may also anchor the device it enrolls. `Some(true)`
    /// = it will, for this role (a Windows machine-wide install: the wizard
    /// then asks for a second administrator prompt); `Some(false)` = it could,
    /// but this role has no SYSTEM service to anchor; `None` = a plain token.
    pub will_anchor: Option<bool>,
}

/// Introspect a JWT WITHOUT verifying the signature (the wizard has
/// no signing key; the server re-verifies on every enrollment POST).
/// Used by the Token step to show "Issuer / Token type / Expires in
/// N min" before the operator hits Continue.
///
/// `rename_all = "camelCase"` so the JS arg keys bind 1:1 (see
/// `cmd_install` for the field repro that motivates the attribute).
#[tauri::command(rename_all = "camelCase")]
pub fn cmd_validate_token(token: String, role: Option<Role>) -> Result<TokenValidation, String> {
    use roomlerd::jwt_introspect::{is_likely_expired, parse_unverified};
    let view = parse_unverified(&token).map_err(|e| e.to_string())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let token_type = wizard_shared::token_peek::parse_token_type(&token);
    let audience_matches = match role {
        Some(Role::TunnelClient) => Some(token_type.as_deref() == Some("tunnel_enrollment")),
        _ => None,
    };
    let will_anchor = wizard_shared::token_peek::parse_anchor_claim(&token)
        .then(|| role.is_some_and(crate::orchestrator_agent::role_anchors));
    Ok(TokenValidation {
        appears_expired: is_likely_expired(&view, now),
        audience_matches,
        will_anchor,
        issuer: view.issuer,
        audience: view.audience,
        token_type,
        subject: view.subject,
        jti: view.jti,
        expires_at_unix: view.expires_at_unix,
    })
}

// ─── Wizard state persistence ────────────────────────────────────────────────

/// Load the wizard's persisted state. Returns `Default` (= Welcome
/// step, empty fields) when no state file exists or it's corrupt;
/// the wizard's UI always has SOMETHING to render. Token is never
/// in the state — see `wizard_shared::wizard_state` docs.
#[tauri::command]
pub fn cmd_load_state() -> Result<wizard_shared::wizard_state::WizardState, String> {
    let path = wizard_shared::wizard_state::default_state_path().map_err(|e| e.to_string())?;
    Ok(wizard_shared::wizard_state::load(&path))
}

/// Persist wizard state. Called on every form-blur from the SPA so
/// a forced kill mid-flow resumes cleanly on the next launch.
#[tauri::command]
pub fn cmd_save_state(state: wizard_shared::wizard_state::WizardState) -> Result<(), String> {
    let path = wizard_shared::wizard_state::default_state_path().map_err(|e| e.to_string())?;
    wizard_shared::wizard_state::save(&path, &state).map_err(|e| e.to_string())
}

// ─── Install execution ───────────────────────────────────────────────────────

/// Output of a successful `cmd_install`, whichever orchestrator ran.
/// Surfaced on the Done step. `principal_kind` is `"agent"` or
/// `"tunnel_client"`; the trailing `Option` fields are per-role
/// extras (flavour for daemon roles; binary/PATH details for
/// whichever pipeline delivered a CLI; config path for both).
///
/// P4b (role→action composition): daemon MSIs carry the `roomler`
/// CLI, so daemon roles now also populate `binary_path` /
/// `path_updated` and set `cli_included` from a post-install
/// existence check (`Some(false)` = an old pre-P4b MSI was served —
/// the SPA then doesn't promise a CLI that wasn't delivered).
/// `None` for the tunnel role, where the CLI *is* the install.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DoneReport {
    pub principal_kind: String,
    pub principal_id: String,
    pub tenant_id: String,
    pub tag: String,
    pub role: Role,
    pub flavour: Option<String>,
    pub binary_path: Option<String>,
    pub config_path: Option<String>,
    pub path_updated: Option<bool>,
    pub shortcut_created: Option<bool>,
    pub cli_included: Option<bool>,
    /// GAP-A/P6: daemon roles place the `roomler-desktop` GUI
    /// companion beside the daemon (it isn't in the MSI). `Some(true)`
    /// placed, `Some(false)` best-effort failure / no server asset,
    /// `None` for the tunnel role + non-Windows.
    pub desktop_installed: Option<bool>,
    /// FR-104 — the device was anchored for SYSTEM exec in this install:
    /// `Some(true)` anchored, `Some(false)` the step ran and did not (the
    /// administrator prompt was declined, or the anchor failed; the Done
    /// page then shows the manual command), `None` it did not apply (a plain
    /// token, a per-user or tunnel install, non-Windows).
    pub anchored: Option<bool>,
}

/// Drive the full install pipeline end-to-end for the picked role:
/// daemon roles route to [`crate::orchestrator_agent`] (preflight →
/// resolve → download → verify → spawn MSI → wait/decode → enroll),
/// the tunnel-client role to [`crate::orchestrator_tunnel`]
/// (preflight → resolve → download → verify → extract → integrate →
/// enroll). Progress streams over the Tauri `ipc::Channel`; every
/// event is also pushed into the replay log so a late-attaching SPA
/// listener catches up via [`cmd_install_progress_replay`]. The
/// statics + replay log reset on entry inside the orchestrators
/// (legacy semantics preserved: reset on cmd_install entry).
///
/// `rename_all = "camelCase"` because the JS SPA calls this with
/// `deviceName` / `onEvent` arg keys; Tauri 2's default is
/// snake_case which would silently leave `device_name` empty + the
/// channel null. Field repro 2026-05-15 (rc.29): operator's
/// perMachine install ran end-to-end but the Done page rendered
/// blank because the Channel was null + the orchestrator received
/// `device_name = ""`.
#[tauri::command(rename_all = "camelCase")]
pub async fn cmd_install(
    role: Role,
    server: String,
    token: String,
    device_name: String,
    advanced: Option<crate::orchestrator_agent::AdvancedOptions>,
    on_event: tauri::ipc::Channel<wizard_shared::progress::ProgressEvent>,
) -> Result<DoneReport, String> {
    match role {
        Role::TunnelClient => {
            // Advanced options are daemon-config keys — the SPA hides the
            // section for this role; ignore whatever arrives.
            crate::orchestrator_tunnel::run_install(role, server, token, device_name, on_event)
                .await
        }
        Role::DaemonSystem | Role::DaemonUser | Role::DaemonMachine => {
            crate::orchestrator_agent::run_install(
                role,
                server,
                token,
                device_name,
                advanced.unwrap_or_default(),
                on_event,
            )
            .await
        }
    }
}

/// Pre-spawn cancel: flips the process-wide
/// [`crate::CANCEL_REQUESTED`] flag. The active orchestrator bails at
/// its next `check_cancel()` (and the download loop aborts between
/// chunks). No-op once msiexec is spawned — the SPA must surface the
/// "Force-kill" affordance instead.
#[tauri::command]
pub fn cmd_cancel_in_progress() -> Result<(), String> {
    crate::CANCEL_REQUESTED.store(true, Ordering::SeqCst);
    Ok(())
}

/// Force-kill the active msiexec process (daemon roles, Windows).
/// May leave Windows Installer in a partially-rolled-back state; the
/// SPA must show a confirmation dialog before invoking this.
/// Non-Windows returns `Err("not applicable …")`.
#[tauri::command]
pub fn cmd_force_kill_msi() -> Result<(), String> {
    crate::orchestrator_agent::force_kill_msi()
}

/// Snapshot of the ProgressEvent replay log. The SPA calls this on
/// first listener attach to fast-forward through any events emitted
/// before its `ipc::Channel` listener was wired up (H1 mitigation).
#[tauri::command]
pub fn cmd_install_progress_replay() -> Vec<wizard_shared::progress::ProgressEvent> {
    wizard_shared::progress::replay_log().snapshot()
}

// ─── FR-102 P3b: opt-in setup diagnostics ────────────────────────────────────

/// The Welcome page's "Send anonymous setup diagnostics" box, as the
/// operator set it. In memory for this process only — never part of
/// `cmd_save_state`, never read back from an earlier run. Unticking also
/// drops anything buffered while it was ticked
/// ([`crate::diagnostics::Diagnostics::set_opt_in`]).
#[tauri::command]
pub fn cmd_diagnostics_opt_in(enabled: bool) {
    crate::diagnostics::Diagnostics::global().set_opt_in(enabled);
}

/// A page boundary the SPA measured: `welcome` / `server` / `token` with
/// `ok` or `cancelled` and the time spent on the page. Buffered until the
/// server is known; dropped while the box is unticked. A spelling outside
/// the vocabulary is ignored, never an error — diagnostics must not be
/// able to fail the wizard.
#[tauri::command(rename_all = "camelCase")]
pub fn cmd_diagnostics_page(step: String, outcome: String, elapsed_ms: u64) {
    use roomler_ai_remote_control::setup_diagnostics::{Outcome, Step};
    if let (Some(step), Some(outcome)) = (Step::parse(&step), Outcome::parse(&outcome)) {
        crate::diagnostics::Diagnostics::global().page(step, outcome, elapsed_ms);
    }
}

/// Cleanly exit the wizard process. Wired to the Done page's Finish
/// button. JS `window.close()` in Tauri 2 is unreliable: depending on
/// the OS-window vs webview lifecycle, it can blank the webview but
/// leave the wizard process alive (the operator sees a white/gray
/// window with no controls — field repro 2026-05-16 on a Windows
/// field-test host post-SystemContext install). `AppHandle::exit(0)`
/// shuts the runtime down deterministically.
#[tauri::command]
pub fn cmd_exit_wizard(app: tauri::AppHandle) {
    app.exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic JWTs mirroring the server's emitted shape (snake_case
    // `token_type` claim, NO `aud`). Header + signature are
    // placeholder segments (introspection doesn't validate them);
    // payloads are pre-encoded base64url so the test module doesn't
    // need a base64 dev-dep — same convention as the legacy tunnel
    // wizard's command tests.
    const FAKE_HEADER: &str = "eyJhbGciOiJub25lIn0"; // {"alg":"none"}

    /// {"iss":"roomler-ai","token_type":"tunnel_enrollment","exp":9999999999}
    fn tunnel_enrollment_jwt() -> String {
        format!(
            "{FAKE_HEADER}.eyJpc3MiOiJyb29tbGVyLWFpIiwidG9rZW5fdHlwZSI6InR1bm5lbF9lbnJvbGxtZW50IiwiZXhwIjo5OTk5OTk5OTk5fQ.sig"
        )
    }

    /// {"iss":"roomler-ai","token_type":"enrollment","exp":9999999999}
    fn agent_enrollment_jwt() -> String {
        format!(
            "{FAKE_HEADER}.eyJpc3MiOiJyb29tbGVyLWFpIiwidG9rZW5fdHlwZSI6ImVucm9sbG1lbnQiLCJleHAiOjk5OTk5OTk5OTl9.sig"
        )
    }

    /// {"iss":"roomler-ai","exp":1000000}
    fn expired_jwt() -> String {
        format!("{FAKE_HEADER}.eyJpc3MiOiJyb29tbGVyLWFpIiwiZXhwIjoxMDAwMDAwfQ.sig")
    }

    #[test]
    fn detect_result_serialises_camel_case() {
        let r = DetectResult {
            agent: AgentDetect {
                supported: true,
                kind: "peruser".to_string(),
                peruser_version: Some("0.3.0-rc.190".to_string()),
                permachine_version: None,
                ambiguous: false,
            },
            tunnel: TunnelDetect {
                installed: true,
                machine_name: Some("lap".to_string()),
                config_path: Some("/tmp/cfg.toml".to_string()),
            },
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains(r#""agent""#), "{json}");
        assert!(json.contains(r#""tunnel""#), "{json}");
        assert!(json.contains("peruserVersion"), "{json}");
        assert!(json.contains("permachineVersion"), "{json}");
        assert!(json.contains("machineName"), "{json}");
        assert!(json.contains("configPath"), "{json}");
        assert!(json.contains(r#""supported":true"#), "{json}");
        assert!(!json.contains("peruser_version"), "{json}");
        assert!(!json.contains("machine_name"), "{json}");
    }

    #[test]
    fn done_report_serialises_camel_case_with_kebab_role() {
        let r = DoneReport {
            principal_kind: "tunnel_client".to_string(),
            principal_id: "507f1f77bcf86cd799439011".to_string(),
            tenant_id: "507f191e810c19729de860ea".to_string(),
            tag: "tunnel-v0.3.0-rc.194".to_string(),
            role: Role::TunnelClient,
            flavour: None,
            // RETIRED-NAME-ANCHOR(4): fixtures of the INSTALLED layout on hosts that
            // predate the rename.
            binary_path: Some("/usr/local/bin/roomler-tunnel".to_string()),
            config_path: Some("/home/foo/.config/roomler-tunnel/config.toml".to_string()),
            path_updated: Some(true),
            shortcut_created: Some(false),
            cli_included: None,
            desktop_installed: None,
            anchored: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            json.contains(r#""principalKind":"tunnel_client""#),
            "{json}"
        );
        assert!(json.contains("principalId"), "{json}");
        assert!(json.contains("tenantId"), "{json}");
        assert!(json.contains(r#""role":"tunnel-client""#), "{json}");
        assert!(json.contains("binaryPath"), "{json}");
        assert!(json.contains("configPath"), "{json}");
        assert!(json.contains("pathUpdated"), "{json}");
        assert!(json.contains("shortcutCreated"), "{json}");
        // P4b: camelCase lock for the composition flag.
        assert!(json.contains("cliIncluded"), "{json}");
        assert!(!json.contains("cli_included"), "{json}");
        // GAP-A: camelCase lock for the desktop-companion flag.
        assert!(json.contains("desktopInstalled"), "{json}");
        assert!(!json.contains("desktop_installed"), "{json}");
        assert!(!json.contains("principal_kind"), "{json}");
        // Round-trips (Deserialize derive is part of the contract).
        let back: DoneReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.principal_id, r.principal_id);
        assert_eq!(back.role, Role::TunnelClient);
    }

    #[test]
    fn token_validation_serialises_camel_case() {
        let v = TokenValidation {
            issuer: Some("roomler-ai".to_string()),
            audience: None,
            subject: Some("507f1f77bcf86cd799439011".to_string()),
            jti: Some("abc".to_string()),
            expires_at_unix: Some(1_700_000_000),
            appears_expired: false,
            token_type: Some("tunnel_enrollment".to_string()),
            audience_matches: Some(true),
            will_anchor: Some(true),
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("audienceMatches"), "{json}");
        // FR-104 — the SPA reads `willAnchor`.
        assert!(json.contains(r#""willAnchor":true"#), "{json}");
        assert!(json.contains("expiresAtUnix"), "{json}");
        assert!(json.contains("appearsExpired"), "{json}");
        assert!(
            json.contains(r#""tokenType":"tunnel_enrollment""#),
            "{json}"
        );
        assert!(!json.contains("expires_at_unix"), "{json}");
    }

    #[test]
    fn validate_token_gates_audience_only_for_tunnel_role() {
        // Tunnel role: gate evaluates.
        let v = cmd_validate_token(tunnel_enrollment_jwt(), Some(Role::TunnelClient)).unwrap();
        assert_eq!(v.audience_matches, Some(true));
        assert_eq!(v.token_type.as_deref(), Some("tunnel_enrollment"));
        assert_eq!(v.issuer.as_deref(), Some("roomler-ai"));
        // Daemon role: no client-side gate (None), token_type still
        // surfaced for the info card.
        let v = cmd_validate_token(tunnel_enrollment_jwt(), Some(Role::DaemonSystem)).unwrap();
        assert_eq!(v.audience_matches, None);
        // No role: also ungated.
        let v = cmd_validate_token(tunnel_enrollment_jwt(), None).unwrap();
        assert_eq!(v.audience_matches, None);
    }

    #[test]
    fn validate_token_flags_wrong_type_for_tunnel_role() {
        // Operator pasted the AGENT-enrollment token (token_type
        // "enrollment") while on the tunnel-client role.
        let v = cmd_validate_token(agent_enrollment_jwt(), Some(Role::TunnelClient)).unwrap();
        assert_eq!(v.audience_matches, Some(false));
        assert_eq!(v.token_type.as_deref(), Some("enrollment"));
    }

    #[test]
    fn validate_token_reports_expiry() {
        let v = cmd_validate_token(expired_jwt(), None).unwrap();
        assert!(v.appears_expired);
        assert_eq!(v.expires_at_unix, Some(1_000_000));
    }

    #[test]
    fn validate_token_rejects_malformed() {
        assert!(cmd_validate_token("not-a-jwt".to_string(), None).is_err());
    }

    #[test]
    fn default_device_name_returns_non_empty() {
        let n = cmd_default_device_name();
        assert!(!n.is_empty());
    }

    #[test]
    fn default_server_url_is_meshharbor_center() {
        assert_eq!(
            cmd_default_server_url(),
            "https://www.itachi.fans/meshharbor"
        );
    }

    #[test]
    fn detect_install_returns_consistent_shape() {
        // Real probe on whatever host runs the tests: contract is a
        // valid discriminator + `supported` matching the compile
        // target — NOT a specific install state (dev boxes may have
        // real installs).
        let r = cmd_detect_install().unwrap();
        assert!(
            matches!(
                r.agent.kind.as_str(),
                "clean" | "peruser" | "permachine" | "ambiguous"
            ),
            "unexpected agent kind {:?}",
            r.agent.kind
        );
        assert_eq!(r.agent.supported, cfg!(target_os = "windows"));
        if !r.tunnel.installed {
            assert!(r.tunnel.config_path.is_none());
        }
    }
}
