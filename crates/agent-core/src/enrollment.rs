// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! One-shot enrollment exchange.
//!
//! Flow: admin issues an enrollment token in the Roomler UI and hands it to
//! the machine operator. `roomlerd enroll --token <t>` posts it to
//! `POST /api/agent/enroll` with machine metadata, gets back a long-lived
//! agent token, and persists everything to the config file.

use anyhow::{Context, Result, bail};
use roomler_ai_remote_control::models::OsKind;
pub use roomler_ai_remote_control::models::{InstallInfo, InstallMethod, InstallScope};
use serde::{Deserialize, Serialize};

use crate::config::AgentConfig;

/// Env fallbacks for the install trace (FR-102 P3): what `roomlerd enroll`
/// reads when `--install-method` / `--install-scope` are not passed. The
/// served install scripts set these rather than passing the flags, so an
/// agent from before P3 — which has no such flag and would refuse it —
/// still enrolls from a post-P3 script; it simply ignores the variables.
/// For the same reason a value in them that this build does not know is
/// clamped, never refused ([`resolve_install`]).
pub const INSTALL_METHOD_ENV: &str = "ROOMLER_INSTALL_METHOD";
pub const INSTALL_SCOPE_ENV: &str = "ROOMLER_INSTALL_SCOPE";

#[derive(Debug, Serialize)]
struct EnrollRequest<'a> {
    enrollment_token: &'a str,
    machine_id: &'a str,
    machine_name: &'a str,
    os: OsKind,
    agent_version: &'a str,
    /// FR-102 P3 — additive, and OMITTED when unset: a server from before
    /// P3 then sees exactly the body it always saw. (It would ignore an
    /// unknown field anyway — the server's `EnrollRequest` carries no
    /// `deny_unknown_fields` — but the shape on the wire should not change
    /// for a caller that has nothing to say.)
    #[serde(skip_serializing_if = "Option::is_none")]
    install: Option<&'a InstallInfo>,
}

#[derive(Debug, Deserialize)]
struct EnrollResponse {
    agent_id: String,
    tenant_id: String,
    agent_token: String,
    /// FR-51 — the server says what it minted. `#[serde(default)]` so a
    /// pre-FR-51 server (which omits the field) reads as permanent.
    #[serde(default)]
    ephemeral: bool,
}

pub struct EnrollInputs<'a> {
    pub server_url: &'a str,
    pub enrollment_token: &'a str,
    pub machine_id: &'a str,
    pub machine_name: &'a str,
    /// FR-102 P3 — how this install happened, when the caller knows: the
    /// wizard says `wizard`, the scripts say which script, a hand-typed
    /// `roomlerd enroll` says `manual` ([`resolve_install`]). `None` sends
    /// nothing, which the server records as `unknown` on a new row and
    /// leaves alone on a re-enrolled one — the right answer for every
    /// re-enroll path, which knows nothing about how the binary got there.
    pub install: Option<InstallInfo>,
}

/// FR-102 P3 — what `roomlerd enroll` sends as its install trace, from the
/// CLI flags first, the environment second, and `manual` when neither
/// says: a person typed the command. The scope defaults to `unknown`.
///
/// A value outside the vocabulary is judged by where it came from:
///
/// - from a **flag** it is an ERROR — the operator's own command line, and a
///   typo should be seen at the prompt, before the single-use token is
///   spent, rather than stored as `other` forever;
/// - from the **environment** it is CLAMPED (`other` / `unknown`) with a
///   warning, never refused. The variables are set by the served scripts,
///   which are compiled into the SERVER (`include_str!` in
///   `setup_release.rs`) and roll with a promote, while the daemon they
///   install comes from the agent release channel: a script can learn a
///   spelling before the daemon it installs does, and refusing it would
///   fail every scripted enrollment until the next agent release. The trace
///   is a measurement; it never costs a device its enrollment — the server
///   clamps the same way ([`InstallInfo::clamped`]).
///
/// Spellings: [`InstallMethod::ALL`] and [`InstallScope::ALL`].
pub fn resolve_install(cli_method: Option<&str>, cli_scope: Option<&str>) -> Result<InstallInfo> {
    let env = |key: &str| std::env::var(key).ok().filter(|v| !v.trim().is_empty());
    resolve_install_from(
        cli_method,
        cli_scope,
        env(INSTALL_METHOD_ENV).as_deref(),
        env(INSTALL_SCOPE_ENV).as_deref(),
    )
}

/// [`resolve_install`] with the environment passed in, so the precedence is
/// testable without touching the process environment.
pub fn resolve_install_from(
    cli_method: Option<&str>,
    cli_scope: Option<&str>,
    env_method: Option<&str>,
    env_scope: Option<&str>,
) -> Result<InstallInfo> {
    /// The raw value, where it came from, and whether that was the flag —
    /// CLI first.
    fn source<'a>(
        flag: &'static str,
        env_key: &'static str,
        cli: Option<&'a str>,
        env: Option<&'a str>,
    ) -> Option<(&'a str, &'static str, bool)> {
        cli.map(|v| (v.trim(), flag, true))
            .or_else(|| env.map(|v| (v.trim(), env_key, false)))
    }
    /// A spelling outside the vocabulary: refused from a flag, clamped to
    /// `fallback` (with a warning) from the environment.
    fn unknown_spelling<T>(
        what: &str,
        raw: &str,
        origin: &str,
        from_flag: bool,
        allowed: &[&str],
        fallback: T,
        fallback_wire: &str,
    ) -> Result<T> {
        if from_flag {
            bail!(
                "invalid install {what} {raw:?} from {origin}: expected one of {}",
                allowed.join(", ")
            );
        }
        tracing::warn!(
            value = raw,
            origin,
            "install {what} not known to this build; enrolling with {fallback_wire:?}"
        );
        Ok(fallback)
    }

    let method = match source(
        "--install-method",
        INSTALL_METHOD_ENV,
        cli_method,
        env_method,
    ) {
        None => InstallMethod::Manual,
        Some((raw, origin, from_flag)) => match InstallMethod::parse(raw) {
            Some(m) => m,
            None => {
                let allowed: Vec<&str> = InstallMethod::ALL.iter().map(|m| m.wire()).collect();
                unknown_spelling(
                    "method",
                    raw,
                    origin,
                    from_flag,
                    &allowed,
                    InstallMethod::Other,
                    InstallMethod::Other.wire(),
                )?
            }
        },
    };
    let scope = match source("--install-scope", INSTALL_SCOPE_ENV, cli_scope, env_scope) {
        None => InstallScope::Unknown,
        Some((raw, origin, from_flag)) => match InstallScope::parse(raw) {
            Some(s) => s,
            None => {
                let allowed: Vec<&str> = InstallScope::ALL.iter().map(|s| s.wire()).collect();
                unknown_spelling(
                    "scope",
                    raw,
                    origin,
                    from_flag,
                    &allowed,
                    InstallScope::Unknown,
                    InstallScope::Unknown.wire(),
                )?
            }
        },
    };
    Ok(InstallInfo::new(method, scope))
}

pub async fn enroll(inputs: EnrollInputs<'_>) -> Result<AgentConfig> {
    // Promote http:// to https://. The production ingress 301-redirects
    // plaintext to TLS; reqwest then downgrades the POST to a GET (RFC
    // 7231 historical behavior for 301/302) so the second hop hits a
    // route that exists for POST but not GET, producing a 405. Doing the
    // upgrade upfront also keeps the enrollment token off the wire in
    // cleartext, and ensures the stored server_url derives wss:// (not
    // ws://) for the long-lived signaling connection.
    let server_url = normalize_server_url(inputs.server_url);
    let url = format!("{server_url}/api/agent/enroll");
    let os = detect_os();
    let agent_version = env!("CARGO_PKG_VERSION");

    tracing::info!(
        %url, os = ?os,
        install_method = inputs.install.as_ref().map(|i| i.method.as_str()),
        install_scope = inputs.install.as_ref().map(|i| i.scope.as_str()),
        "posting enrollment"
    );

    let resp = reqwest::Client::new()
        .post(&url)
        .json(&EnrollRequest {
            enrollment_token: inputs.enrollment_token,
            machine_id: inputs.machine_id,
            machine_name: inputs.machine_name,
            os,
            agent_version,
            install: inputs.install.as_ref(),
        })
        .send()
        .await
        .context("POST /api/agent/enroll")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("enrollment rejected (status {status}): {body}");
    }

    let body: EnrollResponse = resp.json().await.context("parsing enroll response")?;

    Ok(AgentConfig {
        server_url,
        ws_url: None,
        agent_token: body.agent_token,
        agent_id: body.agent_id,
        tenant_id: body.tenant_id,
        machine_id: inputs.machine_id.to_string(),
        machine_name: inputs.machine_name.to_string(),
        // FR-51 — the server's answer, not the caller's flag: the credential
        // decides what was minted, and the config must not disagree.
        ephemeral: body.ephemeral,
        encoder_preference: crate::config::EncoderPreferenceChoice::default(),
        update_check_interval_h: None,
        localapi_pipe_pool: None,
        enable_remote_browse: true,
        files_dir: None,
        auto_grant_session: true,
        // Fleet RPC stays OFF on a freshly enrolled device: enabling it is a
        // deliberate act by whoever holds the box, never a side effect of
        // joining an org.
        exec_enabled: false,
        // FR-43 P1 — macOS root-daemon supervision of the GUI worker; off at
        // enrollment like every other posture switch.
        macos_supervise_gui_worker: false,
        power_policy: String::new(),
        // FR-84 D6 — the companion opens after install and starts at login by
        // default; a RE-enrollment keeps whatever the device had (the
        // `..existing` tail of `preserve_operator_config`).
        companion_autostart: true,
        // Same rule, one level up: accepting PUSHED config is the opt-in that
        // makes the two flags above refusable by a compromised control plane
        // (`docs/remote-config.md`). Joining an org must never turn it on —
        // that would let enrollment itself hand the server the local veto.
        remote_config_enabled: false,
        // FR-84 D3 — the built-in default (a person at a fresh device may
        // restart it from the companion); `preserve_operator_config` keeps an
        // owner's OFF across a re-enrollment.
        local_restart_enabled: true,
        external_access_enabled: false,
        external_access_setup: None,
        external_access_verifier: None,
        external_consent_mode: None,
        external_max_permissions: None,
        // Same rule for SSH, which grants strictly more than a bounded command.
        // `preserve_operator_config` keeps all three across a RE-enrollment
        // (they sit in the `..existing` tail), so a device that opted in stays
        // opted in.
        ssh_enabled: false,
        ssh_port: None,
        ssh_authorized_keys: Vec::new(),
        // Minted on the first SSH-enabled start, not at enrollment: a device
        // that never turns SSH on never generates a host key at all.
        ssh_host_key: None,
        ssh_account_mode: None,
        ssh_max_privilege: None,
        ssh_activity_log: false,
        // FR-90 — a freshly enrolled device runs no agent sessions: every
        // Hive gate starts closed, and only whoever holds the box opens them.
        hive_enabled: false,
        hive_accounts: Default::default(),
        hive_roots: Vec::new(),
        hive_max_sessions: None,
        hive_harness: None,
        hive_api_key_helper: None,
        hive_api_workspace_id: None,
        hive_update_wait_secs: None,
        hive_core_memory: false,
        hive_adopt: false,
        hive_allow_passwordless_sudo: false,
        hive_replica: false,
        hive_archive: false,
        hive_store_quota_mib: None,
        vault_enabled: false,
        vault_activity_log: false,
        hive_net: false,
        hive_ssh: false,
        // FR-89: on, like every fresh install; `false` is the kill switch
        // an owner reaches for, never a starting point.
        ssh_exec_streaming: true,
        // S2 env-bridged knobs: unset → built-in defaults.
        overlay_quic: None,
        overlay_direct: None,
        overlay_derp: None,
        overlay_server_relay_strategy: None,
        overlay_derp_floor: None,
        overlay_org_relay: None,
        overlay_netcheck: None,
        relay_server_enabled: None,
        relay_server_port: None,
        tunnel_derp_fallback: None,
        tunnel_reupgrade: None,
        tunnel_peers_survive_reattach: None,
        overlay_mbb: None,
        overlay_lan_iface_filter: None,
        overlay_wsl_mirrored_guard: None,
        overlay_init_auth_first: None,
        overlay_srflx_seek: None,
        ws_replaced_exit: None,
        overlay_warm_relay: None,
        overlay_quic_async: None,
        overlay_vpn_vantage: None,
        overlay_portmap: None,
        overlay_ipv6: None,
        net_inventory: None,
        overlay_netstack_tcp_rx_buf: None,
        overlay_netstack_tcp_tx_buf: None,
        overlay_netstack_tcp_cc: None,
        overlay_netstack_tcp_pacing: None,
        overlay_netd: None,
        overlay_pathmon: None,
        overlay_route_events: None,
        overlay_route_tick_secs: None,
        overlay_netmon: None,
        overlay_netmon_debounce_ms: None,
        overlay_relay_tls: None,
        overlay_shared_carrier: None,
        overlay_roam: None,
        overlay_plane_watchdog: None,
        overlay_session_trace: None,
        overlay_data_probe: None,
        overlay_disco_respond: None,
        overlay_disco_probe: None,
        overlay_answer_while_followed: None,
        overlay_tun_stable_guid: None,
        overlay_route_evict: None,
        overlay_iface_metric: None,
        overlay_route_reclaim: None,
        overlay_route_evict_winners_only: None,
        overlay_lan_route_repair: None,
        overlay_tun_persist: None,
        overlay_route_metric0: None,
        overlay_route_win: None,
        local_turn: None,
        dns_aaaa: None,
        magicdns_hosts: None,
        auto_update: None,
        logs_upload_disabled: None,
        rate_factor_h264: None,
        rate_factor_hevc: None,
        rate_factor_vp9: None,
        rate_factor_av1: None,
        rate_factor_h264_444: None,
        rate_factor_hevc_444: None,
        rate_factor_vp9_444: None,
        lanczos_min_pct: None,
        nvenc_spatial_aq: None,
        scale_cq_boost: None,
        idle_refine: None,
        idle_refine_balanced: None,
        gpu_scale: None,
        overlay_lan_capture_probe: None,
        relay_ceiling_learn: None,
        drm_capture: None,
        uinput: None,
        portal_capture: None,
        portal_input: None,
        mutter_capture: None,
        window_capture: None,
        wayland_aware: None,
        wayland_auto: None,
        wayland_auto_system: None,
        x11_auto_system: None,
        mutter_input: None,
        x11_damage: None,
        overlay_key_rotation: None,
        idle_refine_max_edge: None,
        relay_max_hi_kbps: None,
        idle_refine_min_frame_kb: None,
        idle_refine_major_area_permille: None,
        idle_refine_settle_ms: None,
        idle_refine_settle_constrained_ms: None,
        constrained_cq_relief: None,
        constrained_queue_ms: None,
        constrained_hrd_pct: None,
        direct_queue_ms: None,
        direct_hrd_pct: None,
        area_min_bitrate: None,
        measured_ceiling: None,
        encoder_inplace_rate: None,
        ice_relay_tcp: None,
        relay_max_kbps: None,
        rate_slow_start: None,
        media_thread: None,
        pump_stall_watch: None,
        pump_stall_warn_ms: None,
        bg_rebuild_constrained: None,
        slow_link_floor: None,
        slow_link_min_bitrate: None,
        constrained_queue_measured: None,
        seed_contradiction: None,
        viewer_rate_clamp: None,
        queue_drain: None,
        slow_link_profile: None,
        slow_link_profile_bps: None,
        bg_rebuild: None,
        par_convert: None,
        fps_pace: None,
        relay_idr_thrift: None,
        relay_age_feedback: None,
        send_stall_ms: None,
        priority_res_cap: None,
        smoother_rate_pct: None,
        balanced_rate_pct: None,
        scale_threads: None,
        ice_follow_renomination: None,
        ice_warm_standby: None,
        ice_overlay_host_deprioritize: None,
        overlay_tier_detect: None,
        overlay_rtt_q: None,
        relay_probe: None,
        text_mod_neutralize: None,
        caps_cache: None,
        fps_high: None,
        encoder_cells_deny: None,
        fps_deny: None,
        vaapi_device: None,
        d3d12_adapter: None,
        vulkan_device: None,
        record_dir: None,
        record_remote_enabled: false,
        record_remote_audio: false,
        // FR-92 — on by default (operator decision 2026-10-10); the owner
        // turns it off.
        keep_busy_enabled: true,
        // FR-99 — off until the device's owner allows it.
        privacy_mode_allowed: false,
        lock_on_end: Default::default(),
        // FR-108 — display match only while nobody is using the screen.
        display_match: Default::default(),
        // FR-100 P1c — check every browser that offers a session; refuse none.
        peer_auth: Default::default(),
        // FR-101 P2b — no floor of the device's own until its owner sets one.
        rc_clipboard: Default::default(),
        rc_files: Default::default(),
        rc_audio: Default::default(),
        // FR-101 P1b — TLS to the server; a lab says otherwise on the device.
        allow_plaintext_server: false,
        overlay_demote: None,
        overlay_upward_probe: None,
        rc_max_sessions: None,
        overlay_direct_port: None,
        shared_encoder: None,
        overlay_rpf: None,
        last_known_good_version: None,
        crash_count: 0,
        last_crash_unix: 0,
        rollback_attempted: false,
        last_run_unhealthy: false,
        // Stamp the current schema version directly on enrollment so
        // a fresh install skips the rc.18 migration on first launch.
        config_schema_version: Some(crate::config::CURRENT_SCHEMA_VERSION.to_string()),
        // T2.8 default = enabled + empty allowlist (trust server).
        forward_acl: crate::acl::AgentForwardAcl::default(),
        // Remote app-launch: default = enabled with a seeded bash/tmux entry.
        virtual_desktop_apps: crate::apps_config::VirtualDesktopAppsConfig::default(),
        // Phase 3b: overlay opt-in, off until the operator enables it.
        overlay_enabled: false,
        // Multi-org P2c: secondary-org TUN sharing, off until opted in.
        overlay_multi_org: false,
        netstack_socks_port: None,
        derived_org: false,
        derived_netstack: false,
        overlay_wg_secret_key: None,
        overlay_wg_key_epoch: 0,
        // Phase 1: no advertised subnet routes until the operator configures them.
        overlay_advertised_routes: Vec::new(),
        // P5: not an exit node until the operator opts in.
        overlay_exit_node_enabled: false,
        // P5: not routing egress through a mesh exit node until configured.
        overlay_exit_node: None,
        advertise_routes: Vec::new(),
        advertise_local_subnets: true,
        tunnel_routes: Vec::new(),
        orgs: Vec::new(),
    })
}

/// FR-51 P3 — tell the server this EPHEMERAL device is leaving, so a clean
/// stop removes it in seconds instead of on the reap deadline.
///
/// Best-effort by design: the caller is mid-shutdown, so this is bounded (one
/// short attempt) and every failure is merely logged — the reaper is the
/// backstop for exactly the exits that never reach this call. A 401/404 back
/// counts as SUCCESS: the row is already gone (reaped, or admin-deleted),
/// which is the state this call exists to reach.
pub async fn self_unenroll(server_url: &str, agent_token: &str) -> Result<()> {
    let server_url = normalize_server_url(server_url);
    let url = format!("{server_url}/api/agent/self/unenroll");
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(agent_token)
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await
        .context("POST /api/agent/self/unenroll")?;
    let status = resp.status();
    if status.is_success() || status.as_u16() == 401 || status.as_u16() == 404 {
        Ok(())
    } else {
        let body = resp.text().await.unwrap_or_default();
        bail!("self-unenroll rejected (status {status}): {body}");
    }
}

/// Multi-org P1 — how [`apply_enrollment`] folded a fresh enrollment into
/// the on-disk config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollOutcome {
    /// No prior config at the path — the fresh config was written as-is.
    FreshPrimary,
    /// The enrollment resolved to the SAME (server, tenant) as the primary:
    /// identity refreshed, operator state preserved (rc.204 semantics).
    RefreshedPrimary,
    /// The enrollment resolved to an existing `[[orgs]]` entry: its token /
    /// agent_id refreshed in place.
    RefreshedOrg { label: String },
    /// A NEW (server, tenant) pair: appended as a secondary org.
    AppendedOrg { label: String },
    /// `--replace` forced the legacy whole-primary rebind.
    ReplacedPrimary,
}

/// Multi-org P1 — fold a fresh enrollment into an existing config (or none).
///
/// Dispatch, in order:
///   1. no existing config → fresh as-is (`FreshPrimary`);
///   2. `force_replace` → legacy primary rebind via
///      [`preserve_operator_config`] (`ReplacedPrimary`); any secondary
///      entry now duplicating the new primary identity is dropped;
///   3. (server, tenant) == the primary's → [`preserve_operator_config`]
///      (`RefreshedPrimary`) — this is exactly the pre-multi-org re-enroll;
///   4. (server, tenant) == a secondary entry's → refresh that entry's
///      token / agent_id in place (`RefreshedOrg`);
///   5. otherwise → APPEND a new secondary entry (`AppendedOrg`) with a
///      freshly minted WireGuard key — NEVER a copy of another org's (a
///      shared pubkey would let two orgs correlate this device).
///
/// On append the top-level `machine_name` is kept as-is even when the
/// operator passed a different `--name` (the new org's SERVER row got the
/// name from the enroll POST; the machine-scoped local name stays until
/// `roomler set-device-name` changes it everywhere).
pub fn apply_enrollment(
    existing: Option<AgentConfig>,
    fresh: AgentConfig,
    requested_label: Option<&str>,
    force_replace: bool,
) -> anyhow::Result<(AgentConfig, EnrollOutcome)> {
    let Some(existing) = existing else {
        return Ok((fresh, EnrollOutcome::FreshPrimary));
    };

    if force_replace {
        let mut merged = preserve_operator_config(fresh, existing);
        let (server, tenant) = (merged.server_url.clone(), merged.tenant_id.clone());
        merged
            .orgs
            .retain(|o| !(o.server_url == server && o.tenant_id == tenant));
        return Ok((merged, EnrollOutcome::ReplacedPrimary));
    }

    if existing.is_primary_identity(&fresh.server_url, &fresh.tenant_id) {
        return Ok((
            preserve_operator_config(fresh, existing),
            EnrollOutcome::RefreshedPrimary,
        ));
    }

    let mut cfg = existing;
    if let Some(org) = cfg.find_org_by_identity_mut(&fresh.server_url, &fresh.tenant_id) {
        org.agent_token = fresh.agent_token;
        org.agent_id = fresh.agent_id;
        org.ws_url = None;
        let label = org.label.clone();
        return Ok((cfg, EnrollOutcome::RefreshedOrg { label }));
    }

    let label = unique_org_label(&cfg, requested_label, &fresh.server_url)?;
    #[cfg_attr(
        not(any(feature = "overlay-l3", feature = "overlay-netstack")),
        allow(unused_mut)
    )]
    let mut entry = crate::config::OrgEntry {
        label: label.clone(),
        server_url: fresh.server_url,
        ws_url: None,
        agent_token: fresh.agent_token,
        agent_id: fresh.agent_id,
        tenant_id: fresh.tenant_id,
        enabled: true,
        overlay_mode: crate::config::OrgOverlayMode::Off,
        overlay_wg_secret_key: None,
        overlay_wg_key_epoch: 0,
        overlay_advertised_routes: Vec::new(),
        overlay_exit_node_enabled: false,
        advertise_routes: Vec::new(),
        netstack_socks_port: None,
    };
    // Mint this org's OWN WireGuard identity now (builds without an overlay
    // surface leave it None; P2's first overlay-enabled start mints then,
    // mirroring the primary's lazy path in `run_cmd`).
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        entry.overlay_wg_secret_key =
            Some(tunnel_core::overlay::WgKeypair::generate().secret_base64());
    }
    cfg.orgs.push(entry);
    Ok((cfg, EnrollOutcome::AppendedOrg { label }))
}

/// Pick a unique label for a new secondary org: the sanitized requested
/// label if given (hard error when invalid/taken — the operator named it
/// deliberately), else the server host sanitized + `-2`/`-3`… uniquifier.
fn unique_org_label(
    cfg: &AgentConfig,
    requested: Option<&str>,
    server_url: &str,
) -> anyhow::Result<String> {
    use crate::config::sanitize_org_label;
    if let Some(raw) = requested {
        let label = sanitize_org_label(raw).ok_or_else(|| {
            anyhow::anyhow!(
                "invalid --label {raw:?}: use lowercase letters/digits/dashes \
                 (and not the reserved {:?})",
                crate::config::PRIMARY_ORG_LABEL
            )
        })?;
        if cfg.find_org(&label).is_some() {
            bail!("--label {label:?} is already in use (see `roomlerd org ls`)");
        }
        return Ok(label);
    }
    let host = server_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(server_url);
    let base = sanitize_org_label(host).unwrap_or_else(|| "org".to_string());
    if cfg.find_org(&base).is_none() {
        return Ok(base);
    }
    for n in 2..100 {
        let candidate = format!("{base}-{n}");
        if cfg.find_org(&candidate).is_none() {
            return Ok(candidate);
        }
    }
    bail!("could not derive a unique org label from {server_url:?}; pass --label");
}

/// rc.204 — re-enrolling a machine that already has a config must NOT reset
/// operator state. Pre-rc.204, enroll wrote a wholesale-fresh [`AgentConfig`]:
/// a wizard re-install silently flipped `overlay_enabled` back to `false` (the
/// node dropped out of the overlay mesh on its next restart), dropped
/// `overlay_wg_secret_key` (forcing a WG key rotation on the next
/// overlay-enabled start), and wiped `tunnel_routes` / forward ACLs /
/// advertised routes / encoder preference (field-observed on DEVBOX,
/// 2026-07-21: the P4 wizard field-proofs re-enrolled the box and it fell out
/// of the mesh unnoticed). Keep the EXISTING config as the base — it carries
/// every operator-owned knob, including ones this function has never heard of
/// — and take only the enrollment-owned identity fields from the fresh one.
///
/// `ws_url` intentionally follows the FRESH config (i.e. resets to `None`): a
/// pinned override derived for the OLD server would break the new enrollment's
/// signaling connection, and the default derivation from `server_url` is
/// correct in every ordinary setup.
pub fn preserve_operator_config(fresh: AgentConfig, existing: AgentConfig) -> AgentConfig {
    AgentConfig {
        server_url: fresh.server_url,
        ws_url: fresh.ws_url,
        agent_token: fresh.agent_token,
        agent_id: fresh.agent_id,
        tenant_id: fresh.tenant_id,
        machine_id: fresh.machine_id,
        machine_name: fresh.machine_name,
        config_schema_version: fresh.config_schema_version,
        ..existing
    }
}

/// FR-99 decision 3 — does this enrollment write a fresh Windows service
/// install's defaults ([`apply_service_install_defaults`])? Only a fresh
/// primary written to the machine-global config, the one the SystemContext
/// worker reads. A refresh, a rebind or an appended org keeps what the device
/// already had, so no device in the field changes under its owner.
pub fn takes_service_install_defaults(machine_global: bool, outcome: &EnrollOutcome) -> bool {
    machine_global && *outcome == EnrollOutcome::FreshPrimary
}

/// FR-99 decision 3 — what a FRESH Windows service install starts with:
/// `lock_on_end = auto`, which locks at the last session's end when that
/// session began on a locked screen or with nobody at the computer, and so
/// restores what it found. The service's worker is SYSTEM in the console
/// session and reaches the secure desktop, so the next controller can lift
/// that lock (FR-99 §8 rows 12 and 16).
///
/// ⚠️ Never a per-user install: its worker cannot reach the secure desktop,
/// and a lock at the end would leave every later session at a padlock nobody
/// can lift remotely. Not the Linux root daemon yet either: no field cell has
/// shown a remote unlock there. Both keep `never`, as does every existing
/// config that lacks the key.
pub fn apply_service_install_defaults(cfg: &mut AgentConfig) {
    cfg.lock_on_end = roomler_ai_remote_control::models::LockOnEnd::Auto;
}

/// Strip the trailing slash and force the scheme to `https://` if the
/// caller supplied `http://`. Any other scheme (or a bare host) is
/// returned trimmed but otherwise untouched — `https://` URLs stay
/// `https://`, and a malformed input is left to fail at the reqwest
/// layer with a clearer diagnostic than we'd produce here.
///
/// **Loopback is exempt**: `http://127.0.0.1`, `http://localhost`, `http://[::1]`
/// stay `http://`. A loopback address has no off-host network path, so there's
/// no MITM to defend against — and dev / test / CI servers run plaintext on
/// loopback (the integration `TestApp` binds `http://127.0.0.1:<port>`). Forcing
/// TLS there just breaks the enroll POST with a `wrong version number` SSL error.
/// A remote host (the production case) is still upgraded.
fn normalize_server_url(raw: &str) -> String {
    // FR-101 P1b — the same rule every reader of a server URL applies now
    // (`roomler_ai_remote_control::server_url`), which reads the URL as
    // reqwest will: `HTTP:roomler.ai` is plaintext too. No plaintext escape
    // at enrollment: the token must travel over TLS.
    let secured = roomler_ai_remote_control::server_url::secure(raw, false);
    if secured.promoted {
        tracing::warn!(
            original = raw,
            "upgrading http:// to https:// — enrollment tokens must travel over TLS"
        );
    }
    secured.url.trim_end_matches('/').to_string()
}

fn detect_os() -> OsKind {
    match std::env::consts::OS {
        "linux" => OsKind::Linux,
        "macos" => OsKind::Macos,
        "windows" => OsKind::Windows,
        other => {
            tracing::warn!(%other, "unknown OS, defaulting to Linux");
            OsKind::Linux
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_is_promoted_to_https() {
        assert_eq!(
            normalize_server_url("http://roomler.ai"),
            "https://roomler.ai"
        );
        assert_eq!(
            normalize_server_url("http://roomler.ai/"),
            "https://roomler.ai"
        );
        assert_eq!(
            normalize_server_url("http://10.0.0.5:3000"),
            "https://10.0.0.5:3000"
        );
        // FR-101 P1b — spelled as reqwest would still dial it in plaintext.
        assert_eq!(
            normalize_server_url(" HTTP:roomler.ai/ "),
            "https://roomler.ai"
        );
    }

    #[test]
    fn http_loopback_is_not_promoted() {
        // Loopback has no off-host path to MITM — keep it plaintext so a dev /
        // test / CI server on 127.0.0.1 (the integration `TestApp`) enrolls.
        assert_eq!(
            normalize_server_url("http://127.0.0.1:41003"),
            "http://127.0.0.1:41003"
        );
        assert_eq!(
            normalize_server_url("http://localhost:5001/"),
            "http://localhost:5001"
        );
        assert_eq!(
            normalize_server_url("http://[::1]:8080"),
            "http://[::1]:8080"
        );
        assert_eq!(normalize_server_url("http://127.5.5.5"), "http://127.5.5.5");
        // A non-loopback private IP is still upgraded (only loopback is exempt).
        assert_eq!(
            normalize_server_url("http://192.168.1.10:3000"),
            "https://192.168.1.10:3000"
        );
    }

    #[test]
    fn https_is_left_alone() {
        assert_eq!(
            normalize_server_url("https://roomler.ai"),
            "https://roomler.ai"
        );
        assert_eq!(
            normalize_server_url("https://roomler.ai/"),
            "https://roomler.ai"
        );
    }

    #[test]
    fn does_not_upgrade_unrelated_schemes_or_bare_hosts() {
        // We don't validate — the reqwest call will fail with a clearer
        // error than we could produce here. Just confirm we don't
        // accidentally rewrite these.
        assert_eq!(normalize_server_url("roomler.ai"), "roomler.ai");
        assert_eq!(normalize_server_url("file:///tmp/foo"), "file:///tmp/foo");
    }

    // ---- FR-102 P3: the install trace on the wire ----------------------

    fn request<'a>(install: Option<&'a InstallInfo>) -> EnrollRequest<'a> {
        EnrollRequest {
            enrollment_token: "t",
            machine_id: "m",
            machine_name: "n",
            os: OsKind::Linux,
            agent_version: "0.4.136",
            install,
        }
    }

    /// Without an install trace the body is byte-for-byte the pre-P3 shape
    /// — the five fields, nothing else — so a server from before P3 sees
    /// exactly what it always saw; with one, `install` rides along.
    #[test]
    fn the_request_omits_install_when_unset_and_carries_it_when_set() {
        let old = serde_json::to_value(request(None)).unwrap();
        assert_eq!(
            old,
            serde_json::json!({
                "enrollment_token": "t",
                "machine_id": "m",
                "machine_name": "n",
                "os": "linux",
                "agent_version": "0.4.136",
            })
        );
        assert!(old.get("install").is_none());

        let info = InstallInfo::new(InstallMethod::ScriptSh, InstallScope::System);
        let new = serde_json::to_value(request(Some(&info))).unwrap();
        assert_eq!(
            new["install"],
            serde_json::json!({ "method": "script-sh", "scope": "system" })
        );
        assert!(
            new["install"].get("run").is_none(),
            "run is omitted until P3b sets it"
        );
        assert_eq!(new.as_object().unwrap().len(), 6);
    }

    /// CLI over env over the default: a hand-typed enroll is `manual` with
    /// an `unknown` scope; the scripts speak through the env; a flag wins.
    #[test]
    fn install_resolution_prefers_cli_then_env_then_manual() {
        let r = |c: Option<&str>, s: Option<&str>, em: Option<&str>, es: Option<&str>| {
            resolve_install_from(c, s, em, es).map(|i| (i.method, i.scope))
        };
        assert_eq!(
            r(None, None, None, None).unwrap(),
            ("manual".to_string(), "unknown".to_string())
        );
        assert_eq!(
            r(None, None, Some("script-sh"), Some("per-user")).unwrap(),
            ("script-sh".to_string(), "per-user".to_string())
        );
        assert_eq!(
            r(Some("msi"), None, Some("script-ps1"), Some("system")).unwrap(),
            ("msi".to_string(), "system".to_string()),
            "a flag beats the env for its own half only"
        );
        assert_eq!(
            r(Some("container"), Some("system"), None, None).unwrap(),
            ("container".to_string(), "system".to_string())
        );
        // A value outside the vocabulary from a FLAG is refused at the
        // prompt, and the message names the flag and the spellings.
        let e = r(Some("Snap"), None, None, None).unwrap_err().to_string();
        assert!(
            e.contains("--install-method") && e.contains("\"Snap\"") && e.contains("script-sh"),
            "{e}"
        );
        let e = r(None, Some("user"), None, None).unwrap_err().to_string();
        assert!(
            e.contains("--install-scope") && e.contains("per-user"),
            "{e}"
        );
        // From the ENVIRONMENT it is clamped, never refused: the served
        // scripts set the variables and roll with the server, so a script
        // can know a spelling the daemon it installs does not — that must
        // still enroll.
        assert_eq!(
            r(None, None, Some("script-brew"), Some("fleet-wide")).unwrap(),
            ("other".to_string(), "unknown".to_string())
        );
        assert_eq!(
            r(None, None, Some("script"), Some("system")).unwrap(),
            ("other".to_string(), "system".to_string()),
            "each half is clamped on its own"
        );
        // A flag still wins over the env for its half — and a bad flag is
        // refused even when the env beside it is fine.
        assert!(r(Some("Snap"), None, Some("script-sh"), None).is_err());
        // `unknown` is a server-side value, but a caller may spell it out.
        assert_eq!(r(Some("unknown"), None, None, None).unwrap().0, "unknown");
    }

    /// rc.204 — a re-enroll over an existing config preserves every
    /// operator-owned knob (overlay opt-in + WG key, routes, ACL posture,
    /// encoder preference, declared tunnel routes) and takes ONLY the
    /// enrollment-owned identity fields from the fresh config.
    #[test]
    fn preserve_operator_config_keeps_operator_state_and_takes_identity() {
        let mut existing = crate::config::test_fixture();
        existing.overlay_enabled = true;
        existing.overlay_wg_secret_key = Some("OLD-WG-KEY".into());
        existing.overlay_advertised_routes = vec!["192.168.1.0/24".into()];
        existing.advertise_routes = vec!["10.9.0.0/16".into()];
        existing.encoder_preference = crate::config::EncoderPreferenceChoice::Software;
        existing.auto_grant_session = false;
        existing.last_known_good_version = Some("0.3.0-rc.199".into());

        let mut fresh = crate::config::test_fixture();
        fresh.server_url = "https://roomler.ai".into();
        fresh.agent_token = "NEW-TOKEN".into();
        fresh.agent_id = "NEW-AGENT-ID".into();
        fresh.tenant_id = "NEW-TENANT".into();
        fresh.machine_id = "NEW-MID".into();
        fresh.machine_name = "renamed-host".into();
        fresh.config_schema_version = Some("9".into());

        let merged = preserve_operator_config(fresh, existing);

        // The remote-config opt-in rides the `..existing` tail, and BOTH
        // directions matter: a device that opted in must not silently opt out
        // when it re-enrolls, and — the security-relevant half — re-enrolling
        // must never be a way to opt a device IN. `existing` was left at the
        // fixture default (off) above, so this also pins the default.
        assert!(
            !merged.remote_config_enabled,
            "re-enrollment must not opt a device into accepting pushed config"
        );

        // Identity comes from the fresh enrollment…
        assert_eq!(merged.server_url, "https://roomler.ai");
        assert_eq!(merged.agent_token, "NEW-TOKEN");
        assert_eq!(merged.agent_id, "NEW-AGENT-ID");
        assert_eq!(merged.tenant_id, "NEW-TENANT");
        assert_eq!(merged.machine_id, "NEW-MID");
        assert_eq!(merged.machine_name, "renamed-host");
        assert_eq!(merged.config_schema_version.as_deref(), Some("9"));

        // …and the operator state survives the re-enroll.
        assert!(merged.overlay_enabled, "overlay opt-in must survive");
        assert_eq!(
            merged.overlay_wg_secret_key.as_deref(),
            Some("OLD-WG-KEY"),
            "the WG identity must survive (no forced key rotation)"
        );
        assert_eq!(merged.overlay_advertised_routes, vec!["192.168.1.0/24"]);
        assert_eq!(merged.advertise_routes, vec!["10.9.0.0/16"]);
        assert!(matches!(
            merged.encoder_preference,
            crate::config::EncoderPreferenceChoice::Software
        ));
        assert!(!merged.auto_grant_session);
        assert_eq!(
            merged.last_known_good_version.as_deref(),
            Some("0.3.0-rc.199")
        );
    }

    // ---- Multi-org P1: apply_enrollment dispatch --------------------------

    fn fresh_for(server: &str, tenant: &str, token: &str) -> AgentConfig {
        let mut f = crate::config::test_fixture();
        f.server_url = server.into();
        f.tenant_id = tenant.into();
        f.agent_token = token.into();
        f.agent_id = format!("aid-{tenant}");
        f
    }

    fn org(label: &str, server: &str, tenant: &str) -> crate::config::OrgEntry {
        crate::config::OrgEntry {
            label: label.into(),
            server_url: server.into(),
            ws_url: None,
            agent_token: format!("tok-{label}"),
            agent_id: format!("aid-{label}"),
            tenant_id: tenant.into(),
            enabled: true,
            overlay_mode: crate::config::OrgOverlayMode::Off,
            overlay_wg_secret_key: None,
            overlay_wg_key_epoch: 0,
            overlay_advertised_routes: Vec::new(),
            overlay_exit_node_enabled: false,
            advertise_routes: Vec::new(),
            netstack_socks_port: None,
        }
    }

    /// FR-99 decision 3 — a fresh Windows service install (the machine-global
    /// config) starts at `lock_on_end = auto`. Every other enrollment keeps what
    /// the device had: a refresh over a config that never set the key still
    /// reads `never`, and so does a per-user install.
    #[test]
    fn only_a_fresh_service_install_starts_at_lock_on_end_auto() {
        use roomler_ai_remote_control::models::LockOnEnd;

        // A fresh service install: the default applies.
        let fresh = fresh_for("https://a.invalid", "t1", "tok1");
        assert_eq!(
            fresh.lock_on_end,
            LockOnEnd::Never,
            "the config's own default"
        );
        let (mut cfg, outcome) = apply_enrollment(None, fresh.clone(), None, false).unwrap();
        assert!(takes_service_install_defaults(true, &outcome));
        apply_service_install_defaults(&mut cfg);
        assert_eq!(cfg.lock_on_end, LockOnEnd::Auto);

        // A fresh per-user install: nothing changes.
        let (_, outcome) = apply_enrollment(None, fresh.clone(), None, false).unwrap();
        assert!(!takes_service_install_defaults(false, &outcome));

        // A service install already in the field, re-enrolled: it keeps what it
        // had, and a config that never set the key reads `never`.
        let existing = crate::config::test_fixture(); // example.invalid / tid
        let again = fresh_for("https://example.invalid", "tid", "NEW-TOK");
        let (cfg, outcome) =
            apply_enrollment(Some(existing.clone()), again.clone(), None, false).unwrap();
        assert_eq!(outcome, EnrollOutcome::RefreshedPrimary);
        assert!(!takes_service_install_defaults(true, &outcome));
        assert_eq!(cfg.lock_on_end, LockOnEnd::Never);

        // Its owner's own choice survives a rebind and an appended org too.
        let mut owned = existing;
        owned.lock_on_end = LockOnEnd::Always;
        for (fresh, replace) in [
            (again, true),
            (fresh_for("https://b.invalid", "t2", "T2"), false),
        ] {
            let (cfg, outcome) =
                apply_enrollment(Some(owned.clone()), fresh, None, replace).unwrap();
            assert!(
                !takes_service_install_defaults(true, &outcome),
                "{outcome:?}"
            );
            assert_eq!(cfg.lock_on_end, LockOnEnd::Always, "{outcome:?}");
        }
    }

    #[test]
    fn apply_enrollment_fresh_when_no_existing() {
        let fresh = fresh_for("https://a.invalid", "t1", "tok1");
        let (cfg, outcome) = apply_enrollment(None, fresh.clone(), None, false).unwrap();
        assert_eq!(outcome, EnrollOutcome::FreshPrimary);
        assert_eq!(cfg.agent_token, fresh.agent_token);
        assert!(cfg.orgs.is_empty());
    }

    #[test]
    fn apply_enrollment_same_identity_refreshes_primary_and_keeps_orgs() {
        let mut existing = crate::config::test_fixture(); // server example.invalid / tenant tid
        existing.overlay_enabled = true;
        existing.orgs = vec![org("acme", "https://b.invalid", "t-acme")];
        let fresh = fresh_for("https://example.invalid", "tid", "NEW-TOK");
        let (cfg, outcome) = apply_enrollment(Some(existing), fresh, None, false).unwrap();
        assert_eq!(outcome, EnrollOutcome::RefreshedPrimary);
        assert_eq!(cfg.agent_token, "NEW-TOK");
        assert!(cfg.overlay_enabled, "operator state preserved");
        assert_eq!(cfg.orgs.len(), 1, "secondary enrollments must survive");
        assert_eq!(cfg.orgs[0].label, "acme");
    }

    #[test]
    fn apply_enrollment_matching_org_refreshes_in_place() {
        let mut existing = crate::config::test_fixture();
        existing.orgs = vec![org("acme", "https://b.invalid", "t-acme")];
        let fresh = fresh_for("https://b.invalid", "t-acme", "ROTATED");
        let (cfg, outcome) = apply_enrollment(Some(existing), fresh, None, false).unwrap();
        assert_eq!(
            outcome,
            EnrollOutcome::RefreshedOrg {
                label: "acme".into()
            }
        );
        assert_eq!(cfg.orgs.len(), 1);
        assert_eq!(cfg.orgs[0].agent_token, "ROTATED");
        assert_eq!(cfg.orgs[0].agent_id, "aid-t-acme");
        // The primary identity is untouched.
        assert_eq!(cfg.agent_token, "tok");
    }

    #[test]
    fn apply_enrollment_new_identity_appends_secondary() {
        let existing = crate::config::test_fixture();
        let fresh = fresh_for("https://roomler.ai", "t-new", "tok-new");
        let (cfg, outcome) = apply_enrollment(Some(existing), fresh, None, false).unwrap();
        let EnrollOutcome::AppendedOrg { label } = outcome else {
            panic!("expected append, got {outcome:?}");
        };
        assert_eq!(label, "roomler-ai", "label derives from the server host");
        assert_eq!(cfg.orgs.len(), 1);
        let entry = &cfg.orgs[0];
        assert_eq!(entry.tenant_id, "t-new");
        assert!(entry.enabled);
        assert_eq!(entry.overlay_mode, crate::config::OrgOverlayMode::Off);
        // The primary is untouched — an append must never rebind it.
        assert_eq!(cfg.agent_token, "tok");
        assert_eq!(cfg.tenant_id, "tid");
        // With an overlay surface compiled in, the org gets its OWN key —
        // never a copy of the primary's.
        #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
        {
            assert!(entry.overlay_wg_secret_key.is_some());
            assert_ne!(
                entry.overlay_wg_secret_key, cfg.overlay_wg_secret_key,
                "org WG key must not equal the primary's"
            );
        }
    }

    #[test]
    fn apply_enrollment_append_uses_requested_label_and_rejects_taken() {
        let mut existing = crate::config::test_fixture();
        existing.orgs = vec![org("acme", "https://b.invalid", "t-acme")];
        let fresh = fresh_for("https://c.invalid", "t-c", "tok-c");
        let (cfg, outcome) = apply_enrollment(
            Some(existing.clone()),
            fresh.clone(),
            Some("Beta Corp"),
            false,
        )
        .unwrap();
        assert_eq!(
            outcome,
            EnrollOutcome::AppendedOrg {
                label: "beta-corp".into()
            }
        );
        assert_eq!(cfg.orgs.len(), 2);

        // Taken label → hard error (the operator named it deliberately).
        let err = apply_enrollment(Some(existing.clone()), fresh.clone(), Some("acme"), false)
            .unwrap_err();
        assert!(err.to_string().contains("already in use"), "{err}");
        // Reserved label → hard error.
        let err = apply_enrollment(Some(existing), fresh, Some("primary"), false).unwrap_err();
        assert!(err.to_string().contains("invalid --label"), "{err}");
    }

    #[test]
    fn apply_enrollment_replace_rebinds_primary_and_drops_dup_entry() {
        let mut existing = crate::config::test_fixture();
        existing.orgs = vec![
            org("acme", "https://b.invalid", "t-acme"),
            org("keep", "https://c.invalid", "t-keep"),
        ];
        // Replacing the primary with an identity that ALREADY exists as the
        // "acme" secondary: the secondary is dropped (no duplicate identity).
        let fresh = fresh_for("https://b.invalid", "t-acme", "tok-promoted");
        let (cfg, outcome) = apply_enrollment(Some(existing), fresh, None, true).unwrap();
        assert_eq!(outcome, EnrollOutcome::ReplacedPrimary);
        assert_eq!(cfg.server_url, "https://b.invalid");
        assert_eq!(cfg.tenant_id, "t-acme");
        assert_eq!(cfg.agent_token, "tok-promoted");
        assert_eq!(cfg.orgs.len(), 1, "the duplicate entry must be dropped");
        assert_eq!(cfg.orgs[0].label, "keep");
    }

    #[test]
    fn apply_enrollment_appended_label_uniquifies_on_collision() {
        let mut existing = crate::config::test_fixture();
        existing.orgs = vec![org("roomler-ai", "https://other.invalid", "t-x")];
        let fresh = fresh_for("https://roomler.ai", "t-y", "tok-y");
        let (_cfg, outcome) = apply_enrollment(Some(existing), fresh, None, false).unwrap();
        assert_eq!(
            outcome,
            EnrollOutcome::AppendedOrg {
                label: "roomler-ai-2".into()
            }
        );
    }
}
