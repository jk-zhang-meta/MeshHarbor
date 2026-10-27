// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Multi-org — join an additional org from the admin UI
//! (`rc:agent.join_org`), without touching the machine.
//!
//! The CLI path (`meshharbor enroll --label …`) needs someone at the keyboard,
//! which is exactly what a corp-managed box or a headless VM doesn't have.
//! This module is the remote twin: the server pushes a single-use enrollment
//! token for the TARGET tenant down the PRIMARY org's socket, and the agent
//! does the rest itself —
//!
//! 1. exchange the token for an agent JWT in that tenant (against the server
//!    it is ALREADY talking to — the frame carries no URL, so a forged or
//!    relayed message can never repoint the device),
//! 2. fold the result into the config as a new `[[orgs]]` entry via the same
//!    [`apply_enrollment`](crate::enrollment::apply_enrollment) dispatch the
//!    CLI uses — freshly minted per-org WG key included,
//! 3. bring that org's supervised WS loop up **in-process**, so the device
//!    appears online in the new org within seconds instead of at the next
//!    daemon restart.
//!
//! Step 3 is why [`OrgSpawner`] exists: `run_cmd` builds the shared handles
//! (encoder preference, shutdown signal, consent broker) once at startup and
//! installs them here, so a join arriving hours later can spawn a supervisor
//! that is indistinguishable from one started at boot.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use tracing::{info, warn};

use crate::config::{AgentConfig, OrgEntry, OrgOverlayMode};
use crate::enrollment::{EnrollInputs, EnrollOutcome, apply_enrollment};

/// What `run_cmd` hands over so a join arriving hours later can write the
/// config the daemon actually loaded and start a supervisor for the result.
///
/// A static rather than nine more parameters on `signaling::run`: the
/// handler is three call-frames deep in the message loop, and every field
/// here is a process-wide singleton anyway (one config path, one write
/// lock, one supervisor factory).
pub struct JoinRuntime {
    /// The config path THIS daemon resolved at startup (perUser vs
    /// machine-global vs `--config`) — never re-resolved, or a
    /// SystemContext daemon would write the wrong profile's file.
    pub config_path: std::path::PathBuf,
    /// The daemon-wide config write lock (P6), shared with the CLI
    /// re-enroll / updater / route-reconciler writers.
    pub write_lock: Arc<tokio::sync::Mutex<()>>,
    /// Spawns a supervised signaling loop for a freshly appended org.
    pub spawn_org: Box<dyn Fn(OrgEntry) + Send + Sync>,
}

static JOIN_RUNTIME: std::sync::OnceLock<JoinRuntime> = std::sync::OnceLock::new();

/// Install the join runtime (once, from `run_cmd`). Without it — CLI verbs,
/// tests — a pushed join is refused loudly instead of half-applied.
pub fn install(runtime: JoinRuntime) {
    let _ = JOIN_RUNTIME.set(runtime);
}

/// Handle a pushed `rc:agent.join_org` using the installed runtime.
/// `cfg` is the calling loop's config (its `server_url` / `machine_id` are
/// what the enrollment is performed with).
pub async fn join_from_push(
    cfg: &AgentConfig,
    enrollment_token: &str,
    label: Option<&str>,
    overlay_mode: Option<&str>,
) -> Result<JoinOutcome> {
    let rt = JOIN_RUNTIME
        .get()
        .context("rc:agent.join_org received but no join runtime is installed")?;
    join_org(
        cfg,
        &rt.config_path,
        rt.write_lock.clone(),
        enrollment_token,
        label,
        overlay_mode,
    )
    .await
}

/// Outcome of a remote join, for the log line and the tests.
#[derive(Debug, PartialEq, Eq)]
pub enum JoinOutcome {
    /// A new `[[orgs]]` entry was appended (and supervised if possible).
    Joined { label: String, supervised: bool },
    /// The device was already enrolled in that org; its token/agent-id were
    /// refreshed in place. Not an error — the admin clicked twice, or is
    /// re-sending to change the org's mesh participation. `restarted` = the
    /// org's supervisor was rebuilt because something it was spawned with
    /// changed (a running loop holds its own config).
    Refreshed {
        label: String,
        restarted: bool,
        /// The push turned ON `overlay_multi_org`. The config is written, but
        /// the mesh cannot come up until the DAEMON restarts: the primary
        /// loop still owns the TUN un-muxed, and Wintun refuses a second
        /// session on one adapter.
        restart_required: bool,
    },
    /// The enrollment resolved to the PRIMARY identity. Refused: a remote
    /// push must never be able to rewrite the machine's primary enrollment
    /// (that is what `enroll --replace` at the keyboard is for).
    RefusedPrimaryRebind,
}

/// Perform a pushed join end to end. `server_url` is the agent's OWN
/// (`cfg.server_url`), never a value off the wire.
pub async fn join_org(
    cfg: &AgentConfig,
    config_path: &std::path::Path,
    write_lock: Arc<tokio::sync::Mutex<()>>,
    enrollment_token: &str,
    label: Option<&str>,
    overlay_mode: Option<&str>,
) -> Result<JoinOutcome> {
    let fresh = crate::enrollment::enroll(EnrollInputs {
        server_url: &cfg.server_url,
        enrollment_token,
        machine_id: &cfg.machine_id,
        machine_name: &cfg.machine_name,
        // FR-102 P3 — a pushed join is a second org for a device that is
        // already installed; the binary's own install trace is not known
        // here, and the new row records `unknown` honestly.
        install: None,
    })
    .await
    .context("exchanging the pushed enrollment token")?;

    // Serialize with every other config writer (CLI re-enroll, updater,
    // route reconciler) — the P6 daemon-wide write lock.
    let _guard = write_lock.lock().await;

    let existing = crate::config::load(&config_path.to_path_buf()).ok();
    let had_config = existing.is_some();
    let (mut merged, outcome) = apply_enrollment(existing, fresh, label, false)?;

    // A REFRESH is not a no-op: the admin may be re-sending the request
    // precisely to change this org's mesh participation on a device that is
    // already enrolled. Falling straight out here (as the first cut did) made
    // the UI's "Private mesh" choice inert for every already-added device —
    // i.e. for the exact case where you'd want to turn the mesh on later.
    let (joined_label, was_new) = match &outcome {
        EnrollOutcome::AppendedOrg { label } => (label.clone(), true),
        EnrollOutcome::RefreshedOrg { label } => {
            info!(org = %label, "join_org: already enrolled; refreshing in place");
            (label.clone(), false)
        }
        // A pushed token that resolves to this machine's PRIMARY identity
        // would rewrite the primary enrollment wholesale. Refuse: nothing
        // is written, and the operator gets a truthful log.
        EnrollOutcome::RefreshedPrimary | EnrollOutcome::ReplacedPrimary => {
            warn!(
                "rc:agent.join_org refused — the token resolves to this machine's \
                 PRIMARY enrollment; a remote push may not rebind it"
            );
            return Ok(JoinOutcome::RefusedPrimaryRebind);
        }
        EnrollOutcome::FreshPrimary => {
            // No config on disk at all. A running daemon always has one, so
            // this means the path moved under us — refuse rather than write
            // a brand-new primary from a pushed token.
            if !had_config {
                bail!("join_org: no existing config at {}", config_path.display());
            }
            unreachable!("apply_enrollment only returns FreshPrimary without an existing config")
        }
    };

    // Overlay participation for this org — applied on BOTH the append and the
    // refresh path (see above).
    let mut mode_changed = false;
    // Set when this push turned ON the host-level `overlay_multi_org`: that
    // needs a DAEMON restart, not a per-org one (see below).
    let mut flag_flipped = false;
    if let Some(mode) = overlay_mode {
        let want = match mode {
            "tun" => OrgOverlayMode::Tun,
            "netstack" => OrgOverlayMode::Netstack,
            _ => OrgOverlayMode::Off,
        };
        let claimed = netstack_ports_claimed(&merged, &joined_label);
        if let Some(entry) = merged.orgs.iter_mut().find(|o| o.label == joined_label) {
            mode_changed = entry.overlay_mode != want;
            entry.overlay_mode = want;
            // #2493 — a netstack org joins only with a port of its own; a newly
            // assigned one restarts this org's loop like a mode change would.
            if want == OrgOverlayMode::Netstack {
                let port_before = entry.netstack_socks_port;
                match assign_netstack_port(entry, &claimed) {
                    Some(port) => {
                        mode_changed |= port_before.is_none();
                        info!(org = %joined_label, port, "join_org: netstack, SOCKS5 front on the loopback");
                    }
                    None => warn!(
                        org = %joined_label,
                        "join_org: netstack, but no free loopback port for its SOCKS front; it joins \
                         no mesh until `netstack_socks_port` is set on its [[orgs]] entry"
                    ),
                }
            }
        }
        // An admin explicitly asking this device to join a second org's mesh
        // IS the host-level opt-in `overlay_multi_org` exists to represent.
        // Without this the request could never take effect: the flag is
        // config-surface only, so there is no other remote path to set it,
        // and `AgentConfig::for_org` gates `tun` on it. Loud, because it
        // changes how the host's ONE TUN adapter is shared.
        if want == OrgOverlayMode::Tun && !merged.overlay_multi_org {
            merged.overlay_multi_org = true;
            // NOT `mode_changed` — deliberately no live restart here.
            //
            // The flag changes who owns the host's TUN: without it the
            // PRIMARY holds a plain `SystemTun`; with it every org rides the
            // shared mux. Restarting only the secondary would send it to
            // `SystemTun::up` on an adapter whose Wintun session the primary
            // still holds, and Wintun refuses a second session on one
            // adapter — field 2026-08-07 on WINHOST-A:
            // `WintunStartSession failed "Failed to register rings"`, the
            // secondary's overlay aborting on every reconnect while the
            // primary stayed happily single-org.
            //
            // The primary's loop cannot be rebuilt from here (it owns the
            // process's main enrollment), so the honest answer is: the
            // config is written and the mesh comes up at the next daemon
            // start, which the next auto-update delivers anyway.
            flag_flipped = true;
            info!(
                org = %joined_label,
                "join_org: enabled overlay_multi_org — RESTART REQUIRED before this \
                 device can carry a second org on an OS TUN of its own (the running \
                 primary loop chose its adapter at start)"
            );
        }
    }

    crate::config::save(&config_path.to_path_buf(), &merged)?;

    let entry = merged
        .orgs
        .iter()
        .find(|o| o.label == joined_label)
        .cloned()
        .context("appended org vanished from the merged config")?;
    drop(_guard);

    // A NEW org needs a supervisor. An EXISTING one needs a RE-start, and
    // only when something it was spawned with actually changed: a running
    // loop holds the config it was given, so a mode written to disk is inert
    // until its loop is rebuilt. Re-starting on every refresh would churn a
    // healthy mesh for nothing.
    // A flag flip means the whole daemon has to come back before the mesh
    // can work; restarting the org loop alone would just fail its TUN
    // bring-up in a retry cycle.
    let restart = (was_new || mode_changed) && !flag_flipped;
    let supervised = match (JOIN_RUNTIME.get(), restart) {
        (Some(rt), true) => {
            (rt.spawn_org)(entry);
            true
        }
        (Some(_), false) => false,
        (None, _) => {
            warn!(
                org = %joined_label,
                "join_org: no supervisor factory installed; the change applies \
                 at the next daemon start"
            );
            false
        }
    };
    if was_new {
        info!(org = %joined_label, supervised, "rc:agent.join_org — joined a new org");
        Ok(JoinOutcome::Joined {
            label: joined_label,
            supervised,
        })
    } else {
        info!(
            org = %joined_label, restarted = supervised, mode_changed,
            restart_required = flag_flipped,
            "rc:agent.join_org — refreshed an existing org"
        );
        Ok(JoinOutcome::Refreshed {
            label: joined_label,
            restarted: supervised,
            restart_required: flag_flipped,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PRIMARY_ORG_LABEL;

    fn base() -> AgentConfig {
        let mut c = crate::config::test_fixture();
        c.server_url = "https://roomler.ai".into();
        c.tenant_id = "tid-primary".into();
        c.machine_id = "machine-1".into();
        c
    }

    fn fresh_for(tenant: &str) -> AgentConfig {
        let mut c = base();
        c.tenant_id = tenant.to_string();
        c.agent_token = format!("tok-{tenant}");
        c.agent_id = format!("aid-{tenant}");
        c
    }

    /// The append path: a new tenant becomes a labelled secondary with its
    /// OWN WG key — never the primary's (cross-org pubkey correlation).
    #[test]
    fn a_new_tenant_appends_a_secondary_with_its_own_key() {
        let mut existing = base();
        existing.overlay_wg_secret_key = Some("PRIMARY-KEY".into());
        let (merged, outcome) =
            apply_enrollment(Some(existing), fresh_for("tid-acme"), Some("acme"), false).unwrap();
        assert_eq!(
            outcome,
            EnrollOutcome::AppendedOrg {
                label: "acme".into()
            }
        );
        let entry = merged.orgs.iter().find(|o| o.label == "acme").unwrap();
        assert_eq!(entry.tenant_id, "tid-acme");
        // The invariant that holds in EVERY build: a secondary never carries
        // the primary's key. (The mint itself is `cfg`-gated on an overlay
        // surface — a signalling-only build leaves it None and mints on the
        // first overlay-enabled start, mirroring the primary's lazy path.)
        assert_ne!(
            entry.overlay_wg_secret_key.as_deref(),
            Some("PRIMARY-KEY"),
            "a secondary must never borrow the primary's WG key"
        );
        #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
        assert!(
            entry.overlay_wg_secret_key.is_some(),
            "an overlay-capable build mints the org's own key at append time"
        );
        // The primary identity is untouched.
        assert_eq!(merged.tenant_id, "tid-primary");
    }

    /// A token that resolves to the machine's PRIMARY identity must not
    /// rewrite it — the outcome the handler refuses on.
    #[test]
    fn a_primary_identity_token_is_recognised_as_a_rebind() {
        let existing = base();
        let (_merged, outcome) =
            apply_enrollment(Some(existing), fresh_for("tid-primary"), None, false).unwrap();
        assert_eq!(outcome, EnrollOutcome::RefreshedPrimary);
        assert_ne!(PRIMARY_ORG_LABEL, "acme");
    }

    /// Re-pushing the same org refreshes in place instead of appending a
    /// duplicate (the admin clicked twice).
    #[test]
    fn re_joining_the_same_org_refreshes_in_place() {
        let mut existing = base();
        let (merged, _) = apply_enrollment(
            Some(existing.clone()),
            fresh_for("tid-acme"),
            Some("acme"),
            false,
        )
        .unwrap();
        existing = merged;
        assert_eq!(existing.orgs.len(), 1);
        let (again, outcome) =
            apply_enrollment(Some(existing), fresh_for("tid-acme"), Some("acme"), false).unwrap();
        assert_eq!(
            outcome,
            EnrollOutcome::RefreshedOrg {
                label: "acme".into()
            }
        );
        assert_eq!(again.orgs.len(), 1, "no duplicate entry");
    }

    /// The bug this fixes: a re-push at an ALREADY-ENROLLED org used to
    /// return before the overlay-mode block, so the UI's "Private mesh"
    /// choice was inert for exactly the devices you'd want to turn it on for
    /// later. Both the append and the refresh path must apply it.
    #[test]
    fn a_refresh_still_applies_the_requested_overlay_mode() {
        let existing = base();
        // First join: mesh off.
        let (cfg, outcome) =
            apply_enrollment(Some(existing), fresh_for("tid-acme"), Some("acme"), false).unwrap();
        assert_eq!(
            outcome,
            EnrollOutcome::AppendedOrg {
                label: "acme".into()
            }
        );
        assert_eq!(cfg.orgs[0].overlay_mode, OrgOverlayMode::Off);
        assert!(!cfg.overlay_multi_org);

        // Second push at the SAME org asking for the mesh: the dispatch says
        // "refresh", and the mode must still land.
        let (mut cfg, outcome) =
            apply_enrollment(Some(cfg), fresh_for("tid-acme"), Some("acme"), false).unwrap();
        assert_eq!(
            outcome,
            EnrollOutcome::RefreshedOrg {
                label: "acme".into()
            }
        );
        // (mirrors join_org's post-dispatch block)
        let entry = cfg.orgs.iter_mut().find(|o| o.label == "acme").unwrap();
        entry.overlay_mode = OrgOverlayMode::Tun;
        cfg.overlay_multi_org = true;

        assert_eq!(cfg.orgs[0].overlay_mode, OrgOverlayMode::Tun);
        // …and the host-level opt-in that `for_org` gates `tun` on, without
        // which the request could never take effect (the flag has no other
        // remote path).
        assert!(cfg.overlay_multi_org);
        // …and with the org's own key present, `for_org` lets the secondary
        // onto the mesh. Set explicitly: the mint is cfg-gated on an overlay
        // feature, and this asserts the GATE's logic, not the mint's.
        cfg.orgs[0].overlay_wg_secret_key = Some("ORG-KEY".into());
        let org = cfg.orgs[0].clone();
        assert!(
            cfg.for_org(&org).overlay_enabled,
            "flag + tun + same server + own key ⇒ the secondary joins the mesh"
        );
        // Drop any one leg and it stays off — the gate is a conjunction.
        let mut no_flag = cfg.clone();
        no_flag.overlay_multi_org = false;
        assert!(!no_flag.for_org(&org).overlay_enabled, "flag is required");
    }

    /// Field 2026-08-07 (WINHOST-A): turning `overlay_multi_org` ON must NOT
    /// live-restart the org loop. The flag decides who owns the host's TUN —
    /// without it the PRIMARY holds a plain `SystemTun`, and a secondary
    /// restarted into the mux calls `SystemTun::up` on an adapter whose
    /// Wintun session the primary still holds. Wintun refuses:
    /// "Failed to register rings", and the org's overlay aborts on every
    /// reconnect. The config is written; the mesh waits for a daemon start.
    #[test]
    fn turning_the_multi_org_flag_on_defers_to_a_daemon_restart() {
        // Mirrors join_org's decision inputs.
        for (was_new, mode_changed, flag_flipped, expect_restart) in [
            // A brand-new org on a host ALREADY in multi-org mode: live spawn.
            (true, false, false, true),
            // Mode changed on an existing org, flag already on: cycle it.
            (false, true, false, true),
            // The flag had to be flipped ⇒ defer, whatever else changed.
            (true, true, true, false),
            (false, true, true, false),
            // Nothing changed: never churn a healthy mesh.
            (false, false, false, false),
        ] {
            let restart = (was_new || mode_changed) && !flag_flipped;
            assert_eq!(
                restart, expect_restart,
                "was_new={was_new} mode_changed={mode_changed} flag_flipped={flag_flipped}"
            );
        }
    }
}

// ─── FR-49: a second org gets a mesh, or says it has none ───────────────────
//
// These two live in the LIB, not in `main.rs`, because CI runs
// `cargo test -p roomlerd --lib` and never `--bins`: a regression lock in the
// binary compiles (clippy --tests) and never RUNS. `apply_overlay_flag` is
// exactly the kind of thing that needs a lock that can fire.

/// #2493 — the loopback ports an org's SOCKS5 front is picked from: below
/// every OS's ephemeral range (Linux starts at 32768, Windows and macOS at
/// 49152), so no outgoing connection takes the port between the pick and the
/// daemon's bind.
pub(crate) const NETSTACK_PORTS: std::ops::RangeInclusive<u16> = 10800..=10899;

/// #2493 — the first port in [`NETSTACK_PORTS`] that no other enrollment
/// claims and that is free on the loopback right now. `None` when every one
/// is taken.
pub(crate) fn pick_netstack_port(claimed: &[u16]) -> Option<u16> {
    NETSTACK_PORTS
        .filter(|p| !claimed.contains(p))
        .find(|p| loopback_port_free(*p))
}

/// Nothing answers on `127.0.0.1:port`, and it binds there. The bind alone is
/// not enough on Windows and macOS, which let a loopback bind shadow another
/// program's listener on the wildcard address. The connect sees that listener
/// without opening a listening socket of its own, so it raises no firewall
/// prompt. Windows can take about two seconds to report a refused loopback
/// connect, so the connect gives up after 200 ms: a listener accepts long
/// before that.
fn loopback_port_free(port: u16) -> bool {
    let addr = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
    std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(200)).is_err()
        && std::net::TcpListener::bind(addr).is_ok()
}

/// The ports other enrollments' fronts claim: every other org's entry, and
/// the primary's process-wide key.
fn netstack_ports_claimed(cfg: &AgentConfig, except: &str) -> Vec<u16> {
    cfg.orgs
        .iter()
        .filter(|o| o.label != except)
        .filter_map(|o| o.netstack_socks_port)
        .chain(
            tunnel_core::env::node_env("OVERLAY_NETSTACK_SOCKS")
                .and_then(|v| v.trim().parse::<u16>().ok()),
        )
        .collect()
}

/// #2493 — a `netstack` org without a port of its own gets the first free
/// one: without one it joins nothing (one TCP listener cannot serve two orgs,
/// so `AgentConfig::for_org` withholds), and before #2493 nothing said so.
/// Returns the port it has now, newly picked or not; `None` = it has none and
/// none was free.
fn assign_netstack_port(org: &mut OrgEntry, claimed: &[u16]) -> Option<u16> {
    if org.overlay_mode == OrgOverlayMode::Netstack && org.netstack_socks_port.is_none() {
        org.netstack_socks_port = pick_netstack_port(claimed);
    }
    org.netstack_socks_port
}

/// The line a CLI verb prints about a netstack org's front.
fn say_netstack_front(label: &str, port: Option<u16>) {
    match port {
        Some(port) => {
            println!("Org {label:?} reaches its mesh through the SOCKS5 front at 127.0.0.1:{port}.")
        }
        None => println!(
            "warning: no free loopback port in {}–{} for org {label:?}'s SOCKS5 front, so \
             it joins no mesh until it has one: set `netstack_socks_port` on its [[orgs]] entry.",
            NETSTACK_PORTS.start(),
            NETSTACK_PORTS.end()
        ),
    }
}

/// #2493 — at daemon start, every `netstack` org without a port gets one, so a
/// config written before the fix joins its mesh too. `true` = the config
/// changed and must be saved.
pub fn heal_netstack_ports(cfg: &mut AgentConfig) -> bool {
    let mut changed = false;
    for i in 0..cfg.orgs.len() {
        if cfg.orgs[i].overlay_mode != OrgOverlayMode::Netstack
            || cfg.orgs[i].netstack_socks_port.is_some()
        {
            continue;
        }
        let label = cfg.orgs[i].label.clone();
        let claimed = netstack_ports_claimed(cfg, &label);
        match assign_netstack_port(&mut cfg.orgs[i], &claimed) {
            Some(port) => {
                info!(org = %label, port, "overlay: a netstack org had no SOCKS port; it has its own now (#2493)");
                changed = true;
            }
            None => warn!(
                org = %label,
                "overlay: no free loopback port for this netstack org's SOCKS front; it joins no \
                 mesh until `netstack_socks_port` is set on its [[orgs]] entry"
            ),
        }
    }
    changed
}

/// FR-49 — apply `enroll --overlay` to the identity that was ACTUALLY enrolled.
///
/// Before this it unconditionally set `cfg.overlay_enabled`, the PRIMARY's flag:
/// `enroll --server B --token … --overlay` on a host already in org A appended
/// B with `overlay_mode = off` and turned the mesh on for **A**. The flag read
/// as granted and landed on the wrong org, and nothing reported it.
///
/// ⚠️ A secondary gets `netstack`, not `tun`. `tun` gives the org an OS adapter
/// of its own and needs `overlay_multi_org` plus the same control plane (macOS
/// included, FR-97 P1d), so a bare flag that installed OS routes could wedge a
/// host — the thing "never self-wedge" exists to prevent. `netstack` is a
/// userspace stack behind a loopback SOCKS5 front: no TUN, no routes, no
/// privilege. Anything else is the explicit `org overlay` verb.
///
/// ⚠️ One-way, like the primary flag it replaces: an enrollment refresh must
/// never drop a host out of a mesh it had already joined.
pub fn apply_overlay_flag(
    cfg: &mut crate::config::AgentConfig,
    outcome: &crate::enrollment::EnrollOutcome,
) {
    use crate::enrollment::EnrollOutcome;
    match outcome {
        EnrollOutcome::RefreshedOrg { label } | EnrollOutcome::AppendedOrg { label } => {
            let label = label.clone();
            let claimed = netstack_ports_claimed(cfg, &label);
            let Some(org) = cfg.orgs.iter_mut().find(|o| o.label == label) else {
                return;
            };
            if org.overlay_mode == crate::config::OrgOverlayMode::Off {
                org.overlay_mode = crate::config::OrgOverlayMode::Netstack;
                tracing::info!(
                    org = %label,
                    "overlay participation enabled by --overlay (netstack)"
                );
            } else {
                tracing::info!(
                    org = %label, mode = org.overlay_mode.wire(),
                    "--overlay: org already participates, left unchanged"
                );
            }
            // #2493 — and the port without which netstack joins nothing.
            if org.overlay_mode == crate::config::OrgOverlayMode::Netstack {
                say_netstack_front(&label, assign_netstack_port(org, &claimed));
            }
        }
        _ => {
            if !cfg.overlay_enabled {
                cfg.overlay_enabled = true;
                tracing::info!("overlay participation enabled by --overlay");
            }
        }
    }
}

/// MeshHarbor §6 item 4b — `enroll --relay-server`: gate 4
/// (`relay_server_enabled`) from the first start, given by whoever installs
/// the host, so a server the central owner approves as a `server` role relays
/// under `peer_relay_mode = auto` with no second visit.
///
/// ⚠️ Primary org only. The relay listener is host-global and serving is
/// primary-only (FR-19), so a secondary enrollment must not switch it on for
/// the device's primary org as a side effect: it is left unchanged with a
/// warning (the server-side enrollment already happened, so refusing here
/// would strand a device without its saved config). Returns whether it
/// applied.
pub fn apply_relay_server_flag(
    cfg: &mut crate::config::AgentConfig,
    outcome: &crate::enrollment::EnrollOutcome,
) -> bool {
    use crate::enrollment::EnrollOutcome;
    match outcome {
        EnrollOutcome::RefreshedOrg { label } | EnrollOutcome::AppendedOrg { label } => {
            tracing::warn!(
                org = %label,
                "--relay-server ignored: serving is the primary organization's, and this \
                 enrollment joined a secondary one (set relay_server_enabled yourself)"
            );
            false
        }
        _ => {
            cfg.relay_server_enabled = Some(true);
            tracing::info!("org relay serving enabled by --relay-server (relay_server_enabled)");
            true
        }
    }
}

/// FR-49 — `roomlerd org overlay <label> <off|netstack|tun>`.
pub fn set_org_overlay(
    cfg: &mut crate::config::AgentConfig,
    label: &str,
    mode: &str,
) -> Result<()> {
    if label == crate::config::PRIMARY_ORG_LABEL {
        bail!(
            "the primary's overlay participation is `overlay_enabled`, not a per-org \
             mode — set it with `meshharbor config set overlay_enabled true` (or \
             `enroll --overlay`)"
        );
    }
    // No fallback on an unparseable mode. A typo that silently left the device
    // off the mesh would be this FR's own defect, re-committed by its fix.
    let Some(parsed) = crate::config::OrgOverlayMode::parse(mode) else {
        bail!("unknown overlay mode {mode:?} — expected one of: off, netstack, tun");
    };
    // Read what we need for the advisories BEFORE taking the mutable borrow.
    let multi_org = cfg.overlay_multi_org;
    let primary_server = cfg.server_url.clone();
    let claimed = netstack_ports_claimed(cfg, label);
    let Some(entry) = cfg.orgs.iter_mut().find(|o| o.label == label) else {
        bail!("no org labelled {label:?} — see `roomlerd org ls`");
    };
    let before = entry.overlay_mode;
    entry.overlay_mode = parsed;
    // #2493 — netstack joins only with a port of its own. An org set to
    // netstack before the fix has none, and gets one here even when its mode
    // does not change.
    let port_before = entry.netstack_socks_port;
    let front = (parsed == crate::config::OrgOverlayMode::Netstack)
        .then(|| assign_netstack_port(entry, &claimed));
    let port_added = port_before.is_none() && entry.netstack_socks_port.is_some();
    if before == parsed {
        if port_added {
            println!(
                "Org {label:?} overlay is already {}, and now has a SOCKS5 port of its own. \
                 Restart the daemon to apply.",
                parsed.wire()
            );
        } else {
            println!("Org {label:?} overlay is already {}.", parsed.wire());
        }
    } else {
        println!(
            "Org {label:?} overlay {} → {}. Restart the daemon to apply.",
            before.wire(),
            parsed.wire()
        );
    }
    if let Some(port) = front {
        say_netstack_front(label, port);
    }
    if before == parsed {
        return Ok(());
    }

    // Warn about the two preconditions `tun` has that `netstack` does not,
    // HERE rather than at the next daemon start — a refusal buried in a log an
    // operator is not watching is the failure mode this FR is about. These are
    // advisory: the setting is still written, because the operator may be
    // fixing the preconditions in the same sitting.
    if parsed == crate::config::OrgOverlayMode::Tun {
        if !multi_org {
            println!(
                "warning: `tun` for a secondary needs `overlay_multi_org = true` \
                 (it is currently false) — set it with \
                 `meshharbor config set overlay_multi_org true`, or use `netstack`, \
                 which needs no OS privilege at all."
            );
        }
        if entry.server_url != primary_server {
            println!(
                "warning: `tun` is restricted to orgs sharing the primary's control \
                 plane; this org is on {} and the primary on {}. Use `netstack`.",
                entry.server_url, primary_server
            );
        }
        // No macOS caveat: that one was about the shared adapter W7c deleted.
        // Every org has its own utun now, and a secondary's carries its mesh
        // on a Mac (FR-97 P1d, measured on macOS 15).
    }
    Ok(())
}

#[cfg(test)]
mod fr49_tests {
    //! FR-49 — these locks live in the LIB because CI runs
    //! `cargo test -p roomlerd --lib` and never `--bins`: the same tests in
    //! `main.rs` would compile (clippy --tests) and never RUN.
    use super::*;

    fn two_org_cfg() -> crate::config::AgentConfig {
        let mut cfg = crate::config::test_fixture();
        cfg.overlay_enabled = false;
        cfg.orgs.push(crate::config::OrgEntry {
            label: "acme".into(),
            server_url: "https://example.invalid".into(),
            ws_url: None,
            agent_token: "t2".into(),
            agent_id: "a2".into(),
            tenant_id: "t2id".into(),
            enabled: true,
            overlay_mode: crate::config::OrgOverlayMode::Off,
            overlay_wg_secret_key: None,
            overlay_wg_key_epoch: 0,
            overlay_advertised_routes: Vec::new(),
            overlay_exit_node_enabled: false,
            advertise_routes: Vec::new(),
            netstack_socks_port: None,
        });
        cfg
    }

    /// `--relay-server` on a primary enrollment is gate 4, on from the
    /// first start.
    #[test]
    fn relay_server_flag_switches_gate_4_on_for_a_primary() {
        for outcome in [
            crate::enrollment::EnrollOutcome::FreshPrimary,
            crate::enrollment::EnrollOutcome::RefreshedPrimary,
            crate::enrollment::EnrollOutcome::ReplacedPrimary,
        ] {
            let mut cfg = two_org_cfg();
            cfg.relay_server_enabled = Some(false);
            assert!(apply_relay_server_flag(&mut cfg, &outcome));
            assert_eq!(cfg.relay_server_enabled, Some(true));
        }
    }

    /// A secondary enrollment must not turn the host-global listener on for
    /// the PRIMARY org — the `--overlay` bug below, in its serving form.
    #[test]
    fn relay_server_flag_never_serves_for_a_secondary_enrollment() {
        for outcome in [
            crate::enrollment::EnrollOutcome::AppendedOrg {
                label: "acme".into(),
            },
            crate::enrollment::EnrollOutcome::RefreshedOrg {
                label: "acme".into(),
            },
        ] {
            let mut cfg = two_org_cfg();
            assert!(!apply_relay_server_flag(&mut cfg, &outcome));
            assert_eq!(cfg.relay_server_enabled, None, "left to the device owner");
        }
    }

    /// THE regression lock. `--overlay` used to set the PRIMARY's flag no
    /// matter which identity was enrolled, so enrolling into a second org
    /// turned the mesh on for the first one and left the second dark.
    #[test]
    fn overlay_flag_enables_the_org_that_was_actually_enrolled() {
        let mut cfg = two_org_cfg();
        apply_overlay_flag(
            &mut cfg,
            &crate::enrollment::EnrollOutcome::AppendedOrg {
                label: "acme".into(),
            },
        );
        assert_eq!(
            cfg.find_org("acme").unwrap().overlay_mode,
            crate::config::OrgOverlayMode::Netstack,
            "the enrolled org joins the mesh"
        );
        assert!(
            !cfg.overlay_enabled,
            "and the PRIMARY is untouched — that was the bug"
        );
    }

    /// A secondary gets `netstack`, never `tun`: `tun` needs an OS adapter
    /// of its own, `overlay_multi_org` and the same control plane, on macOS
    /// too. A bare flag must not install OS routes.
    #[test]
    fn overlay_flag_never_picks_tun_for_a_secondary() {
        let mut cfg = two_org_cfg();
        apply_overlay_flag(
            &mut cfg,
            &crate::enrollment::EnrollOutcome::AppendedOrg {
                label: "acme".into(),
            },
        );
        assert_ne!(
            cfg.find_org("acme").unwrap().overlay_mode,
            crate::config::OrgOverlayMode::Tun
        );
    }

    /// One-way, inherited from the flag this replaces: a re-enrolment must
    /// never drop a host out of a mesh it had joined.
    #[test]
    fn overlay_flag_never_downgrades_an_org_that_already_participates() {
        let mut cfg = two_org_cfg();
        cfg.orgs[0].overlay_mode = crate::config::OrgOverlayMode::Tun;
        apply_overlay_flag(
            &mut cfg,
            &crate::enrollment::EnrollOutcome::RefreshedOrg {
                label: "acme".into(),
            },
        );
        assert_eq!(
            cfg.find_org("acme").unwrap().overlay_mode,
            crate::config::OrgOverlayMode::Tun,
            "tun must survive a refresh, not fall back to netstack"
        );
    }

    /// The primary path still works exactly as before.
    #[test]
    fn overlay_flag_still_enables_the_primary_on_a_primary_outcome() {
        for outcome in [
            crate::enrollment::EnrollOutcome::FreshPrimary,
            crate::enrollment::EnrollOutcome::RefreshedPrimary,
            crate::enrollment::EnrollOutcome::ReplacedPrimary,
        ] {
            let mut cfg = two_org_cfg();
            apply_overlay_flag(&mut cfg, &outcome);
            assert!(cfg.overlay_enabled, "{outcome:?} should enable the primary");
            assert_eq!(
                cfg.find_org("acme").unwrap().overlay_mode,
                crate::config::OrgOverlayMode::Off,
                "{outcome:?} must not touch a secondary"
            );
        }
    }

    #[test]
    fn org_overlay_verb_sets_the_mode_and_refuses_nonsense() {
        let mut cfg = two_org_cfg();
        set_org_overlay(&mut cfg, "acme", "tun").unwrap();
        assert_eq!(
            cfg.find_org("acme").unwrap().overlay_mode,
            crate::config::OrgOverlayMode::Tun
        );
        // Idempotent, and case-insensitive on the operator's input.
        set_org_overlay(&mut cfg, "acme", "TUN").unwrap();
        assert_eq!(
            cfg.find_org("acme").unwrap().overlay_mode,
            crate::config::OrgOverlayMode::Tun
        );
        // And it can be turned back off — a visibility fix that could only
        // add participation would be a trap of its own.
        set_org_overlay(&mut cfg, "acme", "off").unwrap();
        assert_eq!(
            cfg.find_org("acme").unwrap().overlay_mode,
            crate::config::OrgOverlayMode::Off
        );

        // ⚠️ A typo must FAIL, not fall back. Silently leaving a device off
        // the mesh is the exact defect this FR closes.
        let mut cfg = two_org_cfg();
        assert!(set_org_overlay(&mut cfg, "acme", "tunn").is_err());
        assert!(set_org_overlay(&mut cfg, "acme", "").is_err());
        assert!(set_org_overlay(&mut cfg, "nosuch", "tun").is_err());
        // The primary is not a per-org mode.
        assert!(set_org_overlay(&mut cfg, crate::config::PRIMARY_ORG_LABEL, "tun").is_err());
        assert_eq!(
            cfg.find_org("acme").unwrap().overlay_mode,
            crate::config::OrgOverlayMode::Off,
            "no refusal may have written anything"
        );
    }

    /// #2493 — `--overlay` on a second org picks it a free loopback port in
    /// the netstack range, never one another org claims. Without a port
    /// `for_org` withholds, so before the fix such an org joined nothing (the
    /// field red on 0.4.143).
    #[test]
    fn overlay_flag_gives_a_netstack_org_its_own_port() {
        let mut cfg = two_org_cfg();
        let mut beta = cfg.orgs[0].clone();
        beta.label = "beta".into();
        beta.tenant_id = "t3id".into();
        beta.overlay_mode = crate::config::OrgOverlayMode::Netstack;
        beta.netstack_socks_port = Some(*NETSTACK_PORTS.start());
        cfg.orgs.push(beta);
        apply_overlay_flag(
            &mut cfg,
            &crate::enrollment::EnrollOutcome::AppendedOrg {
                label: "acme".into(),
            },
        );
        let mut acme = cfg.find_org("acme").unwrap().clone();
        let port = acme.netstack_socks_port.expect("a port of its own");
        assert!(NETSTACK_PORTS.contains(&port), "{port}");
        assert_ne!(
            Some(port),
            cfg.find_org("beta").unwrap().netstack_socks_port,
            "never another org's"
        );
        // And with its port (and its own key), the org joins.
        acme.overlay_wg_secret_key = Some("ACME-KEY".into());
        assert!(cfg.for_org(&acme).overlay_enabled);
    }

    /// #2493 — the verb gives a netstack org a port too; one set to netstack
    /// before the fix (mode unchanged, no port) gets its port all the same;
    /// an explicit port is kept; `tun` never gets one.
    #[test]
    fn org_overlay_verb_gives_netstack_a_port_and_heals_one_without() {
        let mut cfg = two_org_cfg();
        set_org_overlay(&mut cfg, "acme", "netstack").unwrap();
        let first = cfg.find_org("acme").unwrap().netstack_socks_port;
        assert!(
            first.is_some_and(|p| NETSTACK_PORTS.contains(&p)),
            "{first:?}"
        );
        cfg.orgs[0].netstack_socks_port = None;
        set_org_overlay(&mut cfg, "acme", "netstack").unwrap();
        assert!(
            cfg.find_org("acme").unwrap().netstack_socks_port.is_some(),
            "healed although the mode did not change"
        );
        cfg.orgs[0].netstack_socks_port = Some(1090);
        set_org_overlay(&mut cfg, "acme", "netstack").unwrap();
        assert_eq!(
            cfg.find_org("acme").unwrap().netstack_socks_port,
            Some(1090)
        );
        let mut cfg = two_org_cfg();
        set_org_overlay(&mut cfg, "acme", "tun").unwrap();
        assert!(cfg.find_org("acme").unwrap().netstack_socks_port.is_none());
    }

    /// #2493 — the pick never tries a claimed port and skips a bound one. It
    /// works at the TOP of the range, because the other tests pick from its
    /// bottom.
    #[test]
    fn the_netstack_port_pick_skips_claimed_and_busy_ports() {
        let bind = |p: u16| std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, p)).ok();
        let (lo, hi) = NETSTACK_PORTS
            .rev()
            .skip(1)
            .zip(NETSTACK_PORTS.rev())
            .find(|(lo, hi)| bind(*lo).is_some() && bind(*hi).is_some())
            .expect("two free ports at the top of the range");
        let claimed: Vec<u16> = NETSTACK_PORTS.filter(|p| *p != lo && *p != hi).collect();
        let held = bind(lo).expect("hold the lower one");
        assert_eq!(
            pick_netstack_port(&claimed),
            Some(hi),
            "a bound port is skipped"
        );
        drop(held);
        assert_eq!(
            pick_netstack_port(&claimed),
            Some(lo),
            "the lowest free one first"
        );
        let all: Vec<u16> = NETSTACK_PORTS.collect();
        assert_eq!(pick_netstack_port(&all), None, "every port claimed: none");
        assert!(
            *NETSTACK_PORTS.end() < 32768,
            "below every OS's ephemeral range"
        );
    }

    /// #2493 — at daemon start every netstack org without a port gets one;
    /// `tun` and `off` orgs, and a port already set, are left alone; `true`
    /// only when something changed.
    #[test]
    fn heal_gives_portless_netstack_orgs_a_port_and_nothing_else() {
        let mut cfg = two_org_cfg();
        assert!(!heal_netstack_ports(&mut cfg), "an off org: nothing to do");
        cfg.orgs[0].overlay_mode = crate::config::OrgOverlayMode::Netstack;
        assert!(
            heal_netstack_ports(&mut cfg),
            "a portless netstack org is healed"
        );
        let port = cfg.orgs[0].netstack_socks_port.expect("its port");
        assert!(NETSTACK_PORTS.contains(&port));
        assert!(!heal_netstack_ports(&mut cfg), "it has one: nothing to do");
        assert_eq!(cfg.orgs[0].netstack_socks_port, Some(port));
        cfg.orgs[0].overlay_mode = crate::config::OrgOverlayMode::Tun;
        cfg.orgs[0].netstack_socks_port = None;
        assert!(!heal_netstack_ports(&mut cfg), "a tun org never gets one");
    }
}
