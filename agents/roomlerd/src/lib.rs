// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Library crate for `roomlerd`. The binary at `src/main.rs` is a thin
//! CLI shell around these modules; exposing them here lets integration
//! tests drive the agent in-process against a `TestApp` server.

// P3e lever E: the daemon-free building blocks (appdirs, machine, config,
// config_surface, enrollment, logging, logs_upload, crash_recorder, the
// notify primitives, the forward ACL, the apps config shapes) moved to the
// `roomler-node-core` crate so the desktop companion can link them without
// this crate's data plane. Re-exported here under their old `crate::` paths —
// every internal call site is unchanged. `notify` stays a real module (it
// layers the daemon-only worker-aware wrappers over the core primitives);
// `apps` re-exports the moved config shapes; the ACL is re-exported inside
// `tunnel/mod.rs` so `crate::tunnel::acl::…` still resolves.
pub use roomler_node_core::{
    appdirs, config, config_surface, crash_recorder, enrollment, files_dir, logging, logs_upload,
    machine, token_slot,
};

pub mod apps;
/// FR-97 P0d — the machine's native CPU architecture, for the hello.
pub(crate) mod arch;
/// FR-90 P2h-1 — `roomlerd enroll --archive-replica`: an archive replica's
/// posture, written with the enrolled config.
pub mod archive_replica;
pub mod artifact_version;
#[cfg(feature = "audio")]
pub mod audio;
/// FR-97 P3c — what "computer audio" may open, and why it opened nothing.
pub mod audio_source;
pub mod capture;
#[cfg(feature = "clipboard")]
pub mod clipboard;
pub mod clock;
pub mod code_signature;
pub mod companion;
pub mod consent;
pub mod crash_uploader;
pub mod delegate;
#[cfg(unix)]
pub mod delegate_worker;
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
pub mod derp;
pub mod desktop_brief;
pub mod display_match;
pub mod displays;
#[cfg(target_os = "windows")]
pub mod dpi;
pub mod encode;
pub mod exec;
/// FR-94 — Fleet RPC as SYSTEM on Windows: the anchor, the doorbell between
/// the worker and the SYSTEM service, and the service's runner. Compiled
/// everywhere; off Windows it advertises nothing and refuses every ring.
pub mod exec_service;
/// FR-52 P3c — the device's answer to `rc:extauth.*`. Ungated: every build
/// advertises `external-access`, so every build must answer, if only with
/// `unavailable`.
pub mod extauth;
/// FR-52 gate 4 — the device-held external-access password. Feature-gated
/// (`external-access`): the OPAQUE stack is +7 crates, and only a build that
/// serves cross-org access needs it.
#[cfg(feature = "external-access")]
pub mod external_access;
/// FR-52 P3b — gate 4's policy: the guess budget, in-flight logins, and the
/// single-use key a verified login leaves for the session offer.
#[cfg(feature = "external-access")]
pub mod external_logins;
pub mod files;
pub mod fp16;
/// A thread's filesystem identity: a root daemon's work in a person's folder,
/// done as the person (FR-85's, shared with received files by FR-97 P3d).
#[cfg(any(target_os = "linux", all(unix, feature = "recording")))]
pub(crate) mod fs_identity;
pub mod gpu_clock;
/// FR-90 — Hive agent sessions on this device (`hive_enabled`, default off).
/// Linux, macOS and Windows (`cfg(hive_host)`, set by `build.rs`): elsewhere
/// the feature compiles nothing here and the build does not advertise `hive`,
/// so no server sends it a session.
#[cfg(hive_host)]
pub mod hive;
/// FR-90 P1i — agent sessions on Windows: the console user, the harness, the
/// session's preparation, its toolbelt pipe and its directories' DACLs.
#[cfg(all(windows, feature = "hive"))]
pub mod hive_win;
/// FR-99 P4 — the host's speakers are muted while a privacy curtain is up, and
/// restored after it, after a crash too; the controller keeps the audio.
pub mod host_mute;
/// #1740 — a closed ICE agent (the vendored `webrtc-ice`) leaves nothing
/// running behind it; black-box over the agent this daemon's sessions use.
#[cfg(test)]
mod ice_lifetime_tests;
pub mod indicator;
pub mod input;
pub mod install_cleanup;
pub mod install_detect;
pub mod instance_lock;
pub mod jwt_introspect;
pub mod keep_busy;
/// FR-40 — the overlay-key mint behind `rc:agent.key_rotate`. Ungated: it
/// carries the overlay feature split inside so the handler compiles the same
/// in every build (see the module doc for the rustc ICE that forced this).
pub mod key_rotation;
pub mod localapi_state;
pub mod lock_on_end;
pub mod lock_overlay;
pub mod lock_state;
pub mod logs_fetch;
pub mod macos_supervisor;
pub mod mdns_resolve;
pub mod mem_trim;
pub mod power;
pub mod remote_config;
// P5 — crate-private: its surface leans on `peer::TargetResolution`
// (pub(crate)) and nothing outside the agent consumes it. Compiled on
// every build so its pure logic unit-tests on the default feature set
// (mirrors `encode::viewer_rate`); the dead_code allow covers builds
// without the DC video pumps, which are its only production callers.
#[cfg_attr(
    not(any(feature = "vp9-444", feature = "ffmpeg-encoder")),
    allow(dead_code)
)]
pub(crate) mod media_share;
pub mod notify;
pub mod org_join;
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
pub mod overlay;
pub mod peer;
/// FR-100 P1a — this enrollment's device key: made here, kept in its own file
/// beside the config, only its public half on the hello.
pub mod peer_auth;
/// FR-27 P11 — the person-at-the-device socket of a Linux system install; FR-97
/// P2g — and of a Mac's root half, which its per-user half asks for the
/// machine's Devices and Mesh. The pure decisions build everywhere, for tests.
pub mod person_socket;
/// The pinned-key `.asc` check, which lives in `tunnel-core` since FR-97 P6b
/// so the CLI's `self-update` shares it. Re-exported, so `crate::pgp_verify`
/// still names it.
pub use tunnel_core::pgp_verify;
pub mod post_install;
pub mod preflight;
/// FR-108 — is someone using this screen? The idle clock, less the machine's
/// own input, for display match.
pub mod presence;
/// FR-99 P1b — privacy mode: the owner's gate, the `privacy-*` words, and the
/// session's `privacy` channel that puts the overlay's curtain up.
pub mod privacy;
/// FR-16 L4 — `roomlerd probe-target`: a corner window whose marker changes
/// on real pointer moves, so a bench viewer times input to photon on a
/// release build. The layout is pure and tested everywhere; the window is
/// Windows-only.
pub mod probe_target;
/// Pseudo-terminals for Roomler SSH interactive sessions (P4a, Unix only —
/// the module gates itself, so the `cfg` here would be redundant).
pub mod pty;
pub mod rc_local_turn;
/// #1882 — may a remote-desktop session use the overlay (the device's policy,
/// default off), and the ICE filters that keep it off.
pub mod rc_overlay;
pub mod rc_sessions;
/// FR-101 P1 — a remote-desktop session's transport hardening: GCM-only
/// DTLS, with its switch back, and the SRTP/SRTCP replay windows pinned.
pub mod rc_transport;
#[cfg(feature = "recording")]
pub mod recording;
pub mod relay_probe;
/// FR-19 P1d — the org-relay reachability responder (process-wide, opt-in).
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
pub mod relay_server;
/// FR-96 P2b — a per-user Linux daemon restarts onto its replaced binary once
/// nothing it serves would be cut.
pub mod replaced_binary;
/// FR-98 C6 — `playout-delay` 0/0 on the RTP fallback track, so the
/// browser's jitter buffer renders as soon as it decodes (default off).
pub mod rtp_playout;
/// FR-84 D5b — the companion's Devices page: the org's device list and mesh,
/// asked of the server with the org's agent token.
pub mod self_view;
pub mod service;
/// FR-102 P9c — the carrier a remote-control session rides (direct, TURN,
/// the overlay's own carrier under an overlay pair: DERP, an org relay),
/// recorded once the session reaches Active. Record, never decide.
pub mod session_carrier;
/// FR-101 P4b-2 — the idle limit, kept by the device: no input from the
/// controller and no significant change on the screen for `idle_secs` ends
/// the session.
pub mod session_idle;
/// FR-101 P2b — the session policy for clipboard, files and audio, the
/// device's half: the owner's floor, and the masking every grant goes through.
pub mod session_policy;
pub mod session_telemetry;
pub mod shared_lease;
pub mod signaling;
/// FR-93 P5h — a computer going to sleep tells every viewer first.
pub mod sleep_notice;
/// Roomler SSH — the in-daemon SSH surface served on this node's overlay
/// address, intercepted before the OS (`ssh_enabled`, default off). Gated with
/// [`overlay`]: without an overlay there is no address to serve on.
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
pub mod ssh;
/// FR-90 P3-8-2b — this daemon's own SSH client, for an agent session's one
/// command on another device. With the SSH server, whose `russh` it shares.
#[cfg(feature = "ssh-server")]
pub mod ssh_client;
/// The ORIGINATING side of Roomler SSH. Ungated on purpose — [`ssh`] needs an
/// overlay to serve on, but an answer to a request WE sent arrives on the
/// plain control WS and must be deliverable in every build.
pub mod ssh_origin;
/// FR-105 — roomler SSH through a Windows device's SYSTEM service: the framed
/// SSH pipe between the worker and the service, the service's grant claim and
/// endpoint publisher, and the worker's word. Compiled everywhere; off
/// Windows it advertises nothing.
pub mod ssh_service;
pub mod ssh_shared_bridge;
#[cfg(feature = "ssh-server")]
pub mod ssh_shared_stream;
pub mod subnet_detect;
/// FR-84 D3 — which supervisor will relaunch this process, decided from
/// evidence the supervisor left; the only gate on `RestartDaemon`. Pure and
/// ungated so its table is a unit test on every platform.
pub mod supervision;
#[cfg(feature = "system-context")]
pub mod system_context;
/// Re-export, not a module: the TCC probes live in `agent-core` so the desktop
/// companion can use them without depending on the agent (P3e lever E). Every
/// `crate::tcc::…` call site here is unchanged.
#[cfg(target_os = "macos")]
pub use roomler_node_core::tcc;
/// A tarball install's directories given back to root at every start: up to
/// 0.4.126 a tarball install left `/usr` another account's.
#[cfg(target_os = "linux")]
pub mod tarball_owner;
pub mod telemetry;
/// FR-103 — renewing each enrollment's agent token before it expires.
pub mod token_renewal;
pub mod tunnel;
pub mod updater;
/// FR-90 P3-3 — the device's vault key: made while `vault_enabled` is on, in
/// memory only, its public half in the primary enrollment's hello. Compiled
/// everywhere; without the `vault` feature it makes nothing.
pub mod vault;
/// FR-90 P3-5 — the vault's proxies: an endpoint that authenticates upstream
/// with a leased value. P3-5b-1 builds the engine; the endpoint
/// (`hive::vault_connect`, P3-5b-2, and P3-5b-4 on Windows) serves it.
#[cfg(feature = "vault")]
pub(crate) mod vault_proxy;
pub mod version_sweep;
pub mod virtual_desktop;
pub mod watchdog;
#[cfg(target_os = "windows")]
pub mod win32_monitors;
/// FR-84 D4 — "is this process LocalSystem, and whose profile is its
/// session's?", on every Windows build: the `files_dir` placement rule must
/// not depend on the `system-context` feature.
#[cfg(target_os = "windows")]
pub mod win_identity;
#[cfg(target_os = "windows")]
pub mod win_service;
#[cfg(target_os = "windows")]
pub mod win_timer;
/// FR-85 / FR-90 P1i-2 — a token's identity on every Windows build: the
/// restricted, medium copy a daemon that is not SYSTEM starts a person's
/// processes with (a recording, an agent session).
#[cfg(target_os = "windows")]
pub mod win_token;
/// #2187 — the control WS and DERP dial the server's remembered address
/// (`tunnel_core::ctl_dns`), so a dead exit DNS can never keep them offline.
pub mod ws_connect;

/// P5 exit-node crash-safety (A2) — synchronously purge any leftover
/// split-default routes from the overlay NIC. Called at agent startup (the
/// boot-time reconciler: heal a `/1` a crash / kill / unclean reboot left
/// behind) AND immediately before each `std::process::exit` that bypasses the
/// runtime's RAII teardown (watchdog stall, self-update, agent-deleted) — those
/// paths run NO destructors, so without this a Windows host keeps a stale
/// `0.0.0.0/1` pointed at a dead Wintun adapter and blackholes all egress until
/// reboot.
///
/// Lives at the crate root (always compiled) so the exit paths in `watchdog` /
/// `signaling` / `main` can call it WITHOUT an overlay-feature gate — the
/// `overlay` module itself is `cfg`-gated. No-op unless this is an `overlay-l3`
/// build (only the OS-TUN surface installs OS routes; the userspace netstack has
/// none). Best-effort + scoped to the roomler NIC.
pub fn purge_exit_routes() {
    #[cfg(feature = "overlay-l3")]
    {
        // Multi-org v2 — the purges are per-adapter now; this boot/pre-exit
        // path heals the LEGACY/PRIMARY adapter (per-org adapters are Phase
        // 2c, whose reconciler will walk the configured set).
        tunnel_core::overlay::tun::purge_split_default(tunnel_core::overlay::tun::IF_NAME);
        // Drop peer/subnet routes a PREVIOUS generation left on a persisted TUN.
        // Their crypto-router entries died with that runtime, so they black-hole
        // silently: the OS route looks right, the peer is online, and only the
        // traffic vanishes (field case 2026-08-03). Safe here because the router
        // is empty until `install_peers` runs, which re-adds the live set.
        tunnel_core::overlay::tun::purge_stale_peer_routes(tunnel_core::overlay::tun::IF_NAME);
        // S4b — also drop any leftover exit-node DNS steer. On Windows the `.`-root
        // NRPT rule is machine-global and PERSISTS across a crash/reboot, so a stale
        // rule pointing at a dead resolver would blackhole ALL DNS until removed —
        // this boot/pre-exit purge is the load-bearing cleanup for it.
        tunnel_core::overlay::dns::purge_exit_dns();
        // FR-97 P0b-2b / P0e — and what the host ledger records: the IPv4
        // forwarding a Windows router turned on (its revert runs in `Drop`,
        // which these exits skip, #2077 defect 2), and every exit-client pin
        // (host routes through the PHYSICAL uplink, which outlive the TUN; a
        // leftover pin on the server's address blocks the next start's
        // control WS after a network change). A no-op when it is empty.
        tunnel_core::overlay::host_ledger::purge();
    }
}

/// #1690 — [`purge_exit_routes`] for a process that may NOT own the overlay
/// adapter: `roomlerd self-update` run by hand or through `roomler exec`.
/// While a daemon is running (it answers the LocalAPI), the routes, the
/// exit split-default and the DNS steer are that daemon's: its route guard
/// would re-add the routes within seconds, but nothing re-asserts the DNS
/// steer before its next start, and the installer is about to stop it — its
/// own teardown and the new binary's boot reconciler handle what is left.
/// With no daemon running, the leftovers have no owner and are purged as
/// before. Returns whether it purged.
pub fn purge_exit_routes_unless_owned(daemon_running: bool) -> bool {
    if daemon_running {
        return false;
    }
    purge_exit_routes();
    true
}

#[cfg(test)]
mod tests {
    /// #1690 — a running daemon keeps its routes: `roomlerd self-update`, a
    /// second process, must not purge them. Only this branch is exercised —
    /// the other deletes real routes on an `overlay-l3` build.
    #[test]
    fn a_running_daemon_keeps_its_routes() {
        assert!(!super::purge_exit_routes_unless_owned(true));
    }
}
