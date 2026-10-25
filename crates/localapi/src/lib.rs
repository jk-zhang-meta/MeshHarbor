// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Roomler **LocalAPI** — the local control surface (P1: read-only).
//!
//! The unified daemon (`roomlerd`) will expose this over a local-only channel
//! (named pipe on Windows / unix socket elsewhere; ACL-authenticated — wired in
//! P1-cont) so thin clients — the CLI (`roomler`) and the desktop app (Roomler)
//! — can read live
//! node / peer / flow state without reaching into the daemon's internals. This
//! module is the **transport-agnostic protocol**: the request/response wire
//! types plus a pure [`handle`] dispatch over a [`LocalApiState`] snapshot. The
//! pipe listener + the daemon's `LocalApiState` impl (gathering real overlay /
//! tunnel / forward state) land in P1-cont; keeping the protocol pure here makes
//! it unit-testable with a mock and reusable by both the daemon and clients.
//!
//! Wire shape: newline-delimited JSON, adjacently tagged (`{"t":<verb>}` /
//! `{"t":<verb>,"d":<payload>}`) so a payload may be a struct OR a sequence.

pub mod path_trials;
pub use path_trials::*;

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::sync::watch;

// FR-90 P1j — the adopt socket's protocol: a separate socket, open to every
// account, whose peer the daemon identifies by the kernel's word alone.
pub mod hive_adopt;

// FR-84 D5b — the device's own view of its org (the Devices page's grid and
// mesh), in its own file so the verbs' types don't sprawl through this one.
mod devices;
pub use devices::{
    DeviceRowLite, DevicesPage, DevicesQuery, DirectoryError, MeshAgentLite, MeshCenter,
    MeshEdgeEndLite, MeshEdgeLite, MeshNodeLite, MeshView,
};

/// How this node currently reaches a peer — the Tailscale-style connection
/// type shown per device in the UI. `Tunnel` is the userspace SOCKS/forward
/// path (used when a corp full-tunnel VPN captures the overlay's routes);
/// `Blocked` = a peer with no working carrier; `Offline` = not currently up.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionType {
    Direct,
    Relay,
    Tunnel,
    Blocked,
    Offline,
}

/// What kind of node the daemon is. It says nothing about the account the
/// process runs as: a per-user `roomlerd` is a full node and reports
/// `Service`. That account is [`NodeStatus::privileged`].
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DaemonMode {
    /// SYSTEM service — full node (can *be accessed* + *reach others*).
    Service,
    /// Unprivileged user session — *reach others* only, no admin.
    User,
}

/// P5 exit-node — this node's default-route-egress status (Tailscale "use exit
/// node"). Published by the overlay runtime so `roomler status` / the desktop can
/// show whether this node is routing its internet egress through a mesh peer and,
/// crucially, WHY it isn't when it's configured but not active — the split-tunnel
/// signal (S4): the client withholds default routing rather than self-wedge when
/// the exit peer is absent / uncarriered / unapproved, or a carrier-endpoint
/// exemption can't be pinned.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ExitNodeStatus {
    /// The configured exit-node selector (a peer name or node-id hex).
    pub selector: String,
    /// `true` when the split-default is installed — this node's internet egress
    /// currently routes through the exit peer.
    pub active: bool,
    /// Human-readable reason routing is NOT active while `active == false`
    /// (e.g. "exit node not visible in the mesh yet", "not an approved exit
    /// node", "carrier-endpoint exemption unavailable"). `None` when `active`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withheld_reason: Option<String>,
    /// P5/S3b — `true` when GLOBAL IPv6 egress ALSO routes through the exit. When
    /// `active` but this is `false`, v6 is fail-closed (blackholed, never leaked)
    /// — the exit is v6-incapable (e.g. Windows: WinNAT has no v6) or this host
    /// has no v6 uplink to exempt the coordination server. Defaults false for
    /// back-compat with a daemon/CLI that predates v6 egress.
    #[serde(default)]
    pub v6_active: bool,
    /// P5/S4b — `true` when the DEFAULT ("." catch-all) DNS namespace is steered
    /// through the exit, so every non-overlay query resolves from the exit's
    /// vantage (no DNS leak to the local ISP resolver). When `active` but this is
    /// `false`, DNS is NOT steered — the local overlay resolver failed to bind, or
    /// `resolvectl`/NRPT is unavailable — and queries may resolve via the local
    /// uplink; surfaced so it's never a SILENT leak. Defaults false for back-compat
    /// with a daemon/CLI that predates DNS steering.
    #[serde(default)]
    pub dns_steered: bool,
    /// FR-97 P0c-3 — `Some(port)` when this node runs the userspace netstack.
    /// It installs no OS routes, so the exit carries only what its SOCKS5
    /// front on `127.0.0.1:<port>` dials: IPv4 destinations, including names
    /// the SOCKS client resolves itself. Nothing else on the host uses the
    /// exit; the front refuses IPv6 destinations and resolves names only to
    /// overlay peers; no DNS is steered. Measured 2026-10-17 (FR-97 §8).
    /// `None` on an OS-TUN node, and from an older daemon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks5_port: Option<u16>,
}

/// FR-97 P3i — what the host's own firewall lets a mesh peer reach on this
/// node's overlay address.
///
/// Measured (FR-97 §8): carriers pass a host firewall, because hole-punched
/// and LAN-direct paths both ride conntrack, but the overlay adapter falls
/// under the firewall's default zone or default incoming policy, so a service
/// on the overlay address is refused unless the firewall admits it. The daemon
/// leaves the firewall to the host's owner and reports what governs the
/// adapter, so a refused connection has a stated cause.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HostFirewallStatus {
    /// `firewalld` or `ufw`.
    pub kind: String,
    /// The overlay adapter this describes (`roomler0`).
    pub interface: String,
    /// firewalld: the zone that governs the adapter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// firewalld: the adapter is in no zone, so the default zone governs it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub zone_is_default: bool,
    /// Every inbound connection on the adapter is accepted: a zone whose
    /// target is `ACCEPT`, ufw allowing incoming by default, or a ufw rule
    /// open to anything on the adapter.
    pub admits_all: bool,
    /// Otherwise what it admits, as the firewall names it: firewalld services,
    /// ports, protocols and a count of rich rules; ufw's incoming ALLOW rules
    /// that apply to the adapter. Empty = nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub admits: Vec<String>,
}

/// Snapshot of the local node.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NodeStatus {
    /// Owner-local bounded path-trial observation. Absent on old/off/detached runtimes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_trials: Option<PathTrialStatus>,
    pub node_id: String,
    pub name: String,
    pub version: String,
    pub mode: DaemonMode,
    /// The account the daemon process runs as: `Some(true)` = root or
    /// LocalSystem (a system install), `Some(false)` = the signed-in user (a
    /// per-user install). Before this field, `status` printed "SYSTEM" for
    /// every `Service` daemon, per-user ones included. Additive: `None` from
    /// an older daemon, and an older CLI ignores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay_ip: Option<String>,
    /// The node's *derived* overlay IPv6 (`fd72:6f6f:6d6c::<v4>`), published by
    /// the overlay runtime alongside the v4. Absent on a v4-only daemon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay_ip6: Option<String>,
    /// Connected to the coordination server.
    pub connected: bool,
    /// FR-51 P4 — this daemon's PRIMARY enrollment is ephemeral: the server
    /// reaps the device after silence, and the daemon de-enrolls itself on a
    /// clean stop. Additive both ways: an older daemon omits it (⇒ false),
    /// an older CLI ignores it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ephemeral: bool,
    /// P5 exit-node routing status. `None` unless this node is configured as an
    /// exit-node CLIENT (`overlay_exit_node`). Backward-compatible (older CLIs
    /// ignore the extra field; a v4-only / non-exit daemon omits it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_node: Option<ExitNodeStatus>,
    /// FR-97 P0b — why this node offers no `/0` and no subnet route although
    /// it was configured to: the host cannot forward or NAT for the overlay.
    /// `None` = offering as configured (or nothing configured). Additive both
    /// ways: an older daemon omits it, an older CLI ignores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_offer_withheld: Option<String>,
    /// FR-97 P3i — what the host's own firewall lets a mesh peer reach on this
    /// node's overlay address, copied from [`OverlayView::host_firewall`].
    /// `None` when no firewalld or ufw is active (or the daemon cannot ask),
    /// and from an older daemon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_firewall: Option<HostFirewallStatus>,
    /// S1b — the config file this daemon actually LOADED. Ends the desktop's
    /// guessing game about which of the per-user / machine-global copies is
    /// live (their resolution ladders disagreed for plain-SCM installs).
    /// Additive; absent from older daemons.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_path: Option<String>,
    /// S2 — MagicDNS status, copied verbatim from [`OverlayView::dns`].
    /// `None` when the overlay is off, MagicDNS is off for the tenant, or
    /// the daemon predates the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsStatus>,
    /// NAT-traversal — the outcome of this node's srflx (STUN) gather, copied
    /// verbatim from [`OverlayView::srflx`]. `None` from a daemon that predates
    /// the field or one with the overlay off. An **empty `candidates`** list is
    /// the fleet-health signal: this node cannot hole-punch, and every peer
    /// reads it as UDP-blocked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub srflx: Option<SrflxStatus>,
    /// C4 stage 1 — the standing warm TURN/UDP allocation's state, copied
    /// verbatim from [`OverlayView::warm_relay`]. `None` from a daemon that
    /// predates the feature or has `overlay_warm_relay` off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warm_relay: Option<WarmRelayStatus>,
    /// FR-33 — LAN prefixes this host owns an address in whose traffic the OS
    /// routes through ANOTHER interface (a corp-VPN split-prefix capture: LAN
    /// handshakes arrive, our replies leave through the VPN and die, and the
    /// LAN tier can never latch while it lasts). `None` from a daemon that
    /// predates the field or has the probe off; `Some(empty)` = probed,
    /// nothing captured — the two must stay distinguishable, or an old daemon
    /// would read as "clear".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lan_captures: Option<Vec<LanCaptureStatus>>,
    /// FR-33 — whether the capture probe is switched ON on this daemon
    /// (`overlay_lan_capture_probe`, built-in default on). `Some(false)` =
    /// the operator turned it off, so there is NO capture verdict: `why`
    /// cannot say `lan-captured` and the RC pill cannot name a VPN. Field
    /// 2026-09-04: with the probe off the daemon sent `lan_captures:
    /// Some(empty)` and `status` printed `clear` — the same word as a
    /// genuinely clear host, which is exactly the misreading FR-33 exists to
    /// prevent. Now the daemon sends `lan_captures: None` + this flag, so an
    /// old CLI prints nothing (the documented contract) and a new one prints
    /// `probe OFF`. `None` from a daemon that predates the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lan_capture_probe: Option<bool>,
    /// FR-47 — the last overlay join the server REFUSED, if any. `None` means
    /// no refusal has been seen this daemon lifetime (or the daemon predates
    /// the field). See [`JoinRefusalStatus`] for why it is not cleared once a
    /// later join succeeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join_refusal: Option<JoinRefusalStatus>,
    /// B4 (overlay v3) — the measured netcheck capability vector + its age
    /// (`roomler netcheck`). `None` from a pre-B4 daemon or before the
    /// first measurement completes (~45 s after start).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netcheck: Option<NetcheckStatus>,
    /// Multi-org P1 — one row per enrollment (the primary first, then each
    /// `[[orgs]]` entry). Empty from a pre-multi-org daemon and omitted by a
    /// single-org one; the top-level scalar fields (`node_id` / `tenant_id`
    /// / `connected`) keep aliasing the PRIMARY enrollment so older tray /
    /// CLI builds render unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub orgs: Vec<OrgStatus>,
    /// Multi-org v2 retirement evidence — cumulative compensation-layer
    /// PR-B1 — per-bound-direct-socket receive liveness, copied verbatim from
    /// [`OverlayView::direct_socks`]. A socket whose `rx_pkts` is frozen while
    /// peers punch its advertised endpoint is the 2026-08-10 wedge signature
    /// (bound, reader-less, Recv-Q pegged). Empty from older daemons.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub direct_socks: Vec<DirectSockStatus>,
    /// #32 — `(unrouted, backpressure)` inbound `/derp` frames the mux could not
    /// hand to a consumer, cumulative for this process. `None` from older daemons.
    ///
    /// `unrouted > 0` means a peer is relaying to us while we hold it on a
    /// different carrier — the demote-follow's input, and the first thing to read
    /// when a pair is dark after a network transition. `backpressure > 0` means a
    /// LIVE consumer stopped draining.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derp_inbound_drops: Option<(u64, u64)>,
    /// PR-B1 tripwire — direct-socket binds that walked off the stable base
    /// port this run (`tunnel_core::evidence::DIRECT_BIND_WALKS`). Nonzero on a
    /// host with a configured stable port = external squatter OR an
    /// in-process bind collision (bug signal). `None` from older daemons.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_bind_walks: Option<u64>,
    /// A3 — peer endpoints adopted via WG-style roaming since daemon start
    /// (`tunnel_core::evidence::ROAM_ADOPTIONS`). A few is normal (symmetric-NAT
    /// mapping learned); a steadily climbing count is endpoint thrash. `None`
    /// from older daemons.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roam_adoptions: Option<u64>,
    /// FR-68 — route-guard evidence, all cumulative since daemon start:
    /// `(evictions, sibling_spares, waves, forced_revalidations)`.
    ///
    /// Grouped because no single one of them means anything alone. The pair
    /// that carries the #1237 signal is evictions vs sibling spares: on a
    /// healthy multi-org host spares climb while evictions stay flat, and with
    /// `OVERLAY_SIBLING_EXEMPT=0` that inverts. ⚠️ There is deliberately no
    /// "sibling evictions" number — after #1246 such a row is spared, so the
    /// count would read zero whether the fix works or was reverted.
    ///
    /// `None` from daemons predating FR-68; on a non-Windows host the route
    /// guard is a no-op, so evictions and spares stay 0 honestly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_guard: Option<(u64, u64, u64, u64)>,
    /// #1282 — which ARM armed each route-defense wave: `(tick, event)`,
    /// cumulative.
    ///
    /// A SEPARATE field rather than two more slots on `route_guard`,
    /// deliberately: that tuple's shape already shipped in 0.4.58, and
    /// widening it would make a 0.4.58 CLI fail to parse a newer daemon's
    /// status — a mixed-version pair is the normal state during a fleet roll.
    /// Additive + `serde(default)` keeps both directions working.
    ///
    /// `route_guard.2 - (tick + event)` should be 0; anything else is a third
    /// caller of `run_defense_wave` that nobody attributed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_wave_arms: Option<(u64, u64)>,
    /// #1328 — times the route guard STOOD DOWN from a prefix it kept losing
    /// (`tunnel_core::evidence::ROUTE_YIELDS`), cumulative.
    ///
    /// Its own scalar for the same compatibility reason as `route_wave_arms`:
    /// both tuples above already shipped, and widening a released tuple breaks
    /// an older CLI's parse against a newer daemon — the normal state mid-roll.
    ///
    /// ⚠️ Read it WITH `route_guard.0`. Yields climbing while evictions go flat
    /// is the stand-down working; BOTH climbing means the backoff is being
    /// out-paced and the cooldown is too short for that competitor. Zero on a
    /// healthy host, and zero on every non-Windows host (the guard is a no-op).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_yields: Option<u64>,
    /// #1282 — TICK-arm waves an EVENT pulled forward
    /// (`tunnel_core::evidence::ROUTE_WAVES_PULLED`), cumulative.
    ///
    /// Its own scalar for the same compatibility reason as `route_wave_arms`.
    /// Read it against `route_wave_arms.0`: `pulled ≈ tick` is a guard whose
    /// own route writes keep re-arming it (the macOS and Windows 3 s loops of
    /// #1856 / #1282). `None` from daemons that predate it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_wave_pulls: Option<u64>,
    /// C1 (disco) — out-of-tunnel carrier echoes this node ANSWERED
    /// (`tunnel_core::evidence::DISCO_ANSWERED`). Nonzero on every node is the C1
    /// field gate: the fleet can answer, so a prober may ship next. `None`
    /// from a daemon predating the responder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disco_answered: Option<u64>,
    /// FR-19 — this node's org-relay probe responder, or `None` when it is not
    /// running (the default: `relay_server_enabled` is opt-in).
    ///
    /// ⚠️ `None` and a running-but-idle responder are **different states** and
    /// must stay distinguishable. "No relay here" and "a relay that has
    /// answered nothing" lead to opposite next actions, and collapsing them is
    /// how FR-18's `dropped_stale` became unevaluable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_relay: Option<OrgRelayStatus>,
    // RETIRED-NAME-ANCHOR: names the retired prefixes this field exists to DETECT.
    // It is live compatibility, not history: delete the legacy arm in `node_env` and
    // this field has nothing left to report, so it goes with it. docs/fr/FR-46
    /// FR-46 (#1051) — full env-var names this daemon has actually READ through
    /// a RETIRED prefix since it started (`ROOMLER_NODE_*`), sorted and deduped.
    /// `None` from a daemon predating the field. Since FR-46 P2b `ROOMLER_AGENT_*`
    /// can never appear here — it is not read at all; see `retired_env_present`.
    ///
    /// This exists because the warning was write-only. `env::note_legacy_use`
    /// logs once per variable near startup, so a `roomler logs` tail on a
    /// long-running daemon cannot find it, and "does any host still depend on a
    /// retired name?" had to be answered by sweeping env vars and registries by
    /// hand — which under-reported twice: once to a `tail -1`, once because
    /// Windows drops EMPTY variables from a process env block while leaving
    /// them in the registry a future start will read.
    ///
    /// ⚠️ **`Some([])` means "nothing retired has been read YET", NOT "this
    /// host sets none."** Knobs are read lazily and some sit on a code path
    /// that has not run. The positive is authoritative; the negative is weak
    /// evidence — the same asymmetry as `ssh_activity`, and it must not be
    /// collapsed into "clean".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_env_uses: Option<Vec<String>>,
    /// FR-46 P2b — retired-prefix variables that are SET on this host and are
    /// NOT read by anything. `None` from a daemon predating the field.
    ///
    /// ⚠️ Distinct from [`Self::legacy_env_uses`], and folding the two together
    /// would lose the distinction that matters: that one is "a non-current
    /// prefix was READ" (rename it, something depends on it), this one is "a
    /// retired prefix EXISTS and was ignored" (the host was configured for a
    /// spelling the daemon no longer honours). Opposite actions.
    ///
    /// This exists because the alternative to reporting is silence: the read
    /// chain simply stops seeing the variable, the daemon starts fine, and the
    /// host quietly runs without a setting its operator believes is applied.
    /// Two fleet sweeps found exactly that shape — systemd drop-ins no package
    /// upgrade rewrites, and machine-wide registry values in no runbook.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_env_present: Option<Vec<String>>,
    /// FR-84 D3 — the process that answered. A client waiting out a restart
    /// ([`Request::RestartDaemon`]) must know the relaunched daemon from the
    /// one that accepted: the old process keeps answering for a moment after
    /// it says yes, and "reachable" alone would read that as "back". `None`
    /// from a daemon that predates the field. See [`DaemonInstance`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// FR-84 D3 — when this daemon process started (unix ms). With `pid` it
    /// names the PROCESS, not just a number: Windows can hand a PID freed a
    /// moment ago to the very next process — which, after a restart, is the
    /// relaunched daemon itself. `None` from a daemon that predates the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at_ms: Option<u64>,
    /// FR-84 D4 — where a file dropped onto a remote-control session would
    /// land RIGHT NOW: the configured `files_dir` (validated for this
    /// daemon's identity and the active user, `~` expanded) when it passes,
    /// else the default ladder (the active user's Downloads). `None` from a
    /// daemon that predates the field. The Overview shows it next to
    /// "Change…" / "Use default".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files_dir: Option<String>,
}

/// FR-19 — the org-relay probe responder's live state (see
/// [`NodeStatus::org_relay`]).
///
/// This exists because the log was not enough in the field: the responder
/// summarises its counters every 300 s **and sleeps before the first report**,
/// so a freshly restarted relay is unreadable for five minutes — exactly the
/// window in which someone is asking "is it working?". Reading it out of
/// `roomler status` answers that immediately.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OrgRelayStatus {
    /// The bound `ip:port`.
    ///
    /// ⚠️ Present means **bound**, which is NOT the same as reachable. A
    /// coturn-style DNAT can consume the port in `PREROUTING` while the socket
    /// sees nothing and `ss -ulnp` shows it free — measured on mars, where that
    /// confound nearly inverted FR-19's port decision. `answered > 0` is the
    /// evidence of reachability; this field is only evidence of a listener.
    pub listening: String,
    /// Probes answered since start.
    pub answered: u64,
    /// Datagrams refused for not being org-relay shaped at all.
    pub refused_not_shaped: u64,
    /// Org-relay shaped, but not a probe (wrong length, or a data frame).
    pub refused_not_probe: u64,
    /// Refused because the source had spent its per-window allowance.
    ///
    /// One counter per refusal REASON rather than a single "refused", because
    /// during a flood the reason is the whole diagnostic: an attack and a
    /// misconfigured peer look identical in a total.
    pub refused_rate_limited: u64,
}

/// PR-B1 — one bound direct socket's receive liveness (plane or per-device
/// demux). See [`NodeStatus::direct_socks`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DirectSockStatus {
    /// The socket's bound `ip:port` (the wildcard public dialer is labeled).
    pub local: String,
    /// Datagrams the owning recv loop actually READ (cumulative since bind).
    pub rx_pkts: u64,
    /// Seconds since the last read datagram; `None` = never read one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_rx_age_s: Option<u64>,
}

/// Multi-org P1 — one enrollment's live state (see [`NodeStatus::orgs`]).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OrgStatus {
    /// `primary` for the scalar identity, else the `[[orgs]]` label.
    pub label: String,
    pub server_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// This org's server-assigned agent id (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    pub primary: bool,
    /// Config-level soft-enable; a disabled org has no supervised WS loop.
    pub enabled: bool,
    /// This org's signaling WS is currently established.
    pub connected: bool,
    /// The org's supervisor stopped permanently this run (server goodbye /
    /// duplicate-instance escalation). Cleared by a daemon restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_error: Option<String>,
    /// `rc:agent.update` pushes ignored on this org's WS because only the
    /// primary enrollment may drive the machine-wide self-updater.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub updates_ignored: u32,
    /// FR-49 — this enrollment's overlay participation: `off` | `netstack` |
    /// `tun` (`OrgOverlayMode::wire`).
    ///
    /// ⚠️ **Empty means "this daemon does not report it", NOT "off".** A
    /// secondary org defaults to `off` and its WS still connects, so an org
    /// with no mesh was indistinguishable from a healthy one on every surface
    /// an operator has — which is the whole reason this field exists. Rendering
    /// an absent value as `off` would put that same lie back, one layer up, and
    /// it is the identical trap to an absent age reading as 0 ms.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub overlay_mode: String,
    /// FR-103 — when the agent token this enrollment uses now expires (unix
    /// seconds), read from the token itself, so it moves when the daemon
    /// renews it. Absent = a daemon older than FR-103, or a token with no
    /// readable expiry: "not reported", never "does not expire".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_expires_at: Option<i64>,
}

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

/// S2 — the MagicDNS state the overlay runtime publishes: what the
/// desktop's DNS section and `roomler status` render. Tenant-level
/// domain administration stays server-side (web admin); these are the
/// per-node facts.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DnsStatus {
    /// The magic domain in effect (e.g. `tenant.roomler.net`).
    pub magic_domain: String,
    /// The local resolver bound `<overlay-ip>:53` (the split-DNS target).
    pub resolver_bound: bool,
    /// The OS was successfully pointed at our resolver for the magic
    /// domain (split-DNS steer active; reverted on daemon exit).
    pub os_steer_active: bool,
    /// Upstream resolver non-overlay queries forward to.
    pub upstream: String,
    /// AAAA (derived overlay IPv6) answers are enabled.
    pub answer_aaaa: bool,
    /// FR-97 P3h — the steer is in place, but this host's own resolver never
    /// asks it, and this says where it asks instead. Linux only: the steer
    /// lives in systemd-resolved, so it is bypassed when nsswitch has no
    /// `resolve` and `/etc/resolv.conf` does not name resolved's stub (WSL's
    /// generated file, a static one). `None` from an older daemon too, so
    /// nothing is claimed that was never measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_steer_bypassed: Option<String>,
}

/// NAT-traversal: the outcome of this node's server-reflexive (STUN) gather.
///
/// Exists because the srflx tier failed **fleet-wide and silently** for an
/// unknown period (2026-08-06: coturn emitted its UDP replies with `TTL=1`, so
/// every forwarded reply was dropped before the FORWARD chain). Both failure
/// paths logged at `debug!`, so nothing above DEBUG ever said a word — while
/// every pair in the mesh silently degraded to the DERP carrier, its slowest
/// tier. An empty `candidates` here is the single most useful number for
/// "why is everything on relay?".
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct SrflxStatus {
    /// Public `ip:port` candidates STUN reported for our direct sockets.
    /// **Empty = the whole srflx tier is dead on this node**: no hole-punch,
    /// and every peer reads us as UDP-blocked.
    #[serde(default)]
    pub candidates: Vec<String>,
    /// The STUN server actually queried, once resolved. `None` = none of the
    /// netmap's `stun_urls` resolved to a usable v4 endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stun_server: Option<String>,
    /// Our probed NAT class — `cone` (hole-punchable) / `symmetric` /
    /// `None` = unclassified (the punch is still attempted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nat: Option<String>,
    /// R2 — the mapping was gathered via the wildcard public-dial socket
    /// (full-tunnel VPN egress rescue: every LAN-bound vantage was dead and
    /// the captured default route answered). Punches ride the tunnel path.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub via_public_dial: bool,
    /// Why the gather produced nothing, when it produced nothing. `None` on
    /// success. Rendered verbatim by `roomler status`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// §6 item 5 — the gateway port mapping advertised first among
    /// `candidates` (`"pcp ip:port"` / `"nat-pmp ip:port"`). `None` = no
    /// gateway granted one (or `OVERLAY_PORTMAP` is off).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portmap: Option<String>,
}

impl SrflxStatus {
    /// Did the srflx tier come up at all?
    pub fn is_healthy(&self) -> bool {
        !self.candidates.is_empty()
    }
}

/// B4 (overlay v3) — the measured netcheck capability vector as surfaced by
/// `roomler netcheck`: what selection actually keys on, plus the
/// measurement's age (fresh under 60 min; stale vectors are treated as
/// absent by every consumer).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NetcheckStatus {
    /// The srflx gather found a public mapping.
    pub stun_udp: bool,
    /// Raw UDP reaches coturn's relay band, measured over the exact
    /// single-relay dialer path. `None` = could not be measured (no creds /
    /// no srflx to permit) — absence of measurement is never evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_band_udp: Option<bool>,
    /// The central `/derp` WS is up + registered (the floor's health).
    pub derp_ws_ok: bool,
    /// Probed NAT class (`cone` / `symmetric`), when typed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nat: Option<String>,
    /// Seconds since the vector was measured.
    pub age_s: u64,
}

/// C4 stage 1 — the standing warm TURN/UDP allocation (measurement-only:
/// nothing routes over it yet). Exists so a VPN transition's effect on the
/// grandfathered relay flow is READABLE — "the allocation survived the VPN
/// connect" must be a status line, not log archaeology.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WarmRelayStatus {
    /// `live` | `none` | `lost`. `none` = never established this run (or
    /// re-establish pending); `lost` = it existed and a probe/allocation
    /// failure ended it (see `detail`).
    pub state: String,
    /// The allocation's relayed transport address (`worker-ip:port`) —
    /// the future rendezvous `R`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relayed: Option<String>,
    /// C4 stage 2 — which transport the warm leg rides: `udp` (the
    /// grandfather-measurable flavor) or `tls` (TURNS/TCP:443 — the
    /// strict-corp fallback that survives a VPN capture). `None` from a
    /// pre-stage-2 daemon or while nothing is live.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flavor: Option<String>,
    /// Seconds since the allocation was established.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_s: Option<u64>,
    /// Seconds until the ephemeral credentials expire (negative = past
    /// due; stage 1 re-establishes fresh rather than re-allocating on the
    /// same socket, so expiry on a UDP-blocked network means `lost`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cred_expiry_in_s: Option<i64>,
    /// Seconds since the last successful liveness probe (a 1-byte
    /// permission assert through the allocation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_probe_ok_s: Option<u64>,
    /// Why `none`/`lost`, when known. Rendered verbatim by `roomler status`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// A peer device as this node currently sees it.
// NOTE: no `Eq` — `PeerWhy` carries the selector's f64 scores, and rounding
// them to keep `Eq` would make the diagnostic lie about the numbers the
// selector actually used. Nothing compares `PeerInfo` for total equality.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PeerInfo {
    pub node_id: String,
    pub name: String,
    /// Multi-org — the label of the org this peer belongs to (the `[[orgs]]`
    /// label, or `primary`). A device in N orgs runs N overlay engines with
    /// DISJOINT peer sets and disjoint address spaces, so a flat peer list is
    /// ambiguous: two orgs can each hold a peer named the same, and the same
    /// physical host appears once per shared org under different overlay IPs.
    ///
    /// Empty for a single-org device and for a daemon older than the field
    /// (`#[serde(default)]` — an older CLI renders its flat table unchanged).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub org: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay_ip: Option<String>,
    /// The peer's *derived* overlay IPv6 (`fd72:6f6f:6d6c::<their-v4>`),
    /// published by the overlay runtime alongside the v4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay_ip6: Option<String>,
    pub online: bool,
    pub connection: ConnectionType,
    /// P8-cosmetics — a make-before-break direct-upgrade probe is currently in
    /// flight for this (relay-carried) peer: the CLI renders `upgrading`
    /// instead of `relay`, so a snapshot taken mid-transition reads as what it
    /// is rather than contradicting observed latency. `false` from older
    /// daemons (serde default) and for non-relay peers.
    #[serde(default)]
    pub upgrading: bool,
    /// rc.275 honesty — the carrier is installed but SILENTLY ONE-WAY (no
    /// completed WG handshake past the warm-up grace, or the one-way strike
    /// counter accumulating). The CLI renders `stalled` instead of a
    /// healthy-looking `direct`/`relay`. `#[serde(default)]` — absent from a
    /// pre-rc.275 daemon ⇒ `false` (wire-compatible both ways).
    #[serde(default)]
    pub stalled: bool,
    /// Which relay this peer's carrier rides, when relayed: `turn` | `derp`.
    ///
    /// A bare `relay` in the CONN column could not distinguish a 52 ms coturn
    /// hop from a 175 ms DERP one, nor a healthy PoP from a DEAD one — on
    /// 2026-08-12 a coturn worker was down for 90 minutes while agents
    /// crash-looped and this column said only "relay". Empty for direct peers
    /// and for daemons older than the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_kind: Option<String>,
    /// How that relay is reached: `udp` | `tcp`. Load-bearing for latency
    /// expectations, and for corporate paths where only 443/TCP survives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_transport: Option<String>,
    /// The relay server / PoP, when the carrier knows it (`host:port`). This
    /// is what you would check `kubectl -n coturn get pods` against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_ms: Option<u64>,
    /// The `agents._id` (hex) backing this peer, when it's an agent node
    /// (P3b-3). Carried from the netmap so the daemon can join this peer to a
    /// daemon-originated tunnel flow (keyed by agent id) and label it
    /// `ConnectionType::Tunnel`. `None` for a tunnel-client node / pre-P3b-3
    /// runtime. Not a display column — a join key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// rc.187 — for a RELAY peer: our own coturn-relayed address and the peer's
    /// relayed address we dial (both `host:port`). `None` for direct/blocked/
    /// offline. Lets `peers --json` show which coturn worker each end pinned —
    /// same-worker (the two IPs match) vs cross-worker — without a debug-log hunt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_local: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_dst: Option<String>,
    /// rc.276 diagnostics — the installed carrier's forensic snapshot (which
    /// flow each peer rides + whether it actually works), for `peers --json`
    /// only. `None` for a peer with no installed carrier or from a pre-rc.276
    /// daemon (wire-compatible both ways).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debug: Option<PeerCarrierDebug>,
    /// F — the path decision for this peer, in readable form
    /// (`roomler why <peer>`). Always populated by a current daemon; `None`
    /// from an older one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<PeerWhy>,
    /// A — what the disco prober measures for this peer's path(s). Empty when
    /// the prober is off, or before it has issued a round.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub probes: Vec<PathProbe>,
}

/// A — the disco prober's measurement of one path to this peer (C2).
///
/// Measurement ONLY: nothing in the selector reads this. It is here so an
/// operator (and `roomler why`) can see what the path actually does next to
/// the decision the selector made about it — the two disagreeing is the
/// interesting case, and until now the measurement was visible only in a
/// 5-minute digest log line.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PathProbe {
    /// The remote endpoint probed (`host:port`).
    pub dst: String,
    /// Windowed loss 0.0..=1.0. `None` until enough rounds to judge — an
    /// UNMEASURED path must never read as a bad one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss: Option<f64>,
    /// Smoothed round-trip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
    /// 95th percentile of the raw window — the EWMA above smooths spikes away
    /// by design, and spikes are what make a path feel bad.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_p95_ms: Option<f64>,
    /// Worst raw round-trip in the window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_max_ms: Option<f64>,
}

/// F — why this peer sits on the tier it sits on (`roomler why <peer>`).
///
/// Populated on every view publish, like [`PeerCarrierDebug`], rather than
/// computed on demand: an incident capture is usually a `peers --json` taken
/// at the time, and the explanation is worth far more inside that snapshot
/// than in a command someone had to know to run while the fault was live.
///
/// `None` from a daemon older than the field (`#[serde(default)]`, wire
/// compatible both ways).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PeerWhy {
    /// LAN, public, srflx, relay — already in ladder order.
    pub tiers: Vec<TierWhy>,
    /// Seconds left on the demote-follow hold-down, if open. While this is
    /// set, EVERY direct tier is ineligible regardless of its own health —
    /// the peer is relaying to us, so we follow it rather than fight it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relayed_instead_s: Option<u64>,
    /// Consecutive demote-follows inside the memory window — the rung of the
    /// escalation ladder. A climbing value is the signature of a pair whose
    /// two ends persistently disagree about the path, which is a different
    /// problem from a path that is simply bad.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub relayed_instead_strikes: u32,
    /// Seconds left on the server's forced-DERP pin, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forced_derp_s: Option<u64>,
    /// A direct-upgrade probe is in flight on this tier right now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probing: Option<String>,
}

/// One tier's row in [`PeerWhy`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TierWhy {
    /// `lan` | `public` | `srflx` | `relay`.
    pub tier: String,
    /// May this tier be attempted at all right now?
    pub eligible: bool,
    /// When not eligible, which gate refused: `peer-relays-instead` |
    /// `lan-captured` (FR-33 — this host's route to the peer's LAN prefix
    /// leaves via another adapter, a VPN split-prefix capture) | `penalty`.
    /// Resolved in the same order the selector tests them, so it cannot
    /// contradict `eligible`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_by: Option<String>,
    /// #2089 — did this tier have a dialable candidate at the last decision?
    /// The selector only considers a tier that is available AND eligible,
    /// and an untried tier carries no penalty, so `eligible` alone reads
    /// "yes" for a tier with nothing to dial. `None` before the first
    /// decision, and from a daemon that predates the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub available: Option<bool>,
    /// The tier's fixed prior.
    pub base: f64,
    /// Measured-quality term (ranking only — never eligibility).
    pub q: f64,
    /// Decaying penalty from recent failures.
    pub penalty: f64,
    /// `base + q − penalty`; meaningful only among ELIGIBLE tiers.
    pub score: f64,
    /// Consecutive failures booked against this tier.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fails: u32,
}

/// rc.276 — per-carrier forensic fields (see [`PeerInfo::debug`]). Built for
/// the winhost-a-class corp-VPN investigations: two `peers --json` snapshots
/// 30 s apart show exactly which carriers move which counters, which flows
/// were initiated by whom, and whether the WG session ever completed —
/// one-shot field captures instead of multi-session log archaeology.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PeerCarrierDebug {
    /// Carrier tier: `lan` / `public` / `srflx` / `relay`.
    pub tier: String,
    /// `true` = we initiated this flow (outbound dial / our allocation);
    /// `false` = adopted from the peer's authenticated inbound dial.
    pub initiated: bool,
    /// The WG session latch (either role) as of the last health sweep.
    pub hs_done: bool,
    /// Carrier socket's local address (relay: our relayed address).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local: Option<String>,
    /// Carrier send destination (direct: dial dst / accepted src; relay: the
    /// peer's relayed address).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst: Option<String>,
    /// IP-data packets sent / received over this carrier (handshakes and
    /// keepalives touch NEITHER — `tx>0, rx==0` past the grace = one-way).
    pub tx: u64,
    pub rx: u64,
    /// Seconds since we last heard ANY authenticated packet (keepalives
    /// included) from this peer.
    pub last_rx_age_s: u64,
    /// Relay flavor (`turn` / `derp`); `None` for direct carriers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_kind: Option<String>,
    /// P4 — inbound packets from this peer the ingress ACL refused: a forged
    /// SOURCE, a DESTINATION outside this node's advertised scope, or a
    /// cidr/port/proto the tenant's policies didn't grant. Monotonic since the
    /// carrier was installed.
    ///
    /// Under the default `overlay_rpf=warn` NOTHING is dropped, so a non-zero
    /// value is pure evidence: it is exactly what `enforce` WOULD have killed.
    /// Read this before flipping. Omitted when 0 so a healthy fleet's
    /// `peers --json` stays unchanged.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub rx_denied: u64,
    /// The `Rpf(NoRoute)` subset of [`Self::rx_denied`]: packets from a source
    /// NO installed peer owns. Worse than a plain denial even under `warn` —
    /// the packet is delivered but replies to that source are unroutable from
    /// this node, so the flow fails silently. The signature of a multi-org
    /// sender whose OS picked the wrong org's overlay address as source.
    /// Omitted when 0.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub rx_denied_noroute: u64,
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

/// Whether a forward is a static `--remote` forward or a SOCKS5 listener.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FlowKind {
    Forward,
    Socks5,
}

/// One active forward / SOCKS5 listener with cumulative throughput. Sourced
/// from the per-flow `forward::FlowStats` the data plane already records.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FlowInfo {
    pub id: String,
    pub kind: FlowKind,
    pub local_addr: String,
    /// `host:port` for a static forward; `None` for a SOCKS5 listener (its
    /// target is chosen per connection).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Peer node this forward reaches (name or id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    pub transport: String,
    pub active_flows: u32,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// A DECLARED, daemon-supervised route (P6). Unlike an ephemeral flow
/// (created over the LocalAPI, gone when the daemon restarts), a route is
/// persisted in the daemon's config (`[[tunnel_routes]]` — this struct IS
/// the config-TOML shape, one type for wire + disk) and reconciled back
/// into a live flow on every daemon start until removed or disabled.
///
/// `node` is REQUIRED in v1: daemon-side SOCKS5 needs a concrete target
/// node (mesh-mode routes are a later slice, matching the CLI's own
/// "--daemon socks5 requires --agent" bail).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RouteDescriptor {
    /// Operator-chosen slug, unique among routes. Empty on `RouteAdd` ⇒
    /// the daemon generates one (returned in [`Response::RouteAdded`]).
    #[serde(default)]
    pub id: String,
    pub kind: FlowKind,
    /// Target node (hex agent id).
    pub node: String,
    /// Local loopback listen port.
    pub local: u16,
    /// `host:port` for a static forward; `None` for a SOCKS5 route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    /// `auto` (default) | `quic` | `webrtc`. Empty ⇒ `auto`.
    #[serde(default)]
    pub transport: String,
    /// Soft-disable without deletion. Defaults true so a hand-written
    /// config entry without the key is live.
    #[serde(default = "route_enabled_default")]
    pub enabled: bool,
    /// Multi-org P1 — which enrollment this route rides. `None` (the wire
    /// default every pre-multi-org client sends) and `"primary"` both mean
    /// the config's scalar primary identity. A secondary org's label is
    /// accepted in the schema today but the P1 reconciler surfaces it as
    /// `Failed` (secondary-org route supervision lands with P2/P3 of the
    /// multi-org program).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

fn route_enabled_default() -> bool {
    true
}

/// Runtime state of a declared route, computed by the daemon's reconciler.
///
/// #1685 — `Active` means the route's local listener is BOUND and serving.
/// Before it, `Active` meant only "a hub flow exists for this route": a route
/// to an offline node read `active` while nothing listened on its port and
/// every connect was refused, and the reader had no way to tell it from a
/// healthy one. The two retrying shapes are told apart by `flow_id`: absent,
/// the reconciler could not CREATE the flow (its port is taken); present, the
/// flow exists and its tunnel SESSION toward the node is what is not up (node
/// offline, control WS down, transport setup failing).
///
/// Wire compatibility: the tag set is unchanged and every new field is
/// additive (`default`, skipped when empty). A reader parses this enum with
/// serde, and a tag it does not know fails the WHOLE `RouteList` reply — a
/// companion older than a new tag would lose its Routes page for as long as
/// any route sat in that state. So a pre-#1685 reader sees `pending` /
/// `backoff … <error>` for a route that is dialing or retrying — statements it
/// already renders truthfully, never a false `active` — and a reader from this
/// version on maps a tag it does not know to [`RouteState::Unknown`].
///
/// `Failed` is TERMINAL: a permanent open-failure (enrollment revoked,
/// cross-tenant, ACL policy deny) stops supervision for the route until an
/// operator re-enables it — without this, a revoked route would hammer the
/// server with a TunnelOpen every backoff tick, across reboots, forever.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RouteState {
    /// `enabled = false` — not supervised.
    Disabled,
    /// Declared and enabled, not serving yet. `flow_id` (#1685) is present
    /// once the daemon has a flow for the route whose first session attempt
    /// is in flight — "connecting" — and absent while the reconciler has not
    /// created the flow. Serialises as the bare `{"state":"pending"}` when
    /// absent, byte-identical to the pre-#1685 wire.
    Pending {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        flow_id: Option<String>,
    },
    /// The route's local listener is bound and serving through `flow_id`.
    Active { flow_id: String },
    /// Not serving; retrying with backoff. Without `flow_id`: flow creation
    /// failed (the local port is taken) and the reconciler retries in
    /// `next_retry_secs`. With `flow_id` (#1685): the flow exists and its
    /// tunnel session is what failed — `last_error` is the last attempt's
    /// error, `attempts` the consecutive failures since the route last
    /// served, `next_retry_secs` the wait before the next attempt (`0` while
    /// one is in flight).
    Backoff {
        next_retry_secs: u64,
        last_error: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        flow_id: Option<String>,
        #[serde(default, skip_serializing_if = "is_zero_u32")]
        attempts: u32,
    },
    /// Permanent failure — requires operator re-enable (or remove).
    Failed { reason: String },
    /// A `state` word this reader does not know — a newer daemon (#1685).
    /// Rendered as its word, never an error; a daemon never produces it.
    #[serde(other)]
    Unknown,
}

impl RouteState {
    /// The hub flow behind this state, if one exists (#1685): always for
    /// `Active`; for `Pending` / `Backoff` when the flow exists and is what
    /// is dialing or retrying.
    pub fn flow_id(&self) -> Option<&str> {
        match self {
            RouteState::Active { flow_id } => Some(flow_id),
            RouteState::Pending { flow_id } | RouteState::Backoff { flow_id, .. } => {
                flow_id.as_deref()
            }
            RouteState::Disabled | RouteState::Failed { .. } | RouteState::Unknown => None,
        }
    }
}

/// A declared route joined with its live runtime state — the
/// [`Request::RouteList`] row.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RouteInfo {
    pub route: RouteDescriptor,
    pub state: RouteState,
}

/// One request awaiting an operator consent decision (rc.46).
/// Surfaced by [`Request::ConsentPending`] so the desktop app renders its
/// Approve/Deny modal over the LocalAPI instead of reading the daemon's private
/// sentinel dir — which lives in the daemon's profile and is unreachable to the
/// interactive-user app when the daemon runs as SYSTEM (P2b bug fix).
///
/// FR-27 — no longer remote-control only. Fleet-RPC `exec` and Roomler SSH have
/// always prompted through the same broker, but never wrote a marker, so their
/// prompts were invisible to every UI and answerable only by someone who greped
/// the daemon log for a request id inside 30 s. [`Self::kind`] is what lets one
/// modal serve all three without lying about which is which — "approve this"
/// means something very different for a screen share and for a root shell.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ConsentRequest {
    pub session_id: String,
    #[serde(default)]
    pub controller_name: String,
    /// Pipe-separated permission names (the agent's `Permissions` serde form).
    #[serde(default)]
    pub permissions: String,
    #[serde(default)]
    pub timeout_secs: u64,
    /// FR-27 — which subsystem is asking: `rc` (screen control), `exec` (a
    /// command) or `ssh` (a shell). `#[serde(default)]` yields `""` from a
    /// pre-FR-27 daemon, which a reader should treat as `rc` — the only kind
    /// that existed then.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kind: String,
    /// FR-27 — the one line that makes the decision answerable: the redacted
    /// command for `exec`, the principal + account mode for `ssh`, empty for
    /// `rc` (where `controller_name` and `permissions` already say everything).
    ///
    /// ⚠️ Redacted BY THE DAEMON before it is written. A consent prompt is
    /// rendered by a GUI process and can be screenshotted, and `exec` payloads
    /// routinely carry tokens — `exec::redactor()` runs first, as it does for
    /// exec output leaving the host.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    /// FR-27 — unix-millis deadline, so a panel can show a real countdown
    /// instead of restarting one every time it re-reads the list. `0` from a
    /// pre-FR-27 daemon means "unknown"; fall back to `timeout_secs`.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub expires_at_ms: u64,
    /// FR-27 — who is ALREADY showing this prompt: `native` (the daemon's own
    /// overlay is up) or `companion` / absent (nobody is; the desktop app
    /// should).
    ///
    /// ⚠️ Load-bearing for the desktop app, not informational. The daemon
    /// writes a marker even when its native panel is up, because this list is
    /// also what `roomlerd consent --list` reads — so without this field the
    /// companion would pop a SECOND panel asking the same question, and two
    /// Approve buttons for one decision is how someone approves the wrong
    /// thing. A UI must LIST a `native` entry and not render a prompt for it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub surface: String,
    // NOTE: `org` stays LAST; the struct is built field-by-field at three call
    // sites and keeping the multi-org line at the end matches how it reads.
    /// Multi-org — the organization the request comes from, so the modal can
    /// say WHO is asking. On a device enrolled in two orgs, "Alice wants to
    /// control this machine" is not enough to decide on: Alice may be a
    /// colleague in one org and an outside contractor in the other.
    ///
    /// Empty for a single-org device, and for a daemon older than the field
    /// (`#[serde(default)]` — the desktop app simply shows no org line).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub org: String,
}

/// FR-27 — one remote-control session currently LIVE on this device.
///
/// The device side of "who is watching my screen". Distinct from
/// [`ConsentRequest`], which is about sessions not yet allowed to start: this
/// is what the "Being viewed by …" banner renders, and what its Disconnect
/// button acts on.
///
/// There was no LocalAPI verb for this at all before, which is why the banner
/// existed only as the Windows-native overlay inside the daemon — no thin
/// client could see a session, let alone end one.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct RcSessionInfo {
    /// Hex `ObjectId` — the handle [`Request::RcDisconnect`] takes.
    pub session_id: String,
    /// Display name of whoever is controlling.
    #[serde(default)]
    pub controller_name: String,
    /// Pipe-separated permission names — what they were actually granted, so
    /// a view-only watcher is distinguishable from someone typing.
    #[serde(default)]
    pub permissions: String,
    /// Asking organization on a multi-org device; empty otherwise.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub org: String,
    /// Unix millis when the session started, for an "N min" age in the banner.
    /// `0` = unknown.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub started_at_ms: u64,
    /// FR-85 P3 — this controller is RECORDING the screen. The banner must
    /// say so, with a way to stop it, before the first frame is written.
    /// Additive: an older companion ignores it (and an older daemon never
    /// records remotely).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub recording: bool,
    /// FR-85 P3b-3 — the SESSION is gone, and its recording goes on for up to
    /// a minute while its controller reconnects. The banner keeps saying so,
    /// with its Stop: a recording is never unseen. There is no session left
    /// to disconnect. Additive, like `recording`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reconnecting: bool,
    /// FR-93 P6h — the desktop's own dialog (the portal's *Remote Control* /
    /// *Share screen*) is asking the person at the screen right now: nothing
    /// is shared yet, and the answer is theirs to give in that dialog. The
    /// banner waits rather than say "Being viewed" over the very window that
    /// asks. Additive: an older companion ignores it, an older daemon never
    /// sets it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub asking: bool,
}

/// A string that must never reach a log, wrapped so the compiler carries that
/// rule instead of a comment. [`Request`] derives `Debug`, and the day someone
/// adds `tracing::debug!(?req)` to [`serve_connection`] — an entirely reasonable
/// thing to want while debugging a client — the plaintext external-access
/// password would land in the daemon's rolling log, which `roomler logs` uploads.
/// Serialisation is transparent (the wire carries the bare string); only `Debug`
/// is redacted, which is exactly the direction the leak travels.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(transparent)]
pub struct Secret(pub String);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Not even the length: it narrows a brute force, and no debugging
        // session needs it.
        f.write_str("Secret(***)")
    }
}

impl Secret {
    /// Borrow the plaintext. Every call site is a place to ask "can this end up
    /// in a log line or an error message?".
    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// FR-52 — what the DEVICE believes about the two gates it owns itself
/// ([`Request::ExternalPasswordStatus`]).
///
/// The three states an operator needs told apart, which one boolean would
/// collapse into "no":
/// - `supported: false` — this BUILD has no credential stack, so no password
///   can be held at all. Fix: a build/update. (Same reasoning as
///   `RpcCap::ExternalAccess` being unconditional: "too old" and "opted out"
///   have different fixes and must not render alike.)
/// - `password_set: false` — the build can hold one, none is set. Fix: set it.
/// - `enabled: false` — a password may be set, but gate 3 is shut, so nothing
///   external is admitted. Fix: `roomler config set external_access_enabled true`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct ExternalPasswordState {
    /// Was this daemon compiled with the external-access credential stack?
    pub supported: bool,
    /// Gate 4 — is a password record stored? Never the record itself: it is
    /// not readable back by design, and the answer an operator needs is a
    /// boolean.
    pub password_set: bool,
    /// Gate 3 — `external_access_enabled` in this device's own config.
    pub enabled: bool,
    /// The device's local consent mode for external sessions, if it overrides
    /// the default. `None` = the daemon's built-in default applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_mode: Option<String>,
    /// The device's local permission ceiling for external sessions, if set.
    /// `None` = whatever the org approved, clamped by the built-in default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_permissions: Option<String>,
}

/// A LocalAPI request. P1 exposed read-only verbs; P2b adds the (mutating)
/// consent verbs. Adjacently tagged on `t`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "t", content = "d", rename_all = "snake_case")]
pub enum Request {
    /// Local node status.
    Status,
    /// Peers with their current connection type.
    Peers,
    /// Active forwards / SOCKS5 listeners + throughput.
    Flows,
    /// Remote-control sessions awaiting an operator consent decision.
    ConsentPending,
    /// Approve (`allow=true`) or deny a pending consent, by session id.
    ConsentDecide { session_id: String, allow: bool },
    /// FR-27 — remote-control sessions currently LIVE on this device.
    RcSessions,
    /// FR-27 — end a live remote-control session from the device side. This is
    /// the Disconnect the "Being viewed by …" banner offers; mutating, and the
    /// pipe/socket ACL is the trust boundary, like [`Self::ConsentDecide`].
    RcDisconnect { session_id: String },
    /// ICMP-ping an overlay peer (by name or IP) over the userspace netstack —
    /// the OS-free reachability probe. `timeout_ms` 0 ⇒ the daemon's default.
    Ping {
        target: String,
        #[serde(default)]
        timeout_ms: u64,
        /// Resolve a *name* target to the peer's derived overlay IPv6 instead
        /// of its v4 (`roomler ping -6`). Ignored for literal-IP targets.
        #[serde(default)]
        prefer_v6: bool,
    },
    /// Create a daemon-driven static forward: the daemon opens a tunnel to
    /// `node` (a hex agent id) over its own agent WS and listens on `local`,
    /// dialing `remote` (`host:port`) from the target. Mutating — like
    /// [`Request::ConsentDecide`], the pipe/socket ACL is the trust boundary
    /// (P3b-2). Returns [`Response::FlowCreated`] with the assigned flow id.
    CreateForward {
        node: String,
        local: u16,
        remote: String,
        /// `auto` (default) | `quic` | `webrtc`. Empty ⇒ `auto`.
        #[serde(default)]
        transport: String,
        /// FR-86 P2 test lever — a word (`auto` | `quic` | `webrtc`) forcing the
        /// daemon's FIRST session's transport, so an `auto` flow can be started
        /// on a below-best carrier (`webrtc`) the make-before-break re-upgrade
        /// probe then upgrades, without restarting daemons. Empty ⇒ no override
        /// (the ladder picks). Later sessions and the probe behave as `auto`.
        /// Additive + `skip` when empty, so the wire is unchanged for every
        /// client that doesn't set it.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        start_transport: String,
    },
    /// Create a daemon-driven SOCKS5 listener toward `node` (userspace mode —
    /// per-connection CONNECT target, no OS routing). Returns
    /// [`Response::FlowCreated`].
    CreateSocks5 {
        node: String,
        local: u16,
        #[serde(default)]
        transport: String,
    },
    /// Stop + deregister a daemon flow by its id. Returns
    /// [`Response::FlowKilled`] (`ok=false` if the id was unknown).
    KillFlow { id: String },
    /// Declared routes + their live runtime state (P6). Read-only.
    RouteList,
    /// Declare a new supervised route: the daemon persists it to config
    /// (surviving restarts) and reconciles it into a live flow. Mutating —
    /// the pipe/socket ACL is the trust boundary, same as
    /// [`Request::CreateForward`]. Returns [`Response::RouteAdded`] with
    /// the effective descriptor (id generated if empty).
    RouteAdd { route: RouteDescriptor },
    /// Remove a declared route by id: kills its live flow (if any) and
    /// deletes it from config. Returns [`Response::RouteRemoved`]
    /// (`ok=false` if the id was unknown).
    RouteRemove { id: String },
    /// Enable/disable a declared route by id without deleting it.
    /// Disabling kills the live flow; enabling clears a terminal
    /// `Failed` state and re-supervises. Returns
    /// [`Response::RouteUpdated`].
    RouteSetEnabled { id: String, enabled: bool },
    /// FR-84 D1 — replace a declared route IN ONE STEP, keyed by `route.id`.
    /// The daemon validates the new descriptor exactly as [`Self::RouteAdd`]
    /// does (bad node, missing/forbidden `remote`, a local port another
    /// enabled route already holds — the route being replaced excepted);
    /// an invalid replacement is refused and the OLD route keeps running and
    /// stays persisted. A valid one is written to config in ONE save, its
    /// old flow is stopped and the new descriptor is reconciled. The
    /// alternative — `RouteRemove` then `RouteAdd` — loses the route
    /// entirely when the add fails. Unknown id ⇒ [`Response::Error`].
    /// Mutating — the pipe/socket ACL is the trust boundary. Returns
    /// [`Response::RouteReplaced`] with the effective descriptor.
    RouteUpdate { route: RouteDescriptor },
    /// Rename this device: the daemon persists the new `machine_name` to ITS
    /// OWN config file — profile-correct by construction (under a SYSTEM/SCM
    /// install the machine-global config is writable by the daemon but NOT by
    /// an unelevated desktop app / CLI doing a direct file write). Mutating —
    /// the pipe/socket ACL is the trust boundary, like [`Request::RouteAdd`].
    /// The new name is announced on the next server reconnect. Returns
    /// [`Response::DeviceNameSet`] with the effective (trimmed) name.
    SetDeviceName { name: String },
    /// S1b — archive the STALE config copy on a host carrying both a
    /// per-user and a machine-global `config.toml` (the desktop's
    /// "Two configurations found" banner). The DAEMON does the work —
    /// it knows which copy it loaded and has the rights (an unelevated
    /// desktop app can't touch `%PROGRAMDATA%`). Guarded: both copies
    /// must parse, carry the SAME agent identity, and the stale copy is
    /// renamed aside (`config.toml.stale-<ts>`), never deleted. Mutating —
    /// the pipe/socket ACL is the trust boundary, like
    /// [`Request::SetDeviceName`]. Returns [`Response::ConfigCleaned`].
    ConfigCleanupStale,
    /// S2 — list every EDITABLE config key with its current value +
    /// editor metadata (the daemon reads its own config file, so pending
    /// not-yet-restarted edits show). Secrets are excluded by
    /// construction. Returns [`Response::ConfigEntries`].
    ConfigGet,
    /// S2 — set (or clear, `value: None`) one editable config key. The
    /// daemon validates per key, persists through its own config path +
    /// write lock (profile-correct under SYSTEM), and echoes the updated
    /// entry. Mutating — the pipe/socket ACL is the trust boundary.
    /// Returns [`Response::ConfigUpdated`] or [`Response::Error`].
    ConfigSet {
        key: String,
        #[serde(default)]
        value: Option<String>,
    },
    /// FR-52 gate 4 — set the device-held external-access password.
    ///
    /// The plaintext crosses this pipe and **nothing else**: the daemon runs the
    /// whole OPAQUE registration itself (it plays both halves — no network is
    /// involved) and persists only the resulting record, so the password exists
    /// in no file, no log and, above all, on no server. That is the one
    /// constraint the whole feature is shaped around — the alternative a reviewer
    /// finds obvious, POST the password and let the server compare a hash on the
    /// `agents` row, turns a database dump into a fleet-wide credential dump.
    ///
    /// Deliberately **not** a `config set` key: `config get` lists every editable
    /// key with its value, and `config set` would let anyone who can write the
    /// config file choose the password without proving they know the old one.
    ///
    /// Mutating; the pipe/socket ACL is the trust boundary — the same authority
    /// that already flips `exec_enabled`, which is a strictly stronger grant.
    /// Returns [`Response::ExternalPassword`] or [`Response::Error`].
    ExternalPasswordSet { password: Secret },
    /// FR-52 gate 4 — forget the device-held password, closing gate 4.
    ///
    /// Clears **both** halves of the record together: a half-cleared credential
    /// is a parse failure at verify time, which is a *refusal that looks like a
    /// bug* instead of the clean "no password set" the operator asked for.
    /// Deliberately works on a build without the credential stack — a device
    /// that held a password and was then downgraded must still be able to drop
    /// it. Returns [`Response::ExternalPassword`].
    ExternalPasswordClear,
    /// FR-52 — the device's own view of gates 3 and 4
    /// ([`Response::ExternalPassword`]). Read-only, and never carries the record.
    ExternalPasswordStatus,
    /// S2 — read the tail of one of the daemon's log files. `source` is
    /// `daemon` (this process's active rolling log), `service` (the
    /// machine-global SCM host log), or `panic` (the newest panic dump).
    /// `max_bytes` is clamped daemon-side (≤64 KiB) — bounded response,
    /// poll-based follow (no streaming). Returns [`Response::LogTail`].
    TailLog {
        source: String,
        #[serde(default)]
        max_bytes: Option<u64>,
    },
    /// Fleet RPC — run a command on ANOTHER device in this org and return its
    /// output (`roomler exec <device> -- <cmd>`).
    ///
    /// The daemon relays this over its own already-authenticated agent WS, so
    /// the CLI needs no user credentials of its own. The server resolves this
    /// device's owner as the acting principal and applies all four gates —
    /// the pipe/socket ACL only establishes that the caller is on THIS box,
    /// which is not by itself authority to run commands on another one.
    ///
    /// Mutating in the strongest sense available, so unlike the other verbs
    /// this one's trust boundary is deliberately NOT just the pipe ACL: the
    /// device must also carry `ExecPolicy::can_originate` server-side.
    /// Returns [`Response::ExecResult`].
    ExecRemote {
        /// Target device: a name (e.g. `winhost-a`) or a hex agent id.
        node: String,
        /// `pwsh` | `powershell` | `cmd` | `bash` | `sh`; empty ⇒ host default.
        #[serde(default)]
        shell: String,
        command: String,
        /// 0 ⇒ the server's default; clamped server- and agent-side.
        #[serde(default)]
        timeout_ms: u64,
    },
    /// Roomler SSH (P6b) — ask the server for a single-use session grant on
    /// ANOTHER device, so `roomler ssh <device>` can dial it.
    ///
    /// The daemon relays this over its already-authenticated agent WS; the CLI
    /// carries no user credentials of its own, exactly as with
    /// [`Request::ExecRemote`], and the same four gates apply server-side.
    ///
    /// **The caller supplies `public_key` and keeps the private half.** The
    /// daemon never sees it and the grant is bound to that key, so a grant
    /// intercepted anywhere on this path is useless without the private half
    /// that never left the requesting process.
    ///
    /// Returns [`Response::SshSession`].
    SshSession {
        /// Target device: a name (e.g. `winhost-a`) or a hex agent id.
        node: String,
        /// OpenSSH public key of the caller's EPHEMERAL, single-session
        /// keypair (`ssh-ed25519 AAAA… comment`).
        public_key: String,
        /// 0 ⇒ the server's ceiling; clamped server-side.
        #[serde(default)]
        session_secs: u64,
    },
    /// FR-85 — start a LOCAL screen recording (the daemon spawns
    /// `roomlerd record`). Mutating, and the endpoint ACL is NOT the whole
    /// boundary: the caller must be the console user
    /// ([`ClientPeer::is_console_user`]) — an RDP guest must not record the
    /// console user's desktop. Returns [`Response::Recording`].
    RecordStart {
        #[serde(default)]
        opts: RecordStartOpts,
    },
    /// FR-85 — stop the active recording; answers once the file is final.
    /// Console user only. Returns [`Response::Recording`].
    RecordStop,
    /// FR-85 — the recorder's state. Read-only. Returns [`Response::Recording`].
    RecordStatus,
    /// FR-85 — the recordings folder and what is in it. Read-only. Returns
    /// [`Response::Recordings`].
    RecordingsList,
    /// FR-85 — delete one recording (and its sidecar) from the folder, by file
    /// name. Console user only. Returns [`Response::RecordingDeleted`].
    RecordingDelete { name: String },
    /// FR-92 — keep busy on this device (pointer patterns that keep it active
    /// until switched off): what it is doing and why. Read-only. Returns
    /// [`Response::KeepBusy`].
    KeepBusyStatus,
    /// FR-92 — stop keep busy. Open to every peer the endpoint admits, the
    /// person socket included: stopping is the safe direction, and it is the
    /// person's own pointer. Returns [`Response::KeepBusy`].
    KeepBusyOff,
    /// FR-92 P10 — the person at the console turns keep busy ON (the tray's
    /// "Start keep busy", `roomler keep-busy on`). Unlike status and off,
    /// this is gated on the peer ([`ClientPeer::may_start_keep_busy`]): root
    /// never, SYSTEM never (P10b), session 0 never, another session never.
    /// The server itself has no "on" (FR-92 §7). ⚠️ The gate decides who is
    /// NAMED; it is not a wall against `roomler exec`, which on an attended
    /// Windows install runs as the person and passes it (FR-92 §3g). Returns
    /// [`Response::KeepBusy`].
    KeepBusyOn {
        #[serde(default)]
        opts: KeepBusyStartOpts,
    },
    /// FR-84 D5b — one page of the devices THIS device may see (itself
    /// included): `GET /api/agent/self/devices` on the org's server, asked by
    /// the daemon with that org's agent token. The server searches, sorts and
    /// pages (`q` / `sort` / `dir` / `page` / `per_page`, its own grid
    /// contract). `org` is an enrollment label; empty or `primary` = the
    /// primary enrollment.
    ///
    /// Read-only, and the token never crosses the pipe: the answer is the
    /// server's list, nothing of the daemon's credentials. Returns
    /// [`Response::Devices`] or a [`Response::Upstream`] naming why not. A
    /// daemon older than the verb answers "unknown variant", which a client
    /// renders as "this service predates the device list".
    Devices {
        #[serde(default, skip_serializing_if = "String::is_empty")]
        org: String,
        #[serde(default)]
        page: u64,
        #[serde(default)]
        per_page: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sort: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dir: Option<String>,
    },
    /// FR-84 D5b — the org mesh graph restricted to the same set
    /// (`GET /api/agent/self/mesh`). Returns [`Response::Mesh`] (whose
    /// `enabled: false` means the server has statistics off — data, not an
    /// error) or a [`Response::Upstream`].
    Mesh {
        #[serde(default, skip_serializing_if = "String::is_empty")]
        org: String,
    },
    /// FR-84 D3 — restart this daemon through the service manager that
    /// supervises it ("Apply now" in the companion, `roomler restart`).
    ///
    /// Mutating; the endpoint ACL is the trust boundary, as for
    /// [`Self::ConfigSet`], and the daemon refuses on its own terms: no
    /// supervisor it can prove (an orphan `roomlerd run` would go offline, not
    /// restart), `local_restart_enabled = false`, a recording in progress, or
    /// a previous restart less than 30 s ago. Never sent by a server — remote
    /// configuration does not restart daemons (`docs/remote-config.md` §7b).
    ///
    /// Returns [`Response::DaemonRestarting`] — after which the daemon exits,
    /// once that answer is written — or an `Error` carrying the refusal. A
    /// daemon older than the verb answers `Error("bad request: unknown
    /// variant ...")` ([`RestartAnswer::Unsupported`]).
    RestartDaemon {
        /// Why — logged by the daemon and kept in its restart record.
        #[serde(default)]
        reason: String,
    },
    /// FR-84 D4 — what this device can encode: the codec × backend × chroma
    /// cells the capability probe opened, the denylist, the resolved encoder
    /// preference. READ-ONLY and cheap by contract: it reports the probe's
    /// cached result and **never starts a probe** — the probe runs in child
    /// processes at the first server hello, and a control-surface poll must
    /// not be what launches vendor driver code. Before that first hello the
    /// answer is `not_probed`; a build without encoders answers
    /// `unsupported`. Returns [`Response::EncoderCaps`].
    EncoderCaps,
    /// FR-90 P1h-2 (AC7 on macOS) — the root update helper asks this daemon
    /// to hold for its running agent turns before `installer(8)` restarts it
    /// and, with it, every session's harness: what the in-process updater
    /// does on Linux (P1d-1). Answered [`Response::HiveUpdateHeld`] once no
    /// turn runs, or once the device's `hive_update_wait_secs` is spent; from
    /// then on new prompts and starts are refused until THIS CONNECTION
    /// closes. A successful install has restarted the daemon by then; a
    /// failed one takes prompts and starts again. Root only. A daemon older
    /// than the verb answers `Error("bad request: …")`, and the helper
    /// installs without a hold, as before.
    HiveUpdateHold,
    /// FR-90 P3-9-2b — `roomler connect`: a local endpoint that signs in to a
    /// secret's upstream as the secret's user, the value held by the daemon.
    /// Its leases are asked for the device's OWNER (decision 23) and renewed
    /// while it is held (decision 25), and it serves the account that asked,
    /// as the listener read it from the OS ([`ClientPeer::asker`]). Answered
    /// [`Response::Connected`]. It closes when THIS CONNECTION does. Only
    /// root or SYSTEM, an elevated administrator, or the daemon's own account
    /// may ask ([`peer_may_connect`]); never on the person socket. A daemon
    /// older than the verb answers `Error("bad request: …")`.
    Connect { args: ConnectArgs },
    /// FR-90 P3-9-2b — where endpoint `id`, opened by a [`Request::Connect`]
    /// on this same connection, stands: [`Response::ConnectState`]. Any other
    /// id is refused.
    ConnectStatus { id: u64 },
}

/// FR-90 P3-9-2b — what `roomler connect` asks for: the arguments a
/// session's `vault_connect` takes, by the same names, and checked by the
/// daemon as it checks a session's (`docs/vault.md` §19).
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectArgs {
    /// A structured secret, by its path or this organization's RRN, with no
    /// `#field`.
    pub handle: String,
    /// `postgres`, `mongodb`, `http`, `kubernetes` or `ssh`.
    pub engine: String,
    /// The upstream, exactly as the secret's `audiences` names it.
    pub upstream: String,
    /// `http` and `kubernetes`: `basic`, `bearer` or `client-cert`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    /// A database's, named in the connection string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    /// A secret whose value is the upstream's CA (PEM).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<String>,
    /// MongoDB's: the database the secret's user is defined in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_source: Option<String>,
    /// How long each lease is asked for, in seconds (30 to 900, default
    /// 300); renewed before it ends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_s: Option<u32>,
}

/// FR-90 P3-9-2b — where a person's endpoint stands
/// ([`Request::ConnectStatus`]).
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct EndpointState {
    /// How long its leases have left, in seconds, as the daemon holds them.
    pub left_s: u64,
    /// How many times its leases were renewed.
    pub renewals: u32,
    /// The vault refused a renewal, saying this: the endpoint serves to its
    /// leases' end, then closes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<String>,
    /// Why it closed, once it has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed: Option<String>,
}

/// FR-84 D4 — what this device can encode, as [`Request::EncoderCaps`]
/// reports it. Plain strings on the wire (the vocabulary lives in
/// `roomler_ai_remote_control::models`; this leaf crate carries none of it),
/// every field additive.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct EncoderCapsSummary {
    /// `ready` (the probe ran; `cells` is the matrix), `not_probed` (the
    /// daemon has not connected to a server yet — poll again) or
    /// `unsupported` (this build carries no video encoder at all).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub state: String,
    /// One row per encoder the probe opened, with the chroma formats it
    /// produced. Empty until `ready`, and on a host with no encoder.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cells: Vec<EncoderCell>,
    /// The legacy descriptive labels (`ffmpeg-hevc_nvenc`, `openh264-sw`, …)
    /// exactly as the hello advertises them — what `roomlerd caps` prints.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hw_encoders: Vec<String>,
    /// Codecs this device can produce (`h264`, `h265`, `av1`, `vp9`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub codecs: Vec<String>,
    /// How long the probe took, or the cached probe's duration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_ms: Option<u32>,
    /// The matrix came from the on-disk probe cache, not a fresh probe.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub probe_cached: bool,
    /// The effective `encoder_cells_deny` list — `name:chroma` entries in
    /// FFmpeg's spelling (`hevc_qsv:yuv444`) — env, config or the built-in
    /// default, whichever is in force. A denied cell is never opened by the
    /// probe or a session, so it appears here and not in `cells`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied: Vec<String>,
    /// The encoder preference the daemon RESOLVED (CLI > env > config >
    /// `auto`), as `auto` | `hardware` | `software`. `None` when the daemon
    /// has not resolved one (a `caps`-only process).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoder_preference: Option<String>,
}

/// FR-84 D4 — one encoder the probe opened: a codec × backend pair and the
/// chroma formats it produced (`yuv420` first).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct EncoderCell {
    /// `h264` · `hevc` · `av1` · `vp9`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub codec: String,
    /// `nvenc` · `qsv` · `amf` · `videotoolbox` · `vaapi` · `d3d12` ·
    /// `vulkan` · `mf` · `openh264` · `libvpx`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub backend: String,
    /// `yuv420` and/or `yuv444`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chroma: Vec<String>,
    /// Verified hardware encode (the session will not fall back to software
    /// silently). `false` = a software cell, or a backend whose hardware
    /// path could not be proven.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hardware: bool,
}

/// One editable config entry (S2 config surface). Values travel as
/// strings — bools as `"true"`/`"false"`, lists comma-separated,
/// structured keys as JSON; `kind` tells the client which editor to
/// render. Secrets are never in this surface.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ConfigEntry {
    pub key: String,
    /// Current value; `None` = unset (built-in default applies).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Editor hint: `bool` | `tribool` (unset/on/off) | `string` |
    /// `enum:<a|b|c>` | `list` (comma-separated) | `json`.
    pub kind: String,
    /// The change only takes effect after a daemon restart. `false` = the
    /// daemon puts the new value into force at once (FR-84 D2: the surface
    /// says so per key instead of a client keeping its own list).
    pub restart_required: bool,
    /// One-line operator help.
    pub description: String,
    /// FR-84 D2 — the Settings group this key belongs to, as a stable wire
    /// id (`access` | `network` | `network_carriers` | `network_routing` |
    /// `tunnels` | `ssh` | `remote_desktop` | `capture_input` |
    /// `video_encoding` | `video_rate` | `files` | `device`). Empty from a
    /// daemon older than D2 — the client's cue to render the flat list.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub group: String,
    /// Human label for `group` (e.g. `Private network`), so a client never
    /// needs its own id → label table.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub group_label: String,
    /// `essential` | `standard` | `advanced`. Essentials are the handful a
    /// person is expected to touch; the rest start collapsed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tier: String,
    /// The built-in default, rendered exactly as `value` would be for a
    /// config that never set this key. `None` = the key is unset by
    /// default (the `tribool` / optional-number keys), which is also what
    /// an older daemon sends — so "modified" is `value != default` only
    /// once `group` is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
}

/// A LocalAPI response. Adjacently tagged so a payload may be a struct
/// (`Status`) or a sequence (`Peers` / `Flows`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "t", content = "d", rename_all = "snake_case")]
pub enum Response {
    /// Boxed: `NodeStatus` is ~408 bytes against a 137-byte second-largest,
    /// so EVERY `Response` (including the frequent `Peers` / `Pong`) paid for a
    /// variant only `status` uses. Serde is transparent through `Box`, so the
    /// wire format is unchanged.
    Status(Box<NodeStatus>),
    Peers(Vec<PeerInfo>),
    Flows(Vec<FlowInfo>),
    /// Sessions awaiting a consent decision.
    ConsentPending(Vec<ConsentRequest>),
    /// Result of a [`Request::ConsentDecide`] — `ok` = the decision was recorded.
    ConsentDecided {
        ok: bool,
    },
    /// FR-27 — live remote-control sessions.
    RcSessions(Vec<RcSessionInfo>),
    /// FR-27 — result of [`Request::RcDisconnect`]; `ok` = a session with that
    /// id was found and asked to stop.
    RcDisconnected {
        ok: bool,
    },
    /// Round-trip result of [`Request::Ping`] — the resolved overlay IP + RTT.
    Pong {
        target: String,
        overlay_ip: String,
        /// Round-trip time in microseconds. Integer keeps the wire type `Eq`;
        /// the client renders it as milliseconds.
        rtt_micros: u64,
    },
    /// A forward / SOCKS5 listener was created — carries its assigned flow id
    /// (usable with [`Request::KillFlow`] + shown by [`Request::Flows`]).
    FlowCreated {
        id: String,
    },
    /// Result of [`Request::KillFlow`] — `ok=false` if the id wasn't found.
    FlowKilled {
        ok: bool,
    },
    /// Declared routes + live state ([`Request::RouteList`]).
    Routes(Vec<RouteInfo>),
    /// A route was declared + persisted — carries the effective descriptor
    /// (id filled in if the request left it empty).
    RouteAdded {
        route: RouteDescriptor,
    },
    /// Result of [`Request::RouteRemove`] — `ok=false` if the id was unknown.
    RouteRemoved {
        ok: bool,
    },
    /// Result of [`Request::RouteSetEnabled`] — `ok=false` if the id was
    /// unknown.
    RouteUpdated {
        ok: bool,
    },
    /// FR-84 D1 — a route was replaced + persisted ([`Request::RouteUpdate`])
    /// — carries the effective descriptor. A daemon that predates the verb
    /// answers the request with a bad-request [`Response::Error`] instead,
    /// which a client should render as "this service predates route
    /// editing", never as a blank page.
    RouteReplaced {
        route: RouteDescriptor,
    },
    /// The device was renamed + persisted ([`Request::SetDeviceName`]) —
    /// carries the effective (trimmed) name.
    DeviceNameSet {
        name: String,
    },
    /// Result of [`Request::ConfigCleanupStale`] — `ok=true` means the
    /// stale copy was archived; `detail` explains either outcome
    /// (archived-to path, or why nothing was touched).
    ConfigCleaned {
        ok: bool,
        detail: String,
    },
    /// The editable config surface ([`Request::ConfigGet`]).
    ConfigEntries(Vec<ConfigEntry>),
    /// One key was set/cleared + persisted ([`Request::ConfigSet`]) —
    /// echoes the updated entry (normalized value + restart flag).
    ConfigUpdated {
        entry: ConfigEntry,
    },
    /// FR-52 — the device's gate-3 / gate-4 state after a set/clear, or on a
    /// bare status read. One shape for all three verbs so a client renders the
    /// outcome from the same struct it renders the status from.
    ExternalPassword(ExternalPasswordState),
    /// The tail of a daemon log file ([`Request::TailLog`]). `size` is
    /// the file's TOTAL size — a client polls it to detect growth and
    /// re-request; `content` starts on a line boundary when the tail cut
    /// mid-line (lossy UTF-8).
    LogTail {
        path: String,
        size: u64,
        content: String,
    },
    /// Result of [`Request::ExecRemote`]. `exit_code: None` + `error: Some`
    /// covers every way the command didn't run (any of the four gates, an
    /// offline device, a timeout) — a caller must be able to tell that from
    /// "ran and exited 0".
    ExecResult {
        /// Server-minted; addresses a later cancel.
        request_id: String,
        node: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        stdout: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        stderr: String,
        #[serde(default)]
        truncated: bool,
        #[serde(default)]
        duration_ms: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Answer to [`Request::SshSession`]. Either every dial field is present
    /// or `error` is — a caller must never be left with half a connection.
    SshSession {
        request_id: String,
        node: String,
        /// The target's overlay address.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
        /// The target's SSH host public key (P6a). **Absent means the device
        /// cannot prove itself** — never "any key is fine". A client that
        /// cannot verify should refuse rather than fall back to TOFU.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host_pubkey: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grant_id: Option<String>,
        /// Unix ms the grant stops being redeemable — dial before this.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at_ms: Option<u64>,
        /// Set when the request was refused, naming which gate said no.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// FR-84 D4 — answer to [`Request::EncoderCaps`].
    EncoderCaps(EncoderCapsSummary),
    /// FR-85 — the recorder's state, answering [`Request::RecordStart`],
    /// [`Request::RecordStop`] and [`Request::RecordStatus`].
    Recording(RecordingState),
    /// FR-85 — the recordings folder and what is in it.
    Recordings(RecordingsListing),
    /// FR-92 — keep busy's state, answering [`Request::KeepBusyStatus`] and
    /// [`Request::KeepBusyOff`].
    KeepBusy(KeepBusyInfo),
    /// FR-85 — the result of [`Request::RecordingDelete`].
    RecordingDeleted {
        ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
    /// FR-84 D3 — the restart was accepted ([`Request::RestartDaemon`]). The
    /// daemon exits once this answer is written, with `exit_code`, and
    /// `restart_by` names who brings it back: `"supervisor"`, or `"caller"` —
    /// the Windows Scheduled Task, whose own restart is a minute away at best,
    /// so the caller runs `roomlerd service start` until a NEW daemon (a
    /// different [`DaemonInstance`]) answers.
    DaemonRestarting {
        /// `scm` | `task` | `systemd` | `launchd` | `macos-supervisor`.
        supervisor: String,
        /// `supervisor` | `caller`.
        restart_by: String,
        exit_code: i32,
        /// The process that is about to exit ([`NodeStatus::pid`]).
        #[serde(default)]
        pid: u32,
        /// When it started ([`NodeStatus::started_at_ms`]).
        #[serde(default)]
        started_at_ms: u64,
        /// #1684 — how long, in seconds, a stop + relaunch of this daemon may
        /// take, as its supervisor reports it (systemd: `TimeoutStopSec +
        /// RestartSec`). A caller waits at LEAST this long before giving up, so
        /// a SIGTERM-deaf process in the unit's cgroup can't make the verdict
        /// lie. Additive: absent from an older daemon (and every non-systemd
        /// supervisor), where the caller keeps its own fixed wait.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        restart_within_s: Option<u64>,
    },
    /// The verb couldn't be served (bad request, state unavailable).
    Error {
        message: String,
    },
    /// FR-84 D5b — one page of the device list ([`Request::Devices`]).
    /// Boxed for the same reason as `Status`: the envelope is the largest
    /// payload on the enum, and every other response would pay for it.
    Devices(Box<DevicesPage>),
    /// FR-84 D5b — the mesh graph ([`Request::Mesh`]).
    Mesh(Box<MeshView>),
    /// FR-90 P1h-2 — the daemon holds for the update ([`Request::HiveUpdateHold`]):
    /// install now. It waited `waited_secs` for agent turns; `cut` turns were
    /// still running when the device's `hive_update_wait_secs` ran out, and the
    /// install cuts them. New prompts and starts are refused until the
    /// connection that asked closes.
    HiveUpdateHeld {
        waited_secs: u64,
        cut: u32,
    },
    /// FR-90 P3-9-2b — the endpoint a [`Request::Connect`] opened: what a
    /// session's `vault_connect` answers (where it is, a connection string
    /// that holds no credential, what to set, how long its leases have), and
    /// its `id` for [`Request::ConnectStatus`] on the same connection.
    Connected {
        id: u64,
        endpoint: serde_json::Value,
    },
    /// FR-90 P3-9-2b — [`Request::ConnectStatus`]'s answer.
    ConnectState(EndpointState),
    /// FR-84 D5b — the daemon answered FOR THE SERVER and the server did not
    /// give it the list. `code` names the cause so a client can choose what
    /// to show without reading prose: `server_unreachable` (connect / TLS /
    /// timeout) · `unauthorized` (401 — the device's credentials were
    /// refused) · `unsupported_server` (404 — a server older than the route)
    /// · `module_unmounted` (the server's own 503) · `rate_limited` (429) ·
    /// `server_error` (any other failure status) · `bad_request` (400 — e.g.
    /// an unknown sort key) · `bad_response` (a 2xx the daemon could not
    /// read) · `unknown_org` · `org_disabled` · `unsupported` (this node has
    /// no server to ask). `status` is the HTTP status when there was one.
    Upstream {
        code: String,
        message: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<u16>,
    },
}

/// FR-85 — options for a LOCAL recording. The microphone and system audio are
/// OFF unless asked for, and only a local caller can ask: this verb is served
/// on the device's own LocalAPI, which no remote controller reaches.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordStartOpts {
    /// 1–60; `None` ⇒ 30.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fps: Option<u32>,
    /// `auto` | `hardware` | `software`; `None` ⇒ `auto`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoder: Option<String>,
    /// Stop cleanly after this many minutes; `None` ⇒ 240.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_minutes: Option<u32>,
    /// Record what the computer plays.
    #[serde(default)]
    pub system_audio: bool,
    /// Record the microphone. Local only, by construction.
    #[serde(default)]
    pub microphone: bool,
}

/// FR-92 — keep busy on this device: what the engine is doing, and why.
/// The codes are the agent's (`docs/fr/FR-92-keep-busy.md`); `sentence` is its
/// own wording of `reason`, ready to show — the tray and the CLI never
/// compose their own.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct KeepBusyInfo {
    /// Keep busy can run here at all: built for this host, and allowed by
    /// the device owner and the org.
    #[serde(default)]
    pub available: bool,
    #[serde(default)]
    pub on: bool,
    /// `off` · `calibrating` · `running` · `paused` · `locked` · `unavailable`.
    #[serde(default)]
    pub phase: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sentence: Option<String>,
    /// `local` · `remote`, while paused for a person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paused_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resumes_in_ms: Option<u64>,
    /// The pattern's wire name (`circle`, `heart`, …).
    #[serde(default)]
    pub pattern: String,
    /// Who turned it on (a controller's display name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_off_at_ms: Option<u64>,
}

impl KeepBusyInfo {
    /// What a service that cannot run keep busy answers.
    pub fn unavailable() -> Self {
        KeepBusyInfo {
            phase: "unavailable".into(),
            reason: Some("unsupported".into()),
            sentence: Some("Unavailable on this computer.".into()),
            ..Default::default()
        }
    }
}

/// FR-92 P10 — what the person at the console asks for when turning keep
/// busy on locally ([`Request::KeepBusyOn`]). Every field is optional:
/// absent means the product default (circle, size m, normal speed, resume
/// after 30 s, no auto-off). The values are the viewer's own wire names
/// (`rc:keep-busy.set`), and the agent checks them with the same parser, so
/// "circel" is refused, never quietly drawn as something else.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct KeepBusyStartOpts {
    /// One of [`KEEP_BUSY_PATTERNS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// `s` · `m` · `l`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
    /// `slow` · `normal` · `fast`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub speed: Option<String>,
    /// How long the computer must be left alone before it resumes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_after_s: Option<u64>,
    /// Turn itself off after this many minutes; absent or 0 = never.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_off_min: Option<u64>,
}

/// FR-92 P10 — every keep-busy pattern's wire name, in the viewer's order:
/// what `roomler keep-busy on --pattern` offers. The agent owns the list (a
/// test there keeps this copy equal to it).
pub const KEEP_BUSY_PATTERNS: [&str; 13] = [
    "circle",
    "triangle",
    "square",
    "star",
    "figure8",
    "heart",
    "spirograph",
    "lissajous",
    "rose",
    "wave",
    "wander",
    "subtle",
    "shuffle",
];

/// FR-85 — what the recorder is doing now, and how the last recording ended.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordingState {
    /// A local recording can be started here at all. `false` on a service
    /// built without the recorder, and on a SYSTEM/root service until the
    /// recorder can run as the console user — the reason says which. A
    /// client greys its Start out instead of offering one that can only fail.
    #[serde(default)]
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
    pub active: bool,
    /// The file being written (its final path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Unix milliseconds the recording started; 0 when idle.
    #[serde(default)]
    pub started_at_ms: u64,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub frames: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoder: Option<String>,
    #[serde(default)]
    pub width: u32,
    #[serde(default)]
    pub height: u32,
    #[serde(default)]
    pub fps: u32,
    /// FR-85 P1c — which audio is going into the active recording.
    #[serde(default)]
    pub system_audio: bool,
    #[serde(default)]
    pub microphone: bool,
    /// #1760 — why a recording here could not include what the computer
    /// plays (`system_audio` in [`RecordStartOpts`]), in words: the service
    /// was built without audio capture, or the platform has no loopback to
    /// open (macOS, until ScreenCaptureKit). `None` where it can. A client
    /// greys its "Computer audio" box out with the words, and the owner's
    /// "Include computer audio" remote toggle likewise, instead of offering
    /// a start that can only fail. Absent from a service older than this,
    /// which reads as "it can": today's behaviour, the recorder refusing by
    /// name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_audio_unavailable_reason: Option<String>,
    /// FR-85 P3 — the active recording was started by a REMOTE controller
    /// (this is their display name); `None` for a local one. What the host
    /// sees in the tray and the Recordings view: "recording for Alice".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_controller: Option<String>,
    /// Why the default or configured folder was not used, when it was not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder_reason: Option<String>,
    /// How the previous recording ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<RecordingEnded>,
}

/// FR-85 — why a service without the recorder cannot record.
pub const NO_RECORDER: &str = "this device service was built without the screen recorder";

impl RecordingState {
    /// Idle, and unable to record here, for `reason`.
    pub fn unavailable(reason: &str) -> Self {
        Self {
            available: false,
            unavailable_reason: Some(reason.to_string()),
            ..Default::default()
        }
    }
}

/// FR-85 — how a recording ended.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordingEnded {
    /// The closed stop-reason set (`requested`, `disk_low`, …), or a refusal
    /// code (`encoder_unavailable`, `no_frame`, …) when it never started.
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// FR-85 — one finished recording in the folder.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordingItem {
    /// File name (no path — it lives in [`RecordingsListing::dir`]).
    pub name: String,
    pub bytes: u64,
    #[serde(default)]
    pub duration_ms: u64,
    /// RFC 3339, from the sidecar; empty when the sidecar is missing.
    #[serde(default)]
    pub started_at: String,
    /// `local` | `remote`.
    #[serde(default)]
    pub origin: String,
    /// A remote recording's controller, as the sidecar names them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
    #[serde(default)]
    pub width: u32,
    #[serde(default)]
    pub height: u32,
}

/// FR-85 — the recordings folder, why it is that one, and its recordings.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordingsListing {
    pub dir: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder_reason: Option<String>,
    pub items: Vec<RecordingItem>,
}

/// FR-85 — who is on the other end of a LocalAPI connection, captured by the
/// listener at accept time from the OS (never from anything the client says).
///
/// The pipe ACL admits every Interactive User — RDP sessions included — and
/// the unix socket every process of its uid. That is the right boundary for
/// reading status, and the wrong one for starting a screen recording: a guest
/// in an RDP session must not be able to record the CONSOLE user's desktop.
/// The recording verbs, and a `ConfigSet` of any `record_*` key, therefore
/// require [`ClientPeer::is_console_user`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientPeer {
    /// Windows: the client process's session id.
    pub session_id: Option<u32>,
    /// Unix: the client's uid.
    pub uid: Option<u32>,
    /// Windows (FR-92 P10b): does the client process run as a service
    /// account — SYSTEM, LocalService or NetworkService? Read from its token
    /// at accept time. `None` when it could not be read, and always `None` off
    /// Windows.
    pub system_account: Option<bool>,
    /// Unix (FR-90 P3-9-2b): the client's gid, read with its uid.
    pub gid: Option<u32>,
    /// Windows (FR-90 P3-9-2b): the account the client process runs as, by
    /// SID (`S-1-5-…`), read from the same token as `system_account`.
    pub sid: Option<String>,
    /// Windows (FR-90 P3-9-2b): whether that token is elevated.
    pub elevated: Option<bool>,
}

impl ClientPeer {
    /// A peer nothing is known about (tests, and any transport that cannot
    /// say). Fails every console check — the gate is fail-closed.
    pub const UNKNOWN: ClientPeer = ClientPeer {
        session_id: None,
        uid: None,
        system_account: None,
        gid: None,
        sid: None,
        elevated: None,
    };

    /// Is this peer the person at the console? Windows: its session is the
    /// active CONSOLE session. Unix: it is this daemon's own uid (a per-user
    /// daemon, whose socket is 0600 anyway), or root.
    pub fn is_console_user(&self) -> bool {
        peer_is_console_user(self, console_session_id(), own_uid())
    }

    /// FR-90 P1h-2 — is this peer root (Unix)? What may hold the daemon for
    /// an update: a hold refuses every new agent prompt and start until it
    /// ends, so no other local account may place one. Unknown is not root.
    pub fn is_root(&self) -> bool {
        self.uid == Some(0)
    }

    /// FR-92 P10 — may this peer turn keep busy ON? Only the person at the
    /// console, on `scope`'s endpoint ([`peer_may_start_keep_busy`]).
    pub fn may_start_keep_busy(&self, scope: Scope) -> bool {
        peer_may_start_keep_busy(self, scope, console_session_id(), own_uid())
    }

    /// FR-90 P3-9-2b — may this peer run `roomler connect` here (decision
    /// 26)? [`peer_may_connect`].
    pub fn may_connect(&self) -> bool {
        peer_may_connect(self, own_uid(), own_sid())
    }

    /// FR-90 P3-9-2b — the account a [`Request::Connect`] from this peer
    /// serves its endpoint to: its own, as the OS said at accept time. `None`
    /// when the OS did not say.
    pub fn asker(&self) -> Option<Asker> {
        match (self.uid, self.gid, &self.sid) {
            (Some(uid), Some(gid), _) => Some(Asker::Unix { uid, gid }),
            (None, _, Some(sid)) => Some(Asker::Windows { sid: sid.clone() }),
            _ => None,
        }
    }
}

/// FR-90 P3-9-2b — the account a person's endpoint ([`Request::Connect`])
/// is served to: the one that asked, read by the listener from the OS before
/// a byte of the request, never from anything the client says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asker {
    /// Its uid and gid.
    Unix { uid: u32, gid: u32 },
    /// Its account, by SID (`S-1-5-…`).
    Windows { sid: String },
}

/// FR-90 P3-9-2b — the pure decision behind [`ClientPeer::may_connect`]
/// (decision 26, its recommendation, pending the operator's word).
///
/// `roomler connect` lends the device's OWNER's vault grants (decision 23),
/// whoever runs it, so it is held to who may already act for the whole
/// device:
/// - **Unix**: root, or the daemon's own uid. On a system install the daemon's
///   socket is root's anyway, and the person socket refuses the verb
///   ([`person_may`]).
/// - **Windows**: SYSTEM (and the other service accounts, as
///   [`ClientPeer::system_account`] reads them), an elevated administrator,
///   or the account the daemon itself runs as (an attended install's
///   person). ⚠️ The pipe's ACL is wider than that: it admits every
///   interactive user, an RDP session's included (`LOCALAPI_SDDL`'s `IU`), so
///   without this gate anyone signed in would reach the owner's grants.
/// - Anything unknown: no.
///
/// The endpoint serves the account that asked ([`ClientPeer::asker`]), read
/// from the same token this decides on, so the account that passes is the
/// account that is served.
pub fn peer_may_connect(peer: &ClientPeer, own_uid: Option<u32>, own_sid: Option<&str>) -> bool {
    if let Some(uid) = peer.uid {
        return uid == 0 || Some(uid) == own_uid;
    }
    if peer.system_account == Some(true) || peer.elevated == Some(true) {
        return true;
    }
    matches!((peer.sid.as_deref(), own_sid), (Some(p), Some(o)) if p == o)
}

/// FR-92 P10 — the pure decision behind [`ClientPeer::may_start_keep_busy`].
///
/// Stricter than [`peer_is_console_user`] in one way that matters: **root
/// never**. That gate lets root through on Unix, and root is how
/// `roomler exec` arrives there — so with it, a plain
/// `roomler exec <host> -- roomler keep-busy on` would start synthetic input
/// under the person's name.
/// - **Windows**: the active console session, never session 0 (services),
///   and (P10b) **never a service account** — SYSTEM, LocalService or
///   NetworkService — nor a peer whose account could not be read.
/// - **A per-user daemon's own socket** (macOS GUI worker, Linux user
///   daemon): its owner, who is the person.
/// - **The person socket of a Linux system install** ([`Scope::Person`]):
///   its ACL admits only the person it was made for.
/// - Anything unknown: no.
///
/// **SYSTEM is Windows' root** (P10b). A SystemContext-mode worker runs as
/// SYSTEM *inside* the console session, and `roomler exec` runs as that
/// worker, so before P10b an exec there passed the session test. The account
/// comes from the client's token, read by the listener at accept time
/// ([`ClientPeer::system_account`]), never from anything the client says.
/// The pipe is served by the worker, so what it can read depends on what the
/// worker is:
/// - **An attended install, an admin** (the user's elevated token): the
///   person's tray and CLI are the same user, so their tokens open and read
///   as a user. A SYSTEM client usually opens too and reads as SYSTEM.
/// - **An attended install, a standard user** (a filtered token): the
///   person's own processes open. A SYSTEM process usually does not, and an
///   account that cannot be read is a refusal, so SYSTEM is refused either
///   way.
/// - **SystemContext mode** (the worker is SYSTEM): every client opens. The
///   person reads as a user; an exec runs as the worker, reads as SYSTEM, and
///   is refused.
///
/// ⚠️ **Not a wall against `roomler exec`.** On an attended install exec runs
/// as the signed-in user, in the console session, so it passes and is named
/// "the person at this computer" (measured on 0.4.129, FR-92 §9 row 43). On
/// Unix root can `sudo -u` the person. Nothing a local gate sees tells them
/// apart: what an exec caller may do on a device is the owner's
/// `exec_enabled`, not this. Which identity exec should have is #2021.
pub fn peer_may_start_keep_busy(
    peer: &ClientPeer,
    scope: Scope,
    console_session: Option<u32>,
    own_uid: Option<u32>,
) -> bool {
    if peer.uid == Some(0) {
        return false;
    }
    if let (Some(p), Some(c)) = (peer.session_id, console_session) {
        // P10b — `Some(false)` only: SYSTEM and its kin never, and an
        // account that could not be read never either (fail closed).
        return p == c && p != 0 && peer.system_account == Some(false);
    }
    match scope {
        Scope::Person => peer.uid.is_some(),
        Scope::Full => matches!((peer.uid, own_uid), (Some(p), Some(o)) if p == o),
    }
}

/// The pure decision behind [`ClientPeer::is_console_user`], testable
/// without an OS.
pub fn peer_is_console_user(
    peer: &ClientPeer,
    console_session: Option<u32>,
    own_uid: Option<u32>,
) -> bool {
    if let (Some(p), Some(c)) = (peer.session_id, console_session) {
        return p == c;
    }
    match (peer.uid, own_uid) {
        (Some(p), Some(o)) => p == o || p == 0,
        _ => false,
    }
}

/// The active console session (Windows), `None` when there is none or on
/// other platforms.
fn console_session_id() -> Option<u32> {
    #[cfg(windows)]
    {
        // SAFETY: no arguments, no preconditions.
        let s =
            unsafe { windows_sys::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId() };
        (s != u32::MAX).then_some(s)
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// This process's effective uid (unix), `None` elsewhere.
fn own_uid() -> Option<u32> {
    #[cfg(unix)]
    {
        // SAFETY: geteuid never fails.
        Some(unsafe { libc::geteuid() })
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// Who is on the far end of a server pipe handle, from the OS: the client
/// process's session and, from its token, (FR-92 P10b) whether it runs as a
/// service account and (FR-90 P3-9-2b) as which account, elevated or not.
/// Whatever cannot be read stays `None`, which every gate reads as "no".
#[cfg(windows)]
fn pipe_client_peer(handle: std::os::windows::io::RawHandle) -> ClientPeer {
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
    let mut pid = 0u32;
    // SAFETY: `handle` is a live server-end pipe handle owned by the caller for
    // the duration of this call; the out-param is a valid u32.
    if unsafe { GetNamedPipeClientProcessId(handle as _, &mut pid) } == 0 {
        return ClientPeer::UNKNOWN;
    }
    let token = process_token(pid);
    ClientPeer {
        session_id: process_session(pid),
        system_account: token.as_ref().map(|t| t.service),
        sid: token.as_ref().and_then(|t| t.sid.clone()),
        elevated: token.as_ref().and_then(|t| t.elevated),
        ..ClientPeer::UNKNOWN
    }
}

/// What a process's token says about who runs it, read in one opening of
/// the token, so every gate decides on one account.
#[cfg(windows)]
struct TokenFacts {
    /// FR-92 P10b — its user is a service account ([`sid_is_service_account`]).
    service: bool,
    /// FR-90 P3-9-2b — its user, by SID; `None` when it would not convert.
    sid: Option<String>,
    /// FR-90 P3-9-2b — whether it is elevated; `None` when that could not be
    /// read.
    elevated: Option<bool>,
}

/// FR-90 P3-9-2b — the account this process runs as, by SID (Windows), read
/// once; `None` elsewhere, or when it could not be read.
fn own_sid() -> Option<&'static str> {
    #[cfg(windows)]
    {
        static OWN: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
        OWN.get_or_init(|| {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::Security::TOKEN_QUERY;
            use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
            let mut token = std::ptr::null_mut();
            // SAFETY: our own process's pseudo-handle; `token` is a valid
            // out-param, closed below once.
            if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
                return None;
            }
            let facts = token_facts(token);
            // SAFETY: closes the token opened above, exactly once.
            unsafe { CloseHandle(token) };
            facts.and_then(|f| f.sid)
        })
        .as_deref()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// The session process `pid` runs in.
#[cfg(windows)]
fn process_session(pid: u32) -> Option<u32> {
    use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    let mut session = 0u32;
    // SAFETY: a plain query by pid; the out-param is a valid u32.
    (unsafe { ProcessIdToSessionId(pid, &mut session) } != 0).then_some(session)
}

/// What process `pid`'s token says ([`TokenFacts`]): FR-92 P10b — whether it
/// runs as SYSTEM, LocalService or NetworkService; FR-90 P3-9-2b — as which
/// account, and whether elevated. `None` when its token cannot be opened or
/// its user read, which every gate treats as a refusal.
///
/// The token is opened by pid rather than through `ImpersonateNamedPipeClient`
/// because the peer is captured at accept time, before a byte is read, and a
/// pipe server can impersonate only after it has read from the client.
#[cfg(windows)]
fn process_token(pid: u32) -> Option<TokenFacts> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    // SAFETY: a query-only open by pid; the handle is closed below, once.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return None;
    }
    let mut token = std::ptr::null_mut();
    // SAFETY: `process` is the live handle opened above; `token` is a valid
    // out-param.
    let opened = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } != 0;
    // SAFETY: closes the process handle opened above, exactly once.
    unsafe { CloseHandle(process) };
    if !opened {
        return None;
    }
    let facts = token_facts(token);
    // SAFETY: closes the token opened above, exactly once.
    unsafe { CloseHandle(token) };
    facts
}

/// What `token` says ([`TokenFacts`]). `None` when its user cannot be read.
#[cfg(windows)]
fn token_facts(token: windows_sys::Win32::Foundation::HANDLE) -> Option<TokenFacts> {
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_USER, TokenElevation, TokenUser,
    };
    // A TOKEN_USER and the SID it points into. A SID is at most 68 bytes
    // (SECURITY_MAX_SID_SIZE), so 256 bytes is ample; u64 keeps the
    // structure's pointer-sized field aligned.
    let mut buf = [0u64; 32];
    let mut len = 0u32;
    // SAFETY: `token` is a live token handle with TOKEN_QUERY; `buf` is
    // writable for the length passed and aligned for TOKEN_USER.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast(),
            std::mem::size_of_val(&buf) as u32,
            &mut len,
        )
    } != 0;
    if !ok {
        return None;
    }
    // SAFETY: on success `buf` begins with a TOKEN_USER whose SID points into
    // `buf`, which outlives every use of `sid` below.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    // SAFETY: a live token; `elevation` is sized for TokenElevation.
    let elevated = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&raw mut elevation).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    } != 0;
    Some(TokenFacts {
        service: sid_is_service_account(sid),
        sid: sid_text(sid),
        elevated: elevated.then_some(elevation.TokenIsElevated != 0),
    })
}

/// FR-90 P3-9-2b — `sid` as text (`S-1-5-…`), as every other place this
/// device names an account by SID writes it. `None` when it would not
/// convert.
#[cfg(windows)]
fn sid_text(sid: windows_sys::Win32::Security::PSID) -> Option<String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    let mut text: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: `sid` is a valid SID for this call; on success `text` is a
    // LocalAlloc'd, NUL-terminated wide string, freed below exactly once.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 || text.is_null() {
        return None;
    }
    // SAFETY: `text` is NUL-terminated, so every unit read up to it is
    // inside the allocation.
    let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
    // SAFETY: `len` units from `text` were just read as the string's.
    let s = String::from_utf16(unsafe { std::slice::from_raw_parts(text, len) }).ok();
    // SAFETY: the one allocation ConvertSidToStringSidW made, freed once.
    unsafe { LocalFree(text.cast()) };
    s
}

/// FR-92 P10b — SYSTEM (S-1-5-18), LocalService (S-1-5-19) or NetworkService
/// (S-1-5-20): the accounts services run as, and Windows' counterparts of
/// root. A person never signs in as one.
#[cfg(windows)]
fn sid_is_service_account(sid: windows_sys::Win32::Security::PSID) -> bool {
    use windows_sys::Win32::Security::{
        IsWellKnownSid, WinLocalServiceSid, WinLocalSystemSid, WinNetworkServiceSid,
    };
    [WinLocalSystemSid, WinLocalServiceSid, WinNetworkServiceSid]
        .into_iter()
        // SAFETY: `sid` is a valid SID for the duration of this call.
        .any(|kind| unsafe { IsWellKnownSid(sid, kind) } != 0)
}

/// The overlay runtime's live view of the mesh, republished on a
/// [`tokio::sync::watch`] channel whenever the netmap / carrier state changes
/// (see `overlay::runtime`). NOT a wire type — it's the daemon-internal bridge
/// between the overlay runtime (which owns `by_node` inside its single
/// `select!` loop and has no other external accessor) and the daemon's
/// [`LocalApiState`] impl, which turns it into [`Response::Status`]'s
/// `overlay_ip` + [`Response::Peers`]. Kept here (not under the overlay
/// feature) so a daemon compiled WITHOUT `overlay-l3` can still hold an empty
/// `Default` one and answer `peers` with `[]`.
#[derive(Debug, Clone, Default)]
pub struct OverlayView {
    pub path_trials: Option<PathTrialStatus>,
    /// This node's assigned overlay IP (the netmap `self_ip`), once joined.
    pub self_ip: Option<String>,
    /// This node's *derived* overlay IPv6, filled by the overlay runtime
    /// alongside `self_ip` (the daemon never derives — it has no `overlay`
    /// feature guarantee).
    pub self_ip6: Option<String>,
    /// Peers as the runtime currently reaches them.
    pub peers: Vec<PeerInfo>,
    /// P5 exit-node routing status (S4), filled by the overlay runtime. `None`
    /// unless this node is configured as an exit-node client. The daemon copies
    /// it verbatim into [`NodeStatus::exit_node`].
    pub exit_node: Option<ExitNodeStatus>,
    /// FR-97 P0b — why this node offers no routes it was configured to, filled
    /// by the overlay runtime. The daemon copies it verbatim into
    /// [`NodeStatus::route_offer_withheld`].
    pub route_offer_withheld: Option<String>,
    /// FR-97 P3i — what the host's firewall lets a mesh peer reach on this
    /// node's overlay adapter, probed by the overlay runtime at bring-up and
    /// every ten minutes. The daemon copies it verbatim into
    /// [`NodeStatus::host_firewall`].
    pub host_firewall: Option<HostFirewallStatus>,
    /// S2 — MagicDNS status, filled by the overlay runtime after its DNS
    /// bring-up. `None` when MagicDNS is off. The daemon copies it
    /// verbatim into [`NodeStatus::dns`].
    pub dns: Option<DnsStatus>,
    /// NAT-traversal — the srflx gather outcome, filled by the overlay runtime
    /// on every gather (success or failure). The daemon copies it verbatim
    /// into [`NodeStatus::srflx`]. `None` before the first gather.
    pub srflx: Option<SrflxStatus>,
    /// C4 stage 1 — the warm TURN/UDP allocation's state, filled by the
    /// overlay runtime on every view publish when `overlay_warm_relay` is
    /// on. The daemon copies it verbatim into [`NodeStatus::warm_relay`].
    pub warm_relay: Option<WarmRelayStatus>,
    /// PR-B1 — per-bound-direct-socket receive liveness, filled by the overlay
    /// runtime on every view publish (plane stats when the shared carrier
    /// plane is on, per-device demux stats otherwise). The daemon copies it
    /// verbatim into [`NodeStatus::direct_socks`].
    pub direct_socks: Vec<DirectSockStatus>,
    /// #32 — see [`NodeStatus::derp_inbound_drops`]. Filled by the overlay
    /// runtime on every view publish; the daemon copies it verbatim.
    pub derp_inbound_drops: Option<(u64, u64)>,
}

/// Read-only snapshot the daemon provides to [`handle`]. The daemon's impl
/// gathers this from its live overlay / tunnel / forward state; the trait keeps
/// the protocol unit-testable with a mock and free of daemon internals.
#[async_trait]
pub trait LocalApiState: Send + Sync {
    fn status(&self) -> NodeStatus;
    fn peers(&self) -> Vec<PeerInfo>;
    fn flows(&self) -> Vec<FlowInfo>;
    /// FR-97 P2h — what a `Status` request answers. Default: [`Self::status`].
    /// A daemon whose network view is another process's (a two-half Mac's
    /// per-user half, which has no overlay node) overrides it to ask that
    /// process; the sync read stays what everything else uses.
    async fn status_view(&self) -> NodeStatus {
        self.status()
    }
    /// FR-97 P2h — what a `Peers` request answers. Default: [`Self::peers`];
    /// overridden as [`Self::status_view`] is.
    async fn peers_view(&self) -> Vec<PeerInfo> {
        self.peers()
    }
    /// Remote-control sessions awaiting an operator consent decision (P2b).
    /// Default: none — so existing impls / mocks and the read-only contract are
    /// undisturbed; the agent daemon overrides this.
    fn consent_pending(&self) -> Vec<ConsentRequest> {
        Vec::new()
    }
    /// Apply an operator consent decision to `session_id` (P2b). Returns whether
    /// it was recorded. Default: no-op `false`.
    fn consent_decide(&self, _session_id: &str, _allow: bool) -> bool {
        false
    }
    /// FR-27 — remote-control sessions currently LIVE on this device. Distinct
    /// from [`Self::consent_pending`], which is about sessions not yet allowed
    /// to start. Default: none.
    fn rc_sessions(&self) -> Vec<RcSessionInfo> {
        Vec::new()
    }
    /// FR-27 — tear down a live remote-control session from the device side.
    /// Returns whether a session with that id was found and asked to stop.
    /// Default: no-op `false`.
    fn rc_disconnect(&self, _session_id: &str) -> bool {
        false
    }
    /// ICMP-ping an overlay peer by name/IP over the userspace netstack, and
    /// return a [`Response::Pong`] (or [`Response::Error`]). Async — awaited by
    /// [`serve_connection`], not the sync [`handle`]. `prefer_v6` resolves a
    /// name target to the peer's derived overlay IPv6. Default: unsupported (a
    /// node not running the netstack has no OS-free ICMP path).
    async fn ping(&self, _target: &str, _timeout_ms: u64, _prefer_v6: bool) -> Response {
        Response::Error {
            message: "ping is not supported on this node (not running the userspace netstack)"
                .into(),
        }
    }
    /// Create a daemon-driven static forward (P3b-2). Async — awaited by
    /// [`serve_connection`], not the sync [`handle`]. Returns
    /// [`Response::FlowCreated`] or [`Response::Error`]. Default: unsupported
    /// (a node that can't originate tunnels, e.g. no agent WS).
    async fn create_forward(
        &self,
        _node: &str,
        _local: u16,
        _remote: &str,
        _transport: &str,
        _start_transport: &str,
    ) -> Response {
        Response::Error {
            message: "forward origination is not supported on this node".into(),
        }
    }
    /// Create a daemon-driven SOCKS5 listener (P3b-2). Async; default
    /// unsupported.
    async fn create_socks5(&self, _node: &str, _local: u16, _transport: &str) -> Response {
        Response::Error {
            message: "socks5 origination is not supported on this node".into(),
        }
    }
    /// Stop + deregister a daemon flow by id (P3b-2). Returns whether a flow was
    /// found + killed. Default: no-op `false`.
    fn kill_flow(&self, _id: &str) -> bool {
        false
    }
    /// Declared routes + their live runtime state (P6). Default: none —
    /// a node without a route reconciler has no declared routes.
    fn route_list(&self) -> Vec<RouteInfo> {
        Vec::new()
    }
    /// Declare + persist a supervised route (P6). Async — config I/O.
    /// Default: unsupported.
    async fn route_add(&self, _route: RouteDescriptor) -> Response {
        Response::Error {
            message: "declared routes are not supported on this node".into(),
        }
    }
    /// Remove a declared route by id (P6). Async — config I/O. Default:
    /// unsupported.
    async fn route_remove(&self, _id: &str) -> Response {
        Response::Error {
            message: "declared routes are not supported on this node".into(),
        }
    }
    /// Enable/disable a declared route by id (P6). Async — config I/O.
    /// Default: unsupported.
    async fn route_set_enabled(&self, _id: &str, _enabled: bool) -> Response {
        Response::Error {
            message: "declared routes are not supported on this node".into(),
        }
    }
    /// FR-84 D1 — replace a declared route in one step (async — config
    /// I/O). Default: unsupported.
    async fn route_update(&self, _route: RouteDescriptor) -> Response {
        Response::Error {
            message: "declared routes are not supported on this node".into(),
        }
    }
    /// Rename this device — persist the new name to the daemon's own config
    /// (async — config I/O). Default: unsupported, so existing impls / mocks
    /// and the read-only contract are undisturbed; the agent daemon overrides.
    async fn set_device_name(&self, _name: &str) -> Response {
        Response::Error {
            message: "renaming is not supported on this node".into(),
        }
    }
    /// S1b — archive the stale config copy on a split-config host
    /// (async — config I/O). Default: unsupported; the agent daemon
    /// overrides.
    async fn config_cleanup_stale(&self) -> Response {
        Response::Error {
            message: "config cleanup is not supported on this node".into(),
        }
    }
    /// S2 — list the editable config surface (async — reads the config
    /// file). Default: unsupported; the agent daemon overrides.
    async fn config_entries(&self) -> Response {
        Response::Error {
            message: "config editing is not supported on this node".into(),
        }
    }
    /// S2 — set/clear one editable config key (async — config I/O).
    /// Default: unsupported; the agent daemon overrides.
    async fn config_set(&self, _key: &str, _value: Option<&str>) -> Response {
        Response::Error {
            message: "config editing is not supported on this node".into(),
        }
    }
    /// S2 — tail a daemon log file (async — file I/O). Default:
    /// unsupported; the agent daemon overrides.
    /// FR-52 gate 4 — register `password` and persist the record. Default: an
    /// older daemon answers a clean `Error` rather than a silent success.
    async fn external_password_set(&self, _password: &Secret) -> Response {
        Response::Error {
            message: "this daemon does not support external access".into(),
        }
    }

    /// FR-52 gate 4 — drop the stored record.
    async fn external_password_clear(&self) -> Response {
        Response::Error {
            message: "this daemon does not support external access".into(),
        }
    }

    /// FR-52 — report gates 3 and 4. The default is a truthful "nothing here",
    /// not an error: a client asking *whether* the feature exists must get an
    /// answer it can render, and `supported: false` is that answer.
    async fn external_password_status(&self) -> Response {
        Response::ExternalPassword(ExternalPasswordState::default())
    }

    async fn tail_log(&self, _source: &str, _max_bytes: Option<u64>) -> Response {
        Response::Error {
            message: "log tailing is not supported on this node".into(),
        }
    }
    /// Fleet RPC — relay an exec request to another device over this daemon's
    /// agent WS and await the answer (async — a full server round-trip).
    /// Default: unsupported — a node with no agent WS can't originate one.
    async fn exec_remote(
        &self,
        _node: &str,
        _shell: &str,
        _command: &str,
        _timeout_ms: u64,
    ) -> Response {
        Response::Error {
            message: "this node cannot originate remote commands (no server connection)".into(),
        }
    }

    /// Ask the server for a single-use SSH grant on another device (P6b).
    /// Default: this node has no server connection, so it cannot originate.
    async fn ssh_session(&self, _node: &str, _public_key: &str, _session_secs: u64) -> Response {
        Response::Error {
            message: "this node cannot originate SSH sessions (no server connection)".into(),
        }
    }
    /// FR-85 — start a local recording. The console-user check has already
    /// passed when this is called ([`serve_connection_as`] enforces it).
    /// Default: this build has no recorder.
    async fn record_start(&self, _opts: RecordStartOpts) -> Response {
        Response::Error {
            message: "screen recording is not available in this build".into(),
        }
    }
    /// FR-85 — stop the active recording (console user, checked by the caller).
    async fn record_stop(&self) -> Response {
        Response::Error {
            message: "screen recording is not available in this build".into(),
        }
    }
    /// FR-85 — the recorder's state.
    async fn record_status(&self) -> Response {
        Response::Recording(RecordingState::unavailable(NO_RECORDER))
    }
    /// FR-92 — keep busy's state.
    async fn keep_busy_status(&self) -> Response {
        Response::KeepBusy(KeepBusyInfo::unavailable())
    }
    /// FR-92 — stop keep busy (any admitted peer; checked by nobody, on
    /// purpose — see [`Request::KeepBusyOff`]).
    async fn keep_busy_off(&self) -> Response {
        Response::KeepBusy(KeepBusyInfo::unavailable())
    }
    /// FR-92 P10 — the person at the console turns keep busy on. The
    /// dispatcher has already checked the peer IS that person.
    async fn keep_busy_on(&self, _opts: KeepBusyStartOpts) -> Response {
        Response::KeepBusy(KeepBusyInfo::unavailable())
    }
    /// FR-85 — the recordings folder and its recordings.
    async fn recordings_list(&self) -> Response {
        Response::Error {
            message: "screen recording is not available in this build".into(),
        }
    }
    /// FR-85 — delete a recording by name (console user, checked by the caller).
    async fn recording_delete(&self, _name: &str) -> Response {
        Response::Error {
            message: "screen recording is not available in this build".into(),
        }
    }

    /// FR-84 D5b — one page of the devices this device may see, fetched from
    /// `org`'s server (async — an HTTP round-trip). Default: this node has no
    /// server to ask, which is an [`Response::Upstream`] with code
    /// `unsupported` rather than a bare error, so a client falls back the
    /// same way it does for every other upstream failure.
    async fn devices(&self, _org: &str, _query: &DevicesQuery) -> Response {
        Response::Upstream {
            code: "unsupported".into(),
            message: "this node has no server connection to list devices from".into(),
            status: None,
        }
    }

    /// FR-84 D5b — the mesh graph for `org`'s visible set (async). Default:
    /// unsupported, as for [`Self::devices`].
    async fn mesh(&self, _org: &str) -> Response {
        Response::Upstream {
            code: "unsupported".into(),
            message: "this node has no server connection to read the mesh from".into(),
            status: None,
        }
    }

    /// FR-84 D3 — decide a restart request: [`Response::DaemonRestarting`]
    /// when accepted (the implementation arms it, it does NOT exit yet), or
    /// an `Error` with the refusal. Default: this node cannot restart itself.
    async fn restart_daemon(&self, _reason: &str) -> Response {
        Response::Error {
            message: "restarting is not supported on this node".into(),
        }
    }
    /// FR-84 D3 — called by the connection loop right after an accepted
    /// [`Response::DaemonRestarting`] has been written (or its write failed —
    /// the restart was accepted and recorded either way). This is the ONLY
    /// point where the shutdown may begin, so a client never sees its
    /// connection die before it learns the restart was accepted. Default:
    /// no-op.
    fn restart_commit(&self) {}
    /// FR-90 P1h-2 — hold this daemon for an update the root helper is about
    /// to install: wait for running agent turns (at most the device's
    /// `hive_update_wait_secs`), refuse new prompts and starts, and answer
    /// [`Response::HiveUpdateHeld`]. The hold lasts until the asking
    /// connection closes ([`Self::hive_update_release`]). Default: this node
    /// runs no agent sessions, so there is nothing to hold for.
    async fn hive_update_hold(&self) -> Response {
        Response::Error {
            message: "this node runs no agent sessions".into(),
        }
    }
    /// FR-90 P1h-2 — the connection that held the daemon closed. An install
    /// that worked restarted the daemon long before, so this is one that did
    /// not: take prompts and starts again. Default: no-op.
    fn hive_update_release(&self) {}
    /// FR-90 P3-9-2b — open a person's endpoint (`roomler connect`) served to
    /// `asker`, the account that asked, and answer [`Response::Connected`].
    /// The peer has passed [`peer_may_connect`] by now. Default: a daemon
    /// built without the vault lends nothing.
    async fn connect(&self, _asker: &Asker, _args: &ConnectArgs) -> Response {
        Response::Error {
            message: "this device's daemon was built without the vault, so it opens no \
                      endpoint"
                .into(),
        }
    }
    /// FR-90 P3-9-2b — where endpoint `id` stands: [`Response::ConnectState`].
    /// Asked only for an id this connection opened.
    fn connect_status(&self, _id: u64) -> Response {
        Response::Error {
            message: "this daemon holds no endpoint".into(),
        }
    }
    /// FR-90 P3-9-2b — the connection that opened endpoint `id` closed: close
    /// it, with its connections, and let its leases go. Default: no-op.
    fn connect_release(&self, _id: u64) {}
    /// FR-84 D4 — what this device can encode, from the probe's CACHED
    /// result only (never a probe). `None` = this node does not report
    /// encoder capabilities at all (mocks, non-daemon impls); the daemon
    /// overrides and answers `not_probed` / `unsupported` / `ready`.
    fn encoder_caps(&self) -> Option<EncoderCapsSummary> {
        None
    }
}

/// FR-85 — the refusal a non-console caller gets for a recording verb.
fn not_the_console_user() -> Response {
    Response::Error {
        message: "only the person at this device's console can start, stop or delete a \
                  recording, or change where recordings are saved"
            .into(),
    }
}

/// FR-52 — the answer to anyone but the person at the console who tries to
/// open this device to people outside its organization, or change how.
fn not_the_console_user_for_external_access() -> Response {
    Response::Error {
        message: "only the person at this device's console can open it to people outside \
                  the organization, or change how"
            .into(),
    }
}

/// FR-92 P10 — the answer to a keep-busy start from anyone but the person at
/// the console.
fn not_the_person_for_keep_busy() -> Response {
    Response::Error {
        message: "only the person at this device's console can turn keep busy on here — \
                  not root or SYSTEM, not a background service, not another session \
                  (anyone may stop it)"
            .into(),
    }
}

/// FR-90 P3-9-2b (decision 26) — the answer to a `roomler connect` from
/// anyone [`peer_may_connect`] refuses.
fn not_one_who_may_connect() -> Response {
    Response::Error {
        message: if cfg!(windows) {
            "roomler connect lends this device's owner's vault grants, so here only SYSTEM, an \
             elevated administrator, or the account Roomler's service runs as may run it: run \
             it from an elevated prompt"
        } else {
            "roomler connect lends this device's owner's vault grants, so here only root, or \
             the account the daemon runs as, may run it: `sudo roomler connect …`"
        }
        .into(),
    }
}

/// FR-27 P11 — what a connection may ask, decided by WHICH socket it came in on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The daemon's own endpoints. Their ACL is the boundary, so every verb is
    /// served (the per-verb console checks above still apply).
    Full,
    /// The person-at-the-device socket of a Linux system install, and of a
    /// Mac's root half ([`serve_person_socket`]): only what that person needs
    /// to see who is viewing their screen, end it, answer a consent prompt, and
    /// see the devices the machine's private network lets it see.
    Person,
}

/// FR-27 P11 — may the person-at-the-device socket serve this request?
///
/// ⚠️ Exhaustive on purpose, with no `_` arm. A verb added to [`Request`]
/// must be put on one side of this line by hand, so the person socket can
/// never pick up a new administrative verb by default. The allowed set is the
/// safety surface the companion draws for the person: the status that says
/// the service is up, the sessions behind the "Being viewed by …" banner, its
/// Disconnect, the consent prompt and its answer, and whether a recording is
/// running (the tray turns red). FR-97 P2g adds the companion's Devices page,
/// and P2h the live links its Connection column and Overview read.
pub fn person_may(req: &Request) -> bool {
    match req {
        Request::Status
        | Request::RcSessions
        | Request::RcDisconnect { .. }
        | Request::ConsentPending
        | Request::ConsentDecide { .. }
        | Request::RecordStatus
        // FR-92 — keep busy moves the person's own pointer: they must see it
        // and be able to stop it from the companion, even on a system
        // install where this socket is all they can reach. P10 — and turn it
        // on: this socket's ACL admits only that person (the start is gated
        // again, on the peer, in the dispatcher).
        | Request::KeepBusyStatus
        | Request::KeepBusyOff
        | Request::KeepBusyOn { .. }
        // FR-97 P2g — the companion's Devices page and mesh graph: the devices
        // THIS machine's private network lets it see. Read-only. The server
        // shapes the list by the machine's own overlay ACL, and the person
        // can search, sort and page it but not widen it. Windows serves the
        // same to its interactive users (the pipe's `IU` ace). A Mac's
        // per-user half asks for it here, because only the root half is on
        // the network; before this it listed itself alone.
        | Request::Devices { .. }
        | Request::Mesh { .. }
        // FR-97 P2h — the live state of this machine's links to those devices
        // (online, direct or relayed, round trip), which the Devices page's
        // Connection column and Overview's count read. Read-only, and served
        // without the endpoints and probe detail (`person_view`).
        | Request::Peers => true,
        Request::Flows
        | Request::Ping { .. }
        | Request::CreateForward { .. }
        | Request::CreateSocks5 { .. }
        | Request::KillFlow { .. }
        | Request::RouteList
        | Request::RouteAdd { .. }
        | Request::RouteRemove { .. }
        | Request::RouteSetEnabled { .. }
        | Request::RouteUpdate { .. }
        | Request::SetDeviceName { .. }
        | Request::ConfigCleanupStale
        | Request::ConfigGet
        | Request::ConfigSet { .. }
        // FR-52 — the device-held external-access password: administrative,
        // like every config verb (`sudo roomler rc password …` on a system
        // install).
        | Request::ExternalPasswordSet { .. }
        | Request::ExternalPasswordClear
        | Request::ExternalPasswordStatus
        | Request::TailLog { .. }
        | Request::ExecRemote { .. }
        | Request::SshSession { .. }
        | Request::RecordStart { .. }
        | Request::RecordStop
        | Request::RecordingsList
        | Request::RecordingDelete { .. }
        | Request::RestartDaemon { .. }
        | Request::EncoderCaps
        | Request::HiveUpdateHold
        // FR-90 P3-9-2b — `roomler connect` lends the device OWNER's vault
        // grants: whoever sits at the screen need not be the owner.
        | Request::Connect { .. }
        | Request::ConnectStatus { .. } => false,
    }
}

/// FR-97 P2h — an answer as the person socket serves it. `Peers` keeps what
/// the companion draws (the link: online, direct or relayed and over what,
/// round trip, last seen) and loses what only an administrator debugging a
/// path needs: the endpoints of either end and of the relay (`relay_local`,
/// `relay_dst`, `relay_server`), the carrier's forensic snapshot (`debug`), the
/// path decision (`why`) and the prober's measurements (`probes`). Those name
/// other devices' public and LAN addresses. Everything else passes as it is.
pub fn person_view(resp: Response) -> Response {
    match resp {
        Response::Peers(mut peers) => {
            for p in &mut peers {
                p.relay_local = None;
                p.relay_dst = None;
                p.relay_server = None;
                p.debug = None;
                p.why = None;
                p.probes.clear();
            }
            Response::Peers(peers)
        }
        other => other,
    }
}

/// FR-27 P11 — the answer to anything else on the person-at-the-device socket.
fn not_on_the_person_socket() -> Response {
    Response::Error {
        message: "this is the person-at-the-device socket of a system install: it shows who is \
                  viewing this screen, ends it, answers consent prompts, and lists the devices \
                  this machine's private network reaches and its links to them. Everything else \
                  goes to the daemon's own socket — run `sudo roomler …`"
            .into(),
    }
}

/// Pure dispatch: map a [`Request`] to a [`Response`] over a state snapshot.
/// No I/O — the pipe listener (P1-cont) reads a JSON line, deserialises a
/// [`Request`], calls this, and writes the [`Response`] back.
pub fn handle(req: &Request, state: &dyn LocalApiState) -> Response {
    match req {
        Request::Status => Response::Status(Box::new(state.status())),
        Request::Peers => Response::Peers(state.peers()),
        Request::Flows => Response::Flows(state.flows()),
        Request::ConsentPending => Response::ConsentPending(state.consent_pending()),
        Request::ConsentDecide { session_id, allow } => Response::ConsentDecided {
            ok: state.consent_decide(session_id, *allow),
        },
        Request::RcSessions => Response::RcSessions(state.rc_sessions()),
        Request::RcDisconnect { session_id } => Response::RcDisconnected {
            ok: state.rc_disconnect(session_id),
        },
        Request::KillFlow { id } => Response::FlowKilled {
            ok: state.kill_flow(id),
        },
        Request::RouteList => Response::Routes(state.route_list()),
        // FR-84 D4 — sync by contract: a cached read, never a probe.
        Request::EncoderCaps => match state.encoder_caps() {
            Some(summary) => Response::EncoderCaps(summary),
            None => Response::Error {
                message: "encoder capabilities are not reported on this node".into(),
            },
        },
        // `Ping` / `Create*` / the mutating `Route*` verbs are async —
        // intercepted in `serve_connection` before this sync dispatch runs.
        // These arms only satisfy match exhaustiveness.
        Request::Ping { .. }
        | Request::CreateForward { .. }
        | Request::CreateSocks5 { .. }
        | Request::RouteAdd { .. }
        | Request::RouteRemove { .. }
        | Request::RouteSetEnabled { .. }
        | Request::RouteUpdate { .. }
        | Request::SetDeviceName { .. }
        | Request::ConfigCleanupStale
        | Request::ConfigGet
        | Request::ConfigSet { .. }
        | Request::ExternalPasswordSet { .. }
        | Request::ExternalPasswordClear
        | Request::ExternalPasswordStatus
        | Request::TailLog { .. }
        | Request::ExecRemote { .. }
        | Request::SshSession { .. }
        | Request::RecordStart { .. }
        | Request::RecordStop
        | Request::RecordStatus
        | Request::KeepBusyStatus
        | Request::KeepBusyOff
        | Request::KeepBusyOn { .. }
        | Request::RecordingsList
        | Request::RecordingDelete { .. }
        | Request::Devices { .. }
        | Request::Mesh { .. }
        | Request::RestartDaemon { .. }
        | Request::HiveUpdateHold
        | Request::Connect { .. }
        | Request::ConnectStatus { .. } => Response::Error {
            message: "this verb must be served on the async path".into(),
        },
    }
}

/// Serve one LocalAPI client connection to completion: read
/// newline-delimited JSON [`Request`]s, [`handle`] each against `state`,
/// write the newline-delimited JSON [`Response`] back, and loop until the
/// client closes the stream (EOF). A line that isn't a valid `Request`
/// gets an [`Response::Error`] and the connection stays open (so a client
/// can recover). **Transport-agnostic** — the platform listeners (Windows
/// named pipe with an ACL'd security descriptor, unix socket; P1-cont)
/// accept a connection and hand the accepted stream here. The daemon
/// spawns one task per connection: `serve_connection(stream, state.as_ref())`.
pub async fn serve_connection<S>(stream: S, state: &dyn LocalApiState) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    serve_connection_as(stream, state, ClientPeer::UNKNOWN).await
}

/// [`serve_connection`] with the peer the listener identified at accept time.
/// FR-85: the recording verbs and a `ConfigSet` of any `record_*` key require
/// [`ClientPeer::is_console_user`]; an unknown peer fails that check.
pub async fn serve_connection_as<S>(
    stream: S,
    state: &dyn LocalApiState,
    peer: ClientPeer,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    serve_connection_scoped(stream, state, peer, Scope::Full).await
}

/// [`serve_connection_as`] under a [`Scope`]. FR-27 P11: on a
/// [`Scope::Person`] connection, a request [`person_may`] does not allow is
/// answered with a refusal before it reaches any handler.
fn path_trial_observation_allowed(peer: &ClientPeer, scope: Scope) -> bool {
    scope == Scope::Full && peer.may_connect()
}

pub async fn serve_connection_scoped<S>(
    stream: S,
    state: &dyn LocalApiState,
    peer: ClientPeer,
    scope: Scope,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (rd, mut wr) = tokio::io::split(stream);
    let mut lines = tokio::io::BufReader::new(rd).lines();
    // FR-90 P1h-2 — a hold this connection placed ends with it, however it
    // ends: EOF, a read error, a write error.
    let mut held = false;
    // FR-90 P3-9-2b — and so does every endpoint it opened (decision 25:
    // `roomler connect` in the foreground).
    let mut opened: Vec<u64> = Vec::new();
    let served: std::io::Result<()> = async {
        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let resp = match serde_json::from_str::<Request>(&line) {
                // FR-27 P11 — on the person-at-the-device socket, anything but the
                // safety surface is refused before any handler runs.
                Ok(ref req) if scope == Scope::Person && !person_may(req) => {
                    not_on_the_person_socket()
                }
                // The async verbs — await them here; everything else is a pure sync
                // dispatch through `handle`.
                // FR-97 P2h — the network view, which a daemon may take from
                // another process (a two-half Mac's root half).
                Ok(Request::Status) => {
                    let mut status = state.status_view().await;
                    if !status.connected || !path_trial_observation_allowed(&peer, scope) {
                        status.path_trials = None;
                    }
                    Response::Status(Box::new(status))
                }
                Ok(Request::Peers) => Response::Peers(state.peers_view().await),
                Ok(Request::Ping {
                    target,
                    timeout_ms,
                    prefer_v6,
                }) => state.ping(&target, timeout_ms, prefer_v6).await,
                Ok(Request::CreateForward {
                    node,
                    local,
                    remote,
                    transport,
                    start_transport,
                }) => {
                    state
                        .create_forward(&node, local, &remote, &transport, &start_transport)
                        .await
                }
                Ok(Request::CreateSocks5 {
                    node,
                    local,
                    transport,
                }) => state.create_socks5(&node, local, &transport).await,
                Ok(Request::RouteAdd { route }) => state.route_add(route).await,
                Ok(Request::RouteRemove { id }) => state.route_remove(&id).await,
                Ok(Request::RouteSetEnabled { id, enabled }) => {
                    state.route_set_enabled(&id, enabled).await
                }
                Ok(Request::RouteUpdate { route }) => state.route_update(route).await,
                Ok(Request::SetDeviceName { name }) => state.set_device_name(&name).await,
                Ok(Request::ConfigCleanupStale) => state.config_cleanup_stale().await,
                Ok(Request::ConfigGet) => state.config_entries().await,
                // FR-85 — where recordings are written is the console user's call.
                Ok(Request::ConfigSet { key, .. })
                    if key.starts_with("record_") && !peer.is_console_user() =>
                {
                    not_the_console_user()
                }
                // FR-84 D4 — and so is where files dropped into the console
                // user's session land: the pipe admits RDP guests too, and one
                // must not steer another person's incoming files (say, into
                // their Startup folder). Equality, not a prefix match.
                Ok(Request::ConfigSet { key, .. })
                    if key == "files_dir" && !peer.is_console_user() =>
                {
                    Response::Error {
                        message: "only the person at this device's console can change where \
                              incoming files land"
                            .into(),
                    }
                }
                // FR-92 — and whether a controller may keep this console's
                // pointer moving: it is the console person's mouse. Equality.
                Ok(Request::ConfigSet { key, .. })
                    if key == "keep_busy_enabled" && !peer.is_console_user() =>
                {
                    Response::Error {
                        message: "only the person at this device's console can change \
                              whether keep busy is allowed here"
                            .into(),
                    }
                }
                // FR-99 — and whether a controller may cover this console's
                // screen: it is the console person who would sit in front of
                // the curtain. Equality.
                Ok(Request::ConfigSet { key, .. })
                    if key == "privacy_mode_allowed" && !peer.is_console_user() =>
                {
                    Response::Error {
                        message: "only the person at this device's console can change \
                              whether privacy mode is allowed here"
                            .into(),
                    }
                }
                // FR-99 P3 — and whether this console's screen is locked when a
                // remote session ends: it is the console person who would
                // have to sign in again. Equality.
                Ok(Request::ConfigSet { key, .. })
                    if key == "lock_on_end" && !peer.is_console_user() =>
                {
                    Response::Error {
                        message: "only the person at this device's console can change \
                              whether this computer locks when a remote session ends"
                            .into(),
                    }
                }
                // FR-108 — and whether a controller's display match may switch
                // this console's display mode: it is the console person whose
                // screen would change. Equality.
                Ok(Request::ConfigSet { key, .. })
                    if key == "display_match" && !peer.is_console_user() =>
                {
                    Response::Error {
                        message: "only the person at this device's console can change \
                              whether a remote session may switch this display"
                            .into(),
                    }
                }
                // FR-100 P1c — and whether this device checks the browsers that
                // connect to it: switching the check off weakens the console
                // person's own remote access, and the pipe admits RDP guests
                // and non-admins too. Equality.
                Ok(Request::ConfigSet { key, .. })
                    if key == "peer_auth" && !peer.is_console_user() =>
                {
                    Response::Error {
                        message: "only the person at this device's console can change \
                              whether this device checks the browsers that connect to it"
                            .into(),
                    }
                }
                // FR-101 P2b — and what a remote session may take from this
                // console: its clipboard, its files, its audio. Equality.
                Ok(Request::ConfigSet { key, .. })
                    if matches!(key.as_str(), "rc_clipboard" | "rc_files" | "rc_audio")
                        && !peer.is_console_user() =>
                {
                    Response::Error {
                        message: "only the person at this device's console can change what \
                              a remote session may use here (clipboard, files, audio)"
                            .into(),
                    }
                }
                // FR-101 P1b — and whether this device may reach its server
                // without TLS. Equality, like the arm above.
                Ok(Request::ConfigSet { key, .. })
                    if key == "allow_plaintext_server" && !peer.is_console_user() =>
                {
                    Response::Error {
                        message: "only the person at this device's console can let it reach \
                              its server without TLS"
                            .into(),
                    }
                }
                // FR-52 — and whether someone OUTSIDE the organization may
                // take this console's screen at all: gates 3–5 and the
                // password behind gate 4 are the console person's to give.
                // A prefix, like `record_`: the whole surface is one decision.
                Ok(Request::ConfigSet { key, .. })
                    if key.starts_with("external_") && !peer.is_console_user() =>
                {
                    not_the_console_user_for_external_access()
                }
                Ok(Request::ConfigSet { key, value }) => {
                    state.config_set(&key, value.as_deref()).await
                }
                Ok(Request::ExternalPasswordSet { .. } | Request::ExternalPasswordClear)
                    if !peer.is_console_user() =>
                {
                    not_the_console_user_for_external_access()
                }
                Ok(Request::ExternalPasswordSet { password }) => {
                    state.external_password_set(&password).await
                }
                Ok(Request::ExternalPasswordClear) => state.external_password_clear().await,
                // Read-only, and it never carries the record: anyone may ask.
                Ok(Request::ExternalPasswordStatus) => state.external_password_status().await,
                Ok(Request::TailLog { source, max_bytes }) => {
                    state.tail_log(&source, max_bytes).await
                }
                Ok(Request::ExecRemote {
                    node,
                    shell,
                    command,
                    timeout_ms,
                }) => state.exec_remote(&node, &shell, &command, timeout_ms).await,
                Ok(Request::SshSession {
                    node,
                    public_key,
                    session_secs,
                }) => state.ssh_session(&node, &public_key, session_secs).await,
                // FR-85 — recording. Reading state is open to every local client;
                // starting, stopping and deleting are the console user's alone.
                Ok(Request::RecordStatus) => state.record_status().await,
                Ok(Request::RecordingsList) => state.recordings_list().await,
                // FR-92 — keep busy: reading AND stopping are open to every
                // local client. Stopping is the safe direction.
                Ok(Request::KeepBusyStatus) => state.keep_busy_status().await,
                Ok(Request::KeepBusyOff) => state.keep_busy_off().await,
                // P10 — turning it ON is the console person's alone: root
                // never (how `roomler exec` arrives on Unix), session 0 never,
                // and (P10b) SYSTEM never — how exec arrives on a Windows
                // host in SystemContext mode. ⚠️ Not a wall against exec on an
                // attended Windows install, where it runs as the person
                // (FR-92 §3g).
                Ok(Request::KeepBusyOn { .. }) if !peer.may_start_keep_busy(scope) => {
                    not_the_person_for_keep_busy()
                }
                Ok(Request::KeepBusyOn { opts }) => state.keep_busy_on(opts).await,
                Ok(
                    Request::RecordStart { .. }
                    | Request::RecordStop
                    | Request::RecordingDelete { .. },
                ) if !peer.is_console_user() => not_the_console_user(),
                Ok(Request::RecordStart { opts }) => state.record_start(opts).await,
                Ok(Request::RecordStop) => state.record_stop().await,
                Ok(Request::RecordingDelete { name }) => state.recording_delete(&name).await,
                // FR-84 D5b — read-only, open to every local client like `Peers`.
                Ok(Request::Devices {
                    org,
                    page,
                    per_page,
                    q,
                    sort,
                    dir,
                }) => {
                    let query = DevicesQuery {
                        page,
                        per_page,
                        q,
                        sort,
                        dir,
                    };
                    state.devices(&org, &query).await
                }
                Ok(Request::Mesh { org }) => state.mesh(&org).await,
                // FR-84 D3 — the daemon decides (and records) here; it leaves only
                // after the answer below is on the wire.
                Ok(Request::RestartDaemon { reason }) => state.restart_daemon(&reason).await,
                // FR-90 P1h-2 — root alone holds the daemon for an update: the
                // hold refuses every new agent prompt and start until it ends.
                Ok(Request::HiveUpdateHold) if !peer.is_root() => Response::Error {
                    message: "only root may hold this daemon for an update".into(),
                },
                Ok(Request::HiveUpdateHold) => state.hive_update_hold().await,
                // FR-90 P3-9-2b (decision 26) — `roomler connect` lends the
                // device owner's grants: root or SYSTEM, an elevated
                // administrator, or the daemon's own account. The endpoint
                // serves the account that asked, as the OS read it.
                Ok(Request::Connect { .. }) if !peer.may_connect() => not_one_who_may_connect(),
                Ok(Request::Connect { args }) => match peer.asker() {
                    Some(asker) => state.connect(&asker, &args).await,
                    None => Response::Error {
                        message: "this device could not read which account asked, so it \
                                  serves none"
                            .into(),
                    },
                },
                // Only an endpoint this connection opened: another
                // connection's may be another account's.
                Ok(Request::ConnectStatus { id }) if !opened.contains(&id) => Response::Error {
                    message: format!("no endpoint {id} was opened on this connection"),
                },
                Ok(Request::ConnectStatus { id }) => state.connect_status(id),
                Ok(req) => handle(&req, state),
                Err(e) => Response::Error {
                    message: format!("bad request: {e}"),
                },
            };
            // FR-97 P2h — what the person socket serves leaves out what only
            // an administrator needs (see `person_view`).
            let resp = if scope == Scope::Person {
                person_view(resp)
            } else {
                resp
            };
            let restart_accepted = matches!(resp, Response::DaemonRestarting { .. });
            held |= matches!(resp, Response::HiveUpdateHeld { .. });
            // Kept before the answer is written: a client gone by then still
            // has its endpoint closed below.
            if let Response::Connected { id, .. } = &resp {
                opened.push(*id);
            }
            // A Response always serialises; fall back to an Error line if a
            // custom serializer ever failed, so we never break the frame.
            let mut out = serde_json::to_vec(&resp).unwrap_or_else(|e| {
                serde_json::to_vec(&Response::Error {
                    message: format!("encode error: {e}"),
                })
                .expect("Error response always serialises")
            });
            out.push(b'\n');
            let written = async {
                wr.write_all(&out).await?;
                wr.flush().await
            }
            .await;
            if restart_accepted {
                // FR-84 D3 — the answer is out (or the caller is gone; the
                // restart was accepted and recorded either way): only NOW may the
                // shutdown begin.
                state.restart_commit();
            }
            written?;
        }
        Ok(())
    }
    .await;
    if held {
        state.hive_update_release();
    }
    for id in opened {
        state.connect_release(id);
    }
    served
}

// ---------------------------------------------------------------------------
// Platform listener (unification P1-cont)
//
// The daemon (`roomlerd` / today's `roomlerd`) calls [`serve`] once at
// startup. It binds the local-only control endpoint — a named pipe on Windows,
// a unix socket elsewhere — restricts it to trusted local principals via the
// pipe/socket ACL (no token: the OS enforces WHO can connect), and serves each
// accepted connection with [`serve_connection`]. Returns when `shutdown` flips
// true (or on a fatal bind error, which the daemon logs without dying).
// ---------------------------------------------------------------------------

/// Bind the platform LocalAPI endpoint and serve clients until `shutdown`
/// fires. Auth is the endpoint ACL, not a token:
/// - **Windows**: named pipe `\\.\pipe\roomler` with a security descriptor
///   granting only `SYSTEM`, `Administrators`, and the interactive user — so a
///   low-privilege local process can't read node state (and, once mutating
///   verbs land in P2, can't drive the daemon).
/// - **Unix**: socket at `$XDG_RUNTIME_DIR/roomler.sock` (per-user, 0700 dir),
///   chmod `0600` — owner-only.
///
/// Each accepted connection is served on its own task; a slow or misbehaving
/// client can't stall the accept loop or another client.
///
/// Uses the built-in listening-instance pool ([`DEFAULT_PIPE_POOL`]); the
/// daemon threads its configured `localapi_pipe_pool` through
/// [`serve_with_pool`] instead.
pub async fn serve(
    state: Arc<dyn LocalApiState>,
    shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    serve_with_pool(state, shutdown, DEFAULT_PIPE_POOL).await
}

/// [`serve`] with an explicit named-pipe listener pool size (FR-84 D1).
///
/// `pipe_pool` is how many pipe instances stay LISTENING at once on Windows
/// (clamped to `1..=`[`MAX_PIPE_POOL`]); `1` is the pre-FR-84 single
/// instance. The unix socket has a kernel accept backlog and ignores it.
pub async fn serve_with_pool(
    state: Arc<dyn LocalApiState>,
    shutdown: watch::Receiver<bool>,
    pipe_pool: u32,
) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        serve_windows(state, shutdown, pipe_pool).await
    }
    #[cfg(not(windows))]
    {
        let _ = pipe_pool;
        serve_unix(state, shutdown).await
    }
}

/// FR-84 D1 — the built-in number of named-pipe instances kept listening
/// (`localapi_pipe_pool` unset). Four covers the companion's worst measured
/// burst — device view, routes and flows opening within the same
/// millisecond — with one to spare for the CLI.
pub const DEFAULT_PIPE_POOL: u32 = 4;

/// Upper bound on the listener pool. Each instance is a kernel object plus
/// a parked accept task; beyond this a burst that large is a bug elsewhere.
pub const MAX_PIPE_POOL: u32 = 16;

/// The pool size the listener actually runs with for a configured value:
/// `None` ⇒ [`DEFAULT_PIPE_POOL`], anything else clamped to
/// `1..=`[`MAX_PIPE_POOL`]. `1` is the kill switch (one listening instance,
/// the pre-FR-84 behaviour).
pub fn effective_pipe_pool(configured: Option<u32>) -> u32 {
    configured
        .unwrap_or(DEFAULT_PIPE_POOL)
        .clamp(1, MAX_PIPE_POOL)
}

// ---- Windows: named pipe + SDDL security descriptor ----------------------

/// The LocalAPI named-pipe path. Fixed name so thin clients (CLI, desktop app)
/// know where to connect.
#[cfg(windows)]
const LOCALAPI_PIPE_NAME: &str = r"\\.\pipe\roomler";

/// SDDL for the pipe. DACL: allow (`A`) generic-all (`GA`) to Local `SY`stem,
/// `B`uiltin `A`dministrators, and `I`nteractive `U`sers — and, by omission,
/// deny everyone else. IU covers the desktop app / CLI running in the operator's
/// interactive session (including a non-elevated admin, whose Administrators SID
/// is deny-only but who still matches IU). No OWNER is set — a user-mode daemon
/// can't assign one it doesn't hold, and the creator is a valid owner anyway.
///
/// SACL `S:(ML;;NW;;;ME)` — a mandatory-integrity label at **Medium** with
/// No-Write-Up: a process **below** medium integrity (an AppContainer / sandboxed
/// browser child / low-IL malware) can't write to the pipe, so it can't send a
/// request at all — hardening the (mutating) consent verb against a low-IL
/// caller (P2b security review H1). The interactive user's tray + CLI run at
/// medium IL and SYSTEM above it, so both are unaffected. Setting a label at or
/// below the creator's own IL needs no privilege.
#[cfg(windows)]
const LOCALAPI_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)S:(ML;;NW;;;ME)";

/// `SDDL_REVISION_1` — the only defined SDDL revision.
#[cfg(windows)]
const SDDL_REVISION_1: u32 = 1;

/// A security descriptor built from an SDDL string plus the
/// `SECURITY_ATTRIBUTES` that `create_with_security_attributes_raw` consumes.
/// Owns the `LocalAlloc`'d descriptor and `LocalFree`s it on drop.
#[cfg(windows)]
struct PipeSecurity {
    sa: windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
    psd: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
}

// SAFETY: the security descriptor is a plain `LocalAlloc`'d heap buffer with no
// thread affinity — moving ownership of `PipeSecurity` (and thus the pointer)
// to another thread and calling `LocalFree` there is sound. Needed because the
// accept loop holds it across `.await`, so `localapi::serve`'s future must be
// `Send` for `tokio::spawn`.
#[cfg(windows)]
unsafe impl Send for PipeSecurity {}

#[cfg(windows)]
impl PipeSecurity {
    fn new(sddl: &str) -> std::io::Result<Self> {
        use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
        use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `wide` is a NUL-terminated UTF-16 buffer; `psd` is a valid
        // out-pointer; the size-out argument is null (documented optional).
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut psd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: psd,
            bInheritHandle: 0,
        };
        Ok(Self { sa, psd })
    }

    /// Pointer to the `SECURITY_ATTRIBUTES`, valid while `self` lives. The OS
    /// copies the descriptor when the pipe instance is created, so reusing this
    /// across instances is fine.
    fn as_ptr(&mut self) -> *mut core::ffi::c_void {
        &raw mut self.sa as *mut core::ffi::c_void
    }
}

#[cfg(windows)]
impl Drop for PipeSecurity {
    fn drop(&mut self) {
        if !self.psd.is_null() {
            // SAFETY: `psd` was allocated by ConvertStringSecurityDescriptor…
            // (LocalAlloc); LocalFree is the documented release.
            unsafe {
                windows_sys::Win32::Foundation::LocalFree(self.psd as _);
            }
        }
    }
}

#[cfg(windows)]
async fn serve_windows(
    state: Arc<dyn LocalApiState>,
    shutdown: watch::Receiver<bool>,
    pipe_pool: u32,
) -> std::io::Result<()> {
    serve_windows_at(LOCALAPI_PIPE_NAME, state, shutdown, pipe_pool).await
}

/// The named-pipe listener, parameterised on the pipe name so tests can use a
/// private one. Binds the FIRST instance (retrying while another process
/// holds the name), then runs a POOL of `pipe_pool` accept tasks, each owning
/// one listening instance — so there is never a moment with zero listening
/// instances, which is what a client sees as `ERROR_PIPE_BUSY`.
///
/// Before FR-84 there was exactly one listening instance, and its replacement
/// was created only after `connect()` had returned to this task. A client
/// opening the pipe in that gap — or while the one instance was already taken
/// — was refused on the spot (`CreateFileW` does not wait). The desktop
/// companion opens three connections within the same millisecond every 2 s,
/// and the raw 3-open probe measured on the reporting host had open #2 fail
/// 60/60 times. With `pipe_pool = 1` this is exactly the old behaviour (the
/// kill switch); with N, up to N clients can open back-to-back and each
/// accept task re-creates its own instance after handing the connected one
/// off.
#[cfg(windows)]
pub(crate) async fn serve_windows_at(
    pipe_name: &str,
    state: Arc<dyn LocalApiState>,
    mut shutdown: watch::Receiver<bool>,
    pipe_pool: u32,
) -> std::io::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    if *shutdown.borrow() {
        return Ok(());
    }
    let pool = effective_pipe_pool(Some(pipe_pool));
    let mut security = PipeSecurity::new(LOCALAPI_SDDL)?;
    // Retry the FIRST-instance create instead of failing permanently. If another
    // process already holds `\\.\pipe\roomler` (a stale/leftover agent, or a
    // rogue squatter), a one-shot bind would leave the LocalAPI dead until the
    // daemon restarts — and a squatter keeps feeding thin clients FAKE data
    // (field-observed: a leftover test server made the tray show mock peers +
    // no consent prompts). Retrying every 30 s self-heals the moment the pipe
    // frees, with a loud warning so the operator sees the contention.
    //
    // SAFETY: `security.as_ptr()` stays valid for the lifetime of `security`,
    // which outlives every create call below.
    let first = loop {
        match unsafe {
            ServerOptions::new()
                .first_pipe_instance(true)
                .create_with_security_attributes_raw(pipe_name, security.as_ptr())
        } {
            Ok(s) => break s,
            Err(e) => {
                tracing::warn!(
                    pipe = pipe_name, error = %e,
                    "localapi: pipe bind failed — another process may hold the pipe; retrying in 30s"
                );
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() { return Ok(()); }
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {}
                }
            }
        }
    };

    // The spare instances. Only the very first create above may claim
    // `first_pipe_instance`; these join the name the first one now owns. Each
    // accept task gets its own `PipeSecurity` (it is `Send`, not `Sync`).
    // Best-effort: a spare that cannot be created degrades the pool, it does
    // not take the listener down — slot 0 still serves.
    let mut spares = Vec::new();
    for slot in 1..pool {
        let mut sec = match PipeSecurity::new(LOCALAPI_SDDL) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(slot, error = %e, "localapi: pipe pool slot skipped (security descriptor)");
                break;
            }
        };
        match create_pipe_instance(pipe_name, &mut sec) {
            Ok(server) => {
                spares.push(tokio::spawn(accept_pipe(
                    pipe_name.to_string(),
                    slot,
                    server,
                    sec,
                    state.clone(),
                    shutdown.clone(),
                )));
            }
            Err(e) => {
                tracing::warn!(slot, error = %e, "localapi: pipe pool slot skipped (create failed)");
                break;
            }
        }
    }
    tracing::info!(
        pipe = pipe_name,
        pool = spares.len() + 1,
        "localapi: named-pipe listener up (SYSTEM + Administrators + interactive user)"
    );

    // Slot 0 runs inline; every slot exits on the same shutdown watch, and
    // the abort below is only a belt for the case where slot 0 returns first.
    let result = accept_pipe(pipe_name.to_string(), 0, first, security, state, shutdown).await;
    for task in spares {
        task.abort();
    }
    result
}

/// One more listening instance of an already-bound pipe.
///
/// SAFETY: `security.as_ptr()` is valid for the lifetime of `security`; the OS
/// copies the descriptor into the new instance.
#[cfg(windows)]
fn create_pipe_instance(
    pipe_name: &str,
    security: &mut PipeSecurity,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use tokio::net::windows::named_pipe::ServerOptions;
    // SAFETY: see the function doc — the pointer outlives the call and the
    // kernel copies the descriptor.
    unsafe {
        ServerOptions::new().create_with_security_attributes_raw(pipe_name, security.as_ptr())
    }
}

/// One pool slot: own a listening instance, and on every client connect hand
/// the connected instance to its own task and re-create the listener. A
/// re-create that fails is retried (bounded by `shutdown`) rather than ending
/// the slot — with one slot that would be today's whole listener dying.
#[cfg(windows)]
async fn accept_pipe(
    pipe_name: String,
    slot: u32,
    first: tokio::net::windows::named_pipe::NamedPipeServer,
    mut security: PipeSecurity,
    state: Arc<dyn LocalApiState>,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    const RETRY: std::time::Duration = std::time::Duration::from_millis(200);
    let mut listening = Some(first);
    loop {
        let Some(server) = listening.as_mut() else {
            // The replacement create failed after the last handoff; this slot
            // is dark until it succeeds.
            match create_pipe_instance(&pipe_name, &mut security) {
                Ok(s) => listening = Some(s),
                Err(e) => {
                    tracing::warn!(slot, error = %e, "localapi: pipe instance create failed; retrying");
                    tokio::select! {
                        biased;
                        _ = shutdown.changed() => {
                            if *shutdown.borrow() { return Ok(()); }
                        }
                        _ = tokio::time::sleep(RETRY) => {}
                    }
                }
            }
            continue;
        };
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!(slot, "localapi: shutdown; pipe listener exiting");
                    return Ok(());
                }
            }
            conn = server.connect() => match conn {
                Ok(()) => {
                    let connected = listening.take().expect("a connected instance");
                    // Re-create BEFORE handing off, so with a pool of one the
                    // gap is no wider than it ever was; a failure here is
                    // retried at the top of the loop, after the client is served.
                    match create_pipe_instance(&pipe_name, &mut security) {
                        Ok(next) => listening = Some(next),
                        Err(e) => {
                            tracing::warn!(slot, error = %e, "localapi: pipe instance re-create failed; will retry");
                        }
                    }
                    let st = state.clone();
                    // FR-85 — who connected, from the OS, before a byte is read
                    // (P10b: and as which account).
                    let peer = {
                        use std::os::windows::io::AsRawHandle;
                        pipe_client_peer(connected.as_raw_handle())
                    };
                    tokio::spawn(async move {
                        if let Err(e) = serve_connection_as(connected, &*st, peer).await {
                            tracing::debug!(error = %e, "localapi: pipe client ended");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(slot, error = %e, "localapi: pipe connect failed; retrying");
                    tokio::time::sleep(RETRY).await;
                }
            }
        }
    }
}

// ---- Unix: socket in the per-user runtime dir, chmod 0600 -----------------

/// The LocalAPI socket file name (under the per-user runtime dir).
#[cfg(unix)]
const LOCALAPI_SOCKET_NAME: &str = "roomler.sock";

/// Well-known home for a SYSTEM (root) daemon's control socket.
///
/// A per-user path cannot serve a root daemon. On macOS `temp_dir()` is
/// already per-user (`/var/folders/…`), so a root daemon's socket would land
/// in ROOT's folder and a user-session `roomler peers` would look in its own
/// and find *nothing* — not a permission error, an apparent absence. That is
/// the trap the macOS LaunchDaemon split walks into, and this is the fix:
/// when the process can own `/var/run/roomler`, it is the daemon and the
/// socket goes somewhere every session can name.
#[cfg(unix)]
const LOCALAPI_SYSTEM_DIR: &str = "/var/run/roomler";

/// The PER-USER socket path — `$XDG_RUNTIME_DIR/roomler.sock` when the
/// runtime dir is set (systemd guarantees it's 0700 + user-owned — the right
/// home for a control socket), else a `roomler/` subdir under the temp dir
/// (locked to 0700 by the listener). The socket itself is chmod 0600.
#[cfg(unix)]
pub(crate) fn user_socket_path() -> std::path::PathBuf {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        return std::path::PathBuf::from(dir).join(LOCALAPI_SOCKET_NAME);
    }
    // No runtime dir (common on macOS, where temp_dir() is already per-user).
    std::env::temp_dir()
        .join("roomler")
        .join(LOCALAPI_SOCKET_NAME)
}

/// The SYSTEM socket path, used by a daemon privileged enough to bind it,
/// and by the root update helper (FR-90 P1h-2), which holds THAT daemon.
#[cfg(unix)]
pub fn system_socket_path() -> std::path::PathBuf {
    std::path::PathBuf::from(LOCALAPI_SYSTEM_DIR).join(LOCALAPI_SOCKET_NAME)
}

/// Where a CLIENT looks, in order: a per-user daemon first (unchanged fast
/// path for every existing install), then the system daemon.
#[cfg(unix)]
pub(crate) fn unix_socket_candidates() -> [std::path::PathBuf; 2] {
    [user_socket_path(), system_socket_path()]
}

/// Bind the daemon's control socket, preferring the SYSTEM path.
///
/// Which path is right depends on whether this process is privileged, and
/// rather than ask (`geteuid` would mean a `libc` dependency for one call —
/// and a uid is only a PROXY for the thing we actually need) this TESTS the
/// capability: if `/var/run/roomler` can be created and bound, we are the
/// system daemon and belong there. An unprivileged daemon fails that and
/// keeps exactly its current per-user path.
///
/// A system daemon ALSO binds the per-user path, best-effort. That is
/// forward-compat for one release, the same shape as the P2a rollout: a
/// `roomler` CLI that predates this change only knows the per-user path, and
/// packaging does not guarantee the CLI and the daemon step forward in the
/// same instant. Drop the second bind once the fleet is past it.
#[cfg(unix)]
async fn serve_unix(
    state: Arc<dyn LocalApiState>,
    shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let system = system_socket_path();
    match prepare_unix_listener(&system) {
        Ok(listener) => {
            tracing::info!(
                path = %system.display(),
                "localapi: system-daemon socket (privileged); a user session reaches it here"
            );
            let legacy = user_socket_path();
            if let Ok(l) = prepare_unix_listener(&legacy) {
                let st = state.clone();
                let sd = shutdown.clone();
                tracing::info!(
                    path = %legacy.display(),
                    "localapi: also serving the legacy per-user path (pre-split CLIs)"
                );
                tokio::spawn(async move { accept_unix(l, legacy, st, sd).await });
            }
            accept_unix(listener, system, state, shutdown).await
        }
        Err(e) => {
            tracing::debug!(
                path = %system.display(), error = %e,
                "localapi: not privileged for the system socket; using the per-user path"
            );
            serve_unix_at(user_socket_path(), state, shutdown).await
        }
    }
}

/// The unix-socket accept loop, parameterised on the path so tests can use a
/// private one.
#[cfg(unix)]
pub(crate) async fn serve_unix_at(
    path: std::path::PathBuf,
    state: Arc<dyn LocalApiState>,
    shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    if *shutdown.borrow() {
        return Ok(());
    }
    let listener = prepare_unix_listener(&path)?;
    accept_unix(listener, path, state, shutdown).await
}

/// Create the parent dir, clear a stale socket, bind, and lock the socket to
/// 0600. Split out from the accept loop so a caller can TEST whether a path is
/// bindable (the privileged-vs-per-user decision) without committing to
/// serving it forever.
#[cfg(unix)]
fn prepare_unix_listener(path: &std::path::Path) -> std::io::Result<tokio::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        // Lock the parent to owner-only when we own it (the temp-subdir case);
        // for $XDG_RUNTIME_DIR this is already true and the chmod is harmless
        // (ignored if we don't own it).
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    // A stale socket from an unclean exit makes bind fail with EADDRINUSE.
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    // Owner-only: no other local user can open the control socket.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    tracing::info!(path = %path.display(), "localapi: unix-socket listener up (0600)");
    Ok(listener)
}

#[cfg(unix)]
async fn accept_unix(
    listener: tokio::net::UnixListener,
    path: std::path::PathBuf,
    state: Arc<dyn LocalApiState>,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    let _ = std::fs::remove_file(&path);
                    tracing::info!("localapi: shutdown; unix listener exiting");
                    return Ok(());
                }
            }
            accept = listener.accept() => match accept {
                Ok((stream, _addr)) => {
                    let st = state.clone();
                    // FR-85 — who connected, from the kernel (SO_PEERCRED);
                    // FR-90 P3-9-2b — its gid with its uid.
                    let cred = stream.peer_cred().ok();
                    let peer = ClientPeer {
                        uid: cred.map(|c| c.uid()),
                        gid: cred.map(|c| c.gid()),
                        ..ClientPeer::UNKNOWN
                    };
                    tokio::spawn(async move {
                        if let Err(e) = serve_connection_as(stream, &*st, peer).await {
                            tracing::debug!(error = %e, "localapi: unix client ended");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "localapi: unix accept failed; retrying");
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            }
        }
    }
}

/// FR-27 P11 — where a Linux system install's person-at-the-device socket
/// lives: that person's own `$XDG_RUNTIME_DIR/roomler.sock` (logind's
/// `/run/user/<uid>`). Their companion and their CLI already try it FIRST
/// ([`unix_socket_candidates`]), so neither needs to know it exists.
#[cfg(target_os = "linux")]
pub fn person_socket_path(uid: u32) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("/run/user/{uid}")).join(LOCALAPI_SOCKET_NAME)
}

/// FR-97 P2g — where a Mac's ROOT half serves the console user's person socket.
/// Not in a directory of theirs, as on Linux: on a Mac the per-user half
/// already serves that person a socket of its own (in their temp dir), which
/// is what their companion and CLI talk to. This one is what the per-user half
/// asks for the machine's private-network view (Devices and Mesh), which only
/// the root half has, since only root can hold a utun.
#[cfg(target_os = "macos")]
pub const MACOS_PERSON_SOCKET_DIR: &str = "/var/run/roomler-person";

/// FR-97 P2g — see [`MACOS_PERSON_SOCKET_DIR`].
#[cfg(target_os = "macos")]
pub fn person_socket_path(uid: u32) -> std::path::PathBuf {
    std::path::PathBuf::from(MACOS_PERSON_SOCKET_DIR).join(format!("{uid}.sock"))
}

/// FR-27 P11 — the caller check on the person socket, per connection, from
/// the kernel (`SO_PEERCRED`): the person it belongs to, or root. Unknown is
/// neither.
#[cfg(unix)]
pub fn person_peer_ok(peer: &ClientPeer, owner_uid: u32) -> bool {
    matches!(peer.uid, Some(u) if u == owner_uid || u == 0)
}

/// FR-27 P11 — serve the person-at-the-device socket for `owner_uid` until
/// `stop` flips true (or its sender goes away).
///
/// A Linux system daemon's own socket (`/var/run/roomler`, 0700 / 0600) is
/// root-only, and rightly: it is the trust boundary for every administrative
/// verb. But the person at the screen must still be able to see who is
/// viewing it, end that, and answer a consent prompt, and their companion runs
/// as them (#1911). This socket gives them exactly that and nothing more:
/// - it lives in THEIR runtime dir, which logind created and they own — this
///   function never creates it, and refuses a dir owned by anyone else;
/// - it is made AS THEM ([`bind_as_person`]), so it is theirs and 0600 from
///   the start, and no path operation runs with root's rights in their dir;
/// - every connection's `SO_PEERCRED` uid must be theirs or root
///   ([`person_peer_ok`]) — that check, not the file's mode, is what keeps
///   every other account out;
/// - every request goes through [`Scope::Person`] ([`person_may`]).
///
/// ⚠️ It never replaces a LIVE socket at that path (a per-user daemon of the
/// same person would own it), removes a stale file only if it IS a socket,
/// and on the way out unlinks only the entry it bound (`lstat`, never
/// following a link).
///
/// FR-97 P2g — a Mac's root half serves one too, at [`person_socket_path`]
/// in a directory only root can write ([`bind_person_socket`]), with the same
/// per-connection uid check and the same [`Scope::Person`].
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub async fn serve_person_socket(
    path: std::path::PathBuf,
    owner_uid: u32,
    state: Arc<dyn LocalApiState>,
    mut stop: watch::Receiver<bool>,
) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    use tokio::net::UnixListener;

    if *stop.borrow() {
        return Ok(());
    }
    let (std_listener, bound_ino) = bind_person_socket(path.clone(), owner_uid).await?;
    std_listener.set_nonblocking(true)?;
    let listener = UnixListener::from_std(std_listener)?;
    tracing::info!(
        path = %path.display(), uid = owner_uid,
        "localapi: person-at-the-device socket up (FR-27 P11)"
    );
    // ⚠️ Connections are held HERE, not detached: when the person at the seat
    // changes this listener is stopped, and a connection the previous person
    // still holds open must not keep answering consent for the new person's
    // screen. Stopping aborts every one of them.
    let mut conns = tokio::task::JoinSet::new();
    let served = loop {
        tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    break Ok(());
                }
            }
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
            accept = listener.accept() => match accept {
                Ok((stream, _addr)) => {
                    let cred = stream.peer_cred().ok();
                    let peer = ClientPeer {
                        uid: cred.map(|c| c.uid()),
                        gid: cred.map(|c| c.gid()),
                        ..ClientPeer::UNKNOWN
                    };
                    if !person_peer_ok(&peer, owner_uid) {
                        tracing::warn!(
                            peer_uid = ?peer.uid, owner_uid,
                            "localapi: person socket refused a caller that is neither its person nor root"
                        );
                        continue;
                    }
                    let st = state.clone();
                    conns.spawn(async move {
                        if let Err(e) = serve_connection_scoped(stream, &*st, peer, Scope::Person).await {
                            tracing::debug!(error = %e, "localapi: person-socket client ended");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "localapi: person-socket accept failed; retrying");
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            }
        }
    };
    conns.shutdown().await;
    if matches!(std::fs::symlink_metadata(&path), Ok(m) if m.ino() == bound_ino) {
        let _ = std::fs::remove_file(&path);
    }
    tracing::info!(path = %path.display(), "localapi: person-at-the-device socket down");
    served
}

/// FR-27 P11 — the Linux bind: in the person's own runtime dir, which logind
/// made and they own (this never creates it, and refuses a dir owned by anyone
/// else), and AS them ([`bind_as_person`]).
#[cfg(target_os = "linux")]
async fn bind_person_socket(
    path: std::path::PathBuf,
    owner_uid: u32,
) -> std::io::Result<(std::os::unix::net::UnixListener, u64)> {
    use std::io::{Error, ErrorKind};
    use std::os::unix::fs::MetadataExt;
    let dir = path
        .parent()
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "person socket path has no parent"))?;
    let dir_meta = std::fs::metadata(dir)?;
    if !dir_meta.is_dir() || dir_meta.uid() != owner_uid {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "{} is not a directory owned by uid {owner_uid}",
                dir.display()
            ),
        ));
    }
    let owner_gid = dir_meta.gid();
    tokio::task::spawn_blocking(move || bind_as_person(&path, owner_uid, owner_gid))
        .await
        .map_err(|e| Error::other(format!("person socket: the bind task failed: {e}")))?
}

/// FR-97 P2g — the Mac bind: in [`MACOS_PERSON_SOCKET_DIR`], a directory
/// ROOT owns and only root can write, so no one else can make, swap or link an
/// entry in it. That is what lets root bind and then hand the socket over,
/// which on Linux, in the person's own dir, is the race [`bind_as_person`]
/// exists to avoid (macOS has no per-thread filesystem ids to borrow).
#[cfg(target_os = "macos")]
async fn bind_person_socket(
    path: std::path::PathBuf,
    owner_uid: u32,
) -> std::io::Result<(std::os::unix::net::UnixListener, u64)> {
    tokio::task::spawn_blocking(move || bind_root_owned(&path, owner_uid))
        .await
        .map_err(|e| std::io::Error::other(format!("person socket: the bind task failed: {e}")))?
}

/// FR-97 P2g — the directory check of [`bind_root_owned`], on plain facts so
/// it is tested on every platform: a real directory (not a link to one),
/// root's, and writable by nobody else.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn root_only_dir(is_dir: bool, is_symlink: bool, uid: u32, mode: u32) -> bool {
    is_dir && !is_symlink && uid == 0 && mode & 0o022 == 0
}

/// FR-97 P2g — see [`bind_person_socket`]. Makes the directory 0755 if it is
/// missing (under `/var/run` only root can), refuses one that is not
/// [`root_only_dir`], clears a stale socket (never anything else), binds, and
/// only then gives the socket to the person, 0600. Nothing is accepted before
/// that, and every connection is checked against the person or root
/// ([`person_peer_ok`]) whatever the mode was in between. The `chmod` follows
/// links, which is safe only because nobody but root can change an entry in
/// this directory. Returns the listener and its inode.
#[cfg(target_os = "macos")]
fn bind_root_owned(
    path: &std::path::Path,
    uid: u32,
) -> std::io::Result<(std::os::unix::net::UnixListener, u64)> {
    use std::io::{Error, ErrorKind};
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
    let dir = path
        .parent()
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "person socket path has no parent"))?;
    if let Err(e) = std::fs::symlink_metadata(dir) {
        if e.kind() != ErrorKind::NotFound {
            return Err(e);
        }
        std::fs::DirBuilder::new().mode(0o755).create(dir)?;
        // The mode above is under the umask; the person must be able to
        // search the directory to reach their socket in it.
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
    }
    let m = std::fs::symlink_metadata(dir)?;
    if !root_only_dir(m.is_dir(), m.file_type().is_symlink(), m.uid(), m.mode()) {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "{} is not a directory only root owns and writes",
                dir.display()
            ),
        ));
    }
    if std::os::unix::net::UnixStream::connect(path).is_ok() {
        return Err(Error::new(
            ErrorKind::AddrInUse,
            format!("{} is already served by another process", path.display()),
        ));
    }
    if let Ok(m) = std::fs::symlink_metadata(path) {
        if !m.file_type().is_socket() {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
        std::fs::remove_file(path)?;
    }
    let listener = std::os::unix::net::UnixListener::bind(path)?;
    std::os::unix::fs::lchown(path, Some(uid), None)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    let ino = std::fs::symlink_metadata(path)?.ino();
    Ok((listener, ino))
}

/// FR-27 P11 — make the person socket AS the person: check the path, clear a
/// stale socket, bind, and chmod 0600, all with THIS thread's filesystem ids
/// switched to theirs. Returns the listener and the inode it bound.
///
/// ⚠️ Load-bearing, not tidiness. The socket's directory belongs to the
/// person, so they can swap its entry between any two calls the daemon makes
/// on the PATH, and `chmod` and `chown` follow symlinks. A root daemon that
/// bound the socket and then chown'ed the path could be raced into handing
/// them `/etc/shadow`. With `setfsuid`/`setfsgid` (per-thread on Linux; glibc
/// broadcasts only the POSIX set*id calls to every thread) the socket is born
/// theirs, so there is no chown at all, and whatever a swapped entry
/// redirects to is reached with THEIR rights, i.e. only what they already
/// own. The previous ids are restored on every way out, error and panic
/// included, before this blocking-pool thread serves anything else.
#[cfg(target_os = "linux")]
fn bind_as_person(
    path: &std::path::Path,
    uid: u32,
    gid: u32,
) -> std::io::Result<(std::os::unix::net::UnixListener, u64)> {
    use std::io::{Error, ErrorKind};
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    struct Restore {
        uid: u32,
        gid: u32,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            // SAFETY: setfsuid/setfsgid change only this thread's filesystem
            // ids. The uid first, which brings back the filesystem
            // capabilities a non-zero fsuid drops.
            unsafe {
                libc::setfsuid(self.uid);
                libc::setfsgid(self.gid);
            }
        }
    }
    // SAFETY: as above. The group first, while the fsuid is still ours.
    let prev_gid = unsafe { libc::setfsgid(gid) } as u32;
    let prev_uid = unsafe { libc::setfsuid(uid) } as u32;
    let _restore = Restore {
        uid: prev_uid,
        gid: prev_gid,
    };
    // Both calls report the PREVIOUS id and fail silently; an invalid id
    // changes nothing and reports the current one, which proves the switch.
    // SAFETY: as above.
    let (now_uid, now_gid) = unsafe {
        (
            libc::setfsuid(u32::MAX) as u32,
            libc::setfsgid(u32::MAX) as u32,
        )
    };
    if now_uid != uid || now_gid != gid {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!("could not act as uid {uid} to make its person socket"),
        ));
    }
    if std::os::unix::net::UnixStream::connect(path).is_ok() {
        return Err(Error::new(
            ErrorKind::AddrInUse,
            format!("{} is already served by another process", path.display()),
        ));
    }
    if let Ok(m) = std::fs::symlink_metadata(path) {
        if !m.file_type().is_socket() {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
        std::fs::remove_file(path)?;
    }
    let listener = std::os::unix::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    let ino = std::fs::symlink_metadata(path)?.ino();
    Ok((listener, ino))
}

// ---------------------------------------------------------------------------
// Client (unification P2)
//
// The thin clients — the CLI (`roomler`) and the desktop app — connect to the
// daemon's LocalAPI over the same platform endpoint the server binds and issue
// read-only requests. Lives in-module so it shares the endpoint constants
// (`LOCALAPI_PIPE_NAME` / `unix_socket_candidates`) and the wire types with the
// server: one source of truth, no re-declared pipe name.
// ---------------------------------------------------------------------------

/// A boxed local-endpoint stream (Windows named pipe or unix socket) — both are
/// `AsyncRead + AsyncWrite`, so the client is transport-agnostic like the
/// server's [`serve_connection`].
trait ClientStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> ClientStream for T {}

/// A connected LocalAPI client. Open with [`connect`], then issue requests one
/// at a time. The daemon serves multiple requests on one connection, so a
/// single `Client` is reused across a poll (e.g. `status()` then `peers()`).
pub struct Client {
    stream: tokio::io::BufReader<Box<dyn ClientStream>>,
}

/// Connect to the local daemon's LocalAPI endpoint (the fixed
/// `\\.\pipe\roomler` / `$XDG_RUNTIME_DIR/roomler.sock`). "Daemon not running"
/// surfaces as [`std::io::ErrorKind::NotFound`] — callers should render that as
/// "device service not running", not a hard failure.
pub async fn connect() -> std::io::Result<Client> {
    #[cfg(windows)]
    {
        connect_windows_at(LOCALAPI_PIPE_NAME).await
    }
    #[cfg(not(windows))]
    {
        // Try a per-user daemon first (unchanged, and the common case), then
        // the system daemon. Without the second candidate a root daemon is
        // invisible to a user session on macOS, where the per-user path lives
        // under ROOT's `/var/folders/…` — the CLI would report "not running"
        // for a daemon that is running perfectly well.
        let mut last: Option<std::io::Error> = None;
        for path in unix_socket_candidates() {
            match connect_unix_at(path).await {
                Ok(client) => return Ok(client),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "no LocalAPI socket")
        }))
    }
}

/// The OTHER daemon's socket, when this host runs two and [`connect`] would
/// have taken the per-user one.
///
/// macOS installs two halves by necessity — a per-user LaunchAgent for capture
/// and input, a root LaunchDaemon for the overlay — and they listen on
/// different sockets. `connect()` prefers the per-user one, so an unprivileged
/// `roomler status` on such a host answers for the half that has no overlay and
/// prints `overlay ip —`, while `roomler peers` prints nothing. Both are
/// truthful about the process they reached and completely misleading about the
/// machine, which reads as "the overlay is broken".
///
/// Returns `Some(path)` only when BOTH exist AND different processes answer
/// them, i.e. exactly when a caller could be looking at the wrong one.
///
/// #2511 — both existing is not two daemons. A system daemon ALSO binds the
/// legacy per-user path (`serve_unix`), so a root CLI on a host with one root
/// daemon found both, and told its reader a second daemon ran and to use the
/// sudo they already had: on every `roomler exec <linux host> -- roomler
/// status`. Each socket is now asked who answers it, by the peer's PID. A PID
/// that cannot be read keeps the note, because staying silent would hide a
/// real second daemon.
#[cfg(unix)]
pub async fn other_daemon_socket() -> Option<std::path::PathBuf> {
    let [user, system] = unix_socket_candidates();
    let (user_exists, system_exists) = (user.exists(), system.exists());
    let same_process = if user_exists && system_exists {
        match (socket_peer_pid(&user).await, socket_peer_pid(&system).await) {
            (Some(a), Some(b)) => Some(a == b),
            _ => None,
        }
    } else {
        None
    };
    second_daemon(user_exists, system_exists, same_process).then_some(system)
}

/// The decision behind [`other_daemon_socket`]: a second daemon only when
/// both sockets exist and they are not known to lead to one process.
#[cfg(unix)]
fn second_daemon(user_exists: bool, system_exists: bool, same_process: Option<bool>) -> bool {
    user_exists && system_exists && same_process != Some(true)
}

/// The PID of whoever answers `path`, from its peer credentials (Linux's
/// `SO_PEERCRED`, macOS's `LOCAL_PEEREPID`). `None` when nothing answers
/// within half a second or the OS does not say.
#[cfg(unix)]
async fn socket_peer_pid(path: &std::path::Path) -> Option<tokio::net::unix::pid_t> {
    let stream = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        tokio::net::UnixStream::connect(path),
    )
    .await
    .ok()?
    .ok()?;
    stream.peer_cred().ok()?.pid()
}

/// Windows runs a single daemon, so there is never another one to point at.
#[cfg(windows)]
pub async fn other_daemon_socket() -> Option<std::path::PathBuf> {
    None
}

/// FR-84 D1 — how long to wait before the `attempt`-th retry of a pipe open
/// that was refused with `ERROR_PIPE_BUSY` (every listening instance taken):
/// `5, 10, 20, 40, 80, 160` ms, then `None` = give up and surface the error.
/// Bounded at 315 ms in total — this is an interactive path, and a daemon
/// that keeps every instance busy for longer than that is not "momentarily
/// between instances", it is wedged, and the caller must hear about it.
///
/// Before FR-84 the client retried ONCE after 50 ms. Against a single
/// listening instance that lost to the companion's own sibling poll every
/// 2 s: the loser's retry landed while the winner's instance was still being
/// replaced, and the error became an empty table.
#[cfg_attr(not(windows), allow(dead_code))] // only the pipe client backs off; the pure test runs everywhere
pub(crate) fn pipe_busy_backoff(attempt: u32) -> Option<std::time::Duration> {
    const LADDER_MS: [u64; 6] = [5, 10, 20, 40, 80, 160];
    LADDER_MS
        .get(attempt as usize)
        .map(|ms| std::time::Duration::from_millis(*ms))
}

/// Named-pipe connect, parameterised on the pipe name so tests can target a
/// private one. Retries `ERROR_PIPE_BUSY` (every listening instance taken)
/// on the bounded [`pipe_busy_backoff`] ladder; any other error (notably
/// `ERROR_FILE_NOT_FOUND` = daemon not running) propagates immediately.
#[cfg(windows)]
pub(crate) async fn connect_windows_at(pipe_name: &str) -> std::io::Result<Client> {
    use tokio::net::windows::named_pipe::ClientOptions;
    const ERROR_PIPE_BUSY: i32 = 231;
    let mut attempt = 0u32;
    let pipe = loop {
        match ClientOptions::new().open(pipe_name) {
            Ok(p) => break p,
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => match pipe_busy_backoff(attempt)
            {
                Some(delay) => {
                    attempt += 1;
                    tokio::time::sleep(delay).await;
                }
                None => return Err(e),
            },
            Err(e) => return Err(e),
        }
    };
    Ok(Client::new(Box::new(pipe)))
}

/// Unix-socket connect, parameterised on the path so tests can target a private
/// one, and the root update helper the system daemon (FR-90 P1h-2).
#[cfg(unix)]
pub async fn connect_unix_at(path: std::path::PathBuf) -> std::io::Result<Client> {
    let stream = tokio::net::UnixStream::connect(path).await?;
    Ok(Client::new(Box::new(stream)))
}

/// FR-97 P2g — [`connect_unix_at`], kept only when the process serving the
/// socket is ROOT (its uid, from the kernel). A Mac's per-user half asks the
/// root half's person socket for the machine's Devices and Mesh, and shows the
/// answer to the person as the machine's own. Only root can make an entry in
/// [`MACOS_PERSON_SOCKET_DIR`] in the first place, so this is the second lock:
/// a socket served by anyone else is refused, not believed.
#[cfg(unix)]
pub async fn connect_unix_served_by_root(path: std::path::PathBuf) -> std::io::Result<Client> {
    let stream = tokio::net::UnixStream::connect(&path).await?;
    let server = stream.peer_cred()?.uid();
    if server != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("{} is served by uid {server}, not root", path.display()),
        ));
    }
    Ok(Client::new(Box::new(stream)))
}

impl Client {
    fn new(stream: Box<dyn ClientStream>) -> Self {
        Self {
            stream: tokio::io::BufReader::new(stream),
        }
    }

    /// One newline-JSON round-trip — write the request, read one response line.
    /// Mirrors the server's [`serve_connection`] framing.
    pub async fn request(&mut self, req: &Request) -> std::io::Result<Response> {
        let mut buf = serde_json::to_vec(req).map_err(std::io::Error::other)?;
        buf.push(b'\n');
        self.stream.write_all(&buf).await?;
        self.stream.flush().await?;

        let mut line = String::new();
        if self.stream.read_line(&mut line).await? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "localapi: connection closed before a response",
            ));
        }
        serde_json::from_str(line.trim_end()).map_err(std::io::Error::other)
    }

    /// `Request::Status` → [`NodeStatus`]. A `Response::Error` maps to `Err`.
    pub async fn status(&mut self) -> std::io::Result<NodeStatus> {
        match self.request(&Request::Status).await? {
            Response::Status(s) => Ok(*s),
            other => Err(unexpected_response(other)),
        }
    }

    /// `Request::Peers` → the peer list with connection types.
    pub async fn peers(&mut self) -> std::io::Result<Vec<PeerInfo>> {
        match self.request(&Request::Peers).await? {
            Response::Peers(p) => Ok(p),
            other => Err(unexpected_response(other)),
        }
    }

    /// `Request::Flows` → active forwards / SOCKS5 listeners (empty on the agent
    /// daemon until the tunnel-client folds in at P3).
    pub async fn flows(&mut self) -> std::io::Result<Vec<FlowInfo>> {
        match self.request(&Request::Flows).await? {
            Response::Flows(f) => Ok(f),
            other => Err(unexpected_response(other)),
        }
    }

    /// `Request::Ping` → the resolved `(overlay_ip, rtt_ms)`. A daemon
    /// [`Response::Error`] (unknown peer / not a netstack node / timeout)
    /// surfaces its message verbatim.
    pub async fn ping(
        &mut self,
        target: &str,
        timeout_ms: u64,
        prefer_v6: bool,
    ) -> std::io::Result<(String, f64)> {
        let req = Request::Ping {
            target: target.to_string(),
            timeout_ms,
            prefer_v6,
        };
        match self.request(&req).await? {
            Response::Pong {
                overlay_ip,
                rtt_micros,
                ..
            } => Ok((overlay_ip, rtt_micros as f64 / 1000.0)),
            Response::Error { message } => Err(std::io::Error::other(message)),
            other => Err(unexpected_response(other)),
        }
    }

    /// `Request::ConsentPending` → remote-control sessions awaiting a decision.
    pub async fn consent_pending(&mut self) -> std::io::Result<Vec<ConsentRequest>> {
        match self.request(&Request::ConsentPending).await? {
            Response::ConsentPending(v) => Ok(v),
            other => Err(unexpected_response(other)),
        }
    }

    /// FR-27 — `Request::RcSessions` → remote-control sessions currently live
    /// on this device.
    pub async fn rc_sessions(&mut self) -> std::io::Result<Vec<RcSessionInfo>> {
        match self.request(&Request::RcSessions).await? {
            Response::RcSessions(v) => Ok(v),
            other => Err(unexpected_response(other)),
        }
    }

    /// FR-27 — `Request::RcDisconnect` → end a live session from the device
    /// side. `false` = no session with that id (already gone, or never here).
    pub async fn rc_disconnect(&mut self, session_id: &str) -> std::io::Result<bool> {
        let req = Request::RcDisconnect {
            session_id: session_id.to_string(),
        };
        match self.request(&req).await? {
            Response::RcDisconnected { ok } => Ok(ok),
            other => Err(unexpected_response(other)),
        }
    }

    /// `Request::ConsentDecide` → approve/deny a pending consent. Returns
    /// whether the daemon recorded the decision.
    pub async fn consent_decide(&mut self, session_id: &str, allow: bool) -> std::io::Result<bool> {
        let req = Request::ConsentDecide {
            session_id: session_id.to_string(),
            allow,
        };
        match self.request(&req).await? {
            Response::ConsentDecided { ok } => Ok(ok),
            other => Err(unexpected_response(other)),
        }
    }

    /// `Request::CreateForward` → the assigned flow id. A daemon
    /// [`Response::Error`] (bad node/remote, port unavailable, no agent WS)
    /// surfaces its message verbatim.
    pub async fn create_forward(
        &mut self,
        node: &str,
        local: u16,
        remote: &str,
        transport: &str,
        start_transport: &str,
    ) -> std::io::Result<String> {
        let req = Request::CreateForward {
            node: node.to_string(),
            local,
            remote: remote.to_string(),
            transport: transport.to_string(),
            start_transport: start_transport.to_string(),
        };
        match self.request(&req).await? {
            Response::FlowCreated { id } => Ok(id),
            Response::Error { message } => Err(std::io::Error::other(message)),
            other => Err(unexpected_response(other)),
        }
    }

    /// `Request::CreateSocks5` → the assigned flow id.
    pub async fn create_socks5(
        &mut self,
        node: &str,
        local: u16,
        transport: &str,
    ) -> std::io::Result<String> {
        let req = Request::CreateSocks5 {
            node: node.to_string(),
            local,
            transport: transport.to_string(),
        };
        match self.request(&req).await? {
            Response::FlowCreated { id } => Ok(id),
            Response::Error { message } => Err(std::io::Error::other(message)),
            other => Err(unexpected_response(other)),
        }
    }

    /// `Request::KillFlow` → whether a flow with that id was found + killed.
    pub async fn kill_flow(&mut self, id: &str) -> std::io::Result<bool> {
        match self
            .request(&Request::KillFlow { id: id.to_string() })
            .await?
        {
            Response::FlowKilled { ok } => Ok(ok),
            other => Err(unexpected_response(other)),
        }
    }

    /// `Request::RouteList` → declared routes + live state.
    pub async fn route_list(&mut self) -> std::io::Result<Vec<RouteInfo>> {
        match self.request(&Request::RouteList).await? {
            Response::Routes(v) => Ok(v),
            other => Err(unexpected_response(other)),
        }
    }

    /// `Request::RouteAdd` → the effective persisted descriptor (id
    /// generated if the request left it empty). A daemon
    /// [`Response::Error`] (duplicate id/port, bad node, config write
    /// failure) surfaces its message verbatim.
    pub async fn route_add(&mut self, route: RouteDescriptor) -> std::io::Result<RouteDescriptor> {
        match self.request(&Request::RouteAdd { route }).await? {
            Response::RouteAdded { route } => Ok(route),
            other => Err(unexpected_response(other)),
        }
    }

    /// `Request::RouteRemove` → whether a route with that id existed.
    pub async fn route_remove(&mut self, id: &str) -> std::io::Result<bool> {
        match self
            .request(&Request::RouteRemove { id: id.to_string() })
            .await?
        {
            Response::RouteRemoved { ok } => Ok(ok),
            other => Err(unexpected_response(other)),
        }
    }

    /// `Request::RouteSetEnabled` → whether a route with that id existed.
    pub async fn route_set_enabled(&mut self, id: &str, enabled: bool) -> std::io::Result<bool> {
        match self
            .request(&Request::RouteSetEnabled {
                id: id.to_string(),
                enabled,
            })
            .await?
        {
            Response::RouteUpdated { ok } => Ok(ok),
            other => Err(unexpected_response(other)),
        }
    }

    /// FR-84 D1 — `Request::RouteUpdate` → the effective persisted
    /// descriptor. A daemon [`Response::Error`] (unknown id, bad node,
    /// duplicate port, config write failure, or "unknown variant" from a
    /// daemon older than the verb) surfaces its message verbatim as `Err`.
    pub async fn route_update(
        &mut self,
        route: RouteDescriptor,
    ) -> std::io::Result<RouteDescriptor> {
        match self.request(&Request::RouteUpdate { route }).await? {
            Response::RouteReplaced { route } => Ok(route),
            other => Err(unexpected_response(other)),
        }
    }

    /// `Request::SetDeviceName` → the effective (trimmed) name the daemon
    /// persisted. An old daemon that predates the verb answers with a
    /// bad-request [`Response::Error`], which surfaces here as `Err` — callers
    /// with a legacy direct-file path can fall back on that.
    pub async fn set_device_name(&mut self, name: &str) -> std::io::Result<String> {
        match self
            .request(&Request::SetDeviceName {
                name: name.to_string(),
            })
            .await?
        {
            Response::DeviceNameSet { name } => Ok(name),
            other => Err(unexpected_response(other)),
        }
    }

    /// S1b — ask the daemon to archive the stale config copy on a
    /// split-config host. Returns `(ok, detail)`; an older daemon
    /// answers with a clean `Error` (surfaced as `Err`) so callers can
    /// fall back to showing the manual instructions.
    pub async fn config_cleanup_stale(&mut self) -> std::io::Result<(bool, String)> {
        match self.request(&Request::ConfigCleanupStale).await? {
            Response::ConfigCleaned { ok, detail } => Ok((ok, detail)),
            other => Err(unexpected_response(other)),
        }
    }

    /// S2 — fetch the editable config surface (key + current value +
    /// editor metadata). An older daemon answers with a clean `Error`
    /// (surfaced as `Err`) so callers can hide the editor.
    pub async fn config_entries(&mut self) -> std::io::Result<Vec<ConfigEntry>> {
        match self.request(&Request::ConfigGet).await? {
            Response::ConfigEntries(entries) => Ok(entries),
            other => Err(unexpected_response(other)),
        }
    }

    /// S2 — set (`Some(value)`) or clear (`None`) one editable config
    /// key; the daemon validates + persists and echoes the updated entry.
    pub async fn config_set(
        &mut self,
        key: &str,
        value: Option<&str>,
    ) -> std::io::Result<ConfigEntry> {
        match self
            .request(&Request::ConfigSet {
                key: key.to_string(),
                value: value.map(str::to_string),
            })
            .await?
        {
            Response::ConfigUpdated { entry } => Ok(entry),
            other => Err(unexpected_response(other)),
        }
    }

    /// FR-52 gate 4 — hand the daemon a plaintext password to register.
    ///
    /// ⚠️ Slow **on purpose**: the daemon derives the record with Argon2id, so
    /// this round trip is the KDF's cost (hundreds of ms, and more on a weak
    /// CPU). A caller must not treat a delay here as a hung daemon.
    pub async fn external_password_set(
        &mut self,
        password: &str,
    ) -> std::io::Result<ExternalPasswordState> {
        match self
            .request(&Request::ExternalPasswordSet {
                password: Secret(password.to_string()),
            })
            .await?
        {
            Response::ExternalPassword(state) => Ok(state),
            other => Err(unexpected_response(other)),
        }
    }

    /// FR-52 gate 4 — drop the stored record.
    pub async fn external_password_clear(&mut self) -> std::io::Result<ExternalPasswordState> {
        match self.request(&Request::ExternalPasswordClear).await? {
            Response::ExternalPassword(state) => Ok(state),
            other => Err(unexpected_response(other)),
        }
    }

    /// FR-52 — read gates 3 and 4 as the device sees them.
    pub async fn external_password_status(&mut self) -> std::io::Result<ExternalPasswordState> {
        match self.request(&Request::ExternalPasswordStatus).await? {
            Response::ExternalPassword(state) => Ok(state),
            other => Err(unexpected_response(other)),
        }
    }

    /// S2 — tail one of the daemon's log files (`daemon` / `service` /
    /// `panic`). Returns `(path, total_size, content)`; poll `size` to
    /// detect growth. An older daemon answers with a clean `Error`.
    pub async fn tail_log(
        &mut self,
        source: &str,
        max_bytes: Option<u64>,
    ) -> std::io::Result<(String, u64, String)> {
        match self
            .request(&Request::TailLog {
                source: source.to_string(),
                max_bytes,
            })
            .await?
        {
            Response::LogTail {
                path,
                size,
                content,
            } => Ok((path, size, content)),
            other => Err(unexpected_response(other)),
        }
    }

    /// FR-85 — start a recording of this device's screen. Answers once the
    /// recorder has begun encoding (the state names the file and encoder) or
    /// refused (an `Err` naming why). Console user only.
    pub async fn record_start(&mut self, opts: RecordStartOpts) -> std::io::Result<RecordingState> {
        match self.request(&Request::RecordStart { opts }).await? {
            Response::Recording(s) => Ok(s),
            other => Err(unexpected_response(other)),
        }
    }

    /// FR-85 — stop the active recording. Answers once the file is final
    /// (`last` says how it ended). Console user only.
    pub async fn record_stop(&mut self) -> std::io::Result<RecordingState> {
        match self.request(&Request::RecordStop).await? {
            Response::Recording(s) => Ok(s),
            other => Err(unexpected_response(other)),
        }
    }

    /// FR-85 — what the recorder is doing, and how the last recording ended.
    pub async fn record_status(&mut self) -> std::io::Result<RecordingState> {
        match self.request(&Request::RecordStatus).await? {
            Response::Recording(s) => Ok(s),
            other => Err(unexpected_response(other)),
        }
    }

    /// FR-92 — keep busy's state on this device.
    pub async fn keep_busy_status(&mut self) -> std::io::Result<KeepBusyInfo> {
        match self.request(&Request::KeepBusyStatus).await? {
            Response::KeepBusy(s) => Ok(s),
            other => Err(unexpected_response(other)),
        }
    }

    /// FR-92 — stop keep busy. Answers with the state once the engine has
    /// applied it (or after a short wait — then `on` may still read true).
    pub async fn keep_busy_off(&mut self) -> std::io::Result<KeepBusyInfo> {
        match self.request(&Request::KeepBusyOff).await? {
            Response::KeepBusy(s) => Ok(s),
            other => Err(unexpected_response(other)),
        }
    }

    /// FR-92 P10 — turn keep busy on, as the person at this computer.
    /// Answers with the state once the engine has applied it (or refused:
    /// then `on` is false and `reason` says why).
    pub async fn keep_busy_on(&mut self, opts: KeepBusyStartOpts) -> std::io::Result<KeepBusyInfo> {
        match self.request(&Request::KeepBusyOn { opts }).await? {
            Response::KeepBusy(s) => Ok(s),
            other => Err(unexpected_response(other)),
        }
    }

    /// FR-85 — the recordings folder, why it is that one, and its recordings.
    pub async fn recordings_list(&mut self) -> std::io::Result<RecordingsListing> {
        match self.request(&Request::RecordingsList).await? {
            Response::Recordings(l) => Ok(l),
            other => Err(unexpected_response(other)),
        }
    }

    /// FR-85 — delete one recording (and its sidecar) by file name. Console
    /// user only.
    pub async fn recording_delete(&mut self, name: &str) -> std::io::Result<()> {
        match self
            .request(&Request::RecordingDelete {
                name: name.to_string(),
            })
            .await?
        {
            Response::RecordingDeleted { ok: true, .. } => Ok(()),
            Response::RecordingDeleted { message, .. } => Err(std::io::Error::other(
                message.unwrap_or_else(|| "the recording was not deleted".into()),
            )),
            other => Err(unexpected_response(other)),
        }
    }

    /// FR-84 D5b — `Request::Devices` → one page of the devices this device
    /// may see. The error says WHY not, by cause ([`DirectoryError`]): the
    /// server's refusal as the daemon relayed it, a daemon too old to know
    /// the verb, or the pipe itself — each has a different fallback.
    pub async fn devices(
        &mut self,
        org: &str,
        query: &DevicesQuery,
    ) -> Result<DevicesPage, DirectoryError> {
        let req = Request::Devices {
            org: org.to_string(),
            page: query.page,
            per_page: query.per_page,
            q: query.q.clone(),
            sort: query.sort.clone(),
            dir: query.dir.clone(),
        };
        match self.request(&req).await? {
            Response::Devices(page) => Ok(*page),
            other => Err(directory_error(other)),
        }
    }

    /// FR-84 D5b — `Request::Mesh` → the mesh graph for the same set.
    /// `Ok` with `enabled: false` is the server's statistics being off.
    pub async fn mesh(&mut self, org: &str) -> Result<MeshView, DirectoryError> {
        let req = Request::Mesh {
            org: org.to_string(),
        };
        match self.request(&req).await? {
            Response::Mesh(view) => Ok(*view),
            other => Err(directory_error(other)),
        }
    }

    /// FR-84 D3 — ask the daemon to restart itself through its supervisor.
    /// `Err` only when the exchange itself failed; the daemon's decision —
    /// accepted, refused, or "I predate the verb" — is the [`RestartAnswer`].
    /// After `Accepted` the daemon exits: this connection is spent.
    pub async fn restart_daemon(&mut self, reason: &str) -> std::io::Result<RestartAnswer> {
        let resp = self
            .request(&Request::RestartDaemon {
                reason: reason.to_string(),
            })
            .await?;
        Ok(RestartAnswer::from_response(resp))
    }

    /// FR-84 D4 — what this device can encode, from the probe's cached
    /// result. An older daemon answers with a bad-request [`Response::Error`]
    /// (surfaced as `Err`), which a client renders as "update the service".
    pub async fn encoder_caps(&mut self) -> std::io::Result<EncoderCapsSummary> {
        match self.request(&Request::EncoderCaps).await? {
            Response::EncoderCaps(summary) => Ok(summary),
            other => Err(unexpected_response(other)),
        }
    }
}

/// FR-84 D3 — what a daemon said to [`Request::RestartDaemon`], classified
/// once here so the CLI and the companion cannot disagree about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestartAnswer {
    /// Accepted: the daemon `leaving` exits with `exit_code`; `restart_by`
    /// says who relaunches it (see [`Response::DaemonRestarting`]).
    Accepted {
        supervisor: String,
        restart_by: String,
        exit_code: i32,
        leaving: DaemonInstance,
        /// #1684 — the supervisor's own bound on how long the relaunch may
        /// take, in seconds; `None` when unknown (an older daemon, or a
        /// non-systemd supervisor). A caller waits at least this long.
        restart_within_s: Option<u64>,
    },
    /// Refused, with the daemon's own reason (shown verbatim).
    Refused(String),
    /// The daemon predates the verb — it cannot parse the request at all.
    Unsupported(String),
}

/// FR-84 D3 — one daemon PROCESS: its pid and when it started. Two answers
/// come from the same process only if both match — a pid alone does not
/// say it, because Windows can give a just-freed PID to the very next
/// process, and after a restart that is the relaunched daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DaemonInstance {
    pub pid: Option<u32>,
    pub started_at_ms: Option<u64>,
}

impl DaemonInstance {
    /// The process a `Status` answer came from.
    pub fn of(status: &NodeStatus) -> Self {
        Self {
            pid: status.pid,
            started_at_ms: status.started_at_ms,
        }
    }

    /// The process a `DaemonRestarting` answer came from (`0` = not
    /// reported).
    pub fn leaving(pid: u32, started_at_ms: u64) -> Self {
        Self {
            pid: (pid != 0).then_some(pid),
            started_at_ms: (started_at_ms != 0).then_some(started_at_ms),
        }
    }
}

/// FR-84 D5b — a non-answer to `Devices` / `Mesh`, classified by cause.
fn directory_error(resp: Response) -> DirectoryError {
    match resp {
        Response::Upstream {
            code,
            message,
            status,
        } => DirectoryError::Upstream {
            code,
            message,
            status,
        },
        Response::Error { message } => DirectoryError::from_daemon_error(message),
        other => DirectoryError::Io(std::io::Error::other(format!(
            "localapi: unexpected response: {other:?}"
        ))),
    }
}

impl RestartAnswer {
    pub fn from_response(resp: Response) -> Self {
        match resp {
            Response::DaemonRestarting {
                supervisor,
                restart_by,
                exit_code,
                pid,
                started_at_ms,
                restart_within_s,
            } => RestartAnswer::Accepted {
                supervisor,
                restart_by,
                exit_code,
                leaving: DaemonInstance::leaving(pid, started_at_ms),
                restart_within_s,
            },
            Response::Error { message } if is_unknown_verb(&message) => {
                RestartAnswer::Unsupported(message)
            }
            Response::Error { message } => RestartAnswer::Refused(message),
            other => RestartAnswer::Refused(format!("unexpected answer: {other:?}")),
        }
    }
}

/// The one reply a daemon gives to a verb it has never heard of: its serde
/// rejects the tag with "unknown variant". Every "this service predates …"
/// message in a client keys on this, and only this.
pub fn is_unknown_verb(message: &str) -> bool {
    message.contains("unknown variant")
}

/// #1684 — margin added to the supervisor's own stop+relaunch bound
/// ([`Response::DaemonRestarting::restart_within_s`]) before a caller gives up:
/// the bound covers `TimeoutStopSec + RestartSec`, after which the relaunched
/// daemon still has to boot and open its LocalAPI. Success returns the instant
/// a new daemon answers, so this only moves the give-up point.
pub const RESTART_WAIT_MARGIN: std::time::Duration = std::time::Duration::from_secs(15);

/// #1684 — the most a caller will ever wait, whatever the supervisor reports: a
/// unit with `TimeoutStopSec=1h` must not turn `roomler restart` into an
/// hour-long hang.
pub const RESTART_WAIT_CAP: std::time::Duration = std::time::Duration::from_secs(600);

/// #1684 — how long a caller should wait for the relaunched daemon: at least
/// `floor` (the historic fixed wait, so a wait never SHORTENS), and at least
/// the supervisor's reported bound plus [`RESTART_WAIT_MARGIN`], capped at
/// [`RESTART_WAIT_CAP`]. `hint` is `Response::DaemonRestarting::restart_within_s`
/// — `None` (an older daemon, or a non-systemd supervisor) keeps `floor`.
pub fn restart_wait(hint: Option<u64>, floor: std::time::Duration) -> std::time::Duration {
    let want = match hint {
        Some(secs) => {
            floor.max(std::time::Duration::from_secs(secs).saturating_add(RESTART_WAIT_MARGIN))
        }
        None => floor,
    };
    want.min(RESTART_WAIT_CAP)
}

/// FR-84 D3 — how often a caller waiting out a restart polls `Status`.
pub const RESTART_POLL: std::time::Duration = std::time::Duration::from_millis(500);
/// FR-84 D3 — the least time between two "start the service" attempts by a
/// caller that owns the relaunch (`restart_by: "caller"`).
pub const RESTART_START_EVERY: std::time::Duration = std::time::Duration::from_secs(3);

/// FR-84 D3 — one poll of a restart in progress, as the waiting caller sees
/// the endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartProbe {
    /// A daemon answered `Status` — this process.
    Up(DaemonInstance),
    /// No daemon at all: the pipe does not exist / nothing listens on the
    /// socket.
    Gone,
    /// The endpoint exists but did not answer — busy, or mid-shutdown.
    Busy,
}

/// FR-84 D3 — what a waiting caller does after one probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartStep {
    /// A NEW daemon answered (its pid, when it reports one).
    Back(Option<u32>),
    /// Keep polling.
    Wait,
    /// Nothing is running and the relaunch is ours: start the service, then
    /// keep polling.
    StartThenWait,
}

/// The waiting caller's decision, pure. The daemon that accepted the restart
/// keeps answering for a moment after it said yes, so "reachable" is not
/// "back" — only a different PROCESS is ([`DaemonInstance`]: pid AND start
/// time, because the relaunched daemon may well get the old one's pid). And a
/// caller that owns the relaunch starts the service whenever NOTHING answers
/// (never while the old process still does), again every
/// [`RESTART_START_EVERY`] until something does: under the Scheduled Task a
/// start that lands while the old instance is still exiting is dropped by its
/// `IgnoreNew` policy, so one attempt is not enough, and every extra one is
/// harmless.
pub fn restart_step(
    probe: RestartProbe,
    leaving: DaemonInstance,
    caller_starts: bool,
    start_due: bool,
) -> RestartStep {
    match probe {
        RestartProbe::Up(answered) if answered == leaving => RestartStep::Wait,
        RestartProbe::Up(answered) => RestartStep::Back(answered.pid),
        RestartProbe::Gone if caller_starts && start_due => RestartStep::StartThenWait,
        RestartProbe::Gone | RestartProbe::Busy => RestartStep::Wait,
    }
}

/// Probe the LocalAPI endpoint once for [`restart_step`].
pub async fn probe_restart() -> RestartProbe {
    match connect().await {
        Ok(mut client) => match client.status().await {
            Ok(status) => RestartProbe::Up(DaemonInstance::of(&status)),
            Err(_) => RestartProbe::Busy,
        },
        // No pipe (Windows), no socket file or nothing listening on it (unix,
        // where an exited daemon can leave the file behind).
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            RestartProbe::Gone
        }
        Err(_) => RestartProbe::Busy,
    }
}

/// FR-84 D3 — the caller's half of a restart the daemon accepted: poll until
/// a daemon process other than `leaving` answers, running `start` along the
/// way when the relaunch is the caller's (`caller_starts`, i.e. `restart_by:
/// "caller"`). `Ok` carries the new daemon's pid; `Err` says what was seen by
/// the deadline (and the last start failure, if any), worded for a person.
pub async fn wait_for_restart<F, Fut>(
    leaving: DaemonInstance,
    caller_starts: bool,
    mut start: F,
    within: std::time::Duration,
) -> Result<Option<u32>, String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let begun = tokio::time::Instant::now();
    let mut last_start: Option<tokio::time::Instant> = None;
    let mut start_error: Option<String> = None;
    loop {
        let due = last_start.is_none_or(|t| t.elapsed() >= RESTART_START_EVERY);
        match restart_step(probe_restart().await, leaving, caller_starts, due) {
            RestartStep::Back(pid) => return Ok(pid),
            RestartStep::StartThenWait => {
                last_start = Some(tokio::time::Instant::now());
                start_error = start().await.err();
            }
            RestartStep::Wait => {}
        }
        if begun.elapsed() >= within {
            return Err(match start_error {
                Some(e) => format!(
                    "no new daemon answered within {} s; the last attempt to start it failed: {e}",
                    within.as_secs()
                ),
                None => format!("no new daemon answered within {} s", within.as_secs()),
            });
        }
        tokio::time::sleep(RESTART_POLL).await;
    }
}

/// Map an error / mismatched response to an `io::Error` for the typed helpers.
fn unexpected_response(resp: Response) -> std::io::Error {
    match resp {
        Response::Error { message } => std::io::Error::other(format!("localapi error: {message}")),
        other => std::io::Error::other(format!("localapi: unexpected response: {other:?}")),
    }
}

/// FR-47 — the last time the server REFUSED this node's overlay join, as
/// [`NodeStatus::join_refusal`] reports it.
///
/// The failure this exists for: before the refusal frame, a node that could
/// not be given an address simply waited for a netmap that never arrived, so
/// it was indistinguishable from one that was merely offline — on the host as
/// much as on the dashboard. The daemon log carries the reason now; this puts
/// it where an operator actually looks first.
///
/// ⚠️ Reported even after a LATER join succeeds, with its timestamp, rather
/// than being cleared: "we were refused twenty minutes ago and are fine now"
/// is a different and more useful fact than silence, and it is the only trace
/// left once the log has rotated. `connected` already says whether the node is
/// up right now, so this cannot be mistaken for the current state.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct JoinRefusalStatus {
    /// The enumerated reason, as the wire spelled it
    /// (`address_space_exhausted`, `network_unavailable`, `store_unavailable`,
    /// or `unknown` from a newer server).
    #[serde(default)]
    pub reason: String,
    /// The server's human-readable detail.
    #[serde(default)]
    pub detail: String,
    /// Unix seconds when the refusal arrived.
    #[serde(default)]
    pub at_unix: i64,
    /// Whether another attempt could plausibly succeed. A full block does not
    /// empty on retry; a transient store fault might.
    #[serde(default)]
    pub retryable: bool,
}

/// FR-33 — one captured LAN prefix, as [`NodeStatus::lan_captures`] reports it.
/// Detect-and-report only: the daemon never routes around a capture.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct LanCaptureStatus {
    /// The captured prefix, `a.b.c.d/n`.
    #[serde(default)]
    pub prefix: String,
    /// The interface that owns our address in it (name).
    #[serde(default)]
    pub owner: String,
    /// The interface a packet to a neighbour in the prefix actually leaves by
    /// (ifindex on Windows, device name on Unix).
    #[serde(default)]
    pub via: String,
    /// That interface's name when the daemon could resolve it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #2511 — one process behind both sockets is one daemon (the system
    /// daemon's legacy per-user bind), and only that case goes quiet.
    #[cfg(unix)]
    #[test]
    fn one_daemon_behind_both_sockets_is_not_a_second_daemon() {
        assert!(!second_daemon(true, true, Some(true)), "the legacy bind");
        assert!(second_daemon(true, true, Some(false)), "macOS's two halves");
        assert!(second_daemon(true, true, None), "unknowable: keep the note");
        assert!(
            !second_daemon(true, false, None),
            "only the per-user socket"
        );
        assert!(
            !second_daemon(false, true, Some(false)),
            "only the system socket"
        );
    }

    /// #2511 — the PID the decision compares is the listener's: our own
    /// process, for a listener this test holds.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_peer_pid_of_a_listener_is_its_process() {
        let path = std::env::temp_dir().join(format!("roomler-2511-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).expect("bind a test socket");
        let accept = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
        let pid = socket_peer_pid(&path).await;
        let _ = accept.await;
        let _ = std::fs::remove_file(&path);
        assert_eq!(pid, Some(std::process::id() as tokio::net::unix::pid_t));
        assert_eq!(
            socket_peer_pid(&path).await,
            None,
            "nothing answers a removed socket"
        );
    }

    /// FR-97 P0c-3 — WIRE SHAPE. An OS-TUN exit client's status is
    /// byte-identical to one from before the field existed, and a status from
    /// an older daemon (no key) reads as an OS-TUN node, never as SOCKS-only.
    #[test]
    fn socks5_port_is_absent_on_an_os_tun_node_and_carried_for_netstack() {
        let os_tun = ExitNodeStatus {
            selector: "exit".into(),
            active: true,
            withheld_reason: None,
            v6_active: true,
            dns_steered: true,
            socks5_port: None,
        };
        let json = serde_json::to_string(&os_tun).unwrap();
        assert!(!json.contains("socks5_port"), "{json}");
        let older: ExitNodeStatus = serde_json::from_str(
            r#"{"selector":"exit","active":true,"v6_active":true,"dns_steered":true}"#,
        )
        .unwrap();
        assert_eq!(older, os_tun);
        let netstack = ExitNodeStatus {
            socks5_port: Some(1080),
            v6_active: false,
            dns_steered: false,
            ..os_tun
        };
        let json = serde_json::to_string(&netstack).unwrap();
        assert!(json.contains(r#""socks5_port":1080"#), "{json}");
        assert_eq!(
            serde_json::from_str::<ExitNodeStatus>(&json).unwrap(),
            netstack
        );
    }

    /// WIRE SHAPE. A node that is not serving relay probes must produce
    /// **byte-identical** status JSON to one built before FR-19 existed —
    /// otherwise every older `roomler status` / desktop reader has its shape
    /// changed by a feature it does not have.
    ///
    /// And the `Some` case must carry the counters even when they are zero:
    /// "serving, has answered nothing" is a real and important state, and it
    /// is the one a freshly-restarted relay is in while someone is asking
    /// whether it works.
    #[test]
    fn org_relay_is_absent_when_not_serving_and_explicit_when_it_is() {
        let mut s = Mock.status();
        s.org_relay = None;
        let json = serde_json::to_string(&s).unwrap();
        assert!(
            !json.contains("org_relay"),
            "a non-serving node must not emit the key at all: {json}"
        );

        s.org_relay = Some(OrgRelayStatus {
            listening: "0.0.0.0:3478".into(),
            answered: 0,
            refused_not_shaped: 0,
            refused_not_probe: 0,
            refused_rate_limited: 0,
        });
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains(r#""listening":"0.0.0.0:3478""#), "{json}");
        assert!(
            json.contains(r#""answered":0"#),
            "zero counters must be PRESENT, not skipped -- 'serving and idle' \
             is not the same state as 'not serving': {json}"
        );

        // Round trip, so an older field order or a rename is caught here.
        let back: NodeStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back.org_relay, s.org_relay);
    }

    /// FR-33 — the probe-off state must be distinguishable on the wire from
    /// both "probed, clear" and "old daemon": `lan_capture_probe: false`
    /// travels, and a daemon that predates the field reads as `None` (so the
    /// CLI keeps its old silence rather than inventing a verdict).
    #[test]
    fn lan_capture_probe_flag_is_additive_on_the_wire() {
        let mut s = Mock.status();
        s.lan_captures = None;
        s.lan_capture_probe = Some(false);
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains(r#""lan_capture_probe":false"#), "{json}");
        assert!(
            !json.contains("lan_captures"),
            "probe off ⇒ no capture list at all, not an empty one: {json}"
        );
        let back: NodeStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back.lan_capture_probe, Some(false));
        assert_eq!(back.lan_captures, None);

        // An older daemon omits both fields.
        let old: NodeStatus =
            serde_json::from_str(&json.replace(r#","lan_capture_probe":false"#, "")).unwrap();
        assert_eq!(old.lan_capture_probe, None);
        assert_eq!(old.lan_captures, None);
    }

    struct Mock;
    #[async_trait]
    impl LocalApiState for Mock {
        fn status(&self) -> NodeStatus {
            NodeStatus {
                path_trials: None,
                node_id: "n1".into(),
                name: "devbox".into(),
                version: "0.3.0-rc.154".into(),
                mode: DaemonMode::Service,
                privileged: None,
                tenant_id: Some("t1".into()),
                overlay_ip: Some("100.64.0.2".into()),
                overlay_ip6: None,
                connected: true,
                ephemeral: false,
                exit_node: None,
                route_offer_withheld: None,
                host_firewall: None,
                config_path: None,
                dns: None,
                srflx: None,
                warm_relay: None,
                lan_captures: None,
                lan_capture_probe: None,
                join_refusal: None,
                orgs: Vec::new(),
                direct_socks: Vec::new(),
                direct_bind_walks: None,
                roam_adoptions: None,
                route_guard: None,
                route_wave_arms: None,
                route_yields: None,
                route_wave_pulls: None,
                disco_answered: None,
                org_relay: None,
                legacy_env_uses: Some(Vec::new()),
                retired_env_present: Some(Vec::new()),
                files_dir: None,
                derp_inbound_drops: None,
                netcheck: None,
                pid: None,
                started_at_ms: None,
            }
        }
        fn peers(&self) -> Vec<PeerInfo> {
            vec![
                PeerInfo {
                    node_id: "n2".into(),
                    name: "winhost-a".into(),
                    org: String::new(),
                    overlay_ip: Some("100.64.0.1".into()),
                    overlay_ip6: None,
                    online: true,
                    connection: ConnectionType::Tunnel,
                    upgrading: false,
                    stalled: false,
                    rtt_ms: Some(52),
                    last_seen_ms: Some(1000),
                    agent_id: Some("6a074fe5ef3ba556ab041966".into()),
                    relay_local: Some("94.130.141.74:10850".into()),
                    relay_dst: Some("5.9.157.226:12728".into()),
                    relay_kind: None,
                    relay_transport: None,
                    relay_server: None,
                    why: None,
                    probes: Vec::new(),
                    debug: None,
                },
                PeerInfo {
                    node_id: "n3".into(),
                    name: "home".into(),
                    org: String::new(),
                    overlay_ip: Some("100.64.0.9".into()),
                    overlay_ip6: None,
                    online: true,
                    connection: ConnectionType::Direct,
                    upgrading: false,
                    stalled: false,
                    rtt_ms: Some(3),
                    last_seen_ms: Some(1200),
                    agent_id: None,
                    relay_local: None,
                    relay_dst: None,
                    relay_kind: None,
                    relay_transport: None,
                    relay_server: None,
                    why: None,
                    probes: Vec::new(),
                    debug: None,
                },
            ]
        }
        fn flows(&self) -> Vec<FlowInfo> {
            vec![FlowInfo {
                id: "f1".into(),
                kind: FlowKind::Socks5,
                local_addr: "127.0.0.1:1080".into(),
                target: None,
                node: Some("winhost-a".into()),
                transport: "quic-v1".into(),
                active_flows: 2,
                bytes_in: 4096,
                bytes_out: 8192,
            }]
        }
        fn consent_pending(&self) -> Vec<ConsentRequest> {
            vec![ConsentRequest {
                session_id: "sess-1".into(),
                controller_name: "alice".into(),
                permissions: "view|control".into(),
                timeout_secs: 30,
                kind: "rc".into(),
                detail: String::new(),
                expires_at_ms: 0,
                surface: String::new(),
                org: "Acme".into(),
            }]
        }
        fn consent_decide(&self, session_id: &str, allow: bool) -> bool {
            // Test echo: proves both args crossed the wire (real impl writes a
            // sentinel). Records only a non-empty session that was approved.
            !session_id.is_empty() && allow
        }
        async fn create_forward(
            &self,
            node: &str,
            local: u16,
            _remote: &str,
            _transport: &str,
            _start_transport: &str,
        ) -> Response {
            // Echo the args back as the flow id so the test proves they crossed.
            Response::FlowCreated {
                id: format!("{node}:{local}"),
            }
        }
        async fn create_socks5(&self, node: &str, local: u16, _transport: &str) -> Response {
            Response::FlowCreated {
                id: format!("socks-{node}:{local}"),
            }
        }
        fn kill_flow(&self, id: &str) -> bool {
            id == "f1"
        }
    }

    #[test]
    fn handle_dispatches_each_verb() {
        let s = Mock;
        match handle(&Request::Status, &s) {
            Response::Status(st) => {
                assert_eq!(st.overlay_ip.as_deref(), Some("100.64.0.2"));
                assert_eq!(st.mode, DaemonMode::Service);
            }
            other => panic!("expected Status, got {other:?}"),
        }
        match handle(&Request::Peers, &s) {
            Response::Peers(p) => {
                assert_eq!(p.len(), 2);
                assert_eq!(p[0].connection, ConnectionType::Tunnel);
                assert_eq!(p[1].connection, ConnectionType::Direct);
            }
            other => panic!("expected Peers, got {other:?}"),
        }
        match handle(&Request::Flows, &s) {
            Response::Flows(f) => {
                assert_eq!(f.len(), 1);
                assert_eq!(f[0].kind, FlowKind::Socks5);
                assert!(f[0].target.is_none());
            }
            other => panic!("expected Flows, got {other:?}"),
        }
    }

    #[test]
    fn handle_dispatches_consent_verbs() {
        let s = Mock;
        match handle(&Request::ConsentPending, &s) {
            Response::ConsentPending(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].session_id, "sess-1");
                assert_eq!(v[0].permissions, "view|control");
            }
            other => panic!("expected ConsentPending, got {other:?}"),
        }
        // The `allow` bit crosses the wire (Mock echoes it).
        match handle(
            &Request::ConsentDecide {
                session_id: "sess-1".into(),
                allow: true,
            },
            &s,
        ) {
            Response::ConsentDecided { ok } => assert!(ok),
            other => panic!("expected ConsentDecided, got {other:?}"),
        }
        match handle(
            &Request::ConsentDecide {
                session_id: "sess-1".into(),
                allow: false,
            },
            &s,
        ) {
            Response::ConsentDecided { ok } => assert!(!ok),
            other => panic!("expected ConsentDecided, got {other:?}"),
        }
        // Wire shape — locks the discriminators the tray/CLI depend on.
        assert_eq!(
            serde_json::to_string(&Request::ConsentDecide {
                session_id: "s".into(),
                allow: true,
            })
            .unwrap(),
            r#"{"t":"consent_decide","d":{"session_id":"s","allow":true}}"#
        );
        assert_eq!(
            serde_json::from_str::<Request>(r#"{"t":"consent_pending"}"#).unwrap(),
            Request::ConsentPending
        );
    }

    #[tokio::test]
    async fn create_and_kill_flow_verbs_dispatch_and_lock_wire_shape() {
        let s = Mock;
        // KillFlow is sync — through `handle`.
        assert!(matches!(
            handle(&Request::KillFlow { id: "f1".into() }, &s),
            Response::FlowKilled { ok: true }
        ));
        assert!(matches!(
            handle(&Request::KillFlow { id: "nope".into() }, &s),
            Response::FlowKilled { ok: false }
        ));
        // CreateForward / CreateSocks5 are async — awaited on the trait (the
        // `handle` sync arm returns the async-path Error, also asserted).
        match s.create_forward("aid", 5432, "db:5432", "auto", "").await {
            Response::FlowCreated { id } => assert_eq!(id, "aid:5432"),
            other => panic!("expected FlowCreated, got {other:?}"),
        }
        match s.create_socks5("aid", 1080, "quic").await {
            Response::FlowCreated { id } => assert_eq!(id, "socks-aid:1080"),
            other => panic!("expected FlowCreated, got {other:?}"),
        }
        assert!(matches!(
            handle(
                &Request::CreateForward {
                    node: "a".into(),
                    local: 1,
                    remote: "h:2".into(),
                    transport: String::new(),
                    start_transport: String::new()
                },
                &s
            ),
            Response::Error { .. }
        ));

        // Wire shape — locks the discriminators the CLI depends on. An empty
        // `start_transport` (FR-86 P2) is `skip`ped, so the wire is unchanged
        // for a client that doesn't use the lever.
        assert_eq!(
            serde_json::to_string(&Request::CreateForward {
                node: "aid".into(),
                local: 5432,
                remote: "db:5432".into(),
                transport: "auto".into(),
                start_transport: String::new(),
            })
            .unwrap(),
            r#"{"t":"create_forward","d":{"node":"aid","local":5432,"remote":"db:5432","transport":"auto"}}"#
        );
        // A non-empty `start_transport` DOES ride the wire (the test lever).
        assert_eq!(
            serde_json::to_string(&Request::CreateForward {
                node: "aid".into(),
                local: 5432,
                remote: "db:5432".into(),
                transport: "auto".into(),
                start_transport: "webrtc".into(),
            })
            .unwrap(),
            r#"{"t":"create_forward","d":{"node":"aid","local":5432,"remote":"db:5432","transport":"auto","start_transport":"webrtc"}}"#
        );
        // An old client's payload (no `start_transport`) still deserialises.
        assert_eq!(
            serde_json::from_str::<Request>(
                r#"{"t":"create_forward","d":{"node":"aid","local":5432,"remote":"db:5432","transport":"auto"}}"#
            )
            .unwrap(),
            Request::CreateForward {
                node: "aid".into(),
                local: 5432,
                remote: "db:5432".into(),
                transport: "auto".into(),
                start_transport: String::new(),
            }
        );
        assert_eq!(
            serde_json::to_string(&Request::KillFlow { id: "f1".into() }).unwrap(),
            r#"{"t":"kill_flow","d":{"id":"f1"}}"#
        );
        assert_eq!(
            serde_json::to_string(&Response::FlowCreated { id: "f1".into() }).unwrap(),
            r#"{"t":"flow_created","d":{"id":"f1"}}"#
        );
        assert_eq!(
            serde_json::to_string(&Response::FlowKilled { ok: true }).unwrap(),
            r#"{"t":"flow_killed","d":{"ok":true}}"#
        );
        // `transport` defaults when omitted (older CLI / minimal request).
        assert_eq!(
            serde_json::from_str::<Request>(
                r#"{"t":"create_socks5","d":{"node":"aid","local":1080}}"#
            )
            .unwrap(),
            Request::CreateSocks5 {
                node: "aid".into(),
                local: 1080,
                transport: String::new(),
            }
        );
    }

    #[test]
    fn request_wire_shape_is_stable() {
        assert_eq!(
            serde_json::to_string(&Request::Status).unwrap(),
            r#"{"t":"status"}"#
        );
        assert_eq!(
            serde_json::from_str::<Request>(r#"{"t":"peers"}"#).unwrap(),
            Request::Peers
        );
    }

    /// #2089 — `available` is additive in both directions: an old daemon's
    /// row decodes to `None` (unknown, never "unavailable"), `None` is not
    /// sent, and `Some(false)` survives the trip.
    #[test]
    fn tier_why_available_wire_compat() {
        let old =
            r#"{"tier":"public","eligible":true,"base":330.0,"q":0.0,"penalty":0.0,"score":330.0}"#;
        let t: TierWhy = serde_json::from_str(old).unwrap();
        assert_eq!(t.available, None, "absent must read as unknown");
        assert!(
            !serde_json::to_string(&t).unwrap().contains("available"),
            "None is not sent"
        );
        let unavailable = TierWhy {
            available: Some(false),
            ..t
        };
        let wire = serde_json::to_string(&unavailable).unwrap();
        assert!(wire.contains(r#""available":false"#), "{wire}");
        let round: TierWhy = serde_json::from_str(&wire).unwrap();
        assert_eq!(round, unavailable);
    }

    /// F/A — `why` and `probes` are wire-compatible in BOTH directions, which
    /// is the property a mixed fleet actually depends on: an old daemon sends
    /// neither field (a current CLI must read that as "unknown", not as "no
    /// hold-down and a clean path"), and an old CLI must not choke on a
    /// current daemon that sends both.
    #[test]
    fn peer_info_why_and_probes_wire_compat() {
        // An old daemon's payload: both fields absent.
        let old = r#"{"node_id":"n1","name":"pc","online":true,"connection":"relay"}"#;
        let p: PeerInfo = serde_json::from_str(old).unwrap();
        assert!(
            p.why.is_none(),
            "absent must be UNKNOWN, not 'nothing wrong'"
        );
        assert!(p.probes.is_empty());

        let mut p2 = p.clone();
        p2.why = Some(PeerWhy {
            tiers: vec![TierWhy {
                tier: "lan".into(),
                eligible: false,
                blocked_by: Some("peer-relays-instead".into()),
                available: Some(true),
                base: 400.0,
                q: 0.0,
                penalty: 0.0,
                score: 400.0,
                fails: 0,
            }],
            relayed_instead_s: Some(174),
            relayed_instead_strikes: 3,
            forced_derp_s: None,
            probing: None,
        });
        p2.probes = vec![PathProbe {
            dst: "192.168.68.129:43881".into(),
            loss: Some(0.0),
            rtt_ms: Some(7.8),
            rtt_p95_ms: Some(98.0),
            rtt_max_ms: Some(169.0),
        }];
        let round: PeerInfo = serde_json::from_str(&serde_json::to_string(&p2).unwrap()).unwrap();
        assert_eq!(round, p2);

        // An OLD reader (no such fields) must still parse a current payload.
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct OldPeerInfo {
            node_id: String,
            name: String,
            online: bool,
        }
        let as_old: OldPeerInfo = serde_json::from_str(&serde_json::to_string(&p2).unwrap())
            .expect("a current payload must not choke an older reader");
        assert_eq!(as_old.node_id, "n1");

        // A zero strike count and an empty probe list stay OFF the wire, so a
        // healthy fleet's `peers --json` is unchanged by this feature.
        let mut quiet = p.clone();
        quiet.why = Some(PeerWhy {
            tiers: vec![],
            relayed_instead_s: None,
            relayed_instead_strikes: 0,
            forced_derp_s: None,
            probing: None,
        });
        let json = serde_json::to_string(&quiet).unwrap();
        assert!(!json.contains("relayed_instead_strikes"), "{json}");
        assert!(!json.contains("probes"), "{json}");
    }
    /// rc.276 — `PeerInfo.debug` is wire-compatible: absent (pre-rc.276
    /// daemon) ⇒ `None`; a populated snapshot round-trips.
    #[test]
    fn peer_info_debug_wire_compat() {
        let old = r#"{"node_id":"n1","name":"pc","online":true,"connection":"relay"}"#;
        let p: PeerInfo = serde_json::from_str(old).unwrap();
        assert!(p.debug.is_none());
        let mut p2 = p.clone();
        p2.debug = Some(PeerCarrierDebug {
            tier: "relay".into(),
            initiated: true,
            hs_done: false,
            local: Some("94.130.141.74:10850".into()),
            dst: Some("5.9.157.226:12728".into()),
            tx: 42,
            rx: 0,
            last_rx_age_s: 7,
            relay_kind: Some("turn".into()),
            rx_denied: 0,
            rx_denied_noroute: 0,
        });
        let s = serde_json::to_string(&p2).unwrap();
        assert!(s.contains(r#""tier":"relay""#) && s.contains(r#""tx":42"#));
        // P4 — a clean peer omits the counter entirely, so a healthy fleet's
        // `peers --json` is byte-identical to pre-P4.
        assert!(!s.contains("rx_denied"));
        let back: PeerInfo = serde_json::from_str(&s).unwrap();
        assert_eq!(back.debug, p2.debug);

        // …and a peer the ingress ACL refused surfaces the count, with the
        // NoRoute subset beside it (omitted when 0, absent-tolerant on read).
        let mut p3 = p2.clone();
        if let Some(d) = p3.debug.as_mut() {
            d.rx_denied = 17;
            d.rx_denied_noroute = 5;
        }
        let s3 = serde_json::to_string(&p3).unwrap();
        assert!(s3.contains(r#""rx_denied":17"#));
        assert!(s3.contains(r#""rx_denied_noroute":5"#));
        let back3: PeerInfo = serde_json::from_str(&s3).unwrap();
        let d3 = back3.debug.unwrap();
        assert_eq!(d3.rx_denied, 17);
        assert_eq!(d3.rx_denied_noroute, 5);
    }

    /// rc.275 — `PeerInfo.stalled` is wire-compatible in both directions: a
    /// pre-rc.275 daemon's JSON (no `stalled` key) deserialises to `false`,
    /// and a set flag round-trips.
    #[test]
    fn peer_info_stalled_wire_compat() {
        // Absent → default false (an old daemon talking to a new CLI).
        let old = r#"{"node_id":"n1","name":"pc","overlay_ip":null,"overlay_ip6":null,
                      "online":true,"connection":"relay","upgrading":false}"#;
        let p: PeerInfo = serde_json::from_str(old).unwrap();
        assert!(!p.stalled);
        // Set → survives a round-trip.
        let mut p2 = p.clone();
        p2.stalled = true;
        let s = serde_json::to_string(&p2).unwrap();
        assert!(s.contains(r#""stalled":true"#));
        assert!(serde_json::from_str::<PeerInfo>(&s).unwrap().stalled);
    }

    #[tokio::test]
    async fn set_device_name_wire_shape_and_default_unsupported() {
        // Wire lock: adjacently tagged, snake_case.
        assert_eq!(
            serde_json::to_string(&Request::SetDeviceName { name: "neo".into() }).unwrap(),
            r#"{"t":"set_device_name","d":{"name":"neo"}}"#
        );
        assert_eq!(
            serde_json::to_string(&Response::DeviceNameSet { name: "neo".into() }).unwrap(),
            r#"{"t":"device_name_set","d":{"name":"neo"}}"#
        );
        // Trait default: unsupported — a node without a config writer (mocks,
        // non-daemon impls) answers with a clean Error, and the sync `handle`
        // path refuses it (async-only verb).
        let s = Mock;
        assert!(matches!(
            s.set_device_name("neo").await,
            Response::Error { .. }
        ));
        assert!(matches!(
            handle(&Request::SetDeviceName { name: "neo".into() }, &s),
            Response::Error { .. }
        ));
    }

    /// FR-84 D3 — the restart verb's wire shape, locked as JSON TEXT so the
    /// test also compiles against a daemon that predates the verb and is RED
    /// there: its serde answers `unknown variant`, which is the exact phrase
    /// a newer client turns into "this service predates Apply now" — so the
    /// phrase is pinned here too, on a spelling no build will ever accept.
    #[test]
    fn restart_daemon_verb_is_on_the_wire() {
        let req: Result<Request, _> =
            serde_json::from_str(r#"{"t":"restart_daemon","d":{"reason":"settings"}}"#);
        assert!(req.is_ok(), "restart_daemon must parse: {req:?}");
        let resp: Result<Response, _> = serde_json::from_str(
            r#"{"t":"daemon_restarting","d":{"supervisor":"scm","restart_by":"supervisor","exit_code":0}}"#,
        );
        assert!(resp.is_ok(), "daemon_restarting must parse: {resp:?}");
        let old = serde_json::from_str::<Request>(r#"{"t":"restart_daemon_v0"}"#)
            .unwrap_err()
            .to_string();
        assert!(old.contains("unknown variant"), "{old}");
    }

    /// FR-84 D3 — the rest of the wire: a bare request (no reason) parses,
    /// the answer carries the pid the caller waits out, an answer from a
    /// build before `pid` still parses, and a node that cannot restart says
    /// so on both dispatch paths.
    #[tokio::test]
    async fn restart_verbs_round_trip_and_default_refuses() {
        assert_eq!(
            serde_json::from_str::<Request>(r#"{"t":"restart_daemon","d":{}}"#).unwrap(),
            Request::RestartDaemon {
                reason: String::new()
            }
        );
        let req = Request::RestartDaemon {
            reason: "settings: overlay_enabled".into(),
        };
        let wire = serde_json::to_string(&req).unwrap();
        assert_eq!(
            wire,
            r#"{"t":"restart_daemon","d":{"reason":"settings: overlay_enabled"}}"#
        );
        assert_eq!(serde_json::from_str::<Request>(&wire).unwrap(), req);

        let resp = Response::DaemonRestarting {
            supervisor: "systemd".into(),
            restart_by: "supervisor".into(),
            exit_code: 9,
            pid: 4242,
            started_at_ms: 1_700_000_000_000,
            restart_within_s: None,
        };
        let wire = serde_json::to_string(&resp).unwrap();
        // #1684 — `restart_within_s` is additive: absent (skipped) when `None`,
        // so the wire an older client parses is byte-identical.
        assert_eq!(
            wire,
            r#"{"t":"daemon_restarting","d":{"supervisor":"systemd","restart_by":"supervisor","exit_code":9,"pid":4242,"started_at_ms":1700000000000}}"#
        );
        assert_eq!(serde_json::from_str::<Response>(&wire).unwrap(), resp);
        // Present when known, and it round-trips. (Built explicitly — `..base`
        // record-update syntax is not allowed on an enum variant.)
        let with_hint = Response::DaemonRestarting {
            supervisor: "systemd".into(),
            restart_by: "supervisor".into(),
            exit_code: 9,
            pid: 4242,
            started_at_ms: 1_700_000_000_000,
            restart_within_s: Some(95),
        };
        let wire_hint = serde_json::to_string(&with_hint).unwrap();
        assert!(
            wire_hint.contains(r#""restart_within_s":95"#),
            "{wire_hint}"
        );
        assert_eq!(
            serde_json::from_str::<Response>(&wire_hint).unwrap(),
            with_hint
        );
        assert!(matches!(
            serde_json::from_str::<Response>(
                r#"{"t":"daemon_restarting","d":{"supervisor":"scm","restart_by":"supervisor","exit_code":0}}"#
            )
            .unwrap(),
            Response::DaemonRestarting {
                pid: 0,
                started_at_ms: 0,
                restart_within_s: None,
                ..
            }
        ));
        // `NodeStatus::{pid, started_at_ms}` are additive: absent from an
        // older daemon.
        let s = Mock.status();
        let old_wire = serde_json::to_string(&s).unwrap();
        assert!(!old_wire.contains("\"pid\"") && !old_wire.contains("started_at_ms"));
        let with_instance = NodeStatus {
            pid: Some(7),
            started_at_ms: Some(1_700_000_000_000),
            ..s
        };
        let back: NodeStatus =
            serde_json::from_str(&serde_json::to_string(&with_instance).unwrap()).unwrap();
        assert_eq!(
            DaemonInstance::of(&back),
            DaemonInstance::leaving(7, 1_700_000_000_000)
        );

        assert!(matches!(
            Mock.restart_daemon("x").await,
            Response::Error { .. }
        ));
        assert!(matches!(
            handle(&Request::RestartDaemon { reason: "x".into() }, &Mock),
            Response::Error { .. }
        ));
    }

    /// One classification for every client: accepted, refused (verbatim),
    /// and the exact reply an OLD daemon gives to a verb it cannot parse.
    #[test]
    fn restart_answer_classifies_accept_refuse_and_old_daemon() {
        assert_eq!(
            RestartAnswer::from_response(Response::DaemonRestarting {
                supervisor: "systemd".into(),
                restart_by: "supervisor".into(),
                exit_code: 9,
                pid: 11,
                started_at_ms: 22,
                restart_within_s: Some(95),
            }),
            RestartAnswer::Accepted {
                supervisor: "systemd".into(),
                restart_by: "supervisor".into(),
                exit_code: 9,
                leaving: DaemonInstance {
                    pid: Some(11),
                    started_at_ms: Some(22),
                },
                restart_within_s: Some(95),
            }
        );
        // A non-systemd (or older) daemon carries no bound; the caller keeps
        // its floor.
        assert_eq!(
            RestartAnswer::from_response(Response::DaemonRestarting {
                supervisor: "task".into(),
                restart_by: "caller".into(),
                exit_code: 9,
                pid: 11,
                started_at_ms: 22,
                restart_within_s: None,
            }),
            RestartAnswer::Accepted {
                supervisor: "task".into(),
                restart_by: "caller".into(),
                exit_code: 9,
                leaving: DaemonInstance {
                    pid: Some(11),
                    started_at_ms: Some(22),
                },
                restart_within_s: None,
            }
        );
        // The wait follows the bound, and never shortens below the floor.
        let floor = std::time::Duration::from_secs(60);
        assert_eq!(restart_wait(None, floor), floor);
        assert_eq!(restart_wait(Some(10), floor), floor); // 10+15 < 60
        assert_eq!(
            restart_wait(Some(95), floor),
            std::time::Duration::from_secs(95) + RESTART_WAIT_MARGIN
        );
        // …and never past the cap: a unit with TimeoutStopSec=1h must not turn
        // `roomler restart` into an hour-long hang.
        assert!(RESTART_WAIT_CAP > std::time::Duration::from_secs(95) + RESTART_WAIT_MARGIN);
        assert_eq!(restart_wait(Some(3600), floor), RESTART_WAIT_CAP);
        assert_eq!(restart_wait(Some(u64::MAX), floor), RESTART_WAIT_CAP);
        let refusal = "restarting from this device is turned off (local_restart_enabled = false)";
        assert_eq!(
            RestartAnswer::from_response(Response::Error {
                message: refusal.into()
            }),
            RestartAnswer::Refused(refusal.into())
        );
        // What `serve_connection_as` sends for a line it cannot parse — the
        // real serde error, not a hand-typed imitation of it.
        let e = serde_json::from_str::<Request>(r#"{"t":"restart_daemon_v0","d":{}}"#).unwrap_err();
        let old = format!("bad request: {e}");
        assert!(matches!(
            RestartAnswer::from_response(Response::Error { message: old }),
            RestartAnswer::Unsupported(_)
        ));
    }

    /// FR-84 D3 — the waiting caller: reachable is not "back" (the old
    /// process answers for a moment after it said yes), only another PROCESS
    /// is — and a relaunched daemon that got the old one's pid (Windows
    /// reuses a just-freed PID) is still another process; and only a caller
    /// that owns the relaunch ever starts anything, only when NOTHING answers,
    /// and only when a start is due.
    #[test]
    fn restart_wait_steps() {
        use RestartProbe::*;
        use RestartStep::*;
        let old = DaemonInstance::leaving(100, 1_000);
        // The old process, still answering: wait — whoever relaunches.
        for caller in [true, false] {
            assert_eq!(restart_step(Up(old), old, caller, true), Wait);
        }
        // A new pid: back.
        let new = DaemonInstance::leaving(101, 5_000);
        assert_eq!(restart_step(Up(new), old, true, true), Back(Some(101)));
        assert_eq!(restart_step(Up(new), old, false, false), Back(Some(101)));
        // The SAME pid, started later: the relaunched daemon, not the old
        // one — pid alone would wait here until the deadline.
        let reused = DaemonInstance::leaving(100, 5_000);
        assert_eq!(restart_step(Up(reused), old, true, true), Back(Some(100)));
        // A daemon that reports neither is not the one that accepted (that one
        // always reports both): back.
        let older_build = DaemonInstance {
            pid: None,
            started_at_ms: None,
        };
        assert_eq!(restart_step(Up(older_build), old, false, true), Back(None));
        // Nothing at all: the caller that owns the relaunch starts it — when
        // due — and a supervisor-owned relaunch is only ever waited for.
        assert_eq!(restart_step(Gone, old, true, true), StartThenWait);
        assert_eq!(restart_step(Gone, old, true, false), Wait);
        assert_eq!(restart_step(Gone, old, false, true), Wait);
        // Busy / mid-shutdown: the old process may still hold the task
        // instance, so a start now would be dropped — wait.
        assert_eq!(restart_step(Busy, old, true, true), Wait);
        // The cadence the caller re-asks at is bounded, never a hot loop.
        assert!(RESTART_START_EVERY >= RESTART_POLL * 2);
    }

    /// A stream whose reads come from a script and whose writes land in a
    /// buffer the state can inspect — so a test can ask what the client had
    /// been SENT at the moment something happened.
    struct Scripted {
        input: std::io::Cursor<Vec<u8>>,
        output: Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl tokio::io::AsyncRead for Scripted {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let n = std::io::Read::read(&mut self.input, buf.initialize_unfilled())?;
            buf.advance(n);
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl tokio::io::AsyncWrite for Scripted {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            data: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.output.lock().unwrap().extend_from_slice(data);
            std::task::Poll::Ready(Ok(data.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// Accepts or refuses every restart, and records what the client had
    /// been sent each time the loop committed one.
    struct RestartMock {
        accept: bool,
        output: Arc<std::sync::Mutex<Vec<u8>>>,
        commits: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait]
    impl LocalApiState for RestartMock {
        fn status(&self) -> NodeStatus {
            Mock.status()
        }
        fn peers(&self) -> Vec<PeerInfo> {
            Vec::new()
        }
        fn flows(&self) -> Vec<FlowInfo> {
            Vec::new()
        }
        async fn restart_daemon(&self, _reason: &str) -> Response {
            if self.accept {
                Response::DaemonRestarting {
                    supervisor: "scm".into(),
                    restart_by: "supervisor".into(),
                    exit_code: 0,
                    pid: 1,
                    started_at_ms: 2,
                    restart_within_s: None,
                }
            } else {
                Response::Error {
                    message: "refused".into(),
                }
            }
        }
        fn restart_commit(&self) {
            let sent = String::from_utf8_lossy(&self.output.lock().unwrap()).to_string();
            self.commits.lock().unwrap().push(sent);
        }
    }

    /// FR-84 D3 — the shutdown may start only once the client has its
    /// answer: `restart_commit` runs after the `daemon_restarting` line is
    /// written, exactly once, and never for a refusal or any other verb.
    #[tokio::test]
    async fn restart_commit_runs_only_after_the_answer_is_written() {
        for accept in [true, false] {
            let output = Arc::new(std::sync::Mutex::new(Vec::new()));
            let state = RestartMock {
                accept,
                output: output.clone(),
                commits: std::sync::Mutex::new(Vec::new()),
            };
            let script =
                b"{\"t\":\"status\"}\n{\"t\":\"restart_daemon\",\"d\":{\"reason\":\"x\"}}\n";
            let stream = Scripted {
                input: std::io::Cursor::new(script.to_vec()),
                output: output.clone(),
            };
            serve_connection_as(stream, &state, ClientPeer::UNKNOWN)
                .await
                .unwrap();
            let commits = state.commits.lock().unwrap().clone();
            if accept {
                assert_eq!(commits.len(), 1, "exactly one commit: {commits:?}");
                assert!(
                    commits[0].contains(r#""t":"daemon_restarting""#),
                    "the answer must already be on the wire when the shutdown starts: {:?}",
                    commits[0]
                );
            } else {
                assert!(commits.is_empty(), "a refusal never starts a shutdown");
            }
        }
    }

    #[tokio::test]
    async fn config_verbs_wire_shape_and_default_unsupported() {
        // Wire lock: adjacently tagged, snake_case; unset `value` is
        // omitted on the wire (both directions), a set value is a plain
        // string.
        assert_eq!(
            serde_json::to_string(&Request::ConfigGet).unwrap(),
            r#"{"t":"config_get"}"#
        );
        assert_eq!(
            serde_json::to_string(&Request::ConfigSet {
                key: "overlay_quic".into(),
                value: Some("true".into()),
            })
            .unwrap(),
            r#"{"t":"config_set","d":{"key":"overlay_quic","value":"true"}}"#
        );
        // Clearing a key: `value` may be omitted entirely by old/terse
        // clients — serde(default) maps that to None.
        assert_eq!(
            serde_json::from_str::<Request>(r#"{"t":"config_set","d":{"key":"overlay_quic"}}"#)
                .unwrap(),
            Request::ConfigSet {
                key: "overlay_quic".into(),
                value: None,
            }
        );
        let entry = ConfigEntry {
            key: "overlay_quic".into(),
            value: None,
            kind: "tribool".into(),
            restart_required: true,
            description: "d".into(),
            group: String::new(),
            group_label: String::new(),
            tier: String::new(),
            default: None,
        };
        // The pre-D2 shape: the four FR-84 D2 fields are omitted while
        // empty, so an entry a D2 daemon has not classified is byte-for-byte
        // what it always was.
        assert_eq!(
            serde_json::to_string(&Response::ConfigUpdated {
                entry: entry.clone()
            })
            .unwrap(),
            r#"{"t":"config_updated","d":{"entry":{"key":"overlay_quic","kind":"tribool","restart_required":true,"description":"d"}}}"#
        );
        assert_eq!(
            serde_json::to_string(&Response::ConfigEntries(vec![])).unwrap(),
            r#"{"t":"config_entries","d":[]}"#
        );
        // Trait defaults: unsupported on non-daemon impls; the sync
        // `handle` path refuses both (async-only verbs).
        let s = Mock;
        assert!(matches!(s.config_entries().await, Response::Error { .. }));
        assert!(matches!(
            s.config_set("overlay_quic", None).await,
            Response::Error { .. }
        ));
        assert!(matches!(
            handle(&Request::ConfigGet, &s),
            Response::Error { .. }
        ));
    }

    /// FR-84 D2 — the Settings metadata on a `ConfigEntry` is ADDITIVE in
    /// both directions: an entry a pre-D2 daemon sends (no `group`,
    /// `group_label`, `tier`, `default`) still parses, with the fields empty
    /// — which is exactly the cue the desktop uses to fall back to the flat
    /// list — and a classified entry round-trips with every field intact.
    #[test]
    fn config_entry_settings_metadata_is_additive() {
        // An OLD daemon's entry, exactly as it was serialised before D2.
        let old: ConfigEntry = serde_json::from_str(
            r#"{"key":"overlay_quic","kind":"tribool","restart_required":true,"description":"d"}"#,
        )
        .unwrap();
        assert_eq!(old.group, "");
        assert_eq!(old.group_label, "");
        assert_eq!(old.tier, "");
        assert_eq!(old.default, None);
        assert!(old.restart_required);

        // A NEW daemon's entry: every field survives a round-trip, and the
        // wire spellings of the metadata are plain strings a client can
        // switch on without a table of its own.
        let full = ConfigEntry {
            key: "exec_enabled".into(),
            value: Some("false".into()),
            kind: "bool".into(),
            restart_required: false,
            description: "d".into(),
            group: "access".into(),
            group_label: "Access & consent".into(),
            tier: "essential".into(),
            default: Some("false".into()),
        };
        let json = serde_json::to_string(&full).unwrap();
        assert_eq!(
            json,
            r#"{"key":"exec_enabled","value":"false","kind":"bool","restart_required":false,"description":"d","group":"access","group_label":"Access & consent","tier":"essential","default":"false"}"#
        );
        let back: ConfigEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back, full);

        // A classified key whose built-in default is UNSET (a tribool) omits
        // `default` rather than sending `null`, so "unset by default" and
        // "an old daemon" look the same on that one field — `group` is the
        // discriminator, never `default`.
        let unset = ConfigEntry {
            default: None,
            group: "network_carriers".into(),
            ..full.clone()
        };
        let json = serde_json::to_string(&unset).unwrap();
        assert!(!json.contains("\"default\""), "{json}");
        assert!(json.contains("\"group\":\"network_carriers\""), "{json}");
    }

    /// FR-84 D4 — the encoder-caps verb: wire shape locked (the desktop and
    /// `roomler` depend on the discriminators), every summary field
    /// additive (absent when default, so an old reader sees nothing new and
    /// a new reader of an old daemon fills in defaults), and the trait
    /// default is a clean Error — a mock is not an encoder host.
    #[tokio::test]
    async fn encoder_caps_wire_shape_round_trip_and_default_unsupported() {
        assert_eq!(
            serde_json::to_string(&Request::EncoderCaps).unwrap(),
            r#"{"t":"encoder_caps"}"#
        );
        // A `not_probed` answer is exactly one field: nothing else is known
        // yet, and nothing else is sent.
        let pending = EncoderCapsSummary {
            state: "not_probed".into(),
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_string(&Response::EncoderCaps(pending.clone())).unwrap(),
            r#"{"t":"encoder_caps","d":{"state":"not_probed"}}"#
        );
        let full = EncoderCapsSummary {
            state: "ready".into(),
            cells: vec![
                EncoderCell {
                    codec: "hevc".into(),
                    backend: "nvenc".into(),
                    chroma: vec!["yuv420".into(), "yuv444".into()],
                    hardware: true,
                },
                EncoderCell {
                    codec: "h264".into(),
                    backend: "openh264".into(),
                    chroma: vec!["yuv420".into()],
                    hardware: false,
                },
            ],
            hw_encoders: vec!["ffmpeg-hevc_nvenc".into(), "openh264-sw".into()],
            codecs: vec!["h264".into(), "h265".into()],
            probe_ms: Some(812),
            probe_cached: true,
            denied: vec!["hevc_qsv:yuv444".into()],
            encoder_preference: Some("auto".into()),
        };
        let s = serde_json::to_string(&Response::EncoderCaps(full.clone())).unwrap();
        assert!(s.starts_with(r#"{"t":"encoder_caps","d":{"state":"ready","cells":[{"codec":"hevc","backend":"nvenc","chroma":["yuv420","yuv444"],"hardware":true},{"codec":"h264","backend":"openh264","chroma":["yuv420"]}]"#), "{s}");
        assert!(s.contains(r#""probe_ms":812,"probe_cached":true,"denied":["hevc_qsv:yuv444"],"encoder_preference":"auto"}"#), "{s}");
        // A software cell omits `hardware` (false is the default).
        assert!(!s.contains(r#""hardware":false"#), "{s}");
        match serde_json::from_str::<Response>(&s).unwrap() {
            Response::EncoderCaps(back) => assert_eq!(back, full),
            other => panic!("unexpected: {other:?}"),
        }
        // A newer daemon's extra field is ignored; a missing one defaults.
        let newer: EncoderCapsSummary =
            serde_json::from_str(r#"{"state":"ready","future":1}"#).unwrap();
        assert_eq!(newer.state, "ready");
        assert!(newer.cells.is_empty() && !newer.probe_cached);

        // Trait default: a mock reports no encoder caps — the sync dispatch
        // turns that into a clean Error rather than an empty matrix that
        // would read as "this host has no encoders".
        let s = Mock;
        assert!(s.encoder_caps().is_none());
        assert!(matches!(
            handle(&Request::EncoderCaps, &s),
            Response::Error { .. }
        ));
    }

    /// FR-84 D4 — `NodeStatus.files_dir` is additive: absent when the
    /// daemon has none to report, and an old status line without it still
    /// parses.
    #[test]
    fn node_status_files_dir_is_additive() {
        let mut st = Mock.status();
        let without = serde_json::to_string(&st).unwrap();
        assert!(!without.contains("files_dir"));
        st.files_dir = Some(r"C:\Users\alice\Downloads".into());
        let with = serde_json::to_string(&st).unwrap();
        assert!(
            with.contains(r#""files_dir":"C:\\Users\\alice\\Downloads""#),
            "{with}"
        );
        let back: NodeStatus = serde_json::from_str(&without).unwrap();
        assert_eq!(back.files_dir, None);
    }

    #[tokio::test]
    async fn route_verbs_dispatch_and_lock_wire_shape() {
        let s = Mock;
        // RouteList is sync — through `handle`; the Mock has no reconciler,
        // so the default-impl empty list comes back.
        assert!(matches!(
            handle(&Request::RouteList, &s),
            Response::Routes(ref v) if v.is_empty()
        ));
        // The mutating Route* verbs are async-path only; the sync arm errors.
        assert!(matches!(
            handle(&Request::RouteRemove { id: "r".into() }, &s),
            Response::Error { .. }
        ));
        // Default trait impls report unsupported.
        assert!(matches!(s.route_remove("r").await, Response::Error { .. }));

        // Wire shape — locks the discriminators the CLI + desktop depend on.
        let route = RouteDescriptor {
            id: "pg-buildhost".into(),
            kind: FlowKind::Forward,
            node: "aabbcc".into(),
            local: 15432,
            remote: Some("db:5432".into()),
            transport: "auto".into(),
            enabled: true,
            org: None,
        };
        assert_eq!(
            serde_json::to_string(&Request::RouteAdd {
                route: route.clone()
            })
            .unwrap(),
            r#"{"t":"route_add","d":{"route":{"id":"pg-buildhost","kind":"forward","node":"aabbcc","local":15432,"remote":"db:5432","transport":"auto","enabled":true}}}"#
        );
        assert_eq!(
            serde_json::to_string(&Request::RouteSetEnabled {
                id: "pg-buildhost".into(),
                enabled: false,
            })
            .unwrap(),
            r#"{"t":"route_set_enabled","d":{"id":"pg-buildhost","enabled":false}}"#
        );
        // FR-84 D1 — the atomic replace, keyed by the descriptor's own id.
        assert_eq!(
            serde_json::to_string(&Request::RouteUpdate {
                route: route.clone()
            })
            .unwrap(),
            r#"{"t":"route_update","d":{"route":{"id":"pg-buildhost","kind":"forward","node":"aabbcc","local":15432,"remote":"db:5432","transport":"auto","enabled":true}}}"#
        );
        assert_eq!(
            serde_json::to_string(&Response::RouteReplaced {
                route: route.clone()
            })
            .unwrap(),
            r#"{"t":"route_replaced","d":{"route":{"id":"pg-buildhost","kind":"forward","node":"aabbcc","local":15432,"remote":"db:5432","transport":"auto","enabled":true}}}"#
        );
        assert!(matches!(
            handle(
                &Request::RouteUpdate {
                    route: route.clone()
                },
                &s
            ),
            Response::Error { .. }
        ));
        assert!(matches!(
            s.route_update(route.clone()).await,
            Response::Error { .. }
        ));
        // A daemon older than the verb answers the request line with a
        // bad-request error — the reply a client must render as "this
        // service predates route editing", never as an empty page.
        let old_daemon: Response = serde_json::from_str(
            r#"{"t":"error","d":{"message":"bad request: unknown variant `route_update`"}}"#,
        )
        .unwrap();
        assert!(
            matches!(old_daemon, Response::Error { ref message } if message.contains("unknown variant"))
        );
        assert_eq!(
            serde_json::to_string(&Response::RouteAdded {
                route: route.clone()
            })
            .unwrap(),
            r#"{"t":"route_added","d":{"route":{"id":"pg-buildhost","kind":"forward","node":"aabbcc","local":15432,"remote":"db:5432","transport":"auto","enabled":true}}}"#
        );
        let info = RouteInfo {
            route,
            state: RouteState::Backoff {
                next_retry_secs: 30,
                last_error: "bind: in use".into(),
                flow_id: None,
                attempts: 0,
            },
        };
        let s = serde_json::to_string(&Response::Routes(vec![info.clone()])).unwrap();
        assert!(
            s.contains(
                r#""state":{"state":"backoff","next_retry_secs":30,"last_error":"bind: in use"}"#
            ),
            "the pre-#1685 backoff shape is byte-identical: {s}"
        );
        assert_eq!(
            serde_json::from_str::<Response>(&s).unwrap(),
            Response::Routes(vec![info])
        );
        // A minimal hand-written config-style descriptor: id/remote/transport
        // omitted, enabled defaults TRUE (a bare [[tunnel_routes]] entry is
        // live), socks5 needs no remote.
        assert_eq!(
            serde_json::from_str::<RouteDescriptor>(
                r#"{"kind":"socks5","node":"aabbcc","local":1080}"#
            )
            .unwrap(),
            RouteDescriptor {
                id: String::new(),
                kind: FlowKind::Socks5,
                node: "aabbcc".into(),
                local: 1080,
                remote: None,
                transport: String::new(),
                enabled: true,
                org: None,
            }
        );
        // Terminal-state wire shape (the pane's re-enable affordance keys on
        // "failed").
        assert_eq!(
            serde_json::to_string(&RouteState::Failed {
                reason: "revoked".into()
            })
            .unwrap(),
            r#"{"state":"failed","reason":"revoked"}"#
        );
    }

    /// #1685 — the route-state wire is ADDITIVE in both directions. The tag
    /// set is unchanged and the new fields are skipped when empty, so a
    /// reader that predates them (the pre-#1685 enum, reproduced here as a
    /// pre-#1685 companion / CLI would compile it) parses everything a new
    /// daemon emits and renders a dialing or retrying route as `pending` /
    /// `backoff … <error>` — true, never a false `active`. A reader from this
    /// version on maps a tag it does not know to `Unknown` instead of failing
    /// the whole `RouteList` reply.
    #[test]
    fn route_state_wire_is_additive_and_an_older_reader_still_parses_it() {
        /// `RouteState` exactly as shipped before #1685.
        #[derive(Deserialize, Debug, PartialEq)]
        #[serde(tag = "state", rename_all = "snake_case")]
        enum OldRouteState {
            Disabled,
            Pending,
            Active {
                flow_id: String,
            },
            Backoff {
                next_retry_secs: u64,
                last_error: String,
            },
            Failed {
                reason: String,
            },
        }

        // Byte-identical to the old wire when the new fields are empty.
        assert_eq!(
            serde_json::to_string(&RouteState::Pending { flow_id: None }).unwrap(),
            r#"{"state":"pending"}"#
        );
        // The new daemon's "connecting" and "retrying" shapes…
        let connecting = RouteState::Pending {
            flow_id: Some("fl-2".into()),
        };
        let retrying = RouteState::Backoff {
            next_retry_secs: 4,
            last_error: "server error during tunnel.open: agent_unavailable: agent is offline"
                .into(),
            flow_id: Some("fl-2".into()),
            attempts: 3,
        };
        let connecting_json = serde_json::to_string(&connecting).unwrap();
        let retrying_json = serde_json::to_string(&retrying).unwrap();
        assert_eq!(connecting_json, r#"{"state":"pending","flow_id":"fl-2"}"#);
        assert_eq!(
            retrying_json,
            r#"{"state":"backoff","next_retry_secs":4,"last_error":"server error during tunnel.open: agent_unavailable: agent is offline","flow_id":"fl-2","attempts":3}"#
        );
        // …round-trip on this version…
        assert_eq!(
            serde_json::from_str::<RouteState>(&connecting_json).unwrap(),
            connecting
        );
        assert_eq!(
            serde_json::from_str::<RouteState>(&retrying_json).unwrap(),
            retrying
        );
        // …and an OLDER reader parses them too, as true (if less specific)
        // statements — never `active`.
        assert_eq!(
            serde_json::from_str::<OldRouteState>(&connecting_json).unwrap(),
            OldRouteState::Pending
        );
        assert_eq!(
            serde_json::from_str::<OldRouteState>(&retrying_json).unwrap(),
            OldRouteState::Backoff {
                next_retry_secs: 4,
                last_error: "server error during tunnel.open: agent_unavailable: agent is offline"
                    .into(),
            }
        );
        // An OLDER daemon's rows parse on this version with the new fields
        // at their defaults.
        assert_eq!(
            serde_json::from_str::<RouteState>(r#"{"state":"pending"}"#).unwrap(),
            RouteState::Pending { flow_id: None }
        );
        assert_eq!(
            serde_json::from_str::<RouteState>(
                r#"{"state":"backoff","next_retry_secs":30,"last_error":"bind: in use"}"#
            )
            .unwrap(),
            RouteState::Backoff {
                next_retry_secs: 30,
                last_error: "bind: in use".into(),
                flow_id: None,
                attempts: 0,
            }
        );
        assert_eq!(
            RouteState::Active {
                flow_id: "fl-1".into()
            }
            .flow_id(),
            Some("fl-1")
        );
        assert_eq!(retrying.flow_id(), Some("fl-2"));
        assert_eq!(RouteState::Disabled.flow_id(), None);

        // A tag from a daemon NEWER than this reader: the row survives as
        // `Unknown`, and so does the rest of the reply.
        let newer: Response = serde_json::from_str(
            r#"{"t":"routes","d":[
                {"route":{"id":"a","kind":"socks5","node":"aabbcc","local":1081},"state":{"state":"draining","flow_id":"fl-9","reason":"x"}},
                {"route":{"id":"b","kind":"socks5","node":"aabbcc","local":1082},"state":{"state":"active","flow_id":"fl-3"}}
            ]}"#,
        )
        .unwrap();
        match newer {
            Response::Routes(rows) => {
                assert_eq!(rows.len(), 2);
                assert_eq!(rows[0].state, RouteState::Unknown);
                assert_eq!(rows[0].state.flow_id(), None);
                assert_eq!(
                    rows[1].state,
                    RouteState::Active {
                        flow_id: "fl-3".into()
                    }
                );
            }
            other => panic!("expected routes: {other:?}"),
        }
        // …whereas the OLD reader could not: a new tag failed its whole reply.
        // (That is why #1685 kept the tag set and added fields instead.)
        assert!(
            serde_json::from_str::<OldRouteState>(r#"{"state":"connecting","flow_id":"fl-2"}"#)
                .is_err()
        );
    }

    #[test]
    fn org_status_wire_shape_and_omissions() {
        // Multi-org P1 — lock the OrgStatus row shape + the NodeStatus.orgs
        // omission rules (single-org daemons stay byte-identical on the wire;
        // zero counters and absent errors are skipped).
        let row = OrgStatus {
            label: "acme".into(),
            server_url: "https://acme.invalid".into(),
            tenant_id: Some("aabbccddeeff001122334455".into()),
            agent_id: Some("554433221100ffeeddccbbaa".into()),
            primary: false,
            enabled: true,
            connected: false,
            terminal_error: None,
            updates_ignored: 0,
            overlay_mode: String::new(),
            token_expires_at: None,
        };
        assert_eq!(
            serde_json::to_string(&row).unwrap(),
            r#"{"label":"acme","server_url":"https://acme.invalid","tenant_id":"aabbccddeeff001122334455","agent_id":"554433221100ffeeddccbbaa","primary":false,"enabled":true,"connected":false}"#
        );
        // Old-daemon JSON (no orgs field) parses to an empty list; a
        // populated one round-trips.
        let old = r#"{"node_id":"n","name":"h","version":"v","mode":"service","connected":true}"#;
        let st: NodeStatus = serde_json::from_str(old).unwrap();
        assert!(st.orgs.is_empty());
        let mut with = st.clone();
        with.orgs = vec![OrgStatus {
            terminal_error: Some("server goodbye".into()),
            updates_ignored: 2,
            ..row
        }];
        let s = serde_json::to_string(&with).unwrap();
        assert!(
            s.contains(r#""terminal_error":"server goodbye""#),
            "got {s}"
        );
        assert!(s.contains(r#""updates_ignored":2"#), "got {s}");
        assert_eq!(serde_json::from_str::<NodeStatus>(&s).unwrap(), with);
        // Empty orgs is omitted entirely (old-CLI-identical wire).
        assert!(!serde_json::to_string(&st).unwrap().contains("orgs"));
    }

    /// `privileged` is additive both ways, and independent of `mode`. An older
    /// daemon sends no such key, which parses as `None`: a new CLI then names
    /// no account rather than guessing one. `None` is never written. Both
    /// values round-trip with `mode` untouched, because a per-user daemon is
    /// still a `Service` node.
    #[test]
    fn privileged_is_additive_and_independent_of_mode() {
        let old = r#"{"node_id":"n","name":"h","version":"v","mode":"service","connected":true}"#;
        let st: NodeStatus = serde_json::from_str(old).unwrap();
        assert_eq!(st.privileged, None);
        assert!(!serde_json::to_string(&st).unwrap().contains("privileged"));
        for p in [true, false] {
            let with = NodeStatus {
                privileged: Some(p),
                ..st.clone()
            };
            let wire = serde_json::to_string(&with).unwrap();
            assert!(wire.contains(&format!(r#""privileged":{p}"#)), "{wire}");
            let back: NodeStatus = serde_json::from_str(&wire).unwrap();
            assert_eq!(back.privileged, Some(p));
            assert_eq!(back.mode, DaemonMode::Service);
        }
    }

    /// FR-49 — an OLDER daemon reports no `overlay_mode`, and that must parse
    /// as "unknown", never as `off`. The two are opposite claims: `off` says
    /// the operator's device is not on that org's mesh; absent says nobody
    /// asked. Collapsing them would rebuild the exact ambiguity this field was
    /// added to remove.
    #[test]
    fn an_absent_overlay_mode_is_not_off() {
        let old = r#"{"label":"acme","server_url":"https://acme.invalid","primary":false,"enabled":true,"connected":true}"#;
        let row: OrgStatus = serde_json::from_str(old).unwrap();
        assert_eq!(row.overlay_mode, "", "absent stays empty, not \"off\"");
        assert_ne!(row.overlay_mode, "off");

        // And a reporting daemon's `off` is carried verbatim, so the two are
        // distinguishable downstream.
        let reported = r#"{"label":"acme","server_url":"https://acme.invalid","primary":false,"enabled":true,"connected":true,"overlay_mode":"off"}"#;
        let row: OrgStatus = serde_json::from_str(reported).unwrap();
        assert_eq!(row.overlay_mode, "off");
    }

    #[test]
    fn response_round_trips_struct_and_sequence_payloads() {
        // Adjacently-tagged so a sequence payload (Peers) is legal where an
        // internally-tagged enum would reject it — locks that choice.
        let peers = handle(&Request::Peers, &Mock);
        let s = serde_json::to_string(&peers).unwrap();
        assert!(s.starts_with(r#"{"t":"peers","d":["#), "got {s}");
        assert_eq!(serde_json::from_str::<Response>(&s).unwrap(), peers);

        let status = handle(&Request::Status, &Mock);
        let s = serde_json::to_string(&status).unwrap();
        assert!(s.contains(r#""t":"status""#));
        assert_eq!(serde_json::from_str::<Response>(&s).unwrap(), status);

        let err = Response::Error {
            message: "nope".into(),
        };
        assert_eq!(
            serde_json::to_string(&err).unwrap(),
            r#"{"t":"error","d":{"message":"nope"}}"#
        );

        // Connection types serialise snake_case (UI + wire contract).
        assert_eq!(
            serde_json::to_string(&ConnectionType::Tunnel).unwrap(),
            r#""tunnel""#
        );
    }

    #[tokio::test]
    async fn serve_connection_round_trips_and_recovers_from_garbage() {
        // In-memory duplex stands in for the named pipe / unix socket, so the
        // dispatch loop is transport-independently tested.
        let (client, server) = tokio::io::duplex(4096);
        let srv = tokio::spawn(async move {
            let state = Mock;
            serve_connection(server, &state).await
        });
        let (crd, mut cwr) = tokio::io::split(client);
        let mut clines = tokio::io::BufReader::new(crd).lines();

        cwr.write_all(b"{\"t\":\"status\"}\n").await.unwrap();
        let r = clines.next_line().await.unwrap().unwrap();
        assert!(matches!(
            serde_json::from_str::<Response>(&r).unwrap(),
            Response::Status(_)
        ));

        cwr.write_all(b"{\"t\":\"peers\"}\n").await.unwrap();
        let r = clines.next_line().await.unwrap().unwrap();
        assert!(matches!(
            serde_json::from_str::<Response>(&r).unwrap(),
            Response::Peers(p) if p.len() == 2
        ));

        // Garbage line → Error response, and the connection survives for the
        // next request (recoverable, not a frame break).
        cwr.write_all(b"not json\n").await.unwrap();
        let r = clines.next_line().await.unwrap().unwrap();
        assert!(matches!(
            serde_json::from_str::<Response>(&r).unwrap(),
            Response::Error { .. }
        ));

        // Client closes the stream → serve_connection returns Ok(()).
        drop(cwr);
        drop(clines);
        srv.await.unwrap().unwrap();
    }

    // ── FR-85 — the recording verbs and the console-user gate ───────────────

    #[test]
    fn the_console_user_decision_table() {
        let win = |s| ClientPeer {
            session_id: Some(s),
            uid: None,
            system_account: None,
            ..ClientPeer::UNKNOWN
        };
        let unix = |u| ClientPeer {
            session_id: None,
            uid: Some(u),
            system_account: None,
            ..ClientPeer::UNKNOWN
        };
        // Windows: the peer's session must be the active console session.
        assert!(peer_is_console_user(&win(1), Some(1), None));
        assert!(
            !peer_is_console_user(&win(2), Some(1), None),
            "an RDP session"
        );
        assert!(
            !peer_is_console_user(&win(1), None, None),
            "no console session at all"
        );
        // Unix: the daemon's own uid, or root.
        assert!(peer_is_console_user(&unix(1000), None, Some(1000)));
        assert!(peer_is_console_user(&unix(0), None, Some(1000)));
        assert!(!peer_is_console_user(&unix(1001), None, Some(1000)));
        // Fail-closed on anything unknown.
        assert!(!peer_is_console_user(
            &ClientPeer::UNKNOWN,
            Some(1),
            Some(1000)
        ));
        assert!(!ClientPeer::UNKNOWN.is_console_user());
    }

    /// FR-92 P10 — who may turn keep busy ON. Root never: it is how
    /// `roomler exec` arrives on Unix, and [`peer_is_console_user`] would let
    /// it through. P10b — SYSTEM never either, nor a Windows peer whose
    /// account could not be read.
    #[test]
    fn the_keep_busy_start_decision_table() {
        // A Windows peer, as a person (a user account read from its token).
        let win = |s| ClientPeer {
            session_id: Some(s),
            uid: None,
            system_account: Some(false),
            ..ClientPeer::UNKNOWN
        };
        let win_as = |s, system_account| ClientPeer {
            session_id: Some(s),
            uid: None,
            system_account,
            ..ClientPeer::UNKNOWN
        };
        let unix = |u| ClientPeer {
            session_id: None,
            uid: Some(u),
            system_account: None,
            ..ClientPeer::UNKNOWN
        };
        let full = Scope::Full;
        let person = Scope::Person;
        // Windows: the active console session only; session 0 never.
        assert!(peer_may_start_keep_busy(&win(1), full, Some(1), None));
        // P10b — SYSTEM (and LocalService / NetworkService) never, even inside
        // the console session: that is how `roomler exec` arrives on a host in
        // SystemContext mode. The console-user gate would let it through.
        assert!(
            !peer_may_start_keep_busy(&win_as(1, Some(true)), full, Some(1), None),
            "SYSTEM in the console session"
        );
        assert!(
            peer_is_console_user(&win_as(1, Some(true)), Some(1), None),
            "the gate this one tightens"
        );
        // P10b — an account the listener could not read is a refusal.
        assert!(
            !peer_may_start_keep_busy(&win_as(1, None), full, Some(1), None),
            "an unreadable account"
        );
        assert!(
            !peer_may_start_keep_busy(&win(2), full, Some(1), None),
            "an RDP session"
        );
        assert!(
            !peer_may_start_keep_busy(&win(0), full, Some(0), None),
            "session 0"
        );
        assert!(
            !peer_may_start_keep_busy(&win(1), full, None, None),
            "no console"
        );
        // A per-user daemon: its owner — and NOT root, unlike the console gate.
        assert!(peer_may_start_keep_busy(&unix(501), full, None, Some(501)));
        assert!(
            !peer_may_start_keep_busy(&unix(0), full, None, Some(501)),
            "root"
        );
        assert!(
            peer_is_console_user(&unix(0), None, Some(501)),
            "the gate this one tightens"
        );
        assert!(
            !peer_may_start_keep_busy(&unix(502), full, None, Some(501)),
            "another user"
        );
        // A root daemon's own socket: only root reaches it, and root may not.
        assert!(!peer_may_start_keep_busy(&unix(0), full, None, Some(0)));
        // The person socket of a system install: its person; root never.
        assert!(peer_may_start_keep_busy(&unix(1000), person, None, Some(0)));
        assert!(!peer_may_start_keep_busy(&unix(0), person, None, Some(0)));
        // Fail closed.
        for scope in [full, person] {
            assert!(!peer_may_start_keep_busy(
                &ClientPeer::UNKNOWN,
                scope,
                Some(1),
                Some(501)
            ));
        }
    }

    /// FR-92 P10 — the start's wire. A bare start (no options) is the
    /// product default.
    #[test]
    fn the_keep_busy_start_round_trips() {
        let req = Request::KeepBusyOn {
            opts: KeepBusyStartOpts {
                pattern: Some("wander".into()),
                size: Some("l".into()),
                speed: None,
                resume_after_s: Some(10),
                auto_off_min: Some(60),
            },
        };
        let j = serde_json::to_string(&req).unwrap();
        assert_eq!(
            j,
            r#"{"t":"keep_busy_on","d":{"opts":{"pattern":"wander","size":"l","resume_after_s":10,"auto_off_min":60}}}"#
        );
        assert_eq!(serde_json::from_str::<Request>(&j).unwrap(), req);
        let bare: Request = serde_json::from_str(r#"{"t":"keep_busy_on","d":{}}"#).unwrap();
        assert_eq!(
            bare,
            Request::KeepBusyOn {
                opts: KeepBusyStartOpts::default()
            }
        );
    }

    /// FR-92 P10 — the gate in the dispatcher: root and an unknown peer are
    /// refused before any state is asked; status and off stay open to them.
    #[tokio::test]
    async fn a_keep_busy_start_from_root_or_an_unknown_peer_is_refused() {
        let root = ClientPeer {
            session_id: None,
            uid: Some(0),
            system_account: None,
            ..ClientPeer::UNKNOWN
        };
        for peer in [root, ClientPeer::UNKNOWN] {
            let r = ask(peer.clone(), r#"{"t":"keep_busy_on","d":{}}"#).await;
            assert!(
                matches!(&r, Response::Error { message }
                    if message.contains("turn keep busy on") && message.contains("root or SYSTEM")),
                "{peer:?} → {r:?}"
            );
            assert!(matches!(
                ask(peer, r#"{"t":"keep_busy_off"}"#).await,
                Response::KeepBusy(_)
            ));
        }
    }

    /// FR-92 P10 — the person a per-user daemon runs as reaches the state.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_keep_busy_start_from_the_person_reaches_the_state() {
        let me = ClientPeer {
            session_id: None,
            uid: own_uid(),
            system_account: None,
            ..ClientPeer::UNKNOWN
        };
        if me.uid == Some(0) {
            return; // a root test runner IS root: the case above covers it
        }
        assert!(matches!(
            ask(
                me,
                r#"{"t":"keep_busy_on","d":{"opts":{"pattern":"circle"}}}"#
            )
            .await,
            Response::KeepBusy(_)
        ));
    }

    /// FR-92 P10b — the accounts the Windows keep-busy gate refuses, by SID:
    /// SYSTEM, LocalService and NetworkService, and nothing a person signs in
    /// as.
    #[cfg(windows)]
    #[test]
    fn service_account_sids_are_system_and_its_kin() {
        use windows_sys::Win32::Security::{
            CreateWellKnownSid, WELL_KNOWN_SID_TYPE, WinBuiltinUsersSid, WinInteractiveSid,
            WinLocalServiceSid, WinLocalSystemSid, WinNetworkServiceSid, WinWorldSid,
        };
        let is_service = |kind: WELL_KNOWN_SID_TYPE| {
            let mut buf = [0u64; 16];
            let mut len = std::mem::size_of_val(&buf) as u32;
            // SAFETY: `buf` is writable for `len` bytes; these well-known SIDs
            // need no domain SID.
            let ok = unsafe {
                CreateWellKnownSid(
                    kind,
                    std::ptr::null_mut(),
                    buf.as_mut_ptr().cast(),
                    &mut len,
                )
            };
            assert_ne!(ok, 0, "CreateWellKnownSid({kind})");
            sid_is_service_account(buf.as_mut_ptr().cast())
        };
        assert!(is_service(WinLocalSystemSid), "SYSTEM");
        assert!(is_service(WinLocalServiceSid), "LocalService");
        assert!(is_service(WinNetworkServiceSid), "NetworkService");
        assert!(!is_service(WinWorldSid), "Everyone");
        assert!(!is_service(WinBuiltinUsersSid), r"BUILTIN\Users");
        assert!(!is_service(WinInteractiveSid), "INTERACTIVE");
    }

    /// FR-92 P10b — the probe the pipe listener runs at accept time, against a
    /// real pipe: a client this test process opens is read from the OS as this
    /// process — its session, and a person's account. CI runs the tests as an
    /// admin user, not as SYSTEM, and so does a developer.
    #[cfg(windows)]
    #[tokio::test]
    async fn a_pipe_client_is_read_from_its_token() {
        use std::os::windows::io::AsRawHandle;
        use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};
        let pipe = format!(r"\\.\pipe\roomler-test-p10b-{}", std::process::id());
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&pipe)
            .unwrap();
        let _client = ClientOptions::new().open(&pipe).unwrap();
        server.connect().await.unwrap();
        let peer = pipe_client_peer(server.as_raw_handle());
        assert!(peer.session_id.is_some(), "{peer:?}");
        assert_eq!(
            peer.session_id,
            process_session(std::process::id()),
            "the client's session is this process's"
        );
        assert_eq!(peer.uid, None);
        assert_eq!(
            peer.system_account,
            Some(false),
            "a person's token, read: {peer:?}"
        );
        // FR-90 P3-9-2b — and its account, by SID, from the same token: this
        // process's own, so the daemon's own account may connect.
        assert!(
            peer.sid.as_deref().is_some_and(|s| s.starts_with("S-1-5-")),
            "{peer:?}"
        );
        assert_eq!(peer.sid.as_deref(), own_sid(), "the client is this process");
        assert!(peer.elevated.is_some(), "its elevation, read: {peer:?}");
        assert!(peer.may_connect(), "{peer:?}");
        assert_eq!(
            peer.asker(),
            peer.sid.clone().map(|sid| Asker::Windows { sid })
        );
    }

    #[test]
    fn the_recording_verbs_round_trip() {
        for req in [
            Request::RecordStart {
                opts: RecordStartOpts {
                    fps: Some(60),
                    encoder: Some("software".into()),
                    max_minutes: Some(5),
                    system_audio: true,
                    microphone: false,
                },
            },
            Request::RecordStop,
            Request::RecordStatus,
            Request::RecordingsList,
            Request::RecordingDelete {
                name: "Roomler Recording 2026-09-25 14-30-12.mp4".into(),
            },
        ] {
            let j = serde_json::to_string(&req).unwrap();
            assert_eq!(serde_json::from_str::<Request>(&j).unwrap(), req, "{j}");
        }
        // An older client's bare start (no opts) still parses, with audio off.
        let bare: Request = serde_json::from_str(r#"{"t":"record_start","d":{}}"#).unwrap();
        assert_eq!(
            bare,
            Request::RecordStart {
                opts: RecordStartOpts::default()
            }
        );
        let resp = Response::Recording(RecordingState {
            active: true,
            path: Some("C:\\x\\r.mp4".into()),
            fps: 30,
            ..Default::default()
        });
        let j = serde_json::to_string(&resp).unwrap();
        assert_eq!(serde_json::from_str::<Response>(&j).unwrap(), resp);
    }

    async fn ask(peer: ClientPeer, line: &str) -> Response {
        let (client, server) = tokio::io::duplex(4096);
        let srv = tokio::spawn(async move {
            let state = Mock;
            serve_connection_as(server, &state, peer).await
        });
        let (crd, mut cwr) = tokio::io::split(client);
        let mut clines = tokio::io::BufReader::new(crd).lines();
        cwr.write_all(format!("{line}\n").as_bytes()).await.unwrap();
        let r = clines.next_line().await.unwrap().unwrap();
        drop(cwr);
        drop(clines);
        srv.await.unwrap().unwrap();
        serde_json::from_str(&r).unwrap()
    }

    fn is_console_refusal(r: &Response) -> bool {
        matches!(r, Response::Error { message } if message.contains("console"))
    }

    fn is_person_refusal(r: &Response) -> bool {
        matches!(r, Response::Error { message } if message.contains("person-at-the-device socket"))
    }

    async fn ask_scoped(scope: Scope, line: &str) -> Response {
        let (client, server) = tokio::io::duplex(4096);
        let srv = tokio::spawn(async move {
            let state = Mock;
            serve_connection_scoped(server, &state, ClientPeer::UNKNOWN, scope).await
        });
        let (crd, mut cwr) = tokio::io::split(client);
        let mut clines = tokio::io::BufReader::new(crd).lines();
        cwr.write_all(format!("{line}\n").as_bytes()).await.unwrap();
        let r = clines.next_line().await.unwrap().unwrap();
        drop(cwr);
        drop(clines);
        srv.await.unwrap().unwrap();
        serde_json::from_str(&r).unwrap()
    }

    /// FR-27 P11 — the person socket serves the safety surface and nothing
    /// else. The match in [`person_may`] is exhaustive, so a NEW verb cannot
    /// slip onto it by default; this pins which side today's verbs are on.
    #[test]
    fn person_may_is_exactly_the_safety_surface() {
        let allowed = [
            r#"{"t":"status"}"#,
            r#"{"t":"rc_sessions"}"#,
            r#"{"t":"rc_disconnect","d":{"session_id":"6ac95ff543d358ac1a427048"}}"#,
            r#"{"t":"consent_pending"}"#,
            r#"{"t":"consent_decide","d":{"session_id":"6ac95ff543d358ac1a427048","allow":true}}"#,
            r#"{"t":"record_status"}"#,
            // FR-92 — it is the person's own pointer.
            r#"{"t":"keep_busy_status"}"#,
            r#"{"t":"keep_busy_off"}"#,
            // P10 — and theirs to start (the peer is gated again on top).
            r#"{"t":"keep_busy_on","d":{}}"#,
            // FR-97 P2g — the machine's device list and mesh, read-only.
            r#"{"t":"devices","d":{"org":"primary"}}"#,
            r#"{"t":"mesh","d":{"org":"primary"}}"#,
            // FR-97 P2h — and its live links, without the endpoints.
            r#"{"t":"peers"}"#,
        ];
        for j in allowed {
            let req: Request = serde_json::from_str(j).unwrap();
            assert!(person_may(&req), "the person must be able to: {j}");
        }
        let refused = [
            Request::Flows,
            Request::RouteList,
            Request::ConfigGet,
            Request::ConfigCleanupStale,
            Request::RecordStop,
            Request::RecordingsList,
            Request::EncoderCaps,
            Request::HiveUpdateHold,
            Request::KillFlow { id: "f".into() },
            Request::RouteRemove { id: "r".into() },
            Request::SetDeviceName { name: "x".into() },
            Request::RecordingDelete {
                name: "x.mp4".into(),
            },
            // FR-90 P3-9-2b — the owner's grants, never the seat's.
            Request::Connect {
                args: ConnectArgs::default(),
            },
            Request::ConnectStatus { id: 1 },
        ];
        for req in refused {
            assert!(!person_may(&req), "the person socket must refuse {req:?}");
        }
    }

    /// FR-92 — the keep-busy verbs and their answer on the wire, and a
    /// service without keep busy says why instead of failing the request.
    #[tokio::test]
    async fn keep_busy_verbs_round_trip_and_default_to_unavailable() {
        assert_eq!(
            serde_json::to_string(&Request::KeepBusyStatus).unwrap(),
            r#"{"t":"keep_busy_status"}"#
        );
        assert_eq!(
            serde_json::to_string(&Request::KeepBusyOff).unwrap(),
            r#"{"t":"keep_busy_off"}"#
        );
        let info = KeepBusyInfo {
            available: true,
            on: true,
            phase: "paused".into(),
            reason: Some("user_active".into()),
            sentence: Some("Paused: someone is using this computer.".into()),
            paused_by: Some("local".into()),
            resumes_in_ms: Some(23_000),
            pattern: "heart".into(),
            set_by: Some("Alice".into()),
            set_at_ms: Some(5),
            auto_off_at_ms: None,
        };
        let j = serde_json::to_string(&Response::KeepBusy(info.clone())).unwrap();
        let back: Response = serde_json::from_str(&j).unwrap();
        assert_eq!(back, Response::KeepBusy(info));
        // Older agents' default: unavailable, with a reason.
        match ask_scoped(Scope::Full, r#"{"t":"keep_busy_status"}"#).await {
            Response::KeepBusy(s) => {
                assert!(!s.available && !s.on);
                assert_eq!(s.reason.as_deref(), Some("unsupported"));
            }
            other => panic!("expected KeepBusy, got {other:?}"),
        }
    }

    /// FR-27 P11 — on a person-scope connection an administrative verb is
    /// refused before any handler runs, with a pointer to `sudo`; the safety
    /// surface is served; and the same verb on a full-scope connection is
    /// served as ever.
    #[tokio::test]
    async fn a_person_connection_serves_the_safety_surface_and_refuses_the_rest() {
        assert!(matches!(
            ask_scoped(Scope::Person, r#"{"t":"status"}"#).await,
            Response::Status(_)
        ));
        let r = ask_scoped(Scope::Person, r#"{"t":"config_get"}"#).await;
        assert!(is_person_refusal(&r), "{r:?}");
        assert!(
            matches!(&r, Response::Error { message } if message.contains("sudo roomler")),
            "the refusal says where to go instead: {r:?}"
        );
        let r = ask_scoped(Scope::Person, r#"{"t":"flows"}"#).await;
        assert!(is_person_refusal(&r), "{r:?}");
        // The banner's Disconnect and the consent answer reach the state.
        for j in [
            r#"{"t":"rc_disconnect","d":{"session_id":"6ac95ff543d358ac1a427048"}}"#,
            r#"{"t":"consent_decide","d":{"session_id":"6ac95ff543d358ac1a427048","allow":false}}"#,
        ] {
            let r = ask_scoped(Scope::Person, j).await;
            assert!(!is_person_refusal(&r), "{j} must pass through: {r:?}");
        }
        // FR-97 P2g — so do the Devices page and the mesh, read-only.
        for j in [
            r#"{"t":"devices","d":{"org":"primary"}}"#,
            r#"{"t":"mesh","d":{"org":"primary"}}"#,
        ] {
            let r = ask_scoped(Scope::Person, j).await;
            assert!(!is_person_refusal(&r), "{j} must pass through: {r:?}");
        }
        // FR-97 P2h — the peers pass too, without the relay endpoints the
        // Mock's first peer carries; the daemon's own socket keeps them.
        match ask_scoped(Scope::Person, r#"{"t":"peers"}"#).await {
            Response::Peers(p) => {
                assert_eq!(p.len(), 2, "every peer, as the daemon knows them");
                assert_eq!(p[0].rtt_ms, Some(52), "the link itself is served");
                assert_eq!(p[0].relay_local, None);
                assert_eq!(p[0].relay_dst, None);
            }
            other => panic!("expected Peers on the person socket, got {other:?}"),
        }
        match ask_scoped(Scope::Full, r#"{"t":"peers"}"#).await {
            Response::Peers(p) => {
                assert_eq!(p[0].relay_local.as_deref(), Some("94.130.141.74:10850"));
                assert_eq!(p[0].relay_dst.as_deref(), Some("5.9.157.226:12728"));
            }
            other => panic!("expected Peers on the full socket, got {other:?}"),
        }
    }

    /// FR-97 P2h — the person's view of the peers keeps the link and drops
    /// every endpoint and diagnostic; any other answer passes untouched.
    #[test]
    fn person_view_keeps_the_link_and_drops_the_endpoints() {
        let mut p = Mock.peers().remove(0);
        p.relay_kind = Some("derp".into());
        p.relay_transport = Some("tcp".into());
        p.relay_server = Some("derp.example:443".into());
        p.why = Some(PeerWhy {
            tiers: Vec::new(),
            relayed_instead_s: Some(30),
            relayed_instead_strikes: 1,
            forced_derp_s: None,
            probing: Some("198.51.100.7:41641".into()),
        });
        p.probes = vec![PathProbe {
            dst: "198.51.100.7:41641".into(),
            loss: Some(0.0),
            rtt_ms: Some(12.0),
            rtt_p95_ms: None,
            rtt_max_ms: None,
        }];
        p.debug = Some(PeerCarrierDebug {
            tier: "direct".into(),
            initiated: true,
            hs_done: true,
            local: Some("192.0.2.10:41641".into()),
            dst: Some("198.51.100.7:41641".into()),
            tx: 1,
            rx: 1,
            last_rx_age_s: 0,
            relay_kind: None,
            rx_denied: 0,
            rx_denied_noroute: 0,
        });
        let Response::Peers(out) = person_view(Response::Peers(vec![p.clone()])) else {
            panic!("a Peers answer stays a Peers answer");
        };
        let q = &out[0];
        assert_eq!(
            (
                q.relay_local.as_deref(),
                q.relay_dst.as_deref(),
                q.relay_server.as_deref()
            ),
            (None, None, None)
        );
        assert!(q.debug.is_none() && q.why.is_none() && q.probes.is_empty());
        assert_eq!(q.node_id, p.node_id);
        assert_eq!(q.online, p.online);
        assert_eq!(q.rtt_ms, p.rtt_ms);
        assert_eq!(q.relay_kind.as_deref(), Some("derp"));
        assert_eq!(q.relay_transport.as_deref(), Some("tcp"));
        let status = Response::Status(Box::new(Mock.status()));
        assert_eq!(person_view(status.clone()), status);
    }

    /// FR-97 P2g — the Mac person socket's directory must be a real
    /// directory, root's, and writable by nobody else, or root's bind-then-
    /// chown there could be raced.
    #[test]
    fn a_mac_person_socket_dir_is_root_only() {
        assert!(root_only_dir(true, false, 0, 0o40755));
        assert!(root_only_dir(true, false, 0, 0o40700));
        // Group- or world-writable: someone else could make or swap entries.
        assert!(!root_only_dir(true, false, 0, 0o40775));
        assert!(!root_only_dir(true, false, 0, 0o41777));
        // Not root's, a link to a directory, or not a directory at all.
        assert!(!root_only_dir(true, false, 501, 0o40755));
        assert!(!root_only_dir(false, true, 0, 0o120755));
        assert!(!root_only_dir(false, false, 0, 0o100644));
    }

    #[cfg(unix)]
    #[test]
    fn the_person_socket_admits_its_person_and_root_only() {
        let as_uid = |uid: Option<u32>| ClientPeer {
            session_id: None,
            uid,
            system_account: None,
            ..ClientPeer::UNKNOWN
        };
        assert!(person_peer_ok(&as_uid(Some(1000)), 1000));
        assert!(person_peer_ok(&as_uid(Some(0)), 1000));
        assert!(!person_peer_ok(&as_uid(Some(1001)), 1000));
        assert!(!person_peer_ok(&as_uid(None), 1000));
    }

    /// FR-97 P2g — a Mac's per-user half believes the machine's view only from
    /// a socket ROOT serves: served by anyone else, the same socket is refused.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_machine_view_is_taken_only_from_root() {
        let me = own_uid().unwrap();
        let dir = std::env::temp_dir().join(format!("roomler-p2g-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("served.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let held = tokio::spawn(async move { listener.accept().await.map(|(s, _)| s) });
        let r = connect_unix_served_by_root(path.clone()).await;
        if me == 0 {
            assert!(r.is_ok(), "a root server is believed: {:?}", r.err());
        } else {
            let e = r
                .err()
                .expect("a socket a non-root process serves must be refused");
            assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
            assert!(e.to_string().contains(&format!("uid {me}")), "{e}");
        }
        held.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// FR-27 P11 — the real socket: 0600 and the person's; serves and refuses
    /// over an actual unix socket; never replaces a live socket; refuses a
    /// non-socket file at the path; clears a stale socket; refuses a dir the
    /// person does not own; and removes its own file on stop.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_person_socket_is_the_persons_and_never_takes_over() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        let me = own_uid().unwrap();
        let dir = std::env::temp_dir().join(format!("roomler-p11-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("roomler.sock");
        let state: Arc<dyn LocalApiState> = Arc::new(Mock);

        // A plain file at the path is not a socket: left alone, refused.
        std::fs::write(&path, b"x").unwrap();
        let (_tx0, rx0) = watch::channel(false);
        let e = serve_person_socket(path.clone(), me, state.clone(), rx0)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"x");
        std::fs::remove_file(&path).unwrap();

        // A stale socket (bound, then abandoned) is cleared and replaced.
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        let (tx, rx) = watch::channel(false);
        let srv = tokio::spawn(serve_person_socket(path.clone(), me, state.clone(), rx));
        let mut up = false;
        for _ in 0..100 {
            if std::os::unix::net::UnixStream::connect(&path).is_ok() {
                up = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(up, "the person socket came up over the stale one");
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(meta.uid(), me);

        let stream = tokio::net::UnixStream::connect(&path).await.unwrap();
        let (rd, mut wr) = tokio::io::split(stream);
        let mut lines = tokio::io::BufReader::new(rd).lines();
        wr.write_all(b"{\"t\":\"status\"}\n").await.unwrap();
        let r: Response = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        assert!(matches!(r, Response::Status(_)), "{r:?}");
        wr.write_all(b"{\"t\":\"config_get\"}\n").await.unwrap();
        let r: Response = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        assert!(is_person_refusal(&r), "{r:?}");
        // This connection stays OPEN across the stop below, having just been
        // served twice: the stop must cut it.

        // A second server at the same path must not take the live one over.
        let (_tx2, rx2) = watch::channel(false);
        let e = serve_person_socket(path.clone(), me, state.clone(), rx2)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AddrInUse);

        // Stop: the file it bound goes with it, and so does every connection
        // it was serving — a person switched away keeps nothing open.
        tx.send(true).unwrap();
        srv.await.unwrap().unwrap();
        assert!(!path.exists(), "the person socket removes its own file");
        let _ = wr.write_all(b"{\"t\":\"status\"}\n").await;
        let after =
            tokio::time::timeout(std::time::Duration::from_secs(2), lines.next_line()).await;
        assert!(
            matches!(after, Ok(Ok(None)) | Ok(Err(_))),
            "a connection held across the stop is cut, not served: {after:?}"
        );

        // A dir the person does not own is refused before anything is
        // created in it (skipped as root, where `/` would be "owned").
        if me != 0 {
            let (_tx3, rx3) = watch::channel(false);
            let e = serve_person_socket("/roomler-p11-never.sock".into(), me, state, rx3)
                .await
                .unwrap_err();
            assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
            assert!(!std::path::Path::new("/roomler-p11-never.sock").exists());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// FR-90 P1h-2 — a daemon that holds at once, counting holds and releases.
    #[derive(Default)]
    struct HoldMock {
        holds: std::sync::atomic::AtomicUsize,
        releases: std::sync::atomic::AtomicUsize,
    }
    #[async_trait]
    impl LocalApiState for HoldMock {
        fn status(&self) -> NodeStatus {
            Mock.status()
        }
        fn peers(&self) -> Vec<PeerInfo> {
            Mock.peers()
        }
        fn flows(&self) -> Vec<FlowInfo> {
            Mock.flows()
        }
        async fn hive_update_hold(&self) -> Response {
            self.holds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Response::HiveUpdateHeld {
                waited_secs: 7,
                cut: 0,
            }
        }
        fn hive_update_release(&self) {
            self.releases
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// FR-90 P1h-2 — root alone holds the daemon for an update (a hold
    /// refuses every new agent prompt and start), and the hold ends with the
    /// connection that placed it; a refusal places none. The wire is pinned:
    /// the helper and the daemon are different processes, often of different
    /// builds.
    #[tokio::test]
    async fn only_root_holds_the_daemon_and_the_hold_ends_with_its_connection() {
        use std::sync::atomic::Ordering::SeqCst;
        let root = ClientPeer {
            session_id: None,
            uid: Some(0),
            system_account: None,
            ..ClientPeer::UNKNOWN
        };
        let someone = ClientPeer {
            session_id: None,
            uid: Some(1000),
            system_account: None,
            ..ClientPeer::UNKNOWN
        };
        for (peer, holds) in [(root, true), (someone, false), (ClientPeer::UNKNOWN, false)] {
            let state = std::sync::Arc::new(HoldMock::default());
            let (client, server) = tokio::io::duplex(4096);
            let st = std::sync::Arc::clone(&state);
            let served = peer.clone();
            let srv = tokio::spawn(async move { serve_connection_as(server, &*st, served).await });
            let (crd, mut cwr) = tokio::io::split(client);
            let mut clines = tokio::io::BufReader::new(crd).lines();
            cwr.write_all(b"{\"t\":\"hive_update_hold\"}\n")
                .await
                .unwrap();
            let line = clines.next_line().await.unwrap().unwrap();
            if holds {
                assert_eq!(
                    line,
                    r#"{"t":"hive_update_held","d":{"waited_secs":7,"cut":0}}"#
                );
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                assert_eq!(
                    state.releases.load(SeqCst),
                    0,
                    "held while the helper installs"
                );
            } else {
                let r: Response = serde_json::from_str(&line).unwrap();
                assert!(
                    matches!(&r, Response::Error { message } if message.contains("only root")),
                    "{peer:?} → {r:?}"
                );
            }
            drop(cwr);
            drop(clines);
            srv.await.unwrap().unwrap();
            assert_eq!(state.holds.load(SeqCst), usize::from(holds), "{peer:?}");
            assert_eq!(
                state.releases.load(SeqCst),
                usize::from(holds),
                "released once its connection closed: {peer:?}"
            );
        }
    }

    /// FR-90 P3-9-2b — a daemon whose `connect` opens at once, keeping whom
    /// it served and which endpoints were let go.
    #[derive(Default)]
    struct ConnectMock {
        asked: std::sync::Mutex<Vec<Asker>>,
        released: std::sync::Mutex<Vec<u64>>,
        opened: std::sync::atomic::AtomicU64,
    }
    #[async_trait]
    impl LocalApiState for ConnectMock {
        fn status(&self) -> NodeStatus {
            Mock.status()
        }
        fn peers(&self) -> Vec<PeerInfo> {
            Mock.peers()
        }
        fn flows(&self) -> Vec<FlowInfo> {
            Mock.flows()
        }
        async fn connect(&self, asker: &Asker, args: &ConnectArgs) -> Response {
            self.asked.lock().unwrap().push(asker.clone());
            let id = self
                .opened
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
            Response::Connected {
                id,
                endpoint: serde_json::json!({ "upstream": args.upstream }),
            }
        }
        fn connect_status(&self, id: u64) -> Response {
            Response::ConnectState(EndpointState {
                left_s: 100 + id,
                ..EndpointState::default()
            })
        }
        fn connect_release(&self, id: u64) {
            self.released.lock().unwrap().push(id);
        }
    }

    /// One connection's conversation with a [`ConnectMock`]: each line sent
    /// and its answer, then the connection closed and served to its end.
    async fn converse(
        state: &std::sync::Arc<ConnectMock>,
        peer: ClientPeer,
        scope: Scope,
        lines: &[&str],
    ) -> Vec<Response> {
        let (client, server) = tokio::io::duplex(4096);
        let st = std::sync::Arc::clone(state);
        let srv =
            tokio::spawn(async move { serve_connection_scoped(server, &*st, peer, scope).await });
        let (crd, mut cwr) = tokio::io::split(client);
        let mut clines = tokio::io::BufReader::new(crd).lines();
        let mut answers = Vec::new();
        for line in lines {
            cwr.write_all(format!("{line}\n").as_bytes()).await.unwrap();
            let answer = clines.next_line().await.unwrap().unwrap();
            answers.push(serde_json::from_str(&answer).unwrap());
        }
        drop(cwr);
        drop(clines);
        srv.await.unwrap().unwrap();
        answers
    }

    const CONNECT: &str = r#"{"t":"connect","d":{"args":{"handle":"db/orders","engine":"postgres","upstream":"db.internal:5432"}}}"#;

    /// FR-90 P3-9-2b — an endpoint lives as long as the connection that
    /// opened it (decision 25: `roomler connect` in the foreground): it is
    /// served to the account that asked, read by the listener, and its state
    /// is that connection's to read, no other's.
    #[tokio::test]
    async fn an_endpoint_serves_the_account_that_asked_and_ends_with_its_connection() {
        let state = std::sync::Arc::new(ConnectMock::default());
        let root = ClientPeer {
            uid: Some(0),
            gid: Some(0),
            ..ClientPeer::UNKNOWN
        };
        let answers = converse(
            &state,
            root,
            Scope::Full,
            &[
                CONNECT,
                r#"{"t":"connect_status","d":{"id":1}}"#,
                // Not this connection's: refused, and its state never read.
                r#"{"t":"connect_status","d":{"id":2}}"#,
            ],
        )
        .await;
        assert_eq!(
            answers[0],
            Response::Connected {
                id: 1,
                endpoint: serde_json::json!({ "upstream": "db.internal:5432" }),
            }
        );
        assert_eq!(
            answers[1],
            Response::ConnectState(EndpointState {
                left_s: 101,
                ..EndpointState::default()
            })
        );
        assert!(
            matches!(&answers[2], Response::Error { message } if message.contains("no endpoint 2")),
            "{:?}",
            answers[2]
        );
        assert_eq!(
            *state.asked.lock().unwrap(),
            [Asker::Unix { uid: 0, gid: 0 }],
            "served to the account the listener read"
        );
        assert_eq!(
            *state.released.lock().unwrap(),
            [1],
            "let go once its connection closed"
        );
    }

    /// FR-90 P3-9-2b (decision 26) — `roomler connect` lends the device
    /// owner's grants: anyone the gate refuses, a peer whose account the OS
    /// did not name, and the person socket all get a refusal, and the daemon
    /// is never asked.
    #[tokio::test]
    async fn a_connect_is_refused_before_the_daemon_is_asked() {
        // A uid no runner signs in as, and not root.
        let someone = ClientPeer {
            uid: Some(4_000_000_001),
            gid: Some(4_000_000_001),
            ..ClientPeer::UNKNOWN
        };
        // SYSTEM, whose SID could not be read: the gate passes, and still no
        // account is served.
        let unnamed = ClientPeer {
            session_id: Some(1),
            system_account: Some(true),
            elevated: Some(true),
            ..ClientPeer::UNKNOWN
        };
        let root = ClientPeer {
            uid: Some(0),
            gid: Some(0),
            ..ClientPeer::UNKNOWN
        };
        for (peer, scope, says) in [
            (someone, Scope::Full, "owner's vault grants"),
            (ClientPeer::UNKNOWN, Scope::Full, "owner's vault grants"),
            (unnamed, Scope::Full, "could not read which account asked"),
            (root, Scope::Person, "person-at-the-device socket"),
        ] {
            let state = std::sync::Arc::new(ConnectMock::default());
            let answers = converse(&state, peer.clone(), scope, &[CONNECT]).await;
            assert!(
                matches!(&answers[0], Response::Error { message } if message.contains(says)),
                "{peer:?} on {scope:?} → {:?}",
                answers[0]
            );
            assert!(state.asked.lock().unwrap().is_empty(), "{peer:?}");
            assert!(state.released.lock().unwrap().is_empty(), "{peer:?}");
        }
    }

    /// FR-90 P3-9-2b (decision 26) — who may run `roomler connect`: root or
    /// the daemon's own uid on Unix; SYSTEM, an elevated administrator or the
    /// daemon's own account on Windows. Never another interactive user (the
    /// pipe admits them all), and never a peer nothing is known about.
    #[test]
    fn only_root_system_an_elevated_administrator_or_the_daemons_own_account_may_connect() {
        let unix = |uid| ClientPeer {
            uid: Some(uid),
            gid: Some(uid),
            ..ClientPeer::UNKNOWN
        };
        assert!(peer_may_connect(&unix(0), Some(1000), None), "root");
        assert!(
            peer_may_connect(&unix(1000), Some(1000), None),
            "the daemon's own uid"
        );
        assert!(
            !peer_may_connect(&unix(1001), Some(1000), None),
            "another uid"
        );
        assert!(
            !peer_may_connect(&unix(1001), None, None),
            "no own uid read"
        );
        let me = "S-1-5-21-10-20-30-1001";
        let win = |sid: &str, system: bool, elevated: Option<bool>| ClientPeer {
            session_id: Some(2),
            system_account: Some(system),
            sid: Some(sid.into()),
            elevated,
            ..ClientPeer::UNKNOWN
        };
        assert!(
            peer_may_connect(&win("S-1-5-18", true, Some(true)), None, Some(me)),
            "SYSTEM"
        );
        assert!(
            peer_may_connect(
                &win("S-1-5-21-10-20-30-500", false, Some(true)),
                None,
                Some(me)
            ),
            "an elevated administrator"
        );
        assert!(
            peer_may_connect(&win(me, false, Some(false)), None, Some(me)),
            "the daemon's own account, not elevated"
        );
        let guest = win("S-1-5-21-10-20-30-1002", false, Some(false));
        assert!(
            !peer_may_connect(&guest, None, Some(me)),
            "another interactive user, an RDP guest"
        );
        assert!(!peer_may_connect(&guest, None, None), "no own account read");
        assert!(
            !peer_may_connect(&win("S-1-5-21-10-20-30-1002", false, None), None, Some(me)),
            "an elevation that could not be read is no elevation"
        );
        assert!(
            !peer_may_connect(&ClientPeer::UNKNOWN, Some(0), Some(me)),
            "a peer nothing is known about"
        );
    }

    /// FR-90 P3-9-2b — the account an endpoint is served to is the one the
    /// OS named, whole: a uid with its gid, or a SID; else none.
    #[test]
    fn the_account_served_is_the_one_the_os_named() {
        let unix = ClientPeer {
            uid: Some(1000),
            gid: Some(100),
            ..ClientPeer::UNKNOWN
        };
        assert_eq!(
            unix.asker(),
            Some(Asker::Unix {
                uid: 1000,
                gid: 100
            })
        );
        let win = ClientPeer {
            session_id: Some(2),
            sid: Some("S-1-5-18".into()),
            ..ClientPeer::UNKNOWN
        };
        assert_eq!(
            win.asker(),
            Some(Asker::Windows {
                sid: "S-1-5-18".into()
            })
        );
        assert_eq!(ClientPeer::UNKNOWN.asker(), None);
        let half = ClientPeer {
            uid: Some(1000),
            ..ClientPeer::UNKNOWN
        };
        assert_eq!(half.asker(), None, "a uid without its gid");
    }

    /// FR-90 P3-9-2b — the connect verbs on the wire: the CLI and the daemon
    /// are often different builds.
    #[test]
    fn the_connect_verbs_wire_is_locked() {
        let req = Request::Connect {
            args: ConnectArgs {
                handle: "db/orders".into(),
                engine: "postgres".into(),
                upstream: "db.internal:5432".into(),
                ttl_s: Some(120),
                ..ConnectArgs::default()
            },
        };
        let wire = r#"{"t":"connect","d":{"args":{"handle":"db/orders","engine":"postgres","upstream":"db.internal:5432","ttl_s":120}}}"#;
        assert_eq!(serde_json::to_string(&req).unwrap(), wire);
        assert_eq!(serde_json::from_str::<Request>(wire).unwrap(), req);
        assert_eq!(
            serde_json::to_string(&Request::ConnectStatus { id: 7 }).unwrap(),
            r#"{"t":"connect_status","d":{"id":7}}"#
        );
        assert_eq!(
            serde_json::to_string(&Response::Connected {
                id: 7,
                endpoint: serde_json::json!({ "uri": "postgresql:///" }),
            })
            .unwrap(),
            r#"{"t":"connected","d":{"id":7,"endpoint":{"uri":"postgresql:///"}}}"#
        );
        assert_eq!(
            serde_json::to_string(&Response::ConnectState(EndpointState {
                left_s: 200,
                renewals: 1,
                refused: None,
                closed: None,
            }))
            .unwrap(),
            r#"{"t":"connect_state","d":{"left_s":200,"renewals":1}}"#
        );
    }

    #[tokio::test]
    async fn an_unidentified_peer_cannot_start_stop_delete_or_move_recordings() {
        for line in [
            r#"{"t":"record_start","d":{}}"#,
            r#"{"t":"record_stop"}"#,
            r#"{"t":"recording_delete","d":{"name":"x.mp4"}}"#,
            r#"{"t":"config_set","d":{"key":"record_dir","value":"C:\\elsewhere"}}"#,
        ] {
            let r = ask(ClientPeer::UNKNOWN, line).await;
            assert!(is_console_refusal(&r), "{line} → {r:?}");
        }
        // Reading state is open to every local client.
        assert!(matches!(
            ask(ClientPeer::UNKNOWN, r#"{"t":"record_status"}"#).await,
            Response::Recording(_)
        ));
        // And a ConfigSet of any OTHER key is not the recorder's business.
        let r = ask(
            ClientPeer::UNKNOWN,
            r#"{"t":"config_set","d":{"key":"exec_enabled","value":"true"}}"#,
        )
        .await;
        assert!(!is_console_refusal(&r), "{r:?}");
    }

    /// FR-84 D4 — where files dropped into the console user's session land
    /// is the console user's call, like where recordings go: an unidentified
    /// (or RDP-guest) peer is refused, set AND clear, while the console user
    /// reaches the state (the mock's own answer — a different error, so the
    /// gate demonstrably passed). The match is on the exact key.
    #[tokio::test]
    async fn only_the_console_user_moves_incoming_files() {
        for line in [
            r#"{"t":"config_set","d":{"key":"files_dir","value":"~\\Desktop"}}"#,
            r#"{"t":"config_set","d":{"key":"files_dir"}}"#,
        ] {
            let r = ask(ClientPeer::UNKNOWN, line).await;
            assert!(
                matches!(&r, Response::Error { message } if message.contains("console") && message.contains("incoming files")),
                "{line} → {r:?}"
            );
        }
        // A key that merely starts with the name is not this gate's business.
        let r = ask(
            ClientPeer::UNKNOWN,
            r#"{"t":"config_set","d":{"key":"files_dir_x","value":"1"}}"#,
        )
        .await;
        assert!(!is_console_refusal(&r), "{r:?}");
        let me = ClientPeer {
            session_id: console_session_id(),
            uid: own_uid(),
            system_account: None,
            ..ClientPeer::UNKNOWN
        };
        if me.is_console_user() {
            let r = ask(
                me,
                r#"{"t":"config_set","d":{"key":"files_dir","value":"~\\Desktop"}}"#,
            )
            .await;
            assert!(!is_console_refusal(&r), "{r:?}");
        }
    }

    /// FR-101 P1b — whether this device may reach its server without TLS is
    /// the console person's call: an unidentified peer is refused, set AND
    /// clear, while the console user reaches the state. The match is on the
    /// exact key.
    #[tokio::test]
    async fn only_the_console_user_lets_the_device_skip_tls() {
        for line in [
            r#"{"t":"config_set","d":{"key":"allow_plaintext_server","value":"true"}}"#,
            r#"{"t":"config_set","d":{"key":"allow_plaintext_server"}}"#,
        ] {
            let r = ask(ClientPeer::UNKNOWN, line).await;
            assert!(
                matches!(&r, Response::Error { message } if message.contains("console") && message.contains("without TLS")),
                "{line} → {r:?}"
            );
        }
        let r = ask(
            ClientPeer::UNKNOWN,
            r#"{"t":"config_set","d":{"key":"allow_plaintext_server_x","value":"true"}}"#,
        )
        .await;
        assert!(!is_console_refusal(&r), "{r:?}");
        let me = ClientPeer {
            session_id: console_session_id(),
            uid: own_uid(),
            system_account: None,
            ..ClientPeer::UNKNOWN
        };
        if me.is_console_user() {
            let r = ask(
                me,
                r#"{"t":"config_set","d":{"key":"allow_plaintext_server","value":"true"}}"#,
            )
            .await;
            assert!(!is_console_refusal(&r), "{r:?}");
        }
    }

    /// FR-99 P3 — whether this console locks when a remote session ends is the
    /// console person's call, as for the TLS escape above: an unidentified
    /// peer is refused, set AND clear, on the exact key only.
    #[tokio::test]
    async fn only_the_console_user_decides_the_lock_on_end() {
        for line in [
            r#"{"t":"config_set","d":{"key":"lock_on_end","value":"always"}}"#,
            r#"{"t":"config_set","d":{"key":"lock_on_end"}}"#,
        ] {
            let r = ask(ClientPeer::UNKNOWN, line).await;
            assert!(
                matches!(&r, Response::Error { message } if message.contains("console") && message.contains("locks")),
                "{line} → {r:?}"
            );
        }
        let r = ask(
            ClientPeer::UNKNOWN,
            r#"{"t":"config_set","d":{"key":"lock_on_end_x","value":"always"}}"#,
        )
        .await;
        assert!(!is_console_refusal(&r), "{r:?}");
        let me = ClientPeer {
            session_id: console_session_id(),
            uid: own_uid(),
            system_account: None,
            ..ClientPeer::UNKNOWN
        };
        if me.is_console_user() {
            let r = ask(
                me,
                r#"{"t":"config_set","d":{"key":"lock_on_end","value":"auto"}}"#,
            )
            .await;
            assert!(!is_console_refusal(&r), "{r:?}");
        }
    }

    /// FR-108 — whether a remote session may switch this console's display is
    /// the console person's call too: an unidentified peer is refused, set AND
    /// clear, on the exact key only.
    #[tokio::test]
    async fn only_the_console_user_decides_display_match() {
        for line in [
            r#"{"t":"config_set","d":{"key":"display_match","value":"always"}}"#,
            r#"{"t":"config_set","d":{"key":"display_match"}}"#,
        ] {
            let r = ask(ClientPeer::UNKNOWN, line).await;
            assert!(
                matches!(&r, Response::Error { message } if message.contains("console") && message.contains("display")),
                "{line} → {r:?}"
            );
        }
        let r = ask(
            ClientPeer::UNKNOWN,
            r#"{"t":"config_set","d":{"key":"display_match_x","value":"always"}}"#,
        )
        .await;
        assert!(!is_console_refusal(&r), "{r:?}");
        let me = ClientPeer {
            session_id: console_session_id(),
            uid: own_uid(),
            system_account: None,
            ..ClientPeer::UNKNOWN
        };
        if me.is_console_user() {
            let r = ask(
                me,
                r#"{"t":"config_set","d":{"key":"display_match","value":"never"}}"#,
            )
            .await;
            assert!(!is_console_refusal(&r), "{r:?}");
        }
    }

    /// FR-100 P1c — whether this device checks the browsers that connect to it
    /// is the console person's call: an unidentified peer is refused, set AND
    /// clear, on the exact key only.
    #[tokio::test]
    async fn only_the_console_user_decides_peer_auth() {
        for line in [
            r#"{"t":"config_set","d":{"key":"peer_auth","value":"off"}}"#,
            r#"{"t":"config_set","d":{"key":"peer_auth"}}"#,
        ] {
            let r = ask(ClientPeer::UNKNOWN, line).await;
            assert!(
                matches!(&r, Response::Error { message } if message.contains("console") && message.contains("browsers")),
                "{line} → {r:?}"
            );
        }
        let r = ask(
            ClientPeer::UNKNOWN,
            r#"{"t":"config_set","d":{"key":"peer_auth_x","value":"off"}}"#,
        )
        .await;
        assert!(!is_console_refusal(&r), "{r:?}");
        let me = ClientPeer {
            session_id: console_session_id(),
            uid: own_uid(),
            system_account: None,
            ..ClientPeer::UNKNOWN
        };
        if me.is_console_user() {
            let r = ask(
                me,
                r#"{"t":"config_set","d":{"key":"peer_auth","value":"audit"}}"#,
            )
            .await;
            assert!(!is_console_refusal(&r), "{r:?}");
        }
    }

    /// FR-52 — who may open this device to people OUTSIDE its organization is
    /// the console person's call, like `files_dir`: the pipe admits RDP guests
    /// too, and gates 3–5 decide who may take the console's screen. An
    /// unidentified (or guest) peer is refused setting or clearing the
    /// password and every `external_*` key; the read-only status stays open.
    #[tokio::test]
    async fn only_the_console_user_opens_the_device_to_outsiders() {
        // Built, never a literal: a scanner cannot tell a test password from a leak.
        let set = format!(
            r#"{{"t":"external_password_set","d":{{"password":"{}"}}}}"#,
            "p".repeat(16)
        );
        for line in [
            set.as_str(),
            r#"{"t":"external_password_clear"}"#,
            r#"{"t":"config_set","d":{"key":"external_access_enabled","value":"true"}}"#,
            r#"{"t":"config_set","d":{"key":"external_consent_mode","value":"auto"}}"#,
            r#"{"t":"config_set","d":{"key":"external_max_permissions"}}"#,
        ] {
            let r = ask(ClientPeer::UNKNOWN, line).await;
            assert!(
                matches!(&r, Response::Error { message } if message.contains("console") && message.contains("outside")),
                "{line} → {r:?}"
            );
        }
        let r = ask(ClientPeer::UNKNOWN, r#"{"t":"external_password_status"}"#).await;
        assert!(!is_console_refusal(&r), "{r:?}");
    }

    /// FR-85 P2b — a state without a recorder says so AHEAD of a start, so a
    /// client greys its Start out instead of offering one that can only fail.
    /// A state from a service that predates `available` parses, and reads as
    /// unable to record — the fail-closed direction (no release carried the
    /// recording verbs before the field existed).
    #[tokio::test]
    async fn a_service_without_a_recorder_says_so_before_any_start() {
        match ask(ClientPeer::UNKNOWN, r#"{"t":"record_status"}"#).await {
            Response::Recording(st) => {
                assert!(!st.available && !st.active, "{st:?}");
                assert_eq!(st.unavailable_reason.as_deref(), Some(NO_RECORDER));
            }
            other => panic!("{other:?}"),
        }
        let older: RecordingState = serde_json::from_str(r#"{"active":false}"#).unwrap();
        assert!(
            !older.available,
            "absent = cannot record, never the reverse"
        );
    }

    /// #1760 — a state says, ahead of any start, why computer audio cannot
    /// go into a recording here (a Mac; a service built without audio), so
    /// a client greys the box out with the words. The field is absent where
    /// it can, and absent from a service older than the field, which reads
    /// as "it can": the behaviour of the day, the recorder refusing by name.
    #[test]
    fn a_state_says_why_computer_audio_cannot_be_recorded_before_any_start() {
        let cannot = RecordingState {
            available: true,
            system_audio_unavailable_reason: Some(
                "macOS can't capture what the computer plays yet".into(),
            ),
            ..Default::default()
        };
        let j = serde_json::to_string(&Response::Recording(cannot.clone())).unwrap();
        assert!(
            j.contains(r#""system_audio_unavailable_reason":"macOS"#),
            "{j}"
        );
        assert_eq!(
            serde_json::from_str::<Response>(&j).unwrap(),
            Response::Recording(cannot)
        );
        let can = RecordingState {
            available: true,
            ..Default::default()
        };
        let j = serde_json::to_string(&Response::Recording(can)).unwrap();
        assert!(
            !j.contains("system_audio_unavailable_reason"),
            "absent where it can: {j}"
        );
        let older: RecordingState = serde_json::from_str(r#"{"active":false}"#).unwrap();
        assert_eq!(older.system_audio_unavailable_reason, None);
    }

    #[tokio::test]
    async fn the_console_user_passes_the_gate() {
        let me = ClientPeer {
            session_id: console_session_id(),
            uid: own_uid(),
            system_account: None,
            ..ClientPeer::UNKNOWN
        };
        if !me.is_console_user() {
            // A Windows host with no active console session (some CI runners):
            // the refusal half above is the part that must hold everywhere.
            return;
        }
        // The gate lets the console user through to the state, which in this
        // mock has no recorder — a DIFFERENT error, proving the gate passed.
        let r = ask(me, r#"{"t":"record_start","d":{}}"#).await;
        assert!(!is_console_refusal(&r), "{r:?}");
        assert!(matches!(r, Response::Error { message } if message.contains("not available")));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn client_round_trips_over_named_pipe() {
        // Drives the real `Client` against `serve_windows_at` — exercises the
        // named pipe + the SDDL security descriptor (PipeSecurity::new must
        // convert the SDDL, or bind fails) + the client connect/request path. A
        // private pipe name avoids colliding with a real daemon on the box.
        let pipe = format!(r"\\.\pipe\roomler-test-{}", std::process::id());
        let (sd_tx, sd_rx) = watch::channel(false);
        let state: Arc<dyn LocalApiState> = Arc::new(Mock);
        let pipe_srv = pipe.clone();
        let srv = tokio::spawn(async move {
            serve_windows_at(&pipe_srv, state, sd_rx, DEFAULT_PIPE_POOL).await
        });

        let mut client = connect_when_up(&pipe).await;

        let status = client.status().await.unwrap();
        assert_eq!(status.name, "devbox");
        assert!(status.connected);
        let peers = client.peers().await.unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].connection, ConnectionType::Tunnel);
        // A second request on the SAME connection works (the daemon loops).
        assert_eq!(client.peers().await.unwrap().len(), 2);

        // Consent verbs over the real pipe (P2b).
        let pending = client.consent_pending().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].session_id, "sess-1");
        assert!(client.consent_decide("sess-1", true).await.unwrap());
        assert!(!client.consent_decide("sess-1", false).await.unwrap());

        sd_tx.send(true).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), srv).await;
    }

    /// Retry the real client connect until the server's first instance exists.
    #[cfg(windows)]
    async fn connect_when_up(pipe: &str) -> Client {
        for _ in 0..200 {
            match connect_windows_at(pipe).await {
                Ok(c) => return c,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        }
        panic!("connect to the LocalAPI pipe {pipe}");
    }

    /// FR-84 D1 — the field measurement, as a test. After one round trip the
    /// server sits in its accept loop; then N raw `CreateFileW` opens with NO
    /// await between them — exactly what the desktop's three pollers do
    /// every 2 s — must all succeed. Raw opens, not `connect_windows_at`:
    /// the client's backoff would hide the gap this test exists to see.
    ///
    /// On a current-thread runtime nothing else runs between the opens, so
    /// the outcome is decided purely by how many instances were LISTENING
    /// when the burst started. Pre-FR-84 (one instance, replaced only after
    /// `connect()` returned to the accept task) the second open failed with
    /// `ERROR_PIPE_BUSY` (231) deterministically — 60/60 on the reporting
    /// host, and 100% here.
    #[cfg(windows)]
    #[tokio::test]
    async fn pipe_accepts_back_to_back_opens_without_pipe_busy() {
        let (opens, _keep) = raw_open_burst(DEFAULT_PIPE_POOL, 4).await;
        let refused: Vec<String> = opens
            .iter()
            .enumerate()
            .filter_map(|(i, r)| r.as_ref().err().map(|e| format!("open #{}: {e}", i + 1)))
            .collect();
        assert!(
            refused.is_empty(),
            "every back-to-back open must find a listening instance; refused: {refused:?}"
        );
    }

    /// FR-84 D1 — the kill switch is real: `localapi_pipe_pool = 1` is the
    /// pre-FR-84 listener, and the pre-FR-84 listener refuses the second of
    /// two back-to-back opens with 231. If this ever passes with `1`, the
    /// pool parameter has stopped meaning anything.
    #[cfg(windows)]
    #[tokio::test]
    async fn pipe_pool_of_one_refuses_the_second_back_to_back_open() {
        let (opens, _keep) = raw_open_burst(1, 2).await;
        assert!(opens[0].is_ok(), "the one listening instance takes open #1");
        let second = match &opens[1] {
            Err(e) => e,
            Ok(_) => panic!("with one instance the second raw open must be refused"),
        };
        assert_eq!(
            second.raw_os_error(),
            Some(231),
            "the refusal is ERROR_PIPE_BUSY, got {second}"
        );
    }

    /// Serve a private pipe with `pool` listening instances, do one real
    /// client round trip (so every accept task has run once and re-created
    /// its instance), then perform `burst` raw opens back-to-back. Returns
    /// each open's outcome; the second tuple field keeps the server alive
    /// until the caller drops it.
    #[cfg(windows)]
    async fn raw_open_burst(
        pool: u32,
        burst: usize,
    ) -> (
        Vec<std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient>>,
        (
            watch::Sender<bool>,
            tokio::task::JoinHandle<std::io::Result<()>>,
        ),
    ) {
        use tokio::net::windows::named_pipe::ClientOptions;
        let pipe = format!(r"\\.\pipe\roomler-test-pool{pool}-{}", std::process::id());
        let (sd_tx, sd_rx) = watch::channel(false);
        let state: Arc<dyn LocalApiState> = Arc::new(Mock);
        let pipe_srv = pipe.clone();
        let srv =
            tokio::spawn(async move { serve_windows_at(&pipe_srv, state, sd_rx, pool).await });

        // One round trip through the real client. Its awaits let every accept
        // task run: the one whose instance we took re-creates it, the others
        // park on `connect()`. Dropping the client ends that connection.
        let mut client = connect_when_up(&pipe).await;
        assert_eq!(client.status().await.unwrap().name, "devbox");
        drop(client);

        // The burst: no `.await` between opens, so no accept task can run.
        let mut opens = Vec::with_capacity(burst);
        for _ in 0..burst {
            opens.push(ClientOptions::new().open(&pipe));
        }
        (opens, (sd_tx, srv))
    }

    /// FR-84 D1 — the client's `ERROR_PIPE_BUSY` ladder: six bounded steps
    /// summing to 315 ms, then give up. Interactive path: a refusal must
    /// surface within a third of a second, never become a hang.
    #[test]
    fn pipe_busy_backoff_is_bounded() {
        let mut total = std::time::Duration::ZERO;
        let mut steps = Vec::new();
        let mut attempt = 0u32;
        while let Some(d) = pipe_busy_backoff(attempt) {
            steps.push(d.as_millis() as u64);
            total += d;
            attempt += 1;
            assert!(attempt <= 16, "the ladder must end");
        }
        assert_eq!(steps, vec![5, 10, 20, 40, 80, 160]);
        assert_eq!(total, std::time::Duration::from_millis(315));
        assert!(pipe_busy_backoff(6).is_none());
        assert!(
            pipe_busy_backoff(u32::MAX).is_none(),
            "no overflow at the top"
        );
        assert!(
            steps.windows(2).all(|w| w[1] == w[0] * 2),
            "each step doubles the previous one"
        );
    }

    /// The client must look for a per-user daemon FIRST and the system
    /// daemon second.
    ///
    /// Order is the whole contract. Reversed, every unprivileged daemon on a
    /// host that also has a system one would be shadowed; and without the
    /// system candidate at all, a root daemon is invisible from a user
    /// session on macOS — `temp_dir()` is per-user there, so the CLI would
    /// search its own `/var/folders/…`, find nothing, and report "not
    /// running" for a daemon that is running.
    #[cfg(unix)]
    #[test]
    fn socket_candidates_prefer_the_per_user_daemon() {
        let cands = super::unix_socket_candidates();
        assert_eq!(cands[0], super::user_socket_path(), "per-user first");
        assert_eq!(cands[1], super::system_socket_path(), "system second");
        assert_ne!(cands[0], cands[1], "the two must be distinct paths");
        assert!(
            cands[1].starts_with("/var/run/roomler"),
            "the system path must be well-known, not per-user: {:?}",
            cands[1]
        );
        // Every candidate is the same socket FILE name — only the directory
        // (and therefore the privilege domain) differs.
        for c in &cands {
            assert_eq!(c.file_name().unwrap(), super::LOCALAPI_SOCKET_NAME);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn client_round_trips_over_unix_socket_and_is_0600() {
        // Drives the real `Client` against `serve_unix_at` + asserts the socket
        // is owner-only.
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("roomler-lat-{}", std::process::id()));
        let path = dir.join("s.sock");
        let (sd_tx, sd_rx) = watch::channel(false);
        let state: Arc<dyn LocalApiState> = Arc::new(Mock);
        let p = path.clone();
        let srv = tokio::spawn(async move { serve_unix_at(p, state, sd_rx).await });

        for _ in 0..200 {
            if path.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let mut client = connect_unix_at(path.clone())
            .await
            .expect("connect to the LocalAPI socket");
        assert_eq!(client.status().await.unwrap().name, "devbox");
        assert_eq!(client.peers().await.unwrap().len(), 2);

        // The control socket must be private to the owner.
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "control socket must be 0600");

        sd_tx.send(true).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), srv).await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─── srflx health ────────────────────────────────────────────────

    #[test]
    fn srflx_health_is_candidate_presence() {
        // The whole point of the field: "no candidates" is the failure, and it
        // must be readable without interpreting an error string.
        assert!(!SrflxStatus::default().is_healthy());
        assert!(
            !SrflxStatus {
                stun_server: Some("1.2.3.4:3478".into()),
                error: Some("timed out".into()),
                ..Default::default()
            }
            .is_healthy()
        );
        assert!(
            SrflxStatus {
                candidates: vec!["94.130.141.98:43649".into()],
                nat: Some("cone".into()),
                ..Default::default()
            }
            .is_healthy()
        );
    }

    #[test]
    fn srflx_absent_and_empty_are_different_on_the_wire() {
        // A daemon that predates the field omits `srflx` entirely; a daemon
        // that MEASURED zero candidates sends an empty list. Collapsing those
        // two would turn "we don't know" into "it's broken" for every older
        // node in the fleet.
        let mut s: NodeStatus = serde_json::from_str(
            r#"{"node_id":"n","name":"x","version":"v","mode":"service","connected":true}"#,
        )
        .unwrap();
        assert!(s.srflx.is_none(), "absent must decode to None");
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains("srflx"), "None must not serialise: {json}");

        s.srflx = Some(SrflxStatus::default());
        let json = serde_json::to_string(&s).unwrap();
        assert!(
            json.contains(r#""srflx":{"candidates":[]}"#),
            "a measured zero MUST serialise: {json}"
        );
        let back: NodeStatus = serde_json::from_str(&json).unwrap();
        assert!(!back.srflx.unwrap().is_healthy());
    }

    /// Multi-org — the consent modal's `org` line is ADDITIVE: a daemon that
    /// predates it (no `org` key) must still deserialize, and a single-org
    /// device must not ship an empty string that renders a blank "On behalf
    /// of" row.
    #[test]
    fn consent_request_org_is_additive_and_omitted_when_empty() {
        // An older daemon's payload — no `org` key at all.
        let legacy: ConsentRequest = serde_json::from_str(
            r#"{"session_id":"abc","controller_name":"Alice","permissions":"VIEW_SCREEN","timeout_secs":30}"#,
        )
        .expect("a pre-org payload must still parse");
        assert_eq!(legacy.org, "");

        // A single-org device omits the key entirely rather than sending "".
        let single = ConsentRequest {
            session_id: "abc".into(),
            controller_name: "Alice".into(),
            permissions: "VIEW_SCREEN".into(),
            timeout_secs: 30,
            kind: String::new(),
            detail: String::new(),
            expires_at_ms: 0,
            surface: String::new(),
            org: String::new(),
        };
        let json = serde_json::to_string(&single).unwrap();
        assert!(
            !json.contains("\"org\""),
            "empty org must not be serialized: {json}"
        );

        // A multi-org device names the asking organization.
        let multi = ConsentRequest {
            org: "Acme GmbH".into(),
            ..single
        };
        let round: ConsentRequest =
            serde_json::from_str(&serde_json::to_string(&multi).unwrap()).unwrap();
        assert_eq!(round.org, "Acme GmbH");
    }

    /// FR-27 — `kind` / `detail` / `expires_at_ms` are additive in exactly the
    /// same way, and for the same reason: the desktop app and the daemon do not
    /// step forward in the same instant.
    ///
    /// The empty defaults are load-bearing, not incidental. A pre-FR-27 daemon
    /// wrote only remote-control prompts, so an absent `kind` MUST read as
    /// `rc` at the UI — an empty string rendered literally would label a real
    /// screen-control request with a blank type.
    #[test]
    fn consent_request_kind_and_detail_are_additive() {
        let legacy: ConsentRequest = serde_json::from_str(
            r#"{"session_id":"abc","controller_name":"Alice","permissions":"VIEW_SCREEN","timeout_secs":30}"#,
        )
        .expect("a pre-FR-27 payload must still parse");
        assert_eq!(legacy.kind, "");
        assert_eq!(legacy.detail, "");
        assert_eq!(legacy.expires_at_ms, 0);

        // An rc prompt carries no detail and must not ship empty keys.
        let rc = ConsentRequest {
            session_id: "abc".into(),
            controller_name: "Alice".into(),
            permissions: "VIEW".into(),
            timeout_secs: 30,
            kind: "rc".into(),
            detail: String::new(),
            expires_at_ms: 0,
            surface: String::new(),
            org: String::new(),
        };
        let json = serde_json::to_string(&rc).unwrap();
        assert!(
            !json.contains("\"detail\""),
            "empty detail must be omitted: {json}"
        );
        assert!(
            !json.contains("\"expires_at_ms\""),
            "an unknown deadline must be omitted, not sent as 0: {json}"
        );

        // An exec prompt carries the whole point of the change: what is about
        // to run, and until when.
        let exec = ConsentRequest {
            kind: "exec".into(),
            detail: "systemctl restart roomlerd".into(),
            expires_at_ms: 1_700_000_000_000,
            surface: String::new(),
            ..rc
        };
        let round: ConsentRequest =
            serde_json::from_str(&serde_json::to_string(&exec).unwrap()).unwrap();
        assert_eq!(round.kind, "exec");
        assert_eq!(round.detail, "systemctl restart roomlerd");
        assert_eq!(round.expires_at_ms, 1_700_000_000_000);
    }

    /// FR-27 — `surface` decides whether a UI RENDERS a prompt or merely lists
    /// it. The daemon writes a marker even when its own native panel is up
    /// (this list is also what `roomlerd consent --list` reads), so a UI that
    /// ignored the field would put a SECOND Approve button in front of one
    /// decision.
    ///
    /// The absent case is the load-bearing one: a pre-FR-27 daemon had no
    /// native panel at all, so "" must mean "nobody is showing it" — i.e. the
    /// companion should — and never be mistaken for "native".
    #[test]
    fn consent_request_surface_defaults_to_the_companion() {
        let legacy: ConsentRequest = serde_json::from_str(
            r#"{"session_id":"abc","controller_name":"Alice","permissions":"VIEW","timeout_secs":30}"#,
        )
        .expect("a pre-FR-27 payload must still parse");
        assert_eq!(legacy.surface, "");
        assert_ne!(legacy.surface, "native", "absent must never read as native");

        let native = ConsentRequest {
            session_id: "abc".into(),
            controller_name: "Alice".into(),
            permissions: "VIEW".into(),
            timeout_secs: 30,
            kind: "rc".into(),
            detail: String::new(),
            expires_at_ms: 0,
            surface: "native".into(),
            org: String::new(),
        };
        let round: ConsentRequest =
            serde_json::from_str(&serde_json::to_string(&native).unwrap()).unwrap();
        assert_eq!(round.surface, "native");

        // A companion-served prompt omits the key rather than shipping the
        // default spelling, exactly as `org` does.
        let companion = ConsentRequest {
            surface: String::new(),
            ..native
        };
        let json = serde_json::to_string(&companion).unwrap();
        assert!(
            !json.contains("\"surface\""),
            "an empty surface must be omitted: {json}"
        );
    }

    /// FR-52 — the password cannot be printed, not even through the request
    /// that carries it.
    ///
    /// The second half is the one that matters. `Secret`'s own `Debug` is easy
    /// to get right; the leak that would actually happen is someone adding
    /// `tracing::debug!(?req)` to `serve_connection` while chasing a client bug,
    /// and that path goes through `Request`'s DERIVED `Debug`. This asserts the
    /// derive is safe, so the tempting debugging line stays safe to write.
    #[test]
    fn a_password_never_prints_itself_through_debug() {
        // Built, not written: a secret scanner cannot tell a test fixture from a
        // leaked credential, and it is right not to try.
        let marker = format!("fr52-{}-not-a-credential", "marker");

        let s = Secret(marker.clone());
        assert!(!format!("{s:?}").contains(&marker), "Secret's own Debug");
        assert_eq!(s.expose(), marker, "but it is still readable on purpose");

        let req = Request::ExternalPasswordSet {
            password: Secret(marker.clone()),
        };
        let printed = format!("{req:?}");
        assert!(
            !printed.contains(&marker),
            "Request's derived Debug leaked the password: {printed}"
        );
        // Not the length either — it narrows a brute force and no debugging
        // session needs it.
        assert!(!printed.contains(&marker.len().to_string()));
    }

    /// FR-52 — the three verbs and their response survive the wire, and the
    /// password travels as a BARE STRING.
    ///
    /// `Secret` is `#[serde(transparent)]` on purpose: the redaction is a `Debug`
    /// property, not a wire format. If it ever serialised as `{"0": "…"}` the
    /// daemon would still parse it (same type both sides) while every other
    /// client of this protocol — the desktop companion, a future tray — would
    /// break, and the test that caught it would be someone else's field report.
    #[test]
    fn the_external_password_verbs_round_trip() {
        let marker = format!("fr52-{}-not-a-credential", "wire");
        let set = Request::ExternalPasswordSet {
            password: Secret(marker.clone()),
        };
        let json = serde_json::to_string(&set).unwrap();
        assert!(
            json.contains(&format!(r#""d":{{"password":"{marker}"}}"#)),
            "the password must be a bare string on the wire: {json}"
        );
        assert_eq!(serde_json::from_str::<Request>(&json).unwrap(), set);

        for req in [
            Request::ExternalPasswordClear,
            Request::ExternalPasswordStatus,
        ] {
            let json = serde_json::to_string(&req).unwrap();
            assert_eq!(serde_json::from_str::<Request>(&json).unwrap(), req);
        }

        let state = ExternalPasswordState {
            supported: true,
            password_set: true,
            enabled: false,
            consent_mode: Some("always-ask".into()),
            max_permissions: None,
        };
        let json = serde_json::to_string(&Response::ExternalPassword(state.clone())).unwrap();
        assert!(
            !json.contains("max_permissions"),
            "an unset ceiling is omitted, not null: {json}"
        );
        match serde_json::from_str::<Response>(&json).unwrap() {
            Response::ExternalPassword(back) => assert_eq!(back, state),
            other => panic!("wrong response: {other:?}"),
        }
    }

    /// FR-52 — an older daemon answers the status verb rather than erroring.
    ///
    /// A client's first question is "does this device support external access at
    /// all", and `supported: false` is an answer it can render. An `Error` would
    /// make the question unanswerable and indistinguishable from a daemon that
    /// is simply broken — while `set` and `clear` DO default to an error, because
    /// there the caller asked for a change that did not happen.
    #[tokio::test]
    async fn an_older_daemon_still_answers_the_status_verb() {
        // `Mock` predates these verbs and overrides none of them, which is
        // exactly the shape of the daemon this is about.
        match Mock.external_password_status().await {
            Response::ExternalPassword(s) => {
                assert!(!s.supported);
                assert!(!s.password_set);
                assert!(!s.enabled);
            }
            other => panic!("status must not be an error on an older daemon: {other:?}"),
        }
        for r in [
            Mock.external_password_set(&Secret("x".into())).await,
            Mock.external_password_clear().await,
        ] {
            assert!(
                matches!(r, Response::Error { .. }),
                "a change that did not happen must be an error, got {r:?}"
            );
        }
    }
    struct PathObservationMock;
    #[async_trait]
    impl LocalApiState for PathObservationMock {
        fn status(&self) -> NodeStatus {
            let mut s = Mock.status();
            s.path_trials = Some(PathTrialStatus {
                reset_diagnostics: None,
                runtime_id: 1,
                epoch: 7,
                observed_at_ms: 9,
                history_ttl_ms: 30000,
                active: vec![],
                transitions: vec![],
            });
            s
        }
        fn peers(&self) -> Vec<PeerInfo> {
            vec![]
        }
        fn flows(&self) -> Vec<FlowInfo> {
            vec![]
        }
    }
    async fn path_observation_status(peer: ClientPeer, scope: Scope) -> NodeStatus {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        let (client, server) = tokio::io::duplex(65536);
        let join = tokio::spawn(async move {
            serve_connection_scoped(server, &PathObservationMock, peer, scope)
                .await
                .unwrap()
        });
        let (rd, mut wr) = tokio::io::split(client);
        wr.write_all(b"{\"t\":\"status\"}\n").await.unwrap();
        let mut rd = tokio::io::BufReader::new(rd);
        let mut line = String::new();
        tokio::time::timeout(std::time::Duration::from_secs(1), rd.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        drop(rd);
        drop(wr);
        join.await.unwrap();
        match serde_json::from_str::<Response>(&line).unwrap() {
            Response::Status(s) => *s,
            other => panic!("unexpected {other:?}"),
        }
    }
    #[tokio::test]
    async fn path_trial_observation_status_transport_is_owner_only_and_person_hidden() {
        let root = ClientPeer {
            uid: Some(0),
            ..ClientPeer::UNKNOWN
        };
        assert!(
            path_observation_status(root.clone(), Scope::Full)
                .await
                .path_trials
                .is_some()
        );
        assert!(
            path_observation_status(root, Scope::Person)
                .await
                .path_trials
                .is_none()
        );
        let unknown = path_observation_status(ClientPeer::UNKNOWN, Scope::Full).await;
        assert!(unknown.path_trials.is_none());
        assert_eq!(unknown.connected, Mock.status().connected);
        let other = ClientPeer {
            uid: Some(own_uid().unwrap_or(0).saturating_add(1)),
            ..ClientPeer::UNKNOWN
        };
        assert!(
            path_observation_status(other, Scope::Full)
                .await
                .path_trials
                .is_none()
        );
        let elevated = ClientPeer {
            elevated: Some(true),
            ..ClientPeer::UNKNOWN
        };
        assert!(
            path_observation_status(elevated, Scope::Full)
                .await
                .path_trials
                .is_some()
        );
        let old = serde_json::to_value(Mock.status()).unwrap();
        assert!(old.get("path_trials").is_none());
        assert!(
            serde_json::from_value::<NodeStatus>(old)
                .unwrap()
                .path_trials
                .is_none()
        );
    }
}
