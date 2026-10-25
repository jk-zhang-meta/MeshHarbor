// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! S2 config surface — the curated, secret-free slice of [`AgentConfig`]
//! that the LocalAPI `ConfigGet` / `ConfigSet` verbs expose to the
//! desktop app / CLI.
//!
//! One registry drives both verbs: every key carries an editor `kind`
//! (see [`tunnel_core::localapi::ConfigEntry`]), a one-line description,
//! and a per-key parse/validate in [`apply`]. Values travel as strings —
//! bools as `"true"`/`"false"`, lists comma-separated, structured keys
//! (`forward_acl`, `virtual_desktop_apps`) as JSON documents.
//!
//! Deliberately NOT here: secrets (`agent_token`,
//! `overlay_wg_secret_key`), identity (`machine_id`; `machine_name` has
//! its own `SetDeviceName` verb), `[[tunnel_routes]]` (the `Route*`
//! verbs + Routes pane own those), `[[orgs]]` (multi-org P1 — identity +
//! per-org secrets managed by `roomlerd enroll` / the `org` CLI
//! verbs, same policy as `tunnel_routes`; a future desktop org pane gets
//! dedicated LocalAPI verbs, not surface keys), and the crash-bookkeeping
//! fields.
//!
//! Most keys are read once at daemon startup, so `restart_required` holds
//! for them. [`KeyMeta::live`] marks the exceptions, among them `exec_enabled` and
//! `remote_config_enabled`, which `RemoteConfigServices::adopt_local` puts
//! into force the moment `ConfigSet` saves them (docs/remote-config.md §7b),
//! `record_dir` (FR-85), read when a recording starts,
//! `local_restart_enabled` (FR-84 D3), read by the restart verb on every
//! request, `files_dir`, which `files::set_files_dir` re-seeds on the
//! same path and every drop re-reads (FR-84 D4), and FR-52's three
//! `external_*` keys, read from the FILE each time an outsider knocks and
//! each time an external session is requested.
//! FR-84 D2 made that per-key truth part of the registry ([`KeyMeta::live`])
//! instead of a list each client kept by hand, and gave every key a
//! [`Group`] and a [`Tier`] so the Settings page can be more than 150 rows.

use crate::config::{AgentConfig, EncoderPreferenceChoice};
use roomler_localapi::ConfigEntry;
use std::sync::OnceLock;

/// Mirror of `tunnel_core::overlay::direct::MAX_DIRECT_PORT_BASE`
/// (`u16::MAX - PUBLIC_DIAL_PORT_OFFSET - DIRECT_PORT_BAND`): the largest
/// `overlay_direct_port` base whose public-dial band still fits under 65535.
/// Duplicated rather than imported because `tunnel_core::overlay` lives
/// behind the `overlay` CARGO FEATURE and this surface must compile in every
/// feature combination. Source of truth is `direct.rs`; keep in sync.
const MAX_OVERLAY_DIRECT_PORT_BASE: u32 = 64_759;

/// Where a key lives on the Settings page (FR-84 D2).
///
/// The variant order is the DISPLAY order: [`entries`] emits the surface
/// grouped this way, so a client (the desktop companion, `roomler config
/// ls`) renders sections in the order they arrive and never needs an order
/// table of its own. [`Group::wire`] ids are a compatibility surface — a
/// renamed id makes every key of that group land in "unknown" on an older
/// client — and are locked, with the labels, by `group_wire_ids_are_stable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Group {
    /// Who may connect, run commands, or push configuration.
    Access,
    /// The overlay mesh: joining it, what this node routes for others.
    Network,
    /// How a carrier is chosen and kept: relays, probes, the netcheck.
    NetworkCarriers,
    /// The OS route table and the TUN adapter (the Windows route wars).
    NetworkRouting,
    /// Userspace tunnels and the SOCKS5 mesh.
    Tunnels,
    /// The in-process SSH server on the overlay address.
    Ssh,
    /// Remote-control sessions and their media ICE.
    RemoteDesktop,
    /// Screen-capture backends and input injection.
    CaptureInput,
    /// Encoder selection, the encoder cells, the pipeline's threads.
    VideoEncoding,
    /// Rate control, queues, and latency levers.
    VideoRate,
    /// File transfer and remote browsing.
    Files,
    /// The daemon itself: updates, power, logs, supervision.
    Device,
}

impl Group {
    /// Every group, in display order.
    pub const ALL: [Group; 12] = [
        Group::Access,
        Group::Network,
        Group::NetworkCarriers,
        Group::NetworkRouting,
        Group::Tunnels,
        Group::Ssh,
        Group::RemoteDesktop,
        Group::CaptureInput,
        Group::VideoEncoding,
        Group::VideoRate,
        Group::Files,
        Group::Device,
    ];

    /// The stable wire id (`ConfigEntry::group`).
    pub const fn wire(self) -> &'static str {
        match self {
            Group::Access => "access",
            Group::Network => "network",
            Group::NetworkCarriers => "network_carriers",
            Group::NetworkRouting => "network_routing",
            Group::Tunnels => "tunnels",
            Group::Ssh => "ssh",
            Group::RemoteDesktop => "remote_desktop",
            Group::CaptureInput => "capture_input",
            Group::VideoEncoding => "video_encoding",
            Group::VideoRate => "video_rate",
            Group::Files => "files",
            Group::Device => "device",
        }
    }

    /// The human label (`ConfigEntry::group_label`).
    pub const fn label(self) -> &'static str {
        match self {
            Group::Access => "Access & consent",
            Group::Network => "Private network",
            Group::NetworkCarriers => "Network carriers & relays",
            Group::NetworkRouting => "Routing & adapter (Windows)",
            Group::Tunnels => "Tunnels & SOCKS",
            Group::Ssh => "Roomler SSH",
            Group::RemoteDesktop => "Remote desktop",
            Group::CaptureInput => "Capture & input",
            Group::VideoEncoding => "Video encoding",
            Group::VideoRate => "Video rate & latency",
            Group::Files => "Files",
            Group::Device => "Device & service",
        }
    }

    /// Position in [`Group::ALL`] — the sort key [`entries`] groups by.
    const fn order(self) -> usize {
        match self {
            Group::Access => 0,
            Group::Network => 1,
            Group::NetworkCarriers => 2,
            Group::NetworkRouting => 3,
            Group::Tunnels => 4,
            Group::Ssh => 5,
            Group::RemoteDesktop => 6,
            Group::CaptureInput => 7,
            Group::VideoEncoding => 8,
            Group::VideoRate => 9,
            Group::Files => 10,
            Group::Device => 11,
        }
    }
}

/// How much a key expects to be touched (FR-84 D2).
///
/// `Essential` keys are the handful a person is expected to decide on —
/// the Settings page shows them open, first. `Standard` keys sit in their
/// group. `Advanced` keys are field levers: every one documented, none a
/// healthy device needs a hand on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tier {
    Essential,
    Standard,
    Advanced,
}

impl Tier {
    /// The stable wire id (`ConfigEntry::tier`).
    pub const fn wire(self) -> &'static str {
        match self {
            Tier::Essential => "essential",
            Tier::Standard => "standard",
            Tier::Advanced => "advanced",
        }
    }
}

/// One registry row. Every field is a claim the desktop puts on screen, so
/// a wrong one is a lie to the person at the machine — `live` above all:
/// `true` means the daemon applies a change WITHOUT a restart, which today
/// holds for exactly the two gate-4 flags `RemoteConfigServices::adopt_local`
/// re-seeds after a `ConfigSet`, `record_dir`, read when a recording starts,
/// `local_restart_enabled`, read by the restart verb per request, and
/// `files_dir`, which the same `ConfigSet` path hands to
/// `files::set_files_dir` and every drop re-reads. Everything else is read
/// once at startup. Locked by
/// `live_keys_are_exactly_the_adopt_local_set`.
#[derive(Debug, Clone, Copy)]
pub struct KeyMeta {
    pub key: &'static str,
    /// The client-side editor hint contract — see [`ConfigEntry::kind`].
    pub kind: &'static str,
    pub group: Group,
    pub tier: Tier,
    /// The daemon puts a change into force without a restart.
    pub live: bool,
    pub description: &'static str,
}

/// The whole surface, in registry order (grouped for display by
/// [`entries`]). `kind` is the client-side editor hint contract — see
/// [`ConfigEntry`].
/// CONTRACT (rc.280): a key whose daemon read goes through
/// `tunnel_core::env::node_env` must ALSO appear in
/// [`crate::config::env_bridge_bools`] / `env_bridge_numerics`, else
/// `roomler config set <key>` writes TOML the daemon ignores. The parity
/// test `env_bridge_pairs_have_surface_parity` locks the mapping (and
/// covers set/echo for every bridged key, replacing per-key boilerplate).
const KEYS: &[KeyMeta] = &[
    KeyMeta {
        key: "overlay_enabled",
        group: Group::Network,
        tier: Tier::Essential,
        live: false,
        kind: "bool",
        description: "Join the L3 overlay mesh (WireGuard-style private network). Default: off.",
    },
    KeyMeta {
        key: "overlay_multi_org",
        group: Group::Network,
        tier: Tier::Advanced,
        live: false,
        kind: "bool",
        description: "Multi-org: let secondary [[orgs]] entries with overlay_mode=\"tun\" join \
         their own tenant's mesh, each on an OS adapter of its own (same server_url as \
         the primary required). A netstack secondary needs no opt-in. Default: off.",
    },
    KeyMeta {
        key: "overlay_advertised_routes",
        group: Group::Network,
        tier: Tier::Standard,
        live: false,
        kind: "list",
        description: "CIDRs this node offers to route for overlay peers (subnet router); admin approval required. Comma-separated.",
    },
    KeyMeta {
        key: "overlay_exit_node_enabled",
        group: Group::Network,
        tier: Tier::Standard,
        live: false,
        kind: "bool",
        description: "Offer this node as an overlay exit node (advertises 0.0.0.0/0; admin approval required). Default: off.",
    },
    KeyMeta {
        key: "overlay_exit_node",
        group: Group::Network,
        tier: Tier::Standard,
        live: false,
        kind: "string",
        description: "Route ALL of this node's internet egress through the named mesh peer (name or node-id hex). Empty = normal routing.",
    },
    KeyMeta {
        key: "advertise_routes",
        group: Group::Tunnels,
        tier: Tier::Standard,
        live: false,
        kind: "list",
        description: "CIDRs this host advertises for the tunnel/SOCKS mesh; admin approval required. Comma-separated.",
    },
    KeyMeta {
        key: "advertise_local_subnets",
        group: Group::Tunnels,
        tier: Tier::Standard,
        live: false,
        kind: "bool",
        description: "Auto-detect and advertise directly-connected IPv4 subnets (untrusted until admin-approved). Default: on.",
    },
    KeyMeta {
        key: "auto_grant_session",
        group: Group::Access,
        tier: Tier::Essential,
        live: false,
        kind: "bool",
        description: "Auto-approve incoming remote-control session requests without an operator prompt. Default: on.",
    },
    KeyMeta {
        key: "enable_remote_browse",
        group: Group::Files,
        tier: Tier::Standard,
        live: false,
        kind: "bool",
        description: "Answer remote filesystem-browse requests from the controller. Default: on.",
    },
    KeyMeta {
        key: "files_dir",
        group: Group::Files,
        tier: Tier::Essential,
        // LIVE: the daemon's `ConfigSet` hands the saved value to
        // `files::set_files_dir`, and every drop re-validates it
        // (agents/roomlerd/src/files.rs) — nothing is read at startup only.
        live: true,
        kind: "string",
        description: "FR-84 - where files dropped onto a remote-control session land. An absolute folder, or `~/...` for the active user's profile (expanded per user, at the time of the drop). Must be outside system folders and, when the service runs as SYSTEM/root, inside the active user's profile; created if missing. Empty = the default: the active user's Downloads folder (Windows falls back to %PROGRAMDATA%\\roomler\\...\\uploads when that is unreachable). Only the person at the device's console can change it. Applies at once.",
    },
    KeyMeta {
        key: "exec_enabled",
        group: Group::Access,
        tier: Tier::Essential,
        // LIVE: `RemoteConfigServices::adopt_local` re-seeds the gate-4
        // flag from the file `ConfigSet` just wrote (localapi_state.rs).
        live: true,
        kind: "bool",
        description: "Run Fleet-RPC commands sent by the server (commands inherit the daemon's SYSTEM/root identity). Default: OFF.",
    },
    KeyMeta {
        key: "macos_supervise_gui_worker",
        group: Group::Device,
        tier: Tier::Advanced,
        live: false,
        kind: "bool",
        description: "macOS only. Let the root daemon spawn and babysit the GUI-session worker (FR-43 P1). Stands down whenever the LaunchAgent is loaded, so one enrollment is never served twice. Default: OFF.",
    },
    KeyMeta {
        key: "power_policy",
        group: Group::Device,
        tier: Tier::Essential,
        live: false,
        // `enum:` so the desktop renders a select — it was a bare
        // `never|on-ac|always`, which the editor contract reads as free text.
        kind: "enum:never|on-ac|always",
        description: "Ask the OS to stay awake so this device stays reachable (FR-55). `on-ac` is the setting a laptop usually wants. A live remote-control or SSH session ALWAYS holds the machine awake regardless of this. ⚠️ macOS clamshell sleep (lid closed, no external display) ignores it — an OS limit, not a setting. Default: never.",
    },
    KeyMeta {
        key: "companion_autostart",
        group: Group::Device,
        tier: Tier::Standard,
        live: false,
        kind: "bool",
        description: "FR-84 - whether the service opens the desktop companion once after installation (the Welcome tour) and keeps it registered to start at login (Windows: the `Roomler Desktop` Run value). Off = neither; the companion still runs when someone opens it. A person's own 'Start at login' choice is separate and needs no admin. Takes effect at the next service start. Default: on.",
    },
    KeyMeta {
        key: "remote_config_enabled",
        group: Group::Access,
        tier: Tier::Essential,
        // LIVE: the owner's revocation of the delegation must never be the
        // slower of the two paths (docs/remote-config.md §7b).
        live: true,
        kind: "bool",
        description: "Accept configuration pushed by the control plane. NEVER settable by the server — it is what keeps exec_enabled/ssh_enabled refusable by a compromised one. Turning it ON delegates that last refusal. Default: OFF.",
    },
    KeyMeta {
        key: "external_access_enabled",
        group: Group::Access,
        tier: Tier::Standard,
        // LIVE: read from the FILE each time an outsider knocks
        // (`RemoteConfigServices::external_access_live`) — the owner's OFF is
        // a revocation, and it is in force for the very next knock.
        live: true,
        kind: "bool",
        description: "Let someone OUTSIDE this device's organization control it (FR-52 gate 3). NEVER settable by the server — the whole `external_*` surface is absent from remote config, because a server able to set this could admit a stranger to a machine whose owner never agreed. Opens nothing on its own: an org admin must also approve this device, the outsider must prove the password held HERE, and whoever is at the machine is still asked. Default: OFF.",
    },
    KeyMeta {
        key: "external_consent_mode",
        group: Group::Access,
        tier: Tier::Standard,
        // LIVE: read from the FILE each time an external session is
        // requested (`RemoteConfigServices::external_session_live`).
        live: true,
        kind: "enum:prompt|auto",
        description: "How consent is obtained when the controller is from OUTSIDE this organization (FR-52 gate 5). Deliberately separate from the org's consent setting: its answer for a colleague is not automatically its answer for a stranger. `auto` is the unattended case the password exists for, and has to be chosen HERE, on this device. Default: prompt.",
    },
    KeyMeta {
        key: "external_max_permissions",
        group: Group::Access,
        tier: Tier::Advanced,
        // LIVE: read with the consent mode, in the same single read.
        live: true,
        kind: "string",
        description: "Permission names joined by `|`, e.g. `VIEW | INPUT`. This device's OWN ceiling on what an external session may do. Unset defers to the org's ceiling; where both are set a session gets the INTERSECTION, so a device can narrow what its org allows but never widen it. RECORD and PRIVACY are never granted to an external session, whatever this names. NOTE: the external-access PASSWORD is not settable here - use `roomler rc password set`, which never writes it anywhere readable.",
    },
    KeyMeta {
        key: "local_restart_enabled",
        group: Group::Access,
        tier: Tier::Standard,
        // LIVE: the restart verb reads it from the file on every request
        // (localapi_state.rs, `restart_daemon`), so an owner's OFF is in force
        // for the very next "Apply now".
        live: true,
        kind: "bool",
        description: "FR-84 - let a person at this device restart the service from the companion (Apply now) or `roomler restart`. The daemon restarts itself only under a service manager it can prove (a Windows service or scheduled task, systemd, launchd), and at most once every 30 s; a hand-started `roomlerd run` always refuses. Off = every such request is refused. Never settable by the server, which cannot restart a daemon at all. Default: on.",
    },
    // FR-90 — Hive. Every key is the DEVICE's: none is settable by the server
    // (they are absent from `DesiredConfig`), because which account runs a
    // session and where it may run are exactly what a compromised server must
    // not be able to choose.
    KeyMeta {
        key: "hive_enabled",
        group: Group::Access,
        tier: Tier::Essential,
        live: false,
        kind: "bool",
        description: "FR-90 - run AI agent sessions (Claude Code) on this device when a member of the org starts one. Each runs as the local account hive_accounts maps that member to - never SYSTEM/root - and only in a folder under hive_roots. Never settable by the server. Default: OFF.",
    },
    KeyMeta {
        key: "hive_accounts",
        group: Group::Access,
        tier: Tier::Standard,
        live: false,
        kind: "json",
        description: "FR-90 - which local account a Roomler user's agent sessions run as: JSON {\"<user id or proven email>\": \"<account>\"}. Unmapped = refused (no_account), and a uid-0 account is refused too. Empty = nobody.",
    },
    KeyMeta {
        key: "hive_roots",
        group: Group::Access,
        tier: Tier::Standard,
        live: false,
        kind: "list",
        description: "FR-90 - comma-separated absolute folders agent sessions may run in, checked on the resolved path (no `..` or symlink escape). Empty = nowhere.",
    },
    KeyMeta {
        key: "hive_max_sessions",
        group: Group::Access,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "FR-90 - the most agent sessions this device runs at once (1-64). Empty = built-in default (4).",
    },
    KeyMeta {
        key: "hive_harness",
        group: Group::Access,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "FR-90 - absolute path of the agent harness (Claude Code). Empty = the first of ~/.local/bin/claude, /usr/local/bin/claude, /usr/bin/claude that exists for the mapped account.",
    },
    KeyMeta {
        key: "hive_api_key_helper",
        group: Group::Access,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "FR-90 - a command the DAEMON runs (as SYSTEM/root) to print the model API key. Sessions never see it: each gets a per-session token for the loopback model sidecar. Empty = no model credential, and sessions' model calls fail.",
    },
    KeyMeta {
        key: "hive_api_workspace_id",
        group: Group::Access,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "FR-90 - the provider workspace for a model key that is not scoped to one: the sidecar sends it as anthropic-workspace-id with every model call. Empty = no header (right for a workspace-scoped key).",
    },
    KeyMeta {
        key: "hive_update_wait_secs",
        group: Group::Access,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "FR-90 - how long an update waits for running agent turns before it restarts the daemon (0-7200 seconds; 0 = never wait). It holds a server-pushed update too. Empty = built-in default (1800, 30 minutes).",
    },
    KeyMeta {
        key: "hive_core_memory",
        group: Group::Access,
        tier: Tier::Advanced,
        live: false,
        kind: "bool",
        description: "FR-90 - show the organization's core memory (facts its people keep in Roomler) to the agent sessions on this device, as the session's CLAUDE.md and auto-memory. Claude Code reads CLAUDE.md as the user's own overriding instructions, so this is the one place text from the server reaches a session's model. Never settable by the server. Default: OFF.",
    },
    KeyMeta {
        key: "hive_adopt",
        group: Group::Access,
        tier: Tier::Advanced,
        live: false,
        kind: "bool",
        description: "FR-90 - let the people who use this device adopt the Claude Code sessions they run in a terminal (roomler hive adopt): mirrored into this device's store and shown to their owner alone, read-only. Each person still opts in, and their account must map in hive_accounts. Never settable by the server. Default: OFF.",
    },
    KeyMeta {
        key: "hive_allow_passwordless_sudo",
        group: Group::Access,
        tier: Tier::Advanced,
        live: false,
        kind: "bool",
        description: "FR-90 - macOS: run agent sessions as an account whose sudo needs no password. Off, such a start is refused: macOS's sudo reads the account's groups from the directory, so the session would have root whatever groups it drops. No effect on Linux, where a session cannot sudo at all. Never settable by the server. Default: OFF.",
    },
    KeyMeta {
        key: "hive_replica",
        group: Group::Access,
        tier: Tier::Advanced,
        live: false,
        kind: "bool",
        description: "FR-90 - hold copies of the agent sessions this device's owner runs on their other devices, so a session can move here when its device is gone. A copy is everything the agent saw, in plain text on this device. Never settable by the server. Default: OFF.",
    },
    KeyMeta {
        key: "hive_archive",
        group: Group::Access,
        tier: Tier::Advanced,
        live: false,
        kind: "bool",
        description: "FR-90 - offer this device as the organization's archive replica: once an administrator designates it, it holds every agent session the organization's rules allow, for their retention. Needs hive_replica on. Never settable by the server. Default: OFF.",
    },
    KeyMeta {
        key: "hive_store_quota_mib",
        group: Group::Access,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "FR-90 - the most this device keeps of the agent sessions it holds as a replica, in MiB (1-4194304). Never settable by the server. Empty = no bound but the disk's.",
    },
    KeyMeta {
        key: "vault_enabled",
        group: Group::Access,
        tier: Tier::Advanced,
        live: false,
        kind: "bool",
        description: "FR-90 - let the organization's vault lease secrets to the agent sessions on this device. On, the daemon makes a key at each start, in memory only, and a leased value is decrypted in the daemon, never in the session's process. Never settable by the server. Default: OFF.",
    },
    KeyMeta {
        key: "vault_activity_log",
        group: Group::Access,
        tier: Tier::Advanced,
        live: false,
        kind: "bool",
        description: "FR-90 - report to the org what this device does with the values its vault leases it: each command a session ran with them (the program and how it ended) and each file it wrote (the name). Never a value. Never settable by the server. Default: OFF.",
    },
    KeyMeta {
        key: "hive_net",
        group: Group::Access,
        tier: Tier::Advanced,
        live: false,
        kind: "bool",
        description: "FR-90 - offer the agent sessions on this device their own egress (net_socks, net_forward): a loopback listener per call, served to the session's account alone, its flows decided by the organization's vault and tunnel policies. Only with vault_enabled. Never settable by the server. Default: OFF.",
    },
    KeyMeta {
        key: "hive_ssh",
        group: Group::Access,
        tier: Tier::Advanced,
        live: false,
        kind: "bool",
        description: "FR-90 - offer the agent sessions on this device ssh_run: one command on another device of the organization over Roomler SSH, as the account that device's SSH policy maps (it may be SYSTEM or root there), each call decided by the organization's vault and approved by a person. Only with vault_enabled. Never settable by the server. Default: OFF.",
    },
    KeyMeta {
        key: "ssh_enabled",
        group: Group::Ssh,
        tier: Tier::Essential,
        live: false,
        kind: "bool",
        description: "Serve SSH in-process on this node's overlay address (intercepted before the OS; sessions inherit the daemon's SYSTEM/root identity). Default: OFF.",
    },
    KeyMeta {
        key: "ssh_activity_log",
        group: Group::Ssh,
        tier: Tier::Standard,
        live: false,
        kind: "bool",
        description: "Report SSH session activity to the org: commands and their exit codes, and that a shell / SFTP / forward happened. NEVER session content — no pty stream, no command output. Default: OFF.",
    },
    KeyMeta {
        key: "ssh_port",
        group: Group::Ssh,
        tier: Tier::Standard,
        live: false,
        kind: "string",
        description: "TCP port intercepted on the overlay address when ssh_enabled is on (1-65535). Empty = built-in default (2222).",
    },
    KeyMeta {
        key: "ssh_authorized_keys",
        group: Group::Ssh,
        tier: Tier::Standard,
        live: false,
        kind: "list",
        description: "Comma-separated OpenSSH public keys allowed to open an SSH session. Empty = nobody (ssh_enabled alone grants no access). Set ssh_account_mode too, or these keys authenticate and run nothing.",
    },
    KeyMeta {
        key: "ssh_account_mode",
        group: Group::Ssh,
        tier: Tier::Standard,
        live: false,
        kind: "string",
        description: "What an ssh_authorized_keys session runs as: daemon | console_user | named:<account>. Empty = sessions authenticate but run nothing (listing a key must not silently hand out SYSTEM/root).",
    },
    KeyMeta {
        key: "ssh_max_privilege",
        group: Group::Ssh,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "Ceiling on what a SERVER-GRANTED ssh session may run as: daemon (or empty) = no device-side limit; console_user = a grant asking for the daemon identity is refused. The device's answer to 'what do I still refuse when the server asking is the compromised thing'.",
    },
    KeyMeta {
        key: "ssh_exec_streaming",
        group: Group::Ssh,
        tier: Tier::Advanced,
        live: false,
        kind: "bool",
        description: "FR-89 - stream a one-shot command's output (`ssh <node> 'cmd'`) as it is produced: no 1 MiB ceiling, no 300 s wall clock, and the command lives exactly as long as the channel does (closing it kills the command and its process tree). Off = the buffered pre-FR-89 path, the kill switch. Fleet RPC (`roomler exec`) is unaffected either way. Default: on. Restart required.",
    },
    // `ssh_host_key` is deliberately ABSENT from this surface: it is private
    // key material, and everything here is readable over the LocalAPI.
    KeyMeta {
        key: "encoder_preference",
        group: Group::VideoEncoding,
        tier: Tier::Essential,
        live: false,
        kind: "enum:auto|hardware|software",
        description: "Video encoder selection: auto (HW probe then fallback), hardware, or software.",
    },
    KeyMeta {
        key: "update_check_interval_h",
        group: Group::Device,
        tier: Tier::Standard,
        live: false,
        kind: "string",
        description: "Hours between self-update checks (1-8760). Empty = built-in default (24 h).",
    },
    KeyMeta {
        key: "localapi_pipe_pool",
        group: Group::Device,
        tier: Tier::Advanced,
        live: false,
        kind: "number",
        description: "FR-84 - LocalAPI named-pipe instances kept listening at once (Windows; 1-16). Every companion poll, `roomler` call and wizard step opens the pipe fresh, and a client that finds no listening instance is refused with ERROR_PIPE_BUSY on the spot - the Routes page blanking every few seconds was three opens racing one instance. 1 = one instance (the pre-FR-84 behaviour, the kill switch). Empty = built-in default (4). Restart required.",
    },
    KeyMeta {
        key: "overlay_quic",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "QUIC-over-TURN overlay carrier. Built-in default: off.",
    },
    KeyMeta {
        key: "overlay_direct",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Direct (LAN / hole-punched) overlay carriers. Built-in default: on.",
    },
    KeyMeta {
        key: "overlay_derp",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "DERP (WebSocket-relay) overlay fallback tier. Built-in default: on.",
    },
    KeyMeta {
        key: "overlay_server_relay_strategy",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "U2 — accept the server's computed relay-tier verdict instead of the local derivation. Built-in default: off.",
    },
    KeyMeta {
        key: "overlay_derp_floor",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Overlay v3 Phase A — DERP always-on floor: keep the central /derp mux open + registered for the whole session, advertise the capability, and floor fresh pairs at birth. Built-in default: on since rc.400.",
    },
    KeyMeta {
        key: "overlay_org_relay",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "FR-19 P4b - ride a tenant-owned ORG RELAY when the server mints a session for a \
         pair (org switch on, an ACL rule granting each member the relay node, an approved \
         and serving relay). Advertised on the join as supports_org_relay; the serving half \
         is relay_server_enabled. Built-in default: ON (MeshHarbor); false opts this host out.",
    },
    KeyMeta {
        key: "relay_server_enabled",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "FR-19 - offer this node as an ORG RELAY: bind relay_server_port and answer \
         reachability probes (it forwards nothing until the relay data path ships). \
         Device-local by design and never server-pushable: this is the refusal that \
         survives a compromised server. Built-in default: OFF.",
    },
    KeyMeta {
        key: "relay_server_port",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "number",
        description: "FR-19 - UDP port for the org-relay listener (1-65535). Built-in default: 3478, \
         measured rather than guessed - the corp-managed target host reaches 3478 on an \
         arbitrary public IP and no other port. A successful bind does NOT prove \
         reachability: a coturn DNAT can consume the port in PREROUTING while ss shows it \
         free.",
    },
    KeyMeta {
        key: "overlay_netcheck",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Overlay v3 Phase B — netcheck: measure egress capabilities (relay-band probe over the dialer path, STUN/NAT, /derp health) every ~20 min and publish the capability vector. Built-in default: on.",
    },
    KeyMeta {
        key: "tunnel_derp_fallback",
        group: Group::Tunnels,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "R4 — tunnel quic-derp-v1 fallback: after repeated quick tunnel session deaths (a corp capture window killing fresh TURN/TLS legs), lead the next attempt with QUIC over the ESTABLISHED /derp WS. Client-side only. Built-in default: off.",
    },
    KeyMeta {
        key: "tunnel_reupgrade",
        group: Group::Tunnels,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "FR-86 - make-before-break tunnel transport re-upgrade: an auto declared route that fell back to a lower transport probes for the best one (quic-v1) in the background and switches to it when it comes up, never cutting an established connection. Client-side only. Read at each serving epoch (a config change applies on the next daemon restart; the env var flips it live). Built-in default: ON. Set false for the P1 behaviour.",
    },
    KeyMeta {
        key: "tunnel_peers_survive_reattach",
        group: Group::Tunnels,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "R3 — keep established tunnel QUIC peers alive across a control-WS reattach instead of tearing them down on every transient WS drop, so a QUIC/derp data plane survives a corp-VPN control-WS blip. Needs the server-side grace. Agent (target) side. Built-in default: off.",
    },
    KeyMeta {
        key: "overlay_mbb",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Make-before-break overlay carrier upgrades. Built-in default: on.",
    },
    KeyMeta {
        key: "overlay_lan_iface_filter",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "LAN-gather virtual-interface filter (skip WSL/Hyper-V/other-VPN adapters). Built-in default: on.",
    },
    KeyMeta {
        key: "overlay_wsl_mirrored_guard",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "WSL2 mirrored-networking guard: a mirrored guest shares the Windows host's adapters, so skip its LAN gather (binding the host's address starves the host agent). Built-in default: on.",
    },
    KeyMeta {
        key: "overlay_init_auth_first",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Auth-first handshake routing on a multi-org carrier plane: route an inbound WG initiation by trial-authentication instead of the source shortcut (fixes the dual-org direct lockout). Built-in default: on.",
    },
    KeyMeta {
        key: "overlay_srflx_seek",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "srflx SEEKING mode: when the STUN gather finds no public candidate, keep re-gathering with backoff + on interface events instead of staying NONE for the daemon lifetime. Built-in default: on.",
    },
    KeyMeta {
        key: "ws_replaced_exit",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "LEGACY ReplacedByNewer escalation: exit the process after 3 displacements in the window instead of backing off in-process. Built-in default: off (W4d — zombie-WS storms must not tear down the overlay).",
    },
    KeyMeta {
        key: "overlay_warm_relay",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "C4 stage 1: keep one standing warm TURN/UDP allocation (established while UDP works) alive across VPN transitions — measurement-only, nothing routes over it yet. Built-in default: off.",
    },
    KeyMeta {
        key: "overlay_quic_async",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Raw-first QUIC-over-TURN upgrade: commit the raw relay immediately, rendezvous in the background (90s window), swap in on success. Off restores the blocking 8s pre-install window. Built-in default: on.",
    },
    KeyMeta {
        key: "overlay_vpn_vantage",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "R2: srflx gather falls back to the wildcard public-dial socket when every LAN-bound vantage is dead (full-tunnel VPN rescue — on AnyConnect-class clients the tunnel is the only path that passes UDP). Built-in default: on.",
    },
    KeyMeta {
        key: "overlay_portmap",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Ask the gateway (PCP, then NAT-PMP) to map the direct punch port and advertise the mapping first, so a peer behind a symmetric NAT can still reach this node directly. Built-in default: on.",
    },
    KeyMeta {
        key: "overlay_netd",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Track A stage 1 (SCAFFOLD): spawn the session-independent network daemon (roomlerd netd) as a second supervisor child. netd hosts nothing yet; flag read at service start. Built-in default: off.",
    },
    KeyMeta {
        key: "overlay_pathmon",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "Overlay PathMonitor mode: on (authoritative — built-in default) | shadow (compare-only revert rail) | off. Env: ROOMLERD_OVERLAY_PATHMON.",
    },
    KeyMeta {
        key: "overlay_demote",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "B2 - score-driven demotion of degraded-but-live direct carriers: shadow (count only - built-in default) | on | off. Env: ROOMLERD_OVERLAY_DEMOTE.",
    },
    KeyMeta {
        key: "overlay_rpf",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "P4 - ingress filtering of inbound overlay packets: drops a SOURCE address the sending peer does not own, and a DESTINATION outside the subnets this node advertises. warn (count + log, still deliver - built-in default) | enforce | off. Env: ROOMLERD_OVERLAY_RPF.",
    },
    KeyMeta {
        key: "overlay_route_events",
        group: Group::NetworkRouting,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Event-driven route guard (OS route-table change subscription; the blind tick backstops it). Built-in default: on.",
    },
    KeyMeta {
        key: "overlay_route_tick_secs",
        group: Group::NetworkRouting,
        tier: Tier::Advanced,
        live: false,
        kind: "number",
        description: "Route-guard blind-tick seconds while the route-event subscription is live (2-300; 2 = pre-demotion war cadence). Built-in default: 30. Always 2 s without a live subscription.",
    },
    KeyMeta {
        key: "overlay_netmon",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "netstate - the process-wide network monitor: ONE OS change subscription, typed \
         snapshots/deltas, non-blocking fan-out (the route-event feed and the PR-2 \
         reaction fast lanes ride it). Built-in default: on.",
    },
    KeyMeta {
        key: "overlay_netmon_debounce_ms",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "number",
        description: "netstate - debounce window in ms coalescing OS signal bursts (a VPN connect \
         injects dozens of routes) into one delta (100-5000). Built-in default: 750.",
    },
    KeyMeta {
        key: "netstack_socks_port",
        group: Group::Network,
        tier: Tier::Standard,
        live: false,
        kind: "number",
        description: "Multi-org: the loopback SOCKS5 port serving THIS org's userspace netstack \
         (overlay_mode=\"netstack\"). One TCP listener per org — two orgs configured onto \
         one port means the second joins no mesh. The primary reads \
         ROOMLERD_OVERLAY_NETSTACK_SOCKS instead; set this on an [[orgs]] entry. \
         Built-in default: unset (OS-TUN mode).",
    },
    KeyMeta {
        key: "rc_max_sessions",
        group: Group::RemoteDesktop,
        tier: Tier::Standard,
        live: false,
        kind: "number",
        description: "Concurrent remote-control sessions this agent accepts (1-8). Same-profile DC viewers share one capture+encoder (see shared_encoder); distinct profiles run their own — weak-GPU hosts may prefer 1. Built-in default: 2.",
    },
    KeyMeta {
        key: "overlay_direct_port",
        group: Group::Network,
        tier: Tier::Advanced,
        live: false,
        kind: "number",
        description: "Stable UDP base port for the overlay direct sockets (per-interface LAN; the public/srflx dialer takes base+256). Stateful corp firewalls grandfather pre-VPN UDP flows — a stable port lets a rebuilt carrier reuse the same 5-tuple instead of relay-locking. A swallowed base walks an 8-port band, then the same walk at base+512 (Hyper-V/WSL reserve invisible pools that move between boots). 0 = ephemeral ports. Built-in default: DERIVED per machine (43648 + machine-id-hash slot, 43648..43896) so siblings behind one NAT never collide; set 43648 explicitly to pin the old fleet-wide constant. Env: ROOMLERD_OVERLAY_DIRECT_PORT.",
    },
    KeyMeta {
        key: "overlay_iface_metric",
        group: Group::NetworkRouting,
        tier: Tier::Advanced,
        live: false,
        kind: "number",
        description: "The overlay NIC's IPv4 interface metric (Windows). Windows ranks a route by route metric + INTERFACE metric; corp endpoint managers (Check Point, AnyConnect) mirror overlay prefixes at route metric 1 on an interface also pinned to 1, producing an exact tie that Windows breaks by lower ifIndex — the VPN's — and the per-destination pick is sticky, so peers stay captured across restarts. Unlike metric-0 routes (which those products delete), an interface metric has no route-monitor hook, so 0 wins outright. Raise only to make the overlay deliberately lose against another interface. Built-in default: 0. Env: ROOMLERD_OVERLAY_IFACE_METRIC.",
    },
    KeyMeta {
        key: "shared_encoder",
        group: Group::VideoEncoding,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "P5 shared-floor encoder: concurrent same-profile DC viewers share one capture+encoder with floor-merged rate/dials. off = one pipeline per session (rc.302 behaviour). Built-in default: on.",
    },
    KeyMeta {
        key: "overlay_relay_tls",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Force overlay coturn allocations onto the TURNS/TCP (TLS) tier — corp-VPN probe. Built-in default: off.",
    },
    KeyMeta {
        key: "overlay_shared_carrier",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Multi-org v2 shared carrier plane: every org's engine shares ONE process-wide direct-socket set (receiver-index demux) instead of racing the per-org port band. Built-in default: off.",
    },
    KeyMeta {
        key: "overlay_roam",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "WG-style endpoint roaming: adopt a peer's observed source after an authenticated inbound from it (repoints the carrier in place). Completes a punch from a symmetric-NAT peer and heals a mid-session NAT rebind. off = strict no-roam demux. Built-in default: on.",
    },
    KeyMeta {
        key: "overlay_plane_watchdog",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Carrier-plane socket-liveness watchdog: force a debounced plane rebuild when the shared punch-socket keepalive fails N consecutive cycles (reader-less/wedged socket). off = warn-only. Built-in default: on.",
    },
    KeyMeta {
        key: "overlay_session_trace",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Diagnostic: per-session plane-demux + carrier-health INFO traces (inbound src vs expected, poke/proof/rx state). Verbose; enable briefly on an affected host to diagnose a specific peer's carrier. Built-in default: off.",
    },
    KeyMeta {
        key: "overlay_disco_respond",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Answer out-of-tunnel disco echoes on the carrier socket (path liveness, answered by the daemon itself — no OS, firewall or tunnel session involved). Answering only; this node does not probe. Built-in default: on.",
    },
    KeyMeta {
        key: "overlay_disco_probe",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Probe peers with out-of-tunnel disco echoes and record per-path loss + RTT. Measurement only — nothing acts on the table (scoring is a later stage). Built-in default: off; enable only where every peer already answers.",
    },
    KeyMeta {
        key: "overlay_answer_while_followed",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Answer a peer's direct handshake even while that tier is suppressed, when accepting cannot cost the relay (it becomes a shadow probe). The demote-follow hold-down otherwise stops this node ANSWERING for up to 15 min, so two followed ends go mutually deaf and a good LAN pair sits on relay. Built-in default: ON since 0.4.2 (set false as the kill switch).",
    },
    KeyMeta {
        key: "overlay_tun_stable_guid",
        group: Group::NetworkRouting,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Stable Wintun adapter identity (constant requested GUID + boot stray-adapter sweep; Windows). Built-in default: on.",
    },
    KeyMeta {
        key: "overlay_route_evict",
        group: Group::NetworkRouting,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Route-war eviction of competing VPN-installed routes for overlay prefixes (Windows). Built-in default: on.",
    },
    KeyMeta {
        key: "overlay_route_reclaim",
        group: Group::NetworkRouting,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Route-war stolen-path reclaim (targeted evict + cache pin for tie-captured destinations) and evict-on-change debounce (Windows). Built-in default: on.",
    },
    KeyMeta {
        key: "overlay_route_evict_winners_only",
        group: Group::NetworkRouting,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Evict a competing VPN route only when it wins the route lookup; a mirror that loses every lookup is left alone (Windows). Built-in default: on.",
    },
    KeyMeta {
        key: "overlay_lan_route_repair",
        group: Group::NetworkRouting,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Repair a LAN interface's own prefix route when its next hop is not on that LAN (a VPN's stale gateway), by adding the prefix on-link as two halves; never routes around another interface's capture (Windows). Built-in default: on.",
    },
    KeyMeta {
        key: "overlay_tun_persist",
        group: Group::NetworkRouting,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Keep the overlay TUN device alive across signaling reconnects (process-lifetime cache). Built-in default: on.",
    },
    KeyMeta {
        key: "overlay_route_metric0",
        group: Group::NetworkRouting,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Install defended peer /32s (and the ULA /96 + connected /10) at route metric 0 so they outrank a corp VPN's metric-1 mirror routes (Windows). Built-in default: off — an opt-in experiment that auto-yields to metric 1 where a VPN route monitor deletes routes that would win.",
    },
    KeyMeta {
        key: "overlay_route_win",
        group: Group::NetworkRouting,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Win the contested prefixes outright instead of evicting a competitor off them forever (Windows). Built-in default: off. Two halves: it pins the overlay adapter's IPv6 interface metric, the lever IPv4 has had since rc.410 and IPv6 never got; and it asserts the derived-ULA /96 AND the connected v4 prefix (the carved block or legacy /10) at the defended route metric 1 instead of the stock connected-route 256. Measured against a corp VPN, v6 was 261 for us vs 26 for the VPN — lost outright, which is why the route guard evicts the VPN's mirrored /96 about 20 times a minute forever on a host whose IPv4 is quiet; the v4 half closes the same gap on the carved block, where the VPN holds it at effective 2 against our 256. Not the metric-0 variant a VPN route monitor deletes outright — it uses the same metric 1 IPv4 runs fleet-wide.",
    },
    KeyMeta {
        key: "local_turn",
        group: Group::RemoteDesktop,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Loopback-TURN relay for controllers on the same corporate network. Built-in default: on.",
    },
    KeyMeta {
        key: "dns_aaaa",
        group: Group::Network,
        tier: Tier::Standard,
        live: false,
        kind: "tribool",
        description: "MagicDNS AAAA (IPv6) answers for overlay names. Built-in default: on.",
    },
    KeyMeta {
        key: "magicdns_hosts",
        group: Group::Network,
        tier: Tier::Standard,
        live: false,
        kind: "tribool",
        description: "MagicDNS hosts-file fallback: when the OS DNS path is MEASURED not to \
         reach the local resolver (a corporate DNS-enforcement layer refusing \
         the host's own queries), write overlay names into the hosts file \
         instead, and remove them again as soon as DNS works. Built-in default: \
         off.",
    },
    KeyMeta {
        key: "auto_update",
        group: Group::Device,
        tier: Tier::Essential,
        live: false,
        kind: "tribool",
        description: "Periodic self-update checks (also gates web-pushed updates). Built-in default: on.",
    },
    KeyMeta {
        key: "logs_upload_disabled",
        group: Group::Device,
        tier: Tier::Standard,
        live: false,
        kind: "tribool",
        description: "Disable centralized diagnostic-log upload. Built-in default: uploads on.",
    },
    KeyMeta {
        key: "rate_factor_h264",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "H.264 maxrate ceiling factor, % (50-400). Env: ROOMLERD_RATE_FACTOR_H264. Empty = built-in 150. Restart required.",
    },
    KeyMeta {
        key: "rate_factor_hevc",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "HEVC maxrate ceiling factor, % (50-400). Env: ROOMLERD_RATE_FACTOR_HEVC. Empty = built-in 125. Restart required.",
    },
    KeyMeta {
        key: "rate_factor_vp9",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "VP9 maxrate ceiling factor, % (50-400). Env: ROOMLERD_RATE_FACTOR_VP9. Empty = built-in 125. Restart required.",
    },
    KeyMeta {
        key: "rate_factor_av1",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "AV1 maxrate ceiling factor, % (50-400). Env: ROOMLERD_RATE_FACTOR_AV1. Empty = built-in 100. Restart required.",
    },
    KeyMeta {
        key: "rate_factor_h264_444",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "FR-77 P3 - the chroma column: H.264 4:4:4 cells' extra maxrate factor, % (50-400), applied on top of rate_factor_h264. Env: ROOMLERD_RATE_FACTOR_H264_444. Empty = built-in 150. Restart required.",
    },
    KeyMeta {
        key: "rate_factor_hevc_444",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "FR-77 P3 - the chroma column: HEVC 4:4:4 cells' extra maxrate factor, % (50-400), applied on top of rate_factor_hevc. Env: ROOMLERD_RATE_FACTOR_HEVC_444. Empty = built-in 150. Restart required.",
    },
    KeyMeta {
        key: "rate_factor_vp9_444",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "FR-77 P3 - the chroma column: VP9 4:4:4 cells' extra maxrate factor, % (50-400), applied on top of rate_factor_vp9. Env: ROOMLERD_RATE_FACTOR_VP9_444. Empty = built-in 150. Restart required.",
    },
    KeyMeta {
        key: "lanczos_min_pct",
        group: Group::VideoEncoding,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "P7 - minimum linear downscale (percent, 0-100) at which the Lanczos-3 text-sharp filter engages; shallower shrinks use box. Empty = built-in 34 (covers the Smoother rungs; 56 restores the pre-P7 gate; 0 = always). Env: ROOMLERD_LANCZOS_MIN_PCT. Restart required.",
    },
    KeyMeta {
        key: "nvenc_spatial_aq",
        group: Group::VideoEncoding,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "P7 - NVENC spatial AQ. Built-in default: OFF (AQ steals bits from desktop text); true restores it for camera-heavy hosts. Env: ROOMLERD_NVENC_SPATIAL_AQ. Restart required.",
    },
    KeyMeta {
        key: "scale_cq_boost",
        group: Group::VideoEncoding,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "P7 - CQ sharpening steps granted at deep resolution rungs (0-12; spends the maxrate-floor headroom on text). Empty = built-in 4; 0 disables. Env: ROOMLERD_SCALE_CQ_BOOST. Restart required.",
    },
    KeyMeta {
        key: "idle_refine",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "P7 - idle native-rung refinement: lift the resolution cap when the scene settles so text is crisp at rest; motion restores it in ~300 ms. Built-in default: on (Smoother scope). Env: ROOMLERD_IDLE_REFINE. Restart required.",
    },
    KeyMeta {
        key: "idle_refine_balanced",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "P7 - idle refinement on Balanced+relay sessions (lifts the B1 physics cap at idle). Built-in default: on since P7c (field-proven on the winhost-b relay); off restores the un-refined Balanced rung. Env: ROOMLERD_IDLE_REFINE_BALANCED. Restart required.",
    },
    KeyMeta {
        key: "gpu_scale",
        group: Group::VideoEncoding,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "HW-downscale Phase B - GPU scale-before-readback (D3D11 VideoProcessor) on DXGI-direct capture: the Smoother rung is scaled on the GPU and the readback shrinks with it. Built-in default: on; off reverts to the Phase-A CPU resample. Env: ROOMLERD_GPU_SCALE. Restart required.",
    },
    KeyMeta {
        key: "overlay_lan_capture_probe",
        group: Group::Network,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "FR-33 - probe each LAN prefix for a corp-VPN split-prefix capture (own address on interface A, traffic to the prefix leaves via interface B) and surface it in status / why / the RC pill. Built-in default: on (a read-only route lookup per LAN address per netstate snapshot). Env: ROOMLERD_OVERLAY_LAN_CAPTURE_PROBE. Restart required.",
    },
    KeyMeta {
        key: "relay_ceiling_learn",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "FR-35 - let the constrained (relay) ceiling grow above the nominal 3 Mbps on delivery evidence (AIMD pinned at the ceiling, the window carried >=70% of it, no decrease/stall for 10 s, viewer age within 1.5x floor) and remember the pair's stable rate so the next session opens there. Built-in default: on. Env: ROOMLERD_RELAY_CEILING_LEARN. Restart required.",
    },
    KeyMeta {
        key: "drm_capture",
        group: Group::CaptureInput,
        tier: Tier::Standard,
        live: false,
        kind: "tribool",
        description: "FR-36 - capture the scanout framebuffer via DRM/KMS, BELOW the compositor. The only backend that can see a Wayland desktop, a locked screen or the login greeter (the xdg portal refuses all three). Built-in default: OFF - it carries no damage information, so enabling it where X11 works costs the FR-29 idle-CPU win. Env: ROOMLERD_DRM_CAPTURE. Restart required.",
    },
    KeyMeta {
        key: "uinput",
        group: Group::CaptureInput,
        tier: Tier::Standard,
        live: false,
        kind: "tribool",
        description: "FR-36 - inject input through /dev/uinput, below the compositor. Pair with drm_capture on a Wayland host: XTest reaches Xwayland clients ONLY, so without this a captured Wayland session is read-only. Built-in default: OFF - a uinput device is host-global and injects into whatever has focus, including the greeter and lock screen. Env: ROOMLERD_UINPUT. Restart required.",
    },
    KeyMeta {
        key: "portal_capture",
        group: Group::CaptureInput,
        tier: Tier::Standard,
        live: false,
        kind: "tribool",
        description: "FR-45 - capture a Wayland desktop through xdg-desktop-portal ScreenCast + PipeWire. The ATTENDED path: needs a logged-in user session, and the first use shows that user a consent dialog (later ones restore the grant without asking). Serves hosts DRM cannot reach - no scanout, nested compositors. Built-in default: OFF - an unattended host would wait on a dialog nobody answers. A per-user install in its own Wayland session uses the portal by itself where mutter is absent (wayland_auto, FR-93 P2d-3), so this key matters there only to force it (true) or to keep it off (false). Tried after DRM, before X11. Env: ROOMLERD_PORTAL_CAPTURE. Restart required.",
    },
    KeyMeta {
        key: "portal_input",
        group: Group::CaptureInput,
        tier: Tier::Standard,
        live: false,
        kind: "tribool",
        description: "FR-45 P4 - inject input through the portal RemoteDesktop interface, riding the SAME portal session (one consent dialog covers see+touch). Unset, it depends on who chose the portal arm (FR-93 P4b): the AUTOMATIC portal (wayland_auto, a per-user session where mutter is absent, such as KDE) asks for remote control in its one dialog, and false keeps it a screen share; a CONFIGURED portal_capture takes input only with this key true, because an input session needs its own grant and restore token, so switching it on makes an already-granted screen share ask again. A person who refuses remote control is then asked for the screen only: input never costs capture. On a configured mutter arm (mutter_capture) it means mutter's own RemoteDesktop. NOTE (measured on GNOME): the portal's consent dialog carries a SEPARATE 'Allow Remote Interaction' switch that defaults OFF, so a human who only clicks Share grants capture and the session runs view-only. Env: ROOMLERD_PORTAL_INPUT. Restart required.",
    },
    KeyMeta {
        key: "mutter_capture",
        group: Group::CaptureInput,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "FR-45 P5 - take screencast frames from org.gnome.Mutter.ScreenCast DIRECTLY instead of the desktop portal. For hosts where no portal backend can run at all (measured on WSL2: xdg-desktop-portal-gnome exits without a GNOME session, while mutter itself works). GNOME-only. Built-in default: OFF. ** UNATTENDED - this shows NO consent dialog; its peer is drm_capture, not portal_capture.** Env: ROOMLERD_MUTTER_CAPTURE. Restart required.",
    },
    KeyMeta {
        key: "window_capture",
        group: Group::CaptureInput,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "FR-56 P4 - capture ONE application window instead of the whole monitor (the RAIL-shaped half of Remote Apps: the viewer sees one app, not the desktop). Built-in default: OFF. ** ATTENDED BY CONSTRUCTION - the portal answers this by showing the person at the screen a WINDOW PICKER, and nothing agent-side can name a window (GNOME refuses Introspect.GetWindows), so on an unattended host the capture never starts.** Env: ROOMLERD_WINDOW_CAPTURE. Restart required.",
    },
    KeyMeta {
        key: "wayland_aware",
        group: Group::CaptureInput,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "FR-93 - when this host shows a Wayland desktop and nothing on this device may capture it, say so (wayland_not_enabled, naming the keys that would) instead of calling the host headless or streaming Xwayland's empty root as a black picture. Switches no capture on. Built-in default: ON. Off = the behaviour before FR-93, unchanged (the kill switch). Env: ROOMLERD_WAYLAND_AWARE. Restart required.",
    },
    KeyMeta {
        key: "wayland_auto",
        group: Group::CaptureInput,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "FR-93 P2 - a PER-USER install in its own Wayland session, with no capture key set, switches capture on by itself: on GNOME mutter's own screencast (** it asks nobody **), elsewhere (KDE and other desktops) the desktop portal, which asks the person at the screen once and restores their answer afterwards (P2d-3); it asks for remote control, unless portal_input is false (P4b). A root (system) install has its own half, wayland_auto_system (FR-95). Any capture key set (drm_capture, portal_capture, mutter_capture, window_capture) takes the choice back. Built-in default: ON. Off = the behaviour before P2 (the kill switch), for both halves. Env: ROOMLERD_WAYLAND_AUTO. Restart required.",
    },
    KeyMeta {
        key: "wayland_auto_system",
        group: Group::CaptureInput,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "FR-95 - a SYSTEM (root) install on a Wayland desktop, with no capture key set, switches DRM capture and uinput input on by itself where the person at the screen can be told they are being viewed (the desktop companion, or the desktop's own notifications, with Disconnect), and for their session only: the screen is read while that session is on it, unlocked, and never the greeter or the lock screen (** it asks nobody **, like DRM always has). With no way to tell the person, nothing changes and the hint names what is missing. Any capture key set takes the choice back; drm_capture = true also reads the greeter and the lock screen, as before. Built-in default: ON. Off = the behaviour before FR-95 (the kill switch); wayland_auto = false turns it off too. Env: ROOMLERD_WAYLAND_AUTO_SYSTEM. Restart required.",
    },
    KeyMeta {
        key: "x11_auto_system",
        group: Group::CaptureInput,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "FR-113 - the same as wayland_auto_system, for an X11 desktop: a SYSTEM (root) install, with no capture key set, switches DRM capture and uinput input on by itself for the person's X11 session on screen, on the same terms (told first, read only while that session is on screen, unlocked, never the greeter or the lock screen; ** it asks nobody **), only where the desktop reports its lock to the system (GNOME, KDE; any other X11 desktop is refused, since its lock screen could not be told from the desktop), and skips an idle X11 desktop's unchanged frames. Where it cannot capture, the viewer is told x11_not_enabled with the reason, not headless. Any capture key set takes the choice back. Built-in default: ON. Off = the behaviour before FR-113 (the kill switch: no picture of an X11 desktop by default, no_display); wayland_auto = false turns it off too. Env: ROOMLERD_X11_AUTO_SYSTEM. Restart required.",
    },
    KeyMeta {
        key: "mutter_input",
        group: Group::CaptureInput,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "FR-93 P4 - a mutter screencast is driven by mutter's own RemoteDesktop, so the viewer's mouse and keyboard reach the whole desktop through it, native Wayland windows included (** it asks nobody **, like the screencast it drives). The automatic arm (wayland_auto, a per-user GNOME session) carries it; a configured one (mutter_capture) carries it only with portal_input too. Built-in default: ON. Off = mutter capture is view-only again, the behaviour before P4 (the kill switch). Env: ROOMLERD_MUTTER_INPUT. Restart required.",
    },
    KeyMeta {
        key: "x11_damage",
        group: Group::CaptureInput,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "FR-29 - skip the XShm readback when XDAMAGE proves the screen is unchanged. Built-in default: on; took a Linux host's idle capture from 45.8% of a core to 2.8%. Env: ROOMLERD_X11_DAMAGE. Restart required.",
    },
    KeyMeta {
        key: "overlay_key_rotation",
        group: Group::Network,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "FR-40 - honour rc:agent.key_rotate: an admin retiring this device's overlay (WireGuard) key from the dashboard. The device mints the new key locally, persists it and re-joins the mesh under it; the server never sees a private key. Built-in default: on (a kill switch, not a gate - the order leaks nothing). Env: ROOMLERD_OVERLAY_KEY_ROTATION. Restart required.",
    },
    KeyMeta {
        key: "relay_max_hi_kbps",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "FR-35 - upper bound (kbps, 0-100000) for the learned relay ceiling. Empty = built-in 8000 (one pair measured: sustained 6-9 Mbps, choked at 12.8); 0 = learning off. Env: ROOMLERD_RELAY_MAX_HI_KBPS. Restart required.",
    },
    KeyMeta {
        key: "idle_refine_max_edge",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "P7 - long-edge cap for the refined rung (0-8192). Empty/0 = full native. Env: ROOMLERD_IDLE_REFINE_MAX_EDGE. Restart required.",
    },
    KeyMeta {
        key: "idle_refine_min_frame_kb",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "P7c - encoded-size floor (KiB, 0-256) for a frame to count as motion in the idle-refine machine; caret/keystroke deltas stay invisible so terminals keep the crisp rung while typing. Defined at the 1024x640 reference rung and scaled by the live encode area (P7c-2 - a fixed floor oscillated across rungs). Empty = built-in 12; 0 = every real frame counts (pre-P7c). Env: ROOMLERD_IDLE_REFINE_MIN_FRAME_KB. Restart required.",
    },
    KeyMeta {
        key: "idle_refine_major_area_permille",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "P8a-2 - MAJOR-motion area floor (permille of the frame, 0-1000) on capture-tracked backends (DXGI-direct/WGC): only damage at/above it restores the resolution cap; smaller damage (typing, popups, windowed terminal scrolls, PiP video) stays at native so text is sharp all the time. Empty = built-in 400 (40%); 0 = any non-empty tracked damage counts (pre-P8a-2 posture). Env: ROOMLERD_IDLE_REFINE_MAJOR_AREA_PERMILLE. Restart required.",
    },
    KeyMeta {
        key: "idle_refine_settle_ms",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "P8a-2 - up-flip settle (ms, 100-5000) on capture-tracked backends: the cap lifts this long after the last major-damage frame (damage truth needs no 1s window drain). Empty = built-in 500. Env: ROOMLERD_IDLE_REFINE_SETTLE_MS. Restart required.",
    },
    KeyMeta {
        key: "idle_refine_settle_constrained_ms",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "Phase B - tracked settle (ms, 100-10000) on CONSTRAINED transports: the cap lifts only after this long without major damage, because the refined IDR itself costs link time and a 500 ms settle fired on ordinary drag pauses (field: freezing/lag). Empty = built-in 1200 (2000 before the constrained HRD trim bounded the IDR). Env: ROOMLERD_IDLE_REFINE_SETTLE_CONSTRAINED_MS. Restart required.",
    },
    KeyMeta {
        key: "constrained_cq_relief",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "Constrained-motion CQ relief (softening steps, 0-12) applied at the resolution rung of a RELAY session; the rung exists for motion fluidity and softer frames arrive steadily instead of in lumps (field 2026-08-21: the sharpening bias at the rung was the 9 fps equilibrium). At-rest native quality is untouched; an explicit resolution pick is exempt. Empty = built-in 4; 0 = no relief. Env: ROOMLERD_CONSTRAINED_CQ_RELIEF. Restart required.",
    },
    KeyMeta {
        key: "constrained_queue_ms",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "Constrained send-queue byte budget (ms of the relay ceiling, 0-2000): frame production skips while more than this much link time is queued, converting viewer lag into a small fps reduction (field 2026-08-21: the drag-start freeze was ~0.5-1 MB of native motion frames queued on a ~2 Mbps relay). Empty = built-in 450; 0 = unbounded (pre-rc.442). Env: ROOMLERD_CONSTRAINED_QUEUE_MS. Restart required.",
    },
    KeyMeta {
        key: "constrained_hrd_pct",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "HRD/VBV window for CONSTRAINED sessions (percent of maxrate, 25-200). Empty = built-in 200 (the rc.234 2x window; rc.442 defaulted 75 to bound IDR transit and rc.443 reverted it - av1_qsv errors and hangs on a forced IDR that exceeds a sub-1x reservoir). Sub-100 values are per-host experiments only. Env: ROOMLERD_CONSTRAINED_HRD_PCT. Restart required.",
    },
    KeyMeta {
        key: "direct_queue_ms",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "DIRECT-path send-queue byte budget (ms of the path's rate ceiling, 0-2000, and since FR-74 P1b also the lag bound: bytes over the budget gate only once the MEASURED send wait has crossed this many ms, while bytes alone gate at the encoder's HRD reservoir; it was ms of the AIMD's live target until FR-74 P1 measured that as a self-reinforcing trap): frame production skips while more than this much link time is queued, bounding the standing lag a drag burst can build on a direct session (field 2026-08-26: 100-345 KB queued = the sluggish, rubber-band drag). Empty = built-in 150; 0 = unbounded (pre-P1 posture). Env: ROOMLERD_DIRECT_QUEUE_MS. Restart required.",
    },
    KeyMeta {
        key: "direct_hrd_pct",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "HRD/VBV window for DIRECT sessions (percent of maxrate, 25-200). Empty = built-in 100 - half the rc.234 2x window, which legalised drag-start bursts of seconds' worth of bits (the standing-queue lag). av1_* encoders are floored at 200 regardless (rc.443: Intel AV1 VDENC errors on an over-reservoir IDR instead of QP-clamping). Env: ROOMLERD_DIRECT_HRD_PCT. Restart required.",
    },
    KeyMeta {
        key: "bg_rebuild",
        group: Group::VideoEncoding,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Background encoder rebuild (2026-08-27, drag-latency P3). Default ON: on encoders with no in-place bitrate reconfigure (QSV/AMF), a bitrate change opens the replacement on a blocking thread while the current encoder keeps producing, then swaps between frames - no mid-drag stall, and rate drops land DURING motion as smaller frames instead of production skips. false = the rc.445 motion-defer (applies held until 1.2s of quiet, then a blocking re-open). Env: ROOMLERD_BG_REBUILD. Restart required.",
    },
    KeyMeta {
        key: "par_convert",
        group: Group::VideoEncoding,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Parallel colour conversion (2026-08-27, drag-latency P5). Default ON: big frames run the BGRA->NV12/I444 convert in row bands across threads - byte-identical output, roughly halves the convert share of encode time at 2880x1800+. false = single-threaded convert. Env: ROOMLERD_PAR_CONVERT. Restart required.",
    },
    KeyMeta {
        key: "fps_pace",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "fps-first cadence pacing on HW encoders (2026-08-27, drag-latency P5). Default ON: when the encoder cannot hold target fps, frames are consumed on an EVEN grid at the sustainable rate (5 fps steps, floor 15) instead of dropping ~33% at random phases - even cadence beats a jittery higher rate. While engaged the encode-pressure bitrate factor is masked at 1.0 (pixels-bound HW encode time does not respond to bitrate); the resolution tier stays the second lever. false = unpaced pre-P5 behaviour. Env: ROOMLERD_FPS_PACE. Restart required.",
    },
    KeyMeta {
        key: "relay_idr_thrift",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Relay IDR thrift (2026-08-27, FR-10). Default ON: constrained (relay) sessions suppress the idle-settle keyframe (a quality refresh, not a correctness need on a reliable DataChannel - the request-driven resync stays) and space deferred bitrate re-opens to >=15s unless the move is >=40%. Each such IDR was a single ~300 KB frame = 1.2-1.5s of a ~2 Mbps relay (the CORPLAP-3 bulky lumps). false = previous relay behaviour. Direct sessions unaffected. Env: ROOMLERD_RELAY_IDR_THRIFT. Restart required.",
    },
    KeyMeta {
        key: "send_stall_ms",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "number",
        description: "Blocked-send congestion threshold in ms (2026-08-28, FR-15 P2 follow-up). Default 250; 0 disables. A frame that sat longer than this inside the DataChannel send call is unambiguous congestion - the pipe refused to drain - and the pump feeds the AIMD a congestion sample. This is the one congestion signal that needs NO clock sync and NO viewer and works on both transports, which matters on a relay where the measured-rate clamp is direct-only and the age loop rides a probe the congestion itself biases. Acted on for CONSTRAINED sessions only; direct keeps the measured ceiling. Env: ROOMLER_NODE_SEND_STALL_MS. Restart required.",
    },
    KeyMeta {
        key: "relay_age_feedback",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Relay age feedback (2026-08-27, FR-15). Default ON: the viewer reports the true paint AGE of the frames it showed (the FR-1 P7 clock probe) on its rc:decodestat window; the agent learns the session's age FLOOR and treats sustained excess (>=70ms over floor for 2 consecutive windows) on a CONSTRAINED transport as over-rate - capping send-fps and feeding the AIMD a congestion sample, so the decrease lands through the normal (FR-10-deferred) apply path. It exists because a relay backlog sits BELOW every agent counter: the field measured 1000ms of viewer age against a 26KB agent queue. false = open-loop 0.4.7 relay posture. Direct sessions unaffected. Env: ROOMLERD_RELAY_AGE_FEEDBACK. Restart required.",
    },
    KeyMeta {
        key: "measured_ceiling",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Measured-rate stage 1 (2026-08-27). Default ON: the bitrate ceiling is clamped to 85% of the session's MEASURED drain rate while an estimate holds, so the encoder converges just under the pipe instead of congesting the send queue on every drag burst (the chunky production skips). Only ever lowers the nominal ceiling; confidence decays after 60s without evidence. false = observe-and-report only. Env: ROOMLERD_MEASURED_CEILING. Restart required.",
    },
    KeyMeta {
        key: "encoder_inplace_rate",
        group: Group::VideoEncoding,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "In-place encoder rate changes (2026-09-02, FR-62 A1). Default OFF: a QSV rate move REBUILDS the encoder (a 0.65-0.87 s blocking open on Iris-Xe-class, the reason the defer/swap machinery exists), and the NVENC in-place move writes a 1x HRD buffer. ON: QSV writes bit_rate + rc_max_rate + rc_buffer_size on the AVCodecContext (qsvenc's per-frame update_bitrate resets the BRC, no rebuild) and NVENC sizes the buffer to the window the session opened with. Ships OFF and inert until A0 clears the QSV MFXVideoENCODE_Reset on real Iris-Xe silicon; OFF is byte-for-byte the pre-A1 behaviour. Env: ROOMLERD_ENCODER_INPLACE_RATE. Restart required.",
    },
    KeyMeta {
        key: "ice_relay_tcp",
        group: Group::RemoteDesktop,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Pin remote-control's ICE to a TURN relay (diagnostic). Default OFF: the session takes whatever pair ICE nominates, and `constrained` is MEASURED from that pair (a public relay candidate = constrained; the loopback-TURN does not count). ON forces the relay path, which is bandwidth- and head-of-line-limited, so the encoder runs its constrained posture. ⚠️ This DEGRADES a session that would otherwise be direct - it is a test pin, not a tuning knob, and a device left with it set will be slow for no visible reason. It exists as a key because the constrained posture is otherwise only reproducible when a corporate VPN happens to be up, which makes every constrained-path acceptance test hostage to one laptop's network state; virtual-desktop mode sets the same flag for the same reason. Clear it (empty = default) when the measurement is done. WARNING: on a VIRTUAL-DESKTOP host with a hostile NAT the vd startup auto-pins this to 1, and its check for an explicit operator override reads the OS env var ONLY - so setting this key to false there does not defeat the auto-pin; use a real ROOMLERD_ICE_RELAY_TCP=0 for that one case. Env: ROOMLERD_ICE_RELAY_TCP. Restart required.",
    },
    KeyMeta {
        key: "relay_max_kbps",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "number",
        description: "Bitrate ceiling for a CONSTRAINED (relay) remote-control transport, kbps. Built-in default: 3000; clamped 100-100000. A single TURN relay carries roughly 1-4 Mbps and head-of-line blocks on TCP, so a ceiling sized for a direct pair (a 1920x1200 pair resolves ~12 Mbps) collapses it. LOWER it on a relay population that is thinner than the default assumes. RAISE it only to build a deliberate over-drive for a rate-control measurement: field 2026-09-03, a forced-relay cell on CORPLAP-1 opened at the 2.55 Mbps plan rate into a coturn carrying ~3 Mbps, which is NOT an over-drive - the AIMD simply climbed to the cap and viewer age stayed at 30-49 ms, so the FR-63 A/B had nothing to measure. At 12000 the same real pipe and real encoder give a genuine 4x over-drive on demand, instead of waiting for a corporate VPN to produce one. Pairs with ice_relay_tcp. Env: ROOMLERD_RELAY_MAX_KBPS. Restart required.",
    },
    KeyMeta {
        key: "rate_slow_start",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Slow-start the session opener (2026-09-03, FR-63). Default OFF. A session commits to a bitrate before it has any evidence about the pipe, and the same host over-drove from BOTH directions on one day: opened at a REMEMBERED 6134627 -> 6287ms of viewer paint age; opened at the NOMINAL relay cap 2550000 into a path measured at ~213000 -> 444ms of queue, 1550ms paint, and six windows collapsing back down. No constant is safe, because a constant is an assumption about a band. ON: open at 300000 (lifted by any PROVEN floor, e.g. the FR-59 P8 remembered-slow-pair open) and DOUBLE per clean window until the ceiling; the first congestion evidence ends the ramp and hands control back to the normal controller. A fast pair reaches a 6.1 Mbps ceiling in 5 windows. Only ever LOWERS the opening commitment - it can never raise a rate above what the controller already allows. Env: ROOMLERD_RATE_SLOW_START. Restart required.",
    },
    KeyMeta {
        key: "media_thread",
        group: Group::VideoEncoding,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "The encoder runs on its own OS thread per session (2026-09-05, FR-70 M1). Default ON since 0.4.70 - M1c met its gate on all three CORPLAP hosts on 0.4.69 (encode and capture averages unchanged, the loop's worst pass per window down on every host, the >50 ms windows fewer). ON: the FFmpeg encoder lives on a dedicated thread named rc-enc-<session> behind a command channel - the pump sends each frame and awaits the packets, and every rate move, keyframe request and background-rebuild adoption is a message applied in order - instead of encoding under block_in_place on whichever async worker happens to poll the pump. Nothing the pump decides changes: same frame, same decision, same packet, one thread hop later. What changes is that the async runtime is never held for the 5-30 ms of an encode (the send task, the control channel and the heartbeats stop sharing a worker with it) and hardware encoders that are thread-affine (Media Foundation per-thread COM, QSV sessions) are driven from one thread for the whole session. A thread that cannot be spawned falls back to the inline path with a warning; a thread that dies surfaces as the next encode's error, which the existing error ladder turns into a rebuild. Gate for flipping the default: FR-65's iter_ms_max / pump_stalls / apply_ms_max on the three CORPLAP hosts, unchanged or better. false = the inline encode, the pre-0.4.70 path. Env: ROOMLERD_MEDIA_THREAD. Restart required.",
    },
    KeyMeta {
        key: "pump_stall_watch",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Pump stall watch (2026-09-03, FR-65 P0). Default ON: a send-pump iteration slower than pump_stall_warn_ms is logged once with its phase breakdown (capture/scale/encode/apply/send), and the per-heartbeat apply_us / apply_us_max / iter_us_max / pump_stalls counters are published. Costs two Instant::now() per iteration (~20-40ns against a 16.7ms budget at 60fps) and logs nothing until an iteration actually overruns. It exists because a 2s blocking encoder open hid for months: the pump measured capture/scale/encode/send and the stall appeared in NONE of them - the apply/rebuild phase was untimed, and a per-heartbeat AVERAGE cannot represent a single outlier even where it is counted. false = no timing, no counters. Env: ROOMLERD_PUMP_STALL_WATCH. Restart required.",
    },
    KeyMeta {
        key: "pump_stall_warn_ms",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "number",
        description: "Pump stall threshold in ms (2026-09-03, FR-65 P0). Built-in default: 100; clamped 10-5000. Lowered from the 250 this shipped with, because the first field data said 250 was blind to the class that actually hurts: a corp-VPN host reported iter_ms_max=107.6 - real 100ms+ passes, matching the operator's own '>100ms' and '>148ms' age reports - while pump_stalls stayed 0. Deliberately a FLAT wall-clock threshold, NOT a multiple of the frame budget: the pump lowers target_fps BECAUSE it is already struggling, so a budget-relative bar RISES as the session degrades and stops reporting precisely when the trouble starts. Env: ROOMLERD_PUMP_STALL_WARN_MS. Restart required.",
    },
    KeyMeta {
        key: "bg_rebuild_constrained",
        group: Group::VideoEncoding,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Off-thread encoder rebuild on CONSTRAINED transports too (2026-09-03, FR-65). Default ON: a rebuild-mode encoder open is 0.65-0.87s of BLOCKING work on Iris-Xe-class silicon, and running it on the send pump stalls capture, encode and send together - measured as a ~2s hole. The open now runs on spawn_blocking for constrained paths as it already did for direct ones. Changes only WHERE the open runs, never WHEN the change lands: adoption stays gated on the same quiet window the defer policy uses, so the swap's IDR still arrives on a static scene - adopting mid-motion on a thin pipe is the 2026-08-27 relay regression that put the !constrained guard there originally. false = rebuild inline on constrained paths (pre-FR-65). Env: ROOMLERD_BG_REBUILD_CONSTRAINED. Restart required.",
    },
    KeyMeta {
        key: "slow_link_floor",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Slow-link floor relief (2026-09-01, FR-59 P1). Default ON: on a CONSTRAINED transport the AIMD legibility floor descends toward the session MEASURED drain rate instead of pinning at the flat 1.5 Mbps MIN_BITRATE_BPS. That flat floor is calibrated for the 2-9 Mbps band every measured relay sat in; on a slower link it is not a floor but a PIN, because it is also where the multiplicative decrease bottoms out - field 2026-09-01 measured a 395 kbps pipe met by a 1.5 Mbps floor, 3.8x over, with the excess landing as 2.3-7.1 s of viewer paint age. Evidence-gated: with no held goodput estimate the nominal floor stands, so a session that never measures is byte-for-byte unchanged. Never descends below slow_link_min_bitrate. false = flat floor (pre-FR-59). Env: ROOMLERD_SLOW_LINK_FLOOR. Restart required.",
    },
    KeyMeta {
        key: "slow_link_min_bitrate",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "number",
        description: "Absolute stop for the FR-59 P1 floor relief, bps (50000-1500000). Empty = built-in 200000. Below roughly this a full-resolution frame is illegible at any QP, so the honest lever is fewer PIXELS rather than fewer bits; the relief exists to let the AIMD converge onto a slow pipe, not to chase it to zero. A value at or above the nominal 1.5 Mbps floor is inert by construction. Env: ROOMLERD_SLOW_LINK_MIN_BITRATE. Restart required.",
    },
    KeyMeta {
        key: "constrained_queue_measured",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Constrained queue budget denominated in the MEASURED rate (2026-09-01, FR-59 P2). Default ON: the constrained send-queue byte budget is re-derived each iteration from the session measured drain rate instead of being resolved once against the nominal relay ceiling. A budget expressed in MILLISECONDS is a lie unless the bits-per-second it divides by is the pipe: constrained_queue_ms 450 against a nominal 3 Mbps is 168750 bytes, which on a measured 395 kbps link is 3.4 SECONDS of standing queue - and the gate never fired while the viewer sat seconds behind. A held measurement may only ever LOWER the reference. Note this consumes the same lumpy TURN-TCP estimate measured_ceiling deliberately refuses for the CEILING; the asymmetry is the point, since an under-estimate here shrinks the budget (more shedding, LOWER latency) where an under-estimated ceiling collapses quality. false = pre-FR-59. Env: ROOMLERD_CONSTRAINED_QUEUE_MEASURED. Restart required.",
    },
    KeyMeta {
        key: "seed_contradiction",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Abandon a contradicted rate-memory seed (2026-09-01, FR-59 P6). Default ON: a held goodput measurement more than 2x below the FR-35 learned or seeded ceiling abandons it back to the nominal band. The rate memory keys on the nominated ICE pair remote address, which on a RELAYED session is the relay address rather than the viewer - so one fast day writes a number every later session through that relay inherits for the memory 7-day TTL, whatever network the client is on today (field 2026-09-01: a 5069353 bps seed opened a session on a hotspot measured at 395122 bps, 12.8x under it). Applies to an in-session learned ceiling too, since a measurement is evidence either way and re-climbing is something the learner already does. false = keep the seed until the AIMD walks it down. Env: ROOMLERD_SEED_CONTRADICTION. Restart required.",
    },
    KeyMeta {
        key: "viewer_rate_clamp",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Viewer-reported link clamp (2026-09-01, FR-59 P3). Default ON: the VIEWER reports the bytes/s it actually received and how much its transit queue GREW this window, and on a constrained transport a sustained growing queue caps send-fps, feeds the AIMD a congestion sample, and bounds the ceiling at 90% of the measured arrival rate. It exists because the agent structurally cannot see this: on a relayed path its own send channel reads empty (field 2026-09-01: bytes_inflight 1-4 KB, send_wait_max_ms 0.1 ms) while seconds of video sit in the relay and the carrier. Unlike the FR-15 age report it needs NO clock probe - a byte count is local and the queue drift is a difference of two intervals, so the unknown offset cancels - which matters because on exactly these links the age is absent or rejected in most windows. The arrival rate may bound the ceiling ONLY while the queue is growing, since otherwise it is merely whatever the agent happened to send. false = observe-and-report only. Env: ROOMLERD_VIEWER_RATE_CLAMP. Restart required.",
    },
    KeyMeta {
        key: "queue_drain",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Queue drain (2026-09-01, FR-59 P4). Default ON: when the viewer reports a transit queue deeper than a rate cut can clear in reasonable time, the pump STOPS producing for a bounded sub-second pause so the queue drains. A rate cut alone drains at capacity minus inflow, which is the slowest possible way - converging to 90% of a 400 kbps pipe clears a 2 s backlog at 40 kbps, i.e. over ~20 s, which is why a field session stayed seconds behind even after it stopped growing. Pausing sets inflow to zero so the same backlog clears in the ~2 s it represents. Deliberately no forced keyframe on resume: a pause loses no frames so the delta chain survives, and an IDR at these rates is itself seconds of transit. Skipping production rather than discarding the agent queue is the only lever that reaches a queue living in the relay and the carrier - those bytes are already sent and cannot be recalled. false = rate control only. Env: ROOMLERD_QUEUE_DRAIN. Restart required.",
    },
    KeyMeta {
        key: "slow_link_profile",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Slow-link opening profile (2026-09-01, FR-59 P5). Default ON: a CONSTRAINED session whose pair the rate memory remembers at or below slow_link_profile_bps opens with a 1280 long-edge cap and 15 fps instead of native. The bitrate levers (FR-59 P1-P4) can make the encoder TRACK a 400 kbps pipe but cannot make 1920x1200 at 30 fps legible through it - that is about 1.7 KB per frame; halving the long edge quarters the pixels and halving the rate doubles the per-frame budget, together about 8x the bits per pixel. Resolved ONCE at pump start and never as a mid-session rung, because every rung flip pays a BLOCKING encoder open (0.65-0.87 s measured on Iris Xe) plus a fresh IDR - which is why priority_res_cap is off by default. A pair with NO memory never engages it: an unknown link is not a slow one, and guessing soft would degrade the first session on every healthy relay. false = open at the normal size. Env: ROOMLERD_SLOW_LINK_PROFILE. Restart required.",
    },
    KeyMeta {
        key: "slow_link_profile_bps",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "number",
        description: "Remembered rate at or below which the FR-59 P5 slow-link profile engages, bps. Empty = built-in 1000000; 0 = never engage. Env: ROOMLERD_SLOW_LINK_PROFILE_BPS. Restart required.",
    },
    KeyMeta {
        key: "area_min_bitrate",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Area-scaled AIMD bitrate floor (2026-08-26). Default ON: the flat 1.5 Mbps floor was a 1080p legibility tuning and is unreadable mush at 5+ MPix; the scaled floor is ~3.1 Mbps at 2880x1800, capped 4 Mbps, unconstrained sessions only (a relay's 3 Mbps clamp keeps the flat floor so the MD keeps room). false = flat 1.5 Mbps floor. Env: ROOMLERD_AREA_MIN_BITRATE. Restart required.",
    },
    KeyMeta {
        key: "priority_res_cap",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "rc.445 - restore the pre-rc.445 Priority-dial resolution caps (Smoother 1024 everywhere / Balanced 1280 on relay). Default OFF: every mid-motion rung flip costs a blocking encoder open (0.65-0.87s measured on Iris Xe) and the field verdict was that never flipping beats the rung; the dial's bit-shedding moved to the ceiling factors. Env: ROOMLERD_PRIORITY_RES_CAP. Restart required.",
    },
    KeyMeta {
        key: "smoother_rate_pct",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "rc.445 - Smoother's bitrate-ceiling factor (percent, 30-100): a lower ceiling makes the HRD raise QP during motion continuously (smaller frames, steadier fps) with ZERO encoder rebuilds; at-rest quality untouched. Empty = built-in 70. Env: ROOMLERD_SMOOTHER_RATE_PCT. Restart required.",
    },
    KeyMeta {
        key: "balanced_rate_pct",
        group: Group::VideoRate,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "rc.445 - Balanced's bitrate-ceiling factor (percent, 30-100). Empty = built-in 85. Env: ROOMLERD_BALANCED_RATE_PCT. Restart required.",
    },
    KeyMeta {
        key: "scale_threads",
        group: Group::VideoEncoding,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "HW-downscale Phase A - worker threads (1-8) for the CPU resampler's row-banded passes; a lever for weak hosts where the Smoother rung's downscale eats the frame budget. Empty = built-in 1 (inline, no threads). Env: ROOMLERD_SCALE_THREADS. Restart required.",
    },
    KeyMeta {
        key: "ice_follow_renomination",
        group: Group::RemoteDesktop,
        tier: Tier::Advanced,
        live: false,
        kind: "enum:auto|always|never",
        description: "Media-ICE nomination-follow policy. auto (empty) = upward-only + stale-failover (recommended); always = legacy follow-everything (thrash-prone, diagnostics only); never = pin to first nomination. Env: ROOMLER_ICE_FOLLOW_RENOMINATION.",
    },
    KeyMeta {
        key: "ice_warm_standby",
        group: Group::RemoteDesktop,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Keepalive pings on validated-but-unselected media ICE pairs (keeps the real-path fallback's NAT mapping alive). Built-in default: on. Env: ROOMLER_ICE_WARM_STANDBY.",
    },
    KeyMeta {
        key: "ice_overlay_host_deprioritize",
        group: Group::RemoteDesktop,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Rank overlay-TUN host candidates below srflx in media ICE (media prefers the real path). Built-in default: on. Env: ROOMLER_ICE_OVERLAY_HOST_DEPRIORITIZE.",
    },
    KeyMeta {
        key: "overlay_tier_detect",
        group: Group::RemoteDesktop,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Clamp media bitrate when the overlay carrier under a nominated pair is relay-tier. Built-in default: on. Env: ROOMLERD_OVERLAY_TIER_DETECT.",
    },
    KeyMeta {
        key: "overlay_rtt_q",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "B1 - feed the 15 s overlay RTT probes into the PathMonitor quality plane (Q-only, never eligibility). Built-in default: on. Env: ROOMLERD_OVERLAY_RTT_Q.",
    },
    KeyMeta {
        key: "overlay_upward_probe",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "B3 - probe an eligible higher tier from a healthy srflx/public incumbent every >=120 s (MBB; incumbent held until latch). Built-in default: on. Env: ROOMLERD_OVERLAY_UPWARD_PROBE.",
    },
    KeyMeta {
        key: "relay_probe",
        group: Group::NetworkCarriers,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "Multi-region relay PoPs - probe the server-pushed region list (timed STUN per PoP) and report RTTs; the server derives this node's relay_home from them. Built-in default: on. Env: ROOMLERD_RELAY_PROBE.",
    },
    KeyMeta {
        key: "text_mod_neutralize",
        group: Group::CaptureInput,
        tier: Tier::Standard,
        live: false,
        kind: "tribool",
        description: "KeyText typing: temporarily release physically-held Shift/Ctrl/Alt the remote layout does not want around each character tap (fixes wrong/dead symbols on non-US layouts). Built-in default: on. Env: ROOMLERD_TEXT_MOD_NEUTRALIZE. Restart required.",
    },
    KeyMeta {
        key: "caps_cache",
        group: Group::VideoEncoding,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "FR-77 P3 - cache the hardware encoder probe across daemon restarts, keyed by GPU + driver + OS build + roomlerd build; re-probed on any change or after 7 days. Built-in default: on. Env: ROOMLERD_CAPS_CACHE.",
    },
    KeyMeta {
        key: "encoder_cells_deny",
        group: Group::VideoEncoding,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "FR-77 - encoder cells this device must not open or advertise: comma-separated name:chroma entries (e.g. hevc_qsv:yuv444). Empty = the built-in list (hevc_qsv:yuv444, hevc_vaapi:yuv444, vp9_qsv:yuv444, vp9_vaapi:yuv444); `none` = deny nothing. Env: ROOMLERD_ENCODER_CELLS_DENY. Pushable through remote config. Restart required.",
    },
    KeyMeta {
        key: "fps_high",
        group: Group::VideoEncoding,
        tier: Tier::Advanced,
        live: false,
        kind: "tribool",
        description: "FR-119 - offer a viewer that asks a frame rate above 60 (120 or 144): advertise fps-high, and grant a higher rate only on a direct path, on a rate class this host has proven or as a trial, and where the pipe covers it. Built-in default: off. Env: ROOMLERD_FPS_HIGH. Restart required.",
    },
    KeyMeta {
        key: "fps_deny",
        group: Group::VideoEncoding,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "FR-119 - frame rates above 60 this device must not grant: comma-separated name:fps entries (e.g. hevc_qsv:120), `*` for every encoder (e.g. *:144). Empty or `none` = deny nothing. Env: ROOMLERD_FPS_DENY. Pushable through remote config. Restart required.",
    },
    KeyMeta {
        key: "vaapi_device",
        group: Group::VideoEncoding,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "FR-77 P4 - pin the VAAPI render node the Linux daemon opens (e.g. /dev/dri/renderD129). Empty = the first node libva accepts, /dev/dri/renderD128..135 in order. Env: ROOMLERD_VAAPI_DEVICE. Restart required.",
    },
    KeyMeta {
        key: "d3d12_adapter",
        group: Group::VideoEncoding,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "FR-78 P1 - pin the DXGI adapter index the D3D12 video-encode device opens on (Windows; e.g. 1). Empty = adapters 0..3 in order, the first FFmpeg accepts. Env: ROOMLERD_D3D12_ADAPTER. Restart required.",
    },
    KeyMeta {
        key: "vulkan_device",
        group: Group::VideoEncoding,
        tier: Tier::Advanced,
        live: false,
        kind: "string",
        description: "FR-78 P1 - pin the Vulkan physical device by index or name (e.g. 1, or NVIDIA GeForce RTX 5090). Empty = the loader's default device. Env: ROOMLERD_VULKAN_DEVICE. Restart required.",
    },
    KeyMeta {
        key: "record_dir",
        group: Group::Files,
        tier: Tier::Standard,
        // LIVE: the recorder's supervisor reads it when a recording starts
        // (FR-85), and nothing caches it.
        live: true,
        kind: "string",
        description: "FR-85 - the folder screen recordings are saved to: an absolute local path (no ~, no network share, no symlink or junction). Empty = Videos\\Roomler on Windows when it is local and writable (else %USERPROFILE%\\Roomler Recordings), ~/Movies/Roomler on macOS, the XDG videos folder + Roomler on Linux. Read when a recording starts. Device-only: never pushable through remote config.",
    },
    KeyMeta {
        key: "record_remote_enabled",
        group: Group::RemoteDesktop,
        tier: Tier::Standard,
        // LIVE: read per start request, and OFF stops a remote recording in
        // progress; the capability follows on the next heartbeat.
        live: true,
        kind: "bool",
        description: "FR-85 - let a remote controller record this screen during a session (default off). The recording is made and kept on this device, with a banner on screen while it runs; the controller downloads it. Off also stops a remote recording in progress. Device-only: never pushable through remote config. On a supervised Mac the signed-in person's own setting decides (their GUI worker records); the root daemon's copy has no effect there.",
    },
    KeyMeta {
        key: "record_remote_audio",
        group: Group::RemoteDesktop,
        tier: Tier::Standard,
        live: true,
        kind: "bool",
        description: "FR-85 - let a remote recording include what this computer plays (default off; needs record_remote_enabled). The microphone is never recorded remotely. Device-only: never pushable through remote config.",
    },
    KeyMeta {
        key: "keep_busy_enabled",
        group: Group::RemoteDesktop,
        tier: Tier::Standard,
        // LIVE: off stops a keep-busy in progress and refuses a new one; the
        // capability follows on the next heartbeat.
        live: true,
        kind: "bool",
        description: "FR-92 - let a remote controller turn on keep busy: mouse patterns that keep this computer active (no screensaver, idle lock or Away) until switched off, paused whenever someone uses the computer (default on). Off also stops it. While it runs it keeps the computer awake, whatever power_policy says. Device-only: never pushable through remote config.",
    },
    KeyMeta {
        key: "privacy_mode_allowed",
        group: Group::RemoteDesktop,
        tier: Tier::Standard,
        // LIVE: read at every "on", and OFF takes a curtain that is up down;
        // the capability follows on the next heartbeat.
        live: true,
        kind: "bool",
        description: "FR-99 - let a remote controller turn on privacy mode during a session: a curtain covers this screen for the person in front of it, with a notice saying who is connected, while the controller still sees the desktop (default off). Windows 10 2004 and later. The curtain hides the screen; it does not stop someone at this keyboard. Off also takes a curtain that is up down. Only the person at this device's console can change it. Device-only: never pushable through remote config.",
    },
    KeyMeta {
        key: "lock_on_end",
        group: Group::RemoteDesktop,
        tier: Tier::Standard,
        // LIVE: read at each session's start; applied when the last session
        // ends.
        live: true,
        kind: "string",
        description: "FR-99 - lock this computer when the last remote session ends: never (default) | auto (lock if the session began on a locked screen or with nobody at the computer) | always. A new Windows service install starts at auto. Windows and Linux. With always, a per-user install cannot unlock the screen remotely afterwards: someone must sign in at the computer. Only the person at this device's console can change it. Device-only: never pushable through remote config.",
    },
    KeyMeta {
        key: "display_match",
        group: Group::RemoteDesktop,
        tier: Tier::Standard,
        // LIVE: read at every display-match request.
        live: true,
        kind: "string",
        description: "FR-108 - whether a remote controller's display match may switch this computer's display mode to fit their window: auto (default: only while nobody is using this screen, that is no one has touched its keyboard or mouse for 5 minutes) | always (whenever asked) | never. Windows. A locked screen is switched only once it is unlocked. The original mode comes back when the session ends. Only the person at this device's console can change it. Device-only: never pushable through remote config.",
    },
    KeyMeta {
        key: "peer_auth",
        group: Group::RemoteDesktop,
        tier: Tier::Standard,
        // LIVE: every offer is judged by the value at that moment.
        live: true,
        kind: "string",
        description: "FR-100 - whether this device checks the browser that offers it a remote session: audit (default: verify the browser's signature over its offer, remember each browser key per user, record the result, refuse nothing) | off (none of it). enforce arrives later and cannot be set yet. Whatever this says, the device still signs its own answers, so the browser can check it. Only the person at this device's console can change it. Device-only: never pushable through remote config.",
    },
    KeyMeta {
        key: "rc_clipboard",
        group: Group::RemoteDesktop,
        tier: Tier::Standard,
        // LIVE: read at every session start; the hub hears it on the next
        // heartbeat.
        live: true,
        kind: "string",
        description: "FR-101 - this device's own rule for the clipboard in a remote session: on (default) | ask (only when the person here approves the session, on a prompt that names it) | off. The stricter of this and the organization's policy wins, and the device applies it whatever the server sends. Device-only: never pushable through remote config.",
    },
    KeyMeta {
        key: "rc_files",
        group: Group::RemoteDesktop,
        tier: Tier::Standard,
        live: true,
        kind: "string",
        description: "FR-101 - this device's own rule for file transfer in a remote session: on (default) | ask | off, as rc_clipboard. Device-only: never pushable through remote config.",
    },
    KeyMeta {
        key: "rc_audio",
        group: Group::RemoteDesktop,
        tier: Tier::Standard,
        live: true,
        kind: "string",
        description: "FR-101 - this device's own rule for sending this computer's audio in a remote session: on (default) | ask | off, as rc_clipboard. Device-only: never pushable through remote config.",
    },
    KeyMeta {
        key: "allow_plaintext_server",
        group: Group::Access,
        tier: Tier::Advanced,
        // Read with the config at start: the server URLs are dialled from it.
        live: false,
        kind: "bool",
        description: "FR-101 - keep a plaintext http:// server URL as written (default off: a remote http:// URL is used as https://, so signalling, token renewal, updates and uploads go over TLS). Only for a lab whose server serves no TLS; loopback never needs it. Only the person at this device's console can change it. Device-only: never pushable through remote config.",
    },
    KeyMeta {
        key: "forward_acl",
        group: Group::Tunnels,
        tier: Tier::Standard,
        live: false,
        kind: "json",
        description: "Agent-side allowlist for tunnel forwards (JSON: {\"enabled\": bool, \"allowlist\": [...]}).",
    },
    KeyMeta {
        key: "virtual_desktop_apps",
        group: Group::RemoteDesktop,
        tier: Tier::Advanced,
        live: false,
        kind: "json",
        description: "Remote app launcher config for virtual-desktop hosts (JSON; browser only ever sends an allowlist key).",
    },
];

/// The full editable surface with current values from `cfg`, in DISPLAY
/// order: grouped by [`Group::ALL`], registry order within a group. A
/// client renders sections in the order they arrive.
pub fn entries(cfg: &AgentConfig) -> Vec<ConfigEntry> {
    let mut ordered: Vec<&KeyMeta> = KEYS.iter().collect();
    // Stable, so registry order survives inside each group.
    ordered.sort_by_key(|m| m.group.order());
    ordered.into_iter().map(|m| to_entry(cfg, m)).collect()
}

/// One entry by key (post-apply echo). `None` = unknown key.
pub fn entry_for(cfg: &AgentConfig, key: &str) -> Option<ConfigEntry> {
    KEYS.iter().find(|m| m.key == key).map(|m| to_entry(cfg, m))
}

fn to_entry(cfg: &AgentConfig, m: &KeyMeta) -> ConfigEntry {
    ConfigEntry {
        key: m.key.to_string(),
        value: current_value(cfg, m.key),
        kind: m.kind.to_string(),
        restart_required: !m.live,
        description: m.description.to_string(),
        group: m.group.wire().to_string(),
        group_label: m.group.label().to_string(),
        tier: m.tier.wire().to_string(),
        default: builtin_default(m.key),
    }
}

/// The built-in default for `key`, rendered exactly as [`current_value`]
/// renders a set value — what the wire reports as `ConfigEntry::default`
/// so a client can say "modified" truthfully. `None` = unset by default
/// (the tribool and optional-number keys).
///
/// Derived from a config in which NO surface key is present, through the
/// SAME serde defaults `config::load` applies to an absent key — so it
/// cannot drift from what clearing a key produces. Locked per key by
/// `wire_default_is_what_clearing_yields`.
fn builtin_default(key: &str) -> Option<String> {
    static DEFAULTS: OnceLock<Option<AgentConfig>> = OnceLock::new();
    DEFAULTS
        .get_or_init(|| {
            // Only the six identity fields have no serde default; every
            // surface key does (that is what "absent = built-in" means for
            // the file on disk).
            match toml::from_str::<AgentConfig>(
                "server_url = \"\"\nagent_token = \"\"\nagent_id = \"\"\n\
                 tenant_id = \"\"\nmachine_id = \"\"\nmachine_name = \"\"\n",
            ) {
                Ok(cfg) => Some(cfg),
                Err(e) => {
                    // Never fatal: the surface still serves, the desktop
                    // just loses its "modified" chips. The unit test is the
                    // real guard — this cannot fail there without failing CI.
                    tracing::warn!(error = %e, "config surface: built-in defaults unavailable");
                    None
                }
            }
        })
        .as_ref()
        .and_then(|cfg| current_value(cfg, key))
}

fn current_value(cfg: &AgentConfig, key: &str) -> Option<String> {
    match key {
        "overlay_enabled" => Some(fmt_bool(cfg.overlay_enabled)),
        "overlay_multi_org" => Some(fmt_bool(cfg.overlay_multi_org)),
        "overlay_advertised_routes" => Some(cfg.overlay_advertised_routes.join(",")),
        "overlay_exit_node_enabled" => Some(fmt_bool(cfg.overlay_exit_node_enabled)),
        "overlay_exit_node" => cfg.overlay_exit_node.clone(),
        "advertise_routes" => Some(cfg.advertise_routes.join(",")),
        "advertise_local_subnets" => Some(fmt_bool(cfg.advertise_local_subnets)),
        "auto_grant_session" => Some(fmt_bool(cfg.auto_grant_session)),
        "enable_remote_browse" => Some(fmt_bool(cfg.enable_remote_browse)),
        "files_dir" => cfg.files_dir.clone(),
        "exec_enabled" => Some(fmt_bool(cfg.exec_enabled)),
        "macos_supervise_gui_worker" => Some(fmt_bool(cfg.macos_supervise_gui_worker)),
        "power_policy" => Some(if cfg.power_policy.is_empty() {
            "never".to_string()
        } else {
            cfg.power_policy.clone()
        }),
        "companion_autostart" => Some(fmt_bool(cfg.companion_autostart)),
        "remote_config_enabled" => Some(fmt_bool(cfg.remote_config_enabled)),
        "local_restart_enabled" => Some(fmt_bool(cfg.local_restart_enabled)),
        "external_access_enabled" => Some(fmt_bool(cfg.external_access_enabled)),
        "external_consent_mode" => cfg.external_consent_mode.clone(),
        "external_max_permissions" => cfg.external_max_permissions.clone(),
        "ssh_enabled" => Some(fmt_bool(cfg.ssh_enabled)),
        "ssh_port" => cfg.ssh_port.map(|p| p.to_string()),
        "ssh_authorized_keys" => Some(cfg.ssh_authorized_keys.join(",")),
        "ssh_account_mode" => cfg.ssh_account_mode.clone(),
        "ssh_max_privilege" => cfg.ssh_max_privilege.clone(),
        "ssh_activity_log" => Some(fmt_bool(cfg.ssh_activity_log)),
        "hive_enabled" => Some(fmt_bool(cfg.hive_enabled)),
        "hive_accounts" => serde_json::to_string(&cfg.hive_accounts).ok(),
        "hive_roots" => Some(cfg.hive_roots.join(",")),
        "hive_max_sessions" => cfg.hive_max_sessions.map(|n| n.to_string()),
        "hive_harness" => cfg.hive_harness.clone(),
        "hive_api_key_helper" => cfg.hive_api_key_helper.clone(),
        "hive_api_workspace_id" => cfg.hive_api_workspace_id.clone(),
        "hive_update_wait_secs" => cfg.hive_update_wait_secs.map(|n| n.to_string()),
        "hive_core_memory" => Some(fmt_bool(cfg.hive_core_memory)),
        "hive_adopt" => Some(fmt_bool(cfg.hive_adopt)),
        "hive_allow_passwordless_sudo" => Some(fmt_bool(cfg.hive_allow_passwordless_sudo)),
        "hive_replica" => Some(fmt_bool(cfg.hive_replica)),
        "hive_archive" => Some(fmt_bool(cfg.hive_archive)),
        "hive_store_quota_mib" => cfg.hive_store_quota_mib.map(|n| n.to_string()),
        "vault_enabled" => Some(fmt_bool(cfg.vault_enabled)),
        "vault_activity_log" => Some(fmt_bool(cfg.vault_activity_log)),
        "hive_net" => Some(fmt_bool(cfg.hive_net)),
        "hive_ssh" => Some(fmt_bool(cfg.hive_ssh)),
        "ssh_exec_streaming" => Some(fmt_bool(cfg.ssh_exec_streaming)),
        "encoder_preference" => Some(
            match cfg.encoder_preference {
                EncoderPreferenceChoice::Auto => "auto",
                EncoderPreferenceChoice::Hardware => "hardware",
                EncoderPreferenceChoice::Software => "software",
            }
            .to_string(),
        ),
        "update_check_interval_h" => cfg.update_check_interval_h.map(|h| h.to_string()),
        "overlay_quic" => cfg.overlay_quic.map(fmt_bool),
        "overlay_direct" => cfg.overlay_direct.map(fmt_bool),
        "overlay_derp" => cfg.overlay_derp.map(fmt_bool),
        "overlay_server_relay_strategy" => cfg.overlay_server_relay_strategy.map(fmt_bool),
        "overlay_derp_floor" => cfg.overlay_derp_floor.map(fmt_bool),
        "overlay_org_relay" => cfg.overlay_org_relay.map(fmt_bool),
        "overlay_netcheck" => cfg.overlay_netcheck.map(fmt_bool),
        "relay_server_enabled" => cfg.relay_server_enabled.map(fmt_bool),
        "relay_server_port" => cfg.relay_server_port.map(|v| v.to_string()),
        "tunnel_derp_fallback" => cfg.tunnel_derp_fallback.map(fmt_bool),
        "tunnel_reupgrade" => cfg.tunnel_reupgrade.map(fmt_bool),
        "tunnel_peers_survive_reattach" => cfg.tunnel_peers_survive_reattach.map(fmt_bool),
        "overlay_mbb" => cfg.overlay_mbb.map(fmt_bool),
        "overlay_lan_iface_filter" => cfg.overlay_lan_iface_filter.map(fmt_bool),
        "overlay_wsl_mirrored_guard" => cfg.overlay_wsl_mirrored_guard.map(fmt_bool),
        "overlay_init_auth_first" => cfg.overlay_init_auth_first.map(fmt_bool),
        "overlay_srflx_seek" => cfg.overlay_srflx_seek.map(fmt_bool),
        "ws_replaced_exit" => cfg.ws_replaced_exit.map(fmt_bool),
        "overlay_warm_relay" => cfg.overlay_warm_relay.map(fmt_bool),
        "overlay_quic_async" => cfg.overlay_quic_async.map(fmt_bool),
        "overlay_vpn_vantage" => cfg.overlay_vpn_vantage.map(fmt_bool),
        "overlay_portmap" => cfg.overlay_portmap.map(fmt_bool),
        "overlay_netd" => cfg.overlay_netd.map(fmt_bool),
        "overlay_pathmon" => cfg.overlay_pathmon.clone(),
        "overlay_demote" => cfg.overlay_demote.clone(),
        "overlay_rpf" => cfg.overlay_rpf.clone(),
        "overlay_route_events" => cfg.overlay_route_events.map(fmt_bool),
        "overlay_route_tick_secs" => cfg.overlay_route_tick_secs.map(|v| v.to_string()),
        "overlay_netmon" => cfg.overlay_netmon.map(fmt_bool),
        "overlay_netmon_debounce_ms" => cfg.overlay_netmon_debounce_ms.map(|v| v.to_string()),
        "netstack_socks_port" => cfg.netstack_socks_port.map(|v| v.to_string()),
        "localapi_pipe_pool" => cfg.localapi_pipe_pool.map(|v| v.to_string()),
        "rc_max_sessions" => cfg.rc_max_sessions.map(|v| v.to_string()),
        "overlay_direct_port" => cfg.overlay_direct_port.map(|v| v.to_string()),
        "overlay_iface_metric" => cfg.overlay_iface_metric.map(|v| v.to_string()),
        "shared_encoder" => cfg.shared_encoder.map(fmt_bool),
        "overlay_relay_tls" => cfg.overlay_relay_tls.map(fmt_bool),
        "overlay_shared_carrier" => cfg.overlay_shared_carrier.map(fmt_bool),
        "overlay_roam" => cfg.overlay_roam.map(fmt_bool),
        "overlay_plane_watchdog" => cfg.overlay_plane_watchdog.map(fmt_bool),
        "overlay_session_trace" => cfg.overlay_session_trace.map(fmt_bool),
        "overlay_disco_respond" => cfg.overlay_disco_respond.map(fmt_bool),
        "overlay_disco_probe" => cfg.overlay_disco_probe.map(fmt_bool),
        "overlay_answer_while_followed" => cfg.overlay_answer_while_followed.map(fmt_bool),
        "overlay_tun_stable_guid" => cfg.overlay_tun_stable_guid.map(fmt_bool),
        "overlay_route_evict" => cfg.overlay_route_evict.map(fmt_bool),
        "overlay_route_reclaim" => cfg.overlay_route_reclaim.map(fmt_bool),
        "overlay_route_evict_winners_only" => cfg.overlay_route_evict_winners_only.map(fmt_bool),
        "overlay_lan_route_repair" => cfg.overlay_lan_route_repair.map(fmt_bool),
        "overlay_tun_persist" => cfg.overlay_tun_persist.map(fmt_bool),
        "overlay_route_metric0" => cfg.overlay_route_metric0.map(fmt_bool),
        "overlay_route_win" => cfg.overlay_route_win.map(fmt_bool),
        "local_turn" => cfg.local_turn.map(fmt_bool),
        "dns_aaaa" => cfg.dns_aaaa.map(fmt_bool),
        "magicdns_hosts" => cfg.magicdns_hosts.map(fmt_bool),
        "auto_update" => cfg.auto_update.map(fmt_bool),
        "logs_upload_disabled" => cfg.logs_upload_disabled.map(fmt_bool),
        "rate_factor_h264" => cfg.rate_factor_h264.map(|p| p.to_string()),
        "rate_factor_hevc" => cfg.rate_factor_hevc.map(|p| p.to_string()),
        "rate_factor_vp9" => cfg.rate_factor_vp9.map(|p| p.to_string()),
        "rate_factor_av1" => cfg.rate_factor_av1.map(|p| p.to_string()),
        "rate_factor_h264_444" => cfg.rate_factor_h264_444.map(|p| p.to_string()),
        "rate_factor_hevc_444" => cfg.rate_factor_hevc_444.map(|p| p.to_string()),
        "rate_factor_vp9_444" => cfg.rate_factor_vp9_444.map(|p| p.to_string()),
        "lanczos_min_pct" => cfg.lanczos_min_pct.map(|p| p.to_string()),
        "nvenc_spatial_aq" => cfg.nvenc_spatial_aq.map(fmt_bool),
        "scale_cq_boost" => cfg.scale_cq_boost.map(|p| p.to_string()),
        "idle_refine" => cfg.idle_refine.map(fmt_bool),
        "idle_refine_balanced" => cfg.idle_refine_balanced.map(fmt_bool),
        "gpu_scale" => cfg.gpu_scale.map(fmt_bool),
        "overlay_lan_capture_probe" => cfg.overlay_lan_capture_probe.map(fmt_bool),
        "relay_ceiling_learn" => cfg.relay_ceiling_learn.map(fmt_bool),
        "drm_capture" => cfg.drm_capture.map(fmt_bool),
        "uinput" => cfg.uinput.map(fmt_bool),
        "portal_capture" => cfg.portal_capture.map(fmt_bool),
        "portal_input" => cfg.portal_input.map(fmt_bool),
        "mutter_capture" => cfg.mutter_capture.map(fmt_bool),
        "window_capture" => cfg.window_capture.map(fmt_bool),
        "wayland_aware" => cfg.wayland_aware.map(fmt_bool),
        "wayland_auto" => cfg.wayland_auto.map(fmt_bool),
        "wayland_auto_system" => cfg.wayland_auto_system.map(fmt_bool),
        "x11_auto_system" => cfg.x11_auto_system.map(fmt_bool),
        "mutter_input" => cfg.mutter_input.map(fmt_bool),
        "x11_damage" => cfg.x11_damage.map(fmt_bool),
        "overlay_key_rotation" => cfg.overlay_key_rotation.map(fmt_bool),
        "idle_refine_max_edge" => cfg.idle_refine_max_edge.map(|p| p.to_string()),
        "relay_max_hi_kbps" => cfg.relay_max_hi_kbps.map(|p| p.to_string()),
        "idle_refine_min_frame_kb" => cfg.idle_refine_min_frame_kb.map(|p| p.to_string()),
        "idle_refine_major_area_permille" => {
            cfg.idle_refine_major_area_permille.map(|p| p.to_string())
        }
        "idle_refine_settle_ms" => cfg.idle_refine_settle_ms.map(|p| p.to_string()),
        "idle_refine_settle_constrained_ms" => {
            cfg.idle_refine_settle_constrained_ms.map(|p| p.to_string())
        }
        "constrained_cq_relief" => cfg.constrained_cq_relief.map(|p| p.to_string()),
        "constrained_queue_ms" => cfg.constrained_queue_ms.map(|p| p.to_string()),
        "constrained_hrd_pct" => cfg.constrained_hrd_pct.map(|p| p.to_string()),
        "direct_queue_ms" => cfg.direct_queue_ms.map(|p| p.to_string()),
        "direct_hrd_pct" => cfg.direct_hrd_pct.map(|p| p.to_string()),
        "area_min_bitrate" => cfg.area_min_bitrate.map(fmt_bool),
        "measured_ceiling" => cfg.measured_ceiling.map(fmt_bool),
        "encoder_inplace_rate" => cfg.encoder_inplace_rate.map(fmt_bool),
        "ice_relay_tcp" => cfg.ice_relay_tcp.map(fmt_bool),
        "relay_max_kbps" => cfg.relay_max_kbps.map(|p| p.to_string()),
        "rate_slow_start" => cfg.rate_slow_start.map(fmt_bool),
        "media_thread" => cfg.media_thread.map(fmt_bool),
        "pump_stall_watch" => cfg.pump_stall_watch.map(fmt_bool),
        "pump_stall_warn_ms" => cfg.pump_stall_warn_ms.map(|p| p.to_string()),
        "bg_rebuild_constrained" => cfg.bg_rebuild_constrained.map(fmt_bool),
        "slow_link_floor" => cfg.slow_link_floor.map(fmt_bool),
        "slow_link_min_bitrate" => cfg.slow_link_min_bitrate.map(|p| p.to_string()),
        "constrained_queue_measured" => cfg.constrained_queue_measured.map(fmt_bool),
        "seed_contradiction" => cfg.seed_contradiction.map(fmt_bool),
        "viewer_rate_clamp" => cfg.viewer_rate_clamp.map(fmt_bool),
        "queue_drain" => cfg.queue_drain.map(fmt_bool),
        "slow_link_profile" => cfg.slow_link_profile.map(fmt_bool),
        "slow_link_profile_bps" => cfg.slow_link_profile_bps.map(|p| p.to_string()),
        "bg_rebuild" => cfg.bg_rebuild.map(fmt_bool),
        "par_convert" => cfg.par_convert.map(fmt_bool),
        "fps_pace" => cfg.fps_pace.map(fmt_bool),
        "relay_idr_thrift" => cfg.relay_idr_thrift.map(fmt_bool),
        "relay_age_feedback" => cfg.relay_age_feedback.map(fmt_bool),
        "send_stall_ms" => cfg.send_stall_ms.map(|v| v.to_string()),
        "priority_res_cap" => cfg.priority_res_cap.map(fmt_bool),
        "smoother_rate_pct" => cfg.smoother_rate_pct.map(|p| p.to_string()),
        "balanced_rate_pct" => cfg.balanced_rate_pct.map(|p| p.to_string()),
        "scale_threads" => cfg.scale_threads.map(|p| p.to_string()),
        "ice_follow_renomination" => cfg
            .ice_follow_renomination
            .map(|b| if b { "always" } else { "never" }.to_string()),
        "ice_warm_standby" => cfg.ice_warm_standby.map(fmt_bool),
        "ice_overlay_host_deprioritize" => cfg.ice_overlay_host_deprioritize.map(fmt_bool),
        "overlay_tier_detect" => cfg.overlay_tier_detect.map(fmt_bool),
        "overlay_rtt_q" => cfg.overlay_rtt_q.map(fmt_bool),
        "overlay_upward_probe" => cfg.overlay_upward_probe.map(fmt_bool),
        "relay_probe" => cfg.relay_probe.map(fmt_bool),
        "text_mod_neutralize" => cfg.text_mod_neutralize.map(fmt_bool),
        "caps_cache" => cfg.caps_cache.map(fmt_bool),
        "fps_high" => cfg.fps_high.map(fmt_bool),
        "encoder_cells_deny" => cfg.encoder_cells_deny.clone(),
        "fps_deny" => cfg.fps_deny.clone(),
        "vaapi_device" => cfg.vaapi_device.clone(),
        "d3d12_adapter" => cfg.d3d12_adapter.clone(),
        "vulkan_device" => cfg.vulkan_device.clone(),
        "record_dir" => cfg.record_dir.clone(),
        "record_remote_enabled" => Some(fmt_bool(cfg.record_remote_enabled)),
        "record_remote_audio" => Some(fmt_bool(cfg.record_remote_audio)),
        "keep_busy_enabled" => Some(fmt_bool(cfg.keep_busy_enabled)),
        "privacy_mode_allowed" => Some(fmt_bool(cfg.privacy_mode_allowed)),
        "lock_on_end" => Some(fmt_lock_on_end(cfg.lock_on_end)),
        "display_match" => Some(fmt_display_match(cfg.display_match)),
        "peer_auth" => Some(fmt_peer_auth(cfg.peer_auth)),
        "rc_clipboard" => Some(fmt_feature_policy(cfg.rc_clipboard)),
        "rc_files" => Some(fmt_feature_policy(cfg.rc_files)),
        "rc_audio" => Some(fmt_feature_policy(cfg.rc_audio)),
        "allow_plaintext_server" => Some(fmt_bool(cfg.allow_plaintext_server)),
        "forward_acl" => serde_json::to_string(&cfg.forward_acl).ok(),
        "virtual_desktop_apps" => serde_json::to_string(&cfg.virtual_desktop_apps).ok(),
        _ => None,
    }
}

/// Parse + validate + write one key into `cfg`. `value: None` clears the
/// key back to its built-in default. Returns a human-readable error (no
/// partial writes — `cfg` is only mutated on the success path of each
/// arm).
pub fn apply(cfg: &mut AgentConfig, key: &str, value: Option<&str>) -> Result<(), String> {
    match key {
        "overlay_enabled" => cfg.overlay_enabled = parse_bool_or(value, false)?,
        "overlay_multi_org" => cfg.overlay_multi_org = parse_bool_or(value, false)?,
        "overlay_advertised_routes" => cfg.overlay_advertised_routes = parse_cidr_list(value)?,
        "overlay_exit_node_enabled" => cfg.overlay_exit_node_enabled = parse_bool_or(value, false)?,
        "overlay_exit_node" => {
            cfg.overlay_exit_node = value
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        }
        "advertise_routes" => cfg.advertise_routes = parse_cidr_list(value)?,
        "advertise_local_subnets" => cfg.advertise_local_subnets = parse_bool_or(value, true)?,
        "auto_grant_session" => cfg.auto_grant_session = parse_bool_or(value, true)?,
        "enable_remote_browse" => cfg.enable_remote_browse = parse_bool_or(value, true)?,
        "files_dir" => {
            cfg.files_dir = match value.map(str::trim).filter(|s| !s.is_empty()) {
                None => None,
                Some(v) => {
                    // SHAPE only. Placement (the SYSTEM/root-inside-the-
                    // profile rule) and writability need the daemon's own
                    // identity and its disk; the daemon runs them in its
                    // `ConfigSet` before this apply, and again on every
                    // drop — this surface also serves the desktop's
                    // direct-file fallback, which has neither.
                    crate::files_dir::check_shape(v, &crate::files_dir::Rules::from_env())?;
                    Some(v.to_string())
                }
            }
        }
        // Clearing the key (`value: None`) resets to OFF, not ON — the
        // fail-safe direction for a gate that grants root.
        "exec_enabled" => cfg.exec_enabled = parse_bool_or(value, false)?,
        "record_remote_enabled" => cfg.record_remote_enabled = parse_bool_or(value, false)?,
        "record_remote_audio" => cfg.record_remote_audio = parse_bool_or(value, false)?,
        // FR-92 — cleared means the default, which is ON (operator decision
        // 2026-10-10); the owner turns it off by setting it false.
        "keep_busy_enabled" => cfg.keep_busy_enabled = parse_bool_or(value, true)?,
        "privacy_mode_allowed" => cfg.privacy_mode_allowed = parse_bool_or(value, false)?,
        "lock_on_end" => cfg.lock_on_end = parse_lock_on_end(value)?,
        "display_match" => cfg.display_match = parse_display_match(value)?,
        "peer_auth" => cfg.peer_auth = parse_peer_auth(value)?,
        // FR-101 P2b — cleared means the default, `on`; a value is read
        // strictly here, where a typo is made, rather than becoming `off`
        // silently the way an unknown value in the file reads.
        "rc_clipboard" => cfg.rc_clipboard = parse_feature_policy("rc_clipboard", value)?,
        "rc_files" => cfg.rc_files = parse_feature_policy("rc_files", value)?,
        "rc_audio" => cfg.rc_audio = parse_feature_policy("rc_audio", value)?,
        // FR-101 P1b — cleared means the default: TLS.
        "allow_plaintext_server" => cfg.allow_plaintext_server = parse_bool_or(value, false)?,
        "macos_supervise_gui_worker" => {
            cfg.macos_supervise_gui_worker = parse_bool_or(value, false)?
        }
        // FR-55 — validated HERE rather than at read time, so a typo is
        // refused when it is made instead of silently becoming `never` weeks
        // later on a device nobody is looking at.
        "power_policy" => {
            let v = value.unwrap_or("never").trim().to_ascii_lowercase();
            if !matches!(v.as_str(), "never" | "on-ac" | "on_ac" | "ac" | "always") {
                return Err(format!(
                    "power_policy must be one of never | on-ac | always (got {v:?})"
                ));
            }
            cfg.power_policy = v;
        }
        // FR-84 D6 — clearing returns to ON, the built-in default.
        "companion_autostart" => cfg.companion_autostart = parse_bool_or(value, true)?,
        // Same fail-safe direction, and note WHERE this is settable from:
        // locally (this surface — CLI, desktop companion), never from a
        // server push. A future config-push handler must reject this field
        // explicitly; if the server could set it, every other gate here would
        // be one push away from meaningless. See `docs/remote-config.md`.
        "remote_config_enabled" => cfg.remote_config_enabled = parse_bool_or(value, false)?,
        // FR-84 D3 — clearing restores the built-in ON: unlike the gates
        // above, this grants nothing, so OFF is an owner's choice rather than
        // the fail-safe direction. Settable only from here (never pushed).
        "local_restart_enabled" => cfg.local_restart_enabled = parse_bool_or(value, true)?,
        "external_access_enabled" => cfg.external_access_enabled = parse_bool_or(value, false)?,
        // FR-52 P4 — both validated on the way IN, the FR-55 rule: the session
        // path REFUSES a value it cannot read (never falls back — `auto` is the
        // one value that skips a human, and a typo must not be what decides
        // it), so a typo accepted here would surface weeks later as external
        // access that silently never works. Blank clears, as elsewhere.
        "external_consent_mode" => {
            cfg.external_consent_mode = match value.map(str::trim).filter(|s| !s.is_empty()) {
                None => None,
                Some(v @ ("prompt" | "auto")) => Some(v.to_string()),
                Some(v) => {
                    return Err(format!(
                        "external_consent_mode must be prompt | auto (got {v:?})"
                    ));
                }
            }
        }
        "external_max_permissions" => {
            cfg.external_max_permissions = match value.map(str::trim).filter(|s| !s.is_empty()) {
                None => None,
                Some(v) => {
                    let parsed =
                        roomler_ai_remote_control::permissions::Permissions::from_wire_names(v)
                            .ok_or_else(|| {
                                format!(
                                    "external_max_permissions must be permission names joined by \
                                 `|`, e.g. \"VIEW | INPUT\" (got {v:?})"
                                )
                            })?;
                    // `"|"` parses to NO permission, which would be stored as
                    // "" and read back as "unset: defer to the org" — the
                    // opposite of what was typed.
                    if parsed.is_empty() {
                        return Err("external_max_permissions names no permission; clear it to \
                                    defer to the org, or set external_access_enabled false"
                            .to_string());
                    }
                    // Stored in the canonical spelling, so what `config get`
                    // prints is what the session path will read.
                    Some(parsed.wire_names())
                }
            }
        }
        // Same fail-safe direction as `exec_enabled`: clearing the key means
        // OFF. An SSH session is strictly more than a bounded command.
        "ssh_enabled" => cfg.ssh_enabled = parse_bool_or(value, false)?,
        // Clearing it means OFF, like every other reporting/capability switch.
        "ssh_activity_log" => cfg.ssh_activity_log = parse_bool_or(value, false)?,
        "hive_enabled" => cfg.hive_enabled = parse_bool_or(value, false)?,
        // Validated on the way IN, like `ssh_account_mode`: a typo should be a
        // rejected `config set`, not a session refused `no_account` for a
        // reason the owner then has to dig out of the daemon log.
        "hive_accounts" => cfg.hive_accounts = parse_hive_accounts(value)?,
        // Clearing empties the list, i.e. nowhere — the fail-safe direction.
        "hive_roots" => cfg.hive_roots = parse_absolute_list("hive_roots", value)?,
        "hive_max_sessions" => {
            cfg.hive_max_sessions = parse_u32_range("hive_max_sessions", value, 1, 64)?
        }
        "hive_harness" => cfg.hive_harness = parse_absolute_path("hive_harness", value)?,
        "hive_api_key_helper" => {
            cfg.hive_api_key_helper = match value.map(str::trim).filter(|s| !s.is_empty()) {
                None => None,
                Some(v) if v.chars().any(char::is_control) => {
                    return Err("hive_api_key_helper must be one line".into());
                }
                Some(v) => Some(v.to_string()),
            }
        }
        // An identifier, sent as a header: letters, digits, `_` and `-` only.
        "hive_api_workspace_id" => {
            cfg.hive_api_workspace_id = match value.map(str::trim).filter(|s| !s.is_empty()) {
                None => None,
                Some(v)
                    if v.len() > 128
                        || !v
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') =>
                {
                    return Err(
                        "hive_api_workspace_id is a workspace id (letters, digits, _ and -)".into(),
                    );
                }
                Some(v) => Some(v.to_string()),
            }
        }
        // FR-90 P1d-1 — clearing restores the built-in 30 minutes; 0 is an
        // owner's choice to let updates cut turns at once.
        "hive_core_memory" => cfg.hive_core_memory = parse_bool_or(value, false)?,
        "hive_adopt" => cfg.hive_adopt = parse_bool_or(value, false)?,
        "hive_allow_passwordless_sudo" => {
            cfg.hive_allow_passwordless_sudo = parse_bool_or(value, false)?
        }
        "hive_replica" => cfg.hive_replica = parse_bool_or(value, false)?,
        "hive_archive" => cfg.hive_archive = parse_bool_or(value, false)?,
        "hive_store_quota_mib" => {
            cfg.hive_store_quota_mib =
                parse_u32_range("hive_store_quota_mib", value, 1, 4 * 1024 * 1024)?
        }
        "vault_enabled" => cfg.vault_enabled = parse_bool_or(value, false)?,
        "vault_activity_log" => cfg.vault_activity_log = parse_bool_or(value, false)?,
        "hive_net" => cfg.hive_net = parse_bool_or(value, false)?,
        "hive_ssh" => cfg.hive_ssh = parse_bool_or(value, false)?,
        "hive_update_wait_secs" => {
            cfg.hive_update_wait_secs = parse_u32_range("hive_update_wait_secs", value, 0, 7200)?
        }
        // FR-89 — clearing restores the built-in ON: this is a kill switch
        // for a data-path shape, not a gate, so OFF is an owner's choice.
        "ssh_exec_streaming" => cfg.ssh_exec_streaming = parse_bool_or(value, true)?,
        "ssh_port" => {
            cfg.ssh_port = match value.map(str::trim).filter(|s| !s.is_empty()) {
                None => None,
                Some(v) => {
                    let p: u16 = v
                        .parse()
                        .map_err(|_| format!("ssh_port must be a number (got {v:?})"))?;
                    if p == 0 {
                        return Err("ssh_port must be between 1 and 65535".into());
                    }
                    Some(p)
                }
            }
        }
        // Clearing the key empties the list, i.e. revokes everyone — the
        // fail-safe direction, and the fastest way to shut SSH access off
        // without touching the transport.
        "ssh_authorized_keys" => {
            cfg.ssh_authorized_keys = value
                .unwrap_or("")
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        }
        // Validated on the way IN rather than at session time: a typo should be
        // a rejected `config set`, not a session that authenticates and then
        // refuses every command for a reason the operator has to go digging in
        // the daemon log to find.
        "ssh_account_mode" => {
            cfg.ssh_account_mode = match value.map(str::trim).filter(|s| !s.is_empty()) {
                None => None,
                Some(v) => {
                    let ok = v == "daemon"
                        || v == "console_user"
                        || v.strip_prefix("named:")
                            .is_some_and(|a| !a.trim().is_empty());
                    if !ok {
                        return Err(format!(
                            "ssh_account_mode must be daemon | console_user | named:<account> \
                             (got {v:?})"
                        ));
                    }
                    Some(v.to_string())
                }
            }
        }
        // Only the two values that name a comparable privilege level. `named:`
        // is deliberately NOT accepted: a ceiling has to be an ordering, and
        // "is `named:svc-backup` above or below `console_user`?" has no answer
        // — so it would be a setting whose meaning nobody could state.
        "ssh_max_privilege" => {
            cfg.ssh_max_privilege = match value.map(str::trim).filter(|s| !s.is_empty()) {
                None => None,
                Some(v) if v == "daemon" || v == "console_user" => Some(v.to_string()),
                Some(other) => {
                    return Err(format!(
                        "ssh_max_privilege must be daemon | console_user (got {other:?}); \
                         empty means no device-side limit"
                    ));
                }
            }
        }
        "encoder_preference" => {
            cfg.encoder_preference = match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
                None | Some("") | Some("auto") => EncoderPreferenceChoice::Auto,
                Some("hardware") | Some("hw") | Some("mf") => EncoderPreferenceChoice::Hardware,
                Some("software") | Some("sw") | Some("openh264") => {
                    EncoderPreferenceChoice::Software
                }
                Some(other) => {
                    return Err(format!(
                        "encoder_preference must be auto|hardware|software (got {other:?})"
                    ));
                }
            }
        }
        "update_check_interval_h" => {
            cfg.update_check_interval_h = match value.map(str::trim).filter(|s| !s.is_empty()) {
                None => None,
                Some(v) => {
                    let h: u32 = v.parse().map_err(|_| {
                        format!("update_check_interval_h must be a number (got {v:?})")
                    })?;
                    if !(1..=8760).contains(&h) {
                        return Err("update_check_interval_h must be between 1 and 8760".into());
                    }
                    Some(h)
                }
            }
        }
        "overlay_quic" => cfg.overlay_quic = parse_tribool(value)?,
        "overlay_direct" => cfg.overlay_direct = parse_tribool(value)?,
        "overlay_derp" => cfg.overlay_derp = parse_tribool(value)?,
        "overlay_server_relay_strategy" => {
            cfg.overlay_server_relay_strategy = parse_tribool(value)?
        }
        "overlay_derp_floor" => cfg.overlay_derp_floor = parse_tribool(value)?,
        "overlay_org_relay" => cfg.overlay_org_relay = parse_tribool(value)?,
        "overlay_netcheck" => cfg.overlay_netcheck = parse_tribool(value)?,
        "relay_server_enabled" => cfg.relay_server_enabled = parse_tribool(value)?,
        "relay_server_port" => {
            cfg.relay_server_port = match value.map(str::trim).filter(|s| !s.is_empty()) {
                None => None,
                Some(v) => {
                    let n: u32 = v
                        .parse()
                        .map_err(|_| format!("relay_server_port must be a number (got {v:?})"))?;
                    // No 0-means-ephemeral escape hatch here, deliberately: a
                    // relay peers must be able to FIND is useless on a port the
                    // operator cannot state, and 3478 is the only port E2E-3
                    // measured the target population reaching.
                    if n == 0 || n > 65535 {
                        return Err(format!("relay_server_port must be 1-65535 (got {n})"));
                    }
                    Some(n)
                }
            }
        }
        "tunnel_derp_fallback" => cfg.tunnel_derp_fallback = parse_tribool(value)?,
        "tunnel_reupgrade" => cfg.tunnel_reupgrade = parse_tribool(value)?,
        "tunnel_peers_survive_reattach" => {
            cfg.tunnel_peers_survive_reattach = parse_tribool(value)?
        }
        "overlay_mbb" => cfg.overlay_mbb = parse_tribool(value)?,
        "overlay_lan_iface_filter" => cfg.overlay_lan_iface_filter = parse_tribool(value)?,
        "overlay_wsl_mirrored_guard" => cfg.overlay_wsl_mirrored_guard = parse_tribool(value)?,
        "overlay_init_auth_first" => cfg.overlay_init_auth_first = parse_tribool(value)?,
        "overlay_srflx_seek" => cfg.overlay_srflx_seek = parse_tribool(value)?,
        "ws_replaced_exit" => cfg.ws_replaced_exit = parse_tribool(value)?,
        "overlay_warm_relay" => cfg.overlay_warm_relay = parse_tribool(value)?,
        "overlay_quic_async" => cfg.overlay_quic_async = parse_tribool(value)?,
        "overlay_vpn_vantage" => cfg.overlay_vpn_vantage = parse_tribool(value)?,
        "overlay_portmap" => cfg.overlay_portmap = parse_tribool(value)?,
        "overlay_netd" => cfg.overlay_netd = parse_tribool(value)?,
        "overlay_pathmon" => {
            cfg.overlay_pathmon = match value.map(str::trim).filter(|s| !s.is_empty()) {
                None => None,
                Some(v) => {
                    let mode = v.to_ascii_lowercase();
                    if !matches!(mode.as_str(), "on" | "shadow" | "off") {
                        return Err("overlay_pathmon must be on | shadow | off".to_string());
                    }
                    Some(mode)
                }
            }
        }
        "overlay_demote" => {
            cfg.overlay_demote = match value.map(str::trim).filter(|s| !s.is_empty()) {
                None => None,
                Some(v) => {
                    let mode = v.to_ascii_lowercase();
                    if !matches!(mode.as_str(), "on" | "shadow" | "off") {
                        return Err("overlay_demote must be on | shadow | off".to_string());
                    }
                    Some(mode)
                }
            }
        }
        "overlay_rpf" => {
            cfg.overlay_rpf = match value.map(str::trim).filter(|s| !s.is_empty()) {
                None => None,
                Some(v) => {
                    let mode = v.to_ascii_lowercase();
                    if !matches!(mode.as_str(), "warn" | "enforce" | "off") {
                        return Err("overlay_rpf must be warn | enforce | off".to_string());
                    }
                    Some(mode)
                }
            }
        }
        "overlay_route_events" => cfg.overlay_route_events = parse_tribool(value)?,
        "overlay_route_tick_secs" => {
            cfg.overlay_route_tick_secs = match value.map(str::trim).filter(|s| !s.is_empty()) {
                None => None,
                Some(v) => {
                    let s: u32 = v.parse().map_err(|_| {
                        format!("overlay_route_tick_secs must be a number (got {v:?})")
                    })?;
                    if !(2..=300).contains(&s) {
                        return Err("overlay_route_tick_secs must be between 2 and 300".into());
                    }
                    Some(s)
                }
            }
        }
        "overlay_netmon" => cfg.overlay_netmon = parse_tribool(value)?,
        "overlay_netmon_debounce_ms" => {
            cfg.overlay_netmon_debounce_ms = match value.map(str::trim).filter(|s| !s.is_empty()) {
                None => None,
                Some(v) => {
                    let ms: u32 = v.parse().map_err(|_| {
                        format!("overlay_netmon_debounce_ms must be a number (got {v:?})")
                    })?;
                    if !(100..=5000).contains(&ms) {
                        return Err(
                            "overlay_netmon_debounce_ms must be between 100 and 5000".into()
                        );
                    }
                    Some(ms)
                }
            }
        }
        "netstack_socks_port" => {
            cfg.netstack_socks_port = match value.map(str::trim).filter(|s| !s.is_empty()) {
                None => None,
                Some(v) => {
                    let n: u16 = v.parse().map_err(|_| {
                        format!("netstack_socks_port must be a port number (got {v:?})")
                    })?;
                    if n < 1024 {
                        return Err("netstack_socks_port must be >= 1024 \
                                    (it binds a loopback listener)"
                            .into());
                    }
                    Some(n)
                }
            }
        }
        // FR-84 D1 — the listener pool is sized once, at bind time; 1 is the
        // pre-FR-84 single instance, 16 the ceiling `serve_with_pool` clamps
        // to anyway (refused here so a typo is a failed set, not a silent
        // clamp).
        "localapi_pipe_pool" => {
            cfg.localapi_pipe_pool = parse_u32_range("localapi_pipe_pool", value, 1, 16)?
        }
        "rc_max_sessions" => {
            cfg.rc_max_sessions = match value.map(str::trim).filter(|s| !s.is_empty()) {
                None => None,
                Some(v) => {
                    let n: u32 = v
                        .parse()
                        .map_err(|_| format!("rc_max_sessions must be a number (got {v:?})"))?;
                    if !(1..=8).contains(&n) {
                        return Err("rc_max_sessions must be between 1 and 8".into());
                    }
                    Some(n)
                }
            }
        }
        "overlay_iface_metric" => {
            cfg.overlay_iface_metric = match value.map(str::trim).filter(|s| !s.is_empty()) {
                None => None,
                Some(v) => {
                    let n: u32 = v.parse().map_err(|_| {
                        format!("overlay_iface_metric must be a number (got {v:?})")
                    })?;
                    if n > 9999 {
                        return Err(format!("overlay_iface_metric must be 0..=9999 (got {n})"));
                    }
                    Some(n)
                }
            }
        }
        "overlay_direct_port" => {
            cfg.overlay_direct_port = match value.map(str::trim).filter(|s| !s.is_empty()) {
                None => None,
                Some(v) => {
                    let n: u32 = v
                        .parse()
                        .map_err(|_| format!("overlay_direct_port must be a number (got {v:?})"))?;
                    // 0 = ephemeral (explicit opt-out); otherwise a base whose
                    // public-dial band must still fit under the port space.

                    let max = MAX_OVERLAY_DIRECT_PORT_BASE;
                    if n > max {
                        return Err(format!(
                            "overlay_direct_port must be 0 (ephemeral) or 1-{max} \
                             (the public-dial band must fit under 65535)"
                        ));
                    }
                    Some(n)
                }
            }
        }
        "shared_encoder" => cfg.shared_encoder = parse_tribool(value)?,
        "overlay_relay_tls" => cfg.overlay_relay_tls = parse_tribool(value)?,
        "overlay_shared_carrier" => cfg.overlay_shared_carrier = parse_tribool(value)?,
        "overlay_roam" => cfg.overlay_roam = parse_tribool(value)?,
        "overlay_plane_watchdog" => cfg.overlay_plane_watchdog = parse_tribool(value)?,
        "overlay_session_trace" => cfg.overlay_session_trace = parse_tribool(value)?,
        "overlay_disco_respond" => cfg.overlay_disco_respond = parse_tribool(value)?,
        "overlay_disco_probe" => cfg.overlay_disco_probe = parse_tribool(value)?,
        "overlay_answer_while_followed" => {
            cfg.overlay_answer_while_followed = parse_tribool(value)?
        }
        "overlay_tun_stable_guid" => cfg.overlay_tun_stable_guid = parse_tribool(value)?,
        "overlay_route_evict" => cfg.overlay_route_evict = parse_tribool(value)?,
        "overlay_route_reclaim" => cfg.overlay_route_reclaim = parse_tribool(value)?,
        "overlay_route_evict_winners_only" => {
            cfg.overlay_route_evict_winners_only = parse_tribool(value)?
        }
        "overlay_lan_route_repair" => cfg.overlay_lan_route_repair = parse_tribool(value)?,
        "overlay_tun_persist" => cfg.overlay_tun_persist = parse_tribool(value)?,
        "overlay_route_metric0" => cfg.overlay_route_metric0 = parse_tribool(value)?,
        "overlay_route_win" => cfg.overlay_route_win = parse_tribool(value)?,
        "local_turn" => cfg.local_turn = parse_tribool(value)?,
        "dns_aaaa" => cfg.dns_aaaa = parse_tribool(value)?,
        "magicdns_hosts" => cfg.magicdns_hosts = parse_tribool(value)?,
        "auto_update" => cfg.auto_update = parse_tribool(value)?,
        "logs_upload_disabled" => cfg.logs_upload_disabled = parse_tribool(value)?,
        "rate_factor_h264" => cfg.rate_factor_h264 = parse_rate_factor(key, value)?,
        "rate_factor_hevc" => cfg.rate_factor_hevc = parse_rate_factor(key, value)?,
        "rate_factor_vp9" => cfg.rate_factor_vp9 = parse_rate_factor(key, value)?,
        "rate_factor_av1" => cfg.rate_factor_av1 = parse_rate_factor(key, value)?,
        "rate_factor_h264_444" => cfg.rate_factor_h264_444 = parse_rate_factor(key, value)?,
        "rate_factor_hevc_444" => cfg.rate_factor_hevc_444 = parse_rate_factor(key, value)?,
        "rate_factor_vp9_444" => cfg.rate_factor_vp9_444 = parse_rate_factor(key, value)?,
        "lanczos_min_pct" => cfg.lanczos_min_pct = parse_u32_range(key, value, 0, 100)?,
        "nvenc_spatial_aq" => cfg.nvenc_spatial_aq = parse_tribool(value)?,
        "scale_cq_boost" => cfg.scale_cq_boost = parse_u32_range(key, value, 0, 12)?,
        "idle_refine" => cfg.idle_refine = parse_tribool(value)?,
        "idle_refine_balanced" => cfg.idle_refine_balanced = parse_tribool(value)?,
        "gpu_scale" => cfg.gpu_scale = parse_tribool(value)?,
        "overlay_lan_capture_probe" => cfg.overlay_lan_capture_probe = parse_tribool(value)?,
        "relay_ceiling_learn" => cfg.relay_ceiling_learn = parse_tribool(value)?,
        "drm_capture" => cfg.drm_capture = parse_tribool(value)?,
        "uinput" => cfg.uinput = parse_tribool(value)?,
        "portal_capture" => cfg.portal_capture = parse_tribool(value)?,
        "portal_input" => cfg.portal_input = parse_tribool(value)?,
        "mutter_capture" => cfg.mutter_capture = parse_tribool(value)?,
        "window_capture" => cfg.window_capture = parse_tribool(value)?,
        "wayland_aware" => cfg.wayland_aware = parse_tribool(value)?,
        "wayland_auto" => cfg.wayland_auto = parse_tribool(value)?,
        "wayland_auto_system" => cfg.wayland_auto_system = parse_tribool(value)?,
        "x11_auto_system" => cfg.x11_auto_system = parse_tribool(value)?,
        "mutter_input" => cfg.mutter_input = parse_tribool(value)?,
        "x11_damage" => cfg.x11_damage = parse_tribool(value)?,
        "overlay_key_rotation" => cfg.overlay_key_rotation = parse_tribool(value)?,
        "idle_refine_max_edge" => cfg.idle_refine_max_edge = parse_u32_range(key, value, 0, 8192)?,
        "relay_max_hi_kbps" => cfg.relay_max_hi_kbps = parse_u32_range(key, value, 0, 100_000)?,
        "idle_refine_min_frame_kb" => {
            cfg.idle_refine_min_frame_kb = parse_u32_range(key, value, 0, 256)?
        }
        "idle_refine_major_area_permille" => {
            cfg.idle_refine_major_area_permille = parse_u32_range(key, value, 0, 1000)?
        }
        "idle_refine_settle_ms" => {
            cfg.idle_refine_settle_ms = parse_u32_range(key, value, 100, 5000)?
        }
        "idle_refine_settle_constrained_ms" => {
            cfg.idle_refine_settle_constrained_ms = parse_u32_range(key, value, 100, 10000)?
        }
        "constrained_cq_relief" => cfg.constrained_cq_relief = parse_u32_range(key, value, 0, 12)?,
        "constrained_queue_ms" => cfg.constrained_queue_ms = parse_u32_range(key, value, 0, 2000)?,
        "constrained_hrd_pct" => cfg.constrained_hrd_pct = parse_u32_range(key, value, 25, 200)?,
        "direct_queue_ms" => cfg.direct_queue_ms = parse_u32_range(key, value, 0, 2000)?,
        "direct_hrd_pct" => cfg.direct_hrd_pct = parse_u32_range(key, value, 25, 200)?,
        "area_min_bitrate" => cfg.area_min_bitrate = parse_tribool(value)?,
        "measured_ceiling" => cfg.measured_ceiling = parse_tribool(value)?,
        "encoder_inplace_rate" => cfg.encoder_inplace_rate = parse_tribool(value)?,
        "ice_relay_tcp" => cfg.ice_relay_tcp = parse_tribool(value)?,
        "relay_max_kbps" => cfg.relay_max_kbps = parse_u32_range(key, value, 100, 100_000)?,
        "rate_slow_start" => cfg.rate_slow_start = parse_tribool(value)?,
        "media_thread" => cfg.media_thread = parse_tribool(value)?,
        "pump_stall_watch" => cfg.pump_stall_watch = parse_tribool(value)?,
        "pump_stall_warn_ms" => cfg.pump_stall_warn_ms = parse_u32_range(key, value, 10, 5000)?,
        "bg_rebuild_constrained" => cfg.bg_rebuild_constrained = parse_tribool(value)?,
        "slow_link_floor" => cfg.slow_link_floor = parse_tribool(value)?,
        "slow_link_min_bitrate" => {
            cfg.slow_link_min_bitrate = parse_u32_range(key, value, 50_000, 1_500_000)?
        }
        "constrained_queue_measured" => cfg.constrained_queue_measured = parse_tribool(value)?,
        "seed_contradiction" => cfg.seed_contradiction = parse_tribool(value)?,
        "viewer_rate_clamp" => cfg.viewer_rate_clamp = parse_tribool(value)?,
        "queue_drain" => cfg.queue_drain = parse_tribool(value)?,
        "slow_link_profile" => cfg.slow_link_profile = parse_tribool(value)?,
        "slow_link_profile_bps" => {
            cfg.slow_link_profile_bps = parse_u32_range(key, value, 0, 100_000_000)?
        }
        "bg_rebuild" => cfg.bg_rebuild = parse_tribool(value)?,
        "par_convert" => cfg.par_convert = parse_tribool(value)?,
        "fps_pace" => cfg.fps_pace = parse_tribool(value)?,
        "relay_idr_thrift" => cfg.relay_idr_thrift = parse_tribool(value)?,
        "relay_age_feedback" => cfg.relay_age_feedback = parse_tribool(value)?,
        "send_stall_ms" => cfg.send_stall_ms = parse_u32_range(key, value, 0, 10_000)?,
        "priority_res_cap" => cfg.priority_res_cap = parse_tribool(value)?,
        "smoother_rate_pct" => cfg.smoother_rate_pct = parse_u32_range(key, value, 30, 100)?,
        "balanced_rate_pct" => cfg.balanced_rate_pct = parse_u32_range(key, value, 30, 100)?,
        "scale_threads" => cfg.scale_threads = parse_u32_range(key, value, 1, 8)?,
        "ice_follow_renomination" => {
            cfg.ice_follow_renomination =
                match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
                    None | Some("") | Some("auto") => None,
                    Some("always") => Some(true),
                    Some("never") => Some(false),
                    Some(other) => {
                        return Err(format!(
                            "ice_follow_renomination must be auto|always|never (got {other:?})"
                        ));
                    }
                }
        }
        "ice_warm_standby" => cfg.ice_warm_standby = parse_tribool(value)?,
        "ice_overlay_host_deprioritize" => {
            cfg.ice_overlay_host_deprioritize = parse_tribool(value)?
        }
        "overlay_tier_detect" => cfg.overlay_tier_detect = parse_tribool(value)?,
        "overlay_rtt_q" => cfg.overlay_rtt_q = parse_tribool(value)?,
        "overlay_upward_probe" => cfg.overlay_upward_probe = parse_tribool(value)?,
        "relay_probe" => cfg.relay_probe = parse_tribool(value)?,
        "text_mod_neutralize" => cfg.text_mod_neutralize = parse_tribool(value)?,
        "caps_cache" => cfg.caps_cache = parse_tribool(value)?,
        "fps_high" => cfg.fps_high = parse_tribool(value)?,
        "vaapi_device" => {
            cfg.vaapi_device = value
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        }
        "d3d12_adapter" => {
            cfg.d3d12_adapter = value
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        }
        "vulkan_device" => {
            cfg.vulkan_device = value
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        }
        "record_dir" => {
            cfg.record_dir = match value.map(str::trim).filter(|s| !s.is_empty()) {
                None => None,
                Some(v) => Some(
                    crate::recording_dir::validate_record_dir(v)?
                        .to_string_lossy()
                        .into_owned(),
                ),
            }
        }
        "encoder_cells_deny" => {
            cfg.encoder_cells_deny = match value.map(str::trim).filter(|s| !s.is_empty()) {
                None => None,
                Some(v) => {
                    validate_denylist(v)?;
                    Some(v.to_string())
                }
            }
        }
        "fps_deny" => {
            cfg.fps_deny = match value.map(str::trim).filter(|s| !s.is_empty()) {
                None => None,
                Some(v) => {
                    validate_fps_denylist(v)?;
                    Some(v.to_string())
                }
            }
        }
        "forward_acl" => {
            cfg.forward_acl = match value.map(str::trim).filter(|s| !s.is_empty()) {
                None => Default::default(),
                Some(v) => serde_json::from_str(v)
                    .map_err(|e| format!("forward_acl: invalid JSON: {e}"))?,
            }
        }
        "virtual_desktop_apps" => {
            cfg.virtual_desktop_apps = match value.map(str::trim).filter(|s| !s.is_empty()) {
                None => Default::default(),
                Some(v) => serde_json::from_str(v)
                    .map_err(|e| format!("virtual_desktop_apps: invalid JSON: {e}"))?,
            }
        }
        other => return Err(format!("unknown or non-editable config key {other:?}")),
    }
    Ok(())
}

/// P7 — shared bounded-u32 parse for the plain numeric keys: empty clears
/// (built-in applies), numeric must be within `lo..=hi`.
fn parse_u32_range(
    key: &str,
    value: Option<&str>,
    lo: u32,
    hi: u32,
) -> Result<Option<u32>, String> {
    match value.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(v) => {
            let n: u32 = v
                .parse()
                .map_err(|_| format!("{key} must be a number (got {v:?})"))?;
            if !(lo..=hi).contains(&n) {
                return Err(format!("{key} must be between {lo} and {hi}"));
            }
            Ok(Some(n))
        }
    }
}

/// FR-90 — `hive_accounts`: a JSON object of `"<user id or email>": "<account>"`.
/// Empty clears to nobody. A key must name a user the way the start frame
/// does — a 24-hex user id, or an address (`@`) — and an account must be one
/// plain local name. `root` is refused here as well as at launch: the launch
/// refuses any uid-0 account whatever its name, but a mapping to root should
/// never get as far as being saved.
fn parse_hive_accounts(
    value: Option<&str>,
) -> Result<std::collections::BTreeMap<String, String>, String> {
    let Some(v) = value.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(Default::default());
    };
    let raw: std::collections::BTreeMap<String, String> = serde_json::from_str(v).map_err(|e| {
        format!("hive_accounts: invalid JSON (want {{\"<user id or email>\": \"<account>\"}}): {e}")
    })?;
    let mut out = std::collections::BTreeMap::new();
    for (user, account) in raw {
        let user = user.trim();
        let account = account.trim();
        let is_id = user.len() == 24 && user.chars().all(|c| c.is_ascii_hexdigit());
        if !(is_id || user.contains('@')) || user.chars().any(char::is_control) {
            return Err(format!(
                "hive_accounts: {user:?} is neither a user id (24 hex) nor an email address"
            ));
        }
        if account.is_empty()
            || account.len() > 64
            || account
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || matches!(c, ':' | '/' | '\\'))
        {
            return Err(format!(
                "hive_accounts: {account:?} is not a local account name"
            ));
        }
        if account == "root" {
            return Err("hive_accounts: sessions never run as root".into());
        }
        out.insert(user.to_string(), account.to_string());
    }
    Ok(out)
}

/// A comma-separated list of absolute paths; empty clears.
fn parse_absolute_list(key: &str, value: Option<&str>) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for token in value.unwrap_or("").split(',').map(str::trim) {
        if token.is_empty() {
            continue;
        }
        if !std::path::Path::new(token).is_absolute() {
            return Err(format!("{key}: {token:?} is not an absolute path"));
        }
        out.push(token.to_string());
    }
    Ok(out)
}

/// One absolute path, or empty to clear.
fn parse_absolute_path(key: &str, value: Option<&str>) -> Result<Option<String>, String> {
    match value.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(v) if std::path::Path::new(v).is_absolute() => Ok(Some(v.to_string())),
        Some(v) => Err(format!("{key}: {v:?} is not an absolute path")),
    }
}

/// Shared parse/validate for the four `rate_factor_*` keys: empty clears
/// (built-in applies), numeric must be 50–400 %.
fn parse_rate_factor(key: &str, value: Option<&str>) -> Result<Option<u32>, String> {
    match value.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(v) => {
            let pct: u32 = v
                .parse()
                .map_err(|_| format!("{key} must be a number (got {v:?})"))?;
            if !(50..=400).contains(&pct) {
                return Err(format!("{key} must be between 50 and 400 (percent)"));
            }
            Ok(Some(pct))
        }
    }
}

/// FR-77 — `encoder_cells_deny` entries are `name:chroma` with a plain
/// FFmpeg encoder name and one of the two chroma formats, or the single word
/// `none`. Validated here so a typo cannot silently deny nothing (an entry
/// that matches no cell is inert, and the operator would read the built-in
/// list as still in force while it is not).
pub fn validate_denylist(v: &str) -> Result<(), String> {
    if v.trim().eq_ignore_ascii_case("none") {
        return Ok(());
    }
    for entry in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let Some((name, chroma)) = entry.split_once(':') else {
            return Err(format!(
                "encoder_cells_deny entry {entry:?} must be name:chroma (e.g. hevc_qsv:yuv444)"
            ));
        };
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(format!(
                "encoder_cells_deny entry {entry:?}: the encoder name must be a plain FFmpeg name (lowercase, digits, underscores)"
            ));
        }
        if !matches!(chroma, "yuv420" | "yuv444") {
            return Err(format!(
                "encoder_cells_deny entry {entry:?}: chroma must be yuv420 or yuv444"
            ));
        }
    }
    Ok(())
}

/// FR-119 P2b — `fps_deny` entries are `name:fps`: a plain FFmpeg encoder
/// name or `*`, and a rate above 60. Validated for the reason
/// `validate_denylist` is: an entry that matches nothing is inert, and the
/// operator would read it as in force. A rate at or below 60 is never granted
/// above anything, so denying it would deny nothing. The single word `none`
/// denies nothing on purpose: it is how a remote push says so, where a blank
/// box hands the key back to the device.
pub fn validate_fps_denylist(v: &str) -> Result<(), String> {
    if v.trim().eq_ignore_ascii_case("none") {
        return Ok(());
    }
    for entry in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let Some((name, fps)) = entry.split_once(':') else {
            return Err(format!(
                "fps_deny entry {entry:?} must be name:fps (e.g. hevc_qsv:120, or *:144 for every encoder)"
            ));
        };
        if name != "*"
            && (name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'))
        {
            return Err(format!(
                "fps_deny entry {entry:?}: the encoder must be a plain FFmpeg name (lowercase, digits, underscores) or *"
            ));
        }
        match fps.parse::<u32>() {
            Ok(f) if f > 60 => {}
            _ => {
                return Err(format!(
                    "fps_deny entry {entry:?}: the rate must be a whole number above 60 (only those are ever granted)"
                ));
            }
        }
    }
    Ok(())
}

fn fmt_bool(b: bool) -> String {
    if b { "true" } else { "false" }.to_string()
}

/// `"true"/"1"/"yes"/"on"` → true; `"false"/"0"/"no"/"off"` → false
/// (case-insensitive). Anything else is an error.
fn parse_bool(v: &str) -> Result<bool, String> {
    match v.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        other => Err(format!("expected true/false (got {other:?})")),
    }
}

/// Plain-bool keys: `None`/empty clears back to the serde default.
fn parse_bool_or(v: Option<&str>, default: bool) -> Result<bool, String> {
    match v.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(default),
        Some(v) => parse_bool(v),
    }
}

/// FR-101 P2b — how an `rc_*` key prints: the word the file and the wire use.
fn fmt_lock_on_end(p: roomler_ai_remote_control::models::LockOnEnd) -> String {
    use roomler_ai_remote_control::models::LockOnEnd;
    match p {
        LockOnEnd::Never => "never",
        LockOnEnd::Auto => "auto",
        LockOnEnd::Always => "always",
    }
    .to_string()
}

/// FR-99 P3 — `lock_on_end` as a person sets it: `never`, `auto` or `always`,
/// in any case; cleared is `never`, the default. Anything else is refused,
/// where the file's reader would have read it as `always` without a word.
fn parse_lock_on_end(
    v: Option<&str>,
) -> Result<roomler_ai_remote_control::models::LockOnEnd, String> {
    use roomler_ai_remote_control::models::LockOnEnd;
    match v
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        None | Some("never") => Ok(LockOnEnd::Never),
        Some("auto") => Ok(LockOnEnd::Auto),
        Some("always") => Ok(LockOnEnd::Always),
        Some(_) => Err("lock_on_end must be never | auto | always".to_string()),
    }
}

fn fmt_display_match(p: crate::config::DisplayMatchPolicy) -> String {
    use crate::config::DisplayMatchPolicy;
    match p {
        DisplayMatchPolicy::Auto => "auto",
        DisplayMatchPolicy::Always => "always",
        DisplayMatchPolicy::Never => "never",
    }
    .to_string()
}

/// FR-108 — `display_match` as a person sets it: `auto`, `always` or `never`,
/// in any case; cleared is `auto`, the default. Anything else is refused,
/// where the file's reader would have read it as `never` without a word.
fn parse_display_match(v: Option<&str>) -> Result<crate::config::DisplayMatchPolicy, String> {
    use crate::config::DisplayMatchPolicy;
    match v
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        None | Some("auto") => Ok(DisplayMatchPolicy::Auto),
        Some("always") => Ok(DisplayMatchPolicy::Always),
        Some("never") => Ok(DisplayMatchPolicy::Never),
        Some(_) => Err("display_match must be auto | always | never".to_string()),
    }
}

fn fmt_peer_auth(p: crate::config::PeerAuthPolicy) -> String {
    use crate::config::PeerAuthPolicy;
    match p {
        PeerAuthPolicy::Off => "off",
        PeerAuthPolicy::Audit => "audit",
    }
    .to_string()
}

/// FR-100 P1c — `peer_auth` as a person sets it: `off` or `audit`, in any case;
/// cleared is `audit`, the default. `enforce` is refused by name until P3
/// brings the controller keys and the prompts it needs: before them it would
/// refuse every session to this device, which is a self-wedge, not a setting.
/// Anything else is refused, where the file's reader would have read it as
/// `audit` without a word.
fn parse_peer_auth(v: Option<&str>) -> Result<crate::config::PeerAuthPolicy, String> {
    use crate::config::PeerAuthPolicy;
    match v
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        None | Some("audit") => Ok(PeerAuthPolicy::Audit),
        Some("off") => Ok(PeerAuthPolicy::Off),
        Some("enforce") => Err(
            "peer_auth = enforce arrives with FR-100 P3; until then this device can check and \
             record the browsers that connect (audit) or not check them (off)"
                .to_string(),
        ),
        Some(_) => Err("peer_auth must be off | audit".to_string()),
    }
}

fn fmt_feature_policy(p: roomler_ai_remote_control::models::FeaturePolicy) -> String {
    use roomler_ai_remote_control::models::FeaturePolicy;
    match p {
        FeaturePolicy::On => "on",
        FeaturePolicy::Ask => "ask",
        FeaturePolicy::Off => "off",
    }
    .to_string()
}

/// FR-101 P2b — an `rc_*` key as a person sets it: `on`, `ask` or `off`, in
/// any case; cleared is `on`, the default. Anything else is refused, where
/// the file's reader would have read it as `off` without a word.
fn parse_feature_policy(
    key: &str,
    v: Option<&str>,
) -> Result<roomler_ai_remote_control::models::FeaturePolicy, String> {
    use roomler_ai_remote_control::models::FeaturePolicy;
    match v
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        None | Some("on") => Ok(FeaturePolicy::On),
        Some("ask") => Ok(FeaturePolicy::Ask),
        Some("off") => Ok(FeaturePolicy::Off),
        Some(_) => Err(format!("{key} must be on | ask | off")),
    }
}

/// Tri-state keys: `None`/empty = unset (built-in default applies).
fn parse_tribool(v: Option<&str>) -> Result<Option<bool>, String> {
    match v.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(v) => parse_bool(v).map(Some),
    }
}

/// S2 wizard — validate a comma-separated CIDR list WITHOUT a config
/// (the setup wizard checks route inputs before the MSI runs and the
/// single-use enrollment token is burned). Same parser [`apply`] uses,
/// so a value that validates here can't fail there.
pub fn validate_cidr_list(v: &str) -> Result<(), String> {
    parse_cidr_list(Some(v)).map(|_| ())
}

/// Comma-separated CIDR list; each token must be `addr/prefix` with a
/// prefix that fits the address family. `None`/empty clears the list.
fn parse_cidr_list(v: Option<&str>) -> Result<Vec<String>, String> {
    let Some(v) = v else { return Ok(Vec::new()) };
    let mut out = Vec::new();
    for token in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (addr, prefix) = token
            .split_once('/')
            .ok_or_else(|| format!("{token:?} is not CIDR notation (addr/prefix)"))?;
        let ip: std::net::IpAddr = addr
            .trim()
            .parse()
            .map_err(|_| format!("{token:?}: bad IP address"))?;
        let bits: u8 = prefix
            .trim()
            .parse()
            .map_err(|_| format!("{token:?}: bad prefix length"))?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        if bits > max {
            return Err(format!("{token:?}: prefix /{bits} exceeds /{max}"));
        }
        out.push(token.to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_key_gets_and_applies() {
        let mut cfg = crate::config::test_fixture();
        let all = entries(&cfg);
        assert_eq!(all.len(), KEYS.len());
        // Every listed key roundtrips through entry_for + a no-op apply
        // of its own current value (or a clear for unset optionals).
        // (`restart_required` per key is `live_keys_are_exactly_the_adopt_local_set`.)
        for e in &all {
            assert!(!e.description.is_empty());
            apply(&mut cfg, &e.key, e.value.as_deref()).expect("self-value apply");
            let echoed = entry_for(&cfg, &e.key).expect("known key");
            assert_eq!(echoed.value, e.value, "roundtrip for {}", e.key);
        }
    }

    /// FR-84 D2 — `restart_required` is the truth PER KEY, not a blanket.
    /// The keys the daemon applies without a restart are the two gate-4
    /// flags `RemoteConfigServices::adopt_local` re-seeds after a
    /// `ConfigSet` (agents/roomlerd/src/localapi_state.rs), `record_dir`
    /// (FR-85), which the recorder's supervisor reads fresh when a recording
    /// starts (`recording/manager.rs`, `configured_dir`),
    /// `local_restart_enabled` (FR-84 D3), which the restart verb reads fresh
    /// on every request (`localapi_state.rs`, `restart_daemon`),
    /// `files_dir` (FR-84 D4), which the same `ConfigSet` hands to
    /// `files::set_files_dir` and every drop re-reads, and the two remote
    /// recording gates, re-seeded after a `ConfigSet` the same way as the
    /// gate-4 flags (`recording/remote.rs`, `adopt`). A key wrongly
    /// claiming `live` tells a person their change is in force while the
    /// daemon still runs the old value; a live key claiming `restart` has
    /// them bounce a healthy service — or believe a refusal they just made
    /// is not yet in force. Red on the pre-D2 surface, which reported
    /// `restart_required = true` for every key and left the desktop and
    /// the CLI each keeping the live list by hand.
    #[test]
    fn live_keys_are_exactly_the_adopt_local_set() {
        let cfg = crate::config::test_fixture();
        let live: std::collections::BTreeSet<String> = entries(&cfg)
            .into_iter()
            .filter(|e| !e.restart_required)
            .map(|e| e.key)
            .collect();
        let expected: std::collections::BTreeSet<String> = [
            "exec_enabled",
            "remote_config_enabled",
            "record_dir",
            "local_restart_enabled",
            "files_dir",
            "record_remote_enabled",
            "record_remote_audio",
            "keep_busy_enabled",
            "privacy_mode_allowed",
            "rc_clipboard",
            "rc_files",
            "rc_audio",
            "lock_on_end",
            "display_match",
            // FR-100 P1c — re-seeded by `adopt_local`; every offer reads it.
            "peer_auth",
            // FR-52 — read at use: from the config FILE at every knock and
            // every external session request, so nothing re-seeds them.
            "external_access_enabled",
            "external_consent_mode",
            "external_max_permissions",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        assert_eq!(
            live, expected,
            "the live set is exactly what adopt_local re-seeds, plus the keys read at use"
        );
        // The post-apply echo says the same thing as the listing.
        for key in &expected {
            assert!(
                !entry_for(&cfg, key).expect("known key").restart_required,
                "{key} must echo live"
            );
        }
        assert!(entry_for(&cfg, "overlay_enabled").unwrap().restart_required);
        assert!(entry_for(&cfg, "ssh_enabled").unwrap().restart_required);
    }

    /// FR-84 D4 — `files_dir` is LIVE: the daemon's `ConfigSet` re-seeds the
    /// drop folder and every drop re-validates it, so a restart prompt
    /// would send a person bouncing a healthy service for nothing. Red
    /// with `live: false` on the row.
    #[test]
    fn files_dir_is_live() {
        let cfg = crate::config::test_fixture();
        let e = entry_for(&cfg, "files_dir").expect("files_dir is on the surface");
        assert!(!e.restart_required, "files_dir applies at once");
        assert_eq!(e.group, Group::Files.wire());
        assert_eq!(e.tier, Tier::Essential.wire());
        assert_eq!(e.kind, "string");
        assert_eq!(e.value, None, "unset by default — the Downloads ladder");
        assert_eq!(e.default, None);
    }

    /// FR-52 — the external-access keys are LIVE: the daemon reads them from
    /// the FILE at every knock and every external session request, so `config
    /// set external_access_enabled false` — an owner shutting outsiders out —
    /// is in force at once. Reporting a restart there told that owner a
    /// revocation was not in force yet, inviting a restart of a healthy daemon
    /// or the belief they were still exposed. Red with `live: false` on a row.
    #[test]
    fn the_external_access_keys_are_live() {
        let cfg = crate::config::test_fixture();
        for key in [
            "external_access_enabled",
            "external_consent_mode",
            "external_max_permissions",
        ] {
            let e = entry_for(&cfg, key).expect("on the surface");
            assert!(!e.restart_required, "{key} applies at once");
        }
    }

    /// FR-84 D4 — the surface checks the SHAPE of `files_dir` (absolute or
    /// `~/…`, no device paths, no `..`, no system roots) and nothing more:
    /// placement against the writer's identity and writability are the
    /// daemon's, which has the identity and the disk. A clear goes back to
    /// the built-in ladder.
    #[test]
    fn files_dir_set_echo_clear_and_shape_validate() {
        let mut cfg = crate::config::test_fixture();
        assert_eq!(current_value(&cfg, "files_dir"), None);
        let good = if cfg!(windows) {
            r"D:\Drops\in"
        } else {
            "/srv/drops"
        };
        apply(&mut cfg, "files_dir", Some(&format!("  {good}  "))).unwrap();
        assert_eq!(
            cfg.files_dir.as_deref(),
            Some(good),
            "trimmed, stored as spelled"
        );
        assert_eq!(
            entry_for(&cfg, "files_dir").unwrap().value.as_deref(),
            Some(good)
        );
        // `~/…` is a shape the surface accepts without knowing whose home —
        // the daemon expands it per user at the time of the drop.
        apply(&mut cfg, "files_dir", Some("~/Drops")).unwrap();
        assert_eq!(cfg.files_dir.as_deref(), Some("~/Drops"));
        // Clearing, by null or by blank.
        apply(&mut cfg, "files_dir", None).unwrap();
        assert_eq!(cfg.files_dir, None);
        apply(&mut cfg, "files_dir", Some("~/Drops")).unwrap();
        apply(&mut cfg, "files_dir", Some("   ")).unwrap();
        assert_eq!(cfg.files_dir, None, "blank clears to the built-in ladder");
        // Refusals leave the stored value untouched.
        apply(&mut cfg, "files_dir", Some("~/Drops")).unwrap();
        let system_dir = if cfg!(windows) {
            r"C:\Windows\Temp"
        } else {
            "/etc/roomler"
        };
        for bad in [
            "drops",
            "~/../x",
            r"\\?\GLOBALROOT\Device\HarddiskVolume1\x",
            "~user/x",
            system_dir,
        ] {
            let err = apply(&mut cfg, "files_dir", Some(bad)).unwrap_err();
            assert!(err.contains("files_dir"), "{bad:?}: {err}");
            assert_eq!(
                cfg.files_dir.as_deref(),
                Some("~/Drops"),
                "{bad:?} must not land"
            );
        }
    }

    /// FR-84 D2 — the compiler already forces a `Group` and a `Tier` on
    /// every row; this locks the CONTENT of the classification that the
    /// Settings page shows open by default, and that the wire carries
    /// exactly what the table says.
    #[test]
    fn every_key_is_classified_and_essentials_are_the_named_set() {
        use std::collections::BTreeSet;
        let mut seen = BTreeSet::new();
        for m in KEYS {
            assert!(seen.insert(m.key), "duplicate registry key {}", m.key);
        }
        for g in Group::ALL {
            assert!(
                KEYS.iter().any(|m| m.group == g),
                "group {g:?} has no key — an empty section on screen"
            );
        }
        let essentials: BTreeSet<&str> = KEYS
            .iter()
            .filter(|m| m.tier == Tier::Essential)
            .map(|m| m.key)
            .collect();
        let named: BTreeSet<&str> = [
            "overlay_enabled",
            "auto_grant_session",
            "exec_enabled",
            "remote_config_enabled",
            "ssh_enabled",
            "hive_enabled",
            "encoder_preference",
            "files_dir",
            "power_policy",
            "auto_update",
        ]
        .into_iter()
        .collect();
        assert_eq!(essentials, named);

        // The wire carries the table, for every key.
        let cfg = crate::config::test_fixture();
        for m in KEYS {
            let e = entry_for(&cfg, m.key).expect("known key");
            assert_eq!(e.group, m.group.wire(), "{}", m.key);
            assert_eq!(e.group_label, m.group.label(), "{}", m.key);
            assert_eq!(e.tier, m.tier.wire(), "{}", m.key);
            assert_eq!(e.restart_required, !m.live, "{}", m.key);
            assert!(!e.group.is_empty() && !e.tier.is_empty(), "{}", m.key);
        }

        // `entries()` is display order: grouped by `Group::ALL`, registry
        // order inside a group — so a client needs no order table.
        let all = entries(&cfg);
        assert_eq!(all.len(), KEYS.len());
        let order = |e: &ConfigEntry| {
            Group::ALL
                .iter()
                .position(|g| g.wire() == e.group)
                .unwrap_or_else(|| panic!("unknown group id {:?}", e.group))
        };
        for w in all.windows(2) {
            assert!(
                order(&w[0]) <= order(&w[1]),
                "{} ({}) listed after {} ({})",
                w[1].key,
                w[1].group,
                w[0].key,
                w[0].group
            );
            if w[0].group == w[1].group {
                let pos = |k: &str| KEYS.iter().position(|m| m.key == k).unwrap();
                assert!(
                    pos(&w[0].key) < pos(&w[1].key),
                    "registry order within a group"
                );
            }
        }
        // And every editor kind still meets the `ConfigEntry::kind` contract
        // (the desktop switches on these; `power_policy` used to be a bare
        // `a|b|c` that rendered as free text).
        for m in KEYS {
            assert!(
                matches!(
                    m.kind,
                    "bool" | "tribool" | "string" | "list" | "json" | "number"
                ) || m.kind.starts_with("enum:"),
                "{} has an unknown editor kind {:?}",
                m.key,
                m.kind
            );
        }
    }

    /// FR-84 D2 — the wire ids and labels are a compatibility surface: a
    /// renamed id lands every key of that group in "unknown" on an older
    /// desktop, a renamed label is a silent UI change. Spell them out.
    /// FR-85 — the surface's first path-valued key: set, echo, validate,
    /// clear. A refused path leaves the previous value in place.
    #[test]
    fn record_dir_set_echo_clear_and_validate() {
        let mut cfg = crate::config::test_fixture();
        assert_eq!(current_value(&cfg, "record_dir"), None);
        let dir = std::env::temp_dir()
            .join("roomler-fr85-surface")
            .join("Recordings");
        let raw = format!("  {}  ", dir.display());
        apply(&mut cfg, "record_dir", Some(&raw)).unwrap();
        assert_eq!(
            cfg.record_dir.as_deref(),
            Some(dir.to_string_lossy().as_ref())
        );
        assert_eq!(
            entry_for(&cfg, "record_dir").unwrap().value.as_deref(),
            Some(dir.to_string_lossy().as_ref())
        );
        for bad in [
            "relative/rec",
            "~/Videos",
            r"\\nas\share\rec",
            r"\\?\C:\rec",
        ] {
            let err = apply(&mut cfg, "record_dir", Some(bad)).unwrap_err();
            assert!(err.starts_with("record_dir:"), "{bad}: {err}");
        }
        assert_eq!(
            cfg.record_dir.as_deref(),
            Some(dir.to_string_lossy().as_ref())
        );
        apply(&mut cfg, "record_dir", Some("   ")).unwrap();
        assert_eq!(cfg.record_dir, None, "blank clears to the default folder");
    }

    #[test]
    fn group_wire_ids_are_stable() {
        let ids: Vec<&str> = Group::ALL.iter().map(|g| g.wire()).collect();
        assert_eq!(
            ids,
            [
                "access",
                "network",
                "network_carriers",
                "network_routing",
                "tunnels",
                "ssh",
                "remote_desktop",
                "capture_input",
                "video_encoding",
                "video_rate",
                "files",
                "device",
            ]
        );
        let labels: Vec<&str> = Group::ALL.iter().map(|g| g.label()).collect();
        assert_eq!(
            labels,
            [
                "Access & consent",
                "Private network",
                "Network carriers & relays",
                "Routing & adapter (Windows)",
                "Tunnels & SOCKS",
                "Roomler SSH",
                "Remote desktop",
                "Capture & input",
                "Video encoding",
                "Video rate & latency",
                "Files",
                "Device & service",
            ]
        );
        // ALL is the order() ranking, one-to-one.
        for (i, g) in Group::ALL.iter().enumerate() {
            assert_eq!(g.order(), i, "{g:?}");
        }
        assert_eq!(
            [
                Tier::Essential.wire(),
                Tier::Standard.wire(),
                Tier::Advanced.wire()
            ],
            ["essential", "standard", "advanced"]
        );
    }

    /// FR-84 D2 — `ConfigEntry::default` is what the desktop compares a
    /// value against to say "modified", so it has to be what CLEARING the
    /// key yields — for every key, including the ones whose clear is not
    /// the serde default's obvious spelling (`power_policy` renders `never`
    /// for an empty string, the JSON keys render their struct default).
    #[test]
    fn wire_default_is_what_clearing_yields() {
        let mut cfg = crate::config::test_fixture();
        for m in KEYS {
            apply(&mut cfg, m.key, None).unwrap_or_else(|e| panic!("clear {}: {e}", m.key));
            let e = entry_for(&cfg, m.key).expect("known key");
            assert_eq!(
                e.default, e.value,
                "{}: the wire default must equal a cleared value",
                m.key
            );
        }
        // A set value is NOT the default (the chip has something to say).
        apply(&mut cfg, "overlay_enabled", Some("true")).unwrap();
        let e = entry_for(&cfg, "overlay_enabled").unwrap();
        assert_eq!(e.default.as_deref(), Some("false"));
        assert_eq!(e.value.as_deref(), Some("true"));
        // Tribools are unset by default: no `default` on the wire, and the
        // value alone says "modified".
        let e = entry_for(&cfg, "overlay_quic").unwrap();
        assert_eq!(e.default, None);
    }

    #[test]
    fn tribool_set_and_clear() {
        let mut cfg = crate::config::test_fixture();
        apply(&mut cfg, "overlay_quic", Some("on")).unwrap();
        assert_eq!(cfg.overlay_quic, Some(true));
        assert_eq!(
            entry_for(&cfg, "overlay_quic").unwrap().value.as_deref(),
            Some("true")
        );
        apply(&mut cfg, "overlay_quic", Some("0")).unwrap();
        assert_eq!(cfg.overlay_quic, Some(false));
        apply(&mut cfg, "overlay_quic", None).unwrap();
        assert_eq!(cfg.overlay_quic, None);
        assert!(apply(&mut cfg, "overlay_quic", Some("maybe")).is_err());
    }

    /// FR-36 — the DRM-capture / uinput pair, set/echo/clear (per the
    /// every-new-env-gets-a-config-key rule; both shipped as env-only first
    /// and this closes that gap).
    ///
    /// ⚠️ The property worth locking is that **unset means OFF for both**, and
    /// that unset is distinguishable from an explicit `false`. Both switch on
    /// behaviour a host must opt into: DRM capture carries no damage
    /// information (turning it on where X11 works costs the FR-29 idle-CPU
    /// win), and a uinput device is host-global, injecting into whatever has
    /// focus — including the greeter and the lock screen.
    #[test]
    fn fr36_drm_capture_and_uinput_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        assert_eq!(cfg.drm_capture, None, "unset by default");
        assert_eq!(cfg.uinput, None, "unset by default");

        for key in [
            "drm_capture",
            "uinput",
            "x11_damage",
            "portal_capture",
            "portal_input",
            "mutter_capture",
            "window_capture",
            "wayland_aware",
            "wayland_auto",
            "wayland_auto_system",
            "x11_auto_system",
            "mutter_input",
        ] {
            apply(&mut cfg, key, Some("on")).unwrap();
            assert_eq!(
                entry_for(&cfg, key).unwrap().value.as_deref(),
                Some("true"),
                "{key} echoes what was set"
            );
            apply(&mut cfg, key, Some("off")).unwrap();
            assert_eq!(
                entry_for(&cfg, key).unwrap().value.as_deref(),
                Some("false")
            );
            apply(&mut cfg, key, None).unwrap();
            assert_eq!(
                entry_for(&cfg, key).unwrap().value,
                None,
                "{key} clears back to unset, which is NOT the same as false"
            );
            assert!(apply(&mut cfg, key, Some("sometimes")).is_err());
        }
        assert_eq!(cfg.drm_capture, None);
        assert_eq!(cfg.uinput, None);
    }

    /// The bridge is what makes a config key reach the backend at all — the
    /// gates read `ROOMLERD_*` via `env::flag`, and `main.rs` feeds those
    /// fallbacks from this array. A key that is absent here is editable and
    /// inert, which looks exactly like a broken feature.
    #[test]
    fn fr36_keys_are_wired_into_the_env_bridge() {
        let mut cfg = crate::config::test_fixture();
        cfg.drm_capture = Some(true);
        cfg.uinput = Some(true);
        cfg.x11_damage = Some(false);
        cfg.portal_capture = Some(true);
        cfg.portal_input = Some(false);
        cfg.mutter_capture = Some(true);
        cfg.window_capture = Some(true);
        // FR-93 — default ON, so the direction worth bridging is the kill switch.
        cfg.wayland_aware = Some(false);
        // FR-93 P2 — default ON too: the kill switch is what must reach it.
        cfg.wayland_auto = Some(false);
        // FR-93 P4 — the same shape.
        cfg.mutter_input = Some(false);
        let bridged = crate::config::env_bridge_bools(&cfg);
        for (name, want) in [
            ("DRM_CAPTURE", Some(true)),
            ("UINPUT", Some(true)),
            ("X11_DAMAGE", Some(false)),
            ("PORTAL_CAPTURE", Some(true)),
            ("PORTAL_INPUT", Some(false)),
            ("MUTTER_CAPTURE", Some(true)),
            ("WINDOW_CAPTURE", Some(true)),
            ("WAYLAND_AWARE", Some(false)),
            ("WAYLAND_AUTO", Some(false)),
            ("MUTTER_INPUT", Some(false)),
        ] {
            let got = bridged
                .iter()
                .find(|(k, _)| *k == name)
                .unwrap_or_else(|| panic!("{name} missing from env_bridge_bools"));
            assert_eq!(got.1, want, "{name} bridges the configured value");
        }
    }

    /// rc.276 — the forced-TLS-relay probe key set/echo/clear (per the
    /// every-new-env-gets-a-config-key rule).
    #[test]
    fn overlay_relay_tls_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        apply(&mut cfg, "overlay_relay_tls", Some("on")).unwrap();
        assert_eq!(cfg.overlay_relay_tls, Some(true));
        assert_eq!(
            entry_for(&cfg, "overlay_relay_tls")
                .unwrap()
                .value
                .as_deref(),
            Some("true")
        );
        apply(&mut cfg, "overlay_relay_tls", Some("0")).unwrap();
        assert_eq!(cfg.overlay_relay_tls, Some(false));
        apply(&mut cfg, "overlay_relay_tls", None).unwrap();
        assert_eq!(cfg.overlay_relay_tls, None);
        assert!(apply(&mut cfg, "overlay_relay_tls", Some("maybe")).is_err());
    }

    /// FR-99 P3 — `lock_on_end` takes its three words in any case, echoes them,
    /// clears to `never`, and refuses anything else (the file's reader would
    /// read it as `always` without a word).
    #[test]
    fn lock_on_end_set_echo_clear() {
        use roomler_ai_remote_control::models::LockOnEnd;
        let mut cfg = crate::config::test_fixture();
        assert_eq!(cfg.lock_on_end, LockOnEnd::Never);
        apply(&mut cfg, "lock_on_end", Some(" AUTO ")).unwrap();
        assert_eq!(cfg.lock_on_end, LockOnEnd::Auto);
        assert_eq!(
            entry_for(&cfg, "lock_on_end").unwrap().value.as_deref(),
            Some("auto")
        );
        apply(&mut cfg, "lock_on_end", Some("always")).unwrap();
        assert_eq!(cfg.lock_on_end, LockOnEnd::Always);
        apply(&mut cfg, "lock_on_end", None).unwrap();
        assert_eq!(cfg.lock_on_end, LockOnEnd::Never);
        assert!(apply(&mut cfg, "lock_on_end", Some("sometimes")).is_err());
        assert_eq!(
            cfg.lock_on_end,
            LockOnEnd::Never,
            "a refused value changes nothing"
        );
    }

    /// FR-108 — `display_match` takes its three words in any case, echoes them,
    /// clears to `auto`, and refuses anything else (the file's reader would read
    /// it as `never` without a word).
    #[test]
    fn display_match_set_echo_clear() {
        use crate::config::DisplayMatchPolicy;
        let mut cfg = crate::config::test_fixture();
        assert_eq!(cfg.display_match, DisplayMatchPolicy::Auto);
        apply(&mut cfg, "display_match", Some(" NEVER ")).unwrap();
        assert_eq!(cfg.display_match, DisplayMatchPolicy::Never);
        assert_eq!(
            entry_for(&cfg, "display_match").unwrap().value.as_deref(),
            Some("never")
        );
        apply(&mut cfg, "display_match", Some("always")).unwrap();
        assert_eq!(cfg.display_match, DisplayMatchPolicy::Always);
        apply(&mut cfg, "display_match", None).unwrap();
        assert_eq!(cfg.display_match, DisplayMatchPolicy::Auto);
        assert!(apply(&mut cfg, "display_match", Some("sometimes")).is_err());
        assert_eq!(
            cfg.display_match,
            DisplayMatchPolicy::Auto,
            "a refused value changes nothing"
        );
    }

    /// FR-108 — a value in the file that this build does not know reads as
    /// `never` (leave the screen alone), and never fails the file.
    #[test]
    fn display_match_reads_an_unknown_value_as_never() {
        use crate::config::DisplayMatchPolicy;
        #[derive(serde::Deserialize)]
        struct One {
            display_match: DisplayMatchPolicy,
        }
        for (text, want) in [
            ("display_match = \"auto\"", DisplayMatchPolicy::Auto),
            ("display_match = \"always\"", DisplayMatchPolicy::Always),
            ("display_match = \"never\"", DisplayMatchPolicy::Never),
            ("display_match = \"when-idle\"", DisplayMatchPolicy::Never),
            ("display_match = 1", DisplayMatchPolicy::Never),
        ] {
            let got: One = toml::from_str(text).expect(text);
            assert_eq!(got.display_match, want, "{text}");
        }
    }

    /// FR-100 P1c — `peer_auth` takes `off` and `audit` in any case, echoes
    /// them and clears to `audit`. `enforce` is refused BY NAME until P3 (before
    /// the controller keys and the prompts exist it would refuse every session
    /// to this device), and anything else is refused too; a refusal changes
    /// nothing.
    #[test]
    fn peer_auth_set_echo_clear_and_no_enforce_yet() {
        use crate::config::PeerAuthPolicy;
        let mut cfg = crate::config::test_fixture();
        assert_eq!(cfg.peer_auth, PeerAuthPolicy::Audit);
        apply(&mut cfg, "peer_auth", Some(" OFF ")).unwrap();
        assert_eq!(cfg.peer_auth, PeerAuthPolicy::Off);
        assert_eq!(
            entry_for(&cfg, "peer_auth").unwrap().value.as_deref(),
            Some("off")
        );
        apply(&mut cfg, "peer_auth", None).unwrap();
        assert_eq!(cfg.peer_auth, PeerAuthPolicy::Audit);
        let refused = apply(&mut cfg, "peer_auth", Some("enforce")).unwrap_err();
        assert!(refused.contains("P3"), "the refusal says when: {refused}");
        assert!(apply(&mut cfg, "peer_auth", Some("strict")).is_err());
        assert_eq!(
            cfg.peer_auth,
            PeerAuthPolicy::Audit,
            "a refused value changes nothing"
        );
    }

    /// FR-100 P1c — a value in the file that this build does not know (a newer
    /// build's `enforce`) reads as `audit`: keep checking, refuse nothing this
    /// build cannot enforce, and never fail the file.
    #[test]
    fn peer_auth_reads_an_unknown_value_as_audit() {
        use crate::config::PeerAuthPolicy;
        #[derive(serde::Deserialize)]
        struct One {
            peer_auth: PeerAuthPolicy,
        }
        for (text, want) in [
            ("peer_auth = \"off\"", PeerAuthPolicy::Off),
            ("peer_auth = \"audit\"", PeerAuthPolicy::Audit),
            ("peer_auth = \"enforce\"", PeerAuthPolicy::Audit),
            ("peer_auth = \"OFF\"", PeerAuthPolicy::Audit),
            ("peer_auth = 0", PeerAuthPolicy::Audit),
        ] {
            let got: One = toml::from_str(text).expect(text);
            assert_eq!(got.peer_auth, want, "{text}");
        }
    }

    /// Multi-org v2 shared-carrier soak flag set/echo/clear (per the
    /// every-new-env-gets-a-config-key rule).
    #[test]
    fn overlay_shared_carrier_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        apply(&mut cfg, "overlay_shared_carrier", Some("on")).unwrap();
        assert_eq!(cfg.overlay_shared_carrier, Some(true));
        assert_eq!(
            entry_for(&cfg, "overlay_shared_carrier")
                .unwrap()
                .value
                .as_deref(),
            Some("true")
        );
        apply(&mut cfg, "overlay_shared_carrier", Some("0")).unwrap();
        assert_eq!(cfg.overlay_shared_carrier, Some(false));
        apply(&mut cfg, "overlay_shared_carrier", None).unwrap();
        assert_eq!(cfg.overlay_shared_carrier, None);
        assert!(apply(&mut cfg, "overlay_shared_carrier", Some("maybe")).is_err());
    }

    /// A3 — WG-style roaming kill switch set/echo/clear (per the
    /// every-new-env-gets-a-config-key rule).
    #[test]
    fn overlay_roam_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        apply(&mut cfg, "overlay_roam", Some("off")).unwrap();
        assert_eq!(cfg.overlay_roam, Some(false));
        assert_eq!(
            entry_for(&cfg, "overlay_roam").unwrap().value.as_deref(),
            Some("false")
        );
        apply(&mut cfg, "overlay_roam", Some("1")).unwrap();
        assert_eq!(cfg.overlay_roam, Some(true));
        apply(&mut cfg, "overlay_roam", None).unwrap();
        assert_eq!(cfg.overlay_roam, None);
        assert!(apply(&mut cfg, "overlay_roam", Some("maybe")).is_err());
    }

    /// B4 — plane-watchdog kill switch set/echo/clear (per the
    /// every-new-env-gets-a-config-key rule).
    #[test]
    fn overlay_plane_watchdog_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        apply(&mut cfg, "overlay_plane_watchdog", Some("off")).unwrap();
        assert_eq!(cfg.overlay_plane_watchdog, Some(false));
        assert_eq!(
            entry_for(&cfg, "overlay_plane_watchdog")
                .unwrap()
                .value
                .as_deref(),
            Some("false")
        );
        apply(&mut cfg, "overlay_plane_watchdog", Some("1")).unwrap();
        assert_eq!(cfg.overlay_plane_watchdog, Some(true));
        apply(&mut cfg, "overlay_plane_watchdog", None).unwrap();
        assert_eq!(cfg.overlay_plane_watchdog, None);
        assert!(apply(&mut cfg, "overlay_plane_watchdog", Some("maybe")).is_err());
    }

    /// C1 — the disco responder kill switch set/echo/clear (per the
    /// every-new-env-gets-a-config-key rule).
    #[test]
    fn overlay_disco_probe_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        apply(&mut cfg, "overlay_disco_probe", Some("on")).unwrap();
        assert_eq!(cfg.overlay_disco_probe, Some(true));
        apply(&mut cfg, "overlay_disco_probe", None).unwrap();
        assert_eq!(cfg.overlay_disco_probe, None);
        assert!(apply(&mut cfg, "overlay_disco_probe", Some("maybe")).is_err());
    }

    #[test]
    fn overlay_disco_respond_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        apply(&mut cfg, "overlay_disco_respond", Some("off")).unwrap();
        assert_eq!(cfg.overlay_disco_respond, Some(false));
        apply(&mut cfg, "overlay_disco_respond", None).unwrap();
        assert_eq!(cfg.overlay_disco_respond, None);
        assert!(apply(&mut cfg, "overlay_disco_respond", Some("maybe")).is_err());
    }

    /// Diagnostic session-trace kill switch set/echo/clear (per the
    /// every-new-env-gets-a-config-key rule).
    #[test]
    fn overlay_session_trace_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        apply(&mut cfg, "overlay_session_trace", Some("on")).unwrap();
        assert_eq!(cfg.overlay_session_trace, Some(true));
        apply(&mut cfg, "overlay_session_trace", None).unwrap();
        assert_eq!(cfg.overlay_session_trace, None);
        assert!(apply(&mut cfg, "overlay_session_trace", Some("maybe")).is_err());
    }

    /// The WSL2 mirrored-networking guard key set/echo/clear (per the
    /// every-new-env-gets-a-config-key rule). The kill switch matters here:
    /// the guard SUPPRESSES a guest's whole LAN gather, so a misdetection
    /// must be recoverable with `roomler config set …` and no rebuild.
    #[test]
    fn overlay_wsl_mirrored_guard_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        apply(&mut cfg, "overlay_wsl_mirrored_guard", Some("off")).unwrap();
        assert_eq!(cfg.overlay_wsl_mirrored_guard, Some(false));
        assert_eq!(
            entry_for(&cfg, "overlay_wsl_mirrored_guard")
                .unwrap()
                .value
                .as_deref(),
            Some("false")
        );
        apply(&mut cfg, "overlay_wsl_mirrored_guard", None).unwrap();
        assert_eq!(
            cfg.overlay_wsl_mirrored_guard, None,
            "clear → built-in default"
        );
        // The env bridge must carry it, or `config set` writes TOML the daemon
        // silently ignores — the exact failure the bridge test guards against.
        assert!(
            crate::config::env_bridge_bools(&cfg)
                .iter()
                .any(|(k, _)| *k == "OVERLAY_WSL_MIRRORED_GUARD"),
            "key must be bridged to the daemon's env"
        );
    }

    /// The srflx SEEKING key set/echo/clear (per the
    /// every-new-env-gets-a-config-key rule). This is the kill switch for
    /// the W5 self-healing NONE-regather; off restores the pre-W5
    /// return-the-sink (sticky NONE) behaviour.
    #[test]
    fn overlay_srflx_seek_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        apply(&mut cfg, "overlay_srflx_seek", Some("off")).unwrap();
        assert_eq!(cfg.overlay_srflx_seek, Some(false));
        assert_eq!(
            entry_for(&cfg, "overlay_srflx_seek")
                .unwrap()
                .value
                .as_deref(),
            Some("false")
        );
        apply(&mut cfg, "overlay_srflx_seek", None).unwrap();
        assert_eq!(cfg.overlay_srflx_seek, None, "clear → built-in default");
        assert!(
            crate::config::env_bridge_bools(&cfg)
                .iter()
                .any(|(k, _)| *k == "OVERLAY_SRFLX_SEEK"),
            "key must be bridged to the daemon's env"
        );
    }

    /// W4(d) — the legacy ReplacedByNewer process-exit escalation is
    /// opt-in via `ws_replaced_exit`; the built-in default (cleared) is
    /// the in-process backoff ladder.
    #[test]
    fn ws_replaced_exit_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        assert_eq!(cfg.ws_replaced_exit, None, "built-in default is OFF");
        apply(&mut cfg, "ws_replaced_exit", Some("on")).unwrap();
        assert_eq!(cfg.ws_replaced_exit, Some(true));
        assert_eq!(
            entry_for(&cfg, "ws_replaced_exit")
                .unwrap()
                .value
                .as_deref(),
            Some("true")
        );
        apply(&mut cfg, "ws_replaced_exit", None).unwrap();
        assert_eq!(cfg.ws_replaced_exit, None, "clear → built-in default");
        assert!(
            crate::config::env_bridge_bools(&cfg)
                .iter()
                .any(|(k, _)| *k == "WS_REPLACED_EXIT"),
            "key must be bridged to the daemon's env"
        );
    }

    /// C4 stage 1 — the warm-relay opt-in key: tribool, default OFF,
    /// bridged to the daemon env.
    #[test]
    fn overlay_warm_relay_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        assert_eq!(cfg.overlay_warm_relay, None, "built-in default is OFF");
        apply(&mut cfg, "overlay_warm_relay", Some("on")).unwrap();
        assert_eq!(cfg.overlay_warm_relay, Some(true));
        apply(&mut cfg, "overlay_warm_relay", None).unwrap();
        assert_eq!(cfg.overlay_warm_relay, None, "clear → built-in default");
        assert!(
            crate::config::env_bridge_bools(&cfg)
                .iter()
                .any(|(k, _)| *k == "OVERLAY_WARM_RELAY"),
            "key must be bridged to the daemon's env"
        );
    }

    /// R2 — the public-dial srflx fallback key: tribool, default None
    /// (daemon built-in ON), bridged to the daemon env.
    #[test]
    fn overlay_vpn_vantage_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        assert_eq!(cfg.overlay_vpn_vantage, None, "unset → daemon default (on)");
        apply(&mut cfg, "overlay_vpn_vantage", Some("off")).unwrap();
        assert_eq!(cfg.overlay_vpn_vantage, Some(false));
        apply(&mut cfg, "overlay_vpn_vantage", None).unwrap();
        assert_eq!(cfg.overlay_vpn_vantage, None, "clear → built-in default");
        assert!(
            crate::config::env_bridge_bools(&cfg)
                .iter()
                .any(|(k, _)| *k == "OVERLAY_VPN_VANTAGE"),
            "key must be bridged to the daemon's env"
        );
    }

    /// §6 item 5 — the gateway port-mapping key: tribool, default None
    /// (daemon built-in ON), bridged to the daemon env.
    #[test]
    fn overlay_portmap_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        assert_eq!(cfg.overlay_portmap, None, "unset → daemon default (on)");
        apply(&mut cfg, "overlay_portmap", Some("off")).unwrap();
        assert_eq!(cfg.overlay_portmap, Some(false));
        assert_eq!(current_value(&cfg, "overlay_portmap").as_deref(), Some("false"));
        apply(&mut cfg, "overlay_portmap", None).unwrap();
        assert_eq!(cfg.overlay_portmap, None, "clear → built-in default");
        assert!(
            crate::config::env_bridge_bools(&cfg)
                .iter()
                .any(|(k, _)| *k == "OVERLAY_PORTMAP"),
            "key must be bridged to the daemon's env"
        );
    }

    /// W6 phase 3 — the raw-first QUIC upgrade kill switch: tribool,
    /// default ON, bridged to the daemon env.
    #[test]
    fn overlay_quic_async_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        assert_eq!(
            cfg.overlay_quic_async, None,
            "built-in default is ON via env fallback"
        );
        apply(&mut cfg, "overlay_quic_async", Some("off")).unwrap();
        assert_eq!(cfg.overlay_quic_async, Some(false));
        apply(&mut cfg, "overlay_quic_async", None).unwrap();
        assert_eq!(cfg.overlay_quic_async, None, "clear → built-in default");
        assert!(
            crate::config::env_bridge_bools(&cfg)
                .iter()
                .any(|(k, _)| *k == "OVERLAY_QUIC_ASYNC"),
            "key must be bridged to the daemon's env"
        );
    }

    /// Track A stage 1 — the netd scaffold key: tribool, default OFF,
    /// supervisor-scoped (deliberately NOT env-bridged — the worker's
    /// runtime never reads it).
    #[test]
    fn overlay_netd_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        assert_eq!(cfg.overlay_netd, None, "built-in default is OFF");
        apply(&mut cfg, "overlay_netd", Some("on")).unwrap();
        assert_eq!(cfg.overlay_netd, Some(true));
        apply(&mut cfg, "overlay_netd", None).unwrap();
        assert_eq!(cfg.overlay_netd, None, "clear → built-in default");
    }

    /// The auth-first type-1 routing key set/echo/clear (per the
    /// every-new-env-gets-a-config-key rule). This is the kill switch for
    /// the dual-org lockout fix — it must be flippable per host with
    /// `roomler config set …` and no rebuild.
    #[test]
    fn overlay_init_auth_first_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        apply(&mut cfg, "overlay_init_auth_first", Some("off")).unwrap();
        assert_eq!(cfg.overlay_init_auth_first, Some(false));
        assert_eq!(
            entry_for(&cfg, "overlay_init_auth_first")
                .unwrap()
                .value
                .as_deref(),
            Some("false")
        );
        apply(&mut cfg, "overlay_init_auth_first", None).unwrap();
        assert_eq!(
            cfg.overlay_init_auth_first, None,
            "clear → built-in default"
        );
        assert!(
            crate::config::env_bridge_bools(&cfg)
                .iter()
                .any(|(k, _)| *k == "OVERLAY_INIT_AUTH_FIRST"),
            "key must be bridged to the daemon's env"
        );
    }

    /// rc.275 — the LAN-gather virtual-interface filter key set/echo/clear
    /// (per the every-new-env-gets-a-config-key rule).
    #[test]
    fn overlay_lan_iface_filter_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        apply(&mut cfg, "overlay_lan_iface_filter", Some("off")).unwrap();
        assert_eq!(cfg.overlay_lan_iface_filter, Some(false));
        assert_eq!(
            entry_for(&cfg, "overlay_lan_iface_filter")
                .unwrap()
                .value
                .as_deref(),
            Some("false")
        );
        apply(&mut cfg, "overlay_lan_iface_filter", Some("1")).unwrap();
        assert_eq!(cfg.overlay_lan_iface_filter, Some(true));
        apply(&mut cfg, "overlay_lan_iface_filter", None).unwrap();
        assert_eq!(cfg.overlay_lan_iface_filter, None);
        assert!(apply(&mut cfg, "overlay_lan_iface_filter", Some("maybe")).is_err());
    }

    /// rc.279 — the stable-Wintun-identity key set/echo/clear (per the
    /// every-new-env-gets-a-config-key rule).
    #[test]
    fn overlay_tun_stable_guid_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        apply(&mut cfg, "overlay_tun_stable_guid", Some("off")).unwrap();
        assert_eq!(cfg.overlay_tun_stable_guid, Some(false));
        assert_eq!(
            entry_for(&cfg, "overlay_tun_stable_guid")
                .unwrap()
                .value
                .as_deref(),
            Some("false")
        );
        apply(&mut cfg, "overlay_tun_stable_guid", Some("1")).unwrap();
        assert_eq!(cfg.overlay_tun_stable_guid, Some(true));
        apply(&mut cfg, "overlay_tun_stable_guid", None).unwrap();
        assert_eq!(cfg.overlay_tun_stable_guid, None);
        assert!(apply(&mut cfg, "overlay_tun_stable_guid", Some("maybe")).is_err());
    }

    /// rc.279 — the route-war eviction kill-switch key set/echo/clear (per
    /// the every-new-env-gets-a-config-key rule).
    #[test]
    fn overlay_route_evict_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        apply(&mut cfg, "overlay_route_evict", Some("off")).unwrap();
        assert_eq!(cfg.overlay_route_evict, Some(false));
        assert_eq!(
            entry_for(&cfg, "overlay_route_evict")
                .unwrap()
                .value
                .as_deref(),
            Some("false")
        );
        apply(&mut cfg, "overlay_route_evict", Some("1")).unwrap();
        assert_eq!(cfg.overlay_route_evict, Some(true));
        apply(&mut cfg, "overlay_route_evict", None).unwrap();
        assert_eq!(cfg.overlay_route_evict, None);
        assert!(apply(&mut cfg, "overlay_route_evict", Some("maybe")).is_err());
    }

    /// rc.280 — parity lock between the editable surface and the config→env
    /// bridge (the S2 fallback map). Asserts (1) every bridged suffix maps
    /// back to an editable surface key of the right kind (no orphan bridge
    /// entries), and (2) a surface write is visible to the bridge — the mass
    /// set/echo that replaces per-key boilerplate tests for bridged keys.
    /// The inverse (every tribool key must be bridged) is deliberately NOT
    /// asserted: some tribool keys are read straight from config by agent
    /// code rather than via `node_env`.
    #[test]
    fn env_bridge_pairs_have_surface_parity() {
        let mut cfg = crate::config::test_fixture();
        let bool_suffixes: Vec<&'static str> = crate::config::env_bridge_bools(&cfg)
            .iter()
            .map(|(s, _)| *s)
            .collect();
        for suffix in &bool_suffixes {
            let key = suffix.to_ascii_lowercase();
            let entry = entry_for(&cfg, &key)
                .unwrap_or_else(|| panic!("bridged suffix {suffix} has no surface key '{key}'"));
            assert_eq!(
                entry.kind, "tribool",
                "bridged bool '{key}' must be a tribool key"
            );
            apply(&mut cfg, &key, Some("1")).unwrap_or_else(|e| panic!("set {key}: {e}"));
        }
        assert!(
            crate::config::env_bridge_bools(&cfg)
                .iter()
                .all(|(_, v)| *v == Some(true)),
            "every bridged bool must reflect the surface write"
        );
        for (suffix, _) in crate::config::env_bridge_numerics(&cfg) {
            let key = suffix.to_ascii_lowercase();
            let entry = entry_for(&cfg, &key)
                .unwrap_or_else(|| panic!("bridged suffix {suffix} has no surface key '{key}'"));
            // Historically "string" (the rate_factor keys predate the
            // "number" editor kind); newer numerics use "number" like
            // overlay_route_tick_secs. Either is a validated numeric edit.
            assert!(
                matches!(entry.kind.as_str(), "string" | "number"),
                "bridged numeric '{key}' must be a validated string/number key, got {:?}",
                entry.kind
            );
        }
    }

    /// PR-D — the PathMonitor mode key: multi-state (on|shadow|off), so a
    /// validated string, not a tribool (per the every-new-env rule's
    /// enum-not-tribool clause). Case-normalized; empty/None clears.
    #[test]
    fn overlay_pathmon_set_echo_clear_and_validate() {
        let mut cfg = crate::config::test_fixture();
        apply(&mut cfg, "overlay_pathmon", Some("shadow")).unwrap();
        assert_eq!(cfg.overlay_pathmon.as_deref(), Some("shadow"));
        assert_eq!(
            entry_for(&cfg, "overlay_pathmon").unwrap().value.as_deref(),
            Some("shadow")
        );
        apply(&mut cfg, "overlay_pathmon", Some("ON")).unwrap();
        assert_eq!(cfg.overlay_pathmon.as_deref(), Some("on"));
        apply(&mut cfg, "overlay_pathmon", None).unwrap();
        assert_eq!(cfg.overlay_pathmon, None);
        assert!(apply(&mut cfg, "overlay_pathmon", Some("sideways")).is_err());
    }

    /// B2 — the demotion-mode key set/echo/clear + validation.
    #[test]
    fn overlay_rpf_set_echo_clear_and_validate() {
        let mut cfg = crate::config::test_fixture();
        apply(&mut cfg, "overlay_rpf", Some("enforce")).unwrap();
        assert_eq!(cfg.overlay_rpf.as_deref(), Some("enforce"));
        assert_eq!(
            entry_for(&cfg, "overlay_rpf").unwrap().value.as_deref(),
            Some("enforce")
        );
        apply(&mut cfg, "overlay_rpf", Some("WARN")).unwrap();
        assert_eq!(cfg.overlay_rpf.as_deref(), Some("warn"));
        apply(&mut cfg, "overlay_rpf", Some("off")).unwrap();
        assert_eq!(cfg.overlay_rpf.as_deref(), Some("off"));
        apply(&mut cfg, "overlay_rpf", None).unwrap();
        assert_eq!(cfg.overlay_rpf, None);
        // `shadow` is B2's vocabulary, not this key's — reject it rather than
        // silently landing on the default.
        assert!(apply(&mut cfg, "overlay_rpf", Some("shadow")).is_err());
        assert!(apply(&mut cfg, "overlay_rpf", Some("yes")).is_err());
    }

    #[test]
    fn overlay_demote_set_echo_clear_and_validate() {
        let mut cfg = crate::config::test_fixture();
        apply(&mut cfg, "overlay_demote", Some("on")).unwrap();
        assert_eq!(cfg.overlay_demote.as_deref(), Some("on"));
        assert_eq!(
            entry_for(&cfg, "overlay_demote").unwrap().value.as_deref(),
            Some("on")
        );
        apply(&mut cfg, "overlay_demote", Some("SHADOW")).unwrap();
        assert_eq!(cfg.overlay_demote.as_deref(), Some("shadow"));
        apply(&mut cfg, "overlay_demote", None).unwrap();
        assert_eq!(cfg.overlay_demote, None);
        assert!(apply(&mut cfg, "overlay_demote", Some("maybe")).is_err());
    }

    /// P4/PR-D — the event-driven route-guard key set/echo/clear.
    #[test]
    fn overlay_route_tick_secs_set_echo_clear_and_validate() {
        let mut cfg = crate::config::test_fixture();
        apply(&mut cfg, "overlay_route_tick_secs", Some("120")).unwrap();
        assert_eq!(cfg.overlay_route_tick_secs, Some(120));
        assert_eq!(
            entry_for(&cfg, "overlay_route_tick_secs")
                .unwrap()
                .value
                .as_deref(),
            Some("120")
        );
        apply(&mut cfg, "overlay_route_tick_secs", None).unwrap();
        assert_eq!(cfg.overlay_route_tick_secs, None);
        assert!(apply(&mut cfg, "overlay_route_tick_secs", Some("1")).is_err());
        assert!(apply(&mut cfg, "overlay_route_tick_secs", Some("301")).is_err());
        assert!(apply(&mut cfg, "overlay_route_tick_secs", Some("fast")).is_err());
    }

    #[test]
    fn overlay_direct_port_set_echo_clear_and_validate() {
        let mut cfg = crate::config::test_fixture();
        apply(&mut cfg, "overlay_direct_port", Some("43648")).unwrap();
        assert_eq!(cfg.overlay_direct_port, Some(43648));
        assert_eq!(
            entry_for(&cfg, "overlay_direct_port")
                .unwrap()
                .value
                .as_deref(),
            Some("43648")
        );
        // 0 = explicit ephemeral opt-out; stored, not rejected.
        apply(&mut cfg, "overlay_direct_port", Some("0")).unwrap();
        assert_eq!(cfg.overlay_direct_port, Some(0));
        apply(&mut cfg, "overlay_direct_port", None).unwrap();
        assert_eq!(cfg.overlay_direct_port, None);
        // A base whose public-dial band would overflow the port space is
        // rejected (mirrors `direct::MAX_DIRECT_PORT_BASE`); garbage too.
        let max = MAX_OVERLAY_DIRECT_PORT_BASE;
        apply(&mut cfg, "overlay_direct_port", Some(&max.to_string())).unwrap();
        assert_eq!(cfg.overlay_direct_port, Some(max));
        assert!(
            apply(
                &mut cfg,
                "overlay_direct_port",
                Some(&(max + 1).to_string())
            )
            .is_err()
        );
        assert!(apply(&mut cfg, "overlay_direct_port", Some("65535")).is_err());
        assert!(apply(&mut cfg, "overlay_direct_port", Some("forty")).is_err());
    }

    #[test]
    fn rc_max_sessions_set_echo_clear_and_validate() {
        let mut cfg = crate::config::test_fixture();
        apply(&mut cfg, "rc_max_sessions", Some("3")).unwrap();
        assert_eq!(cfg.rc_max_sessions, Some(3));
        assert_eq!(
            entry_for(&cfg, "rc_max_sessions").unwrap().value.as_deref(),
            Some("3")
        );
        apply(&mut cfg, "rc_max_sessions", None).unwrap();
        assert_eq!(cfg.rc_max_sessions, None);
        assert!(apply(&mut cfg, "rc_max_sessions", Some("0")).is_err());
        assert!(apply(&mut cfg, "rc_max_sessions", Some("9")).is_err());
        assert!(apply(&mut cfg, "rc_max_sessions", Some("many")).is_err());
    }

    #[test]
    fn shared_encoder_set_echo_clear_and_validate() {
        let mut cfg = crate::config::test_fixture();
        apply(&mut cfg, "shared_encoder", Some("off")).unwrap();
        assert_eq!(cfg.shared_encoder, Some(false));
        assert_eq!(
            entry_for(&cfg, "shared_encoder").unwrap().value.as_deref(),
            Some("false")
        );
        apply(&mut cfg, "shared_encoder", Some("on")).unwrap();
        assert_eq!(cfg.shared_encoder, Some(true));
        apply(&mut cfg, "shared_encoder", None).unwrap();
        assert_eq!(cfg.shared_encoder, None);
        assert!(apply(&mut cfg, "shared_encoder", Some("maybe")).is_err());
    }

    #[test]
    fn overlay_route_events_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        apply(&mut cfg, "overlay_route_events", Some("off")).unwrap();
        assert_eq!(cfg.overlay_route_events, Some(false));
        assert_eq!(
            entry_for(&cfg, "overlay_route_events")
                .unwrap()
                .value
                .as_deref(),
            Some("false")
        );
        apply(&mut cfg, "overlay_route_events", None).unwrap();
        assert_eq!(cfg.overlay_route_events, None);
        assert!(apply(&mut cfg, "overlay_route_events", Some("maybe")).is_err());
    }

    #[test]
    fn rate_factor_set_echo_clear_and_validate() {
        let mut cfg = crate::config::test_fixture();
        for key in [
            "rate_factor_h264",
            "rate_factor_hevc",
            "rate_factor_vp9",
            "rate_factor_av1",
        ] {
            apply(&mut cfg, key, Some("120")).unwrap();
            assert_eq!(
                entry_for(&cfg, key).unwrap().value.as_deref(),
                Some("120"),
                "set/echo for {key}"
            );
            assert!(apply(&mut cfg, key, Some("49")).is_err(), "{key} below 50");
            assert!(
                apply(&mut cfg, key, Some("401")).is_err(),
                "{key} above 400"
            );
            assert!(apply(&mut cfg, key, Some("fast")).is_err(), "{key} garbage");
            // Failed applies never partially wrote:
            assert_eq!(entry_for(&cfg, key).unwrap().value.as_deref(), Some("120"));
            apply(&mut cfg, key, None).unwrap();
            assert_eq!(entry_for(&cfg, key).unwrap().value, None, "clear {key}");
        }
    }

    #[test]
    fn ice_follow_renomination_enum_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        apply(&mut cfg, "ice_follow_renomination", Some("always")).unwrap();
        assert_eq!(cfg.ice_follow_renomination, Some(true));
        assert_eq!(
            entry_for(&cfg, "ice_follow_renomination")
                .unwrap()
                .value
                .as_deref(),
            Some("always")
        );
        apply(&mut cfg, "ice_follow_renomination", Some("never")).unwrap();
        assert_eq!(cfg.ice_follow_renomination, Some(false));
        apply(&mut cfg, "ice_follow_renomination", Some("auto")).unwrap();
        assert_eq!(cfg.ice_follow_renomination, None);
        assert_eq!(
            entry_for(&cfg, "ice_follow_renomination").unwrap().value,
            None
        );
        assert!(apply(&mut cfg, "ice_follow_renomination", Some("on")).is_err());
    }

    #[test]
    fn ice_and_overlay_hatch_tribools_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        for key in [
            "ice_warm_standby",
            "ice_overlay_host_deprioritize",
            "overlay_tier_detect",
            "overlay_rtt_q",
            "overlay_upward_probe",
            "relay_probe",
            "text_mod_neutralize",
        ] {
            apply(&mut cfg, key, Some("off")).unwrap();
            assert_eq!(
                entry_for(&cfg, key).unwrap().value.as_deref(),
                Some("false"),
                "set/echo for {key}"
            );
            apply(&mut cfg, key, None).unwrap();
            assert_eq!(entry_for(&cfg, key).unwrap().value, None, "clear {key}");
        }
    }

    /// Fleet RPC gate 4 — set/echo/clear, and above all: clearing must land
    /// on OFF. This is the one refusal that survives a compromised control
    /// plane, so a `roomler config set exec_enabled` with no value must never
    /// be a way to turn it on.
    #[test]
    fn exec_enabled_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        assert_eq!(
            current_value(&cfg, "exec_enabled").as_deref(),
            Some("false"),
            "Fleet RPC must be off on a fresh device"
        );
        apply(&mut cfg, "exec_enabled", Some("true")).unwrap();
        assert!(cfg.exec_enabled);
        assert_eq!(
            entry_for(&cfg, "exec_enabled").unwrap().value.as_deref(),
            Some("true")
        );
        apply(&mut cfg, "exec_enabled", None).unwrap();
        assert!(!cfg.exec_enabled, "clearing must fail SAFE, not open");
        assert!(apply(&mut cfg, "exec_enabled", Some("perhaps")).is_err());
    }

    /// FR-84 D3 — the switch that keeps "Apply now" off a shared machine.
    /// Default ON (a personal device wants it); clearing returns to ON, the
    /// built-in default — unlike the root-granting gates, OFF is not the
    /// fail-safe direction here, it only removes a convenience. LIVE: the
    /// restart verb re-reads the file on every request, so an administrator's
    /// edit is in force at once and the desktop must not ask for a restart to
    /// apply it. Written against strings so it compiles on the pre-D3 tree,
    /// where it is RED: the key was unknown to the surface.
    #[test]
    fn local_restart_enabled_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        assert_eq!(
            current_value(&cfg, "local_restart_enabled").as_deref(),
            Some("true"),
            "a fresh device lets the person at it restart the service"
        );
        apply(&mut cfg, "local_restart_enabled", Some("false")).unwrap();
        assert_eq!(
            entry_for(&cfg, "local_restart_enabled")
                .unwrap()
                .value
                .as_deref(),
            Some("false")
        );
        apply(&mut cfg, "local_restart_enabled", None).unwrap();
        assert_eq!(
            current_value(&cfg, "local_restart_enabled").as_deref(),
            Some("true"),
            "clearing restores the built-in default"
        );
        assert!(apply(&mut cfg, "local_restart_enabled", Some("perhaps")).is_err());
        let e = entry_for(&cfg, "local_restart_enabled").unwrap();
        assert_eq!(e.group, "access");
        assert_eq!(e.tier, "standard");
        assert!(
            !e.restart_required,
            "the restart verb reads the file per request — the key is live"
        );
    }

    /// FR-90 — every Hive gate defaults CLOSED and clears closed: off, nobody,
    /// nowhere. The defaults are the security property here, as for
    /// `remote_config_enabled` below.
    #[test]
    fn hive_gates_default_closed_and_clear_closed() {
        let mut cfg = crate::config::test_fixture();
        assert!(!cfg.hive_enabled);
        assert!(cfg.hive_accounts.is_empty(), "nobody");
        assert!(cfg.hive_roots.is_empty(), "nowhere");
        // The wire default agrees with the serde default of an absent key.
        let e = entry_for(&cfg, "hive_enabled").unwrap();
        assert_eq!(e.default.as_deref(), Some("false"));
        assert_eq!(e.group, Group::Access.wire());

        apply(&mut cfg, "hive_enabled", Some("true")).unwrap();
        let root = if cfg!(windows) {
            r"C:\src"
        } else {
            "/home/dev/src"
        };
        apply(&mut cfg, "hive_roots", Some(&format!(" {root} , "))).unwrap();
        assert_eq!(
            cfg.hive_roots,
            vec![root.to_string()],
            "trimmed, blanks dropped"
        );
        apply(
            &mut cfg,
            "hive_accounts",
            Some(r#"{"dev@example.com": "dev", "0123456789abcdef01234567": " svc "}"#),
        )
        .unwrap();
        assert_eq!(
            cfg.hive_accounts.get("dev@example.com").map(String::as_str),
            Some("dev")
        );
        assert_eq!(
            cfg.hive_accounts
                .get("0123456789abcdef01234567")
                .map(String::as_str),
            Some("svc"),
            "values are trimmed"
        );
        // It echoes as the JSON it was set from.
        let echoed = entry_for(&cfg, "hive_accounts").unwrap().value.unwrap();
        assert!(echoed.contains("\"dev@example.com\":\"dev\""), "{echoed}");

        // Clearing closes every gate again.
        for key in ["hive_enabled", "hive_accounts", "hive_roots"] {
            apply(&mut cfg, key, None).unwrap();
        }
        assert!(!cfg.hive_enabled && cfg.hive_accounts.is_empty() && cfg.hive_roots.is_empty());
    }

    /// FR-90 P1e — core memory is shown to a session only when the device's
    /// owner says so: off by default, off again when cleared, and the wire
    /// default agrees with the serde default of an absent key.
    #[test]
    fn hive_core_memory_defaults_off_and_clears_off() {
        let mut cfg = crate::config::test_fixture();
        assert!(!cfg.hive_core_memory);
        let e = entry_for(&cfg, "hive_core_memory").unwrap();
        assert_eq!(e.default.as_deref(), Some("false"));
        assert_eq!(e.group, Group::Access.wire());
        apply(&mut cfg, "hive_core_memory", Some("true")).unwrap();
        assert!(cfg.hive_core_memory);
        assert_eq!(
            entry_for(&cfg, "hive_core_memory")
                .unwrap()
                .value
                .as_deref(),
            Some("true")
        );
        apply(&mut cfg, "hive_core_memory", None).unwrap();
        assert!(!cfg.hive_core_memory, "cleared is off");
        assert!(apply(&mut cfg, "hive_core_memory", Some("maybe")).is_err());
    }

    /// FR-90 P1j — adopting terminal sessions is the device owner's to allow,
    /// off until they say so and off again when cleared.
    #[test]
    fn hive_adopt_defaults_off_and_clears_off() {
        let mut cfg = crate::config::test_fixture();
        assert!(!cfg.hive_adopt);
        let e = entry_for(&cfg, "hive_adopt").unwrap();
        assert_eq!(e.default.as_deref(), Some("false"));
        assert_eq!(e.group, Group::Access.wire());
        apply(&mut cfg, "hive_adopt", Some("true")).unwrap();
        assert!(cfg.hive_adopt);
        apply(&mut cfg, "hive_adopt", None).unwrap();
        assert!(!cfg.hive_adopt, "cleared is off");
        assert!(apply(&mut cfg, "hive_adopt", Some("sometimes")).is_err());
    }

    /// FR-90 P2c — holding copies of sessions, offering the device as an
    /// archive, and how much it keeps are the device owner's: off and unbound
    /// until they say so, and so again when cleared.
    #[test]
    fn hive_replica_archive_and_quota_are_the_owners_and_off_by_default() {
        let mut cfg = crate::config::test_fixture();
        for key in ["hive_replica", "hive_archive"] {
            let e = entry_for(&cfg, key).unwrap();
            assert_eq!(e.default.as_deref(), Some("false"), "{key}");
            assert_eq!(e.group, Group::Access.wire());
            apply(&mut cfg, key, Some("true")).unwrap();
            apply(&mut cfg, key, None).unwrap();
            assert!(apply(&mut cfg, key, Some("sometimes")).is_err());
        }
        assert!(!cfg.hive_replica && !cfg.hive_archive, "cleared is off");
        apply(&mut cfg, "hive_replica", Some("true")).unwrap();
        assert!(cfg.hive_replica);
        apply(&mut cfg, "hive_archive", Some("true")).unwrap();
        assert!(cfg.hive_archive);

        assert_eq!(cfg.hive_store_quota_mib, None);
        apply(&mut cfg, "hive_store_quota_mib", Some("10240")).unwrap();
        assert_eq!(cfg.hive_store_quota_mib, Some(10240));
        assert!(apply(&mut cfg, "hive_store_quota_mib", Some("0")).is_err());
        assert!(apply(&mut cfg, "hive_store_quota_mib", Some("4194305")).is_err());
        assert!(apply(&mut cfg, "hive_store_quota_mib", Some("10GiB")).is_err());
        apply(&mut cfg, "hive_store_quota_mib", None).unwrap();
        assert_eq!(cfg.hive_store_quota_mib, None, "cleared is unbound");
    }

    /// FR-90 P3-3 — whether the vault may lease values to this device's
    /// sessions is the device owner's: off until they say so, off again when
    /// cleared, and read at start, where the daemon makes its key.
    #[test]
    fn vault_enabled_defaults_off_and_clears_off() {
        let mut cfg = crate::config::test_fixture();
        assert!(!cfg.vault_enabled);
        let e = entry_for(&cfg, "vault_enabled").unwrap();
        assert_eq!(e.default.as_deref(), Some("false"));
        assert_eq!(e.group, Group::Access.wire());
        assert!(e.restart_required, "the key is made at start");
        apply(&mut cfg, "vault_enabled", Some("true")).unwrap();
        assert!(cfg.vault_enabled);
        apply(&mut cfg, "vault_enabled", None).unwrap();
        assert!(!cfg.vault_enabled, "cleared is off");
        assert!(apply(&mut cfg, "vault_enabled", Some("sometimes")).is_err());
    }

    /// FR-90 P3-7-3c — whether a session here may reach a network through
    /// this device is the device owner's: off until they say so, off again
    /// when cleared, and read at start, as the other `hive_*` keys are.
    #[test]
    fn hive_net_defaults_off_and_clears_off() {
        let mut cfg = crate::config::test_fixture();
        assert!(!cfg.hive_net);
        let e = entry_for(&cfg, "hive_net").unwrap();
        assert_eq!(e.default.as_deref(), Some("false"));
        assert_eq!(e.group, Group::Access.wire());
        assert!(e.restart_required, "the hive snapshot is read at start");
        apply(&mut cfg, "hive_net", Some("true")).unwrap();
        assert!(cfg.hive_net);
        apply(&mut cfg, "hive_net", None).unwrap();
        assert!(!cfg.hive_net, "cleared is off");
        assert!(apply(&mut cfg, "hive_net", Some("on-ish")).is_err());
    }

    /// FR-90 P3-8-2b-2 — so is whether a session here may run a command on
    /// another device: off until the owner says so, off again when cleared,
    /// and read at start.
    #[test]
    fn hive_ssh_defaults_off_and_clears_off() {
        let mut cfg = crate::config::test_fixture();
        assert!(!cfg.hive_ssh);
        let e = entry_for(&cfg, "hive_ssh").unwrap();
        assert_eq!(e.default.as_deref(), Some("false"));
        assert_eq!(e.group, Group::Access.wire());
        assert!(e.restart_required, "the hive snapshot is read at start");
        apply(&mut cfg, "hive_ssh", Some("true")).unwrap();
        assert!(cfg.hive_ssh);
        assert!(!cfg.hive_net, "and it is not hive_net");
        apply(&mut cfg, "hive_ssh", None).unwrap();
        assert!(!cfg.hive_ssh, "cleared is off");
        assert!(apply(&mut cfg, "hive_ssh", Some("on-ish")).is_err());
    }

    /// FR-90 P3-4d-2 — whether the device reports what it does with its
    /// leases is the device owner's, as `ssh_activity_log` is: off until they
    /// say so, off again when cleared, read at the primary connection.
    #[test]
    fn vault_activity_log_defaults_off_and_clears_off() {
        let mut cfg = crate::config::test_fixture();
        assert!(!cfg.vault_activity_log);
        let e = entry_for(&cfg, "vault_activity_log").unwrap();
        assert_eq!(e.default.as_deref(), Some("false"));
        assert_eq!(e.group, Group::Access.wire());
        assert!(e.restart_required);
        apply(&mut cfg, "vault_activity_log", Some("true")).unwrap();
        assert!(cfg.vault_activity_log);
        apply(&mut cfg, "vault_activity_log", None).unwrap();
        assert!(!cfg.vault_activity_log, "cleared is off");
        assert!(apply(&mut cfg, "vault_activity_log", Some("sometimes")).is_err());
    }

    /// FR-90 decision 15 — a Mac session as an account whose `sudo` needs no
    /// password is the device owner's to allow: off until they say so, and
    /// off again when cleared.
    #[test]
    fn hive_allow_passwordless_sudo_defaults_off_and_clears_off() {
        let mut cfg = crate::config::test_fixture();
        assert!(!cfg.hive_allow_passwordless_sudo);
        let e = entry_for(&cfg, "hive_allow_passwordless_sudo").unwrap();
        assert_eq!(e.default.as_deref(), Some("false"));
        assert_eq!(e.group, Group::Access.wire());
        apply(&mut cfg, "hive_allow_passwordless_sudo", Some("true")).unwrap();
        assert!(cfg.hive_allow_passwordless_sudo);
        apply(&mut cfg, "hive_allow_passwordless_sudo", None).unwrap();
        assert!(!cfg.hive_allow_passwordless_sudo, "cleared is off");
        assert!(apply(&mut cfg, "hive_allow_passwordless_sudo", Some("yes-ish")).is_err());
    }

    /// FR-90 — what `config set` refuses for the Hive keys, so a typo is a
    /// refusal now rather than a session refused later for a reason the owner
    /// has to dig out of a log.
    #[test]
    fn hive_keys_refuse_what_a_launch_would_misread() {
        let mut cfg = crate::config::test_fixture();
        for bad in [
            r#"{"dev@example.com": "root"}"#,
            r#"{"dev@example.com": ""}"#,
            r#"{"dev@example.com": "two words"}"#,
            r#"{"dev@example.com": "named:dev"}"#,
            r#"{"just-a-name": "dev"}"#,
            r#"{"0123": "dev"}"#,
            "not json",
            r#"["dev"]"#,
        ] {
            let err = apply(&mut cfg, "hive_accounts", Some(bad)).unwrap_err();
            assert!(err.contains("hive_accounts"), "{bad}: {err}");
        }
        assert!(cfg.hive_accounts.is_empty(), "nothing half-applied");

        assert!(apply(&mut cfg, "hive_roots", Some("src,relative/dir")).is_err());
        assert!(apply(&mut cfg, "hive_harness", Some("claude")).is_err());
        assert!(apply(&mut cfg, "hive_max_sessions", Some("0")).is_err());
        assert!(apply(&mut cfg, "hive_max_sessions", Some("65")).is_err());
        apply(&mut cfg, "hive_max_sessions", Some("2")).unwrap();
        assert_eq!(cfg.hive_max_sessions, Some(2));
        assert!(apply(&mut cfg, "hive_api_key_helper", Some("a\nb")).is_err());
        // A header value: an identifier, nothing that could smuggle another.
        for bad in ["wrkspc 1", "wrkspc\r\nx-api-key: k", "a:b"] {
            assert!(
                apply(&mut cfg, "hive_api_workspace_id", Some(bad)).is_err(),
                "{bad:?}"
            );
        }
        apply(&mut cfg, "hive_api_workspace_id", Some("wrkspc_01Ab-9")).unwrap();
        assert_eq!(cfg.hive_api_workspace_id.as_deref(), Some("wrkspc_01Ab-9"));
        apply(&mut cfg, "hive_api_workspace_id", None).unwrap();
        assert_eq!(cfg.hive_api_workspace_id, None);
        // P1d-1 — 0 is a real choice (never wait), the ceiling is two hours,
        // and a clear goes back to the built-in 30 minutes.
        apply(&mut cfg, "hive_update_wait_secs", Some("0")).unwrap();
        assert_eq!(cfg.hive_update_wait_secs, Some(0));
        assert!(apply(&mut cfg, "hive_update_wait_secs", Some("7201")).is_err());
        assert!(apply(&mut cfg, "hive_update_wait_secs", Some("-1")).is_err());
        apply(&mut cfg, "hive_update_wait_secs", None).unwrap();
        assert_eq!(cfg.hive_update_wait_secs, None);
    }

    /// The opt-in that keeps `exec_enabled` / `ssh_enabled` refusable by a
    /// compromised control plane (`docs/remote-config.md`). Locked here
    /// because the DEFAULT is the security property: a device that has not
    /// opted in cannot be opened by any server, so a stray `#[serde(default)]`
    /// change or a "sensible" default-on would silently undo the design.
    #[test]
    fn remote_config_opt_in_defaults_off_and_clears_off() {
        let mut cfg = crate::config::test_fixture();
        assert_eq!(
            current_value(&cfg, "remote_config_enabled").as_deref(),
            Some("false"),
            "a fresh device must not accept pushed config"
        );
        apply(&mut cfg, "remote_config_enabled", Some("true")).unwrap();
        assert!(cfg.remote_config_enabled);
        assert_eq!(
            entry_for(&cfg, "remote_config_enabled")
                .unwrap()
                .value
                .as_deref(),
            Some("true")
        );
        // Clearing opts back OUT. The fail-safe direction for this key is the
        // one that RESTORES the local veto.
        apply(&mut cfg, "remote_config_enabled", None).unwrap();
        assert!(
            !cfg.remote_config_enabled,
            "clearing must re-close the door"
        );
        assert!(apply(&mut cfg, "remote_config_enabled", Some("maybe")).is_err());
    }

    /// A config file written before this key existed must load as opted-OUT.
    /// Every device in the field predates it, so the `#[serde(default)]`
    /// behaviour here is what decides whether the fleet wakes up closed.
    #[test]
    fn absent_remote_config_key_loads_as_opted_out() {
        let cfg: crate::config::AgentConfig =
            toml::from_str("server_url = \"https://example.invalid\"\nws_url = \"wss://example.invalid/ws\"\nagent_token = \"t\"\nagent_id = \"a\"\ntenant_id = \"t\"\nmachine_id = \"m\"\nmachine_name = \"n\"\n")
                .expect("minimal config parses");
        assert!(
            !cfg.remote_config_enabled,
            "a config predating the key must not be opted in"
        );
    }

    #[test]
    fn bool_clear_restores_serde_default() {
        let mut cfg = crate::config::test_fixture();
        apply(&mut cfg, "auto_grant_session", Some("false")).unwrap();
        assert!(!cfg.auto_grant_session);
        apply(&mut cfg, "auto_grant_session", None).unwrap();
        assert!(cfg.auto_grant_session, "default_auto_grant_session is true");
        apply(&mut cfg, "overlay_enabled", None).unwrap();
        assert!(!cfg.overlay_enabled, "overlay default is off");
    }

    /// P2c — the multi-org TUN opt-in round-trips through set/echo and
    /// clears back to its off default.
    #[test]
    fn overlay_multi_org_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        assert_eq!(
            current_value(&cfg, "overlay_multi_org").as_deref(),
            Some("false")
        );
        apply(&mut cfg, "overlay_multi_org", Some("true")).unwrap();
        assert!(cfg.overlay_multi_org);
        assert_eq!(
            current_value(&cfg, "overlay_multi_org").as_deref(),
            Some("true")
        );
        apply(&mut cfg, "overlay_multi_org", None).unwrap();
        assert!(!cfg.overlay_multi_org, "multi-org TUN default is off");
    }

    #[test]
    fn cidr_list_validates() {
        let mut cfg = crate::config::test_fixture();
        apply(
            &mut cfg,
            "advertise_routes",
            Some("192.168.1.0/24, 10.0.0.0/8"),
        )
        .unwrap();
        assert_eq!(cfg.advertise_routes, vec!["192.168.1.0/24", "10.0.0.0/8"]);
        assert!(apply(&mut cfg, "advertise_routes", Some("not-a-cidr")).is_err());
        assert!(apply(&mut cfg, "advertise_routes", Some("10.0.0.0/40")).is_err());
        // Bad input never partially wrote:
        assert_eq!(cfg.advertise_routes, vec!["192.168.1.0/24", "10.0.0.0/8"]);
        apply(&mut cfg, "advertise_routes", Some("")).unwrap();
        assert!(cfg.advertise_routes.is_empty());
    }

    #[test]
    fn json_keys_validate() {
        let mut cfg = crate::config::test_fixture();
        let acl = r#"{"enabled": false, "allowlist": []}"#;
        apply(&mut cfg, "forward_acl", Some(acl)).unwrap();
        assert!(!cfg.forward_acl.enabled);
        assert!(apply(&mut cfg, "forward_acl", Some("{nope")).is_err());
        apply(&mut cfg, "forward_acl", None).unwrap();
        assert!(cfg.forward_acl.enabled, "default ACL is enabled");
    }

    #[test]
    fn secrets_and_identity_are_not_exposed() {
        let cfg = crate::config::test_fixture();
        for hidden in [
            "agent_token",
            "overlay_wg_secret_key",
            "machine_id",
            "machine_name",
            "tunnel_routes",
        ] {
            assert!(entry_for(&cfg, hidden).is_none(), "{hidden} must be hidden");
            let mut c = cfg.clone();
            assert!(apply(&mut c, hidden, Some("x")).is_err());
        }
    }

    #[test]
    fn enum_and_interval_parse() {
        let mut cfg = crate::config::test_fixture();
        apply(&mut cfg, "encoder_preference", Some("hw")).unwrap();
        assert!(matches!(
            cfg.encoder_preference,
            EncoderPreferenceChoice::Hardware
        ));
        assert!(apply(&mut cfg, "encoder_preference", Some("fast")).is_err());
        apply(&mut cfg, "update_check_interval_h", Some("168")).unwrap();
        assert_eq!(cfg.update_check_interval_h, Some(168));
        assert!(apply(&mut cfg, "update_check_interval_h", Some("0")).is_err());
        assert!(apply(&mut cfg, "update_check_interval_h", Some("nope")).is_err());
        apply(&mut cfg, "update_check_interval_h", None).unwrap();
        assert_eq!(cfg.update_check_interval_h, None);
    }

    /// FR-77 P3 — the denylist key validates its shape (a typo would deny
    /// nothing while reading as if the built-in list were still in force),
    /// echoes, clears, and accepts the `none` spelling.
    #[test]
    fn encoder_cells_deny_set_echo_clear_and_validate() {
        let mut cfg = crate::config::test_fixture();
        assert_eq!(current_value(&cfg, "encoder_cells_deny"), None);
        apply(
            &mut cfg,
            "encoder_cells_deny",
            Some(" hevc_qsv:yuv444, vp9_qsv:yuv444 "),
        )
        .unwrap();
        assert_eq!(
            cfg.encoder_cells_deny.as_deref(),
            Some("hevc_qsv:yuv444, vp9_qsv:yuv444")
        );
        assert_eq!(
            entry_for(&cfg, "encoder_cells_deny")
                .unwrap()
                .value
                .as_deref(),
            Some("hevc_qsv:yuv444, vp9_qsv:yuv444")
        );
        apply(&mut cfg, "encoder_cells_deny", Some("none")).unwrap();
        assert_eq!(cfg.encoder_cells_deny.as_deref(), Some("none"));
        apply(&mut cfg, "encoder_cells_deny", None).unwrap();
        assert_eq!(cfg.encoder_cells_deny, None);
        apply(&mut cfg, "encoder_cells_deny", Some("")).unwrap();
        assert_eq!(cfg.encoder_cells_deny, None, "blank clears to the built-in");
        for bad in [
            "hevc_qsv",
            "hevc_qsv:yuv422",
            "HEVC_QSV:yuv444",
            ":yuv444",
            "a b:yuv444",
        ] {
            assert!(
                apply(&mut cfg, "encoder_cells_deny", Some(bad)).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    /// FR-119 P2b — `fps_deny` sets, echoes, clears, and refuses an entry that
    /// could only ever deny nothing.
    #[test]
    fn fps_deny_set_echo_clear_and_validate() {
        let mut cfg = crate::config::test_fixture();
        assert_eq!(current_value(&cfg, "fps_deny"), None);
        apply(&mut cfg, "fps_deny", Some(" hevc_qsv:120, *:144 ")).unwrap();
        assert_eq!(cfg.fps_deny.as_deref(), Some("hevc_qsv:120, *:144"));
        assert_eq!(
            entry_for(&cfg, "fps_deny").unwrap().value.as_deref(),
            Some("hevc_qsv:120, *:144")
        );
        apply(&mut cfg, "fps_deny", Some("none")).unwrap();
        assert_eq!(cfg.fps_deny.as_deref(), Some("none"));
        apply(&mut cfg, "fps_deny", Some("")).unwrap();
        assert_eq!(cfg.fps_deny, None, "blank clears: deny nothing");
        for bad in [
            "hevc_qsv",
            "hevc_qsv:60",
            "hevc_qsv:fast",
            "HEVC_QSV:120",
            ":120",
            "a b:120",
            "**:120",
        ] {
            assert!(
                apply(&mut cfg, "fps_deny", Some(bad)).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn caps_cache_is_a_tribool_that_bridges() {
        let mut cfg = crate::config::test_fixture();
        assert_eq!(entry_for(&cfg, "caps_cache").unwrap().kind, "tribool");
        apply(&mut cfg, "caps_cache", Some("0")).unwrap();
        assert_eq!(cfg.caps_cache, Some(false));
        assert!(
            crate::config::env_bridge_bools(&cfg)
                .iter()
                .any(|(s, v)| *s == "CAPS_CACHE" && *v == Some(false)),
            "the kill switch must reach the daemon through the S2 bridge"
        );
        apply(&mut cfg, "caps_cache", None).unwrap();
        assert_eq!(cfg.caps_cache, None);
    }

    /// FR-119 — `fps_high` is a tribool that reaches the daemon as
    /// `ROOMLERD_FPS_HIGH`, and unset publishes nothing (off).
    #[test]
    fn fps_high_is_a_tribool_that_bridges() {
        let mut cfg = crate::config::test_fixture();
        assert_eq!(entry_for(&cfg, "fps_high").unwrap().kind, "tribool");
        let bridged = |cfg: &crate::config::AgentConfig| {
            crate::config::env_bridge_bools(cfg)
                .iter()
                .find(|(s, _)| *s == "FPS_HIGH")
                .map(|(_, v)| *v)
        };
        assert_eq!(bridged(&cfg), Some(None), "unset: bridged as nothing");
        apply(&mut cfg, "fps_high", Some("true")).unwrap();
        assert_eq!(cfg.fps_high, Some(true));
        assert_eq!(bridged(&cfg), Some(Some(true)));
        apply(&mut cfg, "fps_high", None).unwrap();
        assert_eq!(cfg.fps_high, None);
    }

    /// The chroma column keys ride the numeric bridge like the codec factors.
    #[test]
    fn chroma_column_rate_factors_bridge_and_validate() {
        let mut cfg = crate::config::test_fixture();
        for key in [
            "rate_factor_h264_444",
            "rate_factor_hevc_444",
            "rate_factor_vp9_444",
        ] {
            apply(&mut cfg, key, Some("120")).unwrap();
            assert_eq!(entry_for(&cfg, key).unwrap().value.as_deref(), Some("120"));
            assert!(apply(&mut cfg, key, Some("10")).is_err(), "{key}: below 50");
        }
        let bridged: Vec<&str> = crate::config::env_bridge_numerics(&cfg)
            .iter()
            .filter(|(_, v)| *v == Some(120))
            .map(|(s, _)| *s)
            .collect();
        assert_eq!(
            bridged,
            vec![
                "RATE_FACTOR_H264_444",
                "RATE_FACTOR_HEVC_444",
                "RATE_FACTOR_VP9_444"
            ]
        );
    }
}

#[cfg(test)]
mod netstack_port_surface_tests {
    use super::{apply, current_value};

    /// Multi-org netstack: the per-org port is a real config key, so it has
    /// to round-trip through the surface like every other one.
    #[test]
    fn netstack_socks_port_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        assert_eq!(current_value(&cfg, "netstack_socks_port"), None);

        apply(&mut cfg, "netstack_socks_port", Some("41080")).unwrap();
        assert_eq!(cfg.netstack_socks_port, Some(41080));
        assert_eq!(
            current_value(&cfg, "netstack_socks_port").as_deref(),
            Some("41080")
        );

        // Privileged ports would need the daemon to bind below 1024 for a
        // loopback convenience listener — refuse rather than fail at bind.
        assert!(apply(&mut cfg, "netstack_socks_port", Some("80")).is_err());
        assert!(apply(&mut cfg, "netstack_socks_port", Some("nope")).is_err());
        assert_eq!(
            cfg.netstack_socks_port,
            Some(41080),
            "a rejected set is a no-op"
        );

        apply(&mut cfg, "netstack_socks_port", None).unwrap();
        assert_eq!(
            cfg.netstack_socks_port, None,
            "clearing returns to OS-TUN mode"
        );
    }

    /// The M5 privilege ceiling. Two values only — a ceiling has to be an
    /// ordering, and `named:<account>` has no place in one — and the reject
    /// happens on the way IN, so a typo is a failed `config set` rather than
    /// a device that silently kept accepting root sessions.
    #[test]
    fn ssh_max_privilege_set_echo_clear_and_validate() {
        let mut cfg = crate::config::test_fixture();
        assert_eq!(
            current_value(&cfg, "ssh_max_privilege"),
            None,
            "unset by default: arriving switched on would revoke a working config mid-roll"
        );

        apply(&mut cfg, "ssh_max_privilege", Some("console_user")).unwrap();
        assert_eq!(cfg.ssh_max_privilege.as_deref(), Some("console_user"));
        assert_eq!(
            current_value(&cfg, "ssh_max_privilege").as_deref(),
            Some("console_user")
        );

        apply(&mut cfg, "ssh_max_privilege", Some("daemon")).unwrap();
        assert_eq!(
            cfg.ssh_max_privilege.as_deref(),
            Some("daemon"),
            "explicit `daemon` is a stated no-limit, distinct from never having chosen"
        );

        // `named:` is accepted for ssh_account_mode and refused here on
        // purpose: "is named:svc-backup above or below console_user?" has no
        // answer, so it cannot bound anything.
        assert!(apply(&mut cfg, "ssh_max_privilege", Some("named:svc")).is_err());
        assert!(apply(&mut cfg, "ssh_max_privilege", Some("Console_User")).is_err());
        assert_eq!(
            cfg.ssh_max_privilege.as_deref(),
            Some("daemon"),
            "a rejected set is a no-op"
        );

        apply(&mut cfg, "ssh_max_privilege", None).unwrap();
        assert_eq!(cfg.ssh_max_privilege, None, "clearing returns to no limit");
    }
}

#[cfg(test)]
mod localapi_pipe_pool_surface_tests {
    use super::{apply, current_value, entry_for};

    /// FR-84 D1 — the listener-pool kill switch is a real config key: it
    /// round-trips through the surface, refuses anything outside 1..=16, and
    /// clears back to the built-in default. Written against the surface API
    /// only (no field access), so it compiles — and fails with "unknown or
    /// non-editable config key" — on a tree that does not register the key.
    #[test]
    fn localapi_pipe_pool_set_echo_clear_and_validate() {
        let mut cfg = crate::config::test_fixture();
        let entry = entry_for(&cfg, "localapi_pipe_pool").expect("a registered surface key");
        assert_eq!(entry.kind, "number");
        assert!(
            entry.restart_required,
            "the pool is sized once, at bind time"
        );
        assert_eq!(
            current_value(&cfg, "localapi_pipe_pool"),
            None,
            "unset = built-in default"
        );

        apply(&mut cfg, "localapi_pipe_pool", Some("1")).unwrap();
        assert_eq!(
            current_value(&cfg, "localapi_pipe_pool").as_deref(),
            Some("1"),
            "1 = the pre-FR-84 single instance"
        );
        apply(&mut cfg, "localapi_pipe_pool", Some(" 16 ")).unwrap();
        assert_eq!(
            current_value(&cfg, "localapi_pipe_pool").as_deref(),
            Some("16")
        );

        for bad in ["0", "17", "-1", "four", "4.0", "1e3"] {
            assert!(
                apply(&mut cfg, "localapi_pipe_pool", Some(bad)).is_err(),
                "{bad:?} must be refused"
            );
            assert_eq!(
                current_value(&cfg, "localapi_pipe_pool").as_deref(),
                Some("16"),
                "a rejected set is a no-op ({bad:?})"
            );
        }

        apply(&mut cfg, "localapi_pipe_pool", None).unwrap();
        assert_eq!(
            current_value(&cfg, "localapi_pipe_pool"),
            None,
            "cleared = built-in default again"
        );
        apply(&mut cfg, "localapi_pipe_pool", Some("")).unwrap();
        assert_eq!(
            current_value(&cfg, "localapi_pipe_pool"),
            None,
            "empty clears too"
        );
    }
}

#[cfg(test)]
mod companion_autostart_surface_tests {
    use super::{apply, current_value, entry_for};

    /// FR-84 D6 — `companion_autostart` is the kill switch for the whole of
    /// D6's launch behaviour, so it has to be a real surface key: default ON,
    /// echoed as a plain bool, a restart-bound Device key (the Run value is
    /// synced and the post-install launch decided at service start), and
    /// clearing it returns to ON rather than OFF. Written against the surface
    /// API only, so on a tree that does not register the key it compiles and
    /// fails with "unknown or non-editable config key".
    #[test]
    fn companion_autostart_set_echo_clear() {
        let mut cfg = crate::config::test_fixture();
        let entry = entry_for(&cfg, "companion_autostart").expect("a registered surface key");
        assert_eq!(entry.kind, "bool");
        assert_eq!(entry.group, "device");
        assert_eq!(entry.tier, "standard");
        assert!(
            entry.restart_required,
            "read at service start: the Run-value sync and the launch-once"
        );
        assert_eq!(entry.default.as_deref(), Some("true"), "on by default");
        assert_eq!(
            current_value(&cfg, "companion_autostart").as_deref(),
            Some("true")
        );

        apply(&mut cfg, "companion_autostart", Some("false")).unwrap();
        assert_eq!(
            current_value(&cfg, "companion_autostart").as_deref(),
            Some("false")
        );
        apply(&mut cfg, "companion_autostart", Some(" ON ")).unwrap();
        assert_eq!(
            current_value(&cfg, "companion_autostart").as_deref(),
            Some("true")
        );

        apply(&mut cfg, "companion_autostart", Some("off")).unwrap();
        assert!(apply(&mut cfg, "companion_autostart", Some("sometimes")).is_err());
        assert_eq!(
            current_value(&cfg, "companion_autostart").as_deref(),
            Some("false"),
            "a rejected set is a no-op"
        );
        apply(&mut cfg, "companion_autostart", None).unwrap();
        assert_eq!(
            current_value(&cfg, "companion_autostart").as_deref(),
            Some("true"),
            "cleared = the built-in default, which is ON"
        );
    }
}

#[cfg(test)]
mod external_access_surface_tests {
    use super::{KEYS, apply};

    /// FR-52 — the credential half of the `external_*` surface is not editable
    /// here, and a NEW `external_*` key has to be defended deliberately.
    ///
    /// Both directions of this surface are the problem, and each is worse than
    /// it first looks:
    /// - `config get` lists every key **with its value**, so a registered
    ///   `external_access_verifier` is a credential printed on a terminal.
    /// - `config set` would let anyone who can reach the LocalAPI store a record
    ///   they generated themselves — and the pipe admits the **interactive
    ///   user**, not just an admin. That is gate 4 replaced by a stranger's
    ///   password without knowing the old one, which is the one thing the gate
    ///   exists to make impossible.
    ///
    /// ⚠️ The allowlist, not a pair of `assert!(absent)` lines, is the point. The
    /// two keys that exist today are excluded by **omission** — nothing stops the
    /// next `external_*` field from being registered for symmetry, and the key
    /// that matters is always the one added after the test was written. This is
    /// the same shape as the `DesiredConfig` prefix guard for the same reason.
    #[test]
    fn no_external_credential_key_is_editable_through_the_config_surface() {
        /// `external_*` keys an operator MAY edit on their own device. A new
        /// `external_*` key fails this test until it is added here, which is the
        /// moment to ask whether it is a setting or a secret.
        const EDITABLE_EXTERNAL_KEYS: &[&str] = &[
            "external_access_enabled",
            "external_consent_mode",
            "external_max_permissions",
        ];

        let registered: Vec<&str> = KEYS
            .iter()
            .map(|m| m.key)
            .filter(|k| k.starts_with("external"))
            .collect();
        for key in &registered {
            assert!(
                EDITABLE_EXTERNAL_KEYS.contains(key),
                "`{key}` is on the editable config surface. If it is a SETTING, add it to \
                 EDITABLE_EXTERNAL_KEYS. If it is any part of the password record, it must not be \
                 here at all — `config get` would print it and `config set` would let the \
                 interactive user choose the password. Set it with `roomler rc password set`."
            );
        }

        // And the two that exist today, named explicitly, so the failure message
        // points straight at them if someone registers them.
        for key in ["external_access_setup", "external_access_verifier"] {
            assert!(
                !registered.contains(&key),
                "`{key}` is part of the OPAQUE record and must never be on this surface"
            );
            // `apply` is the write half — belt and braces, because a key could
            // be handled there without appearing in `KEYS`, and then it would be
            // settable while staying invisible to `config ls`.
            let mut cfg = crate::config::test_fixture();
            assert!(
                apply(&mut cfg, key, Some("anything")).is_err(),
                "`{key}` must be unsettable through `apply`, listed or not"
            );
        }
    }

    /// FR-52 P4 — the device's terms for an external session are validated
    /// when they are SET: the session path refuses what it cannot read (never
    /// falls back), so a typo accepted here would be external access that
    /// silently never works, found weeks later on a device nobody is watching.
    #[test]
    fn the_external_session_terms_are_validated_when_set() {
        let mut cfg = crate::config::test_fixture();

        for good in ["prompt", "auto", " auto "] {
            apply(&mut cfg, "external_consent_mode", Some(good)).unwrap();
            assert_eq!(cfg.external_consent_mode.as_deref(), Some(good.trim()));
        }
        for bad in ["Auto", "always", "yes"] {
            assert!(
                apply(&mut cfg, "external_consent_mode", Some(bad)).is_err(),
                "{bad:?}"
            );
        }
        apply(&mut cfg, "external_consent_mode", Some("  ")).unwrap();
        assert_eq!(cfg.external_consent_mode, None, "blank clears: prompt");

        apply(&mut cfg, "external_max_permissions", Some("input|VIEW")).unwrap_err();
        apply(&mut cfg, "external_max_permissions", Some("INPUT|VIEW")).unwrap();
        assert_eq!(
            cfg.external_max_permissions.as_deref(),
            Some("VIEW | INPUT"),
            "stored in the spelling the session path reads"
        );
        for bad in ["VIEW | TELEPORT", "|", " | "] {
            assert!(
                apply(&mut cfg, "external_max_permissions", Some(bad)).is_err(),
                "{bad:?}"
            );
        }
        apply(&mut cfg, "external_max_permissions", None).unwrap();
        assert_eq!(
            cfg.external_max_permissions, None,
            "clears: defer to the org"
        );
    }
}
