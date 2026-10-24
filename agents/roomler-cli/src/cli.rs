// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! `roomler` — TeamViewer-style native tunnel client.
//!
//! Forwards a local TCP port over a WebRTC P2P data channel to an
//! enrolled `roomlerd`, which dials the corresponding intranet
//! destination. The Roomler API is signalling-only — payload never
//! touches the server.
//!
//! CLI surface:
//!
//!   roomler enroll --server <url> --token <enrollment-jwt> --name <label>
//!   roomler forward --agent <agent_id> --local <port> --remote <host:port>
//!   roomler run [--config <path>]
//!   roomler diagnose [--agent <agent_id>]
//!   roomler status [--json]     # local daemon's node state (LocalAPI)
//!   roomler peers  [--json] [--display-name] [NAME…]   # peers + connection types (LocalAPI)
//!   roomler devices [--json]    # the devices this one may see, server-listed (LocalAPI)
//!   roomler flows  [--json]     # active forwards / SOCKS5 (LocalAPI)

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

use crate::{config, forward, localclient, mesh, update};

/// CLI transport shim — the parsed `--transport` value. The real preference
/// enum (`tunnel_core::driver::TransportPref`) is clap-free (so the driver
/// crate needn't depend on clap); this mirrors its variants for the CLI and
/// converts into it at dispatch. Wire values are lowercase (`auto`/`quic`/
/// `webrtc`), matching the pre-refactor `#[value(rename_all = "lowercase")]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
#[value(rename_all = "lowercase")]
enum CliTransport {
    #[default]
    Auto,
    Quic,
    Webrtc,
}

impl From<CliTransport> for forward::TransportPref {
    fn from(t: CliTransport) -> Self {
        match t {
            CliTransport::Auto => forward::TransportPref::Auto,
            CliTransport::Quic => forward::TransportPref::Quic,
            CliTransport::Webrtc => forward::TransportPref::Webrtc,
        }
    }
}

impl CliTransport {
    /// The lowercase wire word the daemon's LocalAPI `create_*` verbs expect.
    fn as_word(self) -> &'static str {
        match self {
            CliTransport::Auto => "auto",
            CliTransport::Quic => "quic",
            CliTransport::Webrtc => "webrtc",
        }
    }
}

#[derive(Debug, Parser)]
#[command(name = "roomler", version, about, long_about = None)]
struct Cli {
    // RETIRED-NAME-ANCHOR(4): the config segment is frozen — it holds the
    // ENROLLED credential on tunnel-only hosts, and renaming it strands
    // every one of them. agents/roomler-cli/src/config.rs
    /// Override config file location. Defaults to the platform config dir
    /// (`%APPDATA%\roomler\roomler-tunnel\config.toml` on Windows,
    /// `~/.config/roomler-tunnel/config.toml` on Linux, the equivalent on
    /// macOS via the `directories` crate).
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// SSH to one explicitly shared device, using the approved recipient account.
    /// No org enrollment, overlay membership or OS SSH server is required.
    /// SSH itself retains the selected OS account's powers, not a sandbox.
    ShareSsh {
        #[arg(long, default_value = "https://www.itachi.fans/meshharbor")]
        server: String,
        #[arg(long)]
        share: String,
        /// File containing a valid recipient access JWT; never passed in argv/URL.
        #[arg(long, required_unless_present = "login", conflicts_with = "login")]
        access_token_file: Option<PathBuf>,
        /// Prompt for account password without echo; Access JWT stays in memory.
        /// No browser-cookie export, refresh, persistent login or MFA downgrade.
        #[arg(long, requires = "username", conflicts_with = "access_token_file")]
        login: bool,
        #[arg(long, requires = "login")]
        username: Option<String>,
        #[arg(long, default_value_t = 0)]
        session_secs: u64,
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Enroll this laptop against a Roomler server using an admin-issued
    /// tunnel-enrollment token. Writes the long-lived `TunnelClient` JWT
    /// to the config file. Mirrors `roomlerd enroll`.
    Enroll {
        /// Base URL of the Roomler API (e.g. https://roomler.ai).
        #[arg(long)]
        server: String,
        /// Tunnel-enrollment token, as printed by the admin UI.
        #[arg(long)]
        token: String,
        /// Friendly name shown in the admin tunnel-clients list.
        #[arg(long)]
        name: String,
    },
    /// Open one TCP forward: listen on `--local`, accept TCP connections,
    /// dial `--remote` from the named agent's host. Stays in the
    /// foreground; Ctrl-C tears down.
    Forward {
        /// Hex `agent_id` of the target agent (visible in the admin UI).
        #[arg(long)]
        agent: String,
        /// Local TCP port to listen on (bound to 127.0.0.1).
        #[arg(long)]
        local: u16,
        /// Remote destination `host:port` that the agent dials. Subject
        /// to the agent's allowlist + the tenant's tunnel_policies.
        #[arg(long)]
        remote: String,
        /// Data-plane transport. `auto` (default) prefers QUIC and
        /// transparently falls back to WebRTC if QUIC setup fails;
        /// `quic` forces QUIC (no fallback); `webrtc` forces the proven
        /// WebRTC DataChannel path. Server-side QUIC negotiation is
        /// deployed and gates on the agent's reported version, so `auto`
        /// only attempts QUIC against agents that actually support it.
        #[arg(long, value_enum, default_value = "auto")]
        transport: CliTransport,
        /// Hand the forward to the LOCAL daemon over the LocalAPI instead of
        /// running it in this process: the daemon opens it over its own agent
        /// WS (no tunnel-client token needed) + supervises it, and this command
        /// returns immediately. The flow survives this CLI's exit — manage it
        /// with `flows` / `kill`. (Becomes the default at the P3d rename.)
        #[arg(long)]
        daemon: bool,
        /// FR-86 P2 TEST LEVER (`--daemon` only) — force the daemon's FIRST
        /// session onto this transport (e.g. `webrtc`) so an `auto` flow starts
        /// on a below-best carrier the make-before-break re-upgrade probe then
        /// upgrades, without restarting any daemon. Later sessions and the probe
        /// behave as `auto`. Omit for normal operation.
        #[arg(long, value_enum)]
        start_transport: Option<CliTransport>,
    },
    /// Run a local SOCKS5 proxy ("userspace mode"): apps point at
    /// `127.0.0.1:<local>` and each connection's SOCKS5 CONNECT target is dialed
    /// by the named agent over the tunnel. Needs NO OS routing, so it works on
    /// strict full-tunnel corporate VPNs (Check Point, etc.) where the L3 overlay
    /// can't win the routing table. Same server policy + agent allowlist as
    /// `forward`. Stays in the foreground; Ctrl-C tears down. TCP CONNECT only.
    Socks5 {
        /// Hex `agent_id` of the target agent. OMIT for **mesh mode**: one proxy
        /// reaches the whole tenant, addressing an agent by its 24-hex id as the
        /// SOCKS hostname (`--socks5-hostname <agent-id>:<port>`).
        #[arg(long)]
        agent: Option<String>,
        /// Local TCP port for the SOCKS5 listener (bound to 127.0.0.1).
        #[arg(long)]
        local: u16,
        /// Data-plane transport — same semantics as `forward` (`auto` prefers
        /// QUIC with WebRTC-DC fallback).
        #[arg(long, value_enum, default_value = "auto")]
        transport: CliTransport,
        /// Hand the listener to the LOCAL daemon over the LocalAPI (see
        /// `forward --daemon`). Requires `--agent` (daemon mesh mode is a later
        /// slice); returns immediately, manage with `flows` / `kill`.
        #[arg(long)]
        daemon: bool,
    },
    /// Stop a daemon-run forward / SOCKS5 listener by its flow id (from
    /// `flows`). Talks to the LOCAL daemon over the LocalAPI — no config/token.
    Kill {
        /// Flow id to stop (as shown in the `flows` `ID` column).
        id: String,
    },
    /// Manage DECLARED routes — daemon-supervised forwards / SOCKS5
    /// listeners persisted in the daemon's config: they come back on
    /// every daemon start (and reboot) until removed. The persistent
    /// counterpart of the ephemeral `forward --daemon` flow (P6).
    Route {
        #[command(subcommand)]
        action: RouteAction,
    },
    /// Read a multi-forward config from disk and run all forwards as
    /// persistent listeners. Superseded by daemon-supervised declared
    /// routes — use `route add` instead; never wired.
    Run {},
    /// Probe path-MTU, ICE candidate reachability, and TURN-relay status
    /// against the named agent. Prints a structured diagnostic dump.
    /// T3 implementation.
    Diagnose {
        #[arg(long)]
        agent: Option<String>,
    },
    /// Check for a newer roomler CLI release and self-replace the running
    /// binary (Windows). Mirrors `roomlerd self-update`.
    SelfUpdate {
        /// Only check + report whether an update is available; don't install.
        #[arg(long)]
        check: bool,
    },
    /// Show the local daemon's node state (id, version, mode, overlay IP,
    /// server connection) over the LocalAPI. Read-only; needs no config/token —
    /// the OS pipe/socket ACL is the trust boundary.
    Status {
        #[command(flatten)]
        fmt: OutputFmt,
    },
    /// Tail a daemon log, resolved BY the daemon — the path differs per process
    /// and per platform, and two of the candidates on a Windows host are decoys.
    /// Pairs with Fleet RPC: `roomler exec <host> -- roomler logs --grep ICE`.
    Logs {
        /// Which log: `daemon` (this process's rolling log — the one with the
        /// overlay/media events), `service` (the SCM host log), or `panic`
        /// (the newest panic dump).
        #[arg(long, default_value = "daemon")]
        source: String,
        /// Tail size in bytes; the daemon clamps it (≤64 KiB).
        #[arg(long)]
        max_bytes: Option<u64>,
        /// Case-insensitive substring filter applied to the returned tail.
        #[arg(long)]
        grep: Option<String>,
        /// Keep only the last N lines (applied after `--grep`; the transport
        /// stays byte-bounded, so N is capped by `--max-bytes` worth of log).
        #[arg(short = 'n', long)]
        lines: Option<usize>,
        #[command(flatten)]
        fmt: OutputFmt,
    },
    /// List the peers the local daemon currently sees, with each peer's live
    /// connection type (direct / relay / tunnel / blocked / offline).
    ///
    /// `roomler peers --display-name` puts the dashboard display names in
    /// NAME; `roomler peers laptop "Office PC"` shows only those two, in
    /// that order — each a mesh name or a display name.
    Peers {
        /// FR-49 - show only this enrollment (`roomlerd org ls`; `primary` for
        /// the scalar identity). Without it every org's peers are printed
        /// together, which on a device enrolled in a customer org and a
        /// personal one is unusable on a shared screen or in a bug report.
        #[arg(long)]
        org: Option<String>,
        /// Show each peer's dashboard display name in NAME (the mesh name
        /// where a device has none), joined from the org's device list. When
        /// that list is unavailable the mesh names are shown and one warning
        /// says so. With `--json`, adds a `display_name` field to every peer
        /// (null when unknown); without this flag the JSON is unchanged.
        #[arg(long)]
        display_name: bool,
        /// Only these peers — each a mesh name or a dashboard display name,
        /// case-insensitive — in the order given. A name that matches nothing
        /// is warned about; the command fails only when none matched.
        #[arg(value_name = "NAME")]
        names: Vec<String>,
        #[command(flatten)]
        fmt: OutputFmt,
    },
    /// List the devices this device's private network lets it see — itself
    /// included — as the SERVER records them: display names, OS, version,
    /// presence, overlay IP and MagicDNS, with this node's live carrier in
    /// CONN. Search, sort and paging run on the server; the local daemon asks
    /// it with this device's own credentials (FR-84).
    ///
    ///   roomler devices
    ///   roomler devices -q build --sort last_seen_at --desc
    Devices {
        /// Enrollment to list (`roomlerd org ls`; `primary` for the scalar
        /// identity). Default: the primary.
        #[arg(long)]
        org: Option<String>,
        /// Search text (name, display name, tags, OS, version, overlay IP,
        /// MagicDNS), matched by the server.
        #[arg(short = 'q', long = "query")]
        q: Option<String>,
        /// Sort key: name | kind | os | status | version | overlay_ip |
        /// magic_dns | last_seen_at. Default: online first, then name.
        #[arg(long)]
        sort: Option<String>,
        /// Sort descending.
        #[arg(long)]
        desc: bool,
        /// Page number (1-based).
        #[arg(long, default_value_t = 1)]
        page: u64,
        /// Rows per page (the server caps it at 100).
        #[arg(long, default_value_t = 50)]
        per_page: u64,
        #[command(flatten)]
        fmt: OutputFmt,
    },
    /// Explain why ONE peer rides the carrier it rides: the tier ladder with
    /// each tier's eligibility and score, and any hold-down that is
    /// overriding the raw ranking (a demote-follow window, a server DERP pin,
    /// a probe in flight).
    ///
    /// Accepts a device name (or a unique part of one), an overlay IP, or a
    /// node id — whatever you can read out of `roomler peers`.
    Why {
        /// Peer to explain: name / name fragment / overlay IP / node id.
        peer: String,
        #[command(flatten)]
        fmt: OutputFmt,
    },
    /// Show this node's measured network capability vector (overlay v3
    /// netcheck): STUN reachability, the raw relay-band verdict the dialer
    /// role keys on, `/derp` floor health, NAT class, and the measurement's
    /// age. `None`/absent until the first probe completes (~45 s after the
    /// daemon starts).
    Netcheck {
        #[command(flatten)]
        fmt: OutputFmt,
    },
    /// List the local daemon's active forwards / SOCKS5 listeners + throughput.
    /// (Empty until the tunnel data plane folds into the daemon — P3b.)
    Flows {
        #[command(flatten)]
        fmt: OutputFmt,
    },
    /// Rename this device via the running daemon: the daemon persists the new
    /// name to its OWN config (profile-correct even under a SYSTEM service —
    /// no elevation needed) and announces it on the next server reconnect.
    Rename {
        /// The new device name (trimmed; max 64 characters).
        name: String,
    },
    /// Read / edit this device's advanced configuration via the running
    /// daemon (S2 config surface): overlay knobs, subnet routes, update
    /// policy, encoder preference. The daemon validates per key and
    /// persists to its OWN config (profile-correct even under a SYSTEM
    /// service). Most changes take effect on the next daemon restart; `ls`
    /// shows which apply at once.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Record this device's screen to an HQ MP4 in the recordings folder
    /// (FR-85). Change the folder with `roomler config set record_dir <path>`.
    /// The daemon runs the recorder; only the person at the console may
    /// start, stop or delete a recording.
    Record {
        #[command(subcommand)]
        action: RecordAction,
    },
    /// Keep busy (FR-92): moves this computer's pointer in a pattern to keep
    /// it active (no screensaver, idle lock or "Away"), and pauses by itself
    /// whenever someone uses the computer. Turn it on from a remote-desktop
    /// session, or here as the person at this computer; anyone may stop it.
    #[command(name = "keep-busy")]
    KeepBusy {
        #[command(subcommand)]
        action: KeepBusyAction,
    },
    /// FR-90 — Claude Code sessions you run in a terminal, adopted into
    /// Roomler: mirrored by this device and shown to you alone, read-only.
    Hive {
        #[command(subcommand)]
        action: HiveAction,
    },
    /// Restart the local daemon through the service manager that runs it —
    /// the companion's "Apply now" (FR-84), for changes `config ls` marks as
    /// needing a restart.
    ///
    /// The daemon decides, and this exits non-zero when it refuses: it
    /// restarts only under a supervisor it can prove (a Windows service or
    /// scheduled task, systemd, launchd) — a hand-started `roomlerd run` is
    /// never taken offline — at most once every 30 s, and never while
    /// `local_restart_enabled` is off or a recording is running. Then waits
    /// (up to 60 s) until the NEW daemon answers, starting the scheduled task
    /// itself where that is how the daemon comes back.
    ///
    ///   roomler restart --reason "applied overlay settings"
    Restart {
        /// Why — written to the daemon's log and its restart record.
        #[arg(long, default_value = "")]
        reason: String,
        /// Return as soon as the daemon has accepted, without waiting for the
        /// new one (the relaunch is then the supervisor's alone).
        #[arg(long)]
        no_wait: bool,
    },
    /// Remote-control settings for THIS device — the gates whose last word
    /// belongs to whoever is at the machine, not to the organization.
    Rc {
        #[command(subcommand)]
        action: RcAction,
    },
    /// ICMP-ping an overlay peer (by name or IP) over the userspace netstack —
    /// the OS-free reachability probe. Only meaningful when the local daemon runs
    /// in netstack mode (a locked-down host with no OS route to the mesh).
    ///
    /// `roomler ping build-box` — or, by dashboard display name,
    /// `roomler ping "Office PC"`.
    Ping {
        /// Overlay peer to ping — a mesh name (e.g. `build-box`), a dashboard
        /// display name, or an overlay IP (either family;
        /// `fd72:6f6f:6d6c::<v4>` is the derived overlay IPv6). A display name
        /// is looked up in the org's device list only when no mesh name
        /// matches it, and refused when two devices share it; the typed name
        /// is what the output line shows.
        target: String,
        /// Round-trip timeout in milliseconds.
        #[arg(long, default_value_t = 3000)]
        timeout_ms: u64,
        /// Ping the peer's derived overlay IPv6 instead of its IPv4 (name
        /// targets only; a literal IP already picks its own family).
        #[arg(short = '6', long = "ipv6")]
        prefer_v6: bool,
        #[command(flatten)]
        fmt: OutputFmt,
    },
    /// Run a command on another device in this organization (Fleet RPC).
    ///
    /// The local daemon relays it over its own server connection, so no
    /// separate login is needed — but the SERVER decides, not this CLI:
    /// the org kill-switch, your EXEC_DEVICE permission, the target's
    /// policy, and the target's own `exec_enabled` key must all allow it,
    /// and this device must be marked as permitted to originate.
    ///
    /// Commands run privileged — root under systemd; on Windows SYSTEM, through
    /// the device's service, once an administrator anchored it
    /// (`roomlerd anchor create`), and otherwise the console-session worker
    /// (the signed-in user on an attended install, SYSTEM in SystemContext
    /// mode). Every attempt is audited, with the identity that ran it.
    ///
    /// `roomler exec build-box -- uptime` — or, by dashboard display name,
    /// `roomler exec "Office PC" -- hostname`.
    Exec {
        /// Target device — a device name (e.g. `build-box`), a dashboard
        /// display name, or a hex agent id. A display name is resolved from
        /// the org's device list only when no device NAME matches it, and
        /// refused when two devices share it — the server then resolves and
        /// gates whatever is sent, exactly as before.
        device: String,
        /// `pwsh` | `powershell` | `cmd` | `bash` | `sh`. Default: the
        /// target host's own default shell.
        #[arg(long, default_value = "")]
        shell: String,
        /// Command timeout in seconds on the target (max 300).
        #[arg(long, default_value_t = 30)]
        timeout: u64,
        #[command(flatten)]
        fmt: OutputFmt,
        /// The command. Put it after `--` so its own flags aren't parsed
        /// by roomler: `roomler exec winhost-a -- Get-NetRoute -AddressFamily IPv4`
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Open an SSH session to another device in this org, over the overlay.
    ///
    /// No `sshd` and no open port on the target: the roomler daemon there
    /// intercepts the connection below the OS. The session itself runs through
    /// your system `ssh` — roomler supplies a single-use identity, the address,
    /// and the target's host key, then gets out of the way.
    ///
    /// The host key is VERIFIED, never trusted on first use. If the server has
    /// no key for the device, this refuses to connect.
    ///
    ///   roomler ssh winhost-a
    ///   roomler ssh winhost-a -- uptime
    ///
    /// A dashboard display name works too: `roomler ssh "Office PC"`.
    Ssh {
        /// Target device — a device name (e.g. `build-box`), a dashboard
        /// display name, or a hex agent id. Resolved like `exec`'s: a display
        /// name counts only when no device NAME matches it, and one that two
        /// devices share is refused rather than guessed.
        device: String,
        /// Session lifetime in seconds. 0 = the server's ceiling.
        #[arg(long, default_value_t = 0)]
        session_secs: u64,
        /// Anything after `--` is passed to `ssh` verbatim — a remote command,
        /// or extra client options: `roomler ssh box -- -v uptime`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Reach a database, an HTTP API, a Kubernetes API server or an SSH host
    /// as a vault secret's user, through a local endpoint this device's
    /// daemon serves (FR-90 P3-9). The secret's value never leaves the
    /// daemon: your client connects to the endpoint with no credential, and
    /// the endpoint signs in upstream.
    ///
    /// It acts as this DEVICE'S OWNER, so only root or the account the daemon
    /// runs as may run it (on Windows: SYSTEM, an elevated administrator, or
    /// that account), and it serves the account that ran it, no other.
    /// It stays in the foreground: the endpoint lives while this runs, its
    /// leases renewed before they end. Ctrl-C closes it.
    ///
    ///   sudo roomler connect db/orders --engine postgres --upstream db.internal:5432
    ///   roomler connect ci/kube --engine kubernetes --upstream https://api.k8s.internal:6443 --auth bearer
    Connect {
        /// The secret: its path, or this organization's RRN, with no `#field`.
        handle: String,
        /// What the endpoint speaks.
        #[arg(long, value_parser = ["postgres", "mongodb", "http", "kubernetes", "ssh"])]
        engine: String,
        /// The upstream, exactly as the secret's `audiences` names it:
        /// `host:port` for a database, `https://host[:port]` for http and
        /// kubernetes, `ssh://[user@]host[:port]` for ssh.
        #[arg(long)]
        upstream: String,
        /// How `http` and `kubernetes` present the secret.
        #[arg(long, value_parser = ["basic", "bearer", "client-cert"])]
        auth: Option<String>,
        /// A database's: named in the connection string.
        #[arg(long)]
        database: Option<String>,
        /// A secret whose value is the upstream's CA (PEM).
        #[arg(long)]
        ca: Option<String>,
        /// MongoDB's: the database the secret's user is defined in.
        #[arg(long)]
        auth_source: Option<String>,
        /// Each lease's life in seconds (30 to 900; the daemon's default 300),
        /// renewed before it ends.
        #[arg(long)]
        ttl: Option<u32>,
        #[command(flatten)]
        fmt: OutputFmt,
    },
    /// stdio↔TCP pipe for OpenSSH's `ProxyCommand`, so stock `ssh`, `scp`,
    /// `rsync` and `git` can reach mesh devices BY NAME.
    ///
    ///   # ~/.ssh/config
    ///   Host *.roomler
    ///     ProxyCommand roomler proxy %h %p
    ///     Port 2222
    ///
    ///   scp report.pdf corplap-3.roomler:/tmp/
    ///
    /// A device is matched by its bare name, as <name>.roomler, or by its
    /// MagicDNS name. 2222 is roomler SSH's default port; drop the `Port`
    /// line to reach a device's own sshd on 22 instead.
    ///
    /// ⚠️ OpenSSH applies a `HostName` line BEFORE substituting %h, so a host
    /// that also has a `HostName` entry hands this its public address, not
    /// its name — a connect error naming no device (`scp -v` shows it).
    ///
    /// Transport and name resolution only: `ProxyCommand` cannot supply an
    /// identity or a host key, so this uses keys YOU manage. For a
    /// grant-issued session with the account resolved by policy and the host
    /// key verified for you, use `roomler ssh` instead.
    Proxy {
        /// Device name (bare, <name>.roomler, or MagicDNS) or overlay address
        /// (OpenSSH passes `%h`).
        host: String,
        /// Port (OpenSSH passes `%p`).
        port: u16,
    },
    /// Collect a standard diagnostic bundle from one or two devices and
    /// print it side by side.
    ///
    /// Distinct from `diagnose`, which probes MTU/ICE from THIS host. This
    /// one runs a canned, OS-appropriate evidence set ON the target devices
    /// via Fleet RPC — adapters, routes, firewall posture, overlay carrier
    /// state, recent overlay warnings — which is the evidence set a
    /// "why is this pair on relay?" question actually needs.
    Diag {
        #[command(subcommand)]
        action: DiagAction,
    },
}

/// `roomler diag …` — remote evidence bundles over Fleet RPC.
#[derive(Debug, Subcommand)]
enum DiagAction {
    /// Bundle from one device.
    Host {
        device: String,
        #[command(flatten)]
        fmt: OutputFmt,
    },
    /// Bundle from BOTH ends of a pair — the shape of the question
    /// "why can't these two reach each other directly?".
    Pair {
        a: String,
        b: String,
        #[command(flatten)]
        fmt: OutputFmt,
    },
}

/// Shared output flag for the read-only LocalAPI verbs (`status`/`peers`/
/// `flows`). `--json` emits the raw wire structs for scripting; omitted, a
/// human table is printed. Meaningless on `enroll`/`forward`, so it's flattened
/// only onto the three read verbs rather than made global.
#[derive(Debug, Args)]
struct OutputFmt {
    /// Emit raw JSON instead of a human-readable table.
    #[arg(long)]
    json: bool,
}

/// `roomler config …` — the S2 editable config surface. All verbs talk
/// to the LOCAL daemon over the LocalAPI; secrets are excluded by
/// construction, and the daemon says per key whether a change applies at
/// once or on the next restart.
#[derive(Debug, Subcommand)]
enum ConfigAction {
    /// List every editable key with its current value, type and whether a
    /// change applies live or on restart, grouped the way Settings shows them.
    Ls {
        #[command(flatten)]
        fmt: OutputFmt,
    },
    /// Set one key. Value formats: `true`/`false` for switches,
    /// comma-separated CIDRs for route lists, a JSON document for the
    /// structured keys (`forward_acl`, `virtual_desktop_apps`).
    Set {
        /// Config key (as shown by `config ls`).
        key: String,
        /// The new value.
        value: String,
    },
    /// Clear one key back to its built-in default.
    Clear {
        /// Config key (as shown by `config ls`).
        key: String,
    },
}

/// `roomler record …` — FR-85 local screen recording. Every verb talks to the
/// LOCAL daemon; `start`, `stop` and `rm` are refused unless the caller is the
/// console user (an RDP guest must not record the console user's desktop).
#[derive(Debug, Subcommand)]
enum HiveAction {
    /// Mirror the Claude Code sessions YOU run in a terminal on this machine
    /// into Roomler, where only you see them (read-only). Adds three hooks to
    /// your own user-level Claude Code settings and touches nothing else. The
    /// device's owner must allow it (`hive_adopt`) and map your account in
    /// `hive_accounts`.
    Adopt {
        /// The Claude Code settings file. Default: `/settings.json`,
        /// else `~/.claude/settings.json`.
        #[arg(long)]
        settings: Option<PathBuf>,
    },
    /// Take out exactly the hooks `adopt` put in; every other setting and hook
    /// stays.
    Unadopt {
        #[arg(long)]
        settings: Option<PathBuf>,
    },
    /// What Claude Code runs at those hooks: reads the hook's input on stdin
    /// and hands the session's new transcript lines to this device. Prints
    /// nothing; always exits 0.
    #[command(hide = true)]
    Hook,
}

#[derive(Debug, Subcommand)]
enum RecordAction {
    /// Start recording the screen. Answers once the recorder is encoding.
    Start {
        /// Frames per second (1–60). Default: 30.
        #[arg(long)]
        fps: Option<u32>,
        /// `auto` (hardware, then software) | `hardware` | `software`.
        #[arg(long)]
        encoder: Option<String>,
        /// Stop by itself after this many minutes. Default: 240.
        #[arg(long)]
        max_minutes: Option<u32>,
        /// Also record what the computer plays (Windows, Linux).
        #[arg(long)]
        system_audio: bool,
        /// Also record the microphone.
        #[arg(long)]
        microphone: bool,
        #[command(flatten)]
        fmt: OutputFmt,
    },
    /// Stop the recording. Answers once the file is final.
    Stop {
        #[command(flatten)]
        fmt: OutputFmt,
    },
    /// Whether a recording is running, and how the last one ended.
    Status {
        #[command(flatten)]
        fmt: OutputFmt,
    },
    /// The recordings folder and the recordings in it, newest first.
    Ls {
        #[command(flatten)]
        fmt: OutputFmt,
    },
    /// Delete a recording (and its sidecar) by file name.
    Rm {
        /// File name, as `record ls` shows it.
        name: String,
    },
}

#[derive(Debug, Subcommand)]
enum KeepBusyAction {
    /// Whether keep busy is on, what it is doing, and who turned it on.
    Status {
        #[command(flatten)]
        fmt: OutputFmt,
    },
    /// Stop keep busy on this computer.
    Off {
        #[command(flatten)]
        fmt: OutputFmt,
    },
    /// Turn keep busy on, as the person at this computer. Root, SYSTEM and
    /// services are refused, so `sudo roomler keep-busy on` is, and so is a
    /// SYSTEM shell. It stays on until someone turns it off, and resumes at
    /// your next login.
    On {
        /// The pattern: circle, triangle, square, star, figure8, heart,
        /// spirograph, lissajous, rose, wave, wander (the most human),
        /// subtle (an invisible nudge every ~45 s) or shuffle.
        #[arg(long)]
        pattern: Option<String>,
        /// The pattern's size: s, m or l.
        #[arg(long)]
        size: Option<String>,
        /// slow, normal or fast.
        #[arg(long)]
        speed: Option<String>,
        /// Seconds the computer must be left alone before it resumes after
        /// someone used it (default 30).
        #[arg(long = "resume-after", value_name = "SECONDS")]
        resume_after: Option<u64>,
        /// Turn itself off after this many minutes (default: never).
        #[arg(long = "auto-off", value_name = "MINUTES")]
        auto_off: Option<u64>,
        #[command(flatten)]
        fmt: OutputFmt,
    },
}

/// `roomler rc …` — this device's own remote-control settings.
#[derive(Debug, Subcommand)]
enum RcAction {
    /// The external-access password (FR-52 gate 4) — what lets someone
    /// OUTSIDE this device's organization control it, the way TeamViewer's
    /// unattended password does.
    Password {
        #[command(subcommand)]
        action: RcPasswordAction,
    },
}

/// `roomler rc password …` — set, clear or inspect the device-held password.
///
/// The password is registered by the daemon as an OPAQUE record and is not
/// readable back, by anyone, including this CLI and including the server. There
/// is deliberately no way to set it from the dashboard: a password typed into a
/// web form has already crossed the server, which is the one thing gate 4
/// exists to prevent.
#[derive(Debug, Subcommand)]
enum RcPasswordAction {
    /// Set (or change) it. Prompted twice and never echoed.
    ///
    /// ⚠️ There is deliberately **no** `--password <value>` flag. A process's
    /// argv is readable by other local users through `/proc/<pid>/cmdline` on
    /// Linux, and it lands in shell history; a flag would make the documented
    /// way to use this command the insecure one. Unattended setup pipes the
    /// password on stdin instead.
    Set {
        /// Read the password from stdin (one line) instead of prompting, for
        /// unattended setup: `printf '%s' "$PW" | roomler rc password set --stdin`.
        /// Only the line terminator is stripped.
        #[arg(long)]
        stdin: bool,
    },
    /// Forget it — closes gate 4 on this device. Nothing outside the
    /// organization can connect afterwards, whatever the org has approved.
    Clear,
    /// What this device believes about the gates it owns: is a password set, is
    /// external access switched on, and can this build hold one at all.
    Status {
        #[command(flatten)]
        fmt: OutputFmt,
    },
}

/// `roomler route …` — declared-route management (P6). All verbs talk to
/// the LOCAL daemon over the LocalAPI; the daemon persists changes into
/// its own config and reconciles them into live flows.
#[derive(Debug, Subcommand)]
enum RouteAction {
    /// Declare a supervised route. With `--remote` it's a static forward;
    /// without, a SOCKS5 listener toward the node.
    Add {
        /// Target agent id (24-hex) to reach.
        #[arg(long)]
        agent: String,
        /// Local loopback port to listen on.
        #[arg(long)]
        local: u16,
        /// Forward target `host:port` (as reachable FROM the agent).
        /// Omit for a SOCKS5 route.
        #[arg(long)]
        remote: Option<String>,
        /// Transport preference: auto (default) | quic | webrtc.
        #[arg(long, value_enum, default_value_t = CliTransport::Auto)]
        transport: CliTransport,
        /// Route id (slug shown in `route ls`); generated when omitted.
        #[arg(long)]
        id: Option<String>,
        /// Declare disabled (enable later with `route enable`).
        #[arg(long)]
        disabled: bool,
    },
    /// Remove a declared route (kills its live flow, deletes it from the
    /// daemon config).
    Rm {
        /// Route id (from `route ls`).
        id: String,
    },
    /// List declared routes with their live state (pending / connecting /
    /// active / retrying / backoff / failed / disabled). `active` means the
    /// local port is bound and serving.
    Ls {
        #[command(flatten)]
        fmt: OutputFmt,
    },
    /// Enable a declared route (also clears a terminal `failed` state).
    Enable {
        /// Route id (from `route ls`).
        id: String,
    },
    /// Disable a declared route without deleting it (kills its live flow).
    Disable {
        /// Route id (from `route ls`).
        id: String,
    },
    /// Edit a declared route in place (FR-84). The daemon replaces it in
    /// ONE step: an invalid edit is refused and the old route keeps
    /// running; a valid one restarts the route with the new settings.
    Edit {
        /// Route id (from `route ls`).
        id: String,
        /// New target agent id (24-hex).
        #[arg(long)]
        agent: Option<String>,
        /// New local loopback port.
        #[arg(long)]
        local: Option<u16>,
        /// New forward target `host:port` (turns a SOCKS5 route into a forward).
        #[arg(long, conflicts_with = "socks5")]
        remote: Option<String>,
        /// Make it a SOCKS5 route (drops the forward target).
        #[arg(long)]
        socks5: bool,
        /// New transport preference: auto | quic | webrtc.
        #[arg(long, value_enum)]
        transport: Option<CliTransport>,
    },
}

/// Which binary is hosting this command surface.
///
/// Only `self-update` branches on it today (see that arm), but it is the
/// honest place to hang any future "the daemon owns this concern" divergence
/// rather than sniffing argv[0] or an env var.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// The standalone `roomler` binary on a tunnel-only host.
    Standalone,
    /// Dispatched from `roomlerd cli` on a daemon host.
    EmbeddedInDaemon,
}

/// FR-84 D3 — the `roomlerd` binary `roomler restart` runs `service start`
/// with, when bringing the daemon back is the caller's job (the Windows
/// Scheduled Task). Embedded in the daemon — `roomlerd cli`, which is what the
/// installed `roomler` shim re-execs — that is this very executable;
/// standalone, a sibling, else whatever `roomlerd` PATH finds.
fn daemon_exe(origin: Origin) -> Option<PathBuf> {
    let me = std::env::current_exe().ok();
    if origin == Origin::EmbeddedInDaemon {
        return me;
    }
    let name = if cfg!(windows) {
        "roomlerd.exe"
    } else {
        "roomlerd"
    };
    if let Some(sibling) = me
        .as_deref()
        .and_then(std::path::Path::parent)
        .map(|dir| dir.join(name))
        .filter(|p| p.is_file())
    {
        return Some(sibling);
    }
    Some(PathBuf::from(name))
}

/// Entry point for the standalone `roomler` binary — parses the process's
/// own argv.
pub async fn run() -> Result<()> {
    run_from(std::env::args_os(), Origin::Standalone).await
}

/// Entry point for an EMBEDDED caller (P3e lever D): `roomlerd cli -- <args>`
/// dispatches here so a daemon host ships ONE copy of this CLI's code instead
/// of a second 22 MiB binary that is ~92 % the same crates. `args` follows the
/// usual convention — element 0 is the program name.
///
/// Logging init is `try_init` (not `init`) precisely because of that embedded
/// caller: `roomlerd` has already installed a global subscriber by the time it
/// reaches this dispatch, and `init()` PANICS on a second install. Ignoring an
/// `Err` here means "someone else already set logging up", which is exactly
/// right for both callers.
pub async fn run_from<I, T>(args: I, origin: Origin) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    // Rust starts with SIGPIPE ignored, so `roomler peers | head` PANICS with
    // "failed printing to stdout: Broken pipe" the moment `head` closes the
    // pipe (field-hit on buildhost, rc.368, via `roomlerd cli`). Restore the
    // normal Unix CLI contract — die quietly on EPIPE — for BOTH callers:
    // this entry is only ever a CLI invocation (the daemon's `run` path never
    // comes through here), so the process-wide reset is exactly scoped.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    let cli = Cli::parse_from(args);
    match cli.command {
        Command::Enroll {
            server,
            token,
            name,
        } => enroll_cmd(cli.config, server, token, name).await,
        Command::Forward {
            agent,
            local,
            remote,
            transport,
            daemon,
            start_transport,
        } => {
            if daemon {
                // Thin-client path: hand it to the local daemon over the
                // LocalAPI (no config/token — the pipe ACL is the boundary).
                // FR-86 P2 — the start-transport lever is a word ("" = none).
                localclient::create_forward(
                    &agent,
                    local,
                    &remote,
                    transport.as_word(),
                    start_transport.map(CliTransport::as_word).unwrap_or(""),
                )
                .await
            } else {
                if start_transport.is_some() {
                    anyhow::bail!(
                        "--start-transport requires --daemon (it is a daemon re-upgrade test lever)"
                    );
                }
                let mut cfg = config::load(cli.config.clone()).context("loading tunnel config")?;
                // FR-103 — renew a token that is due before dialling with it.
                crate::credential::renew_if_due(&mut cfg, cli.config.as_deref()).await;
                forward::run(cfg, &agent, local, &remote, transport.into()).await
            }
        }
        Command::Socks5 {
            agent,
            local,
            transport,
            daemon,
        } => {
            if daemon {
                let node = agent.context(
                    "--daemon socks5 requires --agent (daemon mesh mode is a later slice)",
                )?;
                localclient::create_socks5(&node, local, transport.as_word()).await
            } else {
                let mut cfg = config::load(cli.config.clone()).context("loading tunnel config")?;
                // FR-103 — renew a token that is due before dialling with it.
                crate::credential::renew_if_due(&mut cfg, cli.config.as_deref()).await;
                let transport = transport.into();
                match agent {
                    Some(agent) => forward::run_socks5(cfg, &agent, local, transport).await,
                    None => mesh::run_mesh(cfg, local, transport).await,
                }
            }
        }
        Command::Kill { id } => localclient::kill(&id).await,
        Command::Route { action } => match action {
            RouteAction::Add {
                agent,
                local,
                remote,
                transport,
                id,
                disabled,
            } => {
                localclient::route_add(
                    id.unwrap_or_default(),
                    &agent,
                    local,
                    remote,
                    transport.as_word(),
                    !disabled,
                )
                .await
            }
            RouteAction::Rm { id } => localclient::route_rm(&id).await,
            RouteAction::Ls { fmt } => localclient::route_ls(fmt.json).await,
            RouteAction::Enable { id } => localclient::route_set_enabled(&id, true).await,
            RouteAction::Disable { id } => localclient::route_set_enabled(&id, false).await,
            RouteAction::Edit {
                id,
                agent,
                local,
                remote,
                socks5,
                transport,
            } => {
                localclient::route_edit(localclient::RouteEdit {
                    id,
                    agent,
                    local,
                    remote,
                    socks5,
                    transport: transport.map(CliTransport::as_word),
                })
                .await
            }
        },
        Command::Run {} => bail!(
            "`run` was superseded by daemon-supervised declared routes — use `route add` \
             (persisted in the daemon config, restarts with the daemon)"
        ),
        Command::Diagnose { agent } => {
            bail!("T3: diagnose not yet wired (agent={:?})", agent);
        }
        Command::SelfUpdate { check } => {
            // "One updater per role" (see CLAUDE.md, P4c-2): tunnel-ONLY hosts
            // self-update this binary; daemon hosts get the whole node stack
            // refreshed by the MSI. Before P3e lever D that distinction was
            // only a convention — a daemon host running `roomler self-update`
            // would happily overwrite the MSI-owned roomler.exe out from under
            // the installer. Now it would ALSO swap the 150 KB shim for a
            // 22 MiB standalone CLI, silently undoing the lever. Refuse, and
            // name the right updater instead.
            if origin == Origin::EmbeddedInDaemon {
                bail!(
                    "`self-update` is not available on a daemon host — this `roomler` is a shim \
                     over the installed daemon, and the MSI updates the whole node stack \
                     (daemon + CLI + desktop companion) as a unit.\n\
                     Update with:  roomlerd self-update"
                );
            }
            let cfg = update::config_for_self_update(cli.config)?;
            update::self_update(&cfg, check).await
        }
        // Read-only LocalAPI verbs: no config/token — talk straight to the
        // local daemon over its ACL-gated pipe/socket.
        Command::Status { fmt } => localclient::status(fmt.json).await,
        Command::Logs {
            source,
            max_bytes,
            grep,
            lines,
            fmt,
        } => localclient::logs(source, max_bytes, grep, lines, fmt.json).await,
        Command::Peers {
            org,
            display_name,
            names,
            fmt,
        } => {
            localclient::peers(localclient::PeersArgs {
                org,
                display_name,
                names,
                json: fmt.json,
            })
            .await
        }
        Command::Devices {
            org,
            q,
            sort,
            desc,
            page,
            per_page,
            fmt,
        } => {
            localclient::devices(localclient::DevicesArgs {
                org,
                q,
                sort,
                desc,
                page,
                per_page,
                json: fmt.json,
            })
            .await
        }
        Command::Why { peer, fmt } => localclient::why(&peer, fmt.json).await,
        Command::Netcheck { fmt } => localclient::netcheck(fmt.json).await,
        Command::Flows { fmt } => localclient::flows(fmt.json).await,
        Command::Rename { name } => localclient::rename(&name).await,
        Command::Config { action } => match action {
            ConfigAction::Ls { fmt } => localclient::config_ls(fmt.json).await,
            ConfigAction::Set { key, value } => localclient::config_set(&key, Some(&value)).await,
            ConfigAction::Clear { key } => localclient::config_set(&key, None).await,
        },
        Command::Hive { action } => match action {
            HiveAction::Adopt { settings } => {
                crate::hive_hooks::adopt(settings, origin == Origin::EmbeddedInDaemon)
            }
            HiveAction::Unadopt { settings } => crate::hive_hooks::unadopt(settings),
            HiveAction::Hook => {
                crate::hive_hooks::hook().await;
                Ok(())
            }
        },
        Command::Record { action } => match action {
            RecordAction::Start {
                fps,
                encoder,
                max_minutes,
                system_audio,
                microphone,
                fmt,
            } => {
                localclient::record_start(
                    fps,
                    encoder,
                    max_minutes,
                    system_audio,
                    microphone,
                    fmt.json,
                )
                .await
            }
            RecordAction::Stop { fmt } => localclient::record_stop(fmt.json).await,
            RecordAction::Status { fmt } => localclient::record_status(fmt.json).await,
            RecordAction::Ls { fmt } => localclient::recordings_ls(fmt.json).await,
            RecordAction::Rm { name } => localclient::recording_rm(&name).await,
        },
        Command::KeepBusy { action } => match action {
            KeepBusyAction::Status { fmt } => localclient::keep_busy_status(fmt.json).await,
            KeepBusyAction::Off { fmt } => localclient::keep_busy_off(fmt.json).await,
            KeepBusyAction::On {
                pattern,
                size,
                speed,
                resume_after,
                auto_off,
                fmt,
            } => {
                localclient::keep_busy_on(
                    localclient::KeepBusyStart {
                        pattern,
                        size,
                        speed,
                        resume_after_s: resume_after,
                        auto_off_min: auto_off,
                    },
                    fmt.json,
                )
                .await
            }
        },
        Command::Restart { reason, no_wait } => {
            localclient::restart(&reason, no_wait, daemon_exe(origin)).await
        }
        Command::Rc { action } => match action {
            RcAction::Password { action } => match action {
                RcPasswordAction::Set { stdin } => localclient::rc_password_set(stdin).await,
                RcPasswordAction::Clear => localclient::rc_password_clear().await,
                RcPasswordAction::Status { fmt } => localclient::rc_password_status(fmt.json).await,
            },
        },
        Command::Ping {
            target,
            timeout_ms,
            prefer_v6,
            fmt,
        } => localclient::ping(&target, timeout_ms, prefer_v6, fmt.json).await,
        Command::Exec {
            device,
            shell,
            timeout,
            fmt,
            command,
        } => {
            localclient::exec(
                &device,
                &shell,
                &command.join(" "),
                timeout.saturating_mul(1000),
                fmt.json,
            )
            .await
        }
        Command::ShareSsh {
            server,
            share,
            access_token_file,
            login,
            username,
            session_secs,
            args,
        } => {
            let code = if login {
                crate::native_auth::interactive(
                    &server,
                    &share,
                    username.as_deref().context("--username required")?,
                    session_secs,
                    &args,
                )
                .await?
            } else {
                crate::share_sshcmd::run(
                    &server,
                    &share,
                    access_token_file.context("--access-token-file required")?,
                    session_secs,
                    &args,
                )
                .await?
            };
            match code {
                0 => Ok(()),
                code => std::process::exit(code),
            }
        }
        Command::Ssh {
            device,
            session_secs,
            args,
        } => {
            // Mirror ssh's own exit status, the same way `exec` mirrors the
            // remote command's — so `roomler ssh box -- false` composes in a
            // script instead of always looking successful.
            match crate::sshcmd::run(&device, session_secs, &args).await? {
                0 => Ok(()),
                code => std::process::exit(code),
            }
        }
        Command::Connect {
            handle,
            engine,
            upstream,
            auth,
            database,
            ca,
            auth_source,
            ttl,
            fmt,
        } => {
            let args = tunnel_core::localapi::ConnectArgs {
                handle,
                engine,
                upstream,
                auth,
                database,
                ca,
                auth_source,
                ttl_s: ttl,
            };
            crate::connectcmd::run(args, fmt.json).await
        }
        Command::Proxy { host, port } => crate::sshcmd::proxy(&host, port).await,
        Command::Diag { action } => match action {
            DiagAction::Host { device, fmt } => localclient::diag_bundle(&[device], fmt.json).await,
            DiagAction::Pair { a, b, fmt } => localclient::diag_bundle(&[a, b], fmt.json).await,
        },
    }
}

/// `roomler enroll` — exchange a tunnel-enrollment JWT for a
/// long-lived `TunnelClient` JWT via the server, then persist server
/// URL + token to the local config file.
async fn enroll_cmd(
    cfg_path: Option<PathBuf>,
    server_url: String,
    enrollment_token: String,
    machine_name: String,
) -> Result<()> {
    // FR-101 P1b — the enrollment token travels over TLS, as the agent's does:
    // a remote `http://` URL is posted to, and saved, as `https://`.
    let server_url = config::enrollment_server_url(&server_url);
    let enroll_url = format!("{server_url}/api/tunnel-client/enroll");
    let body = serde_json::json!({
        "enrollment_token": enrollment_token,
        "machine_name": machine_name,
        "machine_id": derive_machine_id(&machine_name),
        // The server's TunnelEnrollRequest requires `os` (OsKind,
        // snake_case) + `client_version`. `std::env::consts::OS` already
        // yields the exact wire values ("windows" / "linux" / "macos").
        // Without these the enroll fails with HTTP 422 "missing field".
        "os": std::env::consts::OS,
        "client_version": env!("CARGO_PKG_VERSION"),
    });
    let resp = reqwest::Client::new()
        .post(&enroll_url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {enroll_url}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("enrollment failed (HTTP {status}): {body}");
    }
    #[derive(serde::Deserialize)]
    struct EnrollResponse {
        tunnel_client_token: String,
    }
    let parsed: EnrollResponse = resp.json().await.context("parsing enrollment response")?;

    let cfg = config::TunnelConfig {
        server_url,
        tunnel_client_token: parsed.tunnel_client_token,
        machine_name,
        allow_plaintext_server: false,
    };
    let path = config::save(&cfg, cfg_path.as_deref()).context("saving tunnel config")?;
    println!("Enrolled. Config written to {}", path.display());
    Ok(())
}

/// Hash `machine_name` + the hostname to a hex-encoded blob the server
/// uses to dedupe re-enrollments from the same host. Mirrors the
/// agent's `derive_machine_id` shape (lowercase 16-hex of the SHA-256).
fn derive_machine_id(machine_name: &str) -> String {
    use sha2::{Digest, Sha256};
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
    use clap::Parser;

    #[test]
    fn parses_forward() {
        let cli = Cli::try_parse_from([
            "roomler",
            "forward",
            "--agent",
            "507f1f77bcf86cd799439011",
            "--local",
            "5432",
            "--remote",
            "10.0.0.5:5432",
        ])
        .unwrap();
        match cli.command {
            Command::Forward {
                agent,
                local,
                remote,
                transport,
                daemon,
                start_transport,
            } => {
                assert_eq!(agent, "507f1f77bcf86cd799439011");
                assert_eq!(local, 5432);
                assert_eq!(remote, "10.0.0.5:5432");
                // No --transport given → default is auto (prefer QUIC,
                // fall back to WebRTC on setup failure).
                assert_eq!(transport, CliTransport::Auto);
                // No --daemon → in-process standalone (the current default).
                assert!(!daemon);
                // No --start-transport → no FR-86 P2 first-session override.
                assert_eq!(start_transport, None);
            }
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    #[test]
    fn parses_forward_transport_quic() {
        let cli = Cli::try_parse_from([
            "roomler",
            "forward",
            "--agent",
            "507f1f77bcf86cd799439011",
            "--local",
            "5432",
            "--remote",
            "10.0.0.5:5432",
            "--transport",
            "quic",
        ])
        .unwrap();
        match cli.command {
            Command::Forward { transport, .. } => {
                assert_eq!(transport, CliTransport::Quic);
            }
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    #[test]
    fn parses_forward_transport_auto() {
        let cli = Cli::try_parse_from([
            "roomler",
            "forward",
            "--agent",
            "507f1f77bcf86cd799439011",
            "--local",
            "5432",
            "--remote",
            "10.0.0.5:5432",
            "--transport",
            "auto",
        ])
        .unwrap();
        match cli.command {
            Command::Forward { transport, .. } => {
                assert_eq!(transport, CliTransport::Auto);
            }
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    #[test]
    fn parses_socks5() {
        let cli = Cli::try_parse_from([
            "roomler",
            "socks5",
            "--agent",
            "507f1f77bcf86cd799439011",
            "--local",
            "1080",
        ])
        .unwrap();
        match cli.command {
            Command::Socks5 {
                agent,
                local,
                transport,
                daemon,
            } => {
                assert_eq!(agent.as_deref(), Some("507f1f77bcf86cd799439011"));
                assert_eq!(local, 1080);
                assert_eq!(transport, CliTransport::Auto);
                assert!(!daemon);
            }
            other => panic!("expected Socks5, got {other:?}"),
        }
    }

    #[test]
    fn parses_socks5_mesh_without_agent() {
        let cli = Cli::try_parse_from(["roomler", "socks5", "--local", "1080"]).unwrap();
        match cli.command {
            Command::Socks5 { agent, local, .. } => {
                assert_eq!(agent, None); // mesh mode
                assert_eq!(local, 1080);
            }
            other => panic!("expected Socks5, got {other:?}"),
        }
    }

    #[test]
    fn parses_forward_daemon_flag() {
        let cli = Cli::try_parse_from([
            "roomler",
            "forward",
            "--agent",
            "507f1f77bcf86cd799439011",
            "--local",
            "5432",
            "--remote",
            "10.0.0.5:5432",
            "--daemon",
        ])
        .unwrap();
        match cli.command {
            Command::Forward { daemon, .. } => assert!(daemon),
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    #[test]
    fn parses_kill_verb() {
        let cli = Cli::try_parse_from(["roomler", "kill", "fl-7"]).unwrap();
        match cli.command {
            Command::Kill { id } => assert_eq!(id, "fl-7"),
            other => panic!("expected Kill, got {other:?}"),
        }
    }

    #[test]
    fn transport_as_word_matches_localapi_wire() {
        assert_eq!(CliTransport::Auto.as_word(), "auto");
        assert_eq!(CliTransport::Quic.as_word(), "quic");
        assert_eq!(CliTransport::Webrtc.as_word(), "webrtc");
    }

    #[test]
    fn parses_enroll() {
        let cli = Cli::try_parse_from([
            "roomler",
            "enroll",
            "--server",
            "https://roomler.ai",
            "--token",
            "eyJhbGciOiJIUzI1NiJ9.payload.sig",
            "--name",
            "example-laptop",
        ])
        .unwrap();
        match cli.command {
            Command::Enroll {
                server,
                token,
                name,
            } => {
                assert_eq!(server, "https://roomler.ai");
                assert_eq!(token, "eyJhbGciOiJIUzI1NiJ9.payload.sig");
                assert_eq!(name, "example-laptop");
            }
            other => panic!("expected Enroll, got {other:?}"),
        }
    }

    #[test]
    fn derive_machine_id_is_deterministic() {
        let a = derive_machine_id("test-name");
        let b = derive_machine_id("test-name");
        assert_eq!(a, b);
        assert_eq!(a.len(), 32); // 16 bytes hex-encoded
    }

    #[test]
    fn derive_machine_id_changes_with_name() {
        assert_ne!(derive_machine_id("a"), derive_machine_id("b"));
    }

    #[test]
    fn parses_status_peers_flows() {
        for verb in ["status", "peers", "flows"] {
            let cli = Cli::try_parse_from(["roomler", verb]).unwrap();
            match (verb, cli.command) {
                ("status", Command::Status { fmt }) => assert!(!fmt.json),
                (
                    "peers",
                    Command::Peers {
                        org,
                        display_name,
                        names,
                        fmt,
                    },
                ) => {
                    assert!(!fmt.json);
                    // FR-49 - absent means "every org", never "the primary".
                    assert!(org.is_none());
                    // The default table is the mesh-name table, unfiltered.
                    assert!(!display_name);
                    assert!(names.is_empty());
                }
                ("flows", Command::Flows { fmt }) => assert!(!fmt.json),
                (v, other) => panic!("verb {v} parsed as {other:?}"),
            }
        }
    }

    /// `peers --display-name NAME…` — the flag, the positional filter (in
    /// order, spaces and all), `--org` and `--json` together; and the filter
    /// alone, without the flag.
    #[test]
    fn parses_peers_display_names_and_filter() {
        let cli = Cli::try_parse_from([
            "roomler",
            "peers",
            "--org",
            "acme",
            "--display-name",
            "laptop",
            "Office PC",
            "--json",
        ])
        .unwrap();
        match cli.command {
            Command::Peers {
                org,
                display_name,
                names,
                fmt,
            } => {
                assert_eq!(org.as_deref(), Some("acme"));
                assert!(display_name);
                assert_eq!(names, ["laptop", "Office PC"]);
                assert!(fmt.json);
            }
            other => panic!("expected Peers, got {other:?}"),
        }
        match Cli::try_parse_from(["roomler", "peers", "home-server"])
            .unwrap()
            .command
        {
            Command::Peers {
                display_name,
                names,
                ..
            } => {
                assert!(!display_name, "a filter does not switch the column");
                assert_eq!(names, ["home-server"]);
            }
            other => panic!("expected Peers, got {other:?}"),
        }
    }

    /// FR-84 D5b — `devices` with every flag, and with none (the primary,
    /// page 1, the server's default order).
    #[test]
    fn parses_devices() {
        let cli = Cli::try_parse_from([
            "roomler",
            "devices",
            "--org",
            "acme",
            "-q",
            "build box",
            "--sort",
            "last_seen_at",
            "--desc",
            "--page",
            "2",
            "--per-page",
            "10",
            "--json",
        ])
        .unwrap();
        match cli.command {
            Command::Devices {
                org,
                q,
                sort,
                desc,
                page,
                per_page,
                fmt,
            } => {
                assert_eq!(org.as_deref(), Some("acme"));
                assert_eq!(q.as_deref(), Some("build box"));
                assert_eq!(sort.as_deref(), Some("last_seen_at"));
                assert!(desc);
                assert_eq!((page, per_page), (2, 10));
                assert!(fmt.json);
            }
            other => panic!("expected Devices, got {other:?}"),
        }
        match Cli::try_parse_from(["roomler", "devices"]).unwrap().command {
            Command::Devices {
                org,
                q,
                sort,
                desc,
                page,
                per_page,
                fmt,
            } => {
                assert!(org.is_none() && q.is_none() && sort.is_none());
                assert!(!desc && !fmt.json);
                assert_eq!((page, per_page), (1, 50));
            }
            other => panic!("expected Devices, got {other:?}"),
        }
    }

    /// FR-90 P3-9-2b — `roomler connect`: a handle, an engine and an
    /// upstream are required; the rest are the daemon's to check, but an
    /// engine or an auth outside the words it knows is refused here first.
    #[test]
    fn parses_connect() {
        let cli = Cli::try_parse_from([
            "roomler",
            "connect",
            "ci/kube",
            "--engine",
            "kubernetes",
            "--upstream",
            "https://api.k8s.internal:6443",
            "--auth",
            "bearer",
            "--ttl",
            "120",
            "--json",
        ])
        .unwrap();
        match cli.command {
            Command::Connect {
                handle,
                engine,
                upstream,
                auth,
                database,
                ca,
                auth_source,
                ttl,
                fmt,
            } => {
                assert_eq!(
                    (handle.as_str(), engine.as_str(), upstream.as_str()),
                    ("ci/kube", "kubernetes", "https://api.k8s.internal:6443")
                );
                assert_eq!(auth.as_deref(), Some("bearer"));
                assert_eq!((database, ca, auth_source), (None, None, None));
                assert_eq!(ttl, Some(120));
                assert!(fmt.json);
            }
            other => panic!("expected Connect, got {other:?}"),
        }
        let cli = Cli::try_parse_from([
            "roomler",
            "connect",
            "db/orders",
            "--engine",
            "mongodb",
            "--upstream",
            "db.internal:27017",
            "--auth-source",
            "orders",
            "--database",
            "orders",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Connect { ref auth_source, ref database, ttl: None, .. }
                if auth_source.as_deref() == Some("orders") && database.as_deref() == Some("orders")
        ));
        for bad in [
            &[
                "roomler",
                "connect",
                "db/orders",
                "--upstream",
                "db.internal:5432",
            ][..],
            &["roomler", "connect", "db/orders", "--engine", "postgres"],
            &[
                "roomler",
                "connect",
                "db/orders",
                "--engine",
                "oracle",
                "--upstream",
                "db.internal:1521",
            ],
            &[
                "roomler",
                "connect",
                "api/x",
                "--engine",
                "http",
                "--upstream",
                "https://api.internal",
                "--auth",
                "digest",
            ],
        ] {
            assert!(Cli::try_parse_from(bad).is_err(), "{bad:?}");
        }
    }

    /// FR-92 — `status` and `off`, and deliberately no `on`: only a
    /// remote-desktop session with input turns keep busy on.
    #[test]
    fn parses_keep_busy_verbs_including_a_local_on() {
        let cli = Cli::try_parse_from(["roomler", "keep-busy", "status", "--json"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::KeepBusy {
                action: KeepBusyAction::Status { .. }
            }
        ));
        let cli = Cli::try_parse_from(["roomler", "keep-busy", "off"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::KeepBusy {
                action: KeepBusyAction::Off { .. }
            }
        ));
        // FR-92 P10 — a bare `on` is the product default…
        let cli = Cli::try_parse_from(["roomler", "keep-busy", "on"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::KeepBusy {
                action: KeepBusyAction::On {
                    pattern: None,
                    resume_after: None,
                    ..
                }
            }
        ));
        // …and every setting is a flag. The values are the agent's to check.
        let cli = Cli::try_parse_from([
            "roomler",
            "keep-busy",
            "on",
            "--pattern",
            "wander",
            "--size",
            "l",
            "--resume-after",
            "10",
            "--auto-off",
            "60",
            "--json",
        ])
        .unwrap();
        match cli.command {
            Command::KeepBusy {
                action:
                    KeepBusyAction::On {
                        pattern,
                        size,
                        resume_after,
                        auto_off,
                        fmt,
                        ..
                    },
            } => {
                assert_eq!(pattern.as_deref(), Some("wander"));
                assert_eq!(size.as_deref(), Some("l"));
                assert_eq!(
                    (resume_after, auto_off, fmt.json),
                    (Some(10), Some(60), true)
                );
            }
            other => panic!("expected keep-busy on, got {other:?}"),
        }
    }

    #[test]
    fn parses_record_verbs() {
        let cli = Cli::try_parse_from([
            "roomler",
            "record",
            "start",
            "--fps",
            "60",
            "--encoder",
            "software",
            "--json",
        ])
        .unwrap();
        match cli.command {
            Command::Record {
                action:
                    RecordAction::Start {
                        fps,
                        encoder,
                        max_minutes,
                        system_audio,
                        microphone,
                        fmt,
                    },
            } => {
                assert_eq!(fps, Some(60));
                assert_eq!(encoder.as_deref(), Some("software"));
                assert_eq!(max_minutes, None, "absent = the daemon's default");
                assert!(
                    !system_audio && !microphone,
                    "audio is OFF unless asked for"
                );
                assert!(fmt.json);
            }
            other => panic!("expected record start, got {other:?}"),
        }
        let cli = Cli::try_parse_from([
            "roomler",
            "record",
            "start",
            "--system-audio",
            "--microphone",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Record {
                action: RecordAction::Start {
                    system_audio: true,
                    microphone: true,
                    ..
                }
            }
        ));
        let cli = Cli::try_parse_from(["roomler", "record", "rm", "a.mp4"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Record {
                action: RecordAction::Rm { ref name }
            } if name == "a.mp4"
        ));
        for verb in ["stop", "status", "ls"] {
            let cli = Cli::try_parse_from(["roomler", "record", verb]).unwrap();
            assert!(matches!(cli.command, Command::Record { .. }), "{verb}");
        }
        // Audio flags belong to `start` alone.
        assert!(Cli::try_parse_from(["roomler", "record", "stop", "--microphone"]).is_err());
    }

    #[test]
    fn parses_status_json_flag() {
        let cli = Cli::try_parse_from(["roomler", "status", "--json"]).unwrap();
        match cli.command {
            Command::Status { fmt } => assert!(fmt.json),
            other => panic!("expected Status, got {other:?}"),
        }
    }

    #[test]
    fn json_flag_is_not_global() {
        // A fully-valid `forward` + `--json` must fail: `--json` belongs only to
        // the read verbs (flattened there), not globally.
        let r = Cli::try_parse_from([
            "roomler",
            "forward",
            "--agent",
            "507f1f77bcf86cd799439011",
            "--local",
            "5432",
            "--remote",
            "10.0.0.5:5432",
            "--json",
        ]);
        assert!(r.is_err(), "--json must not be accepted on `forward`");
    }
    #[test]
    fn native_shared_ssh_auth_modes_are_exclusive_and_password_is_not_an_argument() {
        let base = [
            "roomler",
            "share-ssh",
            "--share",
            "111111111111111111111111",
        ];
        assert!(Cli::try_parse_from(base).is_err());
        for tail in [
            vec!["--login"],
            vec!["--username", "alice"],
            vec![
                "--login",
                "--username",
                "alice",
                "--access-token-file",
                "file",
            ],
            vec![
                "--login",
                "--username",
                "alice",
                "--password",
                "not-accepted",
            ],
        ] {
            assert!(Cli::try_parse_from(base.into_iter().chain(tail)).is_err());
        }
        assert!(
            Cli::try_parse_from(base.into_iter().chain(["--login", "--username", "alice"])).is_ok()
        );
        assert!(
            Cli::try_parse_from(base.into_iter().chain(["--access-token-file", "file"])).is_ok()
        );
    }
}
