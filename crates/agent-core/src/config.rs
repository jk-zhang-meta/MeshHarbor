// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
// RETIRED-NAME-ANCHOR(4): names the PRE-RENAME appdirs segment a host installed before
// P4b still has; appdirs::app_segment resolves it, so it is an input.
//! Agent on-disk configuration.
//!
//! Stored at `<user config dir>/roomler/config.toml`. On Linux that
//! resolves to `$XDG_CONFIG_HOME/roomler/` or `~/.config/roomler/`. A host
//! installed before the rename keeps its `roomler-agent` tree — see
//! [`crate::appdirs`], whose `app_segment` picks the old segment only when
//! that tree already exists.
//!
//! The file holds the enrolled agent's identity, its long-lived agent
//! token, and the server URL. It is the user's responsibility to keep
//! the file at mode 0600; on Linux/macOS we set that permission on write.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::acl::AgentForwardAcl;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Base URL of the Roomler API, e.g. `https://roomler.live`. No trailing slash.
    pub server_url: String,
    /// Derived WSS URL; recomputed from `server_url` if absent.
    #[serde(default)]
    pub ws_url: Option<String>,
    /// Opaque agent JWT issued by `/api/agent/enroll`.
    pub agent_token: String,
    /// Server-assigned agent id (hex ObjectId).
    pub agent_id: String,
    /// Server-assigned tenant id (hex ObjectId).
    pub tenant_id: String,
    /// Stable machine fingerprint. Persisted so re-enrollment maps to the
    /// same `agents` row.
    ///
    /// ⚠️ For an [`ephemeral`](Self::ephemeral) enrollment this is NOT the
    /// derived fingerprint — it is random per enrollment (FR-51 F1), which is
    /// exactly why a restart of an ephemeral device is a NEW device.
    pub machine_id: String,
    /// User-friendly name shown in the admin UI.
    pub machine_name: String,
    /// FR-51 P3 — this enrollment declared itself temporary (it arrived on an
    /// ephemeral enrollment key): the server reaps the row after silence, and
    /// the daemon de-enrolls itself on SIGTERM/SIGINT so a clean stop removes
    /// the device in seconds instead of on the deadline.
    ///
    /// Recorded FROM THE SERVER'S ENROLL RESPONSE, never from a local flag
    /// alone — the credential decides what was minted, and the config must
    /// not disagree with the row. Absent (every pre-FR-51 config) = a normal
    /// permanent device, byte-for-byte today's behaviour.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ephemeral: bool,
    /// Encoder preference: `auto` (default), `hardware`, or `software`.
    /// Can be overridden at launch by `ROOMLERD_ENCODER` env var or
    /// `--encoder` CLI flag.
    #[serde(default)]
    pub encoder_preference: EncoderPreferenceChoice,

    /// How often (hours) the auto-updater polls GitHub Releases.
    /// `None` keeps the built-in default (24 h, see
    /// `updater::CHECK_INTERVAL`). Override at launch via the
    /// `ROOMLERD_UPDATE_INTERVAL_H` env var. Setting this to a
    /// large value (e.g. 168 = weekly) is the recommended way to
    /// dampen update load on bandwidth-constrained fleets.
    #[serde(default)]
    pub update_check_interval_h: Option<u32>,

    /// FR-84 D1 — how many LocalAPI named-pipe instances the daemon keeps
    /// LISTENING at once (Windows; the unix socket has a kernel backlog and
    /// ignores this). Every thin client — the companion's pollers, the
    /// `roomler` CLI, the wizard — opens the pipe fresh per request, and a
    /// client that finds no listening instance is refused with
    /// `ERROR_PIPE_BUSY` on the spot: the Routes page blanking every few
    /// seconds was three such opens racing ONE instance. `None` = the
    /// built-in default (4, `roomler_localapi::DEFAULT_PIPE_POOL`); `1` =
    /// one instance, the pre-FR-84 behaviour (the kill switch). Clamped to
    /// 1..=16; read once at startup (restart required).
    #[serde(default)]
    pub localapi_pipe_pool: Option<u32>,

    /// Whether the agent answers `files:dir` (filesystem browse)
    /// requests from the browser controller. Default `true` to
    /// preserve self-controlled-host auto-grant semantics
    /// (`docs/remote-control.md` §11.2). Operators on org-controlled
    /// fleets can disable per-host via `config.toml`. When `false`,
    /// `files:dir` returns `dir-error { message: "remote browse
    /// disabled" }`. Single-file downloads (`files:get`) and uploads
    /// are NOT gated by this flag — they're consent-bound by the
    /// session itself.
    #[serde(default = "default_enable_remote_browse")]
    pub enable_remote_browse: bool,

    /// FR-84 D4 — where files dropped onto a remote-control session land.
    /// Absolute, or `~/…` for the ACTIVE user's profile (expanded at use
    /// time, so one machine-global config is right for whoever is logged
    /// in). `None` = the default ladder in `files::download_dir` (the
    /// active user's Downloads). Validated by [`crate::files_dir`]: shape
    /// in `config_surface::apply`, placement + writability in the daemon,
    /// at set time AND at every drop — when the daemon runs as SYSTEM/root
    /// the folder must be inside the active user's profile, or a non-admin
    /// at the LocalAPI could make SYSTEM write remote-supplied files
    /// anywhere. Live: the daemon re-reads it per transfer, no restart.
    #[serde(default)]
    pub files_dir: Option<String>,

    /// Whether incoming `rc:session.request` messages are
    /// auto-granted without operator interaction. Default `true` to
    /// match historical self-host behaviour (`docs/remote-control.md`
    /// §11.2 + signaling.rs's pre-Plan-3 auto-grant). Org-controlled
    /// fleets set this to `false` so every session start waits for
    /// an explicit operator decision via the `roomlerd consent
    /// --session <hex> --approve|--deny` CLI fallback (or, in a
    /// future version, a tray prompt). 30 s timeout → auto-deny.
    /// Has NO effect on the file-DC path — uploads/downloads/dir
    /// browsing remain gated by `enable_remote_browse` + the
    /// agent's denylist.
    #[serde(default = "default_auto_grant_session")]
    pub auto_grant_session: bool,

    /// Fleet RPC — gate 4 of four. Whether this device will run a
    /// `rc:rpc.exec` command at all.
    ///
    /// Default **`false`**, unlike every other capability flag here. The
    /// other three gates (org kill-switch, caller permission, the device's
    /// server-side `ExecPolicy`) all live on the control plane; this one
    /// belongs to whoever physically holds the box, and it is the only
    /// refusal that survives a compromised server. Defaulting it on would
    /// make the other three the whole story.
    ///
    /// Commands inherit the daemon's identity — SYSTEM under a perMachine
    /// Windows install, root under systemd. Turning this on is granting
    /// root, and the admin UI says so.
    #[serde(default)]
    pub exec_enabled: bool,

    /// FR-43 P1 — on macOS, let the ROOT daemon spawn and babysit the
    /// GUI-session worker instead of leaving that to a separate LaunchAgent.
    /// First step toward ONE enrollment (one device row) for a Mac: two
    /// processes are forced by the OS, two device rows are not.
    ///
    /// Default OFF — with it off the two halves behave exactly as today. Even
    /// ON, the supervisor stands down whenever the LaunchAgent is loaded, so
    /// one enrollment is never served twice (the hub displaces the older
    /// control WS, which would flap). See `macos_supervisor`.
    ///
    /// No effect on any other platform.
    #[serde(default)]
    pub macos_supervise_gui_worker: bool,

    /// FR-55 — whether this device asks the OS to stay awake so it remains
    /// reachable: `never` (default) | `on-ac` | `always`.
    ///
    /// ⚠️ Device-owned and default OFF, the same last-word rule as
    /// `exec_enabled` and `ssh_enabled`: a remote-access tool that silently
    /// drains a laptop battery earns the reputation it gets. An unrecognised
    /// value parses to `never`, so a typo costs reachability rather than a
    /// battery.
    ///
    /// ⚠️ This does NOT govern a live session — an rc or SSH session always
    /// holds the machine awake, whatever this says, because cutting a session
    /// someone is watching with an idle timer is never what was wanted.
    #[serde(default)]
    pub power_policy: String,

    /// FR-84 D6 — whether the service opens the desktop companion once after
    /// installation and keeps it registered to start at login.
    ///
    /// Default **on**: the companion is this device's consent prompt and the
    /// only place that explains what the device can do, and an install that
    /// ends with nothing on screen leaves a person unsure it worked. OFF is
    /// the kill switch for the whole of D6's launch behaviour: the one-shot
    /// post-install launch is skipped, and the Windows Run value
    /// (`HKLM`/`HKCU\…\Run\Roomler Desktop`) is removed at the next service
    /// start. The companion itself still runs when someone opens it.
    ///
    /// ⚠️ This is the DEVICE's switch. A person's own "Start Roomler at login"
    /// choice lives in the companion's per-user state
    /// ([`crate::desktop_state`]) and needs no admin.
    #[serde(default = "default_true")]
    pub companion_autostart: bool,

    /// Whether this device accepts configuration pushed from its control
    /// plane (see `docs/remote-config.md`).
    ///
    /// Default **`false`**, and **never settable by the server** — that
    /// exclusion is the entire point, not an oversight. [`Self::exec_enabled`]
    /// and [`Self::ssh_enabled`] are "the only refusal that survives a
    /// compromised server" for exactly one reason: the server cannot write
    /// them. A config-push feature deletes that property unless something
    /// replaces it, and this key is that replacement — a device that has not
    /// opted in cannot be opened by any control plane, compromised or not.
    ///
    /// ⚠️ Be honest about what turning it ON costs: it delegates that last
    /// refusal to the control plane for every key the push covers. It trades a
    /// per-key local decision for a one-time local decision. That is a real
    /// reduction in safety and the reason the default is OFF — opting in has
    /// to be a deliberate act by whoever holds the box.
    ///
    /// ⚠️ If the server could set this, the whole design would be one push
    /// away from meaningless. Any future config-push handler must refuse to
    /// apply this field, and the refusal belongs in the handler rather than in
    /// a comment.
    ///
    /// Inert on its own: nothing reads it yet. The key lands first so that a
    /// device can be opted in before the mechanism exists, rather than the
    /// mechanism arriving and finding every device closed.
    #[serde(default)]
    pub remote_config_enabled: bool,

    /// FR-84 D3 — whether a LOCAL client (the companion's "Apply now",
    /// `roomler restart`) may ask the daemon to restart itself through its
    /// supervisor (`Request::RestartDaemon`).
    ///
    /// Default **`true`**, unlike the gate-4 keys above: this grants nothing —
    /// it only spares a person a trip to the service manager — so OFF is not
    /// the fail-safe direction, it is the choice of an owner who wants no
    /// restarts offered on this machine (a kiosk, a shared host). LIVE: the
    /// verb re-reads the file on every request.
    ///
    /// ⚠️ Not a security boundary against the person at the machine: the
    /// LocalAPI admits the interactive user, who can `config set` it back on,
    /// as for every key on that surface. And it has no remote half — the
    /// server can neither set it nor restart a daemon (docs/remote-config.md
    /// §7b).
    #[serde(default = "default_true")]
    pub local_restart_enabled: bool,

    /// FR-52 gate 3 — let someone **outside this device's organization**
    /// control it.
    ///
    /// Default **`false`**, and the strictest member of the
    /// `exec_enabled` / `ssh_enabled` / `remote_config_enabled` family: those
    /// decide what a COLLEAGUE may do, this decides whether a stranger may do
    /// anything at all. Turning it on still opens nothing by itself — an org
    /// admin must approve the device (gate 2), the outsider must prove the
    /// password this device holds (gate 4), and whoever is at the machine is
    /// still asked (gate 5).
    ///
    /// ⚠️ **Not server-settable, structurally.** Like `remote_config_enabled`,
    /// this key is absent from `DesiredConfig` and a test matches the whole
    /// `external_*` PREFIX so the next key added to the surface inherits the
    /// guard rather than needing to remember it. A server able to set this
    /// could admit a stranger to a machine whose owner never agreed, which is
    /// the single move FR-52's design exists to prevent.
    ///
    /// ⚠️ Advertising [`RpcCap::ExternalAccess`] is a property of the BUILD and
    /// says nothing about this key — the server reads the verb to know the
    /// device could *explain* an outside controller to the person at the
    /// machine, and reads nothing at all about whether it has opted in. The
    /// two are deliberately independent so "too old to be approved" and
    /// "approved but opted out" stay different states on the fleet view.
    ///
    /// Inert on its own for now: the session path that reads it is FR-52 P4.
    /// The key lands first for the reason `remote_config_enabled`'s did — a
    /// device can be opted in before the mechanism exists, rather than the
    /// mechanism arriving to find every device closed.
    ///
    /// [`RpcCap::ExternalAccess`]: roomler_ai_remote_control::models::RpcCap::ExternalAccess
    #[serde(default)]
    pub external_access_enabled: bool,

    /// FR-52 gate 4 — the OPAQUE **server setup**, base64.
    ///
    /// Long-lived, per-device, and minted once on the first
    /// `rc password set`. OPAQUE needs it for both registration and every
    /// later login, so losing it invalidates the stored password record — it
    /// travels with [`Self::external_access_verifier`] and neither is useful
    /// alone.
    ///
    /// ⚠️ **A secret.** Deliberately absent from the config SURFACE, so
    /// `roomler config get` cannot print it and `roomler config set` cannot
    /// paste one in: a settable verifier would let anyone who can write the
    /// config choose the password, which is the property gate 4 exists to
    /// deny. It is written by `rc password set` and nothing else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_access_setup: Option<String>,

    /// FR-52 gate 4 — the OPAQUE **registration record** for this device's
    /// external-access password, base64. `None` = no password is set, which is
    /// what every device has until its owner sets one.
    ///
    /// ⚠️ This is a VERIFIER, not the password: OPAQUE's registration record
    /// is not password-equivalent, and (with the `argon2` KSF) recovering the
    /// password from a stolen record costs a full offline attack against a
    /// memory-hard function. That is the property that makes it safe to keep
    /// on the device at all — and the reason the server is never given a copy.
    ///
    /// ⚠️ Same surface exclusion as [`Self::external_access_setup`], and the
    /// same persistence rule as `ssh_host_key`: if it cannot be written
    /// durably the feature stays OFF rather than running on a value that
    /// disappears at reboot, because a password that silently stops working is
    /// worse than one that was never set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_access_verifier: Option<String>,

    /// FR-52 gate 5 — how consent is obtained for an EXTERNAL controller.
    ///
    /// `None` = `prompt`, the attended default, and deliberately not
    /// `AccessPolicy.consent_mode`: the org's answer for a colleague is not
    /// automatically its answer for a stranger. `auto` is reachable — an
    /// unattended headless box is the case the password exists for — but it
    /// has to be chosen here, on the device, by whoever holds it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_consent_mode: Option<String>,

    /// FR-52 — the device's OWN ceiling on what an external session may be
    /// granted, in the pipe-separated form (`"VIEW | INPUT"`).
    ///
    /// `None` = defer to the org's ceiling. Where both are set the session
    /// gets the INTERSECTION: a device may narrow what its org allows, never
    /// widen it, which is the same direction every other gate runs in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_max_permissions: Option<String>,

    /// Serve SSH on this node's overlay address, in-process.
    ///
    /// Default **`false`**, for the same reason as [`Self::exec_enabled`] and
    /// then some: an SSH session is a superset of a Fleet-RPC command (it is
    /// interactive, it carries file transfer and port forwarding, and it lasts).
    /// The gate that belongs to whoever holds the box has to be off until they
    /// say otherwise, and it is the refusal that survives a compromised server.
    ///
    /// ⚠️ Turning this on changes *who answers* for mesh traffic to
    /// `<overlay ip>:<ssh_port>`: the daemon intercepts those packets before the
    /// OS sees them (see `tunnel_core::overlay::split_tun`), so on a host whose
    /// `sshd` already serves that address the in-process server takes over for
    /// peers. The daemon logs a warning when it detects that case at start-up.
    #[serde(default)]
    pub ssh_enabled: bool,

    /// TCP port intercepted on the overlay address when [`Self::ssh_enabled`]
    /// is on. `None` = the built-in default, **2222**.
    ///
    /// The default is deliberately not 22: four of the seven hosts in the first
    /// field survey already had something on `:22` (`sshd` on `0.0.0.0:22` on
    /// the Linux boxes, `sshd` bound to the overlay address on `devbox`, WSL's
    /// relay on `corplap`'s loopback). 2222 lets roomler SSH and an existing `sshd`
    /// coexist while the fleet migrates; set it to 22 per device once the
    /// in-process server is the one you want peers to reach.
    #[serde(default)]
    pub ssh_port: Option<u16>,

    /// OpenSSH public keys allowed to open an SSH session, one entry per key
    /// in `authorized_keys` form (`ssh-ed25519 AAAA… comment`).
    ///
    /// **Empty means nobody**, which is why [`Self::ssh_enabled`] alone cannot
    /// let anyone in. P3 replaced this as the primary path with server-minted,
    /// short-lived session grants tied to a roomler user — but the list stays
    /// as the break-glass route for when the control plane is the thing that is
    /// broken, which is exactly when a remote shell is most wanted.
    ///
    /// ⚠️ A key here is only half of it: set [`Self::ssh_account_mode`] too, or
    /// the session authenticates and then runs nothing. Break-glass access that
    /// silently ran as SYSTEM/root is what that key exists to end.
    ///
    /// Reaching the port at all already requires clearing WireGuard as an
    /// enrolled peer of this org; this is the second, device-owned factor.
    #[serde(default)]
    pub ssh_authorized_keys: Vec<String>,

    /// This node's SSH host private key, OpenSSH format, generated on the first
    /// SSH-enabled start.
    ///
    /// It lives in the config rather than a file of its own so it inherits
    /// every protection the config already has: atomic write with `sync_all`
    /// before the rename, `.prev` rotation, `0600` on Unix and the hardened
    /// ACL on a machine-global Windows install. The file already holds
    /// `agent_token`, so this changes the file's sensitivity not at all.
    ///
    /// Rotating it makes every client that pinned the old fingerprint refuse to
    /// connect, which is the correct behaviour — clear the key only when you
    /// mean to invalidate that trust.
    #[serde(default)]
    pub ssh_host_key: Option<String>,

    /// Which local account a session authenticated by
    /// [`Self::ssh_authorized_keys`] runs as: `daemon` | `console_user` |
    /// `named:<account>`.
    ///
    /// **Unset means sessions authenticate but run nothing.** That is
    /// deliberate. A key-list session carries no server policy, so there is
    /// nothing to infer an identity from — and the previous behaviour,
    /// silently falling back to the daemon's own identity, meant listing a key
    /// handed out SYSTEM/root without ever saying so. It also made a device
    /// policy of `account_mode = console_user` a lie for that path: the policy
    /// said one thing and the key list did another.
    ///
    /// So the operator who lists a key also states what it gets. Same rule the
    /// `RunAs` type enforces everywhere else: never run as something more
    /// privileged than was actually asked for.
    ///
    /// Server-minted grants are unaffected by THIS key — they carry their own
    /// account mode from the device's `SshPolicy`. See
    /// [`Self::ssh_max_privilege`] for the device-owned ceiling that does
    /// apply to them.
    #[serde(default)]
    pub ssh_account_mode: Option<String>,

    /// The most privileged identity a SERVER-GRANTED ssh session may run as.
    /// Default unset = no device-side limit.
    ///
    /// ## What this is for
    ///
    /// A grant arrives from the control plane carrying its own `account_mode`
    /// and `consent_mode`, and until this key existed the device had no say in
    /// either: a server that sent `account_mode: daemon` + `consent_mode: auto`
    /// got an unattended SYSTEM/root shell, on every device, whatever the
    /// device's owner had configured. `ssh_account_mode` did not help — it
    /// governs only the key-list path.
    ///
    /// That is the whole M5 question: what does a device still refuse when the
    /// server asking is the compromised thing? `ssh_enabled` and
    /// `exec_enabled` are already answers of that shape — device-owned
    /// switches a server cannot talk past. This is the same idea applied to
    /// how much privilege a grant may claim.
    ///
    /// ## Values, and why unset is permissive
    ///
    /// `daemon` (or unset) — no additional limit; a grant may ask for
    /// anything. `console_user` — a grant asking for the daemon identity is
    /// REFUSED, not quietly downgraded, because a caller who asked for root
    /// and silently got a user shell has been told something untrue about
    /// their own session.
    ///
    /// ⚠️ Unset is permissive **so that shipping this changes nothing**. A
    /// device-side default of `console_user` would have been the fail-safe
    /// direction and matches how `ssh_enabled` / `exec_enabled` default, but
    /// it would revoke a working configuration during a fleet update, and the
    /// device you lose root SSH to may be the one you needed it for. Measured
    /// on the fleet 2026-08-25: exactly ONE device is currently configured
    /// `account_mode=daemon, consent_mode=auto`. Flipping this default is a
    /// deliberate operator decision, not a side effect of an agent roll.
    ///
    /// The agent logs a WARN at startup naming this key whenever SSH is on and
    /// no ceiling is set, so the exposure is visible rather than implicit.
    #[serde(default)]
    pub ssh_max_privilege: Option<String>,

    /// Report SSH session activity to the org (P8). Default **off**.
    ///
    /// When on, the device tells the server what it did inside a session —
    /// commands and their exit codes, that a shell or SFTP subsystem opened,
    /// which forwards it allowed or refused. It never reports session
    /// CONTENT: no pty byte stream, no command output. Recording those would
    /// ship whatever the operator typed, passwords included, off this host,
    /// which is the property this whole subsystem is built not to have.
    ///
    /// Off by default because it is the DEVICE that decides what it says
    /// about itself, exactly as `ssh_enabled` and `exec_enabled` are the
    /// device's last word. That is not a weakening: a server can never force
    /// a host to self-report honestly, so making the switch explicit says out
    /// loud what was always true. The org's own record of who was ALLOWED in
    /// lives in `ssh_audit` and does not depend on this key.
    #[serde(default)]
    pub ssh_activity_log: bool,

    // ─── FR-90: Hive agent sessions ─────────────────────────────────────
    // The device's own gates, every one of them default-deny, and none of them
    // settable by the server: which local account runs a session and where it
    // may run are the DEVICE's answer, so a compromised server can neither
    // pick SYSTEM/root nor point a session at `/etc` (design §4.2, §13).
    /// May this device RUN agent sessions (`rc:hive.start`)? Default
    /// **`false`** — gate 4, the refusal that survives a compromised server,
    /// like [`Self::exec_enabled`] and [`Self::ssh_enabled`]. A session is a
    /// model running commands on this machine as one of its accounts.
    #[serde(default)]
    pub hive_enabled: bool,

    /// Which local account a Roomler user's sessions run as:
    /// `{ "<user id, or the user's proven email>" = "<account>" }`.
    ///
    /// **Unmapped means refused** (`no_account`) — never a fallback to the
    /// daemon's own identity, and never an account the server names (the
    /// start frame carries none). A mapping to a uid-0 account is refused at
    /// launch too, by the same privilege path exec and SSH use.
    #[serde(default)]
    pub hive_accounts: BTreeMap<String, String>,

    /// The folders sessions may run in, checked on the resolved path, so
    /// `..` and a symlink out of a root do not count. **Empty means nowhere**,
    /// never anywhere — the overlay ACL's `Some([])` lesson, applied before
    /// anyone ships the other reading.
    #[serde(default)]
    pub hive_roots: Vec<String>,

    /// The most sessions this device runs at once (`at_capacity` past it).
    /// `None` = 4.
    #[serde(default)]
    pub hive_max_sessions: Option<u32>,

    /// The harness binary (Claude Code), absolute. `None` = the first of
    /// `~/.local/bin/claude`, `/usr/local/bin/claude`, `/usr/bin/claude` that
    /// exists, the first one resolved in the mapped account's home.
    #[serde(default)]
    pub hive_harness: Option<String>,

    /// FR-90 P0e — the command the DAEMON runs (as SYSTEM/root) to print the
    /// model provider's API key. The key stays in the daemon: a session's
    /// Claude Code gets a per-session token for the loopback model sidecar,
    /// which checks it (this session, still running here at its fence, and a
    /// device not offline past `offline_grace`) and swaps the key in on the
    /// way out. Unset = no model credential, and a session's model calls fail
    /// (a per-session config directory holds no login of its own).
    #[serde(default)]
    pub hive_api_key_helper: Option<String>,
    /// FR-90 P0g — the provider workspace the model calls are made in, for
    /// a key that is not scoped to one: the API then requires an
    /// `anthropic-workspace-id` header on every call. The sidecar adds it
    /// with the key; a session never sets it (field, 2026-10-07: such a key
    /// answered every call `400 This API key is not scoped to a workspace`).
    /// Unset = no header — right for a workspace-scoped key.
    #[serde(default)]
    pub hive_api_workspace_id: Option<String>,
    /// FR-90 P1d-1 (AC7) — how long an update waits for running agent turns
    /// before it restarts the daemon, which cuts every session's turn, in
    /// seconds. A turn is a person's work in progress, so the wait holds a
    /// server-pushed update too; it is bounded, so a busy session cannot hold
    /// the device's updates back. `None` = 1800 (30 min); `0` = never wait.
    #[serde(default)]
    pub hive_update_wait_secs: Option<u32>,
    /// FR-90 P1e — show the org's core memory to the sessions on this device:
    /// the snapshot the server sends with a start, written into the session's
    /// own config dir as `CLAUDE.md` and the auto-memory `MEMORY.md`. Default
    /// OFF, and never pushable: Claude Code reads `CLAUDE.md` as the user's
    /// own OVERRIDING instructions, so this is the one place server-authored
    /// text reaches a session's model, and whether it may is the device
    /// owner's call alone.
    #[serde(default)]
    pub hive_core_memory: bool,
    /// FR-90 P1j — let the people who use this device adopt the Claude Code
    /// sessions they run in a terminal (`roomler hive adopt`): mirrored into
    /// this device's store and listed for their owner alone, read-only.
    /// Default OFF, and never pushable: a terminal session passed none of
    /// Hive's start gates, so whether this machine reports on its terminals
    /// at all is the device owner's call alone. Each person still opts in
    /// themselves, and their account must map in `hive_accounts`.
    #[serde(default)]
    pub hive_adopt: bool,
    /// FR-90 decision 15 — on a Mac, run sessions as an account whose `sudo`
    /// needs no password. Default OFF: such a start is refused, because
    /// macOS's `sudo` reads the account's groups from the directory, so the
    /// session would have root whatever groups it drops. Never pushable:
    /// whether an agent on this machine may be root is the device owner's
    /// call alone. Linux needs no such key: a session there cannot `sudo`.
    #[serde(default)]
    pub hive_allow_passwordless_sudo: bool,
    /// FR-90 P2c — hold copies of the sessions this device's owner runs on
    /// their other devices: a replica, which a promotion can move a session
    /// to once its device is gone. Default OFF, and never pushable: a replica
    /// is a plaintext copy of everything the agent saw, so whether this
    /// device holds one is its owner's call alone. Off, it advertises no
    /// `hive-replica` and refuses a join on its own word.
    #[serde(default)]
    pub hive_replica: bool,
    /// FR-90 P2c — offer this device as an archive replica of the org: once
    /// an `ADMINISTRATOR` designates it, it holds every session the org's
    /// rules allow, for their retention. Counts only with `hive_replica` on.
    /// Default OFF, never pushable: offering is the device owner's, as
    /// designating is the org's.
    #[serde(default)]
    pub hive_archive: bool,
    /// FR-90 P2c — the most this device keeps of the sessions it holds as a
    /// replica, in MiB; `None` = no bound but the disk's. Never pushable: the
    /// device owner's disk.
    #[serde(default)]
    pub hive_store_quota_mib: Option<u32>,
    /// FR-90 P3-3 — let the org's vault lease values to the agent sessions on
    /// this device. On, the daemon makes a vault key at start (in memory
    /// only, a new one each start) and publishes its public half in the
    /// primary enrollment's hello; off, it makes none, publishes none, and
    /// the vault leases it nothing. Default OFF, and never pushable: whether
    /// org secrets are ever decrypted on this machine is the device owner's
    /// call alone, as whether sessions run here at all is `hive_enabled`'s.
    #[serde(default)]
    pub vault_enabled: bool,
    /// FR-90 P3-4d-2 — report to the organization what this device does with
    /// the values its vault leases it: each command a session ran with them
    /// (the program and how it ended) and each file it wrote (the name),
    /// never a value. Off by default because it is the DEVICE that decides
    /// what it says about itself, as `ssh_activity_log` is; the org's record
    /// of what it released lives in `vault_audit` and does not depend on this
    /// key. Never pushable.
    #[serde(default)]
    pub vault_activity_log: bool,
    /// FR-90 P3-7-3c — offer the agent sessions on this device their own
    /// egress: `net_socks` and `net_forward`, a loopback listener per call,
    /// served to the session's account alone, its flows leaving from another
    /// device of the organization as its vault and tunnel policies decide.
    /// Only beside `vault_enabled`. Default OFF, and never pushable: whether
    /// a session here reaches a network beyond this device is the owner's call.
    #[serde(default)]
    pub hive_net: bool,
    /// FR-90 P3-8-2b-2 — offer the agent sessions on this device `ssh_run`:
    /// one command on another device of the organization over Roomler SSH,
    /// as the account that device's SSH policy maps (which may be SYSTEM or
    /// root there), its key minted by this daemon for the one call. Only
    /// beside `vault_enabled`: the vault decides each call, and a person
    /// approves it. Default OFF, and never pushable: whether a session here
    /// reaches into another device is the owner's call.
    #[serde(default)]
    pub hive_ssh: bool,
    /// FR-89 — stream a one-shot command's output (`ssh <node> 'cmd'`) to
    /// the client as it is produced. Default **on**.
    ///
    /// ON: no output ceiling and no wall-clock timeout. The command lives as
    /// long as the channel does — closing it, disconnecting, or the grant's
    /// session limit kills the command and its process tree — redaction runs
    /// over the stream, and a client that stops reading stops the command
    /// rather than growing the daemon.
    ///
    /// OFF is the kill switch: the pre-FR-89 path, where the command runs
    /// inside the Fleet-RPC engine's bounds — output buffered up to a 1 MiB
    /// combined ceiling (then cut, with a notice on stderr) and a 300 s wall
    /// clock. Read at daemon start; a change applies on the next restart.
    ///
    /// Device-owned and never settable by the server: it grants nothing, but
    /// a control plane that could switch a device's data path from under its
    /// owner would be a precedent this surface has refused since
    /// `remote_config_enabled`. Fleet RPC (`roomler exec`) is unaffected
    /// either way.
    #[serde(default = "default_true")]
    pub ssh_exec_streaming: bool,

    // ─── S2: env-bridged operator knobs ──────────────────────────────────
    // Each mirrors an env var read through `tunnel_core::env::node_env`
    // (precedence: env — either prefix — > this config key > built-in
    // default). `None` keeps the default. All are applied at daemon
    // startup, so changes take effect on the next service restart.
    /// QUIC-over-TURN overlay carrier (`ROOMLERD_OVERLAY_QUIC`).
    /// Built-in default: off.
    #[serde(default)]
    pub overlay_quic: Option<bool>,
    /// Direct (LAN / hole-punched) overlay carriers
    /// (`ROOMLERD_OVERLAY_DIRECT`). Built-in default: on.
    #[serde(default)]
    pub overlay_direct: Option<bool>,
    /// DERP (WS-relay) overlay fallback tier (`ROOMLERD_OVERLAY_DERP`).
    /// Built-in default: on.
    #[serde(default)]
    pub overlay_derp: Option<bool>,
    /// U2 — accept the server's computed relay-tier verdict in place of the
    /// local `relay_strategy()` derivation
    /// (`ROOMLERD_OVERLAY_SERVER_RELAY_STRATEGY`). Built-in default: **on**
    /// since D1 (overlay v3); `false` is the per-host off-switch — the server
    /// withholds stamps unless BOTH ends advertise, so opting out cleanly
    /// reverts that host's pairs to the client-authoritative path.
    #[serde(default)]
    pub overlay_server_relay_strategy: Option<bool>,
    /// Phase A (overlay v3) — DERP always-on floor: open the central `/derp`
    /// mux at startup unconditionally, advertise `supports_derp_floor`, and
    /// floor fresh pairs at birth (`ROOMLERD_OVERLAY_DERP_FLOOR`).
    /// Built-in default: **on** since rc.400 (soak-proven); explicit `false`
    /// is the per-host off-switch.
    #[serde(default)]
    pub overlay_derp_floor: Option<bool>,
    /// FR-19 P4b — ride tenant-owned org relays (tunnel-core
    /// `OVERLAY_ORG_RELAY`). Built-in default: **on** (MeshHarbor §6 item
    /// 4c); explicit `false` is the per-host off-switch.
    pub overlay_org_relay: Option<bool>,
    /// Phase B (overlay v3) — netcheck: measure egress capabilities (relay-band
    /// probe, STUN/NAT, /derp health) every ~20 min and publish the CapVector
    /// (`ROOMLERD_OVERLAY_NETCHECK`). Built-in default: on.
    #[serde(default)]
    pub overlay_netcheck: Option<bool>,
    /// FR-19 — offer this node as an **org relay**: bind `relay_server_port`
    /// and answer reachability probes. Opt-IN, default **off**
    /// (`ROOMLER_NODE_RELAY_SERVER_ENABLED`).
    ///
    /// ⚠️ This is FR-19's gate 4 — the refusal that survives a compromised
    /// server — so it is deliberately device-local and must **never** become
    /// server-pushable: it is structurally absent from `DesiredConfig`, and a
    /// test asserts no `relay_*` key ever appears in one.
    #[serde(default)]
    pub relay_server_enabled: Option<bool>,
    /// FR-19 — UDP port for the org-relay listener. Built-in default **3478**,
    /// which is not a guess: E2E-3 measured the corp-managed target host
    /// reaching 3478 on an arbitrary public IP and **no other port** (11000 and
    /// 41641 both failed), so any other default is unreachable by the
    /// population the feature exists for.
    ///
    /// ⚠️ A successful bind does NOT prove reachability. On a host with a
    /// coturn DNAT the port can be fully consumed in `PREROUTING` while
    /// `ss -ulnp` shows it free and the listener receives nothing — measured on
    /// mars, where this exact confound nearly inverted E2E-3's result.
    #[serde(default)]
    pub relay_server_port: Option<u32>,
    /// R4 — tunnel `quic-derp-v1` fallback: after repeated quick tunnel
    /// session deaths (a corp capture window killing fresh TURN/TLS legs),
    /// lead the next attempt with QUIC over the ESTABLISHED `/derp` WS
    /// (`ROOMLERD_TUNNEL_DERP_FALLBACK`). Built-in default: off while the
    /// leg is field-proven. Client-side only (the flow supervisor reads it).
    #[serde(default)]
    pub tunnel_derp_fallback: Option<bool>,
    /// FR-86 P2 — make-before-break tunnel transport RE-UPGRADE: an `auto`
    /// declared route that fell back to a lower transport probes for the best
    /// one (`quic-v1`) in the background and, when it comes up, switches to it
    /// without cutting any established connection (`ROOMLERD_TUNNEL_REUPGRADE`).
    /// Built-in default: ON. Client-side only (the flow supervisor reads it).
    /// Set false to keep the P1 behaviour (a route keeps whatever transport it
    /// happened to land on). Read at each serving epoch, so a config change
    /// takes effect on the next daemon restart; the env var flips it live.
    #[serde(default)]
    pub tunnel_reupgrade: Option<bool>,
    /// R3 — keep established tunnel QUIC peers ALIVE across a control-WS
    /// reattach instead of tearing them down on every transient WS drop
    /// (`ROOMLERD_TUNNEL_PEERS_SURVIVE_REATTACH`). QUIC flows self-signal
    /// over their own streams (no welded control-WS sender), so a QUIC/derp
    /// data plane survives a corp-VPN control-WS blip. Needs the server-side
    /// grace (`ROOMLER__RC__TUNNEL_GRACE_SECS`) to be useful. Built-in
    /// default: off while field-proven. Agent (target) side.
    #[serde(default)]
    pub tunnel_peers_survive_reattach: Option<bool>,
    /// Make-before-break carrier upgrades (`ROOMLERD_OVERLAY_MBB`).
    /// Built-in default: on.
    #[serde(default)]
    pub overlay_mbb: Option<bool>,
    /// LAN-gather virtual-interface filter — drop WSL/Hyper-V/other-VPN
    /// adapters from advertised LAN endpoints
    /// (`ROOMLERD_OVERLAY_LAN_IFACE_FILTER`). Built-in default: on.
    #[serde(default)]
    pub overlay_lan_iface_filter: Option<bool>,
    /// WSL2 mirrored-networking guard — a mirrored guest shares the Windows
    /// host's adapters, so its visible LAN addresses are the HOST's; binding
    /// them starves the host agent's own sockets
    /// (`ROOMLERD_OVERLAY_WSL_MIRRORED_GUARD`). Built-in default: on.
    #[serde(default)]
    pub overlay_wsl_mirrored_guard: Option<bool>,
    /// Auth-first type-1 routing on a multi-org carrier plane — an inbound
    /// handshake initiation is routed by trial-authentication, never by the
    /// source-keyed shortcut that fed the sibling org's inits to whichever
    /// org held a session at that source first (the dual-org direct lockout)
    /// (`ROOMLERD_OVERLAY_INIT_AUTH_FIRST`). Built-in default: on.
    #[serde(default)]
    pub overlay_init_auth_first: Option<bool>,
    /// srflx SEEKING mode — when the shared gather finds NO public candidate,
    /// keep re-gathering with backoff (20 s → ×3 → 300 s cap) plus an
    /// immediate retry on interface events, instead of the pre-W5 sticky
    /// "srflx NONE for the daemon lifetime"
    /// (`ROOMLERD_OVERLAY_SRFLX_SEEK`). Built-in default: on.
    #[serde(default)]
    pub overlay_srflx_seek: Option<bool>,
    /// W4(d) — restore the LEGACY ReplacedByNewer escalation (3 displacements
    /// in the window ⇒ sentinel + process exit). Built-in default: OFF —
    /// displacement storms on TLS-inspected paths are zombie half-open
    /// WSes, and exiting tore down the whole overlay for an event that
    /// needed none of it (`ROOMLERD_WS_REPLACED_EXIT`).
    #[serde(default)]
    pub ws_replaced_exit: Option<bool>,
    /// C4 stage 1 — the standing warm TURN/UDP allocation, established
    /// while UDP works and kept alive so corp-VPN flow-grandfathering
    /// preserves a UDP relay leg across a VPN connect. Measurement-only
    /// in stage 1 (`ROOMLERD_OVERLAY_WARM_RELAY`). Built-in default: off.
    #[serde(default)]
    pub overlay_warm_relay: Option<bool>,
    /// W6 phase 3 — raw-first QUIC-over-TURN upgrade: commit the raw relay
    /// immediately, rendezvous in the background (90 s window) and swap in
    /// on success (`ROOMLERD_OVERLAY_QUIC_ASYNC`). Built-in default: on.
    #[serde(default)]
    pub overlay_quic_async: Option<bool>,
    /// R2 — srflx gather falls back to the wildcard public-dial socket when
    /// every LAN-bound vantage is dead (full-tunnel VPN rescue: AnyConnect-
    /// class clients filter the physical NICs while the tunnel passes UDP;
    /// field corplap-3 2026-08-15). Built-in default: on
    /// (`ROOMLERD_OVERLAY_VPN_VANTAGE`).
    #[serde(default)]
    pub overlay_vpn_vantage: Option<bool>,
    /// §6 item 5 — ask the gateway (PCP, then NAT-PMP) to map the punch
    /// socket's port and advertise the mapping first among the srflx
    /// candidates, so a peer behind a symmetric NAT can still reach this node
    /// directly. Built-in default: on (`ROOMLERD_OVERLAY_PORTMAP`).
    #[serde(default)]
    pub overlay_portmap: Option<bool>,
    /// §6 item 5 — bind an IPv6 direct socket and advertise this host's
    /// global IPv6 addresses as srflx candidates, so two IPv6-capable peers go
    /// direct with no NAT in the way. Built-in default: on
    /// (`ROOMLERD_OVERLAY_IPV6`).
    #[serde(default)]
    pub overlay_ipv6: Option<bool>,
    /// MeshHarbor #19 — report this host's read-only network inventory
    /// (interfaces, routes, rules, listeners, firewall/NAT) to the server
    /// (`ROOMLERD_NET_INVENTORY`). Built-in default: on (single-org devices).
    #[serde(default)]
    pub net_inventory: Option<bool>,
    /// §6 item 5 — netstack per-socket smoltcp receive buffer in bytes, the
    /// window this stack advertises (`ROOMLERD_OVERLAY_NETSTACK_TCP_RX_BUF`,
    /// 16384–16777216). Built-in default: 8 MiB.
    #[serde(default)]
    pub overlay_netstack_tcp_rx_buf: Option<u32>,
    /// §6 item 5 — netstack per-socket smoltcp send buffer in bytes, the most
    /// this stack can have in flight; the congestion window paces below it
    /// (`ROOMLERD_OVERLAY_NETSTACK_TCP_TX_BUF`, 16384–16777216). Built-in
    /// default: 8 MiB (sized for paced SACK recovery).
    #[serde(default)]
    pub overlay_netstack_tcp_tx_buf: Option<u32>,
    /// §6 item 5 — netstack TCP congestion control
    /// (`ROOMLERD_OVERLAY_NETSTACK_TCP_CC`): `cubic` (the built-in default,
    /// RFC 9438 in the vendored smoltcp) | `reno` (its NewReno-lite) | `none`
    /// (the kill switch: the send buffer alone bounds bytes in flight).
    #[serde(default)]
    pub overlay_netstack_tcp_cc: Option<String>,
    /// §6 item 5 — netstack TCP send pacing: data leaves at gain × cwnd / srtt
    /// instead of a window at a time (`ROOMLERD_OVERLAY_NETSTACK_TCP_PACING`).
    /// Built-in default: on (with SACK recovery it rides policed paths).
    #[serde(default)]
    pub overlay_netstack_tcp_pacing: Option<bool>,
    /// §6 item 5 — netstack TCP SACK loss recovery: a loss resends only the
    /// holes the peer's SACK blocks reveal, not the whole window after it
    /// (`ROOMLERD_OVERLAY_NETSTACK_TCP_SACK`). Built-in default: on.
    #[serde(default)]
    pub overlay_netstack_tcp_sack: Option<bool>,
    /// §6 item 5 — netstack TCP retransmission-timeout floor in ms
    /// (`ROOMLERD_OVERLAY_NETSTACK_TCP_MIN_RTO_MS`, 10–1000). Built-in
    /// default: 200, Linux's and gVisor's; 1000 is RFC 6298's.
    #[serde(default)]
    pub overlay_netstack_tcp_min_rto_ms: Option<u32>,
    /// Track A stage 1 — spawn the session-independent network daemon
    /// (`roomlerd netd`) as a SECOND supervisor child. SCAFFOLD ONLY for
    /// now: netd heartbeats and hosts nothing; the network plane still
    /// lives in the session worker. Read by the SUPERVISOR at service
    /// start (change needs a service restart). Built-in default: off.
    #[serde(default)]
    pub overlay_netd: Option<bool>,
    /// Overlay PathMonitor engagement (`ROOMLERD_OVERLAY_PATHMON`):
    /// `on` (authoritative — the built-in default since PR-D's two green
    /// soaks) | `shadow` (fed + compared, legacy decides — the per-host
    /// revert rail) | `off`. Multi-state, so a string key, not a tribool.
    #[serde(default)]
    pub overlay_pathmon: Option<String>,
    /// P4 — event-driven route guard (OS route-table change subscription:
    /// NotifyRouteChange2 / `ip monitor route`)
    /// (`ROOMLERD_OVERLAY_ROUTE_EVENTS`). Built-in default: on.
    #[serde(default)]
    pub overlay_route_events: Option<bool>,
    /// P4 demotion — route-guard blind-tick seconds while the route-event
    /// subscription is live (`ROOMLERD_OVERLAY_ROUTE_TICK_SECS`, 2–300).
    /// Built-in default: 30 (the demoted heartbeat); `2` = the pre-demotion
    /// war cadence (operator revert). Without a live subscription the tick
    /// is always 2 s regardless of this key.
    #[serde(default)]
    pub overlay_route_tick_secs: Option<u32>,
    /// netstate — the process-wide network monitor (ONE OS change
    /// subscription, typed snapshots/deltas, non-blocking fan-out)
    /// (`ROOMLERD_OVERLAY_NETMON`). Built-in default: on.
    #[serde(default)]
    pub overlay_netmon: Option<bool>,
    /// netstate — debounce window in ms for coalescing OS signal bursts
    /// into one delta (`ROOMLERD_OVERLAY_NETMON_DEBOUNCE_MS`, 100–5000).
    /// Built-in default: 750.
    #[serde(default)]
    pub overlay_netmon_debounce_ms: Option<u32>,
    /// Force overlay coturn allocations onto the TURNS/TCP (TLS) tier —
    /// the corp-VPN field probe (`ROOMLERD_OVERLAY_RELAY_TLS`).
    /// Built-in default: off.
    #[serde(default)]
    pub overlay_relay_tls: Option<bool>,
    /// Multi-org v2 shared carrier plane — ONE process-wide direct-socket
    /// set shared by every org's engine, inbound demultiplexed by WireGuard
    /// receiver index (`ROOMLERD_OVERLAY_SHARED_CARRIER`). Retires the
    /// per-org stable-port band race (which org holds the base port stops
    /// being spawn-order timing). Built-in default: on since rc.339
    /// (explicit `false` is the kill switch).
    #[serde(default)]
    pub overlay_shared_carrier: Option<bool>,
    /// A3 — WG-style endpoint roaming: adopt a peer's observed source after an
    /// AUTHENTICATED inbound from it, repointing the carrier in place
    /// (`ROOMLERD_OVERLAY_ROAM`). Completes a punch from a symmetric-NAT
    /// peer whose real per-destination mapping differs from its advert, and
    /// heals a mid-session NAT rebind without waiting out rx-staleness.
    /// Built-in default: on (explicit `false` restores the strict no-roam
    /// demux).
    #[serde(default)]
    pub overlay_roam: Option<bool>,
    /// B4 — carrier-plane socket-liveness watchdog: when the shared plane's
    /// punch-socket keepalive fails N consecutive cycles (reader-less /
    /// wedged socket), self-heal by forcing a debounced plane rebuild
    /// (`ROOMLERD_OVERLAY_PLANE_WATCHDOG`). Built-in default: on
    /// (explicit `false` = warn-only, never auto-rebuild).
    #[serde(default)]
    pub overlay_plane_watchdog: Option<bool>,
    /// Diagnostic — per-session plane-demux + carrier-health traces
    /// (`ROOMLERD_OVERLAY_SESSION_TRACE`). Verbose; enable briefly on an
    /// affected host to field-diagnose a specific peer's carrier. Built-in
    /// default: off.
    #[serde(default)]
    pub overlay_session_trace: Option<bool>,
    /// RETIRED in C1 — the in-tunnel data-probe is deleted (it could only
    /// catch a fully-dead path, and shipping its prober before the fleet had
    /// responders caused the rc.346 false-positive demotes). Kept as a DEAD,
    /// IGNORED key for one release so an existing `overlay_data_probe=…` in a
    /// deployed config still parses instead of failing the whole file.
    #[serde(default)]
    pub overlay_data_probe: Option<bool>,
    /// C1 — answer out-of-tunnel disco echoes on the carrier socket
    /// (`ROOMLERD_OVERLAY_DISCO_RESPOND`). Answering only; nothing on this
    /// node probes yet. Built-in default: ON.
    #[serde(default)]
    pub overlay_disco_respond: Option<bool>,
    /// C2 — PROBE peers with disco echoes and record per-path loss + RTT
    /// (`ROOMLERD_OVERLAY_DISCO_PROBE`). Measurement only; nothing acts
    /// on the table. Built-in default: OFF (enable only where every peer is
    /// already running the C1 responder).
    #[serde(default)]
    pub overlay_disco_probe: Option<bool>,
    /// #33 — answer a peer's direct handshake initiation even while that tier
    /// is suppressed, when accepting cannot cost us the relay
    /// (`ROOMLERD_OVERLAY_ANSWER_WHILE_FOLLOWED`). The demote-follow
    /// hold-down otherwise makes this node stop ANSWERING for up to 15 min, so
    /// two followed ends go mutually deaf and a perfectly good LAN pair sits on
    /// relay. Built-in default: ON since 0.4.2 — set `false` as the kill switch.
    #[serde(default)]
    pub overlay_answer_while_followed: Option<bool>,
    /// Stable Wintun adapter identity — constant requested GUID + boot
    /// stray-adapter sweep, Windows only
    /// (`ROOMLERD_OVERLAY_TUN_STABLE_GUID`). Built-in default: on.
    #[serde(default)]
    pub overlay_tun_stable_guid: Option<bool>,
    /// Route-war eviction — delete competing VPN-installed routes for
    /// overlay prefixes (peer + own `/32`s), Windows only
    /// (`ROOMLERD_OVERLAY_ROUTE_EVICT`). Built-in default: on.
    #[serde(default)]
    pub overlay_route_evict: Option<bool>,
    /// Route-war stolen-path reclaim — repoint destinations whose OS
    /// forwarding cache a corp VPN captured at an equal-metric tie
    /// (targeted evict + immediate cache pin), and debounce the in-block
    /// eviction to evict-on-change, Windows only
    /// (`ROOMLERD_OVERLAY_ROUTE_RECLAIM`). Built-in default: on; off
    /// restores the pre-rc.409 blind per-wave eviction.
    #[serde(default)]
    pub overlay_route_reclaim: Option<bool>,
    /// #1405 — evict a competing VPN route only when it WINS the FIB
    /// decision, Windows only (`ROOMLERD_OVERLAY_ROUTE_EVICT_WINNERS_ONLY`).
    /// Built-in default: on; off restores evicting every competing row on
    /// every wave.
    #[serde(default)]
    pub overlay_route_evict_winners_only: Option<bool>,
    /// Repair a LAN interface's OWN prefix route when its next hop is not on
    /// that LAN (a VPN's stale gateway), by adding the prefix on-link as two
    /// halves; never routes around another interface's capture. Windows only
    /// (`ROOMLERD_OVERLAY_LAN_ROUTE_REPAIR`). Built-in default: on; off
    /// removes the halves.
    #[serde(default)]
    pub overlay_lan_route_repair: Option<bool>,
    /// Keep the overlay TUN device alive across signaling reconnects
    /// (process-lifetime cache in the agent's TUN factory)
    /// (`ROOMLERD_OVERLAY_TUN_PERSIST`). Built-in default: on.
    #[serde(default)]
    pub overlay_tun_persist: Option<bool>,
    /// Install defended peer `/32`s (and the ULA `/96` + connected `/10`) at
    /// route metric 0 so they outrank a corp VPN's metric-1 mirror routes,
    /// Windows only (`ROOMLERD_OVERLAY_ROUTE_METRIC0`). Built-in
    /// default: **off** — AnyConnect's route monitor deletes routes that
    /// would out-rank its own, which leaves the prefix unrouted (rc.289);
    /// opt-in experiment, auto-yields to metric 1 when it doesn't stick.
    #[serde(default)]
    pub overlay_route_metric0: Option<bool>,
    /// #1342 — WIN the contested prefixes outright instead of evicting a
    /// competitor off them forever. Windows only
    /// (`ROOMLERD_OVERLAY_ROUTE_WIN`). Built-in default: **off**.
    ///
    /// Two halves, and ⚠️ the second is NOT v6-only:
    ///   * pin the overlay adapter's **IPv6** interface metric, the lever
    ///     IPv4 has had since rc.410 and IPv6 never got;
    ///   * assert the derived-ULA `/96` **and the CONNECTED v4 prefix** (the
    ///     carved block / legacy `/10`) at the defended route metric 1
    ///     instead of the stock connected-route 256.
    ///
    /// Measured against a corp VPN: v6 was **261 for us vs 26 for the VPN**,
    /// lost outright — which is why the guard evicts the VPN's mirrored
    /// `/96` ~20/min forever on a host whose IPv4 is perfectly quiet. The v4
    /// half closes rc.288's unfinished business: the VPN holds the carved
    /// `/22` at effective 2 against our 256, so a block address outside the
    /// `/24`s separately defended falls through into the corp tunnel.
    ///
    /// ⚠️ NOT the rc.289 metric-0 variant that the VPN deletes outright:
    /// this uses the same metric 1 IPv4 has run fleet-wide for months.
    #[serde(default)]
    pub overlay_route_win: Option<bool>,
    /// Stable UDP port for the overlay's direct sockets
    /// (`ROOMLERD_OVERLAY_DIRECT_PORT`). Built-in default: **derived
    /// per machine** — `43648 + (fnv1a(machine_id) % 16) × 8` (see
    /// [`derived_default_direct_port`]) — so two nodes behind ONE NAT pick
    /// distinct stable ports by construction (2026-08-15: both household
    /// laptops pinned the old fleet-wide 43648 behind one Fritz!Box; only
    /// one could hold a destination-independent external mapping, the
    /// other's srflx went per-destination and every inbound punch landed
    /// on the sibling ⇒ relay-locked pairs). Per-interface LAN sockets
    /// bind the base; the public/srflx dialer takes base+128; a swallowed
    /// base walks an 8-port band. Explicit value = pinned (set 43648 to
    /// restore the old fleet-wide constant); `0` = ephemeral ports (the
    /// pre-rc.307 behavior). Rationale for stability: stateful corp
    /// firewalls (Check Point) grandfather UDP flows that predate the
    /// VPN's session table — with a stable port a rebuilt carrier (agent
    /// update, control-WS reconnect) reproduces the SAME 5-tuple and keeps
    /// riding the grandfathered session instead of relay-locking until the
    /// next VPN-off window (winhost-a, 2026-08-05). A bind conflict falls
    /// back to an ephemeral port with a WARN, restoring the old behavior.
    #[serde(default)]
    pub overlay_direct_port: Option<u32>,
    /// The overlay NIC's IPv4 interface metric, Windows only
    /// (`ROOMLERD_OVERLAY_IFACE_METRIC`). Built-in default: **0** — the
    /// route war's decisive lever. Windows ranks routes by route metric +
    /// INTERFACE metric, and corp endpoint managers mirror overlay prefixes
    /// at route metric 1 on an interface also pinned to 1, so the historical
    /// pin of 1 tied at every prefix length and lost the ifIndex tie-break.
    /// Unlike metric-0 routes (which those products delete), an interface
    /// metric has no route-monitor hook. Raise it only to make the overlay
    /// deliberately lose against another interface.
    #[serde(default)]
    pub overlay_iface_metric: Option<u32>,
    /// Loopback-TURN corp-relay for co-located controllers
    /// (`ROOMLERD_LOCAL_TURN`). Built-in default: on.
    #[serde(default)]
    pub local_turn: Option<bool>,
    /// MagicDNS AAAA answers for derived overlay v6
    /// (`ROOMLERD_DNS_AAAA`). Built-in default: on.
    #[serde(default)]
    pub dns_aaaa: Option<bool>,
    /// FR-72 P6 - the MagicDNS hosts-file fallback
    /// (`ROOMLERD_MAGICDNS_HOSTS`). Built-in default: OFF. Only engages where
    /// the OS DNS steer is MEASURED not to reach our resolver.
    #[serde(default)]
    pub magicdns_hosts: Option<bool>,
    /// The periodic self-updater (`ROOMLERD_AUTO_UPDATE`).
    /// Built-in default: on. Disabling also ignores web-pushed
    /// forced updates.
    #[serde(default)]
    pub auto_update: Option<bool>,
    /// Disable the centralized log uploader
    /// (`ROOMLERD_LOGS_UPLOAD_DISABLED`). `Some(true)` = uploads
    /// OFF. Built-in default: uploads on.
    #[serde(default)]
    pub logs_upload_disabled: Option<bool>,
    /// Per-codec maxrate ceiling factor overrides, percent (50–400).
    /// (`ROOMLERD_RATE_FACTOR_H264` etc.) Built-ins: H264 150,
    /// HEVC 125, VP9 100, AV1 100.
    #[serde(default)]
    pub rate_factor_h264: Option<u32>,
    #[serde(default)]
    pub rate_factor_hevc: Option<u32>,
    #[serde(default)]
    pub rate_factor_vp9: Option<u32>,
    #[serde(default)]
    pub rate_factor_av1: Option<u32>,
    /// FR-77 P3 — the chroma column of the ceiling table: the factor a
    /// 4:4:4 cell applies ON TOP of the codec factor, percent (50–400)
    /// (`ROOMLERD_RATE_FACTOR_H264_444` etc.). Built-in 150 for every codec —
    /// what the libvpx 4:4:4 pump used before the column existed — until a
    /// cell's field test sets its own. AV1 has no 4:4:4 cell, so no key.
    #[serde(default)]
    pub rate_factor_h264_444: Option<u32>,
    #[serde(default)]
    pub rate_factor_hevc_444: Option<u32>,
    #[serde(default)]
    pub rate_factor_vp9_444: Option<u32>,
    /// P7 — minimum linear downscale (percent) at which the Lanczos-3
    /// filter engages; shallower shrinks fall back to box
    /// (`ROOMLERD_LANCZOS_MIN_PCT`). Built-in default: 34 — covers the
    /// Smoother rungs; 56 restores the pre-P7 gate; 0 = Lanczos always.
    #[serde(default)]
    pub lanczos_min_pct: Option<u32>,
    /// P7 — NVENC spatial AQ (`ROOMLERD_NVENC_SPATIAL_AQ`).
    /// Built-in default: OFF (AQ softens desktop text); `Some(true)`
    /// restores it for camera-heavy hosts.
    #[serde(default)]
    pub nvenc_spatial_aq: Option<bool>,
    /// P7 — CQ sharpening steps granted at deep resolution rungs
    /// (`ROOMLERD_SCALE_CQ_BOOST`). Built-in default: 4; 0 disables.
    #[serde(default)]
    pub scale_cq_boost: Option<u32>,
    /// P7 — idle native-rung refinement: lift the resolution cap when the
    /// scene settles so text is crisp at rest
    /// (`ROOMLERD_IDLE_REFINE`). Built-in default: on (Smoother scope).
    #[serde(default)]
    pub idle_refine: Option<bool>,
    /// P7 — idle refinement on Balanced+relay sessions (lifts the B1
    /// physics cap at idle) (`ROOMLERD_IDLE_REFINE_BALANCED`).
    /// Built-in default: ON since P7c (was opt-in at v1).
    #[serde(default)]
    pub idle_refine_balanced: Option<bool>,
    /// HW-downscale Phase B — GPU scale-before-readback on D3D11 capture
    /// backends (`ROOMLERD_GPU_SCALE`). Built-in default: ON; off
    /// reverts to the Phase-A CPU resample (a field A/B in one flip).
    #[serde(default)]
    pub gpu_scale: Option<bool>,
    /// FR-33 — probe each LAN prefix for a VPN split-prefix capture and
    /// surface it (`ROOMLERD_OVERLAY_LAN_CAPTURE_PROBE`). Built-in default:
    /// ON; a read-only route lookup per LAN address per netstate snapshot.
    #[serde(default)]
    pub overlay_lan_capture_probe: Option<bool>,
    /// FR-35 — let the constrained (relay) ceiling grow above the nominal on
    /// delivery evidence and remember the pair's stable rate
    /// (`ROOMLERD_RELAY_CEILING_LEARN`). Built-in default: ON.
    #[serde(default)]
    pub relay_ceiling_learn: Option<bool>,
    /// FR-36 — capture the scanout framebuffer via DRM/KMS, below the
    /// compositor (`ROOMLERD_DRM_CAPTURE`). Built-in default: **OFF**. The only
    /// backend that can see a Wayland desktop, a locked screen or the login
    /// greeter — but it carries no damage information, so turning it on where
    /// X11 works costs the FR-29 idle-CPU win. Restart required.
    #[serde(default)]
    pub drm_capture: Option<bool>,
    /// FR-36 — inject input through `/dev/uinput`, below the compositor
    /// (`ROOMLERD_UINPUT`). Built-in default: **OFF**. Pair with `drm_capture`
    /// on a Wayland host: XTest reaches Xwayland clients only, so without this
    /// a captured Wayland session is read-only. ⚠️ A uinput device is
    /// host-global and injects into whatever has focus. Restart required.
    #[serde(default)]
    pub uinput: Option<bool>,
    /// FR-45 — capture a Wayland desktop through xdg-desktop-portal
    /// ScreenCast and PipeWire (`ROOMLERD_PORTAL_CAPTURE`). Built-in default: **OFF** — the
    /// portal is ATTENDED-only (needs a logged-in user; the first use shows
    /// that user a consent dialog), so defaulting it on would leave an
    /// unattended host waiting on a dialog nobody will answer. Tried after
    /// DRM, before X11. Restart required.
    #[serde(default)]
    pub portal_capture: Option<bool>,
    /// FR-45 P4 — inject input through the portal's RemoteDesktop interface,
    /// riding the SAME session as the portal's capture (`ROOMLERD_PORTAL_INPUT`).
    ///
    /// Unset, it depends on who chose the portal arm (FR-93 P4b):
    /// - the **automatic** portal (`wayland_auto`: a per-user session where
    ///   mutter is absent, such as KDE) asks for remote control, seeing and
    ///   controlling, in its one dialog. `false` keeps it a screen share.
    /// - a **configured** `portal_capture` takes input only with this key
    ///   `true`. An input session needs its own grant and restore token, so
    ///   switching it on makes an already-granted screen share ask again.
    ///
    /// Either way, a person who refuses remote control is then asked for the
    /// screen only: input never costs capture. On a configured mutter arm
    /// (`mutter_capture`) it means mutter's own RemoteDesktop. Restart required.
    ///
    /// ⚠️ Measured 2026-09-01: on GNOME this key is NOT sufficient on its own. The
    /// consent dialog carries a SEPARATE "Allow Remote Interaction" switch
    /// that is OFF by default, and a human who just clicks "Share" grants
    /// capture only — the session then reports no input and runs view-only.
    #[serde(default)]
    pub portal_input: Option<bool>,
    /// FR-45 P5 - take screencast frames from `org.gnome.Mutter.ScreenCast`
    /// DIRECTLY instead of the desktop portal (`ROOMLERD_MUTTER_CAPTURE`).
    /// Built-in default: **OFF**.
    ///
    /// For hosts where no portal backend can run at all - measured on WSL2,
    /// where `xdg-desktop-portal-gnome` exits without a GNOME session while
    /// mutter itself works. GNOME-only.
    ///
    /// **UNATTENDED: this shows NO consent dialog.** Its peer in *behaviour*
    /// is `drm_capture`, not `portal_capture`. Restart required.
    ///
    /// ⚠️ **Inert unless `portal_capture` is on as well.** It is a MODE of the
    /// portal backend, read inside it (`capture/portal/backend.rs`), and the
    /// capture cascade only enters that backend under `portal_capture`
    /// (`capture/mod.rs`) — FR-45 field-verified P5 with both keys set. Set
    /// alone it does nothing: the cascade falls through to X11, which on a
    /// Wayland session is Xwayland's EMPTY root — a live stream of a black
    /// picture, with nothing anywhere saying why. The vmtest Ubuntu lane ran
    /// that way for weeks (#1719).
    #[serde(default)]
    pub mutter_capture: Option<bool>,
    /// FR-56 P4 - capture ONE application window instead of the whole monitor
    /// (`ROOMLERD_WINDOW_CAPTURE`). Built-in default: **OFF**.
    ///
    /// The RAIL-shaped half of Remote Apps: the viewer sees one app rather
    /// than the desktop.
    ///
    /// **Attended by construction** - the portal answers this by showing the
    /// person at the screen a WINDOW PICKER, and nothing on the agent side can
    /// name a window (GNOME refuses `Introspect.GetWindows`). On a host with
    /// nobody at it the capture simply never starts. Restart required.
    #[serde(default)]
    pub window_capture: Option<bool>,
    /// FR-93 — name a Wayland desktop that nothing on this device may capture,
    /// instead of calling the host headless or streaming black
    /// (`ROOMLERD_WAYLAND_AWARE`). Built-in default: **ON**.
    ///
    /// It switches no capture on. With every Wayland arm off, a root daemon
    /// reported `no_display` ("headless") for a host with GNOME on its seat —
    /// a root unit has none of the session's variables — and a per-user daemon
    /// streamed Xwayland's empty root window: a live black picture with no
    /// reason given. With this on, both report `wayland_not_enabled` and name
    /// the keys that would capture it. `false` is the kill switch: the
    /// behaviour before FR-93, unchanged. Restart required.
    #[serde(default)]
    pub wayland_aware: Option<bool>,
    /// FR-93 P2 (decision D1) — a per-user install in a Wayland session,
    /// with no capture key set, switches capture on by itself
    /// (`ROOMLERD_WAYLAND_AUTO`). Built-in default: **ON**.
    ///
    /// The automatic arm is mutter's own screencast, which asks nobody (GNOME),
    /// and where mutter is absent the desktop portal, which asks the person at
    /// the screen once and restores their answer afterwards (FR-93 P2d-3). It
    /// asks for remote control, unless `portal_input` is `false` (P4b). A
    /// root (system) install never switches an arm on by itself: D1 keeps DRM
    /// and uinput opt-in there until a desktop companion ships for non-Debian
    /// hosts. Any capture key set, to anything, takes the choice back. `false`
    /// is the kill switch: the behaviour before P2, unchanged. Restart
    /// required.
    #[serde(default)]
    pub wayland_auto: Option<bool>,
    /// FR-95 P2 — the SYSTEM half of `wayland_auto`
    /// (`ROOMLERD_WAYLAND_AUTO_SYSTEM`). A root install on a Wayland desktop,
    /// with no capture key set, switches DRM and uinput on by itself where the
    /// person at the screen can be told they are being viewed (the companion,
    /// or the desktop's notifications), and for their own session only: it
    /// reads the screen while that session is on it, unlocked, and never the
    /// greeter or the lock screen. Built-in default: **ON**. `false` is the
    /// kill switch: the behaviour before FR-95. `wayland_auto = false` turns it
    /// off too. Restart required.
    #[serde(default)]
    pub wayland_auto_system: Option<bool>,
    /// FR-113 P1 — the same system half for an **X11** desktop
    /// (`ROOMLERD_X11_AUTO_SYSTEM`): a root install, with no capture key set,
    /// switches DRM and uinput on by itself for the person's X11 session on
    /// screen, on the same terms (told first; read only while that session is
    /// on screen, unlocked; never the greeter or the lock screen), and only
    /// where the desktop reports its lock to logind (GNOME, KDE): any other
    /// X11 desktop is refused with `x11_not_enabled`. It skips an idle X11
    /// desktop's unchanged frames by dense rows. Built-in default:
    /// **ON**. `false` is the kill switch: 0.4.143 exactly (no picture of an
    /// X11 seat by default, `no_display`). `wayland_auto = false` turns it off
    /// too. Restart required.
    #[serde(default)]
    pub x11_auto_system: Option<bool>,
    /// FR-93 P4 — a mutter screencast is driven by mutter's own RemoteDesktop,
    /// which takes the viewer's mouse and keyboard (`ROOMLERD_MUTTER_INPUT`).
    /// Built-in default: **ON**.
    ///
    /// It asks nobody, like the mutter screencast it drives, so it follows that
    /// arm: the automatic one (`wayland_auto`, a per-user GNOME session) carries
    /// input; a configured one (`mutter_capture`) carries it only with
    /// `portal_input` too, input staying opt-in wherever the operator chose the
    /// arm. `false` is the kill switch: mutter capture is view-only again, the
    /// behaviour before P4. Restart required.
    #[serde(default)]
    pub mutter_input: Option<bool>,
    /// FR-29 — skip the XShm readback when XDAMAGE proves the screen is
    /// unchanged (`ROOMLERD_X11_DAMAGE`). Built-in default: ON; took a Linux
    /// host's idle capture from 45.8 % of a core to 2.8 %. Restart required.
    #[serde(default)]
    pub x11_damage: Option<bool>,
    /// FR-40 — honour `rc:agent.key_rotate` (an admin retiring this device's
    /// overlay key from the dashboard; `ROOMLERD_OVERLAY_KEY_ROTATION`).
    /// Built-in default: ON. A kill switch for a defective implementation,
    /// not a gate — the order mints locally and leaks nothing.
    #[serde(default)]
    pub overlay_key_rotation: Option<bool>,
    /// P7 — long-edge cap for the refined rung
    /// (`ROOMLERD_IDLE_REFINE_MAX_EDGE`). Built-in default: 0 = full
    /// native.
    #[serde(default)]
    pub idle_refine_max_edge: Option<u32>,
    /// FR-35 — upper bound (kbps) for the learned relay ceiling
    /// (`ROOMLERD_RELAY_MAX_HI_KBPS`). Built-in default: 8000; 0 = learning
    /// off.
    #[serde(default)]
    pub relay_max_hi_kbps: Option<u32>,
    /// P7c — encoded-size floor (KiB) for a frame to count as motion in
    /// the idle-refine machine; smaller deltas (caret, keystrokes) are
    /// invisible to it (`ROOMLERD_IDLE_REFINE_MIN_FRAME_KB`).
    /// Built-in default: 12; 0 = every real frame counts.
    #[serde(default)]
    pub idle_refine_min_frame_kb: Option<u32>,
    /// P8a-2 — MAJOR-motion area floor (permille of the frame) on
    /// tracked-damage backends: only damage at/above it can restore the
    /// resolution cap; smaller damage (typing, popups, windowed
    /// terminal scrolls) stays at native
    /// (`ROOMLERD_IDLE_REFINE_MAJOR_AREA_PERMILLE`). Built-in
    /// default: 400 (40 %); 0 = any non-empty tracked damage counts.
    #[serde(default)]
    pub idle_refine_major_area_permille: Option<u32>,
    /// P8a-2 — up-flip settle (ms) on tracked-damage backends: the cap
    /// lifts this long after the last major-damage frame
    /// (`ROOMLERD_IDLE_REFINE_SETTLE_MS`). Built-in default: 500;
    /// clamped 100-5000.
    #[serde(default)]
    pub idle_refine_settle_ms: Option<u32>,
    /// Phase B — the tracked settle on CONSTRAINED transports
    /// (`ROOMLERD_IDLE_REFINE_SETTLE_CONSTRAINED_MS`). Built-in
    /// default: 1200 (2000 before the constrained HRD trim bounded the
    /// refine IDR); clamped 100-10000. The Up must outlast its own
    /// refined IDR's transmission time on the link it rides.
    #[serde(default)]
    pub idle_refine_settle_constrained_ms: Option<u32>,
    /// Constrained-motion CQ relief (softening steps applied at the
    /// resolution rung of a RELAY session —
    /// `ROOMLERD_CONSTRAINED_CQ_RELIEF`). Built-in default: 4;
    /// 0 = no relief; clamped 0-12. Field 2026-08-21: the P7 sharpening
    /// bias at the constrained rung produced frames too big for the
    /// clamped pipe to drain per frame interval — the "9 fps during
    /// motion" equilibrium.
    #[serde(default)]
    pub constrained_cq_relief: Option<u32>,
    /// Constrained send-queue byte budget, in milliseconds of the relay
    /// ceiling (`ROOMLERD_CONSTRAINED_QUEUE_MS`). Built-in default:
    /// 450; 0 = unbounded (pre-rc.442 posture); clamped 0-2000. Bounds
    /// the viewer lag a relay session can accumulate in queued frames.
    #[serde(default)]
    pub constrained_queue_ms: Option<u32>,
    /// HRD/VBV window for constrained sessions, percent of maxrate
    /// (`ROOMLERD_CONSTRAINED_HRD_PCT`). Built-in default: 200 (the
    /// rc.234 window — rc.442's 75 % default was reverted in rc.443
    /// after av1_qsv died on an over-budget forced IDR); clamped 25-200.
    /// Sub-100 values are per-host experiments only.
    #[serde(default)]
    pub constrained_hrd_pct: Option<u32>,
    /// 2026-08-26 drag-latency P1 — DIRECT-path send-queue byte budget,
    /// in milliseconds of the AIMD's live target
    /// (`ROOMLERD_DIRECT_QUEUE_MS`). Built-in default: 150; 0 =
    /// unbounded (the pre-P1 posture); clamped 0-2000. Bounds the
    /// standing queue a drag burst can build on a direct session — the
    /// field "sluggish, bulky" lag.
    #[serde(default)]
    pub direct_queue_ms: Option<u32>,
    /// 2026-08-26 drag-latency P4 — HRD/VBV window for DIRECT sessions,
    /// percent of maxrate (`ROOMLERD_DIRECT_HRD_PCT`). Built-in
    /// default: 100 (half the rc.234 2× window — the 2× reservoir
    /// legalised the drag-start burst that became the standing queue);
    /// clamped 25-200. `av1_*` encoders are floored at 200 regardless
    /// (rc.443 — Intel AV1 VDENC errors on an over-reservoir IDR).
    #[serde(default)]
    pub direct_hrd_pct: Option<u32>,
    /// 2026-08-26 drag-latency P4 — area-scaled AIMD bitrate floor
    /// (`ROOMLERD_AREA_MIN_BITRATE`). Default ON: the flat 1.5 Mbps
    /// floor was a 1080p legibility tuning and is mush at 5+ MPix; the
    /// scaled floor is ~3.1 M at 2880×1800, capped 4 M, direct-only.
    /// `false` restores the flat floor.
    #[serde(default)]
    pub area_min_bitrate: Option<bool>,
    /// 2026-08-27 drag-latency P2 — measured-rate stage 1
    /// (`ROOMLERD_MEASURED_CEILING`). Default ON: the bitrate
    /// ceiling is clamped to 85 % of the session's MEASURED drain rate
    /// while an estimate holds, so the encoder converges just under the
    /// pipe instead of congesting the send queue on every burst (the
    /// "chunky" production skips). Only ever lowers the nominal
    /// ceiling; confidence decays after 60 s without evidence. `false`
    /// = observe-and-report only (the pre-P2 posture).
    #[serde(default)]
    pub measured_ceiling: Option<bool>,
    /// FR-59 P1 — the AIMD's legibility floor descends toward a MEASURED
    /// pipe on a constrained transport (`ROOMLERD_SLOW_LINK_FLOOR`).
    /// Built-in default: on. The flat 1.5 Mbps floor is calibrated for
    /// the 2-9 Mbps band every measured relay sat in; on a slower link it
    /// is not a floor but a PIN, because it is also where the
    /// multiplicative decrease bottoms out. Evidence-gated: with no held
    /// goodput estimate the nominal floor stands. `false` = flat floor.
    #[serde(default)]
    pub slow_link_floor: Option<bool>,
    /// FR-62 A1 — in-place encoder rate changes (QSV) + corrected NVENC HRD
    /// sizing. Default OFF; ships inert. See `encoder_inplace_rate` in the
    /// config surface.
    #[serde(default)]
    pub encoder_inplace_rate: Option<bool>,
    /// Pin remote-control's ICE to a TURN relay so the encoder runs its
    /// CONSTRAINED posture on demand. Default OFF. A diagnostic pin that
    /// degrades an otherwise-direct session — see `ice_relay_tcp` in the
    /// config surface.
    #[serde(default)]
    pub ice_relay_tcp: Option<bool>,
    /// Bitrate ceiling for a CONSTRAINED (relay) remote-control transport,
    /// kbps. Built-in default 3000; clamped 100-100000. See `relay_max_kbps`
    /// in the config surface.
    #[serde(default)]
    pub relay_max_kbps: Option<u32>,
    /// FR-63 — open a session with slow-start instead of committing to a
    /// constant rate. Default OFF (a controller change ships behind evidence).
    /// See `rate_slow_start` in the config surface.
    #[serde(default)]
    pub rate_slow_start: Option<bool>,
    /// FR-70 M1 — the encoder runs on its own OS thread per session behind a
    /// command channel instead of `block_in_place` on a runtime worker.
    /// Default ON since 0.4.70 (M1c met its gate on 0.4.69); `false` restores
    /// the inline encode. See `media_thread`.
    pub media_thread: Option<bool>,
    /// FR-65 P0 — the pump stall watch. Default ON. See `pump_stall_watch`.
    #[serde(default)]
    pub pump_stall_watch: Option<bool>,
    /// FR-65 P0 — the stall threshold in ms. Built-in default 100; clamped
    /// 10-5000. See `pump_stall_warn_ms` in the config surface.
    #[serde(default)]
    pub pump_stall_warn_ms: Option<u32>,
    /// FR-65 — run a CONSTRAINED encoder rebuild off the pump thread too.
    /// Default ON. See `bg_rebuild_constrained` in the config surface.
    #[serde(default)]
    pub bg_rebuild_constrained: Option<bool>,
    /// FR-59 P1 — absolute stop for that relief, bps
    /// (`ROOMLERD_SLOW_LINK_MIN_BITRATE`). Built-in default: 200000;
    /// clamped 50000-1500000. Below roughly this a full-resolution frame
    /// is illegible at any QP and the honest lever is fewer PIXELS.
    #[serde(default)]
    pub slow_link_min_bitrate: Option<u32>,
    /// FR-59 P2 — denominate the CONSTRAINED send-queue byte budget in
    /// the MEASURED drain rate rather than the nominal relay ceiling
    /// (`ROOMLERD_CONSTRAINED_QUEUE_MEASURED`). Built-in default: on. A
    /// budget in milliseconds is a lie unless the bits-per-second it
    /// divides by is the pipe's: 450 ms of a nominal 3 Mbps is 168750
    /// bytes, which on a measured 395 kbps link is 3.4 SECONDS of queue.
    /// A measurement may only ever LOWER the reference. `false` =
    /// pre-FR-59 (once-resolved nominal budget).
    #[serde(default)]
    pub constrained_queue_measured: Option<bool>,
    /// FR-59 P6 — a held goodput measurement far below the FR-35
    /// learned/seeded ceiling abandons it back to the nominal band
    /// (`ROOMLERD_SEED_CONTRADICTION`). Built-in default: on. The rate
    /// memory keys on the nominated pair's remote address, which on a
    /// relayed session is the RELAY's — so one fast day writes a number
    /// later sessions through that relay inherit for 7 days regardless of
    /// the client's own network. `false` = keep the seed until the AIMD
    /// walks it down.
    #[serde(default)]
    pub seed_contradiction: Option<bool>,
    /// FR-59 P3 — the VIEWER's own report of what is arriving (bytes/s
    /// received, and how much its transit queue grew) drives the
    /// constrained rate loop (`ROOMLERD_VIEWER_RATE_CLAMP`). Built-in
    /// default: on. This is the signal the agent cannot produce for
    /// itself: on a relayed path its send channel reads empty while
    /// seconds of video sit in the relay and the carrier. Needs no clock
    /// probe, so it survives the links where FR-15's age report is
    /// absent or rejected. `false` = observe-and-report only.
    #[serde(default)]
    pub viewer_rate_clamp: Option<bool>,
    /// FR-59 P4 — a transit queue too deep to cut our way out of is
    /// DRAINED by pausing production for a bounded, sub-second window
    /// (`ROOMLERD_QUEUE_DRAIN`). Built-in default: on. A rate cut alone
    /// drains a queue at capacity minus inflow, the slowest possible way:
    /// converging to 90% of a 400 kbps pipe clears a 2 s backlog at
    /// 40 kbps, i.e. over ~20 s. Pausing sets inflow to zero, so it
    /// clears in the ~2 s it represents. No forced keyframe on resume - a
    /// pause loses no frames. `false` = rate control only.
    #[serde(default)]
    pub queue_drain: Option<bool>,
    /// FR-59 P5 — a constrained session whose pair the rate memory
    /// remembers as SLOW opens with fewer pixels and fewer frames
    /// (`ROOMLERD_SLOW_LINK_PROFILE`). Built-in default: on. The bitrate
    /// levers can make the encoder track a 400 kbps pipe; they cannot make
    /// 1920x1200 at 30 fps legible through it (~1.7 KB per frame).
    /// Resolved ONCE at pump start, never as a mid-session rung, because
    /// every rung flip pays a blocking encoder open. `false` = open at the
    /// normal size regardless.
    #[serde(default)]
    pub slow_link_profile: Option<bool>,
    /// FR-59 P5 — remembered rate at or below which that profile engages,
    /// bps (`ROOMLERD_SLOW_LINK_PROFILE_BPS`). Built-in default: 1000000;
    /// 0 = never engage. A pair with NO memory never engages it: an
    /// unknown link is not a slow one.
    #[serde(default)]
    pub slow_link_profile_bps: Option<u32>,
    /// 2026-08-27 drag-latency P3 — background encoder rebuild
    /// (`ROOMLERD_BG_REBUILD`). Default ON: on encoders with no
    /// in-place bitrate reconfigure (QSV/AMF), a bitrate change opens
    /// the replacement on a blocking thread while the current encoder
    /// keeps producing, then swaps between frames — no mid-drag stall,
    /// and rate drops land DURING motion as smaller frames instead of
    /// production skips. `false` restores the rc.445 motion-defer
    /// (applies held until 1.2 s of quiet, then a blocking re-open).
    #[serde(default)]
    pub bg_rebuild: Option<bool>,
    /// 2026-08-27 drag-latency P5 — parallel colour conversion
    /// (`ROOMLERD_PAR_CONVERT`). Default ON: big frames run the
    /// BGRA→NV12/I444 convert in row bands across threads
    /// (byte-identical output, roughly halves the convert share of the
    /// encode time at 2880×1800+). `false` restores the single-threaded
    /// call.
    #[serde(default)]
    pub par_convert: Option<bool>,
    /// 2026-08-27 drag-latency P5 — fps-first cadence pacing on HW
    /// encoders (`ROOMLERD_FPS_PACE`). Default ON: when the encoder
    /// can't hold target fps, the pump consumes frames on an even grid
    /// at the sustainable rate (quantized to 5 fps, floor 15) instead of
    /// letting the capture layer drop ~33 % at random phases — even
    /// cadence beats a higher-but-jittery rate. While engaged the
    /// encode-pressure bitrate factor is masked at 1.0 (pixels-bound HW
    /// encode time doesn't respond to bitrate); the resolution tier
    /// stays the second lever. `false` restores the unpaced pre-P5
    /// behaviour.
    #[serde(default)]
    pub fps_pace: Option<bool>,
    /// 2026-08-27 FR-10 — relay IDR thrift
    /// (`ROOMLERD_RELAY_IDR_THRIFT`). Default ON: constrained (relay)
    /// sessions suppress the idle-settle keyframe (a quality refresh, not
    /// a correctness need on a reliable DC — the request-driven resync
    /// stays) and space deferred bitrate re-opens to ≥15 s unless the
    /// move is ≥40 % — each such IDR was a single ~300 KB frame ≈
    /// 1.2–1.5 s of a ~2 Mbps relay (the CORPLAP-3 "bulky" lumps). `false`
    /// restores the previous relay behaviour. Direct sessions unaffected.
    #[serde(default)]
    pub relay_idr_thrift: Option<bool>,
    /// FR-15 — constrained-transport age feedback (2026-08-27). Default
    /// ON: the viewer reports the paint age of the frames it actually
    /// showed, the agent learns the session floor, and sustained excess
    /// over it caps send-fps AND feeds the AIMD a congestion sample. It
    /// exists because a relay backlog lives BELOW every agent counter:
    /// field 2026-08-27 measured 1000 ms of viewer age against a 26 KB
    /// agent queue.  = the open-loop 0.4.7 relay posture. Direct
    /// sessions are unaffected (they have the measured ceiling + byte
    /// gate). Env: ROOMLERD_RELAY_AGE_FEEDBACK. Restart required.
    #[serde(default)]
    pub relay_age_feedback: Option<bool>,
    /// How long ONE frame may sit inside the DataChannel send call before
    /// the pump treats it as congestion, ms (default 250; 0 disables).
    ///
    /// `send_wait` measures the pipe's refusal to drain directly — no clock,
    /// no viewer, both transports — so it is the one congestion signal that
    /// still works on a relay, where the goodput clamp is off and the age
    /// loop rides a probe the congestion itself biases. Acted on for
    /// CONSTRAINED sessions only. Env: ROOMLER_NODE_SEND_STALL_MS.
    #[serde(default)]
    pub send_stall_ms: Option<u32>,
    /// rc.445 — restore the pre-rc.445 Priority-dial resolution caps
    /// (Smoother 1024 everywhere / Balanced 1280 on relay;
    /// `ROOMLERD_PRIORITY_RES_CAP`). Default OFF: every mid-motion
    /// rung flip costs a blocking encoder open (0.65-0.87 s measured on
    /// Iris Xe) and the field verdict was "never flipping beats the
    /// rung"; the dial's bit-shedding moved to the rebuild-free ceiling
    /// factors below.
    #[serde(default)]
    pub priority_res_cap: Option<bool>,
    /// rc.445 — Smoother's bitrate-ceiling factor, percent
    /// (`ROOMLERD_SMOOTHER_RATE_PCT`). Built-in default: 70; clamped
    /// 30-100. A lower ceiling makes the HRD raise QP during motion
    /// continuously (smaller frames, steadier fps) with zero rebuilds;
    /// at-rest quality is untouched.
    #[serde(default)]
    pub smoother_rate_pct: Option<u32>,
    /// rc.445 — Balanced's bitrate-ceiling factor, percent
    /// (`ROOMLERD_BALANCED_RATE_PCT`). Built-in default: 85; clamped
    /// 30-100.
    #[serde(default)]
    pub balanced_rate_pct: Option<u32>,
    /// HW-downscale Phase A — worker threads for the CPU resampler's
    /// row-banded passes (`ROOMLERD_SCALE_THREADS`). Built-in
    /// default: 1 (inline, no threads spawned); clamped 1-8. A lever for
    /// weak hosts where the Smoother rung's downscale eats the frame
    /// budget; HW-encode hosts have idle cores during motion.
    #[serde(default)]
    pub scale_threads: Option<u32>,
    /// Media-ICE follow-renomination policy
    /// (`ROOMLER_ICE_FOLLOW_RENOMINATION`, raw env in the vendored
    /// webrtc-ice — bridged via a set_var-if-unset shim in `run_cmd`).
    /// `None`/"auto" = built-in upward-only+stale policy (rc.268);
    /// `Some(true)`/"always" = legacy follow-everything (rc.260 —
    /// thrash-prone, diagnostics only); `Some(false)`/"never" = pin to
    /// first nomination (rc.262 semantics).
    #[serde(default)]
    pub ice_follow_renomination: Option<bool>,
    /// Warm-standby keepalive pings on validated-but-unselected media
    /// ICE pairs (`ROOMLER_ICE_WARM_STANDBY`, vendored-crate raw env —
    /// same shim). Built-in default: on.
    #[serde(default)]
    pub ice_warm_standby: Option<bool>,
    /// Deprioritize overlay-TUN host candidates in media ICE
    /// (`ROOMLER_ICE_OVERLAY_HOST_DEPRIORITIZE`, vendored-crate raw
    /// env — same shim). Built-in default: on.
    #[serde(default)]
    pub ice_overlay_host_deprioritize: Option<bool>,
    /// Overlay-carrier-aware constrained detection in the media pumps
    /// (`ROOMLERD_OVERLAY_TIER_DETECT`). Built-in default: on.
    #[serde(default)]
    pub overlay_tier_detect: Option<bool>,
    /// B1 — feed the 15 s overlay RTT probes into the PathMonitor's
    /// quality plane (`ROOMLERD_OVERLAY_RTT_Q`). Q-only — never
    /// eligibility. Built-in default: on (kill switch).
    #[serde(default)]
    pub overlay_rtt_q: Option<bool>,
    /// Multi-region relay PoPs — probe the server-pushed region list (timed
    /// STUN binding per PoP) and report RTTs so the server derives this
    /// node's `relay_home` (`ROOMLERD_RELAY_PROBE`). Built-in default:
    /// on (kill switch).
    #[serde(default)]
    pub relay_probe: Option<bool>,
    /// 2026-08-04 - KeyText modifier neutralization: temporarily release
    /// physically-held Shift/Ctrl/Alt that the remote layout does NOT
    /// want around a scancode tap (fixes '+'->'*' / dead '|' on non-US
    /// hosts), restoring them after (`ROOMLERD_TEXT_MOD_NEUTRALIZE`).
    /// Built-in default: on (kill switch).
    #[serde(default)]
    pub text_mod_neutralize: Option<bool>,
    /// FR-77 P3 — cache the hardware encoder probe across daemon restarts
    /// (`ROOMLERD_CAPS_CACHE`): keyed by GPU + driver + OS build + roomlerd
    /// build, re-probed on any change or after 7 days, and only ever a
    /// result that opened a hardware cell. Built-in: on.
    #[serde(default)]
    pub caps_cache: Option<bool>,
    /// FR-119 — offer a viewer that asks a frame rate above 60
    /// (`ROOMLERD_FPS_HIGH`): advertise `fps-high`, and grant a higher rate
    /// only on a direct path, on a rate class this host has proven (or as a
    /// trial), and where the pipe covers it. Built-in: off. Read at start,
    /// with the hello's capabilities, so a change needs a restart.
    #[serde(default)]
    pub fps_high: Option<bool>,
    /// FR-77 — encoder cells this device must not open or advertise,
    /// comma-separated `name:chroma` (`hevc_qsv:yuv444`). Unset = the
    /// built-in list; `none` = deny nothing. Env
    /// `ROOMLERD_ENCODER_CELLS_DENY`. Pushable through remote config: it is
    /// the matrix's kill switch, not a security gate — it only ever REMOVES
    /// cells, so `MANAGE_AGENTS` is enough and no opt-in beyond
    /// `remote_config_enabled` is needed.
    #[serde(default)]
    pub encoder_cells_deny: Option<String>,
    /// FR-119 P2b — frame rates this device must not grant above its usual
    /// rate, comma-separated `name:fps` (`hevc_qsv:120`, `*:144` for every
    /// encoder). Unset = deny nothing. Env `ROOMLERD_FPS_DENY`, read once per
    /// session. Pushable through remote config for the same reason as
    /// `encoder_cells_deny`: it only ever REMOVES rates.
    #[serde(default)]
    pub fps_deny: Option<String>,
    /// FR-77 P4 — pin the VAAPI render node (`ROOMLERD_VAAPI_DEVICE`,
    /// e.g. `/dev/dri/renderD129`). Unset = the first node libva opens, in
    /// order `/dev/dri/renderD128`…`renderD135`. Read once per process at
    /// the first VAAPI open.
    #[serde(default)]
    pub vaapi_device: Option<String>,
    /// FR-78 P1 — pin the DXGI adapter index the D3D12 video-encode device
    /// opens on (`ROOMLERD_D3D12_ADAPTER`, e.g. `1`). Unset = adapters
    /// `0`…`3` in order, the first FFmpeg accepts. Windows only.
    #[serde(default)]
    pub d3d12_adapter: Option<String>,
    /// FR-78 P1 — pin the Vulkan physical device by index or name
    /// (`ROOMLERD_VULKAN_DEVICE`, e.g. `1` or `NVIDIA GeForce RTX 5090`).
    /// Unset = the loader's default device.
    #[serde(default)]
    pub vulkan_device: Option<String>,
    /// FR-85 — where screen recordings go. Unset = the per-user default
    /// (`Videos\Roomler` on Windows when local and writable, `~/Movies/Roomler`,
    /// the XDG videos dir + `Roomler`). Validated by
    /// [`crate::recording_dir::validate_record_dir`]. ⚠️ Device-owned: a
    /// server-pushed path would pick where the recorder writes, so it is
    /// structurally absent from `DesiredConfig` (the `record_` prefix test).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_dir: Option<String>,
    /// FR-85 P3 — let a remote controller record this screen. Default OFF.
    /// The recording is made and kept on this device; the controller
    /// downloads it over the session. The agent advertises the `record`
    /// capability only while this is on, so the server never grants
    /// `Permissions::RECORD` to a controller of a device whose owner did not
    /// opt in. Read live: OFF also stops a remote recording in progress.
    /// ⚠️ Device-owned: structurally absent from `DesiredConfig` (the
    /// `record_` prefix test), like `record_dir`.
    #[serde(default)]
    pub record_remote_enabled: bool,
    /// FR-85 P3 — let a remote recording include what the computer plays.
    /// Default OFF, and meaningless without `record_remote_enabled`. The
    /// microphone is never a remote option.
    #[serde(default)]
    pub record_remote_audio: bool,
    /// FR-92 — let a remote controller holding INPUT turn on keep busy here:
    /// mouse patterns that keep this computer active (no screensaver, idle
    /// lock or "Away") until switched off, paused whenever a real person uses
    /// it. Default ON (operator decision, 2026-10-10). Read LIVE: off also
    /// stops a keep-busy in progress, and the capability follows on the next
    /// heartbeat.
    ///
    /// ⚠️ Device-owned: structurally absent from `DesiredConfig` (the
    /// `keep_busy_` twin of the `record_` prefix test), so no server can turn
    /// it back on. ⚠️ While keep busy runs it overrides `power_policy =
    /// never`: injected input is user activity, and user activity defeats
    /// idle sleep.
    #[serde(default = "default_true")]
    pub keep_busy_enabled: bool,
    /// FR-99 — let a remote controller cover this screen with a privacy
    /// curtain during a session: the person in front of it sees a notice, the
    /// controller still sees the desktop. Default OFF. The agent advertises
    /// `privacy-mode` only while this is on, so the server never grants
    /// `Permissions::PRIVACY` for a device whose owner did not opt in — and the
    /// agent re-reads it at every "on" all the same. Read LIVE: off also takes
    /// a curtain that is up down.
    ///
    /// ⚠️ Device-owned: structurally absent from `DesiredConfig` (the
    /// `privacy_` twin of the `record_` prefix test), and set over the
    /// LocalAPI only by the person at the console, whose screen it covers.
    #[serde(default)]
    pub privacy_mode_allowed: bool,
    /// FR-99 P3 — what this device does to its screen when the last remote
    /// session ends: `never` (the default), `auto` (lock when the session
    /// began on a locked screen or with nobody at the computer) or `always`.
    /// Read LIVE: the decision is taken at each session's start and applied
    /// when the last one ends. A fresh Windows service install is written with
    /// `auto` (decision 3, `enrollment::apply_service_install_defaults`); a
    /// config that lacks the key reads `never`.
    ///
    /// ⚠️ Device-owned: absent from `DesiredConfig`, and set over the LocalAPI
    /// only by the person at the console, whose screen it locks. A server may
    /// ask for stricter on a session (P3b), never lower this floor.
    #[serde(default)]
    pub lock_on_end: roomler_ai_remote_control::models::LockOnEnd,
    /// FR-108 — whether a controller's display match may switch this host's
    /// display mode: `auto` (the default: only while nobody is using this
    /// screen), `always` (whenever asked, rc.191's behaviour) or `never`. Read
    /// LIVE: every request is decided by the value at that moment.
    ///
    /// ⚠️ Device-owned: absent from `DesiredConfig`, and set over the LocalAPI
    /// only by the person at the console, whose screen it would change.
    #[serde(default)]
    pub display_match: DisplayMatchPolicy,
    /// FR-100 P1c — whether this device checks the browser that offers it a
    /// session: `audit` (the default) verifies the controller's signature over
    /// its offer, pins each browser key it sees per user, records the verdict
    /// and refuses nothing; `off` does none of it. `enforce` arrives with P3.
    /// Read LIVE: every offer is judged by the value at that moment.
    ///
    /// ⚠️ Device-owned: absent from `DesiredConfig`, and set over the LocalAPI
    /// only by the person at the console. The device signs its own answers
    /// whatever this says: that protects the browser and costs nothing.
    #[serde(default)]
    pub peer_auth: PeerAuthPolicy,
    /// FR-101 P2b — this device's own floor for the clipboard in a remote
    /// session: `on` (the default), `ask` (only on a session the person here
    /// approves, on a prompt that names it) or `off`. The stricter of this and
    /// the org's policy wins, and the agent masks the grant at every session
    /// start whatever the server sent. Read LIVE: the next session follows,
    /// and the hub is told on the next heartbeat, so a viewer can say why.
    ///
    /// ⚠️ Device-owned: structurally absent from `DesiredConfig`, so no server
    /// can switch back on what the owner switched off.
    #[serde(default)]
    pub rc_clipboard: roomler_ai_remote_control::models::FeaturePolicy,
    /// FR-101 P2b — the same floor for file transfer.
    #[serde(default)]
    pub rc_files: roomler_ai_remote_control::models::FeaturePolicy,
    /// FR-101 P2b — the same floor for this computer's audio.
    #[serde(default)]
    pub rc_audio: roomler_ai_remote_control::models::FeaturePolicy,
    /// FR-101 P1b — keep a plaintext `server_url` (and every `[[orgs]]`
    /// entry's) as written. Without it a loaded `http://` URL to a remote
    /// host is read as `https://` (`roomler_ai_remote_control::server_url`),
    /// so the control socket, the token renewal, the updater and the uploads
    /// all go over TLS. For a lab whose server serves no TLS. Loopback needs
    /// no escape: it is never promoted.
    ///
    /// ⚠️ Device-owned: structurally absent from `DesiredConfig`, and set over
    /// the LocalAPI only from the console. A server that could set it could
    /// talk a device down to plaintext.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_plaintext_server: bool,
    /// B2 — score-driven demotion of degraded-but-live direct carriers
    /// (`ROOMLERD_OVERLAY_DEMOTE`): `off` | `shadow` (compute +
    /// count, never act — the built-in default) | `on` (voluntary MBB
    /// demotions execute). Multi-state, so a string key, not a tribool.
    #[serde(default)]
    pub overlay_demote: Option<String>,
    /// B3 — mid-tier upward probing: srflx/public incumbents probe an
    /// eligible HIGHER tier every ≥120 s via the MBB machinery
    /// (`ROOMLERD_OVERLAY_UPWARD_PROBE`). Built-in default: on.
    #[serde(default)]
    pub overlay_upward_probe: Option<bool>,
    /// Multi-user P3 — concurrent remote-control sessions this agent
    /// advertises (`ROOMLERD_RC_MAX_SESSIONS`, 1–8). Built-in
    /// default: 2. With the P5 shared encoder (default on) same-profile
    /// DC viewers share one capture + encoder; distinct profiles still
    /// run their own — weak-GPU hosts may prefer 1. The server keeps
    /// concurrent INPUT to one holder regardless.
    #[serde(default)]
    pub rc_max_sessions: Option<u32>,
    /// Multi-user P5 — shared-floor encoder for concurrent DC viewers
    /// (`ROOMLERD_SHARED_ENCODER`): same-profile sessions share ONE
    /// capture + encoder with floor-merged rate/dials; `off` reverts to
    /// the rc.302 pump-per-session behaviour. Built-in default: on.
    #[serde(default)]
    pub shared_encoder: Option<bool>,
    /// P4 — ingress filtering of INBOUND overlay packets
    /// (`ROOMLERD_OVERLAY_RPF`): `off` | `warn` (count + log, still
    /// deliver — the built-in default) | `enforce` (drop). Two checks share
    /// the mode: a packet whose SOURCE the sending peer does not own
    /// (forgery), and one whose DESTINATION lies outside the subnets this
    /// node advertises (aiming past a subnet router). Multi-state, so a
    /// string key, not a tribool.
    #[serde(default)]
    pub overlay_rpf: Option<String>,

    /// Most recent version that ran for at least
    /// `CLEAN_RUN_THRESHOLD` seconds before exiting cleanly (or
    /// crashing — the threshold is what gates updates here, not exit
    /// reason). Used by [`should_rollback`] to pick a fallback
    /// target when the current version crash-loops on cold start.
    /// `None` on a fresh install (no prior version to roll back to).
    #[serde(default)]
    pub last_known_good_version: Option<String>,

    /// Consecutive cold-start crashes within `CRASH_WINDOW_SECS` of
    /// each other. Bumped at startup by [`record_crash_at`]; reset
    /// to 0 by [`record_clean_run_at`] once a run survives long
    /// enough.
    #[serde(default)]
    pub crash_count: u32,

    /// Unix timestamp (seconds) of the most recent crash. Compared
    /// against the current time to decide whether the next crash
    /// "extends" the current crash window or starts a new one.
    #[serde(default)]
    pub last_crash_unix: u64,

    /// Set by the rollback path when it fires once. Cleared on next
    /// successful clean run (i.e. when the new-old version has
    /// proven itself stable). Prevents an oscillation loop between
    /// two equally-bad versions: we roll back at most once per
    /// install cycle.
    #[serde(default)]
    pub rollback_attempted: bool,

    /// `true` when the previous run started but never reached the
    /// clean-run threshold AND didn't exit gracefully via Ctrl-C.
    /// Read at startup to decide whether the previous run counts
    /// as a crash for [`record_crash_at`]. Set true by
    /// [`mark_run_starting`] at the top of every run; flipped back
    /// to false by [`record_clean_run_at`] (after the threshold)
    /// or by the graceful-shutdown path (Ctrl-C handler).
    ///
    /// Default `false` so a brand-new install isn't treated as a
    /// crash on its first run.
    #[serde(default)]
    pub last_run_unhealthy: bool,

    /// Last config-schema version this file was migrated to. Used by
    /// [`migrate`] to decide which migration steps to apply at startup.
    /// `None` (or missing in TOML) on pre-rc.18 configs — those run
    /// through the rc.18 migration set and the field is then persisted.
    /// Forward-compat: future RCs key migrations off this string
    /// (e.g. `match version { Some("0.3.0-rc.18") => apply_rc18_to_rc19, … }`).
    #[serde(default)]
    pub config_schema_version: Option<String>,

    /// Tunnel agent-side allowlist (T2.6). Default is
    /// `enabled` with an empty allowlist — meaning "trust the
    /// server's tenant policy on every `ServerMsg::TcpForwardForward`".
    /// Operators on org-controlled hosts narrow further by populating
    /// `forward_acl.allowlist` in the TOML or disable forwards
    /// entirely with `forward_acl.enabled = false`. See
    /// `agents/roomlerd/src/tunnel/acl.rs` for the matching
    /// semantics.
    #[serde(default)]
    pub forward_acl: AgentForwardAcl,

    /// Remote app selection & launch on virtual-desktop hosts. Default:
    /// enabled with a seeded bash/tmux entry so a headless VD host offers
    /// "New bash session" out of the box. Operators add htop/mc/… per host
    /// in the TOML. The browser only ever sends an allowlist KEY, never a
    /// command line. See `agents/roomlerd/src/apps/`.
    #[serde(default)]
    pub virtual_desktop_apps: crate::apps_config::VirtualDesktopAppsConfig,

    /// Phase 3b: opt into the overlay L3 mesh. Default off — an
    /// `overlay-l3` build only joins the mesh when this is set.
    #[serde(default)]
    pub overlay_enabled: bool,

    /// Multi-org P2c: let SECONDARY `[[orgs]]` entries with
    /// `overlay_mode = "tun"` join their own tenant's mesh, each on its OWN
    /// adapter (`per_org_systun_factory` in roomlerd's overlay.rs; W7c
    /// deleted the shared-TUN mux this once rode). Default off: the P1 stance
    /// (secondaries never join) until the operator opts in. Requires the
    /// secondary to share the primary's `server_url` (same control plane)
    /// and to hold its own WG key; a tenant still on the shared legacy
    /// `/10` can coexist with carved-block orgs, but TWO un-migrated
    /// tenants on one host are refused at TUN registration (renumber one —
    /// `docs/multi-org.md` §4.3). Overrides the PRIMARY's netstack mode
    /// (`ROOMLERD_OVERLAY_NETSTACK_SOCKS`) with its OS TUN; a netstack
    /// secondary keeps its own stack either way (#2493).
    #[serde(default)]
    pub overlay_multi_org: bool,

    /// Loopback SOCKS5 port for THIS org's userspace netstack.
    ///
    /// Netstack mode used to be a process-wide singleton keyed off
    /// `ROOMLERD_OVERLAY_NETSTACK_SOCKS`: one stack, one port, one
    /// `roomler ping` backend, none of it org-scoped. A second org did not
    /// join twice — it replaced the first org's stack under a SOCKS front
    /// still answering on the same port, so a caller dialing for org A was
    /// silently routed by org B.
    ///
    /// Each org now gets its OWN stack and front. The primary keeps reading
    /// the env key (unchanged for every existing host); a secondary sets
    /// `netstack_socks_port` on its `[[orgs]]` entry. Two orgs asking for
    /// the same port is a genuine conflict — one TCP listener — so the
    /// second withholds loudly rather than stealing it.
    #[serde(default)]
    pub netstack_socks_port: Option<u16>,

    /// True on a config produced by [`AgentConfig::for_org`] — a SECONDARY
    /// org's view, not the process's own enrollment.
    ///
    /// `#[serde(skip)]`, so it is never written to or read from disk and a
    /// loaded config is always a primary, which is the truth. It exists
    /// because process-wide env keys belong to the primary alone: a
    /// secondary that inherited them would silently contend for the same
    /// single-instance resource (one SOCKS port, one ping backend).
    #[serde(skip)]
    pub derived_org: bool,

    /// #2493 — True on a [`AgentConfig::for_org`] config whose org runs over
    /// the userspace netstack: the overlay then opens that org's own stack
    /// and loopback SOCKS5 front, never the per-org TUN that
    /// `overlay_multi_org`, a device-wide flag, would otherwise choose. That
    /// flag stays as the primary set it, because it is also what the org's
    /// hello says about the DEVICE (`multi_org: tun`). `#[serde(skip)]`, as
    /// [`Self::derived_org`].
    #[serde(skip)]
    pub derived_netstack: bool,

    /// Phase 3b: this node's persisted WireGuard Curve25519 secret key
    /// (base64). Generated on the first overlay-enabled startup in `main`;
    /// the public key is what the netmap distributes. `None` until then.
    #[serde(default)]
    pub overlay_wg_secret_key: Option<String>,
    /// FR-40 — bumped on every rotation of `overlay_wg_secret_key` and sent
    /// as `key_epoch` on the overlay join. `0` = the key minted at first
    /// start (or a config that predates rotation). Persisted NEXT to the key
    /// so the two can never disagree on disk.
    #[serde(default)]
    pub overlay_wg_key_epoch: u32,

    /// Phase 1 subnet router — CIDRs this node offers to route for overlay peers
    /// (e.g. `["192.168.1.0/24"]`). Sent on join as `advertised_routes`; each is
    /// gated behind admin approval server-side before any peer uses it. Empty =
    /// this node is not a subnet router.
    #[serde(default)]
    pub overlay_advertised_routes: Vec<String>,

    /// P5 exit-node: when set, this node advertises `0.0.0.0/0` (the default
    /// route) on the L3 overlay, offering to be an **exit node** — a mesh peer
    /// can route ALL its internet egress through this host (Tailscale exit-node
    /// style). Like every advertised route it stays admin-gated server-side (a
    /// DISTINCT Admin → Subnet routes "Exit node" toggle, not a stray `/0`
    /// checkbox in the CIDR grid) and no peer routes through it until BOTH this
    /// flag AND the admin approval are set. The advertised `0.0.0.0/0` unions
    /// with `overlay_advertised_routes` — see
    /// [`AgentConfig::effective_overlay_advertised_routes`]. The egress
    /// data-plane (NAT masquerade + FORWARD ACCEPT) engages automatically via
    /// the existing subnet-router NAT once `/0` is advertised. Off by default.
    #[serde(default)]
    pub overlay_exit_node_enabled: bool,

    /// P5 exit-node CLIENT opt-in: route THIS node's default internet egress
    /// (`0.0.0.0/0`) through the named mesh peer — its [`overlay`] `NetmapPeer`
    /// name or node-id hex — Tailscale "use exit node" style. `None` (default) =
    /// normal routing (egress via the local uplink). Only takes effect when the
    /// named peer is visible in the netmap, reachable with a live carrier, AND an
    /// admin-approved exit node; the client then installs a split-default with
    /// carrier-endpoint exemptions so the coordination + mesh path survives.
    /// DISTINCT from [`overlay_exit_node_enabled`](Self::overlay_exit_node_enabled),
    /// which makes THIS node OFFER to be an exit for others.
    #[serde(default)]
    pub overlay_exit_node: Option<String>,

    /// Tunnel mesh subnet-router — CIDRs this host advertises it can route for
    /// the SOCKS mesh (e.g. `["192.168.1.0/24"]`). Sent on `rc:agent.hello` as
    /// `advertised_routes`; an admin approves a subset (Admin → Agents → Subnet
    /// routes) before the mesh uses them. Separate from
    /// `overlay_advertised_routes` (the L3 overlay's own subnet router).
    #[serde(default)]
    pub advertise_routes: Vec<String>,

    /// Auto-detect this host's directly-connected IPv4 subnets and advertise
    /// them alongside `advertise_routes` (union). Default ON: a subnet router
    /// is zero-config — the admin sees each LAN the host is on as a suggestion
    /// (Admin → Agents → Subnet routes) and approves what should be routed. Set
    /// `false` to advertise only the explicit `advertise_routes`. Detected
    /// routes are UNTRUSTED until approved, so this is safe to leave on.
    #[serde(default = "default_true")]
    pub advertise_local_subnets: bool,

    /// P6: DECLARED, daemon-supervised tunnel routes (`[[tunnel_routes]]`).
    /// Each enabled entry is reconciled into a live daemon flow on every
    /// startup (and on change) by `tunnel::route_reconciler` — the
    /// persistent counterpart of the ephemeral LocalAPI `CreateForward`
    /// flows. The struct is `roomler_localapi::RouteDescriptor`, one
    /// type for wire + disk. Managed via `roomler route add/rm/...` or the
    /// desktop Tunnels pane (the DAEMON writes this field — LocalAPI verbs
    /// persist through the daemon's config-write lock); hand-editing the
    /// TOML also works (picked up at the next daemon start).
    ///
    /// NB: a crash-rollback to a pre-P6 binary rewrites the config without
    /// this field (no unknown-field preservation) — declared routes do not
    /// survive an auto-rollback.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tunnel_routes: Vec<roomler_localapi::RouteDescriptor>,

    /// Multi-org P1: SECONDARY enrollments (`[[orgs]]`). The top-level scalar
    /// identity fields (`server_url` / `agent_token` / `agent_id` /
    /// `tenant_id`) REMAIN the PRIMARY org — deliberately, so a rollback to a
    /// pre-multi-org binary keeps running the primary unchanged and simply
    /// never reads this table. Each enabled entry gets its own supervised
    /// signaling WS loop in `run_cmd`; `machine_id` / `machine_name` are
    /// machine-scoped and shared by every org (the server dedupes per tenant
    /// via the `agents.{tenant_id, machine_id}` unique index).
    ///
    /// Managed by `roomlerd enroll` (appends when the enrollment
    /// resolves to a NEW (server, tenant) pair) and the `roomlerd org`
    /// verbs. Deliberately NOT on the S2 config surface — same policy as
    /// `[[tunnel_routes]]`: identity + secrets live behind dedicated verbs.
    ///
    /// NB: same rollback caveat as `tunnel_routes` — a crash-rollback to a
    /// pre-multi-org binary rewrites the config without this field, so
    /// secondary enrollments do not survive an auto-rollback.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub orgs: Vec<OrgEntry>,
}

/// Multi-org P1 — one SECONDARY enrollment (see [`AgentConfig::orgs`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrgEntry {
    /// Operator-facing slug, unique among entries and never
    /// [`PRIMARY_ORG_LABEL`]. Used by the `org` CLI verbs, log/tracing
    /// fields, the per-org watchdog pump name, and `[[tunnel_routes]].org`.
    pub label: String,
    /// Base URL of this org's Roomler API. May differ from the primary's
    /// (self-hosted servers); overlay `tun` mode is reserved for orgs sharing
    /// the primary's control plane (enforced in P2 — P1 forces `off`).
    pub server_url: String,
    /// Derived WSS URL; recomputed from `server_url` if absent.
    #[serde(default)]
    pub ws_url: Option<String>,
    /// This org's long-lived agent JWT.
    pub agent_token: String,
    /// This org's server-assigned agent id (hex ObjectId).
    pub agent_id: String,
    /// This org's tenant id (hex ObjectId).
    pub tenant_id: String,
    /// Soft-disable: a disabled org keeps its enrollment but gets no
    /// supervised WS loop until re-enabled (applied at the next daemon
    /// start, like every config key).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// How this org joins the L3 overlay. P1 supervisors force `Off`
    /// regardless of this value; P2 honours `netstack`/`tun` (with `tun`
    /// restricted to same-control-plane orgs + tenant-block addressing).
    #[serde(default)]
    pub overlay_mode: OrgOverlayMode,
    /// This org's OWN WireGuard secret (base64). NEVER copied from the
    /// primary or another org — a shared public key would let two orgs
    /// correlate the same physical device. Minted at enroll-append time
    /// (or on this org's first overlay-enabled start, P2).
    #[serde(default)]
    pub overlay_wg_secret_key: Option<String>,
    /// FR-40 — this org's key epoch (see `AgentConfig::overlay_wg_key_epoch`).
    #[serde(default)]
    pub overlay_wg_key_epoch: u32,
    /// Org-scoped twin of `overlay_advertised_routes` (P2).
    #[serde(default)]
    pub overlay_advertised_routes: Vec<String>,
    /// Org-scoped twin of `overlay_exit_node_enabled` (P2; exit offering is
    /// single-owner across orgs — arbitrated at bring-up).
    #[serde(default)]
    pub overlay_exit_node_enabled: bool,
    /// Org-scoped twin of `advertise_routes` (tunnel/SOCKS mesh subnet
    /// advertisements are per-tenant admin-approved).
    #[serde(default)]
    pub advertise_routes: Vec<String>,
    /// This org's OWN loopback SOCKS5 port for `overlay_mode = "netstack"`.
    ///
    /// Required for a secondary in netstack mode: the port is a real TCP
    /// listener, so orgs cannot share one. Unset (or equal to another org's)
    /// means this org withholds its overlay rather than taking a front that
    /// answers for someone else — see [`AgentConfig::netstack_socks_port`].
    #[serde(default)]
    pub netstack_socks_port: Option<u16>,
}

impl OrgEntry {
    pub fn ws_url(&self) -> String {
        if let Some(url) = &self.ws_url {
            return url.clone();
        }
        derive_ws_url(&self.server_url)
    }
}

/// Multi-org P1 — per-org overlay participation. Multi-state, so an enum
/// (never a tribool): `off` (P1 default for secondaries) | `netstack`
/// (userspace stack — no TUN/OS routes; P2) | `tun` (full OS-TUN presence;
/// P2, same-control-plane orgs only).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrgOverlayMode {
    #[default]
    Off,
    Netstack,
    Tun,
}

impl OrgOverlayMode {
    /// FR-49 — the ONE spelling, shared by the TOML (`#[serde(rename_all =
    /// "lowercase")]`), `roomlerd org ls`, `roomler status` and the LocalAPI
    /// `OrgStatus.overlay_mode`. The match is exhaustive, so a new variant
    /// cannot reach an operator surface without someone naming it.
    pub fn wire(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Netstack => "netstack",
            Self::Tun => "tun",
        }
    }

    /// Parse an operator-supplied mode. Deliberately strict and with NO
    /// fallback: `roomlerd org overlay <label> tunn` must fail loudly rather
    /// than quietly leaving a device off the mesh — which is the entire defect
    /// FR-49 exists to close.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "netstack" => Some(Self::Netstack),
            "tun" => Some(Self::Tun),
            _ => None,
        }
    }
}

/// The reserved label naming the config's scalar (primary) identity.
pub const PRIMARY_ORG_LABEL: &str = "primary";

impl AgentConfig {
    /// Enabled secondary enrollments, in config order.
    pub fn enabled_secondary_orgs(&self) -> impl Iterator<Item = &OrgEntry> {
        self.orgs.iter().filter(|o| o.enabled)
    }

    /// FR-49 — the PRIMARY identity's overlay participation, expressed in the
    /// same vocabulary as a secondary's `overlay_mode`, so one column can hold
    /// both.
    ///
    /// The primary predates `OrgOverlayMode` and stores this as
    /// `overlay_enabled` plus the presence of a `netstack_socks_port`, which is
    /// why the mapping lives here rather than being read off a field: there is
    /// no field to read, and every caller that reconstructed it by hand would
    /// be a place for the two to drift.
    pub fn primary_overlay_mode(&self) -> OrgOverlayMode {
        if !self.overlay_enabled {
            OrgOverlayMode::Off
        } else if self.netstack_socks_port.is_some() {
            OrgOverlayMode::Netstack
        } else {
            OrgOverlayMode::Tun
        }
    }

    /// Find a secondary org by label (case-sensitive).
    pub fn find_org(&self, label: &str) -> Option<&OrgEntry> {
        self.orgs.iter().find(|o| o.label == label)
    }

    /// Find a secondary org by its enrollment identity — the (server, tenant)
    /// pair that `enroll` resolves against.
    pub fn find_org_by_identity_mut(
        &mut self,
        server_url: &str,
        tenant_id: &str,
    ) -> Option<&mut OrgEntry> {
        self.orgs
            .iter_mut()
            .find(|o| o.server_url == server_url && o.tenant_id == tenant_id)
    }

    /// Does the (server, tenant) pair name the PRIMARY enrollment?
    pub fn is_primary_identity(&self, server_url: &str, tenant_id: &str) -> bool {
        self.server_url == server_url && self.tenant_id == tenant_id
    }

    /// The AgentConfig an org supervisor runs with: machine identity +
    /// operator knobs from `self`, enrollment identity + org-scoped fields
    /// from the entry.
    ///
    /// Overlay participation for a secondary, by its `overlay_mode`, and
    /// always with the org's OWN WG key (minted at enroll-append; NEVER the
    /// primary's):
    /// - `tun`: `overlay_multi_org` (the operator opt-in) and the SAME
    ///   `server_url` as the primary. Its adapter's routes share the host's
    ///   table with every other org's, so its blocks must come from the one
    ///   registry that carved theirs.
    /// - `netstack` (#2493): the org's own `netstack_socks_port`, and nothing
    ///   else. It opens no adapter and installs no route, so it needs neither
    ///   the opt-in nor the primary's control plane. Until #2493 this mode was
    ///   accepted everywhere and joined nothing, while every surface said
    ///   `overlay netstack`.
    /// - `off`: nothing.
    ///
    /// Exit-node roles stay primary-only (split-defaults are host-global).
    /// Declared tunnel routes are reconciled only by the primary-side
    /// reconciler.
    pub fn for_org(&self, org: &OrgEntry) -> AgentConfig {
        let mut c = self.clone();
        c.server_url = org.server_url.clone();
        c.ws_url = org.ws_url.clone();
        c.agent_token = org.agent_token.clone();
        c.agent_id = org.agent_id.clone();
        c.tenant_id = org.tenant_id.clone();
        let tun = self.overlay_multi_org
            && org.overlay_mode == OrgOverlayMode::Tun
            && org.server_url == self.server_url;
        let netstack =
            org.overlay_mode == OrgOverlayMode::Netstack && org.netstack_socks_port.is_some();
        c.overlay_enabled = (tun || netstack) && org.overlay_wg_secret_key.is_some();
        c.derived_netstack = netstack;
        c.overlay_wg_secret_key = org.overlay_wg_secret_key.clone();
        c.overlay_wg_key_epoch = org.overlay_wg_key_epoch;
        c.overlay_advertised_routes = org.overlay_advertised_routes.clone();
        c.overlay_exit_node_enabled = false;
        c.overlay_exit_node = None;
        c.advertise_routes = org.advertise_routes.clone();
        // Explicitly the ORG's port, never inherited: the primary's value
        // comes from the process-wide env key, and silently reusing it would
        // put two orgs on one listener.
        c.netstack_socks_port = org.netstack_socks_port;
        c.derived_org = true;
        c.tunnel_routes = Vec::new();
        c.orgs = Vec::new();
        c
    }

    /// Per-entry runnability partition for the daemon supervisor: each
    /// `[[orgs]]` entry paired with `None` (runnable) or `Some(reason)` (a
    /// validation problem — the supervisor skips it and surfaces the reason
    /// in the LocalAPI `OrgStatus.terminal_error`). Never fatal: a bad
    /// hand-edited entry must not take down the healthy orgs.
    pub fn partition_runnable_orgs(&self) -> Vec<(OrgEntry, Option<String>)> {
        let mut out = Vec::with_capacity(self.orgs.len());
        let mut seen_labels = std::collections::HashSet::new();
        let mut seen_identities = std::collections::HashSet::new();
        for o in &self.orgs {
            let problem = if sanitize_org_label(&o.label).as_deref() != Some(o.label.as_str()) {
                Some(format!("invalid org label {:?}", o.label))
            } else if !seen_labels.insert(o.label.clone()) {
                Some(format!("duplicate org label {:?}", o.label))
            } else if self.is_primary_identity(&o.server_url, &o.tenant_id) {
                Some("duplicates the primary enrollment".to_string())
            } else if !seen_identities.insert((o.server_url.clone(), o.tenant_id.clone())) {
                Some("duplicates another entry's (server, tenant) pair".to_string())
            } else {
                None
            };
            out.push((o.clone(), problem));
        }
        out
    }

    /// Validate the `[[orgs]]` table. Returns human-readable problems; the
    /// caller logs them and SKIPS the offending entries (never fatal — a bad
    /// hand-edited entry must not take down the healthy orgs).
    pub fn validate_orgs(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let mut seen_labels = std::collections::HashSet::new();
        let mut seen_identities = std::collections::HashSet::new();
        for o in &self.orgs {
            if sanitize_org_label(&o.label).as_deref() != Some(o.label.as_str()) {
                problems.push(format!(
                    "org label {:?} is invalid (lowercase alphanumeric + dashes, \
                     not {PRIMARY_ORG_LABEL:?})",
                    o.label
                ));
            }
            if !seen_labels.insert(o.label.clone()) {
                problems.push(format!("duplicate org label {:?}", o.label));
            }
            let identity = (o.server_url.clone(), o.tenant_id.clone());
            if self.is_primary_identity(&o.server_url, &o.tenant_id) {
                problems.push(format!(
                    "org {:?} duplicates the primary enrollment ({} / tenant {})",
                    o.label, o.server_url, o.tenant_id
                ));
            } else if !seen_identities.insert(identity) {
                problems.push(format!(
                    "org {:?} duplicates another entry's (server, tenant) pair",
                    o.label
                ));
            }
        }
        problems
    }
}

/// What [`promote_org_to_primary`] did to each enrollment's place on the
/// mesh, so the CLI can say it rather than leave an operator to find out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Promotion {
    /// The label the demoted primary now has in `[[orgs]]`.
    pub demoted_label: String,
    /// The new primary is on the mesh (its own OS TUN): it was a `tun` entry.
    pub primary_on: bool,
    /// The promoted entry was on the mesh through the userspace netstack. A
    /// primary cannot take that from config (its netstack is the env key
    /// `ROOMLERD_OVERLAY_NETSTACK_SOCKS`, which `overlay_multi_org`
    /// overrides), so it starts off.
    pub primary_was_netstack: bool,
    /// The demoted entry's overlay mode.
    pub demoted_mode: OrgOverlayMode,
    /// The old primary was on the mesh and could not stay on it as a
    /// secondary: a per-org TUN needs `overlay_multi_org`, and a `tun` org
    /// the primary's control plane.
    pub demoted_lost_mesh: bool,
}

/// Multi-org — swap a secondary enrollment into the PRIMARY (scalar) slot;
/// the demoted primary takes the promoted org's `[[orgs]]` position, under
/// `demoted_label` when given (sanitized, refused on a collision), else
/// under the promoted org's old label. Machine identity and operator knobs
/// stay put; the org-scoped fields (WG key, advertised routes, exit offer)
/// travel with their enrollments.
///
/// #2540 — mesh participation travels too, where it maps exactly. Multi-org
/// P1 parked both at off "until P2's per-org overlay lands"; P2 (FR-49)
/// landed, and a swap run to fix updates then took a two-org host off both
/// meshes (measured on the operator's Asahi box, 2026-10-19).
/// - The new primary is on iff its entry was `tun`: that org already ran an
///   OS TUN on this host. `netstack` cannot become a netstack primary
///   through config, so it starts off, and [`Promotion`] says so.
/// - The demoted entry is `tun` iff the old primary was on the mesh with
///   `overlay_multi_org` on (so it ran its own OS TUN) and both orgs share a
///   control plane, as `tun` requires. Otherwise off, as before.
///
/// The exit node a primary USES (`overlay_exit_node`) is org-specific and is
/// cleared; an exit node it OFFERS travels with its enrollment.
pub fn promote_org_to_primary(
    cfg: &mut AgentConfig,
    label: &str,
    demoted_label: Option<&str>,
) -> Result<Promotion> {
    let Some(idx) = cfg.orgs.iter().position(|o| o.label == label) else {
        anyhow::bail!("no org labelled {label:?} — see `roomlerd org ls`");
    };
    let demoted_label = match demoted_label {
        None => cfg.orgs[idx].label.clone(),
        Some(raw) => {
            let Some(clean) = sanitize_org_label(raw) else {
                anyhow::bail!(
                    "{raw:?} is not a usable org label (letters, digits and dashes; not \"primary\")"
                );
            };
            if cfg
                .orgs
                .iter()
                .enumerate()
                .any(|(i, o)| i != idx && o.label == clean)
            {
                anyhow::bail!("another org is already labelled {clean:?} — see `roomlerd org ls`");
            }
            clean
        }
    };
    let entry = cfg.orgs.remove(idx);
    let same_plane = entry.server_url == cfg.server_url;
    let primary_on = entry.overlay_mode == OrgOverlayMode::Tun;
    let primary_was_netstack = entry.overlay_mode == OrgOverlayMode::Netstack;
    let old_primary_on = cfg.overlay_enabled;
    let demoted_mode = if old_primary_on && cfg.overlay_multi_org && same_plane {
        OrgOverlayMode::Tun
    } else {
        OrgOverlayMode::Off
    };
    let demoted = OrgEntry {
        label: demoted_label.clone(),
        server_url: cfg.server_url.clone(),
        ws_url: cfg.ws_url.clone(),
        agent_token: cfg.agent_token.clone(),
        agent_id: cfg.agent_id.clone(),
        tenant_id: cfg.tenant_id.clone(),
        enabled: true,
        overlay_mode: demoted_mode,
        overlay_wg_secret_key: cfg.overlay_wg_secret_key.clone(),
        overlay_wg_key_epoch: cfg.overlay_wg_key_epoch,
        overlay_advertised_routes: cfg.overlay_advertised_routes.clone(),
        overlay_exit_node_enabled: cfg.overlay_exit_node_enabled,
        advertise_routes: cfg.advertise_routes.clone(),
        netstack_socks_port: entry.netstack_socks_port,
    };
    cfg.server_url = entry.server_url;
    cfg.ws_url = entry.ws_url;
    cfg.agent_token = entry.agent_token;
    cfg.agent_id = entry.agent_id;
    cfg.tenant_id = entry.tenant_id;
    cfg.overlay_wg_secret_key = entry.overlay_wg_secret_key;
    cfg.overlay_wg_key_epoch = entry.overlay_wg_key_epoch;
    cfg.overlay_advertised_routes = entry.overlay_advertised_routes;
    cfg.overlay_exit_node_enabled = entry.overlay_exit_node_enabled;
    cfg.overlay_exit_node = None;
    cfg.advertise_routes = entry.advertise_routes;
    cfg.overlay_enabled = primary_on;
    cfg.orgs.insert(idx, demoted);
    Ok(Promotion {
        demoted_label,
        primary_on,
        primary_was_netstack,
        demoted_mode,
        demoted_lost_mesh: old_primary_on && demoted_mode == OrgOverlayMode::Off,
    })
}

/// Normalize an operator-supplied org label: lowercase, spaces/`_` → `-`,
/// strip everything outside `[a-z0-9-]`, trim dashes, cap at 32 chars.
/// Returns `None` when nothing valid remains or the result would collide
/// with the reserved [`PRIMARY_ORG_LABEL`].
pub fn sanitize_org_label(raw: &str) -> Option<String> {
    let mut out = String::new();
    for ch in raw.trim().chars() {
        let ch = ch.to_ascii_lowercase();
        match ch {
            'a'..='z' | '0'..='9' => out.push(ch),
            ' ' | '_' | '-' | '.' if !out.ends_with('-') && !out.is_empty() => out.push('-'),
            _ => {}
        }
        if out.len() >= 32 {
            break;
        }
    }
    let out = out.trim_matches('-').to_string();
    if out.is_empty() || out == PRIMARY_ORG_LABEL {
        None
    } else {
        Some(out)
    }
}

impl AgentConfig {
    /// P5 — the effective set of CIDRs advertised on the L3 overlay: the
    /// configured [`overlay_advertised_routes`](Self::overlay_advertised_routes)
    /// unioned with the default route `0.0.0.0/0` when this node is an exit node
    /// ([`overlay_exit_node_enabled`](Self::overlay_exit_node_enabled)). This is
    /// what feeds the overlay runtime's `with_advertised_routes` — so the
    /// server sees `0.0.0.0/0` in `advertised_routes` and the admin UI offers
    /// the exit-node toggle. Order-preserving; `/0` is appended last and only if
    /// not already present (an operator may also list it explicitly).
    pub fn effective_overlay_advertised_routes(&self) -> Vec<String> {
        let mut routes = self.overlay_advertised_routes.clone();
        if self.overlay_exit_node_enabled {
            let default_route = "0.0.0.0/0".to_string();
            if !routes.contains(&default_route) {
                routes.push(default_route);
            }
        }
        routes
    }

    /// The TCP port the in-process SSH server intercepts on the overlay
    /// address: [`ssh_port`](Self::ssh_port), or the built-in default when
    /// unset. A configured `0` is treated as unset — port 0 means "any" to a
    /// binding API and nothing at all to an intercept rule, so honouring it
    /// would silently disable the feature.
    pub fn effective_ssh_port(&self) -> u16 {
        match self.ssh_port {
            Some(0) | None => DEFAULT_SSH_PORT,
            Some(p) => p,
        }
    }
}

/// Built-in intercepted SSH port. See [`AgentConfig::ssh_port`] for why this is
/// 2222 rather than 22.
pub const DEFAULT_SSH_PORT: u16 = 2222;

/// serde default for `advertise_local_subnets` — auto-detect is ON by default.
fn default_true() -> bool {
    true
}

/// Current schema version. Bumped whenever [`migrate`] gains a new
/// step. Persisted into the config file by the migration so subsequent
/// runs short-circuit the migration check.
///
/// `0.3.0-rc.300` — multi-org P1: `[[orgs]]` secondary enrollments. No
/// structural rewrite is needed (the scalar identity fields REMAIN the
/// primary org, and `orgs` serde-defaults to empty), so the step is a
/// stamp-only pass that rewrites the file with the current in-memory
/// shape.
pub const CURRENT_SCHEMA_VERSION: &str = "0.3.0-rc.300";

/// Apply schema migrations to `cfg` in place. Returns `true` when the
/// caller should persist the mutated config via [`save`]. Safe to call
/// on a freshly-loaded config of any age — same-version configs return
/// `false` after a no-op pass.
///
/// Migrations applied (rc.18 set):
/// 1. Trim trailing slash on `server_url` (older enrollment flows
///    occasionally left one in; harmless until something concatenates
///    a path).
/// 2. If `last_known_good_version` is a pre-rc.18 string (any 0.1.x or
///    0.2.x), reset `crash_count = 0` so the historical counter
///    doesn't trip the rc.18 rollback path.
/// 3. Stamp `config_schema_version = Some(CURRENT_SCHEMA_VERSION)` if
///    not already current.
///
/// Note: defaults for new fields (`enable_remote_browse`,
/// `auto_grant_session`, etc.) are applied at deserialize time by
/// `#[serde(default = "fn")]`. The migration's job is to ensure the
/// on-disk file matches the in-memory shape — so a future operator
/// reading `config.toml` sees ALL fields the running agent actually
/// uses, not just the ones they explicitly set when first enrolling.
pub fn migrate(cfg: &mut AgentConfig) -> bool {
    if cfg
        .config_schema_version
        .as_deref()
        .is_some_and(|v| v == CURRENT_SCHEMA_VERSION)
    {
        // Already on this schema; no-op.
        return false;
    }

    let mut changed = false;

    // 1. Trim trailing slash on server_url.
    let trimmed = cfg.server_url.trim_end_matches('/').to_string();
    if trimmed != cfg.server_url {
        cfg.server_url = trimmed;
        changed = true;
    }

    // 2. Reset crash_count when last_known_good_version is from a
    //    pre-rc.18 branch. The rollback heuristic is keyed off this
    //    counter; carrying it across branches could trip rollback
    //    against a healthy rc.18 install.
    if let Some(ref v) = cfg.last_known_good_version
        && (v.starts_with("0.1.") || v.starts_with("0.2."))
        && cfg.crash_count > 0
    {
        cfg.crash_count = 0;
        cfg.last_crash_unix = 0;
        changed = true;
    }

    // 3. Stamp the new schema version. ALWAYS persist after any
    //    migration ran, even if no other field changed — that's how
    //    we mark the file as having been processed.
    if cfg.config_schema_version.as_deref() != Some(CURRENT_SCHEMA_VERSION) {
        cfg.config_schema_version = Some(CURRENT_SCHEMA_VERSION.to_string());
        changed = true;
    }

    changed
}

/// How long a fresh run must survive before we promote its version
/// to `last_known_good_version` and reset the crash counter. Five
/// minutes is enough to rule out "agent crashed in startup init"
/// while still catching "agent ran fine then deadlocked at session
/// 0" reasonably fast.
pub const CLEAN_RUN_THRESHOLD_SECS: u64 = 5 * 60;

/// How recent a prior crash has to be for the next crash to count
/// against the same window. Ten minutes — chosen so an agent that
/// dies on cold start, gets relaunched in 60 s, and dies again
/// within those ten minutes is recognised as a crash loop and
/// triggers rollback after a few iterations.
pub const CRASH_WINDOW_SECS: u64 = 10 * 60;

/// How many crashes inside `CRASH_WINDOW_SECS` trip the rollback
/// path. Three is the sweet spot — fewer would fire on a single
/// hardware glitch (driver crash, transient OOM); more leaves a
/// genuinely-broken release running longer than necessary.
pub const ROLLBACK_THRESHOLD_CRASHES: u32 = 3;

impl AgentConfig {
    pub fn ws_url(&self) -> String {
        if let Some(url) = &self.ws_url {
            return url.clone();
        }
        derive_ws_url(&self.server_url)
    }

    /// FR-101 P1b — read every URL to a server over TLS: this enrollment's
    /// `server_url` and `ws_url`, and each `[[orgs]]` entry's. A plaintext URL
    /// to a remote host becomes its TLS twin (`roomler_ai_remote_control::
    /// server_url::secure`); loopback stays, and so does everything when the
    /// owner set [`Self::allow_plaintext_server`]. Applied by [`try_load`], the
    /// one parse every reader of the config goes through, so no consumer can
    /// dial the URL as written. Returns what changed, as (field, was) pairs.
    pub fn secure_server_urls(&mut self) -> Vec<(String, String)> {
        use roomler_ai_remote_control::server_url::secure;
        let allow = self.allow_plaintext_server;
        let mut changed = Vec::new();
        let mut one = |field: String, url: &mut String| {
            let s = secure(url, allow);
            if s.promoted {
                changed.push((field, std::mem::replace(url, s.url)));
            }
        };
        one("server_url".into(), &mut self.server_url);
        if let Some(ws) = self.ws_url.as_mut() {
            one("ws_url".into(), ws);
        }
        for (i, org) in self.orgs.iter_mut().enumerate() {
            one(format!("orgs[{i}].server_url"), &mut org.server_url);
            if let Some(ws) = org.ws_url.as_mut() {
                one(format!("orgs[{i}].ws_url"), ws);
            }
        }
        changed
    }
}

/// Mark the start of a fresh run. Sets `last_run_unhealthy=true`
/// optimistically — flipped back to false by either
/// [`record_clean_run_at`] (after the clean-run threshold) or by
/// [`mark_clean_shutdown`] (Ctrl-C handler). Caller saves config.
pub fn mark_run_starting(cfg: &mut AgentConfig) {
    cfg.last_run_unhealthy = true;
}

/// Record that the current run survived long enough to be
/// considered healthy. Resets the crash counter, promotes the
/// running version to `last_known_good_version`, clears the
/// rollback-attempted flag (so future genuine crash loops can
/// trigger another rollback), and clears the unhealthy flag.
pub fn record_clean_run_at(cfg: &mut AgentConfig, current_version: &str) {
    cfg.crash_count = 0;
    cfg.last_crash_unix = 0;
    cfg.rollback_attempted = false;
    cfg.last_run_unhealthy = false;
    cfg.last_known_good_version = Some(current_version.to_string());
}

/// Mark a graceful shutdown. Equivalent to "the run was healthy
/// from the rollback-detector's POV" — clears the unhealthy flag
/// without resetting the crash counter (a brief healthy run after
/// 2 prior crashes shouldn't wipe history that hasn't yet hit the
/// rollback threshold).
pub fn mark_clean_shutdown(cfg: &mut AgentConfig) {
    cfg.last_run_unhealthy = false;
}

/// Record a crash at the given unix timestamp. Increments the
/// counter when the prior crash was within `CRASH_WINDOW_SECS` of
/// `now_unix`; otherwise starts a fresh crash window at 1.
pub fn record_crash_at(cfg: &mut AgentConfig, now_unix: u64) {
    let prior = cfg.last_crash_unix;
    let in_window = prior > 0 && now_unix.saturating_sub(prior) <= CRASH_WINDOW_SECS;
    cfg.crash_count = if in_window {
        cfg.crash_count.saturating_add(1)
    } else {
        1
    };
    cfg.last_crash_unix = now_unix;
}

/// Whether the current state recommends rolling back to
/// `last_known_good_version`. Caller is responsible for actually
/// invoking the rollback (we keep the predicate pure for testing).
pub fn should_rollback(cfg: &AgentConfig, current_version: &str, now_unix: u64) -> bool {
    if cfg.rollback_attempted {
        return false;
    }
    let Some(target) = cfg.last_known_good_version.as_deref() else {
        return false;
    };
    if target == current_version {
        return false;
    }
    if cfg.crash_count < ROLLBACK_THRESHOLD_CRASHES {
        return false;
    }
    cfg.last_crash_unix > 0 && now_unix.saturating_sub(cfg.last_crash_unix) <= CRASH_WINDOW_SECS
}

/// Mark that we just spawned a rollback installer. Sets
/// `rollback_attempted=true` so a same-cycle re-trigger is
/// suppressed.
pub fn mark_rollback_attempted(cfg: &mut AgentConfig) {
    cfg.rollback_attempted = true;
}

/// TOML-friendly mirror of `encode::EncoderPreference`. Kept separate so
/// the `encode` module stays CLI-independent and the config file survives
/// feature gating without needing the `mf-encoder` feature enabled to
/// parse.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EncoderPreferenceChoice {
    #[default]
    Auto,
    Hardware,
    Software,
}

/// FR-108 — when a remote controller's display match may switch this host's
/// display mode to fit their window.
///
/// ⚠️ A value this build does not know reads as [`Self::Never`], never as an
/// error: it must not fail the whole config file, and the strictest reading
/// of a setting about someone's screen is to leave the screen alone.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DisplayMatchPolicy {
    /// Only while nobody is using this screen (the default).
    #[default]
    Auto,
    /// Whenever a controller asks (rc.191's behaviour), for a machine its
    /// owner never sits at.
    Always,
    /// Never.
    Never,
}

impl<'de> Deserialize<'de> for DisplayMatchPolicy {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Text(String),
            Other(serde::de::IgnoredAny),
        }
        Ok(match Raw::deserialize(d)? {
            Raw::Text(s) if s == "auto" => Self::Auto,
            Raw::Text(s) if s == "always" => Self::Always,
            // "never", anything a newer build may write, and anything that is
            // not a string at all.
            _ => Self::Never,
        })
    }
}

/// FR-100 P1c — whether this device checks the browser that offers it a
/// session (see `AgentConfig::peer_auth`).
///
/// ⚠️ A value this build does not know reads as [`Self::Audit`], never as an
/// error: it must not fail the whole config file. A newer build's `enforce`,
/// read by this one, keeps checking and recording without refusing anything
/// this build cannot enforce.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerAuthPolicy {
    /// Neither check, nor pin, nor record. The device still signs its answers.
    Off,
    /// Check every offer, pin each new browser key per user, record the
    /// verdict, refuse nothing (the default).
    #[default]
    Audit,
}

impl<'de> Deserialize<'de> for PeerAuthPolicy {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Text(String),
            Other(serde::de::IgnoredAny),
        }
        Ok(match Raw::deserialize(d)? {
            Raw::Text(s) if s == "off" => Self::Off,
            // "audit", a newer build's word, and anything that is not a string.
            _ => Self::Audit,
        })
    }
}

/// Resolve the default config path. Can be overridden by `--config` on the CLI.
/// Default for `enable_remote_browse` — `true` so a 0.3.0 install
/// preserves self-controlled-host auto-grant semantics. Operators on
/// org-controlled fleets explicitly set `enable_remote_browse = false`
/// in `config.toml`. Hard-coded helper instead of a `bool::default()`
/// because that defaults to `false`.
fn default_enable_remote_browse() -> bool {
    true
}

/// Default for `auto_grant_session` — `true` for back-compat with
/// every pre-0.3.x agent which auto-granted unconditionally
/// (signaling.rs:365 TODO). Org-controlled fleets opt out via
/// `config.toml`. See [`AgentConfig::auto_grant_session`] for the
/// security model.
fn default_auto_grant_session() -> bool {
    true
}

/// Daemon-wide config-WRITE lock (P6). The daemon has several runtime
/// writers of `config.toml` — the clean-run promotion task, the graceful
/// shutdown path, and the route reconciler's LocalAPI verbs. Each does a
/// reload-modify-save; interleaved unlocked, one writer's full-struct save
/// silently drops another's just-written field. Every daemon-side runtime
/// writer must hold this lock across its load→mutate→save. (Cross-PROCESS
/// writers — tray, CLI, wizard — remain last-writer-wins on the file;
/// [`save`]'s atomic rename keeps a torn file impossible either way.)
pub type WriteLock = std::sync::Arc<tokio::sync::Mutex<()>>;

/// A fully-populated config for unit tests in other modules (the route
/// reconciler persists through real [`save`]/[`load`] round-trips).
///
/// `#[cfg(test)]` alone stopped working when this module moved to its own
/// crate (P3e lever E): a DOWNSTREAM crate's test build compiles THIS crate
/// in normal mode, so the fixture vanished for `roomlerd`'s tests. The
/// `test-fixtures` feature is the standard escape — roomlerd enables it
/// from `[dev-dependencies]` only, so no production build ever carries it.
#[cfg(any(test, feature = "test-fixtures"))]
pub fn test_fixture() -> AgentConfig {
    AgentConfig {
        server_url: "https://example.invalid".into(),
        ws_url: None,
        agent_token: "tok".into(),
        agent_id: "aid".into(),
        tenant_id: "tid".into(),
        machine_id: "mid".into(),
        machine_name: "host".into(),
        ephemeral: false,
        encoder_preference: EncoderPreferenceChoice::Auto,
        update_check_interval_h: None,
        localapi_pipe_pool: None,
        enable_remote_browse: true,
        files_dir: None,
        auto_grant_session: true,
        exec_enabled: false,
        macos_supervise_gui_worker: false,
        power_policy: String::new(),
        companion_autostart: true,
        remote_config_enabled: false,
        local_restart_enabled: true,
        external_access_enabled: false,
        external_access_setup: None,
        external_access_verifier: None,
        external_consent_mode: None,
        external_max_permissions: None,
        ssh_enabled: false,
        ssh_port: None,
        ssh_authorized_keys: Vec::new(),
        ssh_host_key: None,
        ssh_account_mode: None,
        ssh_max_privilege: None,
        ssh_activity_log: false,
        hive_enabled: false,
        hive_accounts: BTreeMap::new(),
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
        ssh_exec_streaming: true,
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
        overlay_netstack_tcp_sack: None,
        overlay_netstack_tcp_min_rto_ms: None,
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
        overlay_route_reclaim: None,
        overlay_route_evict_winners_only: None,
        overlay_lan_route_repair: None,
        overlay_tun_persist: None,
        overlay_route_metric0: None,
        overlay_route_win: None,
        overlay_direct_port: None,
        overlay_iface_metric: None,
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
        keep_busy_enabled: true,
        privacy_mode_allowed: false,
        lock_on_end: Default::default(),
        display_match: Default::default(),
        peer_auth: Default::default(),
        rc_clipboard: Default::default(),
        rc_files: Default::default(),
        rc_audio: Default::default(),
        allow_plaintext_server: false,
        overlay_demote: None,
        overlay_upward_probe: None,
        rc_max_sessions: None,
        shared_encoder: None,
        overlay_rpf: None,
        last_known_good_version: None,
        crash_count: 0,
        last_crash_unix: 0,
        rollback_attempted: false,
        last_run_unhealthy: false,
        config_schema_version: None,
        forward_acl: AgentForwardAcl::default(),
        virtual_desktop_apps: crate::apps_config::VirtualDesktopAppsConfig::default(),
        overlay_enabled: false,
        overlay_multi_org: false,
        netstack_socks_port: None,
        derived_org: false,
        derived_netstack: false,
        overlay_wg_secret_key: None,
        overlay_wg_key_epoch: 0,
        overlay_advertised_routes: Vec::new(),
        overlay_exit_node_enabled: false,
        overlay_exit_node: None,
        advertise_routes: Vec::new(),
        advertise_local_subnets: true,
        tunnel_routes: Vec::new(),
        orgs: Vec::new(),
    }
}

/// rc.280 — the operator-grade bool knobs bridged config→env (the S2
/// fallback map), ONE source: `main.rs` feeds
/// `tunnel_core::env::register_config_fallbacks` from this, and the
/// config-surface parity test (`env_bridge_pairs_have_surface_parity`) walks
/// it against the editable key list. Before this the list was a literal in
/// `main.rs` — a key added to the surface but missed there silently didn't
/// bridge (`roomler config set` wrote TOML the daemon then ignored).
/// Suffixes are the `ROOMLERD_…` env suffixes (uppercase surface key).
/// Sibling-safe derived default for `overlay_direct_port` — constants
/// mirror tunnel-core's `direct.rs` layout (locked by an agent-crate test;
/// agent-core's tunnel-core dependency is optional, so no direct import):
/// 32 slots of stride 8 span bases `43648..=43896` (each slot's 8-port
/// bind-walk band stays disjoint from its neighbours'), and the
/// public-dial twin at base+256 lands every public band in
/// `43904..44159`, disjoint from all direct bands. A locally swallowed
/// band falls back to the SECOND derived region at base+512 before
/// giving up to ephemeral (see tunnel-core `SECOND_BAND_OFFSET`).
pub const DERIVED_PORT_BASE: u32 = 43648;
pub const DERIVED_PORT_SLOTS: u32 = 32;
pub const DERIVED_PORT_STRIDE: u32 = 8;

/// The machine's derived stable direct port: `base + (fnv1a-64(machine_id)
/// % slots) × stride`. FNV-1a is hand-rolled so the value can NEVER move
/// between releases (a moved port churns every grandfathered corp-firewall
/// flow once) — no hasher-crate upgrade may change it, and the test below
/// pins concrete outputs. Applied by the env bridge ONLY when the operator
/// left `overlay_direct_port` unset; an explicit value or a real env var
/// always wins.
pub fn derived_default_direct_port(machine_id: &str) -> u32 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in machine_id.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    DERIVED_PORT_BASE + (h % u64::from(DERIVED_PORT_SLOTS)) as u32 * DERIVED_PORT_STRIDE
}

#[cfg(test)]
mod derived_port_tests {
    use super::*;

    /// The derived port is a RELEASE-STABLE function of the machine id:
    /// concrete outputs are pinned so no refactor (hasher swap, slot
    /// arithmetic change) can silently move the fleet's stable ports and
    /// churn every grandfathered corp-firewall flow at once.
    #[test]
    fn derived_port_is_stable_in_range_and_spreads_siblings() {
        for id in ["", "a", "machine-1", "5C-80-B6-AA-BB-CC", "winhost-a-mid"] {
            let p = derived_default_direct_port(id);
            assert_eq!(p, derived_default_direct_port(id), "stable per id");
            assert!(
                (DERIVED_PORT_BASE
                    ..=DERIVED_PORT_BASE + (DERIVED_PORT_SLOTS - 1) * DERIVED_PORT_STRIDE)
                    .contains(&p),
                "in band: {p}"
            );
            assert_eq!(
                (p - DERIVED_PORT_BASE) % DERIVED_PORT_STRIDE,
                0,
                "on a slot: {p}"
            );
        }
        // Pinned concrete outputs (FNV-1a 64, offset basis 0xcbf29ce484222325,
        // prime 0x100000001b3): a change here IS the fleet-port migration.
        assert_eq!(derived_default_direct_port(""), 43688);
        assert_eq!(
            derived_default_direct_port("machine-1"),
            derived_default_direct_port("machine-1")
        );
        // Distinct ids usually land on distinct slots — the sibling case.
        let a = derived_default_direct_port("laptop-A");
        let b = derived_default_direct_port("laptop-B");
        assert_ne!(a, b, "the sample sibling pair must de-conflict");
    }
}

pub fn env_bridge_bools(cfg: &AgentConfig) -> [(&'static str, Option<bool>); 95] {
    [
        ("SHARED_ENCODER", cfg.shared_encoder),
        ("AREA_MIN_BITRATE", cfg.area_min_bitrate),
        ("MEASURED_CEILING", cfg.measured_ceiling),
        ("ENCODER_INPLACE_RATE", cfg.encoder_inplace_rate),
        ("ICE_RELAY_TCP", cfg.ice_relay_tcp),
        ("RATE_SLOW_START", cfg.rate_slow_start),
        ("MEDIA_THREAD", cfg.media_thread),
        ("PUMP_STALL_WATCH", cfg.pump_stall_watch),
        ("BG_REBUILD_CONSTRAINED", cfg.bg_rebuild_constrained),
        ("SLOW_LINK_FLOOR", cfg.slow_link_floor),
        ("CONSTRAINED_QUEUE_MEASURED", cfg.constrained_queue_measured),
        ("SEED_CONTRADICTION", cfg.seed_contradiction),
        ("VIEWER_RATE_CLAMP", cfg.viewer_rate_clamp),
        ("QUEUE_DRAIN", cfg.queue_drain),
        ("SLOW_LINK_PROFILE", cfg.slow_link_profile),
        ("BG_REBUILD", cfg.bg_rebuild),
        ("PAR_CONVERT", cfg.par_convert),
        ("FPS_PACE", cfg.fps_pace),
        ("RELAY_IDR_THRIFT", cfg.relay_idr_thrift),
        ("RELAY_AGE_FEEDBACK", cfg.relay_age_feedback),
        ("PRIORITY_RES_CAP", cfg.priority_res_cap),
        ("NVENC_SPATIAL_AQ", cfg.nvenc_spatial_aq),
        ("IDLE_REFINE", cfg.idle_refine),
        ("IDLE_REFINE_BALANCED", cfg.idle_refine_balanced),
        ("GPU_SCALE", cfg.gpu_scale),
        ("OVERLAY_LAN_CAPTURE_PROBE", cfg.overlay_lan_capture_probe),
        ("RELAY_CEILING_LEARN", cfg.relay_ceiling_learn),
        ("DRM_CAPTURE", cfg.drm_capture),
        ("UINPUT", cfg.uinput),
        ("PORTAL_CAPTURE", cfg.portal_capture),
        ("PORTAL_INPUT", cfg.portal_input),
        ("MUTTER_CAPTURE", cfg.mutter_capture),
        ("WINDOW_CAPTURE", cfg.window_capture),
        ("WAYLAND_AWARE", cfg.wayland_aware),
        ("WAYLAND_AUTO", cfg.wayland_auto),
        ("WAYLAND_AUTO_SYSTEM", cfg.wayland_auto_system),
        ("X11_AUTO_SYSTEM", cfg.x11_auto_system),
        ("MUTTER_INPUT", cfg.mutter_input),
        ("X11_DAMAGE", cfg.x11_damage),
        ("OVERLAY_KEY_ROTATION", cfg.overlay_key_rotation),
        ("OVERLAY_QUIC", cfg.overlay_quic),
        ("OVERLAY_DIRECT", cfg.overlay_direct),
        ("OVERLAY_DERP", cfg.overlay_derp),
        (
            "OVERLAY_SERVER_RELAY_STRATEGY",
            cfg.overlay_server_relay_strategy,
        ),
        ("OVERLAY_DERP_FLOOR", cfg.overlay_derp_floor),
        ("OVERLAY_ORG_RELAY", cfg.overlay_org_relay),
        ("OVERLAY_NETCHECK", cfg.overlay_netcheck),
        ("RELAY_SERVER_ENABLED", cfg.relay_server_enabled),
        ("TUNNEL_DERP_FALLBACK", cfg.tunnel_derp_fallback),
        ("TUNNEL_REUPGRADE", cfg.tunnel_reupgrade),
        (
            "TUNNEL_PEERS_SURVIVE_REATTACH",
            cfg.tunnel_peers_survive_reattach,
        ),
        ("OVERLAY_MBB", cfg.overlay_mbb),
        ("OVERLAY_LAN_IFACE_FILTER", cfg.overlay_lan_iface_filter),
        ("OVERLAY_WSL_MIRRORED_GUARD", cfg.overlay_wsl_mirrored_guard),
        ("OVERLAY_INIT_AUTH_FIRST", cfg.overlay_init_auth_first),
        ("OVERLAY_SRFLX_SEEK", cfg.overlay_srflx_seek),
        ("WS_REPLACED_EXIT", cfg.ws_replaced_exit),
        ("OVERLAY_WARM_RELAY", cfg.overlay_warm_relay),
        ("OVERLAY_QUIC_ASYNC", cfg.overlay_quic_async),
        ("OVERLAY_VPN_VANTAGE", cfg.overlay_vpn_vantage),
        ("OVERLAY_PORTMAP", cfg.overlay_portmap),
        ("OVERLAY_NETSTACK_TCP_PACING", cfg.overlay_netstack_tcp_pacing),
        ("OVERLAY_NETSTACK_TCP_SACK", cfg.overlay_netstack_tcp_sack),
        ("OVERLAY_IPV6", cfg.overlay_ipv6),
        ("NET_INVENTORY", cfg.net_inventory),
        ("OVERLAY_ROUTE_EVENTS", cfg.overlay_route_events),
        ("OVERLAY_NETMON", cfg.overlay_netmon),
        ("OVERLAY_RELAY_TLS", cfg.overlay_relay_tls),
        ("OVERLAY_SHARED_CARRIER", cfg.overlay_shared_carrier),
        ("OVERLAY_ROAM", cfg.overlay_roam),
        ("OVERLAY_PLANE_WATCHDOG", cfg.overlay_plane_watchdog),
        ("OVERLAY_SESSION_TRACE", cfg.overlay_session_trace),
        ("OVERLAY_DISCO_RESPOND", cfg.overlay_disco_respond),
        ("OVERLAY_DISCO_PROBE", cfg.overlay_disco_probe),
        (
            "OVERLAY_ANSWER_WHILE_FOLLOWED",
            cfg.overlay_answer_while_followed,
        ),
        ("OVERLAY_TUN_STABLE_GUID", cfg.overlay_tun_stable_guid),
        ("OVERLAY_ROUTE_EVICT", cfg.overlay_route_evict),
        ("OVERLAY_ROUTE_RECLAIM", cfg.overlay_route_reclaim),
        (
            "OVERLAY_ROUTE_EVICT_WINNERS_ONLY",
            cfg.overlay_route_evict_winners_only,
        ),
        ("OVERLAY_LAN_ROUTE_REPAIR", cfg.overlay_lan_route_repair),
        ("OVERLAY_TUN_PERSIST", cfg.overlay_tun_persist),
        ("OVERLAY_ROUTE_METRIC0", cfg.overlay_route_metric0),
        ("OVERLAY_ROUTE_WIN", cfg.overlay_route_win),
        ("LOCAL_TURN", cfg.local_turn),
        ("DNS_AAAA", cfg.dns_aaaa),
        ("MAGICDNS_HOSTS", cfg.magicdns_hosts),
        ("AUTO_UPDATE", cfg.auto_update),
        ("LOGS_UPLOAD_DISABLED", cfg.logs_upload_disabled),
        ("OVERLAY_TIER_DETECT", cfg.overlay_tier_detect),
        ("OVERLAY_RTT_Q", cfg.overlay_rtt_q),
        ("OVERLAY_UPWARD_PROBE", cfg.overlay_upward_probe),
        ("RELAY_PROBE", cfg.relay_probe),
        ("TEXT_MOD_NEUTRALIZE", cfg.text_mod_neutralize),
        ("CAPS_CACHE", cfg.caps_cache),
        ("FPS_HIGH", cfg.fps_high),
    ]
}

/// rc.280 — numeric twin of [`env_bridge_bools`] (decimal strings on the
/// same fallback map).
pub fn env_bridge_numerics(cfg: &AgentConfig) -> [(&'static str, Option<u32>); 35] {
    [
        ("OVERLAY_NETSTACK_TCP_RX_BUF", cfg.overlay_netstack_tcp_rx_buf),
        ("OVERLAY_NETSTACK_TCP_TX_BUF", cfg.overlay_netstack_tcp_tx_buf),
        ("OVERLAY_NETSTACK_TCP_MIN_RTO_MS", cfg.overlay_netstack_tcp_min_rto_ms),
        ("OVERLAY_IFACE_METRIC", cfg.overlay_iface_metric),
        ("RATE_FACTOR_H264", cfg.rate_factor_h264),
        ("RATE_FACTOR_HEVC", cfg.rate_factor_hevc),
        ("RATE_FACTOR_VP9", cfg.rate_factor_vp9),
        ("RATE_FACTOR_AV1", cfg.rate_factor_av1),
        ("RATE_FACTOR_H264_444", cfg.rate_factor_h264_444),
        ("RATE_FACTOR_HEVC_444", cfg.rate_factor_hevc_444),
        ("RATE_FACTOR_VP9_444", cfg.rate_factor_vp9_444),
        ("LANCZOS_MIN_PCT", cfg.lanczos_min_pct),
        ("SCALE_CQ_BOOST", cfg.scale_cq_boost),
        ("IDLE_REFINE_MAX_EDGE", cfg.idle_refine_max_edge),
        ("RELAY_MAX_HI_KBPS", cfg.relay_max_hi_kbps),
        ("IDLE_REFINE_MIN_FRAME_KB", cfg.idle_refine_min_frame_kb),
        (
            "IDLE_REFINE_MAJOR_AREA_PERMILLE",
            cfg.idle_refine_major_area_permille,
        ),
        ("IDLE_REFINE_SETTLE_MS", cfg.idle_refine_settle_ms),
        (
            "IDLE_REFINE_SETTLE_CONSTRAINED_MS",
            cfg.idle_refine_settle_constrained_ms,
        ),
        ("CONSTRAINED_CQ_RELIEF", cfg.constrained_cq_relief),
        ("CONSTRAINED_QUEUE_MS", cfg.constrained_queue_ms),
        ("SLOW_LINK_MIN_BITRATE", cfg.slow_link_min_bitrate),
        ("RELAY_MAX_KBPS", cfg.relay_max_kbps),
        ("PUMP_STALL_WARN_MS", cfg.pump_stall_warn_ms),
        ("SLOW_LINK_PROFILE_BPS", cfg.slow_link_profile_bps),
        ("CONSTRAINED_HRD_PCT", cfg.constrained_hrd_pct),
        ("DIRECT_QUEUE_MS", cfg.direct_queue_ms),
        ("DIRECT_HRD_PCT", cfg.direct_hrd_pct),
        ("SEND_STALL_MS", cfg.send_stall_ms),
        ("SMOOTHER_RATE_PCT", cfg.smoother_rate_pct),
        ("BALANCED_RATE_PCT", cfg.balanced_rate_pct),
        ("SCALE_THREADS", cfg.scale_threads),
        ("RC_MAX_SESSIONS", cfg.rc_max_sessions),
        ("OVERLAY_DIRECT_PORT", cfg.overlay_direct_port),
        ("RELAY_SERVER_PORT", cfg.relay_server_port),
    ]
}

/// S2 — the whole config→env fallback map (`tunnel_core::env`'s
/// `register_config_fallbacks`), built in ONE place. The daemon publishes it
/// at start, before anything reads a knob; FR-93 P1 has `capture-smoke` and
/// `input-smoke` publish the same map, so a key set with `roomler config set`
/// is honoured by the smoke test that is meant to prove it. Before that they
/// read env and built-in defaults only, and answered about a cascade the
/// daemon was not running.
///
/// Precedence at every read site: env (either prefix) > these fallbacks >
/// built-in default. Bools map to the "1"/"0" strings every read-site parser
/// already accepts.
pub fn env_fallbacks(cfg: &AgentConfig) -> std::collections::HashMap<String, String> {
    let mut fallbacks = std::collections::HashMap::new();
    // rc.280 — the pair lists live in `env_bridge_*` (one source,
    // parity-tested against the editable surface) instead of literals here.
    for (suffix, value) in env_bridge_bools(cfg) {
        if let Some(v) = value {
            fallbacks.insert(suffix.to_string(), if v { "1" } else { "0" }.to_string());
        }
    }
    // Numeric knobs ride the same map as their decimal strings.
    for (suffix, value) in env_bridge_numerics(cfg) {
        if let Some(v) = value {
            fallbacks.insert(suffix.to_string(), v.to_string());
        }
    }
    // Sibling-safe stable-port default (2026-08-15: both household
    // laptops pinned the fleet-wide 43648 behind ONE Fritz!Box — the
    // loser's srflx went per-destination and every inbound punch hit
    // the sibling ⇒ relay-locked pairs). Applied ONLY when the
    // operator left the key unset; like every bridge entry this is a
    // FALLBACK — an explicit config value or a real env var wins.
    if cfg.overlay_direct_port.is_none() {
        fallbacks.insert(
            "OVERLAY_DIRECT_PORT".to_string(),
            derived_default_direct_port(&cfg.machine_id).to_string(),
        );
    }
    // PR-D — overlay_pathmon is multi-state (on|shadow|off), so it rides
    // the fallback map as a string, not the bool pairs above.
    if let Some(mode) = &cfg.overlay_pathmon {
        fallbacks.insert("OVERLAY_PATHMON".to_string(), mode.clone());
    }
    // §6 item 5 — overlay_netstack_tcp_cc (reno|none), same string ride.
    if let Some(cc) = &cfg.overlay_netstack_tcp_cc {
        fallbacks.insert("OVERLAY_NETSTACK_TCP_CC".to_string(), cc.clone());
    }
    // B2 — overlay_demote (off|shadow|on), same string ride.
    if let Some(mode) = &cfg.overlay_demote {
        fallbacks.insert("OVERLAY_DEMOTE".to_string(), mode.clone());
    }
    // P4 — overlay_rpf (off|warn|enforce), same string ride.
    if let Some(mode) = &cfg.overlay_rpf {
        fallbacks.insert("OVERLAY_RPF".to_string(), mode.clone());
    }
    // P4 demotion — numeric heartbeat override, same string ride.
    if let Some(secs) = cfg.overlay_route_tick_secs {
        fallbacks.insert("OVERLAY_ROUTE_TICK_SECS".to_string(), secs.to_string());
    }
    // netstate — numeric debounce override, same string ride.
    if let Some(ms) = cfg.overlay_netmon_debounce_ms {
        fallbacks.insert("OVERLAY_NETMON_DEBOUNCE_MS".to_string(), ms.to_string());
    }
    // FR-77 — the cell denylist is a string key: it reaches the probe
    // child through `config_fallbacks_for_child` like every other knob.
    if let Some(v) = &cfg.encoder_cells_deny {
        fallbacks.insert("ENCODER_CELLS_DENY".to_string(), v.clone());
    }
    // FR-119 P2b — the frame-rate denylist, read by the pump once per session.
    if let Some(v) = &cfg.fps_deny {
        fallbacks.insert("FPS_DENY".to_string(), v.clone());
    }
    // FR-77 P4 / FR-78 P1 — the pinned hardware-frame devices reach the
    // probe child too.
    if let Some(v) = &cfg.vaapi_device {
        fallbacks.insert("VAAPI_DEVICE".to_string(), v.clone());
    }
    if let Some(v) = &cfg.d3d12_adapter {
        fallbacks.insert("D3D12_ADAPTER".to_string(), v.clone());
    }
    if let Some(v) = &cfg.vulkan_device {
        fallbacks.insert("VULKAN_DEVICE".to_string(), v.clone());
    }
    fallbacks
}

pub fn default_config_path() -> Result<PathBuf> {
    let dirs =
        crate::appdirs::project_dirs().context("could not resolve a platform config directory")?;
    let profile = dirs.config_dir().join("config.toml");

    // Linux SYSTEM installs resolve to `/etc/roomler/config.toml`, which is
    // what the packaged `roomlerd.service` passes as `--config`. Keeping the
    // two in agreement is the whole point: when they disagreed, a host could
    // run happily for weeks on an orphan `roomlerd run` (profile path) and
    // then die `no config found` the first time systemd started it.
    //
    // The legacy profile path still wins while it is the ONLY one present, so
    // a host whose migration has not run yet — or could not (see
    // `migrate_system_config`) — keeps working instead of losing its identity.
    #[cfg(target_os = "linux")]
    if crate::appdirs::running_as_root() {
        let system = crate::appdirs::system_config_path();
        if system.exists() {
            return Ok(system);
        }
        if profile.exists() {
            return Ok(profile);
        }
        // Neither exists: a fresh system install. `enroll` writes here, so the
        // unit finds it without a drop-in.
        return Ok(system);
    }

    Ok(profile)
}

// RETIRED-NAME-ANCHOR(2): names the PRE-RENAME appdirs segment a host installed before
// P4b still has; appdirs::app_segment resolves it, so it is an input.
/// rc.52: machine-global config path —
/// `%PROGRAMDATA%\roomler\roomler\config.toml` (a pre-rename host keeps
/// its `\roomler\roomler-agent\` tree — see `appdirs::app_segment`).
///
/// `default_config_path()` resolves to a per-USER profile
/// (`%APPDATA%` via `ProjectDirs`). A SystemContext worker runs as
/// LocalSystem and, crucially, must be able to load its config
/// BEFORE any interactive user logs in (the whole point of M3 A1
/// pre-logon control). A user-profile path is unreachable pre-logon;
/// `%PROGRAMDATA%` is machine-global and LocalSystem-readable with no
/// logged-in user. The perMachine + SystemContext installer writes
/// the enrolled config here; the worker's resolution ladder consults
/// it ahead of the (never-populated) SYSTEM-profile default.
///
/// Windows-only — there is no machine-global config concept on
/// Linux/macOS (the agent there is perUser). Returns `None` if
/// `%PROGRAMDATA%` can't be resolved (it always can on a sane
/// Windows install; the `C:\ProgramData` literal is the documented
/// fallback used elsewhere in the crate).
/// W4(c) — restrict the machine-global config directory to SYSTEM +
/// Administrators, inheritance OFF, applied to existing children (`/T`).
/// SIDs, not names, so it survives localized Windows (this fleet runs
/// German builds where BUILTIN\Users is "Benutzer"): S-1-5-18 = SYSTEM,
/// S-1-5-32-544 = Administrators, S-1-5-32-545 = Users, S-1-5-11 =
/// Authenticated Users. Idempotent and best-effort: a failure WARNs and
/// the save proceeds — an unhardened save is the pre-W4 status quo, not a
/// new exposure. Closing the remaining pre-planted-CONTENT hole (verify
/// the file's OWNER at SystemContext load) is tracked for the Track-A
/// config unification.
#[cfg(windows)]
fn harden_machine_global_dir(dir: &std::path::Path) {
    let d = dir.display().to_string();
    let steps: [&[&str]; 3] = [
        &["/inheritance:r"],
        &["/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"],
        &["/remove", "*S-1-5-32-545", "*S-1-5-11", "/T"],
    ];
    for args in steps {
        match std::process::Command::new("icacls")
            .arg(&d)
            .args(args)
            .output()
        {
            Ok(o) if o.status.success() => {}
            Ok(o) => tracing::warn!(
                dir = %d, ?args,
                stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                "config: machine-global dir ACL hardening step failed"
            ),
            Err(e) => {
                tracing::warn!(dir = %d, %e, "config: icacls spawn failed; dir ACL unhardened");
                return;
            }
        }
    }
}

#[cfg(target_os = "windows")]
pub fn machine_global_config_path() -> PathBuf {
    crate::appdirs::machine_global_dir().join("config.toml")
}

/// Sibling copy of the last config that both saved AND parsed, kept so an
/// unreadable live file can be recovered without re-enrolling the host.
fn prev_path(path: &std::path::Path) -> PathBuf {
    path.with_extension("toml.prev")
}

pub fn load(path: &PathBuf) -> Result<AgentConfig> {
    let err = match try_load(path) {
        Ok(cfg) => return Ok(cfg),
        Err(e) => e,
    };

    // SELF-HEAL (2026-08-12): the live file is unreadable — on devbox an
    // unclean shutdown left it the right length and entirely NUL, and the
    // worker then exit-1'd every 60 s for hours because a bricked config
    // has no recovery path but re-enrollment. If the `.prev` rotation
    // parses, promote it: a slightly stale config still holds the same
    // `agent_token`/`machine_id`, so the host rejoins on its own and the
    // server reconciles the rest. Loud, because silently running on an
    // older config must never look like a normal boot.
    let prev = prev_path(path);
    match try_load(&prev) {
        Ok(cfg) => {
            tracing::error!(
                path = %path.display(),
                recovered_from = %prev.display(),
                error = %format!("{err:#}"),
                "config unreadable — RECOVERED from the previous good copy; \
                 the live file was likely truncated by an unclean shutdown"
            );
            // Reinstate it as the live file so the next save has a base.
            if let Err(e) = save(path, &cfg) {
                tracing::warn!(error = %format!("{e:#}"), "could not reinstate recovered config");
            }
            Ok(cfg)
        }
        Err(prev_err) => {
            tracing::error!(
                path = %path.display(),
                error = %format!("{err:#}"),
                prev = %prev_path(path).display(),
                prev_error = %format!("{prev_err:#}"),
                "config unreadable and no usable previous copy — the host must be re-enrolled"
            );
            Err(err)
        }
    }
}

/// Read a config that is EXPECTED to be absent — a probe, not a load.
///
/// FR-66. [`load`] is deliberately **not** a neutral reader: on the
/// both-copies-missing arm it logs `the host must be re-enrolled` at ERROR.
/// That is correct for the config a process RUNS ON — it is the 2026-08-12
/// all-NUL self-heal, where the worker really was exit-1'ing every 60 s and
/// re-enrollment really was the remedy — and wrong for a caller merely asking
/// whether an optional file happens to exist.
///
/// The distinction is not academic: `netd_enabled()` probed the machine-global
/// path through `load` for one optional boolean, so every healthy user-context
/// install (worker in session 1, config under `%APPDATA%`) was told to
/// re-enroll on **every service start**, about a host with both enrollments
/// connected. The prescribed remedy is destructive — removal is final and a
/// re-enrolled device never gets its old overlay address back — and the noise
/// also buried the genuine all-NUL case, which emits the identical line.
///
/// Absent, unreadable and unparseable all collapse to `None`: a probe has no
/// recovery path and no opinion about which it hit. Details go to `debug!`.
///
/// ⚠️ Never use this for the config the process runs on. Silently returning
/// `None` there is precisely the "running on an older config must never look
/// like a normal boot" failure that [`load`]'s ERROR exists to prevent.
pub fn read_if_present(path: &PathBuf) -> Option<AgentConfig> {
    match try_load(path) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            tracing::debug!(
                path = %path.display(),
                error = %format!("{e:#}"),
                "optional config not readable — treating as absent"
            );
            None
        }
    }
}

fn try_load(path: &PathBuf) -> Result<AgentConfig> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading config at {}", path.display()))?;
    // An all-NUL file of the correct length is the signature of a power loss
    // between `rename` and the data reaching disk. `toml` reports it as a
    // parse error at line 1, which reads like a hand-edit typo; name it.
    if !raw.is_empty() && raw.bytes().all(|b| b == 0) {
        anyhow::bail!(
            "config at {} is {} bytes of NUL (truncated by an unclean shutdown)",
            path.display(),
            raw.len()
        );
    }
    let mut cfg: AgentConfig =
        toml::from_str(&raw).with_context(|| format!("parsing config at {}", path.display()))?;
    // FR-101 P1b — TLS to the server whatever the file says, unless its owner
    // kept plaintext (`allow_plaintext_server`). Here, because every reader
    // parses through this function: the daemon, the probe, the recovery.
    for (field, was) in cfg.secure_server_urls() {
        tracing::warn!(
            path = %path.display(),
            field = %field,
            was = %was,
            "a plaintext server URL in the config is read as TLS; set \
             allow_plaintext_server = true to keep plaintext (a lab without TLS)"
        );
    }
    Ok(cfg)
}

pub fn save(path: &PathBuf, cfg: &AgentConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating parent dir {}", parent.display()))?;
    }
    let serialised = toml::to_string_pretty(cfg).context("serialising config")?;

    // ATOMIC (P6 hardening): write a sibling temp file, then rename over
    // the target. The file holds `agent_token` — a torn `fs::write`
    // (power loss / crash mid-write) used to brick enrollment. `rename`
    // within one directory is atomic on Unix and uses
    // MOVEFILE_REPLACE_EXISTING semantics on Windows. The temp name is
    // pid-suffixed so two PROCESSES (daemon + tray/CLI) can't collide on
    // the temp file itself; last-writer-wins on the rename is the
    // documented cross-process limitation.
    //
    // DURABILITY (2026-08-12): rename-atomicity alone does NOT survive
    // power loss — it only orders the *metadata*. NTFS journals metadata
    // but not file data, so a rename can land while the temp file's bytes
    // are still in the page cache; the post-crash file then has the right
    // name and the right LENGTH but is entirely NUL. That is not a
    // hypothetical: devbox lost power mid-save and came back with a
    // 2995-byte all-NUL config.toml, which crash-looped the worker
    // (exit 1 immediately after "resolved load path") until re-enrolled.
    // `sync_all()` before the rename is what makes the guarantee real:
    // the bytes are on disk first, so the crash window can only ever
    // yield the OLD file or the NEW file.
    let tmp = path.with_extension(format!("toml.tmp.{}", std::process::id()));
    {
        use std::io::Write as _;
        let mut f = std::fs::File::create(&tmp)
            .with_context(|| format!("creating config temp file {}", tmp.display()))?;
        f.write_all(serialised.as_bytes())
            .with_context(|| format!("writing config temp file {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync config temp file {}", tmp.display()))?;
    }

    // Tighten permissions on Unix BEFORE the rename — the file holds a
    // bearer token, and the temp file must never be world-readable even
    // for an instant at the final path.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&tmp)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&tmp, perms)?;
    }
    // W4(c) — the Windows twin, for the MACHINE-GLOBAL location only: the
    // ProgramData default ACL leaves the config (agent bearer token!)
    // BUILTIN\Users-readable, and a non-admin could even pre-create the
    // dir/file a SYSTEM-context worker later loads. Harden the directory
    // before the rename so the renamed file and the `.prev` rotation
    // inherit the tightened ACEs; `/T` re-ACLs children already present.
    #[cfg(windows)]
    if path.starts_with(crate::appdirs::machine_global_dir())
        && let Some(dir) = path.parent()
    {
        harden_machine_global_dir(dir);
    }

    // Rotate the outgoing file to `.prev` so `load` has something to recover
    // from. Gated on it still parsing: a corrupt live file must never be
    // allowed to overwrite the last known-good rotation. Best-effort — a
    // failed rotation costs recoverability, not correctness. On Unix
    // `fs::copy` carries the source's 0600 across, so the token stays private.
    if try_load(path).is_ok() {
        let _ = std::fs::copy(path, prev_path(path));
    }

    std::fs::rename(&tmp, path).with_context(|| {
        // Best-effort cleanup so failed saves don't accrete temp files.
        let _ = std::fs::remove_file(&tmp);
        format!("renaming config into place at {}", path.display())
    })?;

    // Make the rename itself durable. Best-effort: a failure here means the
    // save is still correct in the page cache, so it must not fail the call.
    // Unix only — std cannot open a directory as a File on Windows, and the
    // temp-file `sync_all()` above is the load-bearing half regardless.
    #[cfg(unix)]
    if let Some(parent) = path.parent()
        && let Ok(dir) = std::fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

fn derive_ws_url(http_url: &str) -> String {
    let base = http_url.trim_end_matches('/');
    let ws = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        base.to_string()
    };
    format!("{ws}/ws")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FR-93 P1 — the ONE fallback map, which the daemon and both smoke
    /// commands publish: every kind of bridged value reaches it, an unset key
    /// publishes nothing, and the derived stable port fills in only while the
    /// operator left it unset.
    #[test]
    fn env_fallbacks_carry_every_bridged_kind() {
        let mut cfg = test_fixture();
        cfg.drm_capture = Some(true);
        cfg.uinput = Some(false);
        cfg.overlay_pathmon = Some("shadow".into());
        cfg.overlay_netstack_tcp_cc = Some("none".into());
        cfg.encoder_cells_deny = Some("h264/nvenc".into());
        cfg.fps_deny = Some("hevc_qsv:120".into());
        let m = env_fallbacks(&cfg);
        let get = |k: &str| m.get(k).map(String::as_str);
        assert_eq!(get("FPS_DENY"), Some("hevc_qsv:120"));
        assert_eq!(get("DRM_CAPTURE"), Some("1"));
        assert_eq!(
            get("UINPUT"),
            Some("0"),
            "an explicit false is published, as 0"
        );
        assert_eq!(get("OVERLAY_PATHMON"), Some("shadow"));
        assert_eq!(get("OVERLAY_NETSTACK_TCP_CC"), Some("none"));
        assert_eq!(get("ENCODER_CELLS_DENY"), Some("h264/nvenc"));
        assert_eq!(
            get("PORTAL_CAPTURE"),
            None,
            "an unset key publishes nothing"
        );
        let derived = derived_default_direct_port(&cfg.machine_id).to_string();
        assert_eq!(get("OVERLAY_DIRECT_PORT"), Some(derived.as_str()));

        cfg.overlay_direct_port = Some(41641);
        assert_eq!(
            env_fallbacks(&cfg)
                .get("OVERLAY_DIRECT_PORT")
                .map(String::as_str),
            Some("41641"),
            "the operator's port, not the derived one"
        );
    }

    /// Smallest document `try_load` accepts — enough to exercise save/load.
    fn minimal_toml() -> String {
        r#"
server_url = "https://roomler.ai"
agent_token = "tok"
agent_id = "aid"
tenant_id = "tid"
machine_id = "mid"
machine_name = "devbox"
"#
        .to_string()
    }

    /// Locks the devbox incident (2026-08-12): an unclean shutdown left
    /// config.toml the right LENGTH and entirely NUL, and the worker exit-1'd
    /// every 60 s for hours because a bricked config had no recovery path.
    /// Two properties: the corruption is named rather than reported as a
    /// line-1 TOML syntax error, and the `.prev` rotation heals the host.
    #[test]
    fn all_nul_config_is_named_and_recovered_from_the_previous_copy() {
        let dir = std::env::temp_dir().join(format!("rmlcfg-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("config.toml");

        // A good save, then a second one — the first rotates into `.prev`.
        let cfg: AgentConfig = toml::from_str(&minimal_toml()).expect("minimal config parses");
        save(&path, &cfg).expect("first save");
        save(&path, &cfg).expect("second save populates .prev");
        assert!(prev_path(&path).exists(), ".prev rotation must exist");

        // Reproduce the corruption exactly: same length, all NUL.
        let len = std::fs::metadata(&path).unwrap().len() as usize;
        std::fs::write(&path, vec![0u8; len]).unwrap();

        // Named, not "expected an equals, found an identifier at line 1".
        let msg = format!("{:#}", try_load(&path).unwrap_err());
        assert!(
            msg.contains("NUL") && msg.contains("unclean shutdown"),
            "corruption must be named, got: {msg}"
        );

        // And the host heals instead of crash-looping.
        let healed = load(&path).expect("must recover from .prev");
        assert_eq!(healed.machine_name, "devbox");
        assert_eq!(healed.agent_token, "tok");
        // The recovered copy is reinstated, so the next boot is clean.
        assert_eq!(
            try_load(&path).expect("live file reinstated").machine_id,
            "mid"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A corrupt live file must never be allowed to destroy the good rotation.
    #[test]
    fn rotation_refuses_to_overwrite_prev_with_a_corrupt_live_file() {
        let dir = std::env::temp_dir().join(format!("rmlcfg2-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("config.toml");

        let cfg: AgentConfig = toml::from_str(&minimal_toml()).expect("parses");
        save(&path, &cfg).unwrap();
        save(&path, &cfg).unwrap();
        let good = std::fs::read_to_string(prev_path(&path)).unwrap();

        std::fs::write(&path, vec![0u8; 64]).unwrap();
        save(&path, &cfg).unwrap(); // save over the corrupt file

        assert_eq!(
            std::fs::read_to_string(prev_path(&path)).unwrap(),
            good,
            ".prev must still hold the last PARSEABLE config"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ws_url_from_https() {
        assert_eq!(
            derive_ws_url("https://roomler.live"),
            "wss://roomler.live/ws"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn machine_global_config_path_under_programdata_roomler() {
        let p = machine_global_config_path();
        let s = p.to_string_lossy().to_lowercase();
        assert!(s.contains("roomler"), "path missing roomler: {s}");
        // S1b: appdirs resolves the NEW `roomler` segment on fresh/migrated
        // RETIRED-NAME-ANCHOR(6): pins the pre-rename fallback. The whole
        // point of the assertion is that BOTH segments are accepted.
        // machines and the legacy `roomler-agent` on pre-migration hosts —
        // both are valid; the old exact-tail assertion failed on any clean
        // Windows box.
        assert!(
            s.ends_with(r"roomler\roomler-agent\config.toml")
                || s.ends_with(r"roomler\roomler\config.toml"),
            "unexpected tail: {s}"
        );
        // Distinct from the perUser default (which is under %APPDATA%).
        assert_ne!(p, default_config_path().unwrap());
    }

    #[test]
    fn ws_url_from_http_localhost() {
        assert_eq!(
            derive_ws_url("http://localhost:3000"),
            "ws://localhost:3000/ws"
        );
    }

    /// Write `toml` as a config file and load it the way every reader does.
    fn load_toml(toml: &str) -> AgentConfig {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, toml).expect("write config");
        load(&path).expect("config loads")
    }

    /// FR-101 AC3, on the load path: a config holding `http://roomler.ai`
    /// signals over `wss://`, while `http://127.0.0.1` stays `ws://`.
    #[test]
    fn a_plaintext_server_url_is_read_as_tls_and_loopback_is_not() {
        let remote = load_toml(&minimal_toml().replace(
            "server_url = \"https://roomler.ai\"",
            "server_url = \"http://roomler.ai\"",
        ));
        assert_eq!(remote.server_url, "https://roomler.ai");
        assert_eq!(remote.ws_url(), "wss://roomler.ai/ws");

        let local = load_toml(&minimal_toml().replace(
            "server_url = \"https://roomler.ai\"",
            "server_url = \"http://127.0.0.1:3000\"",
        ));
        assert_eq!(local.server_url, "http://127.0.0.1:3000");
        assert_eq!(local.ws_url(), "ws://127.0.0.1:3000/ws");
    }

    /// The owner's escape keeps plaintext as written; an explicit `ws_url` and
    /// every `[[orgs]]` entry are read over TLS like the primary.
    #[test]
    fn every_server_url_is_secured_unless_the_owner_kept_plaintext() {
        let toml = minimal_toml().replace(
            "server_url = \"https://roomler.ai\"",
            "server_url = \"http://roomler.ai\"\nws_url = \"ws://roomler.ai/ws\"",
        ) + r#"
[[orgs]]
label = "other"
server_url = "HTTP://other.example"
agent_token = "tok2"
agent_id = "aid2"
tenant_id = "tid2"
"#;
        let cfg = load_toml(&toml);
        assert_eq!(cfg.server_url, "https://roomler.ai");
        assert_eq!(cfg.ws_url(), "wss://roomler.ai/ws");
        assert_eq!(cfg.orgs[0].server_url, "https://other.example");
        assert_eq!(cfg.orgs[0].ws_url(), "wss://other.example/ws");

        let lab = load_toml(&format!("allow_plaintext_server = true\n{toml}"));
        assert_eq!(lab.server_url, "http://roomler.ai");
        assert_eq!(lab.ws_url(), "ws://roomler.ai/ws");
        assert_eq!(lab.orgs[0].server_url, "HTTP://other.example");
    }

    /// The escape is the owner's alone: absent from a file it reads as off,
    /// and off never reaches the file.
    #[test]
    fn the_plaintext_escape_is_off_unless_written() {
        let cfg: AgentConfig = toml::from_str(&minimal_toml()).expect("parses");
        assert!(!cfg.allow_plaintext_server);
        let written = toml::to_string_pretty(&cfg).expect("serialises");
        assert!(!written.contains("allow_plaintext_server"), "{written}");
    }

    #[test]
    fn ws_url_strips_trailing_slash() {
        assert_eq!(
            derive_ws_url("https://roomler.live/"),
            "wss://roomler.live/ws"
        );
    }

    // The fixture body moved to `super::test_fixture` (P3e lever E: it must
    // exist under the `test-fixtures` FEATURE too, and this `#[cfg(test)]`
    // module doesn't). Alias kept so the 29 in-module callers read the same.
    pub(super) fn fixture() -> AgentConfig {
        super::test_fixture()
    }

    /// A minimal valid secondary-org entry for tests.
    pub(super) fn org_fixture(label: &str, tenant: &str) -> OrgEntry {
        OrgEntry {
            label: label.to_string(),
            server_url: "https://example.invalid".into(),
            ws_url: None,
            agent_token: format!("tok-{label}"),
            agent_id: format!("aid-{label}"),
            tenant_id: tenant.to_string(),
            enabled: true,
            overlay_mode: OrgOverlayMode::Off,
            overlay_wg_secret_key: None,
            overlay_wg_key_epoch: 0,
            overlay_advertised_routes: Vec::new(),
            overlay_exit_node_enabled: false,
            advertise_routes: Vec::new(),
            netstack_socks_port: None,
        }
    }

    #[test]
    fn orgs_toml_round_trip_preserves_entries() {
        let mut cfg = fixture();
        cfg.orgs = vec![
            org_fixture("acme", "tid-acme"),
            OrgEntry {
                enabled: false,
                overlay_mode: OrgOverlayMode::Netstack,
                overlay_wg_secret_key: Some("KEY-B".into()),
                overlay_advertised_routes: vec!["10.9.0.0/24".into()],
                advertise_routes: vec!["192.168.7.0/24".into()],
                ..org_fixture("beta-corp", "tid-beta")
            },
        ];
        let toml_str = toml::to_string_pretty(&cfg).expect("serialise");
        let back: AgentConfig = toml::from_str(&toml_str).expect("parse");
        assert_eq!(back.orgs, cfg.orgs, "orgs must survive a TOML round-trip");
        // The scalar (primary) identity is untouched by the table.
        assert_eq!(back.agent_id, cfg.agent_id);
        assert_eq!(back.tenant_id, cfg.tenant_id);
    }

    /// A stored PEM must survive a save→load→save cycle, including one that
    /// picked up CRLF somewhere along the way.
    ///
    /// ⚠️ **This test passes on unmodified code, and that is its result.** It
    /// was written to reproduce the field defect in roomler-ai#1564 — a corp
    /// laptop whose `ssh_host_key` held the literal text
    /// `-----BEGIN OPENSSH PRIVATE KEY-----\r\r\`, so the PEM's boundary line
    /// was not newline-terminated and every start logged `PEM error in
    /// pre-encapsulation boundary`. The proposed mechanism was that a CRLF in
    /// the value round-trips through `to_string_pretty` into `\r` escape text
    /// and then into a bare CR.
    ///
    /// It does not. `toml` 0.9 round-trips a CRLF-bearing PEM twice with the
    /// boundary line intact and no escape text in the value. So the save/load
    /// path we ship is **not** how that device's key was mangled, and the origin
    /// is still unknown — an older serializer, an editor writing the escapes
    /// directly, or a writer nobody has thought of yet. Do not cite this test as
    /// an explanation of #1564; it is a forward guard on the property, and it
    /// goes red if the serializer or its escaping is ever swapped.
    ///
    /// Kept because it is cheap and the property is real, and because the next
    /// person to chase that origin should not re-run the experiment that already
    /// came back negative.
    #[test]
    fn a_stored_key_survives_a_round_trip_even_with_crlf_in_it() {
        let pem_lf =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAABBBB\n-----END OPENSSH PRIVATE KEY-----\n";
        let pem_crlf = pem_lf.replace('\n', "\r\n");

        for (label, pem) in [("lf", pem_lf.to_string()), ("crlf", pem_crlf)] {
            let mut cfg = fixture();
            cfg.ssh_host_key = Some(pem.clone());

            // Two full cycles: the field defect only appeared on a LATER save,
            // so one round trip is not enough to reproduce the class.
            let mut current = cfg;
            for pass in 1..=2 {
                let text = toml::to_string_pretty(&current).expect("serialise");
                current = toml::from_str(&text).unwrap_or_else(|e| {
                    panic!("{label}: pass {pass} failed to re-parse its own output: {e}")
                });
            }

            let back = current.ssh_host_key.expect("the key must still be there");
            // The property that actually matters: the boundary line is still a
            // whole line. Comparing to the original would be too strict for the
            // crlf case and too weak for what broke — a PEM whose BEGIN runs
            // into the base64 is exactly what `from_openssh` refuses.
            let first = back.lines().next().unwrap_or("");
            assert_eq!(
                first.trim_end_matches('\r'),
                "-----BEGIN OPENSSH PRIVATE KEY-----",
                "{label}: the boundary line did not survive: {first:?}"
            );
            assert!(
                !back.contains("\\r"),
                "{label}: the round trip left literal backslash-r escape text in the value, \
                 which is the exact shape that wedged a device in the field: {back:?}"
            );
        }
    }

    #[test]
    fn config_without_orgs_field_loads_and_serialises_without_it() {
        // Back-compat both ways: a legacy file has no `orgs` (defaults
        // empty), and a single-org config never writes the key (so a
        // rollback binary's parser has nothing to trip on).
        let raw = r#"
            server_url = "https://example.invalid"
            agent_token = "tok"
            agent_id = "aid"
            tenant_id = "tid"
            machine_id = "mid"
            machine_name = "host"
        "#;
        let cfg: AgentConfig = toml::from_str(raw).expect("legacy config must parse");
        assert!(cfg.orgs.is_empty());
        let out = toml::to_string_pretty(&cfg).expect("serialise");
        assert!(
            !out.contains("[[orgs]]"),
            "empty orgs table must not be written: {out}"
        );
    }

    #[test]
    fn for_org_swaps_identity_and_forces_overlay_off() {
        let mut cfg = fixture();
        cfg.overlay_enabled = true;
        cfg.overlay_wg_secret_key = Some("PRIMARY-KEY".into());
        cfg.overlay_exit_node = Some("exit-1".into());
        cfg.tunnel_routes = vec![roomler_localapi::RouteDescriptor {
            id: "r1".into(),
            kind: roomler_localapi::FlowKind::Forward,
            node: "aid".into(),
            local: 18080,
            remote: Some("127.0.0.1:80".into()),
            transport: String::new(),
            enabled: true,
            org: None,
        }];
        let mut org = org_fixture("acme", "tid-acme");
        org.overlay_wg_secret_key = Some("ACME-KEY".into());
        org.advertise_routes = vec!["10.1.0.0/24".into()];
        cfg.orgs = vec![org.clone()];

        let oc = cfg.for_org(&org);
        // Identity comes from the entry…
        assert_eq!(oc.server_url, org.server_url);
        assert_eq!(oc.agent_token, "tok-acme");
        assert_eq!(oc.agent_id, "aid-acme");
        assert_eq!(oc.tenant_id, "tid-acme");
        // …machine identity + operator knobs are shared…
        assert_eq!(oc.machine_id, cfg.machine_id);
        assert_eq!(oc.machine_name, cfg.machine_name);
        // …the org's own WG key rides along (never the primary's)…
        assert_eq!(oc.overlay_wg_secret_key.as_deref(), Some("ACME-KEY"));
        assert_eq!(oc.advertise_routes, vec!["10.1.0.0/24".to_string()]);
        // …and P1 forces the overlay + route surfaces off/empty.
        assert!(!oc.overlay_enabled, "P1: secondary overlay must be OFF");
        assert!(!oc.overlay_exit_node_enabled);
        assert!(oc.overlay_exit_node.is_none());
        assert!(oc.tunnel_routes.is_empty());
        assert!(oc.orgs.is_empty(), "no recursive org table");
    }

    /// P2c — a `tun` secondary's gate lifts ONLY when every condition holds:
    /// the operator flag, `overlay_mode = tun`, the primary's own control
    /// plane, and the org's own WG key. Each missing leg keeps the P1
    /// behaviour for exactly that org. #2493 — a `netstack` one's gate is its
    /// own port and its own key.
    #[test]
    fn for_org_lifts_overlay_only_under_the_p2c_gate() {
        let mut cfg = fixture();
        cfg.overlay_multi_org = true;
        let mut org = org_fixture("acme", "tid-acme");
        org.overlay_mode = OrgOverlayMode::Tun;
        org.server_url = cfg.server_url.clone(); // same control plane
        org.overlay_wg_secret_key = Some("ACME-KEY".into());

        // All four conditions hold ⇒ the secondary joins.
        assert!(cfg.for_org(&org).overlay_enabled, "full gate ⇒ ON");

        // Flag off ⇒ P1 behaviour, everything else unchanged.
        cfg.overlay_multi_org = false;
        assert!(!cfg.for_org(&org).overlay_enabled, "no operator opt-in");
        cfg.overlay_multi_org = true;

        // A foreign control plane can't ride a tun adapter (its blocks come
        // from a different registry).
        let mut foreign = org.clone();
        foreign.server_url = "https://other.invalid".into();
        assert!(
            !cfg.for_org(&foreign).overlay_enabled,
            "foreign server, tun"
        );
        assert!(
            !cfg.for_org(&org).derived_netstack,
            "a tun org takes its TUN"
        );

        // #2493 — netstack joins with a port of its own, on any control plane
        // and without the opt-in, and stays off without a port or a key.
        // Before the fix every one of these read OFF while `status` said
        // `overlay netstack`.
        let mut ns = org.clone();
        ns.overlay_mode = OrgOverlayMode::Netstack;
        ns.netstack_socks_port = None;
        assert!(!cfg.for_org(&ns).overlay_enabled, "netstack without a port");
        ns.netstack_socks_port = Some(10800);
        let nc = cfg.for_org(&ns);
        assert!(nc.overlay_enabled, "netstack with its port");
        assert!(nc.derived_netstack, "and it takes the netstack, not a TUN");
        assert_eq!(nc.netstack_socks_port, Some(10800), "the org's own port");
        assert!(
            nc.overlay_multi_org,
            "the device-wide flag stays as the primary set it (the hello reads it)"
        );
        ns.server_url = "https://other.invalid".into();
        assert!(
            cfg.for_org(&ns).overlay_enabled,
            "netstack on a foreign server"
        );
        cfg.overlay_multi_org = false;
        assert!(
            cfg.for_org(&ns).overlay_enabled,
            "netstack without the opt-in"
        );
        cfg.overlay_multi_org = true;
        ns.overlay_wg_secret_key = None;
        assert!(
            !cfg.for_org(&ns).overlay_enabled,
            "a keyless netstack org stays off"
        );
        let mut off = org.clone();
        off.overlay_mode = OrgOverlayMode::Off;
        assert!(!cfg.for_org(&off).overlay_enabled, "mode off");

        // No per-org WG key ⇒ can't join (and must never borrow the
        // primary's — cross-org pubkey correlation).
        let mut keyless = org.clone();
        keyless.overlay_wg_secret_key = None;
        let oc = cfg.for_org(&keyless);
        assert!(!oc.overlay_enabled, "keyless org stays off");
        assert!(
            oc.overlay_wg_secret_key.is_none(),
            "never the primary's key"
        );

        // Exit roles remain primary-only regardless of the gate.
        let on = cfg.for_org(&org);
        assert!(!on.overlay_exit_node_enabled);
        assert!(on.overlay_exit_node.is_none());
    }

    #[test]
    fn validate_orgs_flags_dupes_and_bad_labels() {
        let mut cfg = fixture();
        cfg.orgs = vec![
            org_fixture("acme", "tid-a"),
            org_fixture("acme", "tid-b"),    // dup label
            org_fixture("primary", "tid-c"), // reserved
            org_fixture("beta", "tid"), // duplicates the PRIMARY identity (fixture tenant "tid")
            org_fixture("gamma", "tid-a"), // dup (server, tenant) with the first entry
        ];
        let problems = cfg.validate_orgs();
        assert!(problems.iter().any(|p| p.contains("duplicate org label")));
        assert!(problems.iter().any(|p| p.contains("\"primary\"")));
        assert!(
            problems.iter().any(|p| p.contains("primary enrollment")),
            "{problems:?}"
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("another entry's (server, tenant)")),
            "{problems:?}"
        );

        let clean = AgentConfig {
            orgs: vec![org_fixture("acme", "tid-a"), org_fixture("beta", "tid-b")],
            ..fixture()
        };
        assert!(clean.validate_orgs().is_empty());
    }

    #[test]
    fn promote_org_swaps_identity_and_org_scoped_fields() {
        let mut cfg = fixture(); // primary: example.invalid / tid / tok
        cfg.overlay_enabled = true;
        cfg.overlay_wg_secret_key = Some("PRIM-KEY".into());
        cfg.overlay_advertised_routes = vec!["10.0.0.0/24".into()];
        cfg.overlay_exit_node = Some("exit-1".into());
        cfg.encoder_preference = EncoderPreferenceChoice::Software;
        let mut acme = org_fixture("acme", "tid-acme");
        acme.server_url = "https://acme.invalid".into();
        acme.overlay_wg_secret_key = Some("ACME-KEY".into());
        acme.advertise_routes = vec!["192.168.9.0/24".into()];
        cfg.orgs = vec![org_fixture("zeta", "tid-z"), acme];

        let done = promote_org_to_primary(&mut cfg, "acme", None).unwrap();

        // Promoted identity + org-scoped fields are now the scalars…
        assert_eq!(cfg.server_url, "https://acme.invalid");
        assert_eq!(cfg.agent_token, "tok-acme");
        assert_eq!(cfg.agent_id, "aid-acme");
        assert_eq!(cfg.tenant_id, "tid-acme");
        assert_eq!(cfg.overlay_wg_secret_key.as_deref(), Some("ACME-KEY"));
        assert_eq!(cfg.advertise_routes, vec!["192.168.9.0/24".to_string()]);
        // …acme was off the mesh, so the primary is (#2540: it follows the
        // promoted entry), and the exit node it USED, org-specific, clears…
        assert!(!cfg.overlay_enabled);
        assert!(!done.primary_on);
        assert!(cfg.overlay_exit_node.is_none());
        // …operator knobs stay put…
        assert!(matches!(
            cfg.encoder_preference,
            EncoderPreferenceChoice::Software
        ));
        // …and the demoted primary sits in acme's old slot under acme's label.
        assert_eq!(cfg.orgs.len(), 2);
        assert_eq!(cfg.orgs[0].label, "zeta");
        let demoted = &cfg.orgs[1];
        assert_eq!(demoted.label, "acme");
        assert_eq!(demoted.server_url, "https://example.invalid");
        assert_eq!(demoted.tenant_id, "tid");
        assert_eq!(demoted.agent_token, "tok");
        assert_eq!(demoted.overlay_wg_secret_key.as_deref(), Some("PRIM-KEY"));
        // The old primary was on the mesh, but with no `overlay_multi_org` and
        // on another control plane than acme it cannot stay on as `tun`.
        assert_eq!(demoted.overlay_mode, OrgOverlayMode::Off);
        assert!(done.demoted_lost_mesh);
        assert_eq!(done.demoted_label, "acme");
        assert!(demoted.enabled);

        // Unknown label is a hard error, config untouched.
        assert!(promote_org_to_primary(&mut cfg, "ghost", None).is_err());
    }

    /// #2540 — the swap that took a two-org host off both meshes. Both on
    /// their own OS TUN (`overlay_multi_org`, one control plane): both stay.
    #[test]
    fn promote_keeps_both_orgs_on_the_mesh_when_it_maps_exactly() {
        let mut cfg = fixture();
        cfg.overlay_enabled = true;
        cfg.overlay_multi_org = true;
        let mut grox = org_fixture("grox", "tid-grox");
        grox.overlay_mode = OrgOverlayMode::Tun;
        cfg.orgs = vec![grox];

        let done = promote_org_to_primary(&mut cfg, "grox", Some("vmtest")).unwrap();

        assert_eq!(cfg.tenant_id, "tid-grox");
        assert!(
            cfg.overlay_enabled,
            "the promoted tun org stays on the mesh"
        );
        assert!(cfg.overlay_multi_org, "a device-wide knob, untouched");
        assert_eq!(cfg.orgs.len(), 1);
        assert_eq!(cfg.orgs[0].tenant_id, "tid");
        assert_eq!(cfg.orgs[0].label, "vmtest");
        assert_eq!(
            cfg.orgs[0].overlay_mode,
            OrgOverlayMode::Tun,
            "the old primary stays on"
        );
        assert_eq!(
            done,
            Promotion {
                demoted_label: "vmtest".into(),
                primary_on: true,
                primary_was_netstack: false,
                demoted_mode: OrgOverlayMode::Tun,
                demoted_lost_mesh: false,
            }
        );
        assert!(cfg.validate_orgs().is_empty());
    }

    /// A netstack secondary cannot become a netstack primary through config
    /// (the primary's netstack is an env key that `overlay_multi_org`
    /// overrides): it starts off, and the swap says why.
    #[test]
    fn promote_a_netstack_org_starts_its_primary_off_and_says_so() {
        let mut cfg = fixture();
        cfg.overlay_enabled = true;
        cfg.overlay_multi_org = true;
        let mut ns = org_fixture("ns", "tid-ns");
        ns.overlay_mode = OrgOverlayMode::Netstack;
        cfg.orgs = vec![ns];

        let done = promote_org_to_primary(&mut cfg, "ns", None).unwrap();

        assert!(!cfg.overlay_enabled);
        assert!(!done.primary_on);
        assert!(done.primary_was_netstack);
        assert_eq!(
            done.demoted_mode,
            OrgOverlayMode::Tun,
            "the old primary still maps"
        );
    }

    /// Without `overlay_multi_org` a secondary has no per-org TUN, and a
    /// `tun` secondary must share the primary's control plane: the demoted
    /// org parks off in both cases, and the swap reports the mesh it lost.
    #[test]
    fn promote_parks_the_demoted_org_off_without_multi_org_or_across_planes() {
        for (multi_org, plane) in [
            (false, "https://example.invalid"),
            (true, "https://other.invalid"),
        ] {
            let mut cfg = fixture();
            cfg.overlay_enabled = true;
            cfg.overlay_multi_org = multi_org;
            let mut b = org_fixture("b", "tid-b");
            b.server_url = plane.into();
            b.overlay_mode = OrgOverlayMode::Tun;
            cfg.orgs = vec![b];

            let done = promote_org_to_primary(&mut cfg, "b", None).unwrap();

            assert!(
                cfg.overlay_enabled,
                "the promoted tun org stays on ({multi_org}, {plane})"
            );
            assert_eq!(
                cfg.orgs[0].overlay_mode,
                OrgOverlayMode::Off,
                "({multi_org}, {plane})"
            );
            assert!(done.demoted_lost_mesh, "({multi_org}, {plane})");
        }
        // An old primary that was off the mesh loses nothing.
        let mut cfg = fixture();
        cfg.orgs = vec![org_fixture("b", "tid-b")];
        let done = promote_org_to_primary(&mut cfg, "b", None).unwrap();
        assert!(!done.demoted_lost_mesh);
    }

    /// `--demoted-label`: sanitized, never "primary", never a label another
    /// org already has; a refusal leaves the config untouched.
    #[test]
    fn promote_with_a_demoted_label() {
        let mut cfg = fixture();
        cfg.orgs = vec![org_fixture("acme", "tid-a"), org_fixture("beta", "tid-b")];
        let before = cfg.orgs.clone();
        assert!(promote_org_to_primary(&mut cfg, "acme", Some("beta")).is_err());
        assert!(promote_org_to_primary(&mut cfg, "acme", Some("Primary")).is_err());
        assert!(promote_org_to_primary(&mut cfg, "acme", Some("!!")).is_err());
        assert_eq!(cfg.orgs, before);
        assert_eq!(cfg.tenant_id, "tid");

        let done = promote_org_to_primary(&mut cfg, "acme", Some("Old Home")).unwrap();
        assert_eq!(done.demoted_label, "old-home");
        assert_eq!(cfg.orgs[0].label, "old-home");
        assert_eq!(cfg.orgs[0].tenant_id, "tid");
        assert_eq!(cfg.tenant_id, "tid-a");
    }

    #[test]
    fn sanitize_org_label_rules() {
        assert_eq!(sanitize_org_label(" Acme Corp "), Some("acme-corp".into()));
        assert_eq!(sanitize_org_label("roomler.ai"), Some("roomler-ai".into()));
        assert_eq!(sanitize_org_label("Ümlaut__x"), Some("mlaut-x".into()));
        assert_eq!(sanitize_org_label("primary"), None, "reserved");
        assert_eq!(sanitize_org_label("PRIMARY"), None, "reserved, any case");
        assert_eq!(sanitize_org_label("###"), None);
        assert_eq!(sanitize_org_label(""), None);
    }

    #[test]
    fn effective_overlay_routes_appends_default_route_for_exit_node() {
        let mut cfg = fixture();
        // Not an exit node → advertised routes pass through unchanged.
        cfg.overlay_advertised_routes = vec!["192.168.1.0/24".into()];
        assert_eq!(
            cfg.effective_overlay_advertised_routes(),
            vec!["192.168.1.0/24".to_string()]
        );

        // Exit node → 0.0.0.0/0 unioned in, appended last.
        cfg.overlay_exit_node_enabled = true;
        assert_eq!(
            cfg.effective_overlay_advertised_routes(),
            vec!["192.168.1.0/24".to_string(), "0.0.0.0/0".to_string()]
        );

        // An explicitly-listed /0 is not duplicated.
        cfg.overlay_advertised_routes = vec!["0.0.0.0/0".into()];
        assert_eq!(
            cfg.effective_overlay_advertised_routes(),
            vec!["0.0.0.0/0".to_string()]
        );

        // Pure exit node (no subnet routes) → just the default route.
        cfg.overlay_advertised_routes = Vec::new();
        assert_eq!(
            cfg.effective_overlay_advertised_routes(),
            vec!["0.0.0.0/0".to_string()]
        );
    }

    #[test]
    fn record_clean_run_resets_counter_and_promotes_version() {
        let mut cfg = fixture();
        cfg.crash_count = 4;
        cfg.last_crash_unix = 1_000;
        cfg.rollback_attempted = true;
        record_clean_run_at(&mut cfg, "0.1.50");
        assert_eq!(cfg.crash_count, 0);
        assert_eq!(cfg.last_crash_unix, 0);
        assert!(!cfg.rollback_attempted);
        assert_eq!(cfg.last_known_good_version.as_deref(), Some("0.1.50"));
    }

    #[test]
    fn record_crash_starts_window_at_one() {
        let mut cfg = fixture();
        record_crash_at(&mut cfg, 1_000_000);
        assert_eq!(cfg.crash_count, 1);
        assert_eq!(cfg.last_crash_unix, 1_000_000);
    }

    #[test]
    fn record_crash_increments_when_within_window() {
        let mut cfg = fixture();
        record_crash_at(&mut cfg, 1_000_000);
        record_crash_at(&mut cfg, 1_000_060); // +60s, in window
        record_crash_at(&mut cfg, 1_000_300); // +300s, still in window (10 min)
        assert_eq!(cfg.crash_count, 3);
        assert_eq!(cfg.last_crash_unix, 1_000_300);
    }

    #[test]
    fn record_crash_resets_when_outside_window() {
        let mut cfg = fixture();
        record_crash_at(&mut cfg, 1_000_000);
        record_crash_at(&mut cfg, 1_000_060);
        // +700s = 11 min 40s — outside the 10-min window.
        record_crash_at(&mut cfg, 1_000_760);
        assert_eq!(cfg.crash_count, 1, "counter resets on a fresh window");
        assert_eq!(cfg.last_crash_unix, 1_000_760);
    }

    #[test]
    fn should_rollback_false_when_no_known_good() {
        let mut cfg = fixture();
        cfg.crash_count = 5;
        cfg.last_crash_unix = 1_000_000;
        assert!(!should_rollback(&cfg, "0.1.51", 1_000_001));
    }

    #[test]
    fn should_rollback_false_when_under_threshold() {
        let mut cfg = fixture();
        cfg.last_known_good_version = Some("0.1.50".into());
        cfg.crash_count = 2; // threshold is 3
        cfg.last_crash_unix = 1_000_000;
        assert!(!should_rollback(&cfg, "0.1.51", 1_000_001));
    }

    #[test]
    fn should_rollback_false_when_target_equals_current() {
        // Refusing this case prevents a same-version-rollback loop.
        let mut cfg = fixture();
        cfg.last_known_good_version = Some("0.1.51".into());
        cfg.crash_count = 5;
        cfg.last_crash_unix = 1_000_000;
        assert!(!should_rollback(&cfg, "0.1.51", 1_000_001));
    }

    #[test]
    fn should_rollback_false_when_window_expired() {
        // A flaky day that adds 3 unrelated crashes over a week
        // shouldn't trigger rollback.
        let mut cfg = fixture();
        cfg.last_known_good_version = Some("0.1.50".into());
        cfg.crash_count = 3;
        cfg.last_crash_unix = 1_000_000;
        // +700s — outside CRASH_WINDOW_SECS.
        assert!(!should_rollback(&cfg, "0.1.51", 1_000_700));
    }

    #[test]
    fn should_rollback_true_in_active_window_above_threshold() {
        let mut cfg = fixture();
        cfg.last_known_good_version = Some("0.1.50".into());
        cfg.crash_count = 3;
        cfg.last_crash_unix = 1_000_000;
        assert!(should_rollback(&cfg, "0.1.51", 1_000_030));
    }

    #[test]
    fn should_rollback_false_when_already_attempted() {
        let mut cfg = fixture();
        cfg.last_known_good_version = Some("0.1.50".into());
        cfg.crash_count = 5;
        cfg.last_crash_unix = 1_000_000;
        cfg.rollback_attempted = true;
        assert!(
            !should_rollback(&cfg, "0.1.51", 1_000_001),
            "must not oscillate between bad versions"
        );
    }

    #[test]
    fn mark_run_starting_sets_unhealthy_flag() {
        let mut cfg = fixture();
        assert!(!cfg.last_run_unhealthy);
        mark_run_starting(&mut cfg);
        assert!(cfg.last_run_unhealthy);
    }

    #[test]
    fn record_clean_run_clears_unhealthy_flag() {
        let mut cfg = fixture();
        mark_run_starting(&mut cfg);
        record_clean_run_at(&mut cfg, "0.1.50");
        assert!(!cfg.last_run_unhealthy);
        assert_eq!(cfg.last_known_good_version.as_deref(), Some("0.1.50"));
    }

    #[test]
    fn mark_clean_shutdown_clears_only_unhealthy() {
        // Clean shutdown after 2 prior crashes shouldn't wipe the
        // counter — those still represent a crash window that the
        // 3rd crash should escalate.
        let mut cfg = fixture();
        cfg.crash_count = 2;
        cfg.last_crash_unix = 1_000_000;
        mark_run_starting(&mut cfg);
        mark_clean_shutdown(&mut cfg);
        assert!(!cfg.last_run_unhealthy);
        assert_eq!(cfg.crash_count, 2, "clean shutdown preserves crash history");
        assert_eq!(cfg.last_crash_unix, 1_000_000);
    }

    // ---- Migration tests (rc.18 P4) ---------------------------------

    #[test]
    fn migrate_pre_rc18_stamps_schema_version() {
        // Old config has no version field. Migration runs the rc.18
        // step set and stamps CURRENT_SCHEMA_VERSION so subsequent
        // launches no-op.
        let mut cfg = fixture();
        assert!(cfg.config_schema_version.is_none());
        let changed = migrate(&mut cfg);
        assert!(changed, "first migration must rewrite the config");
        assert_eq!(
            cfg.config_schema_version.as_deref(),
            Some(CURRENT_SCHEMA_VERSION)
        );
    }

    #[test]
    fn migrate_same_schema_is_noop() {
        // Second launch on the same version: migrate returns false,
        // caller skips the save.
        let mut cfg = fixture();
        cfg.config_schema_version = Some(CURRENT_SCHEMA_VERSION.to_string());
        let changed = migrate(&mut cfg);
        assert!(!changed, "same-version migration must be a no-op");
    }

    #[test]
    fn migrate_trims_trailing_slash_on_server_url() {
        let mut cfg = fixture();
        cfg.server_url = "https://example.invalid/".into();
        let changed = migrate(&mut cfg);
        assert!(changed);
        assert_eq!(cfg.server_url, "https://example.invalid");
    }

    #[test]
    fn migrate_no_trailing_slash_to_trim() {
        // server_url already clean; ONLY the schema version stamp
        // counts as a change.
        let mut cfg = fixture();
        cfg.server_url = "https://example.invalid".into();
        let changed = migrate(&mut cfg);
        assert!(changed); // schema version stamp
        assert_eq!(cfg.server_url, "https://example.invalid");
    }

    #[test]
    fn migrate_resets_crash_count_from_pre_rc18_branch() {
        // last_known_good_version from 0.2.x with a live crash counter:
        // those crashes happened on a different branch, the counter
        // must not trip rollback against rc.18.
        let mut cfg = fixture();
        cfg.last_known_good_version = Some("0.2.7".into());
        cfg.crash_count = 2;
        cfg.last_crash_unix = 1_700_000_000;
        let changed = migrate(&mut cfg);
        assert!(changed);
        assert_eq!(cfg.crash_count, 0);
        assert_eq!(cfg.last_crash_unix, 0);
    }

    #[test]
    fn migrate_preserves_crash_count_for_same_branch() {
        // 0.3.x crash counter is still relevant when running 0.3.x —
        // don't wipe it.
        let mut cfg = fixture();
        cfg.last_known_good_version = Some("0.3.0-rc.16".into());
        cfg.crash_count = 1;
        cfg.last_crash_unix = 1_700_000_000;
        migrate(&mut cfg);
        assert_eq!(cfg.crash_count, 1, "0.3.x history must be preserved");
        assert_eq!(cfg.last_crash_unix, 1_700_000_000);
    }

    #[test]
    fn old_config_without_new_fields_loads_with_defaults() {
        // Backwards-compat: a config.toml written by a pre-0.1.51
        // agent must continue to load.
        let raw = r#"
            server_url = "https://example.invalid"
            agent_token = "tok"
            agent_id = "aid"
            tenant_id = "tid"
            machine_id = "mid"
            machine_name = "host"
        "#;
        let cfg: AgentConfig = toml::from_str(raw).expect("legacy config must parse");
        assert_eq!(cfg.crash_count, 0);
        assert_eq!(cfg.last_crash_unix, 0);
        assert!(!cfg.rollback_attempted);
        assert!(cfg.last_known_good_version.is_none());
    }

    /// Collects formatted tracing output so a test can assert on what was
    /// logged. FR-66 is a defect about SEVERITY, not about a return value, so
    /// nothing weaker than reading the emitted events can lock it.
    #[derive(Clone, Default)]
    struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl Captured {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// FR-66. Probing an absent optional config must be SILENT, while loading
    /// the config a process runs on must still shout — both halves in one test,
    /// because either alone permits the wrong fix.
    ///
    /// Without the second half, "make it quiet" passes by softening `load`'s
    /// ERROR to `warn!` — which trades a false alarm for a missed one, the
    /// explicit non-goal in `docs/fr/FR-66-*`. Without the first, the defect
    /// itself is unobservable: `netd_enabled()` already returned the right
    /// BOOLEAN while telling every healthy host to re-enroll.
    #[test]
    fn a_probe_is_silent_but_load_still_demands_re_enrollment() {
        use tracing_subscriber::layer::SubscriberExt;

        let cap = Captured::default();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_writer(cap.clone())
                .with_ansi(false),
        );
        let _guard = tracing::subscriber::set_default(subscriber);

        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("config.toml");
        assert!(
            !missing.exists(),
            "precondition: the probe target is absent"
        );

        // 1) The probe: absent means absent. No ERROR, no re-enroll advice.
        assert!(
            read_if_present(&missing).is_none(),
            "an absent optional config must read as None"
        );
        let probe_log = cap.text();
        assert!(
            !probe_log.contains("re-enrolled"),
            "probing an optional config must not advise re-enrollment; got: {probe_log}"
        );
        assert!(
            !probe_log.contains("ERROR"),
            "probing an optional config must not log at ERROR; got: {probe_log}"
        );

        // 2) The alarm still works. Same path, the loud reader.
        assert!(
            load(&missing).is_err(),
            "load of an absent config must still fail"
        );
        let load_log = cap.text();
        assert!(
            load_log.contains("re-enrolled"),
            "load must still say the host needs re-enrolling; got: {load_log}"
        );
        assert!(
            load_log.contains("ERROR"),
            "load must still report at ERROR; got: {load_log}"
        );
    }
}
