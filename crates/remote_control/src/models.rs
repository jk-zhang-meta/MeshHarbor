// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
use bson::{DateTime, oid::ObjectId};
use serde::{Deserialize, Serialize};

use crate::permissions::Permissions;

// ────────────────────────────────────────────────────────────────────────────
// Agent
// ────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OsKind {
    Linux,
    Macos,
    Windows,
}

/// FR-102 P3 — how a device was installed, as the enroll request says it
/// (`docs/growth-observability.md`, the install trace). Shared by both ends
/// of `POST /api/agent/enroll`: the agent builds one, the server clamps it
/// ([`InstallInfo::clamped`]) and stores it once on the agent row.
///
/// Strings on the wire and on the row, not the enums below: a value this
/// build has never heard of must be **clamped to `other`**, never refused —
/// an older server meeting a newer agent's spelling has to keep enrolling
/// it, and an older row must keep reading. [`InstallMethod`] and
/// [`InstallScope`] are the vocabulary both sides validate against.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct InstallInfo {
    /// One of [`InstallMethod`]'s spellings.
    pub method: String,
    /// One of [`InstallScope`]'s spellings; absent reads as `unknown`.
    #[serde(default)]
    pub scope: String,
    /// Reserved for P3b (the wizard's opt-in diagnostics run id). Carried
    /// only when a client sets it; the server keeps at most a short opaque
    /// token here, never anything it could parse as a person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
}

/// The ceiling on a `run` id the server keeps (P3b mints 32 hex chars).
pub const INSTALL_RUN_MAX_LEN: usize = 64;

impl InstallInfo {
    pub fn new(method: InstallMethod, scope: InstallScope) -> Self {
        Self {
            method: method.wire().to_string(),
            scope: scope.wire().to_string(),
            run: None,
        }
    }

    /// What the server stores for an enroll that did not say: an agent from
    /// before P3, or a caller that left the field out.
    pub fn unknown() -> Self {
        Self::new(InstallMethod::Unknown, InstallScope::Unknown)
    }

    /// The server's view of a client's claim: a method outside the
    /// vocabulary is `other`, a scope outside it is `unknown`, and a `run`
    /// that is not a short opaque token is dropped. Never an error — the
    /// enroll must succeed whatever the install trace says.
    pub fn clamped(&self) -> Self {
        let method = InstallMethod::parse(self.method.trim()).unwrap_or(InstallMethod::Other);
        let scope = InstallScope::parse(self.scope.trim()).unwrap_or(InstallScope::Unknown);
        let run = self
            .run
            .as_deref()
            .map(str::trim)
            .filter(|r| {
                !r.is_empty()
                    && r.len() <= INSTALL_RUN_MAX_LEN
                    && r.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })
            .map(str::to_string);
        Self {
            method: method.wire().to_string(),
            scope: scope.wire().to_string(),
            run,
        }
    }
}

/// How the daemon got onto the machine. The wire spelling is the stored
/// spelling and a digest's grouping key, so it is locked by a test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstallMethod {
    /// The `roomler-setup` wizard, in-process.
    Wizard,
    /// The served `install.sh`.
    ScriptSh,
    /// The served `install.ps1`.
    ScriptPs1,
    /// An MSI run by hand.
    Msi,
    /// A `.deb` installed by hand.
    Deb,
    /// A macOS `.pkg` installed by hand.
    Pkg,
    /// A hand-typed `roomlerd enroll` (the default when nothing says
    /// otherwise), or the companion's enroll form.
    Manual,
    /// A container image's entrypoint.
    Container,
    /// A spelling this build does not know — the server's clamp.
    Other,
    /// The enroll did not say: an agent from before P3. Server-assigned;
    /// a client never needs to send it.
    Unknown,
}

impl InstallMethod {
    /// Every variant, for the vocabulary tests and the CLI's help text.
    pub const ALL: [InstallMethod; 10] = [
        InstallMethod::Wizard,
        InstallMethod::ScriptSh,
        InstallMethod::ScriptPs1,
        InstallMethod::Msi,
        InstallMethod::Deb,
        InstallMethod::Pkg,
        InstallMethod::Manual,
        InstallMethod::Container,
        InstallMethod::Other,
        InstallMethod::Unknown,
    ];

    pub fn wire(self) -> &'static str {
        match self {
            InstallMethod::Wizard => "wizard",
            InstallMethod::ScriptSh => "script-sh",
            InstallMethod::ScriptPs1 => "script-ps1",
            InstallMethod::Msi => "msi",
            InstallMethod::Deb => "deb",
            InstallMethod::Pkg => "pkg",
            InstallMethod::Manual => "manual",
            InstallMethod::Container => "container",
            InstallMethod::Other => "other",
            InstallMethod::Unknown => "unknown",
        }
    }

    /// Exact, case-sensitive: `script-sh` is a spelling, `Script-SH` is not.
    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.wire() == raw)
    }
}

/// What the install runs as. `attended` is the Windows perMachine service
/// without SystemContext (the wizard's "Daemon — machine" role): a service,
/// but one that works only beside a signed-in session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstallScope {
    System,
    PerUser,
    Attended,
    Unknown,
}

impl InstallScope {
    pub const ALL: [InstallScope; 4] = [
        InstallScope::System,
        InstallScope::PerUser,
        InstallScope::Attended,
        InstallScope::Unknown,
    ];

    pub fn wire(self) -> &'static str {
        match self {
            InstallScope::System => "system",
            InstallScope::PerUser => "per-user",
            InstallScope::Attended => "attended",
            InstallScope::Unknown => "unknown",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.wire() == raw)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Online,
    Offline,
    Unenrolled,
    Quarantined,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DisplayInfo {
    pub index: u8,
    pub name: String,
    pub width_px: u32,
    pub height_px: u32,
    pub scale: f32,
    pub primary: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AgentCaps {
    pub hw_encoders: Vec<String>,
    pub codecs: Vec<String>,
    pub has_input_permission: bool,
    pub supports_clipboard: bool,
    pub supports_file_transfer: bool,
    pub max_simultaneous_sessions: u8,
    /// Video transport modes the agent supports beyond the default
    /// WebRTC video track. Empty / unset means WebRTC video only
    /// (the legacy default; older agents that don't know about
    /// this field deserialize that way via serde default).
    ///
    /// Known value: `data-channel-vp9-444` — VP9 profile 1
    /// (8-bit 4:4:4) frames over an RTCDataChannel named
    /// `video-bytes`. Bypasses the browser's WebRTC video pipeline
    /// which enforces 4:2:0 across every codec. See
    /// `docs/encoders.md` for the rationale and the wire
    /// format spec.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transports: Vec<String>,
    /// File-DC v2 (0.3.0+) capability list. Replaces the
    /// coarse-grained `supports_file_transfer` bool with explicit
    /// per-feature flags. Recognised values:
    ///
    /// * `upload`   — browser → host file uploads (the v1 default).
    /// * `download` — host → browser single-file downloads.
    /// * `download-folder` — host → browser folder zip streams.
    /// * `browse`   — browser can navigate the host's filesystem
    ///   via `files:dir`. Conditional on the agent's
    ///   `enable_remote_browse` config flag.
    ///
    /// Empty / unset (older agents) deserialises to `[]`; browsers
    /// that see an empty list fall back to `supports_file_transfer`
    /// to determine just upload availability. New browsers that need
    /// download/browse functionality check this list and grey out
    /// the affected toolbar buttons when the capability is missing,
    /// instead of waiting for a 5 s timeout on an unanswered
    /// `files:get` / `files:dir`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
    /// FR-17 — video DATA-CHANNEL wire options the agent supports, as
    /// opposed to which transport it offers (that is `transports`).
    /// Recognised values:
    ///
    /// * `chunk-framing` — every 16 KiB DataChannel message carries an
    ///   8-byte `[frame_seq | chunk_idx | chunk_count]` prefix, so a
    ///   receiver can tell WHICH frame a message belongs to and notice a
    ///   missing one. Without it the stream is only reassemblable because
    ///   the channel is reliable+ordered, which is the property FR-17
    ///   exists to give up: on a lossy relay that ordering costs seconds
    ///   of head-of-line blocking (measured: one frame blocked 10 263 ms).
    /// * `bench` — FR-16 L4: this agent paints the last bench probe it
    ///   received on the input channel (`{"t":"probe","seq":N}`) into a
    ///   marker in every frame, so a viewer in bench mode can time input
    ///   to photon. Only a build with the synthetic frame source, running
    ///   it, with `ROOMLERD_BENCH=1`, ever advertises it; a viewer sends no
    ///   probe to an agent without it.
    ///
    /// Empty / unset (older agents) deserialises to `[]` and the browser
    /// keeps the legacy unframed format. The capability is what makes the
    /// negotiation race-free: the viewer knows before it connects, so
    /// there is never a window where the two ends disagree about how to
    /// parse bytes already in flight.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub video: Vec<String>,
    /// P6 — multi-user input capabilities. Recognised values:
    ///
    /// * `arbiter` — the agent runs the InputArbiter (single fenced
    ///   injection worker); the SERVER lifts the P3 single-INPUT-holder
    ///   downgrade for concurrent sessions on agents advertising this.
    /// * `exclusive` — the arbiter supports the exclusive floor mode
    ///   (`rc:control.request` / `rc:control.mode` on the control DC).
    /// * `ghost-cursor` — other sessions' pointers are rebroadcast as
    ///   `cursor:peer` on the cursor DC.
    /// * `keep-busy` — FR-92: this agent can run keep busy here and its owner
    ///   allows it.
    /// * `mouse-rel` — FR-109: the agent injects relative motion
    ///   (`mouse_rel`) and presses where the pointer is (`mouse_press`). A
    ///   viewer sends either only to an agent advertising it, because an
    ///   older agent cannot parse them.
    /// * `sas` — FR-97 P4a: the agent sends Windows' secure attention sequence
    ///   (`SendSAS`) for `{"t":"sas"}`, which the lock and sign-in screens
    ///   answer where three ordinary keys reach nothing. Advertised only by a
    ///   SYSTEM worker on a host whose policy lets services send it; a viewer
    ///   sends it only to an agent advertising it.
    ///
    /// Empty / unset = a pre-P6 agent → the P3 single-holder rule stays.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub input: Vec<String>,
    /// Host permissions the OS has actually GRANTED this agent, as opposed to
    /// what it was compiled with. Recognised values:
    ///
    /// * `screen-capture` — the agent may capture the screen. On macOS this
    ///   is the Screen Recording TCC grant; elsewhere there is no such gate
    ///   and it is always present.
    /// * `input` — the agent may inject keyboard/mouse events. On macOS this
    ///   is the Accessibility grant.
    /// * `no-gui-session` — a THIRD state, distinct from granted and denied:
    ///   this process is not in a GUI login session (macOS's root
    ///   LaunchDaemon), so capture and input are impossible regardless of any
    ///   grant. Present ALONE — never alongside the two above. Readers must
    ///   treat it as "this device is not a capture target", not as "two
    ///   permissions are missing", or a mesh-only daemon reads as broken and
    ///   sends the operator after a toggle that would change nothing.
    ///
    /// ⚠️ `None` and `Some([])` mean OPPOSITE things and must never be
    /// collapsed: `None` is a pre-rc.454 agent that cannot report (no
    /// information — say nothing), `Some([])` is an agent reporting that it
    /// holds NEITHER permission (a Mac that will show a blank screen and
    /// swallow every click). Same rule as `NetmapPeer.ingress_rules`.
    ///
    /// This exists because macOS never ERRORS on a missing grant: capture
    /// silently returns wallpaper-only frames and injected input is silently
    /// dropped, so without this the product's only symptom is "it doesn't
    /// work" with a clean log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<String>>,
    /// Multi-org capabilities. Recognised values:
    ///
    /// * `join` — the agent honours `rc:agent.join_org`: it enrolls itself
    ///   into an ADDITIONAL org on the same server from a pushed enrollment
    ///   token and brings that org's supervisor up without a restart.
    ///
    /// Empty / unset = a pre-rc.310 agent. The admin UI greys out
    /// "Add to another organization" for those; the server refuses to mint a
    /// token it knows can't be consumed, rather than pushing a message that
    /// lands in the agent's unknown-variant debug branch and vanishes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub multi_org: Vec<String>,
    /// FR-67 P7 — whether THIS enrollment acts on a server-pushed
    /// `rc:agent.update`, and if not, why. Recognised values:
    ///
    /// * `self` — it does: the machine's primary enrollment, its updater on.
    /// * `primary_org` — it ignores it: the self-updater is machine-wide, and
    ///   only the primary enrollment drives it (multi-org; a secondary org's
    ///   admin must not force-update a binary every org shares).
    /// * `off` — it drops it: auto-update is off on the device
    ///   (`auto_update = false` / `ROOMLERD_AUTO_UPDATE=0`).
    ///
    /// Before this the device's refusal was surfaced only locally (a WARN and
    /// a LocalAPI counter), so "Update all" counted it as delivered: on
    /// 2026-10-19 the operator's dashboard "updated" a device three times
    /// while it logged `rc:agent.update ignored` three times.
    ///
    /// Unset (an older agent) = unknown: the server pushes as before. ⚠️ An
    /// unrecognised value is IGNORED (treated as unset), never an error — a
    /// newer agent may say something this server has never heard of.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_mode: Option<String>,
    /// VP9 chroma format the agent will emit on the
    /// `data-channel-vp9-444` transport. Values: `"yuv444"` (default,
    /// current behaviour, VP9 profile 1) for sharpest text via
    /// ClearType chroma preservation, or `"yuv420"` (VP9 profile 0)
    /// for ~1.5× lower bandwidth at the cost of slight chroma loss
    /// on small Windows ClearType text.
    ///
    /// rc.61 — added so the browser-side `rc-vp9-444-worker.ts` can
    /// pick the right codec string (`vp09.01.10.08` vs `vp09.00.10.08`)
    /// when configuring its `VideoDecoder`. Mismatch leaves the canvas
    /// blank. Empty / older agents deserialise to `""`; browsers treat
    /// the empty value as `"yuv444"` for backward compat.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vp9_chroma: String,
    /// P7 (2026-08-20) — chroma formats the agent's HEVC encoder can emit
    /// on the `data-channel-hevc` transport. `"yuv420"` (Main profile —
    /// every HEVC host) and `"yuv444"` (Rext profile — hevc_nvenc only;
    /// NVENC supports HEVC 4:4:4 since Maxwell-gen2). The browser offers
    /// its "HEVC · crisp text (4:4:4)" picker entry only when this list
    /// contains `"yuv444"` AND its own WebCodecs Rext decode probe passes
    /// (Chrome ≥137 + NVIDIA driver ≥572.16, or Intel Gen11+ ≥117 — there
    /// is NO software HEVC fallback in Chrome). Empty / unset (older
    /// agents, non-nvenc hosts) → the picker entry stays hidden and
    /// sessions run Main-profile 4:2:0 exactly as before.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hevc_chroma: Vec<String>,
    /// Audio codecs the agent can stream on the WebRTC audio track
    /// (system / desktop audio, opt-in per session). Empty / unset
    /// (older agents, or agents built without the `audio` feature)
    /// means "no audio track offered" — the browser must not request
    /// `audio_enabled`. Known value: `"opus"` (audio/opus, 48 kHz
    /// stereo, PT 111 — the WebRTC default). Populated by the agent's
    /// caps builder only when the `audio` Cargo feature is compiled in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audio: Vec<String>,
    /// Remote app selection & launch (FR-56). Known values, matched by
    /// EQUALITY:
    ///
    /// * `"list"`, `"focus"`, `"launch"` — the agent could manage a desktop
    ///   when it announced itself (a Linux virtual desktop or a logged-in
    ///   X11/Xwayland session, or Windows) AND `virtual_desktop_apps.enabled`.
    /// * `"status"` (FR-56 AC10) — this build has a Remote Apps backend and
    ///   answers `rc:apps.list` honestly: with the list, or with
    ///   `unavailable: {code, reason}` when there is no desktop to manage.
    ///   Advertised whenever the platform has a backend, so the viewer can
    ///   show WHY rather than hide the button. ⚠️ The hello is a boot-time
    ///   snapshot: `status` without `list` can simply mean nobody had logged
    ///   in yet when the daemon started; only the live reply can say.
    ///
    /// Empty / unset (older agents, macOS) → the browser hides the Apps menu.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub apps: Vec<String>,
    /// Fleet-RPC capabilities. Recognised values:
    ///
    /// * `exec` — the agent honours `rc:rpc.exec` / `rc:rpc.cancel`: it runs
    ///   one bounded shell command and replies `rc:rpc.result`.
    /// * `originate` — the agent honours `rc:rpc.response`, i.e. its LocalAPI
    ///   can originate an exec against ANOTHER device (the `roomler exec`
    ///   CLI path).
    /// * `ssh` — the agent honours `rc:ssh.grant`: it serves roomler SSH on
    ///   its overlay address and will admit the granted key.
    /// * `ssh-originate` — the agent honours `rc:ssh.response`, i.e. its
    ///   LocalAPI can originate an SSH session against ANOTHER device (the
    ///   `roomler ssh` CLI path).
    ///
    /// Empty / unset = a pre-fleet-RPC agent. Same rule as [`Self::multi_org`]:
    /// the server refuses the request with `412` rather than pushing a message
    /// that lands in the agent's unknown-variant debug branch and vanishes,
    /// leaving the caller to hang until its deadline.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rpc: Vec<String>,
    /// FR-85 P3 — what this agent can record for a REMOTE controller, as
    /// [`RecordCap`] wire words:
    ///
    /// * `"available"` (P3c-2) — a recorder can serve a remote session here,
    ///   whether or not the owner allows it. It says the device HAS the
    ///   feature, never that anyone may use it.
    /// * `"remote"` — the device's owner switched remote recording on
    ///   (`record_remote_enabled`), and the agent serves the `record`
    ///   DataChannel.
    /// * `"remote-audio"` — and allows the computer's audio in one
    ///   (`record_remote_audio`). The microphone is never offered remotely.
    ///
    /// `remote` is advertised only while the device gate is on, so an old
    /// agent, or one whose owner never opted in, never receives
    /// `Permissions::RECORD`: the hub strips it. `available` only lets the
    /// hub tell "cannot record here at all" (a viewer shows nothing) from
    /// "the owner has not allowed it" (a viewer says so). ⚠️ `remote` is a
    /// PREFIX of `remote-audio`; matching is equality
    /// ([`AgentCaps::has_record`]), never `starts_with`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub record: Vec<String>,
    /// Clipboard-DC protocol-v2 capability list. Extends the coarse
    /// `supports_clipboard` bool (kept for older browsers) with
    /// per-feature flags. Recognised values:
    ///
    /// * `"ack"`    — the agent replies `clipboard:write-ack` to
    ///   `clipboard:write` / `clipboard:write-chunk` payloads that
    ///   carry an `id`, letting the browser gate its deferred Ctrl+V
    ///   keystroke on the host clipboard actually being written.
    /// * `"events"` — the agent accepts `clipboard:subscribe` and
    ///   pushes unsolicited `clipboard:event` / `clipboard:img-begin`
    ///   messages when the host clipboard changes (host→browser
    ///   auto-sync). Change *watching* for images is Windows-only;
    ///   text watching works everywhere arboard does.
    /// * `"images"` — the agent understands PNG image payloads on the
    ///   clipboard DC in both directions (`clipboard:img-begin` /
    ///   binary frames / `clipboard:img-end`, and `accept:["image"]`
    ///   on `clipboard:read`).
    ///
    /// Empty / unset (older agents, builds without the `clipboard`
    /// feature) deserialises to `[]`; browsers then fall back to the
    /// v1 button-driven text-only flow.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clipboard: Vec<String>,
    /// Keyboard-layout integration (Windows hosts with input
    /// injection). Recognised values:
    ///
    /// * `"report"` — the agent pushes `rc:layout` snapshots (active +
    ///   installed layouts) over the control DC.
    /// * `"set"` — the agent accepts `rc:layout.set {hkl}` manual
    ///   switches from the viewer's layout picker.
    ///
    /// Empty / unset (older agents, non-Windows hosts, builds without
    /// `enigo-input`) → the browser hides all layout UI. The per-char
    /// auto-switch itself is agent-local and needs no browser
    /// involvement.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub layout: Vec<String>,
    /// FR-77 — every **cell** (codec × chroma format) this host can produce,
    /// one entry per *encoder* (codec × backend) the start-up probe actually
    /// OPENED, with the chroma formats that open succeeded for. Additive: an
    /// agent older than FR-77 sends nothing and a viewer derives cells from
    /// the legacy fields (`hw_encoders`, `transports`, `hevc_chroma`,
    /// `vp9_chroma`), which keep being filled forever — renaming or dropping
    /// them would strand every deployed agent.
    ///
    /// The wire stays strings ([`VideoCell`]); both sides go through
    /// [`VideoCodec`], [`VideoBackend`] and [`ChromaFormat`] so the vocabulary
    /// lives in one place. Unknown codecs, backends or chroma formats from a
    /// NEWER agent are ignored by an older reader, never an error — the
    /// additive-list rule the `rpc` verbs follow.
    ///
    /// `hw` is VERIFIED, never assumed: NVENC, AMF, VideoToolbox and VAAPI are
    /// hardware by construction; a QSV open is hardware only on the oneVPL
    /// build, whose dispatcher filters `MFX_IMPL_TYPE_HARDWARE` and never
    /// enumerates the CPU runtime; Media Foundation reports what its cascade
    /// landed on; `openh264` and `libvpx` are software.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub video_cells: Vec<VideoCell>,
    /// FR-77 — wall-clock milliseconds the start-up capability probe took
    /// (child spawn to parsed result), so the fleet can MEASURE what opening
    /// every cell costs instead of assuming it. `None` when the probe child did
    /// not come back (the caps are then the driver-free fallback) or from an
    /// agent older than FR-77.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_ms: Option<u32>,
    /// FR-77 P3 — true when the cells above came from the daemon's probe
    /// cache rather than a fresh probe this start (`probe_ms` is then the
    /// cached probe's duration). Absent on the wire when false, so a
    /// pre-P3 reader sees nothing new.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub probe_cached: bool,
    /// FR-93 P2b — the desktop this Linux device would show a controller now,
    /// and what would capture it. Lets the server count Wayland hosts and the
    /// arm serving each, which an exec sweep cannot (it reaches only what is
    /// online). Live, unlike the probed fields above: re-announced on the
    /// heartbeat when it changes. `None` off Linux and from older agents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desktop: Option<DesktopBrief>,
    /// FR-101 P2b — the device's OWN session policy (its owner's `rc_clipboard`,
    /// `rc_files`, `rc_audio`), so the hub can strip what this device will
    /// refuse and say why (`device_policy_off`) instead of the viewer finding
    /// out at the channel. Informative only: the agent enforces its policy
    /// whatever the server does. `None` when the device restricts nothing, and
    /// from every agent before P2b. Live, re-announced on the heartbeat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_policy: Option<SessionPolicy>,
    /// FR-97 P0c — the honest "no": a feature this device does NOT offer on
    /// this host, keyed by feature, with why. A viewer shows the reason on the
    /// control instead of offering one that fails silently, and hides the
    /// control only for [`Unavailable::NOT_APPLICABLE`]. Keys, matched by
    /// EQUALITY ([`Unavailable::KEYS`], locked by test):
    ///
    /// * `audio` — no system-audio capture here (macOS until FR-97 P2a); the
    ///   `audio` list is then empty, so no silent track is ever offered.
    /// * `clipboard` — no clipboard this process can reach (a root Linux
    ///   daemon outside any desktop session); `clipboard` and
    ///   `supports_clipboard` are then empty/false.
    /// * `clipboard-image-events` — `events` still pushes text, but copied
    ///   images are not watched here (everywhere but Windows), so images move
    ///   only on request.
    /// * `sas` — Ctrl+Alt+Del is sent as ordinary keys (`keys-only`): on
    ///   Windows they miss the lock and sign-in screens until FR-97 P4a sends
    ///   the real secure attention sequence; on Linux the desktop binds them.
    ///   On macOS the chord means nothing (`not-applicable`).
    /// * `display-match` — FR-97 P3e-2: this host's display cannot be switched
    ///   to the viewer's stage (macOS; a Linux system install, a Wayland
    ///   desktop). Until P3e-2 the viewer offered the toggle on Windows only,
    ///   by OS; it now follows this word, and an absent key still offers it.
    ///
    /// Empty from every agent before P0c: those agents claim what their lists
    /// say, so an absent key never means "unavailable".
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub unavailable: std::collections::BTreeMap<String, Unavailable>,
}

/// FR-67 P7 — why an enrollment will not act on a pushed `rc:agent.update`;
/// see [`AgentCaps::update_refusal`]. The server refuses such a push up front
/// (a 409, or a `refused` row in a bulk update) rather than counting a frame
/// the device will ignore as an update delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateRefusal {
    /// A secondary enrollment: only the machine's primary drives its updater.
    PrimaryOrg,
    /// `auto_update = false` on the device.
    AutoUpdateOff,
}

impl UpdateRefusal {
    /// The stable code a client branches on.
    pub fn code(self) -> &'static str {
        match self {
            Self::PrimaryOrg => "primary_org",
            Self::AutoUpdateOff => "auto_update_off",
        }
    }

    /// What an admin is told, including the way out.
    pub fn reason(self) -> &'static str {
        match self {
            Self::PrimaryOrg => {
                "this device takes its updates from another organization: only the \
                 machine's primary enrollment drives its self-updater, so an update \
                 ordered here is ignored. Order it from that organization, or make this \
                 one the device's primary (on the device: `roomlerd org set-primary \
                 <this org's label>`, then restart its daemon)"
            }
            Self::AutoUpdateOff => {
                "auto-update is off on this device (`auto_update = false`, or \
                 `ROOMLERD_AUTO_UPDATE=0` in its service environment), so it drops an \
                 update ordered from here. Switch it on at the device (`roomler config \
                 set auto_update true`, or its Roomler settings), then restart its daemon"
            }
        }
    }
}

/// FR-97 P0c — why a feature is not offered here; see [`AgentCaps::unavailable`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Unavailable {
    /// Machine-readable. [`Self::NOT_APPLICABLE`] means the feature means
    /// nothing on this OS, so a viewer hides the control. Any other code
    /// leaves the control to the lists, which say whether it works, and
    /// adds [`Self::reason`] to it.
    pub code: String,
    /// One sentence for the person at the viewer.
    pub reason: String,
}

impl Unavailable {
    /// The feature means nothing on this OS: hide the control.
    pub const NOT_APPLICABLE: &'static str = "not-applicable";
    /// The keys [`AgentCaps::unavailable`] may carry, in wire spelling.
    pub const KEYS: [&'static str; 5] = [
        "audio",
        "clipboard",
        "clipboard-image-events",
        "sas",
        "display-match",
    ];

    pub fn new(code: &str, reason: &str) -> Self {
        Self {
            code: code.to_string(),
            reason: reason.to_string(),
        }
    }
}

/// FR-77 — one encoder (codec × backend) and the chroma formats it produced
/// when the probe opened it. See [`AgentCaps::video_cells`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct VideoCell {
    /// A [`VideoCodec`] wire name: `h264` · `hevc` · `av1` · `vp9`.
    pub codec: String,
    /// A [`VideoBackend`] wire name: `nvenc` · `qsv` · `amf` · `videotoolbox`
    /// · `vaapi` · `mf` · `openh264` · `libvpx`.
    pub backend: String,
    /// [`ChromaFormat`] wire names the open succeeded for, `yuv420` first.
    #[serde(default)]
    pub chroma: Vec<String>,
    /// Verified hardware encode (see [`AgentCaps::video_cells`]).
    #[serde(default)]
    pub hw: bool,
}

/// FR-77 — a codec the agent can produce. Same contract as [`RpcCap`]: the
/// wire is a string, the vocabulary is this enum, unknown strings are ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VideoCodec {
    H264,
    Hevc,
    Av1,
    Vp9,
}

impl VideoCodec {
    /// Exactly what crosses the wire. ⚠️ A compatibility surface — see
    /// [`RpcCap::wire`].
    pub const fn wire(self) -> &'static str {
        match self {
            Self::H264 => "h264",
            Self::Hevc => "hevc",
            Self::Av1 => "av1",
            Self::Vp9 => "vp9",
        }
    }

    pub const ALL: [VideoCodec; 4] = [Self::H264, Self::Hevc, Self::Av1, Self::Vp9];

    pub fn from_wire(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.wire() == s)
    }
}

/// FR-77 — the implementation that produced a codec's bitstream. A property of
/// the HOST, discovered at runtime, never chosen by the controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VideoBackend {
    Nvenc,
    Qsv,
    Amf,
    VideoToolbox,
    Vaapi,
    /// FR-78 — D3D12 video encode (Windows): FFmpeg's `*_d3d12va`, the
    /// graphics driver's own encode DDI, no vendor SDK.
    D3d12,
    /// FR-78 — Vulkan video encode (Linux, Windows): FFmpeg's `*_vulkan`,
    /// `VK_KHR_video_encode_*` through whichever ICD the loader finds.
    Vulkan,
    /// The agent's native Media Foundation module (Windows), not FFmpeg's
    /// `*_mf` wrappers, which are deliberately not built.
    MediaFoundation,
    Openh264,
    Libvpx,
}

impl VideoBackend {
    /// Exactly what crosses the wire. ⚠️ A compatibility surface.
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Nvenc => "nvenc",
            Self::Qsv => "qsv",
            Self::Amf => "amf",
            Self::VideoToolbox => "videotoolbox",
            Self::Vaapi => "vaapi",
            Self::D3d12 => "d3d12",
            Self::Vulkan => "vulkan",
            Self::MediaFoundation => "mf",
            Self::Openh264 => "openh264",
            Self::Libvpx => "libvpx",
        }
    }

    pub const ALL: [VideoBackend; 10] = [
        Self::Nvenc,
        Self::Qsv,
        Self::Amf,
        Self::VideoToolbox,
        Self::Vaapi,
        Self::D3d12,
        Self::Vulkan,
        Self::MediaFoundation,
        Self::Openh264,
        Self::Libvpx,
    ];

    pub fn from_wire(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|b| b.wire() == s)
    }

    /// Split an FFmpeg encoder name (`hevc_nvenc`, `h264_videotoolbox`) into
    /// its codec and backend. `None` for a name this build does not know —
    /// which is how a NEW backend fails loudly in a test instead of being
    /// advertised under a name nobody parses.
    pub fn from_ffmpeg_name(name: &str) -> Option<(VideoCodec, VideoBackend)> {
        let (codec, backend) = name.split_once('_')?;
        let codec = VideoCodec::from_wire(codec)?;
        let backend = match backend {
            "nvenc" => Self::Nvenc,
            "qsv" => Self::Qsv,
            "amf" => Self::Amf,
            "videotoolbox" => Self::VideoToolbox,
            "vaapi" => Self::Vaapi,
            "d3d12va" => Self::D3d12,
            "vulkan" => Self::Vulkan,
            _ => return None,
        };
        Some((codec, backend))
    }
}

/// FR-77 — how much colour resolution an encoded stream keeps. A property of
/// the STREAM that both the encoder and the decoder must support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChromaFormat {
    /// Colour at quarter resolution — the video default, every backend.
    Yuv420,
    /// Full colour resolution — what keeps coloured text and thin lines sharp.
    Yuv444,
}

impl ChromaFormat {
    /// Exactly what crosses the wire — the same spellings `vp9_chroma`,
    /// `hevc_chroma` and `chroma_pref` have carried since rc.61.
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Yuv420 => "yuv420",
            Self::Yuv444 => "yuv444",
        }
    }

    pub const ALL: [ChromaFormat; 2] = [Self::Yuv420, Self::Yuv444];

    pub fn from_wire(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.wire() == s)
    }
}

/// FR-77 — a [`VideoCell`] read back through the vocabulary. Anything the
/// reader does not know is simply not here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedCell {
    pub codec: VideoCodec,
    pub backend: VideoBackend,
    pub chroma: Vec<ChromaFormat>,
    pub hw: bool,
}

impl VideoCell {
    /// Build a wire cell from the vocabulary — the producer side.
    pub fn new(
        codec: VideoCodec,
        backend: VideoBackend,
        chroma: &[ChromaFormat],
        hw: bool,
    ) -> Self {
        Self {
            codec: codec.wire().to_string(),
            backend: backend.wire().to_string(),
            chroma: chroma.iter().map(|c| c.wire().to_string()).collect(),
            hw,
        }
    }

    /// Parse a wire cell. `None` when the codec or backend is unknown to this
    /// build (a NEWER agent), and unknown chroma strings are dropped — the
    /// additive-list rule.
    pub fn typed(&self) -> Option<TypedCell> {
        let codec = VideoCodec::from_wire(&self.codec)?;
        let backend = VideoBackend::from_wire(&self.backend)?;
        let chroma = self
            .chroma
            .iter()
            .filter_map(|c| ChromaFormat::from_wire(c))
            .collect();
        Some(TypedCell {
            codec,
            backend,
            chroma,
            hw: self.hw,
        })
    }
}

/// A verb in [`AgentCaps::rpc`] — "this agent understands this frame".
///
/// The WIRE stays `Vec<String>` on purpose. Agents in the field span many
/// releases, and a typed wire format would strand every one of them; the point
/// of this enum is not to change the protocol but to make sure **both sides go
/// through one vocabulary**. Before it, the agent wrote four string literals
/// and three server call sites compared against four more, so a typo could
/// only be caught by a device silently looking unsupported — the exact
/// failure the capability list exists to prevent.
///
/// Advertising a verb says only that the agent UNDERSTANDS the frame. The org
/// kill-switch, the device's policy and the agent-local config key all still
/// have to say yes before anything happens.
///
/// **Adding one:** add the variant, then its arm in [`Self::wire`] (the match
/// is exhaustive, so the compiler makes you), then the entry in [`Self::ALL`]
/// (the `all_entries_are_unique_and_round_trip` test makes you). Consumers then
/// name it by variant and can no longer misspell it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RpcCap {
    /// `rc:rpc.exec` — run a bounded command (Fleet RPC).
    Exec,
    /// This device's LocalAPI may ORIGINATE a session against another device
    /// (`roomler ssh` / `roomler exec` from the device itself).
    Originate,
    /// `rc:ssh.grant` — the agent runs an SSH server and can redeem a grant.
    /// Gated on the `ssh-server` build feature, not merely on the version.
    Ssh,
    /// The agent HONOURS `SshPolicy.consent_mode`.
    ///
    /// Deliberately distinct from [`Self::Ssh`]: agents rc.419 and earlier
    /// advertise `ssh` while destructuring `consent_mode` away, so the server
    /// needs to ask "does this device actually do the thing?" rather than
    /// "does it know the feature exists". Expect that distinction to recur —
    /// it is why a verb is finer-grained than a version check.
    SshConsent,
    /// `rc:agent.config` — the agent understands a pushed desired-config and
    /// will reconcile against it (`docs/remote-config.md`).
    ///
    /// ⚠️ Advertising this says only that the frame is UNDERSTOOD, never that
    /// it will be obeyed. A device still refuses unless it has opted in with
    /// `remote_config_enabled`, and a secondary org's push is ignored
    /// regardless. The server needs the distinction because an older agent
    /// drops an unknown frame SILENTLY — the parse-error arm logs at `debug!`
    /// and carries on — so without this verb a dashboard would show a change
    /// that simply evaporated.
    Config,
    /// `rc:agent.config_status` — the agent reports back what it DID with a
    /// pushed desired-config.
    ///
    /// ⚠️ Distinct from [`Self::Config`] for the reason [`Self::SshConsent`] is
    /// distinct from [`Self::Ssh`], and this is the second time that shape has
    /// occurred exactly as `SshConsent`'s doc predicted: agents rc.457 and
    /// rc.458 shipped `config` — they apply a pushed config and say NOTHING
    /// about it. Folding the report into `config` would tell the dashboard
    /// "this device reports its outcome" about a fleet that does not, so a
    /// device that refused would be indistinguishable from one still thinking
    /// about it. A verb is finer-grained than a version check.
    ///
    /// ⚠️ `config` is a PREFIX of `config-report` and they mean different
    /// things, so matching must stay equality — see
    /// [`AgentCaps::has_rpc`] and the test that locks it.
    ConfigReport,
    /// FR-19 — this device runs an **org-relay server**: it has bound
    /// `relay_server_port`, answers probes, and (P2c+) forwards ciphertext
    /// between bound members. The server never installs a relay session on a
    /// device that does not advertise this.
    ///
    /// ⚠️ Equality-matched like every verb here. There is no `relay` verb
    /// today, and if one is ever added it must not be matched by prefix
    /// against this one — the `ssh` / `ssh-consent` trap, locked by test.
    RelayServer,
    /// FR-40 — `rc:agent.key_rotate`: the agent will mint a fresh overlay
    /// (WireGuard) key on order, persist it, report back and re-join under
    /// it (`docs/fr/FR-40-overlay-key-rotation.md`).
    ///
    /// ⚠️ Unlike `rc:agent.update`, the order must NOT be sent blind. The
    /// dashboard shows an operator a rotation in flight, so a pre-feature
    /// agent dropping the unknown tag in its `debug!` branch would be a lie
    /// on a screen — and a lie about a SECURITY action, which is worse than
    /// the config case this verb copies. Gate on it and say "device too old".
    ///
    /// Only advertised by builds with an overlay surface (`overlay-l3` /
    /// `overlay-netstack`): a build with no key has nothing to rotate.
    KeyRotate,
    /// FR-83 — the agent answers every `rc:ssh.grant` with
    /// `rc:ssh.grant_ack`, sent only once the grant is in the table its auth
    /// path reads (or naming why it refused it). The server then answers the
    /// CALLER only after that ack — before it, "queued for the device" was
    /// read as "the device has it", and a caller with a faster control path
    /// than the target dialled first and got `Permission denied (publickey)`
    /// (#1597).
    ///
    /// ⚠️ Third verb with `ssh` as its prefix, after `ssh-consent`: an agent
    /// advertising `ssh` alone never acks, so a server that read an ack out of
    /// `ssh` would wait out its whole bound on every grant to such a device.
    /// Equality-matched, locked by test.
    SshGrantAck,
    /// FR-90 — `rc:hive.start` / `rc:hive.stop`: the agent runs Hive agent
    /// sessions — it answers a start with `rc:hive.start_ack` and reports
    /// each session's lifecycle with `rc:hive.state`
    /// (`docs/roomler-hive-design.md` §3.4).
    ///
    /// ⚠️ Never sent blind, for the `exec` reason: a caller waits for the
    /// start's answer, and a pre-feature agent drops the unknown tag at
    /// `debug!`. Advertising it says the frames are UNDERSTOOD — the device's
    /// own `hive_enabled` (default off), `hive_accounts` and `hive_roots`
    /// still decide whether anything runs.
    ///
    /// ⚠️ `hive` is the prefix of `hive-replica` (P2c), and the two mean
    /// different things — running sessions is not holding copies of other
    /// devices' — so matching stays equality, as for `ssh` / `ssh-consent`.
    Hive,
    /// FR-90 P0d-2 — `rc:hive.view.*`: the agent serves a session's
    /// transcript to a browser over a data-only WebRTC peer. It answers a view
    /// grant with `rc:hive.view.grant_ack` before the browser is told to dial,
    /// answers the relayed offer, and closes the peer when the grant ends.
    ///
    /// ⚠️ `hive` is its prefix and the two are different promises — a P0c
    /// agent runs sessions and drops every `rc:hive.view.*` frame at `debug!`,
    /// so a server that read `hive-view` out of `hive` would leave the viewer
    /// waiting out its bound on every open. Equality-matched, locked by test.
    HiveView,
    /// FR-90 P1e — `rc:hive.memory`: the agent understands a session's
    /// core-memory snapshot, sent just before its start. Advertising it says
    /// the frame is UNDERSTOOD; the device's own `hive_core_memory` (default
    /// off) still decides whether a session ever sees it, because the model
    /// reads core memory as the user's own overriding instructions.
    ///
    /// ⚠️ `hive` is its prefix and NOT the same promise: an agent before P1e
    /// drops the frame at `debug!`. Equality-matched, locked by test.
    HiveMemory,
    /// FR-90 P1j — `rc:hive.adopt`: the agent mirrors terminal sessions its
    /// accounts adopted (`roomler hive adopt`), and its own `hive_adopt` (default
    /// off, never pushable) is on. Advertised only then: a device whose owner
    /// has not allowed adopting offers nothing, and the server honours an
    /// offer only from a device that advertises it.
    ///
    /// ⚠️ `hive` is its prefix and NOT the same promise — running sessions
    /// a person starts from Roomler is not mirroring the ones they started in a
    /// terminal. Equality-matched, locked by test.
    HiveAdopt,
    /// FR-90 P2c — the agent holds copies of its owner's sessions run on other
    /// devices: its own `hive_replica` (default off, never pushable) is on.
    /// Advertised only then — the gate that survives a compromised server — so
    /// a device that does not advertise it is never placed in a replicaset,
    /// and it refuses a join on its own word too.
    ///
    /// ⚠️ `hive` is its prefix and NOT the same promise: running sessions is
    /// not holding copies of other devices'. Equality-matched, locked by test.
    HiveReplica,
    /// FR-90 P2c — the agent offers itself as an archive replica: its own
    /// `hive_archive` (default off, never pushable) is on, beside
    /// `hive_replica`. An archive holds every session the org's rules allow
    /// once an `ADMINISTRATOR` designates it: offering is the device's,
    /// designating the org's.
    ///
    /// ⚠️ Neither `hive` nor `hive-replica` is this promise: a replica that is
    /// no archive holds its owner's own sessions only. Equality-matched,
    /// locked by test.
    HiveArchive,
    /// FR-90 P2d — the agent carries replica streams: it serves a session it
    /// holds to a member over QUIC (`rc:hive.replica.grant`), and, as a
    /// member, asks for and dials one (`rc:hive.replica.want`). A build
    /// capability, advertised while its store is open: a primary serves the
    /// sessions it runs whether or not its owner lets it hold copies of
    /// others' (`hive-replica`).
    ///
    /// ⚠️ `hive` is its prefix and NOT the same promise: a build before P2d
    /// drops every stream frame. Equality-matched, locked by test.
    HiveStream,
    /// FR-90 P2e-2 — the agent holds a leased session to the server's word:
    /// it runs one, and lets it call the model, after a restart or a
    /// reconnect only once the server has said on THAT connection that it
    /// still holds the session (`rc:hive.lease`). Only a connection with it
    /// is sent the word, or a start that asks for it (`lease`).
    ///
    /// ⚠️ `hive` is its prefix and NOT the same promise: a build before P2e-2
    /// runs what it hosts on its own word. Equality-matched, locked by test.
    HiveLease,
    /// FR-90 P2e-3 — the agent takes part in a promotion at either end: as
    /// the member a session moves to, it answers `rc:hive.prepare` with
    /// `rc:hive.prepare_ack` and runs the move (`rc:hive.move`, then the
    /// start); as the primary it moves from, it answers `rc:hive.drain` with
    /// `rc:hive.drained`, and a later `rc:hive.lease` at the same fence lifts
    /// the drain. The server promotes only between two connections that
    /// advertise it.
    ///
    /// ⚠️ `hive` is its prefix and NOT the same promise: a build before it
    /// drops every one of those frames, so a server that read it out of
    /// `hive` would wait out every bound of a promotion and leave the
    /// primary drained. Equality-matched, locked by test.
    HivePromote,
    /// FR-90 P2f-1a — the agent takes part in a teleport, a move to a device
    /// that holds no copy of the session yet, at either end: as the target,
    /// a `rc:hive.prepare` with `teleport` passes every start gate but the
    /// copy, and admits that one session's `teleport` join whatever its
    /// owner's `hive_replica`; as the primary, a join in the primary's role
    /// takes the session's first checkpoint at once when no turn runs, and
    /// says where its copy ends either way. A build property, like
    /// `hive-promote`: the device still refuses what its own gates refuse.
    ///
    /// ⚠️ `hive` is its prefix and NOT the same promise: a build before it
    /// refuses a teleport's prepare for want of a copy, and its primary says
    /// nothing at a join, so a server that read it out of `hive` would wait
    /// out a teleport's every bound. Equality-matched, locked by test.
    HiveTeleport,
    /// FR-90 P2f-3a — `hive-fork`: the device starts a fork of a session it
    /// holds a copy of. A start carrying `fork_of` takes the parent's last
    /// checkpoint under the fork's ids and launches `--resume <parent>
    /// --fork-session --session-id <fork>`, and the fork's checkpoints keep
    /// the parent's history beside its own. A build property.
    ///
    /// ⚠️ `hive` is its prefix and NOT the same promise: a build before it
    /// ignores `fork_of` and starts the fork EMPTY, a new conversation in
    /// the folder as it is. Equality-matched, locked by test.
    HiveFork,
    /// FR-90 P2f-4a — `hive-manage`: the device makes a terminal session it
    /// adopted, whose terminal ended there, a managed one. A start carrying
    /// `from_terminal` puts the terminal's own history in place as the
    /// account it ran as, by this device's record of whose terminal it was,
    /// and resumes it. A build property, on the platforms that adopt.
    ///
    /// ⚠️ `hive` is its prefix and NOT the same promise: a build before it
    /// ignores `from_terminal` and starts the conversation afresh, under the
    /// terminal's session id. Equality-matched, locked by test.
    HiveManage,
    /// FR-90 P2g-1 — `hive-purge`: the device purges a session on
    /// `rc:hive.purge` and answers `rc:hive.purge_ack` per part: its own copy,
    /// and, as the session's account, its state directory and the refs its
    /// checkpoints left. A build property, on every build that runs sessions.
    ///
    /// ⚠️ `hive` is its prefix and NOT the same promise: a build before it
    /// drops the frame, so a purge pushed to it would wait for an answer that
    /// never comes. Equality-matched, locked by test.
    HivePurge,
    /// FR-90 P2g-4a — `hive-purge-all`: the device purges every session it
    /// holds on `rc:hive.purge_all`, which its enrollment's removal sends. A
    /// build property, on every build that runs sessions.
    ///
    /// ⚠️ `hive` and `hive-purge` are its prefixes and NOT the same promise:
    /// `agent-v0.4.136` purges a session but cannot decode this frame, and
    /// would log a dropped frame at every removal. Nothing waits on the frame,
    /// so a build without it is sent nothing and keeps what it held, as one
    /// offline at its removal does. Equality-matched, locked by test.
    HivePurgeAll,
    /// #2294 — `hive-purge-drain`: on a goodbye (`AgentDeleted`) the daemon
    /// finishes the removal purge `rc:hive.purge_all` started before it exits,
    /// bounded. So a removal's kick may tell it at once: the goodbye that
    /// follows the purge's frame no longer cuts the purge short. A build
    /// property, on every build that runs sessions.
    ///
    /// ⚠️ `hive` and `hive-purge` are its prefixes and NOT the same promise:
    /// `agent-v0.4.137` purges at its removal but exits at once on the
    /// goodbye, so the kick leaves its socket open instead. Equality-matched,
    /// locked by test.
    HivePurgeDrain,
    /// FR-90 P2i-1 — `hive-search`: the device answers full-text search over
    /// the copies it holds, for the sessions a `rc:hive.search.grant` names,
    /// to that grant's viewer peer. Only while it offers itself as an
    /// archive replica (`hive-archive`), whose copies it serves.
    ///
    /// ⚠️ `hive` is its prefix and NOT the same promise: a build before it
    /// drops the grant, and a viewer would wait for an answer that never
    /// comes. Equality-matched, locked by test.
    HiveSearch,
    /// FR-94 — a Windows device runs Fleet RPC as SYSTEM through its
    /// session-0 service. An administrator anchored the device (the service
    /// holds its own credential, in a file only SYSTEM and Administrators can
    /// write), and the service answered the worker's health ring with that
    /// anchor's device id and `exec_enabled`. The server then routes
    /// `rc:rpc.exec` with `via_service`: the worker rings the service's
    /// doorbell with the request id alone, and the service claims the
    /// command from the server itself (FR-94 §5b).
    ///
    /// ⚠️ `exec` is its prefix and NOT the same promise: every agent since
    /// Fleet RPC says `exec`, and a server that read SYSTEM out of it would
    /// route commands to a doorbell nobody answers. Equality-matched, locked by
    /// test.
    ExecSystem,
    /// FR-105 — a Windows device serves roomler SSH from its session-0
    /// SYSTEM service: the anchor allows it (its `ssh` ceiling is not `off`),
    /// and the service answered the worker's health ring. The server then
    /// routes a grant with `via_service`: the service claims it, and the
    /// caller dials the service's port and pins the service's host key.
    ///
    /// ⚠️ `ssh` is its prefix and NOT the same promise: `ssh` says "the
    /// worker runs an SSH server", which on an attended install is the
    /// signed-in user. Equality-matched, locked by test.
    SshSystem,
    /// FR-90 P3-8 — the device's SSH server holds a grant marked
    /// `one_command` to one `exec` and refuses anything else on it: a shell,
    /// a PTY, a forward, a subsystem. The server sends an agent session's
    /// grant only to a device saying so (P3-8-1b); the device's half is
    /// P3-8-2a.
    ///
    /// ⚠️ `ssh` is its prefix and NOT the same promise: an `ssh` device that
    /// cannot read the field would serve a session's key a shell.
    /// Equality-matched, locked by test.
    SshOneCommand,
    /// FR-99 — the device serves privacy mode: it understands the `PRIVACY`
    /// permission, can cover the local screen with a curtain the capture
    /// does not see, and its owner allowed it (`privacy_mode_allowed`,
    /// device-owned, default off, never pushable). Advertised only then, like
    /// [`Self::HiveAdopt`].
    ///
    /// ⚠️ The hub sends `PRIVACY` ONLY to a connection advertising this. The
    /// `rc:*` wire carries `Permissions` as names, and an agent that does not
    /// know a name fails the WHOLE `rc:request` — so a stray `PRIVACY` would
    /// not merely be ignored, it would break the session.
    PrivacyMode,
    /// FR-99 — a curtain is possible on this host, whether or not its owner
    /// allows it. Capability, never permission: it lets the hub tell "the
    /// owner has not switched privacy mode on" (`device_not_opted_in`) from
    /// "this device cannot do it at all", so a viewer explains the first and
    /// offers nothing for the second — FR-85's `available` lesson.
    ///
    /// ⚠️ It never earns a `PRIVACY` grant: an agent advertising it alone
    /// knows the name but must not be asked to serve it.
    PrivacyAvailable,
    /// FR-101 P2 — the agent enforces the session policy: it masks a grant
    /// by `Request.session_policy`, and its host prompt names every feature
    /// the policy says to `ask` about, granting it only when the person there
    /// approves.
    ///
    /// ⚠️ The hub keeps an `ask` feature only for a connection advertising
    /// this. An older agent grants whatever reaches it: its prompt shows the
    /// raw permission names at most (audio, which is no permission, not at
    /// all), and it holds no policy to check the grant against, so "ask"
    /// would mean "on".
    SessionPolicy,
    /// FR-101 P4b-2 — the agent keeps an idle limit: it ends a session that
    /// sat past `Request.idle_secs` with no input from its controller and no
    /// significant change on the screen, as `IdleTimeout` with
    /// `limit: "idle"`, and warns the viewer on the control channel first.
    ///
    /// The hub sends the limit to every agent (an older one ignores it), but
    /// tells a viewer the limit (`SessionCreated.idle_secs`) only for a
    /// connection advertising this: a limit nothing keeps is no limit.
    IdleTimeout,
    /// FR-99 P3b — the agent takes the server's lock ask
    /// (`Request.lock_on_end`) into the lock when the last session ends, the
    /// stricter of it and the owner's own `lock_on_end` winning. Advertised
    /// only by an install that can lift the lock remotely afterwards (the
    /// Windows service, the Linux root daemon), so an admin's ask never leaves
    /// a per-user install at a padlock no session can lift; the
    /// `session_requested` audit row says when an ask is not enforced.
    LockOnEnd,
    /// FR-97 P5a — a Linux or macOS build runs `console_user` as the person
    /// at the device's screen (logind's seat0, the owner of `/dev/console`),
    /// and refuses when nobody is there: SSH's `account_mode`, and Fleet
    /// RPC's `run_as`, which the server then sends in `rc:rpc.exec`. A
    /// property of the BUILD. Windows never advertises it: its
    /// `console_user` is the SYSTEM service's (FR-94, FR-105), keyed on the
    /// OS.
    ///
    /// ⚠️ The server sends `run_as` ONLY to a connection advertising this.
    /// An older agent ignores the field and would run the command as root,
    /// the identity the policy refused. An older agent refuses an SSH
    /// session's `console_user` itself ("a Windows concept"), so that half
    /// fails closed either way, and the server still refuses to store it.
    ConsoleUser,
    /// FR-90 P3-3b — the agent takes vault leases: it sends `rc:vault.lease`
    /// for its sessions and opens the sealed `rc:vault.leased` with the key
    /// its hello carried (`AgentHello::vault_key`). Advertised only while that
    /// key is, on the primary enrollment's connection.
    ///
    /// ⚠️ The vault answers a lease request only from a connection that
    /// advertises this AND whose hello stored a key: an agent without it
    /// cannot open what it would be sent.
    Vault,
    /// FR-52 — this device understands **cross-org remote access**: it honours
    /// `external_access_enabled` (gate 3), can verify the device-held password
    /// (gate 4), and tells the person at the machine that the controller is
    /// from OUTSIDE the organization.
    ///
    /// ⚠️ The prompt half is why this gates the ADMIN approval and not just
    /// the session. An older agent shows the ordinary "Alex wants to control
    /// this machine" panel with no hint that Alex is a stranger — so approving
    /// such a device would put a promise on screen that the device does not
    /// keep, and consent given under it would not be informed consent.
    ///
    /// ⚠️ Equality-matched, like every verb here. `external-access` shares no
    /// prefix with an existing verb today; if a shorter `external` is ever
    /// added, the `ssh` / `ssh-consent` trap applies and the test locks it.
    ExternalAccess,
    /// FR-52 P4 — this build ENFORCES the external session binding: it opens an
    /// external session only against a login it verified itself, refuses an SDP
    /// offer whose DTLS fingerprint is not authenticated under that login's key,
    /// and authenticates its own answer the same way.
    ///
    /// ⚠️ Deliberately NOT the same verb as [`Self::ExternalAccess`], which every
    /// build advertises. `rc:request` carries the external grant in an optional
    /// field, and an agent that predates the binding would IGNORE that field and
    /// run an ordinary session — no binding, no local ceiling, no "outside your
    /// organization" — failing OPEN. The server opens an external session only
    /// on an agent advertising this, so an old agent is never asked.
    ///
    /// ⚠️ `external-access` and `external-session` share a prefix; neither is a
    /// prefix of the other, and matching stays equality regardless.
    ExternalSession,
    /// FR-100 P1b — this build signs its session answer with its device key
    /// (`AgentHello.peer_auth_key`) when the offer asks for it (a nonce in
    /// `rc:sdp.offer`'s `peer_auth`). The signature covers the session's
    /// transcript, both DTLS fingerprints included
    /// ([`crate::signaling::peer_auth_transcript`]), so a browser that pinned
    /// the key catches a hub that swapped the device's certificate.
    ///
    /// A BUILD property, like `config`: an enrollment that could not keep a
    /// key sends an empty `peer_auth_key` and signs nothing, while still
    /// advertising this. No other verb starts with `peer`, and matching stays
    /// equality regardless.
    PeerAuth,
    /// Agent enforces shared sessions with a hard 12-second monotonic lease.
    SharedSessionLease,
    /// Typed single-use embedded SSH stream, no generic forwarding.
    SharedSshStream,
    /// MeshHarbor #20 — `rc:forward.set`: the agent runs managed forwards on
    /// its userspace backend and answers with `rc:forward.status`. The
    /// server pushes a forward set only to a device that advertises this.
    ManagedForward,
    /// MeshHarbor #20 — and on its owned nftables backend (DNAT, optional
    /// source preservation) under commit-confirm: it answers
    /// `rc:forward.status` with the change's `confirm` generation, and rolls
    /// the change back unless `rc:forward.confirm` comes back in time. A
    /// device without it is never sent an `nft` forward.
    ManagedForwardNft,
}

impl RpcCap {
    /// Exactly what crosses the wire.
    ///
    /// ⚠️ These strings are a COMPATIBILITY SURFACE, not an implementation
    /// detail: changing one silently un-advertises the feature on every agent
    /// already deployed, which reads server-side as "this device does not
    /// support it" rather than as an error. Locked by test.
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Exec => "exec",
            Self::Originate => "originate",
            Self::Ssh => "ssh",
            Self::SshConsent => "ssh-consent",
            Self::Config => "config",
            Self::ConfigReport => "config-report",
            Self::RelayServer => "relay-server",
            Self::ManagedForward => "managed-forward",
            Self::ManagedForwardNft => "managed-forward-nft",
            Self::KeyRotate => "key-rotate",
            Self::SshGrantAck => "ssh-grant-ack",
            Self::Hive => "hive",
            Self::HiveView => "hive-view",
            Self::HiveMemory => "hive-memory",
            Self::HiveAdopt => "hive-adopt",
            Self::HiveReplica => "hive-replica",
            Self::HiveArchive => "hive-archive",
            Self::HiveStream => "hive-stream",
            Self::HiveLease => "hive-lease",
            Self::HivePromote => "hive-promote",
            Self::HiveTeleport => "hive-teleport",
            Self::HiveFork => "hive-fork",
            Self::HiveManage => "hive-manage",
            Self::HivePurge => "hive-purge",
            Self::HivePurgeAll => "hive-purge-all",
            Self::HivePurgeDrain => "hive-purge-drain",
            Self::HiveSearch => "hive-search",
            Self::ExecSystem => "exec-system",
            Self::SshSystem => "ssh-system",
            Self::SshOneCommand => "ssh-one-command",
            Self::PrivacyMode => "privacy-mode",
            Self::PrivacyAvailable => "privacy-available",
            Self::SessionPolicy => "session-policy",
            Self::IdleTimeout => "idle-timeout",
            Self::LockOnEnd => "lock-on-end",
            Self::ConsoleUser => "console-user",
            Self::Vault => "vault",
            Self::ExternalAccess => "external-access",
            Self::ExternalSession => "external-session",
            Self::PeerAuth => "peer-auth",
            Self::SharedSessionLease => "shared-session-lease-v1",
            Self::SharedSshStream => "shared-ssh-stream-v1",
        }
    }

    /// Every verb THIS build knows about.
    pub const ALL: [RpcCap; 42] = [
        Self::Exec,
        Self::Originate,
        Self::Ssh,
        Self::SshConsent,
        Self::Config,
        Self::ConfigReport,
        Self::RelayServer,
        Self::KeyRotate,
        Self::SshGrantAck,
        Self::Hive,
        Self::HiveView,
        Self::HiveMemory,
        Self::HiveAdopt,
        Self::HiveReplica,
        Self::HiveArchive,
        Self::HiveStream,
        Self::HiveLease,
        Self::HivePromote,
        Self::HiveTeleport,
        Self::HiveFork,
        Self::HiveManage,
        Self::HivePurge,
        Self::HivePurgeAll,
        Self::HivePurgeDrain,
        Self::HiveSearch,
        Self::ExecSystem,
        Self::SshSystem,
        Self::SshOneCommand,
        Self::PrivacyMode,
        Self::PrivacyAvailable,
        Self::SessionPolicy,
        Self::IdleTimeout,
        Self::LockOnEnd,
        Self::ConsoleUser,
        Self::Vault,
        Self::ExternalAccess,
        Self::ExternalSession,
        Self::PeerAuth,
        Self::SharedSessionLease,
        Self::SharedSshStream,
        Self::ManagedForward,
        Self::ManagedForwardNft,
    ];

    /// Parse a wire verb. `None` for anything unrecognised — see
    /// [`AgentCaps::has_rpc`] for why that is not an error.
    pub fn from_wire(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.wire() == s)
    }
}

/// FR-85 P3 — a remote-recording capability word in [`AgentCaps::record`].
/// The [`RpcCap`] pattern: variant → [`RecordCap::wire`] (the compatibility
/// surface) → [`RecordCap::ALL`], matched by EQUALITY.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordCap {
    /// The device serves remote recording (its owner opted in).
    Remote,
    /// …and may include what the computer plays.
    RemoteAudio,
    /// P3c-2 — a recorder can serve a remote session on this device, whether
    /// or not its owner allows it. Capability, never permission.
    Available,
}

impl RecordCap {
    /// Exactly what crosses the wire. ⚠️ A compatibility surface: renaming
    /// one un-advertises the feature on every deployed agent. Locked by test.
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Remote => "remote",
            Self::RemoteAudio => "remote-audio",
            Self::Available => "available",
        }
    }

    /// Every word THIS build knows about.
    pub const ALL: [RecordCap; 3] = [Self::Remote, Self::RemoteAudio, Self::Available];

    /// Parse a wire word; `None` for anything unrecognised (ignored, never
    /// an error — see [`AgentCaps::has_rpc`]).
    pub fn from_wire(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.wire() == s)
    }
}

impl AgentCaps {
    /// FR-67 P7 — why this enrollment will not act on an `rc:agent.update`
    /// pushed from this organization, or `None` when it will — or when it
    /// does not say (an older agent, or a value this server does not know).
    pub fn update_refusal(&self) -> Option<UpdateRefusal> {
        match self.update_mode.as_deref() {
            Some("primary_org") => Some(UpdateRefusal::PrimaryOrg),
            Some("off") => Some(UpdateRefusal::AutoUpdateOff),
            _ => None,
        }
    }

    /// Does this agent advertise `cap`?
    ///
    /// ⚠️ Unrecognised verbs are IGNORED rather than rejected. A NEWER agent
    /// may advertise something this server has never heard of, and the whole
    /// point of an additive string list is that an older reader keeps working
    /// — so "I don't know that verb" must mean "not one I gate on", never an
    /// error.
    pub fn has_rpc(&self, cap: RpcCap) -> bool {
        self.rpc.iter().any(|v| v == cap.wire())
    }

    /// FR-85 P3 — does this agent advertise the recording word `cap`?
    /// Equality, never a prefix: `remote` is a prefix of `remote-audio`.
    pub fn has_record(&self, cap: RecordCap) -> bool {
        self.record.iter().any(|v| v == cap.wire())
    }

    /// FR-77 — the cells this reader can name. Entries from a newer agent
    /// whose codec or backend this build does not know are skipped, and a
    /// pre-FR-77 agent yields an empty list — callers then fall back to the
    /// legacy fields, never to an error.
    pub fn typed_cells(&self) -> Vec<TypedCell> {
        self.video_cells
            .iter()
            .filter_map(VideoCell::typed)
            .collect()
    }

    /// FR-77 — can this host produce `codec` in `chroma` on ANY backend?
    /// Reads only [`Self::video_cells`]; an agent that predates them answers
    /// `false` here and is judged by the legacy fields instead.
    pub fn has_cell(&self, codec: VideoCodec, chroma: ChromaFormat) -> bool {
        self.typed_cells()
            .iter()
            .any(|c| c.codec == codec && c.chroma.contains(&chroma))
    }
}

/// How consent is obtained before a controller may drive a device. Resolved
/// server-side per session from the device's [`AccessPolicy::consent_mode`]
/// (with `Prompt` — attended — as the system default), then carried to the agent
/// in `ServerMsg::Request` as a directive the agent obeys. Self-control
/// (`controller == owner_user_id`) short-circuits to `Auto` in the API gate
/// unless the device set [`AccessPolicy::prompt_owner`].
///
/// ⚠️ The directive is a CEILING, not a floor. A device that set
/// `auto_grant_session = false` locally always prompts, even under `Auto` —
/// the agent resolves the two with `consent::strictest_of`. Same rule as
/// exec's and SSH's gate 4: the device's own refusal survives the server.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ConsentMode {
    /// Unattended: grant immediately, no prompt. For self-owned / kiosk / server
    /// devices explicitly marked unattended.
    Auto,
    /// Attended (the default): the controlled host prompts (tray / CLI) and the
    /// person there must approve within the timeout.
    #[default]
    Prompt,
    /// Email an approve-link to the device owner; the session waits (Phase 4).
    Email,
    /// Push an in-app consent card to the device owner (Phase 4).
    Push,
    /// Prompt the host AND email the owner, in parallel — first answer wins.
    ///
    /// Not a sequential fallback, despite the name: the server emails the
    /// approve-link the moment the session is requested, at the same time as
    /// the agent raises its on-host prompt. What IS sequential is the two
    /// windows — the host prompt closes after
    /// [`crate::consent::HOST_PROMPT_TIMEOUT`] while the emailed link stays
    /// live for the full [`crate::consent::ASYNC_CONSENT_TIMEOUT`], so a host
    /// nobody answers hands over to the owner instead of ending the session.
    /// An explicit host *Deny* does end it: the person at the machine said no.
    PromptThenEmail,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AccessPolicy {
    /// How consent is obtained for a non-owner controller. `None` = inherit the
    /// system default ([`ConsentMode::Prompt`] — attended). Set per device by a
    /// `MANAGE_AGENTS` admin. (Replaces the legacy `require_consent` bool; old
    /// rows carrying that field deserialize to `None` → attended, the safe
    /// default.)
    #[serde(default)]
    pub consent_mode: Option<ConsentMode>,
    /// FR-27 — apply [`Self::consent_mode`] to the device's OWNER too.
    ///
    /// `None`/`false` (the default, and every pre-FR-27 row) keeps the
    /// historical shortcut: controlling your own device auto-consents, because
    /// unattended access to your own headless boxes is the common case and
    /// prompting them would ask a machine nobody is sitting at.
    ///
    /// That shortcut is also why the picker looked broken. It is applied in
    /// `resolve_session_authz` BEFORE the policy is read, so on a fleet where
    /// one person owns every device, `consent_mode` had no observable effect
    /// whatsoever — and nothing on screen said so. `true` here makes the mode
    /// authoritative for the owner as well, which is both the honest behaviour
    /// for a shared workstation and the only way to field-test the attended
    /// modes without a second account.
    #[serde(default)]
    pub prompt_owner: Option<bool>,
    #[serde(default)]
    pub allowed_role_ids: Vec<ObjectId>,
    #[serde(default)]
    pub allowed_user_ids: Vec<ObjectId>,
    /// FR-101 P4b-2 — this device's own idle limit, in minutes: a session
    /// ends after this long with no input from its controller and no
    /// significant change on the screen. Combined with the org's
    /// (`TenantSettings.rc_limits.idle_secs`), the SHORTER wins, so a device
    /// can tighten its org's limit but never loosen it. `None` or `0` = no
    /// limit of its own. Stored since the first access policy and read by
    /// nothing until P4b-2. See [`Self::idle_limit_secs`].
    pub auto_terminate_idle_minutes: Option<u32>,
    /// P6 — multi-user input arbitration mode. `None` = the system default
    /// ([`InputMode::Free`] — free-for-all with agent-side fencing). Old rows
    /// deserialize to `None` via the default.
    #[serde(default)]
    pub input_mode: Option<InputMode>,
    /// #1882 — may a remote-desktop session ride the WireGuard overlay?
    ///
    /// `None`/`false` (the default, and every row older than the field): no.
    /// The agent keeps every overlay address out of the session's ICE — its
    /// own overlay interface, a browser candidate on a mesh address, and the
    /// loopback-TURN relay the Hub would otherwise hand it — so the media
    /// takes a LAN, srflx or TURN pair. `true` restores the behaviour from
    /// before the field: whichever pair ICE finds best, overlay included.
    ///
    /// Off by default because a session on the overlay inherits the
    /// overlay's failure modes (#1856: a 3 ms route hole on macOS killed
    /// sessions) and hides its carrier from rate control: a pair the mesh
    /// carries over DERP/TCP reads as a direct host pair.
    #[serde(default)]
    pub rc_overlay: Option<bool>,
    /// FR-99 P3b — what this device's sessions ask of it when the last one
    /// ends: `auto` (lock again if the screen was locked, or nobody was at it,
    /// when the session started) or `always`. Set by a `MANAGE_AGENTS` admin.
    /// It can only make the device STRICTER: the device takes the stricter of
    /// this and its own `lock_on_end` (device-owned, never pushable), so
    /// `never` asks nothing, as `None` does (the default, and every older
    /// row). Forwarded on `rc:request` only to an agent advertising
    /// `lock-on-end`.
    #[serde(default)]
    pub lock_on_end: Option<LockOnEnd>,
}

/// FR-101 P4b-2 — the longest idle limit anything sets: a day, the same
/// ceiling as the org's route.
pub const IDLE_LIMIT_MAX_SECS: u32 = 86_400;

/// FR-101 P4b-2 — the org's idle limit and the device's, combined: the
/// SHORTER one, or whichever is set. `None` = no idle limit at all.
pub fn stricter_idle_limit(org_secs: Option<u32>, device_secs: Option<u32>) -> Option<u32> {
    match (org_secs, device_secs) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

impl AccessPolicy {
    /// #1882 — [`Self::rc_overlay`] resolved: off unless explicitly on.
    pub fn rc_overlay_allowed(&self) -> bool {
        self.rc_overlay.unwrap_or(false)
    }

    /// FR-101 P4b-2 — [`Self::auto_terminate_idle_minutes`] as seconds. `0`
    /// reads as no limit, the way RDP spells "never", rather than as a
    /// session that ends the moment it starts; anything past a day is held to
    /// [`IDLE_LIMIT_MAX_SECS`].
    pub fn idle_limit_secs(&self) -> Option<u32> {
        match self.auto_terminate_idle_minutes {
            None | Some(0) => None,
            Some(m) => Some(m.saturating_mul(60).min(IDLE_LIMIT_MAX_SECS)),
        }
    }

    /// FR-99 P3b — [`Self::lock_on_end`] as an ask of the device: `None` when
    /// unset or `never`, which asks nothing of a device whose own setting is
    /// already the floor.
    pub fn lock_on_end_ask(&self) -> Option<LockOnEnd> {
        self.lock_on_end.filter(|l| *l > LockOnEnd::Never)
    }

    /// Effective consent mode for a NON-owner controller: the per-device mode,
    /// or the system default (`Prompt` = attended) when unset.
    pub fn effective_consent_mode(&self) -> ConsentMode {
        self.consent_mode.unwrap_or(ConsentMode::Prompt)
    }

    /// FR-27 — the mode for a controller who IS the device owner. `Auto` unless
    /// the device opted into being asked ([`Self::prompt_owner`]).
    ///
    /// Split from [`Self::effective_consent_mode`] rather than folded into it
    /// so the owner shortcut is a named, greppable decision instead of an
    /// `if` buried in the API gate — which is how it stayed invisible.
    pub fn owner_consent_mode(&self) -> ConsentMode {
        if self.prompt_owner.unwrap_or(false) {
            self.effective_consent_mode()
        } else {
            ConsentMode::Auto
        }
    }
}

/// P6 — multi-user input arbitration mode for a device. `Free` (the default)
/// lets every INPUT-granted session inject, serialized + modifier-fenced by
/// the agent's InputArbiter; `Exclusive` funnels input through one explicit
/// floor holder (request/grant, idle takeover). Set per device via
/// `AccessPolicy.input_mode`; toggleable in-session on the control DC.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum InputMode {
    #[default]
    Free,
    Exclusive,
}

/// FR-101 P2 — one sensitive session feature (clipboard, files, audio), as a
/// policy allows it. The wire twin of the org setting
/// (`roomler_ai_db::models::RcFeaturePolicy`): this crate stays a leaf the
/// agent links, so it cannot name the db type, and the two read the same.
///
/// ⚠️ A value this build does not know reads as [`Self::Off`], never as an
/// error: a restriction from a newer server is still a restriction, and an
/// unknown string must not fail the whole `rc:request`.
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FeaturePolicy {
    /// Allowed, subject to the session's grant.
    #[default]
    On,
    /// Allowed only on a session the person at the device approves, on a
    /// host prompt that names the feature (an agent advertising
    /// [`RpcCap::SessionPolicy`]). Under any other consent mode nobody there
    /// is asked, so the session goes without it.
    Ask,
    /// Never.
    Off,
}

impl<'de> Deserialize<'de> for FeaturePolicy {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // Any JSON type, not only a string, for the same reason.
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Text(String),
            Other(serde::de::IgnoredAny),
        }
        Ok(match Raw::deserialize(d)? {
            Raw::Text(s) if s == "on" => Self::On,
            Raw::Text(s) if s == "ask" => Self::Ask,
            // "off", anything a newer server may send, and anything that is
            // not a string at all.
            _ => Self::Off,
        })
    }
}

/// FR-101 P2 — the session policy for clipboard, files and audio. P2a sends
/// the ORG's in `ServerMsg::Request::session_policy`, so an agent can name
/// the `ask` features on its prompt and enforce the rest even where the hub
/// was bypassed. Every field defaults to `on`: absent means unrestricted.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SessionPolicy {
    #[serde(default)]
    pub clipboard: FeaturePolicy,
    #[serde(default)]
    pub files: FeaturePolicy,
    #[serde(default)]
    pub audio: FeaturePolicy,
}

impl FeaturePolicy {
    /// The stricter of two: `off` beats `ask` beats `on`. How an org's policy
    /// and a device's floor combine, on the hub and on the agent alike.
    pub fn stricter(self, other: Self) -> Self {
        match (self, other) {
            (Self::Off, _) | (_, Self::Off) => Self::Off,
            (Self::Ask, _) | (_, Self::Ask) => Self::Ask,
            (Self::On, Self::On) => Self::On,
        }
    }
}

impl SessionPolicy {
    /// Nothing restricted: the policy every org had before the feature.
    pub fn is_unrestricted(&self) -> bool {
        *self == Self::default()
    }
}

/// FR-99 P3 — what a device does to its screen when the last remote session
/// ends. Ordered from the loosest to the strictest, so [`Self::stricter`] is a
/// `max`: the device's own setting is a floor a server may raise, never lower.
///
/// ⚠️ A value this build does not know reads as [`Self::Always`], never as an
/// error, as [`FeaturePolicy`] reads one as `off`: a stricter setting from a
/// newer build is still a stricter setting, and an unknown string must not
/// fail the whole config file or frame.
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[serde(rename_all = "snake_case")]
pub enum LockOnEnd {
    /// Leave the screen as it is (the default).
    #[default]
    Never,
    /// Restore what was found: lock when the session began on a locked screen,
    /// or with nobody at the computer.
    Auto,
    /// Lock at the end of every remote session.
    Always,
}

impl LockOnEnd {
    /// The stricter of two: `always` beats `auto` beats `never`.
    pub fn stricter(self, other: Self) -> Self {
        self.max(other)
    }
}

impl<'de> Deserialize<'de> for LockOnEnd {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Text(String),
            Other(serde::de::IgnoredAny),
        }
        Ok(match Raw::deserialize(d)? {
            Raw::Text(s) if s == "never" => Self::Never,
            Raw::Text(s) if s == "auto" => Self::Auto,
            // "always", anything a newer build may write, and anything that is
            // not a string at all.
            _ => Self::Always,
        })
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Fleet RPC (remote command execution)
// ────────────────────────────────────────────────────────────────────────────

/// Execution bounds. The server clamps an incoming request to these before it
/// reaches the wire; the agent enforces them again on its own side, so a
/// forged or replayed frame can't ask for an unbounded run.
pub mod exec_limits {
    /// Wall-clock budget when the caller doesn't specify one.
    pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;
    /// Hard ceiling. Longer work belongs in a job the command kicks off, not
    /// in a request a caller is blocked on.
    pub const MAX_TIMEOUT_MS: u64 = 300_000;
    /// Combined stdout+stderr ceiling when the caller doesn't specify one.
    pub const DEFAULT_MAX_OUTPUT_BYTES: u64 = 256 * 1024;
    /// Hard ceiling on combined output.
    pub const MAX_OUTPUT_BYTES: u64 = 1024 * 1024;
    /// Concurrent commands one device will run. Beyond this the agent
    /// refuses rather than queues — a caller blocked on a deadline would
    /// rather get a fast "busy" than a slow timeout.
    pub const MAX_CONCURRENT_PER_AGENT: usize = 4;
    /// Requests per minute per (caller, device) pair.
    pub const RATE_LIMIT_PER_MINUTE: u32 = 30;

    /// Clamp a caller-supplied timeout into range, substituting the default
    /// for `None`/0.
    pub fn clamp_timeout_ms(requested: u64) -> u64 {
        match requested {
            0 => DEFAULT_TIMEOUT_MS,
            n => n.min(MAX_TIMEOUT_MS),
        }
    }

    /// Clamp a caller-supplied output ceiling into range, substituting the
    /// default for `None`/0.
    pub fn clamp_output_bytes(requested: u64) -> u64 {
        match requested {
            0 => DEFAULT_MAX_OUTPUT_BYTES,
            n => n.min(MAX_OUTPUT_BYTES),
        }
    }
}

/// Whether a device accepts remote command execution at all.
///
/// Default `Off` — every existing row deserialises to it, so enabling the
/// feature can never retroactively open a device.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExecMode {
    /// Refuse every exec request. The default.
    #[default]
    Off,
    /// Accept exec from callers that clear every other gate.
    On,
}

/// Per-device remote-execution policy — gate 3 of four (see
/// `docs/fleet-rpc.md`). Deliberately NOT folded into [`AccessPolicy`]:
/// that grants screen-view, and "may watch your screen" must never be the
/// same checkbox as "may run a root shell".
///
/// ⚠️ On a systemd host commands run as **root**, and on an anchored Windows
/// device as **SYSTEM** through its service (FR-94; [`Self::run_as`]) — so
/// `ExecMode::On` is root-equivalent by construction. That is required for
/// the diagnostics this exists for (`Get-NetFirewallRule`, `netsh`, route
/// tables, service state) and is stated in the admin UI's opt-in copy rather
/// than buried here.
/// `PartialEq` so a caller can ask "is this indistinguishable from the
/// untouched default?" — the API listing needs exactly that question to avoid
/// reporting a policy nobody set (see `AgentResponse::exec_policy`).
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct ExecPolicy {
    /// Does this device accept exec requests? Gate 3.
    #[serde(default)]
    pub mode: ExecMode,
    /// May this device *originate* exec against other devices (the
    /// `roomler exec` CLI path, where the daemon's own agent WS carries the
    /// request)? Default `false` — without this, compromising any enrolled
    /// laptop would inherit its owner's exec rights across the whole fleet.
    #[serde(default)]
    pub can_originate: bool,
    /// Restrict callers to these users. Empty = no user restriction (the
    /// permission bit + the other gates still apply).
    #[serde(default)]
    pub allowed_user_ids: Vec<ObjectId>,
    /// Restrict callers to holders of these roles. Empty = no role
    /// restriction.
    #[serde(default)]
    pub allowed_role_ids: Vec<ObjectId>,
    /// How consent is obtained before a command runs. `None` = the safe
    /// default ([`ConsentMode::Prompt`]); unattended servers set `Auto`.
    /// Only `Auto` and `Prompt` are honoured — the email/push variants are
    /// session-shaped and resolve to `Prompt`.
    #[serde(default)]
    pub consent_mode: Option<ConsentMode>,
    /// Shells the device will accept, e.g. `["pwsh", "powershell"]`. Empty =
    /// every shell the host supports.
    #[serde(default)]
    pub shells: Vec<String>,
    /// FR-94 P4 — which account a Windows device's commands run as through
    /// its SYSTEM service. Default SYSTEM. FR-97 P5a: on Linux and macOS,
    /// `console_user` is the person at the device's screen, to whom the
    /// daemon drops (`rc:rpc.exec`'s `run_as`), storable only for an agent
    /// that advertises `console-user`; `system` is root.
    #[serde(default)]
    pub run_as: ExecRunAs,
}

/// FR-94 P4 — the account a Windows command runs as, through the device's
/// SYSTEM service ([`ExecPolicy::run_as`]). FR-97 P5a: on Linux and macOS,
/// in the daemon itself.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExecRunAs {
    /// `NT AUTHORITY\SYSTEM`, in session 0. The default. Root off Windows.
    #[default]
    System,
    /// The user signed in at the console. The service reaches them through
    /// `WTSQueryUserToken`, which only SYSTEM may call; with nobody signed in
    /// the command is refused. Off Windows (FR-97 P5a), the person at the
    /// screen (logind's seat0, the owner of `/dev/console`), to whom the
    /// daemon drops; refused there too when nobody is at it.
    ConsoleUser,
}

impl ExecRunAs {
    /// The spelling the claim hands the service, and the audit's `ran_as`.
    pub fn wire(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::ConsoleUser => "console_user",
        }
    }
}

impl ExecPolicy {
    /// Effective consent mode. Unset ⇒ [`ConsentMode::Prompt`] (attended);
    /// the session-shaped variants collapse to `Prompt` because there is no
    /// exec equivalent of an approve-link flow.
    pub fn effective_consent_mode(&self) -> ConsentMode {
        match self.consent_mode {
            Some(ConsentMode::Auto) => ConsentMode::Auto,
            _ => ConsentMode::Prompt,
        }
    }

    /// The shell an empty / `auto` request resolves to on `os`.
    ///
    /// The server resolves BEFORE checking [`Self::allows_shell`], so the
    /// allowlist is compared against the shell that will actually run. Without
    /// this, a device allowing `["powershell"]` refuses the default-shell
    /// request that would have become powershell — which is what
    /// `roomler exec <device> -- …` and every `roomler diag` bundle sends.
    /// Field-caught 2026-08-06: it made `diag` unusable on every device with a
    /// narrowed allowlist.
    ///
    /// MUST stay in lockstep with the agent's `exec::resolve_shell`, or the
    /// policy check and the execution would disagree about what ran.
    pub fn default_shell_for(os: OsKind) -> &'static str {
        match os {
            OsKind::Windows => "powershell",
            _ => "bash",
        }
    }

    /// Normalise a requested shell: empty / `auto` become the host default.
    pub fn resolve_shell(requested: &str, os: OsKind) -> String {
        let t = requested.trim();
        if t.is_empty() || t.eq_ignore_ascii_case("auto") {
            Self::default_shell_for(os).to_string()
        } else {
            t.to_string()
        }
    }

    /// Is `shell` permitted by this policy? An empty list allows everything
    /// the host itself supports. Callers pass an already-resolved name (see
    /// [`Self::resolve_shell`]) — never a bare `""`.
    pub fn allows_shell(&self, shell: &str) -> bool {
        self.shells.is_empty() || self.shells.iter().any(|s| s.eq_ignore_ascii_case(shell))
    }
}

/// FR-93 P2b — a Linux device's desktop, as its daemon sees it. A CLAIM by
/// the device, counted by the server, never enforced on. Strings, not enums,
/// for the additive-wire reason: a newer agent's arm or session class must
/// reach an older server as a word it can count, not a parse failure.
///
/// `capture_arm` is the arm a session opened now would try first, in the
/// cascade's own order. The arm a session actually used rides that
/// session's `rc:video-info`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DesktopBrief {
    /// logind's class for the session a controller would see: `user` ·
    /// `greeter` · `lock-screen` · …, or `none` (nobody at a seat).
    pub session: String,
    /// `wayland` · `x11` · `tty` · `none`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The session's desktop as logind names it (`gnome`, `KDE`, …), when it
    /// names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desktop: Option<String>,
    /// `mutter` · `drm` · `portal` · `x11` · `none` (nothing would capture: a
    /// Wayland desktop with no arm switched on, or no desktop at all).
    pub capture_arm: String,
    /// `full` · `xwayland_only` · `none`: how far a controller's input would
    /// reach (the `rc:input-reach` words).
    pub input_reach: String,
}

/// FR-92 P5b — what a device says about its keep busy, on every heartbeat.
///
/// A CLAIM by the device, like `ssh_activity`: shown to the org (which
/// devices are being kept awake, and by whom), never enforced on — the
/// device's own engine and gates are the enforcement. Strings, not enums,
/// for the usual additive-wire reason: a newer agent's phase or reason must
/// reach an older dashboard as a word it can print, not a parse failure.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct KeepBusyBrief {
    pub on: bool,
    /// `off` · `calibrating` · `running` · `paused` · `locked` · `unavailable`.
    pub phase: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// While on: the pattern drawn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// While on: the controller who turned it on, by display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_by: Option<String>,
}

/// FR-92 P8 — the keep-busy patterns, by their exact wire names, as the
/// agent spells them (`agents/roomlerd/src/keep_busy/patterns.rs`
/// `Pattern::wire`) and the viewer lists them
/// (`ui/src/composables/keepBusy.ts` `KEEP_BUSY_PATTERNS`). The org's
/// default pattern is validated against this list by EQUALITY — never a
/// prefix or a case-fold — because the word travels to the agent verbatim
/// and an agent matches it by equality too.
///
/// ⚠️ Three copies, one spelling. A pattern added on the agent is not
/// selectable as an org default until it is added here as well.
pub const KEEP_BUSY_PATTERNS: &[&str] = &[
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

/// The product's default keep-busy pattern, what an org gets until it
/// chooses another (operator, 2026-10-10: circle, as originally asked for).
pub const KEEP_BUSY_DEFAULT_PATTERN: &str = "circle";

/// FR-92 P7 — what one [`KeepBusyEvent`] records.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeepBusyEventKind {
    /// Keep busy came on on a device (`pattern` and `actor_name` say which
    /// pattern and who, as the device reported them).
    On,
    /// Keep busy went off on a device (`reason` is the device's code).
    Off,
    /// The org denied keep busy.
    OrgDenied,
    /// The org allowed keep busy again.
    OrgAllowed,
    /// The org's default pattern changed (`pattern`; absent = cleared back
    /// to the product default).
    OrgDefaultPattern,
}

/// FR-92 P7 — who is speaking in a [`KeepBusyEvent`]. The same trust split
/// as `ssh_audit` vs `ssh_activity`, inside ONE collection, so a reader can
/// never mistake one for the other.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeepBusyEventSource {
    /// The server's OWN decision — an admin changed the org's policy through
    /// an authenticated route. Authoritative.
    Server,
    /// A CLAIM reported by a device on its heartbeat (derived from two
    /// consecutive briefs). A compromised host can say anything here; it is
    /// shown as the device's word, never enforced on.
    Device,
}

/// FR-92 P7 — one keep-busy transition, kept for good (`keep_busy_events`).
///
/// **Permanent — there is deliberately no TTL** (operator, 2026-10-11:
/// "permanent history"), unlike every other audit collection in this file.
/// Rows outlive the device: `agent_name` is denormalised at write time so a
/// removed device still reads by name.
///
/// Two sources share the collection (see [`KeepBusyEventSource`]):
/// - the server writes `org_*` rows itself, from the settings route, only
///   when a value actually changed, naming the acting admin;
/// - device rows are DERIVED on the heartbeat path from the previous stored
///   brief against the new one, so their resolution is the heartbeat cadence
///   (~30 s): an on and an off inside one beat are not seen at all.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeepBusyEvent {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    /// The device, for a device-sourced row. `None` for an org-level event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<ObjectId>,
    /// The device's display label when the row was written. Denormalised:
    /// the row must still read after the device is removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    pub at: DateTime,
    pub kind: KeepBusyEventKind,
    pub source: KeepBusyEventSource,
    /// Server rows: the admin who changed it. Device rows: never set — a
    /// device reports a display name, not an identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_user_id: Option<ObjectId>,
    /// Server rows: the admin's display name at the time. Device rows: the
    /// brief's `set_by` claim, verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_name: Option<String>,
    /// `on`: the pattern the device drew. `org_default_pattern`: the new
    /// default (`None` = cleared to the product default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// `off`: the device's reason code (`stopped_by_controller`, `expired`,
    /// `org_denied`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl KeepBusyEvent {
    pub const COLLECTION: &'static str = "keep_busy_events";
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Agent {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    /// The user who "owns" this device — consent for a non-self controller can
    /// route to them (email/push), and a controller equal to the owner
    /// self-controls (no external allowlist needed). Set to `enrolled_by` at
    /// enrollment; reassignable by a `MANAGE_AGENTS` admin.
    pub owner_user_id: ObjectId,
    /// The user whose enrollment token created this agent (audit; the initial
    /// `owner_user_id`). `#[serde(default)]` → older rows deserialize to `None`.
    #[serde(default)]
    pub enrolled_by: Option<ObjectId>,
    pub name: String,
    /// Friendly label an admin sets purely for display. Never propagates —
    /// `name` is what the overlay/MagicDNS label derives from. `None` = the
    /// UI shows `name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Free-form admin labels for fleet filtering/search.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// True once an admin renamed this device. `rehydrate` (re-enroll) then
    /// stops overwriting `name` with the machine-reported one — without this
    /// flag the next re-enroll silently reverted every admin rename.
    #[serde(default)]
    pub name_admin_set: bool,
    pub machine_id: String,
    /// FR-51 — this device declared AT ENROLLMENT that it is temporary: the
    /// reaper may remove it (row, overlay lease, address, MagicDNS name) once
    /// it has been silent past its TTL, and removal is a HARD delete — an
    /// ephemeral row must not tombstone, because the `(tenant_id, machine_id)`
    /// unique index is not partial on `deleted_at`, so a tombstone would
    /// reserve its (random, never-reused) machine_id forever.
    ///
    /// Set only from the enrollment credential (FR-51 P2), never from the
    /// enrollment request body and never editable afterwards: a device that
    /// could declare itself permanent would evade the reaper, and a permanent
    /// device that could be flipped ephemeral would be scheduled for silent
    /// deletion. `#[serde(default)]` → every pre-FR-51 row deserialises to
    /// permanent, so enabling the reaper can never touch an existing fleet.
    #[serde(default)]
    pub ephemeral: bool,
    /// FR-51 — per-device inactivity deadline override, in seconds. `None` =
    /// the server default (`rc.ephemeral_default_ttl_secs`). Clamped to the
    /// 60 s floor at READ time by the reaper, not at write time, so a bad
    /// stored value can never disable the clamp. Meaningless (and absent)
    /// on a permanent row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ephemeral_ttl_secs: Option<u64>,
    /// FR-51 P2 — the [`EnrollmentKey`] this device was minted by, when it
    /// was. Half of the "which key created this device" chain; the half that
    /// survives the reap is the [`EnrollmentKeyUse`] row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enroll_key_id: Option<ObjectId>,
    pub os: OsKind,
    /// FR-97 P0d — the machine's native CPU architecture from its last hello
    /// that reported one (`x86_64`, `aarch64`, …). `None` until a device on
    /// an agent with the field connects; a hello without it leaves this alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// FR-97 P0d — the agent binary runs under emulation on that hardware.
    #[serde(default)]
    pub arch_emulated: bool,
    pub agent_version: String,
    /// FR-27 — the version of the `roomler-desktop` companion INSTALLED on this
    /// host, reported on the heartbeat. `None` means one of three different
    /// things and the grid must not flatten them: a pre-FR-27 agent that never
    /// reports the field, a host with no companion installed, or a probe that
    /// could not read one.
    ///
    /// It exists because the daemon and the companion update through DIFFERENT
    /// mechanisms on every platform — Windows: the daemon side-loads the EXE
    /// (`companion::refresh_if_stale`), macOS: the `.pkg` carries
    /// `/Applications/Roomler.app`, Linux: a separate `roomler-desktop` .deb
    /// that apt owns — so "Update all" moving the daemon says nothing about the
    /// companion, and until now nothing on screen could tell you it had been
    /// left behind. That was the operator's report, not a hypothetical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub companion_version: Option<String>,
    /// FR-92 P5b — keep busy as the device last reported it on a heartbeat.
    /// `None` = it does not say: a device without keep busy, one that
    /// predates the field, or a supervised Mac's root daemon, which cannot
    /// speak for the GUI worker that runs it. So "unknown", never "off".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_busy: Option<KeepBusyBrief>,
    /// P6 — OpenSSH public half of the device's SSH host key, as reported on
    /// its last hello. Published so a caller can verify what it dialled
    /// instead of trusting it on first use.
    ///
    /// Empty = the device stores no host key (never SSH-enabled, or a build
    /// without `ssh-server`), which is NOT "any key is acceptable" — it means
    /// the device cannot prove itself, and a client that cares should refuse.
    ///
    /// ⚠️ The converse does NOT hold. `ssh_host_key` stays in the config after
    /// SSH is switched back off, so a NON-empty value here does not mean the
    /// device is accepting sessions (field-checked: fleet-host-1, `ssh_enabled =
    /// false`, still publishing its P4a key). Whether a session can be opened
    /// is the gate chain's answer, never this field's.
    /// Refreshed from every hello rather than written once, so rotating the
    /// key on the device is enough to move the fleet view with it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ssh_host_pubkey: String,
    /// FR-90 P3-3a — the public half of the vault key the device's daemon
    /// holds now, as its last hello reported it (standard base64 of 32 bytes,
    /// [`crate::signaling::vault_key_is_well_formed`]): what the vault seals
    /// a leased value to.
    ///
    /// Written on EVERY hello, the empty string included, so it never outlives
    /// the process that made it: the daemon makes a new key at each start and
    /// keeps it in memory only. Empty = the device takes no leases (its
    /// `vault_enabled` is off, a build without the `vault` feature, an agent
    /// before P3-3a, or a hello whose key was not well formed).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vault_key: String,
    /// FR-100 P1a — the public half of this enrollment's device key, as its
    /// last hello reported it ([`crate::signaling::peer_auth_key_is_well_formed`]).
    /// A HINT for a browser's first pin, never an authority: the browser
    /// pins the key that signed what it received, and a change is the
    /// browser's to flag, not the server's to approve
    /// (`docs/fr/FR-100-controller-identity.md` §3e).
    ///
    /// Written on EVERY hello, the empty string included, as
    /// `ssh_host_pubkey` is: a device rolled back to a build that predates
    /// the key no longer signs with it, and a key left standing here would
    /// have browsers expecting a signature that never comes. Empty = the
    /// device cannot prove who it is.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub peer_auth_key: String,
    pub agent_token_hash: String,
    /// FR-103: the token generation. An agent token is accepted only while
    /// its `gen` claim equals this. Removing the device bumps it
    /// (`AgentDao::soft_delete`), so every token minted before the removal
    /// is refused, even after the same machine re-enrolls and revives this
    /// row. Enrollment and renewal mint at the current value. 0 on every row
    /// that was never removed, which is also what every pre-FR-103 token
    /// carries.
    #[serde(default)]
    pub token_gen: u32,
    /// FR-103: the `exp` of the agent token this device last connected with,
    /// stamped at each socket connect. What the device list shows as "the
    /// credential expires", so a device nearing its anniversary can be found
    /// before it drops. `None` on rows that have not connected since FR-103.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_exp: Option<DateTime>,
    pub status: AgentStatus,
    pub last_seen_at: DateTime,
    /// P4 — the presence value (`online`/`stale`/`offline`) most recently
    /// BROADCAST as a `device:presence` event. A cluster-wide transition
    /// ledger: every emit path (register, teardown, staleness sweep, on any
    /// pod) does a CAS on this field and fans out only when it actually
    /// changed, so a transition is announced exactly once no matter how many
    /// pods observe it. `None` on pre-P4 rows / fresh enrollments — the first
    /// observed state always emits. NOT the read-path truth (that stays the
    /// live hub + Redis directory + heartbeat derivation).
    #[serde(default)]
    pub last_presence: Option<String>,
    /// C4 stage 2 — the agent's standing warm TURN allocation's relayed
    /// transport address (`worker-ip:port`), refreshed by every heartbeat
    /// while a leg is live and `$unset` while none is. Stored PAIR-LESS so
    /// a peer whose pair to this agent died can be handed a dial target
    /// without a coordination round-trip through this agent's (possibly
    /// captured) control WS. `None` on pre-stage-2 rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warm_relay_endpoint: Option<String>,
    #[serde(default)]
    pub displays: Vec<DisplayInfo>,
    #[serde(default)]
    pub capabilities: AgentCaps,
    #[serde(default)]
    pub access_policy: AccessPolicy,
    /// Fleet-RPC policy for this device (gate 3). `#[serde(default)]` → every
    /// pre-feature row deserialises to [`ExecMode::Off`].
    #[serde(default)]
    pub exec_policy: ExecPolicy,
    /// FR-94 — an administrator anchored this Windows device, so its SYSTEM
    /// service holds a credential of its own (`POST /api/agent/anchor`). Who
    /// and when. The credential itself is never stored. `None` on every
    /// unanchored device and every pre-FR-94 row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_anchor: Option<ExecAnchor>,
    /// FR-105 — the SSH endpoint this device's SYSTEM service published, if
    /// any. Only routes while it names the CURRENT `exec_anchor`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_service: Option<SshServiceEndpoint>,
    /// FR-104 — the `jti` of the enrollment token that last enrolled or
    /// revived this row. A token minted with `anchor: true` may also anchor
    /// the device it enrolled, once: this is how the anchor route knows which
    /// device that is. An id, never the token. `None` on every row enrolled
    /// before FR-104, and on an ephemeral one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrolled_with_jti: Option<String>,
    /// FR-102 P3 — how this device was installed, as its enroll said
    /// (`{method, scope, run}`, the spellings of [`InstallMethod`] and
    /// [`InstallScope`]). Written at every enrollment that creates the row
    /// (`{method: "unknown"}` when the request did not say — an agent from
    /// before P3) and refreshed by a re-enrollment only when that request
    /// says. `None` = the row was created before P3; the digest reads both
    /// `None` and `unknown` as *unknown*.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install: Option<InstallInfo>,
    /// Roomler-SSH policy for this device (gate 3). Same shape and the same
    /// closed default as [`Self::exec_policy`] — every pre-feature row
    /// deserialises to [`SshMode::Off`].
    #[serde(default)]
    pub ssh_policy: SshPolicy,
    /// FR-19 gate 3 — org-relay approval for this device. Same closed default
    /// as the two above: every pre-FR-19 row deserialises to "not approved".
    #[serde(default)]
    pub peer_relay_policy: PeerRelayPolicy,
    /// FR-52 gate 2 — approval for control by someone OUTSIDE this org. Same
    /// closed default as the three above.
    #[serde(default)]
    pub external_access_policy: ExternalAccessPolicy,
    /// FR-52 — the dictatable handle an outsider names this device by
    /// (`crate::connect_code`). Canonical form: 12 Crockford base32
    /// characters, no dashes.
    ///
    /// `None` — every pre-FR-52 row, and every device nobody has minted one
    /// for — means the device is simply unaddressable from outside, which is
    /// the correct default: a code is minted on demand, not at enrollment, so
    /// enabling the feature writes nothing to a fleet that is not using it.
    ///
    /// ⚠️ NOT a secret and NOT a credential — gate 4 (the device-held
    /// password) is what stops a stranger, and gate 2 is what lets them try.
    /// What the code's 60 bits buy is that the fleet cannot be ENUMERATED.
    /// It is nonetheless not published to ordinary members: `AgentResponse`
    /// deliberately omits it, because `list_agents` requires only tenant
    /// membership and handing every member a working address for every device
    /// is a wider audience than the admin who is supposed to be handing it out.
    ///
    /// ⚠️ Globally unique across tenants — an outsider types a code with no
    /// org context, so it has to resolve on its own — and its unique index is
    /// NOT scoped to live rows. A tombstone keeps its code reserved forever,
    /// on purpose: recycling one would silently point a stranger who still has
    /// the old note at a DIFFERENT machine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_code: Option<String>,
    /// When [`Self::connect_code`] was last minted or rotated. Rotation is the
    /// revocation story for a leaked code, so "since when has this code been
    /// the valid one?" has to be answerable from the row as well as the audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_code_rotated_at: Option<DateTime>,
    /// Device config an operator has ASKED for, reconciled by the agent when
    /// it next connects (`docs/remote-config.md` step 2).
    ///
    /// Desired state, not applied state: writing here records an intent, and
    /// the device remains free to refuse it — a device without
    /// `remote_config_enabled` ignores this entirely, which is the property
    /// that keeps `exec_enabled`/`ssh_enabled` refusable by a compromised
    /// server. Never read this to decide whether a device HAS exec or SSH on;
    /// the device's own heartbeat is the only truth for that.
    ///
    /// `#[serde(default)]` → every pre-feature row deserialises to "nothing
    /// requested", which is also what an operator clearing the form leaves.
    #[serde(default)]
    pub desired_config: DesiredConfig,
    /// What the DEVICE last said it did with [`Self::desired_config`].
    ///
    /// `None` = it has never reported. That is three different situations —
    /// it has not connected since the push, its agent predates
    /// [`RpcCap::ConfigReport`], or nothing has ever been pushed — and the
    /// reader must resolve which from the capability list and the revision,
    /// never assume the last one.
    ///
    /// ⚠️ Read this ALONGSIDE [`Self::desired_config`], never instead of it:
    /// a report whose `revision` is behind the desired one is a device that
    /// has not caught up, which reads on a dashboard exactly like a device
    /// that refused unless the two numbers are compared.
    #[serde(default)]
    pub config_report: Option<ConfigReport>,
    /// FR-40 — the standing request that this device retire its overlay key.
    /// Desired state, exactly like [`Self::desired_config`]: it lives on the
    /// row so a device that is offline rotates on its next connect through
    /// the same reconcile path as one that was online when the admin clicked.
    #[serde(default)]
    pub key_rotation: Option<KeyRotationRequest>,
    /// What the DEVICE last said it did with a rotation order. A claim by the
    /// device, in the [`Self::config_report`] sense — read it against
    /// [`Self::key_rotation`] by `request_id`, never alone.
    #[serde(default)]
    pub key_rotation_report: Option<KeyRotationReport>,
    /// FR-40 — what the device last PRESENTED at its overlay join, stamped by
    /// the server from the join frame it verified. This is the half of a
    /// rotation the control plane can actually vouch for: a report says
    /// "I rotated", the identity says "and here is the key it joined with".
    #[serde(default)]
    pub overlay_identity: Option<OverlayIdentity>,
    /// Subnet-router CIDRs this agent is a gateway for (Phase 2). The SOCKS
    /// mesh longest-prefix-matches a LAN-IP target against these to pick the
    /// covering agent, which then dials the real IP (still gated by the
    /// tenant's `tunnel_policies`). Admin-configured. `#[serde(default)]` →
    /// older rows deserialize to no routes.
    #[serde(default)]
    pub routes: Vec<String>,
    /// Subnet CIDRs the AGENT itself advertises it can route (from its
    /// `advertise_routes` config, refreshed on each `rc:agent.hello`). These
    /// are untrusted SUGGESTIONS — an admin approves a subset into `routes`
    /// (what the mesh actually consumes). `#[serde(default)]` → older rows /
    /// pre-feature agents deserialize to none.
    #[serde(default)]
    pub advertised_routes: Vec<String>,
    /// Multi-region relay PoPs: the agent's nearest relay region (a
    /// `relay_regions` id), derived server-side from its STUN probe reports
    /// with hysteresis. `None` = never probed / all probes timed out — every
    /// issuance path then uses the default region. `#[serde(default)]` →
    /// older rows deserialize to `None`.
    #[serde(default)]
    pub relay_home: Option<String>,
    /// The agent's last full probe table (observability; the UI shows it on
    /// the device detail). `#[serde(default)]` → older rows deserialize to
    /// `None`.
    #[serde(default)]
    pub relay_rtt: Option<Vec<crate::signaling::RelayRegionRtt>>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
    pub deleted_at: Option<DateTime>,
}

impl Agent {
    pub const COLLECTION: &'static str = "agents";
}

// ────────────────────────────────────────────────────────────────────────────
// FR-51 P2 — ephemeral enrollment keys
// ────────────────────────────────────────────────────────────────────────────

/// A REUSABLE enrollment credential that mints EPHEMERAL devices (FR-51 §4).
///
/// The single-use `enroll-token` is deliberately unusable for autoscaling
/// (ten minutes, once, minted by a human), so this is a second credential
/// kind with an explicitly different risk profile: a standing secret that
/// creates device identities inside an org for as long as it lives. The four
/// controls that make that acceptable are ALL FOUR structural here — a use
/// ceiling (`max_uses`, claimed atomically), an absolute expiry
/// (`expires_at`, enforced on the row as well as in the JWT), revocability
/// (`revoked_at`, checked inside the same atomic claim — expiry alone would
/// mean a leaked key can only be waited out, never stopped), and a per-use
/// audit row ([`EnrollmentKeyUse`]).
///
/// The ephemeral property RIDES THIS CREDENTIAL, never the enrollment
/// request body: a device that could declare itself would either evade the
/// reaper or schedule a permanent device for silent deletion.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EnrollmentKey {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    /// The JWT's `jti`, and the value the use-claim is keyed by. Unique.
    pub jti: String,
    /// Operator label ("ci-runners", "preview-envs"), display only.
    pub label: String,
    /// Admin who minted it — every device it creates records this chain:
    /// key → `created_by`, device → `enroll_key_id`.
    pub created_by: ObjectId,
    /// Use ceiling. `uses` is `$inc`'d inside the same atomic
    /// `find_one_and_update` that checks it, so N racing enrollments can
    /// never mint more than `max_uses` devices between them.
    pub max_uses: i64,
    pub uses: i64,
    pub expires_at: DateTime,
    /// Set = the key is dead, whatever its expiry says. Checked inside the
    /// atomic claim, so revocation takes effect on the very next use.
    pub revoked_at: Option<DateTime>,
    /// Per-device reap TTL this key stamps onto every device it mints
    /// (`Agent::ephemeral_ttl_secs`). `None` = the server default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ephemeral_ttl_secs: Option<u64>,
    #[serde(default)]
    pub last_used_at: Option<DateTime>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

impl EnrollmentKey {
    pub const COLLECTION: &'static str = "enrollment_keys";
}

/// One successful use of an [`EnrollmentKey`] — control 4 of FR-51 §4:
/// "which key created this device" stays answerable AFTER the device row is
/// reaped (ephemeral rows hard-delete, so the device row cannot be the
/// audit trail). 90-day TTL like the other audit collections.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EnrollmentKeyUse {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    pub key_id: ObjectId,
    pub agent_id: ObjectId,
    pub machine_id: String,
    pub machine_name: String,
    pub created_at: DateTime,
    /// P4 — when the device this use minted was REMOVED, making the row the
    /// device's whole lifecycle record (born → removed) in one place that
    /// survives both ends: the device row hard-deletes, and `audit_logs` is
    /// a dead collection nothing writes (checked before "the reap in
    /// audit_logs" was implemented as spec'd — recording into a surface
    /// nothing reads would be paperwork, not audit). `None` = still alive,
    /// or removed before P4 shipped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_at: Option<DateTime>,
    /// P4 — which path removed it: `ephemeral_expired` (the reaper) /
    /// `ephemeral_self_unenroll` (clean stop) / `agent_delete` (admin).
    /// The same `reason` string every removal path already threads through
    /// `release_overlay_node`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removal: Option<String>,
}

impl EnrollmentKeyUse {
    pub const COLLECTION: &'static str = "enrollment_key_uses";
}

// ────────────────────────────────────────────────────────────────────────────
// Roomler SSH
// ────────────────────────────────────────────────────────────────────────────

/// Bounds on a roomler-SSH session grant. The server clamps before minting;
/// the agent re-clamps on receipt, so a forged or replayed grant cannot ask for
/// a longer-lived session than policy allows.
pub mod ssh_limits {
    /// How long a minted grant stays usable before the target discards it.
    ///
    /// Short on purpose: the grant is consumed by a TCP connection the caller
    /// makes immediately after receiving it, so this only has to cover
    /// signalling latency plus a slow WireGuard handshake. A grant that
    /// lingered would be a standing key to the device.
    pub const GRANT_TTL_SECS: u64 = 60;
    /// FR-83 — how long the server holds the CALLER while it waits for the
    /// target to confirm a grant (`rc:ssh.grant_ack`). No confirmation in
    /// time ⇒ the request is refused as unconfirmed, never answered with an
    /// address the device may not honour.
    ///
    /// Sized from the field, not guessed: the slowest grant delivery measured
    /// (#1597, a corp laptop on DERP behind a TLS-inspecting middlebox) was
    /// 4.4 s, so this is twice that. It must also stay well inside the
    /// originating device's own 30 s wait for `rc:ssh.response`, so the caller
    /// hears the server's reason rather than its own timeout, and leave most
    /// of [`GRANT_TTL_SECS`] to dial in once confirmed.
    pub const GRANT_ACK_TIMEOUT_SECS: u64 = 10;
    /// Hard ceiling on a session's lifetime, after which the agent closes it.
    /// Twelve hours is long enough for a working day and short enough that a
    /// forgotten terminal does not stay open for a week.
    pub const MAX_SESSION_SECS: u64 = 12 * 3600;
    /// Concurrent SSH sessions one device will serve. Beyond this the agent
    /// refuses rather than queues.
    pub const MAX_CONCURRENT_PER_AGENT: usize = 8;
    /// Grants per minute per (caller, device) pair.
    pub const RATE_LIMIT_PER_MINUTE: u32 = 20;
    /// FR-105 — the overlay port a Windows device's SYSTEM service answers
    /// SSH on. The worker intercepts it beside its own (2222) and splices it,
    /// still encrypted, into the service's pipe. One fixed port rather than a
    /// device setting, because the server, not the device, tells the caller
    /// where to dial, and it can only say what it knows.
    pub const SERVICE_PORT: u16 = 2223;

    /// Clamp a caller-supplied session budget into range, substituting the
    /// ceiling for `None`/0.
    pub fn clamp_session_secs(requested: u64) -> u64 {
        match requested {
            0 => MAX_SESSION_SECS,
            n => n.min(MAX_SESSION_SECS),
        }
    }
}

/// Whether a device accepts roomler-SSH sessions at all.
///
/// Default `Off` — every existing row deserialises to it, so enabling the
/// feature can never retroactively open a device.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SshMode {
    /// Refuse every SSH grant request. The default.
    #[default]
    Off,
    /// Accept grants for callers that clear every other gate.
    On,
}

/// Which local account an SSH session runs as.
///
/// Windows has no password-free way to become an arbitrary local user, so the
/// choices are deliberately the two the daemon can actually reach: its own
/// identity, or the token of whoever is signed in at the console (which the
/// SystemContext machinery already obtains for the lock-screen path). Naming a
/// specific Unix account is the third, and is Unix-only by construction.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SshAccountMode {
    /// The daemon's own identity — SYSTEM on Windows, root under systemd.
    ///
    /// The default *today* because it is what P2 can actually do, and it is
    /// why `SshMode::On` is root-equivalent until the P5 privilege-drop slice
    /// lands. It is not the right long-term default and the admin UI says so.
    #[default]
    Daemon,
    /// The user signed in at the console, via their session token. No password
    /// required, and the session cannot outlive their sign-in.
    ConsoleUser,
    /// A named local account (Unix only; requires the P5 privilege drop).
    Named,
}

impl SshAccountMode {
    /// FR-90 P3-8-1a — the word for each mode, as serde spells it: what
    /// `rc:ssh.grant` carries, and what the vault's `ssh:run` reads as
    /// `context.account` and its ticket names. ⚠️ A compatibility surface,
    /// locked by test against serde's own spelling.
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Daemon => "daemon",
            Self::ConsoleUser => "console_user",
            Self::Named => "named",
        }
    }

    pub const ALL: [SshAccountMode; 3] = [Self::Daemon, Self::ConsoleUser, Self::Named];

    /// Parse a mode's word. `None` for a word this build cannot name.
    pub fn from_wire(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.wire() == s)
    }
}

/// FR-105 — how far an anchored Windows device's SYSTEM service will go with
/// roomler SSH. Set on the device, elevated (`roomlerd anchor ssh <…>`), in
/// the anchor file only SYSTEM and Administrators can write, and published by
/// the service with its own credential. Default `off`: an exec anchor never
/// silently gains SYSTEM SSH.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SshServiceCeiling {
    /// The service serves no SSH; grants go to the worker as before.
    #[default]
    Off,
    /// Sessions as the signed-in user only (`console_user`).
    ConsoleUser,
    /// SYSTEM in session 0 (`daemon`) as well as the signed-in user.
    System,
}

impl SshServiceCeiling {
    /// Does this ceiling allow a session as `mode`? A named account is never
    /// the service's (Unix only, and outside FR-105).
    pub fn permits(self, mode: SshAccountMode) -> bool {
        matches!(
            (self, mode),
            (
                Self::System,
                SshAccountMode::Daemon | SshAccountMode::ConsoleUser
            ) | (Self::ConsoleUser, SshAccountMode::ConsoleUser)
        )
    }
}

/// FR-105 — what a Windows device's SYSTEM service published about its own
/// SSH endpoint (`PUT /api/agent/service/ssh-host-key`, with the service's
/// credential, never the worker's).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SshServiceEndpoint {
    /// The OpenSSH public half of the SERVICE's host key, which a caller
    /// dialling the service port pins. The worker's own key is a different
    /// one, in a file the signed-in user can write; it never stands in.
    pub host_pubkey: String,
    pub ceiling: SshServiceCeiling,
    /// The anchor the publishing credential named. A re-anchor or an
    /// un-anchor makes this record stale without anyone deleting it: routing
    /// requires it to name the device's CURRENT anchor.
    pub anchor_id: String,
    pub published_at: DateTime,
    /// FR-90 P3-8-2a — the service said it holds an agent session's grant to
    /// one command. Only then is such a grant routed to it: the worker's
    /// `ssh-one-command` speaks for the worker's own server, never for a
    /// service that may be older. Absent (false) in every record published
    /// before it.
    #[serde(default)]
    pub one_command: bool,
}

/// Device config an operator has requested, for the agent to reconcile
/// (`docs/remote-config.md`).
///
/// Every field is `Option`, and the distinction is load-bearing: `None` means
/// **not managed** — the device keeps whatever it has locally — while `Some`
/// means "this is what it should be". A struct of plain values could not say
/// "leave the rest alone", so an operator toggling exec would silently assert a
/// value for every other key on the surface.
///
/// ⚠️ `remote_config_enabled` is deliberately ABSENT and must never be added.
/// It is the device's opt-in to accepting anything here at all; a server able
/// to set it could opt a device in and then open every other key, which is the
/// one move the whole design exists to prevent.
///
/// ⚠️ `ssh_max_privilege` (M5) is ABSENT for the same reason. It is the
/// device's ceiling on what a SERVER GRANT may run as — the one SSH gate that
/// still holds when the server is the compromised thing — so a server able to
/// set it could raise its own ceiling and the setting would mean nothing. This
/// list is an allowlist, so leaving it out is sufficient; the trap is a later
/// change that adds "the rest of the ssh_* surface" for symmetry.
///
/// ⚠️ `ssh_exec_streaming` (FR-89 D5) is ABSENT, and it is exactly that trap.
/// It grants nothing — it only chooses whether a one-shot command's output
/// streams or buffers — but it is the owner's kill switch for that data path,
/// and a server able to set it could turn streaming back on under an owner
/// who switched it off. "It is only a performance knob" is how the symmetry
/// argument gets made. It is device-local like `ssh_max_privilege`; this is
/// NOT the status of `exec_enabled` and `ssh_enabled`, which are fields
/// below, settable behind the device's `remote_config_enabled`.
///
/// ⚠️ `local_restart_enabled` (FR-84 D3) is ABSENT, and so is any notion of
/// "restart after applying". The daemon restarts itself only when a LOCAL
/// client asks over the LocalAPI; a server that could trigger it would hold
/// every device's uptime on a button, and a push that restarted daemons would
/// take down exactly the orphan `roomlerd run` hosts that cannot come back
/// (docs/remote-config.md §7b).
///
/// ⚠️ **The whole `relay_*` surface (FR-19) is ABSENT**, and unlike the two
/// above this is enforced by a test that matches on the PREFIX rather than on
/// a name. `relay_server_enabled` is gate 4 — the refusal that survives a
/// compromised server — and `relay_server_port` is just as load-bearing: a
/// server able to move the port could point the listener somewhere the
/// operator never opened, or away from one they did. The prefix rule exists
/// because the feature will grow more keys (`relay_max_sessions`,
/// `relay_static_endpoints`), and a per-name test would silently fail to cover
/// the one someone adds later.
///
/// ⚠️ **The whole `external_*` surface (FR-52) is ABSENT**, under the same
/// prefix rule and for the sharpest version of the same reason. Gate 3
/// (`external_access_enabled`) is the device owner's opt-in to being reachable
/// by someone *outside the org*, and gate 4 is the password the device holds
/// and this server never sees. A server able to push either could admit a
/// stranger to a machine whose owner never agreed — the whole point of FR-52
/// is that it cannot. The surface will grow (`external_access_verifier`,
/// `external_consent_mode`, `external_max_permissions`), which is exactly why
/// the guard matches the prefix rather than today's one name.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct DesiredConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_authorized_keys: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_account_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_port: Option<u16>,
    /// FR-77 P3 — the encoder-cell denylist (`encoder_cells_deny`): the kill
    /// switch of the cell matrix, comma-separated `name:chroma` entries or
    /// `none`. Pushable because it is NOT a security gate — it only ever
    /// REMOVES cells a device would otherwise open — so `MANAGE_AGENTS` is
    /// enough. Applied at the next daemon start (the probe runs once per
    /// process), which the device reports as `needs_restart`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoder_cells_deny: Option<String>,
    /// FR-119 P2b — the frame-rate denylist (`fps_deny`): comma-separated
    /// `name:fps` entries, `*` for every encoder. Pushable for the same reason
    /// as `encoder_cells_deny`: it only ever REMOVES rates a device would
    /// otherwise grant, so `MANAGE_AGENTS` is enough. The daemon reads it once
    /// per process, which the device reports as `needs_restart`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fps_deny: Option<String>,
    /// Bumped on every write. The agent reports the revision it has applied,
    /// so "asked for" and "actually running" can be told apart in the UI —
    /// without it, a device that refused the config and one that never heard
    /// about it look identical.
    #[serde(default)]
    pub revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<ObjectId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime>,
}

impl DesiredConfig {
    /// Whether anything is actually requested. A cleared form is `revision`
    /// plus provenance and no keys — still "nothing to reconcile".
    pub fn is_empty(&self) -> bool {
        self.exec_enabled.is_none()
            && self.ssh_enabled.is_none()
            && self.ssh_authorized_keys.is_none()
            && self.ssh_account_mode.is_none()
            && self.ssh_port.is_none()
            && self.encoder_cells_deny.is_none()
            && self.fps_deny.is_none()
    }

    /// Whether this request touches the Fleet-RPC grant. Drives the
    /// `EXEC_DEVICE` requirement — see `remote_config::decide`.
    pub fn touches_exec(&self) -> bool {
        self.exec_enabled.is_some()
    }

    /// Whether this request touches the SSH grant. Every `ssh_*` key counts,
    /// not just `ssh_enabled`: authorized keys decide WHO may connect, and
    /// `ssh_account_mode` decides what a key-list session may run — handing
    /// those out is granting SSH just as much as flipping the switch is.
    pub fn touches_ssh(&self) -> bool {
        self.ssh_enabled.is_some()
            || self.ssh_authorized_keys.is_some()
            || self.ssh_account_mode.is_some()
            || self.ssh_port.is_some()
    }

    /// Does this request ask for the same exec state as `other`?
    ///
    /// Used to tell "granting exec" from "leaving the exec ask exactly as some
    /// other admin already set it" — see `remote_config::decide`.
    pub fn same_exec_as(&self, other: &Self) -> bool {
        self.exec_enabled == other.exec_enabled
    }

    /// [`Self::same_exec_as`] for the SSH family.
    ///
    /// Destructured EXHAUSTIVELY: a new key added to this struct must be
    /// classified as exec, SSH, or neither before this compiles. A key that
    /// silently fell outside both comparisons would let an unchanged-request
    /// carve-out pass a change nobody checked.
    pub fn same_ssh_as(&self, other: &Self) -> bool {
        let Self {
            exec_enabled: _,
            ssh_enabled,
            ssh_authorized_keys,
            ssh_account_mode,
            ssh_port,
            // FR-77 P3 — neither exec nor SSH: the cell denylist only removes
            // encoder cells and needs MANAGE_AGENTS alone (see `remote_config::decide`).
            encoder_cells_deny: _,
            // FR-119 P2b — the same for the frame-rate denylist: it only removes.
            fps_deny: _,
            revision: _,
            updated_by: _,
            updated_at: _,
        } = self;
        *ssh_enabled == other.ssh_enabled
            && *ssh_authorized_keys == other.ssh_authorized_keys
            && *ssh_account_mode == other.ssh_account_mode
            && *ssh_port == other.ssh_port
    }
}

/// What a device did with a pushed [`DesiredConfig`].
///
/// ⚠️ Every arm except [`Self::Applied`] / [`Self::Noop`] is a REFUSAL, and the
/// refusals are the reason this type exists. Without them the dashboard cannot
/// tell a device that declined from one that never heard — the two look
/// identical, which is exactly the "a switch that silently does nothing" state
/// the whole feature is trying not to produce.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfigOutcome {
    /// Reconciled. Which keys are in force NOW and which are merely written
    /// down is in `live` / `needs_restart` — see [`ConfigReport`].
    Applied,
    /// The device already matched; nothing was written. Distinct from
    /// `Applied` with two empty lists so a reader can tell "converged" from
    /// "applied nothing, and I am not sure why".
    Noop,
    /// The device has not opted in: `remote_config_enabled` is off. This is
    /// gate 4 doing its job, not an error — the operator's move is to set the
    /// key ON THE HOST, which no server can do for them.
    NotOptedIn,
    /// The push arrived on a SECONDARY org's socket. `exec_enabled` / `ssh_*`
    /// are machine-wide, so only the primary enrollment may drive them; this
    /// org borrows the device and cannot reconfigure it.
    NotPrimary,
    /// The device tried and failed — see `detail`. Almost always an I/O or
    /// permission problem writing `config.toml`.
    Failed,
}

impl ConfigOutcome {
    /// Did the device actually reconcile? `false` for every refusal, which is
    /// what a caller usually wants to branch on.
    pub fn is_success(self) -> bool {
        matches!(self, Self::Applied | Self::Noop)
    }
}

/// The DEVICE's account of what it did with revision `revision`.
///
/// ⚠️ This is a CLAIM BY THE DEVICE, exactly like [`SshActivityEvent`] and
/// unlike anything in `config_audit`. The audit collection records the
/// SERVER's decision and is authoritative; this records what a host — which
/// may be compromised, may be lying, may simply be old — says happened
/// afterwards. Never fold the two together: a reader has to be able to tell
/// which is which, and only one of them survives a dishonest device.
///
/// ⚠️ An ABSENT report is not evidence of anything. A device that predates
/// [`RpcCap::ConfigReport`] applies the config perfectly well and never says
/// so, which is why the capability is checked before this is read as silence.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ConfigReport {
    /// Which `desired_config.revision` this is about. A report for an older
    /// revision than the row currently holds means the device has not caught
    /// up yet — not that the newer one was refused.
    pub revision: u64,
    pub outcome: ConfigOutcome,
    /// Keys changed and ALREADY in force.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub live: Vec<String>,
    /// Keys written to disk but waiting for a daemon restart.
    ///
    /// ⚠️ Kept SEPARATE from `live` all the way to the screen. Collapsing them
    /// would let the dashboard report SSH as on while the daemon has not
    /// re-spliced the packet path — the device would refuse every session
    /// while the UI insisted it was open.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub needs_restart: Vec<String>,
    /// Why, for [`ConfigOutcome::Failed`]. Capped — see [`Self::MAX_DETAIL`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// When the server received it. Server-stamped, never taken off the wire:
    /// a device's clock is not a fact the control plane should inherit.
    pub reported_at: DateTime,
}

impl ConfigReport {
    /// Bound on `detail`, applied on the device AND re-clamped on receipt — a
    /// limit that exists only on the reporting side is not a limit.
    pub const MAX_DETAIL: usize = 400;
}

/// FR-40 — an operator's standing request that a device retire its overlay
/// (WireGuard) key and mint a fresh one (`docs/fr/FR-40-overlay-key-rotation.md`).
///
/// Desired state on the agent row, so the offline case has somewhere to
/// live: the device is ordered on connect if this is present and unanswered.
/// ⚠️ Carries NO key material in either direction — the server orders a
/// re-mint it never sees; the only key that ever crosses the wire is the
/// PUBLIC half in the device's report. A test asserts the order frame has
/// no key-shaped field at all.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct KeyRotationRequest {
    /// Fresh per request. The device echoes it in its report, which is what
    /// lets a report about an EARLIER order be told apart from the answer to
    /// this one — compare ids, never outcomes alone.
    pub request_id: String,
    pub requested_by: ObjectId,
    pub requested_at: DateTime,
    /// When the order was actually pushed to a live socket. Absent = queued
    /// for the device's next connect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered_at: Option<DateTime>,
    /// P1c — the overlay PUBLIC key the device held when the order was placed
    /// (its [`OverlayIdentity`] at that moment; absent if it had never
    /// joined). The join under a DIFFERENT key is what proves the rotation:
    /// the device's report rides the session that is about to end and can be
    /// lost (second field run), and a report is only ever a claim anyway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_before: Option<String>,
}

/// How a device answered a rotation order. Every arm but [`Self::Rotated`] is
/// a refusal, and — as with [`ConfigOutcome`] — the refusals are the reason
/// the type exists: each has a different fix, and without them a device that
/// declined and one that never heard are the same thing on a screen.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyRotationOutcome {
    /// Minted, persisted, and the device is reconnecting under the new key.
    /// The join that follows is what proves it — see [`OverlayIdentity`].
    Rotated,
    /// The device's `overlay_key_rotation` kill switch is off.
    Disabled,
    /// A second order arrived inside the device's own 60 s ceiling.
    RateLimited,
    /// This build has no overlay surface, so it has no key to rotate.
    Unsupported,
    /// Mint or persist failed — see `detail`. The identity is UNCHANGED: a key
    /// that cannot be written down is not adopted, or the next restart would
    /// bring the retired one back.
    Failed,
}

impl KeyRotationOutcome {
    pub fn is_success(self) -> bool {
        matches!(self, Self::Rotated)
    }
}

/// The DEVICE's account of a rotation order — a claim, in the
/// [`ConfigReport`] sense, never the server's own record.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct KeyRotationReport {
    /// Echoed from the order.
    pub request_id: String,
    pub outcome: KeyRotationOutcome,
    /// Base64 WireGuard PUBLIC keys. Public by construction — the device
    /// never has a reason to send the secret half, and the server never
    /// stores one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_public_key: Option<String>,
    /// The epoch the device will present on its next join (bumped per
    /// rotation, persisted next to the key).
    #[serde(default)]
    pub key_epoch: u32,
    /// Why, for the refusals. Redacted and capped by the device; re-clamped
    /// on receipt (see [`Self::MAX_DETAIL`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Server-stamped, never taken off the wire.
    pub reported_at: DateTime,
}

impl KeyRotationReport {
    pub const MAX_DETAIL: usize = 400;
}

/// What a device last presented at its overlay join, as the server verified
/// it (`ws::overlay`). Stamped on every join, so it is also simply "this
/// device's current overlay public key" for the dashboard.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct OverlayIdentity {
    /// Base64 WireGuard public key.
    pub public_key: String,
    #[serde(default)]
    pub key_epoch: u32,
    pub joined_at: DateTime,
}

/// Per-device roomler-SSH policy — gate 3 of four, the exact shape of
/// [`ExecPolicy`] because the reasoning is identical and a reader who knows one
/// should recognise the other.
///
/// Deliberately NOT folded into [`ExecPolicy`]: "may run one clamped command"
/// and "may hold an interactive session" are different grants, and an operator
/// who enabled the first must not silently acquire the second.
///
/// ⚠️ With [`SshAccountMode::Daemon`] — the current default — `SshMode::On` is
/// root-equivalent by construction, exactly like `ExecMode::On`.
/// `PartialEq` for the same reason [`ExecPolicy`] carries it, and it matters
/// more here: the untouched default names [`SshAccountMode::Daemon`], so an
/// API that could not tell "never configured" from "explicitly all-defaults"
/// would hand the dialog a pre-selected root shell.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct SshPolicy {
    /// Does this device accept SSH sessions? Gate 3.
    #[serde(default)]
    pub mode: SshMode,
    /// May this device *originate* SSH against other devices (the
    /// `roomler ssh` CLI path, where the daemon's own agent WS carries the
    /// request)? Default `false` — without it, compromising any enrolled
    /// laptop would inherit its owner's SSH rights across the whole fleet.
    #[serde(default)]
    pub can_originate: bool,
    /// Restrict callers to these users. Empty = no user restriction (the
    /// permission bit + the other gates still apply).
    #[serde(default)]
    pub allowed_user_ids: Vec<ObjectId>,
    /// Restrict callers to holders of these roles. Empty = no role
    /// restriction.
    #[serde(default)]
    pub allowed_role_ids: Vec<ObjectId>,
    /// Which local account sessions run as.
    #[serde(default)]
    pub account_mode: SshAccountMode,
    /// The account for [`SshAccountMode::Named`]. Ignored otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// How consent is obtained before a session opens. `None` = the safe
    /// default ([`ConsentMode::Prompt`]); unattended servers set `Auto`.
    /// Only `Auto` and `Prompt` are honoured, as for exec.
    #[serde(default)]
    pub consent_mode: Option<ConsentMode>,
}

impl SshPolicy {
    /// Split into the two halves the server actually uses: what is checked at
    /// AUTHORIZE time ([`SshGates`]) and what crosses to the device in the
    /// grant at MINT time ([`SshGrantSpec`]).
    ///
    /// The destructure is deliberately EXHAUSTIVE — no `..` — and this is the
    /// only sanctioned way to consume a policy for a session decision. A field
    /// added to `SshPolicy` therefore stops compiling HERE, and stays broken
    /// until someone routes it into one of the halves in writing. That is the
    /// point: `consent_mode` crossed the wire for weeks while being
    /// destructured away (`consent_mode: _`), and reading fields off the
    /// policy à la carte is exactly how the next field gets the same
    /// treatment.
    pub fn split(self) -> (SshGates, SshGrantSpec) {
        let SshPolicy {
            mode,
            can_originate,
            allowed_user_ids,
            allowed_role_ids,
            account_mode,
            account,
            consent_mode,
        } = self;
        (
            SshGates {
                mode,
                can_originate,
                allowed_user_ids,
                allowed_role_ids,
            },
            SshGrantSpec {
                account_mode,
                account,
                consent_mode,
            },
        )
    }
}

/// The authorize-time half of an [`SshPolicy`] — everything consulted before
/// the server decides a grant may exist at all.
#[derive(Debug, Clone)]
pub struct SshGates {
    /// Does this device accept SSH sessions? Gate 3.
    pub mode: SshMode,
    /// May this device ORIGINATE sessions (`roomler ssh` over its own WS)?
    /// Not a gate for inbound sessions — it is read off the ORIGIN device's
    /// policy on the device-originated leg.
    pub can_originate: bool,
    pub allowed_user_ids: Vec<ObjectId>,
    pub allowed_role_ids: Vec<ObjectId>,
}

impl SshGates {
    /// Is `user` allowed by the user/role allowlists?
    ///
    /// Empty lists mean "no restriction at this layer" — never "deny all" —
    /// because the permission bit and the org kill-switch are the layers that
    /// decide *whether* anyone may connect. Mirrors the exec check so the two
    /// policies cannot drift apart in meaning.
    pub fn allows_caller(&self, user_id: &ObjectId, role_ids: &[ObjectId]) -> bool {
        if !self.allowed_user_ids.is_empty() && !self.allowed_user_ids.contains(user_id) {
            return false;
        }
        if !self.allowed_role_ids.is_empty()
            && !role_ids.iter().any(|r| self.allowed_role_ids.contains(r))
        {
            return false;
        }
        true
    }
}

/// The mint-time half of an [`SshPolicy`] — what the grant carries to the
/// device. Its fields map 1:1 onto `ServerMsg::SshGrant`, and the mint site
/// destructures it exhaustively, so a field routed here cannot be dropped on
/// the way to the wire.
#[derive(Debug, Clone)]
pub struct SshGrantSpec {
    pub account_mode: SshAccountMode,
    pub account: Option<String>,
    /// Raw policy value. Only an explicit `Auto` may cross as `Auto`; the mint
    /// site collapses everything else — including unset — to `Prompt`, the
    /// attended default (mirroring [`ExecPolicy::effective_consent_mode`]).
    pub consent_mode: Option<ConsentMode>,
}

// ────────────────────────────────────────────────────────────────────────────
// Tunnel client (roomler-cli)
// ────────────────────────────────────────────────────────────────────────────

/// A laptop running `roomler`. Mirrors [`Agent`] structurally
/// (same lifecycle, same `AgentStatus`, same `(tenant_id, machine_id)`
/// uniqueness for rehydrate-on-re-enroll) but slimmer — tunnel clients
/// don't capture screens or hold capability lists. The `_role_` is
/// inverted vs an agent: a tunnel client *initiates* forwards; an
/// agent *serves* them.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TunnelClient {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    /// User who installed + runs the CLI on this laptop. Carried into
    /// `TunnelClientClaims.owner_user_id` at enrollment time and
    /// recorded in every `tunnel_audit` row.
    pub owner_user_id: ObjectId,
    pub name: String,
    /// Friendly label an admin sets purely for display (see `Agent::display_name`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Free-form admin labels for fleet filtering/search.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// True once an admin renamed this client server-side (see
    /// `Agent::name_admin_set` — same rehydrate-clobber protection; a
    /// CLIENT-side rename can't rename in place at all, it derives a new
    /// machine_id and enrolls a new row).
    #[serde(default)]
    pub name_admin_set: bool,
    pub machine_id: String,
    pub os: OsKind,
    pub client_version: String,
    pub status: AgentStatus,
    pub last_seen_at: DateTime,
    pub created_at: DateTime,
    pub updated_at: DateTime,
    pub deleted_at: Option<DateTime>,
    /// FR-103: the token generation, as for [`Agent::token_gen`].
    #[serde(default)]
    pub token_gen: u32,
}

impl TunnelClient {
    pub const COLLECTION: &'static str = "tunnel_clients";
}

// ────────────────────────────────────────────────────────────────────────────
// A device's own view of its org (FR-84 D5a)
// ────────────────────────────────────────────────────────────────────────────
//
// `GET /api/agent/self/devices` — what THIS device's overlay netmap already
// carries, plus itself, for the desktop companion (which reaches only its
// local daemon, and the daemon holds an AGENT token, never a user's). Shared
// with the daemon, which proxies it to the companion, so every field is
// additive: `#[serde(default)]` on the way in, skipped when empty on the way
// out, and a newer server may add fields an older daemon ignores.
//
// ⚠️ Deliberately ABSENT, by shape rather than by policy: `machine_id`, the
// owner / user ids, the WG public key and its epoch, the consent settings,
// the codecs. A device sees its peers the way the netmap shows them to it —
// an admin's label and an address — never the fleet record. Adding one of
// those here is a security change, not a convenience.

/// One device THIS device may see — itself, or a peer its netmap carries.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct VisibleDeviceRow {
    /// `agent` | `tunnel_client`.
    #[serde(default)]
    pub kind: String,
    /// The agent / tunnel-client id (hex).
    #[serde(default)]
    pub id: String,
    /// The machine-reported (or admin-renamed) technical name.
    #[serde(default)]
    pub name: String,
    /// The admin's friendly label; the grid shows it over `name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub os: OsKind,
    /// agent_version / client_version, unified.
    #[serde(default)]
    pub version: String,
    /// `online` | `stale` | `offline` — the control-plane presence.
    #[serde(default)]
    pub presence: String,
    #[serde(default)]
    pub is_online: bool,
    /// RFC 3339.
    #[serde(default)]
    pub last_seen_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay_node_id: Option<String>,
    /// The node's MagicDNS label (bare, no domain).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub magic_dns_name: Option<String>,
    /// `<label>.<tenant magic_dns_domain>`, when the tenant has a domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub magic_dns_fqdn: Option<String>,
    /// Admin labels — the same class of operator-authored label as
    /// `display_name` (operator decision, FR-84).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// The netmap's presence verdict for the peer's overlay node: may this
    /// device dial it right now? `false` for a device with no overlay node.
    #[serde(default)]
    pub reachable: bool,
    /// FR-51 — enrolled as temporary. Serialised only when true.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ephemeral: bool,
    /// The caller itself.
    #[serde(default)]
    pub is_self: bool,
}

/// The page `GET /api/agent/self/devices` answers with.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct VisibleDevicesPage {
    #[serde(default)]
    pub items: Vec<VisibleDeviceRow>,
    #[serde(default)]
    pub total: u64,
    #[serde(default)]
    pub page: u64,
    #[serde(default)]
    pub per_page: u64,
    #[serde(default)]
    pub total_pages: u64,
    /// Why the list is what it is: `ok` (the netmap shaping applied) ·
    /// `no_node` (this device has no live overlay node — overlay off) ·
    /// `no_network` (the org has no overlay network yet) · `unavailable`
    /// (the server mounts no network module). Every value but `ok` lists
    /// the caller alone.
    #[serde(default)]
    pub overlay: String,
    /// The tenant's overlay ACL posture the shaping ran under: `off` | `warn`
    /// | `enforce` (`unknown` when the network module is absent).
    #[serde(default)]
    pub acl_mode: String,
    /// The caller's own overlay node id (hex), when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_node_id: Option<String>,
}

#[cfg(test)]
mod visible_device_tests {
    use super::*;

    fn row() -> VisibleDeviceRow {
        VisibleDeviceRow {
            kind: "agent".into(),
            id: "0123456789abcdef01234567".into(),
            name: "alpha-box".into(),
            display_name: Some("Alpha".into()),
            os: OsKind::Linux,
            version: "0.4.103".into(),
            presence: "online".into(),
            is_online: true,
            last_seen_at: "2026-09-25T00:00:00Z".into(),
            overlay_ip: Some("100.64.0.7".into()),
            overlay_node_id: Some("76543210fedcba9876543210".into()),
            magic_dns_name: Some("alpha-box".into()),
            magic_dns_fqdn: None,
            tags: vec!["prod".into()],
            reachable: true,
            ephemeral: false,
            is_self: false,
        }
    }

    /// The fleet-record fields a device must never see have no slot on the
    /// wire: the guarantee is the struct's shape, and this pins it so a
    /// "helpful" addition fails a test before it reaches a review.
    #[test]
    fn a_visible_row_has_no_slot_for_the_fleet_record() {
        let v = serde_json::to_value(row()).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        for forbidden in [
            "machine_id",
            "owner_user_id",
            "enrolled_by",
            "overlay_public_key",
            "wg_public_key",
            "overlay_key_epoch",
            "key_epoch",
            "access_policy",
            "capabilities",
            "codecs",
            "status",
            "created_at",
        ] {
            assert!(!keys.contains(&forbidden), "{forbidden} leaked: {keys:?}");
        }
        assert_eq!(v["display_name"], serde_json::json!("Alpha"));
        assert_eq!(v["reachable"], serde_json::json!(true));
        // `ephemeral: false` is omitted, like the admin row.
        assert!(v.get("ephemeral").is_none());
    }

    /// Additive on the way in: a page from an older server (fewer fields)
    /// still parses, and a round trip is lossless.
    #[test]
    fn page_round_trips_and_tolerates_missing_fields() {
        let page = VisibleDevicesPage {
            items: vec![row()],
            total: 1,
            page: 1,
            per_page: 25,
            total_pages: 1,
            overlay: "ok".into(),
            acl_mode: "enforce".into(),
            self_node_id: Some("76543210fedcba9876543210".into()),
        };
        let text = serde_json::to_string(&page).unwrap();
        let back: VisibleDevicesPage = serde_json::from_str(&text).unwrap();
        assert_eq!(back, page);

        let older: VisibleDevicesPage = serde_json::from_str(
            r#"{"items":[{"kind":"agent","id":"x","name":"n","os":"windows"}],"total":1}"#,
        )
        .unwrap();
        assert_eq!(older.items[0].os, OsKind::Windows);
        assert_eq!(older.items[0].presence, "");
        assert!(!older.items[0].is_self);
        assert_eq!(older.overlay, "");
        assert!(older.self_node_id.is_none());
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tunnel policy
// ────────────────────────────────────────────────────────────────────────────
//
// Single source of truth for ACL data shapes — DB rows AND the
// evaluator in `tunnel-core::policy` both consume these types. The
// evaluator re-exports them so callers have one import path; this
// keeps the DB schema authoritative without inverting the dep graph
// (`services` already depends on `remote_control` for `Agent` etc.).

/// Matches a destination hostname. Adjacently tagged so JSON wire
/// shape is `{"kind":"exact","value":"db.intranet"}` etc.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum HostPattern {
    /// Literal match — `"db.intranet"`.
    Exact(String),
    /// Glob — `"*.intranet"` matches one or more subdomains.
    Wildcard(String),
    /// CIDR range — `"10.0.0.0/24"`. Resolves against literal IPs only;
    /// hostnames must be resolved by the caller first.
    Cidr(String),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PortRange {
    /// Inclusive lower bound.
    pub low: u16,
    /// Inclusive upper bound. Equal to `low` for single-port rules.
    pub high: u16,
}

/// Which L4 protocol a [`DestinationRule`] permits. `Any` (the default,
/// and what pre-UDP stored rules deserialise to) matches both TCP
/// CONNECT forwards and UDP ASSOCIATE forwards; `Tcp` / `Udp` narrow a
/// rule to one. The forward gate evaluates the request's protocol
/// against this via [`ProtocolKind::permits`].
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolKind {
    Tcp,
    Udp,
    /// Matches any protocol. Default so a rule authored (or stored)
    /// without a `proto` field keeps its pre-UDP behaviour.
    #[default]
    Any,
}

impl ProtocolKind {
    /// Does a rule declaring `self` permit a forward request of
    /// protocol `req`? `Any` permits everything; otherwise the request
    /// must match exactly. `req` is always concrete (`Tcp` / `Udp`) —
    /// a request never carries `Any`.
    pub fn permits(self, req: ProtocolKind) -> bool {
        matches!(self, ProtocolKind::Any) || self == req
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DestinationRule {
    pub host_pattern: HostPattern,
    pub port_range: PortRange,
    /// L4 protocol this rule permits. `#[serde(default)]` → `Any` for
    /// pre-UDP stored rules + omitting it on the wire. Gated in
    /// `tunnel_core::policy::evaluate`.
    #[serde(default)]
    pub proto: ProtocolKind,
}

/// Match a `(dst_host, dst_port)` tuple against a single destination
/// rule.
///
/// Lived in `tunnel_core::policy` until P3e lever E moved it HERE, next to
/// the shapes it matches over (this crate is where `HostPattern` /
/// `PortRange` / `DestinationRule` are canonical — the doc block above this
/// section says so). The move lets `roomler-node-core`'s config-side ACL
/// evaluate rules without depending on tunnel-core's data plane; tunnel-core
/// re-exports both fns from `policy` so its callers are unchanged.
pub fn dst_matches(rule: &DestinationRule, dst_host: &str, dst_port: u16) -> bool {
    if dst_port < rule.port_range.low || dst_port > rule.port_range.high {
        return false;
    }
    host_matches(&rule.host_pattern, dst_host)
}

pub fn host_matches(pattern: &HostPattern, host: &str) -> bool {
    match pattern {
        HostPattern::Exact(s) => s.eq_ignore_ascii_case(host),
        HostPattern::Wildcard(s) => match s.strip_prefix("*.") {
            Some(suffix) => {
                host.to_ascii_lowercase()
                    .ends_with(&suffix.to_ascii_lowercase())
                    && host.len() > suffix.len()
                    && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
            }
            // A wildcard without a leading "*." is treated as exact —
            // safer than allow-all.
            None => s.eq_ignore_ascii_case(host),
        },
        HostPattern::Cidr(cidr) => match (
            cidr.parse::<ipnet::IpNet>(),
            host.parse::<std::net::IpAddr>(),
        ) {
            (Ok(net), Ok(ip)) => net.contains(&ip),
            _ => false,
        },
    }
}

/// Who a policy applies to. `{"kind":"all_users"}` is the catch-all
/// (default-allow lite — still scoped to the tenant). Externally
/// tagged would be cleaner but mixes object-vs-string on the wire
/// when one variant is a unit; `tag = "kind"` keeps everything as
/// objects.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicySubject {
    UserId {
        #[serde(rename = "id")]
        user_id: ObjectId,
    },
    RoleId {
        #[serde(rename = "id")]
        role_id: ObjectId,
    },
    TunnelClientId {
        #[serde(rename = "id")]
        tunnel_client_id: ObjectId,
    },
    /// A specific agent acting as a tunnel CLIENT (node-stack unification,
    /// P3b-2). Orthogonal to `PolicyTarget::AgentId` (which names the forward's
    /// DESTINATION): here the agent is the ORIGIN of the tunnel. Purely additive
    /// — old policy docs never carry this variant, so no migration is needed.
    AgentId {
        #[serde(rename = "id")]
        agent_id: ObjectId,
    },
    /// Every user in the policy's tenant.
    AllUsers,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyTarget {
    AgentId {
        #[serde(rename = "id")]
        agent_id: ObjectId,
    },
    /// Every agent in the policy's tenant.
    AllAgents,
}

/// A tenant-scoped allowlist. Default-deny: a forward is permitted
/// only if at least one matching policy exists. See plan §"Security
/// model" + `tunnel-core::policy::evaluate` for the eval semantics.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TunnelPolicy {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    pub name: String,
    pub subjects: Vec<PolicySubject>,
    pub targets: Vec<PolicyTarget>,
    pub allowlist: Vec<DestinationRule>,
    /// Per-session concurrent-flow ceiling. `None` = unlimited.
    /// Default 64 in v1 (covers JDBC pools comfortably).
    pub max_concurrent_flows: Option<u32>,
    /// Per-session byte ceiling (sum of bytes_in + bytes_out).
    /// `None` = unlimited.
    pub max_bytes_per_session: Option<u64>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
    pub deleted_at: Option<DateTime>,
}

impl TunnelPolicy {
    pub const COLLECTION: &'static str = "tunnel_policies";
}

// ────────────────────────────────────────────────────────────────────────────
// Overlay ACL
// ────────────────────────────────────────────────────────────────────────────

/// Who an [`OverlayPolicy`] applies to — the node ORIGINATING traffic.
///
/// Deliberately a separate enum from [`PolicySubject`]: the overlay is pure
/// L3, so the tunnel's client/agent-origin distinction is meaningless here,
/// and a node is addressed by its `overlay_nodes` id regardless of whether it
/// is backed by an agent or a tunnel client. Reusing `PolicySubject` would
/// offer variants that can never match an overlay node.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OverlaySelector {
    /// One specific overlay node.
    NodeId {
        #[serde(rename = "id")]
        node_id: ObjectId,
    },
    /// Every node owned by this user (resolved through the node's backing
    /// agent / tunnel-client `owner_user_id`).
    UserId {
        #[serde(rename = "id")]
        user_id: ObjectId,
    },
    /// Every node whose owner holds this role.
    RoleId {
        #[serde(rename = "id")]
        role_id: ObjectId,
    },
    /// Every node in the policy's tenant.
    AllNodes,
}

/// Which node a policy lets the sources reach — the peer, and (when it is a
/// subnet router) the gateway for its approved CIDRs.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OverlayTarget {
    NodeId {
        #[serde(rename = "id")]
        node_id: ObjectId,
    },
    /// Every node in the policy's tenant.
    AllNodes,
}

/// One destination grant: a CIDR plus an optional port/protocol narrowing.
///
/// ⚠️ `port_range` / `proto` **do not affect netmap shaping**: peer visibility
/// and route lists are the only primitives the netmap can express, so a
/// port-narrowed rule still makes the whole peer visible. Under `enforce` the
/// server ships them per source as `ingress_rules`, and the RECEIVING node's
/// ingress filter enforces them on every carrier (direct, DERP, org relay),
/// for traffic to the node itself and to the subnets it routes (#18). The
/// filter is stateful: only a new TCP connection (bare SYN), an unsolicited
/// UDP datagram or a fragment is judged; replies to flows the node opened,
/// ICMP errors and echo requests to the node itself always pass.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OverlayRule {
    /// Destination prefix, e.g. `"10.84.6.0/24"` or a peer's `"100.64.0.7/32"`.
    pub cidr: String,
    #[serde(default = "OverlayRule::all_ports")]
    pub port_range: PortRange,
    #[serde(default)]
    pub proto: ProtocolKind,
}

impl OverlayRule {
    fn all_ports() -> PortRange {
        PortRange {
            low: 1,
            high: u16::MAX,
        }
    }
}

/// How strictly a tenant's overlay ACL is applied. Stored on the tenant's
/// [`OverlayNetwork`] (one row per tenant) rather than on each policy — it is
/// a network-wide posture, and putting it there means the join path already
/// has it loaded.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum OverlayAclMode {
    /// Legacy behaviour: every node sees every peer and every approved route.
    /// The default, so enabling the feature never breaks a live mesh.
    #[default]
    Off,
    /// Evaluate and log what WOULD be denied, but ship the permissive netmap.
    /// The safe way to author policies against real traffic before cutting over.
    Warn,
    /// Evaluate and enforce.
    Enforce,
}

/// FR-19 gate 1 — the org's switch for peer relays. Same shape and the same
/// closed default as [`OverlayAclMode`], for the same reason: every
/// `overlay_networks` row written before FR-19 lacks the field, and the
/// default must make enabling the feature a no-op for them.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PeerRelayMode {
    /// No sessions are minted. The default.
    #[default]
    Off,
    /// Decide and audit what WOULD be minted, but mint nothing.
    Warn,
    /// Mint.
    On,
    /// MeshHarbor: mint as [`Self::On`] does, and additionally let a device
    /// whose CENTRAL `server` role is current serve any two members whose
    /// live connections were observed in the same business zone as its own,
    /// with no `serve` approval and no overlay policy naming it. An unknown
    /// zone anywhere refuses ([`PeerRelayDenyReason::ZoneDenied`]).
    Auto,
}

/// An administrator-approved directional backbone edge. This does not grant
/// any client permission to dial private endpoints: only a separately opted-in
/// relay process, with its own CIDR allowlist, may consume such an edge.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PeerRelayBackboneEdge {
    /// Same-tenant, live, separately relay-approved target agent (hex ObjectId).
    pub relay_agent_id: String,
    /// Exact UDP ip:port, never DNS. Private unicast is allowed ONLY here.
    pub endpoint: String,
    /// MeshHarbor #21 exception: this edge is an approved cross-border line
    /// (any private path between the two relays: an interconnect, an IPLC,
    /// or any UDP route the operator vouches for). A pair whose business zones differ
    /// may ride it, the ingress relay in the requester's zone and the exit
    /// in the peer's; nothing else carries a pair across zones.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cross_border: bool,
}

pub const MAX_PEER_RELAY_BACKBONE_EDGES: usize = 8;

/// FR-19 gate 3 — may THIS device serve as an org relay for its tenant?
/// Per-device and admin-set; the device's own `relay_server_enabled` (gate 4)
/// is separate and device-local, so approving here does nothing on a device
/// that has not opted in itself — an offer is not a grant, and a grant is not
/// an offer.
///
/// `PartialEq` so a listing can ask "is this the untouched default?" — the
/// same question [`ExecPolicy`] answers for the same reason.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct PeerRelayPolicy {
    /// Approved to serve. Default `false`.
    #[serde(default)]
    pub serve: bool,
    /// Admin-declared `ip:port`s the relay is reachable at — the port-forwarded
    /// or multi-homed case the node's own srflx/static candidates cannot
    /// discover. Each entry is SSRF-validated at approval time (a public IP
    /// literal, never a name) and re-checked at mint time: a server-pushed
    /// probe target is an oracle-returning port scanner run by every device
    /// in the tenant as SYSTEM/root, so `169.254.169.254:80` must never get
    /// through here. Tried AFTER the measured candidates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub static_endpoints: Vec<String>,
    /// Default-empty server policy, NOT a device-local opt-in. Ordinary enroll
    /// tokens must preserve this field and never acquire backbone permission.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approved_backbone_edges: Vec<PeerRelayBackboneEdge>,
}

/// Bounds on FR-19 relay minting. Server-side only — the relay device
/// re-clamps every session lifetime against its own table
/// (`orgrelay::session`), so nothing here is trusted by a device.
pub mod peer_relay_limits {
    /// Experimental two-hop payload ceiling; no existing TUN MTU is changed.
    pub const BACKBONE_MAX_CIPHERTEXT: usize = 1400;
    /// WG data payload is padded to 16 bytes, then adds 32 bytes of framing.
    pub const BACKBONE_MAX_OVERLAY_MTU: u16 = 1360;

    /// Mints per minute per (requesting node, relay node) pair — the key the
    /// spec prescribes (§4 "Rate limiting"): a mint writes state onto a THIRD
    /// device, so the pair to bound is requester × relay, not requester × peer.
    /// The number is the exec precedent (`exec_limits::RATE_LIMIT_PER_MINUTE`)
    /// so a fleet boot — one requester asking for every unreachable peer
    /// through the same relay inside a minute — fits under it.
    pub const MINT_RATE_LIMIT_PER_MINUTE: u32 = 30;
    /// The relay-server UDP port assumed when a join carries none — the
    /// value E2E-3 settled (spec §5) and `orgrelay::DEFAULT_RELAY_SERVER_PORT`
    /// on the device; the two are the same number by contract.
    pub const DEFAULT_RELAY_PORT: u16 = 3478;
    /// Seconds a member has to complete its bind at the relay.
    pub const BIND_SECS: u32 = 30;
    /// Idle seconds before the relay drops a bound session. Refreshed by
    /// traffic, so under a WireGuard keepalive it never fires — which is why
    /// `MAX_LIFETIME_SECS` exists.
    pub const IDLE_SECS: u32 = 300;
    /// Absolute session lifetime, independent of traffic. Also the exposure
    /// window after a server restart loses the session registry: a session
    /// the server can no longer revoke ends here at the latest.
    pub const MAX_LIFETIME_SECS: u32 = 3600;
    /// Live sessions the server will place on one relay — mirrors the
    /// device's own `orgrelay::session::MAX_SESSIONS`, which refuses beyond it.
    pub const MAX_SESSIONS_PER_RELAY: usize = 64;
    /// How long a reachability report counts toward relay ranking.
    pub const PROBE_TTL_SECS: u64 = 600;
    /// The STUN magic cookie as a 24-bit VNI — never minted, so a STUN
    /// packet arriving at the relay port can never alias a session.
    pub const STUN_COOKIE_VNI: u32 = 0x2112A4;
    /// The 24-bit Geneve VNI ceiling.
    pub const VNI_MAX: u32 = 0xFF_FFFF;
}

/// Why a peer-relay decision — an admin's approval or a session mint — was
/// refused. The FR-19 twin of [`ExecDenyReason`] / [`SshDenyReason`], kept
/// separate for the reason those two are: the vocabularies diverge (a mint has
/// no caller permission, an approval has no relay).
///
/// Every arm is auditable. A refusal nobody can query is a refusal nobody will
/// notice, and the refused rows are what an operator hunting "why is this pair
/// still on DERP?" actually reads.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PeerRelayDenyReason {
    /// Gate 1 — the org's [`PeerRelayMode`] is `Off`. ⚠️ Deliberately NEVER
    /// audited: with the feature off there must be zero rows and zero reads
    /// (acceptance: "`peer_relay_mode=off` ⇒ no `peer_relay_audit` rows").
    OrgDisabled,
    /// Approval — the caller lacks `MANAGE_AGENTS`.
    NotDeviceAdmin,
    /// Approval — turning `serve` ON additionally requires `EXEC_DEVICE`: you
    /// cannot grant a power you do not hold (#600/#605), and nominating a
    /// relay makes a device a chokepoint for the whole tenant's traffic.
    CannotGrantRelay,
    /// The requesting node did not advertise `supports_org_relay` on its join
    /// — a pre-FR-19 build that could not act on a session anyway.
    RequesterUnsupported,
    /// The peer the requester wants to reach did not advertise it; a session
    /// with one deaf end is a session nobody can use.
    PeerUnsupported,
    /// The peer is in another tenant.
    CrossTenant,
    /// Gate 2 — no overlay policy grants this pair relay use. Evaluated
    /// regardless of `acl_mode`: an affirmative capability (spec §4).
    AclDenied,
    /// Gate 2 could not be evaluated because the policy rows were unreadable.
    /// The fail-CLOSED arm, distinct from [`Self::AclDenied`] so a Mongo blip
    /// is never mistaken for a policy decision.
    PolicyUnreadable,
    /// No device in the tenant is approved (gate 3), advertising
    /// `relay-server` (gate 4) and online.
    NoRelay,
    /// The chosen relay's endpoint failed the SSRF validator — it would have
    /// steered members at a loopback / RFC1918 / metadata / overlay address.
    NonRoutableEndpoint,
    /// The requester or the relay is a SECONDARY-org row on a multi-org
    /// device; serving is primary-only (a UDP listener is host-global).
    SecondaryOrg,
    /// Per-(requesting node, relay node) ceiling
    /// ([`peer_relay_limits::MINT_RATE_LIMIT_PER_MINUTE`]).
    RateLimited,
    /// [`PeerRelayMode::Auto`] — a Server-role relay's implicit grant needs
    /// the requester, the peer and the relay each observed in ONE business
    /// zone on their live connections; a zone that differs or is unknown
    /// refuses (hard mainland / non-mainland isolation, failing closed).
    ZoneDenied,
}

impl PeerRelayDenyReason {
    /// One line an operator can act on — names WHICH gate said no.
    pub fn message(self) -> &'static str {
        match self {
            Self::OrgDisabled => "peer relays are off for this organization",
            Self::NotDeviceAdmin => "Missing MANAGE_AGENTS permission",
            Self::CannotGrantRelay => {
                "Approving a device as an org relay requires EXEC_DEVICE — it makes the device \
                 a traffic chokepoint for the whole organization, and you cannot grant a power \
                 you do not hold"
            }
            Self::RequesterUnsupported => "the requesting device does not support org relays",
            Self::PeerUnsupported => "the peer does not support org relays",
            Self::CrossTenant => "the peer is not in this organization",
            Self::AclDenied => "no overlay policy grants this pair the use of a relay",
            Self::PolicyUnreadable => {
                "the overlay policies could not be read; refusing rather than guessing"
            }
            Self::NoRelay => "no approved, serving, online relay device in this organization",
            Self::NonRoutableEndpoint => "the relay's endpoint is not a public address",
            Self::SecondaryOrg => "org relays serve the device's primary organization only",
            Self::RateLimited => "too many relay requests through this relay; try again shortly",
            Self::ZoneDenied => {
                "the relay and both members were not all observed in one business zone"
            }
        }
    }
}

/// Which decision a [`PeerRelayAuditEvent`] records.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PeerRelayAuditAction {
    /// An admin set a device's [`PeerRelayPolicy`] — the privilege-granting
    /// act, audited because the exit-node precedent auditing nothing is a gap
    /// not to copy.
    Approve,
    /// A node asked for a session to a peer and the server decided.
    Mint,
    /// The server tore a session down — org mode off, an ACL edit that no
    /// longer grants the pair the relay, the relay's approval cleared, or a
    /// party removed. A push, never an expiry (§7): the idle deadline never
    /// fires under a WireGuard keepalive.
    Revoke,
}

/// One peer-relay decision, granted or refused. TTL-expired after 90 days like
/// [`ExecAuditEvent`].
///
/// One collection for both actions on purpose: the question an incident review
/// asks — "who made this device a relay, and what has been routed through it
/// since?" — is ONE query on `agent_id`, which two collections would split.
/// The optional fields each belong to one action; [`Self::action`] says which.
///
/// **A mint row records the DECISION, not the session.** The server pushes a
/// session to three devices and its involvement ends there; it never sees a
/// byte of what they exchange. Same discipline as [`SshAuditEvent`].
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeerRelayAuditEvent {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    pub action: PeerRelayAuditAction,
    /// The device the row is ABOUT: the one being approved, or the relay
    /// chosen to carry the session (absent on a mint no relay qualified for).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<ObjectId>,
    /// The admin who asked (`approve`). A mint has no person behind it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<ObjectId>,
    /// `mint` — the node that asked, and the peer it asked to reach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_node_id: Option<ObjectId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_node_id: Option<ObjectId>,
    /// `mint` — the overlay node chosen as the relay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_node_id: Option<ObjectId>,
    /// `approve` — the requested value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serve: Option<bool>,
    /// `mint` — the VNI issued. Absent on refusal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vni: Option<u32>,
    /// `mint` under [`PeerRelayMode::Warn`]: the decision was taken and
    /// recorded exactly as `On` would have, and NOTHING was pushed.
    #[serde(default)]
    pub warn_only: bool,
    pub at: DateTime,
    /// Refusal reason; `None` = approved / minted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denied: Option<PeerRelayDenyReason>,
    /// `revoke` — which of the four triggers fired (`mode_off` |
    /// `acl_revoked` | `policy_revoked` | `device_removed` | `device_left`);
    /// `mint` — `cross_border_line` when the pair crossed business zones.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl PeerRelayAuditEvent {
    pub const COLLECTION: &'static str = "peer_relay_audit";
}

#[cfg(test)]
mod peer_relay_audit_tests {
    use super::*;

    /// The wire strings are what the audit UI and the integration tests match
    /// on; a rename here would silently turn a filtered view empty.
    #[test]
    fn deny_reason_wire_strings_are_locked() {
        let all = [
            (PeerRelayDenyReason::OrgDisabled, "org_disabled"),
            (PeerRelayDenyReason::NotDeviceAdmin, "not_device_admin"),
            (PeerRelayDenyReason::CannotGrantRelay, "cannot_grant_relay"),
            (
                PeerRelayDenyReason::RequesterUnsupported,
                "requester_unsupported",
            ),
            (PeerRelayDenyReason::PeerUnsupported, "peer_unsupported"),
            (PeerRelayDenyReason::CrossTenant, "cross_tenant"),
            (PeerRelayDenyReason::AclDenied, "acl_denied"),
            (PeerRelayDenyReason::PolicyUnreadable, "policy_unreadable"),
            (PeerRelayDenyReason::NoRelay, "no_relay"),
            (
                PeerRelayDenyReason::NonRoutableEndpoint,
                "non_routable_endpoint",
            ),
            (PeerRelayDenyReason::SecondaryOrg, "secondary_org"),
            (PeerRelayDenyReason::RateLimited, "rate_limited"),
        ];
        for (reason, wire) in all {
            assert_eq!(
                serde_json::to_value(reason).unwrap(),
                serde_json::json!(wire)
            );
            assert!(!reason.message().is_empty());
        }
        assert_eq!(
            serde_json::to_value(PeerRelayAuditAction::Approve).unwrap(),
            serde_json::json!("approve")
        );
        assert_eq!(
            serde_json::to_value(PeerRelayAuditAction::Mint).unwrap(),
            serde_json::json!("mint")
        );
        assert_eq!(
            serde_json::to_value(PeerRelayAuditAction::Revoke).unwrap(),
            serde_json::json!("revoke")
        );
    }

    /// A row must explain itself without a join, and the optional fields are
    /// skipped when absent so an `approve` row carries no mint noise.
    #[test]
    fn approve_row_serialises_without_mint_fields() {
        let row = PeerRelayAuditEvent {
            id: None,
            tenant_id: ObjectId::new(),
            action: PeerRelayAuditAction::Approve,
            agent_id: Some(ObjectId::new()),
            user_id: Some(ObjectId::new()),
            requester_node_id: None,
            peer_node_id: None,
            relay_node_id: None,
            serve: Some(true),
            vni: None,
            warn_only: false,
            at: DateTime::now(),
            denied: Some(PeerRelayDenyReason::CannotGrantRelay),
            reason: None,
        };
        let doc = bson::to_document(&row).unwrap();
        assert!(doc.contains_key("serve"));
        assert!(!doc.contains_key("vni"));
        assert!(!doc.contains_key("requester_node_id"));
        assert_eq!(doc.get_str("denied").unwrap(), "cannot_grant_relay");
        let back: PeerRelayAuditEvent = bson::from_document(doc).unwrap();
        assert_eq!(back.action, PeerRelayAuditAction::Approve);
        assert_eq!(back.denied, Some(PeerRelayDenyReason::CannotGrantRelay));
    }
}

/// A tenant-scoped overlay access rule. Default-deny **once the tenant's
/// [`OverlayAclMode`] is `Enforce`**; `Off` (the default) preserves the
/// historical "same tenant + same network ⇒ full visibility" behaviour.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OverlayPolicy {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    pub name: String,
    /// Lets an admin park a rule without deleting it.
    #[serde(default = "crate::models::default_true")]
    pub enabled: bool,
    pub sources: Vec<OverlaySelector>,
    pub via: Vec<OverlayTarget>,
    pub destinations: Vec<OverlayRule>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
    pub deleted_at: Option<DateTime>,
}

impl OverlayPolicy {
    pub const COLLECTION: &'static str = "overlay_policies";
}

pub(crate) fn default_true() -> bool {
    true
}

// ────────────────────────────────────────────────────────────────────────────
// FR-52 — cross-org remote access
// ────────────────────────────────────────────────────────────────────────────

/// Per-device approval for control by someone **outside the organization** —
/// gate 2 of five (`docs/fr/FR-52-cross-org-remote-access.md` §3).
///
/// Shaped on [`PeerRelayPolicy`], and default-closed for the same reason:
/// every pre-feature row deserialises to "not approved", so shipping the
/// feature can never retroactively open a device.
///
/// ⚠️ This is an org-admin gate, not the device's. Approving here grants
/// nothing on its own — the device must still opt in locally
/// (`external_access_enabled`, gate 3) and the outsider must still prove the
/// device-held password (gate 4). What it *does* decide is the CEILING: an org
/// can allow an outsider to watch a screen without letting them touch it, and
/// no device-side setting can widen that.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct ExternalAccessPolicy {
    /// Approved for external control. Default `false`.
    #[serde(default)]
    pub approved: bool,
    /// Ceiling on what an external session may be granted. `None` — the
    /// default, and every pre-feature row — means
    /// [`DEFAULT_EXTERNAL_PERMISSIONS`], NOT "unrestricted": an unset ceiling
    /// must be the narrow one, or forgetting to set it would be the widest
    /// possible grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_permissions: Option<Permissions>,
    /// When the approval lapses. `None` = it stands until cleared.
    ///
    /// Exists because the common case for this feature is temporary: a
    /// contractor, a support engagement, a vendor with a two-week window. An
    /// approval that can only be revoked by remembering to revoke it is one
    /// that outlives its reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime>,
}

/// What an external session may be granted when the device's policy names no
/// ceiling: **view and input, nothing else**.
///
/// Narrower than [`Permissions::default`] (which adds `CLIPBOARD`, and is
/// grandfathered into `FILES` by the hub). Clipboard and file transfer move
/// data across the org boundary in both directions, and an outsider should get
/// them because an admin decided to, never because nobody narrowed the
/// default. FR-52 open decision 3.
pub const DEFAULT_EXTERNAL_PERMISSIONS: Permissions =
    Permissions::from_bits_truncate(Permissions::VIEW.bits() | Permissions::INPUT.bits());

impl ExternalAccessPolicy {
    /// Split into the two halves the server uses: what is checked when a
    /// session is AUTHORIZED ([`ExternalAccessGates`]) and what bounds the
    /// session once it is ([`ExternalAccessSpec`]).
    ///
    /// The destructure is deliberately EXHAUSTIVE — no `..` — for the reason
    /// [`SshPolicy::split`] is: a field added to this policy stops compiling
    /// HERE until someone routes it into one of the halves in writing. That is
    /// how `consent_mode` came to cross the SSH wire for weeks while being
    /// destructured away, and this policy has the same hazard with a worse
    /// blast radius.
    pub fn split(self) -> (ExternalAccessGates, ExternalAccessSpec) {
        let ExternalAccessPolicy {
            approved,
            max_permissions,
            expires_at,
        } = self;
        (
            ExternalAccessGates {
                approved,
                expires_at,
            },
            ExternalAccessSpec { max_permissions },
        )
    }
}

/// The authorize-time half of an [`ExternalAccessPolicy`].
#[derive(Debug, Clone, PartialEq)]
pub struct ExternalAccessGates {
    pub approved: bool,
    pub expires_at: Option<DateTime>,
}

impl ExternalAccessGates {
    /// Is this approval usable *now*?
    ///
    /// Takes the clock as an argument rather than reading it, so the boundary
    /// is testable without sleeping. An approval whose instant has passed is
    /// exactly as closed as one that was never granted — there is no grace,
    /// because the whole point of the expiry is that nobody has to remember.
    pub fn is_open_at(&self, now: DateTime) -> bool {
        self.approved && self.expires_at.is_none_or(|exp| exp > now)
    }
}

/// The session-time half of an [`ExternalAccessPolicy`] — the ceiling a
/// session's grant is clamped to.
#[derive(Debug, Clone, PartialEq)]
pub struct ExternalAccessSpec {
    pub max_permissions: Option<Permissions>,
}

impl ExternalAccessSpec {
    /// The effective ceiling: what the admin set, or
    /// [`DEFAULT_EXTERNAL_PERMISSIONS`] when they set nothing.
    pub fn ceiling(&self) -> Permissions {
        self.max_permissions.unwrap_or(DEFAULT_EXTERNAL_PERMISSIONS)
    }

    /// Clamp a requested grant to the ceiling.
    ///
    /// Intersection, never substitution: a request for less than the ceiling
    /// stays less, and a request for more is trimmed rather than refused —
    /// an outsider whose viewer asks for clipboard should get a session
    /// without it, not an error they cannot act on.
    pub fn clamp(&self, requested: Permissions) -> Permissions {
        requested & self.ceiling()
    }
}

/// Why an external-access decision was refused.
///
/// The FR-52 sibling of [`SshDenyReason`] / [`PeerRelayDenyReason`], kept
/// separate for the reason those two are separate from each other: the
/// vocabulary is its own. Every arm is auditable, and the refused rows are the
/// ones an operator hunting "why can my contractor not connect?" reads.
///
/// ⚠️ These wire spellings are a compatibility surface — the audit view filters
/// on them. Locked by test.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExternalRcDenyReason {
    /// The caller lacks `MANAGE_AGENTS`, so they may not touch device policy
    /// at all.
    NotDeviceAdmin,
    /// The caller holds `MANAGE_AGENTS` but not `REMOTE_CONTROL`, and asked to
    /// ADD an approval. Clearing one needs only `MANAGE_AGENTS` — revocation
    /// is not a grant.
    CannotGrantExternal,
    /// The device's agent does not advertise [`RpcCap::ExternalAccess`], so it
    /// cannot honour the gates or tell the person at the machine that the
    /// controller is an outsider. Approving it would put a promise on screen
    /// that the device does not keep.
    DeviceUnsupported,
}

impl ExternalRcDenyReason {
    /// Every variant — walked by a test, so a new one cannot be added without
    /// a wire spelling and a message.
    pub const ALL: &'static [ExternalRcDenyReason] = &[
        Self::NotDeviceAdmin,
        Self::CannotGrantExternal,
        Self::DeviceUnsupported,
    ];

    /// One line an operator can act on. Names WHICH gate said no, for the
    /// reason [`SshDenyReason::message`] does: "denied" with no reason turns a
    /// five-second fix into a support ticket.
    pub fn message(self) -> &'static str {
        match self {
            Self::NotDeviceAdmin => {
                "you do not have the MANAGE_AGENTS permission in this organization"
            }
            Self::CannotGrantExternal => {
                "granting external access also requires the REMOTE_CONTROL permission \
                 (clearing it does not)"
            }
            Self::DeviceUnsupported => {
                "this device's agent is too old for external access — it cannot tell the \
                 person at the machine that the controller is from outside the organization"
            }
        }
    }
}

/// What an [`ExternalRcAuditEvent`] row is about.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExternalRcAuditAction {
    /// An admin set (or cleared) a device's [`ExternalAccessPolicy`] — the
    /// privilege-granting act.
    Approve,
    /// An admin minted or rotated a device's connect code. Audited because
    /// rotation is the revocation story for a leaked code, so "when did this
    /// code start being valid?" has to be answerable.
    RotateCode,
    /// FR-52 P3 — an external-access LOGIN ended, verified or refused. One row
    /// per attempt, written when it ends, once the connect code has resolved to
    /// a device (an unresolvable code has no device and no tenant to attach a
    /// row to). `user_id` is the would-be controller, not an admin.
    Login,
    /// FR-52 P4 — a verified login asked to open its session: admitted (with
    /// the `session_id` it got) or refused. One row per ask, keyed to the
    /// login by `attempt_id`, so "who got in, on which login, into which
    /// session" is one join. What the DEVICE then decides — its own consent,
    /// its own ceiling — is the session's own audit trail, not this row.
    Session,
}

/// One external-access decision, granted or refused. TTL-expired after 90 days
/// like [`SshAuditEvent`].
///
/// ⚠️ A row records the SERVER's decision. It is deliberately not a record of
/// the session: the server's involvement ends when it says yes, and the
/// session rides a path it never observes — the same discipline as
/// [`SshAuditEvent`] and [`PeerRelayAuditEvent`].
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExternalRcAuditEvent {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    pub action: ExternalRcAuditAction,
    /// The device the row is about.
    pub agent_id: ObjectId,
    /// The admin who asked.
    pub user_id: ObjectId,
    /// Display name of the acting admin, so a row stays readable after the
    /// account is renamed or removed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub actor: String,
    /// `approve` — the requested approval state. The field a reader scans for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved: Option<bool>,
    /// `approve` — the ceiling that was set, in the pipe-separated wire form
    /// (`"VIEW | INPUT"`). Absent when the policy named none, which means
    /// [`DEFAULT_EXTERNAL_PERMISSIONS`] applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_permissions: Option<String>,
    /// `approve` — when the approval lapses, if it does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime>,
    pub at: DateTime,
    /// Refusal reason; `None` = the decision went through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denied: Option<ExternalRcDenyReason>,
    /// `login` / `session` — the attempt this row closes (`login`) or spends
    /// (`session`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
    /// `login` / `session` — why it was refused; `None` = VERIFIED (`login`)
    /// or ADMITTED (`session`).
    ///
    /// ⚠️ This is the one place the refusal reasons are told apart. The
    /// would-be controller only ever sees `unavailable` for every configuration
    /// refusal; the org's own audit log is where "gate 2 had expired" and "the
    /// device is offline" must be distinguishable, or no admin could act on it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_refused: Option<ExtauthRefusal>,
    /// `login` / `session` — what the SERVER knows about a refusal the
    /// controller saw as `unavailable`: which gate, or offline. `None` when the
    /// device refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_detail: Option<String>,
    /// `session` — the session an admitted login opened. Joins this row to the
    /// session's own audit (`remote_audit`), which records what the device
    /// then decided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<ObjectId>,
}

impl ExternalRcAuditEvent {
    pub const COLLECTION: &'static str = "external_rc_audit";
}

/// FR-52 P3 — why an external-access login step was refused.
///
/// Carried device → server in `rc:extauth.outcome`, and server → controller in
/// the same shape. The server maps its OWN refusals onto the same values, so a
/// controller cannot tell which party said no — see [`Self::Unavailable`].
///
/// ⚠️ Decoded LENIENTLY off the agent (`extauth_refusal_lenient` in
/// `signaling`), for FR-83's reason: an unknown spelling from a newer agent
/// lands on [`Self::Other`] — still a refusal. A strict decode would fail the
/// whole frame, the server would drop it at `debug!`, and a clear refusal would
/// become "no answer" after the full wait. It must never land on "verified".
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExtauthRefusal {
    /// The ONE answer for everything a would-be controller must not be able to
    /// tell apart: no such connect code, the org's switch off (gate 1), the
    /// device not approved or the approval expired (gate 2), the device
    /// offline or too old, the device's own opt-in off (gate 3), no password
    /// set or an unreadable record (gate 4). Distinguishing them would turn the
    /// connect code into a probe of the device's configuration — and would let
    /// the holder of an old, rotated code learn that it once worked.
    Unavailable,
    /// The device has answered too many guesses recently. The one refusal that
    /// carries a `retry_after_secs`, because telling a legitimate outsider when
    /// to try again costs nothing — an attacker is throttled either way.
    Throttled,
    /// The server's own per-caller / per-code ceiling, a second limit behind
    /// the device's (§4b of the FR-52 spec).
    RateLimited,
    /// Too many logins in flight on the device.
    Busy,
    /// A login message that is not an OPAQUE message.
    Malformed,
    /// KE3 did not verify.
    Rejected,
    /// KE3 for an attempt the device does not have in flight — never started,
    /// expired, or already finished.
    UnknownAttempt,
    /// FR-115 P3b — the org the session is for (or the account, when it is in
    /// no org) already runs as many remote sessions as its plan allows. Sent
    /// by the server only, with a `message` naming who holds the slot, so the
    /// outsider can end that session or run this one for another org.
    SessionLimit,
    /// A reason this build does not know. Still a refusal.
    Other,
}

#[cfg(test)]
mod external_access_tests {
    use super::*;

    /// An untouched policy is closed. The whole default-deny story rests on
    /// this one assertion holding for every row that predates the feature.
    #[test]
    fn default_policy_is_closed() {
        let p = ExternalAccessPolicy::default();
        assert!(!p.approved);
        let (gates, _) = p.split();
        assert!(!gates.is_open_at(DateTime::now()));
    }

    /// A pre-FR-52 agent document has no `external_access_policy` key at all.
    /// It must deserialise to the closed default rather than fail the whole
    /// row — a device that stops loading is worse than one that stays shut.
    #[test]
    fn absent_policy_deserialises_closed() {
        let p: ExternalAccessPolicy = serde_json::from_str("{}").unwrap();
        assert_eq!(p, ExternalAccessPolicy::default());
        assert!(!p.approved);
    }

    /// An UNSET ceiling is the narrow one. If this ever flips to
    /// `Permissions::all()`, forgetting to set a ceiling becomes the widest
    /// possible grant to a stranger.
    #[test]
    fn unset_ceiling_is_view_and_input_only() {
        let spec = ExternalAccessSpec {
            max_permissions: None,
        };
        assert_eq!(spec.ceiling(), Permissions::VIEW | Permissions::INPUT);
        assert!(!spec.ceiling().contains(Permissions::CLIPBOARD));
        assert!(!spec.ceiling().contains(Permissions::FILES));
    }

    /// The clamp trims rather than refuses, and never widens.
    #[test]
    fn clamp_is_an_intersection_in_both_directions() {
        let spec = ExternalAccessSpec {
            max_permissions: Some(Permissions::VIEW | Permissions::INPUT),
        };
        // Asking for more than the ceiling is trimmed to it.
        assert_eq!(
            spec.clamp(Permissions::all()),
            Permissions::VIEW | Permissions::INPUT
        );
        // Asking for less than the ceiling stays less — a view-only watcher
        // must not be handed input because the ceiling allowed it.
        assert_eq!(spec.clamp(Permissions::VIEW), Permissions::VIEW);
    }

    /// ⚠️ This policy is a **storage** shape and must never be an HTTP one.
    ///
    /// `bson::DateTime` speaks extended JSON in both directions: it REFUSES the
    /// plain `"2026-09-05T10:00:00Z"` that `Date.toISOString()` produces (so a
    /// body carrying what the dialog's picker yields fails to deserialize —
    /// a 4xx on an optional field, with nothing on screen to explain it), and it
    /// EMITS `{"$date":{"$numberLong":…}}` (a TRUTHY object, so a client
    /// presence check passes and the value renders as `[object Object]`).
    ///
    /// Both halves were found by test before shipping. `routes::external_access`
    /// therefore owns an `ExternalAccessPolicyBody` whose `expires_at` is an
    /// RFC3339 `String`, converted at the edge. This test pins the reason that
    /// indirection exists, so nobody deletes it as ceremony.
    #[test]
    fn the_stored_policy_speaks_extended_json_which_is_why_the_api_has_its_own_shape() {
        // Inbound: the browser's form is REFUSED here.
        let iso: Result<ExternalAccessPolicy, _> =
            serde_json::from_str(r#"{"approved":true,"expires_at":"2026-09-05T10:00:00Z"}"#);
        assert!(
            iso.is_err(),
            "if this ever starts parsing, the API's String hop can be revisited"
        );

        // Outbound: an object, not a string. The trap is that it is truthy.
        let p = ExternalAccessPolicy {
            approved: true,
            max_permissions: None,
            expires_at: Some(DateTime::from_millis(1_788_602_400_000)),
        };
        let v = serde_json::to_value(&p).unwrap();
        assert!(
            v["expires_at"].is_object(),
            "a bson::DateTime serialises as an object; returning this struct \
             from a handler is what produces [object Object] on screen"
        );
    }

    #[test]
    fn expiry_closes_the_gate_with_no_grace() {
        let now = DateTime::from_millis(1_000_000);
        let past = DateTime::from_millis(999_999);
        let future = DateTime::from_millis(1_000_001);

        let open = ExternalAccessGates {
            approved: true,
            expires_at: Some(future),
        };
        assert!(open.is_open_at(now));

        let lapsed = ExternalAccessGates {
            approved: true,
            expires_at: Some(past),
        };
        assert!(!lapsed.is_open_at(now));

        // Exactly at the instant is CLOSED — the bound is exclusive, so a
        // reader never has to wonder which side of it they are on.
        let boundary = ExternalAccessGates {
            approved: true,
            expires_at: Some(now),
        };
        assert!(!boundary.is_open_at(now));

        // No expiry stands until cleared.
        let standing = ExternalAccessGates {
            approved: true,
            expires_at: None,
        };
        assert!(standing.is_open_at(now));
    }

    /// An expiry cannot resurrect an approval that was never granted.
    #[test]
    fn expiry_never_opens_an_unapproved_device() {
        let g = ExternalAccessGates {
            approved: false,
            expires_at: Some(DateTime::from_millis(i64::MAX)),
        };
        assert!(!g.is_open_at(DateTime::from_millis(0)));
    }

    /// Wire spellings are what the audit view filters on; a rename here
    /// silently empties a filtered view rather than failing.
    #[test]
    fn deny_reason_wire_strings_are_locked() {
        for (reason, wire) in [
            (ExternalRcDenyReason::NotDeviceAdmin, "not_device_admin"),
            (
                ExternalRcDenyReason::CannotGrantExternal,
                "cannot_grant_external",
            ),
            (
                ExternalRcDenyReason::DeviceUnsupported,
                "device_unsupported",
            ),
        ] {
            assert_eq!(
                serde_json::to_string(&reason).unwrap(),
                format!("\"{wire}\"")
            );
        }
    }

    /// Walks `ALL`, so a variant added without a message shows up here rather
    /// than as an empty string in front of an operator.
    #[test]
    fn every_deny_reason_has_a_message_and_is_listed() {
        for r in ExternalRcDenyReason::ALL {
            assert!(!r.message().is_empty(), "{r:?} has no message");
        }
        // A new variant that was not added to ALL fails to round-trip here.
        let seen: Vec<_> = ExternalRcDenyReason::ALL.to_vec();
        assert_eq!(seen.len(), 3, "ALL must list every variant");
    }

    #[test]
    fn audit_action_wire_strings_are_locked() {
        assert_eq!(
            serde_json::to_string(&ExternalRcAuditAction::Approve).unwrap(),
            "\"approve\""
        );
        assert_eq!(
            serde_json::to_string(&ExternalRcAuditAction::RotateCode).unwrap(),
            "\"rotate_code\""
        );
        assert_eq!(
            serde_json::to_string(&ExternalRcAuditAction::Login).unwrap(),
            "\"login\""
        );
        assert_eq!(
            serde_json::to_string(&ExternalRcAuditAction::Session).unwrap(),
            "\"session\""
        );
    }

    /// A refusal row must not carry grant-only fields — the reason the SSH
    /// audit builds its row from `outcome.as_ref().ok()` rather than from the
    /// request.
    #[test]
    fn a_refusal_row_serialises_without_the_grant_fields() {
        let ev = ExternalRcAuditEvent {
            id: None,
            tenant_id: ObjectId::new(),
            action: ExternalRcAuditAction::Approve,
            agent_id: ObjectId::new(),
            user_id: ObjectId::new(),
            actor: "alex".into(),
            approved: None,
            max_permissions: None,
            expires_at: None,
            at: DateTime::now(),
            denied: Some(ExternalRcDenyReason::NotDeviceAdmin),
            attempt_id: None,
            login_refused: None,
            login_detail: None,
            session_id: None,
        };
        let json = serde_json::to_value(&ev).unwrap();
        assert!(json.get("approved").is_none());
        assert!(json.get("max_permissions").is_none());
        assert!(json.get("expires_at").is_none());
        assert_eq!(json["denied"], "not_device_admin");
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tunnel audit
// ────────────────────────────────────────────────────────────────────────────

/// What happened. Drives the audit-log roll-up + the admin search
/// view in T4. Wire form is snake_case for consistency with every
/// other enum in this module. Distinct from the existing
/// `AuditKind` (remote-control sessions) — different collection,
/// different concerns, different consumers.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TunnelAuditKind {
    /// WebRTC peer was opened (one per `tunnel forward` invocation).
    PeerOpen,
    /// WebRTC peer was torn down (Ctrl-C, idle-timeout, etc.).
    PeerClose,
    /// `TcpForwardRequest` was allowed and the agent dialed dst
    /// successfully. Has flow_id + dst_host + dst_port set.
    TcpAccept,
    /// `TcpForwardRequest` was denied — by the server-side ACL gate
    /// OR by the agent's belt-and-suspenders allowlist. Reason +
    /// `RejectKind` carried in the `reason` field.
    TcpReject,
    /// Agent tried to dial dst, got a hard failure (timeout / refused
    /// / dns). Separate from `TcpReject` so the dashboard can
    /// distinguish "policy denied" from "network broken".
    TcpDialFailed,
    /// Flow closed cleanly or via I/O error.
    TcpClosed,
    /// Per-policy concurrency or byte ceiling hit.
    RateLimited,
    /// WS revocation re-check fired mid-session (admin set
    /// `Quarantined` or soft-deleted the row).
    StatusRevoke,
}

/// Which relay path the peer connection ended up using. Direct =
/// UDP hole punch worked; TurnUdp/Tcp = went through coturn (counts
/// against our bandwidth bill). Set on `PeerOpen` once ICE finishes
/// gathering, repeated on `PeerClose` for easy aggregation.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayMode {
    Direct,
    TurnUdp,
    TurnTcp,
}

/// Append-only audit event. One row per interesting happening, keyed
/// by `tunnel_session_id` so a single session reconstruct is
/// `find({tunnel_session_id: …}).sort({at: 1})`. 90 d TTL — see
/// `crates/db/src/indexes.rs::tunnel_audit`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TunnelAuditEvent {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    /// Correlation key — every event for one peer lifetime shares
    /// this id. New ObjectId per `tunnel forward` invocation.
    pub tunnel_session_id: ObjectId,
    /// The originating tunnel-CLIENT row, set when a dedicated
    /// `roomler` client opened this session. `None` for an
    /// agent-originated session (P3b-2), where `origin_agent_id` is set
    /// instead. Exactly one of `tunnel_client_id` / `origin_agent_id`
    /// is populated. Optional (not a bare `ObjectId`) since P3b-2 —
    /// old rows carry a bare id which still deserialises into `Some`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_client_id: Option<ObjectId>,
    /// The originating AGENT, set when an enrolled agent drove the
    /// tunnel-client role over its own WS (P3b-2). `None` for a
    /// dedicated-client session. `agent_id` below is always the TARGET
    /// of the tunnel, regardless of origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_agent_id: Option<ObjectId>,
    pub agent_id: ObjectId,
    pub user_id: ObjectId,
    pub at: DateTime,
    pub kind: TunnelAuditKind,
    /// Set for per-flow events (TcpAccept / TcpReject /
    /// TcpDialFailed / TcpClosed / RateLimited); None for
    /// peer-lifetime events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<u16>,
    #[serde(default)]
    pub bytes_in: u64,
    #[serde(default)]
    pub bytes_out: u64,
    /// Inferred proxy for "amount of activity" — packet count proxy
    /// (DC messages received). Helps distinguish bulk transfer from
    /// interactive sessions in the dashboard.
    #[serde(default)]
    pub message_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u32>,
    pub relay: RelayMode,
    /// Source IP of the tunnel client's WS connection (from
    /// X-Forwarded-For on the WS upgrade). Forensic baseline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_src_ip: Option<String>,
    /// Source port on the agent's outgoing TCP socket — lets the DB's
    /// own audit log be correlated with this row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_src_port: Option<u16>,
    pub client_version: String,
    pub client_os: OsKind,
    /// Free-form reason field (e.g. `"acl_denied: no matching policy"`,
    /// `"dial: connection refused"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// FR-90 P3-7-2a — the agent SESSION whose own flows this tunnel
    /// carries, under a grant the vault signed. `origin_agent_id` is then
    /// the device it runs on, and `user_id` the session's owner. `None`
    /// for every tunnel that carries a device's or a person's flows, and in
    /// every row from before P3-7-2a.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<ObjectId>,
    /// FR-90 P3-7-2a — the grant's id, as the vault recorded its allow
    /// (`vault_audit`, target `grant:<id>`). Set with `session_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
}

impl TunnelAuditEvent {
    pub const COLLECTION: &'static str = "tunnel_audit";
}

// ────────────────────────────────────────────────────────────────────────────
// Fleet-RPC audit
// ────────────────────────────────────────────────────────────────────────────

/// The result of one remote command — the Hub's currency, the HTTP response
/// body, and the payload of the cross-pod `exec.dispatch` reply. Mirrors
/// `ClientMsg::RpcResult` minus the correlation id.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecOutcome {
    /// `None` when the command never ran or was killed — see
    /// [`Self::error`]. A caller must be able to tell that apart from
    /// "ran and exited 0".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Already redacted + capped by the agent.
    #[serde(default)]
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// FR-94 — the account the command ran as, as the runner itself reports
    /// it: `system` or `console_user` from a Windows device's SYSTEM
    /// service. `None` from every worker, and from any agent before FR-94.
    /// The audit's own `ran_as` is the server's routing decision. This is
    /// the device's claim beside it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ran_as: Option<String>,
}

/// Why an exec request was refused. `None` on the audit row means it ran.
///
/// Every denial is recorded — a refused exec is the interesting one, and
/// without it a probing caller leaves no trace.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecDenyReason {
    /// Gate 1 — the org's `remote_exec_enabled` kill-switch is off.
    OrgDisabled,
    /// Gate 2 — the caller lacks `EXEC_DEVICE`.
    NoPermission,
    /// Gate 3 — the target device's [`ExecPolicy::mode`] is `Off`.
    DeviceDisabled,
    /// Gate 3 — the caller isn't in the device's allowed users/roles.
    CallerNotAllowed,
    /// Gate 3 — the requested shell isn't in the device's allowed list.
    ShellNotAllowed,
    /// The CLI origin device isn't blessed with `can_originate`.
    OriginNotAllowed,
    /// The agent doesn't advertise the `exec` RPC capability.
    Unsupported,
    /// The device is offline.
    Offline,
    /// The operator denied the consent prompt (or it timed out).
    ConsentDenied,
    /// Per-(user, device) rate limit.
    RateLimited,
    /// Gate 4 — the agent's own `exec_enabled` config key is false. Reported
    /// by the agent rather than decided server-side.
    AgentDisabled,
    /// FR-94 — the org requires Windows commands to run as SYSTEM
    /// (`exec_require_system`), and this Windows device does not offer
    /// `exec-system`: no administrator anchored it, or its service is down.
    /// Refused rather than run as the signed-in user.
    SystemRequired,
    /// FR-94 — a device's SYSTEM service tried to claim a command that is not
    /// pending for it: unknown, already claimed, expired, or another
    /// device's. Nothing ran. Recorded because a forged or replayed doorbell
    /// is exactly what this refusal is for (FR-94 AC4).
    ClaimRefused,
    /// FR-94 P4 — the device's policy runs commands as the signed-in user
    /// (`ExecRunAs::ConsoleUser`), which only its SYSTEM service can do, and
    /// this command cannot take that path (not anchored, or the service is
    /// down). Refused rather than run as whatever the worker is: in
    /// SystemContext mode that would be SYSTEM, the opposite of the policy.
    /// FR-97 P5a: on Linux and macOS, the agent connected does not advertise
    /// `console-user`, and would run the command as root.
    RunAsUnavailable,
}

/// Why a roomler-SSH grant was refused. The twin of [`ExecDenyReason`]; kept
/// separate so the two features' reasons cannot drift into each other's
/// vocabulary as they diverge (SSH grows account modes and session limits that
/// mean nothing to exec).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SshDenyReason {
    /// Gate 1 — the org's `remote_ssh_enabled` kill-switch is off.
    OrgDisabled,
    /// Gate 2 — the caller lacks `SSH_DEVICE`.
    NoPermission,
    /// Gate 3 — the target device's [`SshPolicy::mode`] is `Off`.
    DeviceDisabled,
    /// Gate 3 — the caller isn't in the device's allowed users/roles.
    CallerNotAllowed,
    /// The originating device isn't blessed with `can_originate`.
    OriginNotAllowed,
    /// The agent doesn't advertise the `ssh` RPC capability — an older build,
    /// or one compiled without the `ssh-server` feature.
    Unsupported,
    /// The device is offline.
    Offline,
    /// The device is on the mesh but has no overlay address to dial, so there
    /// is nowhere to send the caller even though every gate passed.
    NoOverlayAddress,
    /// Per-(user, device) rate limit.
    RateLimited,
    /// The caller offered something other than a usable ed25519 public key.
    BadPublicKey,
    /// FR-83 — gate 4: the device's own `ssh_enabled` is off. Reported BY the
    /// device (in `rc:ssh.grant_ack`), the twin of
    /// [`ExecDenyReason::AgentDisabled`]. Before the ack existed this refusal
    /// lived only in the device's log, and the caller was told to dial a port
    /// that nothing intercepts when SSH is off — a bare `Connection refused`.
    AgentDisabled,
    /// FR-83 — the grant had already expired when the device received it:
    /// the device's clock is ahead of the server's, or its control connection
    /// is slower than the grant's whole life.
    GrantExpiredOnArrival,
    /// FR-83 — the device refused the grant for a reason with no dedicated
    /// variant (an unusable key, or a reason newer than this server).
    GrantRefused,
    /// FR-83 — the device did not confirm the grant within
    /// [`ssh_limits::GRANT_ACK_TIMEOUT_SECS`]. The caller is refused rather
    /// than told to dial: the one thing known at that moment is that the
    /// device has NOT confirmed, and "dial here" is the answer that produced
    /// `Permission denied (publickey)` in #1597.
    GrantUnconfirmed,
    /// FR-105 — a device's SYSTEM service tried to claim a grant that is not
    /// pending for it: unknown, claimed already, withdrawn, past its window,
    /// or another device's. Not told apart, so a forged ring learns nothing.
    /// Audited with no user: the device's service asked, not a person.
    ClaimRefused,
    /// FR-90 P3-8-1b — an agent session's request carried a ticket that does
    /// not hold: not one this server signed, ended, for another organization,
    /// device or target, or naming an account the target's policy no longer
    /// maps. Never served as the owner's request instead.
    TicketRefused,
    /// FR-90 P3-8-1b — gate 3 for an agent session: no SSH policy names
    /// sessions yet (decision 22), so none admits one.
    SessionNotAllowed,
    /// FR-90 P3-8-1b — the target does not advertise `ssh-one-command`, so it
    /// could not hold an agent session's grant to one command.
    TargetTooOld,
}

impl SshDenyReason {
    /// One line an operator can act on. Deliberately names WHICH gate said no:
    /// "denied" without a reason turns a five-second config fix into a
    /// support ticket.
    pub fn message(self) -> &'static str {
        match self {
            Self::OrgDisabled => {
                "roomler SSH is disabled for this organization (an admin must enable it)"
            }
            Self::NoPermission => "you do not have the SSH_DEVICE permission in this organization",
            Self::DeviceDisabled => "this device does not accept SSH sessions (its policy is off)",
            Self::CallerNotAllowed => "this device's policy does not list you as an allowed caller",
            Self::OriginNotAllowed => {
                "the device you are calling from is not permitted to originate SSH sessions"
            }
            Self::Unsupported => {
                "this device's agent does not support roomler SSH (needs a build with the \
                 ssh-server feature)"
            }
            Self::Offline => "the device is offline",
            Self::NoOverlayAddress => {
                "the device has no overlay address — it is not on the mesh right now"
            }
            Self::RateLimited => "too many SSH requests for this device; try again shortly",
            Self::BadPublicKey => "the session public key is missing or not a usable ed25519 key",
            Self::AgentDisabled => {
                "roomler SSH is switched off on the device itself (its own ssh_enabled \
                 setting) — only someone with access to that device can turn it on"
            }
            Self::GrantExpiredOnArrival => {
                "the grant had already expired when the device received it — the \
                 device's clock is probably ahead of the server's by a minute or more"
            }
            Self::GrantRefused => {
                "the device refused the session grant — its own log (`roomler logs \
                 --grep ssh:` on that device) says why"
            }
            Self::GrantUnconfirmed => {
                "the device did not confirm the grant within 10 s — its connection to \
                 the server may be slow or stale; try again, or check it with \
                 `roomler exec`"
            }
            Self::ClaimRefused => {
                "the device's SYSTEM service claimed a grant that was not pending for \
                 it (unknown, already claimed, withdrawn, expired or another device's)"
            }
            Self::TicketRefused => {
                "the agent session's SSH ticket does not hold for this request (ended, \
                 for another device or target, or the target's account changed)"
            }
            Self::SessionNotAllowed => "no SSH policy on this device admits agent sessions",
            Self::TargetTooOld => {
                "this device's agent cannot hold an agent session to one command (needs a \
                 build that advertises ssh-one-command)"
            }
        }
    }
}

/// FR-83 — why a device refused an `rc:ssh.grant`, carried back to the server
/// in `rc:ssh.grant_ack` (see [`crate::signaling::ClientMsg::SshGrantAck`]).
///
/// Absent from the ack = RECORDED: the grant is in the table the device's
/// auth path reads, and the caller may dial. Present = the grant will never
/// be honoured, and [`Self::deny_reason`] is what the caller is told.
///
/// ⚠️ Decoded LENIENTLY on the ack (`grant_refusal_lenient` in `signaling`):
/// an unknown spelling from a newer agent lands on [`Self::Other`] — still a
/// refusal. Strict decoding would fail the whole frame, the server would drop
/// it at `debug!`, and a clear refusal would turn into `grant_unconfirmed`
/// after the full wait. It must never land on "recorded" either: that would
/// tell a caller to dial a device that has just said no.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SshGrantRefusal {
    /// Gate 4 — the device's own `ssh_enabled` is off.
    SshDisabled,
    /// The grant arrived past its deadline.
    Expired,
    /// The device could not use what the server had validated.
    Invalid,
    /// A reason this build does not know.
    Other,
}

impl SshGrantRefusal {
    /// The refusal the CALLER is answered with.
    pub fn deny_reason(self) -> SshDenyReason {
        match self {
            Self::SshDisabled => SshDenyReason::AgentDisabled,
            Self::Expired => SshDenyReason::GrantExpiredOnArrival,
            Self::Invalid | Self::Other => SshDenyReason::GrantRefused,
        }
    }
}

/// One remote-execution attempt. Written on EVERY attempt, allowed or denied.
/// TTL-expired after 90 days like [`RemoteAuditEvent`].
///
/// `stdout` / `stderr` here are the REDACTED, truncated samples — the agent
/// sweeps its output for the agent token, `Bearer …`, and JWT-shaped strings
/// before anything leaves the host, so a secret echoed by a command never
/// reaches this collection.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExecAuditEvent {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    /// The device the command was aimed at.
    pub agent_id: ObjectId,
    /// The acting principal. For a CLI-originated request this is the
    /// originating device's `owner_user_id`.
    pub user_id: ObjectId,
    /// Set when the request came from a device's LocalAPI (`roomler exec`)
    /// rather than an authenticated HTTP caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_agent_id: Option<ObjectId>,
    /// Correlates the audit row with the wire `request_id`.
    pub request_id: String,
    /// `cli` | `ui` | `api`.
    pub source: String,
    pub shell: String,
    /// The command verbatim, as submitted.
    pub command: String,
    pub at: DateTime,
    /// `None` when the request never ran (see [`Self::denied`]) or the agent
    /// failed to report one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Refusal reason; `None` = the command ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denied: Option<ExecDenyReason>,
    /// Redacted, truncated output sample (both streams, capped).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub output_sample: String,
    /// SHA-256 of the full redacted output, so a truncated sample can still
    /// be tied to what actually ran.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub output_sha256: String,
    #[serde(default)]
    pub output_bytes: u64,
    #[serde(default)]
    pub truncated: bool,
    /// FR-94 — the identity the server routed the command to:
    /// - `system` (a Windows device's SYSTEM service);
    /// - `console_user` (the same service, as the signed-in user);
    /// - `worker` (the agent's own process, as before FR-94: root under
    ///   systemd, the signed-in user on an attended Windows install).
    ///
    /// `None` on a refusal, and on every row written before FR-94. The
    /// device's own report rides in the outcome beside it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ran_as: Option<String>,
}

impl ExecAuditEvent {
    pub const COLLECTION: &'static str = "exec_audit";
    /// Cap on the persisted output sample. Keeps a busy fleet's audit
    /// collection bounded while retaining enough to read at a glance.
    pub const SAMPLE_BYTES: usize = 4096;
}

/// FR-94 — the record that an administrator anchored a Windows device for
/// SYSTEM exec ([`Agent::exec_anchor`]). It is what the admin UI shows as the
/// device's exec identity. Re-anchoring overwrites it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ExecAnchor {
    pub anchored_at: DateTime,
    /// The administrator who issued the enrollment token used to anchor.
    pub anchored_by: ObjectId,
    /// Names this anchor in the service credential it minted. A credential
    /// is accepted only while its `anchor_id` equals this one, so
    /// re-anchoring (a new id) revokes every credential an earlier anchor
    /// minted. One live anchor per device, as a WireGuard key has one live
    /// node. Empty on a row that predates the field, which no credential
    /// can match.
    #[serde(default)]
    pub anchor_id: String,
}

/// FR-94 — one Fleet RPC routed to a Windows device's SYSTEM service, from
/// the dispatch that writes it to the result the service posts. The command
/// lives HERE, not in the doorbell. The worker rings the service with the
/// request id alone, and the service claims these fields from the server
/// with its own credential, so nothing the signed-in user can write decides
/// what SYSTEM runs (FR-94 §4). Shared through Mongo because a claim and a
/// result can land on any pod, while the caller waits on the pod that holds
/// the device's socket.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExecPending {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub request_id: String,
    pub tenant_id: ObjectId,
    pub agent_id: ObjectId,
    pub shell: String,
    pub command: String,
    pub timeout_ms: u64,
    pub max_output_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// The acting principal's display name, as `rc:rpc.exec` carries it.
    pub caller: String,
    /// `system` or `console_user` (FR-94 P4).
    pub run_as: String,
    /// [`ExecPending::PENDING`] → [`ExecPending::CLAIMED`] →
    /// [`ExecPending::DONE`].
    pub state: String,
    pub created_at: DateTime,
    /// A claim at or after this instant is refused. It is the caller's own
    /// deadline: once nobody waits for the answer, nothing may run.
    pub claim_by: DateTime,
    /// The TTL monitor deletes the row after this. It is later than
    /// `claim_by`, so a result that arrives late still finds its row.
    pub expires_at: DateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_at: Option<DateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<ExecOutcome>,
}

impl ExecPending {
    pub const COLLECTION: &'static str = "exec_pending";
    pub const PENDING: &'static str = "pending";
    pub const CLAIMED: &'static str = "claimed";
    pub const DONE: &'static str = "done";
    /// Withdrawn by the caller (`…/exec/{request_id}/cancel`) before a claim.
    pub const CANCELLED: &'static str = "cancelled";
}

/// One roomler-SSH session REQUEST. Written on every attempt, granted or
/// refused. TTL-expired after 90 days like [`ExecAuditEvent`].
///
/// **This records the DECISION, not the session.** The server's involvement
/// ends when it hands back an address and a grant — the session itself rides
/// the overlay directly between the caller and the device, and the server
/// never observes it. So a row here means "a grant was issued", never "a
/// session happened", and there is deliberately no duration, exit code or
/// output: the design that keeps the server out of the data path is the same
/// design that stops it from auditing the data path. What lands on the DEVICE
/// (which grant authenticated, as whom, when) is the device's own log.
///
/// The refused rows are the load-bearing ones. Without them, someone probing
/// which devices will let them in leaves no trace at all — which is why every
/// exit from `agent_ssh::dispatch` funnels through one audit write rather than
/// each refusal site remembering to log itself.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SshAuditEvent {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    /// The device the session was aimed at.
    pub agent_id: ObjectId,
    /// The acting principal. For a device-originated request this is the
    /// originating device's `owner_user_id`.
    pub user_id: ObjectId,
    /// Set when the request came from a device's LocalAPI rather than an
    /// authenticated HTTP caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_agent_id: Option<ObjectId>,
    /// The minted grant, absent on refusal. Correlates this row with the
    /// device-side log line that redeemed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    /// `cli` (device LocalAPI leg) | `api` (authenticated HTTP caller) |
    /// (FR-90 P3-8-1b) `session` (an agent session's request, with its ticket).
    pub source: String,
    /// FR-90 P3-8-1b — the agent session that asked, once its ticket held:
    /// the acting principal then, with `user_id` the person it acts for.
    /// Absent on every other row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<ObjectId>,
    /// FR-90 P3-8-1b — the vault's ticket the session presented, by its id
    /// (`ticket:<id>` in `vault_audit`). Absent on every other row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_ticket_id: Option<String>,
    /// Display name of the principal, as it was pushed to the device.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub caller: String,
    /// Which identity the grant authorised — the field that makes this log
    /// worth reading, since it is the difference between a shell as the
    /// console user and a shell as SYSTEM/root. Absent on refusal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_mode: Option<String>,
    /// Bound placed on the session, in seconds. Absent on refusal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_secs: Option<u64>,
    pub at: DateTime,
    /// Refusal reason; `None` = a grant was issued.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denied: Option<SshDenyReason>,
    /// FR-105 — the server's decision about WHO serves the session: `system`
    /// or `console_user` (the device's SYSTEM service), or `worker` (the
    /// device's console-session process, which on an attended Windows
    /// install is the signed-in user). Absent on refusal and on every row
    /// written before FR-105.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ran_as: Option<String>,
}

impl SshAuditEvent {
    pub const COLLECTION: &'static str = "ssh_audit";
}

/// FR-105 — an SSH grant routed to a Windows device's SYSTEM service, between
/// the decision that writes it and the service's claim. The service PULLS the
/// grant with its own credential; the worker, which the signed-in user
/// controls, only ever relays its id.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SshPending {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub grant_id: String,
    pub tenant_id: ObjectId,
    pub agent_id: ObjectId,
    /// The caller's ephemeral OpenSSH public key.
    pub public_key: String,
    /// The acting principal's display name, as `rc:ssh.grant` carries it.
    pub caller: String,
    /// `daemon` (SYSTEM) or `console_user`.
    pub account_mode: String,
    pub expires_at_ms: u64,
    pub session_secs: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_mode: Option<ConsentMode>,
    /// FR-90 P3-8-1b — an agent session's grant: the SYSTEM service holds it
    /// to one `exec`, as `rc:ssh.grant`'s `one_command` says. False on every
    /// other row.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub one_command: bool,
    /// [`SshPending::PENDING`] → [`SshPending::CLAIMED`], or
    /// [`SshPending::CANCELLED`] when the caller stopped waiting first.
    pub state: String,
    pub created_at: DateTime,
    /// A claim at or after this instant is refused: the caller has stopped
    /// waiting, and a grant nobody will dial must not be redeemable.
    pub claim_by: DateTime,
    /// The TTL monitor deletes the row after this.
    pub expires_at: DateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_at: Option<DateTime>,
}

impl SshPending {
    pub const COLLECTION: &'static str = "ssh_pending";
    pub const PENDING: &'static str = "pending";
    pub const CLAIMED: &'static str = "claimed";
    pub const CANCELLED: &'static str = "cancelled";
}

/// A desired-config write, granted or refused (`docs/remote-config.md`).
///
/// The refused rows are the point, as in [`SshAuditEvent`]: an admin probing
/// which devices they can open exec on should not be able to do so silently.
///
/// ⚠️ A row records what was **ASKED FOR**, not what the device did. The
/// device may be offline, may not have opted in, and may refuse — so reading
/// these to answer "does this device have exec on?" is wrong in the same way
/// reading `ssh_audit` to answer "how long was that session?" is wrong. The
/// device's own heartbeat is the only truth for applied state.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConfigAuditEvent {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    /// The device the change was aimed at.
    pub agent_id: ObjectId,
    /// Who asked.
    pub user_id: ObjectId,
    pub at: DateTime,
    /// The requested state. Serialised whole so the row explains itself
    /// without a join against a row that has since been overwritten.
    pub requested: DesiredConfig,
    /// `None` on a granted write; the [`ConfigDenyReason`] wire string on a
    /// refusal.
    ///
    /// [`ConfigDenyReason`]: https://docs.rs/  (api crate, routes::remote_config)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denied: Option<String>,
}

impl ConfigAuditEvent {
    pub const COLLECTION: &'static str = "config_audit";
}

/// FR-40 — a key-rotation order, dispatched or refused. The SERVER's own
/// decision (authoritative), as opposed to the device's
/// [`KeyRotationReport`] (a claim). Same discipline as [`ConfigAuditEvent`]:
/// both arms land here from ONE call site, so a new refusal cannot forget to
/// audit itself, and a row records what was ORDERED, never what the device
/// did with it.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyRotationAuditEvent {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    pub agent_id: ObjectId,
    /// Who asked.
    pub user_id: ObjectId,
    pub at: DateTime,
    pub request_id: String,
    /// `pushed` (a live socket took it) or `queued` (the device was offline
    /// and will be ordered on connect). `None` on a refusal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispatch: Option<String>,
    /// The refusal's wire string; `None` when the order went out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denied: Option<String>,
}

impl KeyRotationAuditEvent {
    pub const COLLECTION: &'static str = "key_rotation_audit";
}

/// What a device reported doing inside an SSH session (P8).
///
/// Deliberately coarse. Recording session CONTENT — a pty byte stream — would
/// mean shipping whatever the operator typed, including passwords typed into
/// `sudo` or `mysql -p`, off the host and into the server, which is the exact
/// property [`SshAuditEvent`]'s doc says this system does not have. These
/// answer "what was run", not "what was on the screen".
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SshActivityKind {
    /// A session authenticated. The envelope for everything that follows.
    SessionOpen,
    /// A session ended.
    SessionClose,
    /// A one-shot `ssh <node> <cmd>`. `detail` is the command, `exit_code`
    /// its status.
    Exec,
    /// An interactive shell started. **Its contents are not recorded** — this
    /// row exists so a reader can see that a shell happened at all.
    Shell,
    /// The SFTP subsystem started. File operations happen inside
    /// `sftp-server` and are not visible here.
    Sftp,
    /// A `direct-tcpip` forward was requested. `detail` is `host:port`,
    /// `allowed` says whether the device's `forward_acl` permitted it.
    Forward,
}

/// One thing a device reported doing inside an SSH session (P8).
///
/// ⚠️ **These rows are REPORTED BY THE DEVICE, not observed by the server** —
/// which is why they live in their own collection rather than alongside
/// [`SshAuditEvent`]. An audit row is the server's own decision and is
/// authoritative; an activity row is a claim by a host that could be
/// compromised or simply have reporting switched off. Mixing them would leave
/// a reader unable to tell which is which.
///
/// ⚠️ **Absence of rows is not evidence of inactivity.** A device with
/// `ssh_activity_log = false` (the default) reports nothing at all, and that
/// is indistinguishable from a device nobody used. Read this log together
/// with `ssh_audit`, which records every *grant* regardless of what the device
/// chooses to say afterwards.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SshActivityEvent {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    /// From the authenticated WS, never from the frame — a device must not be
    /// able to write rows against another tenant.
    pub tenant_id: ObjectId,
    /// Likewise from the connection: the device doing the reporting.
    pub agent_id: ObjectId,
    /// Correlates with the [`SshAuditEvent`] that authorised the session, and
    /// therefore with the authoritative `user_id`. `None` for a key-list
    /// session, which no grant backs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    /// Principal as the DEVICE saw it. Unverified; join on `grant_id` for the
    /// server's own record of who asked.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub caller: String,
    pub kind: SshActivityKind,
    /// The command for `Exec`, `host:port` for `Forward`. Redacted and
    /// length-capped on the device before it leaves the host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// `false` when the DEVICE refused the action — a forward its
    /// `forward_acl` did not permit. Those are the rows worth reading.
    pub allowed: bool,
    /// Stamped by the SERVER. A device clock is not evidence.
    pub at: DateTime,
}

/// FR-85 P3 — what a device reports about a REMOTE recording.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecordingActivityKind {
    /// The host allowed the recording at the just-in-time prompt.
    PromptGranted,
    /// The host refused it.
    PromptDenied,
    /// Nobody answered the prompt.
    PromptTimedOut,
    /// The recorder is writing (after the indicator went up).
    Started,
    /// The file is final. `reason` is the stop reason, `bytes` and
    /// `duration_ms` what was recorded.
    Stopped,
    /// The device refused to start: `reason` names why (the gate is off, no
    /// indicator surface, an encoder or disk problem, …).
    Refused,
    /// The controller downloaded a recording (`name`, `bytes`).
    Downloaded,
    /// P3b-3 — the recording's own session dropped, and it continued on a
    /// new session of the SAME controller within the re-attach grace.
    /// Reported on the new session; the `Started` on the old one says where
    /// it began. An older server that does not know the word drops just this
    /// report.
    Reattached,
}

/// FR-85 P3 — one thing a device reported about a remote recording.
///
/// ⚠️ **REPORTED BY THE DEVICE, not observed by the server** — the same split
/// as [`SshActivityEvent`] vs [`SshAuditEvent`]. The server's own decision (was
/// `RECORD` granted, and if not why) lives in `remote_audit`'s
/// `SessionRequested`; this is the host's claim about what then happened.
/// Never content: no frames, no window titles — only the fact, sizes and
/// reasons.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RecordingActivityEvent {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    /// From the authenticated WS, never from the frame.
    pub tenant_id: ObjectId,
    pub agent_id: ObjectId,
    pub session_id: ObjectId,
    /// The controller the live session belongs to — the SERVER's record of
    /// who was recording, not the device's.
    pub controller_user_id: ObjectId,
    pub kind: RecordingActivityKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Stamped by the SERVER. A device clock is not evidence.
    pub at: DateTime,
}

impl RecordingActivityEvent {
    pub const COLLECTION: &'static str = "recording_activity";

    /// Longest `name` / `reason` a device may report: both are free text from
    /// a host that may be compromised, and an unbounded one would let a
    /// session bloat the collection.
    pub const MAX_TEXT: usize = 256;
}

/// FR-101 P3 — which transfer a [`TransferActivityEvent`] is about.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransferActivityKind {
    /// Writes the controller made to the host's clipboard during one sample
    /// window: `count` of them, `bytes` in all.
    ClipboardToHost,
    /// Clipboard content the host sent the controller during one sample
    /// window: reads it asked for, and changes pushed to a subscribed viewer.
    ClipboardFromHost,
    /// One file the controller sent to the host.
    FileToHost,
    /// One file the host sent the controller.
    FileFromHost,
}

/// FR-101 P3 — clipboard and file traffic a device reported for a remote
/// session.
///
/// ⚠️ **REPORTED BY THE DEVICE, not observed by the server**, the same split
/// as [`RecordingActivityEvent`] and [`SshActivityEvent`]. The traffic itself
/// travels peer to peer, so the server never sees a transfer, only the host's
/// account of it. The grant that allowed it (`CLIPBOARD`, `FILES`) is the
/// server's own record, in `remote_audit`. An empty result is therefore not
/// proof that nothing crossed: a compromised host can stay silent, and a
/// session that dies with the control WS loses its last sample.
///
/// Never content and never a file name: counts, sizes, and a hash of the
/// name, so that transfers of one file can be told apart from many.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransferActivityEvent {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    /// From the authenticated WS, never from the frame.
    pub tenant_id: ObjectId,
    pub agent_id: ObjectId,
    pub session_id: ObjectId,
    /// The controller the session belongs to: the SERVER's record of who was
    /// connected, not the device's.
    pub controller_user_id: ObjectId,
    pub kind: TransferActivityKind,
    /// A clipboard row counts its window's transfers; a file row is one.
    pub count: u64,
    pub bytes: u64,
    /// File rows only: SHA-256 of the file's name, lowercase hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_sha256: Option<String>,
    /// Stamped by the SERVER. A device clock is not evidence.
    pub at: DateTime,
}

impl TransferActivityEvent {
    pub const COLLECTION: &'static str = "transfer_activity";

    /// Files one sample may list. A host that may be compromised must not be
    /// able to bloat the collection with one frame; an honest one completes
    /// nowhere near this many in a 30 s window.
    pub const MAX_FILES_PER_SAMPLE: usize = 256;

    /// Is `s` a SHA-256 in lowercase hex? Anything else a device sends as a
    /// name hash is dropped: free text there would let a host store the very
    /// name the hash exists to keep out.
    pub fn is_name_hash(s: &str) -> bool {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
}

/// FR-99 P1d — what a [`PrivacyActivityEvent`] says happened to a session's
/// curtain.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyActivityKind {
    /// The curtain went up, verified out of capture.
    On,
    /// The curtain came down. `reason` says why: `controller` (the viewer
    /// turned it off), `session_end`, `disabled_on_device` (the owner switched
    /// privacy mode off), or `worker_exit` (the process that drew it died with
    /// it up, reported by the next one to start).
    Off,
    /// The device refused to put it up: `disabled_on_device`, `unavailable`
    /// or `no_curtain`, the device's gates in `docs/privacy-mode.md`.
    Refused,
}

/// FR-99 P1d — the device's account of privacy mode in one remote session.
///
/// ⚠️ **REPORTED BY THE DEVICE, not observed by the server**, the same split
/// as [`RecordingActivityEvent`] and [`TransferActivityEvent`]. The curtain is
/// drawn on the host and the request to raise it travels peer to peer, so the
/// server sees neither. The grant that allowed it (`PRIVACY`), or the strip
/// and its reason, is the server's own record, in `remote_audit`'s
/// `SessionRequested`. An empty result is therefore not proof that no curtain
/// went up: a compromised host can stay silent.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PrivacyActivityEvent {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    /// From the authenticated WS, never from the frame.
    pub tenant_id: ObjectId,
    pub agent_id: ObjectId,
    pub session_id: ObjectId,
    /// The controller the session belongs to: the SERVER's record of who was
    /// connected, not the device's.
    pub controller_user_id: ObjectId,
    pub kind: PrivacyActivityKind,
    /// A reason code (see [`PrivacyActivityKind`]), or nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Stamped by the SERVER. A device clock is not evidence.
    pub at: DateTime,
}

impl PrivacyActivityEvent {
    pub const COLLECTION: &'static str = "privacy_activity";

    /// Is `s` a reason code: 1 to 64 of `a-z`, `0-9` and `_`? Every reason the
    /// agent sends is one. Anything else a device reports is dropped (the row
    /// is kept without it): free text there would let a host that may be
    /// compromised write what it likes into the audit.
    pub fn is_reason_code(s: &str) -> bool {
        (1..=64).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    }
}

impl SshActivityEvent {
    pub const COLLECTION: &'static str = "ssh_activity";

    /// Longest `detail` a device may report. A command line is the only
    /// attacker-influenced field here, and an unbounded one would let a single
    /// session bloat the collection.
    pub const MAX_DETAIL: usize = 512;
}

// ────────────────────────────────────────────────────────────────────────────
// Session
// ────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionPhase {
    Pending,
    AwaitingConsent,
    Negotiating,
    Active,
    Closed,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    ControllerHangup,
    AgentHangup,
    UserDenied,
    ConsentTimeout,
    /// FR-27 — the device could raise no consent prompt at all: no desktop
    /// session, no companion, no native overlay. Distinct from
    /// [`Self::ConsentTimeout`] because nobody was ever asked, so the useful
    /// advice is "give that host a prompt surface, or pick email/push", not
    /// "try again and answer it".
    NoPromptSurface,
    AgentDisconnect,
    AdminTerminated,
    IdleTimeout,
    Error,
    /// FR-27 P10 — the person AT THE DEVICE ended the session: the banner's
    /// or the badge's Disconnect. Distinct from [`Self::AgentHangup`] (the
    /// agent process gave the session up) and from
    /// [`Self::ControllerHangup`] (the viewer left) because the viewer
    /// treats this one differently: it is told who ended it and does NOT
    /// auto-reconnect. Only the device may claim it — the hub records a
    /// controller's claim as `ControllerHangup`.
    HostDisconnect,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SessionStats {
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub peak_fps: f32,
    pub avg_rtt_ms: f32,
    pub keyframe_requests: u32,
    pub input_events: u64,
    /// P8 Phase 4 — cumulative seconds this session's shared pipeline
    /// served ≥1 follower. `default` so pre-Phase-4 rows deserialize.
    #[serde(default)]
    pub shared_seconds: u64,
    /// … of which the viewers' dials were NOT all equal (the SVC
    /// go/no-go dataset — see the signalling twin's doc).
    #[serde(default)]
    pub mixed_dial_seconds: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RemoteSession {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub agent_id: ObjectId,
    pub tenant_id: ObjectId,
    pub controller_user_id: ObjectId,
    #[serde(default)]
    pub watchers: Vec<ObjectId>,
    /// Names from the `to_document` projection in `audit.rs`, bits from any
    /// typed `insert_one` — a stored field reads both, explicitly (#1630).
    #[serde(deserialize_with = "crate::permissions::deserialize_stored")]
    pub permissions: Permissions,
    pub phase: SessionPhase,
    pub created_at: DateTime,
    pub started_at: Option<DateTime>,
    pub ended_at: Option<DateTime>,
    pub end_reason: Option<EndReason>,
    pub recording_url: Option<String>,
    #[serde(default)]
    pub stats: SessionStats,
    /// FR-102 P9c — the carrier the session rode, as the agent recorded it
    /// once the session reached Active (`direct` · `turn` · `turn_local` ·
    /// `overlay_direct` · `overlay_turn` · `derp` · `org_relay` ·
    /// `unknown`; [`session_carrier_label`]). Set by the live stats merge,
    /// beside `stats` rather than inside it so `mark_ended`'s whole-`stats`
    /// write cannot reset it. **Absent is unknown, never direct**: a row
    /// from before P9c, from an agent older than the field, or from a
    /// session that ended before the observation landed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carrier: Option<String>,
}

impl RemoteSession {
    pub const COLLECTION: &'static str = "remote_sessions";
    /// A session record — who controlled which device, when, for how long,
    /// its stats and the carrier it rode — is kept **25 months** from
    /// `created_at`, then the database deletes it (a TTL index in the `remote`
    /// module). The privacy policy states this retention (§7; operator
    /// decision 2026-10-17). Until then the rows were kept with no bound,
    /// while the policy claimed 90 days. The long-term numbers survive in the
    /// growth aggregates (`growth_org_daily`, `growth_quality_daily`).
    pub const TTL_SECONDS: u64 = 25 * 30 * 24 * 60 * 60;
}

/// FR-102 P9c — the carrier spellings this server knows (the agent's
/// `session_carrier::SessionCarrier::as_str`). For display and grouping
/// only: a spelling a newer agent sends is stored as sent, so an additive
/// vocabulary stays additive.
pub const SESSION_CARRIERS: &[&str] = &[
    "direct",
    "turn",
    "turn_local",
    "overlay_direct",
    "overlay_turn",
    "derp",
    "org_relay",
    "unknown",
];

/// The carrier label a session row may hold: the agent's spelling when it
/// is a short lowercase code, else nothing — the row is left as it was and
/// reads as unknown. A code, never free text: the device is the only writer
/// and a compromised one must not get a string field to fill.
pub fn session_carrier_label(raw: &str) -> Option<&str> {
    ((1..=32).contains(&raw.len())
        && raw
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'))
    .then_some(raw)
}

// ────────────────────────────────────────────────────────────────────────────
// Session feedback (FR-102 P9b)
// ────────────────────────────────────────────────────────────────────────────

/// FR-102 P9b — a thumb.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackRating {
    Up,
    Down,
}

impl FeedbackRating {
    pub fn as_str(self) -> &'static str {
        match self {
            FeedbackRating::Up => "up",
            FeedbackRating::Down => "down",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "up" => Some(FeedbackRating::Up),
            "down" => Some(FeedbackRating::Down),
            _ => None,
        }
    }
}

/// FR-102 P9b — the reason chips, the whole vocabulary (spec §3f). A reason
/// outside it is refused, never stored: there is no free text in v1, because
/// free text is where personal data hides.
pub const FEEDBACK_REASONS: &[&str] = &["lag", "picture", "input", "could_not_connect", "other"];

/// FR-102 P9b — what the viewer posts: the thumb and the chips. Every other
/// key fails the parse (`deny_unknown_fields`), so a comment field cannot be
/// smuggled in by a client that invents one.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionFeedbackRequest {
    pub rating: String,
    #[serde(default)]
    pub reasons: Vec<String>,
}

impl SessionFeedbackRequest {
    /// The body limit on the route: a thumb and five short codes.
    pub const MAX_BODY_BYTES: usize = 1024;

    /// The rating and the reasons, deduplicated in vocabulary order; or the
    /// refusal code.
    pub fn validate(&self) -> Result<(FeedbackRating, Vec<String>), &'static str> {
        let rating = FeedbackRating::parse(&self.rating).ok_or("unknown_rating")?;
        if self.reasons.len() > FEEDBACK_REASONS.len() {
            return Err("too_many_reasons");
        }
        if self
            .reasons
            .iter()
            .any(|r| !FEEDBACK_REASONS.contains(&r.as_str()))
        {
            return Err("unknown_reason");
        }
        let reasons = FEEDBACK_REASONS
            .iter()
            .filter(|r| self.reasons.iter().any(|given| given == *r))
            .map(|r| r.to_string())
            .collect();
        Ok((rating, reasons))
    }
}

/// FR-102 P9b — one person's rating of one remote session, asked by the
/// viewer after a session of 30 s or more (spec §3f, D10: "a thumbs rating
/// after a session now; NPS later").
///
/// One per session **per person** (a unique index on `(session_id,
/// user_id)` — a rating is one person's experience, and the controller and
/// a watcher of one session may have had different ones), resolved within
/// the tenant, posted only by a person who was in the session (its
/// controller or a watcher). `reasons` are codes from [`FEEDBACK_REASONS`];
/// there is no text field. Kept 25 months (the `remote` module's TTL on
/// `ts`) and deleted with the user (`SessionFeedbackDao::purge_user`, the
/// seam an account deletion calls). A self-hosted server keeps its own rows
/// and sends none anywhere.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SessionFeedback {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub session_id: ObjectId,
    pub tenant_id: ObjectId,
    /// Who answered — from the authenticated request, never from the body.
    pub user_id: ObjectId,
    /// The session's device, denormalised from its row for a per-device
    /// read; not a person.
    pub agent_id: ObjectId,
    pub rating: FeedbackRating,
    pub reasons: Vec<String>,
    /// Stamped by the SERVER.
    pub ts: DateTime,
}

impl SessionFeedback {
    pub const COLLECTION: &'static str = "session_feedback";
    /// 25 months (spec §3p), kept in lockstep with the `remote` module's
    /// index plan.
    pub const TTL_SECONDS: u64 = 25 * 30 * 24 * 60 * 60;
    /// A session shorter than this is never rated: the viewer never offers
    /// the prompt before it, and the route refuses a rating posted earlier
    /// than this after the session was requested.
    pub const MIN_SESSION_SECS: i64 = 30;
}

// ────────────────────────────────────────────────────────────────────────────
// FR-111 P4a — the org's on-screen control presets
// ────────────────────────────────────────────────────────────────────────────

/// FR-111 P4a — one of an org's on-screen control presets (spec
/// `docs/fr/FR-111-touch-controls.md` §3d): the viewer's own `TouchPreset`
/// (`ui/src/composables/touchControls.ts`) stored as it is, with who made and
/// last changed it. Every member's viewer runs what is stored here, so it is
/// written only after [`TouchPresetRequest::validate`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TouchPreset {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    /// Unique per org (the `remote` module's unique index).
    pub name: String,
    pub controls: Vec<TouchControl>,
    /// From the authenticated request, never from the body.
    pub created_by: ObjectId,
    pub updated_by: ObjectId,
    /// Stamped by the SERVER.
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

impl TouchPreset {
    pub const COLLECTION: &'static str = "touch_presets";
    /// An org keeps at most this many.
    pub const MAX_PER_TENANT: u64 = 50;
}

/// A control on the overlay: the viewer's `TouchControl`, tagged by `kind`.
/// ⚠️ Unknown fields are refused, so a misspelt key is an error, never a
/// control that quietly does something else.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TouchControl {
    /// Buttons side by side, or stacked (`dir: column`).
    Row {
        id: String,
        at: ControlPlace,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dir: Option<RowDir>,
        buttons: Vec<ButtonControl>,
    },
    /// Four keys under one thumb, two held on a diagonal.
    Dpad {
        id: String,
        label: String,
        at: ControlPlace,
        /// Diameter in CSS pixels.
        size: u16,
        up: u8,
        down: u8,
        left: u8,
        right: u8,
    },
    /// A thumb stick that moves the host's pointer.
    Stick {
        id: String,
        label: String,
        at: ControlPlace,
        size: u16,
        /// Full deflection moves the pointer this share of the picture's
        /// width a second.
        speed: f32,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RowDir {
    Row,
    Column,
}

/// Where a control sits: CSS pixels from the overlay's edges. An axis given
/// no edge is centred, and an axis given both is refused.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct ControlPlace {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub right: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bottom: Option<f32>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ButtonControl {
    pub id: String,
    pub label: String,
    pub action: ControlAction,
}

/// What a button does. `keys` and `mouse` are G1's (held while the finger
/// is down); `macro` is P4's, a sequence the viewer plays once per press.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlAction {
    /// A chord, pressed in order and released in reverse.
    Keys {
        keys: Vec<u8>,
    },
    Mouse {
        btn: TouchMouseBtn,
    },
    Macro {
        steps: Vec<MacroStep>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TouchMouseBtn {
    Left,
    Right,
    Middle,
}

/// One step of a macro: a key or a mouse button, pressed, released or both
/// (`tap`), then a wait before the next step.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MacroStep {
    pub op: MacroOp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub btn: Option<TouchMouseBtn>,
    #[serde(default)]
    pub wait_ms: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MacroOp {
    Press,
    Release,
    Tap,
}

/// The body of `POST` and `PUT /api/tenant/{tid}/touch-preset[/{id}]`: a name
/// and the controls. Unknown keys fail the parse.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TouchPresetRequest {
    pub name: String,
    pub controls: Vec<TouchControl>,
}

/// Is `k` a HID usage the viewer's keyboard path can send: the Keyboard/Keypad
/// page's keys (`0x04..=0xA4`) or its eight modifiers (`0xE0..=0xE7`)?
pub fn touch_key_ok(k: u8) -> bool {
    (0x04..=0xA4).contains(&k) || (0xE0..=0xE7).contains(&k)
}

impl TouchPresetRequest {
    /// The body limit on the routes.
    pub const MAX_BODY_BYTES: usize = 32 * 1024;
    pub const MAX_NAME_CHARS: usize = 48;
    pub const MAX_LABEL_CHARS: usize = 16;
    pub const MAX_ID_CHARS: usize = 32;
    pub const MAX_CONTROLS: usize = 24;
    pub const MAX_ROW_BUTTONS: usize = 12;
    pub const MAX_CHORD_KEYS: usize = 4;
    pub const MAX_MACRO_STEPS: usize = 32;
    pub const MAX_STEP_WAIT_MS: u16 = 5_000;
    pub const MAX_MACRO_MS: u32 = 30_000;
    /// A control's edge offset, in CSS pixels.
    pub const MAX_PLACE_PX: f32 = 4_000.0;
    pub const SIZE_PX: std::ops::RangeInclusive<u16> = 48..=400;
    pub const STICK_SPEED: std::ops::RangeInclusive<f32> = 0.05..=5.0;

    /// The name, trimmed; or the refusal code. Every member's viewer draws and
    /// runs a stored preset, so everything it holds is bounded here: lengths,
    /// counts, pixel ranges, the keys (only what the keyboard path can send),
    /// ids unique within the preset, and a macro's steps and waits.
    pub fn validate(&self) -> Result<String, &'static str> {
        let name = self.name.trim();
        if name.is_empty() {
            return Err("name_empty");
        }
        if !text_ok(name, Self::MAX_NAME_CHARS) {
            return Err("name_invalid");
        }
        if self.controls.is_empty() {
            return Err("no_controls");
        }
        if self.controls.len() > Self::MAX_CONTROLS {
            return Err("too_many_controls");
        }
        let mut ids = std::collections::HashSet::new();
        let mut id = |s: &str| -> Result<(), &'static str> {
            if s.is_empty() || !text_ok(s, Self::MAX_ID_CHARS) {
                return Err("id_invalid");
            }
            if !ids.insert(s.to_string()) {
                return Err("id_duplicate");
            }
            Ok(())
        };
        for c in &self.controls {
            match c {
                TouchControl::Row {
                    id: cid,
                    at,
                    buttons,
                    ..
                } => {
                    id(cid)?;
                    place_ok(at)?;
                    if buttons.is_empty() || buttons.len() > Self::MAX_ROW_BUTTONS {
                        return Err("row_buttons");
                    }
                    for b in buttons {
                        id(&b.id)?;
                        label_ok(&b.label)?;
                        action_ok(&b.action)?;
                    }
                }
                TouchControl::Dpad {
                    id: cid,
                    label,
                    at,
                    size,
                    up,
                    down,
                    left,
                    right,
                } => {
                    id(cid)?;
                    label_ok(label)?;
                    place_ok(at)?;
                    if !Self::SIZE_PX.contains(size) {
                        return Err("size_invalid");
                    }
                    if ![up, down, left, right].iter().all(|k| touch_key_ok(**k)) {
                        return Err("key_invalid");
                    }
                }
                TouchControl::Stick {
                    id: cid,
                    label,
                    at,
                    size,
                    speed,
                } => {
                    id(cid)?;
                    label_ok(label)?;
                    place_ok(at)?;
                    if !Self::SIZE_PX.contains(size) {
                        return Err("size_invalid");
                    }
                    if !speed.is_finite() || !Self::STICK_SPEED.contains(speed) {
                        return Err("speed_invalid");
                    }
                }
            }
        }
        Ok(name.to_string())
    }
}

/// Printable text of at most `max` characters: no control characters, so a
/// label is a label and never a line break or an escape.
fn text_ok(s: &str, max: usize) -> bool {
    s.chars().count() <= max && !s.chars().any(char::is_control)
}

fn label_ok(s: &str) -> Result<(), &'static str> {
    if s.trim().is_empty() || !text_ok(s, TouchPresetRequest::MAX_LABEL_CHARS) {
        return Err("label_invalid");
    }
    Ok(())
}

fn place_ok(at: &ControlPlace) -> Result<(), &'static str> {
    if at.left.is_some() && at.right.is_some() || at.top.is_some() && at.bottom.is_some() {
        return Err("place_both_edges");
    }
    let ok = |v: Option<f32>| {
        v.is_none_or(|v| v.is_finite() && (0.0..=TouchPresetRequest::MAX_PLACE_PX).contains(&v))
    };
    if !(ok(at.left) && ok(at.right) && ok(at.top) && ok(at.bottom)) {
        return Err("place_invalid");
    }
    Ok(())
}

fn action_ok(a: &ControlAction) -> Result<(), &'static str> {
    match a {
        ControlAction::Keys { keys } => {
            if keys.is_empty() || keys.len() > TouchPresetRequest::MAX_CHORD_KEYS {
                return Err("chord_keys");
            }
            if !keys.iter().all(|k| touch_key_ok(*k)) {
                return Err("key_invalid");
            }
        }
        ControlAction::Mouse { .. } => {}
        ControlAction::Macro { steps } => {
            if steps.is_empty() || steps.len() > TouchPresetRequest::MAX_MACRO_STEPS {
                return Err("macro_steps");
            }
            let mut total: u32 = 0;
            for s in steps {
                // Exactly one of a key or a mouse button.
                match (s.key, s.btn) {
                    (Some(k), None) => {
                        if !touch_key_ok(k) {
                            return Err("key_invalid");
                        }
                    }
                    (None, Some(_)) => {}
                    _ => return Err("step_key_or_button"),
                }
                if s.wait_ms > TouchPresetRequest::MAX_STEP_WAIT_MS {
                    return Err("step_wait");
                }
                total += u32::from(s.wait_ms);
            }
            if total > TouchPresetRequest::MAX_MACRO_MS {
                return Err("macro_too_long");
            }
        }
    }
    Ok(())
}

// ────────────────────────────────────────────────────────────────────────────
// Audit
// ────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditKind {
    /// Multi-user P3 — carries the ACTOR + effective grant (the plan's
    /// per-event attribution): with N concurrent sessions per agent, "who
    /// asked" is no longer derivable from the one live session. The same
    /// event now drives the `remote_sessions` row projection in the audit
    /// sink. Fields are serde-defaulted so pre-P3 rows still deserialize
    /// (defaults: zero ObjectId / empty name / default grant).
    SessionRequested {
        #[serde(default)]
        controller_user_id: ObjectId,
        #[serde(default)]
        controller_name: String,
        /// Stored as `Int32` bits by the driver's typed `insert_many` and read
        /// back through serde's tagged-enum buffering, which hides the format
        /// from `Permissions`' own impl — the explicit opt-in is what makes
        /// this field readable at all (#1630).
        #[serde(default, deserialize_with = "crate::permissions::deserialize_stored")]
        permissions: Permissions,
        /// FR-85 P3 — why `RECORD` was stripped from the requested grant
        /// (`device_cannot_record` / `controller_not_allowed` /
        /// `device_not_opted_in`); `None` = not
        /// requested, or granted. The server's DECISION, kept here beside the
        /// grant; what the host then did lives in `recording_activity`. A
        /// field rather than a new variant, so a pod on an older build can
        /// still read the row mid-rollout.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        record_stripped: Option<String>,
        /// FR-99 — why `PRIVACY` was stripped from the requested grant
        /// (`device_cannot_curtain` / `break_glass` / `device_not_opted_in`);
        /// `None` = not requested, or granted. The server's decision, beside
        /// `record_stripped` and for the same reason a field: an older pod
        /// reads the row mid-rollout.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        privacy_stripped: Option<String>,
        /// FR-101 P2 — the session features the policy took out of the
        /// request, each with why (`{"files": "org_policy_off"}`; the reasons
        /// of `ServerMsg::SessionCreated::features_refused`). `None` = nothing
        /// refused. The server's decision, a field for the same rollout reason.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        features_stripped: Option<std::collections::BTreeMap<String, String>>,
        /// FR-101 P4b-2 — the idle limit sent to the device, in seconds (the
        /// shorter of the org's and the device's own). `None` = no idle limit.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        idle_secs: Option<u32>,
        /// FR-101 P4b-2 — with `idle_secs`: whether the device keeps it (its
        /// agent advertises `idle-timeout`). `Some(false)` is a limit the org
        /// set that this session does not run under, which is worth seeing in
        /// an audit. `None` = no limit to keep.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        idle_enforced: Option<bool>,
        /// FR-99 P3b — what the device's access policy asked of the end of
        /// the session (`auto` / `always`). `None` = nothing asked: unset, or
        /// `never`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lock_on_end: Option<LockOnEnd>,
        /// FR-99 P3b — with `lock_on_end`: whether the device honours the ask
        /// (its agent advertises `lock-on-end`). `Some(false)` is a lock an
        /// admin asked for that this session's end will not take.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lock_enforced: Option<bool>,
    },
    ConsentPrompted,
    ConsentGranted,
    ConsentDenied,
    ConsentTimedOut,
    /// The answer reached the controller: the session is live.
    SessionStarted {
        /// FR-100 P1c — what the device concluded about the browser that
        /// offered the session, as its answer said (one of
        /// `signaling::PEER_AUTH_VERDICTS`; anything else is not recorded).
        /// `None` from a device without it or with `peer_auth = off`, and on
        /// every row written before it.
        ///
        /// ⚠️ A field, never a new variant, so a pod on an older build reads
        /// the row mid-rollout: with no field this serialises exactly as the
        /// unit variant it replaced, and an older pod's unit variant skips the
        /// field it does not know. Both directions are locked by tests.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer_auth: Option<String>,
    },
    SessionEnded {
        reason: EndReason,
        /// FR-101 P4b — which limit ended it, when one did: `max_duration`
        /// (the org's maximum session length). The reason is
        /// `IdleTimeout` either way, a variant every reader already knows; this
        /// says which limit it was. A field rather than a new reason or
        /// variant, so a pod on an older build can still read the row.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<String>,
    },
    // FR-101 P3 — the four clipboard and file kinds below are never written.
    // A transfer is something the DEVICE reports (the payload never crosses
    // the server), and a device's claims live apart from the server's
    // decisions: in `transfer_activity` ([`TransferActivityEvent`]), as
    // recordings' do in `recording_activity`. Kept so a row from a build
    // that ever wrote one still reads.
    ClipboardWriteToHost {
        bytes: u32,
    },
    ClipboardReadFromHost {
        bytes: u32,
    },
    FileSentToHost {
        name: String,
        bytes: u64,
    },
    FileSentFromHost {
        name: String,
        bytes: u64,
    },
    KeyframeRequested,
    PermissionsChanged {
        /// Same as `SessionRequested::permissions` (#1630).
        #[serde(deserialize_with = "crate::permissions::deserialize_stored")]
        permissions: Permissions,
    },
    WatcherJoined {
        user_id: ObjectId,
    },
    WatcherLeft {
        user_id: ObjectId,
    },
    Error {
        message: String,
    },
    /// An `ADMINISTRATOR` started this session via break-glass, skipping the
    /// device's consent mode. `reason` is operator-supplied and mandatory — the
    /// accountability record for a forced, unconsented session (docs §11.5).
    AdminOverride {
        reason: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RemoteAuditEvent {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub session_id: ObjectId,
    pub agent_id: ObjectId,
    pub tenant_id: ObjectId,
    pub at: DateTime,
    pub event: AuditKind,
}

impl RemoteAuditEvent {
    pub const COLLECTION: &'static str = "remote_audit";
}

// ────────────────────────────────────────────────────────────────────────────
// Agent crash report
// ────────────────────────────────────────────────────────────────────────────

/// Why the agent considers this a crash. Shared between the agent's
/// `crash_recorder` writer and the backend's ingest handler so a
/// future tag rename never silently breaks deserialisation.
///
/// Serialised as snake_case strings (`panic` / `watchdog_stall` /
/// `supervisor_detected`) — admin UI keys its chip-colour map off
/// these EXACT strings.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CrashReason {
    /// `std::panic::set_hook` fired in the worker process.
    Panic,
    /// `watchdog::force_exit_on_stall` was called — a registered
    /// pump's heartbeat gap exceeded its threshold (default 90 s).
    WatchdogStall,
    /// Windows SCM supervisor detected the worker process exited
    /// with a non-zero code (and the code wasn't `STALL_EXIT_CODE`,
    /// which is recorded at the watchdog site instead).
    SupervisorDetected,
}

/// Wire shape for the agent → roomler.ai crash-report upload AND the
/// on-disk sidecar the agent writes between crash + upload. `rename_
/// all = "camelCase"` so JS clients get `crashedAtUnix` etc. without
/// a translation step.
///
/// Size budget: 64 KiB total when JSON-serialised. The agent's
/// `crash_recorder::record` enforces this by trimming the
/// `log_tail` (oldest lines first) before write; the backend's
/// ingest route enforces it again with an 80 KiB body limit on the
/// HTTP request (small JSON overhead beyond the payload).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentCrashPayload {
    /// Unix seconds at the moment the crash was recorded ON THE
    /// AGENT. The backend stamps its own `reported_at` server-clock
    /// timestamp on ingest; admin UI shows both so clock-skewed
    /// hosts are visible.
    pub crashed_at_unix: i64,
    pub reason: CrashReason,
    /// One-line summary suitable for a list-view row (panic
    /// message, "pumps stalled (signaling=120s)", or "worker exit
    /// code 134"). May carry a trailing `[scrubbed N tokens]`
    /// marker if the scrub pipeline redacted credentials from the
    /// summary.
    pub summary: String,
    /// Last ~200 lines of the rolling agent log, after credential
    /// scrubbing. Truncated with a leading `[…log truncated to fit
    /// 64 KiB envelope…]\n` marker if the original tail wouldn't
    /// fit the size budget.
    pub log_tail: String,
    /// `env!("CARGO_PKG_VERSION")` at crash time.
    pub agent_version: String,
    /// `"windows"` / `"linux"` / `"macos"` — same string surface as
    /// `OsKind::serialize` would emit but kept as a plain String
    /// here so the payload doesn't depend on the OsKind enum
    /// position.
    pub os: String,
    /// Hostname at crash time.
    pub hostname: String,
    /// OS process id of the crashed worker (or supervisor, for the
    /// supervisor-detected branch).
    pub pid: u32,
    /// rc.51: how many crash sidecars were rate-limit-suppressed
    /// (`crash_recorder` 1/60 s throttle) between the previous
    /// successfully-written sidecar and this one. `0` in steady
    /// state; a high value means a tight crash-loop was in progress
    /// and most of its iterations went unrecorded — so this one
    /// sidecar represents `1 + suppressed_since_last` crashes.
    /// `#[serde(default)]` so pre-rc.51 sidecars (which lack the
    /// field) still deserialise.
    #[serde(default)]
    pub suppressed_since_last: u32,
}

/// Server-side persisted form of an agent crash report. The MongoDB
/// collection is `agent_crashes`; admin UI fetches via the protected
/// `GET /api/tenant/{tenant_id}/agent/{agent_id}/crash` endpoint.
///
/// Fields:
/// - `_id` / `tenant_id` / `agent_id` — server-attributed (resolved
///   from the agent JWT at ingest time).
/// - `reported_at` — server clock at ingest. Distinct from the
///   payload's `crashed_at_unix` (agent clock) so clock-skewed hosts
///   are visible in the admin UI.
/// - Everything else is flattened from [`AgentCrashPayload`] via
///   `#[serde(flatten)]`. The MongoDB BSON uses camelCase keys
///   matching the wire shape — no rename for the DB layer because
///   the payload's `rename_all = "camelCase"` carries through.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentCrashRecord {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    pub agent_id: ObjectId,
    pub reported_at: DateTime,
    #[serde(flatten)]
    pub payload: AgentCrashPayload,
}

impl AgentCrashRecord {
    pub const COLLECTION: &'static str = "agent_crashes";
}

// ────────────────────────────────────────────────────────────────────────────
// Overlay network (Tailscale-style L3 mesh)
// ────────────────────────────────────────────────────────────────────────────
//
// An overlay node is the unifying layer above `Agent` and `TunnelClient`:
// either kind of host can join a per-tenant virtual LAN, get a stable
// overlay IP, and reach any permitted peer at L3 over WireGuard. The two
// underlying collections keep their distinct lifecycles/audiences; an
// `OverlayNode` references one of them via [`NodeRef`] and adds the
// overlay-specific identity (WG pubkey + overlay IP + endpoints).

/// Which underlying host an [`OverlayNode`] is. Adjacently tagged so the
/// BSON/JSON shape is `{"kind":"agent","id":<oid>}` — mirrors the
/// `PolicySubject` / `PolicyTarget` style. The `id` stays a native
/// ObjectId for DB rows (Mongo indexes rely on native encoding); the
/// wire/netmap exposes nodes by their `overlay_nodes._id`, not by this.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NodeRef {
    Agent {
        #[serde(rename = "id")]
        agent_id: ObjectId,
    },
    TunnelClient {
        #[serde(rename = "id")]
        tunnel_client_id: ObjectId,
    },
}

/// One member of a tenant's overlay network. Keyed for rehydrate-on-
/// re-enroll by `(tenant_id, machine_id)` exactly like [`Agent`] /
/// [`TunnelClient`], so a re-joining host keeps its overlay IP (and may
/// register a rotated WG key). The WG **private** key never leaves the
/// node; only `wg_public_key` is stored + distributed in the netmap.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OverlayNode {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    pub node_ref: NodeRef,
    pub network_id: ObjectId,
    /// Rehydrate key — carried from the underlying agent/tunnel-client so
    /// a re-join finds the existing row (and its leased overlay IP).
    pub machine_id: String,
    /// Human-facing node name — denormalized from the underlying
    /// [`Agent`]/[`TunnelClient`] `name` at join, sanitized to a DNS label and
    /// made unique per network (collisions get a `-2`/`-3` suffix). This is the
    /// MagicDNS authority and the netmap's `name`. Empty on rows created before
    /// Phase 0 (Tailscale-style names).
    #[serde(default)]
    pub name: String,
    /// Leased overlay address, e.g. `"100.64.0.7"`. Stable for as long as the
    /// row is LIVE. On release (device removed from the fleet) the row is
    /// tombstoned and the host number goes back to `OverlayNetwork.free_hosts`
    /// for reuse — the address is KEPT here as the forensic record of who held
    /// it, which matters precisely because addresses now recycle. The
    /// `(tenant_id, network_id, overlay_ip)` unique index is scoped to live
    /// rows, so a tombstone holds nothing.
    pub overlay_ip: String,
    /// base64-encoded Curve25519 public key (WireGuard static key).
    pub wg_public_key: String,
    /// Bumped on key rotation (Phase 5). `0` at first join.
    #[serde(default)]
    pub key_epoch: u32,
    /// Current connectivity candidates (srflx / relay), as `host:port`
    /// strings the peer can dial. REPLACED on each `rc:overlay.endpoints`
    /// trickle from the relay coordinator.
    #[serde(default)]
    pub endpoints: Vec<String>,
    /// rc.135 — DIRECT LAN candidates, set from the agent's JOIN (kept in a
    /// SEPARATE bucket so the relay-endpoint trickle — which REPLACES
    /// `endpoints` — can't clobber them). The netmap a peer receives unions
    /// `lan_endpoints ∪ endpoints` so a same-subnet peer can always find the
    /// LAN address and go direct. (Field 2026-06-27: the trickle stripped
    /// `192.168.68.x` from nodes that had allocated a relay, forcing every
    /// peer onto the relay path.) Refreshed on each (re)join, so a DHCP IP
    /// change is picked up.
    #[serde(default)]
    pub lan_endpoints: Vec<String>,
    /// NAT-traversal Phase B — the node's SERVER-REFLEXIVE (srflx) candidates:
    /// its public `ip:port` as seen through its NAT, discovered by the node
    /// querying STUN on its own traffic sockets and trickled up via
    /// `rc:overlay.srflx`. A THIRD bucket, separate from `lan_endpoints` (public
    /// NIC) and `endpoints` (relay), so no trickle clobbers another's provenance
    /// (CC2). Surfaced VERBATIM in the netmap as `NetmapPeer.srflx_endpoints` so
    /// a peer behind a different NAT can dial this node directly (1:1 / cone NAT
    /// only). Reset to empty on each (re)join — the node re-gathers + re-trickles
    /// fresh srflx per connection, so a stale mapping never lingers.
    #[serde(default)]
    pub srflx_endpoints: Vec<String>,
    /// NAT-traversal Phase C — the node's probed NAT mapping type (`"cone"` /
    /// `"symmetric"`), trickled alongside its srflx via `rc:overlay.srflx` and
    /// surfaced as `NetmapPeer.srflx_nat`. A dialer skips the punch only when
    /// BOTH ends are `"symmetric"`. `None` = unknown (attempted, never skipped).
    /// Reset on each (re)join with `srflx_endpoints` — a prior session's NAT
    /// class is meaningless after a roam (A8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub srflx_nat: Option<String>,
    /// Phase B (overlay v3) — the node's MEASURED capability vector
    /// (`rc:overlay.netcheck`), surfaced as `NetmapPeer.caps` behind the
    /// freshness gate on [`Self::caps_measured_at`]. Reset on re-join with
    /// the srflx bucket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caps: Option<crate::signaling::CapVectorWire>,
    /// Receipt stamp for [`Self::caps`] — the freshness gate's input
    /// (vectors older than 3× the measurement cadence are surfaced as
    /// absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caps_measured_at: Option<bson::DateTime>,
    /// Dialer honesty (2026-08-16) — whether this node can raw-UDP-dial
    /// arbitrary relay-band ports (the single-relay DIALER's job), trickled
    /// with `rc:overlay.srflx` and surfaced as `NetmapPeer.udp_dialer_ok`.
    /// `Some(false)` = proved it can't (dialer-role convictions against ≥2
    /// distinct peers); `None` = pre-honesty agent (legacy role inputs).
    /// Reset on each (re)join with `srflx_endpoints`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_dialer_ok: Option<bool>,
    /// Preferred relay region/home, if any (Phase 5 multi-relay).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_home: Option<String>,
    /// C4 stage 2 (PR-B) — the node's STANDING warm TURN allocation's relayed
    /// address (`worker-ip:port`), mirrored from its agent's heartbeats while
    /// a leg is live (`$unset` while none is). The netmap builder reads THIS
    /// row — not the agents collection — so the field must live here to reach
    /// `NetmapPeer.warm_relay_endpoint`, where a single-relay dialer uses it
    /// as the pair-less dial fallback. Cleared on rejoin like `srflx_*`: a
    /// restarted runtime holds no leg until its warm arm re-establishes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warm_relay_endpoint: Option<String>,
    /// rc.142 — the node advertised (on JOIN) that it can carry WG over a
    /// QUIC-over-TURN relay carrier. Echoed per-peer in the netmap so QUIC is
    /// only attempted when both ends support it (no silent QUIC/raw split).
    #[serde(default)]
    pub supports_quic: bool,
    /// Phase D — the node advertised (on JOIN) that it can run the v1
    /// single-relay carrier (one anchor allocation + a raw dialer). Echoed
    /// per-peer in the netmap so single-relay is only chosen when both ends
    /// support it (a mismatch would split the pair into anchor/dialer).
    #[serde(default)]
    pub supports_relay_single: bool,
    /// Phase D (DERP) — the node advertised (on JOIN) that it can carry WG over
    /// the pubkey-addressed `/derp` relay, the last-resort carrier for two
    /// BOTH-UDP-blocked peers. Echoed per-peer in the netmap so DERP is only
    /// chosen when both ends support it. Absent on a pre-DERP row ⇒ `false`.
    #[serde(default)]
    pub supports_derp: bool,
    /// P7 — the node advertised (on JOIN) that it honors the server's per-pair
    /// `rc:overlay.force_derp` escalation push. The broker only escalates a
    /// churning pair when BOTH ends carry this, so a mixed-version pair can
    /// never split tiers. Absent on a pre-P7 row ⇒ `false`.
    #[serde(default)]
    pub supports_forced_derp: bool,
    /// U2 — the node advertised (on JOIN) that it accepts a server-computed
    /// relay-tier verdict. The broker stamps a per-edge `relay_strategy` in
    /// the netmap only when BOTH ends carry this. Absent on a pre-U2 row ⇒
    /// `false` ⇒ the pair keeps the client-authoritative path.
    #[serde(default)]
    pub supports_server_relay_strategy: bool,
    /// Phase A (overlay v3) — the node advertised (on JOIN) the DERP
    /// always-on floor: its central `/derp` mux stays open + registered for
    /// the whole session. Echoed per-peer; the floor is gated on BOTH ends.
    /// Absent on a pre-floor row ⇒ `false`.
    #[serde(default)]
    pub supports_derp_floor: bool,
    /// Data-probe — the node's overlay engine answers the overlay-native echo
    /// probe inline (advertised on JOIN, echoed per-peer in the netmap so
    /// probers prefer the engine-guaranteed echo). Absent on an older row ⇒
    /// `false` ⇒ peers probe it with ICMP.
    #[serde(default)]
    pub supports_overlay_echo: bool,
    /// FR-19 — this node understands `rc:overlay.relay_session` /
    /// `rc:overlay.relay_revoke` and the `org-relay` verdict (advertised on
    /// join, echoed per-peer in the netmap). The server never pushes those to a
    /// node that has not said so. Absent on an older row ⇒ `false`.
    #[serde(default)]
    pub supports_org_relay: bool,
    /// Phase 1 — subnet CIDRs this node CLAIMS it can route for peers (from its
    /// `--advertise-routes` config, refreshed on each join). Untrusted until an
    /// admin approves; see `approved_routes`.
    #[serde(default)]
    pub advertised_routes: Vec<String>,
    /// Phase 1 — the admin-APPROVED subset of `advertised_routes`, distributed
    /// to peers as the netmap `routes`. Empty = this node routes nothing for
    /// anyone. An admin manages this via the overlay-route approval UI.
    ///
    /// P5: a default route `0.0.0.0/0` here marks this node as an approved
    /// exit node (clients infer exit-nodes from an approved `/0` in the
    /// netmap). `/0` may ONLY enter this list via the exit-node toggle
    /// (`set_exit_node`), never the per-CIDR approval grid — see
    /// `set_approved_routes`'s `/0` guard — so an admin can't accidentally
    /// route the whole internet with a mis-clicked checkbox.
    #[serde(default)]
    pub approved_routes: Vec<String>,
    /// P5 — admin has designated this node as an exit node (routes
    /// `0.0.0.0/0` for opted-in clients). Kept as an explicit flag for the
    /// admin UI + approval semantics; the DATA-PLANE signal a client keys
    /// off is still the approved `0.0.0.0/0` in the netmap. Toggling this
    /// on requires the node to have advertised `0.0.0.0/0` and adds it to
    /// `approved_routes`; toggling off removes it.
    #[serde(default)]
    pub is_exit_node: bool,
    /// FR-97 P0b — why the device advertises no `/0` and no subnet route
    /// although it was configured to: it found it cannot forward or NAT for the
    /// overlay (a Mac; Windows Home, #2077). Sent on every join and refreshed
    /// there, so it clears the moment the device can serve again. Shown beside
    /// the route approval, where its absence used to make the node vanish from
    /// the table with no word of why. `None` on an older device or row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_offer_withheld: Option<String>,
    pub status: AgentStatus,
    pub last_seen_at: DateTime,
    pub created_at: DateTime,
    pub updated_at: DateTime,
    pub deleted_at: Option<DateTime>,
}

impl OverlayNode {
    pub const COLLECTION: &'static str = "overlay_nodes";

    /// FR-97 P0b — the routes this node may carry for its peers: those an admin
    /// APPROVED **and** the device still ADVERTISES.
    ///
    /// `approved_routes` survives a rejoin on purpose (a flapping join must not
    /// cost an admin's decision), and the join refreshes only
    /// `advertised_routes`. So an approval on its own is not an offer: a node
    /// that stopped advertising `0.0.0.0/0` (the operator turned the exit off,
    /// or the device found it cannot NAT) stayed an exit in every peer's netmap
    /// until an admin noticed, and each client that picked it lost its whole
    /// internet egress. Every data-plane reader of a node's routes (the netmap
    /// fan and every overlay-ACL evaluation) goes through this, so the approval
    /// takes effect only while the device offers the route, and comes back by
    /// itself when the offer does.
    ///
    /// Exact-string match, like the rest of the approval surface
    /// (`set_approved_routes` admits only a route the node advertised, by its
    /// literal spelling): what the admin grid shows as approved-and-offered is
    /// exactly what peers receive.
    pub fn effective_routes(&self) -> Vec<String> {
        self.approved_routes
            .iter()
            .filter(|a| self.advertised_routes.contains(a))
            .cloned()
            .collect()
    }
}

/// P5 — the IPv4 default route. Its presence in a node's `approved_routes`
/// is the wire signal that the node is an approved exit node; it may only be
/// added via the exit-node toggle, never the per-CIDR approval grid.
pub const DEFAULT_ROUTE_V4: &str = "0.0.0.0/0";

/// IPAM authority for one tenant's overlay. One row per tenant. The allocator
/// prefers a RECYCLED host from `free_hosts` (returned when a device is removed
/// from the fleet) and otherwise hands out the next number from the monotonic
/// `next_host` cursor (atomic `$inc`). A lease is stable for as long as its node
/// row is live.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OverlayNetwork {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    /// CGNAT range per the Tailscale convention, e.g. `"100.64.0.0/10"`.
    pub cidr: String,
    /// Monotonic host cursor — the next host number to hand out. `1` for
    /// a fresh network (host `0` is the network address, reserved). Only
    /// bumped when [`free_hosts`](Self::free_hosts) is empty.
    pub next_host: u32,
    /// Host numbers RECYCLED from removed devices, oldest release first. A
    /// join pops the head before touching `next_host`, so a released address
    /// gets the longest possible cool-down before it is handed out again.
    ///
    /// `#[serde(default)]` is LOAD-BEARING: every `overlay_networks` row
    /// written before the release feature lacks this field, and without the
    /// default they would all fail to deserialize — taking the entire overlay
    /// down on the first `get_or_create`.
    #[serde(default)]
    pub free_hosts: Vec<u32>,
    /// Path MTU for the overlay. 1280 leaves headroom for the WG +
    /// carrier (UDP/relay) overhead under a 1500-byte underlay.
    pub mtu: u16,
    /// How strictly [`OverlayPolicy`] rows are applied for this tenant.
    ///
    /// `#[serde(default)]` is LOAD-BEARING for exactly the reason spelled out
    /// on [`free_hosts`](Self::free_hosts): every row written before the ACL
    /// feature lacks this field, and without the default they would all fail
    /// to deserialize and take the whole overlay down on the next
    /// `get_or_create`. The default is [`OverlayAclMode::Off`], so an existing
    /// mesh keeps its current behaviour until an admin opts in.
    #[serde(default)]
    pub acl_mode: OverlayAclMode,
    /// FR-19 gate 1 — the org's peer-relay switch. `#[serde(default)]` for the
    /// same reason as `acl_mode`: every pre-FR-19 row lacks it, and the default
    /// is [`PeerRelayMode::Off`] so nothing is minted until an admin opts in.
    #[serde(default)]
    pub peer_relay_mode: PeerRelayMode,
    /// MeshHarbor — the tenant's server topology: two devices whose central
    /// role is Server are connected exactly when an ENABLED link names them,
    /// whatever their zones (business isolation `warn` logs, `enforce`
    /// applies). Edited from the topology view.
    #[serde(default)]
    pub server_links: Vec<ServerLink>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

/// One edge of the server topology, between two agents. Stored with
/// `a < b`, so one pair has one row.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ServerLink {
    pub a: ObjectId,
    pub b: ObjectId,
    pub enabled: bool,
}

impl ServerLink {
    /// At most this many links per tenant.
    pub const MAX_PER_TENANT: usize = 4096;

    /// The pair in stored order.
    pub fn ordered(x: ObjectId, y: ObjectId) -> (ObjectId, ObjectId) {
        if x < y { (x, y) } else { (y, x) }
    }
}

impl OverlayNetwork {
    pub const COLLECTION: &'static str = "overlay_networks";
    /// Default tenant overlay range (CGNAT block, like Tailscale).
    pub const DEFAULT_CIDR: &'static str = "100.64.0.0/10";
    /// Default overlay MTU.
    pub const DEFAULT_MTU: u16 = 1280;
    /// Ceiling on [`free_hosts`](Self::free_hosts). A `u32` array element costs
    /// ~9 bytes of BSON, so the 16 MB document cap is ~1.7 M entries — this cap
    /// sits far below it. Past the cap a release is DROPPED and the host leaks
    /// out of a 4.2 M-address `/10`: a leak, never a conflict.
    pub const MAX_FREE_HOSTS: usize = 65_536;

    /// This network's dotted address for `host`. See [`overlay_ip`].
    pub fn host_ip(&self, host: u32) -> Option<String> {
        overlay_ip(&self.cidr, host)
    }

    /// The host number `ip` was leased from in this network. See [`overlay_host`].
    pub fn host_of_ip(&self, ip: &str) -> Option<u32> {
        overlay_host(&self.cidr, ip)
    }

    /// Multi-org P2a — the highest host ordinal this network's CIDR can
    /// lease. See [`cidr_max_host`]; `0` (nothing leasable) on a malformed
    /// CIDR so a bad row FAILS CLOSED at allocation instead of handing out
    /// unbounded addresses.
    pub fn max_host(&self) -> u32 {
        cidr_max_host(&self.cidr).unwrap_or(0)
    }
}

/// Multi-org P2a — the highest leaseable host ordinal for `cidr`:
/// `2^(32-prefix) - 2` (host 0 is the network address, the block's last
/// address is reserved by convention), `None` for a malformed CIDR or a
/// prefix ≥ 31 (no leasable hosts either way).
///
/// The forward-compat point: `allocate_host`'s cursor previously grew
/// UNBOUNDED — under tenant-block addressing (P2b hands tenants sub-blocks
/// of `100.64.0.0/10`, e.g. a `/22`) a busy tenant's cursor would have
/// silently walked into the NEIGHBOR tenant's block: the exact cross-tenant
/// address collision the blocks exist to kill. Every allocation is now
/// bounded by the network's OWN CIDR — behaviour-neutral for today's
/// `/10` tenants (max host 4 194 302, unreachable), binding the moment a
/// tenant's `cidr` becomes a real block.
pub fn cidr_max_host(cidr: &str) -> Option<u32> {
    let (_base, prefix) = cidr.split_once('/')?;
    let prefix: u8 = prefix.parse().ok()?;
    if prefix >= 31 {
        return None;
    }
    // 2^(32-prefix) - 2; prefix 0 would overflow the shift — cap at /1.
    let size: u64 = 1u64 << (32 - prefix.min(31) as u64);
    u32::try_from(size - 2).ok()
}

/// `base_cidr` + host number → dotted overlay IP. e.g.
/// `("100.64.0.0/10", 7) → "100.64.0.7"`. No `ipnet` needed — the host
/// number is added to the network base address as a `u32`.
///
/// The base is taken from the LEFT of the `/` (not the masked network
/// address). [`overlay_host`] inverts this by parsing the same way, and the
/// round-trip test in this module pins the pair together — do not "fix" one
/// to mask without the other.
///
/// Multi-org P2a: `host` is bounded by [`cidr_max_host`] — a host past the
/// block renders `None` instead of an address in the NEIGHBOR block.
pub fn overlay_ip(cidr: &str, host: u32) -> Option<String> {
    if host > cidr_max_host(cidr)? {
        return None;
    }
    let (base, _prefix) = cidr.split_once('/')?;
    let base: std::net::Ipv4Addr = base.parse().ok()?;
    let addr = std::net::Ipv4Addr::from(u32::from(base).checked_add(host)?);
    Some(addr.to_string())
}

/// Exact inverse of [`overlay_ip`] — recover the host number a dotted overlay
/// address was leased from, so a removed device's number can be returned to the
/// network's free pool.
///
/// `None` when `cidr`/`ip` are malformed, when `ip` sorts BELOW the base, or
/// (multi-org P2a) ABOVE the block's last leaseable host: both directions are
/// how a row leased under a DIFFERENT, since-changed CIDR is rejected instead
/// of poisoning the pool with a bogus host number.
pub fn overlay_host(cidr: &str, ip: &str) -> Option<u32> {
    let (base, _prefix) = cidr.split_once('/')?;
    let base: std::net::Ipv4Addr = base.parse().ok()?;
    let addr: std::net::Ipv4Addr = ip.parse().ok()?;
    let host = u32::from(addr).checked_sub(u32::from(base))?;
    if host > cidr_max_host(cidr)? {
        return None;
    }
    Some(host)
}

// ---------------------------------------------------------------------------
// Multi-org P2b — tenant-block addressing
// ---------------------------------------------------------------------------

/// The CGNAT root every tenant block is carved from.
pub const OVERLAY_BLOCK_ROOT: &str = "100.64.0.0/10";

/// Base address of [`OVERLAY_BLOCK_ROOT`] as a `u32`.
const OVERLAY_BLOCK_ROOT_BASE: u32 = u32::from_be_bytes([100, 64, 0, 0]);

/// The allocation grid: every block is an ALIGNED run of `/22`s. A `/22`
/// (1024 addresses, 1022 leasable) is the smallest unit handed out, so the
/// registry can enforce non-overlap with one integer per block.
pub const OVERLAY_BLOCK_SLOT_PREFIX: u8 = 22;

/// Addresses per slot (`2^(32-22)` = 1024).
pub const OVERLAY_BLOCK_SLOT_SIZE: u32 = 1 << (32 - OVERLAY_BLOCK_SLOT_PREFIX as u32);

/// The first slot the allocator may hand out — slot 64, i.e. `100.65.0.0`.
///
/// The whole of `100.64.0.0/16` (slots 0..63) is RESERVED for LEGACY tenants:
/// every network created before blocks existed carries `100.64.0.0/10` with
/// its host cursor seeded at 1, so all of them sit in `100.64.0.x` and grow
/// upward. Starting new blocks above that reserve means a carved tenant can
/// never collide with a legacy one, no matter how many devices the legacy
/// tenant has leased (65 534 before it would reach slot 64).
pub const OVERLAY_BLOCK_FIRST_SLOT: u32 = 64;

/// Number of slots in the `/10` (`2^(22-10)`).
pub const OVERLAY_BLOCK_SLOT_COUNT: u32 = 1 << (OVERLAY_BLOCK_SLOT_PREFIX as u32 - 10);

/// Largest block a tenant may be carved (a `/16`, 64 slots, 65 534 hosts).
pub const OVERLAY_BLOCK_MIN_PREFIX: u8 = 16;

/// Smallest block a tenant may be carved — one slot.
pub const OVERLAY_BLOCK_MAX_PREFIX: u8 = OVERLAY_BLOCK_SLOT_PREFIX;

/// Lifecycle of a registry row.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum OverlayBlockState {
    /// Currently backing a tenant's overlay network.
    #[default]
    Assigned,
    /// Freed by a renumber. The slots are NEVER handed out again: a device
    /// that missed the migration (offline, or a stale binary) still believes
    /// it holds an address in here, and re-issuing the range to a different
    /// tenant would hand that stale node a live neighbour's address. The row
    /// is kept as the forensic record of who held the range.
    Quarantined,
    /// An operator has judged a quarantined range safe to hand out again:
    /// old enough that any device would have reconnected and been
    /// renumbered many times over, and with no live node still holding an
    /// address inside it.
    ///
    /// Reclaimed rows are the allocator's **fallback, not its default**.
    /// Normal allocation stays strictly monotonic-upward — that is what
    /// makes non-overlap structural rather than locked — and only reaches
    /// for a reclaimed range when the monotonic path has genuinely run out
    /// of space above. So the risk this state carries is paid exactly when
    /// the alternative is "no address at all", and never before.
    Reclaimed,
}

/// One entry in the GLOBAL overlay block registry (multi-org P2b).
///
/// Blocks are allocated MONOTONICALLY upward from
/// [`OVERLAY_BLOCK_FIRST_SLOT`]: the allocator takes the highest `end_slot`
/// in the collection, rounds up to this block's alignment, and inserts with a
/// unique `slot`. Two racers either compute the SAME start (one loses the
/// unique index and retries against the winner's row) or compute
/// buddy-aligned, non-overlapping starts — so the registry never issues
/// overlapping ranges without needing a lock. Quarantined rows keep their
/// slots occupied, which is exactly what makes quarantine free.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OverlayBlock {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    /// Offset from `100.64.0.0` in [`OVERLAY_BLOCK_SLOT_SIZE`] units.
    /// Globally unique — this is what makes overlap unrepresentable.
    pub slot: u32,
    /// How many contiguous slots this block spans (a power of two; the start
    /// is always a multiple of it).
    pub slots: u32,
    /// `slot + slots`, denormalized so the allocator's "highest end" probe is
    /// a single indexed `sort + limit 1` instead of a collection scan.
    pub end_slot: u32,
    /// The rendered range, e.g. `"100.65.0.0/22"`. This is copied to
    /// `OverlayNetwork.cidr` — the registry is the authority.
    pub cidr: String,
    /// FR-47 P5b — this block's POSITION in its network's block list, from 0.
    ///
    /// The ordinal space is the blocks concatenated in allocation order
    /// ([`BlockList`]), so the order has to be recoverable exactly — get it
    /// wrong and every ordinal above the misplaced block silently re-points at
    /// a different address.
    ///
    /// ⚠️ It is an explicit field because **neither obvious key works**.
    /// `slot` fails: [`OverlayBlockState::Reclaimed`] ranges are re-issued
    /// from BELOW the cursor, so a newly-allocated block can carry a lower
    /// slot than one allocated years earlier. `created_at` fails too, for the
    /// mirror reason — the reclaim path reuses the ROW, so its `created_at`
    /// is the date the range was first carved for a different tenant.
    ///
    /// `#[serde(default)]` reads every pre-P5b row as `0`, which is correct:
    /// before multi-block a network had exactly one assigned block.
    #[serde(default)]
    pub seq: u32,
    pub tenant_id: ObjectId,
    pub network_id: ObjectId,
    pub state: OverlayBlockState,
    /// Why the block was quarantined (renumber, block grow, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released_at: Option<DateTime>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

impl OverlayBlock {
    pub const COLLECTION: &'static str = "overlay_blocks";

    /// Highest host ordinal this block can lease.
    pub fn max_host(&self) -> u32 {
        cidr_max_host(&self.cidr).unwrap_or(0)
    }
}

/// Slots consumed by a block of `prefix`, or `None` when the prefix is outside
/// the supported band ([`OVERLAY_BLOCK_MIN_PREFIX`] ..=
/// [`OVERLAY_BLOCK_MAX_PREFIX`]). Anything longer than a `/22` would have to
/// sub-divide a slot, which the registry deliberately does not model.
pub fn block_slots_for_prefix(prefix: u8) -> Option<u32> {
    if !(OVERLAY_BLOCK_MIN_PREFIX..=OVERLAY_BLOCK_MAX_PREFIX).contains(&prefix) {
        return None;
    }
    Some(1 << (OVERLAY_BLOCK_SLOT_PREFIX as u32 - prefix as u32))
}

/// The rendered CIDR for an aligned run of `slots` slots starting at `slot`.
/// `None` when the run is unaligned, empty, or would leave the `/10`.
pub fn block_cidr_for_slot(slot: u32, slots: u32) -> Option<String> {
    if slots == 0 || !slots.is_power_of_two() || !slot.is_multiple_of(slots) {
        return None;
    }
    let end = slot.checked_add(slots)?;
    if end > OVERLAY_BLOCK_SLOT_COUNT {
        return None;
    }
    let base = OVERLAY_BLOCK_ROOT_BASE.checked_add(slot.checked_mul(OVERLAY_BLOCK_SLOT_SIZE)?)?;
    let prefix = OVERLAY_BLOCK_SLOT_PREFIX as u32 - slots.trailing_zeros();
    Some(format!(
        "{}/{}",
        std::net::Ipv4Addr::from(base),
        prefix as u8
    ))
}

/// The lowest aligned start for a `slots`-wide block that begins at or after
/// `after`. Alignment (start is a multiple of the width) is what makes two
/// concurrently-computed allocations either identical or disjoint.
pub fn block_align_slot(after: u32, slots: u32) -> u32 {
    if slots == 0 {
        return after;
    }
    after.div_ceil(slots) * slots
}

// ---------------------------------------------------------------------------
// FR-47 P5a — an org's address space as a LIST of blocks
// ---------------------------------------------------------------------------

/// An organization's overlay address space: an ordered, **append-only** list
/// of blocks addressed by one continuous ordinal space.
///
/// Ordinals run `1..=capacity()` across the whole list — `1..=1022` in block 0,
/// `1023..=2044` in block 1, and so on. That concatenation is what lets a
/// network outgrow its first block **without renumbering a single device**:
/// growth appends a block at the tail and every existing ordinal keeps meaning
/// exactly the address it already meant.
///
/// ⚠️ **Append-only is load-bearing, not a convention.** Every entry in
/// `OverlayNetwork.free_hosts` is an ordinal, and so is every address a live
/// node holds. Insert or remove a block anywhere but the tail and every
/// ordinal above it silently re-points at a different address — which is the
/// one failure this whole FR exists to prevent. The invariant holds for free
/// today because blocks are *quarantined*, never removed
/// ([`OverlayBlockState::Quarantined`]).
///
/// A single-block list behaves **identically** to the bare
/// [`overlay_ip`] / [`overlay_host`] pair it generalizes; that equivalence is
/// pinned by test, because it is what makes multi-block safe to ship behind a
/// flag on a live fleet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockList {
    /// Blocks in allocation order. Order IS the ordinal layout.
    cidrs: Vec<String>,
}

impl BlockList {
    /// Build from blocks in allocation order (oldest first).
    ///
    /// Blocks that cannot lease anything are dropped rather than kept as
    /// zero-width entries: a `/31` in the middle of the list would contribute
    /// no ordinals but would still be a position someone could later "fix"
    /// into a real block, shifting everything above it.
    pub fn new<I, S>(cidrs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            cidrs: cidrs
                .into_iter()
                .map(Into::into)
                .filter(|c| cidr_max_host(c).is_some_and(|m| m > 0))
                .collect(),
        }
    }

    /// The single-block case — exactly today's behaviour.
    pub fn single(cidr: &str) -> Self {
        Self::new([cidr])
    }

    /// Blocks in allocation order.
    pub fn cidrs(&self) -> &[String] {
        &self.cidrs
    }

    /// Total leasable ordinals across every block.
    pub fn capacity(&self) -> u32 {
        self.cidrs
            .iter()
            .filter_map(|c| cidr_max_host(c))
            .fold(0u32, |a, b| a.saturating_add(b))
    }

    /// The address for a whole-space ordinal, or `None` past the end.
    pub fn ip_for_ordinal(&self, ordinal: u32) -> Option<String> {
        if ordinal == 0 {
            return None; // host 0 is the network address, never leased
        }
        let mut remaining = ordinal;
        for cidr in &self.cidrs {
            let width = cidr_max_host(cidr)?;
            if remaining <= width {
                return overlay_ip(cidr, remaining);
            }
            remaining -= width;
        }
        None
    }

    /// The whole-space ordinal an address maps to, or `None` when no block in
    /// this list contains it.
    pub fn ordinal_for_ip(&self, ip: &str) -> Option<u32> {
        let mut base = 0u32;
        for cidr in &self.cidrs {
            let width = cidr_max_host(cidr)?;
            // `overlay_host` returns Some(0) for the network address itself,
            // which is not a lease — skip it rather than reporting ordinal 0.
            if let Some(h) = overlay_host(cidr, ip)
                && h > 0
            {
                return Some(base + h);
            }
            base += width;
        }
        None
    }

    /// The block that actually contains `ip`.
    ///
    /// This is what a netmap sends a node as its own `cidr`: an agent derives
    /// its TUN netmask and its subnet-router NAT scope from that string, and
    /// both are only correct for the block the node's OWN address lives in.
    pub fn cidr_for_ip(&self, ip: &str) -> Option<&str> {
        self.cidrs
            .iter()
            .find(|c| overlay_host(c, ip).is_some())
            .map(|c| c.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #1882 — every policy row written before `rc_overlay` existed must read
    /// OFF: the default is the whole point, and it has to hold for the rows
    /// already in Mongo, not just for `AccessPolicy::default()`.
    #[test]
    fn rc_overlay_is_off_unless_a_row_says_on() {
        let old: AccessPolicy = bson::from_document(bson::doc! {
            "consent_mode": "auto",
            "allowed_role_ids": [],
            "allowed_user_ids": [],
            "auto_terminate_idle_minutes": null,
        })
        .expect("a pre-#1882 row deserialises");
        assert_eq!(old.rc_overlay, None);
        assert!(!old.rc_overlay_allowed());
        assert!(!AccessPolicy::default().rc_overlay_allowed());

        let on = AccessPolicy {
            rc_overlay: Some(true),
            ..Default::default()
        };
        let back: AccessPolicy =
            bson::from_document(bson::to_document(&on).expect("serialises")).expect("round-trips");
        assert!(back.rc_overlay_allowed());

        let off = AccessPolicy {
            rc_overlay: Some(false),
            ..Default::default()
        };
        assert!(!off.rc_overlay_allowed());
    }

    /// FR-99 P3b — every row written before `lock_on_end` asks nothing, a
    /// stored `null` asks nothing (the `Option` sees it before `LockOnEnd`'s
    /// unknown-reads-as-`always` rule can), `never` asks nothing, and an ask
    /// survives the round trip.
    #[test]
    fn a_device_policy_asks_a_lock_only_when_it_says_so() {
        let old: AccessPolicy = bson::from_document(bson::doc! {
            "consent_mode": "auto",
            "allowed_role_ids": [],
            "allowed_user_ids": [],
            "auto_terminate_idle_minutes": null,
        })
        .expect("a pre-P3b row deserialises");
        assert_eq!(old.lock_on_end, None);
        assert_eq!(old.lock_on_end_ask(), None);
        let null: AccessPolicy = bson::from_document(bson::doc! {
            "allowed_role_ids": [],
            "allowed_user_ids": [],
            "auto_terminate_idle_minutes": null,
            "lock_on_end": null,
        })
        .expect("a stored null deserialises");
        assert_eq!(null.lock_on_end, None);

        let never = AccessPolicy {
            lock_on_end: Some(LockOnEnd::Never),
            ..Default::default()
        };
        assert_eq!(never.lock_on_end_ask(), None);
        for ask in [LockOnEnd::Auto, LockOnEnd::Always] {
            let p = AccessPolicy {
                lock_on_end: Some(ask),
                ..Default::default()
            };
            let back: AccessPolicy =
                bson::from_document(bson::to_document(&p).expect("serialises"))
                    .expect("round-trips");
            assert_eq!(back.lock_on_end_ask(), Some(ask));
        }
    }

    /// FR-51 — a device row written before the ephemeral fields existed must
    /// deserialise PERMANENT. This is the property that makes enabling the
    /// reaper safe against the existing fleet: every pre-FR-51 row reads
    /// `ephemeral: false`, so the reaper's predicate can never match it.
    #[test]
    fn pre_fr51_agent_row_deserialises_permanent() {
        let now = bson::DateTime::now();
        // The minimal shape of a fielded row: none of the serde-defaulted
        // fields present, and in particular neither `ephemeral` nor
        // `ephemeral_ttl_secs`.
        let doc = bson::doc! {
            "tenant_id": ObjectId::new(),
            "owner_user_id": ObjectId::new(),
            "name": "old-host",
            "machine_id": "m-1",
            "os": "linux",
            "agent_version": "0.4.0",
            "agent_token_hash": "",
            "status": "offline",
            "last_seen_at": now,
            "created_at": now,
            "updated_at": now,
            "deleted_at": bson::Bson::Null,
        };
        let a: Agent = bson::from_document(doc).expect("pre-FR-51 row must deserialise");
        assert!(!a.ephemeral, "an old row must never read as ephemeral");
        assert_eq!(a.ephemeral_ttl_secs, None);
        // FR-102 P3 — and a row from before the install trace reads as
        // "never said", which the digest counts as unknown.
        assert_eq!(a.install, None);
    }

    /// FR-102 P3 — the install vocabulary is a stored spelling and a digest
    /// grouping key: renaming one would split every existing row's count
    /// from every new one's. Locked, and matched by equality only.
    #[test]
    fn install_vocabulary_spellings_are_locked() {
        let methods: Vec<&str> = InstallMethod::ALL.iter().map(|m| m.wire()).collect();
        assert_eq!(
            methods,
            [
                "wizard",
                "script-sh",
                "script-ps1",
                "msi",
                "deb",
                "pkg",
                "manual",
                "container",
                "other",
                "unknown"
            ]
        );
        let scopes: Vec<&str> = InstallScope::ALL.iter().map(|s| s.wire()).collect();
        assert_eq!(scopes, ["system", "per-user", "attended", "unknown"]);
        for m in InstallMethod::ALL {
            assert_eq!(InstallMethod::parse(m.wire()), Some(m));
        }
        for s in InstallScope::ALL {
            assert_eq!(InstallScope::parse(s.wire()), Some(s));
        }
        // Equality, never a prefix or a case fold: `script` is not a method
        // and `Wizard` is not the wizard.
        assert_eq!(InstallMethod::parse("script"), None);
        assert_eq!(InstallMethod::parse("script-sh2"), None);
        assert_eq!(InstallMethod::parse("Wizard"), None);
        assert_eq!(InstallMethod::parse(""), None);
        assert_eq!(InstallScope::parse("user"), None);
        assert_eq!(InstallScope::parse("System"), None);
    }

    /// The server's clamp: a spelling from the future is `other`, a scope it
    /// does not know is `unknown`, a `run` that is not a short opaque token
    /// is dropped, and a known value passes through untouched. The enroll
    /// never fails on any of it.
    #[test]
    fn install_info_clamps_instead_of_refusing() {
        let known = InstallInfo {
            method: "script-ps1".into(),
            scope: "system".into(),
            run: Some("0123456789abcdef0123456789abcdef".into()),
        };
        assert_eq!(known.clamped(), known);

        let future = InstallInfo {
            method: "snap".into(),
            scope: "fleet-wide".into(),
            run: Some(
                "not a token: has spaces and is far too long to be a run id, even if it tried"
                    .into(),
            ),
        };
        assert_eq!(
            future.clamped(),
            InstallInfo {
                method: "other".into(),
                scope: "unknown".into(),
                run: None,
            }
        );
        // Whitespace is not a spelling either way, and an empty `run` is none.
        let padded = InstallInfo {
            method: " wizard ".into(),
            scope: "".into(),
            run: Some("   ".into()),
        };
        assert_eq!(
            padded.clamped(),
            InstallInfo {
                method: "wizard".into(),
                scope: "unknown".into(),
                run: None,
            }
        );
        assert_eq!(
            InstallInfo::unknown(),
            InstallInfo {
                method: "unknown".into(),
                scope: "unknown".into(),
                run: None,
            }
        );
        // On the wire, `scope` may be absent and `run` is omitted when unset.
        let wire: InstallInfo = serde_json::from_str(r#"{"method":"deb"}"#).unwrap();
        assert_eq!(wire.scope, "");
        assert_eq!(wire.clamped().scope, "unknown");
        assert_eq!(
            serde_json::to_string(&InstallInfo::new(
                InstallMethod::Manual,
                InstallScope::Unknown
            ))
            .unwrap(),
            r#"{"method":"manual","scope":"unknown"}"#
        );
    }

    /// FR-19 — the `relay-server` verb: spelling locked (a rename silently
    /// un-advertises the feature fleet-wide), and only ever equality-matched —
    /// a future `relay` verb must not be implied by it, nor it by `relay`.
    #[test]
    fn relay_server_verb_is_locked_and_only_equality_matched() {
        assert_eq!(RpcCap::RelayServer.wire(), "relay-server");
        assert!(matches!(
            RpcCap::from_wire("relay-server"),
            Some(RpcCap::RelayServer)
        ));
        assert!(RpcCap::from_wire("relay").is_none());
        assert!(RpcCap::from_wire("relay-server-x").is_none());
        assert!(RpcCap::from_wire("relay-serve").is_none());
        assert!(RpcCap::ALL.iter().any(|c| c.wire() == "relay-server"));
    }

    /// FR-19 gate 4: **no `relay_*` key may ever be server-pushable.**
    ///
    /// Matches on the PREFIX, not on a name, and that is the whole point. A
    /// per-name assertion would pass forever while covering nothing new, and
    /// this surface is going to grow (`relay_max_sessions`,
    /// `relay_static_endpoints`, …).
    ///
    /// ⚠️ The struct literal below is spelled out in full **on purpose** — no
    /// `..Default::default()`. Every field is populated so the serialised form
    /// cannot pass merely because a value was `None` and got skipped; and,
    /// more importantly, adding any field to [`DesiredConfig`] makes this test
    /// stop compiling, which forces whoever adds it to come here and read why
    /// a `relay_*` key must not be the field they are adding. A tolerant
    /// literal would let that change land silently.
    #[test]
    fn no_relay_key_is_server_pushable_via_desired_config() {
        let full = DesiredConfig {
            exec_enabled: Some(true),
            ssh_enabled: Some(true),
            ssh_authorized_keys: Some(vec!["ssh-ed25519 AAAA".into()]),
            ssh_account_mode: Some("console_user".into()),
            ssh_port: Some(2222),
            encoder_cells_deny: Some("none".into()),
            fps_deny: Some("*:144".into()),
            revision: 7,
            updated_by: None,
            updated_at: None,
        };
        let json = serde_json::to_string(&full).unwrap();
        assert!(
            !json.contains("relay_"),
            "a relay_* key reached DesiredConfig -- that is gate 4 becoming \
             server-settable, which is the one move FR-19's design exists to \
             prevent: {json}"
        );
        // And the round trip cannot smuggle one in either.
        let back: DesiredConfig = serde_json::from_str(
            r#"{"exec_enabled":true,"relay_server_enabled":true,"relay_server_port":9,"revision":1}"#,
        )
        .expect("unknown keys must be ignored, not fail the frame");
        assert_eq!(back.exec_enabled, Some(true));
        assert!(
            !serde_json::to_string(&back).unwrap().contains("relay_"),
            "a relay_* key survived a decode/encode round trip"
        );
    }

    /// FR-85 — the `record_*` twin of the test above. `record_dir` picks where
    /// the recorder writes and (P3) `record_remote_enabled` is the device's
    /// consent to being recorded from afar; a server that could push either
    /// would choose a write path on every device in the tenant, or turn remote
    /// recording on behind the owner's back. Both stay device-owned, so no
    /// `record_*` key may exist here. Spelled out in full, for the same reason
    /// as the relay test: a new field must make this stop compiling.
    /// FR-92 — the `keep_busy_*` twin. `keep_busy_enabled` is the device
    /// owner's consent to a controller keeping this pointer moving after the
    /// session has ended; a server that could push it would turn that on
    /// behind the owner's back on every device in the tenant. Spelled out in
    /// full, so a new `DesiredConfig` field must make this stop compiling.
    #[test]
    fn no_keep_busy_key_is_server_pushable_via_desired_config() {
        let full = DesiredConfig {
            exec_enabled: Some(true),
            ssh_enabled: Some(true),
            ssh_authorized_keys: Some(vec!["ssh-ed25519 AAAA".into()]),
            ssh_account_mode: Some("console_user".into()),
            ssh_port: Some(2222),
            encoder_cells_deny: Some("none".into()),
            fps_deny: Some("*:144".into()),
            revision: 7,
            updated_by: None,
            updated_at: None,
        };
        let json = serde_json::to_string(&full).unwrap();
        assert!(
            !json.contains("keep_busy"),
            "a keep_busy* key reached DesiredConfig -- a server-pushable keep-busy opt-in: {json}"
        );
        let back: DesiredConfig =
            serde_json::from_str(r#"{"exec_enabled":true,"keep_busy_enabled":true,"revision":1}"#)
                .expect("unknown keys must be ignored, not fail the frame");
        assert_eq!(back.exec_enabled, Some(true));
        assert!(
            !serde_json::to_string(&back).unwrap().contains("keep_busy"),
            "a keep_busy* key survived a decode/encode round trip"
        );
    }

    #[test]
    fn no_record_key_is_server_pushable_via_desired_config() {
        let full = DesiredConfig {
            exec_enabled: Some(true),
            ssh_enabled: Some(true),
            ssh_authorized_keys: Some(vec!["ssh-ed25519 AAAA".into()]),
            ssh_account_mode: Some("console_user".into()),
            ssh_port: Some(2222),
            encoder_cells_deny: Some("none".into()),
            fps_deny: Some("*:144".into()),
            revision: 7,
            updated_by: None,
            updated_at: None,
        };
        let json = serde_json::to_string(&full).unwrap();
        assert!(
            !json.contains("record_"),
            "a record_* key reached DesiredConfig -- a server-pushable recording \
             path or remote-recording opt-in: {json}"
        );
        let back: DesiredConfig = serde_json::from_str(
            r#"{"exec_enabled":true,"record_dir":"C:\\pwned","record_remote_enabled":true,"revision":1}"#,
        )
        .expect("unknown keys must be ignored, not fail the frame");
        assert_eq!(back.exec_enabled, Some(true));
        assert!(
            !serde_json::to_string(&back).unwrap().contains("record_"),
            "a record_* key survived a decode/encode round trip"
        );
    }

    /// FR-52 gates 3 and 4: **no `external_*` key may ever be
    /// server-pushable.**
    ///
    /// The `relay_*` rule above, applied to the surface where it bites
    /// hardest. `external_access_enabled` is the device owner's opt-in to
    /// being reachable by someone OUTSIDE the org, and the password behind
    /// gate 4 is held by the device precisely so this server cannot use it. A
    /// server that could push either would be able to admit a stranger to a
    /// machine whose owner never agreed — which is the single move FR-52's
    /// design exists to prevent.
    ///
    /// ⚠️ Prefix, not name: the surface grows (`external_access_verifier`,
    /// `external_consent_mode`, `external_max_permissions`), and the key that
    /// matters is always the one added after the test was written.
    ///
    /// ⚠️ The literal is spelled out in full for the reason the relay test's
    /// is — adding a field to [`DesiredConfig`] must stop this compiling, so
    /// whoever adds it reads why an `external_*` key must not be the one.
    #[test]
    fn no_external_key_is_server_pushable_via_desired_config() {
        let full = DesiredConfig {
            exec_enabled: Some(true),
            ssh_enabled: Some(true),
            ssh_authorized_keys: Some(vec!["ssh-ed25519 AAAA".into()]),
            ssh_account_mode: Some("console_user".into()),
            ssh_port: Some(2222),
            encoder_cells_deny: Some("none".into()),
            fps_deny: Some("*:144".into()),
            revision: 7,
            updated_by: None,
            updated_at: None,
        };
        let json = serde_json::to_string(&full).unwrap();
        assert!(
            !json.contains("external_"),
            "an external_* key reached DesiredConfig -- that is a server \
             opting a device in to being reachable by strangers, which is the \
             one move FR-52's design exists to prevent: {json}"
        );
        // And the round trip cannot smuggle one in either.
        let back: DesiredConfig = serde_json::from_str(
            r#"{"exec_enabled":true,"external_access_enabled":true,
                "external_access_verifier":"x","revision":1}"#,
        )
        .expect("unknown keys must be ignored, not fail the frame");
        assert_eq!(back.exec_enabled, Some(true));
        assert!(
            !serde_json::to_string(&back).unwrap().contains("external_"),
            "an external_* key survived a decode/encode round trip"
        );
    }

    /// FR-100 P1c: **no `peer_auth*` key may ever be server-pushable.**
    ///
    /// `peer_auth` is how a device checks the browser that offers it a
    /// session, and that check exists to hold when the server does not. A
    /// server that could push `peer_auth = off` would switch it off on every
    /// device in the tenant, which is exactly the hostile-server case FR-100
    /// is built against. Prefix, not name, and the literal spelled out in
    /// full, for the reasons the `external_*` test above gives.
    #[test]
    fn no_peer_auth_key_is_server_pushable_via_desired_config() {
        let full = DesiredConfig {
            exec_enabled: Some(true),
            ssh_enabled: Some(true),
            ssh_authorized_keys: Some(vec!["ssh-ed25519 AAAA".into()]),
            ssh_account_mode: Some("console_user".into()),
            ssh_port: Some(2222),
            encoder_cells_deny: Some("none".into()),
            fps_deny: Some("*:144".into()),
            revision: 7,
            updated_by: None,
            updated_at: None,
        };
        let json = serde_json::to_string(&full).unwrap();
        assert!(
            !json.contains("peer_auth"),
            "a peer_auth* key reached DesiredConfig -- a server able to switch \
             off the device's check of the browsers connecting to it: {json}"
        );
        let back: DesiredConfig = serde_json::from_str(
            r#"{"exec_enabled":true,"peer_auth":"off","peer_auth_pins":"reset","revision":1}"#,
        )
        .expect("unknown keys must be ignored, not fail the frame");
        assert_eq!(back.exec_enabled, Some(true));
        assert!(
            !serde_json::to_string(&back).unwrap().contains("peer_auth"),
            "a peer_auth* key survived a decode/encode round trip"
        );
    }

    /// WIRE LOCK. These exact strings are what every deployed agent already
    /// sends and what the server gates on; changing one does not fail loudly,
    /// it silently makes every existing device look like it lacks the feature.
    /// FR-97 P0c — the honest "no" rides the caps. Its keys and the code a
    /// viewer hides on are a compatibility surface with every viewer, and an
    /// absent map must read as "nothing withheld", never as "everything".
    #[test]
    fn unavailable_wire_shape_is_locked() {
        assert_eq!(
            Unavailable::KEYS,
            [
                "audio",
                "clipboard",
                "clipboard-image-events",
                "sas",
                // FR-97 P3e-2 — added, never renamed: an older viewer ignores it.
                "display-match"
            ]
        );
        assert_eq!(Unavailable::NOT_APPLICABLE, "not-applicable");
        let mut caps = AgentCaps::default();
        caps.unavailable.insert(
            "audio".into(),
            Unavailable::new("no-backend", "no sound here"),
        );
        let v = serde_json::to_value(&caps).unwrap();
        assert_eq!(
            v["unavailable"]["audio"],
            serde_json::json!({"code": "no-backend", "reason": "no sound here"})
        );
        let back: AgentCaps = serde_json::from_value(v).unwrap();
        assert_eq!(back.unavailable["audio"].code, "no-backend");
        // The server stores caps on the agent row as BSON.
        let stored: AgentCaps = bson::from_bson(bson::to_bson(&caps).unwrap()).unwrap();
        assert_eq!(stored.unavailable["audio"].reason, "no sound here");
        // Empty stays off the wire, and an older agent's caps (no key) read
        // as nothing withheld.
        let plain = serde_json::to_value(AgentCaps::default()).unwrap();
        assert!(plain.get("unavailable").is_none(), "{plain}");
        let old: AgentCaps = serde_json::from_value(plain).unwrap();
        assert!(old.unavailable.is_empty());
    }

    /// FR-67 P7 — the hello's `update_mode`: absent on the wire when unset (an
    /// older agent's hello stays byte-identical), round-trips, and maps to a
    /// refusal only for the two values that mean "will not act on it".
    /// Unknown words are ignored, never an error.
    #[test]
    fn update_mode_round_trips_and_maps_to_refusals() {
        let unset = AgentCaps::default();
        assert!(
            !serde_json::to_string(&unset)
                .unwrap()
                .contains("update_mode")
        );
        assert_eq!(unset.update_refusal(), None);

        for (word, want) in [
            ("primary_org", Some(UpdateRefusal::PrimaryOrg)),
            ("off", Some(UpdateRefusal::AutoUpdateOff)),
            ("self", None),
            ("some-future-word", None),
        ] {
            let caps = AgentCaps {
                update_mode: Some(word.into()),
                ..Default::default()
            };
            let json = serde_json::to_value(&caps).unwrap();
            assert_eq!(json["update_mode"], word);
            let back: AgentCaps = serde_json::from_value(json).unwrap();
            assert_eq!(back.update_refusal(), want, "{word}");
            // The server stores caps on the agent row as BSON, and the
            // update routes read them back from there.
            let stored: AgentCaps = bson::from_bson(bson::to_bson(&caps).unwrap()).unwrap();
            assert_eq!(stored.update_refusal(), want, "{word} via BSON");
        }

        // An older agent's hello, without the field.
        let plain = serde_json::to_value(AgentCaps::default()).unwrap();
        assert!(plain.get("update_mode").is_none(), "{plain}");
        let old: AgentCaps = serde_json::from_value(plain).unwrap();
        assert_eq!(old.update_mode, None);
        assert_eq!(old.update_refusal(), None);

        // The codes a client branches on, spelled out so a rename is deliberate.
        assert_eq!(UpdateRefusal::PrimaryOrg.code(), "primary_org");
        assert_eq!(UpdateRefusal::AutoUpdateOff.code(), "auto_update_off");
        assert!(UpdateRefusal::PrimaryOrg.reason().contains("set-primary"));
        assert!(
            UpdateRefusal::AutoUpdateOff
                .reason()
                .contains("auto_update")
        );
    }

    /// Spelled out literally rather than derived, so a rename has to be a
    /// deliberate edit here.
    #[test]
    fn rpc_cap_wire_strings_are_locked() {
        assert_eq!(RpcCap::Exec.wire(), "exec");
        assert_eq!(RpcCap::Originate.wire(), "originate");
        assert_eq!(RpcCap::Ssh.wire(), "ssh");
        assert_eq!(RpcCap::SshConsent.wire(), "ssh-consent");
        assert_eq!(RpcCap::Config.wire(), "config");
        assert_eq!(RpcCap::ConfigReport.wire(), "config-report");
        assert_eq!(RpcCap::KeyRotate.wire(), "key-rotate");
        assert_eq!(RpcCap::ManagedForwardNft.wire(), "managed-forward-nft");
        assert_eq!(RpcCap::SshGrantAck.wire(), "ssh-grant-ack");
        assert_eq!(RpcCap::Hive.wire(), "hive");
        assert_eq!(RpcCap::HiveView.wire(), "hive-view");
        assert_eq!(RpcCap::HiveMemory.wire(), "hive-memory");
        assert_eq!(RpcCap::HiveAdopt.wire(), "hive-adopt");
        assert_eq!(RpcCap::HiveReplica.wire(), "hive-replica");
        assert_eq!(RpcCap::HiveArchive.wire(), "hive-archive");
        assert_eq!(RpcCap::HiveStream.wire(), "hive-stream");
        assert_eq!(RpcCap::HiveLease.wire(), "hive-lease");
        assert_eq!(RpcCap::HivePromote.wire(), "hive-promote");
        assert_eq!(RpcCap::HiveTeleport.wire(), "hive-teleport");
        assert_eq!(RpcCap::HiveFork.wire(), "hive-fork");
        assert_eq!(RpcCap::HiveManage.wire(), "hive-manage");
        assert_eq!(RpcCap::HivePurge.wire(), "hive-purge");
        assert_eq!(RpcCap::HivePurgeAll.wire(), "hive-purge-all");
        assert_eq!(RpcCap::HivePurgeDrain.wire(), "hive-purge-drain");
        assert_eq!(RpcCap::HiveSearch.wire(), "hive-search");
        assert_eq!(RpcCap::PrivacyMode.wire(), "privacy-mode");
        assert_eq!(RpcCap::PrivacyAvailable.wire(), "privacy-available");
        assert_eq!(RpcCap::SessionPolicy.wire(), "session-policy");
        assert_eq!(RpcCap::IdleTimeout.wire(), "idle-timeout");
        assert_eq!(RpcCap::LockOnEnd.wire(), "lock-on-end");
        assert_eq!(RpcCap::ConsoleUser.wire(), "console-user");
        assert_eq!(RpcCap::Vault.wire(), "vault");
        assert_eq!(RpcCap::ExternalAccess.wire(), "external-access");
        assert_eq!(RpcCap::ExternalSession.wire(), "external-session");
        assert_eq!(RpcCap::PeerAuth.wire(), "peer-auth");
    }

    /// FR-101 P4b-2 — the device's idle setting as a limit: unset and `0`
    /// are no limit (0 = "never", as RDP spells it), minutes become seconds,
    /// and anything past a day is held to a day.
    #[test]
    fn the_devices_idle_minutes_read_as_a_limit() {
        let with = |m: Option<u32>| AccessPolicy {
            auto_terminate_idle_minutes: m,
            ..Default::default()
        };
        assert_eq!(with(None).idle_limit_secs(), None);
        assert_eq!(with(Some(0)).idle_limit_secs(), None);
        assert_eq!(with(Some(1)).idle_limit_secs(), Some(60));
        assert_eq!(with(Some(30)).idle_limit_secs(), Some(1800));
        assert_eq!(with(Some(1440)).idle_limit_secs(), Some(86_400));
        assert_eq!(with(Some(u32::MAX)).idle_limit_secs(), Some(86_400));
    }

    /// FR-101 P4b-2 — the org's idle limit and the device's combine to the
    /// SHORTER, and either alone stands.
    #[test]
    fn the_shorter_idle_limit_wins() {
        assert_eq!(stricter_idle_limit(None, None), None);
        assert_eq!(stricter_idle_limit(Some(900), None), Some(900));
        assert_eq!(stricter_idle_limit(None, Some(300)), Some(300));
        assert_eq!(stricter_idle_limit(Some(900), Some(300)), Some(300));
        assert_eq!(stricter_idle_limit(Some(300), Some(900)), Some(300));
    }

    /// FR-101 P2b — how an org's policy and a device's floor combine, on
    /// both ends: `off` beats `ask` beats `on`, in either order.
    #[test]
    fn the_stricter_feature_policy_wins_in_either_order() {
        use FeaturePolicy::{Ask, Off, On};
        for (a, b, want) in [
            (On, On, On),
            (On, Ask, Ask),
            (Ask, On, Ask),
            (Ask, Ask, Ask),
            (On, Off, Off),
            (Off, On, Off),
            (Ask, Off, Off),
            (Off, Ask, Off),
            (Off, Off, Off),
        ] {
            assert_eq!(a.stricter(b), want, "{a:?} {b:?}");
        }
    }

    /// FR-101 P2b — the device's floor in its caps: absent when it restricts
    /// nothing (and from every older agent), a policy otherwise; an older
    /// server's caps blob without it reads as no floor.
    #[test]
    fn agent_caps_session_policy_is_additive() {
        let none = serde_json::to_value(AgentCaps::default()).unwrap();
        assert!(none.get("session_policy").is_none(), "{none}");
        let caps = AgentCaps {
            session_policy: Some(SessionPolicy {
                files: FeaturePolicy::Off,
                ..SessionPolicy::default()
            }),
            ..Default::default()
        };
        let v = serde_json::to_value(&caps).unwrap();
        assert_eq!(
            v["session_policy"],
            serde_json::json!({"clipboard": "on", "files": "off", "audio": "on"})
        );
        let back: AgentCaps = serde_json::from_value(v).unwrap();
        assert_eq!(back.session_policy, caps.session_policy);
        let old: AgentCaps = serde_json::from_value(serde_json::json!({
            "hw_encoders": [], "codecs": [], "has_input_permission": true,
            "supports_clipboard": true, "supports_file_transfer": true,
            "max_simultaneous_sessions": 1,
        }))
        .unwrap();
        assert_eq!(old.session_policy, None);
    }

    /// FR-99 — the two privacy words are different promises, and neither is
    /// a prefix of the other. `privacy-available` says a curtain is POSSIBLE;
    /// only `privacy-mode` says the owner allowed it. A matcher that read
    /// either word as both would hand `PRIVACY` to a device whose owner said
    /// no — and a word from a newer agent must stay ignored.
    #[test]
    fn privacy_available_does_not_imply_privacy_mode() {
        let possible = AgentCaps {
            rpc: vec!["privacy-available".into()],
            ..Default::default()
        };
        assert!(possible.has_rpc(RpcCap::PrivacyAvailable));
        assert!(!possible.has_rpc(RpcCap::PrivacyMode));
        let serving = AgentCaps {
            rpc: vec!["privacy-mode".into()],
            ..Default::default()
        };
        assert!(serving.has_rpc(RpcCap::PrivacyMode));
        assert!(!serving.has_rpc(RpcCap::PrivacyAvailable));
        let near_misses = AgentCaps {
            rpc: vec![
                "privacy".into(),
                "privacy-mode-2".into(),
                "Privacy-Mode".into(),
            ],
            ..Default::default()
        };
        assert!(!near_misses.has_rpc(RpcCap::PrivacyMode));
        assert!(!near_misses.has_rpc(RpcCap::PrivacyAvailable));
    }

    /// FR-52 P4 — a P3 agent advertises `external-access` (it can LOG IN an
    /// outsider) but ignores `Request.external`, so it would serve one as an
    /// ordinary controller: the password proven, the session bound to nothing.
    /// The server opens external sessions on `external-session` alone.
    #[test]
    fn external_access_does_not_imply_external_session() {
        let p3 = AgentCaps {
            rpc: vec!["external-access".into()],
            ..AgentCaps::default()
        };
        assert!(p3.has_rpc(RpcCap::ExternalAccess));
        assert!(!p3.has_rpc(RpcCap::ExternalSession));
    }

    /// Every prefix relationship between verbs is a KNOWN one.
    ///
    /// A blanket "no verb is a prefix of another" would be false and always
    /// has been: `ssh`/`ssh-consent` is deliberate, and `config`/`config-report`
    /// now is too. Both encode the same idea — "understands the feature" and
    /// "actually does the thing" are different questions — and both are why
    /// matching is equality everywhere.
    ///
    /// So the claim worth locking is not "there are none" but "there are
    /// exactly these". A THIRD pair appearing by accident (say someone adds
    /// `exec-batch`) fails here and has to be looked at, because each such
    /// pair is one more place a sloppy `starts_with` could be accidentally
    /// right on the devices that already exist.
    #[test]
    fn the_only_prefix_related_verbs_are_the_deliberate_ones() {
        const KNOWN: [(RpcCap, RpcCap); 24] = [
            (RpcCap::Ssh, RpcCap::SshConsent),
            (RpcCap::Config, RpcCap::ConfigReport),
            // MeshHarbor #20 — "runs managed forwards in userspace" is not
            // "runs them on an owned nft table". Locked by
            // `managed_forward_does_not_imply_managed_forward_nft`.
            (RpcCap::ManagedForward, RpcCap::ManagedForwardNft),
            // FR-83 — the third, and the same idea again: "runs an SSH
            // server" is not "confirms a grant". Locked by
            // `ssh_does_not_imply_ssh_grant_ack`.
            (RpcCap::Ssh, RpcCap::SshGrantAck),
            // FR-90 P0d-2 — "runs sessions" is not "serves them to a
            // browser". Locked by `hive_does_not_imply_hive_view`.
            (RpcCap::Hive, RpcCap::HiveView),
            // FR-90 P1e — nor "understands core memory". Locked by
            // `hive_does_not_imply_hive_memory`.
            (RpcCap::Hive, RpcCap::HiveMemory),
            // FR-90 P1j — nor "mirrors adopted terminal sessions". Locked by
            // `hive_does_not_imply_hive_adopt`.
            (RpcCap::Hive, RpcCap::HiveAdopt),
            // FR-90 P2c — nor "holds copies of other devices' sessions", nor
            // "offers itself as an archive". Locked by
            // `hive_replica_and_hive_archive_are_promises_of_their_own`.
            (RpcCap::Hive, RpcCap::HiveReplica),
            (RpcCap::Hive, RpcCap::HiveArchive),
            // FR-90 P2d — nor "carries replica streams". Locked by
            // `hive_stream_is_a_promise_of_its_own`.
            (RpcCap::Hive, RpcCap::HiveStream),
            // FR-90 P2e-2 — nor "holds a leased session to the server's
            // word". Locked by `hive_lease_is_a_promise_of_its_own`.
            (RpcCap::Hive, RpcCap::HiveLease),
            // FR-90 P2e-3 — nor "takes part in a promotion". Locked by
            // `hive_promote_is_a_promise_of_its_own`.
            (RpcCap::Hive, RpcCap::HivePromote),
            // FR-90 P2f-1a — nor "takes part in a teleport". Locked by
            // `hive_teleport_is_a_promise_of_its_own`.
            (RpcCap::Hive, RpcCap::HiveTeleport),
            // FR-90 P2f-3a — nor "starts a fork from a copy". Locked by
            // `hive_fork_is_a_promise_of_its_own`.
            (RpcCap::Hive, RpcCap::HiveFork),
            // FR-90 P2f-4a — nor "makes an ended terminal session a managed
            // one". Locked by `hive_manage_is_a_promise_of_its_own`.
            (RpcCap::Hive, RpcCap::HiveManage),
            // FR-90 P2g-1 — nor "purges a session and answers it". Locked by
            // `hive_purge_is_a_promise_of_its_own`.
            (RpcCap::Hive, RpcCap::HivePurge),
            // FR-90 P2g-4a — nor "purges everything it holds at its removal",
            // and neither is "purges a session". Locked by
            // `hive_purge_all_is_a_promise_of_its_own`.
            (RpcCap::Hive, RpcCap::HivePurgeAll),
            (RpcCap::HivePurge, RpcCap::HivePurgeAll),
            // #2294 — nor "finishes a removal purge before its goodbye exit",
            // and neither is "purges a session". Locked by
            // `hive_purge_drain_is_a_promise_of_its_own`.
            (RpcCap::Hive, RpcCap::HivePurgeDrain),
            (RpcCap::HivePurge, RpcCap::HivePurgeDrain),
            // FR-90 P2i-1 — nor "answers a search over its copies". Locked by
            // `hive_search_is_a_promise_of_its_own`.
            (RpcCap::Hive, RpcCap::HiveSearch),
            // FR-94 — "runs Fleet RPC" is not "runs it as SYSTEM through a
            // service". Locked by `exec_does_not_imply_exec_system`.
            (RpcCap::Exec, RpcCap::ExecSystem),
            // FR-105 — "runs an SSH server" is not "serves SSH from the
            // SYSTEM service". Locked by `ssh_does_not_imply_ssh_system`.
            (RpcCap::Ssh, RpcCap::SshSystem),
            // FR-90 P3-8 — nor "holds a session's grant to one command".
            // Locked by `ssh_does_not_imply_ssh_one_command`.
            (RpcCap::Ssh, RpcCap::SshOneCommand),
        ];
        for a in RpcCap::ALL {
            for b in RpcCap::ALL {
                if a == b || !b.wire().starts_with(a.wire()) {
                    continue;
                }
                assert!(
                    KNOWN.contains(&(a, b)),
                    "`{}` is an UNPLANNED prefix of `{}` — either rename it or \
                     add the pair to KNOWN and write the equality-matching test \
                     that goes with it",
                    a.wire(),
                    b.wire()
                );
            }
        }
    }

    /// The `SshConsent` shape, recurring exactly as its doc predicted.
    ///
    /// Agents rc.457/rc.458 shipped `config` and report NOTHING back — they
    /// apply a pushed config in silence. A matcher using `starts_with` (or a
    /// design that folded the report into `config`) would mark every one of
    /// them as reporting, and the dashboard would wait forever for an answer
    /// that was never going to come, while showing the operator a state it
    /// had no evidence for.
    #[test]
    fn config_does_not_imply_config_report() {
        let rc458_era = AgentCaps {
            rpc: vec!["exec".into(), "originate".into(), "config".into()],
            ..Default::default()
        };
        assert!(rc458_era.has_rpc(RpcCap::Config));
        assert!(
            !rc458_era.has_rpc(RpcCap::ConfigReport),
            "an rc.458-era agent understands a pushed config but never reports \
             on it — it must NOT read as report-capable"
        );

        let both = AgentCaps {
            rpc: vec!["config".into(), "config-report".into()],
            ..Default::default()
        };
        assert!(both.has_rpc(RpcCap::Config) && both.has_rpc(RpcCap::ConfigReport));
    }

    #[test]
    fn all_entries_are_unique_and_round_trip() {
        let mut seen = std::collections::HashSet::new();
        for cap in RpcCap::ALL {
            assert!(seen.insert(cap.wire()), "duplicate wire string {cap:?}");
            assert_eq!(RpcCap::from_wire(cap.wire()), Some(cap));
        }
        assert_eq!(seen.len(), RpcCap::ALL.len());
        assert_eq!(RpcCap::from_wire("no-such-verb"), None);
    }

    /// FR-85 P3 — `remote` is a PREFIX of `remote-audio`: a prefix matcher
    /// would read every recording-capable device as audio-capable, and the
    /// hub would hand computer audio to controllers of devices whose owners
    /// allowed only the picture.
    #[test]
    fn remote_recording_does_not_imply_remote_audio() {
        let video_only = AgentCaps {
            record: vec!["remote".into()],
            ..Default::default()
        };
        assert!(video_only.has_record(RecordCap::Remote));
        assert!(!video_only.has_record(RecordCap::RemoteAudio));
        let both = AgentCaps {
            record: vec!["remote".into(), "remote-audio".into()],
            ..Default::default()
        };
        assert!(both.has_record(RecordCap::Remote) && both.has_record(RecordCap::RemoteAudio));
        // An agent that predates the field, or never opted in, sends no
        // `record` key at all (a round trip, like `absent_rpc_list_…`).
        let wire = serde_json::to_string(&AgentCaps::default()).unwrap();
        assert!(!wire.contains("\"record\""), "{wire}");
        let old: AgentCaps = serde_json::from_str(&wire).unwrap();
        assert!(old.record.is_empty() && !old.has_record(RecordCap::Remote));
        // A word from a newer agent is ignored, never an error.
        let future = AgentCaps {
            record: vec!["remote-4k".into()],
            ..Default::default()
        };
        assert!(!future.has_record(RecordCap::Remote));
        // The wire words are a compatibility surface.
        let words: Vec<&str> = RecordCap::ALL.iter().map(|c| c.wire()).collect();
        assert_eq!(words, vec!["remote", "remote-audio", "available"]);
        for c in RecordCap::ALL {
            assert_eq!(RecordCap::from_wire(c.wire()), Some(c));
        }
    }

    /// FR-85 — the activity words a device reports are a compatibility
    /// surface (the server stores them, the admin reads them): pinned, with
    /// P3b-3's `reattached`.
    #[test]
    fn recording_activity_kinds_keep_their_wire_names() {
        use RecordingActivityKind::*;
        for (k, w) in [
            (PromptGranted, "prompt_granted"),
            (PromptDenied, "prompt_denied"),
            (PromptTimedOut, "prompt_timed_out"),
            (Started, "started"),
            (Stopped, "stopped"),
            (Refused, "refused"),
            (Downloaded, "downloaded"),
            (Reattached, "reattached"),
        ] {
            assert_eq!(serde_json::to_value(k).unwrap(), serde_json::json!(w));
            let back: RecordingActivityKind = serde_json::from_value(serde_json::json!(w)).unwrap();
            assert_eq!(back, k);
        }
    }

    /// FR-101 P3 — the stored kinds are read by the activity route and by
    /// anyone querying the collection; a rename strands every row before it.
    #[test]
    fn transfer_activity_kinds_keep_their_wire_names() {
        use TransferActivityKind::*;
        for (k, w) in [
            (ClipboardToHost, "clipboard_to_host"),
            (ClipboardFromHost, "clipboard_from_host"),
            (FileToHost, "file_to_host"),
            (FileFromHost, "file_from_host"),
        ] {
            assert_eq!(serde_json::to_value(k).unwrap(), serde_json::json!(w));
            let back: TransferActivityKind = serde_json::from_value(serde_json::json!(w)).unwrap();
            assert_eq!(back, k);
        }
    }

    /// FR-99 P3 — the three spellings, the order `stricter` relies on, and an
    /// unknown value reading as the strictest rather than failing.
    #[test]
    fn lock_on_end_reads_and_orders_as_documented() {
        use LockOnEnd::*;
        for (p, w) in [(Never, "never"), (Auto, "auto"), (Always, "always")] {
            assert_eq!(serde_json::to_value(p).unwrap(), serde_json::json!(w));
            assert_eq!(
                serde_json::from_value::<LockOnEnd>(serde_json::json!(w)).unwrap(),
                p
            );
        }
        assert_eq!(LockOnEnd::default(), Never);
        assert!(Never < Auto && Auto < Always);
        assert_eq!(Never.stricter(Auto), Auto);
        assert_eq!(Always.stricter(Never), Always);
        assert_eq!(Auto.stricter(Auto), Auto);
        for unknown in [
            serde_json::json!("sometimes"),
            serde_json::json!(3),
            serde_json::json!(null),
        ] {
            assert_eq!(
                serde_json::from_value::<LockOnEnd>(unknown).unwrap(),
                Always
            );
        }
    }

    #[test]
    fn privacy_activity_kinds_keep_their_wire_names() {
        use PrivacyActivityKind::*;
        for (k, w) in [(On, "on"), (Off, "off"), (Refused, "refused")] {
            assert_eq!(serde_json::to_value(k).unwrap(), serde_json::json!(w));
            let back: PrivacyActivityKind = serde_json::from_value(serde_json::json!(w)).unwrap();
            assert_eq!(back, k);
        }
    }

    /// FR-99 P1d — a reason is a short code. Free text, a path or markup from
    /// a host that may be compromised never passes.
    #[test]
    fn only_a_short_code_passes_for_a_privacy_reason() {
        let (longest, too_long) = ("a".repeat(64), "a".repeat(65));
        for ok in [
            "controller",
            "session_end",
            "worker_exit",
            "no_curtain",
            "x",
            longest.as_str(),
        ] {
            assert!(PrivacyActivityEvent::is_reason_code(ok), "{ok}");
        }
        for bad in [
            "",
            "Controller",
            "session end",
            "worker-exit",
            "<b>",
            "C:\\x",
            too_long.as_str(),
        ] {
            assert!(!PrivacyActivityEvent::is_reason_code(bad), "{bad}");
        }
    }

    /// FR-101 P3 — a name hash is 64 lowercase hex digits and nothing else.
    /// The field is what a device sends instead of the name; free text there
    /// would let a host store the very name the hash keeps out.
    #[test]
    fn only_a_sha256_in_lowercase_hex_passes_for_a_name_hash() {
        let ok = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert!(TransferActivityEvent::is_name_hash(ok));
        assert!(!TransferActivityEvent::is_name_hash(&ok.to_uppercase()));
        assert!(!TransferActivityEvent::is_name_hash(&ok[..63]));
        assert!(!TransferActivityEvent::is_name_hash(&format!("{ok}0")));
        assert!(!TransferActivityEvent::is_name_hash("salaries 2026.xlsx"));
        assert!(!TransferActivityEvent::is_name_hash(&"g".repeat(64)));
        assert!(!TransferActivityEvent::is_name_hash(""));
    }

    /// P3c-2 — `available` says the device HAS a recorder; it is never
    /// permission. An agent whose owner has not opted in advertises it alone,
    /// and that must not read as serving remote recording.
    #[test]
    fn a_recorder_being_available_is_not_permission_to_record() {
        let not_opted_in = AgentCaps {
            record: vec!["available".into()],
            ..Default::default()
        };
        assert!(not_opted_in.has_record(RecordCap::Available));
        assert!(!not_opted_in.has_record(RecordCap::Remote));
        assert!(!not_opted_in.has_record(RecordCap::RemoteAudio));
        let serving = AgentCaps {
            record: vec!["available".into(), "remote".into()],
            ..Default::default()
        };
        assert!(serving.has_record(RecordCap::Remote));
        assert!(!serving.has_record(RecordCap::RemoteAudio));
    }

    /// ⚠️ `ssh` is a PREFIX of `ssh-consent`, and the difference between them
    /// is the difference between "runs an SSH server" and "actually honours
    /// `consent_mode`". A matcher using `starts_with`/`contains` instead of
    /// equality would make every ssh-capable agent look consent-capable — and
    /// re-introduce exactly the lie P5d removed, on every device in the field
    /// at once. Lock the distinction.
    #[test]
    fn ssh_does_not_imply_ssh_consent() {
        let ssh_only = AgentCaps {
            rpc: vec!["exec".into(), "originate".into(), "ssh".into()],
            ..Default::default()
        };
        assert!(ssh_only.has_rpc(RpcCap::Ssh));
        assert!(
            !ssh_only.has_rpc(RpcCap::SshConsent),
            "an rc.419-era agent must NOT read as consent-capable"
        );

        let both = AgentCaps {
            rpc: vec!["ssh".into(), "ssh-consent".into()],
            ..Default::default()
        };
        assert!(both.has_rpc(RpcCap::Ssh) && both.has_rpc(RpcCap::SshConsent));
    }

    /// FR-94 — `exec` is a PREFIX of `exec-system`. Every agent since Fleet
    /// RPC advertises `exec`, so a prefix matcher would route every command
    /// to a SYSTEM-service doorbell that no agent before FR-94 can answer.
    #[test]
    fn exec_does_not_imply_exec_system() {
        let exec_only = AgentCaps {
            rpc: vec!["exec".into(), "originate".into()],
            ..Default::default()
        };
        assert!(exec_only.has_rpc(RpcCap::Exec));
        assert!(
            !exec_only.has_rpc(RpcCap::ExecSystem),
            "an agent before FR-94 must NOT read as able to run exec as SYSTEM"
        );
        let both = AgentCaps {
            rpc: vec!["exec".into(), "exec-system".into()],
            ..Default::default()
        };
        assert!(both.has_rpc(RpcCap::Exec) && both.has_rpc(RpcCap::ExecSystem));
        assert_eq!(RpcCap::ExecSystem.wire(), "exec-system");
        assert_eq!(RpcCap::from_wire("exec-system"), Some(RpcCap::ExecSystem));
    }

    /// FR-105 — the anchor's SSH ceiling: `system` allows SYSTEM and the
    /// signed-in user, `console_user` only the user, `off` nothing; a named
    /// account is never the service's.
    #[test]
    fn the_ssh_ceiling_permits_only_what_it_names() {
        use SshAccountMode::{ConsoleUser, Daemon, Named};
        let c = SshServiceCeiling::System;
        assert!(c.permits(Daemon) && c.permits(ConsoleUser) && !c.permits(Named));
        let c = SshServiceCeiling::ConsoleUser;
        assert!(!c.permits(Daemon) && c.permits(ConsoleUser) && !c.permits(Named));
        let c = SshServiceCeiling::Off;
        assert!(!c.permits(Daemon) && !c.permits(ConsoleUser) && !c.permits(Named));
        assert_eq!(SshServiceCeiling::default(), SshServiceCeiling::Off);
        assert_eq!(
            serde_json::to_string(&SshServiceCeiling::ConsoleUser).unwrap(),
            r#""console_user""#
        );
    }

    /// FR-105 — every SSH-capable agent advertises `ssh`, and on an attended
    /// Windows install that server is the signed-in user. A prefix matcher
    /// would route grants to a SYSTEM service that does not exist, and hand
    /// the caller a host key nothing on the device holds.
    #[test]
    fn ssh_does_not_imply_ssh_system() {
        let ssh_only = AgentCaps {
            rpc: vec!["ssh".into(), "ssh-consent".into(), "ssh-grant-ack".into()],
            ..Default::default()
        };
        assert!(ssh_only.has_rpc(RpcCap::Ssh));
        assert!(
            !ssh_only.has_rpc(RpcCap::SshSystem),
            "an agent before FR-105 must NOT read as serving SSH as SYSTEM"
        );
        let both = AgentCaps {
            rpc: vec!["ssh".into(), "ssh-system".into()],
            ..Default::default()
        };
        assert!(both.has_rpc(RpcCap::Ssh) && both.has_rpc(RpcCap::SshSystem));
        assert_eq!(RpcCap::SshSystem.wire(), "ssh-system");
        assert_eq!(RpcCap::from_wire("ssh-system"), Some(RpcCap::SshSystem));
    }

    /// FR-90 P3-8 — every SSH-capable agent advertises `ssh`, and one that
    /// cannot read `one_command` would serve an agent session's key a shell.
    /// A prefix matcher would send a session's grant to exactly that device.
    #[test]
    fn ssh_does_not_imply_ssh_one_command() {
        let ssh_only = AgentCaps {
            rpc: vec![
                "ssh".into(),
                "ssh-consent".into(),
                "ssh-grant-ack".into(),
                "ssh-system".into(),
            ],
            ..Default::default()
        };
        assert!(ssh_only.has_rpc(RpcCap::Ssh));
        assert!(
            !ssh_only.has_rpc(RpcCap::SshOneCommand),
            "an agent before P3-8-2a must NOT read as holding a grant to one command"
        );
        let both = AgentCaps {
            rpc: vec!["ssh".into(), "ssh-one-command".into()],
            ..Default::default()
        };
        assert!(both.has_rpc(RpcCap::Ssh) && both.has_rpc(RpcCap::SshOneCommand));
        assert_eq!(RpcCap::SshOneCommand.wire(), "ssh-one-command");
        assert_eq!(
            RpcCap::from_wire("ssh-one-command"),
            Some(RpcCap::SshOneCommand)
        );
    }

    /// FR-90 P3-8-1b — an agent session's three refusals, spelled out so a
    /// rename is a deliberate edit: a session's daemon shows them in words.
    #[test]
    fn ssh_session_refusals_are_locked() {
        for (reason, word) in [
            (SshDenyReason::TicketRefused, "ticket_refused"),
            (SshDenyReason::SessionNotAllowed, "session_not_allowed"),
            (SshDenyReason::TargetTooOld, "target_too_old"),
        ] {
            assert_eq!(
                serde_json::to_value(reason).unwrap(),
                serde_json::json!(word)
            );
            assert_eq!(
                serde_json::from_value::<SshDenyReason>(serde_json::json!(word)).unwrap(),
                reason
            );
            assert!(!reason.message().is_empty(), "{word}");
        }
    }

    /// FR-83 — every agent before the ack advertises `ssh` (and most
    /// `ssh-consent`) and never answers a grant. A prefix matcher would make
    /// the server wait out its full bound on every grant to every one of them
    /// and then refuse the session as unconfirmed — turning an intermittent
    /// race into a fleet-wide outage of roomler SSH.
    #[test]
    fn managed_forward_does_not_imply_managed_forward_nft() {
        let userspace = AgentCaps {
            rpc: vec!["managed-forward".into()],
            ..Default::default()
        };
        assert!(userspace.has_rpc(RpcCap::ManagedForward));
        assert!(
            !userspace.has_rpc(RpcCap::ManagedForwardNft),
            "a userspace-only agent must NOT read as running the nft backend"
        );
        let native = AgentCaps {
            rpc: vec!["managed-forward".into(), "managed-forward-nft".into()],
            ..Default::default()
        };
        assert!(native.has_rpc(RpcCap::ManagedForwardNft));
    }

    #[test]
    fn ssh_does_not_imply_ssh_grant_ack() {
        let pre_ack = AgentCaps {
            rpc: vec!["exec".into(), "ssh".into(), "ssh-consent".into()],
            ..Default::default()
        };
        assert!(pre_ack.has_rpc(RpcCap::Ssh));
        assert!(
            !pre_ack.has_rpc(RpcCap::SshGrantAck),
            "an agent that never acks must NOT read as ack-capable"
        );

        let acking = AgentCaps {
            rpc: vec!["ssh".into(), "ssh-consent".into(), "ssh-grant-ack".into()],
            ..Default::default()
        };
        assert!(acking.has_rpc(RpcCap::SshGrantAck));
    }

    /// FR-90 P3-8-1a — an account mode's word is serde's, spelled out here so
    /// a rename is a deliberate edit: a policy's `context.account ==
    /// "daemon"` and a ticket's account must read what `rc:ssh.grant` sends.
    #[test]
    fn ssh_account_mode_words_are_locked_and_are_serdes() {
        let words: Vec<&str> = SshAccountMode::ALL.iter().map(|m| m.wire()).collect();
        assert_eq!(words, ["daemon", "console_user", "named"]);
        for m in SshAccountMode::ALL {
            assert_eq!(
                serde_json::to_value(m).unwrap(),
                serde_json::json!(m.wire())
            );
            assert_eq!(SshAccountMode::from_wire(m.wire()), Some(m));
        }
        assert_eq!(SshAccountMode::from_wire("root"), None);
        assert_eq!(SshAccountMode::from_wire("Daemon"), None);
    }

    /// FR-90 — `hive` is matched by equality, in both directions that
    /// matter: the replica verb (P2c) must not read as "runs sessions", and no
    /// other verb reads as `hive`. A device that holds copies of other
    /// devices' sessions has not agreed to run them.
    #[test]
    fn hive_is_matched_by_equality() {
        let runs = AgentCaps {
            rpc: vec!["exec".into(), "hive".into()],
            ..Default::default()
        };
        assert!(runs.has_rpc(RpcCap::Hive));

        let replica_only = AgentCaps {
            rpc: vec!["hive-replica".into(), "hives".into()],
            ..Default::default()
        };
        assert!(
            !replica_only.has_rpc(RpcCap::Hive),
            "a verb that merely starts with `hive` must not read as `hive`"
        );
        assert_eq!(
            RpcCap::from_wire("hive-replica"),
            Some(RpcCap::HiveReplica),
            "its own verb, never `hive`'s"
        );
    }

    /// FR-90 P0d-2 — `hive` (runs sessions) does not imply `hive-view`
    /// (serves them to a browser), nor the other way round: a P0c agent drops
    /// every view frame, and a server that read the view verb out of `hive`
    /// would leave each viewer waiting out its bound.
    #[test]
    fn hive_does_not_imply_hive_view() {
        let runs = AgentCaps {
            rpc: vec!["hive".into()],
            ..Default::default()
        };
        assert!(runs.has_rpc(RpcCap::Hive));
        assert!(!runs.has_rpc(RpcCap::HiveView));

        let serves = AgentCaps {
            rpc: vec!["hive-view".into()],
            ..Default::default()
        };
        assert!(serves.has_rpc(RpcCap::HiveView));
        assert!(!serves.has_rpc(RpcCap::Hive));
        assert_eq!(RpcCap::HiveView.wire(), "hive-view");
        assert_eq!(RpcCap::from_wire("hive-view"), Some(RpcCap::HiveView));
        assert!(RpcCap::from_wire("hive-views").is_none());
    }

    /// FR-90 P1e — a device that runs sessions may still drop the core-memory
    /// frame (every build before P1e does), so `hive` never implies it, and
    /// `hive-memory` alone says nothing about running sessions.
    #[test]
    fn hive_does_not_imply_hive_memory() {
        let runs = AgentCaps {
            rpc: vec!["hive".into(), "hive-view".into()],
            ..Default::default()
        };
        assert!(!runs.has_rpc(RpcCap::HiveMemory));
        let understands = AgentCaps {
            rpc: vec!["hive-memory".into()],
            ..Default::default()
        };
        assert!(understands.has_rpc(RpcCap::HiveMemory));
        assert!(!understands.has_rpc(RpcCap::Hive));
        assert_eq!(RpcCap::from_wire("hive-memory"), Some(RpcCap::HiveMemory));
        assert!(RpcCap::from_wire("hive-memories").is_none());
    }

    /// FR-90 P1j — running sessions is not mirroring adopted terminal ones:
    /// a device advertising `hive` has not been allowed to adopt.
    #[test]
    fn hive_does_not_imply_hive_adopt() {
        let runs = AgentCaps {
            rpc: vec!["hive".into(), "hive-view".into(), "hive-memory".into()],
            ..Default::default()
        };
        assert!(!runs.has_rpc(RpcCap::HiveAdopt));
        let adopts = AgentCaps {
            rpc: vec!["hive-adopt".into()],
            ..Default::default()
        };
        assert!(adopts.has_rpc(RpcCap::HiveAdopt));
        assert!(!adopts.has_rpc(RpcCap::Hive));
        assert_eq!(RpcCap::from_wire("hive-adopt"), Some(RpcCap::HiveAdopt));
        assert!(RpcCap::from_wire("hive-adopted").is_none());
    }

    /// FR-90 P2c — holding copies of other devices' sessions, and offering to
    /// be an archive of the org's, are promises of their own: neither follows
    /// from running sessions, nor one from the other. A device placed by a
    /// verb it never advertised would be handed sessions its owner never
    /// agreed to hold.
    #[test]
    fn hive_replica_and_hive_archive_are_promises_of_their_own() {
        let runs = AgentCaps {
            rpc: vec!["hive".into(), "hive-view".into(), "hive-adopt".into()],
            ..Default::default()
        };
        assert!(!runs.has_rpc(RpcCap::HiveReplica));
        assert!(!runs.has_rpc(RpcCap::HiveArchive));
        let replica = AgentCaps {
            rpc: vec!["hive-replica".into()],
            ..Default::default()
        };
        assert!(replica.has_rpc(RpcCap::HiveReplica));
        assert!(
            !replica.has_rpc(RpcCap::HiveArchive),
            "a replica is no archive"
        );
        assert!(!replica.has_rpc(RpcCap::Hive), "nor runs sessions");
        let archive = AgentCaps {
            rpc: vec!["hive-archive".into()],
            ..Default::default()
        };
        assert!(archive.has_rpc(RpcCap::HiveArchive));
        assert!(!archive.has_rpc(RpcCap::HiveReplica));
        assert_eq!(RpcCap::from_wire("hive-archive"), Some(RpcCap::HiveArchive));
        assert!(RpcCap::from_wire("hive-replicas").is_none());
        assert!(RpcCap::from_wire("hive-archives").is_none());
    }

    /// FR-90 P2d — carrying replica streams is a promise of its own: a build
    /// that runs sessions or holds copies but predates P2d drops every stream
    /// frame, so a grant pushed to it would wait out its whole timeout. Nor
    /// does carrying streams imply holding copies: a primary serves its own
    /// sessions whatever its owner said of others'.
    #[test]
    fn hive_stream_is_a_promise_of_its_own() {
        let older = AgentCaps {
            rpc: vec!["hive".into(), "hive-replica".into(), "hive-archive".into()],
            ..Default::default()
        };
        assert!(!older.has_rpc(RpcCap::HiveStream));
        let streams = AgentCaps {
            rpc: vec!["hive".into(), "hive-stream".into()],
            ..Default::default()
        };
        assert!(streams.has_rpc(RpcCap::HiveStream));
        assert!(
            !streams.has_rpc(RpcCap::HiveReplica),
            "serving its own sessions is not holding others'"
        );
        assert_eq!(RpcCap::from_wire("hive-stream"), Some(RpcCap::HiveStream));
        assert!(RpcCap::from_wire("hive-streams").is_none());
    }

    /// FR-90 P2e-2 — holding a leased session to the server's word is its own
    /// promise: a build that runs sessions but predates it runs what it hosts
    /// on its own word, so it must never be read as one that waits.
    #[test]
    fn hive_lease_is_a_promise_of_its_own() {
        let older = AgentCaps {
            rpc: vec!["hive".into(), "hive-stream".into(), "hive-replica".into()],
            ..Default::default()
        };
        assert!(!older.has_rpc(RpcCap::HiveLease));
        let leased = AgentCaps {
            rpc: vec!["hive".into(), "hive-lease".into()],
            ..Default::default()
        };
        assert!(leased.has_rpc(RpcCap::HiveLease));
        assert!(!leased.has_rpc(RpcCap::HiveStream));
        assert_eq!(RpcCap::from_wire("hive-lease"), Some(RpcCap::HiveLease));
        assert!(RpcCap::from_wire("hive-leases").is_none());
    }

    /// FR-90 P2e-3 — taking part in a promotion is a promise of its own: an
    /// agent that holds leases (P2e-2) answers no prepare and no drain, and a
    /// server that read the one out of the other would leave a primary
    /// drained until every bound ran out.
    #[test]
    fn hive_promote_is_a_promise_of_its_own() {
        let leased = AgentCaps {
            rpc: vec![
                "hive".into(),
                "hive-replica".into(),
                "hive-stream".into(),
                "hive-lease".into(),
            ],
            ..Default::default()
        };
        assert!(!leased.has_rpc(RpcCap::HivePromote));
        let promotes = AgentCaps {
            rpc: vec!["hive".into(), "hive-promote".into()],
            ..Default::default()
        };
        assert!(promotes.has_rpc(RpcCap::HivePromote));
        assert!(!promotes.has_rpc(RpcCap::HiveLease));
        assert_eq!(RpcCap::from_wire("hive-promote"), Some(RpcCap::HivePromote));
        assert!(RpcCap::from_wire("hive-promotes").is_none());
    }

    /// FR-90 P2f-1a — taking part in a teleport is a promise of its own: an
    /// agent that takes part in a promotion (P2e-3) refuses a teleport's
    /// prepare for want of a copy, and its primary says nothing at a join, so
    /// a server that read the one out of the other would wait out a
    /// teleport's every bound.
    #[test]
    fn hive_teleport_is_a_promise_of_its_own() {
        let promotes = AgentCaps {
            rpc: vec![
                "hive".into(),
                "hive-stream".into(),
                "hive-lease".into(),
                "hive-promote".into(),
            ],
            ..Default::default()
        };
        assert!(!promotes.has_rpc(RpcCap::HiveTeleport));
        let teleports = AgentCaps {
            rpc: vec!["hive".into(), "hive-teleport".into()],
            ..Default::default()
        };
        assert!(teleports.has_rpc(RpcCap::HiveTeleport));
        assert!(!teleports.has_rpc(RpcCap::HivePromote));
        assert_eq!(
            RpcCap::from_wire("hive-teleport"),
            Some(RpcCap::HiveTeleport)
        );
        assert!(RpcCap::from_wire("hive-teleports").is_none());
    }

    /// FR-90 P2f-3a — `hive-fork` is its own promise: a build before it would
    /// start a fork empty, so a server that read it out of `hive`, or out of
    /// `hive-teleport`, would hand a person a fresh conversation for a fork.
    #[test]
    fn hive_fork_is_a_promise_of_its_own() {
        let teleports = AgentCaps {
            rpc: vec!["hive".into(), "hive-teleport".into()],
            ..Default::default()
        };
        assert!(!teleports.has_rpc(RpcCap::HiveFork));
        let forks = AgentCaps {
            rpc: vec!["hive".into(), "hive-fork".into()],
            ..Default::default()
        };
        assert!(forks.has_rpc(RpcCap::HiveFork));
        assert!(!forks.has_rpc(RpcCap::HiveTeleport));
        assert_eq!(RpcCap::from_wire("hive-fork"), Some(RpcCap::HiveFork));
        assert!(RpcCap::from_wire("hive-forks").is_none());
    }

    /// FR-90 P2f-4a — `hive-manage` is its own promise: a build before it
    /// would start an adopted session's conversation afresh, so a server that
    /// read it out of `hive`, or out of `hive-adopt`, would hand a person an
    /// empty session for the terminal they ran.
    #[test]
    fn hive_manage_is_a_promise_of_its_own() {
        let adopts = AgentCaps {
            rpc: vec!["hive".into(), "hive-adopt".into(), "hive-fork".into()],
            ..Default::default()
        };
        assert!(!adopts.has_rpc(RpcCap::HiveManage));
        let manages = AgentCaps {
            rpc: vec!["hive".into(), "hive-manage".into()],
            ..Default::default()
        };
        assert!(manages.has_rpc(RpcCap::HiveManage));
        assert!(!manages.has_rpc(RpcCap::HiveAdopt));
        assert_eq!(RpcCap::from_wire("hive-manage"), Some(RpcCap::HiveManage));
        assert!(RpcCap::from_wire("hive-managed").is_none());
    }

    /// FR-90 P2g-1 — `hive-purge` is its own promise: a build before it drops
    /// `rc:hive.purge`, so a server that read it out of `hive` would push a
    /// purge to a device that never answers, and wait on it for ever.
    #[test]
    fn hive_purge_is_a_promise_of_its_own() {
        let runs = AgentCaps {
            rpc: vec!["hive".into(), "hive-promote".into(), "hive-manage".into()],
            ..Default::default()
        };
        assert!(!runs.has_rpc(RpcCap::HivePurge));
        let purges = AgentCaps {
            rpc: vec!["hive".into(), "hive-purge".into()],
            ..Default::default()
        };
        assert!(purges.has_rpc(RpcCap::HivePurge));
        assert!(!purges.has_rpc(RpcCap::HivePromote));
        assert_eq!(RpcCap::from_wire("hive-purge"), Some(RpcCap::HivePurge));
        assert!(RpcCap::from_wire("hive-purged").is_none());
    }

    /// FR-90 P2g-4a — `hive-purge-all` is its own promise: `agent-v0.4.136`
    /// says `hive` and `hive-purge` and cannot decode `rc:hive.purge_all`, so
    /// a server that read it out of either would send every such device, at
    /// its removal, a frame it drops. Nor does it imply purging a session.
    #[test]
    fn hive_purge_all_is_a_promise_of_its_own() {
        let v0_4_136 = AgentCaps {
            rpc: vec!["hive".into(), "hive-purge".into()],
            ..Default::default()
        };
        assert!(!v0_4_136.has_rpc(RpcCap::HivePurgeAll));
        let at_removal = AgentCaps {
            rpc: vec!["hive".into(), "hive-purge-all".into()],
            ..Default::default()
        };
        assert!(at_removal.has_rpc(RpcCap::HivePurgeAll));
        assert!(!at_removal.has_rpc(RpcCap::HivePurge));
        assert_eq!(
            RpcCap::from_wire("hive-purge-all"),
            Some(RpcCap::HivePurgeAll)
        );
        assert!(RpcCap::from_wire("hive-purge-alls").is_none());
    }

    /// #2294 — `hive-purge-drain` is its own promise: `agent-v0.4.137` purges
    /// at its removal (`hive-purge-all`) but exits at once on the goodbye that
    /// follows, so a server that read the drain out of `hive-purge-all` (or
    /// out of `hive-purge`, its prefix) would cut that purge short.
    #[test]
    fn hive_purge_drain_is_a_promise_of_its_own() {
        let v0_4_137 = AgentCaps {
            rpc: vec!["hive".into(), "hive-purge".into(), "hive-purge-all".into()],
            ..Default::default()
        };
        assert!(!v0_4_137.has_rpc(RpcCap::HivePurgeDrain));
        let drains = AgentCaps {
            rpc: vec!["hive".into(), "hive-purge-drain".into()],
            ..Default::default()
        };
        assert!(drains.has_rpc(RpcCap::HivePurgeDrain));
        assert!(!drains.has_rpc(RpcCap::HivePurge));
        assert!(!drains.has_rpc(RpcCap::HivePurgeAll));
        assert_eq!(
            RpcCap::from_wire("hive-purge-drain"),
            Some(RpcCap::HivePurgeDrain)
        );
        assert!(RpcCap::from_wire("hive-purge-drains").is_none());
    }

    /// FR-90 P2i-1 — `hive-search` is its own promise: a device that holds
    /// copies, an archive replica among them, but predates it drops
    /// `rc:hive.search.grant`, so a server that read it out of `hive`,
    /// `hive-replica` or `hive-archive` would leave a searcher waiting.
    #[test]
    fn hive_search_is_a_promise_of_its_own() {
        let archive_before = AgentCaps {
            rpc: vec!["hive".into(), "hive-replica".into(), "hive-archive".into()],
            ..Default::default()
        };
        assert!(!archive_before.has_rpc(RpcCap::HiveSearch));
        let searches = AgentCaps {
            rpc: vec!["hive-archive".into(), "hive-search".into()],
            ..Default::default()
        };
        assert!(searches.has_rpc(RpcCap::HiveSearch));
        assert!(!searches.has_rpc(RpcCap::Hive));
        assert_eq!(RpcCap::from_wire("hive-search"), Some(RpcCap::HiveSearch));
        assert!(RpcCap::from_wire("hive-searches").is_none());
    }

    /// Forward compatibility: a NEWER agent may advertise verbs this build has
    /// never heard of. An additive string list is only additive if an older
    /// reader ignores what it does not recognise instead of choking.
    #[test]
    fn unknown_verbs_are_ignored_not_fatal() {
        let future = AgentCaps {
            rpc: vec!["exec".into(), "quantum-teleport".into()],
            ..Default::default()
        };
        assert!(future.has_rpc(RpcCap::Exec));
        assert!(!future.has_rpc(RpcCap::Ssh));
    }

    /// A pre-Fleet-RPC agent sends no `rpc` key at all; every gate must read
    /// false rather than defaulting open.
    ///
    /// The fixture is a ROUND TRIP rather than hand-written JSON: `rpc` is
    /// `skip_serializing_if = "Vec::is_empty"`, so an empty one genuinely
    /// disappears from the wire — which is exactly the old-agent shape — and
    /// deriving it this way cannot drift as other fields come and go.
    #[test]
    fn absent_rpc_list_advertises_nothing() {
        let wire = serde_json::to_string(&AgentCaps::default()).unwrap();
        assert!(
            !wire.contains("\"rpc\""),
            "an empty rpc list must not reach the wire at all: {wire}"
        );
        let old: AgentCaps = serde_json::from_str(&wire).unwrap();
        for cap in RpcCap::ALL {
            assert!(!old.has_rpc(cap), "{cap:?} must not be implied by silence");
        }
    }

    /// FR-77 — the cell vocabulary follows the `RpcCap` contract: every wire
    /// string is unique and round-trips, and the spellings are LOCKED because
    /// changing one silently un-advertises a cell on every deployed agent.
    #[test]
    fn video_cell_vocabulary_is_unique_locked_and_round_trips() {
        assert_eq!(
            VideoCodec::ALL.map(VideoCodec::wire),
            ["h264", "hevc", "av1", "vp9"]
        );
        assert_eq!(
            VideoBackend::ALL.map(VideoBackend::wire),
            [
                "nvenc",
                "qsv",
                "amf",
                "videotoolbox",
                "vaapi",
                "d3d12",
                "vulkan",
                "mf",
                "openh264",
                "libvpx"
            ]
        );
        assert_eq!(
            ChromaFormat::ALL.map(ChromaFormat::wire),
            ["yuv420", "yuv444"]
        );
        for c in VideoCodec::ALL {
            assert_eq!(VideoCodec::from_wire(c.wire()), Some(c));
        }
        for b in VideoBackend::ALL {
            assert_eq!(VideoBackend::from_wire(b.wire()), Some(b));
        }
        for c in ChromaFormat::ALL {
            assert_eq!(ChromaFormat::from_wire(c.wire()), Some(c));
        }
        assert_eq!(
            VideoCodec::from_wire("h265"),
            None,
            "the wire name is hevc, not h265"
        );
    }

    /// Every FFmpeg name the agent's dispatch tables carry must parse, and a
    /// name this build does not know must NOT parse — that is how a backend
    /// added to a table without a vocabulary entry fails in a test instead
    /// of shipping under a name no viewer understands.
    #[test]
    fn ffmpeg_names_split_into_codec_and_backend() {
        use VideoBackend as B;
        use VideoCodec as C;
        for (name, want) in [
            ("hevc_nvenc", (C::Hevc, B::Nvenc)),
            ("h264_qsv", (C::H264, B::Qsv)),
            ("av1_amf", (C::Av1, B::Amf)),
            ("vp9_qsv", (C::Vp9, B::Qsv)),
            ("h264_videotoolbox", (C::H264, B::VideoToolbox)),
            ("hevc_vaapi", (C::Hevc, B::Vaapi)),
            // FR-78 added these two backends. They sat in the `unknown` list
            // below — written for FR-77, when they were — and the test failed
            // on master for as long as no CI lane ran this crate.
            ("h264_vulkan", (C::H264, B::Vulkan)),
            ("av1_d3d12va", (C::Av1, B::D3d12)),
        ] {
            assert_eq!(B::from_ffmpeg_name(name), Some(want), "{name}");
        }
        // Real FFmpeg encoder names this build's tables do NOT carry — so a
        // backend added to a dispatch table without a vocabulary entry still
        // fails here, which is the point of the test.
        for unknown in [
            "hevc_mf",
            "h264_v4l2m2m",
            "hevc_mediacodec",
            "libx264",
            "hevc",
            "",
        ] {
            assert_eq!(
                B::from_ffmpeg_name(unknown),
                None,
                "{unknown:?} must not parse"
            );
        }
    }

    /// The additive-list rule for cells: a newer agent's unknown codec /
    /// backend / chroma is skipped, never an error, and a pre-FR-77 agent
    /// (no `video_cells` key at all) yields no cells and `has_cell == false`.
    #[test]
    fn unknown_cells_are_ignored_and_absent_cells_advertise_nothing() {
        let caps = AgentCaps {
            video_cells: vec![
                VideoCell::new(
                    VideoCodec::Hevc,
                    VideoBackend::Nvenc,
                    &[ChromaFormat::Yuv420, ChromaFormat::Yuv444],
                    true,
                ),
                VideoCell {
                    codec: "vvc".into(),
                    backend: "nvenc".into(),
                    chroma: vec!["yuv420".into()],
                    hw: true,
                },
                // A backend this build does not know. It was `vulkan` until
                // FR-78 taught the vocabulary that one, which silently turned
                // "an unknown cell is skipped" into a failing assertion.
                VideoCell {
                    codec: "av1".into(),
                    backend: "mediacodec".into(),
                    chroma: vec!["yuv420".into()],
                    hw: true,
                },
                VideoCell {
                    codec: "vp9".into(),
                    backend: "libvpx".into(),
                    chroma: vec!["yuv420".into(), "yuv422".into(), "yuv444".into()],
                    hw: false,
                },
            ],
            ..Default::default()
        };
        let typed = caps.typed_cells();
        assert_eq!(
            typed.len(),
            2,
            "the vvc and mediacodec cells are unknown here: {typed:?}"
        );
        assert_eq!(
            typed[1].chroma,
            vec![ChromaFormat::Yuv420, ChromaFormat::Yuv444]
        );
        assert!(caps.has_cell(VideoCodec::Hevc, ChromaFormat::Yuv444));
        assert!(
            !caps.has_cell(VideoCodec::Av1, ChromaFormat::Yuv420),
            "the mediacodec cell is unreadable here"
        );
        assert!(!caps.has_cell(VideoCodec::H264, ChromaFormat::Yuv420));

        // The pre-FR-77 shape: the six bare fields only.
        let old: AgentCaps = serde_json::from_str(
            r#"{"hw_encoders":["ffmpeg-hevc_nvenc"],"codecs":["h264","h265"],"has_input_permission":true,"supports_clipboard":true,"supports_file_transfer":true,"max_simultaneous_sessions":2}"#,
        )
        .unwrap();
        assert!(old.video_cells.is_empty());
        assert!(old.probe_ms.is_none());
        assert!(!old.has_cell(VideoCodec::Hevc, ChromaFormat::Yuv420));

        // Empty cells and an absent probe time stay OFF the wire.
        let wire = serde_json::to_string(&AgentCaps::default()).unwrap();
        assert!(
            !wire.contains("video_cells")
                && !wire.contains("probe_ms")
                && !wire.contains("probe_cached"),
            "{wire}"
        );

        // And a full round trip keeps every field of a cell.
        let wire = serde_json::to_string(&caps).unwrap();
        let back: AgentCaps = serde_json::from_str(&wire).unwrap();
        assert_eq!(back.video_cells, caps.video_cells);
    }

    /// FR-93 P2b — the desktop brief's wire shape: `type` on the wire (the
    /// spec's word), an absent desktop name and an absent brief both stay off
    /// it, and words this build has never heard of still parse.
    #[test]
    fn desktop_brief_wire_shape_is_locked_and_additive() {
        let brief = DesktopBrief {
            session: "user".into(),
            kind: "wayland".into(),
            desktop: Some("gnome".into()),
            capture_arm: "mutter".into(),
            input_reach: "full".into(),
        };
        let caps = AgentCaps {
            desktop: Some(brief.clone()),
            ..Default::default()
        };
        let wire = serde_json::to_value(&caps).unwrap();
        assert_eq!(
            wire["desktop"],
            serde_json::json!({
                "session": "user",
                "type": "wayland",
                "desktop": "gnome",
                "capture_arm": "mutter",
                "input_reach": "full",
            })
        );
        let back: AgentCaps = serde_json::from_value(wire).unwrap();
        assert_eq!(back.desktop, Some(brief));

        // No desktop name: the key stays off the wire.
        let nameless = DesktopBrief {
            session: "none".into(),
            kind: "none".into(),
            desktop: None,
            capture_arm: "none".into(),
            input_reach: "none".into(),
        };
        let wire = serde_json::to_string(&nameless).unwrap();
        assert!(!wire.contains("\"desktop\""), "{wire}");

        // No brief at all (off Linux, older agents): nothing on the wire, and
        // an older agent's caps parse to `None`.
        let wire = serde_json::to_string(&AgentCaps::default()).unwrap();
        assert!(!wire.contains("desktop"), "{wire}");
        let old: AgentCaps = serde_json::from_str(
            r#"{"hw_encoders":[],"codecs":["h264"],"has_input_permission":true,"supports_clipboard":false,"supports_file_transfer":false,"max_simultaneous_sessions":1}"#,
        )
        .unwrap();
        assert!(old.desktop.is_none());

        // A newer agent's words parse as words.
        let future: DesktopBrief = serde_json::from_str(
            r#"{"session":"remote","type":"mir","capture_arm":"pipewire-direct","input_reach":"partial","extra":1}"#,
        )
        .unwrap();
        assert_eq!(future.capture_arm, "pipewire-direct");
        assert_eq!(future.kind, "mir");
    }

    #[test]
    fn exec_policy_defaults_are_closed() {
        // The whole safety story rests on this: a device row that predates
        // Fleet RPC — i.e. every device in the fleet today — must deserialise
        // to a policy that refuses.
        let p: ExecPolicy = serde_json::from_str("{}").unwrap();
        assert_eq!(p.mode, ExecMode::Off);
        assert!(!p.can_originate);
        assert_eq!(p.effective_consent_mode(), ConsentMode::Prompt);

        // …and so must an Agent row with no `exec_policy` key at all.
        let caps_free = r#"{
            "tenant_id":"000000000000000000000001",
            "owner_user_id":"000000000000000000000002",
            "name":"old","machine_id":"m","os":"windows",
            "agent_version":"0.1.0","agent_token_hash":"",
            "status":"offline","last_seen_at":{"$date":{"$numberLong":"0"}},
            "created_at":{"$date":{"$numberLong":"0"}},
            "updated_at":{"$date":{"$numberLong":"0"}},
            "deleted_at":null
        }"#;
        let a: Agent = serde_json::from_str(caps_free).unwrap();
        assert_eq!(a.exec_policy.mode, ExecMode::Off);
        // The SSH policy rides the same row and carries the same guarantee:
        // shipping the feature must not retroactively open a single device.
        assert_eq!(a.ssh_policy.mode, SshMode::Off);
    }

    #[test]
    fn ssh_policy_defaults_are_closed() {
        let p: SshPolicy = serde_json::from_str("{}").unwrap();
        assert_eq!(p.mode, SshMode::Off);
        assert!(!p.can_originate);
        // The consent default (unset ⇒ Prompt) is decided where the grant is
        // minted — `agent_ssh::effective_wire_consent`, locked by the api
        // crate's `only_an_explicit_auto_crosses_the_wire_as_auto`. Here the
        // raw field just deserialises to "the admin said nothing".
        assert_eq!(p.consent_mode, None);
        // `Daemon` is root-equivalent, so it must be a DELIBERATE choice that
        // an operator can see — not something a device silently acquires. It
        // is the default only because it is the one mode P2 can actually
        // perform; P5 is what makes the others real.
        assert_eq!(p.account_mode, SshAccountMode::Daemon);
    }

    #[test]
    fn ssh_policy_allowlists_restrict_only_when_populated() {
        let user = ObjectId::new();
        let role = ObjectId::new();
        let other = ObjectId::new();

        let gates = |p: SshPolicy| p.split().0;

        // Empty lists mean "no restriction at THIS layer" — never "deny all".
        // The permission bit and the org kill-switch are the layers that decide
        // whether anyone may connect at all.
        let open = gates(SshPolicy::default());
        assert!(open.allows_caller(&user, &[role]));

        let by_user = gates(SshPolicy {
            allowed_user_ids: vec![user],
            ..Default::default()
        });
        assert!(by_user.allows_caller(&user, &[]));
        assert!(!by_user.allows_caller(&other, &[]));

        let by_role = gates(SshPolicy {
            allowed_role_ids: vec![role],
            ..Default::default()
        });
        assert!(by_role.allows_caller(&other, &[role]));
        assert!(!by_role.allows_caller(&other, &[]));

        // Both populated ⇒ both must match; they are AND, not OR, so
        // narrowing by role cannot widen who the user allowlist admitted.
        let both = gates(SshPolicy {
            allowed_user_ids: vec![user],
            allowed_role_ids: vec![role],
            ..Default::default()
        });
        assert!(both.allows_caller(&user, &[role]));
        assert!(!both.allows_caller(&user, &[other]));
        assert!(!both.allows_caller(&other, &[role]));
    }

    #[test]
    fn ssh_policy_split_routes_every_field() {
        // The split is the ignored-field firewall: every policy field must come
        // out in exactly one half, unchanged. If this test needs editing, make
        // sure the field you added is actually ACTED ON by its consumer — the
        // whole point of `split` is that routing a field is a decision, not a
        // formality.
        let user = ObjectId::new();
        let role = ObjectId::new();
        let policy = SshPolicy {
            mode: SshMode::On,
            can_originate: true,
            allowed_user_ids: vec![user],
            allowed_role_ids: vec![role],
            account_mode: SshAccountMode::ConsoleUser,
            account: Some("goran".into()),
            consent_mode: Some(ConsentMode::Prompt),
        };
        let (gates, spec) = policy.split();
        assert_eq!(gates.mode, SshMode::On);
        assert!(gates.can_originate);
        assert_eq!(gates.allowed_user_ids, vec![user]);
        assert_eq!(gates.allowed_role_ids, vec![role]);
        assert_eq!(spec.account_mode, SshAccountMode::ConsoleUser);
        assert_eq!(spec.account.as_deref(), Some("goran"));
        assert_eq!(spec.consent_mode, Some(ConsentMode::Prompt));
    }

    #[test]
    fn exec_policy_consent_collapses_session_shaped_modes() {
        // Email / Push / PromptThenEmail are approve-link flows with no exec
        // equivalent. They must collapse to Prompt, never silently to Auto.
        for m in [
            ConsentMode::Email,
            ConsentMode::Push,
            ConsentMode::PromptThenEmail,
        ] {
            let p = ExecPolicy {
                consent_mode: Some(m),
                ..Default::default()
            };
            assert_eq!(p.effective_consent_mode(), ConsentMode::Prompt, "{m:?}");
        }
        let p = ExecPolicy {
            consent_mode: Some(ConsentMode::Auto),
            ..Default::default()
        };
        assert_eq!(p.effective_consent_mode(), ConsentMode::Auto);
    }

    #[test]
    fn empty_shell_resolves_before_the_allowlist_is_checked() {
        // Field-caught: `roomler exec <dev> -- …` and every `roomler diag`
        // bundle send an EMPTY shell meaning "the host default". Comparing
        // that literal "" against ["powershell","pwsh","cmd"] refused them
        // all, which made diag unusable on every device that had narrowed its
        // allowlist — i.e. every device an admin had actually configured.
        let narrowed = ExecPolicy {
            shells: vec!["powershell".into(), "pwsh".into(), "cmd".into()],
            ..Default::default()
        };
        assert!(
            !narrowed.allows_shell(""),
            "the raw empty string must NOT match — that is why resolution has to happen first"
        );
        assert!(narrowed.allows_shell(&ExecPolicy::resolve_shell("", OsKind::Windows)));
        assert!(narrowed.allows_shell(&ExecPolicy::resolve_shell("auto", OsKind::Windows)));
        assert!(narrowed.allows_shell(&ExecPolicy::resolve_shell("  ", OsKind::Windows)));

        // …and a genuinely disallowed shell is still refused after resolution.
        assert!(!narrowed.allows_shell(&ExecPolicy::resolve_shell("bash", OsKind::Windows)));
    }

    #[test]
    fn resolve_shell_matches_the_agents_own_defaults() {
        // These MUST equal the agent's `exec::resolve_shell` mapping, or the
        // policy check and the execution would disagree about what ran.
        assert_eq!(ExecPolicy::resolve_shell("", OsKind::Windows), "powershell");
        assert_eq!(ExecPolicy::resolve_shell("", OsKind::Linux), "bash");
        assert_eq!(ExecPolicy::resolve_shell("", OsKind::Macos), "bash");
        // An explicit request passes through untouched (trimmed).
        assert_eq!(ExecPolicy::resolve_shell(" pwsh ", OsKind::Windows), "pwsh");
        assert_eq!(ExecPolicy::resolve_shell("sh", OsKind::Linux), "sh");
    }

    #[test]
    fn exec_policy_shell_allowlist() {
        let open = ExecPolicy::default();
        assert!(open.allows_shell("pwsh"), "empty list allows everything");

        let narrowed = ExecPolicy {
            shells: vec!["pwsh".into()],
            ..Default::default()
        };
        assert!(narrowed.allows_shell("pwsh"));
        assert!(
            narrowed.allows_shell("PWSH"),
            "shell names are ASCII-insensitive"
        );
        assert!(!narrowed.allows_shell("cmd"));
    }

    #[test]
    fn exec_limits_clamp() {
        use exec_limits::*;
        // 0 means "unspecified" on the wire, not "instant timeout".
        assert_eq!(clamp_timeout_ms(0), DEFAULT_TIMEOUT_MS);
        assert_eq!(clamp_timeout_ms(1_000), 1_000);
        assert_eq!(clamp_timeout_ms(u64::MAX), MAX_TIMEOUT_MS);

        assert_eq!(clamp_output_bytes(0), DEFAULT_MAX_OUTPUT_BYTES);
        assert_eq!(clamp_output_bytes(1024), 1024);
        assert_eq!(clamp_output_bytes(u64::MAX), MAX_OUTPUT_BYTES);
    }

    #[test]
    fn overlay_ip_adds_host_to_cgnat_base() {
        let cidr = OverlayNetwork::DEFAULT_CIDR;
        assert_eq!(overlay_ip(cidr, 1).as_deref(), Some("100.64.0.1"));
        assert_eq!(overlay_ip(cidr, 7).as_deref(), Some("100.64.0.7"));
        assert_eq!(overlay_ip(cidr, 256).as_deref(), Some("100.64.1.0"));
        assert_eq!(overlay_ip("not-a-cidr", 1), None);
    }

    #[test]
    fn cidr_bounds_cap_host_ordinals_to_the_block() {
        // Multi-org P2a — the whole reason blocks can't bleed: /22 = 1024
        // addresses ⇒ hosts 1..=1022 leaseable.
        assert_eq!(cidr_max_host("100.68.12.0/22"), Some(1022));
        assert_eq!(cidr_max_host("100.64.0.0/10"), Some((1 << 22) - 2));
        assert_eq!(cidr_max_host("100.64.0.0/30"), Some(2));
        assert_eq!(cidr_max_host("100.64.0.0/31"), None, "no leasable hosts");
        assert_eq!(cidr_max_host("100.64.0.0/32"), None);
        assert_eq!(cidr_max_host("garbage"), None);

        // overlay_ip refuses to render past the block…
        assert_eq!(
            overlay_ip("100.68.12.0/22", 1022).as_deref(),
            Some("100.68.15.254")
        );
        assert_eq!(
            overlay_ip("100.68.12.0/22", 1023),
            None,
            "block's last address"
        );
        assert_eq!(overlay_ip("100.68.12.0/22", 1024), None, "neighbor block");
        // …and overlay_host rejects an address above it (a row leased under a
        // since-shrunk CIDR must not poison the pool).
        assert_eq!(overlay_host("100.68.12.0/22", "100.68.15.254"), Some(1022));
        assert_eq!(overlay_host("100.68.12.0/22", "100.68.16.1"), None);
        // The below-base rejection is unchanged.
        assert_eq!(overlay_host("100.68.12.0/22", "100.68.11.9"), None);
    }

    #[test]
    fn overlay_host_inverts_overlay_ip() {
        let cidr = OverlayNetwork::DEFAULT_CIDR;
        assert_eq!(overlay_host(cidr, "100.64.0.7"), Some(7));
        assert_eq!(overlay_host(cidr, "100.64.1.0"), Some(256));
        assert_eq!(overlay_host("10.0.0.0/8", "10.0.0.1"), Some(1));
    }

    /// The contract that keeps the free pool honest: whatever `overlay_ip`
    /// hands out, `overlay_host` must recover exactly. If someone later masks
    /// `overlay_ip` to the network address without fixing the inverse, released
    /// host numbers would be off and the pool would hand out wrong addresses.
    #[test]
    fn overlay_host_round_trips_for_every_host() {
        let cidr = OverlayNetwork::DEFAULT_CIDR;
        for host in [1u32, 2, 255, 256, 65_535, 1_000_000, 4_194_302] {
            let ip = overlay_ip(cidr, host).expect("forward");
            assert_eq!(overlay_host(cidr, &ip), Some(host), "round-trip for {host}");
        }
    }

    /// Both directions ignore the prefix identically, so a non-canonical CIDR
    /// (base not masked to the prefix) still round-trips.
    #[test]
    fn overlay_host_ignores_the_prefix_like_overlay_ip_does() {
        let cidr = "100.64.0.5/10";
        assert_eq!(overlay_ip(cidr, 2).as_deref(), Some("100.64.0.7"));
        assert_eq!(overlay_host(cidr, "100.64.0.7"), Some(2));
    }

    #[test]
    fn overlay_host_rejects_out_of_range_and_malformed() {
        let cidr = OverlayNetwork::DEFAULT_CIDR;
        // Below the base — a lease from a different, since-changed CIDR.
        assert_eq!(overlay_host(cidr, "10.0.0.1"), None);
        assert_eq!(overlay_host("not-a-cidr", "1.2.3.4"), None);
        assert_eq!(overlay_host(cidr, "nope"), None);
    }

    // --- P2b tenant blocks ------------------------------------------------

    #[test]
    fn block_cidr_renders_the_slot_grid() {
        // The first allocatable slot is 100.65.0.0 — everything below it is
        // the legacy reserve.
        assert_eq!(
            block_cidr_for_slot(OVERLAY_BLOCK_FIRST_SLOT, 1).as_deref(),
            Some("100.65.0.0/22")
        );
        assert_eq!(block_cidr_for_slot(65, 1).as_deref(), Some("100.65.4.0/22"));
        assert_eq!(
            block_cidr_for_slot(128, 1).as_deref(),
            Some("100.66.0.0/22")
        );
        // Wider blocks widen the prefix.
        assert_eq!(block_cidr_for_slot(64, 4).as_deref(), Some("100.65.0.0/20"));
        assert_eq!(
            block_cidr_for_slot(64, 64).as_deref(),
            Some("100.65.0.0/16")
        );
        // Unaligned / non-power-of-two / past the /10 are refused.
        assert_eq!(block_cidr_for_slot(65, 4), None, "unaligned");
        assert_eq!(block_cidr_for_slot(64, 3), None, "not a power of two");
        assert_eq!(block_cidr_for_slot(OVERLAY_BLOCK_SLOT_COUNT, 1), None);
        assert_eq!(block_cidr_for_slot(OVERLAY_BLOCK_SLOT_COUNT - 1, 2), None);
        // The last slot IS allocatable.
        assert_eq!(
            block_cidr_for_slot(OVERLAY_BLOCK_SLOT_COUNT - 1, 1).as_deref(),
            Some("100.127.252.0/22")
        );
    }

    #[test]
    fn block_prefix_maps_to_slot_width() {
        assert_eq!(block_slots_for_prefix(22), Some(1));
        assert_eq!(block_slots_for_prefix(20), Some(4));
        assert_eq!(block_slots_for_prefix(16), Some(64));
        assert_eq!(block_slots_for_prefix(23), None, "sub-slot");
        assert_eq!(block_slots_for_prefix(15), None, "wider than /16");
        assert_eq!(block_slots_for_prefix(0), None);
    }

    /// The allocator's safety property: starts are aligned and monotonic, so
    /// two racers computing from the same "highest end" either collide on the
    /// SAME slot (the unique index arbitrates) or claim disjoint ranges. This
    /// walks every width against every possible predecessor end and asserts
    /// the ranges never partially overlap.
    #[test]
    fn aligned_starts_are_never_partially_overlapping() {
        for after in 0u32..512 {
            let mut claims: Vec<(u32, u32)> = Vec::new();
            for prefix in OVERLAY_BLOCK_MIN_PREFIX..=OVERLAY_BLOCK_MAX_PREFIX {
                let slots = block_slots_for_prefix(prefix).expect("supported prefix");
                let start = block_align_slot(after, slots);
                assert!(start >= after, "monotonic: {start} >= {after}");
                assert_eq!(start % slots, 0, "aligned");
                assert!(
                    start - after < slots,
                    "no more than one width of waste (start {start}, after {after})"
                );
                claims.push((start, slots));
            }
            // Buddy property: any two claims are identical-start or disjoint.
            for (i, (s1, w1)) in claims.iter().enumerate() {
                for (s2, w2) in claims.iter().skip(i + 1) {
                    let overlap = s1.max(s2) < &(s1 + w1).min(s2 + w2);
                    assert!(
                        !overlap || s1 == s2,
                        "partial overlap: [{s1},{}) vs [{s2},{})",
                        s1 + w1,
                        s2 + w2
                    );
                }
            }
        }
    }

    /// A carved block's leasable range must stay strictly inside it — the
    /// whole point of the P2a ceiling.
    #[test]
    fn block_leases_stay_inside_the_block() {
        let cidr = block_cidr_for_slot(64, 1).expect("slot 64");
        assert_eq!(cidr, "100.65.0.0/22");
        assert_eq!(cidr_max_host(&cidr), Some(1022));
        assert_eq!(overlay_ip(&cidr, 1).as_deref(), Some("100.65.0.1"));
        assert_eq!(overlay_ip(&cidr, 1022).as_deref(), Some("100.65.3.254"));
        // …and the first address of the NEXT block is unreachable from here.
        assert_eq!(overlay_ip(&cidr, 1024), None);
        assert_eq!(overlay_host(&cidr, "100.65.4.0"), None);
    }

    /// `DesiredConfig` is an ALLOWLIST, and two keys are outside it because a
    /// server able to set them could open everything else: the device's opt-in
    /// (`remote_config_enabled`) and the device's SSH privilege ceiling
    /// (`ssh_max_privilege`, M5). Both are commented at the type — this is the
    /// part that fails a build when someone adds them "for symmetry".
    #[test]
    fn the_device_owned_refusals_are_not_pushable() {
        // Every field populated, so nothing is skipped by
        // `skip_serializing_if` and the key set is the whole surface.
        let full = DesiredConfig {
            exec_enabled: Some(true),
            ssh_enabled: Some(true),
            ssh_authorized_keys: Some(vec!["ssh-ed25519 AAAA".into()]),
            ssh_account_mode: Some("daemon".into()),
            ssh_port: Some(2222),
            encoder_cells_deny: Some("none".into()),
            fps_deny: Some("*:144".into()),
            revision: 1,
            updated_by: Some(ObjectId::new()),
            updated_at: Some(DateTime::now()),
        };
        let json = serde_json::to_value(&full).expect("serialises");
        let keys: Vec<&str> = json
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        // FR-84 D3 — nor may the server switch the LOCAL restart on, or ask
        // for a restart at all: the daemon restarts itself only when a local
        // client asks over the LocalAPI.
        // FR-90 — nor any Hive gate. Which local account runs an agent
        // session (`hive_accounts`) and where it may run (`hive_roots`) are
        // exactly what a compromised server must not be able to choose, and
        // `hive_enabled` is the device's refusal like `exec_enabled` is. (The
        // design allows `hive_enabled` to become pushable to devices that
        // opted into remote config; until a change argues that here, none is.)
        for forbidden in [
            "remote_config_enabled",
            "ssh_max_privilege",
            "local_restart_enabled",
            "hive_enabled",
            "hive_accounts",
            "hive_roots",
            "hive_harness",
            "hive_api_key_helper",
            "hive_api_workspace_id",
            "hive_max_sessions",
            "hive_update_wait_secs",
            // FR-90 P1e — the one gate on server-authored text reaching a
            // session's model; a server that could set it would vouch for
            // itself.
            "hive_core_memory",
            // FR-90 P1j — whether this machine reports on its terminals at
            // all (decision 11): the device owner's alone.
            "hive_adopt",
            // FR-90 decision 15 — whether an agent on a Mac may be root; a
            // server that could set it could give itself root on the device.
            "hive_allow_passwordless_sudo",
            // FR-90 P2c — whether this device holds copies of other devices'
            // sessions, offers itself as the org's archive, and how much it
            // keeps: a server that could set them could copy every session to
            // a device of its choosing.
            "hive_replica",
            "hive_archive",
            "hive_store_quota",
            // FR-90 P3-3 — whether org secrets are ever decrypted on this
            // machine: a server that could set it would choose where its own
            // vault's values are opened.
            "vault_enabled",
            // FR-90 P3-4d-2 — whether the device describes what it does with
            // its leases: the device's own word about itself, as
            // `ssh_activity_log` is.
            "vault_activity_log",
            // FR-90 P3-7-3c — whether a session here may reach a network
            // beyond this device: a server that could set it could open
            // that path from every device it runs sessions on.
            "hive_net",
            // FR-90 P3-8-2b-2 — whether a session here may run a command on
            // another device over SSH: a server that could set it could
            // reach from every device it runs sessions on into every device
            // whose SSH policy admits a session.
            "hive_ssh",
            // FR-99 — whether a controller may cover this screen: a server
            // that could set it could curtain any device it controls.
            "privacy_mode_allowed",
            // FR-101 P2b — the device's own floor for clipboard, files and
            // audio. A server that could set them could switch back on what
            // the owner switched off; the org's policy is the server's half.
            "rc_clipboard",
            "rc_files",
            "rc_audio",
            // FR-101 P1b — keeping a plaintext server URL. A server that
            // could set it could talk a device down to plaintext.
            "allow_plaintext_server",
            // FR-99 P3 — the device's own floor for locking its screen when a
            // session ends. A server may ask for stricter on a session (P3b),
            // never set the floor.
            "lock_on_end",
            // FR-108 — whether a controller may switch this device's display.
            // A server that could set it could take every screen it reaches.
            "display_match",
        ] {
            assert!(
                !keys.contains(&forbidden),
                "{forbidden} must never be pushable by the server — it is the device's own \
                 refusal, and a server that can set it can set everything. Got keys: {keys:?}"
            );
        }
        assert!(
            !keys.iter().any(|k| k.contains("restart")),
            "remote configuration never restarts a daemon (docs/remote-config.md §7b): {keys:?}"
        );
        // FR-99 — no privacy key at all: whatever privacy mode grows next
        // (the input block, the lock on end), it is the device's.
        assert!(
            !keys.iter().any(|k| k.starts_with("privacy_")),
            "privacy mode is configured on the device only: {keys:?}"
        );

        // And the receiving side ignores it rather than erroring, which is the
        // safe direction: a server asserting it gets no effect, not a refused
        // config push that would also drop the legitimate keys beside it.
        let pushed: DesiredConfig = serde_json::from_value(serde_json::json!({
            "ssh_enabled": true,
            "ssh_max_privilege": "daemon",
            "remote_config_enabled": true,
            "local_restart_enabled": true,
        }))
        .expect("unknown keys are ignored, not fatal");
        assert_eq!(pushed.ssh_enabled, Some(true));
    }

    // ── #1630: an audit row must read back through the driver's own pair ───

    fn audit_row(event: AuditKind) -> RemoteAuditEvent {
        RemoteAuditEvent {
            id: None,
            session_id: ObjectId::new(),
            agent_id: ObjectId::new(),
            tenant_id: ObjectId::new(),
            at: bson::DateTime::now(),
            event,
        }
    }

    fn event_permissions(ev: &AuditKind) -> Permissions {
        match ev {
            AuditKind::SessionRequested { permissions, .. }
            | AuditKind::PermissionsChanged { permissions } => *permissions,
            other => panic!("not a permissions-carrying event: {other:?}"),
        }
    }

    /// FR-100 P1c — `SessionStarted` became a struct variant with one optional
    /// field, and a rollout runs old and new pods side by side over the same
    /// rows. Both directions, through the driver's own pair
    /// (`to_raw_document_buf` / `from_slice`):
    /// - a row written before the field reads as `SessionStarted { peer_auth:
    ///   None }`, and a new row with no verdict is byte-identical to it;
    /// - an OLDER pod, whose `SessionStarted` is still a unit variant, reads a
    ///   new row carrying a verdict: an internally tagged unit variant skips a
    ///   field it does not know.
    #[test]
    fn session_started_reads_both_ways_across_the_verdict_field() {
        #[derive(Deserialize, Debug, PartialEq)]
        #[serde(tag = "kind", rename_all = "snake_case")]
        enum OlderKind {
            SessionStarted,
        }
        #[derive(Deserialize)]
        struct OlderRow {
            event: OlderKind,
        }

        let old_shape = bson::doc! { "kind": "session_started" };
        let read: AuditKind = bson::from_document(old_shape.clone()).unwrap();
        assert!(
            matches!(read, AuditKind::SessionStarted { peer_auth: None }),
            "{read:?}"
        );
        assert_eq!(
            bson::to_document(&AuditKind::SessionStarted { peer_auth: None }).unwrap(),
            old_shape,
            "no verdict writes exactly the row an older pod wrote"
        );

        let new_row = audit_row(AuditKind::SessionStarted {
            peer_auth: Some("verified".into()),
        });
        let raw = bson::to_raw_document_buf(&new_row).unwrap();
        assert_eq!(
            raw.get_document("event")
                .unwrap()
                .get_str("peer_auth")
                .unwrap(),
            "verified"
        );
        let older: OlderRow =
            bson::from_slice(raw.as_bytes()).expect("an older pod reads a new row");
        assert_eq!(older.event, OlderKind::SessionStarted);
        let back: RemoteAuditEvent = bson::from_slice(raw.as_bytes()).unwrap();
        assert!(
            matches!(&back.event, AuditKind::SessionStarted { peer_auth: Some(v) } if v == "verified"),
            "{:?}",
            back.event
        );
    }

    /// `AuditSink::flush` → `insert_many` → `bson::to_raw_document_buf`; the
    /// audit route → typed cursor → `bson::from_slice`. Byte-for-byte the
    /// production pair, with no database. RED before the `deserialize_stored`
    /// opt-ins: the raw serializer stores `Int32` bits, and serde's
    /// tagged-enum buffering made the read look human-readable, so the wire
    /// rule refused them (#1630).
    #[test]
    fn audit_rows_the_driver_writes_read_back_through_the_driver_path() {
        for event in [
            AuditKind::SessionRequested {
                controller_user_id: ObjectId::new(),
                controller_name: "op".into(),
                permissions: Permissions::default(),
                record_stripped: None,
                privacy_stripped: None,
                features_stripped: None,
                idle_secs: None,
                idle_enforced: None,
                lock_on_end: None,
                lock_enforced: None,
            },
            // FR-99 — the new bit takes the same raw path.
            AuditKind::SessionRequested {
                controller_user_id: ObjectId::new(),
                controller_name: "op".into(),
                permissions: Permissions::VIEW | Permissions::INPUT | Permissions::PRIVACY,
                record_stripped: Some("device_not_opted_in".into()),
                privacy_stripped: None,
                // FR-101 P2 — and a row naming what the policy refused.
                features_stripped: Some(
                    [("files".to_string(), "org_policy_off".to_string())].into(),
                ),
                // FR-101 P4b-2 — and an idle limit the device does not keep.
                idle_secs: Some(900),
                idle_enforced: Some(false),
                // FR-99 P3b — and a lock it cannot take.
                lock_on_end: Some(LockOnEnd::Always),
                lock_enforced: Some(false),
            },
            AuditKind::PermissionsChanged {
                permissions: Permissions::VIEW,
            },
        ] {
            let want = event_permissions(&event);
            let raw = bson::to_raw_document_buf(&audit_row(event)).unwrap();
            // Pin the on-disk shape: the driver's raw serializer stores bits,
            // which is what every remote_audit row in prod holds.
            let stored = raw
                .get_document("event")
                .unwrap()
                .get("permissions")
                .unwrap()
                .expect("permissions present");
            assert_eq!(
                stored.element_type(),
                bson::spec::ElementType::Int32,
                "{stored:?}"
            );
            let back: RemoteAuditEvent = bson::from_slice(raw.as_bytes())
                .expect("the cursor must read what insert_many wrote");
            assert_eq!(event_permissions(&back.event), want);
        }
    }

    /// The other shape keeps reading — a row a `to_document` writer produced,
    /// or one an operator repaired by hand.
    #[test]
    fn name_shaped_audit_rows_read_back_too() {
        let doc = bson::doc! {
            "session_id": ObjectId::new(),
            "agent_id": ObjectId::new(),
            "tenant_id": ObjectId::new(),
            "at": bson::DateTime::now(),
            "event": { "kind": "permissions_changed", "permissions": "VIEW | FILES" },
        };
        let back: RemoteAuditEvent = bson::from_slice(&bson::to_vec(&doc).unwrap()).unwrap();
        assert_eq!(
            event_permissions(&back.event),
            Permissions::VIEW | Permissions::FILES
        );
    }

    /// A pre-P3 audit row has no `permissions` at all and still defaults.
    #[test]
    fn pre_p3_session_requested_rows_still_default() {
        let doc = bson::doc! {
            "session_id": ObjectId::new(),
            "agent_id": ObjectId::new(),
            "tenant_id": ObjectId::new(),
            "at": bson::DateTime::now(),
            "event": { "kind": "session_requested" },
        };
        let back: RemoteAuditEvent = bson::from_slice(&bson::to_vec(&doc).unwrap()).unwrap();
        assert_eq!(event_permissions(&back.event), Permissions::default());
    }

    /// `remote_sessions`: names from the `to_document` projection in
    /// `audit.rs` (every row in prod) and bits from a typed `insert_one`, both
    /// through the cursor's `from_slice`.
    #[test]
    fn remote_session_rows_read_back_in_both_shapes() {
        let row = RemoteSession {
            id: Some(ObjectId::new()),
            agent_id: ObjectId::new(),
            tenant_id: ObjectId::new(),
            controller_user_id: ObjectId::new(),
            watchers: Vec::new(),
            permissions: Permissions::VIEW | Permissions::INPUT | Permissions::CLIPBOARD,
            phase: SessionPhase::AwaitingConsent,
            created_at: bson::DateTime::now(),
            started_at: None,
            ended_at: None,
            end_reason: None,
            recording_url: None,
            stats: SessionStats::default(),
            carrier: None,
        };
        let names = bson::to_document(&row).unwrap();
        assert_eq!(
            names.get_str("permissions").unwrap(),
            "VIEW | INPUT | CLIPBOARD"
        );
        let back: RemoteSession = bson::from_slice(&bson::to_vec(&names).unwrap()).unwrap();
        assert_eq!(back.permissions, row.permissions);

        let bits = bson::to_raw_document_buf(&row).unwrap();
        assert_eq!(
            bits.get("permissions").unwrap().unwrap().element_type(),
            bson::spec::ElementType::Int32
        );
        let back: RemoteSession = bson::from_slice(bits.as_bytes()).unwrap();
        assert_eq!(back.permissions, row.permissions);
    }

    /// FR-111 P4a — a preset the viewer writes, in its own JSON: a row of
    /// keys, a d-pad, a stick and a macro, as `touchControls.ts` shapes them.
    fn preset_json() -> serde_json::Value {
        serde_json::json!({
            "name": "  WASD and look  ",
            "controls": [
                { "kind": "row", "id": "keys", "at": { "bottom": 12 }, "buttons": [
                    { "id": "esc", "label": "Esc", "action": { "kind": "keys", "keys": [0x29] } },
                    { "id": "copy", "label": "Copy", "action": { "kind": "keys", "keys": [0xe0, 0x06] } },
                    { "id": "click", "label": "Click", "action": { "kind": "mouse", "btn": "left" } },
                    { "id": "paste2", "label": "Paste x2", "action": { "kind": "macro", "steps": [
                        { "op": "press", "key": 0xe0 },
                        { "op": "tap", "key": 0x19, "wait_ms": 120 },
                        { "op": "tap", "key": 0x19 },
                        { "op": "release", "key": 0xe0 },
                        { "op": "tap", "btn": "right", "wait_ms": 50 }
                    ] } }
                ] },
                { "kind": "dpad", "id": "move", "label": "Move", "at": { "left": 16, "bottom": 16 },
                  "size": 150, "up": 0x1a, "down": 0x16, "left": 0x04, "right": 0x07 },
                { "kind": "stick", "id": "look", "label": "Look", "at": { "right": 16, "bottom": 16 },
                  "size": 150, "speed": 1 },
                { "kind": "row", "id": "col", "dir": "column", "at": { "right": 16, "top": 80 }, "buttons": [
                    { "id": "tab", "label": "Tab", "action": { "kind": "keys", "keys": [0x2b] } }
                ] }
            ]
        })
    }

    fn req(v: serde_json::Value) -> TouchPresetRequest {
        serde_json::from_value(v).expect("parses")
    }

    #[test]
    fn fr111_a_viewer_preset_parses_validates_and_round_trips() {
        let r = req(preset_json());
        assert_eq!(
            r.validate(),
            Ok("WASD and look".to_string()),
            "the name trimmed"
        );
        // What is served back reads as the same controls: nothing lost. (As
        // JSON text a place comes back `12.0` and a step without a wait gains
        // `"wait_ms": 0`, the same numbers to the viewer's `JSON.parse`.)
        let served = serde_json::to_value(&r.controls).unwrap();
        let again: Vec<TouchControl> = serde_json::from_value(served.clone()).unwrap();
        assert_eq!(again, r.controls);
        assert_eq!(served[0]["at"]["bottom"], serde_json::json!(12.0));
        assert_eq!(served[3]["dir"], "column");
        assert!(served[0].get("dir").is_none(), "no dir unless given");
        assert_eq!(served[0]["buttons"][3]["action"]["steps"][0]["wait_ms"], 0);
        assert!(
            served[0]["buttons"][3]["action"]["steps"][0]
                .get("btn")
                .is_none()
        );
        // And through BSON, as Mongo stores them.
        let row = TouchPreset {
            id: None,
            tenant_id: ObjectId::new(),
            name: "x".into(),
            controls: r.controls.clone(),
            created_by: ObjectId::new(),
            updated_by: ObjectId::new(),
            created_at: DateTime::now(),
            updated_at: DateTime::now(),
        };
        let stored: TouchPreset = bson::from_document(bson::to_document(&row).unwrap()).unwrap();
        assert_eq!(stored.controls, r.controls);
    }

    #[test]
    fn fr111_unknown_fields_are_refused_at_every_level() {
        for path in [
            vec!["extra"],
            vec!["controls", "0", "extra"],
            vec!["controls", "0", "at", "extra"],
            vec!["controls", "0", "buttons", "0", "extra"],
            vec!["controls", "0", "buttons", "0", "action", "extra"],
            vec![
                "controls", "0", "buttons", "3", "action", "steps", "0", "extra",
            ],
            vec!["controls", "1", "extra"],
        ] {
            let mut v = preset_json();
            let mut at = &mut v;
            for seg in &path[..path.len() - 1] {
                at = match seg.parse::<usize>() {
                    Ok(i) => &mut at[i],
                    Err(_) => &mut at[*seg],
                };
            }
            at[path[path.len() - 1]] = serde_json::json!(1);
            assert!(
                serde_json::from_value::<TouchPresetRequest>(v).is_err(),
                "an unknown field at {path:?} must fail the parse"
            );
        }
        // A key past a byte is not a HID usage at all.
        let mut v = preset_json();
        v["controls"][0]["buttons"][0]["action"]["keys"][0] = serde_json::json!(300);
        assert!(serde_json::from_value::<TouchPresetRequest>(v).is_err());
    }

    #[test]
    fn fr111_validation_refuses_what_a_viewer_should_not_run() {
        let refused = |edit: &dyn Fn(&mut serde_json::Value), code: &str| {
            let mut v = preset_json();
            edit(&mut v);
            assert_eq!(req(v).validate(), Err(code), "{code}");
        };
        refused(&|v| v["name"] = "   ".into(), "name_empty");
        refused(&|v| v["name"] = "n".repeat(49).into(), "name_invalid");
        refused(&|v| v["name"] = "two\nlines".into(), "name_invalid");
        refused(&|v| v["controls"] = serde_json::json!([]), "no_controls");
        refused(
            &|v| {
                let one = v["controls"][2].clone();
                v["controls"] = serde_json::json!(
                    (0..25)
                        .map(|i| {
                            let mut c = one.clone();
                            c["id"] = format!("s{i}").into();
                            c
                        })
                        .collect::<Vec<_>>()
                );
            },
            "too_many_controls",
        );
        refused(&|v| v["controls"][1]["id"] = "keys".into(), "id_duplicate");
        refused(
            &|v| v["controls"][0]["buttons"][1]["id"] = "esc".into(),
            "id_duplicate",
        );
        refused(&|v| v["controls"][1]["id"] = "".into(), "id_invalid");
        refused(
            &|v| v["controls"][1]["label"] = "a label far too long".into(),
            "label_invalid",
        );
        refused(
            &|v| v["controls"][0]["buttons"][0]["label"] = " ".into(),
            "label_invalid",
        );
        refused(
            &|v| v["controls"][0]["buttons"] = serde_json::json!([]),
            "row_buttons",
        );
        refused(
            &|v| v["controls"][0]["buttons"][0]["action"]["keys"] = serde_json::json!([]),
            "chord_keys",
        );
        refused(
            &|v| {
                v["controls"][0]["buttons"][0]["action"]["keys"] =
                    serde_json::json!([0x04, 0x05, 0x06, 0x07, 0x08])
            },
            "chord_keys",
        );
        // 0x00..0x03 are error codes, 0xA5..0xDF and 0xE8.. are not keys the
        // keyboard path sends.
        for bad in [0x00, 0x03, 0xa5, 0xdf, 0xe8, 0xff] {
            refused(
                &|v| v["controls"][0]["buttons"][0]["action"]["keys"][0] = bad.into(),
                "key_invalid",
            );
        }
        refused(&|v| v["controls"][1]["up"] = 0xf0.into(), "key_invalid");
        refused(&|v| v["controls"][1]["size"] = 47.into(), "size_invalid");
        refused(&|v| v["controls"][2]["size"] = 401.into(), "size_invalid");
        refused(&|v| v["controls"][2]["speed"] = 0.0.into(), "speed_invalid");
        refused(&|v| v["controls"][2]["speed"] = 5.5.into(), "speed_invalid");
        refused(
            &|v| v["controls"][1]["at"]["right"] = 4.into(),
            "place_both_edges",
        );
        refused(
            &|v| v["controls"][3]["at"]["bottom"] = 4.into(),
            "place_both_edges",
        );
        refused(
            &|v| v["controls"][1]["at"]["left"] = (-1).into(),
            "place_invalid",
        );
        refused(
            &|v| v["controls"][1]["at"]["left"] = 4001.into(),
            "place_invalid",
        );
        let step = |v: &mut serde_json::Value| -> serde_json::Value {
            v["controls"][0]["buttons"][3]["action"]["steps"].clone()
        };
        refused(
            &|v| v["controls"][0]["buttons"][3]["action"]["steps"] = serde_json::json!([]),
            "macro_steps",
        );
        refused(
            &|v| {
                let one = step(v)[0].clone();
                v["controls"][0]["buttons"][3]["action"]["steps"] =
                    serde_json::json!(vec![one; 33]);
            },
            "macro_steps",
        );
        refused(
            &|v| v["controls"][0]["buttons"][3]["action"]["steps"][0]["btn"] = "left".into(),
            "step_key_or_button",
        );
        refused(
            &|v| {
                let s = &mut v["controls"][0]["buttons"][3]["action"]["steps"][4];
                s.as_object_mut().unwrap().remove("btn");
            },
            "step_key_or_button",
        );
        refused(
            &|v| v["controls"][0]["buttons"][3]["action"]["steps"][1]["key"] = 0xe9.into(),
            "key_invalid",
        );
        refused(
            &|v| v["controls"][0]["buttons"][3]["action"]["steps"][1]["wait_ms"] = 5001.into(),
            "step_wait",
        );
        refused(
            &|v| {
                let mut one = step(v)[1].clone();
                one["wait_ms"] = 5000.into();
                v["controls"][0]["buttons"][3]["action"]["steps"] = serde_json::json!(vec![one; 7]);
            },
            "macro_too_long",
        );
    }

    #[test]
    fn fr111_touch_keys_are_the_keyboard_page() {
        assert!(touch_key_ok(0x04) && touch_key_ok(0x73) && touch_key_ok(0xa4));
        assert!(touch_key_ok(0xe0) && touch_key_ok(0xe7));
        assert!(!touch_key_ok(0x00) && !touch_key_ok(0x03));
        assert!(!touch_key_ok(0xa5) && !touch_key_ok(0xdf) && !touch_key_ok(0xe8));
    }
}

#[cfg(test)]
mod block_list_tests {
    use super::*;

    /// THE compatibility property: a one-block list is byte-for-byte the
    /// behaviour of the bare `overlay_ip`/`overlay_host` pair. Multi-block
    /// ships behind a flag on a live fleet, so "off" has to be provably the
    /// old code path rather than a re-implementation that agrees most of the
    /// time.
    #[test]
    fn a_single_block_list_is_exactly_the_old_pair() {
        let cidr = "100.65.4.0/22";
        let bl = BlockList::single(cidr);
        assert_eq!(bl.capacity(), cidr_max_host(cidr).unwrap());
        for h in [1u32, 2, 7, 255, 256, 1021, 1022] {
            let want = overlay_ip(cidr, h).unwrap();
            assert_eq!(bl.ip_for_ordinal(h).as_deref(), Some(want.as_str()));
            assert_eq!(bl.ordinal_for_ip(&want), Some(h));
        }
        // Past the end in both directions.
        assert_eq!(bl.ip_for_ordinal(1023), None);
        assert_eq!(bl.ip_for_ordinal(0), None);
        assert_eq!(bl.ordinal_for_ip("100.66.0.1"), None);
    }

    /// Ordinals concatenate across blocks, and the round-trip holds over the
    /// seam — which is the only place it can plausibly break.
    #[test]
    fn ordinals_concatenate_across_blocks_and_round_trip() {
        let bl = BlockList::new(["100.65.4.0/22", "100.65.8.0/22", "100.66.0.0/20"]);
        assert_eq!(bl.capacity(), 1022 + 1022 + 4094);

        // Last of block 0, first of block 1 — the seam.
        assert_eq!(bl.ip_for_ordinal(1022).as_deref(), Some("100.65.7.254"));
        assert_eq!(bl.ip_for_ordinal(1023).as_deref(), Some("100.65.8.1"));
        // Last of block 1, first of block 2 — the second seam.
        assert_eq!(bl.ip_for_ordinal(2044).as_deref(), Some("100.65.11.254"));
        assert_eq!(bl.ip_for_ordinal(2045).as_deref(), Some("100.66.0.1"));

        for o in [1u32, 1022, 1023, 2044, 2045, 6138] {
            let ip = bl.ip_for_ordinal(o).expect("in range");
            assert_eq!(bl.ordinal_for_ip(&ip), Some(o), "round trip at ordinal {o}");
        }
        assert_eq!(bl.ip_for_ordinal(bl.capacity() + 1), None);
    }

    /// Appending a block must not move a single existing ordinal. This is the
    /// property that makes growth non-disruptive, and it is the whole reason
    /// the list is append-only.
    #[test]
    fn appending_a_block_moves_no_existing_ordinal() {
        let before = BlockList::new(["100.65.4.0/22"]);
        let after = BlockList::new(["100.65.4.0/22", "100.65.8.0/22"]);
        for o in 1..=before.capacity() {
            assert_eq!(
                before.ip_for_ordinal(o),
                after.ip_for_ordinal(o),
                "ordinal {o} moved when a block was appended"
            );
        }
        assert!(before.ip_for_ordinal(1023).is_none());
        assert!(after.ip_for_ordinal(1023).is_some());
    }

    /// A node is told the block its OWN address lives in — an agent derives
    /// its TUN netmask and NAT scope from that string, and the first block
    /// would be wrong for a node living in the second.
    #[test]
    fn cidr_for_ip_names_the_block_that_contains_the_address() {
        let bl = BlockList::new(["100.65.4.0/22", "100.65.8.0/22"]);
        assert_eq!(bl.cidr_for_ip("100.65.4.2"), Some("100.65.4.0/22"));
        assert_eq!(bl.cidr_for_ip("100.65.8.2"), Some("100.65.8.0/22"));
        assert_eq!(bl.cidr_for_ip("100.70.0.1"), None);
    }

    /// A block that can lease nothing is dropped, so it can never become a
    /// position that later shifts every ordinal above it.
    #[test]
    fn unleasable_blocks_are_dropped_not_kept_as_zero_width() {
        let bl = BlockList::new(["100.65.4.0/22", "100.65.8.0/31", "100.65.12.0/22"]);
        assert_eq!(bl.cidrs().len(), 2);
        assert_eq!(bl.capacity(), 2044);
        assert_eq!(bl.ip_for_ordinal(1023).as_deref(), Some("100.65.12.1"));
    }
}

// FR-69 P5a — the SSH policy REQUEST shape, here because the fleet module
// accepts it inside its agent-update body while the SSH route (network) reads
// and writes it: a wire shape both sides share lives in the wire crate.
#[derive(Debug, Serialize, Deserialize)]
pub struct SshPolicyBody {
    #[serde(default)]
    pub mode: SshMode,
    #[serde(default)]
    pub can_originate: bool,
    #[serde(default)]
    pub allowed_user_ids: Vec<String>,
    #[serde(default)]
    pub allowed_role_ids: Vec<String>,
    #[serde(default)]
    pub account_mode: SshAccountMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_mode: Option<ConsentMode>,
}

impl From<SshPolicy> for SshPolicyBody {
    /// The stored policy as the dashboard reads it back — hex ids, because
    /// bson's `ObjectId` serialises to `{"$oid": …}` and no client here parses
    /// that.
    ///
    /// Destructured EXHAUSTIVELY for the same reason [`SshPolicy::split`] is:
    /// this is the shape a dialog re-saves, so a field added to [`SshPolicy`]
    /// and forgotten here would not merely fail to display — the next save
    /// would reset it to its default. Better a compile error.
    fn from(p: SshPolicy) -> Self {
        let SshPolicy {
            mode,
            can_originate,
            allowed_user_ids,
            allowed_role_ids,
            account_mode,
            account,
            consent_mode,
        } = p;
        Self {
            mode,
            can_originate,
            allowed_user_ids: allowed_user_ids.iter().map(|i| i.to_hex()).collect(),
            allowed_role_ids: allowed_role_ids.iter().map(|i| i.to_hex()).collect(),
            account_mode,
            account,
            consent_mode,
        }
    }
}

// FR-69 P5c — the key-rotation order predicates the agent socket evaluates on
// connect. Here (the wire crate) because the socket is the fleet module`s and
// the order is network`s: a pure judgement over two models belongs with them.
/// P1b — how long a DELIVERED order is trusted to be in progress before the
/// connect-time reconcile pushes it again. Found in the first field run: the
/// device's `rotated` report rides the dying session and is written by a
/// spawned task, while the device reconnects ~500 ms later — its register ran
/// the reconcile before the report landed, re-pushed the SAME order, the
/// device refused the duplicate under its own 60 s ceiling, and that refusal
/// overwrote the `rotated` report. A freshly delivered order is being
/// executed; its answer is seconds away. Past this window an unanswered order
/// is assumed dropped (the device crashed mid-rotation, say) and re-sent.
pub const REDELIVER_AFTER_SECS: i64 = 120;

/// P1d — an order is SATISFIED once the device has joined under a key that
/// differs from the one it held when the order was placed, whether or not a
/// report ever arrived. Found in the third cycle: the run-2 order's report was
/// lost, the P1b window expired, and every later reconnect (a pod roll, then
/// the 0.4.26 restart) re-delivered the same order — the device rotated three
/// times for one click. The join is the proof; a satisfied order is never
/// pushed again. Orders placed before the snapshot existed (no
/// `public_key_before`) cannot be judged this way and fall back to the report.
pub fn order_is_satisfied(
    request: &KeyRotationRequest,
    identity: Option<&OverlayIdentity>,
) -> bool {
    match (request.public_key_before.as_deref(), identity) {
        (Some(before), Some(id)) => {
            id.public_key != before
                && id.joined_at.timestamp_millis() >= request.requested_at.timestamp_millis()
        }
        _ => false,
    }
}

/// Whether a standing order should be pushed again on THIS connect (the
/// report-and-timing half; callers also check [`order_is_satisfied`]).
pub fn should_redeliver(
    request: &KeyRotationRequest,
    report: Option<&KeyRotationReport>,
    now: DateTime,
) -> bool {
    if report.is_some_and(|r| r.request_id == request.request_id) {
        return false;
    }
    match request.delivered_at {
        None => true,
        Some(at) => (now.timestamp_millis() - at.timestamp_millis()) / 1000 >= REDELIVER_AFTER_SECS,
    }
}

#[cfg(test)]
mod backbone_policy_tests {
    use super::*;
    #[test]
    fn missing_backbone_edges_are_default_closed_and_known_edges_round_trip() {
        let policy: PeerRelayPolicy =
            serde_json::from_str(r#"{"serve":true,"static_endpoints":[]}"#).unwrap();
        assert!(policy.approved_backbone_edges.is_empty());
        assert!(
            serde_json::to_value(&policy)
                .unwrap()
                .get("approved_backbone_edges")
                .is_none()
        );
        let policy = PeerRelayPolicy {
            serve: true,
            static_endpoints: vec!["8.8.8.8:3478".into()],
            approved_backbone_edges: vec![PeerRelayBackboneEdge {
                relay_agent_id: ObjectId::new().to_hex(),
                endpoint: "10.20.0.2:3478".into(),
                cross_border: false,
            }],
        };
        let encoded = bson::to_bson(&policy).unwrap();
        assert_eq!(bson::from_bson::<PeerRelayPolicy>(encoded).unwrap(), policy);
    }
}
