// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! `roomlerd` — the native remote-control agent for the Roomler AI
//! platform. Runs on the controlled host, connects out to the Roomler API
//! over WSS, and (eventually) serves a WebRTC peer to a browser controller.
//!
//! This v1 is signaling-only: it enrols against a token from an admin,
//! connects the WS, sends `rc:agent.hello`, auto-grants consent, and cleanly
//! declines media until the screen-capture / encode / WebRTC pieces land.
//!
//! CLI:
//!   meshharbord enroll --server <url> --token <enrollment-jwt> \
//!                        --name "Goran's Laptop" [--config <path>]
//!   meshharbord run    [--config <path>]

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
#[cfg(target_os = "windows")]
use roomlerd::dpi;
#[cfg(target_os = "macos")]
use roomlerd::tcc;
#[cfg(target_os = "linux")]
use roomlerd::virtual_desktop;
#[cfg(target_os = "windows")]
use roomlerd::win_service;
#[cfg(target_os = "windows")]
use roomlerd::win_timer;
#[cfg(target_os = "windows")]
use roomlerd::win32_monitors;
use roomlerd::{
    config, crash_uploader, encode, enrollment, instance_lock, localapi_state, logging, machine,
    notify, post_install, preflight, service, signaling, updater, watchdog,
};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tunnel_core::env::node_env;
#[cfg(target_os = "linux")]
use tunnel_core::env::node_env_os;

#[derive(Debug, Parser)]
#[command(name = "meshharbord", version, about, long_about = None)]
struct Cli {
    /// Override config file location. Defaults to the platform config dir.
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Enroll this machine against a Roomler server using an admin-issued
    /// enrollment token. Writes the resulting agent token to the config file.
    Enroll {
        /// Base URL of the Roomler API (e.g. https://roomler.live).
        #[arg(long)]
        server: String,
        /// Enrollment token, as printed by the admin UI.
        #[arg(long)]
        token: String,
        /// Friendly name shown in the admin agents list.
        #[arg(long)]
        name: String,
        /// Multi-org: label for the enrollment when it resolves to a NEW
        /// (server, org) pair and is APPENDED as a secondary org
        /// (lowercase letters/digits/dashes). Default: derived from the
        /// server host. Ignored when the enrollment refreshes an existing
        /// one.
        #[arg(long)]
        label: Option<String>,
        /// Legacy behaviour: REBIND the primary enrollment to this
        /// (server, org) wholesale instead of appending a secondary org.
        /// Operator state is preserved (rc.204 semantics); a secondary
        /// entry duplicating the new primary identity is dropped.
        #[arg(long)]
        replace: bool,
        // RETIRED-NAME-ANCHOR: the PRE-RENAME machine-global tree.
        // `machine_global_dir()` still resolves
        // it on a host that has one, so it must stay named here. docs/fr/FR-21
        /// rc.52: write the enrolled config to the machine-global
        /// path (`%PROGRAMDATA%\roomler\roomler-agent\config.toml`)
        /// instead of the per-user `%APPDATA%` default. Required for
        /// perMachine + SystemContext hosts so the LocalSystem worker
        /// can load its config pre-logon. Windows-only; requires an
        /// elevated (Administrator) terminal — a non-elevated enroll
        /// cannot write `%PROGRAMDATA%` and will fail loudly rather
        /// than silently falling back to a path the SC worker can't
        /// read. The installer wizard's `permachine-system-context`
        /// flavour passes this automatically.
        #[arg(long)]
        machine_global: bool,
        /// FR-51 — enroll as an EPHEMERAL device: a fresh RANDOM machine
        /// fingerprint (so N replicas of one image are N devices, and a
        /// restart is a NEW device), and the daemon de-enrolls itself on
        /// SIGTERM/SIGINT. Requires an ephemeral enrollment KEY from the
        /// dashboard — with a standard token the server enrolls a normal
        /// permanent device and this flag warns loudly. Refused when a
        /// config already exists at the target path: an ephemeral identity
        /// must never be folded into a real device's config.
        #[arg(long)]
        ephemeral: bool,
        /// Join the overlay mesh from the first start, instead of leaving
        /// `overlay_enabled` off for the operator to flip afterwards.
        ///
        /// The alternative is a round trip through the running daemon
        /// (`meshharbor config set overlay_enabled true`), which at INSTALL time
        /// means racing the daemon's socket before it exists. This writes the
        /// key with the rest of the enrolled config, so the very first start
        /// is already correct.
        ///
        /// Default-off elsewhere is unchanged: this is opt-in per enrollment,
        /// and the caller asking for it has already chosen to install
        /// something privileged enough to bring up a TUN.
        #[arg(long)]
        overlay: bool,
        /// MeshHarbor — offer this device as an org relay from the first
        /// start (gate 4, `relay_server_enabled`), for a server the central
        /// owner approves as a `server` role. Primary enrollment only: the
        /// listener is host-global. Consent given by whoever installs the
        /// host; the server can never push it.
        #[arg(long)]
        relay_server: bool,
        /// FR-90 P2h-1 — enroll as an archive replica of the organization, as
        /// the archive image does: it holds copies of the org's sessions and
        /// offers itself as an archive (`hive_replica`, `hive_archive`), runs
        /// no session, takes no command or SSH session, is no tunnel exit,
        /// and never updates itself. Written with the enrolled config, so the
        /// first start is already one. Needs a fresh config, and a standard
        /// (never an ephemeral) token; an `ADMINISTRATOR` still designates
        /// the device before it holds anything.
        #[arg(long)]
        archive_replica: bool,
        /// FR-102 — how this daemon was installed, for the server's install
        /// trace: one of `wizard`, `script-sh`, `script-ps1`, `msi`, `deb`,
        /// `pkg`, `manual`, `container`, `other`. Falls back to the
        /// `ROOMLER_INSTALL_METHOD` env var (what the served install scripts
        /// set), then to `manual` — a person typed this command.
        #[arg(long, value_name = "METHOD")]
        install_method: Option<String>,
        /// FR-102 — what the install runs as: `system`, `per-user`,
        /// `attended` or `unknown`. Falls back to `ROOMLER_INSTALL_SCOPE`,
        /// then to `unknown`.
        #[arg(long, value_name = "SCOPE")]
        install_scope: Option<String>,
    },
    /// Refresh this machine's agent token using a fresh enrollment JWT.
    /// Preserves `server_url` and `machine_name` from the existing
    /// config, so the operator only needs the new token. Used after
    /// an admin revokes the prior token (the `re-enrollment required`
    /// attention sentinel surfaces this case).
    ReEnroll {
        /// Fresh enrollment JWT from the admin UI.
        #[arg(long)]
        token: String,
        /// Multi-org: which enrollment to refresh — `primary` (default) or
        /// a `[[orgs]]` label (`roomlerd org ls`). The token is posted
        /// to THAT org's server; the response must resolve to the same
        /// org (a different-tenant token belongs in `enroll`).
        #[arg(long)]
        org: Option<String>,
    },
    /// FR-94 (Windows) — anchor this machine's device, so Fleet RPC runs as
    /// SYSTEM through the Roomler service instead of as the signed-in user.
    /// Every action needs an elevated prompt (Run as administrator).
    Anchor {
        #[command(subcommand)]
        action: AnchorCmd,
    },
    /// Multi-org: inspect + manage this machine's enrollments. The config's
    /// scalar identity is the PRIMARY org; additional enrollments live in
    /// `[[orgs]]` (appended by `enroll`). Changes apply at the next daemon
    /// start.
    Org {
        #[command(subcommand)]
        action: OrgAction,
    },
    /// Connect to the server and sit in the signaling loop (default command
    /// if none is given).
    Run {
        /// Override the config's `encoder_preference`. One of:
        /// `auto` (default — picks HW on Windows, SW elsewhere),
        /// `hardware` (force MF; falls back to SW only on init failure),
        /// `software` (force openh264). Also honours the
        /// `ROOMLERD_ENCODER` env var.
        #[arg(long)]
        encoder: Option<String>,
        /// FR-43 P2a (macOS) — this process was started by the root daemon's
        /// GUI-worker supervisor, and its delegation-channel secret is waiting
        /// on stdin as a single line.
        ///
        /// A FLAG rather than an environment variable because the spawn chain
        /// runs through `sudo`, and `Defaults env_reset` discards the
        /// environment — measured on a real host, which is how P1's
        /// `ROOMLER_MACOS_SUPERVISED` marker turned out never to have arrived
        /// at all. The secret itself stays OFF the command line: argv is world
        /// readable via `ps`, while the pipe is only the parent's.
        #[arg(long, hide = true)]
        supervised: bool,
        /// FR-84 D3 (Windows) — which spawner started this worker: `scm` (the
        /// SCM service host's supervisor, `win_service::worker_args`) or
        /// `task` (the per-user Scheduled Task's action, `service.rs`). It is
        /// the worker's only evidence that an exit for `RestartDaemon` will
        /// be answered by a relaunch; a bare `run` is an orphan and refuses.
        /// Hidden: a person passing it by hand is lying to the daemon about
        /// who will bring it back. Ignored on every other platform
        /// (`supervision::detect_here`).
        #[arg(long, hide = true, value_parser = ["scm", "task"])]
        supervisor: Option<String>,
        /// #1683 (Windows) — the named Win32 event the SCM service host signals
        /// to ask this worker to stop GRACEFULLY (self-unenroll if ephemeral,
        /// mark a clean shutdown) before it falls back to `TerminateProcess`.
        /// The host creates it with a DACL that lets only SYSTEM signal it; the
        /// worker needs only SYNCHRONIZE to wait. Passed only by
        /// `win_service::supervisor` (`--stop-event <name>`); ignored on every
        /// other platform. Hidden: a person passing it by hand is claiming to be
        /// a service host, and no host will be signaling that event.
        #[arg(long, hide = true)]
        stop_event: Option<String>,
        /// FR-97 P4a (Windows) — the named event this worker signals to have
        /// the SCM service host send the real Ctrl+Alt+Del, which only the
        /// service process can (`win_service::sas_relay`). Only SYSTEM may
        /// signal it, so only a SystemContext worker can use it. Passed only by
        /// the host; hidden for the same reason as `--stop-event`.
        #[arg(long, hide = true)]
        sas_event: Option<String>,
    },
    /// Run the codec capability probes and print the result as one
    /// `ROOMLER_CAPS_JSON:{…}` line. Spawned by the daemon itself — never
    /// invoked by operators — so that a vendor driver faulting inside a
    /// probe costs a child process instead of crash-looping the daemon.
    /// Hidden: running it by hand only tells you what `meshharbor status`
    /// already reports.
    #[command(hide = true, name = "caps-probe")]
    CapsProbe,
    /// FR-97 P6a — read a downloaded release artifact's own version and bind
    /// it to the release it is offered as, exactly as the updater does before
    /// it installs anything. Prints the verdict; exits non-zero on a refusal.
    /// For proving the readers against published releases; hidden, since the
    /// updater runs the same check itself.
    #[command(hide = true, name = "artifact-version")]
    ArtifactVersion {
        /// The `.msi`, `.deb`, `.pkg` or `.tar.gz`.
        path: std::path::PathBuf,
        /// The release it is offered as: `agent-v0.4.142` or `0.4.142`.
        claimed: String,
    },
    /// (internal, Linux) FR-45 P2a — run inside the console user's session and
    /// report the desktop portal's availability as one
    /// `ROOMLER_PORTAL_JSON:{…}` line.
    ///
    /// Spawned by the daemon, never by operators. It exists because the daemon
    /// is root and the portal is per-user-session: there is no way to ask the
    /// question from where the daemon stands. Running it by hand from your own
    /// shell answers a *different* question — whether YOUR session has a
    /// portal — which is why it is hidden.
    #[command(hide = true, name = "portal-helper")]
    PortalHelper {
        /// FR-45 P2b — instead of just detecting, open a ScreenCast session
        /// and report its PipeWire node id. ⚠️ Shows a consent dialog on the
        /// first run; later runs carry a restore token and do not.
        #[arg(long)]
        screencast: bool,
        /// FR-45 P3c-ii — open a session and then write frames on stdout until
        /// the parent goes away. ⚠️ stdout is BINARY in this mode; everything
        /// diagnostic goes to stderr.
        #[arg(long)]
        stream: bool,
        /// FR-45 P4 — with --stream: open the session through RemoteDesktop
        /// and consume InputMsg JSON lines on stdin, injecting them into the
        /// session. Falls back to capture-only where the portal has no
        /// RemoteDesktop backend.
        #[arg(long)]
        input: bool,
        /// FR-45 P5 — with --stream: take the frames from
        /// `org.gnome.Mutter.ScreenCast` DIRECTLY instead of the portal. ⚠️
        /// This shows NO consent dialog; it is the unattended sibling, for
        /// hosts where no portal backend can run.
        #[arg(long)]
        mutter: bool,
        /// FR-56 P4 — with --stream: record ONE application window instead of
        /// the whole monitor. ⚠️ The portal shows the person at the screen a
        /// window PICKER; nothing here chooses the window.
        #[arg(long)]
        window: bool,
        /// FR-92 P9 — answer keep busy's questions about this GNOME session
        /// (Mutter's idle clock and monitor layout), one line per question on
        /// stdin, until the daemon closes it. Reads no input, sends none.
        #[arg(long)]
        keep_busy: bool,
        /// FR-93 P6f — post the desktop notification described by one JSON
        /// line on stdin (a consent question with Approve and Deny), say on
        /// stdout what the person did, and close it when stdin closes.
        #[arg(long)]
        notify: bool,
        /// FR-95 P2 — say whether this session can show a notification with
        /// buttons (its notification server, and the `actions` capability),
        /// and post nothing.
        #[arg(long)]
        notify_probe: bool,
        /// FR-97 P3c-2 — record this session's sound (the default output's
        /// monitor, never a microphone) and write raw 48 kHz stereo s16le on
        /// stdout after one marked line, until the daemon closes the pipe.
        /// ⚠️ stdout is BINARY in this mode.
        #[arg(long)]
        audio: bool,
    },
    /// (internal, Linux) FR-45 P2b — open a portal ScreenCast session THROUGH
    /// the session helper and print what came back.
    ///
    /// The root-side counterpart to `portal-helper --screencast`: this is the
    /// path the capture cascade will take, so it is the one worth testing.
    /// ⚠️ Blocks while a person answers the consent dialog.
    #[command(hide = true, name = "portal-session")]
    PortalSession,
    /// FR-16 L4 — open the bench probe target: a small topmost window in the
    /// primary monitor's bottom-right corner whose marker changes when a
    /// real pointer move reaches one of its 16 cells. A viewer with
    /// `roomler-rc-bench=target` moves the remote pointer onto the cells and
    /// times each move to the first painted frame showing it: input to
    /// photon on a release build, injection and the host's compositor
    /// included. Run it in the signed-in desktop session. Windows only.
    #[command(name = "probe-target")]
    ProbeTarget {
        /// Close after this many seconds (it also closes on a right-click),
        /// so a bench window is never left on a host by accident.
        #[arg(long, default_value_t = 600)]
        seconds: u64,
    },
    /// FR-99 P1b — put a privacy curtain up through the production overlay
    /// for `--seconds`, and report whether it went up out of capture
    /// (`possible=… up=…`). A field check that needs no server and no viewer:
    /// a screenshot of the host shows the curtain while a session's stream
    /// shows the desktop under it. Run it in the signed-in desktop session.
    /// Windows 10 2004 or later; exits non-zero when no curtain went up.
    #[command(name = "curtain-smoke")]
    CurtainSmoke {
        /// How long the curtain stays up.
        #[arg(long, default_value_t = 30)]
        seconds: u64,
    },
    /// (internal, macOS and Linux) The body of the `com.roomler.update`
    /// LaunchDaemon and of the Linux `meshharbor-update.service` (FR-96): consume
    /// the wake file, then check → download → verify → install as root,
    /// waiting on it (`installer -pkg … -target /` on macOS, whose postinstall
    /// restarts the agent halves; `apt-get`/`dpkg` or the tarball on Linux).
    /// Root-only and single-shot. Hidden: launchd or systemd is the caller — by
    /// hand it is `sudo meshharbord update-helper`, and running it non-root only
    /// prints the refusal.
    /// `update-helper --capabilities` (FR-96 P3) is answered before this
    /// parser runs: see `daemon_main`.
    #[command(hide = true, name = "update-helper")]
    UpdateHelper,
    /// Smoke-test the encoder cascade: open the preferred encoder at
    /// a small resolution, feed 10 synthetic frames, assert at least
    /// one IDR output. Exits non-zero if no encoder could be opened or
    /// no keyframe was produced. Used in the release CI smoke check
    /// to catch regressions in the MF init path before shipping.
    EncoderSmoke {
        /// Encoder preference for the test. Defaults to `hardware` so
        /// the CI exercise actually verifies the MF path.
        #[arg(long, default_value = "hardware")]
        encoder: String,
        /// Codec to smoke-test. `h264` (default) or `h265` — HEVC
        /// goes through `open_for_codec` and the MF HEVC cascade.
        /// Accepts `hevc` as an alias.
        #[arg(long, default_value = "h264")]
        codec: String,
        /// FR-62 A0 — instead of the 10-frame smoke, open once and sweep the
        /// maxrate down (6M → 200k) and back up via `set_bitrate`, reporting
        /// per rung whether the change forced an IDR, how long the apply took,
        /// and how closely the encoder tracked the target. Measures, on real
        /// silicon, the cost the whole rate-control patch-work exists to
        /// ration. Best with `--codec hevc`/`av1` and `--encoder hardware`.
        #[arg(long)]
        reconfigure_sweep: bool,
        /// FR-78 P2 — open exactly this FFmpeg encoder name (`hevc_d3d12va`,
        /// `av1_vulkan`, `h264_vaapi`, …) instead of the cascade, so a
        /// backend the vendor SDK outranks on this host can be driven with
        /// real bytes (and swept, with `--reconfigure-sweep`). `--encoder`
        /// and `--codec` are ignored when set.
        #[arg(long)]
        name: Option<String>,
        /// FR-78 P3 — write every packet's bytes, back to back, to this file:
        /// an Annex B stream for H.264 / HEVC, a raw OBU stream for AV1
        /// (`ffmpeg -i <file>` reads both). A cell whose SESSION decodes to
        /// garbage in the viewer (the dev box's `av1_vulkan`, 2026-09-08) is
        /// attributed offline this way — FFmpeg's own decoder on the encoder's
        /// bytes says whether the bitstream or the viewer's packaging is at
        /// fault. Not with `--reconfigure-sweep`.
        #[arg(long)]
        dump: Option<String>,
        /// Sweep frame geometry (A0). Corp-laptop default.
        #[arg(long, default_value_t = 1280)]
        width: u32,
        #[arg(long, default_value_t = 800)]
        height: u32,
        /// Frames encoded at each rung before moving to the next (A0).
        #[arg(long, default_value_t = 30)]
        frames_per_rung: u32,
        /// Open the encoder in constrained (relay) mode — the tighter HRD
        /// window a slow-link session runs with (A0).
        #[arg(long)]
        constrained: bool,
        /// Emit the sweep result as one JSON line for the FR doc (A0).
        #[arg(long)]
        json: bool,
    },
    /// Smoke-test the screen-capture cascade on THIS host: run
    /// `open_default`, pull N frames, and report which backend answered,
    /// the geometry, and per-frame timing. Optionally dump the last frame
    /// as a PPM so a human can confirm the pixels are a desktop rather
    /// than plausible-looking garbage.
    ///
    /// Exists because "capture works here" was previously only answerable
    /// by opening a full remote-control session — which conflates capture,
    /// encode, transport and the browser. FR-36 needs it to field-verify a
    /// DRM/KMS backend on a host with no session at all.
    #[command(hide = true, name = "capture-smoke")]
    /// Report whether Remote Apps can manage a desktop on THIS host, and list
    /// what it sees — without opening a remote-control session.
    ///
    /// FR-56 P1. Exists for the same reason `capture-smoke` does: "does Remote
    /// Apps work here" was previously answerable only by driving the feature
    /// over a WebRTC data channel from a browser, which conflates the backend
    /// with signalling, transport and the UI. It also makes the Wayland/X11
    /// asymmetry inspectable on a host instead of inferred.
    #[command(name = "apps-probe")]
    AppsProbe,
    /// FR-85 — record this machine's screen to an HQ MP4 until stopped
    /// (Ctrl+C, `{"cmd":"stop"}` on stdin, or stdin closing). Prints JSON
    /// events (`started`, `progress`, `stopped`, `refused`) on stdout.
    ///
    /// Hidden while the recorder is P1 (no local surface yet): the daemon and
    /// roomler-desktop are its callers from P2 on.
    #[cfg(feature = "recording")]
    #[command(hide = true, name = "record")]
    Record {
        /// Destination folder. Default: the configured one, else Videos\Roomler
        /// (Windows, when local and writable), ~/Movies/Roomler (macOS), the
        /// XDG videos dir + Roomler (Linux).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Frames per second (1–60).
        #[arg(long, default_value_t = 30)]
        fps: u32,
        /// `auto` | `hardware` | `software`.
        #[arg(long, default_value = "auto")]
        encoder: String,
        /// Stop cleanly after this many minutes.
        #[arg(long, default_value_t = 240)]
        max_minutes: u32,
        /// (internal, P3) a remote recording's controller user id.
        #[arg(long, hide = true)]
        remote_user_id: Option<String>,
        /// (internal, P3) the controller's display name.
        #[arg(long, hide = true)]
        remote_user_name: Option<String>,
        /// Also record what the computer plays (Windows, Linux).
        #[arg(long)]
        system_audio: bool,
        /// Also record the microphone.
        #[arg(long)]
        microphone: bool,
        /// (internal, P1e) print the folder a recording would go to, and
        /// why, then exit.
        #[arg(long = "where", hide = true)]
        where_only: bool,
        /// (internal, P1e) print the identity this recorder runs as, then
        /// exit.
        #[arg(long, hide = true)]
        whoami: bool,
    },
    /// FR-85 P5 — the editor's engine, launched by roomler-desktop as the
    /// person: `probe` a recording, `export` one through its edit list.
    /// JSON events on stdout, like `record`.
    #[cfg(all(feature = "recording", feature = "openh264-encoder"))]
    #[command(hide = true, name = "media")]
    Media {
        #[command(subcommand)]
        action: MediaAction,
    },
    CaptureSmoke {
        /// How many frames to pull before reporting.
        #[arg(long, default_value_t = 10)]
        frames: u32,
        /// Write the last captured frame here as a binary PPM (P6).
        /// A wrong-format decode keeps perfect geometry and ruins every
        /// colour, so looking at the image is the only real check.
        #[arg(long)]
        dump: Option<String>,
        /// Target fps for the capture's own pacing gate.
        #[arg(long, default_value_t = 30)]
        fps: u32,
        /// Downscale policy: `never` (default here, so the number is the raw
        /// capture cost), `auto` (what production uses — halves sources above
        /// ~3.5 Mpx), or `always`.
        #[arg(long, default_value = "never")]
        downscale: String,
    },
    /// Smoke-test input injection on THIS host: open the injector cascade
    /// and drive a scripted sequence through it. Reports which backend
    /// answered.
    ///
    /// The counterpart to `capture-smoke`, and needed for the same reason:
    /// "does input work here" was otherwise only answerable through a full
    /// remote-control session. It matters most on Wayland, where XTest does
    /// not fail — it succeeds and does nothing.
    #[command(hide = true, name = "input-smoke")]
    InputSmoke {
        /// Move the pointer to this normalised position first, e.g. `0.5,0.5`.
        #[arg(long)]
        move_to: Option<String>,
        /// Click a button after moving: `left` | `right` | `middle`.
        #[arg(long)]
        click: Option<String>,
        /// Type this ASCII text. ⚠️ Mapped through a **US layout** table that
        /// exists only for this smoke test — the injector itself deliberately
        /// refuses to synthesise text, because evdev carries physical keys and
        /// guessing a layout types mojibake on every other one.
        #[arg(long)]
        text: Option<String>,
        /// Milliseconds between events.
        #[arg(long, default_value_t = 25)]
        delay_ms: u64,
    },
    /// M3 derisking spike: probe Windows.Graphics.Capture init from
    /// the requested desktop. Three modes — `default` (no swap, sanity
    /// baseline; should always pass in a user session), `input`
    /// (reproduces the M3 supervisor's poll-loop swap), `winlogon`
    /// (explicitly opens `winsta0\Winlogon` — requires SYSTEM context
    /// via `psexec -s -i 1 ...` from elevated PowerShell). Reports
    /// first frame size + frame-arrived count + structured errors on
    /// every init step. The 2026-05-02 critic review (item D) flagged
    /// that `psexec -s -i 0` lands on session 0's *visible* desktop,
    /// not Winlogon, so this binary explicitly attaches to the
    /// secure desktop before init. Windows-only, requires
    /// `--features wgc-capture` (or `full-hw`).
    SystemCaptureSmoke {
        /// Which desktop to bind to before the WGC probe.
        #[arg(long, default_value = "default")]
        desktop: String,
        /// How many frames to wait for before declaring success.
        #[arg(long, default_value_t = 3)]
        frames: u32,
        /// Wall-clock cap on the frame wait, in milliseconds.
        #[arg(long, default_value_t = 5000)]
        timeout_ms: u32,
    },
    /// M3 A1 derisking probes (Pre-flight #2/#3/#5 from
    /// `docs/remote-control.md` §19). Three
    /// modes:
    ///   - `winlogon-token`: confirm OpenProcessToken(winlogon.exe) +
    ///     CreateProcessAsUserW spawns SYSTEM-in-active-session child.
    ///     Run via `psexec -s -i 1 ...exe system-context-probe winlogon-token`.
    ///   - `winsta-attach`: prove SetProcessWindowStation(WinSta0) is
    ///     required before OpenDesktopW("Winlogon"|"Default") from a
    ///     SYSTEM service. Run via `psexec -s -i 0 ...`.
    ///   - `dxgi-cadence`: instrument scrap::Capturer over 30 s on
    ///     a static desktop; reports outcome distribution. Runs in
    ///     user context, no psexec needed.
    SystemContextProbe {
        /// Which probe to run: `winlogon-token` / `winsta-attach` /
        /// `dxgi-cadence`.
        mode: String,
    },
    /// Run the capability probe that populates `rc:agent.hello` and
    /// print the result. Useful for verifying what codecs the agent
    /// will actually advertise on this host (the HEVC + AV1 probes
    /// run real MfEncoder activations, so this exits with roughly
    /// the same logs an operator would see in the first session).
    Caps,
    /// Enumerate attached displays and print what the agent will
    /// report in `rc:agent.hello`. Cross-platform via `scrap`.
    Displays,
    /// (M3 A1) Print the peer-presence marker file's state. The
    /// marker is the IPC signal between the user-context worker
    /// (writes when a controller is connected) and the SCM-supervisor
    /// (reads to decide whether to swap to a SystemContext worker).
    /// Use this on the host to diagnose "why isn't the SystemContext
    /// worker spawning when I'm connected?": run with a controller
    /// active and check that `fresh = true` and `age <= 5s`.
    /// Compiled only when the `system-context` feature is on.
    #[cfg(feature = "system-context")]
    PeerPresenceStatus,
    /// Manage the auto-start-on-boot hook (Scheduled Task on Windows,
    /// systemd user unit on Linux, LaunchAgent on macOS). Subcommand
    /// is one of `install`, `uninstall`, `status`.
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Check GitHub Releases for a newer version and — if found —
    /// download + spawn the installer. The agent exits on successful
    /// spawn so the installer can overwrite the binary; your service
    /// hook re-launches it. Safe to run interactively. Pass
    /// `--check-only` to print the verdict without touching disk.
    SelfUpdate {
        /// Don't download or spawn anything; just report whether an
        /// update is available.
        #[arg(long)]
        check_only: bool,
    },
    /// (internal) Remove cross-flavour MSI install leftovers before
    /// the fresh install lands. Invoked by the MSI's WiX custom action
    /// just before `InstallFiles`. The `--target-flavour` arg says
    /// which flavour is being INSTALLED; the helper cleans the OPPOSITE
    /// flavour's stale Scheduled Task / SCM service / data dirs.
    /// Same-flavour invocations exit 0 (no-op).
    ///
    /// Hidden from `--help` because operators never invoke this
    /// directly; the WiX CA does.
    #[command(hide = true, name = "cleanup-legacy-install")]
    CleanupLegacyInstall {
        /// Which flavour is being installed: `perUser` or `perMachine`.
        /// The helper cleans the OTHER flavour's leftovers.
        #[arg(long, name = "target-flavour")]
        target_flavour: String,
        /// Print what WOULD be removed without touching anything.
        /// Used during MSI build smoke validation.
        #[arg(long)]
        dry_run: bool,
    },
    // RETIRED-NAME-ANCHOR: names the OLD MSI product this sweep exists to remove.
    // docs/fr/FR-21
    /// Uninstall older roomler-agent MSI versions left behind on this
    /// host. The release pipeline puts the rc number in the MSI 4th
    /// version field (`0.3.0.N`), which Windows Installer ignores for
    /// upgrade comparison — so `MajorUpgrade` never removes the prior
    /// version and they pile up. This removes every install of THIS
    /// flavour strictly OLDER than the running version; it never touches
    /// the current version, a newer one, or the other flavour.
    ///
    /// perMachine uninstall needs elevation — run from an admin shell.
    /// Start with `--dry-run` to see exactly what would be removed.
    #[command(name = "sweep-old-versions")]
    SweepOldVersions {
        /// Print what WOULD be uninstalled without removing anything.
        #[arg(long)]
        dry_run: bool,
        /// Override flavour autodetection (`perUser` | `perMachine`).
        /// Default: inferred from the running EXE's path — but a
        /// cargo-built dev binary always classifies as perUser, so pass
        /// this to sweep perMachine products from a non-installed build.
        #[arg(long)]
        flavour: Option<String>,
    },
    /// List, approve or deny pending operator-consent prompts (remote
    /// control, `exec`, SSH). Used when the device prompts rather than
    /// auto-granting. Prefers the running device service over its LocalAPI
    /// (works regardless of which profile the service runs under — incl.
    /// SYSTEM/SCM installs); falls back to a sentinel file under
    /// `<log_dir>/consent/` in THIS profile when no service is listening
    /// (console-run agent). 30 s from the agent's POV, after which the
    /// broker auto-denies.
    ///
    /// `--list` is FR-27: the id was previously obtainable only by grepping
    /// the daemon log, inside the same 30 s the operator had to answer in,
    /// which made the headless path close to unusable.
    Consent {
        /// Show every prompt currently awaiting a decision, and exit.
        #[arg(long, short = 'l', conflicts_with_all = ["approve", "deny"])]
        list: bool,
        /// Hex `session_id` (or exec request id) from `--list` or the
        /// agent's "operator consent required" log line — a 24-character
        /// MongoDB ObjectId hex string.
        #[arg(long, required_unless_present = "list")]
        session: Option<String>,
        /// Approve the session.
        #[arg(long, conflicts_with = "deny")]
        approve: bool,
        /// Deny the session.
        #[arg(long, conflicts_with = "approve")]
        deny: bool,
    },
    /// FR-27 — list, or end, remote-control sessions currently LIVE on this
    /// device. The headless twin of the desktop app's "Being viewed by …"
    /// banner, and the only such view on a host with no GUI at all.
    ///
    /// `--disconnect <id>` takes exactly the same teardown path as the
    /// on-screen Disconnect: the daemon closes the peer and tells the server.
    Rc {
        /// End this session (hex id from the plain listing).
        #[arg(long, value_name = "SESSION")]
        disconnect: Option<String>,
    },
    /// (internal) Entry point invoked by the Windows Service Control
    /// Manager when `Roomler` starts. Hands the process
    /// over to `windows-service`'s dispatcher; the agent main loop
    /// runs inside the SCM thread until Stop is signalled. Hidden
    /// from `--help` because operators never invoke this directly —
    /// `service install --as-service` registers it as the service's
    /// `ImagePath` argv.
    #[command(hide = true, name = "service-run")]
    ServiceRun,
    /// Track A stage 1 — the session-independent network daemon,
    /// SCAFFOLD stage: hosts nothing, heartbeats, exits on terminate.
    /// Spawned by the SCM supervisor as a SECOND child when
    /// `overlay_netd` is on; never invoked by operators directly.
    #[command(hide = true)]
    Netd,
    /// Enable SystemContext mode on a perMachine install. Writes
    /// `ROOMLERD_ENABLE_SYSTEM_SWAP=1` into the `Roomler`
    /// SCM `Environment` REG_MULTI_SZ block and restarts the service so
    /// the supervisor picks up the new env on its next worker spawn.
    /// Requires admin (HKLM write + SCM Stop/Start). Idempotent: re-runs
    /// are no-ops if the env var is already set and the service is
    /// running. Used as the operator-facing rescue path AND shelled by
    /// the rc.37 WiX EXE-deferred custom action that runs inside the
    /// MSI's existing UAC elevation.
    EnableSystemContext {
        /// Skip the post-write service restart. Useful when the operator
        /// is about to do something else service-affecting and wants to
        /// batch the restart. Default: restart after writing.
        #[arg(long)]
        no_restart: bool,
    },
    /// Disable SystemContext mode on a perMachine install. Removes
    /// `ROOMLERD_ENABLE_SYSTEM_SWAP` from the `Roomler`
    /// SCM `Environment` block and restarts the service. The supervisor
    /// reverts to the user-context worker on next spawn. Requires admin.
    DisableSystemContext {
        /// Skip the post-write service restart. Mirrors
        /// `enable-system-context --no-restart`.
        #[arg(long)]
        no_restart: bool,
    },
    /// #1727 — keep the SystemContext mode this machine was last switched
    /// to: `enable-system-context` if the last recorded switch was an
    /// enable, `disable-system-context` otherwise. What the perMachine MSI
    /// runs when its command line has no `ENABLE_SYSTEM_CONTEXT` — a
    /// person running `msiexec /i` by hand. Every install recreates the
    /// service and loses the switch with it; the record
    /// (`%PROGRAMDATA%\roomler\last-system-context-attempt.json`) is what
    /// survives. Requires admin.
    #[command(hide = true)]
    KeepSystemContext {
        /// Skip the post-write service restart. Mirrors
        /// `enable-system-context --no-restart`.
        #[arg(long)]
        no_restart: bool,
    },
    /// Write a single name=value entry into the `Roomler`
    /// SCM `Environment` REG_MULTI_SZ block. Omit `--value` to REMOVE
    /// the entry. Operators may use this directly, or the higher-level
    /// `enable-system-context` / `disable-system-context` wrappers.
    /// The rc.30 Done-page snippet in the installer wizard references
    /// this subcommand by name, so the surface is load-bearing for
    /// any rc.28+ wizard EXE in the field. Requires admin (HKLM write).
    ///
    /// Typical use:
    ///   meshharbord set-service-env-var --name ROOMLERD_VP9_FPS --value 60
    ///   meshharbord restart-service
    #[command(name = "set-service-env-var")]
    SetServiceEnvVar {
        /// Env var name (e.g. `ROOMLERD_VP9_FPS`,
        /// `ROOMLERD_ENABLE_SYSTEM_SWAP`).
        #[arg(long)]
        name: String,
        /// Env var value. Empty string is allowed (stored as
        /// `name=`). To REMOVE an entry, omit `--value`.
        #[arg(long)]
        value: Option<String>,
    },
    /// Restart the `Roomler` via the SCM. Used after
    /// `set-service-env-var` (or the higher-level
    /// `enable-system-context` / `disable-system-context`) to apply
    /// the new env block. Windows-only; requires admin (SCM
    /// Stop+Start). Worst-case wall-time is `2 × --timeout-secs`.
    #[command(name = "restart-service")]
    RestartService {
        /// Per-transition timeout in seconds (Stop → Stopped, then
        /// Start → Running). Worst-case wall time is ~2 × this value.
        /// Default 120 s is comfortable for Windows Defender
        /// real-time-scan-during-fresh-EXE-launch — drop to 60 s for
        /// faster CI iteration when Defender isn't in the loop.
        #[arg(long, default_value_t = 120)]
        timeout_secs: u64,
    },
    /// (internal) Watch a running installer process and record its
    /// exit code + the new binary's version to `last-install.json`.
    /// Spawned automatically by the updater immediately before the
    /// agent exits to make room for the installer; not intended for
    /// interactive use. Hidden from `--help` to avoid confusion.
    #[command(hide = true)]
    PostInstallWatch {
        /// PID of the installer (msiexec / dpkg / installer(8))
        /// the parent agent just spawned.
        #[arg(long)]
        installer_pid: u32,
        /// Path of the installer artifact (only logged for the
        /// outcome JSON; not opened).
        #[arg(long)]
        installer_path: PathBuf,
        /// Tag of the release being installed (e.g. `agent-v0.1.51`).
        /// Used to verify the new binary's `--version` output after
        /// install completes.
        #[arg(long)]
        expected_version: String,
        /// Path of the daemon EXE inside the real install dir. Passed
        /// when the watcher was spawned from a staged copy (Windows),
        /// whose own %TEMP% path would misclassify the install
        /// flavour and probe the wrong binary. Absent = the watcher
        /// runs from the install dir itself.
        #[arg(long)]
        origin_exe: Option<PathBuf>,
        /// The install already finished before this watcher started, so
        /// there is nothing to wait for. Set by the Linux arms, whose
        /// installs complete synchronously — the pid handed over is the
        /// daemon's own or a corpse, and waiting on it means waiting for
        /// the very event that kills this process. FR-67 (#1267).
        #[arg(long)]
        installer_already_exited: bool,
    },
}

/// FR-94 — `roomlerd anchor …`.
#[derive(Debug, Subcommand)]
enum AnchorCmd {
    /// Anchor the device: mint the SYSTEM service's credential and write it
    /// where only Administrators can.
    Create {
        /// The server's origin (`https://…`). Asked for here, never read from
        /// this machine's config: on an attended install the signed-in user
        /// can edit that, and the service must not take its server from them.
        #[arg(long)]
        server: String,
        /// A fresh enrollment token from the org's admin (single use).
        #[arg(long)]
        token: String,
        /// The device's id, from its page in the dashboard. Named outright:
        /// on an attended install this machine's enrollment belongs to the
        /// user who made it, and another account would mint another device.
        #[arg(long)]
        device: String,
        /// Anchor although this host's name differs from the device's (a
        /// host renamed since it enrolled).
        #[arg(long)]
        force: bool,
        /// Anchor without turning remote execution on yet
        /// (`roomlerd anchor exec on` later).
        #[arg(long)]
        no_exec: bool,
        /// FR-105 — roomler SSH through the SYSTEM service: `off`,
        /// `console_user` or `system`. Unset keeps what this device's
        /// previous anchor said, and is off for a first anchor.
        #[arg(long, value_parser = ["off", "console_user", "system"])]
        ssh: Option<String>,
    },
    /// Show this machine's anchor (never its credential).
    Status,
    /// Turn remote execution through the SYSTEM service on or off.
    Exec {
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
    /// FR-105 — how far roomler SSH through the SYSTEM service may go:
    /// `off` (the default), `console_user` (sessions as the signed-in user
    /// only) or `system` (SYSTEM as well).
    Ssh {
        #[arg(value_parser = ["off", "console_user", "system"])]
        ceiling: String,
    },
    /// Remove the anchor from this machine.
    Remove,
}

#[derive(Debug, Subcommand)]
enum OrgAction {
    /// List every enrollment (primary + secondaries).
    Ls,
    /// Remove a secondary enrollment from this machine's config. The
    /// device row in THAT org remains until one of its admins removes it
    /// (Devices → remove); this only stops the daemon from serving it.
    /// `primary` cannot be removed — `set-primary` another org first.
    Rm {
        /// The org's label (`org ls`).
        label: String,
    },
    /// Re-enable a disabled secondary enrollment.
    Enable { label: String },
    /// Disable a secondary enrollment without deleting it (no supervised
    /// WS loop for it on the next daemon start).
    Disable { label: String },
    /// Swap a secondary enrollment into the PRIMARY slot (and the current
    /// primary into `[[orgs]]`, under `--demoted-label` or else the given
    /// secondary's old label). The primary drives machine-wide effects:
    /// self-update source, attention sentinels, and declared tunnel routes.
    /// Each enrollment keeps its place on the mesh where it maps exactly
    /// (#2540); the output says what it could not keep.
    SetPrimary {
        label: String,
        /// The label the current primary takes in `[[orgs]]`. Default: the
        /// promoted org's old label.
        #[arg(long)]
        demoted_label: Option<String>,
    },
    /// FR-49 — put a secondary enrollment on (or off) that org's overlay mesh.
    ///
    /// Before this the only way was to hand-edit `config.toml` — the file that
    /// also holds the agent token and the SSH host private key, is written
    /// atomically with a `.prev` sibling, and on Windows lives under a
    /// machine-global ACL-restricted directory. Takes effect on the next daemon
    /// start (the overlay engine is built once, at startup).
    Overlay {
        /// The org's label (`org ls`). `primary` is refused — the primary's
        /// participation is `overlay_enabled`, set by `enroll --overlay`.
        label: String,
        /// `off` | `netstack` | `tun`.
        ///
        /// `netstack` is the userspace stack: no TUN, no OS routes, no
        /// privilege. `tun` shares the primary's adapter and needs
        /// `overlay_multi_org` plus the same control plane.
        mode: String,
    },
}

/// FR-85 P5 — `roomlerd media …`.
#[cfg(all(feature = "recording", feature = "openh264-encoder"))]
#[derive(Debug, Subcommand)]
enum MediaAction {
    /// Length, size, and whether this build can edit the recording.
    Probe { file: PathBuf },
    /// Export a recording through its edit list, beside it, as
    /// `<name> (edited).mp4`. `{"cmd":"cancel"}` on stdin stops it.
    Export {
        /// The edit list, `<name>.edit.json`; it names its recording, in its
        /// own folder.
        #[arg(long)]
        edl: PathBuf,
        /// `auto` | `hardware` | `software`.
        #[arg(long, default_value = "auto")]
        encoder: String,
    },
}

#[derive(Debug, Subcommand)]
enum ServiceAction {
    /// Register the agent for auto-start on the next login.
    Install {
        /// Register the ROOT daemon with the OS's own service manager instead
        /// of the per-user auto-start: on Windows the `Roomler` SCM service
        /// (LocalSystem, AutoStart), on Linux the system unit
        /// `meshharbord.service`, on macOS the LaunchDaemon `com.roomler.daemon`
        /// (FR-97 P6c). For fleet / unattended hosts, or ones that must be
        /// reachable before anyone logs in. Requires elevation. On Linux and
        /// macOS the root daemon is its own enrollment, in
        /// /etc/meshharbor/config.toml, and it is refused until that exists.
        #[arg(long, visible_alias = "system")]
        as_service: bool,
    },
    /// Remove the auto-start hook. Idempotent.
    Uninstall {
        /// Mirror of `install --as-service`: stops the system service (a clean
        /// stop) and deregisters it, rather than the per-user hook. The config
        /// stays. Idempotent. Requires elevation.
        #[arg(long, visible_alias = "system")]
        as_service: bool,
    },
    /// Print the current auto-start status.
    Status {
        /// Report the system service's state instead of the per-user hook's:
        /// `Roomler: Running | Stopped | NotInstalled` on Windows, the unit's
        /// or the job's on Linux and macOS.
        #[arg(long, visible_alias = "system")]
        as_service: bool,
    },
    /// Start the registered daemon NOW, through its service manager:
    /// `schtasks /Run` the Scheduled Task, `systemctl --user start` the unit,
    /// `launchctl kickstart` the LaunchAgent. The daemon is spawned by the
    /// OS, never as a child of this command. Harmless when it is already
    /// running. This is the caller half of a restart under the Scheduled
    /// Task (FR-84 D3, `roomler restart`, the companion's "Apply now").
    Start {
        /// Start the system service instead: the `Roomler` SCM service (and
        /// wait for RUNNING), `meshharbord.service`, or `com.roomler.daemon`.
        /// Requires elevation on a stock install.
        #[arg(long, visible_alias = "system")]
        as_service: bool,
    },
    /// Stop the running daemon NOW, cleanly, so a clean stop's work runs and
    /// an ephemeral device removes itself. On Windows the per-user daemon of
    /// this config is asked through its own stop event, and its Scheduled Task
    /// is ended (`schtasks /End`) only if it does not leave in time or holds no
    /// event; on Linux, `systemctl --user stop` the unit; on macOS, a SIGTERM
    /// through launchd, after which the LaunchAgent stays down until the next
    /// login or `service start` (its plist restarts only a failed exit,
    /// measured in FR-97 P6c; P4d had refused here).
    Stop {
        /// Stop the system service instead. Windows waits for STOPPED, and
        /// its host asks the worker to leave (#1683). Linux stops
        /// `meshharbord.service`. macOS sends `com.roomler.daemon` a SIGTERM;
        /// that clean stop stays down until the next boot or `service start
        /// --as-service`. Requires elevation on a stock install.
        #[arg(long, visible_alias = "system")]
        as_service: bool,
    },
}

/// rc.52: pure config-path precedence ladder. `exists` is injected so
/// the resolution is unit-testable without touching the filesystem.
///
/// Precedence:
///   1. explicit `--config <path>` — operator override, used verbatim
///      (no existence check; the operator named it deliberately).
///   2. machine-global `%PROGRAMDATA%` config — **SystemContext
///      workers only**, when the file exists. This is the canonical
///      pre-logon-readable SC config source (a LocalSystem worker
///      cannot reach a user-profile path before anyone logs in).
///   3. the platform default (`%APPDATA%` perUser) when it exists.
///   4. the active-user fallback — **SystemContext workers only**,
///      when it exists (post-logon: a perUser config the SC worker
///      reaches via `WTSQueryUserToken`).
///   5. nothing exists → the platform default, so `config::load`
///      fails with an honest "not found" naming that path.
///
/// For a non-SystemContext worker the ladder collapses to
/// `explicit > default` — unchanged pre-rc.52 behaviour.
fn pick_config_path(
    explicit: Option<PathBuf>,
    is_system_context: bool,
    machine_global: Option<&std::path::Path>,
    default: &std::path::Path,
    active_user: Option<&std::path::Path>,
    exists: impl Fn(&std::path::Path) -> bool,
) -> PathBuf {
    if let Some(p) = explicit {
        return p;
    }
    if is_system_context
        && let Some(mg) = machine_global
        && exists(mg)
    {
        return mg.to_path_buf();
    }
    if exists(default) {
        return default.to_path_buf();
    }
    if is_system_context
        && let Some(au) = active_user
        && exists(au)
    {
        return au.to_path_buf();
    }
    default.to_path_buf()
}

/// rc.52: resolve the config path by wiring [`pick_config_path`] to
/// the real environment — the worker-role probe, the candidate paths,
/// and `Path::exists`. Logs the chosen path so a "wrong config" or
/// "config not found" investigation lands on a clear line.
fn resolve_config_path(explicit: Option<PathBuf>) -> Result<PathBuf> {
    let default = config::default_config_path().context("resolving default config path")?;

    #[cfg(all(feature = "system-context", target_os = "windows"))]
    {
        use roomlerd::system_context::{user_profile, worker_role};
        let is_sc = matches!(
            worker_role::probe_self(),
            Ok(worker_role::WorkerRole::SystemContext)
        );
        let machine_global = config::machine_global_config_path();
        let active_user = user_profile::active_user_config_path();
        let chosen = pick_config_path(
            explicit,
            is_sc,
            Some(machine_global.as_path()),
            &default,
            active_user.as_deref(),
            |p| p.exists(),
        );
        tracing::info!(
            config_path = %chosen.display(),
            is_system_context = is_sc,
            machine_global = %machine_global.display(),
            "config: resolved load path"
        );
        Ok(chosen)
    }
    #[cfg(not(all(feature = "system-context", target_os = "windows")))]
    {
        // No SystemContext + no machine-global config concept on this
        // build — the ladder collapses to `explicit > default`.
        Ok(pick_config_path(
            explicit,
            false,
            None,
            &default,
            None,
            |p| p.exists(),
        ))
    }
}

/// rc.52 Phase 4: should a healthy-run SystemContext worker copy its
/// config to the machine-global `%PROGRAMDATA%` location? Pure +
/// cross-platform-testable. True only when all three hold: this is a
/// SystemContext worker; the config was loaded from somewhere OTHER
/// than the machine-global path (a perUser `%APPDATA%` / active-user
/// fallback); and the machine-global path does not already hold a
/// config. That is exactly an rc.50-or-earlier SystemContext install
/// pre-dating the machine-global path — promoting it makes the next
/// boot pre-logon-controllable with zero operator action.
///
/// Only the `system-context` + Windows build calls this in non-test
/// code (via [`self_heal_machine_global_config`]); on other builds it
/// is exercised solely by the unit tests, so suppress the dead-code
/// lint there rather than cfg-gating the pure logic out of reach.
#[cfg_attr(
    not(all(feature = "system-context", target_os = "windows")),
    allow(dead_code)
)]
fn should_self_heal_config(
    is_system_context: bool,
    loaded_path: &std::path::Path,
    machine_global: &std::path::Path,
    machine_global_exists: bool,
) -> bool {
    is_system_context && loaded_path != machine_global && !machine_global_exists
}

/// rc.52 Phase 4: promote a perUser-loaded SystemContext config to the
/// machine-global `%PROGRAMDATA%` path after a healthy run. No-op on
/// non-Windows, non-SystemContext, or when the machine-global config
/// already exists. The worker runs as LocalSystem here so it has the
/// rights to write `%PROGRAMDATA%`.
#[cfg(all(feature = "system-context", target_os = "windows"))]
fn self_heal_machine_global_config(loaded_path: &std::path::Path, cfg: &config::AgentConfig) {
    use roomlerd::system_context::worker_role;
    let is_sc = matches!(
        worker_role::probe_self(),
        Ok(worker_role::WorkerRole::SystemContext)
    );
    let mg = config::machine_global_config_path();
    if !should_self_heal_config(is_sc, loaded_path, &mg, mg.exists()) {
        return;
    }
    match config::save(&mg, cfg) {
        Ok(()) => tracing::info!(
            from = %loaded_path.display(),
            to = %mg.display(),
            "config: self-healed perUser config to machine-global path \
             (machine_id preserved; next boot is pre-logon-controllable)"
        ),
        Err(e) => tracing::warn!(
            error = %e,
            "config: machine-global self-heal copy failed (will retry next healthy run)"
        ),
    }
}

#[cfg(not(all(feature = "system-context", target_os = "windows")))]
fn self_heal_machine_global_config(_loaded_path: &std::path::Path, _cfg: &config::AgentConfig) {}

/// `meshharbord cli <args...>` → the argv to hand to the embedded `roomler`
/// CLI, or `None` for every other invocation.
///
/// P3e lever D: daemon hosts install a ~150 KB `roomler.exe` shim that
/// re-execs us this way, instead of the MSI carrying a second full copy of
/// the tunnel CLI (rc.361: 22.1 MiB, ~92 % of it crates we already link).
///
/// Read straight from raw argv, on purpose. Routing it through the daemon's
/// own clap enum would mean a CLI call first ran every daemon-startup side
/// effect below — DPI awareness, the 1 ms multimedia timer, the legacy-tree
/// migration, `logging::init` — none of which the standalone `roomler`
/// binary does. Element 0 is re-labelled so usage text still reads
/// `roomler ...` rather than `roomlerd ...`.
fn embedded_cli_args() -> Option<Vec<std::ffi::OsString>> {
    let mut it = std::env::args_os();
    let _exe = it.next()?;
    if it.next()? != "cli" {
        return None;
    }
    let mut argv = vec![std::ffi::OsString::from("roomler")];
    argv.extend(it);
    Some(argv)
}

/// FR-27 — on macOS with the native consent panel, tokio may NOT own the main
/// thread.
///
/// AppKit delivers every event — including the click on an Approve button —
/// on the main run loop, and `#[tokio::main]` parks the main thread in
/// `block_on` for the daemon's entire life. Nothing drains the main queue, so
/// a window can be created and will never respond. That is the whole reason
/// macOS has had no native overlay: not that nobody wrote one, but that this
/// process shape makes one inert.
///
/// So on that one configuration the roles swap: the runtime is built
/// explicitly and the daemon future runs on a worker, while the main thread
/// hands itself to AppKit. Everywhere else `main` is exactly what it was.
///
/// ⚠️ `NSApp.run()` never returns. The daemon's own exit paths
/// (`std::process::exit`, the watchdog's `STALL_EXIT_CODE`) still work — they
/// terminate the process, not this function — but anything that relied on
/// `main` RETURNING to end the process would not. Nothing does: the daemon's
/// clean shutdown is a `process::exit` after its drain.
#[cfg(all(target_os = "macos", feature = "viewer-indicator-macos"))]
fn main() -> Result<()> {
    // The embedded CLI must still short-circuit before any of this — and it
    // must NOT hand the main thread to AppKit, since a CLI call has to be able
    // to return an exit code.
    if let Some(argv) = embedded_cli_args() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        return rt.block_on(roomler_cli::cli::run_from(
            argv,
            roomler_cli::cli::Origin::EmbeddedInDaemon,
        ));
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    std::thread::Builder::new()
        .name("roomlerd-main".into())
        .spawn(move || {
            let res = rt.block_on(daemon_main());
            // FR-97 P0e — drop the runtime (cancelling every task, as the
            // non-AppKit `main` does) before purging, so nothing re-pins.
            drop(rt);
            purge_after_daemon();
            if let Err(e) = res {
                tracing::error!(error = %format!("{e:#}"), "daemon exited with an error");
                std::process::exit(1);
            }
            // FR-84 D3 — a requested restart leaves with its own code (launchd
            // relaunches only a non-zero exit). Diverges when it applies.
            exit_for_requested_restart();
            // The daemon returning normally is a shutdown. The main thread is
            // inside AppKit and will not notice, so say so explicitly.
            std::process::exit(0);
        })
        .context("spawning the daemon thread")?;

    // Hands the main thread to AppKit, forever. `Accessory` keeps us out of
    // the Dock and the app switcher — the bundle already sets `LSUIElement`,
    // and this makes it true for a non-bundled dev run too.
    //
    // ⚠️ `roomlerd::`, NOT `crate::`. This file is a SEPARATE crate root from
    // the lib, so a `cfg`-gated path here that reads like an intra-crate one
    // compiles nowhere — and, being macOS-only, nowhere is exactly where it
    // would have been noticed. Same trap as rc.454's `tcc` block; the `--bins`
    // in the macOS CI job exists for it and caught this on the first push.
    roomlerd::indicator::mac::run_main_loop();
}

/// Exactly what `#[tokio::main]` expanded to — a multi-thread runtime with
/// every driver enabled, `block_on` the daemon, drop the runtime — spelled out
/// for one reason: FR-84 D3's requested restart must pick its exit code only
/// AFTER the runtime is gone, so its teardown is the one every other clean
/// exit (an auto-update, a SIGTERM) already gets. Nothing else changes.
#[cfg(not(all(target_os = "macos", feature = "viewer-indicator-macos")))]
fn main() -> Result<()> {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pin_mmap_threshold();
    // The runtime is a temporary: it is dropped at the end of this statement,
    // cancelling every task still running and waiting on blocking work.
    let res = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed building the Runtime")
        .block_on(daemon_main());
    // FR-97 P0e — the runtime is gone (dropped with the statement above).
    purge_after_daemon();
    if res.is_ok() {
        // Diverges when a restart was requested; otherwise a no-op.
        exit_for_requested_restart();
    }
    res
}

/// Pin glibc's mmap threshold. The overlay netstack gives each TCP socket
/// multi-MiB buffers that cost nothing until data flows, which holds only
/// while glibc maps them fresh. Its default threshold rises to the size of
/// any mapped block that is freed, so after the first closed socket every
/// later buffer came from the heap, was zeroed in full and stayed resident
/// after free (field, 2026-10-26: one connection a second took a node to its
/// 512 MB cap in about 20 minutes; with the threshold pinned it held 12 MB).
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn pin_mmap_threshold() {
    // SAFETY: the first call in `main`, before any other thread exists.
    unsafe {
        libc::mallopt(libc::M_MMAP_THRESHOLD, 1 << 20);
    }
}

async fn daemon_main() -> Result<()> {
    // P3e lever D — embedded `roomler` CLI. MUST stay the first statement in
    // main(): everything below is daemon-startup setup that a CLI invocation
    // has no business performing. See `embedded_cli_args`.
    //
    // ⚠️ The macOS `main` above ALSO checks this, before it hands the main
    // thread to AppKit. Both are needed: this one covers every other platform,
    // that one has to run before a run loop it can never return from.
    if let Some(argv) = embedded_cli_args() {
        return roomler_cli::cli::run_from(argv, roomler_cli::cli::Origin::EmbeddedInDaemon).await;
    }

    // FR-96 P3 — `meshharbord update-helper --capabilities`: what this binary's
    // update half can do, one word per line, for `install.sh` (any user). None
    // of the setup below is its, and it is read off argv, not through clap.
    // ⚠️ As a `--capabilities` field on `Command::UpdateHelper` it cost ~9 KB
    // more main-thread stack at start in an unoptimized build (measured on
    // Linux: ~1000 KB without it, ~1009 KB with it), and Windows gives the
    // main thread 1 MB: the debug binary overflowed there before printing a
    // line (the FR-85 recorder lane, #2225).
    if updater::answer_capabilities_query() {
        return Ok(());
    }

    // FR-90 P1a — `meshharbord hive-mcp <socket>`: a Hive session's toolbelt
    // relay, started by Claude Code as the session's account. Like the
    // embedded CLI it runs none of the setup below, and it EXITS rather than
    // returns: the runtime's shutdown would wait on a stdin read the harness
    // may hold open.
    #[cfg(hive_host)]
    if let Some(socket) = roomlerd::hive::relay_args() {
        let code = match roomlerd::hive::relay(&socket).await {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("meshharbord hive-mcp: {e:#}");
                1
            }
        };
        std::process::exit(code);
    }

    // FR-90 P2e-7 — `meshharbord hive-resume-note <file>`: a Hive session's
    // `SessionStart` hook, run by Claude Code as the session's account. It
    // prints the resume note the daemon left for a session moved here, if
    // there is one. None of the setup below is its.
    #[cfg(hive_host)]
    if let Some(file) = roomlerd::hive::note_args() {
        std::process::exit(roomlerd::hive::note_main(&file));
    }

    // FR-90 P2b-3a — `meshharbord hive-checkpoint <request>`: a session's
    // checkpoint, which the daemon runs AS THE SESSION'S ACCOUNT at a turn's
    // end; it writes the checkpoint to stdout. None of the setup below is its.
    #[cfg(hive_host)]
    if let Some(request) = roomlerd::hive::checkpoint_args() {
        std::process::exit(roomlerd::hive::checkpoint_main(&request));
    }

    // FR-90 P2b-4a — `meshharbord hive-materialize`: its reverse, a checkpoint
    // written back into a session's config directory AS THE ACCOUNT, from the
    // frames the daemon streams on its stdin.
    #[cfg(hive_host)]
    if roomlerd::hive::materialize_args() {
        std::process::exit(roomlerd::hive::materialize_main());
    }

    // FR-90 P2f-2a — `meshharbord hive-pack`: git's have and want for a
    // session's workspace AS THE ACCOUNT — which commits its folder's
    // repository holds, or a pack thin against them. P2f-2b — the request
    // on stdin, the answer to stdout.
    #[cfg(hive_host)]
    if roomlerd::hive::pack_args() {
        std::process::exit(roomlerd::hive::pack_main());
    }

    // FR-90 P2f-4a — `meshharbord hive-import`: an ended terminal session's own
    // history, put in place as the managed session it is made AS THE
    // TERMINAL'S ACCOUNT. The request on stdin, one line to stdout.
    #[cfg(hive_host)]
    if roomlerd::hive::import_args() {
        std::process::exit(roomlerd::hive::import_main());
    }

    // FR-90 P2g-1 — `meshharbord hive-purge`: what a purged session's account
    // holds of it (its state directory, its checkpoints' refs and index),
    // deleted AS THE ACCOUNT. The request on stdin, one line to stdout.
    #[cfg(hive_host)]
    if roomlerd::hive::purge_args() {
        std::process::exit(roomlerd::hive::purge_main());
    }

    // FR-90 P1i — `meshharbord hive-prep …`: a Windows session's preparation,
    // which the daemon runs AS THE CONSOLE USER before the harness starts, as
    // the Unix wrapper runs as the account. None of the setup below is its.
    #[cfg(all(windows, feature = "hive"))]
    if let Some(prep) = roomlerd::hive_win::PrepArgs::from_env() {
        std::process::exit(match prep.and_then(|a| roomlerd::hive_win::prep(&a)) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("meshharbord hive-prep: {e}");
                1
            }
        });
    }

    // #1705 — the desktop companion's service probes (every 10 s) answer one
    // question about the service manager; none of the daemon setup below is
    // theirs, and its startup lines used to flood the per-user log.
    if let Some(as_service) = service::companion_probe(&std::env::args().collect::<Vec<_>>()) {
        return if as_service {
            service_status_as_service()
        } else {
            let s = service::status().context("querying auto-start status")?;
            println!("Auto-start: {s}");
            Ok(())
        };
    }

    // Set per-monitor-V2 DPI awareness as the very first thing on
    // Windows. Capture frames (WGC / DXGI / scrap) are always physical
    // pixels regardless of awareness, but enigo's mouse-position APIs
    // work in *logical* pixels under the legacy "system DPI aware"
    // default — a 1920×1200 panel at 125% scale reports as 1536×960
    // and `SetCursorPos` interprets coordinates against that, so a
    // browser-side normalised click maps left+above of where the user
    // clicked. Field bug the field-test host 2026-05-01. Idempotent — a noop once
    // some other subsystem has already set DPI for the process.
    // rc.41 — stash the DPI outcome (set + actual) and log it AFTER
    // logging::init() so the diagnostic line lands in the persistent
    // log file. The `actual` field is the authoritative source of
    // truth for "what mode is in force"; `set` distinguishes
    // "we set it now" from "another caller had already pinned it".
    #[cfg(target_os = "windows")]
    let dpi_outcome = dpi::set_per_monitor_aware();

    // rc.92 — request 1 ms multimedia timer resolution for the whole
    // process. Windows defaults to a 15.6 ms timer; that quantized the
    // FFmpeg DC pump's per-frame capture round-trip + `tokio::time::sleep`
    // floor up to 15.6 ms ticks → ~12 fps under motion on the
    // SystemContext path (field WINHOST-E). Held for the process lifetime;
    // the guard's Drop restores the previous resolution. Logged below
    // (after logging::init) alongside the DPI diagnostic. See win_timer.rs.
    #[cfg(target_os = "windows")]
    let _timer_guard = win_timer::TimerResolutionGuard::request_1ms();

    // RETIRED-NAME-ANCHOR: a migration note names BOTH halves by necessity.
    // docs/fr/FR-21
    // S1b — one-shot legacy-tree migration (`roomler-agent` → `roomler`).
    // MUST run before `logging::init` (log files open inside the tree) and
    // before ANY appdirs consumer (segment decisions are OnceLock-cached per
    // process). Skipped while the desktop companion is running — it may hold
    // open handles in the tree; the read-both resolution keeps everything
    // working until the next start retries.
    #[cfg(target_os = "windows")]
    let companion_running = roomlerd::companion::desktop_running();
    #[cfg(not(target_os = "windows"))]
    let companion_running = false;
    roomlerd::appdirs::migrate_legacy_trees(companion_running);

    // Same one-shot, same reason, different axis: a Linux SYSTEM install's
    // config belongs at `/etc/meshharbor/config.toml` (what the packaged unit
    // passes as `--config`), not in root's profile. Before `default_config_path`
    // or any config read, and before logging::init, so it collects notes the
    // same way.
    #[cfg(target_os = "linux")]
    roomlerd::appdirs::migrate_system_config();

    let cli = Cli::parse();

    // S1b — the SCM service host and the SystemContext worker log into the
    // machine-global `service-logs` dir (the one the desktop app has always
    // advertised — it was EMPTY until now because ProjectDirs resolves SYSTEM
    // processes into the invisible systemprofile). Must precede logging::init.
    #[cfg(target_os = "windows")]
    {
        if matches!(cli.command, Some(Command::ServiceRun)) {
            logging::set_service_logging(logging::ServiceLogRole::Host);
        }
        // Track A — netd is a LocalSystem session-0 child like the host;
        // its own basename keeps three concurrent SYSTEM logs apart.
        if matches!(cli.command, Some(Command::Netd)) {
            logging::set_service_logging(logging::ServiceLogRole::Netd);
        }
        #[cfg(feature = "system-context")]
        if matches!(cli.command, Some(Command::Run { .. }) | None) {
            use roomlerd::system_context::worker_role;
            if matches!(
                worker_role::probe_self(),
                Ok(worker_role::WorkerRole::SystemContext)
            ) {
                logging::set_service_logging(logging::ServiceLogRole::Worker);
            }
        }
    }

    logging::init();

    // FR-46 P2b — the retired env prefix is no longer READ, so a host that
    // still sets one must be TOLD rather than quietly ignored. Straight after
    // logging::init, because the whole point is that it reaches the log.
    tunnel_core::env::warn_on_retired_env();
    for note in roomlerd::appdirs::migration_notes() {
        tracing::info!(%note, "appdirs legacy-tree migration");
    }
    // WARN, not INFO: this one moves the file that holds this host's identity,
    // and "where is my config now?" is the first question after an upgrade.
    #[cfg(target_os = "linux")]
    for note in roomlerd::appdirs::system_config_notes() {
        tracing::warn!(%note, "system-config migration");
    }
    if let Some(dir) = logging::log_dir() {
        tracing::debug!(log_dir = %dir.display(), "persistent file logging active");
    }
    #[cfg(target_os = "windows")]
    {
        tracing::info!(
            requested = "per-monitor-v2",
            set_succeeded = dpi_outcome.set,
            actual = dpi_outcome.actual.as_str(),
            "DPI awareness configured at process start (rc.41 diagnostic — surfaces residual the field-test host mouse-misposition cause)"
        );
        // rc.92 — surface the timer-resolution request so the field log
        // confirms 1 ms is in force. If `active=false` the OS refused the
        // request (power throttling of a background session-0 process) and
        // the FFmpeg DC pump's `avg_capture_ms` will stay quantized — the
        // signal to add a ProcessPowerThrottling timer-resolution opt-out.
        tracing::info!(
            requested_ms = _timer_guard.period_ms(),
            active = _timer_guard.active(),
            device_min_ms = _timer_guard.device_min_ms(),
            device_max_ms = _timer_guard.device_max_ms(),
            "multimedia timer resolution requested (rc.92 — 1ms so the FFmpeg DC pump isn't paced by the 15.6ms Windows default)"
        );
        // rc.48 — monitor-layout diagnostic. DPI is correctly set per
        // the rc.41/44 readback, yet the field-test host field reports still show
        // mouse-offset (per the rc.43-ui commit 79d6dee). Hypothesis:
        // the virtual-screen origin is non-zero (multi-monitor layout
        // where primary was repositioned) and our `to_pixels` doesn't
        // apply the origin offset. This logs the actual layout so we
        // can confirm or reject before writing a fix.
        win32_monitors::log_monitor_diagnostic();

        // rc.54 — surface the ROOMLERD_VIRTUAL_SCREEN gate at
        // startup so the operator sees which `to_pixels` path is live.
        // The env var is also captured at first call inside the input
        // worker via LazyLock; this line is the canonical "is the
        // virtual-screen-aware path live?" data point.
        let vscreen =
            roomlerd::input::parse_virtual_screen_flag(node_env("VIRTUAL_SCREEN").as_deref());
        tracing::info!(
            virtual_screen_enabled = vscreen,
            "input mapping — rc.54 ROOMLERD_VIRTUAL_SCREEN gate (false = legacy enigo.main_display path; true = win32_monitors::primary virtual-screen offset)"
        );
    }

    let config_path = resolve_config_path(cli.config.clone())?;
    updater::set_update_config_path(config_path.clone())?;

    let cmd = cli.command.unwrap_or(Command::Run {
        encoder: None,
        // A bare `roomlerd` is never a supervised worker: the supervisor always
        // spawns `run --supervised` explicitly.
        supervised: false,
        // Likewise the Windows spawners always say which one they are.
        supervisor: None,
        // #1683 — only the SCM service host passes a stop-event name.
        stop_event: None,
        // FR-97 P4a — and only it passes a SAS relay.
        sas_event: None,
    });
    // Only the worker subcommand (`Run`) is the one the SCM supervisor
    // spawns + observes for crashes. On non-zero exit from that path,
    // record a sidecar with the WORKER's log tail BEFORE returning so
    // the supervisor's redundant SupervisorDetected sidecar (which
    // would carry SUPERVISOR-side log noise, useless for diagnosing
    // the worker failure) is suppressed by `crash_recorder`'s 30 s
    // rate-limit. Field repro 2026-05-17 a third field-test host: the SystemContext
    // worker was exiting code=1 right after the "couldn't resolve
    // active-user profile" warning, but the admin UI only saw
    // supervisor-side noise. With this hook the modal surfaces the
    // worker's actual log tail.
    let is_worker_run = matches!(cmd, Command::Run { .. });
    let res = match cmd {
        Command::Enroll {
            server,
            token,
            name,
            machine_global,
            label,
            replace,
            ephemeral,
            overlay,
            relay_server,
            archive_replica,
            install_method,
            install_scope,
        } => {
            enroll_cmd(
                &config_path,
                EnrollOptions {
                    server: &server,
                    enrollment_token: &token,
                    machine_name: &name,
                    machine_global,
                    label: label.as_deref(),
                    replace,
                    ephemeral,
                    overlay,
                    relay_server,
                    archive_replica,
                    install_method: install_method.as_deref(),
                    install_scope: install_scope.as_deref(),
                },
            )
            .await
        }
        Command::ReEnroll { token, org } => {
            re_enroll_cmd(&config_path, &token, org.as_deref()).await
        }
        Command::Anchor { action } => {
            use roomlerd::exec_service::{AnchorAction, parse_ssh_ceiling};
            let action = match action {
                AnchorCmd::Create {
                    server,
                    token,
                    device,
                    force,
                    no_exec,
                    ssh,
                } => AnchorAction::Create {
                    server,
                    token,
                    device,
                    force,
                    exec_enabled: !no_exec,
                    ssh: ssh
                        .as_deref()
                        .map(parse_ssh_ceiling)
                        .transpose()
                        .map_err(anyhow::Error::msg)?,
                },
                AnchorCmd::Status => AnchorAction::Status,
                AnchorCmd::Exec { state } => AnchorAction::Exec { on: state == "on" },
                AnchorCmd::Ssh { ceiling } => AnchorAction::Ssh {
                    ceiling: parse_ssh_ceiling(&ceiling).map_err(anyhow::Error::msg)?,
                },
                AnchorCmd::Remove => AnchorAction::Remove,
            };
            roomlerd::exec_service::anchor_cli(action).await
        }
        Command::Org { action } => org_cmd(&config_path, action),
        Command::Run {
            encoder,
            supervised,
            supervisor,
            stop_event,
            sas_event,
        } => {
            // FR-97 P4a — the host's relay, for the real Ctrl+Alt+Del.
            #[cfg(target_os = "windows")]
            if let Some(name) = sas_event {
                roomlerd::input::sas::set_host_relay(name);
            }
            #[cfg(not(target_os = "windows"))]
            let _ = sas_event;
            run_cmd(
                &config_path,
                encoder.as_deref(),
                supervised,
                supervisor.as_deref(),
                stop_event.as_deref(),
            )
            .await
            .map(|restart| {
                // FR-84 D3 — `run` ended through the graceful path a requested
                // restart started. `main` exits with this code, but only once
                // the runtime is gone (see `exit_for_requested_restart`).
                if let Some(code) = restart {
                    let _ = REQUESTED_RESTART_EXIT.set(code);
                }
            })
        }
        Command::CapsProbe => {
            roomlerd::encode::caps::print_probe_result();
            Ok(())
        }
        Command::PortalSession => {
            #[cfg(all(target_os = "linux", feature = "portal-capture"))]
            {
                match roomlerd::capture::portal::helper::open_session() {
                    Ok(r) => {
                        println!("portal-session: {} stream(s)", r.streams.len());
                        for s in &r.streams {
                            println!(
                                "  node_id={} size={}",
                                s.node_id,
                                match (s.width, s.height) {
                                    (Some(w), Some(h)) => format!("{w}x{h}"),
                                    // Absent is normal — PipeWire's own format
                                    // negotiation is authoritative, not this.
                                    _ => "(not advertised)".into(),
                                }
                            );
                        }
                        println!("  pipewire: {}", r.pipewire);
                        println!(
                            "  pipewire_fd_ok={} restore_token={} sent_token={} elapsed={}ms",
                            r.pipewire_fd_ok,
                            // ⚠️ Never print the token itself: it is a standing
                            // grant, and this output goes to a daemon log.
                            if r.restore_token_stored {
                                "yes (stored)"
                            } else {
                                "no"
                            },
                            r.restore_token_sent,
                            r.elapsed_ms
                        );
                        Ok(())
                    }
                    Err(e) => anyhow::bail!("portal-session: {e}"),
                }
            }
            #[cfg(not(all(target_os = "linux", feature = "portal-capture")))]
            {
                anyhow::bail!("portal-session is Linux-only and needs the `portal-capture` feature")
            }
        }
        Command::PortalHelper {
            screencast,
            stream,
            input,
            mutter,
            window,
            keep_busy,
            notify,
            notify_probe,
            audio,
        } => {
            #[cfg(all(target_os = "linux", feature = "portal-capture"))]
            {
                if audio {
                    #[cfg(feature = "audio")]
                    roomlerd::audio::pulse::serve_helper();
                    // The parent reads the marked line: a build without the
                    // feature says so there rather than exit with silence.
                    #[cfg(not(feature = "audio"))]
                    println!(
                        "ROOMLER_AUDIO_FAILED:{}",
                        serde_json::json!({
                            "code": "backend_error",
                            "detail": "this build has no audio capture"
                        })
                    );
                } else if notify_probe {
                    roomlerd::indicator::notify::run_probe_helper();
                } else if notify {
                    roomlerd::indicator::notify::run_helper();
                } else if keep_busy {
                    roomlerd::keep_busy::session_helper::serve();
                } else {
                    roomlerd::capture::portal::helper::run(
                        screencast, stream, input, mutter, window,
                    );
                }
                Ok(())
            }
            // A build without the feature must say so rather than exit 0 with
            // no marked line: the parent would read silence as "the portal is
            // unavailable on this host", which is a different and misleading
            // answer from "this binary cannot ask".
            #[cfg(not(all(target_os = "linux", feature = "portal-capture")))]
            {
                let _ = (
                    screencast,
                    stream,
                    input,
                    mutter,
                    window,
                    keep_busy,
                    notify,
                    notify_probe,
                    audio,
                );
                anyhow::bail!(
                    "portal-helper is Linux-only and needs the `portal-capture` feature; this \
                     build cannot query the desktop portal"
                )
            }
        }
        Command::UpdateHelper => {
            // FR-96 — Linux has the update half too: `meshharbor-update.service`
            // runs this for a per-user install.
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            {
                updater::run_update_helper().await
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            {
                anyhow::bail!(
                    "update-helper is the body of the macOS com.roomler.update LaunchDaemon \
                     and of the Linux meshharbor-update.service; this platform's updater runs \
                     inside the agent itself"
                )
            }
        }
        Command::ProbeTarget { seconds } => roomlerd::probe_target::run(seconds),
        Command::ArtifactVersion { path, claimed } => {
            use roomlerd::artifact_version::{VersionError, verify_artifact_version};
            match verify_artifact_version(&path, &claimed) {
                Ok(found) => {
                    println!("bound: {} is {claimed} (it says {found})", path.display());
                    Ok(())
                }
                Err(e @ VersionError::Unsupported(_)) => {
                    println!("unsupported: {e}");
                    Ok(())
                }
                Err(e) => anyhow::bail!("refused: {e}"),
            }
        }
        Command::CurtainSmoke { seconds } => {
            if !roomlerd::privacy::curtain_smoke(seconds)? {
                anyhow::bail!(
                    "no curtain went up: privacy mode needs Windows 10 2004 or later, a build \
                     with the overlay, and the signed-in desktop session"
                );
            }
            Ok(())
        }
        Command::EncoderSmoke {
            encoder,
            codec,
            reconfigure_sweep,
            name,
            dump,
            width,
            height,
            frames_per_rung,
            constrained,
            json,
        } => {
            if reconfigure_sweep {
                encoder_reconfigure_sweep_cmd(
                    &encoder,
                    &codec,
                    name.as_deref(),
                    width,
                    height,
                    frames_per_rung,
                    constrained,
                    json,
                )
                .await
            } else {
                encoder_smoke_cmd(&encoder, &codec, name.as_deref(), dump.as_deref()).await
            }
        }
        Command::AppsProbe => apps_probe_cmd(&config_path),
        #[cfg(feature = "recording")]
        Command::Record {
            out,
            fps,
            encoder,
            max_minutes,
            remote_user_id,
            remote_user_name,
            system_audio,
            microphone,
            where_only,
            whoami,
        } => {
            roomlerd::recording::child::run(
                roomlerd::recording::child::RecordArgs {
                    out,
                    fps,
                    encoder,
                    max_minutes,
                    remote_user_id,
                    remote_user_name,
                    system_audio,
                    microphone,
                    where_only,
                    whoami,
                },
                &config_path,
            )
            .await
        }
        #[cfg(all(feature = "recording", feature = "openh264-encoder"))]
        Command::Media { action } => match action {
            MediaAction::Probe { file } => roomlerd::recording::media::probe(&file),
            MediaAction::Export { edl, encoder } => {
                roomlerd::recording::media::export(&edl, &encoder).await
            }
        },
        Command::CaptureSmoke {
            frames,
            dump,
            fps,
            downscale,
        } => {
            publish_config_for_smoke(&config_path, "capture-smoke");
            capture_smoke_cmd(frames, dump.as_deref(), fps, &downscale).await
        }
        Command::InputSmoke {
            move_to,
            click,
            text,
            delay_ms,
        } => {
            publish_config_for_smoke(&config_path, "input-smoke");
            input_smoke_cmd(
                move_to.as_deref(),
                click.as_deref(),
                text.as_deref(),
                delay_ms,
            )
        }
        Command::SystemCaptureSmoke {
            desktop,
            frames,
            timeout_ms,
        } => system_capture_smoke_cmd(&desktop, frames, timeout_ms),
        Command::SystemContextProbe { mode } => system_context_probe_cmd(&mode),
        Command::Caps => caps_cmd().await,
        Command::Displays => displays_cmd().await,
        #[cfg(feature = "system-context")]
        Command::PeerPresenceStatus => peer_presence_status_cmd(),
        Command::Service { action } => service_cmd(action, &config_path).await,
        Command::ServiceRun => service_run_cmd().await,
        Command::Netd => netd_cmd().await,
        Command::CleanupLegacyInstall {
            target_flavour,
            dry_run,
        } => cleanup_legacy_install_cmd(&target_flavour, dry_run),
        Command::SweepOldVersions { dry_run, flavour } => {
            sweep_old_versions_cmd(dry_run, flavour.as_deref())
        }
        Command::Consent {
            list,
            session,
            approve,
            deny,
        } => {
            if list {
                consent_list_cmd().await
            } else {
                // `required_unless_present = "list"` makes this infallible.
                let session = session.unwrap_or_default();
                consent_cmd(&session, approve, deny).await
            }
        }
        Command::Rc { disconnect } => rc_cmd(disconnect.as_deref()).await,
        Command::SelfUpdate { check_only } => self_update_cmd(check_only).await,
        Command::EnableSystemContext { no_restart } => enable_system_context_cmd(no_restart),
        Command::DisableSystemContext { no_restart } => disable_system_context_cmd(no_restart),
        Command::KeepSystemContext { no_restart } => keep_system_context_cmd(no_restart),
        Command::SetServiceEnvVar { name, value } => {
            set_service_env_var_cmd(&name, value.as_deref())
        }
        Command::RestartService { timeout_secs } => restart_service_cmd(timeout_secs),
        Command::PostInstallWatch {
            installer_pid,
            installer_path,
            expected_version,
            origin_exe,
            installer_already_exited,
        } => {
            post_install_watch_cmd(
                installer_pid,
                installer_path,
                expected_version,
                origin_exe,
                installer_already_exited,
            )
            .await
        }
    };

    #[cfg(target_os = "windows")]
    if is_worker_run && let Err(ref err) = res {
        record_worker_exit_failure(err);
    }
    let _ = is_worker_run; // silence unused on non-windows
    res
}

/// FR-84 D3 — the exit code a requested restart leaves with. Set by the `run`
/// arm of [`daemon_main`] when `run_cmd` came back from the graceful shutdown
/// a `RestartDaemon` started; read by `main` only after the runtime is gone.
static REQUESTED_RESTART_EXIT: std::sync::OnceLock<i32> = std::sync::OnceLock::new();

/// FR-97 P0e — set when this process ran the daemon (`meshharbord run`, past
/// its single-instance lock), so [`purge_after_daemon`] runs only then: every
/// other subcommand (`enroll`, `status`, `self-update --check-only`), and a
/// `run` that found the lock held, may share the host with a RUNNING daemon,
/// whose routes are not ours to purge.
static DAEMON_RAN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// FR-97 P0e — the daemon is gone: purge what it leaves in the host (the exit
/// `/1`s, the DNS steer, and the host ledger: a Windows router's forwarding
/// and every exit-client pin). Only a requested restart did this before, so a
/// plain stop (SIGTERM, an SCM stop, `launchctl bootout`) left the pins
/// through the physical uplink behind (field, 0.4.134), and a host moved to
/// another network then started with its server address black-holed. Called
/// once the runtime is dropped, so no overlay task can re-pin behind it.
fn purge_after_daemon() {
    if DAEMON_RAN.load(std::sync::atomic::Ordering::SeqCst) {
        roomlerd::purge_exit_routes();
    }
}

/// FR-84 D3 — leave for the supervisor to relaunch us, if a restart was
/// requested; otherwise return and let `main` end the process as it always
/// has.
///
/// By the time this runs, `run_cmd` has completed the SAME graceful path an
/// auto-update's exit takes (internal shutdown, `mark_clean_shutdown` — no
/// crash counted, nothing for the rollback detector), and on every platform
/// but the AppKit one the runtime has been dropped too, so every task still
/// running was cancelled and its teardown ran. The one thing that differs from
/// an update's exit is the code: `0` under the Windows SCM supervisor,
/// `RESTART_REQUESTED_EXIT_CODE` everywhere else
/// (`supervision::Supervision::restart_exit_code`).
fn exit_for_requested_restart() {
    let Some(&code) = REQUESTED_RESTART_EXIT.get() else {
        return;
    };
    // Belt, not load-bearing: the teardown above already ran. A requested
    // restart must never leave the host blackholed for the seconds until the
    // relaunched daemon's own boot reconciler runs (P5/A2).
    roomlerd::purge_exit_routes();
    // #1684 — likewise idempotent: `run_cmd` already tore the virtual desktop
    // down on its way here, so this only matters if a future exit path reaches
    // `exit_for_requested_restart` without unwinding `run_cmd`. Cheap insurance
    // that systemd never waits out `TimeoutStopSec` on our own desktop tree.
    #[cfg(target_os = "linux")]
    virtual_desktop::teardown();
    tracing::info!(
        exit_code = code,
        "requested restart: exiting for the supervisor to relaunch this daemon"
    );
    // The file layer is non-blocking and its guard lives in a static that is
    // never dropped; give it a moment to write the line above.
    std::thread::sleep(std::time::Duration::from_millis(200));
    std::process::exit(code);
}

// RETIRED-NAME-ANCHOR: the PRE-RENAME machine-global tree. `machine_global_dir()` still
// resolves
// it on a host that has one, so it must stay named here. docs/fr/FR-21
/// Record a `SupervisorDetected` crash sidecar when the worker
/// `Run` subcommand returns Err and main is about to exit non-zero.
/// Routed through `crash_recorder::record` so:
///
///   - Under SystemContext (LocalSystem worker), the sidecar lands in
///     `%PROGRAMDATA%\roomler\roomler-agent\crashes\` where the
///     user-context uploader will find it on a later successful start.
///   - Under user-context worker, the sidecar lands in the worker's
///     own `%LOCALAPPDATA%\roomler\…\crashes\` for the same uploader
///     to scan.
///
/// The log_tail attached comes from `read_log_tail()` inside the
/// recorder — that reads the WORKER's rolling log, which is the
/// useful artifact for diagnosis (vs. the supervisor's later
/// SupervisorDetected record which carries supervisor noise + is
/// suppressed by the 30 s rate-limit).
#[cfg(target_os = "windows")]
fn record_worker_exit_failure(err: &anyhow::Error) {
    use roomlerd::crash_recorder::{self, Reason, WriterContext};

    // Choose the writer context the user-context uploader will scan.
    // Under LocalSystem (SystemContext worker): use PROGRAMDATA via
    // WriterContext::Supervisor. Under user-context worker: use the
    // worker's own LOCALAPPDATA via WriterContext::Worker.
    #[cfg(feature = "system-context")]
    let ctx = match roomlerd::system_context::worker_role::probe_self() {
        Ok(roomlerd::system_context::worker_role::WorkerRole::SystemContext) => {
            WriterContext::Supervisor
        }
        _ => WriterContext::Worker,
    };
    #[cfg(not(feature = "system-context"))]
    let ctx = WriterContext::Worker;

    let summary = format!("worker exit: {err:#}");
    crash_recorder::record(Reason::SupervisorDetected, &summary, ctx);
}

/// Remove cross-flavour MSI install leftovers. Invoked by the WiX
/// custom action immediately before `InstallFiles`. Wraps
/// `install_cleanup::run_cleanup` with CLI-friendly arg parsing +
/// summary print. Always exits 0 so the MSI's `Return="ignore"` on
/// the custom action is belt-and-suspenders, not load-bearing.
fn cleanup_legacy_install_cmd(target_flavour: &str, dry_run: bool) -> Result<()> {
    let target = match roomlerd::install_cleanup::TargetFlavour::parse(target_flavour) {
        Some(t) => t,
        None => {
            eprintln!(
                "cleanup-legacy-install: unrecognised --target-flavour {target_flavour:?}; \
                 expected `perUser` or `perMachine` (no-op)"
            );
            return Ok(());
        }
    };
    let report = roomlerd::install_cleanup::run_cleanup(target, dry_run)?;
    // Always print the one-line summary so the MSI's session log
    // (msiexec /l*v) shows what happened. Exit 0 even on errors —
    // a cleanup failure shouldn't sink the install.
    println!("{}", report.summary());
    if !report.errors.is_empty() {
        for e in &report.errors {
            tracing::warn!(error = %e, "cleanup-legacy-install: partial failure");
        }
    }
    Ok(())
}

// RETIRED-NAME-ANCHOR: names the OLD MSI product this sweep exists to remove.
// docs/fr/FR-21
/// Uninstall roomler-agent MSI versions older than the running one
/// (see [`roomlerd::version_sweep`] for why they pile up). Prints
/// a one-line summary; exits 0 even on partial failure (best-effort,
/// like `cleanup-legacy-install`). Use `--dry-run` to preview.
fn sweep_old_versions_cmd(dry_run: bool, flavour: Option<&str>) -> Result<()> {
    let flavour_override = match flavour {
        Some(s) => match roomlerd::install_detect::Flavour::parse(s) {
            Some(f) => Some(f),
            None => {
                eprintln!(
                    "sweep-old-versions: unrecognised --flavour {s:?}; \
                     expected `perUser` or `perMachine`"
                );
                return Ok(());
            }
        },
        None => None,
    };
    let report = roomlerd::version_sweep::run_sweep(dry_run, flavour_override)?;
    println!("{}", report.summary());
    if !report.errors.is_empty() {
        for e in &report.errors {
            tracing::warn!(error = %e, "sweep-old-versions: partial failure");
        }
    }
    Ok(())
}

/// Answer a pending operator-consent prompt.
///
/// P2b security-review M2: prefer the RUNNING daemon over a direct sentinel
/// write. The daemon owns the profile-correct sentinel dir — under a
/// SYSTEM/SCM install, a sentinel written from an interactive user's shell
/// lands in the WRONG profile and the service never sees it (the decision
/// was silently inert). The LocalAPI path reaches the daemon's own broker
/// and rides its live-prompt gating (decisions are honored only while the
/// session is actively being prompted — no pre-approval).
///
/// The direct filesystem write survives as an explicit FALLBACK for a
/// console-run agent in THIS profile when no daemon is listening on the
/// local pipe/socket.
/// FR-27 — list, or end, the remote-control sessions live on this device.
///
/// LocalAPI-only, like [`consent_list_cmd`] and for the same reason: a listing
/// read from the wrong profile would confidently print "nobody is viewing this
/// device" while someone was.
async fn rc_cmd(disconnect: Option<&str>) -> Result<()> {
    let mut client = tunnel_core::localapi::connect()
        .await
        .context("connecting to the device service")?;

    if let Some(session) = disconnect {
        let ok = client
            .rc_disconnect(session)
            .await
            .context("asking the device service to end the session")?;
        if !ok {
            anyhow::bail!(
                "no live remote-control session {session} on this device \
                 (or the id is not a 24-char hex ObjectId)"
            );
        }
        println!("asked the device service to end session {session}");
        return Ok(());
    }

    let sessions = client
        .rc_sessions()
        .await
        .context("asking the device service for live remote-control sessions")?;
    if sessions.is_empty() {
        println!("nobody is viewing this device");
        return Ok(());
    }
    for s in &sessions {
        let who = if s.controller_name.is_empty() {
            "(unnamed)"
        } else {
            &s.controller_name
        };
        // Say what they can DO, not just that they are there: "watching" and
        // "typing on this machine" are different things to be told about.
        let grant = if s.permissions.to_uppercase().contains("INPUT") {
            "keyboard + mouse"
        } else {
            "view only"
        };
        println!("{}  {}  [{}]", s.session_id, who, grant);
        if !s.org.is_empty() {
            println!("    org:        {}", s.org);
        }
        if !s.permissions.is_empty() {
            println!("    granted:    {}", s.permissions);
        }
        println!("    disconnect: roomler rc --disconnect {}", s.session_id);
    }
    Ok(())
}

/// FR-27 — list every prompt the daemon is currently waiting on.
///
/// Before this the id existed only in a log line, and had to be found inside
/// the same 30 s window the operator had to answer in. That made the headless
/// consent path close to unusable, which in turn is part of why every device in
/// the field is left on `auto`.
///
/// Deliberately LocalAPI-only: the sentinel-file fallback in [`consent_cmd`]
/// exists because a decision written to the wrong profile is silently inert,
/// but a LISTING read from the wrong profile is worse — it would confidently
/// print "nothing pending" while the daemon waits.
async fn consent_list_cmd() -> Result<()> {
    let mut client = tunnel_core::localapi::connect()
        .await
        .context("connecting to the device service")?;
    let pending = client
        .consent_pending()
        .await
        .context("asking the device service for pending consent prompts")?;
    if pending.is_empty() {
        println!("no consent prompt is waiting for a decision");
        return Ok(());
    }
    for p in &pending {
        // Pre-FR-27 daemons write no `kind`; the only kind that existed then
        // was remote control.
        let kind = if p.kind.is_empty() { "rc" } else { &p.kind };
        println!("{}  [{}]  from {}", p.session_id, kind, p.controller_name);
        if p.surface == "native" {
            // Worth saying: the operator is about to be told to run a command
            // for something that already has a button in front of them.
            println!("    shown:       on this device's screen already");
        }
        if !p.org.is_empty() {
            println!("    org:         {}", p.org);
        }
        if !p.permissions.is_empty() {
            println!("    permissions: {}", p.permissions);
        }
        if !p.detail.is_empty() {
            println!("    request:     {}", p.detail);
        }
        println!(
            "    approve:     roomlerd consent --session {} --approve",
            p.session_id
        );
    }
    Ok(())
}

async fn consent_cmd(session_hex: &str, approve: bool, deny: bool) -> Result<()> {
    let kind = roomlerd::consent::SentinelKind::from_flags(approve, deny)?;
    let allow = matches!(kind, roomlerd::consent::SentinelKind::Approve);

    match tunnel_core::localapi::connect().await {
        Ok(mut client) => {
            let ok = client
                .consent_decide(session_hex, allow)
                .await
                .context("asking the device service to record the decision")?;
            if !ok {
                anyhow::bail!(
                    "the device service rejected the decision — no live consent prompt \
                     for session {session_hex} (or the id is not a 24-char hex ObjectId)"
                );
            }
            println!(
                "operator consent {} for session {} (recorded by the device service)",
                if allow { "APPROVED" } else { "DENIED" },
                session_hex
            );
            return Ok(());
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "device service not reachable — falling back to a sentinel file in this \
                 user's profile (only a console-run agent in the SAME profile will see it)"
            );
        }
        Err(e) => {
            return Err(anyhow::Error::from(e).context("connecting to the device service"));
        }
    }

    let dir = roomlerd::consent::ConsentBroker::default_sentinel_dir()
        .context("resolving consent sentinel dir")?;
    // `Mode::AutoGrant` here is irrelevant — we're not running the
    // broker, just borrowing its sentinel-path layout. Using
    // AutoGrant skips the directory existence check so the CLI
    // works even before the agent's first session.
    let broker = roomlerd::consent::ConsentBroker::new(roomlerd::consent::Mode::AutoGrant, dir)
        .context("opening consent broker for CLI")?;
    let path = broker.write_sentinel(session_hex, kind)?;
    println!(
        "operator consent {} for session {}\n  sentinel: {}",
        match kind {
            roomlerd::consent::SentinelKind::Approve => "APPROVED",
            roomlerd::consent::SentinelKind::Deny => "DENIED",
        },
        session_hex,
        path.display()
    );
    Ok(())
}

async fn post_install_watch_cmd(
    installer_pid: u32,
    installer_path: PathBuf,
    expected_version: String,
    origin_exe: Option<PathBuf>,
    already_exited: bool,
) -> Result<()> {
    tracing::info!(
        installer_pid,
        path = %installer_path.display(),
        expected = %expected_version,
        origin = ?origin_exe,
        already_exited,
        "post-install watcher started"
    );
    // `watch` is blocking — spin a blocking task so we don't hold
    // the tokio runtime busy-waiting on a sync OS sleep loop.
    let outcome = tokio::task::spawn_blocking(move || {
        post_install::watch(
            installer_pid,
            installer_path,
            expected_version,
            origin_exe,
            already_exited,
        )
    })
    .await
    .context("post-install watcher join")??;
    println!(
        "post-install verdict: {:?} ({})",
        outcome.status, outcome.note
    );
    Ok(())
}

/// Resolution order for `encoder_preference`: CLI flag → env var
/// `ROOMLERD_ENCODER` → config file field → default (Auto).
/// Invalid values fall through to Auto with a warning, so a typo can't
/// prevent the agent from starting.
fn rollback_attention_msg(
    current: &str,
    target: &str,
    crash_count: u32,
    failure_reason: Option<&str>,
) -> String {
    let mut msg = format!(
        "Roomler agent: crash loop detected (auto-rollback failed).\n\n\
         Version {current} has crashed {crash_count} times within \
         {win_min} min. Last known good version: {target}.\n",
        win_min = config::CRASH_WINDOW_SECS / 60,
    );
    if let Some(why) = failure_reason {
        msg.push_str(&format!("\nAutomatic rollback could not run: {why}\n"));
    }
    msg.push_str(
        "\nRecommended action: download the previous installer from\n\
         https://github.com/gjovanov/roomler-ai/releases\n\
         and reinstall manually.",
    );
    msg
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn resolve_encoder_preference(
    cli: Option<&str>,
    cfg_field: config::EncoderPreferenceChoice,
) -> encode::EncoderPreference {
    let from_str = |s: &str, src: &str| match encode::EncoderPreference::from_str(s) {
        Ok(p) => Some(p),
        Err(e) => {
            tracing::warn!(%e, source = src, "ignoring bad encoder preference");
            None
        }
    };
    if let Some(v) = cli.and_then(|s| from_str(s, "cli")) {
        return v;
    }
    if let Some(env_val) = node_env("ENCODER")
        && let Some(v) = from_str(&env_val, "env")
    {
        return v;
    }
    match cfg_field {
        config::EncoderPreferenceChoice::Auto => encode::EncoderPreference::Auto,
        config::EncoderPreferenceChoice::Hardware => encode::EncoderPreference::Hardware,
        config::EncoderPreferenceChoice::Software => encode::EncoderPreference::Software,
    }
}

/// What `enroll` was asked to do.
///
/// A struct rather than eight positionals because three of them are bools:
/// `enroll_cmd(.., true, false, true)` says nothing at the call site and a
/// transposition compiles perfectly. Same reasoning as `OverlayNodeDao::create`
/// (#621). Destructured exhaustively below, so a new field has to be given a
/// meaning rather than silently ignored.
struct EnrollOptions<'a> {
    server: &'a str,
    enrollment_token: &'a str,
    machine_name: &'a str,
    machine_global: bool,
    label: Option<&'a str>,
    replace: bool,
    /// FR-51 P3 — random machine fingerprint + refuse-if-config-exists; the
    /// server's response (not this flag) decides what the CONFIG records.
    ephemeral: bool,
    overlay: bool,
    relay_server: bool,
    /// FR-90 P2h-1 — the archive replica's posture ([`roomlerd::archive_replica`]).
    archive_replica: bool,
    /// FR-102 P3 — the install trace, flag-first; `None` falls back to the
    /// env, then to `manual` / `unknown` (`enrollment::resolve_install`).
    install_method: Option<&'a str>,
    install_scope: Option<&'a str>,
}

async fn enroll_cmd(config_path: &Path, opts: EnrollOptions<'_>) -> Result<()> {
    let EnrollOptions {
        server,
        enrollment_token,
        machine_name,
        machine_global,
        label,
        replace,
        ephemeral,
        overlay,
        relay_server,
        archive_replica,
        install_method,
        install_scope,
    } = opts;
    // FR-102 P3 — resolved FIRST: a typo in the flag or the env must be
    // seen before the single-use token is spent, not after.
    let install = enrollment::resolve_install(install_method, install_scope)?;
    // rc.52: --machine-global retargets the write to
    // RETIRED-NAME-ANCHOR: the PRE-RENAME machine-global tree. `machine_global_dir()`
    // still resolves
    // it on a host that has one, so it must stay named here. docs/fr/FR-21
    // %PROGRAMDATA%\roomler\roomler-agent\config.toml so a perMachine
    // + SystemContext host's LocalSystem worker can load it pre-logon.
    // machine_id is derived from the SAME path the config is written
    // to, so it stays internally consistent for this fresh enrollment.
    let target_path: PathBuf = if machine_global {
        #[cfg(target_os = "windows")]
        {
            config::machine_global_config_path()
        }
        #[cfg(not(target_os = "windows"))]
        {
            bail!(
                "--machine-global is Windows-only (there is no machine-global \
                 config location on this platform)"
            );
        }
    } else {
        config_path.to_path_buf()
    };

    // Multi-org P1: when a config already exists at the target path, reuse
    // ITS machine_id for the POST — every enrollment of this machine must
    // present the SAME fingerprint so the server's `(tenant_id, machine_id)`
    // key recognises the box across orgs (and across the %PROGRAMDATA% vs
    // %APPDATA% path drift that re-enroll's rc.52 BLOCKER-6 guards against).
    // FR-66: `read_if_present`, NOT `load(..).ok()`. A FIRST enrollment has no
    // config by definition, and `load` announces a missing one as `the host
    // must be re-enrolled` at ERROR — so enrolling a clean machine told the
    // operator to re-enroll it, mid-enrollment. Behaviour is unchanged: absent
    // still means "no machine_id to reuse".
    let existing = config::read_if_present(&target_path);
    // FR-51 P3 — an ephemeral enrollment is a FRESH identity by definition:
    // folding it into an existing config would either hand this machine's
    // real device row a random fingerprint or hand the ephemeral row the
    // machine's stable one, and both directions are the F1 trap. Refuse
    // rather than guess.
    if ephemeral && existing.is_some() {
        bail!(
            "--ephemeral needs a fresh config, but one already exists at {} — \
             an ephemeral identity must never be folded into a real device's \
             enrollment. Point --config at an empty path (containers get this \
             for free) or remove the existing enrollment first.",
            target_path.display()
        );
    }
    // FR-90 P2h-1 — before the single-use token is spent, so a refusal
    // leaves no device row behind.
    if archive_replica {
        roomlerd::archive_replica::preflight(existing.is_some(), ephemeral)?;
    }
    let machine_id = match &existing {
        Some(cfg) => {
            tracing::info!(
                machine_id = %cfg.machine_id,
                "existing config found — reusing its machine fingerprint"
            );
            cfg.machine_id.clone()
        }
        None if ephemeral => {
            // Random per enrollment, never derived: N replicas of one image
            // share hostname+OS+arch+path, so the derived fingerprint would
            // collapse them onto ONE server row displacing each other
            // (FR-51 F1). Same 64-hex shape as the derived id.
            let random = hex::encode(rand::random::<[u8; 32]>());
            tracing::info!(machine_id = %random, "minted RANDOM machine fingerprint (--ephemeral)");
            random
        }
        None => {
            let derived = machine::derive_machine_id(&target_path);
            tracing::info!(machine_id = %derived, machine_global, "derived machine fingerprint");
            derived
        }
    };

    let fresh = enrollment::enroll(enrollment::EnrollInputs {
        server_url: server,
        enrollment_token,
        machine_id: &machine_id,
        machine_name,
        install: Some(install),
    })
    .await
    .context("enrollment failed")?;

    // Multi-org P1 dispatch: fresh install → write as-is; same (server,
    // tenant) as the primary or a `[[orgs]]` entry → refresh it in place
    // (operator state preserved — rc.204 semantics); a NEW pair → APPEND a
    // secondary org (with its own freshly minted WG key); `--replace` →
    // legacy whole-primary rebind.
    let (mut cfg, outcome) = enrollment::apply_enrollment(existing, fresh, label, replace)?;

    // FR-51 P3 — the CREDENTIAL decided what was minted; say so when it
    // disagrees with the flag. `--ephemeral` with a standard token has
    // already created a PERMANENT row under a random fingerprint — that row
    // will never rehydrate naturally, so the operator must be told now, not
    // discover an orphan later.
    if ephemeral && !cfg.ephemeral {
        tracing::warn!(
            "--ephemeral was passed but the credential was a standard enrollment \
             token: the server enrolled a PERMANENT device under a RANDOM machine \
             fingerprint. If unintended, delete it from the dashboard and re-enroll \
             with an ephemeral enrollment key."
        );
        println!(
            "WARNING: the credential was not an ephemeral key — this device enrolled \
             as PERMANENT (with a random machine id). Mint an ephemeral enrollment \
             key in the dashboard for a self-removing device."
        );
    }

    // rc.52: a machine-global write needs admin (%PROGRAMDATA% +, on
    // the installer path, an ACL-restricted parent dir). On a
    // non-elevated shell `config::save` fails with ACCESS_DENIED —
    // surface an actionable error rather than letting the operator
    // think they enrolled. We must NOT fall back to %APPDATA%: a
    // SystemContext worker would never find the config there and
    // would crash-loop pre-logon (rc.51 Finding 3).
    // `--overlay`: set BEFORE the save, so the first start already has it.
    // Deliberately only ever turns it ON — an enrollment refresh on a host
    // that already joined the mesh must not silently drop it back out (the
    // same invariant `enrollment.rs` protects when merging an existing
    // config).
    //
    // FR-49 — and it applies to the identity ACTUALLY ENROLLED. Before this it
    // always set the primary's flag: `enroll --server B --token … --overlay` on
    // a host already in org A appended B with `overlay_mode = off` and turned
    // the mesh on for **A**. The flag read as granted and landed on the wrong
    // org, which nothing then reported.
    //
    // ⚠️ A secondary gets `netstack`, not `tun`. `tun` gives the org an OS
    // adapter of its own and needs `overlay_multi_org` + the same control plane
    // (macOS included, FR-97 P1d), so a bare flag that installed OS routes could wedge
    // a host — the one thing "never self-wedge" exists to prevent. `netstack`
    // is a userspace stack behind a loopback SOCKS5 front: no TUN, no routes,
    // no privilege. Anything else is the explicit `org overlay` verb.
    if overlay {
        roomlerd::org_join::apply_overlay_flag(&mut cfg, &outcome);
    }
    if relay_server {
        roomlerd::org_join::apply_relay_server_flag(&mut cfg, &outcome);
    }
    // FR-90 P2h-1 — the archive replica's posture, before the first save. The
    // preflight made this a fresh primary enrollment.
    if archive_replica {
        roomlerd::archive_replica::apply(&mut cfg);
    }
    // FR-99 decision 3 — a fresh Windows service install (`--machine-global`)
    // starts at `lock_on_end = auto`; a refresh keeps what the device had.
    if enrollment::takes_service_install_defaults(machine_global, &outcome) {
        enrollment::apply_service_install_defaults(&mut cfg);
    }

    config::save(&target_path, &cfg).map_err(|e| {
        if machine_global {
            anyhow::anyhow!(
                "{e}\n\nWriting the machine-global config requires an elevated \
                 (Administrator) terminal. Re-run this command from an elevated \
                 prompt — do not retry without --machine-global, that would write \
                 a config the SystemContext service cannot read."
            )
        } else {
            anyhow::anyhow!(e).context("saving config")
        }
    })?;
    use enrollment::EnrollOutcome;
    let enrolled_agent_id = match &outcome {
        EnrollOutcome::RefreshedOrg { label } | EnrollOutcome::AppendedOrg { label } => cfg
            .find_org(label)
            .map(|o| o.agent_id.clone())
            .unwrap_or_else(|| cfg.agent_id.clone()),
        _ => cfg.agent_id.clone(),
    };
    tracing::info!(
        path = %target_path.display(),
        agent_id = %enrolled_agent_id,
        ?outcome,
        "enrollment complete"
    );
    match &outcome {
        EnrollOutcome::FreshPrimary => {
            if cfg.ephemeral {
                println!(
                    "Enrollment successful (EPHEMERAL). Agent id: {enrolled_agent_id}\n\
                     This device removes itself: on clean shutdown immediately, or after \
                     its inactivity deadline. A restart enrolls a NEW device."
                );
            } else {
                println!("Enrollment successful. Agent id: {enrolled_agent_id}");
            }
        }
        EnrollOutcome::RefreshedPrimary => {
            println!(
                "Primary enrollment refreshed (same server + org). Agent id: {enrolled_agent_id}"
            );
        }
        EnrollOutcome::ReplacedPrimary => {
            println!("Primary enrollment REPLACED (--replace). Agent id: {enrolled_agent_id}");
        }
        EnrollOutcome::RefreshedOrg { label } => {
            println!("Org {label:?} enrollment refreshed. Agent id: {enrolled_agent_id}");
        }
        EnrollOutcome::AppendedOrg { label } => {
            println!("Enrolled into an ADDITIONAL org as {label:?}. Agent id: {enrolled_agent_id}");
            println!(
                "This machine now serves {} enrollment(s); manage them with \
                 `roomlerd org ls`.",
                1 + cfg.orgs.len()
            );
            // FR-49 — say what the mesh is doing. A secondary defaults to
            // `overlay_mode = off` while its WS still connects, so without this
            // line the device looks fully enrolled and is on no mesh, and the
            // operator finds out days later by wondering why a peer is missing.
            let mode = cfg
                .find_org(label)
                .map(|o| o.overlay_mode)
                .unwrap_or_default();
            if mode == config::OrgOverlayMode::Off {
                println!(
                    "⚠️  This org's OVERLAY IS OFF, so the machine is enrolled but NOT on \
                     its mesh — it will not appear in `meshharbor peers` for {label:?} and \
                     cannot be reached by overlay address there. Remote control, exec \
                     and SSH over the control plane still work."
                );
                println!(
                    "    Join it with: roomlerd org overlay {label} netstack   \
                     (then restart the daemon)"
                );
            } else {
                println!("Overlay for {label:?}: {}.", mode.wire());
            }
        }
    }
    println!("Config written to: {}", target_path.display());
    // #2371 — the step that connects THIS enrollment on this install: the
    // service manager's (`meshharbord run` beside one is an orphan), and for an
    // added org a restart, since only a restart starts its loop.
    let secondary = matches!(
        outcome,
        EnrollOutcome::RefreshedOrg { .. } | EnrollOutcome::AppendedOrg { .. }
    );
    println!(
        "{}",
        service::Install::detect(&target_path).after_enroll(secondary)
    );

    // rc.53 Phase 7: WINHOST-B's recurring pain — operator runs
    // `enroll --machine-global` from a user PowerShell, the config
    // lands in %PROGRAMDATA% (where the LocalSystem service reads
    // it), but then `meshharbord run` from THAT SAME user shell
    // reads %APPDATA% (a separate config, different machine_id) and
    // looks like a different host to the server. Surface the
    // asymmetry explicitly so the operator doesn't burn an hour
    // chasing "but I just enrolled!".
    #[cfg(target_os = "windows")]
    if machine_global && enroll_user_context_warning_due() {
        eprintln!();
        eprint!("{}", warning_message_for_user_context_enroll());
    }
    Ok(())
}

/// rc.53 Phase 7 predicate: should the `--machine-global` enroll
/// command print the user-vs-LocalSystem warning? True when the
/// current process is NOT the LocalSystem worker — i.e. the operator
/// is enrolling from a user shell where `meshharbord run` would
/// later read %APPDATA% instead of %PROGRAMDATA%.
///
/// Gated on `system-context` feature + Windows; non-Windows / non-SC
/// builds always return false (no risk of asymmetry).
#[cfg(all(feature = "system-context", target_os = "windows"))]
fn enroll_user_context_warning_due() -> bool {
    // main.rs is the bin crate; reach into the lib via its crate name
    // — mirrors the existing call sites at :404, :476, :637, :1032, :1792.
    // Local cargo test caught this only via the bin-tests build path
    // because the test binary doesn't exercise the system-context feature.
    use roomlerd::system_context::worker_role::{WorkerRole, probe_self};
    !matches!(probe_self(), Ok(WorkerRole::SystemContext))
}

#[cfg(all(not(feature = "system-context"), target_os = "windows"))]
fn enroll_user_context_warning_due() -> bool {
    // Without the system-context feature there is no SCM worker that
    // would read %PROGRAMDATA% anyway, so the warning is always
    // appropriate when --machine-global is used (the operator may
    // be testing the install path or building an unusual config).
    true
}

/// rc.53 Phase 7 message body. Extracted as a pure function so the
/// unit test asserts the marker phrases without duplicating the
/// string.
#[cfg(target_os = "windows")]
fn warning_message_for_user_context_enroll() -> String {
    "NOTE: --machine-global wrote config to %PROGRAMDATA%, which is read by\n\
     the LocalSystem service worker. A `meshharbord run` from THIS user\n\
     shell will instead read %APPDATA% (a separate config, different\n\
     machine_id) and will look like a different host to the server.\n\
\n\
Either:\n\
 (a) start the service: `sc start Roomler`  — uses %PROGRAMDATA%;\n\
 (b) re-run `enroll` without --machine-global if you want to test in\n\
     THIS user shell (will produce a different agent_id).\n"
        .to_string()
}

async fn re_enroll_cmd(
    config_path: &PathBuf,
    enrollment_token: &str,
    org: Option<&str>,
) -> Result<()> {
    if !config_path.exists() {
        bail!(
            "no existing config at {}; use `enroll` for first-time setup",
            config_path.display()
        );
    }
    let existing = config::load(config_path).context("loading existing config")?;
    // rc.52 BLOCKER-6: preserve the EXISTING machine_id verbatim — do
    // NOT re-derive from `config_path`. `derive_machine_id` hashes the
    // config path; after rc.52 a SystemContext host's config lives at
    // %PROGRAMDATA% while its original enrollment used %APPDATA%, so
    // re-deriving would mint a DIFFERENT machine_id, orphan the
    // server's `agents` row, and break the `(tenant_id, machine_id)`
    // unique key. The id the host enrolled with is stored in the
    // config — reuse it. (Fresh `enroll` correctly derives from its
    // own write path; only `re-enroll` of an unchanged host must
    // pin the id.)
    let machine_id = existing.machine_id.clone();

    // Multi-org P1: `--org <label>` refreshes THAT enrollment (default:
    // the primary). The token is posted to the selected org's server.
    let org_label = org.unwrap_or(config::PRIMARY_ORG_LABEL);
    let is_primary = org_label == config::PRIMARY_ORG_LABEL;
    let (server_url, expect_tenant, old_agent_id) = if is_primary {
        (
            existing.server_url.clone(),
            existing.tenant_id.clone(),
            existing.agent_id.clone(),
        )
    } else {
        let entry = existing.find_org(org_label).ok_or_else(|| {
            anyhow::anyhow!("no org labelled {org_label:?} in this config — see `roomlerd org ls`")
        })?;
        (
            entry.server_url.clone(),
            entry.tenant_id.clone(),
            entry.agent_id.clone(),
        )
    };
    tracing::info!(
        %machine_id,
        org = %org_label,
        agent_id = %old_agent_id,
        machine_name = %existing.machine_name,
        "re-enrolling against existing config (machine_id preserved)"
    );

    let new_cfg = enrollment::enroll(enrollment::EnrollInputs {
        server_url: &server_url,
        enrollment_token,
        machine_id: &machine_id,
        machine_name: &existing.machine_name,
        // FR-102 P3 — a token refresh knows nothing about how the binary
        // got here; sending nothing leaves the row's recorded install alone.
        install: None,
    })
    .await
    .context("re-enrollment failed")?;

    // The refreshed token must resolve to the SAME org — a token for a
    // different org is an ADD, which is `enroll`'s job (explicit intent).
    if new_cfg.tenant_id != expect_tenant {
        bail!(
            "the enrollment token belongs to a different org (tenant {}) than \
             {org_label:?} (tenant {expect_tenant}). To enroll this machine into an \
             ADDITIONAL org run:\n\n\
             \troomlerd enroll --server {server_url} --token <jwt>",
            new_cfg.tenant_id
        );
    }

    // Fold through the same dispatch as `enroll` — this lands on the
    // refresh-in-place arms and (fixing a pre-multi-org gap) preserves
    // operator state for the primary too, instead of writing the fresh
    // default-everything config wholesale.
    let (merged, _outcome) = enrollment::apply_enrollment(Some(existing), new_cfg, None, false)?;
    let refreshed_agent_id = if is_primary {
        merged.agent_id.clone()
    } else {
        merged
            .find_org(org_label)
            .map(|o| o.agent_id.clone())
            .unwrap_or_default()
    };
    config::save(config_path, &merged).context("saving updated config")?;
    if is_primary {
        notify::clear_all_attention();
    }
    println!("Re-enrollment successful for {org_label:?}. Agent id: {refreshed_agent_id}");
    // #2293 — what actually brings this daemon back depends on its install:
    // systemd never restarts the removal's exit 7, and `meshharbord run` by
    // hand beside a unit is an orphan.
    println!(
        "{}",
        service::Install::detect(config_path).after_re_enroll(is_primary)
    );
    Ok(())
}

/// Multi-org P1 — `roomlerd org <ls|rm|enable|disable|set-primary>`.
/// Direct config-file edits (same model as `enroll`): the daemon applies
/// changes on its next start. Runtime org verbs over the LocalAPI land with
/// the desktop org-management UI in a later phase.
fn org_cmd(config_path: &PathBuf, action: OrgAction) -> Result<()> {
    let mut cfg = config::load(config_path).with_context(|| {
        format!(
            "loading config at {} (run `meshharbord enroll` first)",
            config_path.display()
        )
    })?;
    match action {
        OrgAction::Ls => {
            // FR-49 — OVERLAY is here because its absence was the defect: an
            // appended org gets `overlay_mode = off`, its WS still connects,
            // and every surface an operator had reported it as healthy. ENABLED
            // and OVERLAY are different questions — a row can be enabled (it
            // has a signalling loop, it answers exec and SSH) and still be on
            // no mesh at all.
            println!(
                "{:<14} {:<9} {:<8} {:<9} {:<26} SERVER",
                "LABEL", "PRIMARY", "ENABLED", "OVERLAY", "ORG (tenant)"
            );
            println!(
                "{:<14} {:<9} {:<8} {:<9} {:<26} {}",
                config::PRIMARY_ORG_LABEL,
                "yes",
                "yes",
                cfg.primary_overlay_mode().wire(),
                cfg.tenant_id,
                cfg.server_url
            );
            for o in &cfg.orgs {
                println!(
                    "{:<14} {:<9} {:<8} {:<9} {:<26} {}",
                    o.label,
                    "",
                    if o.enabled { "yes" } else { "no" },
                    o.overlay_mode.wire(),
                    o.tenant_id,
                    o.server_url
                );
            }
            let problems = cfg.validate_orgs();
            for p in problems {
                eprintln!("warning: {p}");
            }
            // Say it once, in words, for the case the column exists to catch.
            // A table column is only read by someone who already suspects the
            // answer is there; this line reaches the operator who does not.
            let dark: Vec<&str> = cfg
                .orgs
                .iter()
                .filter(|o| o.enabled && o.overlay_mode == config::OrgOverlayMode::Off)
                .map(|o| o.label.as_str())
                .collect();
            if !dark.is_empty() {
                println!();
                println!(
                    "note: {} enrolled but NOT on the mesh (overlay off): {}",
                    dark.len(),
                    dark.join(", ")
                );
                println!(
                    "      `roomlerd org overlay <label> netstack|tun` joins one; \
                     restart the daemon to apply."
                );
            }
            return Ok(());
        }
        OrgAction::Rm { label } => {
            if label == config::PRIMARY_ORG_LABEL {
                bail!(
                    "the primary enrollment cannot be removed — `org set-primary <label>` \
                     another org first (or re-`enroll --replace`)"
                );
            }
            let before = cfg.orgs.len();
            cfg.orgs.retain(|o| o.label != label);
            if cfg.orgs.len() == before {
                bail!("no org labelled {label:?} — see `roomlerd org ls`");
            }
            println!(
                "Removed org {label:?} from this machine. NOTE: the device row in that \
                 org remains until one of its admins removes it (Devices page)."
            );
        }
        OrgAction::Enable { label } => set_org_enabled(&mut cfg, &label, true)?,
        OrgAction::Disable { label } => set_org_enabled(&mut cfg, &label, false)?,
        OrgAction::SetPrimary {
            label,
            demoted_label,
        } => {
            let done = config::promote_org_to_primary(&mut cfg, &label, demoted_label.as_deref())?;
            let demoted = &done.demoted_label;
            println!(
                "Org {label:?} is now the PRIMARY enrollment; the previous primary moved \
                 into [[orgs]] as {demoted:?}."
            );
            println!(
                "Mesh: the primary is {}; {demoted:?} is {}.",
                if done.primary_on {
                    "on (its own OS TUN)"
                } else {
                    "off"
                },
                done.demoted_mode.wire()
            );
            if done.primary_was_netstack {
                println!(
                    "  {label:?} was on the mesh through the userspace netstack, which a \
                     primary cannot take from config: `meshharbor config set overlay_enabled \
                     true` puts it on its own OS TUN instead."
                );
            }
            if done.demoted_lost_mesh {
                println!(
                    "  {demoted:?} was on the mesh as the primary and cannot stay on it as \
                     `tun` (that needs `overlay_multi_org` and the primary's control plane): \
                     `roomlerd org overlay {demoted} netstack` keeps it on through the \
                     userspace stack."
                );
            }
            println!("Restart the daemon to apply.");
        }
        OrgAction::Overlay { label, mode } => {
            roomlerd::org_join::set_org_overlay(&mut cfg, &label, &mode)?
        }
    }
    config::save(config_path, &cfg).context("saving config")?;
    Ok(())
}

/// Multi-org P1 — one runnable secondary enrollment's spawn bundle: the
/// config entry, its pre-minted [`signaling::OrgCtx`], the connected flag
/// its `ConnectedGuard` flips, and the terminal-error slot its supervisor
/// writes (the latter two are the SAME instances seeded into the LocalAPI
/// org-status registry).
type OrgSpawn = (
    config::OrgEntry,
    signaling::OrgCtx,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    std::sync::Arc<std::sync::Mutex<Option<String>>>,
);

/// Flip a secondary org's soft-enable flag (see [`org_cmd`]).
fn set_org_enabled(cfg: &mut config::AgentConfig, label: &str, enable: bool) -> Result<()> {
    if label == config::PRIMARY_ORG_LABEL {
        bail!(
            "the primary enrollment is always enabled — use `org set-primary <label>` \
             to change which enrollment is primary"
        );
    }
    let Some(entry) = cfg.orgs.iter_mut().find(|o| o.label == label) else {
        bail!("no org labelled {label:?} — see `roomlerd org ls`");
    };
    entry.enabled = enable;
    println!(
        "Org {label:?} {}. Restart the daemon to apply.",
        if enable { "enabled" } else { "disabled" }
    );
    Ok(())
}

/// True if virtual-desktop mode was requested (`ROOMLERD_VIRTUAL_DESKTOP`).
/// The one copy is `virtual_desktop::requested` (the indicator and the
/// recorder ask it too).
fn virtual_desktop_requested() -> bool {
    roomlerd::virtual_desktop::requested()
}

/// Linux: if requested, bring up the virtual desktop, point capture at it via
/// `DISPLAY`, and — only on a hostile-NAT host with no public IPv4 — auto-enable
/// relay-over-TCP media (WSL / corp NAT flap the UDP TURN relay otherwise; a
/// public-IP server uses normal ICE). Returns a handle to keep alive for the
/// process lifetime. Config comes from env (`ROOMLERD_VIRTUAL_DESKTOP_*`).
#[cfg(target_os = "linux")]
fn maybe_start_virtual_desktop() -> Result<Option<virtual_desktop::VirtualDesktop>> {
    if !virtual_desktop_requested() {
        return Ok(None);
    }
    let startup = node_env("VIRTUAL_DESKTOP_STARTUP")
        .map(|s| {
            s.split(',')
                .map(|a| a.trim().to_string())
                .filter(|a| !a.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let cfg = virtual_desktop::Config {
        resolution: node_env("VIRTUAL_DESKTOP_RESOLUTION")
            .unwrap_or_else(|| "1920x1080".to_string()),
        wm: node_env("VIRTUAL_DESKTOP_WM").unwrap_or_else(|| "openbox".to_string()),
        startup,
    };
    let vd = virtual_desktop::start(&cfg).context("starting virtual desktop")?;
    // Point capture at the virtual display + (by default) pin media to TURNS/TCP.
    // Set here (early in `run_cmd`, before the agent spawns its session tasks) so
    // the caps/display probe and every later capture see it. `set_var` is
    // `unsafe` in edition 2024; sound here because nothing else reads these vars
    // yet.
    //
    // vd-mode auto-pins media to TURNS/TCP ONLY on a hostile-NAT host (WSL /
    // corp laptop), whose default NAT flaps the UDP TURN relay. A host with a
    // routable PUBLIC IPv4 (cloud VM, dedicated server) uses normal ICE instead:
    // forcing TURNS/TCP-only there wastes the direct path AND, against a
    // co-located / dual-public-IP coturn, can strand ICE with no usable
    // candidate ("pingAllCandidates: no candidate pairs"). Either way an operator
    // overrides with an EXPLICIT `ROOMLERD_ICE_RELAY_TCP=0|1` (`=1` on a
    // cloud-NAT VM whose public IP isn't on a local iface; `=0` for WSL
    // mirrored-mode with native UDP).
    let relay_forced = node_env_os("ICE_RELAY_TCP").is_some();
    let host_public = roomlerd::subnet_detect::host_has_public_ipv4();
    unsafe {
        std::env::set_var("DISPLAY", vd.display());
        if !relay_forced && !host_public {
            tunnel_core::env::test_env::set_as("ROOMLERD_", "ICE_RELAY_TCP", "1");
        }
    }
    let relay_over_tcp = node_env("ICE_RELAY_TCP").as_deref() == Some("1");
    tracing::info!(
        display = vd.display(),
        relay_over_tcp,
        host_public_ipv4 = host_public,
        "virtual-desktop active — capturing it"
    );
    Ok(Some(vd))
}

/// Resolves when the OS asks this process to stop — SIGTERM on Unix.
///
/// This is the signal every *deliberate* stop uses: `systemctl stop` and
/// `systemctl restart`, `launchctl kickstart -k` and `launchctl bootout`, a
/// `dpkg`/`.pkg` upgrade replacing the binary, a reboot, and the FR-43 macOS
/// supervisor handing its worker back. None of those are the agent failing.
///
/// It was **not handled at all** until 2026-08-31 (#1040): the shutdown select
/// waited on `tokio::signal::ctrl_c()`, which on Unix is SIGINT only, under a
/// comment that claimed "Ctrl-C / SIGTERM". A SIGTERM therefore killed the
/// process outright, `last_run_unhealthy` stayed `true` on disk, and the next
/// start counted a crash. Three of those inside `CRASH_WINDOW_SECS` while the
/// running version had not yet been promoted to last-known-good — i.e. inside
/// the first `CLEAN_RUN_THRESHOLD_SECS` after an update — trip
/// `should_rollback` and **downgrade the host**. Measured on the MacBook: two
/// `launchctl kickstart -k`s inside the window took `crash_count` 0 → 1 with
/// `previous run did not reach clean-run threshold — counting as crash`, and
/// the FR-43 supervisor (which cycles a worker in seconds) reproduced the full
/// chain to `rollback installer downloaded — spawning + exiting`.
///
/// Windows has no SIGTERM. Its deliberate stop arrives as an SCM
/// Stop / Preshutdown, which the service host turns into a signal on a named
/// event and hands this worker as `--stop-event <name>` (#1683). When that
/// `stop_event` is set, this waits on the event; when it fires, the OS-initiated
/// arm runs and an ephemeral device self-unenrolls, exactly as a Unix SIGTERM
/// makes it. Without a name (the per-user Scheduled Task install, or a hand-run
/// `meshharbord run`) it waits on the process's own per-user event, keyed by
/// `config_path`, which `meshharbord service stop` signals, and on Windows ending
/// the session, which a hidden window hears (FR-97 P4d). Before P4d it never
/// resolved there: `schtasks /End` and the session's end killed such a daemon
/// without a word.
async fn terminate_signal(stop_event: Option<&str>, config_path: &Path) {
    #[cfg(unix)]
    {
        let _ = (stop_event, config_path);
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                sigterm.recv().await;
            }
            Err(e) => {
                // Never installed ⇒ never fires. Say so once: the
                // consequence is silent (deliberate stops go back to
                // looking like crashes), which is exactly the failure
                // mode #1040 was about.
                tracing::warn!(
                    error = %e,
                    "could not install a SIGTERM handler; a service stop will be counted as a crash"
                );
                std::future::pending::<()>().await;
            }
        }
    }
    #[cfg(windows)]
    {
        match stop_event {
            Some(name) => {
                // Polls the event on the runtime — never a blocking task. The
                // other arms of this `select!` win by dropping this future, and
                // `main()` then drops the runtime, which waits for every
                // `spawn_blocking` task to RETURN: a blocking wait here would
                // have held process exit hostage on every non-SCM exit (an
                // auto-update, a requested restart). Dropping the poll closes
                // the handle and leaves nothing behind
                // (`stop_event::wait_for_stop_event`).
                match roomlerd::win_service::stop_event::wait_for_stop_event(name).await {
                    Ok(()) => {
                        tracing::info!(
                            "service host requested a graceful stop (stop event signaled)"
                        );
                    }
                    Err(e) => {
                        // Could not open/probe the event — degrade to today's
                        // behaviour: never fire this arm, let the host's bounded
                        // wait time out into TerminateProcess. Do NOT treat this
                        // as a stop, or we would fabricate a self-unenroll.
                        tracing::warn!(
                            error = %e,
                            "could not wait on the SCM stop event; a service stop will fall back \
                             to TerminateProcess (an ephemeral device may not self-unenroll)"
                        );
                        std::future::pending::<()>().await;
                    }
                }
            }
            // FR-97 P4d — no service host: a per-user daemon (the Scheduled
            // Task install, or a hand-run `run`) holds its own event, keyed by
            // its config, which `meshharbord service stop` signals; and a hidden
            // window turns Windows ending the session (sign-out, shutdown) into
            // the same stop. Same arm, and so the same ephemeral self-unenroll,
            // as the SCM host's event; before P4d nothing but `schtasks /End`
            // or the session's end stopped such a daemon, and neither told it.
            None => {
                use roomlerd::win_service::{session_end, stop_event};
                session_end::watch();
                let channel =
                    stop_event::user_stop_channel(&instance_lock::instance_id(config_path));
                match stop_event::wait_for_user_stop(channel, session_end::ending).await {
                    stop_event::UserStop::Asked => {
                        tracing::info!(
                            "`meshharbord service stop` asked this per-user daemon to stop"
                        );
                    }
                    stop_event::UserStop::SessionEnd(kind) => {
                        tracing::info!(?kind, "Windows is ending the session");
                    }
                }
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (stop_event, config_path);
        std::future::pending::<()>().await;
    }
}

/// How `run` terminates when another process already owns the
/// single-instance lock.
///
/// Linux and Windows exit with a sentinel their supervisor recognises
/// (`RestartPreventExitStatus` in the units; `ExitReaction::Stop` in
/// `win_service::supervisor`). macOS exits 0, which is already the
/// "don't relaunch me" signal for launchd's
/// `KeepAlive{SuccessfulExit:false}` — emitting the sentinel there would
/// *create* the loop it fixes elsewhere.
///
/// The full per-platform reasoning lives on
/// [`watchdog::ALREADY_RUNNING_EXIT_CODE`] — read it before changing an
/// arm, because the platforms want literally opposite exit codes here.
#[cfg(any(target_os = "linux", windows))]
fn already_running_exit() -> Result<()> {
    // Diverges. The stderr line above and the sync stdout tracing layer
    // have already emitted; only the non-blocking FILE layer can lose
    // its copy, which is the same trade `signaling.rs` makes when it
    // exits with `AGENT_DELETED_EXIT_CODE`.
    std::process::exit(watchdog::ALREADY_RUNNING_EXIT_CODE)
}

#[cfg(not(any(target_os = "linux", windows)))]
fn already_running_exit() -> Result<()> {
    Ok(())
}

/// Probe the two macOS grants AT STARTUP and say what is missing.
///
/// Both checks already existed but were lazy — Screen Recording fired when a
/// controller first connected, Accessibility on the first injected event. By
/// then the operator is already staring at a black screen or a dead mouse, and
/// the explanation is in a log file under /tmp that nothing points them at.
/// Neither failure produces an OS error: macOS returns wallpaper-only frames
/// and swallows CGEventPost, silently, forever.
///
/// Requesting (rather than only probing) has a side effect worth having: it
/// registers the app in the relevant Settings pane, so granting is one toggle
/// instead of hunting for a "+" button. The answer lands asynchronously, hence
/// "restart" rather than "retry".
#[cfg(target_os = "macos")]
fn macos_permission_preflight() {
    let capture = tcc::screen_recording_granted() || tcc::request_screen_recording();
    let input = tcc::accessibility_trusted() || tcc::request_accessibility();

    if capture && input {
        tracing::info!("macOS permissions: Screen Recording + Accessibility both granted");
        return;
    }

    if !capture {
        tracing::warn!(
            "macOS Screen Recording is NOT granted — the remote screen will be blank \
             (macOS delivers wallpaper-only frames rather than failing). Grant it under \
             System Settings → Privacy & Security → Screen Recording."
        );
        tcc::open_settings_pane(tcc::PANE_SCREEN_RECORDING);
    }
    if !input {
        tracing::warn!(
            "macOS Accessibility is NOT granted — remote keyboard and mouse will do nothing \
             (macOS drops injected events rather than failing). Grant it under \
             System Settings → Privacy & Security → Accessibility."
        );
        tcc::open_settings_pane(tcc::PANE_ACCESSIBILITY);
    }
    tracing::warn!(
        "after granting, restart the agent: launchctl kickstart -k gui/$(id -u)/com.roomler.agent"
    );
}

/// The daemon. `Ok(Some(code))` = it ended through the graceful path a
/// requested restart (FR-84 D3, `Request::RestartDaemon`) started, and the
/// process must leave with `code` for its supervisor to relaunch it;
/// `Ok(None)` = every other clean end.
async fn run_cmd(
    config_path: &PathBuf,
    cli_encoder: Option<&str>,
    supervised: bool,
    supervisor_flag: Option<&str>,
    // #1683 (Windows) — the SCM host's stop event, waited on by
    // `terminate_signal`. `None` on every non-service run and every other
    // platform.
    stop_event: Option<&str>,
) -> Result<Option<i32>> {
    // FR-84 D3 — this process's own clock, for the restart verb's uptime rule.
    let process_started = std::time::Instant::now();
    if !config_path.exists() {
        bail!(
            "no config found at {}. Run `meshharbord enroll` first.",
            config_path.display()
        );
    }
    // Take the single-instance lock before doing anything else. If
    // another agent is already attached to this config (typically the
    // Scheduled Task / systemd unit launched at logon), exit cleanly
    // instead of fighting it for the WS connection. Only `run` gates
    // on the lock — `enroll`, `service install`, `caps`, `displays`,
    // `encoder-smoke`, `self-update` are intentionally runnable
    // alongside an active agent.
    let _instance_lock =
        match instance_lock::acquire(config_path).context("acquiring single-instance lock")? {
            instance_lock::AcquireOutcome::Acquired(g) => g,
            instance_lock::AcquireOutcome::AlreadyRunning => {
                // FR-97 P6e (#1538) — never `eprintln!`: on a failing stderr it
                // panics, and this benign exit became a crash on a Mac.
                logging::say_on_stderr(
                    "Another roomlerd is already running for this config; exiting.\n\
                 (use `meshharbord service status` to check the auto-start hook,\n\
                 or stop the running instance before starting a new one.)",
                );
                tracing::warn!("single-instance lock held by another process; exiting");
                return already_running_exit().map(|()| None);
            }
        };
    // FR-97 P0e — from here this process IS the daemon, so what it leaves in
    // the host is its own to purge once the runtime is gone
    // (`purge_after_daemon`). Never before the lock: on macOS a second
    // `run` returns through `main` (no `process::exit` there), and would
    // otherwise purge the RUNNING daemon's exit routes and pins.
    DAEMON_RAN.store(true, std::sync::atomic::Ordering::SeqCst);
    // Up to 0.4.126 a tarball install left /usr and the unit directories
    // another account's (tarball_owner.rs). A host that is already damaged
    // updates through its OLD updater, which never looks at a directory, so
    // only this daemon's own start reaches it. Root only; a dozen fstats on a
    // healthy host. After the lock, so one daemon does it.
    #[cfg(target_os = "linux")]
    roomlerd::tarball_owner::repair_at_start();
    // GHSA-r3xj-4wh9-xh2v — the Windows twin: a per-download staging dir a
    // prior update's watcher left behind. Swept once here, behind the same
    // lock, before any update task runs — see the function's doc comment for
    // why it must NOT run on every download instead.
    #[cfg(target_os = "windows")]
    roomlerd::updater::sweep_stale_update_staging_at_start();
    // FR-93 P5 (#2144) — a per-user unit enabled before it was wanted by the
    // graphical session is enabled again, so the next login starts it: it stops
    // with the session (`PartOf=`), and a user manager that outlives a logout
    // never reaches `default.target` twice. Per-user only, on its own thread.
    roomlerd::service::repair_session_wants_at_start();
    let mut cfg = config::load(config_path).context("loading config")?;
    // FR-90 P2k-4 (F4) — an archive replica enrolled before its posture
    // joined the mesh joins it at its first start in a newer image, before
    // anything reads the overlay keys (the WG key is minted below from them).
    if roomlerd::archive_replica::reconcile_at_start(
        &mut cfg,
        std::env::var(roomlerd::archive_replica::IMAGE_ENV).is_ok_and(|v| v == "1"),
    ) {
        match config::save(config_path, &cfg) {
            Ok(()) => tracing::info!(
                "archive replica: joined the mesh, in the userspace stack (FR-90 P2k-4)"
            ),
            Err(e) => tracing::warn!(
                error = %e,
                "archive replica: on the mesh for this run; persisting it failed, so the \
                 next start in the image joins it again"
            ),
        }
    }

    // FR-84 D3 — who will relaunch this process if it exits, decided once,
    // from evidence the supervisor left (argv, environment, cgroup) — never
    // from the config file. `none` is the answer for a hand-run `roomlerd
    // run`, and it is the one that makes "Apply now" refuse instead of
    // taking the device offline.
    let supervision = roomlerd::supervision::detect_here(supervisor_flag, supervised);
    tracing::info!(
        supervisor = supervision.wire(),
        detail = ?supervision,
        "supervision: who relaunches this daemon if it exits (FR-84 D3)"
    );

    #[cfg(target_os = "macos")]
    macos_permission_preflight();

    // S2 — env→config bridge: publish the config-backed fallbacks for the
    // operator-grade env knobs BEFORE anything reads them (the auto-update
    // gate below and every overlay/tunnel runtime consult
    // `tunnel_core::env::node_env`, whose precedence is env — either
    // prefix — > these fallbacks > built-in default). Bools map to the
    // "1"/"0" strings every read-site parser already accepts.
    {
        // FR-93 P1 — built by `config::env_fallbacks`, the one place, so the
        // smoke commands publish exactly the map the daemon runs on.
        let fallbacks = config::env_fallbacks(&cfg);
        if !fallbacks.is_empty() {
            tracing::info!(keys = ?fallbacks.keys().collect::<Vec<_>>(),
                "config-backed env fallbacks registered");
            tunnel_core::env::register_config_fallbacks(fallbacks);
        }
        // R4 — record the PRIMARY enrollment's tenant so the tunnel plane
        // can resolve the right DERP mux for the quic-derp-v1 flavor
        // (declared routes are primary-org-scoped by the reconciler).
        #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
        let _ = roomlerd::overlay::PRIMARY_TENANT_ID.set(cfg.tenant_id.clone());
    }

    // ICE env bridge: the media-ICE hatches live in the VENDORED webrtc-ice
    // crate, which reads raw `ROOMLER_ICE_*` env vars (it cannot depend on
    // tunnel-core's `node_env` — dependency cycle), so the config fallback
    // map above never reaches them. Bridge config → process env here, but
    // only when the operator hasn't set the var (machine/user env wins —
    // note: per-service SCM Environment-block vars do NOT reach the default
    // user-context worker's token env block, only SystemContext workers, so
    // on default hosts these config keys are effectively authoritative).
    // SAFETY: same precedent as the DISPLAY/ICE_RELAY_TCP set_var block in
    // virtual-desktop startup — runs before any session/ICE task exists.
    {
        let ice_keys: [(&str, Option<String>); 3] = [
            (
                "ROOMLER_ICE_FOLLOW_RENOMINATION",
                cfg.ice_follow_renomination
                    .map(|b| if b { "1" } else { "0" }.to_string()),
            ),
            (
                "ROOMLER_ICE_WARM_STANDBY",
                cfg.ice_warm_standby
                    .map(|b| if b { "1" } else { "0" }.to_string()),
            ),
            (
                "ROOMLER_ICE_OVERLAY_HOST_DEPRIORITIZE",
                cfg.ice_overlay_host_deprioritize
                    .map(|b| if b { "1" } else { "0" }.to_string()),
            ),
        ];
        let mut set = 0u32;
        for (var, value) in ice_keys {
            if let Some(v) = value
                && std::env::var_os(var).is_none()
            {
                unsafe { std::env::set_var(var, &v) };
                set += 1;
            }
        }
        if set > 0 {
            tracing::info!(count = set, "ice env bridge: set vars from config");
        }
    }

    // rc.18: run explicit config-schema migration. New fields default
    // via serde at deserialize time, but the on-disk file isn't
    // rewritten — operators reading config.toml would see partial
    // contents. `migrate` stamps `config_schema_version`, trims the
    // server_url, resets cross-branch crash counters, and signals the
    // caller (us, here) to persist if anything actually changed.
    if config::migrate(&mut cfg) {
        if let Err(e) = config::save(config_path, &cfg) {
            tracing::warn!(error = %e, "config migration succeeded but persist failed; in-memory config still up-to-date");
        } else {
            tracing::info!(
                schema_version = %config::CURRENT_SCHEMA_VERSION,
                "config migrated and persisted"
            );
        }
    }

    // rc.162: virtual-desktop mode (Linux) — bring up a headless Xvfb desktop
    // + WM the agent captures, so a Linux/WSL node becomes a browser-remotable
    // desktop. WSLg's own display can't be screen-grabbed (rootless XWayland),
    // so we spawn a dedicated one. The handle is kept alive for the process
    // lifetime; its Drop tears the desktop down.
    #[cfg(target_os = "linux")]
    let _virtual_desktop = maybe_start_virtual_desktop()?;
    #[cfg(not(target_os = "linux"))]
    if virtual_desktop_requested() {
        tracing::warn!("virtual-desktop mode is Linux-only — ignoring on this platform");
    }

    // FR-19 P1d — the org-relay reachability responder. Process-wide and
    // started once (one UDP socket), so deliberately NOT inside the per-org
    // `overlay::maybe_start`. Opt-in and default off: a device that has not
    // set `relay_server_enabled` binds nothing and logs nothing.
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    roomlerd::relay_server::maybe_start().await;

    // Phase 3b: generate + persist this node's WireGuard identity on the
    // first overlay-enabled startup. The public key is what the netmap
    // distributes; the secret never leaves the host. Kept here (not in
    // `migrate`) so `config.rs` stays free of the overlay feature dep. Gated on
    // ANY overlay surface — the netstack (`overlay-netstack`) needs the WG key
    // just as much as the OS-TUN path (`overlay-l3`); an `overlay-l3`-only gate
    // meant a netstack-only build never generated a key and never joined.
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    if cfg.overlay_enabled && cfg.overlay_wg_secret_key.is_none() {
        let kp = tunnel_core::overlay::WgKeypair::generate();
        cfg.overlay_wg_secret_key = Some(kp.secret_base64());
        match config::save(config_path, &cfg) {
            Ok(()) => tracing::info!("overlay: generated + persisted node WireGuard key"),
            Err(e) => tracing::warn!(error = %e, "overlay: failed to persist WG key"),
        }
    }

    // #2493 — a secondary in `netstack` mode joins only with a loopback port
    // of its own. One enrolled before the fix has none and joined nothing, so
    // it gets the first free port now, persisted like the key above.
    #[cfg(feature = "overlay-netstack")]
    if roomlerd::org_join::heal_netstack_ports(&mut cfg)
        && let Err(e) = config::save(config_path, &cfg)
    {
        tracing::warn!(error = %e, "overlay: failed to persist the netstack orgs' SOCKS ports");
    }

    // Roomler SSH (P2) — mint this node's SSH host identity on the first
    // SSH-enabled start, same shape as the WG key above: generated locally,
    // persisted through `config::save` (atomic + fsync + `.prev` + 0600 / ACL),
    // never transmitted. A device that never enables SSH never generates one.
    //
    // Failing to persist is FATAL to the feature rather than merely logged: a
    // host key that changes on every boot trains operators to accept unknown
    // fingerprints, which is precisely the habit that makes SSH host
    // verification worthless. Better to serve nothing than to serve a new
    // identity every restart.
    // ⚠️ The condition is "not USABLE", not "absent". A key that is present but
    // unparseable is the state this guard used to walk straight past, and it is
    // strictly worse than having none: the daemon refuses to serve SSH (right)
    // and publishes no host pubkey (right), and then never mints a replacement —
    // so the device is wedged permanently and every restart repeats the same
    // warning into a log nobody reads. Found in the field on a 0.4.96 corp
    // laptop whose stored PEM had picked up literal `\r` escape text; see
    // `ssh::stored_host_key_is_usable`.
    //
    // Replacing it is safe precisely BECAUSE it was unreadable: the daemon never
    // served with it and never published it, so no client ever verified against
    // it. There is no identity to preserve — which is what separates this from
    // the "never serve a key that changes every restart" rule below.
    #[cfg(feature = "ssh-server")]
    if cfg.ssh_enabled && !roomlerd::ssh::stored_host_key_is_usable(&cfg) {
        if cfg.ssh_host_key.is_some() {
            tracing::warn!(
                "ssh: the stored host key is unreadable — replacing it. Nothing ever \
                 verified against it (the daemon refused to serve SSH with it), so there \
                 is no identity to preserve"
            );
            cfg.ssh_host_key = None;
        }
        match roomlerd::ssh::generate_host_key() {
            Ok(pem) => {
                cfg.ssh_host_key = Some(pem);
                match config::save(config_path, &cfg) {
                    Ok(()) => tracing::info!("ssh: generated + persisted node SSH host key"),
                    Err(e) => {
                        cfg.ssh_host_key = None;
                        cfg.ssh_enabled = false;
                        tracing::error!(
                            error = %e,
                            "ssh: could not persist the host key — SSH stays OFF this run \
                             rather than serving an identity that changes on every restart"
                        );
                    }
                }
            }
            Err(e) => {
                cfg.ssh_enabled = false;
                tracing::error!(error = %e, "ssh: host key generation failed — SSH stays OFF");
            }
        }
    }

    // P5 exit-node crash-safety (A2) — boot-time stale-route reconciler. Purge
    // any split-default (`/1`) route a PRIOR run left on the overlay NIC after a
    // crash / kill / unclean reboot, BEFORE the overlay runtime can (re)install a
    // fresh one. Runs regardless of `overlay_enabled` so a host whose exit
    // routing was active when it died — then had overlay disabled — is still
    // healed (else a persisted Windows Wintun `/1` blackholes egress to a dead
    // NIC until reboot). No-op on non-`overlay-l3` builds.
    roomlerd::purge_exit_routes();

    let encoder_preference = resolve_encoder_preference(cli_encoder, cfg.encoder_preference);
    // FR-84 D4 — publish the RESOLVED preference, so the LocalAPI reports
    // what is in force (a CLI flag or env var may have overridden the config).
    encode::set_resolved_preference(encoder_preference);

    // Wire the file-DC v2 `files:dir` browse capability. Default
    // tracks `cfg.enable_remote_browse` (true unless the operator
    // disabled it in config.toml); env var
    // `ROOMLERD_DISABLE_BROWSE=1` is an escape hatch for
    // emergency in-field disable without a config reload.
    let browse_enabled = cfg.enable_remote_browse
        && !matches!(
            node_env("DISABLE_BROWSE").as_deref(),
            Some("1") | Some("true") | Some("yes")
        );
    roomlerd::files::set_remote_browse_enabled(browse_enabled);
    tracing::info!(browse_enabled, "file-DC remote browse capability");

    // FR-84 D4 — where dropped files land. The raw value is seeded here and
    // re-seeded by the LocalAPI `ConfigSet`; every transfer validates it for
    // the identity doing the writing and the user logged in at that moment,
    // and falls back to the Downloads ladder (with a warning) when it fails.
    roomlerd::files::set_files_dir(cfg.files_dir.clone());
    tracing::info!(
        files_dir = ?cfg.files_dir,
        "file-DC drop folder (unset = the active user's Downloads)"
    );

    // Remote app selection & launch (virtual-desktop hosts). Same
    // process-global install as the browse flag above; the caps builder's
    // `apps::apps_supported()` additionally gates on VD mode (a DISPLAY
    // being set), so this is inert on non-VD hosts.
    roomlerd::apps::set_apps_config(cfg.virtual_desktop_apps.clone());
    tracing::info!(
        apps_enabled = cfg.virtual_desktop_apps.enabled,
        apps_allowlist = cfg.virtual_desktop_apps.allowlist.len(),
        "remote app-launch capability"
    );

    // M3 A1 worker-role probe (perMachine MSI builds with the
    // `system-context` feature only). Reads the worker's own primary
    // token at startup and decides whether downstream plumbing
    // should use the User-mode or SystemContext-mode trees. Logged
    // here so the field can correlate "supervisor said spawn
    // SystemContext" with "worker actually probed SystemContext"
    // in a single grep across the persistent log file.
    //
    // Failure mode: documented infallible against the calling
    // process's own token; on impossible-error we default to User
    // (matches the pre-M3 behaviour). The error is logged at warn
    // so the next pass through the supervisor flags it.
    #[cfg(all(feature = "system-context", target_os = "windows"))]
    let worker_role = match roomlerd::system_context::worker_role::probe_self() {
        Ok(role) => {
            tracing::info!(?role, "worker role probed");
            role
        }
        Err(e) => {
            tracing::warn!(error = %e, "worker role probe failed — defaulting to User");
            roomlerd::system_context::worker_role::WorkerRole::User
        }
    };
    #[cfg(all(feature = "system-context", target_os = "windows"))]
    let _ = worker_role; // M3 A1 follow-up commits wire this into capture/input/lock_state.

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        path = %config_path.display(),
        server = %cfg.server_url,
        agent_id = %cfg.agent_id,
        ?encoder_preference,
        "agent starting"
    );

    // Phase 8: pre-flight diagnostics (DNS / TCP / clock-skew). Non-
    // blocking — the signaling loop runs unconditionally afterward —
    // but logs an actionable hint up front so the operator doesn't
    // chase the wrong rabbit hole when the WS reconnect ladder kicks
    // in. 15 s overall budget, 5 s per probe in parallel.
    let preflight_report = preflight::run_checks(&cfg.server_url).await;
    preflight_report.log();

    // Crash-loop bookkeeping: if the previous run was marked
    // `last_run_unhealthy=true` (started, never reached the clean
    // threshold, never exited gracefully) → count it as a crash. Then
    // mark THIS run as tentatively unhealthy; either the 5-min healthy
    // task or the Ctrl-C handler will flip the flag back to false.
    // Save before checking for rollback so the worst-case state is
    // durable on disk if we then crash again.
    let now_unix = unix_now();
    let current_pkg = env!("CARGO_PKG_VERSION");
    if cfg.last_run_unhealthy {
        config::record_crash_at(&mut cfg, now_unix);
        tracing::warn!(
            crash_count = cfg.crash_count,
            "previous run did not reach clean-run threshold — counting as crash"
        );
    }
    config::mark_run_starting(&mut cfg);
    if let Err(e) = config::save(config_path, &cfg) {
        tracing::warn!(error = %e, "could not persist crash-tracking state");
    }

    // If the crash counter has tripped the rollback threshold AND we
    // have a known-good fallback to roll back TO that isn't this same
    // version, raise an attention sentinel. v1 does NOT auto-execute
    // the rollback install — that requires fetching a specific tag's
    // installer and ships in 0.1.52 alongside the SHA256 / HMAC
    // manifest work. The operator can downgrade manually via
    // `roomlerd self-update --pin <version>` (also 0.1.52) or
    // by reinstalling the previous MSI by hand.
    if config::should_rollback(&cfg, current_pkg, now_unix)
        && let Some(target) = cfg.last_known_good_version.clone()
    {
        let target_tag = format!("agent-v{target}");
        tracing::error!(
            current = %current_pkg,
            target = %target_tag,
            crash_count = cfg.crash_count,
            "crash loop detected; attempting automatic rollback"
        );
        // Mark attempted FIRST so a crash during the rollback
        // itself doesn't loop us back into another rollback. If the
        // rollback fetch / install fails, the operator still gets
        // the attention sentinel below and can act manually.
        config::mark_rollback_attempted(&mut cfg);
        let _ = config::save(config_path, &cfg);

        let outcome = updater::pin_version(&target_tag).await;
        match outcome {
            updater::CheckOutcome::UpdateReady {
                latest,
                installer_path,
                ..
            } => {
                tracing::warn!(
                    target = %latest,
                    path = %installer_path.display(),
                    "rollback installer downloaded — spawning + exiting"
                );
                if let Err(e) = updater::spawn_installer_with_watch(&installer_path, Some(&latest))
                {
                    tracing::error!(error = %e, "rollback installer spawn failed");
                    let _ = notify::raise_attention_with_reason_for_version(
                        notify::REASON_ROLLBACK,
                        &rollback_attention_msg(
                            current_pkg,
                            &target,
                            cfg.crash_count,
                            Some(&format!("automatic install failed: {e}")),
                        ),
                        // FR-53: the build being accused, so a later
                        // healthy connect from a different one can clear this.
                        Some(current_pkg),
                    );
                } else {
                    // Installer is running, agent is about to exit.
                    // The post-install watcher (spawned by
                    // spawn_installer_with_watch) will record the
                    // verdict in last-install.json; the new binary
                    // can surface it on next start.
                    return Ok(None);
                }
            }
            updater::CheckOutcome::Skipped(reason) | updater::CheckOutcome::Unreachable(reason) => {
                tracing::error!(%reason, "rollback fetch skipped — operator action required");
                let _ = notify::raise_attention_with_reason_for_version(
                    notify::REASON_ROLLBACK,
                    &rollback_attention_msg(current_pkg, &target, cfg.crash_count, Some(&reason)),
                    Some(current_pkg),
                );
            }
            updater::CheckOutcome::UpToDate { .. } => {
                tracing::warn!(
                    "rollback target reports as up-to-date — odd state, raising sentinel"
                );
                let _ = notify::raise_attention_with_reason_for_version(
                    notify::REASON_ROLLBACK,
                    &rollback_attention_msg(
                        current_pkg,
                        &target,
                        cfg.crash_count,
                        Some("target version reports as up-to-date — manual investigation needed"),
                    ),
                    Some(current_pkg),
                );
            }
        }
    }

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Resolve runtime knobs that depend on `cfg` BEFORE the signaling
    // task moves cfg out of scope. (Moving cfg lets signaling::run own
    // it for the lifetime of the loop without us having to clone the
    // tokens + URLs that the signaling code rewrites in place.)
    let auto_update_enabled = node_env("AUTO_UPDATE")
        .map(|v| !matches!(v.as_str(), "0" | "false" | "no" | "off"))
        .unwrap_or(true);
    let update_interval = updater::resolve_check_interval(&cfg);
    // S1a — forced-update trigger channel (rc:agent.update → run_periodic),
    // installed only when the updater runs: with it off a push reports
    // undeliverable and the arm says so (#1689) — never queues into a
    // receiver nobody reads.
    let update_trigger_rx = updater::install_update_trigger(auto_update_enabled);

    // S1a — bring the roomler-desktop companion EXE up to this daemon's
    // version (it ships outside both MSIs, so self-updates never touched
    // it). Spawn-and-forget; every failure path logs + retries next start.
    // A user-context worker on a perMachine install can't write
    // %ProgramFiles% and skips — the SCM host hook covers that flavour.
    {
        // A SystemContext worker (LocalSystem) exists only under the
        // `system-context` feature; every other build of `run` executes
        // in a user session.
        #[cfg(all(target_os = "windows", feature = "system-context"))]
        let respawn_ctx = {
            use roomlerd::system_context::worker_role;
            if matches!(
                worker_role::probe_self(),
                Ok(worker_role::WorkerRole::SystemContext)
            ) {
                roomlerd::companion::RespawnContext::SystemService
            } else {
                roomlerd::companion::RespawnContext::UserSession
            }
        };
        #[cfg(not(all(target_os = "windows", feature = "system-context")))]
        let respawn_ctx = roomlerd::companion::RespawnContext::UserSession;

        // FR-84 D6 — after the refresh, in the same task (a launch must never
        // race a swap of the file it launches): the per-user login-start
        // self-heal and the one-shot post-install launch. On Windows a
        // registered SCM service owns both — its host reads this same config,
        // is the one process that can write HKLM, and launches with the
        // console user's own non-elevated token where this worker may hold
        // the elevated one. Everywhere else (the per-user Scheduled Task, the
        // Linux systemd unit) the worker is the launcher.
        // RUNNING, not merely registered: a stopped leftover registration
        // (a per-user install over a half-removed per-machine one) has no
        // host to do it, and this worker must.
        #[cfg(target_os = "windows")]
        let scm_owns_companion = matches!(
            roomlerd::win_service::status(),
            Ok(roomlerd::win_service::InstalledStatus::Running
                | roomlerd::win_service::InstalledStatus::StartPending)
        );
        #[cfg(not(target_os = "windows"))]
        let scm_owns_companion = false;
        let companion_autostart = cfg.companion_autostart;
        let launch_owner =
            (!scm_owns_companion).then(|| roomlerd::companion::LaunchOwner::Worker {
                config_path: config_path.clone(),
                companion_autostart,
                // Read NOW, before this run can promote it five minutes in.
                lkgv_unset: cfg.last_known_good_version.is_none(),
            });
        // #1686 — ONE refresher per install. A worker the SCM host spawned
        // (`run --supervisor scm`) leaves the refresh to that host, which does
        // it at its own start for the install they share; this worker —
        // elevated by default, so it CAN write %ProgramFiles% — used to run
        // the same swap concurrently: measured on the reporting host, its swap
        // 1.4 s after the host's respawn renamed the fresh companion's file.
        // Keyed on WHO spawned this worker, not on "some SCM service runs": a
        // per-user task install beside a running perMachine service still
        // refreshes its own `%LOCALAPPDATA%` companion.
        let host_refreshes_companion =
            matches!(supervision, roomlerd::supervision::Supervision::WindowsScm);
        tokio::spawn(async move {
            if !host_refreshes_companion {
                roomlerd::companion::refresh_if_stale(respawn_ctx).await;
            }
            #[cfg(target_os = "windows")]
            if !scm_owns_companion {
                let _ = tokio::task::spawn_blocking(move || {
                    roomlerd::companion::sync_user_autostart_logged(companion_autostart)
                })
                .await;
            }
            if let Some(owner) = launch_owner {
                roomlerd::companion::launch_once_after_install(owner).await;
            }
            // FR-117 P2 — the refresh again on every tick, so one that failed
            // (a download a middlebox dropped, a companion that would not stop)
            // is retried within hours, not at the next restart. Windows only:
            // on Linux the companion's package moves inside the updater's loop.
            #[cfg(target_os = "windows")]
            if !host_refreshes_companion {
                roomlerd::companion::refresh_periodically(respawn_ctx).await;
            }
        });
    }

    // Install the liveness watchdog. Pumps tick after every iteration;
    // the scan loop force-exits via std::process::exit(STALL_EXIT_CODE)
    // when any pump silently stalls past its threshold, relying on
    // the OS supervisor (Win Scheduled Task with RestartOnFailure /
    // systemd Restart=on-failure / launchd KeepAlive) to relaunch.
    // Encoder + capture are registered but gated off until a session
    // attaches — those pumps can legitimately go idle for hours when
    // no controller is connected.
    //
    // rc.58: `signaling` is registered with `active=false` and only
    // gated `true` after the first successful `connect_async` (inside
    // `signaling::connect_once`). Before rc.58 the pump was active
    // from process start, so the 90 s stall timer counted while the
    // agent was still in initial backoff-reconnect mode against an
    // unreachable server — every cold start against a flaky network
    // got force-exited at 90 s, producing a crash loop. The pump
    // re-toggles to false when each connection ends (the RAII guard
    // in `connect_once`); the next successful connect re-enables it
    // and `gate(true)` resets `last_tick` so each connection gets a
    // clean 90 s budget against the 25 s keepalive cadence.
    // Multi-org P1 — partition `[[orgs]]` into runnable + rejected entries
    // and pre-mint each entry's `OrgCtx` EXACTLY ONCE (its watchdog pump
    // name is interned; the registry rows and the spawned supervisor must
    // share the same instance). Rejects are logged + surfaced via the
    // LocalAPI OrgStatus; they never stop the daemon or the healthy orgs.
    let org_partition = cfg.partition_runnable_orgs();
    // FR-103 — each enrollment's LIVE agent token, minted ONCE like its
    // `OrgCtx`: the loop, its status row, its HTTP identity and (for the
    // primary) the uploaders all share the one slot, so a renewal reaches
    // every one of them. The renewal knobs are read from the environment once.
    let token_renewal = roomlerd::token_renewal::Settings::from_env();
    let primary_token = roomlerd::token_slot::TokenSlot::new(cfg.agent_token.clone());
    let org_ctxs: Vec<signaling::OrgCtx> = org_partition
        .iter()
        .map(|(org, _)| {
            signaling::OrgCtx::secondary(
                &org.label,
                roomlerd::token_slot::TokenSlot::new(org.agent_token.clone()),
            )
            .with_renewal(token_renewal)
        })
        .collect();

    let wd = watchdog::Watchdog::new();
    wd.register("signaling", std::time::Duration::from_secs(90), false);
    // Multi-org P1: one pump per secondary org loop, so one org's healthy
    // ticks can't mask another org's stalled loop.
    for ((org, problem), org_ctx) in org_partition.iter().zip(org_ctxs.iter()) {
        if org.enabled && problem.is_none() {
            wd.register(org_ctx.pump, std::time::Duration::from_secs(90), false);
        }
    }
    wd.register("encoder", std::time::Duration::from_secs(30), false);
    wd.register("capture", std::time::Duration::from_secs(30), false);
    let _ = watchdog::install(wd.clone());
    watchdog::spawn_thread_watchdog(wd.clone());
    let wd_task = tokio::spawn({
        let wd = wd.clone();
        let rx = shutdown_rx.clone();
        async move { watchdog::run(wd, rx, watchdog::force_exit_on_stall).await }
    });

    // rc.19 B1 fix: rebuild the partial-upload registry from disk
    // BEFORE the signaling task spawns. The synchronous await
    // guarantees no DC can carry a `files:resume` message until the
    // registry knows about every surviving `.roomler-partial/<id>/`
    // under Downloads. Sweep also deletes >24h-old orphans. Sweep
    // failure (e.g. Downloads inaccessible under SYSTEM context)
    // logs a debug message and continues — same-process resume via
    // `begin()`-time registry writes still works.
    let (kept, swept) = roomlerd::files::sweep_orphans().await;
    if kept + swept > 0 {
        tracing::info!(kept, swept, "rc19: partial-registry warm-up");
    }

    // Task 9 Phase 1C: drain any crash sidecars left by previous
    // crash-loop iterations. Best-effort + sequential so a fleet
    // reboot doesn't burst the ingest endpoint. Runs in parallel
    // with the signaling loop (no need to gate on first-WS-OK in
    // v1; if the network is offline the HTTP POST fails fast +
    // sidecars stay on disk for the next startup). Snapshots
    // `cfg` BEFORE `signaling::run` consumes it.
    //
    // rc.58: drain runs once at startup AND every CRASH_DRAIN_INTERVAL
    // (5 min) during the run. The startup-only drain leaves sidecars
    // marooned on long-running agents that crashed before connectivity
    // was up — a crash-loop recovered by transient network repair
    // would never deliver its evidence to the admin UI until the next
    // process restart. The periodic loop catches up the moment the
    // network comes back; the HARD_CAP=100 in crash_recorder bounds
    // worst-case disk in the still-offline case.
    let crash_drain_task = tokio::spawn({
        let cfg = cfg.clone();
        let token = primary_token.clone();
        let mut shutdown = shutdown_rx.clone();
        async move {
            // Initial drain (formerly the only call site).
            crash_uploader::drain_and_upload(&cfg, &token).await;
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                crash_uploader::CRASH_DRAIN_INTERVAL_SECS,
            ));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await; // swallow immediate first tick
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        crash_uploader::drain_and_upload(&cfg, &token).await;
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            return;
                        }
                    }
                }
            }
        }
    });

    // 2026-07-27 — heal GPU clocks a crashed predecessor left pinned: the
    // session-scoped pin resets on Drop, but a SIGKILL'd/crashed agent never
    // runs Drop. No-op unless `ROOMLERD_GPU_CLOCK_PIN` is enabled.
    roomlerd::gpu_clock::reset_stale_pins();

    // rc.58 — start the centralized log uploader BEFORE signaling
    // moves cfg out of scope. Default ON; opt out with
    // `ROOMLERD_LOGS_UPLOAD_DISABLED=1` per the rc.58 plan.
    let logs_upload_disabled =
        roomlerd::logs_upload::parse_disable_flag(node_env("LOGS_UPLOAD_DISABLED").as_deref());
    if !logs_upload_disabled && let Some(rx) = logging::take_log_upload_receiver() {
        let host_hash = roomlerd::logs_upload::hash_hostname(
            &roomlerd::machine::hostname().unwrap_or_else(|_| "unknown".to_string()),
        );
        let upload_cfg = roomlerd::logs_upload::UploadConfig {
            server_url: cfg.server_url.clone(),
            tenant_id: cfg.tenant_id.clone(),
            agent_id: cfg.agent_id.clone(),
            agent_jwt: primary_token.clone(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            host_id_hash: host_hash,
            source: roomlerd::logs_upload::LogSource::Agent,
        };
        tokio::spawn(roomlerd::logs_upload::run_uploader(rx, upload_cfg));
        tracing::info!(
            tenant_id = %cfg.tenant_id,
            agent_id = %cfg.agent_id,
            "logs upload task spawned (default ON; set ROOMLERD_LOGS_UPLOAD_DISABLED=1 to opt out)"
        );
    } else if logs_upload_disabled {
        tracing::info!("logs upload disabled via ROOMLERD_LOGS_UPLOAD_DISABLED env var");
    }

    // Unification P1 — LocalAPI: expose read-only node / peer / flow state on a
    // local-only pipe (Windows) / socket (unix) so `meshharbor status` and the
    // desktop app can read it without touching the daemon's internals. The
    // connected flag + the overlay-view channel are created HERE so they're
    // stable across WS reconnects (the signaling loop rebuilds the overlay
    // runtime on each reconnect, but publishes into this same channel). The
    // listener runs regardless of the overlay feature — without it `peers()` is
    // simply empty. A bind failure is logged, never fatal.
    //
    // P2b — the operator-consent broker is created HERE (not inside
    // signaling::run) so the LocalAPI's DaemonState shares the SAME instance the
    // signaling loop prompts on; its live `pending` set gates LocalAPI consent
    // decisions (a decision is honoured only for an actively-prompting session).
    let consent_mode = roomlerd::consent::Mode::from_config(cfg.auto_grant_session);
    let consent_dir =
        roomlerd::consent::ConsentBroker::default_sentinel_dir().unwrap_or_else(|e| {
            tracing::warn!(error = %e, "could not resolve consent sentinel dir; using temp dir");
            std::env::temp_dir().join("roomlerd-consent")
        });
    let consent_broker = roomlerd::consent::ConsentBroker::new(consent_mode, consent_dir)
        .unwrap_or_else(|e| {
            // FAIL CLOSED for prompt-mode fleets: keep the CONFIGURED mode on the
            // temp dir rather than downgrading to AutoGrant. A Prompt broker whose
            // dir doesn't match the tray's simply times out → deny (safe), instead
            // of the pre-P2b fail-OPEN that auto-granted every session on a glitch.
            tracing::error!(error = %e, ?consent_mode, "consent broker init failed; retrying on temp dir with the SAME mode (prompt-mode fails closed)");
            roomlerd::consent::ConsentBroker::new(consent_mode, std::env::temp_dir())
                .expect("consent broker init cannot fail with temp_dir")
        });
    tracing::info!(
        mode = ?consent_broker.mode(),
        sentinel_dir = %consent_broker.sentinel_dir().display(),
        "operator-consent broker ready"
    );
    let localapi_connected = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (overlay_view_tx, overlay_view_rx) =
        tokio::sync::watch::channel(tunnel_core::localapi::OverlayView::default());
    // The netstack ICMP backend for `meshharbor ping` — Some only on a node running
    // the userspace stack (netstack mode); None otherwise (OS-TUN / non-overlay).
    #[cfg(feature = "overlay-netstack")]
    let netstack_pinger = roomlerd::overlay::netstack_pinger(&cfg);
    #[cfg(not(feature = "overlay-netstack"))]
    let netstack_pinger: Option<std::sync::Arc<dyn localapi_state::NetstackPinger>> = None;
    // S1b — ONE pinger for BOTH the interactive `Ping` verb and the RTT
    // prober: netstack when the userspace stack runs, OS ICMP fallback
    // otherwise. The verb previously got the raw Option (no fallback)
    // while the prober had one — so the desktop's per-device Ping button
    // errored on EVERY OS-TUN node ("Ping failed" for all devices, the
    // reported field bug) even though the RTT column populated fine.
    let pinger: std::sync::Arc<dyn localapi_state::NetstackPinger> = match netstack_pinger {
        Some(p) => p,
        None => std::sync::Arc::new(localapi_state::OsPinger),
    };
    // P3b-2 PR-C: the tunnel-client hub, created ONCE here (stable across WS
    // reconnects) and SHARED between the LocalAPI's DaemonState (create/kill/
    // flows verbs) and the signaling loop (publish the live egress + demux).
    let tunnel_hub =
        roomlerd::tunnel::client_mgr::TunnelClientHub::new(env!("CARGO_PKG_VERSION").to_string());
    // FR-90 P3-7-3c — the primary enrollment's hub is where an agent
    // session's own egress opens its flows (`net_socks`, `net_forward`).
    tunnel_hub.set_primary();
    // P3b-3: shared RTT cache — filled by the prober task (below), read by
    // `peers()`. Clone the pinger for the prober; the original moves into
    // `DaemonState` for the `ping` verb.
    let rtt_cache: roomlerd::localapi_state::RttCache =
        std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let pinger_for_prober = pinger.clone();
    // P6: the daemon-wide config-WRITE lock. Every daemon-side runtime
    // writer of config.toml (route reconciler, clean-run promotion,
    // graceful shutdown) holds it across load→mutate→save so one writer's
    // full-struct save can't drop another's just-written field.
    let cfg_write_lock: config::WriteLock = std::sync::Arc::new(tokio::sync::Mutex::new(()));
    // Remote config (docs/remote-config.md) — machine-wide, so ONE instance
    // shared by every org loop. Seeds the live `exec_enabled` from the config
    // this daemon actually loaded.
    let remote_cfg = roomlerd::remote_config::RemoteConfigServices::new(
        config_path.clone(),
        cfg_write_lock.clone(),
        cfg.exec_enabled,
        cfg.remote_config_enabled,
    );
    // FR-100 P1c — and every other live key it holds (`peer_auth`), from the
    // same config: a fresh `new` judges offers under `audit` until told.
    remote_cfg.adopt_local(&cfg);
    // FR-90 — the agent-session supervisor, from this start's `hive_*` keys
    // (restart-required). Built with every gate closed too, so a start is
    // answered with the device's actual refusal rather than silence.
    #[cfg(hive_host)]
    {
        roomlerd::hive::init(&cfg);
        // FR-90 P1d-2 — every way the daemon stops signals this first (an
        // update, a requested restart, a rollback, an OS stop), before its
        // connections close: from that moment, what its sessions do is going
        // down with it, and what the device hosts is frozen for the next one.
        let mut stopping = shutdown_rx.clone();
        tokio::spawn(async move {
            while stopping.changed().await.is_ok() {
                if *stopping.borrow() {
                    roomlerd::hive::begin_shutdown();
                    break;
                }
            }
        });
    }
    // P6: the declared-route reconciler — converges `[[tunnel_routes]]`
    // from the loaded config into live hub flows, and backs the LocalAPI
    // Route* verbs (persisting through the write lock).
    let route_reconciler = roomlerd::tunnel::route_reconciler::RouteReconciler::new(
        tunnel_hub.clone(),
        config_path.clone(),
        cfg_write_lock.clone(),
        cfg.tunnel_routes.clone(),
    );
    route_reconciler.spawn(shutdown_rx.clone());
    // Multi-org P1 — the primary loop's context + the per-enrollment status
    // registry `NodeStatus.orgs` reads. Secondary handles (connected flag /
    // terminal-error slot / OrgCtx) are minted here so the registry rows and
    // the spawned supervisors share the SAME instances.
    let primary_ctx = signaling::OrgCtx::primary(primary_token.clone()).with_renewal(token_renewal);
    let mut org_spawns: Vec<OrgSpawn> = Vec::new();
    // Multi-org — every secondary org.s live overlay view, so `peers` can
    // report all orgs (the receivers used to be dropped on the floor).
    let org_views: localapi_state::OrgViewRegistry = Default::default();
    let org_registry: localapi_state::OrgStatusRegistry = {
        let mut rows = vec![localapi_state::OrgRuntime {
            label: config::PRIMARY_ORG_LABEL.to_string(),
            server_url: cfg.server_url.clone(),
            tenant_id: cfg.tenant_id.clone(),
            agent_id: cfg.agent_id.clone(),
            primary: true,
            enabled: true,
            connected: localapi_connected.clone(),
            terminal_error: std::sync::Arc::new(std::sync::Mutex::new(None)),
            updates_ignored: primary_ctx.updates_ignored.clone(),
            overlay_mode: cfg.primary_overlay_mode().wire(),
            token: primary_ctx.token.clone(),
        }];
        for ((org, problem), org_ctx) in org_partition.iter().zip(org_ctxs.iter()) {
            let org_ctx = org_ctx.clone();
            let connected = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let terminal = std::sync::Arc::new(std::sync::Mutex::new(problem.clone()));
            rows.push(localapi_state::OrgRuntime {
                label: org.label.clone(),
                server_url: org.server_url.clone(),
                tenant_id: org.tenant_id.clone(),
                agent_id: org.agent_id.clone(),
                primary: false,
                enabled: org.enabled,
                connected: connected.clone(),
                terminal_error: terminal.clone(),
                updates_ignored: org_ctx.updates_ignored.clone(),
                overlay_mode: org.overlay_mode.wire(),
                token: org_ctx.token.clone(),
            });
            if org.enabled && problem.is_none() {
                org_spawns.push((org.clone(), org_ctx, connected, terminal));
            } else if let Some(p) = problem {
                tracing::warn!(org = %org.label, problem = %p, "skipping invalid [[orgs]] entry");
            }
        }
        if !org_spawns.is_empty() {
            tracing::info!(
                secondary_orgs = org_spawns.len(),
                "multi-org: spawning one signaling loop per enabled secondary enrollment"
            );
        }
        std::sync::Arc::new(std::sync::Mutex::new(rows))
    };
    // FR-84 D5b — the same enrollments' HTTP identities (server URL + agent
    // token), for the LocalAPI `Devices` / `Mesh` verbs the companion's
    // Devices page asks. Seeded from the SAME config rows as the status
    // registry above, so the list is asked with exactly the credential the
    // org's WS loop runs on; an entry the daemon refused to run is disabled.
    let org_http: roomlerd::self_view::OrgHttpRegistry = {
        let mut rows = vec![roomlerd::self_view::OrgHttp::primary(
            &cfg,
            primary_ctx.token.clone(),
        )];
        for ((org, problem), org_ctx) in org_partition.iter().zip(org_ctxs.iter()) {
            rows.push(roomlerd::self_view::OrgHttp::secondary(
                org,
                problem.is_none(),
                org_ctx.token.clone(),
            ));
        }
        std::sync::Arc::new(std::sync::Mutex::new(rows))
    };

    // FR-27 — ONE registry for the whole daemon; each signalling loop stores
    // its own kill channel per session, so a multi-org host routes a Disconnect
    // to the loop that actually owns that session.
    let rc_sessions = roomlerd::rc_sessions::RcSessionRegistry::new();

    // FR-43 P2a — the macOS GUI-worker delegation channel. It opens no socket
    // and hands out nothing until the supervisor spawns a worker: no secret
    // issued and no endpoint bound IS the refusal, so "the feature is off"
    // needs no separate branch.
    #[cfg(target_os = "macos")]
    let delegate_host = roomlerd::delegate::DelegateHost::new();
    // #1882 — the worker serves its OWN sessions too, and runs no overlay, so
    // the daemon tells it the overlay's blocks (`rc_overlay` off needs them).
    #[cfg(target_os = "macos")]
    delegate_host.set_overlay_footprint(tunnel_core::overlay_footprint::v4_nets);

    // FR-55 — keep the device reachable instead of letting it quietly sleep.
    // Default `never`, so on a device that has not opted in this task holds
    // nothing and the behaviour is byte-for-byte what it was before.
    //
    // Separate from the rc registry because that registry is rc-only: an SSH
    // session or a long `exec` deserves the same protection and has no row
    // there. Handed to both, which take an RAII guard for their lifetime.
    let power_activity = roomlerd::power::shared_activity().clone();
    let power_policy = roomlerd::power::PowerPolicy::parse(&cfg.power_policy);
    // Not aborted at shutdown: it exits on the watch, and its exit is what
    // RELEASES the assertion. An abort would leave the machine unable to sleep.
    let _power_task = tokio::spawn(roomlerd::power::run(
        power_policy,
        Some(rc_sessions.clone()),
        power_activity.clone(),
        shutdown_rx.clone(),
    ));

    // FR-43 P2b-2 — which side of delegation this process is on. A process is
    // the supervising DAEMON or the supervised WORKER, never both, so this is
    // one value and the third case ("neither") is the ordinary one.
    //
    // `--supervised` is the discriminator, and it is the SAME flag the worker
    // uses to look for its attach secret on stdin: a process that was told it
    // is supervised is the worker, and anything else on macOS is the daemon.
    #[cfg(unix)]
    let (delegation_role, worker_channels) = if supervised {
        // Two ordinary channels rather than the socket: the socket outlives a
        // WS reconnect and the signalling loop does not.
        let (in_tx, in_rx) = tokio::sync::mpsc::channel(64);
        let (out_tx, out_rx) = tokio::sync::mpsc::channel(64);
        (
            roomlerd::delegate::Delegation::Worker(roomlerd::delegate::WorkerLink {
                inbound: in_rx,
                outbound: out_tx,
            }),
            Some((in_tx, out_rx)),
        )
    } else {
        #[cfg(target_os = "macos")]
        {
            (
                roomlerd::delegate::Delegation::Daemon(delegate_host.clone()),
                None,
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            (roomlerd::delegate::Delegation::Off, None)
        }
    };
    #[cfg(not(unix))]
    let delegation_role = roomlerd::delegate::Delegation::Off;

    // FR-84 D3 — the ONE door this process restarts itself through: the
    // LocalAPI's `RestartDaemon` verb ("Apply now"), and FR-96 P2b's watch on a
    // replaced binary. It rides the internal-shutdown path the auto-updater
    // uses (`shutdown_tx` below), so a restart is graceful by construction; the
    // select at the end of this function reads back whether one was accepted.
    // Remote configuration never reaches it — there is no server message that
    // restarts a daemon (docs/remote-config.md §7b).
    let restart = localapi_state::RestartHandle::new(
        supervision,
        shutdown_tx.clone(),
        process_started,
        roomlerd::supervision::restart_record_path(config_path),
    );
    let daemon_state = localapi_state::DaemonState::new(
        cfg.agent_id.clone(),
        cfg.machine_name.clone(),
        tunnel_core::localapi::DaemonMode::Service,
        (!cfg.tenant_id.is_empty()).then(|| cfg.tenant_id.clone()),
        localapi_connected.clone(),
        overlay_view_rx,
        consent_broker.clone(),
        Some(pinger.clone()),
        tunnel_hub.clone(),
        rtt_cache.clone(),
    )
    .with_routes(route_reconciler)
    // The rename verb persists through the daemon's own resolved
    // config path + the P6 write lock (profile-correct under SYSTEM).
    .with_config_persist(config_path.clone(), cfg_write_lock.clone())
    // FR-84 D3 — the restart verb (reads `local_restart_enabled` through the
    // config path above, fresh on every request).
    .with_restart(restart.clone())
    // …and the live gate-4 flags, so a `config set` here is in force
    // as fast as a pushed one (docs/remote-config.md).
    .with_remote_config(remote_cfg.clone())
    // Multi-org P1 — live per-enrollment rows for `meshharbor status`.
    // FR-27 — live remote-control sessions, so the desktop app can
    // render "Being viewed by ..." and offer a Disconnect. Written by
    // every signalling loop through its ViewerIndicator.
    .with_rc_sessions(rc_sessions.clone())
    .with_orgs(org_registry.clone())
    .with_org_views(org_views.clone())
    // FR-84 D5b — each enrollment's server + agent token, for the
    // companion's device list and mesh.
    .with_org_http(org_http.clone())
    // FR-51 P4 — surface the enrollment's nature in `meshharbor status`.
    .with_ephemeral(cfg.ephemeral);
    // FR-85 — the local recording verbs: this daemon launches `roomlerd
    // record` (its own image, resolved now, before any package upgrade can
    // leave `/proc/self/exe` pointing at a deleted inode).
    #[cfg(feature = "recording")]
    let daemon_state = match std::env::current_exe() {
        Ok(exe) => {
            let recorder = std::sync::Arc::new(
                roomlerd::recording::manager::RecordingManager::new(exe, config_path.clone()),
            );
            // FR-85 P3b — the SAME recorder serves a remote controller, so a
            // local and a remote recording can never run at once.
            roomlerd::recording::remote::install(recorder.clone());
            daemon_state.with_recorder(recorder)
        }
        Err(e) => {
            tracing::warn!(%e, "recording: cannot resolve our own path — the recording verbs are off");
            daemon_state
        }
    };
    // FR-92 — on a supervised Mac the GUI worker runs keep busy, so the root
    // daemon's keep-busy verbs ask it: `meshharbor exec <mac> roomler keep-busy
    // off` arrives HERE, as root, and never sees the worker's socket.
    #[cfg(target_os = "macos")]
    let daemon_state = if supervised {
        daemon_state
    } else {
        daemon_state.with_keep_busy_worker(delegate_host.clone())
    };
    // FR-85 P3b — the owner's remote-recording gates, live from here on (a
    // local `ConfigSet` re-seeds them; the server cannot reach them).
    #[cfg(feature = "recording")]
    roomlerd::recording::remote::adopt(&cfg);
    // FR-99 P1b — the owner's privacy gate, live from here on (a local
    // `ConfigSet` re-seeds it; the server cannot reach it).
    roomlerd::privacy::set_device_allowed(cfg.privacy_mode_allowed);
    // FR-99 P1d — before any connection, so before any session: the curtains a
    // previous process died holding, to report as `worker_exit`.
    roomlerd::privacy::collect_leftovers();
    // FR-99 P3 — the owner's lock-on-end policy, live from here on (a local
    // `ConfigSet` re-seeds it; the server cannot reach it).
    roomlerd::lock_on_end::set_device_policy(cfg.lock_on_end);
    // FR-108 — the owner's display-match policy, likewise device-only, and the
    // presence sampler from here on (Windows), so a request mid-session can
    // tell the controller's input from a person's.
    roomlerd::display_match::set_device_policy(cfg.display_match);
    roomlerd::presence::start();
    // FR-97 P3e-2 — a switch the last run left on a person's own X11 display
    // (killed or crashed before it restored) goes back, only while the screen
    // still shows the mode display match set.
    roomlerd::display_match::recover_after_restart();
    // FR-101 P2b — the owner's session-policy floor, likewise device-only.
    roomlerd::session_policy::set_device_policy(roomlerd::session_policy::from_config(&cfg));
    // FR-92 — the keep-busy engine: restores a keep-busy the signed-in
    // person left on (it waits for an unlocked session before touching the
    // pointer), and answers `rc:keep-busy.*` from any viewer. Started here,
    // inside the runtime, because it initialises the input arbiter. Every
    // org this device is enrolled in, so a deny stored by an org it has
    // since left is dropped rather than held for good.
    let enrolled_tenants: Vec<String> = std::iter::once(cfg.tenant_id.clone())
        .chain(cfg.orgs.iter().map(|o| o.tenant_id.clone()))
        .collect();
    roomlerd::keep_busy::start(cfg.keep_busy_enabled, enrolled_tenants);
    // FR-93 P2b — the desktop brief's refresher (Linux; nothing elsewhere), so
    // the first hello can carry it. It reads logind on its own thread; the
    // signalling loop only ever reads its cache.
    roomlerd::desktop_brief::start();
    // FR-93 P5h — tell each viewer before this computer sleeps (Linux;
    // nothing elsewhere). A thread of its own; the runtime sends the notices.
    roomlerd::sleep_notice::start(tokio::runtime::Handle::current());
    // FR-94 — ask this machine's SYSTEM service whether it is anchored, and
    // for which device, so the connection for that device offers
    // `exec-system` (Windows; nothing elsewhere).
    roomlerd::exec_service::spawn_health_watch();
    let localapi_state: std::sync::Arc<dyn tunnel_core::localapi::LocalApiState> =
        std::sync::Arc::new(daemon_state);
    // P3b-3: the RTT prober. Pings each carrier-reachable peer every
    // RTT_PROBE_INTERVAL into rtt_cache; exits on shutdown. A fresh
    // `overlay_view_tx.subscribe()` receiver (the original moved into
    // DaemonState). P8-cosmetics — no longer netstack-only: an OS-TUN node
    // probes over the OS ICMP path (`OsPinger`), so the `peers` RTT column is
    // populated everywhere instead of "— by-design on OS-TUN".
    // B1 — bridge each successful probe into the overlay runtime's event
    // channel as an `RttSample` (Q-plane instrumentation). The slot holds
    // the CURRENT connection's sink hook (installed by `connect_once`,
    // wrapping a WEAK sender — the prober must never keep a dead
    // connection's runtime alive). Without overlay features the slot
    // stays `None` forever and the hook is inert.
    let rtt_sample_slot: signaling::RttSampleSlot = Default::default();
    let rtt_hook: roomlerd::localapi_state::RttSampleHook = {
        let slot = rtt_sample_slot.clone();
        std::sync::Arc::new(move |node_hex: &str, rtt_ms: u32| {
            let inner = slot.read().unwrap_or_else(|e| e.into_inner()).clone();
            if let Some(hook) = inner {
                hook(node_hex, rtt_ms);
            }
        })
    };
    roomlerd::localapi_state::spawn_rtt_prober(
        pinger_for_prober,
        overlay_view_tx.subscribe(),
        rtt_cache,
        shutdown_rx.clone(),
        Some(rtt_hook),
    );
    // FR-43 P1 — on macOS, optionally let THIS (root) daemon own the
    // GUI-session worker instead of a separate LaunchAgent. Default off; even
    // on, it stands down while the LaunchAgent is loaded, so enabling it on a
    // live Mac is a no-op until the plist is booted out. Not spawned at all on
    // other platforms — there is no second half to supervise.
    #[cfg(target_os = "macos")]
    // Deliberately not aborted at shutdown, unlike the tasks below: this one
    // exits on the shutdown watch itself, and its exit path is what stops and
    // revokes the worker. An abort would skip exactly that.
    let _macos_supervisor_task = tokio::spawn(roomlerd::macos_supervisor::run(
        cfg.macos_supervise_gui_worker,
        delegate_host.clone(),
        shutdown_rx.clone(),
    ));

    // FR-43 P2a — the WORKER half. Inert unless `--supervised` says the root
    // daemon started us and put an attach secret on our stdin, so a
    // launchd-owned worker, a hand-run `meshharbord run` and the daemon itself all
    // skip it entirely.
    #[cfg(unix)]
    // Same: exits on the shutdown watch, so no abort.
    let _delegate_worker_task = tokio::spawn(roomlerd::delegate_worker::run(
        supervised,
        worker_channels,
        shutdown_rx.clone(),
    ));
    #[cfg(not(unix))]
    let _ = supervised;

    // FR-27 P11 — on a Linux system install, the person at the seat gets a
    // socket of their own for the safety surface (who is viewing, Disconnect,
    // consent): the daemon's own socket is root-only. FR-97 P2g — a Mac's root
    // half serves the console user one too, which the per-user half asks for
    // the machine's Devices and Mesh. Inert for a per-user daemon and with
    // ROOMLERD_PERSON_SOCKET=0; exits on the shutdown watch.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let _person_socket_task = tokio::spawn(roomlerd::person_socket::run(
        localapi_state.clone(),
        shutdown_rx.clone(),
    ));

    // FR-84 D1 — the named-pipe listener pool. `localapi_pipe_pool = 1` is
    // the pre-FR-84 single instance (the kill switch); unset = 4.
    let localapi_pipe_pool = tunnel_core::localapi::effective_pipe_pool(cfg.localapi_pipe_pool);
    let localapi_task = tokio::spawn({
        let shutdown = shutdown_rx.clone();
        async move {
            if let Err(e) =
                tunnel_core::localapi::serve_with_pool(localapi_state, shutdown, localapi_pipe_pool)
                    .await
            {
                tracing::warn!(error = %e, "localapi: listener exited with error");
            }
        }
    });

    // Loopback-TURN corp-relay (Phase 2b): when opted in via
    // ROOMLERD_LOCAL_TURN, serve the browser's loopback probe with a
    // descriptor for a locally-hosted TURN bound to this host's overlay IP — so
    // a co-located corp-Chrome controller (which can't punch direct) relays
    // through the overlay instead of the capped far coturn. Default-OFF; inert
    // without an overlay IP. Spawned before `cfg` moves into the signaling task.
    roomlerd::rc_local_turn::spawn(
        overlay_view_tx.subscribe(),
        cfg.agent_id.clone(),
        shutdown_rx.clone(),
    );

    // Multi-org P1 — one supervised signaling loop per enabled secondary
    // org, spawned BEFORE the primary task consumes `cfg` and the broker.
    // Each gets: a synthesized per-org config (overlay forced OFF in P1),
    // its own connected flag + watchdog pump, an inert overlay-view channel
    // + RTT slot, and an ISOLATED tunnel-client hub (daemon-originated
    // flows stay primary-only in P1 — see the route reconciler's org gate).
    // A terminal stop (server goodbye / duplicate duel) ends only that
    // org's task and is recorded for `NodeStatus.orgs`.
    let mut org_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    for (org, org_ctx, org_connected, org_terminal) in org_spawns {
        // One clone per org task: each spawn MOVES its capture, so a shared
        // binding would be consumed by the first iteration.
        let remote_cfg_org = remote_cfg.clone();
        let rc_sessions_org = rc_sessions.clone();
        let org_cfg = cfg.for_org(&org);
        let (org_view_tx, org_view_rx) =
            tokio::sync::watch::channel(tunnel_core::localapi::OverlayView::default());
        // Keep the receiver: this is what lets `peers` show this org.
        if let Ok(mut v) = org_views.lock() {
            v.push((org.label.clone(), org_view_rx));
        }
        let org_slot: signaling::RttSampleSlot = Default::default();
        let org_hub = roomlerd::tunnel::client_mgr::TunnelClientHub::new(
            env!("CARGO_PKG_VERSION").to_string(),
        );
        let rx = shutdown_rx.clone();
        let broker = consent_broker.clone();
        let span = tracing::info_span!("org", label = %org.label);
        org_tasks.push(tokio::spawn(tracing::Instrument::instrument(
            async move {
                match signaling::run(
                    org_ctx,
                    // FR-43 P2b — secondary orgs never drive the host-global
                    // GUI worker (see `handle_server_msg`'s primary gate).
                    roomlerd::delegate::Delegation::Off,
                    org_cfg,
                    encoder_preference,
                    rx,
                    org_connected,
                    org_view_tx,
                    org_slot,
                    broker,
                    org_hub,
                    remote_cfg_org,
                    rc_sessions_org,
                )
                .await
                {
                    Ok(()) => tracing::info!("org signaling loop ended (shutdown)"),
                    Err(e) => {
                        let chain = format!("{e:#}");
                        // #1750 — the org refuses us: the loop already said
                        // so, once, as a WARN naming the ways out.
                        if signaling::is_secondary_goodbye(&e) {
                            tracing::debug!(error = %chain, "org signaling loop ended: the org refuses this machine");
                        } else {
                            tracing::error!(error = %chain, "org signaling loop terminated");
                        }
                        if let Ok(mut t) = org_terminal.lock() {
                            *t = Some(chain);
                        }
                    }
                }
            },
            span,
        )));
    }

    // Multi-org — the same supervisor recipe as the boot loop above, but
    // callable LATER: `rc:agent.join_org` appends an org at runtime and needs
    // its loop up without a daemon restart. Everything captured here is a
    // process-wide singleton (config path, write lock, shutdown signal,
    // consent broker), so a join arriving hours from now produces a
    // supervisor indistinguishable from one started at boot.
    {
        let shutdown = shutdown_rx.clone();
        let broker = consent_broker.clone();
        let registry = org_registry.clone();
        let org_http_for_join = org_http.clone();
        let org_views_for_join = org_views.clone();
        let enc = encoder_preference;
        let config_path_for_join = config_path.clone();
        // label -> that org loop's own shutdown sender, so a config change can
        // cycle ONE enrollment without disturbing the others.
        let org_stops: std::sync::Arc<
            std::sync::Mutex<std::collections::HashMap<String, tokio::sync::watch::Sender<bool>>>,
        > = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        // Cloned for the org-join closure: it is an `Fn` (called per join), so
        // it must not consume the captured services.
        let remote_cfg2 = remote_cfg.clone();
        let rc_sessions2 = rc_sessions.clone();
        roomlerd::org_join::install(roomlerd::org_join::JoinRuntime {
            config_path: config_path.clone(),
            write_lock: cfg_write_lock.clone(),
            spawn_org: Box::new(move |org: config::OrgEntry| {
                // A re-spawn for a label that is already running must STOP the
                // old loop first: two loops on one enrollment would open two
                // WS with the same agent token, and the server's displacement
                // would evict one of them non-deterministically. Each loop gets
                // its own shutdown channel (fed by the global one) so exactly
                // this org can be cycled without touching the others.
                if let Some(prev) = org_stops.lock().ok().and_then(|mut m| m.remove(&org.label)) {
                    let _: &tokio::sync::watch::Sender<bool> = &prev;
                    let _ = prev.send(true);
                    tracing::info!(org = %org.label, "org supervisor: stopping the previous loop before re-spawn");
                }
                let (org_sd_tx, org_sd_rx) = tokio::sync::watch::channel(false);
                if let Ok(mut m) = org_stops.lock() {
                    m.insert(org.label.clone(), org_sd_tx);
                }
                // Global shutdown must still reach this loop.
                {
                    let mut global = shutdown.clone();
                    let stops = org_stops.clone();
                    let label = org.label.clone();
                    tokio::spawn(async move {
                        while global.changed().await.is_ok() {
                            if *global.borrow() {
                                if let Ok(m) = stops.lock()
                                    && let Some(tx) = m.get(&label)
                                {
                                    let _ = tx.send(true);
                                }
                                break;
                            }
                        }
                    });
                }
                // FR-103 — a fresh slot for the joined (or re-spawned) org,
                // shared by the rows below and its loop.
                let org_ctx = signaling::OrgCtx::secondary(
                    &org.label,
                    roomlerd::token_slot::TokenSlot::new(org.agent_token.clone()),
                )
                .with_renewal(token_renewal);
                let connected = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let terminal = std::sync::Arc::new(std::sync::Mutex::new(None));
                // Surface it in `meshharbor status` / the LocalAPI immediately,
                // replacing any stale row for the same label.
                if let Ok(mut rows) = registry.lock() {
                    rows.retain(|r| r.label != org.label);
                    rows.push(localapi_state::OrgRuntime {
                        label: org.label.clone(),
                        server_url: org.server_url.clone(),
                        tenant_id: org.tenant_id.clone(),
                        agent_id: org.agent_id.clone(),
                        primary: false,
                        enabled: org.enabled,
                        connected: connected.clone(),
                        terminal_error: terminal.clone(),
                        updates_ignored: org_ctx.updates_ignored.clone(),
                        overlay_mode: org.overlay_mode.wire(),
                        token: org_ctx.token.clone(),
                    });
                }
                // FR-84 D5b — and its HTTP identity, replacing any row for
                // the same label (a re-spawn must not keep the old token).
                roomlerd::self_view::upsert(
                    &org_http_for_join,
                    roomlerd::self_view::OrgHttp::secondary(&org, true, org_ctx.token.clone()),
                );
                // The per-org config is synthesized from the CURRENT on-disk
                // config, so operator knobs (including `overlay_multi_org`)
                // apply to the newcomer exactly as they do to boot-time orgs.
                let base = match config::load(&config_path_for_join) {
                    Ok(c) => c,
                    Err(e) => {
                        // The join already wrote this file, so a failure here
                        // means something else broke it. Skip the spawn
                        // rather than run an org on an invented config — the
                        // entry is on disk and comes up at the next start.
                        tracing::error!(
                            org = %org.label, error = %format!("{e:#}"),
                            "join: config reload failed; the new org connects at the next start"
                        );
                        if let Ok(mut t) = terminal.lock() {
                            *t = Some(format!("config reload failed: {e:#}"));
                        }
                        return;
                    }
                };
                let org_cfg = base.for_org(&org);
                let (org_view_tx, org_view_rx) =
                    tokio::sync::watch::channel(tunnel_core::localapi::OverlayView::default());
                if let Ok(mut v) = org_views_for_join.lock() {
                    v.push((org.label.clone(), org_view_rx));
                }
                let org_slot: signaling::RttSampleSlot = Default::default();
                let org_hub = roomlerd::tunnel::client_mgr::TunnelClientHub::new(
                    env!("CARGO_PKG_VERSION").to_string(),
                );
                // The PER-ORG shutdown, not the global one — that is what
                // makes a single org cyclable.
                let rx = org_sd_rx;
                // Cleanup handles: release this org's adapter and SOCKS claims
                // when its loop ends, unless a re-spawn replaced us (see below).
                let cleanup_stops = org_stops.clone();
                let cleanup_label = org.label.clone();
                let cleanup_tenant = org.tenant_id.clone();
                let my_stop = match org_stops.lock() {
                    Ok(m) => m.get(&org.label).cloned(),
                    Err(_) => None,
                };
                let Some(my_stop) = my_stop else {
                    tracing::error!(org = %org.label, "org supervisor: lost our own stop handle; not spawning");
                    return;
                };
                let broker = broker.clone();
                // Per-spawn clone: the async block below MOVES its capture,
                // and this closure runs once per join.
                let remote_cfg_join = remote_cfg2.clone();
                let rc_sessions_join = rc_sessions2.clone();
                let span = tracing::info_span!("org", label = %org.label);
                tokio::spawn(tracing::Instrument::instrument(
                    async move {
                        match signaling::run(
                            org_ctx,
                            // Secondary org — see above.
                            roomlerd::delegate::Delegation::Off,
                            org_cfg,
                            enc,
                            rx,
                            connected,
                            org_view_tx,
                            org_slot,
                            broker,
                            org_hub,
                            remote_cfg_join,
                            rc_sessions_join,
                        )
                        .await
                        {
                            Ok(()) => tracing::info!("joined-org signaling loop ended (shutdown)"),
                            Err(e) => {
                                let chain = format!("{e:#}");
                                // #1750 — see the boot supervisor above.
                                if signaling::is_secondary_goodbye(&e) {
                                    tracing::debug!(error = %chain, "joined-org signaling loop ended: the org refuses this machine");
                                } else {
                                    tracing::error!(error = %chain, "joined-org signaling loop terminated");
                                }
                                if let Ok(mut t) = terminal.lock() {
                                    *t = Some(chain);
                                }
                            }
                        }
                        // This org is done — hand its adapter and SOCKS port back
                        // (docs/multi-org.md §12: they used to linger until the
                        // daemon restarted).
                        //
                        // ONLY when no replacement took our slot: a RE-spawn
                        // stops this loop and immediately registers a fresh
                        // port under the same key, and releasing then would
                        // strip the address the NEW loop just claimed —
                        // leaving that org live with nothing to receive on.
                        // Channel identity is the test; a replacement always
                        // installs its own.
                        let mine = match cleanup_stops.lock() {
                            Ok(m) => m
                                .get(&cleanup_label)
                                .is_some_and(|cur| cur.same_channel(&my_stop)),
                            Err(_) => false,
                        };
                        if mine {
                            if let Ok(mut m) = cleanup_stops.lock() {
                                m.remove(&cleanup_label);
                            }
                            // The overlay module only exists in a build with
                            // an overlay surface; without one there is no
                            // adapter or SOCKS port to release.
                            #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
                            roomlerd::overlay::release_org(&cleanup_tenant);
                            #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
                            let _ = &cleanup_tenant;
                        }
                    },
                    span,
                ));
            }),
        });
    }

    let sig_task = tokio::spawn({
        let rx = shutdown_rx.clone();
        let connected = localapi_connected.clone();
        let view_tx = overlay_view_tx.clone();
        let sample_slot = rtt_sample_slot.clone();
        let rc_sessions_primary = rc_sessions.clone();
        async move {
            signaling::run(
                primary_ctx,
                // FR-43 P2b — the PRIMARY loop is the only one that may hand a
                // session to the GUI worker, and the only one a worker serves.
                delegation_role,
                cfg,
                encoder_preference,
                rx,
                connected,
                view_tx,
                sample_slot,
                consent_broker,
                tunnel_hub,
                remote_cfg,
                rc_sessions_primary,
            )
            .await
        }
    });

    // Clean-run promotion task: after the agent has been alive for
    // CLEAN_RUN_THRESHOLD_SECS, reload + update + save the config
    // to mark this version as last-known-good and reset the crash
    // counter. Reload-then-save (rather than holding cfg) avoids
    // clobbering any concurrent writes from `re-enroll` or the
    // updater path. Aborts cleanly on shutdown.
    let clean_run_task = tokio::spawn({
        let path = config_path.clone();
        let mut shutdown = shutdown_rx.clone();
        let pkg = current_pkg.to_string();
        let write_lock = cfg_write_lock.clone();
        async move {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(
                    config::CLEAN_RUN_THRESHOLD_SECS,
                )) => {
                    // P6: reload-modify-save under the daemon-wide write
                    // lock so this save can't drop a route the LocalAPI
                    // just persisted (and vice versa).
                    let _write_guard = write_lock.lock().await;
                    match config::load(&path) {
                        Ok(mut current) => {
                            config::record_clean_run_at(&mut current, &pkg);
                            if let Err(e) = config::save(&path, &current) {
                                tracing::warn!(error = %e, "could not persist clean-run promotion");
                            } else {
                                tracing::info!(
                                    last_known_good = %pkg,
                                    "clean-run threshold reached; promoted to last-known-good"
                                );
                            }
                            // rc.52 Phase 4: this run proved healthy.
                            // If we're a SystemContext worker that
                            // loaded its config from a perUser path,
                            // promote a copy to the machine-global
                            // %PROGRAMDATA% location so the NEXT boot
                            // can load it pre-logon. machine_id is the
                            // stored config field — copying the loaded
                            // struct preserves it verbatim.
                            self_heal_machine_global_config(&path, &current);
                        }
                        Err(e) => tracing::warn!(error = %e, "could not reload config for clean-run promotion"),
                    }
                }
                _ = shutdown.changed() => {}
            }
        }
    });

    // Background auto-updater — checks GitHub Releases on startup and
    // every `update_check_interval_h` hours (default 24, configurable
    // via the AgentConfig field or `ROOMLERD_UPDATE_INTERVAL_H`
    // env var). Writes to `shutdown_tx` when a newer version is
    // downloaded and the installer is spawned, so the signalling task
    // tears down cleanly before the running binary gets overwritten.
    // Disable entirely with `ROOMLERD_AUTO_UPDATE=0` for air-
    // gapped / operator-managed deployments.
    let upd_task = if let Some(update_trigger_rx) = update_trigger_rx {
        tracing::info!(
            interval_h = update_interval.as_secs() / 3600,
            "auto-updater armed"
        );
        Some(tokio::spawn({
            let rx = shutdown_rx.clone();
            let tx = shutdown_tx.clone();
            async move { updater::run_periodic(rx, tx, update_interval, update_trigger_rx).await }
        }))
    } else {
        tracing::info!("auto-update disabled (auto_update = false / ROOMLERD_AUTO_UPDATE=0)");
        None
    };

    // FR-96 P2b — a per-user Linux daemon restarts onto its replaced binary
    // once nothing it serves would be cut: the root helper's install, an
    // admin's `apt upgrade`, a hand install alike. Not an update, so
    // `auto_update = false` does not stop it; it leaves through FR-84 D3's
    // door (`restart`), the one way this process restarts itself.
    #[cfg(target_os = "linux")]
    let replaced_task =
        roomlerd::replaced_binary::spawn(shutdown_rx.clone(), restart.clone(), rc_sessions.clone());

    // Wait for an internal shutdown, Ctrl-C (SIGINT), or SIGTERM.
    let mut graceful_shutdown = false;
    // FR-51 P3 — true only on the two OS-initiated arms below. The internal
    // arm is the auto-updater restarting the daemon, and de-enrolling there
    // would delete the device on every update.
    let mut os_initiated_stop = false;
    tokio::select! {
        res = sig_task => {
            // FR-90 P1d-2 — first, on every way out: a harness that ends from
            // here on went down with the daemon, and its session is resumed
            // by the next one instead of being ended.
            #[cfg(hive_host)]
            roomlerd::hive::begin_shutdown();
            // FR-84 D3 — an accepted restart leaves through the graceful door
            // whatever the signalling loop did on its way out (an error, even
            // a panic): the shutdown is our own, and a crash counted here
            // would put a button press on the rollback detector's ladder. If
            // the loop ended in the instant between the verb accepting and the
            // LocalAPI committing, commit now — the shutdown flag is what makes
            // this exit graceful below, and an ungraceful one would leave with
            // 0, which launchd does NOT relaunch.
            let restarting = restart.accepted_exit_code().is_some();
            if restarting {
                restart.commit();
            }
            if let Ok(Err(e)) = res {
                if !restarting {
                    tracing::error!(error = %e, "signaling task exited with error");
                    return Err(e);
                }
                tracing::warn!(error = %e,
                    "signaling task ended with an error during a requested restart; restarting anyway");
            }
            // sig_task exited successfully. The only way that happens
            // is via `shutdown_tx.send(true)` from inside the agent
            // (auto-updater spawning the installer, rollback path
            // pinning a previous version, or FR-84 D3's requested
            // restart). Treat that as graceful so
            // the next startup doesn't false-positive a crash counter
            // increment. M5 finding #2 (the field-test host 2026-05-02): every
            // auto-update bumped `crash_count` by 1; three rapid
            // updates would have tripped the rollback threshold.
            if *shutdown_rx.borrow() {
                tracing::info!("signaling task exited via internal shutdown signal; marking graceful");
                graceful_shutdown = true;
            }
        }
        _ = tokio::signal::ctrl_c() => {
            #[cfg(hive_host)]
            roomlerd::hive::begin_shutdown();
            tracing::info!("shutdown requested");
            graceful_shutdown = true;
            os_initiated_stop = true;
            let _ = shutdown_tx.send(true);
            // Give the signaling task a short window to flush.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        // Being asked to stop is not failing to run. See `terminate_signal`
        // for what this cost before it existed (#1040 on Unix; #1683 on the
        // Windows SCM service, where the stop arrived only as a hard kill).
        _ = terminate_signal(stop_event, config_path) => {
            // Under systemd the same stop reaches every harness a moment
            // after this (`KillMode=control-group`).
            #[cfg(hive_host)]
            roomlerd::hive::begin_shutdown();
            tracing::info!("OS/service-manager stop received; shutting down gracefully");
            graceful_shutdown = true;
            os_initiated_stop = true;
            let _ = shutdown_tx.send(true);
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }
    wd_task.abort();
    clean_run_task.abort();
    crash_drain_task.abort();
    localapi_task.abort();
    // Multi-org P1 — the secondary org loops observe the same shutdown
    // watch; the abort is belt-and-suspenders for loops mid-backoff.
    for t in org_tasks {
        t.abort();
    }
    if let Some(t) = upd_task {
        t.abort();
    }
    #[cfg(target_os = "linux")]
    if let Some(t) = replaced_task {
        t.abort();
    }
    // #1684 — take our own virtual desktop down BEFORE we leave. Under systemd
    // `KillMode=control-group`, whatever the daemon spawned that outlives it
    // (the desktop's setsid'd `at-spi-bus-launcher` grandchild, which ignores
    // SIGTERM) holds the unit's cgroup non-empty for `TimeoutStopSec` (90 s)
    // and blocks the restart / stop for that whole time. Reaching every
    // descendant here — a requested restart, an auto-update's exit, a SIGTERM,
    // all arrive at this line — leaves systemd an empty cgroup to reap in ~5 s.
    // Idempotent and a no-op when no desktop was started; a `process::exit`
    // that never returned through here is covered by the RAII Drop of
    // `_virtual_desktop` and by `exit_for_requested_restart`.
    #[cfg(target_os = "linux")]
    virtual_desktop::teardown();
    // FR-90 P1h — the same for the agent sessions this daemon launched: each
    // harness leads its own process group, which a service manager reaches
    // only when it kills a whole cgroup (systemd's `KillMode=control-group`).
    // launchd does not, and nothing does for an unsupervised daemon, so the
    // daemon takes them down itself — after `begin_shutdown`, so each session
    // is kept for the next daemon to resume. Bounded.
    #[cfg(hive_host)]
    roomlerd::hive::wind_down().await;
    // On graceful shutdown, mark the config so the next startup
    // doesn't count this run as a crash. Reload-then-save again to
    // avoid clobbering any concurrent writes (clean_run_task may
    // have just promoted the version, in which case the unhealthy
    // flag is already false — load+save is a no-op).
    if graceful_shutdown {
        // P6: same daemon-wide write lock as the other runtime writers.
        // The LocalAPI task is already aborted at this point, but the
        // clean-run promotion task may still be mid-save.
        let _write_guard = cfg_write_lock.lock().await;
        if let Ok(mut current) = config::load(config_path) {
            // FR-51 P3 — an EPHEMERAL device leaving on an OS stop removes
            // itself NOW instead of waiting out the reap deadline. Bounded
            // and best-effort (the fn caps at 3 s; the reaper is the backstop
            // for every exit that never reaches this line), and only on the
            // signal arms — the internal arm is the updater restarting us.
            //
            // #1683 — and never while an UPDATE is in flight. On Windows the
            // MSI stops the service while it replaces the binary; by then the
            // worker that spawned the installer has exited 0 and the SCM host
            // has respawned this one, which receives that stop as an
            // OS-initiated stop, indistinguishable from `sc stop`. Unenrolling
            // here would delete the device on every auto-update and bring the
            // new version up holding a dead token — the exact outcome the
            // internal-arm rule above exists to prevent. `update_in_flight`
            // reads the `update-attempt` marker the installer spawn touches
            // (rollbacks included); the policy itself is one pure table
            // (`updater::should_self_unenroll`). Platform-neutral on purpose.
            let update_in_flight = updater::update_in_flight();
            if updater::should_self_unenroll(current.ephemeral, os_initiated_stop, update_in_flight)
            {
                match enrollment::self_unenroll(&current.server_url, &current.agent_token).await {
                    Ok(()) => tracing::info!("ephemeral device unenrolled itself on shutdown"),
                    Err(e) => tracing::warn!(error = %e,
                        "ephemeral self-unenroll failed; the server-side reaper will collect this device"),
                }
            } else if current.ephemeral && os_initiated_stop {
                // The one way the gate says no to an ephemeral OS stop. Named,
                // so "why is this row still here?" has an answer in the log.
                tracing::info!(
                    window_secs = updater::UPDATE_STOP_WINDOW.as_secs(),
                    "ephemeral device NOT unenrolling: an update is in flight — the installer \
                     stopped the service; this device stays enrolled"
                );
            }
            config::mark_clean_shutdown(&mut current);
            if let Err(e) = config::save(config_path, &current) {
                tracing::warn!(error = %e, "could not mark clean shutdown");
            }
        }
    }
    // FR-97 P4d — what the session-end window holds `WM_ENDSESSION` for: past
    // this line the clean stop, and an ephemeral device's unenroll, are done,
    // and Windows may end the process.
    #[cfg(target_os = "windows")]
    roomlerd::win_service::session_end::clean_stop_done();
    // FR-84 D3 — leave with the code the supervisor relaunches on, now that
    // the clean shutdown is on disk. Only through the graceful door (a
    // requested restart is always our own internal shutdown), and never
    // against an OS stop that landed in the same instant: `systemctl stop`,
    // a `launchctl bootout`, an admin's `kill` asked this process to STAY
    // down, and relaunching it would fight them.
    let restart_exit = if graceful_shutdown && !os_initiated_stop {
        restart.accepted_exit_code()
    } else {
        None
    };
    Ok(restart_exit)
}

async fn service_cmd(action: ServiceAction, config_path: &PathBuf) -> Result<()> {
    match action {
        ServiceAction::Install { as_service: false } => {
            service::install().context("installing auto-start hook")?;
            println!("Auto-start registered. The agent will launch on next login.");
            // FR-84 D6 — the per-user install's companion login start
            // (`HKCU\…\Run`): the MSI's RegisterAutostart CA runs this as the
            // installing user. A fresh install has no companion beside us yet
            // (the installer places it after the MSI) and writes nothing; the
            // worker's own start and the companion's first run add it then.
            #[cfg(target_os = "windows")]
            roomlerd::companion::sync_user_autostart_logged(
                config::read_if_present(config_path).is_none_or(|c| c.companion_autostart),
            );
            #[cfg(not(target_os = "windows"))]
            let _ = config_path;
            Ok(())
        }
        ServiceAction::Uninstall { as_service: false } => {
            service::uninstall().context("removing auto-start hook")?;
            println!("Auto-start removed.");
            // FR-84 D6 — and the companion's per-user login start with it.
            #[cfg(target_os = "windows")]
            match roomlerd::companion::remove_login_autostart(false) {
                Ok(true) => println!("Companion login start removed."),
                Ok(false) => {}
                Err(e) => tracing::warn!(error = %format!("{e:#}"), "companion login start"),
            }
            Ok(())
        }
        ServiceAction::Status { as_service: false } => {
            let s = service::status().context("querying auto-start status")?;
            println!("Auto-start: {s}");
            Ok(())
        }
        ServiceAction::Start { as_service: false } => {
            service::start().context("starting the auto-start hook")?;
            println!("Start requested; the service manager launches the daemon.");
            Ok(())
        }
        ServiceAction::Install { as_service: true } => service_install_as_service(),
        ServiceAction::Uninstall { as_service: true } => service_uninstall_as_service(),
        ServiceAction::Status { as_service: true } => service_status_as_service(),
        ServiceAction::Start { as_service: true } => service_start_as_service(),
        ServiceAction::Stop { as_service: false } => {
            let how = service::stop(config_path).context("stopping the daemon")?;
            println!("{how}");
            Ok(())
        }
        ServiceAction::Stop { as_service: true } => service_stop_as_service(),
    }
}

#[cfg(target_os = "windows")]
fn service_start_as_service() -> Result<()> {
    win_service::environment::start_service(std::time::Duration::from_secs(30))
        .context("starting the Roomler service")?;
    println!("{}: running", win_service::NEW_SERVICE_NAME);
    Ok(())
}

/// FR-97 P6c — the root daemon, through systemd or launchd.
#[cfg(not(target_os = "windows"))]
fn service_start_as_service() -> Result<()> {
    println!("{}", service::start_system()?);
    Ok(())
}

/// FR-97 P4d — stop the SCM service and wait for STOPPED. The host asks its
/// worker to leave through the #1683 stop event, so an ephemeral device
/// unenrolls, as with `sc stop`.
#[cfg(target_os = "windows")]
fn service_stop_as_service() -> Result<()> {
    win_service::environment::stop_service(std::time::Duration::from_secs(30))
        .context("stopping the Roomler service")?;
    println!("{}: stopped", win_service::NEW_SERVICE_NAME);
    Ok(())
}

/// FR-97 P6c — the root daemon's clean stop, through systemd or launchd.
#[cfg(not(target_os = "windows"))]
fn service_stop_as_service() -> Result<()> {
    println!("{}", service::stop_system()?);
    Ok(())
}

#[cfg(target_os = "windows")]
fn service_install_as_service() -> Result<()> {
    let exe = std::env::current_exe().context("locating current_exe for service install")?;
    win_service::install(&exe).context("registering Roomler with the SCM")?;
    println!(
        "Service registered: {} ({}). Launching `sc start {}` will run the service \
         under LocalSystem; AutoStart fires on next boot.",
        win_service::NEW_SERVICE_NAME,
        win_service::SERVICE_DISPLAY_NAME,
        win_service::NEW_SERVICE_NAME
    );
    // FR-84 D6 — the machine-wide companion login start (`HKLM\…\Run`),
    // written here because this is the elevated step every perMachine install
    // and upgrade runs (the MSI's RegisterService CA, as LocalSystem). A fresh
    // install has no companion beside us yet and writes nothing; the SCM
    // host's start-up self-heal adds it once the installer has placed it.
    roomlerd::companion::sync_machine_autostart_logged(
        roomlerd::companion::scm_companion_autostart(),
    );
    Ok(())
}

/// FR-97 P6c — register the root daemon the package ships with the OS's own
/// service manager (`meshharbord.service`, `com.roomler.daemon`) and start it.
#[cfg(not(target_os = "windows"))]
fn service_install_as_service() -> Result<()> {
    println!("{}", service::install_system()?);
    Ok(())
}

#[cfg(target_os = "windows")]
fn service_uninstall_as_service() -> Result<()> {
    win_service::uninstall().context("deregistering Roomler")?;
    println!("Service deregistered ({}).", win_service::NEW_SERVICE_NAME);
    // FR-84 D6 — no service, no machine-wide companion login start.
    match roomlerd::companion::remove_login_autostart(true) {
        Ok(true) => println!("Companion login start removed."),
        Ok(false) => {}
        Err(e) => tracing::warn!(error = %format!("{e:#}"), "companion login start"),
    }
    Ok(())
}

/// FR-97 P6c — stop the root daemon (a clean stop) and deregister it. The
/// config stays.
#[cfg(not(target_os = "windows"))]
fn service_uninstall_as_service() -> Result<()> {
    println!("{}", service::uninstall_system()?);
    Ok(())
}

#[cfg(target_os = "windows")]
fn service_status_as_service() -> Result<()> {
    let status = win_service::status().context("querying SCM service status")?;
    println!("{}: {:?}", win_service::NEW_SERVICE_NAME, status);
    Ok(())
}

/// FR-97 P6c — the root daemon's state. ⚠️ Never a `Roomler:` line: the
/// companion reads that as Windows' SCM service (`service::system::status_line`).
#[cfg(not(target_os = "windows"))]
fn service_status_as_service() -> Result<()> {
    println!("{}", service::status_system()?);
    Ok(())
}

/// Env var the supervisor reads to gate the SystemContext worker swap.
/// Single source of truth; do NOT inline this string elsewhere — the
/// supervisor reads it via `tunnel_core::env::node_env("ENABLE_SYSTEM_SWAP")`
/// in `win_service::supervisor::system_swap_enabled()` and any drift
/// would silently break the gate.
///
/// Windows-only: the `enable-system-context` / `disable-system-context`
/// CLI commands that reference it are gated on `target_os = "windows"`,
/// so the constant has no Linux/macOS consumers — cfg-gate the const to
/// match (else CI's `cargo clippy --workspace -- -D warnings` on the
/// Ubuntu runner errors with "constant is never used").
#[cfg(target_os = "windows")]
const SYSTEM_CONTEXT_ENV_VAR: &str = "ROOMLERD_ENABLE_SYSTEM_SWAP";

/// Default per-transition timeout for the post-write service restart.
/// 120 s covers Windows Defender real-time-scan delay on a fresh EXE
/// install; cut to 60 s when running in CI without Defender in the
/// loop.
#[cfg(target_os = "windows")]
const DEFAULT_RESTART_TIMEOUT_SECS: u64 = 120;

#[cfg(target_os = "windows")]
fn enable_system_context_cmd(no_restart: bool) -> Result<()> {
    use roomlerd::win_service::{environment, system_context_attempt as attempt};
    use std::time::Duration;

    const COMMAND: &str = attempt::ENABLE_COMMAND;

    // Stage 1: env-var write. On failure, record telemetry so the
    // installer wizard (which reads %PROGRAMDATA%\roomler\
    // last-system-context-attempt.json after an MSI failure) can
    // surface an actionable, stage-scoped error to the operator.
    if let Err(e) = environment::set_service_env_var(SYSTEM_CONTEXT_ENV_VAR, "1") {
        let hint = "Re-run from an elevated shell. If the failure persists, the SCM \
                    service may not exist yet — install the perMachine MSI first.";
        let _ = attempt::record(&attempt::Attempt::failure(
            COMMAND,
            attempt::Stage::EnvVarWrite,
            &e.to_string(),
            hint,
        ));
        return Err(e).with_context(|| format!("setting {SYSTEM_CONTEXT_ENV_VAR}=1"));
    }
    println!("{SYSTEM_CONTEXT_ENV_VAR}=1 written to SCM service env block.");

    if no_restart {
        let _ = attempt::record(&attempt::Attempt::ok(COMMAND));
        println!(
            "--no-restart: skipping service restart. Run `meshharbord restart-service` to apply."
        );
        return Ok(());
    }

    // Stage 2: service restart.
    if let Err(e) = environment::restart_service(Duration::from_secs(DEFAULT_RESTART_TIMEOUT_SECS))
    {
        let hint = "Env-var write succeeded; service restart failed. Common cause: a \
                    `services.msc` window holds a handle on Roomler. Close \
                    any open services consoles and run `meshharbord restart-service` \
                    again.";
        let _ = attempt::record(&attempt::Attempt::failure(
            COMMAND,
            attempt::Stage::ServiceRestart,
            &e.to_string(),
            hint,
        ));
        return Err(e).context("restarting Roomler");
    }
    let _ = attempt::record(&attempt::Attempt::ok(COMMAND));
    println!("Roomler restarted. SystemContext mode is active.");
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn enable_system_context_cmd(_no_restart: bool) -> Result<()> {
    bail!("`enable-system-context` is Windows-only.")
}

#[cfg(target_os = "windows")]
fn disable_system_context_cmd(no_restart: bool) -> Result<()> {
    use roomlerd::win_service::{environment, system_context_attempt as attempt};
    use std::time::Duration;

    const COMMAND: &str = attempt::DISABLE_COMMAND;

    if let Err(e) = environment::unset_service_env_var(SYSTEM_CONTEXT_ENV_VAR) {
        let hint = "Re-run from an elevated shell.";
        let _ = attempt::record(&attempt::Attempt::failure(
            COMMAND,
            attempt::Stage::EnvVarWrite,
            &e.to_string(),
            hint,
        ));
        return Err(e).with_context(|| format!("unsetting {SYSTEM_CONTEXT_ENV_VAR}"));
    }
    println!("{SYSTEM_CONTEXT_ENV_VAR} removed from SCM service env block.");

    if no_restart {
        let _ = attempt::record(&attempt::Attempt::ok(COMMAND));
        println!(
            "--no-restart: skipping service restart. Run `meshharbord restart-service` to apply."
        );
        return Ok(());
    }

    if let Err(e) = environment::restart_service(Duration::from_secs(DEFAULT_RESTART_TIMEOUT_SECS))
    {
        let hint = "Env-var unset succeeded; service restart failed. Close any open \
                    `services.msc` consoles and run `meshharbord restart-service` again.";
        let _ = attempt::record(&attempt::Attempt::failure(
            COMMAND,
            attempt::Stage::ServiceRestart,
            &e.to_string(),
            hint,
        ));
        return Err(e).context("restarting Roomler");
    }
    let _ = attempt::record(&attempt::Attempt::ok(COMMAND));
    println!("Roomler restarted. SystemContext mode is disabled.");
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn disable_system_context_cmd(_no_restart: bool) -> Result<()> {
    bail!("`disable-system-context` is Windows-only.")
}

/// #1727 — the perMachine MSI's action when its command line does not
/// name a mode. It cannot read the mode itself: the switch lives in the
/// service's `Environment`, which RegisterService (and a major upgrade's
/// removal of the old product) has already deleted by the time this runs,
/// and an MSI condition cannot read a REG_MULTI_SZ at all. So it follows
/// the product's own record of the last switch.
///
/// An unreadable record reads as "off": that is what an install with no
/// property always did, so no host is worse off than before.
#[cfg(target_os = "windows")]
fn keep_system_context_cmd(no_restart: bool) -> Result<()> {
    use roomlerd::win_service::system_context_attempt as attempt;

    let last = attempt::read_last().unwrap_or_else(|e| {
        eprintln!(
            "keep-system-context: cannot read {} ({e}); treating it as off",
            attempt::path().display()
        );
        None
    });
    let on = attempt::last_switched_on(last.as_ref());
    match &last {
        Some(a) => println!(
            "keep-system-context: the last recorded switch was `{}` ({:?}) at {} -> SystemContext {}",
            a.command,
            a.stage,
            a.ts,
            if on { "ON" } else { "off" }
        ),
        None => println!("keep-system-context: no recorded switch -> SystemContext off"),
    }
    if on {
        enable_system_context_cmd(no_restart)
    } else {
        disable_system_context_cmd(no_restart)
    }
}

#[cfg(not(target_os = "windows"))]
fn keep_system_context_cmd(_no_restart: bool) -> Result<()> {
    bail!("`keep-system-context` is Windows-only.")
}

#[cfg(target_os = "windows")]
fn set_service_env_var_cmd(name: &str, value: Option<&str>) -> Result<()> {
    use roomlerd::win_service::environment;
    match value {
        Some(v) => {
            environment::set_service_env_var(name, v)
                .with_context(|| format!("set-service-env-var: {name}={v}"))?;
            println!(
                "{name}={v} written to SCM service env block. Run `meshharbord restart-service` to apply."
            );
        }
        None => {
            environment::unset_service_env_var(name)
                .with_context(|| format!("unset-service-env-var: {name}"))?;
            println!(
                "{name} removed from SCM service env block. Run `meshharbord restart-service` to apply."
            );
        }
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn set_service_env_var_cmd(_name: &str, _value: Option<&str>) -> Result<()> {
    bail!("`set-service-env-var` is Windows-only.")
}

#[cfg(target_os = "windows")]
fn restart_service_cmd(timeout_secs: u64) -> Result<()> {
    use roomlerd::win_service::environment;
    use std::time::Duration;
    environment::restart_service(Duration::from_secs(timeout_secs))
        .context("restarting Roomler")?;
    println!("Roomler restarted.");
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn restart_service_cmd(_timeout_secs: u64) -> Result<()> {
    bail!("`restart-service` is Windows-only.")
}

#[cfg(target_os = "windows")]
async fn service_run_cmd() -> Result<()> {
    // Hand control to the SCM dispatcher. Blocks until SCM signals
    // Stop. NOTE: this MUST run on the main OS thread (not inside a
    // tokio worker), because `service_dispatcher::start` calls
    // `StartServiceCtrlDispatcherW` which expects to take over the
    // calling thread. We achieve "main thread" here by running before
    // any other work in the binary's CLI dispatch — the
    // `#[tokio::main]` runtime is already alive but we never await
    // anything before this call, so the OS thread is still
    // effectively the binary's main thread for SCM purposes.
    win_service::run_in_dispatcher().context("running service dispatcher")
}

#[cfg(not(target_os = "windows"))]
async fn service_run_cmd() -> Result<()> {
    bail!("`service-run` is Windows-only — invoked by the SCM, not directly by operators.");
}

/// Track A stage 1 — the session-independent network daemon, SCAFFOLD
/// stage: hosts nothing, heartbeats, exits cleanly on Ctrl-C/terminate.
/// Exists so the two-child supervisor machinery (spawn / independent
/// ladder / shutdown ordering) soaks in the field before the overlay
/// runtime moves into this process (`docs/overlay-session-proof.md` §6).
async fn netd_cmd() -> Result<()> {
    tracing::info!(
        pid = std::process::id(),
        version = env!("CARGO_PKG_VERSION"),
        "netd scaffold alive — Track A stage 1 (no network plane hosted yet)"
    );
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
    tick.tick().await; // the interval's immediate first tick
    loop {
        tokio::select! {
            _ = tick.tick() => tracing::debug!("netd scaffold heartbeat"),
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("netd: terminate signal — exiting cleanly");
                return Ok(());
            }
        }
    }
}

async fn self_update_cmd(check_only: bool) -> Result<()> {
    // macOS: installs are owned by the root update helper
    // (com.roomler.update). A non-root invocation used to download the
    // whole pkg and then fail the spawn on the euid guard — queue the
    // helper instead and say where to watch. Root (`sudo … self-update`)
    // keeps the direct path: it CAN install, and an operator running sudo
    // wants the synchronous behaviour. `--check-only` also stays direct —
    // it touches nothing, so any uid may ask.
    #[cfg(target_os = "macos")]
    if !check_only && unsafe { libc::geteuid() } != 0 {
        // RETIRED-NAME-ANCHOR(14): the printed guidance names
        // /var/log/roomler-agent/update.log and /etc/roomler-agent/disable-auto-update —
        // real macOS paths fixed by the launchd plists, which are pinned to the frozen
        // .app bundle name (D5). They sit inside a string literal, so the anchor is on
        // the statement. docs/fr/FR-21
        return match updater::queue_update_check() {
            Ok(()) => {
                println!(
                    "Queued for the root update helper (com.roomler.update).\n\
                     Watch: /var/log/roomler-agent/update.log\n\
                     (If this Mac set /etc/roomler-agent/disable-auto-update, updates are manual:\n\
                      sudo installer -pkg <pkg> -target /)"
                );
                Ok(())
            }
            Err(e) => Err(anyhow::anyhow!(e).context(format!(
                "could not write the update-helper wake file {}",
                updater::MACOS_UPDATE_TRIGGER
            ))),
        };
    }
    // FR-96 P3 — Linux: where the root update helper owns this host's updates,
    // a non-root `self-update` installs nothing either (it could not write
    // /usr: #2046). It wakes the helper, by the daemon's own decision, so the
    // two never disagree about who installs. Root keeps the direct path, and
    // `--check-only` touches nothing.
    #[cfg(target_os = "linux")]
    if !check_only && let Some(link) = updater::helper_owns_updates() {
        return match updater::queue_update_check() {
            Ok(()) => {
                println!(
                    "Queued for the root update helper (meshharbor-update.service, enabled by {}).\n\
                     Watch: journalctl -u meshharbor-update.service\n\
                     The daemon restarts onto the new binary once nothing it serves would be cut.",
                    link.display()
                );
                Ok(())
            }
            Err(e) => Err(anyhow::anyhow!(e).context(format!(
                "could not write the update-helper wake file {}",
                updater::LINUX_UPDATE_TRIGGER
            ))),
        };
    }
    let outcome = updater::check_once().await;
    match outcome {
        updater::CheckOutcome::UpToDate { current, latest } => {
            println!("Up to date (current: {current}, latest: {latest})");
            Ok(())
        }
        updater::CheckOutcome::UpdateReady {
            current,
            latest,
            installer_path,
        } => {
            if check_only {
                println!("Update available: {current} -> {latest}");
                println!("(skipping install — --check-only)");
                return Ok(());
            }
            println!(
                "Update available: {current} -> {latest}. Installer at {}. Spawning + exiting.",
                installer_path.display()
            );
            // rc.18: route through spawn_installer_with_watch so the
            // manual self-update produces a `last-install.json` trail
            // (matches the BG auto-update path). The watcher subprocess
            // outlives this process and records the installer's exit
            // code + the new binary's --version result. Diagnoses the
            // perMachine UAC-declined / silent-fail case that bit
            // the field-test host on 2026-05-10.
            updater::spawn_installer_with_watch(&installer_path, Some(&latest))
                .context("spawning installer")?;
            // P5/A2 — this process::exit bypasses RAII; drop any exit-node
            // split-default so the update window can't blackhole egress (the new
            // binary's boot reconciler heals it too, but close the gap now).
            // #1690 — only when no daemon owns them: this is a second process,
            // and a running daemon's routes and DNS steer are its own.
            let daemon_running = matches!(
                tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    tunnel_core::localapi::connect()
                )
                .await,
                Ok(Ok(_))
            );
            if !roomlerd::purge_exit_routes_unless_owned(daemon_running) {
                tracing::info!(
                    "self-update: a running daemon owns the overlay's routes and DNS steer — leaving them to it"
                );
            }
            std::process::exit(0);
        }
        updater::CheckOutcome::Skipped(reason) => {
            println!("Update check skipped: {reason}");
            Ok(())
        }
        updater::CheckOutcome::Unreachable(reason) => {
            println!("Update check could not reach the release server: {reason}");
            Ok(())
        }
    }
}

/// Open the preferred encoder, feed it 10 synthetic BGRA frames, and
/// assert at least one keyframe comes out. Used in CI to catch MF init
/// regressions before shipping an MSI. Exits with a non-zero code on
/// any failure so a failed smoke check fails the release build.
async fn encoder_smoke_cmd(
    pref_raw: &str,
    codec_raw: &str,
    name: Option<&str>,
    dump: Option<&str>,
) -> Result<()> {
    use roomlerd::encode::{open_default, open_for_codec};
    use std::io::Write as _;

    // FR-78 P3 — the raw bitstream, for an offline decode (see the flag's doc).
    let mut dump_file = match dump {
        Some(path) => Some(
            std::fs::File::create(path)
                .with_context(|| format!("encoder smoke: cannot create --dump file {path}"))?,
        ),
        None => None,
    };

    // The CI release lane runs `encoder-smoke` on the freshly built EXE, so
    // assert the FFmpeg link contract here instead of paying a separate
    // `cargo test --release --features ...` compile in the workflow (rc.208
    // measured that step at 5m33s per tag: dev-dep tokio-test enables
    // tokio/test-util, dragging the whole tokio subgraph into a test-graph
    // rebuild). Keep the >= 61 floor in LOCKSTEP with the
    // `libavcodec_version_is_ffmpeg_7_or_newer` unit test in encode::ffmpeg.
    #[cfg(feature = "ffmpeg-encoder")]
    {
        let v = roomlerd::encode::ffmpeg::linked_libavcodec_version();
        let major = (v >> 16) & 0xFF;
        let raw = format!("0x{v:06X}");
        tracing::info!(libavcodec_major = major, raw = %raw, "encoder smoke: FFmpeg link check");
        anyhow::ensure!(
            major >= 61,
            "linked libavcodec {major} too old; need FFmpeg 7+ (libavcodec 61+) for hevc_qsv + vp9_qsv (raw {raw})"
        );
    }

    let pref = encode::EncoderPreference::from_str(pref_raw)
        .map_err(|e| anyhow::anyhow!("bad encoder preference {pref_raw:?}: {e}"))?;
    let w = 640u32;
    let h = 480u32;
    let codec = codec_raw.to_ascii_lowercase();
    tracing::info!(width = w, height = h, ?pref, codec = %codec, "encoder smoke: opening encoder");

    // For H.264 keep the historical `open_default` path (preserves
    // logging + behaviour that CI smoke output is pinned to). For any
    // other codec, go through `open_for_codec` which runs the codec-
    // specific cascade and reports whether a demotion happened.
    let (mut enc, actual_codec) = if let Some(name) = name {
        // FR-78 P2 — a named backend, past every cascade: the same open the
        // capability probe runs, so what the probe advertised opens here.
        let (e, actual) = roomlerd::encode::open_named(name, w, h).ok_or_else(|| {
            anyhow::anyhow!(
                "encoder {name} did not open on this host (not a cascade name, no FFmpeg in this build, or no device accepts it)"
            )
        })?;
        (e, actual.to_string())
    } else if codec == "h264" {
        (open_default(w, h, pref), "h264".to_string())
    } else {
        let (e, actual) = open_for_codec(&codec, w, h, pref);
        (e, actual.to_string())
    };
    let backend = enc.name();
    tracing::info!(backend, actual_codec = %actual_codec, "encoder smoke: backend selected");
    if codec != "h264" && actual_codec != codec {
        tracing::warn!(
            requested = %codec,
            actual = %actual_codec,
            "encoder smoke: demoted from requested codec"
        );
    }

    let mut keyframes = 0usize;
    let mut total_bytes = 0usize;
    for i in 0..10 {
        let mut data = vec![0u8; (w * h * 4) as usize];
        // Alternate solid colours so the encoder has content to encode.
        let (b, g, r) = match i % 3 {
            0 => (255, 0, 0),
            1 => (0, 255, 0),
            _ => (0, 0, 255),
        };
        for px in data.chunks_exact_mut(4) {
            px[0] = b;
            px[1] = g;
            px[2] = r;
            px[3] = 255;
        }
        let frame = std::sync::Arc::new(roomlerd::capture::Frame {
            width: w,
            height: h,
            stride: w * 4,
            pixel_format: roomlerd::capture::PixelFormat::Bgra,
            data,
            monotonic_us: (i as u64) * 33_333,
            monitor: 0,
            damage: roomlerd::capture::Damage::Unknown,
            source: None,
        });
        if i == 5 {
            enc.request_keyframe();
        }
        let packets = enc.encode(frame).await?;
        for p in &packets {
            total_bytes += p.data.len();
            if p.is_keyframe {
                keyframes += 1;
            }
            if let Some(f) = dump_file.as_mut() {
                f.write_all(&p.data)
                    .context("encoder smoke: --dump write failed")?;
            }
        }
    }
    if let Some(mut f) = dump_file.take() {
        f.flush().context("encoder smoke: --dump flush failed")?;
        tracing::info!(
            path = dump.unwrap_or(""),
            total_bytes,
            "encoder smoke: bitstream dumped"
        );
    }
    tracing::info!(backend, keyframes, total_bytes, "encoder smoke: done");
    if backend == "noop" {
        bail!("encoder smoke: fell through to NoopEncoder — HW and SW backends both failed");
    }
    if keyframes == 0 {
        bail!("encoder smoke: no keyframes produced (backend={backend})");
    }
    println!(
        "encoder smoke PASSED: backend={backend} keyframes={keyframes} total_bytes={total_bytes}"
    );
    Ok(())
}

/// FR-62 A0 — measure, on THIS host's real encoder, what a `set_bitrate`
/// move actually costs: does it force an IDR, how long does the apply take,
/// and does the encoder track the new maxrate? This is the linchpin of the
/// whole FR-62 decision (the ~9 rate-rationing heuristics exist only because
/// today the answer is "an IDR every time"), so it is measured per host/codec
/// rather than read from a driver table.
///
/// The content is a moving block over a high-frequency stripe band so P-frames
/// carry real residual and the maxrate genuinely clamps quality (solid colours
/// — the plain smoke's content — encode to ~0 bytes and hide the effect).
#[allow(clippy::too_many_arguments)]
async fn encoder_reconfigure_sweep_cmd(
    pref_raw: &str,
    codec_raw: &str,
    name: Option<&str>,
    w: u32,
    h: u32,
    frames_per_rung: u32,
    constrained: bool,
    json: bool,
) -> Result<()> {
    use roomlerd::encode::{open_default, open_for_codec};
    use std::time::Instant;

    let pref = encode::EncoderPreference::from_str(pref_raw)
        .map_err(|e| anyhow::anyhow!("bad encoder preference {pref_raw:?}: {e}"))?;
    let codec = codec_raw.to_ascii_lowercase();
    if constrained {
        tracing::info!(
            "reconfigure-sweep: --constrained noted; A0 opens the encoder's default HRD window \
             (the IDR-on-reconfigure question is independent of HRD %; burst sizes may differ)"
        );
    }
    let (mut enc, actual_codec) = if let Some(name) = name {
        // FR-78 P2 — a named backend, past every cascade: the same open the
        // capability probe runs, so what the probe advertised opens here.
        let (e, actual) = roomlerd::encode::open_named(name, w, h).ok_or_else(|| {
            anyhow::anyhow!(
                "encoder {name} did not open on this host (not a cascade name, no FFmpeg in this build, or no device accepts it)"
            )
        })?;
        (e, actual.to_string())
    } else if codec == "h264" {
        (open_default(w, h, pref), "h264".to_string())
    } else {
        let (e, actual) = open_for_codec(&codec, w, h, pref);
        (e, actual.to_string())
    };
    let backend = enc.name();
    tracing::info!(
        backend,
        actual_codec = %actual_codec,
        width = w, height = h, frames_per_rung,
        "reconfigure-sweep: backend selected"
    );
    if backend == "noop" {
        bail!("reconfigure-sweep: fell through to NoopEncoder — no HW/SW backend on this host");
    }

    // Deterministic moving-block-over-stripes frame. `n` advances the block.
    let make_frame = |n: u32| -> std::sync::Arc<roomlerd::capture::Frame> {
        let mut data = vec![0u8; (w * h * 4) as usize];
        let bx = ((n * 11) % (w.saturating_sub(200)).max(1)) as usize;
        let by = ((n * 7) % (h.saturating_sub(200)).max(1)) as usize;
        for y in 0..h as usize {
            for x in 0..w as usize {
                let i = (y * w as usize + x) * 4;
                let in_block = x >= bx && x < bx + 200 && y >= by && y < by + 200;
                // High-frequency vertical stripes everywhere (spatial detail
                // the encoder must spend bits on), inverted inside the block.
                let stripe = ((x / 3) & 1) == 0;
                let lum: u8 = if in_block ^ stripe { 235 } else { 32 };
                data[i] = lum;
                data[i + 1] = lum;
                data[i + 2] = lum;
                data[i + 3] = 255;
            }
        }
        std::sync::Arc::new(roomlerd::capture::Frame {
            width: w,
            height: h,
            stride: w * 4,
            pixel_format: roomlerd::capture::PixelFormat::Bgra,
            data,
            monotonic_us: (n as u64) * 33_333,
            monitor: 0,
            damage: roomlerd::capture::Damage::Unknown,
            source: None,
        })
    };

    // Rungs: down from 6 Mbps to 200 kbps and back, every value an exact
    // `coarsen_bitrate` ladder rung so coarsening is a no-op and each entry is
    // a genuine reconfigure.
    let down: [u32; 11] = [
        6_000_000, 4_500_000, 3_000_000, 2_000_000, 1_500_000, 1_000_000, 750_000, 550_000,
        400_000, 300_000, 200_000,
    ];
    let rungs: Vec<u32> = down
        .iter()
        .copied()
        .chain(down.iter().rev().copied().skip(1))
        .collect();
    let fps = 60u32; // the ratio's denominator; content is fps-agnostic here.

    let mut frame_n = 0u32;
    struct RungRow {
        target: u32,
        set_ms: f64,
        /// Rate-caused IDR: a keyframe on the FIRST frame after `set_bitrate`.
        key_on_change: u32,
        /// Periodic GOP IDR: a keyframe mid-rung (frame ≥ 1), which is the
        /// encoder's own keyint, not the rate change — reported so it is not
        /// mistaken for one (openh264/vp9_qsv have a short-ish keyint).
        key_periodic: u32,
        mean_bytes: f64,
        first3_max: usize,
        trailing_mean: f64,
        ratio: f64,
    }
    let mut rows: Vec<RungRow> = Vec::new();

    // Warm-up at the top rung: the genuine opening IDR lives here and is not
    // counted as a rate-caused one.
    enc.set_bitrate(rungs[0]);
    for _ in 0..frames_per_rung {
        let _ = enc.encode(make_frame(frame_n)).await?;
        frame_n += 1;
    }

    for (ri, &target) in rungs.iter().enumerate() {
        let t = Instant::now();
        enc.set_bitrate(target);
        let set_ms = t.elapsed().as_secs_f64() * 1000.0;

        let mut key_on_change = 0u32;
        let mut key_periodic = 0u32;
        let mut sizes: Vec<usize> = Vec::with_capacity(frames_per_rung as usize);
        for f in 0..frames_per_rung {
            let packets = enc.encode(make_frame(frame_n)).await?;
            frame_n += 1;
            let mut frame_bytes = 0usize;
            let mut frame_is_key = false;
            for p in &packets {
                frame_bytes += p.data.len();
                frame_is_key |= p.is_keyframe;
            }
            if frame_is_key {
                // Frame 0 of a rung right after `set_bitrate` = the rate change
                // forced it; any later keyframe is the encoder's periodic GOP.
                // (The warm-up rung's frame 0 is the genuine opening IDR.)
                if f == 0 {
                    if ri != 0 {
                        key_on_change += 1;
                    }
                } else {
                    key_periodic += 1;
                }
            }
            sizes.push(frame_bytes);
        }
        let mean_bytes = sizes.iter().sum::<usize>() as f64 / sizes.len().max(1) as f64;
        let first3_max = sizes.iter().take(3).copied().max().unwrap_or(0);
        // Mean of the last few frames of the rung — the settled size the burst
        // is judged against.
        let tail = &sizes[sizes.len().saturating_sub(5)..];
        let trailing_mean = tail.iter().sum::<usize>() as f64 / tail.len().max(1) as f64;
        let expected = target as f64 / fps as f64 / 8.0;
        let ratio = if expected > 0.0 {
            mean_bytes / expected
        } else {
            0.0
        };
        rows.push(RungRow {
            target,
            set_ms,
            key_on_change,
            key_periodic,
            mean_bytes,
            first3_max,
            trailing_mean,
            ratio,
        });
    }

    // Verdict: an in-place-capable backend emits 0 rate-caused IDRs, applies
    // fast, tracks within ±25 %, and does not burst > 2× on the change.
    let total_idr: u32 = rows.iter().map(|r| r.key_on_change).sum();
    let total_periodic: u32 = rows.iter().map(|r| r.key_periodic).sum();
    let max_set_ms = rows.iter().map(|r| r.set_ms).fold(0.0, f64::max);
    let worst_ratio_dev = rows
        .iter()
        .map(|r| (r.ratio - 1.0).abs())
        .fold(0.0, f64::max);
    let worst_burst = rows
        .iter()
        .map(|r| {
            if r.trailing_mean > 0.0 {
                r.first3_max as f64 / r.trailing_mean
            } else {
                0.0
            }
        })
        .fold(0.0, f64::max);
    let pass = total_idr == 0 && max_set_ms < 5.0 && worst_ratio_dev <= 0.25 && worst_burst <= 2.0;

    if json {
        let rungs_json: Vec<String> = rows
            .iter()
            .map(|r| {
                format!(
                    "{{\"target\":{},\"set_ms\":{:.3},\"rate_idr\":{},\"periodic_idr\":{},\"mean_bytes\":{:.0},\"ratio\":{:.3},\"first3_max\":{},\"trailing_mean\":{:.0}}}",
                    r.target, r.set_ms, r.key_on_change, r.key_periodic, r.mean_bytes, r.ratio, r.first3_max, r.trailing_mean
                )
            })
            .collect();
        println!(
            "ROOMLER_A0_JSON:{{\"backend\":\"{backend}\",\"codec\":\"{actual_codec}\",\"w\":{w},\"h\":{h},\"fpr\":{frames_per_rung},\"constrained\":{constrained},\"total_rate_idr\":{total_idr},\"total_periodic_idr\":{total_periodic},\"max_set_ms\":{max_set_ms:.3},\"worst_ratio_dev\":{worst_ratio_dev:.3},\"worst_burst\":{worst_burst:.3},\"pass\":{pass},\"rungs\":[{}]}}",
            rungs_json.join(",")
        );
    } else {
        println!(
            "reconfigure-sweep: backend={backend} codec={actual_codec} {w}x{h} frames/rung={frames_per_rung}"
        );
        println!(
            "  target_bps  set_ms  rate_IDR  gop_IDR  mean_bytes  ratio  first3_max  trailing_mean"
        );
        for r in &rows {
            println!(
                "  {:>9}  {:>6.2}  {:>7}  {:>7}  {:>10.0}  {:>5.2}  {:>10}  {:>13.0}",
                r.target,
                r.set_ms,
                r.key_on_change,
                r.key_periodic,
                r.mean_bytes,
                r.ratio,
                r.first3_max,
                r.trailing_mean
            );
        }
        println!(
            "VERDICT: {} — rate-caused IDRs={total_idr} (want 0), periodic GOP IDRs={total_periodic} (informational), max set_ms={max_set_ms:.2} (want <5), worst |ratio-1|={worst_ratio_dev:.2} (want ≤0.25), worst burst={worst_burst:.2} (want ≤2)",
            if pass {
                "PASS (in-place capable)"
            } else {
                "FAIL (rate change costs an IDR/rebuild)"
            }
        );
    }
    Ok(())
}

/// `capture-smoke` CLI dispatch — "does screen capture work on this host,
/// and does it produce a real picture?"
///
/// Deliberately goes through `capture::open_default` rather than naming a
/// backend, so it answers the question an operator actually has (which
/// backend did this host end up on?) and so the cascade itself is under test.
///
/// ⚠️ The `--dump` PPM is not decoration. A capture backend that decodes the
/// framebuffer with the wrong pixel layout returns a frame of exactly the
/// right size, at the right rate, with perfect geometry — and completely wrong
/// colours. Every counter here would be green for that frame. Only looking at
/// the image catches it, which is how FR-36's 10-bit scanout was found.
/// FR-56 P1 — answer "can Remote Apps manage a desktop here, and what does it
/// see", on the host, with no session.
fn apps_probe_cmd(config_path: &std::path::Path) -> anyhow::Result<()> {
    use roomlerd::apps;

    // FR-56 AC10 — answer as the DAEMON would: install the device's own
    // `[virtual_desktop_apps]` first. Until this the probe ran on the built-in
    // default (apps enabled) and could print `supported: true` on a device
    // whose owner had turned them off — a gap of exactly the kind the probe
    // exists to remove.
    //
    // ⚠️ `read_if_present`, not `load`: this is a PROBE of a config the process
    // does not run on. `load` self-heals — on an unreadable live file it logs
    // "the host must be re-enrolled" at ERROR and can promote the `.prev` copy
    // back over it — and a diagnostic command must never write the device's
    // config as a side effect of being run (FR-66's rule).
    match config::read_if_present(&config_path.to_path_buf()) {
        Some(cfg) => {
            println!(
                "config: {} ([virtual_desktop_apps] enabled = {}, {} allowlisted)",
                config_path.display(),
                cfg.virtual_desktop_apps.enabled,
                cfg.virtual_desktop_apps.allowlist.len()
            );
            apps::set_apps_config(cfg.virtual_desktop_apps.clone());
        }
        None => println!(
            "config: {} absent or unreadable — probing with the built-in default (apps enabled)",
            config_path.display()
        ),
    }

    match apps::availability() {
        Ok(()) => println!("apps supported: true"),
        Err(why) => {
            println!("apps supported: false");
            println!("  reason [{}]: {}", why.code(), why.reason());
            println!(
                "  (the same code + reason ride `rc:apps.list.reply` as `unavailable`, so the \
                 viewer shows this instead of hiding the button)"
            );
            return Ok(());
        }
    }

    let be = match apps::backend() {
        Ok(be) => be,
        Err(why) => {
            println!(
                "  supported a moment ago, but no backend now [{}]: {}",
                why.code(),
                why.reason()
            );
            return Ok(());
        }
    };
    // FR-56 P2 — what this listing covers, and what it structurally cannot.
    let cov = be.coverage();
    println!("sources: {}", cov.sources.join(", "));
    match &cov.unlisted {
        Some(why) => println!("NOT listed: {why}"),
        None => println!("NOT listed: (nothing — this source is the whole desktop)"),
    }
    // FR-56 P5 — a desktop being reachable does not make the buttons work.
    if cov.missing_tools.is_empty() {
        println!("missing tools: (none — every helper this backend runs is installed)");
    } else {
        println!("missing tools:");
        for t in &cov.missing_tools {
            println!("  {} — blocks {} ({})", t.tool, t.blocks, t.install);
        }
        println!(
            "  ⚠️  the desktop IS reachable, so listing and focusing still work — it is the launch buttons above that would fail at click time"
        );
    }

    match be.list() {
        Ok(windows) => {
            println!("windows: {}", windows.len());
            for w in &windows {
                let marks = match (&w.app_key, &w.session, w.focused) {
                    (_, Some(t), _) => format!(" [tmux:{t}]"),
                    (Some(k), _, _) => format!(" [app:{k}]"),
                    _ => String::new(),
                };
                let focus = if w.focused { " *focused" } else { "" };
                println!("  {:<12} {}{marks}{focus}", w.window_id, w.title);
            }
            if windows.is_empty() {
                println!(
                    "  (an EMPTY list is not the same as unsupported — the desktop answered \
                     and has no windows. ⚠️ Native Wayland windows are invisible to this X11 \
                     backend and would not appear here even if present.)"
                );
            }
        }
        Err(e) => println!("list failed: {e:#}"),
    }
    Ok(())
}

/// The capture and input keys a smoke command names when it starts, so the
/// line says which cascade it is about to test.
const SMOKE_CONFIG_KEYS: [&str; 8] = [
    "DRM_CAPTURE",
    "UINPUT",
    "PORTAL_CAPTURE",
    "PORTAL_INPUT",
    "MUTTER_CAPTURE",
    "WINDOW_CAPTURE",
    "X11_DAMAGE",
    "WAYLAND_AWARE",
];

/// FR-93 P1 — a smoke test answers as the DAEMON would: it publishes the
/// device's own config-backed knobs first (`config::env_fallbacks`, the map
/// `run` publishes), so a key set with `meshharbor config set` is honoured by the
/// smoke that is meant to prove it. Before this, `capture-smoke` read env and
/// built-in defaults only, and on a host configured through the config file
/// it tested a cascade the daemon was not running.
///
/// ⚠️ `read_if_present`, not `load`, as `apps-probe` does: a diagnostic must
/// never write the config it probes (`load` self-heals).
fn publish_config_for_smoke(config_path: &std::path::Path, what: &str) {
    let Some(cfg) = config::read_if_present(&config_path.to_path_buf()) else {
        println!(
            "{what}: no config at {} — env and built-in defaults only",
            config_path.display()
        );
        return;
    };
    let fallbacks = config::env_fallbacks(&cfg);
    let set: Vec<String> = SMOKE_CONFIG_KEYS
        .iter()
        .filter_map(|k| {
            fallbacks
                .get(*k)
                .map(|v| format!("{}={v}", k.to_ascii_lowercase()))
        })
        .collect();
    println!(
        "{what}: config {} — {} (an env var still wins)",
        config_path.display(),
        if set.is_empty() {
            "no capture or input keys set".to_string()
        } else {
            set.join(" ")
        }
    );
    tunnel_core::env::register_config_fallbacks(fallbacks);
}

/// FR-93 P1 — how long one `next_frame` may take before the smoke calls the
/// backend stalled. Generous: every real arm delivers in milliseconds once
/// open (the portal's consent wait is inside `open_default`, bounded there).
const SMOKE_FRAME_DEADLINE: std::time::Duration = std::time::Duration::from_secs(15);

async fn capture_smoke_cmd(
    frames: u32,
    dump: Option<&str>,
    fps: u32,
    downscale: &str,
) -> Result<()> {
    use roomlerd::capture::{self, DownscalePolicy, PixelFormat};

    let policy = match downscale.trim().to_ascii_lowercase().as_str() {
        "never" => DownscalePolicy::Never,
        "auto" => DownscalePolicy::Auto,
        "always" => DownscalePolicy::Always,
        other => bail!("unknown --downscale {other:?} (never|auto|always)"),
    };
    // FR-45 P1 — say whether the desktop portal could have served this host.
    // Printed BEFORE the cascade runs, because the useful question when a
    // Wayland host falls through to X11 is "was the portal even an option?",
    // and answering it should not require opening a session.
    //
    // P2a: asks THROUGH THE SESSION HELPER. Run as root — which is how the
    // daemon runs, and how an operator reaches this over `meshharbor exec`/ssh —
    // the direct call can only ever answer `no-session-bus`, so this line was
    // previously unable to report a working portal on any host where one
    // existed. That gap is exactly what P2a closes, and this is where it shows.
    #[cfg(all(target_os = "linux", feature = "portal-capture"))]
    {
        let st = roomlerd::capture::portal::detect_in_session();
        println!("capture-smoke: portal={st} — {}", st.advice());
    }

    let mut cap = capture::open_default(fps.max(1), policy);
    // FR-93 P1 — a capturer that already knows it will produce nothing says so,
    // with the reason a viewer would be given. Asked for frames anyway, it
    // parked this command for an HOUR per frame (`NoopCapture::next_frame`).
    if let Some(reason) = cap.unavailable() {
        bail!(
            "capture-smoke FAILED: this host produces no pixels — {} ({}). {}",
            reason.code.wire(),
            reason.detail,
            reason.code.hint()
        );
    }
    let mut delivered = 0u32;
    let mut empty = 0u32;
    let mut last: Option<capture::Frame> = None;
    let mut worst_ms = 0f64;
    let mut total_ms = 0f64;

    for _ in 0..frames.max(1) {
        let t0 = std::time::Instant::now();
        let Ok(next) = tokio::time::timeout(SMOKE_FRAME_DEADLINE, cap.next_frame()).await else {
            bail!(
                "capture-smoke FAILED: the backend opened, then gave no answer within {} s \
                 ({delivered} frames delivered before it stalled)",
                SMOKE_FRAME_DEADLINE.as_secs()
            );
        };
        match next {
            Ok(Some(f)) => {
                let ms = t0.elapsed().as_secs_f64() * 1000.0;
                total_ms += ms;
                worst_ms = worst_ms.max(ms);
                delivered += 1;
                last = Some(f);
            }
            // Not a failure: a paced backend legitimately reports "nothing new".
            Ok(None) => empty += 1,
            Err(e) => bail!("capture-smoke: next_frame failed: {e:#}"),
        }
    }

    let Some(frame) = last else {
        bail!(
            "capture-smoke FAILED: {frames} attempts, {empty} empty, ZERO frames delivered \
             (monitors={})",
            cap.monitor_count()
        );
    };

    println!(
        "capture-smoke: delivered={delivered} empty={empty} unchanged={} monitors={} \
         {}x{} stride={} format={:?} source={:?} mean_ms={:.2} worst_ms={:.2}",
        cap.frames_unchanged(),
        cap.monitor_count(),
        frame.width,
        frame.height,
        frame.stride,
        frame.pixel_format,
        frame.source,
        total_ms / delivered.max(1) as f64,
        worst_ms,
    );

    if let Some(path) = dump {
        if frame.pixel_format != PixelFormat::Bgra {
            bail!(
                "capture-smoke: --dump only understands BGRA frames, got {:?}",
                frame.pixel_format
            );
        }
        let (w, h) = (frame.width as usize, frame.height as usize);
        let stride = frame.stride as usize;
        let mut out = Vec::with_capacity(w * h * 3 + 32);
        out.extend_from_slice(format!("P6\n{w} {h}\n255\n").as_bytes());
        for y in 0..h {
            let row = &frame.data[y * stride..y * stride + w * 4];
            for x in 0..w {
                // BGRA in memory -> RGB on the wire.
                out.push(row[x * 4 + 2]);
                out.push(row[x * 4 + 1]);
                out.push(row[x * 4]);
            }
        }
        std::fs::write(path, &out).with_context(|| format!("writing {path}"))?;
        println!("capture-smoke: wrote {path} ({} bytes)", out.len());
    }
    Ok(())
}

/// `input-smoke` CLI dispatch — "does input injection work on this host?"
///
/// Goes through `input::open_default` rather than naming a backend, so it
/// answers the operator's actual question (which one did this host pick?) and
/// puts the cascade itself under test.
fn input_smoke_cmd(
    move_to: Option<&str>,
    click: Option<&str>,
    text: Option<&str>,
    delay_ms: u64,
) -> Result<()> {
    use roomlerd::input::{Button, InputMsg};

    let mut inj = roomlerd::input::open_default();
    println!("input-smoke: has_permission={}", inj.has_permission());
    let pause = || std::thread::sleep(std::time::Duration::from_millis(delay_ms));

    let mut pos = (0.5f32, 0.5f32);
    if let Some(spec) = move_to {
        let (a, b) = spec.split_once(',').ok_or_else(|| {
            anyhow::anyhow!("--move-to wants `x,y` (normalised 0..1), got {spec:?}")
        })?;
        pos = (a.trim().parse()?, b.trim().parse()?);
        inj.inject(InputMsg::MouseMove {
            x: pos.0,
            y: pos.1,
            mon: 0,
        })?;
        println!("input-smoke: moved to {:?}", pos);
        pause();
    }

    if let Some(b) = click {
        let btn = match b.trim().to_ascii_lowercase().as_str() {
            "left" => Button::Left,
            "right" => Button::Right,
            "middle" => Button::Middle,
            other => bail!("unknown --click {other:?} (left|right|middle)"),
        };
        for down in [true, false] {
            inj.inject(InputMsg::MouseButton {
                btn,
                down,
                x: pos.0,
                y: pos.1,
                mon: 0,
            })?;
            pause();
        }
        println!("input-smoke: clicked {b}");
    }

    if let Some(t) = text {
        let mut sent = 0usize;
        let mut skipped = 0usize;
        for ch in t.chars() {
            let Some((hid, shift)) = ascii_to_hid(ch) else {
                skipped += 1;
                continue;
            };
            // 0xe1 = HID Left Shift.
            if shift {
                inj.inject(InputMsg::Key {
                    code: 0xe1,
                    down: true,
                    mods: 0,
                })?;
            }
            inj.inject(InputMsg::Key {
                code: hid,
                down: true,
                mods: 0,
            })?;
            pause();
            inj.inject(InputMsg::Key {
                code: hid,
                down: false,
                mods: 0,
            })?;
            if shift {
                inj.inject(InputMsg::Key {
                    code: 0xe1,
                    down: false,
                    mods: 0,
                })?;
            }
            pause();
            sent += 1;
        }
        println!("input-smoke: typed {sent} chars, {skipped} unmappable");
    }
    println!("input-smoke: done");
    Ok(())
}

/// ASCII → HID usage (page 0x07), **US layout**, for `input-smoke` only.
///
/// ⚠️ Deliberately NOT in the injector. evdev carries physical keys, so
/// turning text into keystrokes needs the TARGET's layout; assuming US there
/// would type mojibake on every other layout. Here the operator is typing a
/// known test string and can see the result, so the assumption is visible and
/// bounded.
fn ascii_to_hid(ch: char) -> Option<(u32, bool)> {
    let lower = ch.to_ascii_lowercase();
    let shift = ch.is_ascii_uppercase();
    let hid = match lower {
        'a'..='z' => 0x04 + (lower as u32 - 'a' as u32),
        '1'..='9' => 0x1e + (lower as u32 - '1' as u32),
        '0' => 0x27,
        ' ' => 0x2c,
        '\n' => 0x28,
        '-' => 0x2d,
        '.' => 0x37,
        '/' => 0x38,
        _ => return None,
    };
    Some((hid, shift))
}

/// `system-capture-smoke` CLI dispatch. Synchronous (no .await) — the
/// WGC probe runs on the calling thread which carries the desktop
/// attachment from `SetThreadDesktop`. A tokio runtime would defeat
/// the purpose: tasks would be moved to worker threads that have
/// their own (default) desktop attachment.
#[cfg(all(target_os = "windows", feature = "wgc-capture"))]
fn system_capture_smoke_cmd(desktop_raw: &str, frames: u32, timeout_ms: u32) -> Result<()> {
    use roomlerd::win_service::capture_smoke::{self, DesktopTarget};
    use std::str::FromStr;
    let target = DesktopTarget::from_str(desktop_raw)
        .map_err(|e| anyhow::anyhow!("bad --desktop {desktop_raw:?}: {e}"))?;
    capture_smoke::run(target, frames, timeout_ms)
}

#[cfg(not(all(target_os = "windows", feature = "wgc-capture")))]
fn system_capture_smoke_cmd(_desktop_raw: &str, _frames: u32, _timeout_ms: u32) -> Result<()> {
    bail!(
        "`system-capture-smoke` requires Windows + the `wgc-capture` feature. \
         Rebuild with `cargo build -p roomlerd --release --features full-hw`."
    );
}

/// `system-context-probe` CLI dispatch (M3 A1 Pre-flight #2/#3/#5).
/// Synchronous like `system-capture-smoke` because the probes touch
/// Win32 desktop / token state that is per-thread.
#[cfg(target_os = "windows")]
fn system_context_probe_cmd(mode_raw: &str) -> Result<()> {
    use roomlerd::win_service::system_context_probe::{self, ProbeMode};
    use std::str::FromStr;
    let mode = ProbeMode::from_str(mode_raw)
        .map_err(|e| anyhow::anyhow!("bad probe mode {mode_raw:?}: {e}"))?;
    system_context_probe::run(mode)
}

#[cfg(not(target_os = "windows"))]
fn system_context_probe_cmd(_mode_raw: &str) -> Result<()> {
    bail!("`system-context-probe` is Windows-only.");
}

async fn caps_cmd() -> Result<()> {
    let caps = roomlerd::encode::caps::detect();
    println!("codecs: {:?}", caps.codecs);
    println!("hw_encoders: {:?}", caps.hw_encoders);
    // FR-84 D4 — the cell matrix the desktop's Overview card draws, one
    // line per cell, so a field check can compare the two line by line.
    // `summarize_cached` reads the cache `detect()` just filled, plus the
    // denylist in force.
    let summary = roomlerd::encode::caps::summarize_cached();
    for cell in &summary.cells {
        println!(
            "cell: {}_{} chroma={:?} hw={}",
            cell.codec, cell.backend, cell.chroma, cell.hardware
        );
    }
    println!("denied_cells: {:?}", summary.denied);
    println!(
        "probe_ms: {} ({})",
        summary
            .probe_ms
            .map(|ms| ms.to_string())
            .unwrap_or_else(|| "-".into()),
        if summary.probe_cached {
            "cached"
        } else {
            "fresh"
        }
    );
    println!("transports: {:?}", caps.transports);
    println!("has_input_permission: {}", caps.has_input_permission);
    // macOS has a THIRD state and `has_input_permission` cannot express it.
    // That field is a CONJUNCTION — feature && gui_session_available() &&
    // input_permission_granted() — so a root LaunchDaemon prints `false`
    // because it is not in a GUI session, NOT because the grant is missing.
    // `permissions` is where `caps` already distinguishes them
    // (`no-gui-session` vs `screen-capture` / `input`); it just was never
    // printed, so the CLI could only ever show the ambiguous half.
    //
    // Cost paid 2026-08-30: a week of "Accessibility is still revoked"
    // reports, every one of them read off the macOS `-daemon` row, while the
    // grant had been in place since 08-28 and the per-user half saw it fine.
    // The comment on `permissions` in encode/caps.rs predicts exactly this
    // ("the device list tells the operator to go fix something that is not
    // broken") — the prediction was right and the CLI was the blind spot.
    println!(
        "permissions: {:?}",
        caps.permissions.clone().unwrap_or_default()
    );
    println!("supports_clipboard: {}", caps.supports_clipboard);
    println!("supports_file_transfer: {}", caps.supports_file_transfer);
    println!(
        "max_simultaneous_sessions: {}",
        caps.max_simultaneous_sessions
    );
    Ok(())
}

async fn displays_cmd() -> Result<()> {
    let list = roomlerd::displays::enumerate();
    println!("displays ({}):", list.len());
    for d in &list {
        println!(
            "  index={} name={:?} {}x{} scale={:.2}{}",
            d.index,
            d.name,
            d.width_px,
            d.height_px,
            d.scale,
            if d.primary { " (primary)" } else { "" }
        );
    }
    Ok(())
}

#[cfg(feature = "system-context")]
fn peer_presence_status_cmd() -> Result<()> {
    use roomlerd::system_context::peer_presence;

    let snap = peer_presence::snapshot();
    println!("== peer-presence marker status ==========================");
    println!("path:         {}", snap.path.display());
    println!("exists:       {}", snap.exists);
    match snap.age {
        Some(age) => println!("age:          {:.1}s", age.as_secs_f64()),
        None => println!("age:          n/a (file missing or mtime unreadable)"),
    }
    println!(
        "fresh:        {}  (must be true for SystemContext spawn)",
        snap.fresh
    );
    if let Some(err) = &snap.error {
        println!("error:        {err}");
    }
    println!();
    println!("Constants:");
    println!(
        "  HEARTBEAT_INTERVAL = {:?}",
        peer_presence::HEARTBEAT_INTERVAL
    );
    println!(
        "  PRESENCE_MAX_AGE   = {:?}",
        peer_presence::PRESENCE_MAX_AGE
    );
    println!();
    println!("Diagnostic notes:");
    println!("  * The user-context worker writes the marker every");
    println!("    HEARTBEAT_INTERVAL while WebRTC peer is Connected.");
    println!("  * is_signaled() returns true iff exists AND age <= PRESENCE_MAX_AGE.");
    println!("  * If `exists=false`: the worker isn't writing it.");
    println!("    Check the worker's log for `peer_presence: first heartbeat written`");
    println!("    or `peer_presence heartbeat write failed`.");
    println!("  * If `exists=true` but `fresh=false`: the worker stopped");
    println!("    heartbeating (peer disconnected or worker crashed).");
    println!("  * If `error=Some(...)`: filesystem ACL issue. Verify");
    println!(
        "    {} is writable from the calling process.",
        snap.path.display()
    );

    // Try a write-then-read round-trip from this process to surface
    // ACL errors immediately (the calling user may differ from the
    // user-context worker that the supervisor spawned).
    println!();
    println!("== self-write probe (this process) ======================");
    match peer_presence::signal_connected() {
        Ok(()) => {
            println!("signal_connected(): OK");
            let after = peer_presence::snapshot();
            println!(
                "post-write snapshot: exists={} age={:?} fresh={}",
                after.exists, after.age, after.fresh
            );
        }
        Err(e) => {
            println!("signal_connected(): FAILED — {e}");
            println!("This process cannot write the marker. The user-context");
            println!("worker likely can't either. Check ACL on the parent dir.");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Locks the CLI parses that wizard Done-page snippets rely on:
    //! the unified roomler-setup wizard surfaces
    //! `meshharbord disable-system-context`
    //! (`agents/roomler-setup/src/front/index.html`, SystemContext
    //! note), and the rc.30-era operator snippet still in field hands
    //! used `enable-system-context` / `set-service-env-var`. If any of
    //! these parses break, those instructions go dead in operator
    //! hands.

    use super::*;
    /// FR-21 P3 (D1) — the acceptance case taken from the LIVE fleet, not invented.
    /// The three cluster nodes each carried these exact four entries in an
    /// operator-authored `/etc/systemd/system/meshharbord.service.d/virtual-desktop.conf`,
    /// which a package upgrade never rewrites. While the read chain honoured
    /// the original spelling, this test proved it did — because if it ever
    /// stopped, the daemon would start perfectly and quietly ignore every one
    /// of them, and the virtual desktop would simply never come up.
    ///
    /// FR-46 P2b inverted it. The hosts were migrated FIRST (both spellings
    /// side by side, then the legacy half removed once `systemctl show`
    /// confirmed the current one was in effect), and only then did the arm come
    /// out. So the assertion is now the opposite one, and it is the assertion
    /// that matters from here: the retired spelling must be INERT, and must be
    /// REPORTED rather than silently dropped.
    // RETIRED-NAME-ANCHOR(30): the retired spelling is the INPUT this test
    // feeds in order to prove it does nothing. Rewriting these names would
    // delete the coverage. docs/fr/FR-46
    #[test]
    fn the_retired_drop_in_spelling_is_inert_and_reported() {
        const KEYS: [&str; 4] = [
            "ROOMLER_AGENT_VIRTUAL_DESKTOP",
            "ROOMLER_AGENT_VIRTUAL_DESKTOP_RESOLUTION",
            "ROOMLER_AGENT_VIRTUAL_DESKTOP_WM",
            "ROOMLER_AGENT_VIRTUAL_DESKTOP_STARTUP",
        ];
        // SAFETY (edition 2024): these four suffixes are touched by no other test.
        unsafe {
            for k in KEYS {
                std::env::remove_var(k);
            }
            tunnel_core::env::test_env::clear("VIRTUAL_DESKTOP");
        }
        assert!(
            !virtual_desktop_requested(),
            "unset must not request the virtual desktop"
        );

        // RAW-ENV-DELIBERATE: `test_env::set_as` refuses a prefix outside the
        // read chain, and this needs the retired one set on its own.
        unsafe { std::env::set_var(KEYS[0], "1") };
        assert!(
            !virtual_desktop_requested(),
            "the retired spelling must be IGNORED — the arm was removed once \
             every host that set one had been migrated"
        );
        assert!(
            tunnel_core::env::retired_env_present().contains(&KEYS[0].to_string()),
            "...and being ignored must be REPORTED, or a host that still sets \
             one loses the setting with nothing said"
        );

        // The current spelling works, so a migrated host behaves as before.
        unsafe { std::env::remove_var(KEYS[0]) };
        unsafe { tunnel_core::env::test_env::set_as("ROOMLERD_", "VIRTUAL_DESKTOP", "1") };
        assert!(virtual_desktop_requested());
        unsafe { tunnel_core::env::test_env::clear("VIRTUAL_DESKTOP") };
    }

    use clap::Parser;

    #[test]
    fn parses_enable_system_context_default() {
        let cli = Cli::try_parse_from(["roomlerd", "enable-system-context"]).unwrap();
        match cli.command {
            Some(Command::EnableSystemContext { no_restart }) => assert!(!no_restart),
            other => panic!("expected EnableSystemContext, got {other:?}"),
        }
    }

    #[test]
    fn parses_enable_system_context_no_restart() {
        let cli =
            Cli::try_parse_from(["roomlerd", "enable-system-context", "--no-restart"]).unwrap();
        match cli.command {
            Some(Command::EnableSystemContext { no_restart }) => assert!(no_restart),
            other => panic!("expected EnableSystemContext --no-restart, got {other:?}"),
        }
    }

    #[test]
    fn parses_disable_system_context_default() {
        let cli = Cli::try_parse_from(["roomlerd", "disable-system-context"]).unwrap();
        match cli.command {
            Some(Command::DisableSystemContext { no_restart }) => assert!(!no_restart),
            other => panic!("expected DisableSystemContext, got {other:?}"),
        }
    }

    /// #1727 — the exact spelling `wix-perMachine/main.wxs` puts in the
    /// `KeepSystemContext` action's ExeCommand. That action is
    /// Return='ignore', so a name that stopped parsing would fail silently
    /// and every hand-run install would leave SystemContext off again.
    #[test]
    fn parses_keep_system_context_as_the_msi_spells_it() {
        let cli = Cli::try_parse_from(["roomlerd", "keep-system-context"]).unwrap();
        match cli.command {
            Some(Command::KeepSystemContext { no_restart }) => assert!(!no_restart),
            other => panic!("expected KeepSystemContext, got {other:?}"),
        }
    }

    #[test]
    fn parses_set_service_env_var_long_form() {
        let cli = Cli::try_parse_from([
            "roomlerd",
            "set-service-env-var",
            "--name",
            "ROOMLERD_ENABLE_SYSTEM_SWAP",
            "--value",
            "1",
        ])
        .unwrap();
        match cli.command {
            Some(Command::SetServiceEnvVar { name, value }) => {
                assert_eq!(name, "ROOMLERD_ENABLE_SYSTEM_SWAP");
                assert_eq!(value.as_deref(), Some("1"));
            }
            other => panic!("expected SetServiceEnvVar, got {other:?}"),
        }
    }

    #[test]
    fn parses_set_service_env_var_without_value_for_unset() {
        let cli = Cli::try_parse_from([
            "roomlerd",
            "set-service-env-var",
            "--name",
            "ROOMLERD_ENABLE_SYSTEM_SWAP",
        ])
        .unwrap();
        match cli.command {
            Some(Command::SetServiceEnvVar { name, value }) => {
                assert_eq!(name, "ROOMLERD_ENABLE_SYSTEM_SWAP");
                assert!(value.is_none(), "expected None (unset), got {value:?}");
            }
            other => panic!("expected SetServiceEnvVar, got {other:?}"),
        }
    }

    #[test]
    fn parses_restart_service_default_timeout() {
        let cli = Cli::try_parse_from(["roomlerd", "restart-service"]).unwrap();
        match cli.command {
            Some(Command::RestartService { timeout_secs }) => assert_eq!(timeout_secs, 120),
            other => panic!("expected RestartService, got {other:?}"),
        }
    }

    #[test]
    fn parses_restart_service_custom_timeout() {
        let cli =
            Cli::try_parse_from(["roomlerd", "restart-service", "--timeout-secs", "60"]).unwrap();
        match cli.command {
            Some(Command::RestartService { timeout_secs }) => assert_eq!(timeout_secs, 60),
            other => panic!("expected RestartService --timeout-secs 60, got {other:?}"),
        }
    }

    /// rc.53 Phase 7: the stderr warning for the
    /// `%APPDATA% / %PROGRAMDATA%` same-session asymmetry that WINHOST-B
    /// burned hours on. Locks the marker phrases so a refactor that
    /// drops "sc start Roomler" or "%APPDATA%" or "without
    /// --machine-global" trips the test before it ships.
    #[cfg(target_os = "windows")]
    #[test]
    fn enroll_warning_message_contains_expected_phrases() {
        let msg = warning_message_for_user_context_enroll();
        assert!(
            msg.contains("sc start Roomler"),
            "warning must reference `sc start Roomler` so the operator can run option (a): {msg}"
        );
        assert!(
            msg.contains("%APPDATA%"),
            "warning must call out %APPDATA% explicitly so the operator understands which path the user shell reads: {msg}"
        );
        assert!(
            msg.contains("%PROGRAMDATA%"),
            "warning must call out %PROGRAMDATA% so the operator sees the asymmetry: {msg}"
        );
        assert!(
            msg.contains("without --machine-global"),
            "warning must mention option (b) — re-running enroll without --machine-global: {msg}"
        );
        assert!(
            msg.contains("machine_id"),
            "warning must explain the failure mode (different machine_id) so the operator understands WHY this matters: {msg}"
        );
    }

    /// The rc.30 Done-page snippet's exact form. If this test parses,
    /// any operator copy-pasting `front/index.html:182` will get a
    /// recognised command. If it fails, the snippet is dead-code.
    #[test]
    fn rc30_done_page_snippet_parses() {
        // Line 1: set-service-env-var
        let cli = Cli::try_parse_from([
            "roomlerd",
            "set-service-env-var",
            "--name",
            "ROOMLERD_ENABLE_SYSTEM_SWAP",
            "--value",
            "1",
        ]);
        assert!(cli.is_ok(), "rc.30 snippet line 1 must parse: {cli:?}");
        // Line 2: restart-service
        let cli = Cli::try_parse_from(["roomlerd", "restart-service"]);
        assert!(cli.is_ok(), "rc.30 snippet line 2 must parse: {cli:?}");
    }

    // ─── rc.52: config-path resolution ladder ──────────────────────────────

    #[test]
    // RETIRED-NAME-ANCHOR-BEGIN
    // These cases feed the PRE-RENAME machine-global config path on purpose: that is
    // the path a pre-rename host still has, and picking it correctly is what keeps an
    // upgraded host from losing its enrolment.
    // INVARIANT: a retired name here must be a path a real host can still have.
    // docs/fr/FR-21
    fn pick_config_path_explicit_wins_unconditionally() {
        // --config is an operator override — used verbatim, no
        // existence check, regardless of worker role.
        let explicit = PathBuf::from(r"D:\custom\config.toml");
        let got = pick_config_path(
            Some(explicit.clone()),
            true,
            Some(Path::new(
                r"C:\ProgramData\roomler\roomler-agent\config.toml",
            )),
            Path::new(r"C:\Users\u\AppData\config.toml"),
            None,
            |_| true, // everything "exists" — explicit still wins
        );
        assert_eq!(got, explicit);
    }

    #[test]
    fn pick_config_path_system_context_prefers_machine_global() {
        let mg = Path::new(r"C:\ProgramData\roomler\roomler-agent\config.toml");
        let default = Path::new(r"C:\Windows\System32\config\systemprofile\config.toml");
        let got = pick_config_path(None, true, Some(mg), default, None, |p| p == mg);
        assert_eq!(got, mg);
    }

    #[test]
    fn pick_config_path_non_system_context_ignores_machine_global() {
        // A perUser / perMachine-non-SC worker never reads the
        // machine-global path even if it exists.
        let mg = Path::new(r"C:\ProgramData\roomler\roomler-agent\config.toml");
        let default = Path::new(r"C:\Users\u\AppData\config.toml");
        let got = pick_config_path(None, false, Some(mg), default, None, |p| {
            p == mg || p == default
        });
        assert_eq!(got, default);
    }

    #[test]
    fn pick_config_path_system_context_falls_to_active_user() {
        // Machine-global absent, default (SYSTEM profile) absent —
        // post-logon SC worker uses the active-user fallback.
        let mg = Path::new(r"C:\ProgramData\roomler\roomler-agent\config.toml");
        let default = Path::new(r"C:\Windows\System32\config\systemprofile\config.toml");
        let active = Path::new(r"C:\Users\u\AppData\Roaming\roomler\config.toml");
        let got = pick_config_path(None, true, Some(mg), default, Some(active), |p| p == active);
        assert_eq!(got, active);
    }

    #[test]
    fn pick_config_path_returns_default_when_nothing_exists() {
        // Nothing on disk → default, so config::load fails with an
        // honest "not found" naming that path.
        let mg = Path::new(r"C:\ProgramData\roomler\roomler-agent\config.toml");
        let default = Path::new(r"C:\Windows\System32\config\systemprofile\config.toml");
        let got = pick_config_path(None, true, Some(mg), default, None, |_| false);
        assert_eq!(got, default);
    }

    // ─── rc.52: self-heal predicate ────────────────────────────────────────

    #[test]
    fn should_self_heal_only_for_system_context_peruser_load_without_machine_global() {
        let mg = Path::new(r"C:\ProgramData\roomler\roomler-agent\config.toml");
        let peruser = Path::new(r"C:\Users\u\AppData\Roaming\roomler\config.toml");
        // The one true case: SC worker, loaded from a perUser path,
        // machine-global absent.
        assert!(should_self_heal_config(true, peruser, mg, false));
        // Not a SystemContext worker → never.
        assert!(!should_self_heal_config(false, peruser, mg, false));
        // Already loaded FROM the machine-global path → nothing to do.
        assert!(!should_self_heal_config(true, mg, mg, false));
        // Machine-global already exists → don't clobber it.
        assert!(!should_self_heal_config(true, peruser, mg, true));
    }
    // RETIRED-NAME-ANCHOR-END
}
