# FR-85 — HQ screen recording: a local or remote screen to a file, then cut, speed up and score it

**Issue:** [#1634](https://github.com/gjovanov/roomler-ai/issues/1634) · **Status:** **in progress** — P0's FFmpeg half measured (field log); P1a (the recorder core), P1b (the hardware recording profile), P1c (audio on Windows and Linux), P2a (the local verbs: LocalAPI, console-user gate, `record_dir`, `roomler record`) and P2b (meshharbor-desktop's Recordings view and tray) built; P3a (the server's gates for remote recording), P3b (the device's half: the owner's gates, the `record` DataChannel, the host prompt, the indicator before the first frame), P3b-2 (the download) and P3c (the viewer) built; P1e (the recorder runs as the person at the device) built on Windows and Linux, and on macOS as P1e-mac (a supervised Mac records in its GUI worker); both canaries passed (2026-09-27): Windows on an EDR-managed laptop, macOS TCC on the supervised MacBook; P4a–c built: FFmpeg with the H.264 decoder and the AAC encoder, pinned by P4c, so AAC audio (P4b-1) and editing a hardware encoder's recording (P4b-2) are live; **`recording` is in `full` again** (P4c, the operator's go-ahead of 2026-09-27, after both canaries), with every gate closed and `MESHHARBORD_RECORDING=0` as its kill switch. It was out of `full` from 2026-09-26 (#1692) until then · **Numbering:** claimed as FR-84 and renumbered before landing — [#1633](https://github.com/gjovanov/roomler-ai/issues/1633)'s FR-84 reached master first (issues 68 s apart), and the ledger arbitrates · **Anchors:** master `4b7b28537` · **Glossary:** [`CONTEXT.md`](../../CONTEXT.md) · **Related:** [FR-27](FR-27-consent-surfaces-and-desktop-companion.md) · [FR-44](FR-44-shared-pipeline-multi-viewer.md) · [FR-70](FR-70-media-pipeline-leaves-the-runtime.md) · [FR-77](FR-77-encoder-chroma-matrix.md) · [FR-80](FR-80-a-session-with-no-pixels-says-why.md) · [FR-24](FR-24-licensing-split.md) · [FR-61](FR-61-vmtest-matrix.md) · [`docs/remote-control.md` §11.3](../remote-control.md)

## Goal

Record a screen in high quality to a file, through roomler, in two situations:

1. **Local** — the person at a device running roomlerd + meshharbor-desktop records their own screen.
2. **Remote** — a controller in the browser viewer records the screen of the device they are controlling. The file is
   written **on that device**, and the controller downloads it on demand over the session's P2P channel.

Recordings land in a **default folder the user can override from meshharbor-desktop**. A meshharbor-desktop editor then
**cuts** segments, **speeds up** segments and mixes in **background music**, exporting a new HQ file. The feature states
what it costs in installer size and ships with integration and e2e tests.

## Why — what exists and what does not

- **The permission was designed and never built.** `Permissions::RECORD` is defined
  (`crates/remote_control/src/permissions.rs:21`) and already in `requires_consent_prompt()`, but nothing in `agents/`,
  `crates/modules/` or `ui/src/` uses it. `RemoteSession.recording_url` is always `None`. `docs/remote-control.md`
  §11.3 (`:679`) promises a banner that cannot be dismissed and a red tray dot while recording; neither exists.
- ⚠️ **Any tab can already request RECORD.** `resolve_session_authz` (`crates/modules/remote/src/controller.rs:434`)
  never reads the requested permissions, and `Hub::create_session` narrows only INPUT
  (`crates/modules/fleet/src/hub.rs:1117-881`). Harmless today because no agent honours the bit. It stops being harmless
  the day one does, so the strip ships before the agent learns the bit (P3).
- **Recording what the viewer receives would not be HQ.** The live stream is rate-controlled to the network
  (FR-62/63/79) and its capture is capped by the live plan (`agents/meshharbord/src/peer.rs` `set_output_cap`), so the
  viewer's copy is transport quality. HQ means encoding at the source, in a pipeline of its own.
- **No muxer exists anywhere.** The agent emits raw NAL units over a DataChannel. Vendored FFmpeg n9.0.1 is
  `--disable-everything` plus hardware encoders only: static in `meshharbord.exe`, shared `libavcodec.so` in the .deb,
  dylibs in `meshharbord.app`. No decoders, demuxers, muxers, filters or swscale. **Linux arm64 has no FFmpeg at all**
  (openh264 + libvpx).
- **The parts that do exist:** the capture cascade `capture::open_default` (`agents/meshharbord/src/capture/mod.rs:2252`)
  and a synthetic source with a decodable 64-bit counter strip (`capture/synthetic_backend.rs:41`); `EncoderThread`
  (`encode/thread.rs:125`); the cells, denylist and probe cache; the child-process probe pattern (`encode/caps.rs`); the
  uid drop used by the portal helper (`capture/portal/mod.rs`); cpal loopback audio + audiopus Opus (`audio/`); the
  consent chain and `PromptKind` (`consent.rs:157`); the config surface (`crates/agent-core/src/config_surface.rs:1111`)
  and LocalAPI `ConfigSet`; the capture-excluded Windows indicator (`indicator/win.rs`); the updater's
  `decide_defer` (`updater.rs:119`); the files-DC chunk pump (`peer.rs:11019`); `.roomler-partial` staging (`files.rs`).

## Decisions taken with the operator (2026-09-25)

| Question | Decision |
|---|---|
| Where does a **remote** recording end up? | **On the controlled device**, in its recording folder. The controller downloads it on demand over P2P. The device owner always keeps the copy. |
| Which audio does a recording capture? | **System audio and microphone, both default OFF.** |
| Can a remote controller turn on the host's microphone? | **Never** (this spec). The microphone toggle exists only on local surfaces. |

### Decided 2026-09-26

| Question | Decision |
|---|---|
| Does a host at its **login screen** count as "nobody signed in" for an unattended recording (open decision 6)? | **No.** A remote recording there is refused, by its own name (`login_screen`), before anyone is asked. The unattended exception stays only for a host with no screen anyone could be at (no active graphical session) and for a host running its own virtual desktop. On Windows that is never: the console shows the sign-in screen whenever nobody is signed in. |
| **P2c** — the Linux user unit cannot write into `~/Videos` | The cheap fix: `ReadWritePaths=-%h/Videos` in the user unit. Any other folder keeps its recordings in the data folder, and the Recordings view names the reason. A localized XDG Videos folder falls back to the data folder. The companion-side mover is built only if people ask for it. |
| **P4** — the FFmpeg bump (software decoders, AAC) | Yes, and it ships **with the recorder**: in the release where `recording` rejoins `full`, not before. H.264-only decoding (about −0.4 MiB) is worth considering (open decision 2). AAC is mainly for playback in Apple's players and QuickTime. `lgpl-source-offer.yml` is dispatched before that tag. |
| How do **canary** recorder builds reach hosts? | A separate test build (`full` + `recording`), installed only on the EDR-managed laptop and the Mac, never on the fleet's update channel: through a pre-release channel if the updater has one, otherwise by hand. EDR: open the Recordings view, make a local recording, then a remote one, and watch for alerts or quarantine. Mac: the Screen Recording and Microphone permissions work, and existing grants survive the update. **Settled (the operator, same day):** there is no pre-release channel. The updater and `/api/agent/latest-release` accept pre-releases, so anything published reaches the whole fleet. The canary is therefore:<br>- **version `0.4.106`, reserved:** never tagged; the next fleet release is 0.4.107 (the `ship-it` skill);<br>- from branch `fr85-canary-0.4.106`, never merged, which adds `recording` to the Windows build line only;<br>- a signed `release-agent.yml` dispatch with `publish_release=false`;<br>- installed by hand on one EDR laptop (both corporate laptops run Microsoft Defender for Endpoint and the per-machine service), with auto-update off.<br>**The Mac half was blocked:** the operator's Mac runs a root daemon, which refuses recording (`RootDaemon`), and a session delegated to its GUI worker had no record context. **P1e-mac** unblocks it: a supervised Mac records in its GUI worker (not a drop: the worker already is the person, holding the Screen Recording grant). Its canary is owed: `recording` in the macOS build line, on the operator's Mac, under a version reserved for it — **`0.4.109`** (branch `fr85-canary-0.4.109`, never tagged; the next fleet release is 0.4.110). It checks the Screen Recording grant for the recorder child; the microphone stays refused by name on macOS until P1c-mac. **The Windows half passed on 2026-09-27** (the field log). |

### Decided 2026-09-27

| Question | Decision |
|---|---|
| Who installs the **macOS canary**? | The operator: *"install the canary on the mac yourself via bash. you have ssh and exec cmds options. test & proceed"*, adding that the Mac is a personal development machine and consent is given to use it directly. It was installed over the overlay by a one-shot launchd job outside the daemon's process tree (the postinstall restarts the daemon) and passed: the field log. |
| Does the recorder ship? | **Yes: "proceed" after both canaries.** `recording` rejoins `full` together with P4c (the FFmpeg pins flip to `-h264dec-aac`), which is the release the 2026-09-26 decision tied P4 to. The tag itself stays the operator's. The restricted-token launch (P1e, an elevated user-context worker) runs on no EDR host in this fleet, so that path stays field-unproven. |
| **HEVC editing** (open decision 2) | H.264 only, as built in P4a: no overrule came. |
| Who owns a **supervised Mac's** `record_remote_enabled`? | The person at the console. The canary showed that the key is persisted in the GUI worker's own config (the console user's), which is the process that records. The root daemon's copy is not what counts. The worker re-announces `record=["available","remote"]` at once, and the daemon forwards it on the next heartbeat, with no restart. |

## Key design

### 1. One recorder, two launchers

- **`roomlerd record`** — a new subcommand of the same binary, spawned by the worker and driven by JSON lines on
  stdin/stdout, the probe-child pattern. Parent death means stdin EOF, which means finalize and exit; EPIPE on stdout
  during finalize is tolerated. A driver fault in the recorder never takes the daemon or a live session down. Handles are
  not inherited, so a respawned worker cannot trip its own single-instance lock.
- **Identity rule.** Whenever a console user exists, the recorder runs **as that user at normal integrity** — never
  SYSTEM, never root, never elevated. On Windows the worker holds the interactive admin's *elevated* linked token by
  default (`MESHHARBORD_ELEVATE_WORKER`, `agents/meshharbord/src/win_service/supervisor.rs:341`), so the recorder gets a
  restricted medium-integrity token; a SystemContext worker spawns it with the console user's token; a Linux root daemon
  drops to the console user the way the portal helper does. Only a host with **no console user** (headless, an Xvfb
  virtual desktop, nobody logged in) records as the daemon's identity.
- **Its own capturer**, never a tap on the live pump: native resolution whatever the live plan says, one code path for
  local and remote. A second capturer is viable on every backend — WGC takes a second session; DXGI spends one of its
  ~4 duplication seats; X11, CGDisplayStream and DRM are unaffected. The cursor comes from `MESHHARBORD_WGC_CURSOR=1` on WGC
  and is composited from `capture/cursor.rs` everywhere else. ⚠️ On a Wayland portal a second session may raise a second
  dialog: P0 measures whether the persisted restore token suppresses it, and if not, portal hosts tee the worker's stream
  (P1b).
- **CFR pacer**, 30 fps (60 opt-in). Frames are stamped on the recorder's own `Instant` at receipt and PTS = tick / fps,
  repeating the last frame on `Ok(None)`. ⚠️ Never `Frame.monotonic_us`: its origin differs per backend, and on the portal
  it is wall-clock. A lock screen or `ACCESS_LOST` re-acquires and inserts a black gap; it never aborts. A fast user
  switch terminates the worker, so the recording ends `session_changed` — a recording never follows a user switch.
- **Recording encoder profile.** A new `RateMode { ConstantQuality { q }, Vbr { … } }` and an explicit GOP are threaded
  through `build_encoder` (`encode/ffmpeg/encoder.rs:1507`) and `encoder_options` (`:258`); today both force
  maxrate/bufsize and a 64 800-frame GOP (`:51`).

  | Backend | Recording options |
  |---|---|
  | NVENC | `rc=vbr cq=N b:v=0 preset=p6 tune=hq` |
  | QSV | `global_quality=N b:v=0`, no maxrate, `low_power=0` |
  | AMF | `rc=cqp qp_i=qp_p=N` |
  | VAAPI / D3D12 / Vulkan | CQP, `qp=N` |
  | VideoToolbox | high ABR (≈ 0.3 bits per pixel) |
  | openh264 | `RateControlMode::Quality` or fixed QP |

  ⚠️ **As built in P1b** the recorder does NOT use new per-backend dicts yet. `FfmpegEncoder::new_recording` reuses
  the live option sets, which every fleet GPU has already opened, and changes only three things: `cq` 19, a recording
  ceiling instead of the network's, and a real GOP, plus counter-based PTS. A new private-option dict is a new way
  for a driver to refuse an open, and nothing here has measured one yet. The table above stays the target, and each row
  lands only when a field measurement on that vendor's hardware shows it opens and beats the live dict.

  GOP 2 s and `bf=0` (so PTS = DTS). The **live** option sets stay byte-identical, locked by a test. The recorder uses the
  same cascade, **denylist** and probe cache as live — the child receives the config-fallback denylist explicitly, or
  `encoder_cells_deny` would be silently ignored at this entry point. Default **H.264 4:2:0** (plays everywhere, and
  previews in WebView2); HEVC and 4:4:4 are opt-in.
- **Audio**, both default OFF. System audio is the existing cpal loopback (WASAPI on Windows, the monitor source on
  Linux; macOS has none — ScreenCaptureKit audio needs macOS 13 and the bundle targets 12). The microphone is a new cpal
  input stream. One `Instant` is the master clock; audio PTS come from accumulated samples, and a drift corrector fills
  silence or drops once the error passes 20 ms (which also covers WASAPI's gaps while the endpoint is idle). `rubato`
  resamples, and the sources are summed with a soft clip. Encoded as **Opus** (audiopus) in P1 and **AAC** after the P4
  FFmpeg bump; arm64 keeps Opus. A microphone failure is named, never silent: `mic_unavailable{privacy}` (the Windows
  "let desktop apps use the microphone" switch) or `{permission}` (macOS TCC), and the UI offers to record without it.
- **Container.** `mp4-atom` (MIT/Apache-2.0, allowed by `deny.toml`) writes **fragmented MP4** with keyframe-aligned
  fragments of about 2 s, so a crash loses at most 2 s. On stop the file is **remuxed to a progressive MP4 with
  `moov` first** (no re-encode) so QuickTime, Movies & TV and editors open it. A boot reconciler finalizes orphaned
  partials as `interrupted`. A sidecar `<name>.roomler.json` records the initiator (local user, or the controller's user
  id and name), device, encoder, dimensions, fps, audio sources, events (locks, gaps, dropped frames) and the stop
  reason. Guards: refuse below 2 GiB free, stop below 1 GiB, 240-minute maximum, one active recording per display.

### 2. The folder

- **Default**, resolved per user and shown in the UI with its reason: Windows `FOLDERID_Videos\Roomler` **only if** it
  is on a local fixed volume, not under OneDrive or another sync root, not a redirected share, and passes a real
  create + write + delete probe — Defender Controlled Folder Access lets `metadata()` succeed and then blocks the write.
  Otherwise `%USERPROFILE%\Roomler Recordings`. macOS `~/Movies/Roomler`; Linux `$(xdg-user-dir VIDEOS)/Roomler`.
- **Override**: `record_dir`, a device-owned config key and the surface's first path-valued key. The validator in
  `config_surface.rs:1079` refuses relative paths, `~`, UNC, `\\?\` and device paths, and reparse components.
  meshharbor-desktop sets it through `ConfigSet` with a native folder picker — a Rust command over
  `tauri_plugin_dialog::DialogExt`, because the webview has no dialog capability today — plus "Reset to default".
- **Write rule.** The recorder writes into the folder only when it runs as that folder's user. It stages in
  `<dir>/.roomler-partial/`, opened by handle (`FILE_FLAG_OPEN_REPARSE_POINT`, `O_NOFOLLOW | O_EXCL`), refuses reparse
  components, never calls `create_dir_all` on another identity's path, and renames on finish. Otherwise it stages in its
  **own data dir** and meshharbor-desktop — the same uid — renames or copies the file into the folder; that is the Linux
  user-unit case (`ProtectHome=read-only` in `agents/meshharbord/packaging/linux/meshharbor.service`). A folder that refuses
  both processes (Controlled Folder Access blocks roomlerd *and* meshharbor-desktop) keeps the file in the data dir with
  `reason=cfa`, and the UI names the fix. A host with no console user keeps recordings in the daemon's dir with an
  **explicit DACL** (SYSTEM + Administrators — `appdirs.rs` sets none today, so Users could read) or mode 0700 as root.
  Nothing is streamed over LocalAPI: it is one JSON line per response.

### 3. Local recording

- A **Recordings** view in meshharbor-desktop — the sixth entry in `VIEWS` (`agents/meshharbor-desktop/src/front/app.js:90`):
  Start/Stop with a timer and size; start options (system audio, microphone, fps, quality, codec, cursor), unchecked by
  default and remembered; the list (name, date, duration, size, origin, pending delivery) with Play, Edit, Show in
  folder and Delete; settings for the folder, "Allow remote recording" and "Include computer audio in remote
  recordings". The tray gets Start/Stop and a red REC dot.
- LocalAPI verbs (`crates/localapi/src/lib.rs:1003`, the exhaustive `handle()` and `serve_connection`): `RecordStart`,
  `RecordStop`, `RecordStatus`, `RecordingsList`, `RecordingDelete`.
  ⚠️ **They need a peer check the pipe does not have.** The pipe's DACL admits every Interactive User, RDP sessions
  included (`lib.rs:1657`), and there is no peer-credential check, so a guest in an RDP session could start a local
  recording of the console user's desktop. The new verbs, and `ConfigSet` of any `record_*` key, require
  `GetNamedPipeClientProcessId` → `ProcessIdToSessionId` to equal the worker's session (`SO_PEERCRED` on unix).
- CLI: `roomler record start | stop | status | ls`.
- The updater counts an active recording in `decide_defer` (at most 7 × 1 h). A pushed `rc:agent.update` bypasses that
  gate, and the MSI's Restart Manager kills the child; fragments plus the boot reconciler turn that into a clean
  `interrupted` file, not a loss.
- **As built in P2a** (`docs/recording.md` §6):
  - The gate compares the client's session with the **active console session**
    (`WTSGetActiveConsoleSessionId`), which is the worker's session whenever the worker serves one. On unix the peer's
    uid (tokio `peer_cred`) must be the daemon's, or root. An unidentified peer fails closed. The gate sits in the
    listener (`serve_connection_as`), before any handler runs.
  - The daemon side is `recording/manager.rs` (`RecordingManager`). It spawns `roomlerd record` with the config
    fallbacks in its environment, so the encoder denylist binds the child. `start` answers on `started`/`refused`,
    `stop` once the file is final, and a child that exits silently ends as `recorder_exited`. The CLI gained `rm`.
  - **Until P1e, a SYSTEM/root daemon refuses a local recording** (`recording/identity.rs`). The child would inherit
    SYSTEM/root and save into the service account's own profile, where the person who pressed Record cannot see it.
  - **As built in P2b** (`docs/recording.md` §7): the view and the tray only ask the daemon. Two additions came out of
    building them. First, `RecordingState.available` / `unavailable_reason`, so a client greys Start out ahead of time
    instead of offering one that can only fail. Second, `cmd_config_set` no longer falls back to writing the file when
    the daemon *answered* a `record_*` change: that would have reported a success the console gate refused. The
    view's settings are the folder only; "Allow remote recording" and the audio toggles arrive with P3 and P1c.
  - The "boot reconciler" became **reconcile at every recorder start**. It runs beside the new recording so a big remux
    cannot delay `started`, and only for partials whose OS file lock (`<name>.partial.lock`, `PartialLock`) it can take.
    Without that lock a second recorder in the same folder would finalize, or delete, a live partial; the test that says
    so is red with the lock disabled.

### 4. Remote recording — the gates, in order

Each refusal carries a named reason on the wire and in the UI.

1. **Server authorization.** A new role bit `RECORD_REMOTE_SCREEN` (bit 31: `role.rs` `NAMED`, an `ALL` bump, in no
   managed row below ADMINISTRATOR; the UI mirror is `2 ** 31`, because `1 << 31` is negative in JavaScript).
   `resolve_session_authz` computes `SessionAuthz.may_record` — owner, ADMINISTRATOR or the role bit — and it is
   **false whenever `override_reason` is set**. Break-glass forces `ConsentMode::Auto` (`controller.rs:512`); allowed to
   record, it would be covert monitoring, which §11.4 rules out.
2. **Hub strip.** RECORD survives `create_session` only if `may_record` and the agent advertises
   `AgentCaps.record ∋ "remote"` — a new typed capability list in the `RpcCap` style (variant → `wire()` → `ALL`,
   matched by equality). The agent advertises it only while the device gate is on, and an old agent never does, so
   RECORD never reaches one.
3. **Device gate.** `record_remote_enabled` and `record_remote_audio`, both default **OFF**, device-owned and
   **structurally absent from `DesiredConfig`** — a `record_` twin of `no_relay_key_is_server_pushable_via_desired_config`
   (`crates/remote_control/src/models.rs:5178`). Capabilities are read once at hello, so ON takes effect at the next
   connect; **OFF is immediate** — new starts are refused and a running remote recording stops.
4. **A `record` DataChannel**, attached only when the grant holds RECORD — the same attach-time gate as `files` and
   `input`. The control channel carries no permission context, so it cannot host this. Messages:
   `rc:record.start {id, audio?}` → `rc:record.state {id, state, reason?, name?, bytes?, duration_ms?}`, with state in
   `pending_consent | recording | stopped | refused | failed`; `rc:record.stop`; `rc:record.list`;
   `rc:record.get {name, offset}` (binary chunks, resumable). The microphone is never a remote option.
5. **Just-in-time consent.** A host in prompt mode gets `PromptKind::Record` — "<controller> wants to record your screen
   [and computer audio]" — through the `PromptSurface` chain, with a **fresh ObjectId**, never the session id or a suffix
   of it (the `ssh` / `ssh-consent` lesson), `strictest_of`, one pending prompt per session and a cooldown after a
   deny. The connect prompt says plainly that the controller may ask to record. An auto-grant host skips the prompt:
   its owner opted in at gate 3.
6. **The indicator is up before the first frame.** On an attended host (a real console user): a banner that cannot be
   dismissed, with **Stop**, and a red tray dot (§11.3) — the native indicator on Windows (capture-excluded), the
   companion elsewhere. **No surface means `refused{no_indicator_surface}`.** An unattended host (no console user, or a
   virtual desktop) may record under gate 3. On X11 and macOS the banner is not capture-excluded and appears in the
   recording; that is documented, not hidden.
7. **Lifetime.** Stops on the controller's Stop, the host's Stop, the gate going OFF, or a disk/duration guard. A
   dropped session gets 60 s in which the same controller *user* re-attaches under a new session id: ownership is
   (controller user id, device), kept in the sidecar, because the reconnect ladder mints new session ids.
8. **Download.** `rc:record.list` and `rc:record.get` serve only recordings whose sidecar names this controller's user
   id, confined to the recording dirs — the name has no separators or `..`, the file is opened without following links,
   must be a regular file, and its final path is checked. Resumable by offset, so a relay flap does not restart 3 GB
   from zero; no 2 GiB cap. The viewer writes through `showSaveFilePicker` streams (Chrome, Edge); Firefox and Safari
   fall back to the capped Blob path with a clear message.
9. **Audit — the decision and the claim, kept apart as SSH keeps them.** The server's decision stays in `remote_audit`
   (the grant, with the strip reason). The host's claims — prompt outcome, started, stopped {bytes, duration, reason},
   downloaded {bytes} — go to a new `recording_activity` collection through a new `ClientMsg::RecordingActivity`
   (a `namespace()` arm owned by `remote`, the owners table, a TTL index in the module's index plan, the composition
   baseline re-recorded with `COMPOSITION_UPDATE=1` and a commit message that says why), checked against the live
   session's grant. Never content.

### 5. Editor and export

- An **Edit** view in meshharbor-desktop, plain HTML/JS like the rest of `src/front` (107 KB today): a `<video>` preview
  through the Tauri asset protocol, scoped at runtime to the recording folders (plus `media-src`/`img-src` in the CSP,
  `tauri.conf.json`), falling back to a thumbnail strip and a frame at the playhead when the webview cannot play the codec
  (WebKitGTK without GStreamer plugins, WebView2 without HEVC); a timeline with thumbnails; split at the playhead; per
  segment **Cut** or **Speed** 1.5 / 2 / 4 / 8 / 16×; **music** — file picker, volume, fade in and out, start offset,
  loop — and the original audio's volume; Export with a name, quality, progress and cancel. Edits are non-destructive,
  saved as `<name>.edit.json`.
- The engine is `roomlerd media probe | thumbs | frame | export --edl <file>`, spawned by a Rust command in
  meshharbor-desktop that validates every path, running as the user; it refuses to run elevated. **Untrusted media is never
  parsed inside the daemon.** `mp4-atom` demuxes; FFmpeg's software `h264`/`hevc` decoders decode after P4, and the
  openh264 decoder handles H.264 on arm64 and in the default CI lane. Frames are selected **by PTS** — a cut drops, a
  speed-up of k samples to the output's constant frame rate, and a frame-accurate cut decodes from the preceding keyframe
  (at most 60 frames at a 2 s GOP). The recording encoder profile re-encodes, and the output is a progressive MP4 with
  `moov` first. Audio: `symphonia` (MPL-2.0; mp3, AAC-LC, FLAC, Vorbis, WAV) decodes music, audiopus decodes Opus,
  `rubato` resamples, and gain, fades, loop and mix are plain Rust. The original audio is muted inside sped-up segments.
  AAC out (Opus on arm64). **No libavfilter, and no FFmpeg muxers or demuxers.**

### 6. How this squares with "session content is never recorded"

The SSH pillar never records session content, because a recording ships what the operator typed off the host. A screen
recording is content by definition, so it is bounded the same way: the bytes never leave the device except through an
explicit, permission-gated P2P download; recording is visible on the host while it happens; the device gate is OFF by
default; break-glass can never record; and the server stores only the fact. `recording_url` stays `None`, and no upload
path will exist.

## Installation size — the evaluation

Measured on the 0.4.101 release (see the field log). The Windows MSI guard divides by PowerShell's `1MB`, so its units
are MiB: the MSI is **15.36 MiB against an 18 MiB hard ceiling** (`.github/workflows/release-agent.yml:1872`), 2.64 MiB of
headroom. Its pinned 13.13 baseline is stale, so the +2 warn band fires already, before this FR adds a byte.

**What keeps it small:** no ffmpeg CLI; no new DLL, `.so` or `.dylib`; no libavfilter; no FFmpeg muxers or demuxers
(`mp4-atom` does MP4); no swresample (`rubato`); music decoding in pure-Rust `symphonia`, which is also the safer parser
for untrusted files; and the companion stays FFmpeg-free, because the export runs in the `roomlerd` binary the device
already has.

| Adds | Ships in | Uncompressed | In the installer |
|---|---|---|---|
| FFmpeg `h264` + `hevc` software decoders and the `aac` encoder (one vendored bump, P4) — **measured in P0** | `meshharbord.exe` (static) · `libavcodec.so` · `.dylib` | **+2.79 MiB** linked (Windows) · **+2.04 MiB** (`.so`) · **+1.85 MiB** (`.dylib`) | **+0.82 MiB** (MSI, deflate) · **+0.47 MiB** (.deb, xz) · **+0.42–0.69 MiB** (.pkg) |
| `symphonia` (MP3, AAC/M4A, FLAC, Ogg Vorbis, WAV) and the export's sound (P5b) — **measured in P5b**; no `rubato` (the recorder's own resampler serves) | roomlerd, all platforms | **+1.38 MiB** linked (Windows release, one codegen unit: 35,525,120 → 36,972,544 B); +1.10 MiB with music limited to MP3, AAC/M4A and WAV | ≈ +0.48 MiB (at the MSZip ratio; the P4 release run measures it) |
| recorder, export engine, `mp4-atom`, LocalAPI and CLI verbs | roomlerd, all platforms | +0.5–0.8 MB (est.) | +0.2 MB (est.) |
| the openh264 **decoder** (already compiled by `openh264-sys2`, now kept by the linker) | roomlerd | +0.4 MB (est.) | +0.15 MB (est.) |
| microphone capture (cpal is already linked) | roomlerd | ~0 | ~0 |
| Recordings and Edit views, the folder-picker command | meshharbor-desktop | +0.05–0.1 MB (est.) | < 0.05 MB |
| **Total** | | **≈ +5.1–5.5 MiB** | **≈ +1.5–1.7 MiB per installer (≈ +10–11 %)** |

- **Windows MSI ≈ 17.0 MiB** (15.36 at 0.4.101 + 0.82 for FFmpeg, measured + ≈ 0.48 for P5b, measured linked and
  compressed at the MSZip ratio + ~0.35 estimated for the rest), under the 18 MiB ceiling with about 1.0 MiB to spare.
  P5b came in above its estimate (≈ 0.48 against 0.3). P4 re-pins the baseline **from the measured release run, never
  from this estimate** — the guard's own rule — and says what grew.
- Linux x64 .deb ≈ +0.8–1.1 MB (6–8 %) · macOS .pkg ≈ +0.8–1.3 MB (4–6 %) · **Linux arm64 .deb ≈ +0.3–0.5 MB** (no
  FFmpeg: it records openh264 + Opus and edits H.264 through the openh264 decoder) · meshharbor-desktop < 0.1 MB.
- **Measured (AC9)** by the unpublished P4c rehearsal ([36346825023](https://github.com/gjovanov/roomler-ai/actions/runs/36346825023),
  2026-09-27), with `recording` in `full` and the `-h264dec-aac` FFmpeg. The deltas below include everything merged
  between 0.4.101 and 0.4.108, not only this FR. The recorder's own share of the MSI is **+1.78 MiB** (0.4.105 had no
  recorder: 15.89): the canary measured `recording` at +1.15, and P4c plus the code merged since adds +0.63. The estimate
  of ≈ 17.0 was low by 0.67.

  | installer | 0.4.101 | P4c rehearsal |
  |---|---|---|
  | Windows MSI (both flavours) | 15.36 MiB | **17.67 MiB** |
  | macOS `.pkg` | 21,765,134 B | 24,497,327 B |
  | Linux x64 `.deb` | 13,830,684 B | 15,730,204 B |
  | Linux arm64 `.deb` | 11,410,760 B | 12,761,332 B |
  | meshharbor-desktop `.deb` | 4,422,496 B | 4,810,440 B |

  The guard is re-pinned to 17.67, and its **ceiling moves 18 → 22 MiB** (`release-agent.yml`, with the reason there).
  Against a 17.67 baseline, an 18 ceiling sat inside the +2 warn band. Any growth would then hard-fail a tag without the
  warning a release earlier, which is the opposite of the guard's design. 22 puts the warning (19.67) before the fail,
  with ~4.3 MiB of headroom, close to the ~5 the guard has kept over its baseline since P4b.
- The P0 FFmpeg numbers came from a branch that is never merged (`fr84-p0-measure`, named before the renumber): the
  three vendor builds with the P4 flags, uploaded as Actions artifacts only, and — for Windows, where FFmpeg links
  statically and archive size means nothing — the same registry-pulling probe linked with MSVC against both trees.
- Levers if the ceiling gets tight: H.264-only editing (drop the `hevc` decoder, ≈ −0.4 MB) · MP3/WAV/M4A-only music
  (measured: −0.28 MiB linked, ≈ −0.1 MiB in the installer).
- Not installation size, but why the disk guard exists: HQ 1080p30 screen content is about 1–3 GB per hour, 4K60 about
  4–10 GB per hour.

## Rejected designs

- **Record what the viewer receives.** Transport quality: rate-controlled, capped by the live plan, degraded by loss.
- **Tap the live pump's frames** (`peer.rs`, after the capture). It gets the viewer's capped rung, needs a live session,
  and couples a new consumer to the most-tuned path in the product.
- **libavfilter for the export.** +0.6–1 MB and a filter-argument injection surface, for things that are a few lines of
  Rust.
- **An ffmpeg CLI** (+20–80 MB) · **ffmpeg.wasm** (~30 MB download, slow) · **a WebCodecs editor in the webview** (≈ 0 MB,
  but WebKitGTK cannot export reliably, so Linux would have no editor).
- **Streaming the file to the companion over LocalAPI.** LocalAPI is newline-delimited JSON, one line per response; a
  multi-GB stream is a protocol change on a leaf crate with three clients, and a same-uid `rename(2)` does the job.
- **Choosing the staging path by "is the process elevated".** Wrong on the most common admin laptop: the Windows worker
  of a UAC-split administrator holds the elevated linked token by default, so every such host would take the spool
  path; and an elevated writer in a user-writable folder is a medium-to-high integrity write primitive. The rule is
  identity — the recorder *is* the user.
- **Just-in-time consent "only when the mode is Prompt", with no override check.** Break-glass forces `Auto`, so an
  administrator's recording would have been silent.
- **Carrying recording on the control channel.** It has no permission context; `files` and `input` gate at attach time.
- **Downloading through the files channel, keyed by session id.** That channel exists only when FILES is granted, and
  the reconnect ladder mints a new session id on every flap.
- **Videos as an unconditional default.** OneDrive Known Folder Move would sync gigabytes by default; Controlled Folder
  Access blocks the write after `metadata()` says it is fine.

## Phases

| # | Phase | Kill switch | Status |
|---|---|---|---|
| **P0** | Measure: dispatch the FFmpeg vendor workflows with the P4 flags under a **new, unreleased asset name** (never overwrite the production asset) → library sizes; one rehearsal release run → both MSI sizes; link a stub pulling `mp4-atom` + `symphonia` + `rubato` with and without (how `ssh-server` was measured, `agents/meshharbord/Cargo.toml` ~:629); Windows: a second WGC session and the DXGI seat budget beside two viewers; macOS: TCC for a `roomlerd record` child, and the microphone prompt; Wayland: a silent second portal session through the restore token? | nothing ships | **FFmpeg half measured** on all three platforms (field log). Open: the Rust-side link delta, the Windows seat/second-session smoke, macOS TCC for the child, the Wayland portal question |
| **P1** | Recorder core behind cargo feature `recording` (joins `full`): the child and its identity rule, own capturer + cursor, CFR pacer, `RateMode`/GOP profile, fMP4 + remux + reconciler, audio (system + microphone → Opus), sidecar, guards, write rule. macOS: `NSMicrophoneUsageDescription` (the `Info.plist` heredoc, `release-agent.yml` ~:2417) and the `com.apple.security.device.audio-input` entitlement — neither exists, and `docs/remote-control.md:923-925` wrongly says the entitlement is covered. The designated requirement does not change, so existing Screen Recording grants must survive; verify on the MacBook, because FR-80 was a TCC break. | `MESHHARBORD_RECORDING=0` (built with the ship step: every path answers "switched off", the device stops advertising `record`); in `full` again from P4c (2026-09-27, after both canaries). It was out of `full`, and so out of every release build, from 2026-09-26 (the operator: canary hosts first; it had joined `full` for a day with #1677) | **P1a shipped**: `roomlerd record`, own capturer, CFR pacer + TickFifo, openh264 recording profile (HW backends: the live cascade with a forced GOP), fMP4 + remux + reconciler, folder rules, sidecar, the prefixed JSON-lines protocol; `tests/recorder.rs` named in CI; `docs/recording.md`. **P1b shipped**: `FfmpegEncoder::new_recording` — the live option sets (field-proven) with `cq` 19, a recording ceiling (NVENC ~0.3 bpp·s as a burst cap over CQ; the maxrate-anchored backends ~0.12 bpp·s as the bitrate), a real GOP and counter-based PTS; `hardware` refuses rather than fall back to software; verified locally by `ffprobe` on `h264_nvenc` (High, BT.601 tagged, keyframes at 0/60, zero decode errors). **P1c built (Windows, Linux)**: computer audio (loopback / monitor ONLY, never the Linux fallback to a microphone) and the microphone, both off unless asked for, mixed on the recorder's clock with a 60 ms lag, drift corrected by rate (±0.5 %), soft-clipped, Opus 128 kb/s in the MP4, aligned to the first written video frame; each source asked for and not opened refuses the start by name (`docs/recording.md` §9). Open: true per-backend CQ modes (QSV ICQ, AMF/VAAPI CQP) after field measurement, **P1c-mac** the microphone on macOS (cpal there, `NSMicrophoneUsageDescription`, the `audio-input` entitlement) and computer audio there (ScreenCaptureKit, macOS 13+). **P1d built** (`docs/recording.md` §1 "The pointer"): the mouse pointer is in a recording wherever the platform allows it. WGC's recording session draws it (`capture::open_for_recording`; the live session still does not), and CoreGraphics and an embedded portal cursor already did. On DXGI and X11 the recorder draws it itself, on its own tick, from `GetCursorInfo` and XFixes placed by the display's origin (`recording/pointer.rs` `PointerLayer`: the covered pixels put back, `make_mut` so the encoder's frame is never written, the frame handed over owned so nothing is copied). The sidecar says how (`in_frame`, `drawn`, `none`). CI compiles the Windows capture code (WGC, DXGI, the cursor tracker) for the first time, and runs the X11 source against Xvfb. Open: DRM and the SystemContext capture record no pointer; the field cells (P6). **P1e built on Windows** (`recording/launch.rs`, `docs/recording.md` §6 "Who the recorder runs as"): an elevated worker launches the recorder with a restricted copy of its OWN token (admin-equivalent groups deny-only, `DISABLE_MAX_PRIVILEGE`, medium integrity, owner and default DACL the user's; the linked token is identification-only without `SeTcb`); a SYSTEM worker with someone signed in uses their `WTSQueryUserToken`; both through `CreateProcessAsUserW` with a bounded handle list, the recorder's stderr into the daemon log; the daemon's list, delete and download-open run impersonating the same token; the folder is asked of the recorder (`record --where`, cached a minute); `record --whoami` reports the identity; a new elevated Windows CI lane. Measured here: an elevated daemon (integrity 12288, admin enabled) launches a recorder at 8192 with the admin group deny-only, the same user. **P1e-unix built (Linux)**: a root daemon launches the recorder as the person at the active graphical session (`Class=user`, never a greeter; uid 0 counts as nobody) through the one privilege drop (`exec::drop_to_std`) with that session's environment and X cookie, and does its own folder work with the thread's fsuid, fsgid and supplementary groups switched to theirs (`launch::unix::FsIdentity`: the per-thread `setgroups` syscall, every switch verified, a failed restore aborts); a privileged CI step runs those lib tests as root. **P1f built** (the unattended exception): a SYSTEM or root daemon with nobody signed in records a REMOTE session as itself (`Identity::Unattended`) into its own folder, locked to the service side (a protected DACL of SYSTEM and Administrators in `%PROGRAMDATA%` on Windows, 0700 elsewhere; a link on the path refused; never `record_dir`), with no banner because there is nobody to show one to, the controller told `unattended: true`; the identity is decided once, the launch refused if someone signed in meanwhile, and a running unattended recording stopped `session_changed` the moment someone signs in (all asked fresh, never from the 5 s cache, a review finding); a local recording there is still refused; lists and downloads search both folders; `Dockerfile.agent-e2e` carries `recording`. **Decision 6 built** (2026-09-26): a login screen is not "nobody". Windows' sign-in screen, a Linux display manager's greeter and root's own desktop refuse every start `login_screen`, with the words, a remote one before the host is asked; on Linux the unattended exception now needs the host's own virtual desktop (`virtual_desktop::requested`, now the one copy) or the synthetic test source, or else no active graphical session AND no real screen the recorder could reach — no `DISPLAY`/`WAYLAND_DISPLAY` in the daemon's environment, no DRM scanout (`launch::unix::Seat` `Person`/`NoPerson`/`Empty`/`Unknown`, `Reach`, `shows_a_screen`; from an independent review: "no logind session" is not "no screen", and a `loginctl` that cannot be asked is not "no session"); a Windows service never records unattended; an unattended recording stops `session_changed` when a login screen comes up, and a login screen found at the launch re-check refuses by its own name; the device keeps advertising `available` (a capability, not who is at the screen) and a login screen keeps what was recorded listable. **P1e-mac:** macOS is not a drop. A root daemon has no WindowServer; a supervised Mac records in its GUI worker, which is the person. The daemon carries the record context across (`delegate::SessionParams::record`) and advertises the worker's `record` caps on the primary org's row; the worker re-sends them whenever the person's gate changes. The worker's `RecordingActivity` is relayed only for a session handed over with `RECORD` (`docs/recording.md` "A supervised Mac"). Field owed: the Mac canary. Open: **P1e field** the SystemContext (`ConsoleUser`) path and a real Linux desktop (X11, and GNOME Wayland, where the recorder's own ScreenCast session may make the portal ask the person first) |
| **P2** | Local: `record_*` keys, validators and the `DesiredConfig` prefix exclusion; LocalAPI verbs with the session peer check; the Recordings view, settings, folder picker and tray REC; the CLI; updater defer; delivery from the data dir | meshharbor-desktop greys Start out, with the reason, against a service without the recorder or one that cannot record here (`RecordingState.available`), and says "no screen recorder yet" to one that predates the verbs | **P2a built**: `record_dir` (live, one shared validator, structurally absent from `DesiredConfig`); the five LocalAPI verbs behind the console-user gate in the listener; `RecordingManager` (spawn, event folding, one at a time, `recorder_exited`); the SYSTEM/root refusal until P1e; reconcile at every recorder start, guarded by `PartialLock`; updater defer (`active_work`); `roomler record start\|stop\|status\|ls\|rm`. **P2b built**: meshharbor-desktop's Recordings view (start/stop and options, the folder with Change/Default/Open, the list with Play/Show/two-click Delete), the native folder picker, the tray's Start/Stop item and tooltip, `available`/`unavailable_reason` on the state, a daemon answer final for `record_*` keys, the companion's unit tests in a CI lane at last. **P2c built** (the cheap fix, the operator's choice of 2026-09-26): the Linux user unit (`packaging/linux/meshharbor.service`) lists `~/Videos` as writable (`ReadWritePaths=-%h/Videos`), so the recorder's default folder works under its `ProtectHome=read-only`; a folder anywhere else under home is refused by the test write, falls back, and the Recordings view names the sandbox as the cause (`folder::sandboxed`); a localized Videos folder falls back the same way; the companion-side mover is not built (only if people ask). Found on the way and fixed in the same line: the unit listed the pre-rename folders WITHOUT systemd's `-`, so on a host that never ran the pre-rename agent it failed to start (`226/NAMESPACE`) wherever the sandbox applies — the default `install.sh --role daemon` path. It applies only where the user manager may mount inside an unprivileged user namespace. Where it cannot create one (measured, systemd 255 with `user.max_user_namespaces=0`), or may not mount in it (default Ubuntu 24.04, AppArmor's userns restriction: field-verified by the release session on a fresh vmtest guest, where the daemon shared the session's mount namespace and the unit started without the pre-rename folders), systemd runs the unit with no sandbox at all, so there `~/Videos` was writable all along. A CI step now starts a unit carrying the shipped sandbox lines on a fresh runner and asks the real recorder where it would write. **P2d built**: the tray turns red while any recording runs, this device's own or a controller's, from the 750 ms poll the banner rides as well as its own; only an answer moves it; the red icon is never a macOS template (`tray.rs`, `icons/tray-recording.png`, `docs/recording.md` §7) |
| **P3** | Remote: role bit, `may_record`, hub strip (break-glass included), `AgentCaps.record`, the `record` DataChannel, `PromptKind::Record`, indicator before the first frame, grace re-attach, list/get with resume, `RecordingActivity` + collection + baseline, viewer UI | device gate default **OFF**; the role bit granted to nobody by default; the `remote` module switch makes the hub strip RECORD | **P3a built** (the server's half): `RECORD_REMOTE_SCREEN` (bit 31, `ALL` bumped, in no managed row below ADMINISTRATOR, the UI mirror `2 ** 31`); `SessionAuthz.may_record` (owner, ADMINISTRATOR, or the bit; **false under break-glass**), carried across pods by `relay_rc_frame`; `record_grant` in the hub, after the INPUT rule, naming `controller_not_allowed` / `device_not_opted_in` in `SessionCreated.record_refused` and the audit's `SessionRequested.record_stripped` (a coalesced duplicate request repeats its session's reason); `AgentCaps.record` + `RecordCap` (`remote`, `remote-audio`, equality), kept per connection and refreshed from a heartbeat that re-announces caps, so the owner's ON/OFF needs no reconnect; `rc:recording.activity` → `recording_activity` (TTL 90 d), kept only for a session of the sending device whose effective grant held RECORD — the live one, or its stored row once it has ended; `GET …/recording-activity/{agent_id}` under `VIEW_REMOTE_AUDIT`; `crates/tests` `remote_recording_tests` (`docs/recording.md` §10). **P3b built** (the device's half): `record_remote_enabled` / `record_remote_audio` (device-only, live, console-gated; an OFF stops a remote recording `gate_revoked`); `AgentCaps.record` advertised only while the switch is on AND a recorder can run in the process, re-announced on the heartbeat when it changes (the announcement is now built like the hello, so it no longer drops `multi_org` `tun`); the `record` DataChannel behind the attach-time RECORD gate (`not_granted` otherwise); a start refused by name in order (`disabled_on_device`, `unavailable`, `audio_not_allowed`, `busy`, `already_starting`); a host-consented session asks again with `PromptKind::Record` on a FRESH prompt id, a deny holding 60 s (`rate_limited`); the indicator before the first frame (the Windows badge pinned open and relabelled; the companion's banner with **Stop recording**), or `no_indicator_surface`; `RecordingManager::start_remote` (never the microphone), stops named `requested` / `host_stopped` / `gate_revoked` / `session_ended`; every outcome reported as `rc:recording.activity`; meshharbor-desktop's two switches; `tests/control_dc_record.rs` named in CI. **P3b-2 built** (the download): `rc:record.list` (this controller's recordings, by the sidecar's `controller_user_id`, so a flap's new session id still reaches them) and `rc:record.get {name, offset}` (a bare `*.mp4` name, opened without following a link, someone else's recording answered `not_found` like a missing one; the files channel's pacing; resumable by offset with no size cap; `done` carries the WHOLE file's SHA-256, the prefix hashed from disk; one transfer per session; `downloaded` reported). **P3c built** (the viewer): RECORD asked for on every session, the toolbar reading the grant (a Record menu with the `record` channel; a stripped grant a disabled control whose tooltip names why; an older server, nothing); `useRemoteRecording` (start with computer audio as a separate unticked box and no microphone offer, the REC timer, every refusal and ending one sentence, the device's list, a download streamed into a picked file or held in memory up to 2 GiB and kept only when its SHA-256 matches, a short file an error, resumed on the reconnect ladder's next `record` channel); unit spec plus two agent-lane e2e specs. **P3c-2 built**: a device with no recorder is told apart from one whose owner has not opted in. The agent advertises `available` whenever a recorder can serve a remote session, `remote` only with the owner's switch on as well; the hub's `RecordSupport` (none, not opted in, serves) names `device_cannot_record` first, whoever asks; the viewer shows no Record control for it (`showsRecordRefusal`). Without it, a server promote would have shown every connected session a disabled Record control saying the device's owner had not allowed recording, on a fleet where no device can record. **P3b-3 built** (`docs/recording.md` §10 "A dropped session"): a remote recording outlives its session for `REATTACH_GRACE` (60 s) instead of ending `session_ended` at once. The session's banner is KEPT, marked `reconnecting` (`ViewerIndicator::hide_session` keeps a recording session's entry; `RcSessionInfo.reconnecting`; the companion keeps Stop and drops Disconnect). The SAME controller's next session picks it up when its `record` channel asks for the status (`retarget_remote`, the new banner first, then the old one down, `reattached` reported). Nobody else can. The grace still stops it for the owner's OFF and, unattended, for a sign-in; otherwise it ends `session_ended` when the grace runs out, reported once on the dropped session. A session's end is the signalling loop's word (`remote::session_ended`, before the bounded peer close) as well as the channel's state (`Closing` or `Closed`). **The host's Disconnect STOPS the recording** (`remote::host_ended`, `host_stopped`), and the viewer's Disconnect stops it first. The grace acts on its own recording only and claims it before stopping it; one speaker per recording, keyed by its file (all four from an independent review). The viewer shows REC · reconnecting and adopts the device's recording id. The red tray icon: P2d |
| **P4** | One vendored-FFmpeg bump: `--enable-decoder=h264,hevc --enable-encoder=aac` on Windows (`vendor-ffmpeg-windows.yml` `$inject`), Linux (its configure + `probe.c`) and macOS (`vendor-ffmpeg-macos.yml`); invert the absence assertions (`ff_h264_decoder` becomes required, `ff_mov_muxer` stays forbidden); update `THIRD-PARTY-NOTICES.md`, `docs/encoders.md`, `docs/lgpl-relink.md`, `docs/fr/FR-24-*.md`; dispatch `lgpl-source-offer.yml` before tagging; re-pin the MSI baseline; AAC becomes the audio codec (arm64 keeps Opus) | a new asset suffix flipped in `release-agent.yml` (rollback = flip back) | **Decided 2026-09-26**: ships with the recorder, in the release where `recording` rejoins `full` (never before it); `lgpl-source-offer.yml` dispatched before that tag. **P4a built** (branch `fr85-p4`, unmerged until P4c): the three vendor workflows with `--enable-decoder=h264 --enable-encoder=aac`, uploaded under the new suffix `-h264dec-aac` beside the production assets, which stay pinned. **H.264 only** (open decision 2): no recording is HEVC. **P4b-1 built**: AAC audio (`recording/audio_codec.rs`, `docs/recording.md` §9). It is picked at runtime, so it is inert until the flip, and the `recording-ffmpeg` CI job runs it against the new asset. **P4b-2 built**: FFmpeg's `h264` decodes a hardware encoder's recordings (High, High 4:4:4) in the export, and `media probe` says `editable` from the same runtime question (`recording/decode.rs`, §11). It is proven on two committed `h264_nvenc` recordings. **P4c built** (2026-09-27, with `recording` back in `full`): P4a's vendor workflows merged; the pins flip to `-h264dec-aac` on Windows, Linux and macOS (the release workflow, the ffmpeg-encoder CI lane, `scripts/dev-ffmpeg-windows.ps1`); the FR-24 release gate now checks the recipe too, since the configure options live there, not in a patch, and the gate would have passed the release against an offer describing the old build; `THIRD-PARTY-NOTICES.md`, `docs/encoders.md`, `docs/lgpl-relink.md` and FR-24's log say what the build now carries. The MSI baseline is re-pinned from the measured rehearsal (AC9), and `lgpl-source-offer.yml` is dispatched from master before the tag |
| **P5** | Export engine and the Edit view; the vmtest `record` cell | the Edit button shows only where `roomlerd media --help` succeeds (`cmd_media_available`) | **P5a built** (`docs/recording.md` §11): the edit list (`recording/edit.rs`: contiguous keep / cut / speed segments, speeds 1.25–16 in quarter steps, refused by name) and its exact integer time map; the export engine (`recording/export.rs`: openh264 decode forward with keyframe jumps across cuts, the recording encoder, the partial locked like a recording's, nothing left behind on failure or cancel); `roomlerd media probe\|export`; `tests/export.rs` — the plan's oracle decodes to exactly `0..59, 120…236, 240..299` (red with the map ignoring speed, the frame choice off by one, the cancel check removed, the name check removed). **P5b built**: the recording's own sound through the same plan (muted under a speed-up, gone with a cut) and background music (`recording/export_audio.rs`: symphonia reads MP3, AAC/M4A, FLAC, Ogg Vorbis and WAV, streamed and resampled by the recorder's resampler; volume, start, fade in and out, loop), mixed through the recorder's soft clip into one Opus track; the `done` event says what the sound carries (`none`, `original`, `music`, `original_and_music`, `not_carried`); `tests/export.rs` `mod sound` reads a stepped tone back second by second (red with a speed-up not muted, the cut ignored, no loop, no fade, the volume ignored). The music file is untrusted input: a fuzz pass over 1,800 malformed files found a WAV declaring 0 Hz that panics symphonia 0.5.5's probe, so every call into it is guarded and a rate outside 1–768 kHz is refused `music_unreadable` (red with the guard removed, the range widened). **P5c built**: meshharbor-desktop's Edit view (`src/front/editor.js`, `src/editor.rs`, `docs/recording.md` §11 "The Edit view"): the timeline with split, keep, cut and speed up (a split stays the person's), the sound card with music, the export with progress, cancel and the result named with its sound; every change saved as the edit list roomlerd reads, one shared fixture pinning both ends (`agents/meshharbor-desktop/tests/fixtures/edit-list.json`); `roomlerd media` run as the person, one export at a time, a silent death reported `engine_failed`; the preview through the asset protocol, one file at a time; a delete takes the edit list along. Open: the vmtest `record` cell and the field matrix (P6), FFmpeg decode for hardware recordings and AAC after **P4**, a thumbnail strip where the webview cannot play |
| **P6** | Docs in the house style, the field matrix, close | — | — |

## Acceptance criteria

- [ ] **AC1 — local HQ recording.** On Windows, macOS and Linux x64, a 10-minute local recording at native resolution,
      30 fps, H.264 4:2:0, lands in the default folder as a progressive MP4 (`moov` before `mdat`) that plays in the OS's
      default player; its frames are native resolution while a concurrent session is relay-capped; the sidecar's
      dropped-frame count is ≤ 0.5 %.
- [ ] **AC2 — the folder.** The default resolves per OS as specified, and on a host with OneDrive-redirected or
      CFA-protected Videos it falls back with the reason shown; an override set in meshharbor-desktop is used by the next
      recording and "Reset" restores the default; a `record_dir` that is relative, UNC or contains a reparse point is
      refused at `ConfigSet` with a named reason.
- [ ] **AC3 — audio.** System audio and the microphone are off unless chosen; when both are chosen they stay within
      ±40 ms of the picture over a 30-minute recording (a clap test at start and end); a blocked microphone (Windows
      privacy switch, macOS TCC denied) refuses the start with `mic_unavailable{…}` rather than recording without it.
- [ ] **AC4 — crash safety.** `kill -9` of the recorder loses ≤ 2 s; the boot reconciler turns the partial into a
      playable file marked `interrupted`; a pushed update mid-recording ends the same way.
- [ ] **AC5 — remote gates.** Each gate refuses with its named reason on a real pair, every refusal first shown on the
      current deploy: no role bit · device gate OFF · a break-glass session · a pre-feature agent · a denied prompt ·
      an attended host with no indicator surface. With every gate passed, recording starts only after the host's banner
      and red dot are up, and the host's Stop ends it.
- [ ] **AC6 — remote download.** The controller downloads a ≥ 2 GiB recording made on a relay-carried session and
      survives a forced mid-transfer flap by resuming from the offset; the SHA-256 equals the host's file; a different
      controller of the same device can neither list nor fetch it.
- [ ] **AC7 — the microphone is local-only.** No wire message, CLI flag or API lets a remote controller turn on the
      host's microphone — a test per entry point, and a review that lists every entry point.
- [ ] **AC8 — editor.** An export with a cut, a ×4 speed-up and background music (MP3 and M4A, looped, with fades) has
      the expected duration ± 1 frame, the music at the chosen level, and plays in the OS default player; the
      `export.rs` oracle and its negative control both behave in CI.
- [x] **AC9 — size.** The P4 release run's measured installer sizes are recorded in the field log; the MSI stays under
      the 18 MiB ceiling, or the ceiling moves in a PR that says why; the MSI baseline is re-pinned from that run.
      *(2026-09-27, rehearsal 36346825023: both MSIs measure 17.67 MiB, under 18. The baseline is re-pinned to 17.67, and
      the ceiling moves to 22 in the same PR with the reason written beside it: an 18 ceiling sat inside the +2 warn
      band. `.pkg`, `.deb` and the companion's `.deb` are in "Installation size — the evaluation" and the field log.)*
- [ ] **AC10 — the server never carries a recording.** No code path uploads recording bytes; `recording_url` stays
      `None`; the server stores only `recording_activity` claims, and a test asserts the claim payload has no content
      field.
- [ ] **AC11 — tests run where they claim to.** `--test recorder`, `--test control_dc_record`, `--test export`, the
      `crates/tests` `recording_tests` module and the Playwright specs each run in a named CI lane, and each oracle's
      negative control has been shown RED once.
- [ ] **AC12 — the pointer (P1d).** A local recording on Windows (WGC, and DXGI under `MESHHARBORD_CAPTURE=scrap`), macOS
      and Linux X11 shows the mouse pointer where it was, including while it moves over a still screen, and leaves no
      trail; its sidecar's `pointer` says `in_frame` or `drawn`, and a backend that cannot give one (DRM) says `none`.
- [x] **Docs** — `docs/recording.md` created in the house style (a mermaid component diagram §1, the remote
      start/stop sequence with every gate §10, the write-rule flowchart §4 — the last added 2026-10-08);
      `docs/remote-control.md` §11.3, `docs/permissions.md`, `docs/encoders.md`, `docs/installation.md`,
      `docs/data-model.md`, `docs/lgpl-relink.md` all carry the recording surface, and `CONTEXT.md` gained the
      recording glossary (2026-10-08); the page is linked from `docs/README.md`. (The user-facing docs page at
      `roomler.ai/docs/remote-desktop/recording/` shipped separately in #1815.)

## Test plan

⚠️ `agents/meshharbord/tests/*.rs` **never run in CI today**: every `cargo test -p meshharbord` step is `--lib`
(`.github/workflows/ci.yml:406,463,777`), and `tests/file_dc.rs` is in no workflow. Each new test binary below gets its own
named `--test` step. Every oracle has a **negative control** — the same assertions must fail on the wrong input.

- **Unit** (the default and `ffmpeg-encoder` roomlerd lanes; `crates/remote_control`, `crates/db`, `crates/localapi`):
  edit-list validation and PTS-based selection (property test; audio sample counts derived rationally — 48000/30 is an
  integer); `mp4-atom` avcC/hvcC from Annex-B, keyframe-aligned fragments, a remux that keeps every sample with `moov`
  first; the write-rule decision table and reparse/symlink refusal; drift corrector, soft-clip mix, gain/fade/loop;
  per-backend recording option sets (golden) and a lock that the live sets are unchanged; `PromptKind::Record` text, a
  prompt id that is not the session id, the cooldown; the `record` capability only while the gate is on; serde defaults
  and wire names; `DesiredConfig` refuses every `record_*` key; the role bit sits in no managed row below
  ADMINISTRATOR and `ALL` includes it; the new LocalAPI verbs reach `handle()` and the peer check refuses another
  session.
- **Agent integration** (`agents/meshharbord/tests/`): `recorder.rs` — five seconds at 30 fps of the counter-strip source
  gives a progressive MP4 of 150 ± 1 frames and 5.0 s ± 1 frame whose decoded counters are in order; `kill -9` leaves a
  staged fMP4 that parses to its last fragment and that the reconciler finalizes; stdin EOF finalizes cleanly; the low
  water mark stops it `disk_low`. `control_dc_record.rs`, on the `file_dc.rs` loopback-PeerConnection pattern with the
  production handlers — every refusal reason, list isolation between controllers, `get` SHA-256 and resume, path
  confinement, the microphone refused remotely, the gate going OFF mid-recording. `export.rs` — a 10 s synthetic
  recording, a 440 Hz WAV generated in the test and the edit list keep [0,2) · cut [2,4) · ×4 [4,8) · keep [8,10) decode
  to the counters `0..59 ++ 120,124,…,236 ++ 240..299` and 5.0 s ± 1 frame, with audio in band; the unedited source must
  fail the same assertions.
- **Server integration** (`crates/tests`, new `recording_tests.rs`): RECORD is kept iff (owner, ADMINISTRATOR or the
  role bit) and the capability and no `override_reason`, every cell with a positive control; a `RecordingActivity`
  for a session without RECORD is rejected and lands nowhere; and a **full path** — an in-process agent built with
  `synthetic-frame-source,openh264-encoder,recording` and a webrtc-rs controller record three seconds, download them and
  parse the counters.
- **E2E** (Playwright in the in-pod `pwrunner` sidecar, `scripts/e2e-nightly.sh`; `Dockerfile.agent-e2e` gains
  `recording`): `remote-recording-smoke.spec.ts` (Record → REC chip → Stop → the list → Download → an MP4 box walk in
  the spec → the device activity shows start and stop); `remote-recording-denied.spec.ts` (no role bit, gate off,
  break-glass: no button; the admin control case sees it); meshharbor-desktop's frontend served in Playwright Chromium with a
  mocked Tauri bridge (start/stop/list, folder default/override/reset, editor → golden edit list, export progress and
  cancel); the vmtest `desktop` check goes from five views to six, plus a `record` cell that records, probes, exports and
  probes the output on real OSes.

## Open decisions

1. **Wayland portal** — a silent second session through the restore token, or a tee of the worker's stream? P0 measures.
2. ~~**HEVC editing in v1** (+≈ 0.4 MB compressed)~~ — **decided 2026-09-27: H.264 only**, as built in P4a (no overrule).
   No recording is HEVC: the writer's only video sample entry is `avc1`, and the sidecar's `codec` is always `h264`.
   An HEVC decoder would decode nothing, and it is not free: the static Windows `avcodec.lib` measured 38.0 MB with
   h264 + hevc at P0 and 29.8 MB with h264 alone. Revisit if HEVC recording is ever built.
3. **Owner shortcut for `may_record`** — proposed yes (the organisation's owner may record its own devices, still
   subject to gates 3–6).
4. **The re-attach grace** — 60 s proposed; tune against the reconnect ladder's measured timings.
5. **Quality numbers per backend** (the `q` of each row above) — tuned in P1 on a text-heavy scroll and a video clip.
6. ~~**A host at its login screen, for an UNATTENDED recording (P1f)**~~ — **decided 2026-09-26: a login screen is not
   "nobody"** (see "Decided 2026-09-26"). Built: `Refusal::LoginScreen`, refused `login_screen` before the host is asked
   (`docs/recording.md` §6 and §10). It was: a display manager's greeter counted as "nobody", as consent treats it, so a
   remote recording there ran unattended with no banner, while a login screen shows account names and a person may be
   standing at it.

## Out of scope

Separate audio stems · a webcam overlay, annotations, click highlights, automatic speed-up of idle stretches ·
choosing a monitor (capture is primary-only today) · recording conference calls · an editor in the browser · any
server-side storage or upload of recordings (the plaintext invariant forbids it) · macOS system audio (needs
ScreenCaptureKit and macOS 13) · importing arbitrary videos into the editor.

## Field-verification log

| Date | Where | Phase | Read |
|---|---|---|---|
| 2026-09-25 | release `agent-v0.4.101` assets | P0 baseline | MSI 16,109,568 B (= 15.36 MiB in the guard's units) · Linux x64 .deb 13,830,684 B · arm64 .deb 11,410,760 B · macOS .pkg 21,765,134 B · meshharbor-desktop .exe 15,896,864 B · meshharbor-desktop .deb 4,422,496 B |
| 2026-09-25 | dev box, 0.4.101 installed | P0 baseline | `meshharbord.exe` 43,720,480 B (.text 32,041,105); the MSI's cab is 16,041,977 B holding 45,280,568 B, so MSZip ≈ 0.35. Vendored Windows FFmpeg: `avcodec.lib` 21,812,318 B, `avformat.lib` 3,217,828 B (32 members, no muxer or demuxer), `swresample.lib` 1,031,918 B (built, unused) |
| 2026-09-25 | `release-agent.yml` | P0 baseline | the MSI guard's pinned baseline (13.13) is stale — 0.4.101 is 2.23 over it — so its +2 warn band already fires before this FR adds a byte |
| 2026-09-25 | vendor workflows on `fr84-p0-measure` ([Windows + Linux](https://github.com/gjovanov/roomler-ai/actions/runs/36148229193), [macOS](https://github.com/gjovanov/roomler-ai/actions/runs/36148233530)) | P0 | all three trees built with `--enable-decoder=h264,hevc --enable-encoder=aac`; the new probes found all three components present and prores still trimmed. Linux `libavcodec.so.63.1.101` 1,659,312 → 3,797,744 B (**+2.04 MiB**, xz-9 +0.47 MiB); macOS `libavcodec.63.1.101.dylib` 790,600 → 2,731,480 B (**+1.85 MiB**, xz-9 +0.42 MiB, deflate +0.69 MiB); Windows `avcodec.lib` 21.8 → 38.0 MB (archive size, not a link delta) |
| 2026-09-25 | dev box, MSVC 14.50 | P0 | the Windows link delta, measured: one probe calling `avcodec_find_encoder_by_name` (which pulls the whole codec registry) linked statically against the production tree = 1,439,232 B (`h264dec=NULL`) and against the P0 tree = 4,369,408 B (a live `h264dec`): **+2.79 MiB linked, +0.82 MiB deflate-6** (the MSZip proxy) |
| 2026-09-25 | dev box, Windows | P1a | `cargo test -p meshharbord --features recording,openh264-encoder,synthetic-frame-source`: 47 unit tests and `--test recorder` 8/8, green three runs running. Negative controls shown RED before trusting them: chunk order reversed in the remux → `remux_keeps_every_sample_in_order_with_moov_first` fails; the recorder frozen on its first frame → the end-to-end oracle reads "1 of 91" distinct frames and fails |
| 2026-09-25 | dev box (Windows, NVIDIA), `roomlerd record` on the synthetic source | P1b | `--encoder hardware` → `h264_nvenc` opened in the recording profile; `ffprobe`: High, 320×240, `yuv420p`, `color_range=tv`, `smpte170m` ×3, 30/1 fps, 116 frames / 3.867 s, keyframes at frames 0 and 60, `ftyp → moov → mdat`, `ffmpeg -f null` decode with zero errors. `--encoder software` → openh264: Constrained Baseline, same colour tags, keyframes 0/60, zero decode errors. Recordings deleted after the check |
| 2026-09-25 | dev box (Windows) + WSL Ubuntu 24.04 | P2a | Windows: `--test recorder` 12/12, `--lib recording::` 51, `meshharbor-localapi` 27, `meshharbor-node-core` 184, `remote_control` 194, the CLI's record tests; clippy `-D warnings` with and without `recording`. Linux (WSL): fmt, `meshharbor-localapi` clippy + tests (the unix peer-uid half of the gate, which a Windows build never compiles), agent-core, CLI, and the recorder's clippy, lib and `--test recorder`. Negative controls shown RED before trusting them: the partial lock disabled → the reconciler finalized a LIVE recording's partial; the start-deadline kill disabled → the child reported `started` after its caller had been told it did not start |
| 2026-09-25 19:54Z | production, `hosted-20260925-3f17571` (pre-P3a), the operator's browser | P3a baseline (AC5 "first shown on the current deploy") | The owner asks for `VIEW \| RECORD` on a fresh `/ws` against their own pre-feature Windows device. Answer: `rc:session.created` with `permissions: "VIEW \| RECORD"`, so RECORD was **passed through unstripped**, and no `record_refused` key at all. The socket was closed at once, which tore the session down. Managed role masks: owner 2147483647 (2^31−1, no bit 31), admin 1468006391, moderator 34074513, member 249729, guest 2049, none carrying bit 31. `GET …/recording-activity/{agent_id}` → 404 |
| 2026-09-25 20:06Z | production, `hosted-20260925-d5a7a3d` (P3a live, promote run 36183319196) | P3a post-roll, the pair with the 19:54Z baseline | The same probe as the baseline (owner, `VIEW \| RECORD`, the same pre-feature device). Answer: `permissions: "VIEW"`, `record_refused: "device_not_opted_in"`, so RECORD is now **stripped with its reason**; at 19:54Z it had passed through. Managed masks: owner 4294967295 (bit 31 added by the boot reconcile); admin, moderator, member and guest unchanged, none with bit 31. `GET …/recording-activity/{agent_id}` → 200, `total: 0` (it was 404). Still owed for AC5: the no-role-bit and break-glass cells need a second identity, and the device-side cells need an agent release carrying `recording` |
| 2026-09-26 | the operator, before 0.4.104 | ship step | `recording` taken back out of `full` before any release carried it. It rejoins a release after canary field checks: an EDR-managed corporate laptop first (on Windows the daemon launches a restricted-token child as soon as someone opens the Recordings view, the pattern EDR watches for), then macOS TCC for that child. The kill switch and the macOS `cargo check` stay; the check now names `recording` |
| 2026-09-26 | dev box (Windows, MSVC), release `meshharbord.exe` with the release profile's `CODEGEN_UNITS=1`, features `recording,openh264-encoder,audio`, one worktree and target dir | P5b size | P5a 35,525,120 B → P5b 36,972,544 B: **+1,447,424 B (+1.38 MiB)**. With music limited to MP3, AAC/M4A and WAV: 36,680,704 B (+1.10 MiB), so FLAC and Ogg Vorbis cost 0.28 MiB. ≈ +0.48 MiB in the MSI at the MSZip ratio, above the estimate (0.3) |
| 2026-09-26 | dev box, symphonia 0.5.5 in a scratch crate | P5b | a fuzz-lite over 1,800 malformed music files (random bytes behind each format's magic, hand-made WAV, FLAC and MP3 headers): **one panic**, a WAV declaring 0 Hz (`TimeBase cannot have 0 numerator or denominator`, in the probe); no hang. 1 Hz is accepted, which the resampler would grow 48 000-fold. Both refused `music_unreadable` now, each pinned by a cell shown red first |
| 2026-09-26 | dev box (Windows) + jsdom | P5c | `meshharbor-desktop` editor unit tests 8/8; `ui` companion suites 46/46 (the editor's 22); roomlerd `recording::edit` + `recording::manager` with the shared fixture and the delete. Nine controls red first: an action merging neighbours, an export not waiting for the save, the Edit button without the engine, a gap accepted, `looped` written by the page, a list naming another recording saved, a silent engine death unreported, a delete leaving the list, `looped` read by roomlerd |
| 2026-09-27 | CORPLAP-2 (Windows 11, SystemContext worker, MDE + Defender with tamper protection, 19 ASR rules, NVENC), canary `0.4.106` | Windows canary | Installed by hand (the first attempt switched SystemContext off: #1727, fixed by #1728). Two local recordings (12.1 s, 27.5 s) and one remote recording with its download: progressive MP4s (`ftyp moov mdat`), frame counts exactly 30 fps, 0 late ticks, `h264_nvenc` 1920×1200. The recorder child runs as the console user, its parent the SYSTEM worker (`WTSQueryUserToken`). The viewer offered Record only with the device gate on, listed only this controller's file, and the download's SHA-256 matched the device's. **0 Defender events naming roomlerd, 0 detections** (the only ASR events were `9e6c4e1f` audits raised by Windows' own `svchost.exe`). Not covered: MDE cloud-side alerts; the `CreateRestrictedToken` path (all three corporate laptops run SystemContext); NVENC writes profile 100, `editable = false` until P4. [#1634](https://github.com/gjovanov/roomler-ai/issues/1634#issuecomment-5855766734) |
| 2026-09-27 | dev box (Windows) + WSL Ubuntu | P1e-mac | Windows: fmt; clippy `-D warnings` with and without `recording`; `delegate` tests 21/21, seven new. Four were written with the change: the record context crosses and an older frame still parses; only a session handed over with `RECORD` may report activity; that memory is bounded; the device advertises the attached worker's `record` caps. Three came from an independent review, which found that the relay's positive path was untested, that a session was noted even when no worker received it, and that a replaced worker's sessions stayed reportable by the next one: the relay end to end; an undelivered session is not noted; revoking a worker forgets what it was handed. The review also moved the worker's caps into the hello (a 30 s strip after every reconnect) and raised the bound to 1024. Linux: clippy both ways (the only lane that compiles `delegate_worker`), `delegate` tests 23/23. Negative controls shown red first: admitting any `RecordingActivity` fails two cells; ignoring the worker's caps fails the advertising cell; the relay not consulting the admission, `revoke` not clearing, and noting before the send each fail their cell. The end-to-end path (a delegated session recording in the worker) is the Mac canary's to prove. |
| 2026-09-27 | vmtest `ubuntu/installer/user` (Ubuntu 24.04, kernel 6.8.0-138, systemd 255), release 0.4.107 | P2c regression | The per-user `meshharbor.service` is `active/running` and every cell check passed (install, enroll, overlay, rd, companion autostart). The installed unit carries `ReadWritePaths=-%h/Videos`. The daemon shares the shell's mount namespace (`mnt:[4026531841]` both) with `kernel.apparmor_restrict_unprivileged_userns = 1`, so the sandbox is still inert there, as measured before (run by the release session) |
| 2026-09-27 | vendor workflows on `fr85-p4` ([Windows + Linux](https://github.com/gjovanov/roomler-ai/actions/runs/36323053988), [macOS](https://github.com/gjovanov/roomler-ai/actions/runs/36323055472)) | P4a | All three built with `--enable-decoder=h264 --enable-encoder=aac` (H.264 only, open decision 2). The probes found the h264 decoder and the aac encoder present, and hevc and prores absent; on Windows `ff_mov_muxer` is absent too (positive control `avformat_alloc_context`). Windows `avcodec.lib` 21.8 → **29.8 MB** (P0's h264 + hevc tree: 38.0); zip 16,820,196 → 19,575,016 B. Linux `libavcodec.so.63.1.101` 2,777,744 B; tar.xz 1,843,492 → 2,162,924 B (+319 KB). macOS tar.xz 790,316 → 1,071,108 B (+281 KB; dylib set 3.0 MB). Uploaded as `-h264dec-aac` beside the production assets, which stay pinned until P4c |
| 2026-09-27 | dev box (Windows) + WSL Ubuntu 24.04 against the `-h264dec-aac` Linux tree | P4b-1 | Windows (the Opus path; `CMAKE_POLICY_VERSION_MINIMUM=3.5` for this box's CMake 4 and libopus): `--lib recording::` 116/116, `--test recorder` 21/21, `--test export` 10/10. WSL (the AAC path, `MESHHARBOR_EXPECT_FFMPEG_AAC=1`, `vp9-444` as in CI): clippy `-D warnings --all-targets` clean, `--lib recording::` 124/124, `--test recorder` 19/19, `--test export` 11/11 including an AAC recording read back through keep / cut / 4× / keep. Two controls were RED before trusting them. With the sample-exact cut removed, a click made 30 000 samples after the first frame decodes at 30 240. With AAC's priming unpaid, it lands at 31 024, in the recorder and in the export's reader alike. FFmpeg's AudioSpecificConfig is five bytes (`11 90 56 E5 00`: AAC-LC 48 kHz stereo and an explicit "no SBR"), not the two the first test expected; the file carries the encoder's own |
| 2026-09-27 | the supervised MacBook (macOS 26.6.2, arm64: a root daemon + a `run --supervised` GUI worker + the companion), canary `0.4.109` (run 36332040195) | macOS canary | **PASSED** (#1634 comment). Install: the signed, notarized and stapled `.pkg` was pushed over the overlay and run by a one-shot launchd job outside the daemon's tree. `installer`: *The upgrade was successful*, exit 0. Daemon, worker and companion came back on 0.4.109, and the server showed the device online ~10 s after the start. **TCC:** the designated requirement is unchanged (`fans.itachi.meshharbor.agent`, Developer ID, `leaf[subject.OU] = "4TG7586MY5"`). Right after the upgrade: `macOS permissions: Screen Recording + Accessibility both granted`, and no `permission MISSING` anywhere. **Local** (`roomler record` as the console user): `h264_videotoolbox` cq 19, 3024×1964 @ 30, 246 frames / 8.2 s, 0 late ticks, no events, the pointer in frame. **Remote** (prod viewer, owner, an auto-grant host): the record channel attached; the recorder's encoder is separate from the live `hevc_videotoolbox` @ 60; 781 frames / 26.0 s, 0 late ticks. The viewer's download read *"5.5 MB of 5.5 MB · saved, checksum verified"*, and the device logged `download sent … offset=0 sent=5759995`; the final browser save was suppressed. The viewer listed only its own recording. Both files probe as H.264 profile 100, `editable: false` with P4b-2's reason, until P4c. **The gate:** `record_remote_enabled` persisted in the worker's (console user's) config; the worker re-announced `["available","remote"]` at once, and the daemon forwarded it on the next heartbeat. **Not verified:** the banner's on-screen appearance (the start was not refused `no_indicator_surface`), the microphone (P1c-mac), system audio. Restored: the gate off, the test recordings deleted, the update helper left intact |
| 2026-09-27 | [rehearsal 36346825023](https://github.com/gjovanov/roomler-ai/actions/runs/36346825023) of `fr85-p4c-recorder-release` (unpublished; `recording` in `full`, the `-h264dec-aac` FFmpeg on all three platforms, signed) | P4c / AC9 | **All five builds green.** MSI 17.67 MiB (both flavours) against 0.4.105's 15.89 and the Windows canary's 17.04 (`recording` alone). `.pkg` 24,497,327 B, x64 `.deb` 15,730,204 B, arm64 `.deb` 12,761,332 B, meshharbor-desktop `.deb` 4,810,440 B. The guard warned (+4.54 over the stale 13.13) and passed under 18. Re-pinned to 17.67, with the ceiling moved to 22 (see "Installation size") |
| 2026-10-08 | the Mac, agent 0.4.117 on prod | P6 field matrix | A remote recording from the browser viewer: `h264_videotoolbox`, **native 3024×1964** while the live view read "shown at 0.49×" — the recording keeps every pixel the rate-controlled stream drops — ~87 s, 0 late ticks, saved on the device, listed only to its controller. The **P3b-3 reattach** fired on its own: the viewer's session dropped mid-recording (`session ended while recording — waiting … grace_s=60`), a new session **picked it up** (`remote recording picked up by its controller's new session`), and when the grace ran out it ended `session_ended` into a playable file. A download over the `record` DC (`download sent … sent=4948817`). Throughout, the host's indicator was the "Recording…" banner (FR-27 P9 log, same day). The remote-recording gate was ON as found and left so; the test recording was deleted |
| 2026-10-08 | repo + CI | P6 docs | `docs/recording.md` gained the **write-rule flowchart** (§4, mermaid); `CONTEXT.md` gained the **recording glossary**. The component diagram (§1) and the remote start/stop sequences with every gate (§10) were already there, as were the recording sections of `remote-control.md` §11.3, `permissions.md`, `encoders.md`, `installation.md`, `data-model.md` and `lgpl-relink.md`, and the `docs/README.md` index row — the **Docs** criterion is now met and ticked |
| 2026-10-10 | repo | P6 docs, corrected | The §4 **write-rule flowchart** added above was wrong in two ways. It skipped the fallback chain: `record_dir`, then `Videos/Roomler`, then `~/Roomler Recordings`, then the recorder's data dir (`folder::resolve` → `default_choice`). It also showed meshharbor-desktop moving a fallback's file into the refused folder. That was weighed and deferred on 2026-09-26, and never built, as the text under the chart says. It also listed OneDrive as a failed probe, but OneDrive is ruled out before the probe. Redrawn from the code. The Docs tick stands |
