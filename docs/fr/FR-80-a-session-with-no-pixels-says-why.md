# FR-80 — a session with no pixels says why

**Issue:** [#1532](https://github.com/gjovanov/roomler-ai/issues/1532) · **Status:** **closed 2026-09-08** — shipped `agent-v0.4.94` + `hosted-20260908-aa36044`; both halves field-verified, with the failure cell created deliberately · **Glossary:** [`CONTEXT.md`](../../CONTEXT.md) · **Related:** [FR-27](FR-27-host-consent-prompt-surfaces.md) · [FR-77](FR-77-encoder-chroma-matrix.md) · [`docs/remote-control.md`](../remote-control.md)

## Goal

When a session produces no pixels, the operator learns **why, in the viewer**,
within the time it takes to notice. Two halves, both proven missing in the field
on 2026-09-08:

1. **The agent names the cause.** A capture backend that cannot open today
   degrades to `NoopCapture`, writes one `WARN` to its own log and tells the
   controller nothing. The controller can only show a stall.
2. **The viewer never invents a codec.** The status pill's no-`rc:video-info`
   fallback prints `VP9 <chroma>` unconditionally, so a session on any other
   codec that never delivers a frame reports as VP9.

## Why — the field event that produced it

The MacBook stopped streaming on 2026-09-08. Every session negotiated correctly
and painted black. The operator's read was "the codec picker is broken: I force
H.264 and it picks up VP9 4:4:4, and HEVC does not work either" — a reasonable
conclusion from what the product showed, and wrong.

What actually happened, in order:

- The macOS release began shipping under a **Developer ID** signature that day
  (`Developer ID Application: G ROX EOOD (4TG7586MY5)`), replacing the interim
  self-signed identity. macOS binds a TCC grant to the signature, so the
  host's existing Screen Recording permission stopped matching:
  `Failed to match existing code requirement for subject com.roomler.agent and
  service kTCCServiceScreenCapture` — the stored requirement named the old
  certificate root, the binary presented the Developer ID leaf.
- `scrap::Capturer` therefore failed to open. `capture::open_default` logged
  `scrap capture unavailable — falling back to NoopCapture error=… other error`
  and returned a capturer that yields nothing.
- The pump started correctly: `media pump: H.264 over DataChannel` →
  `FFmpeg DC pump starting codec_label="H264"`. No frame ever reached the
  encoder, so **no `rc:video-info` was ever sent**, so the viewer fell back to
  its VP9 label and reported `VP9 4:4:4` for an H.264 session.
- The viewer saw only `media stalled 6 s` → `media stalled 10 s, keyframe probe
  unanswered — re-creating session`, forever.

Two independent defects compounded into a misdiagnosis: the host knew the answer
and did not say it, and the viewer asserted something it had not been told. The
same shape as FR-27's `no_prompt_surface` (an unattributable failure that reads
as a different one), and the same remedy: **name the cause on the wire**.

⚠️ This will recur on **every** macOS host at its next update, and the class
recurs whenever a signing identity changes. The permission itself is the
operator's to restore; the product's job is to say so.

## Key design

1. **The reason survives the fallback.** `capture::open_default`
   (`agents/meshharbord/src/capture/mod.rs:549`) currently drops the backend's
   error on the floor and returns `Box::new(NoopCapture)`
   (`mod.rs:683`). `NoopCapture` carries a `CaptureUnavailable { code, detail }`
   instead, exposed through one new `ScreenCapture` trait method defaulting to
   `None`, so no call site changes shape and every pump can ask.
2. **The code is derived, never guessed.** `code` is a small closed set —
   `permission` · `no_display` · `not_built` · `backend_error`. On macOS a
   failed open asks the OS through the TCC preflight the agent already owns
   (`meshharbor_node_core::tcc::screen_recording_granted`, the same probe
   `scrap_backend` warns from) rather than pattern-matching an error string,
   because scrap reports a bare `other error` for a denied grant and a broken
   display alike and a guess would be a second lie. On Linux an absent
   `DISPLAY`/`WAYLAND_DISPLAY` is `no_display`. Anything unattributed stays
   `backend_error` with the backend's own text — an honest "we do not know".

   ⚠️ **The agent already knew.** `scrap_backend::primary` preflights the
   grant and logs `macOS Screen Recording permission MISSING — … Grant it
   under System Settings → Privacy & Security`, naming the exact fix. On the
   MacBook it logged that **34 times** on the day of the incident. Every word
   the operator needed existed, in a file on the far machine, and nothing
   carried it the one hop to the person looking at the black rectangle. This
   FR is not about learning the cause; it is about the cause being reachable.
   ⚠️ That backend's comment ("a missing grant does NOT fail `Capturer::new`
   — it delivers wallpaper-only frames") is now half-stale: on this macOS the
   open fails outright. Both shapes must stay handled — the warn covers the
   silent one, this covers the failing one.

   ⚠️ **On macOS the session question comes before the permission question.**
   A root LaunchDaemon lives in session 0, which has no WindowServer and never
   will, and its TCC preflight can still answer "granted" — so asking about
   permission first would send the operator to a toggle that changes nothing.
   `tcc::has_gui_session` is checked first, and `no_display` names it. ⚠️ This
   rests on `tcc`'s own documented reasoning, **not** on a host: an earlier
   draft of this spec cited the MacBook's daemon row as the proof, and that row
   turned out to have a GUI session and to capture fine. The ordering is right;
   the evidence for it was wrong, and no fleet host currently exercises it.
3. **One new control-DC message**, `rc:media-unavailable`, built by a sibling of
   `video_info_payload` (`peer.rs:4596`) and sent with the same
   retry-until-delivered discipline both pumps already use for `rc:video-info`
   (rc.87: a once-only send races the control-DC open and is silently lost).
   It is peer-to-peer JSON on the control channel, **not** a `ClientMsg` /
   `ServerMsg` variant, so the server wire, the namespace table and the
   composition baseline are untouched. An older viewer ignores an unknown `t`.
4. **The pill stops asserting.** The fallback label derives from the transport
   the viewer itself negotiated instead of a hardcoded `VP9`, and a session with
   no frame yet says so rather than naming a codec as if it were running. The
   legacy libvpx path — the one case where the old fallback was right — keeps
   its label because that transport genuinely is VP9.
5. **The viewer surfaces the reason where the operator is looking**: on the
   black canvas, not only in the console, with the macOS case naming the
   setting to change.

## Phases

| # | Phase | Kill switch | Status |
|---|---|---|---|
| P1 | `CaptureUnavailable` on `NoopCapture` + the trait accessor; the macOS/Linux derivation | — (a pure addition; absent reason = today's behaviour) | **shipped** — the reason is classified once at `open_default` and carried by the fallback capturer; macOS reuses the TCC preflight the agent already owns |
| P2 | `rc:media-unavailable` on the control DC, retry-until-delivered, from all three pumps | an old viewer ignores the message | **shipped** — a spawned, deadline-bounded notice, because the control DC opens after capture and the pumps' own retry hangs off a captured frame |
| P3 | The viewer: the reason on the canvas, and the pill's fallback stops naming VP9 | pure UI | **shipped** — the pill reads the DECODER's own config string (`codecLabelFromDecoderConfig`), the canvas shows the cause and the fix, and the health label says "no screen capture" instead of "video stalled" |
| P4 | Docs — `docs/remote-control.md` §5.1a (the sequence, the code table), the FR spec | — | **shipped** |

## Acceptance criteria

- [x] **P1** — a host whose capture cannot open reports a `code` that matches
      the actual cause, with a positive control: the same host with capture
      working reports no reason at all.
- [x] **P2** — the message arrives at the viewer on a session that never
      produces a frame, including on a relay session where the control DC opens
      late (the rc.87 race the retry exists for).
- [x] **P3** — an H.264 session that never delivers a frame **never** displays
      "VP9" anywhere in the viewer; a libvpx VP9 session still reads VP9; a
      healthy session is unchanged and still names its real encoder.
- [x] **Field** — reproduced on a host with no capture (a headless Linux fleet
      node is the natural negative cell) and read in the viewer; and the
      MacBook, permission restored, streams with the pill naming the real
      encoder.
- [x] **Docs** updated in the house style and linked from `docs/README.md`.

## Out of scope

- Restoring the permission itself. A remote agent must not be able to grant
  itself screen capture, and nothing here tries.
- Making `has_input_permission` track the OS rather than the build
  (`encode/caps.rs:1783` records that gap). Same class, separate change.
- Re-signing or pinning the macOS identity so TCC grants survive a
  certificate change. That is FR-7's ground, and the answer there is that a
  Developer ID move is a one-time cost.

## Field-verification log

| Date | Where | Phase | Read |
|---|---|---|---|
| 2026-09-08 | release + deploy | P1–P4 | `agent-v0.4.94` (#1534 → bump #1536 → `81d23b9f7`; release run 34274486566, 28 assets) rolled to all seven hosts in 6 min. The viewer half went to production as `hosted-20260908-aa36044` (promote run 34273234756; both pods confirmed on the image, `/health` 200) |
| 2026-09-08 | MacBook-1 (macOS, grant restored), an H.264 session — **the positive control** | P3 | **PASS, and it is the string that started this.** Pill: `H.264 4:2:0 HW (h264_videotoolbox) · direct · dec HW · FSR`, 17.7 Mbps, 31 fps, real picture at 1940×1260 of a 3024×1964 desktop; `rc:video-info` names `h264_videotoolbox`; **no `rc:media-unavailable` at all** — a healthy session says nothing. The same session on 0.4.92 reported `VP9 4:4:4` |
| 2026-09-08 | zeus, `ROOMLERD_VIRTUAL_DESKTOP=0` via a drop-in — **the failure cell, created deliberately** | P1–P3 | **PASS on every half.** Agent: `scrap capture unavailable — falling back to NoopCapture error=no primary display: connection refused code="no_display"` → `capture unavailable — this session will produce no pixels; telling the controller … code="no_display"`. Wire: `{"t":"rc:media-unavailable","code":"no_display","detail":"no primary display: connection refused","hint":"This host has no display to capture…"}`. Viewer: the canvas reads *This device cannot capture its screen*, the hint, `Reported by the device as no_display`, scrap's own words, and *Remote shell, file transfer and the other channels are unaffected*; the health label reads **`connected · no screen capture`**, not "video stalled"; and **the word VP9 appears nowhere** (the pill names H.265, the codec its decoder was configured with). The classification is the right one of four: `no_display`, not `permission` and not `backend_error` |
| 2026-09-08 | zeus, drop-in removed | — | Restored and re-verified: `ROOMLERD_VIRTUAL_DESKTOP=1`, only `virtual-desktop.conf` remains, and a session streams `H.265 4:2:0 HW (hevc_vaapi) · relay`, 1600×900, with no overlay. The host was left exactly as it was found |

⚠️ **The cell had to be created, and that is worth recording.** The plan was to
use the MacBook's daemon row, which could not capture that afternoon. By
evening it could — the grant restoration covered both rows — and with every
Linux node running a virtual desktop the fleet had **no host that fails
capture**. Rather than assume the path worked, one host was made to fail it
reversibly. A failure path with no host that exercises it is a path nobody has
run.

⚠️ **A correction to this spec's own earlier reasoning.** The `has_gui_session`
ordering was justified here by "the MacBook's daemon row still cannot capture".
That row has a GUI session and captures fine. The ordering is still right — a
session-0 daemon genuinely cannot capture and its TCC preflight can still
answer "granted" — but it stands on `tcc`'s documented reasoning, not on that
host. The `permission` code therefore remains **unproven in the field**: it was
the original incident's cause, and no host now reproduces it.
