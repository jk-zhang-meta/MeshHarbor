# FR-62 — Encoder rate changes without an IDR

**Issue:** [#1242](https://github.com/gjovanov/roomler-ai/issues/1242) · **Status:** A0 measured on BOTH silicon — NVENC passes, **QSV in-place is broken and the flag stays OFF**; **both** recorded causes are REFUTED (the second by measurement on 0.4.62); patch 0004 is what is left; A1 shipped inert; A2 + const flip shipped (0.4.51) · **Plan:** `rate-control-architecture` (approved 2026-09-02)

## Progress

- **A0 — the sweep** (`encoder-smoke --reconfigure-sweep`) shipped in #1247.
- **A0 — NVENC measured on the RTX 5090** (2026-09-02): `hevc_nvenc` forces a rate-caused IDR on
  **20/20** rungs, but the apply is **0.001–0.008 ms** (an in-place `AVCodecContext` field write).
  So the entire cost of a NVENC rate move is the forced keyframe — exactly what patch
  `0001-nvenc-no-idr` removes. Codec-independent (shared `reconfig_encoder`). Full table on #1242.
- **A1 — the in-place path** ships behind `encoder_inplace_rate` (**default OFF, inert**): QSV wrote
  `bit_rate + rc_max_rate + rc_buffer_size` (CBR) so `qsvenc`'s per-frame `update_bitrate` resets the
  BRC with no rebuild; NVENC's in-place buffer is sized to the open window (fixing the pre-A1 1×
  write). `supports_dynamic_bitrate()` = "not a rebuild" so the pump immediate-applies QSV when on.
  Heartbeat gains `inplace_rate / rate_moves / rebuilds / idr_count`.
  ⚠️ This arm **does not work on Iris Xe** and the flag stays OFF; see "Why the Reset fails" below
  for the two explanations that have been tried and refuted.
- 🚨 **A0-QSV MEASURED, AND IT REFUTED THE PLAN'S ASSUMPTION** (CORPLAP-1's Iris Xe, 0.4.51,
  2026-09-02 — full tables on #1242). The flag's flip-ON condition was "A0 clears the QSV
  `MFXVideoENCODE_Reset`". It does not clear:
  - `encoder_inplace_rate=1` fails the Reset outright (`hevc_qsv Error during resetting:
    incompatible video parameters`), in **both** `low_power` modes — the VDENC fixed-function path
    and the VME path fail byte-identically, so `low_power` is ruled out as the cause.
  - The rebuild path that in-place was meant to replace costs **1.3–2.0 s at ≤ 1 Mbps** and
    340–390 ms above 1.5 Mbps, which is the ~2 s pump freeze #1254 then moved off-thread.
  - ⚠️ **`encoder_inplace_rate` must stay OFF for QSV.** Flipping it fleet-wide would break every
    QSV rate move, on the encoder the constrained population actually runs.
  - 🔑 **Consequence for A4, which the deletion list did not anticipate:** the coarsen ladder is
    **load-bearing for QSV**, because QSV has no cheap apply path at all. NVENC is settled (A2: 20
    IDRs → 0, apply 0.004 ms) and can shed its rationing; QSV cannot until it has its own answer.
    A4 is therefore **per-backend, not a flat delete** — see the amended A4 below.

### Why the Reset fails — two explanations tried, both dead

⚠️ **The hypothesis previously recorded on #1242 is refuted by our own open path.** It supposed we
open QSV *quality-driven* (`global_quality`, ICQ), so that `TargetKbps`/`MaxKbps` "aren't the
governing params and MSDK rejects resetting them", and proposed testing it with a sweep that omits
`global_quality`. But `build_encoder` sets `bit_rate = maxrate_bps` for every non-NVENC backend and
the option dict sets `maxrate` to the same value, so `qsvenc.c::select_rc_mode` takes its **CBR**
branch (`rc_max_rate == bit_rate`) before it ever reaches ICQ. `global_quality` is inert there. In
CBR those two fields are exactly what governs, so the stated mechanism cannot be the cause — and the
proposed experiment would have removed an already-inert option and produced a null that looked like
a refutation of something else.

🔑 **The replacement, grounded in the code rather than in inference: the third field.** The in-place
arm writes `bit_rate`, `rc_max_rate` **and** `rc_buffer_size`. `qsvenc` maps `rc_buffer_size` onto
`mfxInfoMFX::BufferSizeInKB`, which sizes an internal bitstream buffer allocated at Init, and our
value is `target × hrd_pct` so it moves on **every** rate change. The oneVPL spec defines
`MFX_ERR_INCOMPATIBLE_VIDEO_PARAM` as *"Reset requires additional memory allocation and cannot be
executed"* — which is what changing that field asks for. It also explains the fact `low_power` ruled
out: an allocation constraint is identical on VDENC and VME, which is exactly what was measured.

🚨 **…and that replacement is REFUTED TOO — measured on 0.4.62, CORPLAP-1, 2026-09-04.** The write
was gated behind a knob so both arms could run from one released binary, and skipping it changes
nothing: the Reset still fails `-14`. Three runs, all `hevc_qsv`, `low_power=1`, `encoder_inplace_rate=1`:

| run | open | first in-place move | `rc_buffer_size` | result |
|---|---|---|---|---|
| A (write restored) | 3 Mbps | → 6 Mbps | rewritten 3 M → 6 M | **-14** |
| B (write skipped) | 3 Mbps | → 6 Mbps | held at 3 M | **-14** |
| B′ (write skipped, clean) | **6 Mbps** | → **4.5 Mbps** (a DECREASE) | held at 6 M — generous and valid | **-14** |

B′ is the one that settles it. The buffer is untouched, larger than the new bitrate needs, and the
move is downward, so none of "the buffer changed", "the buffer grew", or "the buffer is too small
for the new rate" survives. ⚠️ The knob was **verified live** before believing the negative — the
debug line read `write_bufsize=false` on the failing run, because a flag that silently does nothing
produces exactly this result (the FR-63 slow-start trap).

⇒ **This driver rejects the bitrate change itself on Reset**, and `low_power=0` was already measured
identical, so it is not the VDENC path. An earlier sub-prediction died on the way here too: reading
oneVPL's *"requires additional memory allocation"* literally predicted that only buffer GROWTH would
fail, and the 6 Mbps-open decrease case failed identically.

**Code state: reverted.** The knob is gone and the three-field write is restored, so the in-place arm
is byte-for-byte what it was before the experiment. A lever whose hypothesis is dead is not worth a
config surface, and the finding lives here instead.

**What is left**: `mfxExtEncoderResetOption` — the FR's own untested **patch 0004**, now the leading
candidate rather than a footnote. It is an FFmpeg-level change, not reachable from a knob. If it also
fails, QSV has no in-place rate path on this driver at all, and A4 must treat `coarsen_bitrate` as
permanent for QSV rather than transitional.

⚠️ A5 (QVBR) is entangled with this and the spec should stop treating it as independent: moving QSV
off CBR changes `select_rc_mode`'s branch, so it could change whether Reset is accepted — and it is
the only route by which `global_quality` stops being inert.

**Parent/siblings:** FR-59 (the regression that motivated the arc). This is one of three FRs from that plan (FR-62 encoder apply path, FR-63 the controller, FR-64 the data path).

## Goal

A remote-desktop encoder follows the rate controller's target **without an IDR and without a rebuild**. Today `FfmpegEncoder::set_bitrate` (`agents/meshharbord/src/encode/ffmpeg/encoder.rs:1671–1671`) costs an IDR on every move: NVENC through FFmpeg's `reconfig_encoder` (n8.1.2 sets `resetEncoder=1; forceIDR=1` on a bitrate-only change), QSV/AMF/VideoToolbox through a full encoder rebuild under a comment that predates FFmpeg 6.0's runtime `update_bitrate()`. Nine of the 34 rate/quality heuristics in `encode/` exist only to ration that cost (coarsen ladder, deferred applies, 15-s thrift, background swap, settle-KF thrift, refine-vs-cap fight, opener grace, FlipTracker and kf_gate cooldowns); on LAN pairs the AIMD crosses a rung nearly every window — 44 swap IDRs in one day on one host (2026-09-02).

Also found while reading the sources: **our QSV sessions run CBR, not QVBR** (`select_rc_mode` tests `rc_max_rate == bit_rate` first and we set both to the cap), which is why every 0.4.49 frame on CORPLAP-1 was exactly `target ÷ fps ÷ 8` bytes; and the existing NVENC in-place write sizes `rc_buffer_size = target` while the open used `maxrate × hrd_pct` — every move silently resizes the HRD window.

## Key design

- **A0 — measure on silicon**: `roomlerd encoder-smoke --reconfigure-sweep` (moving-block synthetic content, 20 rate changes 6 M → 200 k → 6 M, per rung: key packets, `set_bitrate_ms`, burst, bytes-per-frame ratio). Pass = 0 key packets after the opener, apply < 5 ms, ratio ±25 % by frame 10, burst ≤ 2×. Hosts: Iris Xe (`hevc_qsv`, `low_power` 1/0), Arc (`av1_qsv`), RTX (`hevc/av1_nvenc`), Apple Silicon (`hevc_videotoolbox`); AMD recorded as unmeasured.
- **A1 — in-place applies, gated** (`encoder_inplace_rate`, default OFF in the PR, ON after A0 passes): `RateReconfig::{InPlace, Rebuild}` resolved at open; QSV writes `bit_rate + rc_max_rate + rc_buffer_size` together (CBR); the HRD sizing bug fixed; a 3 % dead-band; counters `rate_moves / rebuilds / idr_count` in the heartbeat; a startup probe per host/codec (a driver table is not evidence).
- **A2 — FFmpeg patches** carried in `.github/ffmpeg-patches/` and applied by all three vendor builders (Linux/macOS from source, Windows via the vcpkg overlay port's `PATCHES`), with a `ROOMLER-PATCHES.txt` hash gate in `release-agent.yml`: `0001-nvenc-no-idr-on-bitrate-reconfig`, `0002-videotoolbox-runtime-bitrate` (as WebRTC's VT encoder does), `0003-amf-runtime-bitrate` (disabled, unmeasured).
- **A3 — VideoToolbox/AMF** per A0; **A4 — retire** the nine rationing heuristics one shippable PR at
  a time (anchors in the spec). ⚠️ **Amended after A0-QSV**: this cannot be a flat delete. A
  heuristic that rations rate moves is dead weight on NVENC (a move is 0.004 ms and no longer costs
  an IDR) and **load-bearing on QSV** (a move is a 0.34–2.0 s rebuild). Each retirement is therefore
  gated on the backend it is retired for, and `coarsen_bitrate` in particular stays until QSV has a
  cheap apply path — deleting it because "FR-62 removed the need" would pin every QSV session to the
  rebuild cost it exists to avoid.
- **A5 (later A/B)**: QSV to QVBR (`bit_rate = 0.9 × maxrate`, keeps `global_quality`) — stops CBR padding idle frames.

## Acceptance criteria

- [x] AC1 — A0 report per backend on real hardware, attached here, with the pass/fail per codec.
      **Done for the two backends the fleet runs**: NVENC on an RTX 5090 (PASS — 20/20 rate-caused
      IDRs before A2, 0 after; apply 0.001–0.008 ms) and QSV on an Iris Xe (**FAIL** — Reset refuses
      in both `low_power` modes; rebuild 0.34–2.0 s). AMD and VideoToolbox remain unmeasured and are
      recorded as such rather than assumed; A3 covers them.
- [ ] AC2 — On a constrained session the bytes-per-frame ratio is ≈ 1.0 within 2 s of every target change (FR-59's instrument).
- [ ] AC3 — A 5-minute constrained session's `idr_count` ≤ dims changes + viewer keyframe requests.
- [ ] AC4 — Every deleted heuristic's kill switch is retired through the registry table with its evidence.
- [ ] AC5 — `encoder_inplace_rate = false` restores today's behaviour byte-for-byte (unit test + field check).

## Open decisions

- VideoToolbox: patch 0002 vs. "rebuild at settle, ≥ 15 s apart" (A0 on a Mac decides).
- Whether to attach `mfxExtEncoderResetOption{StartNewSequence=OFF}` (patch 0004) if any QSV driver starts a new sequence on Reset.

## Out of scope

- The controller itself (FR-63); which path ICE selects (FR-64); the QVBR switch (A5, separate A/B).

## Related

FR-59 #1163 (the regression that exposed the ladder), FR-31 (opening keyframe budget — `max_frame_size` is runtime-updatable in qsvenc and is that lever), FR-10 (relay IDR thrift, to be retired), FR-63, FR-64.
