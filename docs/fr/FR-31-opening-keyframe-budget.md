# FR-31: The opening keyframe of an NVENC session gets one frame's budget — ffmpeg discards the HRD in `cq` mode

Status: **P0 measured; P1 (post-open VBV) and P1b (`ldkfs`) BOTH REFUTED by the A/B — the opening keyframe is ~1.1–1.3 × `maxrate/fps` and nothing ffmpeg exposes changes that; decision pending on the remaining levers** (2026-08-29). Tracking issue: `FR-31` (#897). Implementation PR #900 is a draft (inert knobs + the `open_vbv_bits` log field).
Child of the RC-quality program; sibling of FR-10 (relay IDR thrift), FR-17 (relay transport),
FR-22 (time-to-first-frame). Spec ships with the implementation PR (the default is decided by
an A/B, see "Open decisions").

## The measurement

Operator report (2026-08-29): `neo16 → CORPLAP-2` "starts blurred for 1–2 s, then crystallizes".
The pair rides a DERP relay (CORPLAP-2's corporate VPN captures its LAN prefix — environmental,
out of scope here), so the agent opens `av1_nvenc` with the CONSTRAINED profile:

```
rc=vbr cq=22 preset=p4 tune=ll rc-lookahead=0 bf=0 forced-idr=1 maxrate=2550000 bufsize=5100000 delay=0
```

Per-frame sizes read off the `video-bytes` DataChannel in the browser (FR-17 framing header,
then the pump's own header — `peer.rs:10224`, `byte[4]` flags, bit 0 = keyframe). Identical in
every run:

| frame | bytes | arrival | flags |
|---|---|---|---|
| 1 | **5 616** | t₀ | **KEY** |
| 2 | 1 082 | +55 ms | inter |
| 3 | **117 348** | +230 ms | inter |
| 8 | 59 763 | +440 ms | inter |
| 13, 14 | 20 130 · 25 587 | +0.5–0.6 s | inter |
| 18, 19 | 31 843 · 8 541 | +0.8 s | inter |
| 23, 24 | 29 013 · 32 656 | +1.05–1.1 s | inter |
| 28, 29 | 22 353 · 28 987 | +1.37 s | inter |

≈370 KB in the first 1.4 s — one crisp IDR's worth of bits — delivered as inter frames after a
**5.6 KB keyframe** (a 1920×1200 AV1 IDR at maximum QP: ~562 superblocks × ~10 B). On screen
(Laplacian variance of the rendered canvas, 100 ms samples, viewer sharpening on *and* off):
**2 610 at first light, flat for 1.00 s, then 5 530** (×2.1). 5/5 foreground runs.

Two things this is NOT, both refuted by data rather than assumed:
- Not the viewer's FSR pass (FR-26 made it default-on): the curve is the same with
  `roomler-rc-sharpen=off`.
- Not the DC-open race: `dc_unopen_drops` was 4 and 7 on runs that looked sharp and 5–16 on
  runs that looked blurry — and the "sharp" runs turned out to be a sampling artifact (Chrome
  throttles background-tab timers to 1 Hz, so the sampler missed the first second).

## Root cause — two layers

1. **ffmpeg's NVENC wrapper zeroes the VBV in `cq` mode.** `libavcodec/nvenc.c` (n8.1, the
   vendored build): `:1182-1185` maps `-bufsize` to `vbvBufferSize`, then `:1252-1263` — the
   `if (ctx->quality)` block, which runs *later* in `nvenc_setup_rate_control` — does
   `averageBitRate = bit_rate = 0; vbvBufferSize = rc_buffer_size = 0; maxBitRate = rc_max_rate`.
   So the agent's HRD sizing in `encoder_options`
   (`agents/meshharbord/src/encode/ffmpeg/encoder.rs:246-278`, the rc.234 "2× the ceiling" design
   and the rc.442/443 constrained-window notes) **never reaches the driver on NVENC**. The
   driver runs its own default for the `ll` tuning, which behaves as a single-frame reservoir:
   the opening IDR may spend ~`maxrate/fps` (85 kbit at 2.55 Mbps / 30 fps — the observed
   5.6 KB is that, at maximum QP), the reservoir refills at `maxrate`, and later inter frames
   burst up to it — 117 KB at +230 ms is exactly that curve.
2. **`vbvInitialDelay` is never set by ffmpeg** (no read of `rc_initial_buffer_occupancy`
   anywhere in `nvenc.c`), so even the buffer *size* fix leaves the initial fullness to the
   driver. That is what the A/B has to establish.

The runtime side already works: the agent's `set_bitrate`
(`encoder.rs:1669-1706`) writes `rc_max_rate` / `rc_buffer_size` on the open context and
ffmpeg's reconfigure path (`nvenc.c:2985-3001`) applies both via `NvEncReconfigureEncoder`
before the next frame — the `if (avctx->rc_buffer_size > 0 && vbvBufferSize != rc_buffer_size)`
branch is unconditional on `cq`. Consequence worth writing down: **from the first AIMD step
(~5 s in) the NVENC VBV is 1× `maxrate`** (`set_bitrate` writes `rc_buffer_size = target`), not
the 2× the HRD comment claims; the ~300 KB mid-session "lumps" FR-10 measured fit that 1×
window at 2.5–3 Mbps. The opening reservoir is the outlier, not the mid-session one.

Why it only *shows* on relays: on a direct carrier the cap is 2–5× higher and refills 2–5×
faster, so the same starvation is over in ~0.3 s.

## Design

**P1 — make the intended reservoir reach the driver before frame 0 (NVENC).** Right after
`build_encoder` returns an opened NVENC context (the constructor funnel at
`encoder.rs:1013-1059`, the `Ok(encoder)` arm), write `rc_buffer_size = open_vbv_bits` on the
context, exactly as `set_bitrate` does; ffmpeg's reconfigure applies it on the first
`send_frame`, before the opening IDR is encoded. `open_vbv_bits = buf × pct / 100`, where `buf`
is the same HRD window `encoder_options` already computes (`maxrate × hrd_pct / 100`; AV1 is
floored at 200 % both ways for the rc.443 reason) — factored into one pure function so the
option dictionary and the post-open write cannot drift.

Knob: env `ROOMLERD_NVENC_OPEN_VBV_PCT` / config-surface key `nvenc_open_vbv_pct`
(new-env ⇒ config-key rule). `0` = kill switch (today's behaviour, byte-identical wire), `100`
= the HRD the code always claimed. Default: ships as `100` (the window the code always claimed); the A/B below decides whether it stays or moves to `40` — a choice made on data, **not** by reasoning —
the trade is real: a fuller opening IDR is a larger first frame, which on a 2.55 Mbps pipe is
transit time before first light (a crisp ~300 KB IDR ≈ 1 s) versus today's instant smear that
takes ~1.2 s to repair. Total bits to crisp are the same either way; what changes is what the
operator sees meanwhile.

**P0 result (2026-08-29, on #897):** `pct=100` was handed to the driver (log field + `nvenc.c`
reinit confirmed) and the opening keyframe stayed at 11–16 KB; `tune=hq` likewise; **`maxrate`
×10 gave a 132–140 KB keyframe and 99–100 % first-light sharpness** — the driver sizes the
opening IDR as ~1.3 frame-slices of `maxrate`, full stop. `maxrate` itself is not shippable
(ffmpeg's reconfigure forces a fresh — starved — IDR on any rate change), so **P1b** adds the
parameter NVENC provides for exactly this ratio, `lowDelayKeyFrameScale` (`ldkfs`), as a second
knob (`nvenc_ldkfs`, default unset) in the rejection-tolerant `lowlat` tier. P1's knob stays,
default 0 (inert). If the driver honours `ldkfs` only under CBR, the remaining path is a
vendored-ffmpeg patch mapping `rc_initial_buffer_occupancy` → `vbvInitialDelay`.

**P0 — the A/B, on this box's own daemon** (self-view over `ROOMLERD_ICE_RELAY_TCP=1`, which
forces both a relay-class ICE path and the constrained profile — `peer.rs:1479`; the mirror
recursion only affects inter-frame dynamics, the opening IDR captures a static screen). Legs:
baseline · `pct=100` · `pct=40` · `tune=hq` (driver-default reservoir under a different
tuning; env `ROOMLERD_FFMPEG_TUNE`, no code). Metrics per leg, N ≥ 5, foreground tab, 100 ms
sampling logged: frame-1 bytes on the wire, TTFF, first-light sharpness as a fraction of the
8 s steady state, time-to-crisp (≥ 90 % of steady state).

**P2 — QSV / AMF: measured, no action.** CORPLAP-3 (`av1_qsv`, relayed, same cap) opens with
a **161 B keyframe** (a black first capture) and lands the whole desktop as a **131 KB inter
frame at +300 ms**, with only ~25 KB of repair over the next 14 frames — ffmpeg maps
`-bufsize` to `BufferSizeInKB` for QSV, so the explicit reservoir is real there and the
picture converges in one frame. That is the behaviour P1 aims to give NVENC. AMF: no host in
the fleet; the same browser hook answers it in ten seconds when one appears.

**Not done, deliberately:** `init_qpI` alone (ffmpeg already sets `enableInitialRCQP=1` with a
default I-QP of 26 — `nvenc.c:967-983` — and the IDR still came out at maximum QP, so the
reservoir, not the starting QP, is the binding constraint); changing `rc=vbr`+`cq` to a
bitrate-targeted mode (rewrites the whole rate model); touching the mid-session 1× VBV
(FR-10/FR-18 were tuned against it as it is).

## Acceptance criteria

Measured with the browser harness (recipe in the handover / `reference_corplap2_checkpoint_lan_capture`),
on the relay stand-in and then on the real pair `neo16 → CORPLAP-2`, N ≥ 5 each, shipped default:

- [ ] the first three frames on the wire carry **≥ 250 KB combined** at the 2.55 Mbps
      constrained cap (today 124 KB, of which the keyframe is 5.6 KB) — the desktop lands
      inside the reservoir instead of dribbling in as repairs
- [ ] first-light sharpness **≥ 80 %** of the 8 s steady-state value (today 47 %)
- [ ] time-to-crisp (≥ 90 % of steady state) **not worse than today's 1.2 s**
- [ ] TTFF p50 **not worse than today + 400 ms**; the number is reported either way
- [ ] a 60 s drag on the same session: `send_wait` p99 and `viewer_age` max not regressed
      against the FR-18 numbers (the opening reservoir must not become a mid-session lump)
- [ ] `ROOMLERD_NVENC_OPEN_VBV_PCT=0` restores today's wire byte-for-byte (frame 1 ≈ 5.6 KB)
- [ ] no change on a DIRECT session's `send_wait` (the knob applies to every NVENC open; a
      direct session's larger cap makes the reservoir larger still)

## Open decisions

- **Default `pct`** — 100 vs 40, from the A/B. If neither improves first-light sharpness
  (initial fullness still driver-bound), the fallback is the `tune` leg's result.
- Whether `set_bitrate`'s 1× mid-session VBV should follow `hrd_pct` too. Not in this FR.

## Out of scope

- The carrier. CORPLAP-2 is relayed because a corporate VPN captures its LAN prefix; routing
  around that is VPN policy evasion (operator's standing rule). Surfacing the capture in
  `roomler status` / the RC pill is its own FR.
- The relay ceiling (`relay_max_bps`, the measured-rate program) — a faster relay would
  shrink every number here but is a different lever.
- The viewer's FSR pass, the idle-refine machine, and `dc_unopen_drops` — all measured, none
  causal.

## Field log

| date | build | note |
|---|---|---|
| 2026-08-29 | agent 0.4.15/0.4.17 (CORPLAP-2), web `v20260829-40e8fc071129` | P0: the table above; 5/5 runs; sharpening on/off identical; `dc_unopen_drops` uncorrelated. ffmpeg n8.1 `nvenc.c` read: `cq` zeroes the VBV after `-bufsize` is mapped; `vbvInitialDelay` never set; reconfigure honours `rc_buffer_size`. |
| 2026-08-29 | agent 0.4.17 (CORPLAP-3, `av1_qsv`, relayed) | P2: frame 1 = 161 B key, frame 2 = 131 581 B inter at +300 ms, ~25 KB over the next 14 frames — converges in one frame; QSV needs nothing. |
| 2026-08-29 | branch build (neo16 self-view, `ROOMLERD_ICE_RELAY_TCP=1`) | P0 A/B: kill switch = baseline (13–16 KB); `pct=100` 11.4 KB ×3; `tune=hq` 11.8–14.2 KB; `maxrate` ×10 → 132–140 KB, first light 99–100 %. P1 refuted; `ldkfs` next. |
| 2026-08-29 | branch build + `ldkfs=8` (option line confirms `… delay=0 ldkfs=8` accepted) | frame 1 = 17.2 · 15.3 KB — inert under `rc=vbr`+`cq` (documented for single-frame VBV **and CBR**). `maxrate` ×3 → 34.7 KB: the slope is linear. Remaining levers on #897: the relay ceiling (a different FR), a vendored-ffmpeg `vbvInitialDelay` patch (uncertain), or accept the physics. |
