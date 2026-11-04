# FR-74 — Text clarity on direct paths: the bitrate ceiling follows the content, not a constant

**Issue:** [#1442](https://github.com/gjovanov/roomler-ai/issues/1442) · **Status:** P0 done 2026-09-06;
P1 (0.4.77) + P1b (0.4.79) + P3 (0.4.80) released and **field-verified 2026-09-07 on all four
codecs** by the operator's read and the heartbeat; P2 retired by measurement (0 rate swaps);
AC3 ticked; the thin-direct-path read of the q-cap done 2026-09-07 (sharp but laggy below the
cap's ~10 Mbps floor — an open decision, §P3); AC1 ticked (pixel half: faithful on 4:4:4, not on 4:2:0 — measured); P4 built and field-verified 2026-09-08;
**P5's gate read 2026-09-25** on the FR-79 V3b shadow (agents 0.4.99–0.4.102, four hosts, 104,698
heartbeats in 37 sessions): the relay half holds and V3b-2 is confirmed in the field, the direct half
is content-bound before the first burst and the refined law's floor guard erodes on every push-back —
**P5 stays unbuilt** (§"The gate, read 2026-09-25"); P6 docs written the same day ·
**Parent:** the RC quality program (FR-17/16/14); rides on FR-59's measured pipe and FR-70's
pump instrumentation.

## Goal

Scrolling text over a direct, low-latency path is readable while it moves and crisp
within a second of stopping. The operator's own test that opened this FR: Notepad++
on CORPLAP-3 (av1_qsv, 1920×1200, direct, 4 ms RTT), scrolling through a day's
daemon log — "very blurred text (unreadable), 5–8 s to stabilize, and even when it
stabilizes the text is not crystal clear."

## Field evidence (2026-09-06, the operator's session `6a9db913`, 19:03 UTC)

Everything below is read from the pump's own heartbeat and the session's log lines;
nothing is inferred from source alone.

1. **The direct ceiling is a constant, and Sharper cannot exceed it.**
   `rate_profile::ffmpeg_maxrate_bps_scaled` derives the ceiling as
   `SCREEN_BPP_PER_SECOND (0.07) × width × height × fps`, clamped to [3, 12] Mbps:
   1920×1200 at 60 fps gives **9,676,800 bps**, and the session's `ceiling_bps` says
   exactly that. The Priority dial scales it 70 / 85 / 100 % (Smoother / Balanced /
   Sharper), so Sharper is the ceiling itself. The libvpx VP9-444 pump encodes the
   same content at **0.20 bpp** (24 Mbps at this geometry) — `encode::policy`'s own
   header names the divergence.

2. **Every scroll burst is read as congestion by a controller reacting to its own cap.**
   The encoder runs constant quality (ICQ `global_quality=22`) under `maxrate` = the
   AIMD target. Scrolling text at 60 fps overruns any 6–10 Mbps cap (the rate
   control raises QP: the blur while it moves), the send queue exceeds the direct
   budget (150 ms of the target = 181 KB — `direct byte-budget gate engaged
   inflight=272218 budget=181440` at 19:03:55), the gate skips frames
   (`frames_skipped_backpressure` 0 → 10 over the session), and the AIMD's
   occupancy signal fires: **three ×0.85 cuts in six seconds**, 9.68 → 8.23 → 6.99 →
   5.94 Mbps (19:03:56–19:04:02). The additive climb is target/16 per 5 s settle
   (+605 kbps): **~40 s back to the ceiling** (6.55 M at 19:04:06 … 9.68 M at
   19:04:44). A second scroll at 19:04:14 cut it to 6.08 M again, a third at
   19:06:12 to 8.23 M. The sent rate during a scroll window was 2–4.8 Mbps; at
   rest ~430 kbps. The path itself never showed congestion: viewer age 3–6 ms, no
   goodput estimate below the target.

3. **Each rate change on QSV is a rebuild with a forced IDR.** `coarsen_bitrate`
   snaps the target to the ladder (4.5 / 6 / 8 / 12 Mbps here), and every crossing
   rebuilds the encoder (`background-rebuilt encoder adopted (bitrate swap)`,
   `forced_idr=1`): **37 bitrate swaps and 35 idle-settle keyframes in 11
   minutes** — an IDR every ~9 s, each restarting quality from a keyframe encoded
   under the cap. That is the "5–8 s to stabilize": the picture pumps with the
   ladder.

4. **At native resolution nothing sharpens the still picture.** The P8a idle refine
   is gated on `capped_below_native` (`refine_eligible_now` in the pump), so at
   native the settled frame is whatever the last keyframe and its P-frames encoded
   at ICQ 22 on the VDENC (`low_power=1`) AV1 path, 4:2:0 — and 4:2:0 halves the
   chroma that ClearType text lives on. `cq_bias` is 0 at native (the sharpening
   bias exists for deep rungs only).

5. **Not yet measured**: the viewer's pixel chain. The pill reports the encode
   dims (1920×1200) and `FSR`, not the display scale; if the stage is not 1:1 with
   the frame, the browser's resample softens text no matter what the encoder does
   (rc.191's "Match remote display" exists for exactly that).

## Key design

The thesis: on a direct path the network is rarely the limiter for screen content,
and a controller that caps at a bits-per-pixel constant, then reacts to its own cap
as if it were congestion, produces exactly the symptom above. The remedy is the
same one every other lever in this program has taken: **measure, then follow** —
the ceiling follows the measured pipe and the content's demand; the queue budget is
denominated in the measured pipe; the still picture gets one sharp frame when
motion stops. No new controller, no new kill switch beyond the phase gate.

### P0 — A/B with the knobs that exist (no code)

On CORPLAP-3, the operator judging the same Notepad++ scroll, each cell first
reproducing the FAIL on the current settings, then one change at a time:

| cell | knob | from → to | what it isolates |
|---|---|---|---|
| A | `direct_queue_ms` (config) | 150 → 600 | the gate/AIMD reaction to a burst the wire drains |
| B | `MESHHARBORD_FFMPEG_MAXRATE_KBPS` (env) | 9677 → 24000 | the ceiling (the VP9 pump's bpp at this geometry) |
| C | `MESHHARBORD_FFMPEG_CQ` (env) | 22 → 16 | the still-text quality floor |

Read from the heartbeat: `target_bps` trajectory through a scroll, `frames_skipped`,
`swaps`, keyframes; from the operator: readable while moving, settle time, still
sharpness. A cell that helps names the phase; a cell that does not retires a guess.

**Results (2026-09-06, the operator judging every cell on the same file).**

- **Baseline #2 (FAIL first)**, the operator's session `6a9dc448` at 19:51 UTC on
  0.4.76: one scroll took the target 9.68 → 8.23 → 6.99 → 5.05 → 3.65 → 3.10 →
  2.24 Mbps in 16 s (six ×0.85 cuts) while the gate skipped 49 frames, and it
  never recovered — 2.1–3.7 Mbps for minutes, every +605 kbps climb undone by the
  next small burst. The direct queue budget is 150 ms of the **applied** target,
  so at 2.5 Mbps it is ~47 KB and one text frame trips it: a self-reinforcing
  trap. The "stabilized but not crystal clear" picture was 1920×1200 AV1 at
  ~2.5 Mbps.
- **Cell A** (`direct_queue_ms` 600, restart 20:08): the trap is gone — one cut
  on the scroll (9.68 → 8.23), back at the ceiling in 28 s, 28 skipped frames
  instead of 81, 9 `set_bitrate` instead of 57, **0 rate swaps instead of 37**.
  Operator: still blurred while scrolling, especially the line-number gutter.
- **Cell B** (A + cap 24 Mbps, restart 20:15): a 40 s scroll at 24 Mbps with 0
  cuts, 0 skips, no gate, 12–25 Mbps sent, 25–40 fps. Operator: clear at first,
  blurred after 4–5 s of continuous scrolling (the cap's 2× VBV drains, then QP
  climbs to hold the cap), clears ~1 s after stopping (the idle-settle keyframe;
  was 3 s), and the second stop within 5 s stays blurred (the settle-keyframe
  gate's `SETTLE_KF_MIN_GAP`).
- **Cell B2** (A + cap 40 Mbps, restart 20:34), all four codecs tried: **"could
  not reproduce it with AV1, VP9 4:2:0 and H.264 — only with VP9 4:4:4 is it
  still happening."** The heartbeats agree — AV1 7 scroll windows, 0 cuts, 0
  skips, 15.6 Mbps, 31 fps; vp9_qsv 0 cuts, 15.7 Mbps, 26 fps; h264_qsv 0 cuts,
  23 Mbps, 32 fps; two more AV1 sessions at 22 Mbps, 32–43 fps, one 55 Mbps
  burst window absorbed with no cut.
- **What it decided.** On the FFmpeg hardware pump the ceiling and its budget
  were the whole scrolling problem: P1 is the build, cell C is not needed for
  the scroll. VP9 4:4:4 is the libvpx software pump and neither knob reaches it:
  it captured ~7–19 real frames per second at 1920×1200 4:4:4 (CPU-bound) while
  repeat-encoding 30 per second at `cpu_used=6` against a 20.7 Mbps target, so
  each real full-screen text delta got a 30-fps slot's bits — `avg_qp` 108 → 184
  of 255 in the scroll, 5 at rest. That is P3's item, with its own mechanism.
- Left live on CORPLAP-3 until P1 ships: `direct_queue_ms = 600` (config) and
  the machine environment `MESHHARBORD_FFMPEG_MAXRATE_KBPS=40000`. Revert:
  `roomler config clear direct_queue_ms`, remove the variable, restart.

### P1 — a content-following ceiling on direct paths

When the path is direct and the controller has no congestion evidence of its own
(viewer age flat, no measured goodput below the target — FR-59's `measured_pipe_bps`
and FR-70 M0's split are the instruments), the ceiling lifts toward the measured
pipe instead of the bpp constant, bounded by a sane maximum; the direct queue
budget is denominated in the measured pipe (FR-59 P2's `constrained_queue_measured`
shape, today constrained-only), so a burst the wire drains is not read as
congestion. A path that does show congestion keeps today's behaviour byte for byte
— the AIMD's cut and climb are the right response there.

### P1 — as built (2026-09-06)

Two changes, both on the direct branch of the FFmpeg pump, relay paths untouched
byte for byte, no new switch:

1. **The direct ceiling is a content-generous bound.** `ffmpeg_maxrate_bps_scaled`
   uses 0.25 bpp/s on direct paths (34.6 Mbps at 1920×1200 @ 60), clamped to
   [3, 48] Mbps per codec factor (H.264's ×1.5 lands at 51.8 Mbps; a 4K panel at
   the 48 M top; small rungs stay on the 3 M floor). The constrained branch keeps
   0.07 / [3, 12] and the relay clamp, so every relay session sees exactly what it
   saw. The cap stays a ceiling, never a target: constant-quality rate control
   spends what the content demands and the AIMD follows the pipe below the cap on
   evidence (viewer age, the byte-budget gate).
2. **The direct send-queue budget is denominated in the path's ceiling.**
   `direct_queue_ms` (still 150 by default) is resolved against
   `last_ceiling_bps` instead of the AIMD's applied target. The applied-target
   reference was the self-reinforcing trap P0 measured: at 2.5 Mbps the budget
   was ~47 KB, one text frame tripped the gate, and every climb was cut again.
   A burst the wire drains now passes; a real backlog still trips the gate and
   the AIMD still cuts on that evidence.

Way back: `FFMPEG_MAXRATE_KBPS` (env) and `direct_queue_ms` (config) are the
operator's overrides in both directions, as before. What P1 does not do: it does
not measure the pipe on a direct path (there is no goodput estimate on an
uncongested link); the "follow" half of the design is the AIMD's existing
response to real congestion under a bound that no longer binds on screen
content. Whether a measured direct pipe should also lower the bound (a thin
Wi-Fi) is the open decision left to the field read.

**Field gate.** The P0 knobs on CORPLAP-3 are cleared before the release carrying
this rolls there, so the release's defaults are what is tested: the operator's
Notepad++ scroll on AV1, VP9 4:2:0 and H.264 stays readable while it moves
(AC1), the heartbeat shows no cuts and no gate skips through the scroll windows,
and the relay hosts' counters are unchanged (AC3).

### P1b — the gate judges the measured wait (2026-09-07)

The 0.4.77 gate read (session `6a9e5b03`, CORPLAP-3, av1_qsv 1920×1200 direct,
the release's defaults, P0 knobs cleared) showed both halves of P1 working —
ceiling 34.56 Mbps, scroll windows at 20–36 Mbps and 30–47 fps, viewer age
≤ 20 ms throughout — and one residual: the 150 ms budget (648 KB at that
ceiling) still tripped on the AV1 scroll burst. AV1's HRD window is floored at
200 % of maxrate (8.6 MB) because Intel's VDENC hangs on a forced IDR larger
than its reservoir (the rc.443 incident), so the encoder was *configured* to
burst far past a budget the controller then read as congestion: gate ×1, 54
skipped frames (~8 % of the scroll), two ×0.85 cuts 34.56 → 26.8 Mbps and
~10 s of additive climb back — while the wire drained every byte at ≤ 20 ms of
age. A controller cutting on a burst it had itself legalised.

P1b makes the direct gate the **measured wait's** call:

- **Measure.** The send task already records enqueue→wire-complete per frame
  (`send_wait_us_*`, the P7 telemetry). The pump now keeps an EMA (α = 0.3 per
  pass) of the per-pass average of those waits and — new — the *live age of the
  frame the send task is writing* (`send_head_enqueued_us`): a stalled pipe
  completes nothing, so a completion-based estimate reads stale-low exactly
  when the queue is growing. The gate's wait is the larger of the two.
- **Rule** (`rate_profile::direct_gate_trips`): bytes over the P1 budget gate
  only when the measured wait has also crossed `direct_queue_ms`; bytes alone
  gate at the hard ceiling `max(budget, reservoir)`, where the reservoir is the
  encoder's own HRD window in bytes (`direct_queue_hard_budget_bytes`, with the
  codec's effective `open_hrd_pct` — AV1's 200 % floor included). A LAN scroll
  (1.2 MB in flight at 20 ms) passes; the same bytes at 150 ms on a thin wire
  trip, the AIMD cuts on that evidence as before. Relay paths are untouched
  byte for byte; `0` still disables the gate; no new switch — `direct_queue_ms`
  keeps its meaning, which was always the lag bound.

What it deletes: the byte count as a *proxy* for lag on direct paths. What it
does not do: a standing lag the viewer feels stays the viewer age's call
(FR-15) — this gate bounds the sender-side queue only. The first-time gate log
line now carries `hard_budget` and `measured_wait_ms`, so a field read can tell
which arm tripped.

**Field gate.** The same Notepad++ scroll on the release's defaults: the
heartbeat's scroll windows show `gate: 0`, no `frames_skipped` growth and no
cuts, and the "direct byte-budget gate engaged" line is absent from the session.
### P2 — fewer keyframes on QSV

Hysteresis at the top of the bitrate ladder, so a target hovering near a rung
boundary does not cross it every few seconds; each crossing is a rebuild and an
IDR. Coarser rungs above 8 Mbps where the bits/quality slope is flat. Measured by
`swaps` and keyframes per minute in a scroll session.

### P3 — the libvpx pump: cap the worst quality on direct paths (2026-09-07)

**What the field showed after P1b.** With AV1, VP9 4:2:0 and H.264 clean by the
operator's read, VP9 4:4:4 still blurred on the same scroll. Its heartbeat (1 s
windows, session `6a9e8145`) had this shape: 30 encodes/s in motion, 15/s at idle
(the 60 ms keepalive re-encodes the same frame at ~6 kbps), and in the scroll
windows **8–13 Mbps spent of the 20.7 Mbps CBR target at avg q 113–192 / max
255** — under budget and at the worst quality at the same time. A steady short
scroll at the end converged to q 14–23 at 10 Mbps. So the hypothesis that opened
this phase (a 30-fps budget spread over ~10 real captures) did not fit: the
encoder was not out of bits, it was choosing not to spend them.

**Measured offline, not argued** — an ignored test in `encode/libvpx.rs`
(`fr74_p3_offline_scroll_rate_control`) feeds the real encoder a synthetic
1920×1200 text page: 20 warm frames, 3 s of idle keepalive duplicates (or none),
a 90-frame steady scroll at 24 px/frame, a stop, and a **wheel pattern** (a 54 px
notch, then four repeat frames at the keepalive cadence, ×12). Per-frame q and
bytes, per arm. (WSL: build the harness with
`cargo rustc -p meshharbord --lib --profile test --features ffmpeg-encoder,vp9-444 -- -A warnings`
and run the deps binary — a plain `cargo test` under `vp9-444` alone crashes
rustc's diagnostic renderer on a governor dead-code warning, not on the test.)

| round | arm | steady scroll | wheel notches | reading |
|---|---|---|---|---|
| 1 | as shipped (CBR, cpu-used 6, idle dups fed) | first frame **q 255**, then −7/frame to 0 by ~frame 40; 17.3 Mbps | — | a scene change resets q to the worst and libvpx walks it back over ~1 s |
| 1 | no idle duplicates | identical | — | the keepalive duplicates are innocent (the rate-factor theory refuted) |
| 1 | VBR / CQ modes | q 16 → **255 and pinned**, 2 Mbps | — | one-pass VBR/CQ go into "debt" and stay there — unusable here |
| 1 | cpu-used 5 / target ×2 | identical descent | — | neither speed nor budget enters into it |
| 2 | as shipped | — | **every notch q 255**, mean 231, **4 Mbps** | the field reproduced: worst quality at a fifth of the budget |
| 2 | content tune default / overshoot 100 / cyclic refresh | — | 255/193 alternating · no change · no change | no knob on the rate control fixes it |
| 2 | `rc_max_quantizer` 40 / 32 | descends from the cap | notches AT the cap (q-index 160 / 128) | the cap is the one lever that bounds the damage |
| 3 | constant quality (`VPX_Q`) cq 12–32 | q ≤ 48–128 by construction, **~9 Mbps** | ~8 Mbps | sharp, cheap — but no refine to lossless at idle, no rate bound at all |
| 4 | **CBR + `rc_max_quantizer` 16 / 20 / 24** | cap → 42 → 39 → 33 → … → **0 within ~1 s**, 14.0–14.7 Mbps | **all notches at 64 / 80 / 96**, 7.2–7.5 Mbps | notches readable, refine to lossless kept, the target still an average bound |

**Mechanism.** libvpx's one-pass CBR with the screen-content tune treats each
wheel notch (54 px = most pixels change) as a scene change: `high_source_sad` →
`calc_active_worst_quality_one_pass_cbr` returns `worst_quality` and the ambient
q is reset to it, after which q can only fall as fast as the ambient average
moves (~7 q-index per frame). A steady scroll gets there in a second; a wheel
scroll restarts the walk at every notch and is rendered at q 255 throughout —
while the encoder sits far below its target, because the reset is not a budget
decision at all.

**Built.** `Vp9Encoder::set_max_quantizer` (a runtime `vpx_codec_enc_config_set`,
no IDR) and `vp9_direct_max_q_from_env` (default **16** = q-index 64, env
`MESHHARBORD_VP9_DIRECT_MAX_Q`, clamp 0–63, **63 = the pre-P3 behaviour** — the way
back). The pump applies the cap on a DIRECT transport at encoder open and
re-applies it on every transport flip (uncapped again on a relay, where the rate
cap is what matters). Nothing else changes: CBR, the target, the AIMD, the idle
keepalive, the settle keyframe, `cpu_used` — all as before. 16 rather than 20 or
24 because the three cost the same bytes on the synthetic scroll and 16 is the
sharpest; `avg_qp` / `max_qp` in the heartbeat are the instrument.

**Field gate.** The operator's Notepad++ wheel scroll on CORPLAP-3 with VP9
4:4:4: readable while it moves; the heartbeat's scroll windows show `max_qp` ≤ 64
with the bitrate inside the target (the pre-P3 shape was max 255 at 8–13 Mbps of
20.7); settled text still refines to q 0.


**Thin direct path — measured (2026-09-07 20:08 UTC, field log).** The P1b/P3
expectation ("on a thinner direct path the DC buffered-bytes gate sheds frames
rather than sharpness") is refuted for a pipe throttled below the socket: with
`meshharbord.exe` egress capped at 15 Mbps by a Windows QoS policy (two viewers,
~7.5 Mbps each) the cap held q at ≤ 64 and the encoder kept emitting 10–19 Mbps
— the cap's floor for a full-screen 4:4:4 text scroll — while the AIMD cut the
target to 4.6–5.1 Mbps to no effect, the gate shed nothing (the queue lived in
the OS pacer, invisible to the DC's buffered amount), and the viewer ran
160–380 ms behind. A thin Wi-Fi queues in the driver the same way. So on a pipe
thinner than the cap's floor the trade is **sharp but laggy**, and the open
decision is whether the cap should yield when the AIMD is pinned below that
floor with viewer age high (a measured-pipe relaxation) or whether 200–400 ms at
full sharpness is the right answer for a mode chosen for text. Recorded, not
built: no controller is added on this evidence alone.
### P4 — the viewer's pixel chain

Show the display scale beside the encode dims in the pill (`shown at 0.9×`), verify
the 1:1 case, and point at "Match remote display" when the stage and the frame
disagree. FSR helps only when upscaling.

**As built (2026-09-08).** The last resample in the chain is the browser's, after
the codec, and no encoder setting can undo it — AC1's pixel comparison had to switch
the stage to a 1:1 canvas before it meant anything, because in `Adaptive` the
operator's 1920×1200 frame lands on a 2018×1261 FSR canvas (a 1345×841 CSS stage at
150 % display scaling): every remote pixel spread over 1.05 screen pixels. `Original`
is worse there, not better — it is 1:1 in **CSS** pixels, i.e. 1.5× on screen.

- `displayScale()` (`ui/src/composables/useRemoteControl.ts`, pure, unit-tested) computes
  screen pixels per frame pixel the way the FSR sizing policy computes its fit factor
  (`computeRenderTarget`): the `object-fit: contain` factor in `Adaptive`, the element's
  own CSS box in `Original`/`Custom`, × `devicePixelRatio`.
- A new pill after the resolution one — `1:1 pixels` (within 0.1 %) or `shown at 1.05×` —
  with the explanation and the way to 1:1 in its tooltip: `Custom zoom 100/dpr %`
  (66.7 % at 150 %; the custom zoom now keeps one decimal so that value is reachable) or
  "Match remote display so the host renders at your window's W×H". The same text is the
  hint under Display → *Fit in my window* while connected. Its own metrics checkbox,
  default on; older stored toggle sets read it as on (per-key fallback, tested).
- The stage's CSS box is fed by the existing Fit-mode `ResizeObserver` (measured on every
  resize, whatever the resolution mode), so window drags and browser zoom re-evaluate it
  without a second observer; the 1 s worker stats tick re-evaluates the rest.

Nothing about the encoder or the transport changes. The pill is the verification
"Match remote display" never had: the button asks the host to switch modes, and until
now nothing on screen said whether the frame that came back actually matched the window.

## Phases

| phase | scope | kill switch | status |
|---|---|---|---|
| P0 | A/B with existing knobs on CORPLAP-3 | — (settings only) | **done 2026-09-06** — A + B2 remove the blur on AV1, VP9 4:2:0 and H.264 by the operator's read; the queue budget denominated in the applied target was a self-reinforcing trap, the cap the limiter; VP9 4:4:4 (software) remains |
| P1 | direct ceiling 0.25 bpp / [3, 48] M; direct queue budget denominated in the ceiling | — (no switch: `FFMPEG_MAXRATE_KBPS` and `direct_queue_ms` are the way back) | **built 2026-09-06** (§"P1 — as built"); field gate on the release carrying it |
| P1b | the direct gate is the measured send wait's call below the encoder's HRD reservoir (EMA of completed waits ∨ live head-of-queue age); bytes alone gate only at the reservoir | — (no switch; `direct_queue_ms` keeps its meaning as the lag bound, `0` disables) | **field-verified 2026-09-07 on 0.4.79** — operator: "not seeing the blurring anymore" on AV1, VP9 4:2:0 and H.264; heartbeats of those sessions: 0 cuts, 0 gate skips, 0 gate lines. VP9 4:4:4 (the libvpx pump) still blurs ⇒ P3 |
| P2 | ladder hysteresis on QSV | — (pure policy, measured by `swaps`) | **retired by measurement 2026-09-07** — after P1 the rate ladder no longer fires on direct paths: 0 rate swaps in all 17 sessions on the three hosts today (QSV direct on CORPLAP-1/-3, nvenc relay on CORPLAP-2; the 2026-09-06 baseline had 37 in 11 min). Reopen only if a relay-path QSV session shows swaps |
| P3 | the libvpx pump: `rc_max_quantizer` 16 on DIRECT transports (63 on relay) — libvpx's scene-change reset to the worst quality on every wheel notch was the 4:4:4 blur, measured offline in four rounds (§P3) | `MESHHARBORD_VP9_DIRECT_MAX_Q` (63 = pre-P3) | **built 2026-09-07, released in 0.4.80** — offline: every notch frame at q 64 instead of 255, refine to lossless kept; field gate: **instrument PASS 13:25 UTC** (`max_qp` 64 in every scroll window, was 255; settles to q 0; 0 skips) and **operator PASS** ("scrolling large texts seems much better") ⇒ **field-verified 2026-09-07**; thin direct path measured 20:08 UTC — sharp but laggy below the cap's ~10 Mbps floor (§P3), an open decision |
| P4 | viewer display-scale pill + 1:1 guidance: screen pixels per remote pixel, `1:1 pixels` or `shown at 1.05×`, the way to 1:1 in the tooltip and the Display tab (§P4) | — (UI; the pill has its own metrics checkbox) | **built 2026-09-08 (#1497), field-verified the same morning** on `hosted-20260908-a6257b8`: `shown at 1.05×` in Adaptive = the FSR canvas exactly (2018 ÷ 1920), `1:1 pixels` at Custom zoom 100/dpr % with FSR disengaging on its own; docs `docs/remote-control.md` §18.6.1 |
| P5 | **the direct ceiling FOLLOWS the measured path** — `clamp(believed × HEADROOM, legibility_floor, bpp_bound)`; the bpp product stops being the operating point and becomes a cap (§"P5 — the ceiling follows the path") | — (the belief itself is the way back: with no belief the bound still applies, which is today's behaviour byte for byte) | **decided 2026-09-10, not built.** Gated on FR-79 V3b's belief reading sane in the field first — the shadow ships before the law. **Gate read 2026-09-25** (§"The gate, read 2026-09-25"; 104,698 heartbeats, 37 sessions, four hosts, 0.4.99–0.4.102): the relay half holds; V3b-2 confirmed (19 of 19 push-back-free direct sessions kept their floor); the direct half is content-bound before the first burst by construction; and the refined law's floor guard **erodes** — V3b-2 halves the floor on every push-back regardless of spacing (28.84 → 7.76 M on three, 38.90 → 8.57 M on five) ⇒ **stays unbuilt** until the guard is decided (an undamped demonstrated max beside the damped floor, or time-aware damping — FR-79's `Pipe`), `HEADROOM` and the decay rate are fixed, and a sim replay of the Regal 09-25 arc is read |
| P6 | **docs, in the house style** (the docs-before-close rule, #1401): a design section in `docs/rate-control.md` for P1's direct ceiling and P1b's measured-send-wait gate — today only three changelog rows there, and no mermaid diagram of how the ceiling and the gate compose — joined by P5's path-following ceiling when it is built; linked from `docs/README.md`. P3 (`docs/encoders.md`) and P4 (`docs/remote-control.md` §18.6.1) are documented already | — (docs) | **written 2026-09-25** in the PR carrying this row: `docs/rate-control.md` §"The direct path (FR-74)" — the ceiling chain (P1), the measured-wait gate (P1b), one mermaid of how they compose, the field reads, and P5's status with the gate read; two config rows; the `docs/README.md` row. AC5 ticks on merge |

## Acceptance criteria

- [x] **AC1** — a Notepad++ scroll on CORPLAP-3 stays readable while it moves (no
      unreadable phase), and the settled text matches a local screenshot of the
      same region (pixel comparison of a text block, not an impression).
      *Operator half met on all four codecs 2026-09-07 (0.4.79: AV1, VP9 4:2:0,
      H.264 — "not seeing the blurring anymore"; 0.4.80: VP9 4:4:4 — "scrolling
      large texts seems much better"). Pixel half measured 2026-09-07 (field log): **met on VP9 4:4:4** (mean |Δ| 1.4, 100 % within ±16) and **not met on the 4:2:0 HW path** (AV1 ICQ 22: 13.6 % of a text block's pixels more than 32 off) — a chroma/ICQ property of 4:2:0, not a defect; "crystal clear" is a 4:4:4 property, which FR-77's colour-detail picker now offers on hardware.*
- [ ] **AC2** — sharpness is stable within 1 s of the scroll ending; keyframes per
      minute in a scroll session drop from ~7 to ≤ 2.
      *Measured 2026-09-07 on 0.4.79/0.4.80 (CORPLAP-3, 11 sessions): the ~7/min of
      the baseline were the QSV rate ladder (37 swaps + 35 settle keyframes in
      11 min); rate swaps are now **0** in every session. What remains is the
      idle-settle keyframe, one per scroll stop at ≥ 5 s spacing — 6–12/min in a
      stop-and-go scroll, 0.3/min over a 2-hour session — and it is the mechanism
      that makes the settled text sharp within ~1 s (first half met). The "≤ 2/min"
      figure was a proxy for the ladder pumping and is superseded: the criterion
      that survives is "no keyframes from rate changes", which holds.*
- [x] **AC3** — no regression on constrained hosts: CORPLAP-1/-2's `target_bps`,
      `frames_skipped`, `pipe_states` unchanged across the release (direct-only
      change). *Read 2026-09-07 on 0.4.79 (field log): the relay sessions show
      the relay-clamped targets, a handful of skips per hour and the usual FR-71
      stall mix; no direct gate line can occur there and none did.*
- [ ] **AC4** — every phase carries a before/after from the same instrument (the
      heartbeat's `target_bps`, `frames_skipped`, `swaps`, keyframes) plus the
      operator's read of the same scroll.
- [x] **AC5** — docs in the house style, linked from `docs/README.md` (the
      docs-before-close rule, #1401) — P6. Owed, measured 2026-09-24: P1's direct
      ceiling and P1b's measured-send-wait gate appear in `docs/rate-control.md`
      only as three changelog rows, with no design section and no mermaid diagram
      of how the ceiling and the gate compose; P5 joins them when it is built.
      P3 (`docs/encoders.md`) and P4 (`docs/remote-control.md` §18.6.1) are
      documented already.
      *Written 2026-09-25 in the PR carrying this line: `docs/rate-control.md`
      §"The direct path (FR-74)" (the ceiling chain, the gate, a mermaid of how
      they compose, the field reads, P5's status and its gate read), the
      `direct_queue_ms` / `direct_hrd_pct` / `FFMPEG_MAXRATE_KBPS` /
      `VP9_DIRECT_MAX_Q` config rows, and the `docs/README.md` row — ticked on
      merge, not before.* **Merged 2026-09-25 as `7248975d4` (#1661)** and
      checked on master: the section is at `docs/rate-control.md:270`, the file
      carries 3 mermaid diagrams, and the `docs/README.md` rate-control row names
      it. P5's own docs join the section when P5 is built.

## Open decisions

- ~~Whether the direct ceiling should stay bpp-scaled at all (a higher constant is
  still a constant) or be purely measured — probe-and-follow.~~
  **DECIDED 2026-09-10: probe-and-follow. The constant becomes a BOUND, never
  the operating point.** See §"P5 — the ceiling follows the path" below.
- Whether a 4:4:4 "text" choice is worth offering at all on hosts whose hardware
  encodes 4:2:0 only (software VP9 at a fraction of the frame rate).
- Whether P1's ceiling lift needs the viewer's decode capacity as an input (a 24 Mbps
  AV1 stream on a laptop decoder).

## P5 — the ceiling follows the path (decided 2026-09-10, not yet built)

### The field case that decides it

**Regal-Elena-PZ, 2026-09-10, session `6aa286e4`** — 1920×1080 HEVC over a
DIRECT carrier, paint age 6–11 ms the whole way, reported by the operator as
*"started very blurred and it took maybe over 5s to clear up"*.

Two things were wrong, and only the second is this FR's.

**The opener (~6 s).** The session opened `constrained=true` and was clamped to
the 2,550,000 relay nominal, because the ICE pair nominated the OVERLAY
addresses and the overlay carrier under them was DERP at that instant — a
demote-follow had fired six seconds earlier and the direct probes had just
missed their deadline:

```
10:30:54  overlay: peer is relaying to us over /derp … following it onto DERP (demote-follow)
10:30:59  overlay: direct probe did not handshake within deadline; kept relay
10:31:01  selected pair: 100.65.4.26:50695 <-> 100.65.4.2:51996     ← overlay addresses
10:31:01  overlay carrier under the nominated pair is not direct — treating transport as constrained
10:31:07  constrained=false
```

The clamp is correct *given* the verdict; the verdict was stale by the time
pixels flowed. That belongs to the carrier plane, not here.

**The sawtooth (the rest of the session).** After the flip, the target
oscillated for hours:

| time | target | note |
|---|---|---|
| 10:31:33 | 4,471,680 | climbing |
| 10:33:04 | 34,284,491 | |
| 10:33:34 | **5,281,379** | collapse |
| 10:35:36 | 38,880,000 | ceiling — **4.5 minutes** after session start |
| 10:40:10 | **6,063,469** | collapse again |

`goodput_bps` for that session: **6,028,814**. The collapses land on it almost
exactly. The ceiling resolved to **38,880,000** — a product of constants
(`ffmpeg_maxrate_bps_scaled`: geometry × fps × 0.25 bpp/s, scaled by the codec
and chroma factors and clamped into [3, 48] M × factor) with **no measurement
anywhere in it**. It sat ~6.5× above what the path delivered.

So the additive increase climbs to a constant the path cannot serve, the sends
block, the decrease collapses to the measurement, and it repeats every two to
three minutes. **Every collapse is a visible softening** — the operator's
report is the opening instance of a recurring pattern, not a one-off.

That is this FR's own open decision, in the field: *a higher constant is still
a constant.* P1 raised it from 0.07 to 0.25 bpp/s and that removed the blur on
the hosts P1 was measured on; it could not remove the class, because the number
still owes nothing to the path.

### The decision

**The ceiling FOLLOWS the measured path. The bpp product becomes a safety
bound it may never exceed, not the operating point.**

```
ceiling = clamp(believed × HEADROOM,          // follow
                legibility_floor,             // FR-59 P1's relief
                bpp_bound)                    // today's constant, now a CAP
```

- `believed` is `encode::pipe::Pipe::believed_bps()` (FR-79 V3b) — the
  demonstrated floor when nothing has pushed back, the pushed-back capacity
  when something has, and never `None` once bytes have arrived.
  *(V3b-1, #1578, `0.4.99`, split that accessor the day after this was
  written: `capacity_bps` answers "am I over?", `ceiling_anchor_bps` =
  `max(capacity, floor)` answers "what may the ceiling be?", and the heartbeat
  prints `pipe_belief=(anchor, floor, capacity)`. The refinement below reads
  the two halves separately, which is why it survives the split.)*
- `HEADROOM` is the probe: enough above the belief to discover growth, not
  enough to flood. The sawtooth's amplitude becomes the headroom (tens of
  percent) instead of 650 %.
- `bpp_bound` still protects the decoder and the TURN path — a laptop decoder
  is a real limit (see the third open decision) and a constant is the right
  shape for a bound. It is simply not the right shape for a target.

⚠️ **Why the belief's FLOOR half is load-bearing here.** A ceiling that
followed the blocked-send goodput alone would have pinned this session at
6,028,814 — pessimistic on a path that had demonstrably delivered far more, and
the mirror of the current defect. Following `believed` (which takes the MAX of
capacity and demonstrated delivery) cannot make that mistake.

⚠️ **Probing is not optional.** With no probe the ceiling can only ever ratchet
down: the encoder never offers more than the ceiling, so the path never
demonstrates more, so the belief never rises. The headroom IS the probe, and it
must survive a quiet stretch — which is why the belief's floor is a max over a
window rather than an average.

### ⚠️⚠️ Refined 2026-09-15 — the first formulation had a regression mode

`ceiling = clamp(anchor × HEADROOM, legibility_floor, bpp_bound)` is wrong, and
the shadow's own data says why. Two failures, both worse than the constant:

**1. An idle session starves its first burst.** A session that opens onto a
still screen has a content-driven floor and no push-back at all — the shadow
measured exactly this, CORPLAP-3 reading **12.8 kbps** with `n=(10696, 0)`
against a 34,560,000 target. Anchoring on that clamps the ceiling to the
legibility floor (~3.75 M for HEVC), and the first scroll is then starved on a
path that carries 34 M. The symptom this FR exists to remove, caused by its own
remedy.

**2. The ratchet-down trap.** If the ceiling follows the anchor, the encoder
never offers more than the ceiling, so the path never demonstrates more, so the
anchor never rises. The ceiling can only fall. Forever.

**The asymmetry is the whole design, and it maps onto FR-79 V3b-1's two
accessors exactly:**

| evidence | may it LOWER the ceiling? | may it RAISE it? |
|---|---|---|
| a push-back (`capacity`) — the path refused | **yes** | yes |
| a delivery (`floor`) — the path carried | **never** | yes |

A content-driven floor is evidence the path carried at least X. It is never
evidence the path is *limited to* X, and no amount of idle delivery makes it so.
Only a refusal limits.

```rust
// `cap_limit` exists only once something has actually pushed back.
let cap_limit = capacity_trace.map(|c| c * HEADROOM / 100);
let ceiling = match cap_limit {
    // Never below what the path has demonstrably carried: the floor is the
    // guard against one pessimistic blocked-send sample.
    Some(limit) => bpp_bound.min(limit.max(floor)),
    // Nothing ever refused us ⇒ today's behaviour, byte for byte.
    None => bpp_bound,
};
```

⚠️ **The probe is the capacity trace DECAYING UPWARD.** With the rule above and
nothing else, a path that recovers is never rediscovered — the ceiling holds at
the old limit and the encoder cannot prove otherwise. So the trace must relax
toward `bpp_bound` while nothing pushes back: absence of refusal is weak
evidence the path is fine, and weak evidence is exactly what a slow drift
encodes. Sustained push-back holds it down; quiet lets it climb; a new push-back
pulls it down again — a closed loop with no ratchet in either direction.

⚠️ This is the same shape as FR-70 P1's prior, which already decays toward its
band while nothing measures. Reuse that law rather than inventing a third.

### Sequencing — and why P5 is NOT built in the same breath

FR-79 V3b ships the belief in **shadow** first: computed, reported in both pump
heartbeats as `pipe_belief=(believed, floor, capacity)`, read by nothing. P5
flips the ceiling onto it only once the field says the belief is sane —
specifically that on a direct session `believed` tracks what the path carries
rather than the content, and that on the relay hosts it stops being `None`.

Shipping a new ceiling law on an unvalidated estimate would be the same mistake
twice in two days: FR-79 V5 shipped a rule whose input (`blocked_send_bps`) was
silent on the hosts that needed it, and the fleet had to tell us.

### The gate, read 2026-09-25 — P5 stays unbuilt

**Method.** The hosts' own daemon log files (`service-logs\roomlerd.log.<date>`,
`KEEP_DAYS = 14`) read over Fleet RPC — not `roomler logs`, whose 64 KiB tail
a finished session ages out of. Every heartbeat carrying `pipe_belief=` was
parsed on the host (one regex per pump) and aggregated per session there, so
the wire carried summaries and the windows with a live capacity, never the
logs. The population is the exec-enabled hosts only — the three corp laptops
and the Regal cell — and nobody else's sessions are in it.

| host | files | heartbeats | sessions | agent |
|---|---|---|---|---|
| CORPLAP-3 | 7 (09-11 → 09-25) | 9,765 | 9, all direct (`av1_qsv` 1920×1200) | 0.4.98 on 09-11/09-12 (the pre-V3b-2 control), 0.4.99 → 0.4.101 after |
| CORPLAP-1 | 4 (09-22 → 09-25) | 26 | 3 short direct (`hevc_qsv`) | 0.4.99 → 0.4.102 |
| CORPLAP-2 | 5 (09-11 → 09-25) | 5,274 | 5: 3 short direct (`av1_nvenc`), **2 relay** (5,240 constrained windows) | 0.4.99 → 0.4.102 |
| the Regal cell | 3 (09-23 → 09-25) | 89,633 | 20, all direct (`hevc_qsv` 1920×1080), nine of them 2–8 h long | 0.4.99 → 0.4.102 |

**What the shadow said, against the two conditions above.**

1. **Relay hosts — the anchor is not `None`: holds.** Both relay sessions
   carried a floor within their first five windows (1.7–1.9 M at 10 s) and an
   anchor of 3.5–5.2 M for the rest — `pipe_belief_n` 9,912 / 1 over three
   hours and 155 / 0 over three minutes. One host produced every relay
   session on file (CORPLAP-1 and CORPLAP-3 ran direct in all of theirs).
2. **Direct — "tracks the path, not the content" splits three ways.**
   - *A quiet screen must not read as a thin pipe:* **holds since 0.4.99.**
     On the current law the floor never fell without a push-back: **19 of 19
     push-back-free direct sessions ended at their maximum floor**, and each
     of the 7 sessions whose floor ended below its maximum carried at least
     one push-back. CORPLAP-3 (09-25, `6ab64e41`) held 34.27 M through 3.5 min
     of idle after one scroll (249 deliveries). The 0.4.98 control on the same
     host (09-11, `6aa3d669`): 16.4 M → **13.5 kbps** over 4.3 h with zero
     push-backs — the defect V3b-2 fixed, still visible in the older file.
   - *Before the first burst the anchor is the content's weight — by
     construction.* The Regal sessions open at 0.07–2.4 M and take 2–3,960
     windows (4 s to 2.2 h) to reach half their eventual floor; a 4.6-min
     CORPLAP-3 session (09-24) never rose above 3.5 M on a path that carries
     34 M, because its content peaked at 6 Mbps. Nothing measures capacity on
     an uncongested direct path, so this half of the condition is not
     meetable as written. The 2026-09-15 refinement already makes it
     harmless (a delivery never lowers the ceiling), which turns the gate's
     direct condition into the two rows below.
   - *Are the push-backs real refusals?* On the LAN-class hosts the only
     capacities are the encoder's burst drain **at the cap**: 34.3 M against a
     34.56 M ceiling (CORPLAP-3), 45.6–59.7 M against 43.2 M (CORPLAP-1),
     27.5 M against 34.56 M (CORPLAP-2). Not refusals; under the refined law
     `limit ≥ bound` and the ceiling is untouched. On the Regal cell — the
     case that decided P5 — **14 accepted push-backs in ~51 h of sessions,
     0.85–19.9 M**, with send waits up to 1.36 s in the windows around them
     (two ≥ 1 s hard stalls), and at every one the AIMD target had already
     collapsed from the 38.88 M constant to **1.5–17.0 M (median 3.9 M)**.
     That is today's sawtooth, at one accepted fold per ~3.6 h rather than the
     2–3 min period of 09-10 (collapses without an accepted fold are not
     counted here — the pass that would count them did not run: the host went
     offline for the night between the two sweeps).

   | session (UTC) | when | target at the fold | capacity | floor before → after | anchor then |
   |---|---|---|---|---|---|
   | `6ab3a699` 09-23 | 11:00:04 | 6.24 M | 7.34 M | 28.84 → 18.09 M | 18.09 M |
   | | 12:51:38 | 4.72 M | 5.56 M | 18.09 → 11.82 M | 11.82 M |
   | | 16:32:26 | 3.14 M | 3.69 M | 11.82 → 7.76 M | 7.76 M |
   | `6ab41f5b` 09-23 | 19:17:27 | 16.96 M | 19.95 M | 22.34 → 21.14 M | 21.14 M |
   | | 20:50:45 | 8.63 M | 10.16 M | 30.25 → 20.21 M | 20.21 M |
   | | 20:50:47 | 8.63 M | 11.14 M | 20.21 → 15.67 M | 15.67 M |
   | `6ab447ac` 09-23 | 23:55:53 | 1.50 M | 0.85 M | 23.03 → 11.94 M | 11.94 M |
   | `6ab4d959` 09-24 | 10:24:53 | 14.32 M | 16.85 M | 38.35 → 27.60 M | 27.60 M |
   | `6ab60a69` 09-25 | 05:50:13 | 1.50 M | 1.53 M | 11.74 → 6.64 M | 6.64 M |
   | `6ab62dcb` 09-25 | 11:47:32 | 4.77 M | 5.61 M | 38.90 → 22.26 M | 22.26 M |
   | | 13:03:26 | 2.52 M | 2.96 M | 25.12 → 14.04 M | 14.04 M |
   | | 13:03:28 | 2.52 M | 3.09 M | 14.04 → 8.57 M | 8.57 M |
   | | 13:06:14 | 2.68 M | 3.16 M | 16.40 → 9.78 M | 9.78 M |
   | | 13:21:51 | 2.97 M | 3.50 M | 24.90 → 14.21 M | 14.21 M |

   - *Does the floor guard hold?* **It erodes.** V3b-2 damps the floor by
     half the gap on *every* push-back below it, whatever the spacing: three
     push-backs 5.5 h apart took a 28.84 M demonstration to 7.76 M; five in
     1.6 h took 38.90 M to 8.57 M, the demonstration re-arming to 16–25 M
     between them and being halved again at each. The refinement's "never
     below what the path has demonstrably carried" assumed an undamped
     demonstration. With the damped floor, P5's ceiling on this cell would
     have sat at 8–18 M for hours of sessions whose path also carried
     24–39 M, and — because an encoder under an 8 M ceiling cannot
     demonstrate 25 M — recovery would rest on the upward decay alone, whose
     rate the design leaves open.

**Verdict.** One condition met, one confirmed in the field for the specific
defect it targeted, and the load-bearing one — the guard the refined law
stands on — refuted by the shadow's own arithmetic. **P5 is not built.**
Whether a ceiling at 8–18 M beats the constant with its ~90 % collapses cannot
be read from the belief alone; it needs the viewer's outcome under both laws,
and the 09-23 daytime viewer on the Regal cell reported no paint age at all
(`viewer_age_ms=None` for 6.7 h; the 09-25 sessions do report it, p50 15 ms).

**What unblocks P5, in order.**

1. A decision on the guard: an *undamped* demonstrated maximum kept beside the
   damped floor (a second field on `Pipe`), or a time-aware damping — a
   `Pipe` change, which is FR-79's to make.
2. The two numbers the design leaves open: `HEADROOM`, and the upward-decay
   rate (FR-70 P1's law, reused).
3. A replay of the Regal 09-25 arc (`6ab62dcb`: five refusals, the floors
   above, the 38.88 M constant) in `encode::sim` under both laws — the
   collapse amplitude, the time back to the offered rate — before any release.
4. The release, and an A/B on that cell with a viewer that reports age. The
   cell is exec-reachable, so the same sweep reads the after.

⚠️ **A side finding from the same sweep, not P5's.** CORPLAP-3, 09-25
10:35:58: the *ceiling itself* dropped to 13,824,000 (0.4 ×) at 4 ms of viewer
age and 0 bytes in flight, and was back at 27.8 M eleven seconds later. The
pump's own lines name the cause: `av1_qsv` passes of 120–170 ms (`FFmpeg DC
pump STALL`), the cadence paced 60 → 20 fps, i.e. the **encode-pressure
factor** multiplying the plan's ceiling — a host-side cause with no path in
it. A path-following ceiling must compose with that factor, which is why the
P6 diagram draws the whole chain; and a heartbeat's `target_bps` dropping is
not evidence about the path until `ceiling_bps` on the `set_bitrate` line has
been read.

### Acceptance for P5 (to be written into the criteria when built)

1. On the Regal cell, `target_bps` tracks within the headroom of
   `pipe_belief.believed` instead of oscillating between the measurement and
   the constant; no collapse larger than the headroom.
2. Time-to-usable falls: the 4.5 minutes this session took to first reach its
   ceiling is a ceiling-chasing artefact, and following the belief removes the
   chase.
3. A genuinely fast path is NOT capped at what an idle desktop happened to
   deliver — the probe discovers growth within a bounded number of windows.
4. The bpp bound still binds where it should: a decoder-limited viewer.

## Out of scope

Constrained and relay paths (FR-59 / 62 / 63 own those); the session-start open
(FR-70's AC2 open half); the transport stall classification (FR-71).

## Related

FR-59 (queue budget, measured pipe) · FR-62 / FR-63 (rate control) · FR-70 (media
pipeline, the heartbeat instrument) · FR-71 (transport stalls) · the RC quality
program FR-17 / 16 / 14.

## Field-verification log

| when | build | host | what |
|---|---|---|---|
| 2026-09-06 19:03 UTC | 0.4.75 | CORPLAP-3, av1_qsv 1920×1200, direct, Sharper | The opening evidence (above): ceiling 9.68 Mbps, three ×0.85 cuts per scroll, ~40 s climb, 37 swaps + 35 settle keyframes in 11 min, no idle refine at native. Operator's read: unreadable while scrolling, 5–8 s to settle, not crystal clear after |
| 2026-09-06 19:51 UTC | 0.4.76 | CORPLAP-3, av1_qsv, direct, Sharper, no P0 keys | **Baseline #2 (FAIL first)**: six ×0.85 cuts in 16 s (9.68 → 2.24 Mbps), 49 gate-skipped frames, then 2.1–3.7 Mbps for minutes — the queue budget (150 ms of the applied target, ~47 KB at 2.5 Mbps) tripping on every text frame |
| 2026-09-06 20:10–20:31 UTC | 0.4.76 | CORPLAP-3, av1_qsv, direct | **Cell A** (`direct_queue_ms` 600): one cut, back in 28 s, 0 rate swaps (was 37); operator: still blurred, especially the gutter. **Cell B** (+ cap 24 Mbps): 40 s scroll at 24 Mbps, 0 cuts / 0 skips, 12–25 Mbps, 25–40 fps; operator: clear, then blurred after 4–5 s (the 2× VBV draining), clears ~1 s after stopping, the second stop within 5 s stays blurred (settle-keyframe gap) |
| 2026-09-06 21:25–21:28 UTC | 0.4.76 | CORPLAP-3, direct, all four codecs | **Cell B2** (A + cap 40 Mbps): operator — "could not reproduce it with AV1, VP9 4:2:0 and H.264 — only with VP9 4:4:4". AV1 0 cuts / 0 skips / 15.6–22 Mbps / 31–43 fps (a 55 Mbps burst window absorbed); vp9_qsv 0 cuts / 15.7 Mbps / 26 fps; h264_qsv 0 cuts / 23 Mbps / 32 fps. VP9-444 (libvpx SW) `avg_qp` 108 → 184/255 in the scroll on ~10 real captures/s repeat-encoded at 30, target 20.7 Mbps — its own mechanism (P3) |
| 2026-09-07 06:34–06:40 UTC | **0.4.78** (the auto-updater had rolled it at 06:19; same pump code as 0.4.77) | CORPLAP-3, av1_qsv 1920×1200, direct, defaults (P0 knobs cleared 22:23 UTC the day before) | **P1 gate read**, session `6a9e5b03`: ceiling 34,560,000 confirmed; scroll windows 20–36 Mbps at 30–47 fps, viewer age ≤ 20 ms; **residual** — the 150 ms budget (648 KB) tripped once on the AV1 VBV burst (HRD floored at 200 % = 8.6 MB reservoir): 54 skips (~8 %), two ×0.85 cuts 34.56 → 29.38 → 26.8 Mbps, back within ~10 s; `set_bitrate: 7 swaps: 0 settle-KF: 10 gate: 1`. Operator's read of this session pending. ⇒ P1b |
| 2026-09-07 09:12–09:20 UTC | 0.4.79 | CORPLAP-3, direct, defaults, the operator judging | **P1b gate — PASS on the HW codecs, the 4:4:4 pump is P3.** Operator: "still only with VP9 4:4:4 … it gets blurred. In the other codecs like AV1, VP9 4:2:0 and H.264 I'm not seeing the blurring anymore." Heartbeats: av1_qsv `6a9e8017` (29.4 M opening climb → 34.56 M, 0 skips, 0 gate lines, 29 MB), vp9_qsv `6a9e806b` (43.2 M flat, 0 / 0, 22 MB), h264_qsv `6a9e8087` (44.1 → 50.5 M, 0 / 0, 44 MB). VP9 4:4:4 (libvpx SW) `6a9e8039` + `6a9e8145`: 20.7 M target flat, **8–13 Mbps actually spent in the scroll windows at avg QP 113–192 / max 255**, encodes at 30/s in motion and 15/s at idle (the 60 ms keepalive re-encodes the same frame at ~6 kbps for the whole idle), 1830 encodes for 481 captures; the last short scroll converged to QP 14–23 at 10 Mbps. |
| 2026-09-07 09:30–10:00 UTC | offline (libvpx 1.14, WSL) | the real encoder on a synthetic 1920×1200 text page | **P3 rounds 1–4** (table in §P3): as shipped, every wheel-notch frame is encoded at **q 255** while spending 4 Mbps of 20.7; idle duplicates innocent; VBR/CQ pinned at 255; content tune / overshoot / cyclic refresh / cpu-used / target ×2 change nothing; `rc_max_quantizer` 16 holds every notch at q 64 and keeps the refine to lossless (14.5 Mbps of 20.7 on the steady scroll); constant-quality mode is sharp and cheap (~9 Mbps) but loses the idle refine and the rate bound. ⇒ P3 = the cap. |
| 2026-09-07 09:20–10:44 UTC | 0.4.79 | CORPLAP-1 + CORPLAP-2, every session since the 07:29 restart | **AC3 read.** CORPLAP-2 relay (av1_nvenc, `constrained=true`): a 66-min session at 0 → 7.45 Mbps, 15 backpressure skips, 0 gate lines, `pipe_states` [1, 3761, 1, 53, 0] (1.4 % transit-stalled — the FR-71 gap mix of every previous read); a 7.8-min session 0.2 → 3.0 M, 4 skips; three short ones 0 skips. CORPLAP-1 ran **direct** today (hevc_qsv / vp9_qsv at 43.2 M, 0 skips, 0 gate lines, `pipe_states` all 0). The constrained branch is untouched by P1/P1b/P3 and the counters agree ⇒ AC3 holds. |
| 2026-09-07 10:59–11:04 UTC | 0.4.80 | release | P3 (#1463 → `7b0f7a2a`, bump #1464 → `cc83693f`, 28 assets). CORPLAP-3 pid 7968 (11:01:47), CORPLAP-1 pid 5320 (11:02:30), CORPLAP-2 pid 15416 (11:03:33), each updated while idle. Field gate open: the operator's VP9 4:4:4 wheel scroll on CORPLAP-3. |
| 2026-09-07 13:25 UTC | 0.4.80 | CORPLAP-3, VP9 4:4:4 (libvpx), direct, the operator's scroll | **P3 gate — instrument PASS.** The session opened with `worst-quality cap applied max_q=16`; through the 17 s scroll every 1 s window had **`max_qp` = 64** (0.4.79: max 255, avg 113–192), avg 45–64 while moving, then 4 → 0 within ~2 s of stopping (refine to lossless intact); 0 skips; viewer age ≤ 39 ms. Bitrate 22–52 Mbps in the scroll windows — **above the 20.7 M target**: with q pinned at ≤ 64 the CBR target is a soft bound on content that needs more at that quality; on this direct path it cost nothing, and on a thinner one the DC buffered-bytes gate sheds frames rather than sharpness (the intended trade for a mode chosen for text). Operator's read pending. |
| 2026-09-07 20:06–20:09 UTC | 0.4.82 | CORPLAP-3, VP9 4:4:4, direct, **two viewers** (the operator's tab + the automation tab, `shared ×2`), a Notepad++ copy of the day's log, wheel input by `SendInput` at 15 notches/s (15 s down, 15 s up) from a one-shot task in the interactive session | **Thin direct path, measured.** Control (20:06:58–20:07:29): 30 captures/s, 13–21 Mbps at q 0–2 on the down leg, one ×0.85 cut at the direction change (a 55 Mbps window, q 15/64, +2 skips), up leg 18–35 Mbps at q 0–32, viewer age 19–60 ms. **Throttled** (a Windows QoS policy capping `meshharbord.exe` egress at 15 Mbps — ~7.5 Mbps per viewer; 20:08:26–20:08:57): seven AIMD cuts in 9 s (9.95 → 5.68 M, then 4.6–5.1 M), the encoder still emitting **10–19 Mbps at avg q 56–60 / max 64** — the cap's floor for a full-screen 4:4:4 text scroll is ~10 Mbps and the target below it is inert — **zero new gate skips** (the OS pacer queues below the socket, so the DC buffered-bytes gate never saw a queue) and **viewer age 160–380 ms**. The cost of the cap on a pipe thinner than its floor is lag, not blur. |
| 2026-09-07 21:34 UTC | 0.4.83 | CORPLAP-3, AV1 4:2:0 (av1_qsv, ICQ 22), sole viewer, settled text | **AC1 pixel comparison, HW path.** Host truth = a DPI-aware `CopyFromScreen` PNG from a one-shot task in the interactive session; viewer side = the decoded frame read from the viewer's canvas with the scale mode at `original` (1:1, 1920×1200 — in `adaptive` the canvas is the FSR-upscaled 2018×1261); a 260×160 text block at (100,400), the two captures 6 s apart on a static screen, compared in-page, alignment best at dx=dy=0: **mean \|Δ\| 12.6, 54 % of pixels within ±2, 73 % within ±8, 82 % within ±16, 13.6 % more than 32 off, max 123.** The settled 4:2:0 picture is not pixel-faithful on ClearType text — finding 4, quantified. |
| 2026-09-07 21:42 UTC | 0.4.83 | CORPLAP-3, VP9 4:4:4 (libvpx, settled at q 0), sole viewer, same text block | **AC1 pixel comparison, 4:4:4.** Same method and block: **mean \|Δ\| 1.37, 85 % within ±2, 96.8 % within ±8, 100 % within ±16, max 15, none more than 32 off.** Pixel-faithful up to the BGRA↔YUV 4:4:4 rounding. The two host shots taken 8 min apart differed by mean 5.3 (a caret-line highlight toggling with window focus), so a comparison is only valid when both captures are seconds apart. |
| 2026-09-08 08:27–08:31 UTC | server `hosted-20260908-a6257b8` (0.4.86), agent 0.4.85 | CORPLAP-3, AV1 4:2:0 (av1_qsv), direct, view-only from an automation tab (hidden, display scaling 1.125×, stage 1926×1121 CSS) | **P4 field gate — PASS.** Adaptive: pill `shown at 1.05×`, tooltip "Each remote pixel is spread over 1.05 screen pixels … For 1:1 use Display → Custom zoom 88.9 %, or Match remote display so the host renders at your window's 2167×1261 (your display scaling is 1.125×, so Original is 1.13× on screen)"; the FSR canvas backing was 2018×1261 = 1920 × 1.051, i.e. the pill and the sharpening pass computed the same factor. The Display tab's hint under *Fit in my window* carried the same text. Custom zoom 88.9 % (stored preference, reload, reconnect): pill `1:1 pixels`, tooltip "Pixel-exact", the canvas backing 1920×1200 at 1706.88 CSS px (= 1920 ÷ 1.125) and **FSR disengaged on its own** (the codec pill lost its `· FSR`), which is the sizing policy's own 1:1 verdict agreeing with the pill's. The stored metrics set predated the pill (`{codec,bitrate,fps,resolution,age,paint}`) and the pill still showed — the per-key fallback in the field. |
| 2026-09-25 (logs of 09-11 → 09-25) | agents 0.4.99 → 0.4.102 (V3b shadow; 0.4.98 on CORPLAP-3's 09-11/09-12 files as the control) | CORPLAP-1 / -2 / -3 and the Regal cell — every `pipe_belief=` heartbeat in their daemon log files over Fleet RPC, parsed and aggregated on the host | **P5's gate read — P5 stays unbuilt** (§"The gate, read 2026-09-25"). 104,698 heartbeats in 37 sessions (35 direct, 2 relay). Relay: the anchor is non-`None` from the first 10 s (`pipe_belief_n` 9,912 / 1 over 3 h) — holds. Direct: V3b-2 confirmed — 19 of 19 push-back-free sessions kept their maximum floor, every floor loss coincides with a push-back, CORPLAP-3 held 34.27 M through 3.5 min of idle, while the 0.4.98 control shows 16.4 M → 13.5 kbps over 4.3 h; before the first burst the anchor is the content's weight by construction (openings at 0.07–2.4 M, 4 s to 2.2 h to half the eventual floor); the LAN hosts' only capacities are the burst drain at the cap (34.3 / 45.6–59.7 / 27.5 M against 34.56 / 43.2 / 34.56 M ceilings); the Regal cell's 14 accepted push-backs (0.85–19.9 M, send waits to 1.36 s) each found the target already collapsed to 1.5–17.0 M (median 3.9 M) from 38.88 M; and the refined law's floor guard erodes under V3b-2's per-sample damping (28.84 → 7.76 M on three push-backs 5.5 h apart; 38.90 → 8.57 M on five in 1.6 h). Side finding: CORPLAP-3 10:35:58 the ceiling itself fell to 13.82 M (0.4 ×) under the encode-pressure factor (120–170 ms `av1_qsv` passes, cadence 60 → 20 fps) at 4 ms of viewer age — host-side, recovered in 11 s. Bias: exec-enabled hosts only; the Regal cell went offline before the collapse-count pass, so collapses without an accepted fold are uncounted there. |
