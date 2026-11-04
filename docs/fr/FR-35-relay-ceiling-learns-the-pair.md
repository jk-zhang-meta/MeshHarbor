# FR-35: The constrained ceiling learns the pair — grow the relay cap on delivery evidence, remember it per peer

Status: **P1 + P2 + P2b shipped (0.4.21 / 0.4.23); P3 (opener growth, opener grace, held NVENC increases) + P3b (grace-until-drained, measured growth, stable==0 write-back) + P3c (stuck detector so a hot seed cannot freeze the opener, + applied_bps self-correction) shipped 0.4.27 → 0.4.30 (#986/#988/#996/#1001/#1004). Field: IDR pulses gone; opener sharp from frame 1 with a healthy seed; no spurious freeze on a fast path (maxGap <130 ms at the 8 M ceiling). REMAINING: the stuck detector needs a path that cannot carry the seed to exercise — handed to the operator as a neo16→overlay A/B (100.65.4.2 reseeded to the 7 M froze-value).** (2026-08-30). Tracking issue: `FR-35` (#922).
Child of the RC-quality program. Follows FR-31 (every opening and repair number on an NVENC relay
session is proportional to `maxrate`, and nothing ffmpeg exposes changes that) and the parked
measured-rate line (#678: a sender cannot see capacity it is not using). Operator's directive
2026-08-29: the relay ceiling first; a vendored-ffmpeg patch only if this fails.

## What is in force today

- `relay_max_bps()` = **3 Mbps** (`agents/meshharbord/src/encode/mod.rs:464`, env `RELAY_MAX_KBPS`),
  applied as the encoder's `maxrate` cap on every constrained session
  (`encoder.rs` ↔ `rate_profile::ffmpeg_maxrate_bps_scaled`, `peer.rs:3134`), opened at 85 % =
  **2.55 Mbps**, and as the AIMD's ceiling (`governor.rs:254-273`); the send-queue budget derives
  from the same constant (`peer.rs:4639`).
- The AIMD (`encode/aimd.rs`) climbs additively (+ceiling/16 ≥ 150 kbps per 5 s of quiet) but
  **never above that ceiling**; it decreases ×0.85 on a full send channel, on a send-wait stall
  (#818) and on viewer-age excess (FR-15 P2). The governor's measured-ceiling clamp (stage 1) is
  **direct-only** and only ever lowers.

## The measurement (P0, 2026-08-29, the REAL pair `neo16 → CORPLAP-2`, DERP relay)

`ROOMLERD_FFMPEG_MAXRATE_KBPS=25500` on CORPLAP-2 (machine env + scheduled restart), viewer on neo16
with the FR-31 harness, one 20 s synthetic drag; CORPLAP-2's own heartbeats read afterwards.

| what | today (cap 2.55 Mbps) | cap 25.5 Mbps |
|---|---|---|
| opening | 5.6 KB max-QP keyframe, desktop repaired by inter frames over ~1.2 s | 83 B keyframe (black first capture) + **the whole desktop as one 680 KB frame at +0.3 s**, 1.06 MB in the first three frames |
| delivered rate during the drag | ≤ 2.55 Mbps | **3.3–10.6 Mbps per second**, no inter-message gap > 136 ms |
| agent `goodput` (stage-0 estimator, which never fired at 2.55 Mbps) | `None` | **3.6 → 5.8 → 7.5 → 10.9 Mbps** as the AIMD climbed 9.6 → 11.2 → 12.8 Mbps |
| `send_wait` | ~0.05 ms | ~0.05 ms up to ~11 Mbps; **one 7.9 s stall at 12.8 Mbps** (viewer age 6 986 ms, +556 backpressure skips) → AIMD cut to 4.1 Mbps; a second session opened at 18.8 Mbps and stalled 310 ms at once |

Reading: this path **sustains ~6–9 Mbps**, absorbs short bursts far above that, and chokes above
~12 Mbps. The nominal 3 Mbps is 2–3× too low for it; the 10× value that makes the opening keyframe
crisp is not sustainable. Other corp relays in the same fleet measured ~2 Mbps (CORPLAP-1, CORPLAP-3,
2026-08). **A constant cannot be right for both — the cap must be learned per pair, and it may only
ever climb during a session** (FR-31: any NVENC rate change *down* forces a starved keyframe that
replaces the picture).

## Design

**P1 — growth above the nominal, gated by the signals that predicted the stall.** The constrained
AIMD ceiling becomes `clamp(nominal, hi)` with `hi = relay_max_hi_kbps` (default **8 000**;
`0` = nominal only = today). Above the nominal the additive increase additionally requires, over
the trailing 10 s: no send-wait stall (`send_stalls` unchanged), `send_wait_max` < 20 ms, and —
when the viewer reports age — age ≤ 1.5 × the learned floor. Steps stay +ceiling/16 (≥ 150 kbps)
per 5 s settle. Decreases are unchanged, plus one new rule from the measurement: a send wait
> 1 s is a **hard stall** and cuts to ×0.5 rather than ×0.85 (the 7.9 s stall was answered by
three ×0.85 steps over 4 s). All of it lives in the pure controller/governor (`aimd.rs`,
`governor.rs`, `rate_profile.rs`) — unit-testable on this box; no wire change.

**P2 — rate memory per peer.** The highest target that held ≥ 10 s with no decrease is the
session's *stable rate*. On session end the agent persists `{peer overlay ip → stable_bps, at}`
(`rate_memory.toml` in the data dir; entries expire after 7 days), and the next session on that
pair **opens at 0.85 × stable, clamped `[nominal, hi]`** — so the opening keyframe and the repair
speed scale with what the pair proved, not with a fleet constant. A pair never seen opens at the
nominal (today). Nothing here ever lowers the nominal.

Kill switches: `relay_ceiling_learn` (tribool, default on; off = today's fixed ceiling and no
memory) and `relay_max_hi_kbps` (config-surface + env). Direct sessions are untouched.

**Not done, deliberately:** raising the nominal 3 Mbps (the ~2 Mbps relays are real); an active
startup bandwidth probe (measures burst capacity, which this measurement shows is *not* the
sustainable rate — 18 Mbps instantaneous vs ~8 sustained — and costs bytes on exactly the thin
links); the goodput estimator as the learning input (its down-fast EWMA crashed on relay
lumpiness, governor.rs:246-252 — the AIMD's own stable target is the robust signal).

## Acceptance criteria

Measured with the FR-31 harness on `neo16 → CORPLAP-2`, N ≥ 5 sessions after ≥ 1 learning session,
shipped defaults:

- [ ] opening keyframe ≥ 2.5× today's bytes (≥ 14 KB at 1920×1200, today 5.6 KB) and first-light
      sharpness ≥ 70 % of the 8 s steady state (today 47 %)
- [ ] time-to-crisp ≤ 0.6 s (today 1.2 s)
- [ ] a 60 s drag: no send wait > 1 s, viewer-age p99 not worse than the FR-18 numbers, and the
      ceiling never above `hi`
- [x] a ~2 Mbps relay (CORPLAP-3, `av1_qsv`): `target_bps` never exceeds the nominal unless every growth
      gate passed — read from its heartbeats; the session must not get worse than today
      (0.4.21, 2026-08-29: no learner steps, `learned_ceiling_bps=0`, target ≤ 3.0 Mbps, 65–78 ms)
- [x] the learned rate survives a daemon restart and expires after 7 days (unit-tested; the file is
      `…systemprofileAppDataRoamingoomleroomlerdataate_memory.json` for the SYSTEM service)
- [ ] `relay_ceiling_learn=false` restores today's numbers byte-for-byte

## Open decisions

- **Growth speed — DECIDED 2026-08-30 (P3).** Sessions in the field last seconds and are mostly idle, so
  drag-evidence growth never reaches the crisp opener; and the FR-31 verdict forbids a boost-then-step-down
  (the step-down IDR replaces the crisp picture). P3 therefore grows the memory from evidence every session
  has for free: **the opening burst is a burst probe** — `bytes` sent and `max_send_wait` seen while the
  opener drains — and a session that saw no decrease records `max(stable, growth_target)`
  (`rate_memory::opener_growth_target_bps` + `record_session`). **P3b (#996)** shaped the target from the
  0.4.28 field runs: a burst that **queued** (`max_send_wait ≥ 100 ms`) measured the pipe, target =
  75 % × `bytes / max_send_wait` (a 451 KB opener that waited 802 ms says 4.5 Mbps ⇒ 3.38 M); a burst that
  **never queued** (a 238 KB opener with a 0 ms wait — it fit SCTP's send buffer) proves only "not slower
  than this", so the target is a bounded **×1.5 step on the opener's own maxrate** (the next, larger opener
  then queues and measures) — the first implementation read it as 95 Mbps and wrote the memory straight
  to `hi`. Both are capped at `hi`; a 2 Mbps pipe stays at the nominal; a decrease still lowers. The grace
  holds until the send ledger is EMPTY (≥ 2 s, ≤ 6 s): a fixed 2 s ended while a 451 KB tail was still
  draining and the AIMD took the decrease the grace exists to prevent.
  Two companions, both found on the seeded field run: an **opener grace** (soft send-wait stalls and
  backpressure skips inside the first 2 s are the opener draining, not congestion — they had cut a 5.95 Mbps
  session ×0.85 within 1.8 s) and **held NVENC increases on a constrained session** (an in-place
  reconfigure is a starved IDR; the AIMD's climb back produced one visible pulse per 5-s step — increases
  now flush through the existing spaced quiet arm, coalesced; decreases land at once and anchor the spacing).

- `hi` default: 8 000 kbps from this one pair; the second corp pair (CORPLAP-3) will say whether the
  gates keep it at the nominal there. Revisit with two pairs of data.
- Whether the learned rate should also seed the queue budget (`constrained_queue_budget_bytes`
  is derived from the nominal today). Probably yes, in P2.

## Out of scope

The carrier (FR-33 surfaces the capture); the ffmpeg-side keyframe budget (FR-31, refuted
levers); the direct path's measured clamp.

## Field log

| date | build | note |
|---|---|---|
| 2026-08-29 | agent 0.4.18 (CORPLAP-2), env `FFMPEG_MAXRATE_KBPS=25500`, web `v20260829-40e8fc071129` | P0: the table above. Two daemon restarts on CORPLAP-2 (apply, restore) via a scheduled task; env cleared afterwards. |
| 2026-08-29 | agent 0.4.21 (CORPLAP-2 `av1_nvenc`, CORPLAP-3 `av1_qsv`), web `v20260829-0da90b766dc0` | **First field run.** P1 steps logged and gated on CORPLAP-2: `3.0 → 3.19 → 3.39 Mbps` (marquee), `3.0 → 3.19 → 3.39 → 3.60` (window drag, carried 2.1–2.8 Mbps at 66–80 ms); ≈3 steps per minute of sustained drag. P2 seeds: next session opened at `maxrate = 0.85 × remembered` (3.386 → 2.879, 3.598 → 3.059). Opening keyframe on the seeded sessions: 8.0 / 8.4 / 22.9 / 19.5 KB vs 5.7–6.4 KB baseline — but two later seeded sessions at 2.6 Mbps opened at 5.9 KB, so the opener also tracks screen content and the criterion is not yet met. **Defect**: a 14-s idle session wrote its own seed back as the "stable rate" (3.598 → 3.059) — the memory decays 15 % per idle session; fixed in P2b (`record_session`: a lower value needs a decrease). Age gate 1.5× vetoed the evidence windows (66–80 ms over a 43 ms floor) → 2×. CORPLAP-3 negative control clean. |
| 2026-08-30 08:19–08:21 UTC | agent 0.4.26 (CORPLAP-2 `av1_nvenc`, DERP relay), web `v20260830-6a166a1ec9f7` | **Seeded-opener A/B, same screen a minute apart** (memory hand-seeded at 7 Mbps from P0). Baseline 3.0 Mbps: a ~0 KB black keyframe, the desktop as ONE 221 KB inter frame at +176 ms, first painted sample already at steady sharpness, one keyframe in 12 s. Seeded 5.95 Mbps: 30 KB keyframe (50 % sharpness) → 172 KB P → first light 200 ms earlier, 90 % of steady within ~190 ms — but a **×0.85 decrease inside 1.8 s** (`send_wait_max 367 ms`, 73 backpressure skips — the opener draining) and then **three AIMD climb-back steps at 5-s spacing, each an in-place NVENC reconfigure = a starved IDR** (166 KB at +0.3 s, 222 KB at +5.3 s; sharpness dipped to 91 % at +5.4 s). Also measured: the opener burst drained at ≈ 8 Mbps — the P0 number, now free. ⚠️ Windows PowerShell's `Set-Content -Encoding UTF8` writes a BOM that serde rejects (the memory read as EMPTY until rewritten BOM-free). |
