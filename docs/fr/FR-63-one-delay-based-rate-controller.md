# FR-63 — One delay-based rate controller for remote desktop

**Issue:** [#1243](https://github.com/gjovanov/roomler-ai/issues/1243) · **Status:** in progress — B-opener shipped (default OFF); **B0 simulator shipped**, AC0b answered in simulation and still open in the field · **Plan:** `rate-control-architecture` (approved 2026-09-02)

**Parent/siblings:** FR-59 (the regression that motivated the arc). This is one of three FRs from that plan (FR-62 encoder apply path, FR-63 the controller, FR-64 the data path).

## Goal

Replace eight estimators of one quantity — occupancy AIMD, blocked-send goodput, the FR-35 learner and rate memory, FR-59's floor relief / arrival clamp / drain / seed contradiction / remembered-rate opener, the FR-15 age loop — composed with "the lower of" rules in `RateGovernor::pre_encode_tick` (`agents/meshharbord/src/encode/governor.rs:482`) and `tick_viewer_window` (:708), with **one** pure, delay-based controller that runs in **shadow** for a release before it drives anything, and is verified against a deterministic simulator replaying recorded field traces rather than against the fleet.

## Key design

- `encode::ratectl::Controller` (pure, explicit `Instant`): a GCC-shaped state machine (over-use / hold / under-use) on the viewer's delay trend, loss, and blocked sends; decreases to `0.85 × measured`, **holds while the age level is elevated** (not the growth derivative — the lesson FR-59 paid for twice), bounded pauses on constrained paths only, **never on direct**; slow-start then additive increase; the remembered rate as a 10-s soft cap; `fps == 0` windows are no evidence.
- `RateDomain { floor, ceiling }` as the single source of pins (a second 1.5 M pin cannot exist as a constant), `PathClass` and the remembered rate as priors; `QualityRung { fps_cap, long_edge }` executed only at settles.
- Viewer feedback v2 (`rc:decodestat`, all optional): `frames_lost`, `frames_rx`, `delay_slope_ms_s` (from the per-frame pairs `rc-hop-stats.ts` already holds), `age_p95_ms`.
- **B0** `encode/sim.rs` (test-only): `PipeSim` (token bucket, stalls, loss, RTT), `EncoderSim`, `ViewerSim` producing decodestat-shaped windows; a CSV trace-replay format extracted from `agent_logs` by session; four fixtures (airport hotspot, CORPLAP-1 DERP, LAN Wi-Fi burst, fast pair misremembered slow) with settling-time / steady-state / no-standing-queue assertions.
- **B1** shadow beside the governor at the live positions, heartbeat fields `shadow_target_bps / shadow_state / shadow_measured_bps / shadow_disagree_pct / shadow_pauses / shadow_reason`; `scripts/rc-shadow-report.py` over a week of `agent_logs`. Flip criterion: ≥ 20 constrained + 20 direct sessions, shadow ≤ live in ≥ 90 % of elevated-age windows, all fixtures green.
- **B2** `ratectl = shadow|live|off`; **B3** retire the switches in batches on the registry table and delete `aimd.rs`, `ceiling_learn.rs`, `LinkLoop`/`AgeLoop`, the P1/P3/P4/P6 arms.

## Phases and status

| Phase | What | Kill switch | Status |
|---|---|---|---|
| **B-opener** | Slow-start for the session opener — `encode::slow_start` (pure law) + the governor cap on the opening ceiling **and floor** | `rate_slow_start` (default **OFF**) | shipped **inert** in 0.4.55 (#1262, #1265 capped only the ceiling, which `set_ceiling` raised back to the flat 1.5 M floor); fixed in 0.4.56 (#1275) and **field-verified engaging** — AC0a done, AC0b open |
| B0 | `encode/sim.rs` — pipe/encoder/viewer simulator + the four scenario fixtures, driving the SHIPPED laws | n/a (test-only) | **shipped** — 11 tests in `cargo test -p meshharbord --lib` on the default build. CSV trace replay deferred (see below) |
| B1 | `ratectl` shadow beside the governor, `shadow_*` heartbeat fields | `ratectl = shadow` (default) | not started |
| B2 | Flip to `live` on the flip criterion | `ratectl = shadow\|live\|off` | not started |
| B3 | Retire the eight estimators and their switches | `ratectl = off` for one release | not started |

**B-opener** was not in the original plan; it was added because the field
evidence on #1243 showed the opener over-driving from *both* directions on
the same host in one day — the remembered `6_134_627` (6287 ms of paint) and
the nominal `2_550_000` into a path measured at `213_180` (1550 ms, six
windows to recover). Both are commitments made before any evidence exists,
which the full controller would also have to solve; shipping the opener first
is cheap, is independently testable, and only ever *removes* an unevidenced
commitment — a proven floor (FR-59 P8's remembered-slow-pair open) still wins.

### The constrained cell (why this was blocked, and now is not)

`constrained` is measured from the nominated ICE pair
(`detect_constrained_transport`, `peer.rs:1487`), so the constrained posture
exists only on a path that actually relays. Field-measured 2026-09-03:
CORPLAP-1 on 0.4.55 took a **direct** pair (`tgt=12096000`, `c=false`, paint
age 11-42 ms), so slow-start could not engage and the A/B could not run —
the arc's constrained measurements had all been opportunistic, taken whenever
one laptop's corporate VPN happened to be up.

`ice_relay_tcp` (a config key since #1271; `ROOMLERD_ICE_RELAY_TCP` before
that) pins ICE to a real TURN relay, which is what virtual-desktop mode
already used. Both arms of an A/B then run on **one host, one build, one
encoder, minutes apart**, differing in exactly one flag. It is a test pin and
must be cleared afterwards.

### The cell must be able to FAIL, not merely be constrained

Field-measured 2026-09-03, and the reason AC0b is still open. With
`ice_relay_tcp` alone the cell was genuinely constrained — `host=0 srflx=0
prflx=0 relay=4 relay_tcp=true`, `c=true` in every heartbeat, and the relays
were the **public coturn** (`relay_addr_is_fast_local` was never in play, so
`local_turn` is not the lever) — and arm A still could not be made to fail:

```
13:09:32 tgt=2550000 c=true age=Some(37)      <- the field constant, opening
13:09:36 tgt=2737500 c=true age=Some(30)      <- the AIMD CLIMBS
...      tgt=3000000                          <- reaches the cap and stays
```

Flat age, no queue growth, no coarsening, no skips. A 2.55 Mbps opener into a
relay carrying ~3 Mbps is not an over-drive; the original field case needed a
~213 kbps pipe.

🔑 **An arm that cannot fail is not a baseline.** A constrained *posture* is
necessary and nowhere near sufficient — the pipe has to be thin enough that
the opening commitment is actually wrong.

`relay_max_kbps` (a config key since #1276; default 3000) is `bitrate_cap` on
a constrained path. Raising it to `12000` against the same real coturn gives a
genuine ~4× over-drive, because a 1920×1200 pair resolves ~12 Mbps: the pipe,
the encoder and the relay are all real, and the only thing changed is **what
the encoder believes it may use** — which is exactly the mistake this phase
exists to stop. Clear both pins when the measurement is done.

## B0 — what shipped, and what it found

`encode::sim` (test-only, zero shipped bytes) is a deterministic token-bucket
link, the bounded send channel the AIMD actually observes, a CBR encoder and a
viewer folding arrivals into `decodestat`-shaped windows. It drives
**`SlowStart` and `AimdController` themselves**, in the order `governor.rs`
calls them, so a fixture binds production code rather than a copy of it.

⚠️ **A simulator result is evidence about the LAW, not about the fleet.** It can
show that a rate law over-drives a 213 kbps token bucket; it cannot show that a
corporate VPN behaves like a token bucket. Criteria that say "field-verified"
below still mean field-verified.

Four of the eleven tests assert the **model**, not the product — that the pipe
delivers at its rate and no faster, that an idle bucket does not bank capacity,
that a stall carries nothing, and that a link with headroom grows no queue. A
fixture is only evidence if the harness under it is right, and two of the three
bugs found while building this were in the harness:

- 🔑 **Backpressure has to reach the law or the law is being tested blind.** The
  first version refused byte-full offers inside the link while reporting
  fullness only from the frame-depth limit. On a thin pipe three big frames fill
  a 32 KB buffer before four frames fill the channel, so **every frame was
  dropped and the AIMD was never told**: it sat at its opening 2.55 Mbps for the
  whole 40 s run with not one decrease. That looked exactly like a damning
  result about the AIMD and was entirely an artefact.
- **Sampling the target at window close hides the opener.** A session that opens
  at 2.55 Mbps and is cut by the first decrease reports 1.84 Mbps for window 0 —
  concealing the very commitment this phase exists to remove. Rows now carry the
  window's peak.

## The AC0b A/B — answered in simulation, still open in the field

The blocker was never the flag, it was the **cell**: no reachable host produces a
pipe thin enough for arm A to fail, and three were tried. B0's
`corp_vpn_thin_pipe` fixture replays the recorded 2026-09-02 case — a 213 180 bps
link, a 2 550 000 ceiling, the flat 1 500 000 floor — with the two arms differing
in `rate_slow_start` alone, on one build, deterministically.

| | arm A (`false`) | arm B (`true`) |
|---|---|---|
| peak target committed | 2 550 000 | 1 500 000 |
| over-drive integral (bits above 1.1× pipe) | 19 582 316 | 4 054 846 |
| peak p95 paint age | **10 016 ms** | **1 226 ms** |
| backpressure skips | 453 | 157 |
| windows to settle within 25 % of the pipe | 17 | 7 |

Arm A **can** fail here, which is the property the field cell lacked: it delivers
*nothing* for ten windows. The ordering survives a keyframe-sensitivity re-run at
3×, so it is not an artefact of the modelled IDR size.

⚠️ **The table above was taken under B0's original every-window measurement
rule, which is not the governor's.** Re-taken under the shipped rule on
2026-09-04 (see "B0 re-run under the SHIPPED measurement rule" below) the
commitment and over-drive columns hold, the paint-age column does not: arm B
peaks at 5.9 s, not 1.2 s. Quote the re-run's table, not this one.

⚠️ **This does not tick AC0b.** A model of a corporate VPN is not a corporate
VPN. The box stays open until the same A/B runs on a real thin path; what the
simulation buys is that the law is now known to be right, so the field run is a
confirmation rather than a search.

🔑 **Two findings the field would not have shown, both about the shipped law:**

1. **Most of arm A's harm is the opening KEYFRAME, not the steady rate.** At the
   plan's 25× multiplier a 2.55 Mbps opener emits a ~265 KB IDR, which is ten
   seconds of a 213 kbps pipe — and because nothing arrives, the FR-59 P1 floor
   relief has no measurement, so the floor stays pinned at 1.5 M and the AIMD
   *cannot* descend. The opener's bitrate and the opener's keyframe budget are
   one problem; FR-31's `max_frame_size` is the other half of this phase.
2. **The ramp protects roughly one window on a pipe thinner than `OPEN_BPS`.**
   300 kbps into 213 kbps is still an over-drive, so window 0 congests,
   `on_congestion` ends the ramp permanently, and the flat 1.5 M floor
   immediately re-pins the opener — arm B's peak target is 1.5 M, not 300 k. It
   still wins by a wide margin, but the mechanism is "a smaller opening
   commitment and one clean window", not "a gentle ramp". A ramp that halved
   instead of ending, or a floor that stayed down while the ramp ran, is the
   next lever.

## Acceptance criteria

- [x] AC0a — **the ramp engages and opens where it says.** Field-verified 2026-09-03 on 0.4.56, CORPLAP-1: `FR-63 slow-start armed open_bps=300000 ceiling_bps=2550000`, against an arm-A opener of `2_550_000` on the same host and build — an 8.5× smaller opening commitment. `slf=Some(600000)` on the first window with `gp=None` proves the **floor descent** did it, since the P1 relief cannot fire without a measurement; on 0.4.55, which capped only the ceiling, the opener was pinned at the flat 1.5 M and the ramp was inert.
- [ ] AC0b — **the ramp removes the harm.** **Answered in simulation, still open in the field** — see
      "The AC0b A/B" below for the numbers, the two findings and why this does not tick the box.
- [x] AC1 — All four fixtures green in `cargo test -p meshharbord --lib` on the default build.
      Shipped with seven more: four asserting the simulator itself, the AC0b A/B, and the
      keyframe-sensitivity check. 11 tests, ~10 ms.
- [ ] AC2 — One release of shadow logs across the fleet meets the flip criterion, report attached.
- [ ] AC3 — Field A/B (`scripts/rc-ab.sh`) on CORPLAP-1 (QSV, corp VPN) and CORPLAP-2 (real relay): paint age p90 ≤ 0.4.50's and no window with a standing queue while the encoder tracks (FR-62).
- [ ] AC4 — FR-59 AC4 (< 600 ms sustained on the airport-class link) closes here.
- [ ] AC5 — The eight replaced estimators and their six switches are deleted; `ratectl = off` restores the prior behaviour for one release.

## The ramp-exit rule — measured, not argued

B0 raised it: on a pipe thinner than `slow_start::OPEN_BPS` the opening window
congests, `SlowStart::on_congestion` ends the ramp permanently, and the flat
`area_min_bitrate_bps` floor re-pins the opener — so the ramp protects roughly
one window. `encode::sim::RampExit` models two candidates beside the shipped
rule. ⚠️ **Only `EndsOnCongestion` is shipped**; the other two exist in the
simulator so a candidate can be measured before anyone argues for it.

On the recorded 213 kbps cell (`cargo test -p meshharbord --lib ramp_exit_report --
--ignored --nocapture`):

| exit rule | peak target | over-drive bits | skips | settles | windows > 500 ms |
|---|---|---|---|---|---|
| `EndsOnCongestion` (shipped) | 1 500 000 | 4 054 846 | 157 | w7 | 4 |
| `HalveAndContinue` | 300 000 | **65 502** | 39 | **w1** | 1 |
| `HoldFloorUntilMeasured` | 348 500 | 376 280 | 64 | w3 | 1 |

`HalveAndContinue` cuts the over-drive **62×** and settles six windows sooner.
`HoldFloorUntilMeasured` is close behind and is arguably the more principled
fix, because it targets the actual mechanism — a flat constant re-pinning the
session while there is still no evidence — rather than the ramp. They are not
mutually exclusive.

⚠️ **Peak paint age barely moves** (1226 → 1213 ms). All three open at the same
rate, so they share the same opening keyframe, and that is what the peak
measures. This is the same finding as above from a second direction: the
opener's keyframe budget (FR-31) is a separate lever, and no rate rule will
touch it.

🔑 **The honest gap, as first recorded: I could not build a cell where a
candidate COSTS anything.** Three healthy cells (a 20 Mbps pair, a 5 Mbps LAN
with motion bursts, and a fast pipe deliberately stalled at 2 s while the ramp
was still climbing) returned *byte-identical* numbers for all three rules. That
was not agreement between the rules — it was the exit rule never binding,
because under B0's original measurement rule the FR-59 P1 floor relief tracked
the delivered rate every window and the floor never snapped back to the
constant. **The re-run below, under the shipped rule, closes that gap**: the
LAN-burst cell now discriminates, and a candidate does cost rate there.

## B0 re-run under the SHIPPED measurement rule (2026-09-04, after FR-70 P1)

FR-70 P1 found that B0's measurement rule was not the governor's. B0 fed the
floor relief the window's delivered rate **every window** (`MeasureRule::
EveryWindow`); the shipped governor measures the pipe only on **push-back** —
blocked sends (the goodput estimator) or two windows of viewer-reported queue
growth (the FR-59 P3 link loop) — and its FR-59 P2 byte budget skips frames
before a queue can form. On a remembered pair that difference held a real
session at 200 kbps for four minutes while `EveryWindow` would have freed it in
one window (FR-70 #1330). So every number above was re-taken under the shipped
rule (`MeasureRule::OnPushBack`), with the byte-budget gate and a rebuild-bound
encoder modelled (`cargo test -p meshharbord --lib shipped_rule_report -- --ignored
--nocapture`).

**AC0b, the 213 kbps cell, both rules side by side:**

| | arm A, `EveryWindow` | arm B, `EveryWindow` | arm A, **shipped rule** | arm B, **shipped rule** |
|---|---|---|---|---|
| peak target committed | 2 550 000 | 1 500 000 | 2 550 000 | 1 500 000 |
| over-drive integral (bits above 1.1× pipe) | 19 582 316 | 4 054 846 | 27 533 122 | 8 600 680 |
| peak p95 paint age | 10 016 ms | **1 226 ms** | 10 016 ms | **5 929 ms** |
| windows > 500 ms | — | 4 | 10 | 15 |
| windows to settle within 25 % | 17 | 7 | 30 | 24 |

What survives: the ramp still commits less (peak 1.5 M vs 2.55 M) and still cuts
the over-drive — **3.2×, not 4.8×** — and the ordering survives the 3× keyframe
re-run (1 435 vs 1 636 ms). What does **not** survive is the headline: arm B's
peak paint is **5.9 s, not 1.2 s**. The 1 226 ms was the optimistic rule handing
the floor relief the pipe's rate in window 2; under the shipped rule the ramp
ends at the first congested window, the flat 1.5 M floor re-pins the opener
(exactly the mechanism "the ramp-exit rule" describes), and the session
sawtooths for ~24 windows until push-back finally measures the pipe — and the
first "measurement" it gets is a catch-up burst (window 8 reads 1.25 Mbps on a
213 kbps pipe: the queued keyframe arriving at once), which re-lifts the floor
before the next window corrects it. By windows-over-500-ms arm B is *worse* than
arm A, because arm A delivers nothing for ten windows and then settles once.

🔑 **So the simulated AC0b answer is: slow-start removes most of the opening
commitment and about half of the harm, not most of it.** The remaining harm is
the flat floor re-pinning an unmeasured session, which is the ramp-exit
question — and which FR-70 P1's decaying prior addresses only for REMEMBERED
pairs (an unremembered thin pipe has no prior to decay). AC0b stays open in the
field, and this table is what the field run is now a confirmation of.

**The ramp-exit rule, under the shipped rule:**

| cell | `EndsOnCongestion` (shipped) | `HalveAndContinue` | `HoldFloorUntilMeasured` |
|---|---|---|---|
| thin pipe 213 k — peak / max p95 age / settles | 1 500 000 / 5 929 ms / w24 | 300 000 / **1 226 ms** / w1 | 348 500 / 1 529 ms / w3 |
| fast pair 20 M — final target | 9 300 000 | 9 300 000 | 9 300 000 |
| **LAN 5 M bursts — peak / final target** | 1 941 865 / 1 650 530 | 1 200 000 / **600 000** | 1 500 000 / 1 200 000 |
| fast pipe, stall at 2 s — final target | 10 250 000 | 9 600 000 | 7 768 750 |

Under the shipped rule the candidates matter far more on the thin pipe than
they did (a 3.9–4.8× cut in peak paint, not 1 %) — **and they now cost rate on
the fast cells**: `HalveAndContinue` ends the LAN-burst cell at 600 kbps against
the shipped rule's 1.65 M, and `HoldFloorUntilMeasured` gives up a quarter of
the stalled fast pipe. The adversarial cell exists after all; it needed the
shipped measurement rule to bind. 🔑 This is the trade-off B1's controller is
designed around: on congestion, **hold** — neither end the ramp (and hand the
session to a constant) nor halve (and give away rate the link has).

⚠️ A claim I made while writing this and then refuted in the same hour, kept
because the refutation is the useful part: "FR-59 P2's 16 KiB minimum budget is
615 ms of standing queue on a 213 kbps pipe by construction". It is not. The
budget is a *ceiling* on the bytes in flight, not a standing level; a session
settled onto the pipe carries about one frame. What the report's "26 windows
over 500 ms" under `HalveAndContinue` actually shows is the **p95** paint age —
the average sits at 71–259 ms in the settled tail — i.e. periodic excursions
from the candidate's ×2/÷2 oscillation, each rebuild on a rebuild-bound encoder
costing a keyframe. A test asserting the 615 ms plateau failed on the first run
and was deleted rather than loosened.

⚠️ **And the "fast pair misremembered slow" fixture passes for the wrong
reason under the shipped rule**: its assertion is `> 400 kbps`, and the session
ends at **513 kbps on a 20 Mbps pipe** — pinned by the budget exactly as FR-70
P1 described. What actually frees a misremembered pair is P1's decaying prior,
which is tested in `p1_the_prior_decays_and_the_session_escapes`; the FR-63
fixture only shows the AIMD's own step does not.

The four fixtures under the shipped rule (arm B): airport hotspot settles onto
the pipe (final 200 k against 240 k) but peaks at 7 980 ms with 16 windows over
500 ms; DERP-with-stalls likewise (5 885 ms, 15 windows); the LAN cell is fine
(465 ms peak, none over 500 ms). FR-59's AC4 (< 600 ms sustained on the
airport-class link) is therefore **not** met by the shipped laws in simulation
either — which is the number B1 has to beat.

## Open decisions

- **Deferred from B0: CSV trace replay from `agent_logs`.** The four fixtures are calibrated from
  recorded field numbers but are generated, not replayed. Replay is worth building when a trace
  disagrees with a fixture; building it first would have delayed the AC0b answer for no evidence.
- **Raised by B0, and now MEASURED — see "The ramp-exit rule" below.** Both modelled candidates beat
  the shipped rule on the thin pipe and cost nothing on three healthy cells. Not shipped: the choice
  between them is a design call, and the field A/B (AC0b) has not run on ANY of them yet.
- Whether the viewer computes the delay slope (recommended; the data is there) or sends per-frame pairs.
- Follower (multi-viewer) folding: worst follower's `rx_bps/queue_ms` into the same window.

## Out of scope

- The encoder apply path (FR-62, must land first); ICE path selection (FR-64); encoder-bound pacing/downscale (kept).

## Related

FR-59 #1163, FR-35 #922, FR-15, FR-1 #767, FR-62, FR-64.
