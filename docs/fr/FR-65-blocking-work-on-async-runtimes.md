# FR-65 — Blocking work on async runtimes: measure first, then remove

**Issue:** [#1255](https://github.com/jk-zhang-meta/MeshHarbor/issues/1255) · **Status:** **P0 shipped and field-read on 0.4.60** — the watch (0.4.55, 100 ms bar, #1259), `open_ms`/`other_ms` (#1279), the `work_us` decision + off-thread encoder open (#1284), and the verdict as a pure tested type (#1304). **1 of 7 criteria ticked**: the rest are measurement criteria and none of them has its measurement yet, which is the point of an FR whose first rule is *measure first*. · **Parent:** the FR-62/63/64 rate-control arc (plan `immutable-doodling-neumann`)

## Goal

Find and remove synchronous vendor/OS calls that run on tokio worker threads in
`meshharbord`'s hot paths — **driven by measurement, never by inference**. The
deliverable that matters most is the instrument: today nothing measures a stall,
so stalls are found by accident, months late.

## Why now — the evidence FR-62 produced

A QSV encoder open costs **~340–390 ms at maxrate ≥ 1.5 Mbps and 1.3–2.0 s at
≤ 1 Mbps** (CORPLAP-1, Iris Xe, 0.4.51, identical in both `low_power` modes).
`peer.rs` ran that open **inline on the pump thread** for constrained sessions —
and constrained is exactly the band where those targets live. Every landed rate
change on a slow-link QSV session froze the pump for ~2 s. #1254 fixed it for the
**rate** path only.

🔑 **The reason it went unnoticed for months is the whole thesis of this FR.**
The pump already measures `avg_capture_ms`, `avg_scale_ms`, `avg_encode_ms`,
`avg_send_ms` — and the 2 s stall appeared in **none** of them, because the
apply/rebuild phase was untimed and because a per-heartbeat *average* dilutes or
hides a single outlier. It became visible only when `set_ms` was instrumented
for FR-62 A0, for an unrelated reason.

⚠️ `meshharbord` is **one process**: overlay, DERP, tunnels, the WS control plane
and RC share runtimes. A long synchronous call taxes all of them, which is why an
encoder stall is not only an RC problem.

## Key design

### The shape of the answer (revised 2026-09-04, after P0 shipped)

P1–P5 as originally written are **a list of call sites to wrap in
`spawn_blocking`**. That is the patch-work version of this FR — including the
encoder-open fix (#1284) that shipped under it. Each wrap is individually
correct and collectively unsatisfying, because "is this call blocking?" stays a
question somebody has to re-ask at every site, forever.

The structural answer: **the media pipeline should not live on the async runtime
at all.** One dedicated thread per session owning `capture → scale → encode`,
communicating by channel, with the async side handling only signalling and send.

🔑 **This is not a new pattern here — capture already does exactly it**, on
every backend, and that is why capture turned out not to be a blocking problem
(measured 2026-09-04): `scrap`, `drm` and `system-context` hand the work to a
thread that owns the `!Send` device and return a oneshot; `wgc` uses a `Notify`
with a mutex held only for a `take()`. So the encoder thread is a
*precedent-following* change, and capture is the reference implementation.

It also **respects encoder thread-affinity instead of fighting it**: Windows MF
needs per-thread COM/`MFStartup`, and QSV/MFT sessions can be thread-affine.
⚠️ That is the concrete reason **P2 must NOT be per-frame `spawn_blocking`** —
handing frames to arbitrary pool threads risks breaking hardware encode outright.
A thread that owns the encoder for the session's lifetime is both the safer and
the simpler shape.

Sequencing is unchanged in spirit — measure, then move — but the target is one
move that removes P1, P2 and the capture-open (`capture::open_default`, still
synchronous at pump start and invisible to `open_ms` because it precedes the
loop), rather than three wraps.

### P0 — the stall watch (blocks every other phase)

> **Status 2026-09-04 — shipped, field-read, and now unit-tested.** The watch
> (0.4.55), the 100 ms bar, `open_ms`/`other_ms` (#1279, 0.4.59) and the
> `work_us` decision (#1284, 0.4.60) are all live on CORPLAP-1; the field log
> below shows the breakdown summing to its total on two builds. **AC2 is
> closed** — the verdict moved into `encode::stall::PassTiming`, a pure type on
> the default feature set, with seven tests that assert phase ATTRIBUTION and
> not merely that something was flagged. **AC1** (the overhead A/B) is the last
> P0 item.
>
> 🔑 **Why the extraction, and not a test where the code was:** the decision
> lived inline in `media_pump_ffmpeg_dc`, which is behind `ffmpeg-encoder` — a
> NON-default feature, so `cargo test -p meshharbord --lib` compiled none of it.
> The rule deciding whether an operator ever sees a stall was unreachable in
> the lane everyone runs, which is the same shape as the defect this FR exists
> to fix: an instrument nobody can check is not an instrument.
>
> ⚠️ The `work_us` half of #1284 is verified **deterministically**, not in the
> field: the idle-capture storm never reproduced on a locked host (see the log
> below), and the unit test pins the rule instead — the exact field shape
> `iter 111 ms / capture 101.9 ms` must NOT warn, while a 789 ms encoder open
> must, and must be blamed on `open`.

A per-iteration wall-clock watch on the pump loop, threshold-gated.

- Two `Instant::now()` per iteration (~20–40 ns each) against a 16.7 ms frame
  budget at 60 fps. **Not** `tracing` spans — span entry/exit allocates and
  dispatches per phase per frame, which is the cost profile this FR exists to
  remove.
- Reuse the phase timers the pump already computes; **add the missing
  `apply_ms`** (the rate/dims apply + rebuild), which is precisely the phase the
  2 s stall hid in.
- Track **max** beside **avg** per phase (one compare per phase per iteration).
  An average over a 2 s heartbeat cannot represent a 2 s outlier.
- On `total > stall_warn_ms` (default **250 ms**) emit ONE `WARN` carrying the
  per-phase breakdown, session id, `constrained`, encoder name and target.
- ⚠️ **Rate-limit the WARN** (≤1 per 2 s per session): a stall storm that floods
  its own log becomes a second performance problem.
- Kill switch `pump_stall_watch` (env `MESHHARBORD_PUMP_STALL_WATCH`, default **on** —
  it is near-free, and its absence is what cost us the months above).

**Generalisation is deliberately deferred**: P0 ships pump-local. If P3 needs the
same primitive for the overlay loops it moves to a shared crate then — not
speculatively.

### P1 — dims / chroma / backend rebuilds off-thread

> **Status 2026-09-04 — HALF done, and the half that shipped is the lesser one.**
> #1284 wrapped the single encoder-open call site in `spawn_blocking`, which
> every open flows through (first open *and* every rebuild), so the **runtime
> tax** is gone. But the session is still **without an encoder for the whole
> 0.62–0.73 s**, because the old encoder is torn down before the new one opens.
> P1's actual goal is **make-before-break**, and that needs `rebuild_spec` to
> carry GEOMETRY so the swap machinery can hold the old encoder live — today it
> carries only a bitrate and `adopt_rebuilt` discards a dims change. Do not read
> #1284 as closing P1. (Field read on 0.4.60: the first open is **789 ms** on
> `hevc_qsv` at 1920×1200 against 748 ms one build earlier — unchanged, as
> predicted; see the field-verification log.)

The direct twin of #1254, and the largest remaining known win.

1. It fires **exactly when the session is already struggling** — the downscale
   tier engages on a constrained/congested session, the same conditions that put
   the target ≤ 1 Mbps, i.e. the 1.3–2.0 s band. The pump blocks for ~2 s at the
   moment it is trying to recover.
2. The background-swap machinery **structurally cannot carry it today**:
   `rebuild_spec(&self, bps: u32)` carries only a bitrate, and `adopt_rebuilt`
   returns `false` for a geometry change, logging *"background rebuild stale
   (dims/backend changed) — discarded"*. So a dims change not only runs inline,
   it **throws away any in-flight rate swap**.

Design: extend `RebuildSpec` with geometry (w/h/chroma/backend); `adopt_rebuilt`
compares against the **currently desired** geometry rather than the geometry at
request time, so a swap is stale only if the desire moved again. Adoption stays
**quiet-gated on constrained** (the #1254 invariant — adopting mid-motion on a
thin pipe is the 2026-08-27 regression). Kill switch `bg_rebuild_dims`.

⚠️ Ordering hazard: while the replacement opens, the pump keeps producing at the
OLD geometry. The viewer must never see a geometry change before its
`video_info`; the adoption path already clears `video_info_sent` and bumps
`send_epoch`, but this needs an explicit test, not an assumption.

### P2 — the per-frame encode call

**Confirmed mechanism, unquantified harm.** `FfmpegEncoder::encode()` is
`async fn` in signature only — its body is `self.encode_sync(&frame)` with zero
`.await`, and `spawn_blocking` appears nowhere in `encode/` except in comments.
So FFmpeg `send_frame`/`receive_packet` run **directly on the tokio worker** that
polls the pump. Measured on CORPLAP-1: `avg_encode_ms` **8.57 ms** plus
`avg_capture_ms` **4.16 ms** ≈ 13 ms synchronous per frame.

P2 **starts with the measurement, not the fix**:

- A **runtime canary** — a task that wakes every 10 ms and records its own
  lateness. 🔑 The canary is the right instrument because it measures the
  *symptom* (other tasks not getting scheduled) rather than a proxy for it, and
  it costs a timer.
- Optionally tokio `RuntimeMetrics` (`worker_total_busy_duration`, injection
  queue depth) as corroboration.

Only if starvation is demonstrated: move encode to a **dedicated encoder thread**
fed by a channel — **not** `spawn_blocking` per frame, which adds a handoff every
frame and can grow the blocking pool without bound. ⚠️ A dedicated thread adds a
queue hop, so the A/B must show frame **age** does not rise, not merely that the
stall count fell.

### P3 — overlay guard cadence and rekey storms

A tax rather than a block, in the same family. #1237 fixed the sibling-adapter
cause of the ~100 `net-change — revalidating direct carrier` events/min (each
force-rekeying **every** peer and demoting real carriers); the general guard
cadence is unexamined. Route-table enumeration and eviction are synchronous OS
calls (`GetIpForwardTable2` / netlink).

Measure first: guard waves/min, per-enumeration duration, forced rekeys/min — at
idle and across a VPN flap — with the canary watching for starvation. Then
coalesce/debounce net-change bursts into one revalidation and bound the
per-peer rekey rate. ⚠️ **Debounce, never disable**: the guard exists so a
hostile VPN cannot self-wedge the host, and its worst-case reaction time must
stay within today's SLA.

### P4 — the caps-probe respawn

Observed on neo16: a `caps-probe` **child process every ~10 s for nearly three
hours**. `detect()` is meant to cache in a `OnceLock`, so this is a bug — a
process spawn plus a driver enumeration on a repeating timer. Measure the spawn
rate per host, find the trigger (unshared cache vs. genuine re-detection), fix.
⚠️ Fleet-wide counts via `meshharbor exec` are a **biased sample** (only exec-enabled,
reachable hosts) — say so rather than generalising.

### P5 — the remaining synchronous calls, triaged by measurement

Ranked by expected value, not by ease. Each is **unmeasured** until the canary or
the stall watch says otherwise; the ordering is a hypothesis, and the first job
of each is to produce a number.

| # | Site | Why it might matter | Status |
|---|---|---|---|
| ~~0~~ | ~~`capturer.next_frame()`~~ | ~~a ~100 ms block on every idle pass would dwarf the one-shot open~~ | **REFUTED 2026-09-04** — every backend already yields (oneshot-to-worker, or `Notify`). Not a blocking problem, and it is the reference architecture. |
| 1 | `capture::open_default()` at pump start | DXGI/WGC init, synchronous, at the same session-start moment as the encoder open — same class. `open_ms` does **not** catch it: it runs before the loop. | **bounded ≲50 ms on the system-context backend** (2026-09-03 trace: `pump starting` 07.716 → stalled pass start 07.766 = everything before the loop, capture open included). WGC / scrap / drm unmeasured — do not generalise from one backend. |
| 2 | Route-table work on the overlay guard cadence | `GetIpForwardTable2`/netlink enumeration + eviction every 2 s; #1237 measured ~40 evictions/min per prefix and ~100 carrier revalidations/min. A corp laptop whose VPN pushes hundreds of routes makes that enumeration expensive. ⚠️ **Debounce, never disable** — the guard is what stops a hostile VPN self-wedging the host. | unmeasured |
| 3 | WFP filter operations | `FwpmFilterAdd0` and friends are synchronous RPC to the BFE service — tens of ms, slower under EDR. | unmeasured |
| 4 | `config::save` | atomic write + fsync + `.prev` rotation **under a daemon-wide write lock**, so it is a block *and* a contention point. fsync on a corp laptop behind filter drivers is routinely 100 ms+. | unmeasured |
| 5 | The updater's `WinVerifyTrust` | can trigger CRL/OCSP fetches — a multi-second hang on a blocked corporate network, on the daemon's identity. | unmeasured |

## Explicitly NOT in scope

- **The DataChannel send path.** `avg_send_ms` was **0.013 ms** — it is not a
  bottleneck and must not be "optimised".
- **The SCTP stalls.** Those were a correctness bug (the FORWARD-TSN
  bundled-chunk drop), already fixed by the vendored patch. Do not conflate a
  parser defect with a blocking-design problem.
- The rate-control architecture itself (FR-63), the coarsen-ladder/clamp trap
  (FR-62 A4), and which path ICE selects (FR-64).

## Acceptance criteria

- [ ] **AC1** — the stall watch ships and its overhead is **measured** at < 1 % of
      the frame budget by an A/B with it disabled, on real hardware. An instrument
      that costs what it measures is worthless.
      ⚠️ **Half of this is done and the half that is left is the whole point.**
      The watch ships. What is owed is the A/B, and it must not be closed on the
      analytical figure (*"an `Instant::now()` is ~20–40 ns, and there are N of
      them"*): that is an argument, not a measurement, and this FR's first rule is
      that inference does not count. Arithmetic over a constant nobody timed on
      the hardware in question is exactly what AC7 refuses.
- [x] **AC2** — a synthetic stall is caught and attributed to the correct phase.
      *#1304 (merged 2026-09-04) made the verdict a pure type,
      `encode::stall::PassTiming`, and the tests assert **attribution**, not just
      detection — `an_encoder_open_is_a_stall_and_is_attributed_to_open`,
      `a_gate_skip_is_attributed_to_gate_not_to_other`,
      `an_untimed_phase_surfaces_as_other_and_blames_nobody`. Re-run locally
      2026-09-23: `cargo test -p meshharbord --lib` → **11 `encode::stall` tests, all
      ok**.*
      *The **negative controls** are what make that set mean anything, and they
      are named here so nobody has to rediscover which ones they are:
      `an_idle_capture_wait_is_not_a_stall` and
      `a_cadence_sleep_is_idle_and_does_not_warn`. A suite that only ever asserts
      "a stall was flagged" passes just as happily on a rule that flags
      everything — a cell that would pass with the change reverted proves
      nothing, which FR-79 hit four separate times.*
      *And the word **"synthetic"** in this criterion is what makes a pure-type
      test the right instrument rather than a field run: AC2 asks for a
      fabricated stall attributed correctly, which is exactly what a table of
      hand-written `PassTiming` values is. AC1 and AC3–AC7 ask for measurements
      and none of them can be closed this way.*
      ⚠️ The reason this needed a PR at all is the FR's own subject: the rule
      lived inline behind `ffmpeg-encoder`, **not a default feature**, so
      `cargo test -p meshharbord --lib` compiled none of it — the instrument this FR
      exists to turn on was unreachable in the lane everyone runs. `pub mod stall`
      is now declared unconditionally; verified on master, not assumed, because a
      checked-out test file that no module registers runs nothing and still
      reports green.
- [ ] **AC3** — no pump iteration exceeds 250 ms across a downscale-tier change on
      a constrained QSV session; recorded **before and after** P1.
- [ ] **AC4** — the encode-scheduling question is answered with canary data; if
      starvation is shown it is fixed, and the canary confirms, with frame age
      unchanged or better.
- [ ] **AC5** — overlay guard waves and forced rekeys/min are measured at idle and
      under a VPN flap, and bounded; no rekey storm.
- [ ] **AC6** — caps-probe spawns at steady state are 0/hour on a measured host.
- [ ] **AC7** — every fix carries a before/after from the **same** instrument on
      this issue. A fix with no measurement does not count as shipped.

## Open decisions

- Whether the stall watch generalises to a shared crate (decide in P3, from need).
- Dedicated encoder thread vs. leaving encode on the worker if the canary shows no
  starvation — P2's measurement decides, not preference.
- Whether `apply_ms` belongs in the heartbeat permanently or only under the watch.

## Risks

- The instrument perturbs what it measures → AC1 exists precisely for this.
- Off-thread work adds handoffs → every phase A/Bs **latency**, not just stalls.
- Debouncing the route guard could delay a legitimate heal → bound it and keep the
  worst-case reaction time.

## Related

FR-62 #1242 (produced the measurements that motivated this; #1254 fixed the rate
path), FR-63 #1243, FR-64 #1244, #1237 (the sibling route war).

## Field-verification log

_(every entry must carry a before/after from the stall watch.)_

- **2026-09-04 — `other_ms` found a SECOND untimed phase, and this one is not the
  open.** Operator report: on all three CORPLAP hosts the frame age goes over
  100 ms — sometimes over 400 ms — just after a window drag starts, then
  settles. Reading the stall lines on 0.4.61/0.4.62 separates that into three
  independent causes, which is the whole point of the instrument.
  - **The encoder open, every session, every host** (the known P0 finding):
    `open_ms` 457/495/736/762 on CORPLAP-1, **912** on CORPLAP-2, 532/565/779 on
    CORPLAP-3. #1284 took this off the shared runtime worker, but the session
    still has **no encoder at all** while it runs, so the first frames are late
    by roughly the open. That is P1's make-before-break, still not done.
  - 🔑 **A second gap, with `open_ms = 0`.** CORPLAP-1 at drag onset:
    `iter 171.5 / capture 0.3 / encode 13.6 / open 0 / apply 0 / other 157.6`,
    and `iter 358.8 … other 347.4`. CORPLAP-2 is starker — `iter 662.0` and
    `iter 782.0` passes that are **100 % `other` with capture AND encode both
    zero**, i.e. the pump produced nothing and still spent most of a second.
    Zero capture is the tell: it means the pass took a `continue` *before*
    capture, which only the backpressure gate does.
  - **CORPLAP-3 is additionally encode-bound**: single frames at 346, 371 and
    **502 ms**. A different problem from the other two, on the same symptom.
  - 🚨 **A counter that read zero through the event it counts.** First reading of
    this data said "the encoder applied **zero** rate changes — `rebuilds=0`,
    `rate_moves=0` — while the governor's target swung 4 145 343 → 486 191 →
    2 550 000, so the controller reacted to the drag and the encoder never did."
    **That conclusion was wrong, and the counters caused it.** The daemon log
    carries two `background-rebuilt encoder adopted` lines at 11:03:03 and
    11:03:08 — the encoder moved its rate *twice*, mid-drag. `adopt_rebuilt`
    incremented **neither** counter, and on a DIRECT QSV session every rate move
    goes through exactly that path (`swap_wanted` → `open_rebuilt` →
    `adopt_rebuilt`), so the pair reads zero **by construction** on the one
    configuration where it is most load-bearing.
    A new `swaps` counter now counts adoptions, kept **separate** from
    `rebuilds` because P3's whole point is that a swap is stall-free and folding
    them would lose that. ⚠️ Read `swaps` alongside the other two, never instead
    of them.

  **Instrumented rather than guessed at**: `pace`, `stats`, `ctrl`, `swap` and
  `gate` are now timed, so `other_ms` decomposes itself the way it did for the
  open. ⚠️ `pace_us` is **excluded from `work_us`** alongside `capture_us` — at a
  paced 2 fps the cadence sleep is ~500 ms of one pass, and counting a
  deliberate idle as work is exactly the storm the capture rule removed.

- **2026-09-04 — P0's instrument and #1284, read one build apart on CORPLAP-1**
  (Iris Xe, `hevc_qsv`, 1920×1200, direct host↔host path, host **LOCKED**). Same
  viewer (neo16 Chrome), same procedure (Connect → ~40 s idle → three cursor
  drags → Disconnect), the two sessions eleven minutes apart with the 0.4.60
  roll in between (`rc:agent.update` 23:40:01 UTC → daemon up on 0.4.60 at
  23:40:13).
  - **Before — 0.4.59 (#1279, no #1284), session `6a9a0343`, 23:31 UTC:**
    `START` 23:31:16.931 → `encoder (re)built hevc_qsv` +798 ms →
    `STALL iter_ms=773.1 capture_ms=8.8 encode_ms=15.8 apply_ms=0.0 open_ms=748.1 other_ms=0.29`.
    First heartbeat `open_ms=748.1 open_ms_max=748.1 pump_stalls=1 iter_ms_max=773.1`;
    the 78 heartbeats after it: `pump_stalls=0`, `iter_ms_max` 14.7–16.9 ms,
    `avg_capture_ms` 3.3–4.5, `avg_encode_ms` 10.7–11.3, viewer age 6–29 ms.
  - **After — 0.4.60 (#1279 + #1284), session `6a9a0602`, 23:42 UTC:**
    `START` 23:42:59.253 → `encoder (re)built hevc_qsv` +850 ms →
    `STALL iter_ms=815.7 capture_ms=10.0 encode_ms=16.1 apply_ms=0.0 open_ms=789.0 other_ms=0.57 work_ms=805.7`.
    First heartbeat `open_ms=789.0 open_ms_max=789.0 pump_stalls=1 iter_ms_max=815.7`;
    the 80 heartbeats after it: `pump_stalls=0`, `iter_ms_max` ≤ 25.6 ms
    (the drags), `avg_capture_ms` 3.5–4.4, `avg_encode_ms` 10.7–12.0, viewer
    age 9–12 ms.
  - **Read.** (1) The breakdown now **sums to its total** on both builds
    (0.4.59: 8.8 + 15.8 + 748.1 + 0.29 = 773.0 vs `iter_ms` 773.1; 0.4.60:
    10.0 + 16.1 + 789.0 + 0.57 = 815.7 vs 815.7). The 0.46–0.96 s that the
    0.4.55–0.4.58 lines left in no phase is gone from the log because it is
    *named*: it is the open. (2) `open_ms` is **unchanged across #1284** (748 →
    789 ms, run-to-run spread on a cold QSV open) — exactly what #1288 said to
    expect: the open did not get cheaper, the worker stopped waiting for it.
    (3) `hevc_qsv` opened on a `spawn_blocking` thread and encoded on runtime
    workers for the whole session without an error, so the thread-affinity
    risk did not bite for a QSV *open* (P2 stays per-session-thread, not
    per-frame `spawn_blocking`). (4) `work_ms` (new in 0.4.60) = `iter − capture`
    and is what the stall decision now runs on.
  - ⚠️ **What this cell could NOT show: the idle-capture storm.** On the lock
    screen the system-context capture returns in ~4 ms on every pass
    (`iter_ms_max` 15 ms across 2.7 min of a static screen), so the
    `iter≈105 / capture≈93` shape that made up the majority of 0.4.55/0.4.56
    warnings on an **attended** desktop (2026-09-03 13:30–13:42, 55 lines)
    never occurred on either build here. The "storm gone" half of #1284 — the
    decision on `work_us` — is unverified until an attended-desktop session on
    ≥ 0.4.60 is read. Likewise the runtime-side claim (a worker no longer
    blocked ~0.8 s during session establish) is unobservable in this log by
    construction; that is the P2 canary's job.
