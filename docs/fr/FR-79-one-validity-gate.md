# FR-79: One validity gate — a window is evidence about the pipe, or it is not

**Issue:** [#1524](https://github.com/gjovanov/roomler-ai/issues/1524) · **Status:** proposed 2026-09-08; V1–V5a shipped (`agent-v0.4.93` → `0.4.97`), V3b in SHADOW (`0.4.98` → `0.4.100`), docs 2026-09-25; AC8 half-met, AC9 open ·
**Parent:** the consolidation FR-70's AC4 asks for (8 estimators → 1) and the rule
FR-71's three field events wrote by induction. Deletes rather than adds:
`transit_hold`, `transit_classify`, T2's quarantine and T2b's shadow all go.

## Goal

**One rule, consumed by every estimator, at every site that reads a window.** A
window is evidence about the pipe only if

1. the **agent was free** — no pump pass overran its budget inside it,
2. the **transport was not stalled**, and the window before it was not either,
3. the **carrier it will be attributed to is the carrier that produced it**.

Anything else is not a measurement, and no consumer may act on it: not the
goodput fold, not FR-59 P6's contradiction, not P1's floor relief, not FR-35's
hard halving, not P3's arrival-rate clamp, not FR-15's age loop, not FR-63's
ramp verdict, and not the pair memory's write-back.

## Why this FR exists — the rule of three

One day, three field events on the same host, three different inputs, one shape.
Each was answered with its own rule; the third made the pattern undeniable.

| when | the input that lied | what it cost | the rule it got |
|---|---|---|---|
| 2026-09-08 12:15 | a **blocked send** inside a pump pass that spent 2.9 s and 7.4 s in `other` | 6.60 → 0.68 M in 36 s, ~3 min back | FR-71 T2: quarantine the samples, defer the ×0.5 |
| 2026-09-08 14:52 | the **viewer's arrival-rate report** for the stall, landing one window later | 7.45 M → 834 k, the learned ceiling lost | FR-71 T2b: the stall's shadow gates the clamp |
| 2026-09-08 16:33–16:42 | the **opening burst**, read as capacity while it queued; and a stall-contaminated measurement written back as the pair's rate | the operator's own report: "starts very blurred, 5+ s to crystallize", openers swinging 1.26 ↔ 6.8 M | — (this FR) |

The third one is measured in §The opener, below. Writing a fourth per-input rule
is the wrong move: the inputs differ, the defect does not.

## Key design

### The gate (`agents/meshharbord/src/encode/evidence.rs`, new, pure)

```rust
pub enum Reason { AgentStalled, TransitStalled, StallShadow, CarrierChanged }

pub fn rejected(f: WindowFacts) -> Option<Reason>
```

`WindowFacts` is what the governor already holds at the fold: this window's
classifier verdict, the previous window's, whether a pump pass stalled inside
it, and whether the carrier moved. No new sensor, no threshold, no switch. The
verdict is taken **once per window, before any loop acts**, and every consumer
reads the same one.

⚠️ The classifier stops being a shadow: `transit_classify` is deleted and it
always runs, because the gate is built on its verdict. It has run fleet-wide
since 0.4.67 with the counters as its only effect.

⚠️ `agent_stalled` comes from the FFmpeg pump's own stall watch
(`encode::stall::PhaseAccum::is_stall`, already computed per pass). The VP9-444
pump keeps no send-side figures, so there the input reads false and the gate
falls back to conditions 2 and 3 — the same degradation `WindowSenderStats:
None` already documents.

### What each consumer does with it

| consumer | before | after |
|---|---|---|
| the goodput fold (`GoodputEstimator::observe_window`) | folds every window; T2 quarantined some | folds only a valid window; an invalid one's samples are **dropped**, not held |
| FR-35's hard halving (a send blocked ≥ 1 s) | applied inside `note_send_stall`; T2 deferred it | recorded for the window, applied at the fold **iff** the window is valid |
| FR-59 P6 contradiction, P1 floor relief | read the goodput estimate | unchanged — they see the last **valid** estimate, so no false evidence reaches them |
| FR-59 P3 arrival-rate clamp | `!hold`, then T2b's `!stall_shadow` | `valid` |
| FR-15 age loop | `!hold` (fire), always learns its floor | `valid` (fire), still always learns — a stall cannot lower a minimum |
| FR-63 ramp verdict | `!hold` | `valid` |
| FR-35 pair-memory write-back | the opener burst target and the session's stable rate | V2: the same gate, and the burst measured the way the goodput estimator measures |

### The opener (V2), measured 2026-09-08 16:33–16:42 on CORPLAP-1

`rate_memory::opener_growth_target_bps` divides the whole burst by the **longest
single frame's wait**:

```
bytes * 8 / wait_us * 75 %
```

That is only a rate if the last frame waited for the entire burst. In the
operator's six trials it was not:

| session | burst | longest wait | recorded target | the pipe, measured seconds later |
|---|---|---|---|---|
| 16:33:57 | 951 KB | 107 ms | 8.0 M (capped) | ~2.4 M after 438 gate skips |
| 16:38:52 | 1.19 MB | 440 ms | 8.0 M (capped) | **1.79 M** |
| 16:41:51 | 829 KB | 829 ms | 6.0 M | **3.41 M** |

`record_session` then keeps `max(stable, old, growth_target)`, so the memory
ratchets to the 8 M cap and stays there; the only thing that ever lowers it is a
P6 abandonment writing back the **stall-contaminated** number — which is where
the 16:39:35 session's seed of **1,255,327** came from, and FR-59 P8 opens the
encoder *at* the remembered rate: 1.26 Mbps for 1920×1200 is 0.018 bits per
pixel. That is the blur the operator sees, and the 6.8 M openers are the same
memory at the other extreme, over-driving the relay by 2–4× until P6 collapses
it about a second in.

Third element: the memory key is the nominated pair's remote address — the
**overlay** address — while the carrier under it flips between direct, relay and
DERP (six demote-follows onto DERP on 2026-09-08 alone). P6's own comment says
it: *"relay-keyed rate memory can carry a fast day onto a slow one"*. One key,
carriers with 4× different capacity.

So V2 is condition 3 plus the honest denominator:

- the opener's contribution comes from the **same estimator the session uses**
  (bytes over blocked time, byte-weighted), not from `bytes / max_single_wait`;
- the write-back runs only on evidence the gate accepted;
- the memory is keyed (or the seed clamped) by the **carrier in force**, which
  the pump already knows at session start and logs every 5 s.

### V4 — the memory keeps what was measured, not the maximum (2026-09-08)

V2 made the opener's contribution a measurement. The rule that consumes it is
still `record_session`'s **maximum**:

```rust
let value = if had_decrease && stable_bps > 0 { stable_bps }
            else { stable_bps.max(old).max(growth_target_bps) };
```

Two measurements say that rule has outlived its reason.

**1. A carrier's capacity is not a constant, and max keeps the best minute of
it.** On `100.65.4.2|relay:derp/tcp`, five sessions inside six minutes measured
**1.44, 1.09, (unqueued), 3.32, 6.13 Mbps** (2026-09-08 19:12–19:18). The
maximum keeps 6.13, so the next session opens at 85 % of it — 5.2 M — into a
path that measured 1.09 M five minutes earlier. That is the over-drive this FR
exists to stop, rebuilt out of honest inputs.

**2. The unqueued branch still grows the memory on no evidence at all.** A burst
that never queued gets `maxrate × 150 %`, and with the maximum that is a
one-way ratchet to the `hi` cap. Measured over 2026-09-08: **every** opener on
CORPLAP-2 had `opener_wait_max_ms=0` (its SCTP buffer absorbs the burst), and its
memory sat at the 8 M cap all day; CORPLAP-1 recorded the cap in nine of
nineteen openers before V2. The branch's own comment says what it proves —
*"only 'not slower than this'"* — and the ratchet turns that into "this fast".

**The rule the gate makes possible.** The whole FR is one sentence: only
evidence moves a belief. The memory is a belief about a carrier, so:

> A session writes the memory **only if it measured the carrier**, and a
> measurement is allowed to move the number **in either direction**, damped —
> fast down, slow up, the asymmetry the goodput estimator already uses inside a
> session (`ALPHA_DOWN` 0.50, `ALPHA_UP` 0.10). A session that measured nothing
> leaves the entry exactly as it was.

What that deletes:

- the **maximum** composition, and with it `had_decrease` — the flag exists only
  to stop a non-measurement (an idle session's seed echoed back) from lowering
  the memory, and a session that measures nothing now writes nothing at all;
- the **unqueued growth step** and `OPENER_UNQUEUED_STEP_PCT`: a burst the
  socket absorbed is not a measurement. Convergence for a fast pair is already
  the learner's job — it steps the ceiling up when the pair *carries* it and its
  stable rate is written back, which is evidence rather than a guess;
- `record_session`'s three value parameters collapse to one: the session's
  evidence, or `None`.

**Why damped rather than last-wins.** One unlucky window would otherwise pin a
pair for a week (the TTL), and one lucky burst would re-create the over-drive.
Down-fast/up-slow biases the opener toward the safe side, because the two errors
do not cost the same: opening under costs an AIMD climb the learner shortens,
while opening over costs dropped frames, an abandoned ceiling and a visible
stall — which is what the operator reported and what tonight's five sessions
stopped doing.

## Phases

| phase | scope | kill switch | status |
|---|---|---|---|
| **V1** | the gate + every in-session consumer; **delete** `transit_hold`, `transit_classify`, T2's quarantine, T2b's shadow, and their four counters (one `evidence_rejected` replaces them) | **none — and none is the point**; what it replaces had two | **built 2026-09-08**, shipped `agent-v0.4.93` (#1525); AC1–AC3 met |
| **V2** | the write-back and the seed: the opener measured like every other window (the estimator, not `bytes / max_single_wait`), and the memory keyed by CARRIER — `100.65.0.5|relay:derp/tcp` is not `100.65.0.5|direct` | — | **built 2026-09-08**, shipped `agent-v0.4.93` (#1529); AC4 met, AC5 field-verified |
| **V3a** | ONE belief (`pipe_bps`) composed in one place + one named source (`blocked_send_bps`); delete `remembered_candidate_bps`, the inlined third copy, and the `rate_prior_decay` switch | — | **built 2026-09-08**, shipped `agent-v0.4.95` (#1533); AC6 met |
| **V3b** | the three sources behind one `Pipe` type (`encode::pipe`): a demonstrated FLOOR (the viewer's arrival rate, every window on every carrier) and a pushed-back CAPACITY (an accepted goodput fold, or the arrival rate while the viewer's queue grows); `capacity_bps` answers "am I over?", `ceiling_anchor_bps` answers "what may the ceiling be?" | — | **built 2026-09-10, in SHADOW since `agent-v0.4.98`** (#1575): heartbeat `pipe_belief` / `pipe_belief_n` only, read by NO consumer. The shadow corrected the design three times in five days — V3b-1 (#1578, `0.4.99`): no single `believed_bps()`, the two questions are not interchangeable; V3b-2 (#1580, `0.4.99`): the floor is retired by evidence, never by time; V3b-3 (#1582, `0.4.100`): a capacity sample is also a delivery. "No behaviour change" still holds — nothing acts on it. Its authorising counter is `goodput_samples` (accepted) reading > 1 on a constrained session; the 2026-09-25 sweep found a three-hour relay session with `pipe_belief_n=(9912, 1)` |
| **V4** | the memory keeps what was MEASURED, damped down-fast/up-slow, and writes nothing when a session measured nothing; deletes the `max` rule, `had_decrease`, the opener arithmetic and its three constants | — | **built 2026-09-08** (net −159 lines), shipped `agent-v0.4.95` (#1542); AC8 half-met |
| **V5** | the gate answers *is this a MEASUREMENT*, which V1 let every consumer read as *does this window say anything at all*. A transit stall above the measured pipe still reaches the rate-limited MD, the ramp verdict, the age streak and the prior's push-back; everything that sets a NUMBER still reads `valid` | — | **built 2026-09-09**, shipped `agent-v0.4.96` (#1552); AC9 open |
| **V5a** | `stall_is_ours` compares the target against the composed `pipe_bps` (goodput → the viewer's arrival rate → the prior), not `blocked_send_bps`: the agent's sends block only when the queue is LOCAL, and on a relay it is downstream | — | **built 2026-09-09**, shipped `agent-v0.4.97` (#1566) — `0.4.96` was inert on CORPLAP-3 (`goodput_samples=(0, 5)`) |
| **Docs** | `docs/rate-control.md` opens with the gate: the verdict, every consumer, V5's exception, the write-back and the seed, and the V3b belief labelled as the shadow it is; `docs/README.md` row updated | — | **2026-09-25** (AC7), in the PR that carries these corrections |

## Acceptance criteria

- [x] **AC1 — the deletion is the deliverable.** V1 removes, with nothing put
      in their place: **2 kill switches** (`transit_hold`, `transit_classify`)
      with their config keys, env flags, `config_surface` entries, accessors and
      the simulator's copy; **4 heartbeat counters → 1**; **7 governor state
      fields → 2** (the hold's counter, T2's quarantine buffer, its pending flag
      and two counters, T2b's counter); **3 per-consumer rules → 1** shared
      predicate. Measured 2026-09-08: the edited files are **net −83 lines**
      (`governor.rs` −42, `encode/mod.rs` −16, the config surface −26,
      `peer.rs` +3); the new gate is 255 lines of which 118 are its own tests
      and 97 are comment, i.e. **~40 lines of logic** for what it replaced.
      `cargo test -p meshharbord --lib` 995 pass, `meshharbor-node-core` 175 pass,
      clippy clean. ⚠️ The overall line count is not negative and is not claimed
      to be: the inventory above is the claim.
- [x] **AC2 — the field events replay.** The 12:15 cell (a hard blocked send
      inside a window whose pump pass overran its budget) cuts nothing and is
      attributed to `agent-stalled`; its control (the same blocked send on a
      free loop) still halves at its own window, so FR-35's reaction is intact;
      the 14:52 cell's report in the stall's shadow does not arm the clamp; the
      B0 `finding_4` cell keeps its rate with the gate on and still cuts with
      the gate off (the control arm, which is no longer a daemon
      configuration). The opener cell is V2's.
- [x] **AC3 — one verdict, one counter.** The heartbeat reports
      `evidence_rejected=[agent-stalled, transit-stalled, stall-shadow,
      carrier-changed]` and nothing else about stalls; every rejected window is
      attributable to a reason.
- [x] **AC4 (V2)** — on a pair remembered from one carrier, a session opened on
      a slower carrier does not open above what that carrier has measured, and
      an opening burst that queued does not raise the memory.
      *Built 2026-09-08: `carrier_tag` puts the carrier in the key (`direct` /
      `tunnel` / `relay:<kind>/<transport>`, from the LocalAPI peer record's
      `relay_kind` and `relay_transport`, so DERP and a UDP relay are different
      memories), with `None` for a mid-churn carrier leaving the pre-FR-79 bare
      key; `opener_growth_target_bps` takes the goodput estimator's measurement
      for a burst that queued, and the bounded step is unchanged for one that
      did not. Cells: the 16:41:51 burst records 3.41 M (the measurement) where
      it recorded 6.0 M before, records nothing when the estimator has no
      confidence, and a direct memory does not seed a DERP session. ⚠️ Entries
      written before this are keyed by the bare address and stop matching; they
      age out with the 7-day TTL, at a cost of one session of learning per pair
      and carrier.*
- [x] **AC5 (V2)** — field: five consecutive sessions on CORPLAP-1 open within
      the carrier's measured range, with no 1.26 M opener and no 6.8 M opener.
      *Met on `agent-v0.4.93`, 2026-09-08 19:12–19:18 UTC (field log): openers
      2.55 / 2.55 / 1.44 / 2.55 / 2.82 M against a measured 1.09–6.13 M.*
- [x] **AC6 (V3a)** — ONE belief, composed in one place. `pipe_bps` is the
      session's answer to "how fast is the pipe" and the only place the sources
      are combined; `blocked_send_bps` is the one named SOURCE accessor, read
      by the opener's write-back alone. Deleted with it: `remembered_candidate_bps`
      (the same law under a second name — the two bodies were identical but for
      a flag), the THIRD copy inlined in `pre_encode_tick`, and the
      `rate_prior_decay` kill switch (flag, env accessor, config key, three
      config-surface entries, the enrollment default and its control test) — the
      prior always decays now, which FR-70 P1 field-verified on 0.4.64 with its
      own same-build FAIL control. Net −92 lines; 996 agent tests and 175
      agent-core tests pass. ⚠️ Not claimed: the three SOURCES (blocked-send
      goodput, the viewer's arrival rate, the decaying prior) are still three
      fields on the governor rather than one `Pipe` type. That move is
      mechanical and buys encapsulation, not behaviour; it is V3b, and this AC
      does not pretend to have done it.
- [x] **AC7** — docs updated with diagrams and a `docs/README.md` row
      (`docs/rate-control.md` gains the gate as its first section).
      *Done 2026-09-25: `docs/rate-control.md` opens with "The validity gate"
      — the verdict (mermaid), what every consumer does with it, V5's
      exception and its control, the write-back and the seed (mermaid, the
      four field reads of the write-back), and V3b labelled as the SHADOW it
      still is; the three deleted config keys are marked deleted, not off;
      history rows 0.4.96–0.4.100; the `docs/README.md` row names the gate.
      Every `file:line` anchor was printed from master on the day.*

- [~] **AC8 (V4)** — field, HALF met, and the second half observed in
      MECHANISM but not yet at the magnitude the criterion names. The memory
      MOVES DOWN on a carrier measured well below what is remembered, the next
      write lowers the entry (before V4 it could only rise), and the openers
      that follow stay inside the carrier's measured range. On a host whose
      opener never queues — CORPLAP-2, every opener on 2026-09-08 — the memory
      stops climbing to the `hi` cap, because an absorbed burst now writes
      nothing at all.
      *First half met on `agent-v0.4.95`, 2026-09-08 22:14–22:17 (field log): two
      idle sessions measured nothing and wrote nothing — value and timestamp
      untouched — where the pre-V4 rule would have recorded 3,825,000 from an
      absorbed burst, a 69 % rise on no evidence, twice.*
      *Second half, read 2026-09-25 from the hosts' own log files over Fleet RPC
      (field log): the down-move has happened once — CORPLAP-2, 2026-09-10
      08:39:41 UTC, `agent-v0.4.97`, `100.65.4.2|relay:derp/tcp`: a 61 s AV1
      session whose opener queued (133 ms worst wait,
      `opener_measured_bps=Some(3201927)`) and whose learner proved 3,187,500
      wrote `evidence_bps=Some(3187500) kept_bps=3210512` from a seed of
      3,233,525 — `damp` exactly (3,233,525 − 0.5 × 46,025), where the max rule
      would have kept 3,233,525. A move the old rule could not make, but by
      0.7 % on a carrier measured 1.4 % below the memory, not "well below", and
      the entry aged out (TTL) before the next relay session on 09-24, which
      adopted 3,386,718 outright — so no seeded opener followed. CORPLAP-1's
      6,131,302 did not move down: its next session (2026-09-10 12:51–14:03)
      measured the relay at 11.55–17.04 M, the learner reached the 8 M cap,
      and the write was `Some(8000000) → 6318171` — one damped step UP; that
      entry has since expired as well. The "well below" case needs a thin relay
      day, the same condition AC9 waits for.*

- [ ] **AC9 (V5)** — field: on a session whose transport stalls repeatedly while
      the target sits above the measured pipe, the target CONVERGES toward the
      measurement instead of climbing through every stall. Read `target_bps`
      against `goodput_bps` across a window drag on CORPLAP-2.
      *The failing run is on record (field log, 2026-09-09 07:41): target
      1,741,055 → 1,928,555 against a measurement of 1,058,145 that never moved
      all session, eleven `transit-stalled` windows, paint age 240 → 4,022 →
      7,784 ms, and a nine-second gap in a two-second heartbeat.*
      *Swept 2026-09-25 across the three relay laptops' daemon log files
      (`KEEP_DAYS = 14` ⇒ 2026-09-10 → 09-25; the 09-09 files are gone): 20
      worker logs, 24,013 heartbeats, 7,442 constrained windows in 8 relay
      sessions, 193 transit stalls — and at every one of the 193 the session
      held NO pipe estimate (`goodput_bps` live in 147 windows in total, never
      in a stalled one; `prior_bps` None in every window pulled), so the
      condition never arose (field log). The negative-control half held at
      scale: 117 of 118 stalls in a three-hour CORPLAP-2 session did not move
      the target. Still open — it needs a stall inside a MEASURED minute on a
      thin relay.*
      ⚠️ **The control is FR-71's finding 4**: a transit stall on a path the
      session is NOT overdriving must still not cut — that is what
      `stall_is_ours` gates on, and
      `finding_4_keeps_the_rate_with_the_validity_gate` must stay green.

**What V5 deletes: nothing.** It splits one predicate in two and removes a
blanket `valid` conjunct from three sites. Per the standing rule, the counter
that authorises the next deletion is **`goodput_samples` (accepted)**: it must
read greater than 1 on a constrained session before V3b collapses `prior`,
`goodput` and `link_rx_bps` into one `Pipe` and deletes two of the three. The
CORPLAP-2 session read `(1, 0)` — one accepted sample and, because the gate
intercepted upstream of the estimator, *zero rejected*: a counter blind to its
own starvation.

## Open decisions

- Whether a `ViewerLate` window is evidence about the pipe. Today it is (only
  `TransitStalled` rejects); the viewer being the limiter says nothing about the
  path's capacity, but the goodput estimator only counts blocked sends anyway.
- Whether the carrier should key the memory (a map per carrier) or clamp the
  seed (one entry, bounded by the live carrier's measurement). Keying remembers
  more; clamping cannot go stale.
- Whether `stall_seen` (FR-70 P1's prior verdict) belongs behind the gate too.
- Whether V5's `stall_is_ours` should read the V3b belief's `capacity_bps`
  once the shadow settles. The 2026-09-25 sweep found the blocked-send source
  live in 2 % of relay windows and a three-hour session with one push-back
  (`pipe_belief_n=(9912, 1)`): with the current sources the rule is inert on
  a healthy relay, which is safe, and on a thin one, which is the AC9 gap. The
  belief's capacity is fed by the same two sources today, so reading it would
  change nothing until a transit stall itself feeds the belief — and what a
  stall with no number attached should feed is exactly what is not settled.

## Out of scope

- The plan handoff (FR-70 M3) and the single controller (M4). This FR makes
  those safe by removing the levers they would otherwise have to preserve.
- The viewer's own stall report (FR-71's first open decision).

## Field-verification log

| when | build | cell | result |
|---|---|---|---|
| 2026-09-08 12:15 / 14:52 / 16:33–16:42 | 0.4.87 / 0.4.90 | CORPLAP-1 on the Check Point VPN, relay | the three events this FR generalises; see FR-71's log for the first two and §The opener for the third |
| 2026-09-08 19:12–19:18 UTC | **agent-v0.4.93** (V1 + V2), my view-only sessions | CORPLAP-1 on the Check Point VPN, HEVC over the relay — the carrier keyed itself `relay:derp/tcp` throughout | **AC5 — PASS, five consecutive sessions.** The pre-FR-79 memory (`100.65.0.5` = 8.0 M, bare key) was correctly ignored, so the first two sessions opened at the 2.55 M relay nominal instead of 6.8 M. Openers: **2.55 / 2.55 / 1.44 / 2.55 / 2.82 M** against a carrier the same sessions measured at **1.09–6.13 M** — every opener inside the measured range, no 6.8 M over-drive and no 1.26 M floor-opener. The write-back is the measurement now: `opener_measured_bps=Some(1440672) growth_target_bps=1440672` (653 KB, 179 ms worst wait — the old rule would have computed 21.9 M and recorded the 8 M cap) and `Some(1087230)` for the next (645 KB, 236 ms → 16.4 M, capped, before). The unqueued branch is untouched (`opener_measured_bps=None`, 256 KB, 0 ms → the ×1.5 step). The memory now holds `100.65.0.5\|relay:derp/tcp` and `100.65.4.2\|relay:derp/tcp` beside the stale bare keys, which age out. `evidence_rejected` per session: `[0,2,2,0] [0,1,1,0] [0,0,0,0] [0,1,1,0] [0,0,0,0]` — every rejection a transit stall and exactly one shadow each, none from an agent stall or a carrier change, and no session cut on one. ⚠️ Open, and honest: DERP's own rate moved 1.09 → 6.13 M inside six minutes, and `record_session` still keeps the MAXIMUM, so the memory ratchets toward the high measurement (session 5 opened at 2.82 M from a 3.32 M seed). It ratchets to something measured now rather than to arithmetic that could not be right, but "max of the measurements" is the next thing to question — a V3 candidate beside the single estimator. |
| 2026-09-08 22:14–22:17 UTC | **agent-v0.4.95** (V3a + V4) | CORPLAP-1 on the Check Point VPN, two view-only sessions over `relay:derp/tcp`, an idle desktop | **AC8, first half — PASS: a session that measured nothing wrote nothing.** Both openers were absorbed by the socket (203 KB and 330 KB, `opener_wait_max_ms=0`, `opener_measured_bps=None` ⇒ `growth_target_bps=0`), the goodput estimator held no confidence for the whole of either session (`goodput_bps=None`, send waits 0.08–0.15 ms, age 51–67 ms, `evidence_rejected=[0,0,0,0]`), and the write-back logged `evidence_bps=None kept_bps=2264993` — the entry kept its value **and its timestamp**. The counterfactual is exact: the pre-V4 rule would have taken the unqueued branch (`opener_maxrate 2,550,000 × 150 %`) and `max(old 2,264,993, 3,825,000)`, writing **3,825,000** — a 69 % rise recorded by a session that measured nothing, twice in three minutes. That is the ratchet this phase removed, caught in the act. **Second half still open**: the memory has not yet been observed MOVING DOWN, because neither session pushed back on the pipe (an idle 1.3–1.4 Mbps desktop over a carrier that carries it). It needs a session whose sends block — the ones that measured earlier this evening had 179–236 ms opener waits on a busier screen — and CORPLAP-1's `100.65.4.2|relay:derp/tcp` still holds **6,131,302** from the max rule as the standing target for it. |
| 2026-09-09 07:41 UTC | **agent-v0.4.95** (V1–V4), operator's own session | CORPLAP-2 (`100.65.4.4`) on `relay:derp/tcp`, AV1 on `av1_nvenc` at 1920×1200, `constrained=true`, an idle desktop with window drags | **AC9 — the FAILING RUN, and the defect V5 answers.** Operator report: *"dragging window jumping to over 140ms and more … now reached even over 1000ms, text blurred, freezing."* Heartbeats: `goodput_bps=Some(1058145)` **for the entire session, never once updated**, with `goodput_samples=(1, 0)` — ONE accepted sample and *zero rejected*, because the gate intercepts upstream of the estimator, so the counter is blind to its own starvation. Against that measurement `target_bps` ran **2,001,750 → 2,189,250 → 1,860,820 → 2,048,320 → 1,741,055 → 1,928,555**, i.e. 1.6–2.1× the measured pipe throughout. `viewer_age_ms` 240 → **4,022** → **7,784**, with a **nine-second gap between 07:41:22 and 07:41:31 in a two-second heartbeat** — the freeze. `pipe_states=[2,25,1,11,0]` and `evidence_rejected=[0,11,2,0]`: eleven transit stalls and two shadows, every one of them discarded, so `age_over`, `link_over` and the hard MD were all false and **the rate ENDED HIGHER than it started**. `bytes_inflight=0`, `send_wait_max_ms=0.3` — the local send queue never filled, which is why nothing sender-side could produce a decrease either. Cause: V1 replaced FR-35's quarantine-and-replay (`observe_window(&held)` + `apply_hard_md` once a stall was confirmed) with an unconditional DROP, and every loop that can lower the rate reads `valid`. ⚠️ Not a codec issue — AV1 and HEVC ride the same loop. ⚠️ The daemon restart the operator read as a crash was not one: no panic in the log and no Windows fault record; four `localapi: config key updated … (takes effect on restart)` writes at 07:30:53 (exec/ssh being enabled) restarted the worker one second later and killed the HEVC session that had started at 07:30:34. |
| 2026-09-09 14:41–14:43 UTC | **agent-v0.4.96** (V5), my own session | CORPLAP-2, same host and same cell as the failing run: AV1 4:2:0 HW (`av1_nvenc`) over `relay:derp/tcp`, `constrained=true`, four window drags | **AC9 NOT met — the cell did not reproduce, and the run is a NEGATIVE CONTROL instead.** DERP measured **4,410,833** this time against a target of **3,151,761**, i.e. the session was *under* its measured pipe, not 1.6–2.1× over it as at 07:41 (1,058,145 measured). `stall_is_ours` therefore never armed, and correctly so. What the run does prove is the half that must not regress: `viewer_age_ms` stayed **64–102 ms** across 80 windows with `bytes_inflight=0` throughout, and the one `transit-stalled` window that did occur (14:42:53, `pipe_states=[1,80,1,1,0]`, `evidence_rejected=[0,1,1,0]`) **did not cut** — the target held at 3,151,761. That is FR-71's finding-4 property holding in the field on the new law: a transit stall on a path the session is not overdriving still costs nothing. ⚠️ **The thin-pipe condition is not summonable on demand** — the same carrier measured 1.06 M at 07:41 and 4.41 M at 14:42, and this FR's own 2026-09-08 log already recorded DERP moving 1.09 → 6.13 M inside six minutes. AC9 needs a session caught while the relay is genuinely thin; the failing arc above is the standing baseline to compare it against. ⚠️ `goodput_bps` fell to `None` at 14:42:31 (the confidence TTL, no further blocked sends) — with nothing measured there is no claim to contradict, so a stall in that state cannot cut either, which is the intended conservative direction and another reason a thin-pipe cell needs live blocked sends to be meaningful. |
| 2026-09-10 08:38–08:39 UTC (read 2026-09-25) | **agent-v0.4.97** (V1–V5a) | CORPLAP-2, AV1 over `relay:derp/tcp`, a 61 s session; read from the host's own `roomlerd.log.2026-09-10` over Fleet RPC | **AC8, second half — the mechanism observed, the magnitude not.** Seeded from `100.65.4.2\|relay:derp/tcp` = **3,233,525**; the opener queued (440 KB, 133 ms worst wait, `opener_measured_bps=Some(3201927)`), the goodput held 3,201,927 for 30 windows, the learner proved 3,187,500, and the write-back logged `evidence_bps=Some(3187500) kept_bps=3210512`. That is `damp(3,233,525, 3,187,500)` to the unit (3,233,525 − 0.5 × 46,025 = 3,210,512.5 → 3,210,512), and the first field write that lowered an entry: the pre-V4 rule, `max(stable 3,187,500, old 3,233,525, growth 3,201,927)`, would have kept 3,233,525. 🔑 One line suffices as proof — `kept` lies between the old value and the evidence, so `kept > evidence` means the entry moved DOWN. ⚠️ Honest bound: a 0.7 % move on a carrier measured 1.4 % below the memory is the rule working, not the "measured well below" scenario the criterion describes, and no seeded opener followed inside the TTL — the entry expired on 09-17 and the next relay session (09-24 08:26) adopted its own 3,386,718 outright. |
| 2026-09-10 12:51–14:03 UTC (read 2026-09-25) | **agent-v0.4.97** | CORPLAP-1, HEVC over `relay:derp/tcp`, 72 min, 2,124 constrained windows | **The 6,131,302 question, answered: it moved UP, damped, on a measurement.** The session opened from the 6,131,302 seed at 5,211,606 (85 %), the opener queued 514 ms but the estimator had no confidence (`opener_measured_bps=None`), and then the relay was fast: goodput **11,550,209–17,044,136** in 88 windows, the learner at the 8 M `hi` cap, and the write-back `evidence_bps=Some(8000000) kept_bps=6318171` — one `ALPHA_UP` step (6,131,302 + 0.1 × 1,868,698 = 6,318,171.8). 69 transit stalls with the target (≤ 8 M) UNDER the measured pipe: no V5 cut is attributable and none should be; the cuts that did happen (12:57:48 8.0 → 5.78 M with `send_wait_max_ms=181`, age 3,435; 13:02:52 5.77 → 3.55 M with `send_wait_max_ms=504`, `bytes_inflight=229397`, age 2,132) are the local queue filling — the AIMD's own occupancy loop and the age loop, in windows the gate did not reject. No relay session has written that key since; it expired on 09-17. |
| 2026-09-25 (logs of 2026-09-10 → 09-25) | **agent-v0.4.97 → 0.4.101** (V5a + V3b shadow throughout) | AC9 sweep of the three relay laptops' daemon **log files** over Fleet RPC — not `roomler logs`, whose 64 KiB tail ages a finished session out; `KEEP_DAYS = 14` had already pruned the 09-09 files (V5's first day and the 14:41 control run) | **AC9 — no natural occurrence; coverage recorded so that "none" is a count.** 20 worker logs (`service-logs\roomlerd.log.<date>`), **24,013 heartbeats, 7,442 constrained windows in 8 relay sessions**: CORPLAP-1 5 sessions / 2,171 windows (09-10, 09-11), CORPLAP-2 3 sessions / 5,271 windows (09-10, 09-24), CORPLAP-3 0 constrained in 14,373 heartbeats (every session direct — `av1_qsv` at a 34.56 M target; the zero positive-controlled by counting `constrained=false`). Transit stalls in those sessions: 118 + 69 + 6 = **193**, and at every one of them the session held **no pipe estimate**: `goodput_bps` was live in 147 constrained windows in total (2 %: one accepted sample per long session, held for its 60 s TTL), never in a stalled window, and `prior_bps` was `None` in every window pulled (7,395 of the 7,442 — no seed in force, or a measurement at the band leaving nothing to stand in). The detector's verdict function (`analyse`, kept outside the repo because it names hosts; its selftest had been lost, so it was re-validated the same day: `NONE` on these rows, `did NOT converge — ratio 1.89x → 1.82x` on an arc shaped like the 07:41 failure, `CONVERGED` on one that steps ×0.85 per stall) reads **NONE**. What the sweep does show is the negative-control half at scale: the three-hour CORPLAP-2 session (`6ab4de94`, 09-24 08:26–11:21, AV1 over `relay:derp/tcp`, `0.4.100`) held its target at the learned 3,386,718 through **117 of 118** transit stalls — the exception, 10:33:30–34, is an 800 ms locally blocked send inside an `agent-stalled` window (the AIMD's own loop, not the gate) — at a paint age of p50 76 / p95 99 / max 988 ms, `bytes_inflight` ≤ 71 KB, and `pipe_belief_n=(9912, 1)`: one push-back with a number in three hours. ⚠️ The condition AC9 needs — a stall INSIDE a measured minute on a thin relay — did not happen in two weeks of fleet traffic, and nothing here can summon it; the 07:41 arc stays the baseline. |
