# FR-71 — Transport stall classification: a transit stall is not an over-production signal

**Issue:** [#1362](https://github.com/jk-zhang-meta/MeshHarbor/issues/1362) · **Status:** proposed 2026-09-05; T1a+T1b+T1c shipped (hold default off); AC2 days 1–4 read (96 % gaps); **AC3 field hold-on half FAILED 2026-09-08 — the hold masks the wrong mover; deletion proposed (§Open decisions)**; **T1b, T2 and T2b were superseded 2026-09-08 by [FR-79](FR-79-one-validity-gate.md)'s one validity gate, which deleted all three and their switches** ·
**Parent:** split out of FR-70 (#1330) on its own open question; FR-70's M0 is this FR's instrument.

## Goal

When the path between the wire and the viewer's decode worker stalls — a
DERP/TCP head-of-line block, a relay reconnect, a Wi-Fi roam — the rate
controller must recognise the window as **transit-stalled**, hold the rate and
let the backlog drain, instead of reading the paint age as "the encoder produced
too much" and cutting the rate into a link that was never the limiter. A repeat
of FR-70's finding 4 must be classified correctly **and** must not cut the rate.

## Why this is its own FR

FR-70's plan asked whether transport classification belonged in the media
pipeline FR or in its own, and answered its own question with the case for
splitting: it is the largest measured harm of the 2026-09-04 findings, it shares
nothing with the threading work except the instrument, and bundling would let
the pipeline FR claim credit for work that had not started. M0 has now delivered
the instrument, so the split is clean: FR-70 keeps the attribution half of its
AC5 (met), this FR owns the response.

## Field evidence

- **Finding 4** (CORPLAP-3, 2026-09-04, session `6a9abaa8`), the operator's
  4903 ms paint:

  ```
  12:33:56  age=None  inflight=5339   goodput=5.60M  iter_max=35.6  skips=1
  12:33:58  age=2851  inflight=2377   goodput=5.60M  iter_max=26.9  skips=1
  12:34:01  age=4903  inflight=1485   goodput=8.51M  iter_max=28.5  skips=24
  12:34:03  age=57    inflight=694    goodput=8.51M  iter_max=323   skips=24
  ```

  Frame age 4903 ms while the send queue held 1485 bytes, the worst pump
  iteration was 28 ms and the encoder averaged 14 ms. Nothing sender-side was
  wrong; the viewer sent no report for two windows; 23 frames were skipped to
  backpressure in the same window because the sender *wanted* to send and could
  not; then goodput jumped to 8.5 Mbps as the backlog drained at once. The AIMD
  and the FR-15 age loop cut the rate anyway, because `viewer_age_ms` fused the
  stall into one number that every loop reads as over-production.
- **The instrument is live** (FR-70 M0, `agent-v0.4.66`, field 2026-09-05): every
  heartbeat carries `age_split = AgeSplit { sender_ms, transit_ms, viewer_ms }`;
  a 45 ms relay age read as 44 ms transit + 1–2 ms viewer + 0.1 ms sender on a
  live pinned-relay path. A stall will read as `transit_ms` in the seconds with
  the other two flat.
- **The simulator already has the cell**: `encode::sim::fixtures::derp_with_stalls`
  (400 kbps with 120 kbps dips and 1–4 s stalls) and `fast_pipe_early_stall`,
  plus the shipped-rule harness (`MeasureRule::OnPushBack`, byte-budget gate,
  rebuild-bound encoder) from #1350 — the law can be verified before a field
  cell is even attempted.

## Key design

### `encode::pipe_state` — the classifier (pure)

One verdict per viewer window from signals the governor already holds:

| state | says | evidence |
|---|---|---|
| `Overproduced` | the sender is the limiter | `send_wait` rising, `inflight` at or over the byte budget, blocked sends (goodput samples accepted), budget-gate skips |
| `TransitStalled` | the path is the limiter | `transit_ms` above its learned floor by more than the slack (200 ms) while `viewer_ms` sits near its own floor; or a viewer report gap — silence from a viewer that has reported at least once this session — while the sender kept writing frames through a queue that passed every `Overproduced` check (as built: the "queue under half the budget" clause of the first draft was dropped — a keyframe on a ramp step trips it for one window, and the sender screen already owns "queue over budget"; the "has reported once" clause was added after the first field session on 0.4.67 classified its opening window `transit-stalled` because the viewer's first report had not arrived yet — silence before any report is `Unknown`, so a viewer that never reports can never hold a session under T1b) |
| `ViewerLate` | the browser is the limiter | `viewer_ms` rising, decode queue deep, `struggling` |
| `Clear` | none of the above | |
| `Unknown` | no split reported (pre-M0 viewer, no age this window) | the loops behave exactly as today |

The floors are learned the way the FR-15 age loop learns its floor (window
minimum, bounded by the probe's half round trip), so a permanently slow path is
not a permanent stall. Pure and `Instant`-explicit, like `slow_start` and
`prior`, so it unit-tests on the default build and runs inside B0.

### The response

- On `TransitStalled`: the AIMD takes **no multiplicative decrease** for the
  window, the FR-15 age loop does not fire, and the FR-59 P3 arrival clamp is
  held rather than re-armed. The FR-59 P4 drain may still pause production —
  a pause is a drain, not a cut, and on a stalled path it is the right move.
  The target stays where it was; when the path recovers the backlog drains at
  the rate the link actually has (finding 4 drained at 8.5 Mbps).
  **As built (T1b, 2026-09-05)**: the verdict is taken at the top of the
  viewer-window tick, before any loop acts, and on a held window (a) the
  opener's ramp neither steps nor ends, (b) the age loop still *learns* but
  does not fire and its over-streak is reset — so the backlog's own elevated
  windows after a stall need two fresh windows to fire, not the stall's
  count, (c) the P3 clamp is neither armed nor released, (d) the rate prior
  takes neither a clean window nor a push-back, (e) the P4 drain runs as
  before. The AIMD's per-frame *additive increase* is untouched (an open
  decision below). Held windows are counted in the heartbeat as
  `transit_holds`.
- On `Overproduced`: exactly today's behaviour.
- On `ViewerLate`: today's viewer-rate cap (fps shedding), no bitrate cut.
- `Unknown`: today's behaviour, unchanged — an old viewer costs nothing.

### Kill switches

`transit_classify` (T1a, default on: shadow classification and counters only)
and `transit_hold` (T1b, default **off** for one release — a controller change
ships behind evidence, FR-63's rule).

### What the T1a cell taught (2026-09-05)

Building the classifier against the simulator corrected the spec in three
places; each is recorded here because the next phase depends on it.

1. **Finding 4's stall sits beyond the ack point.** The agent's `inflight` is
   the data channel's buffered amount, which webrtc-rs decrements on the far
   end's SACK — 1485 bytes in flight during a 4.9 s paint means the viewer's
   SCTP had *acked* those frames. A relay that merely buffered them would
   have left them unacked and backed the sender up into the budget gate.
   Whatever held the frames (the browser's main thread, the worker's queue,
   a DERP → viewer leg whose acks still flowed) did so where the sender cannot
   count them. The B0 freeze fixtures (`PipeSpec::stalls`) model the *other*
   kind — a frozen drain that fills the sender's own queue, which the sender
   can see and the classifier rightly calls `Overproduced` once the queue is
   over budget (`t1a_freeze_stalls_are_sender_visible`). The simulator
   therefore gained `PipeSpec::transit_stalls` — acked on time, *observed*
   late — and the `finding4_transit_stall` fixture (8 Mbps, 80 ms, a 4.8 s
   stall at 12 s), which reproduces the field shape: a 15 KB send queue
   throughout, zero gate skips, and the whole backlog painting at once.
2. **The target keeps climbing through a stall.** Through the stall the
   target stepped 1.82 → 1.98 Mbps. *(Corrected while building T1b: the T1a
   write-up blamed the slow-start ramp; the ramp had ended by 5 s and the
   step is the AIMD's per-frame **additive increase**, which sees a clear
   send queue and no congestion sample. The ramp would behave the same way
   — a silent window carries no congestion bit, so it is a clean window to
   it — and T1b freezes it; whether the hold should also pause the additive
   increase is an open decision.)*
3. **The sim's law did not cut on age.** `GovernorLaw` modelled the FR-15
   age loop's push-back (for the prior) but not its rate *cut*, so the
   finding-4 cell under the shipped rule showed the classification and the
   climb but not the harm. T1b added the cut with the real `viewer_rate::AgeLoop`
   (`GovernorLaw::with_age_cut`, opt-in per cell because the FR-63 and FR-70
   conclusions were taken without it), and a post-ack backlog that drains at
   the link's rate rather than landing in one instant — with those two the
   cell reproduces the field: the backlog spans three windows, the second
   fires the age loop, and the AIMD cuts.

### T2 — a hard stall is a deferred verdict (2026-09-08)

The field's finding-4 shape on the corp-VPN host (§Field-verification log,
2026-09-08 12:15) is not the simulated one. It is a send that BLOCKS for seconds
while the overlay's carrier re-establishes itself — a rekey storm, a re-nomination
— on a pipe that carries exactly what it carried once the pause ends. Four movers
read that blocked send as the pipe's CAPACITY, and each is right about its own
input: FR-35's hard halving (`note_send_stall` → `apply_hard_md`: a send blocked
≥ `HARD_STALL` = 1 s is ×0.5 at once — written for a 7.9 s stall the P0 field
measurement read as a collapsed pipe), the goodput fold that turns the blocked
send into an estimate, FR-59 P6's contradiction that abandons the learned
ceiling on that estimate, and FR-59 P1's floor relief that pins the floor to 85 %
of it. The T1b hold masks the age loop, which never fired.

What separates a pause from a collapsed pipe is not visible in the blocked send
itself; it is visible one window later. A collapsed pipe keeps pushing back —
the next window's sends block too. A pause pushes back on nothing: the next
reported window has no blocked send and the age sits on its floor. So the rule
is the make-before-break principle the carrier ladder already follows, applied
to a measurement: **a blocked send ≥ `HARD_STALL` is a verdict deferred to the
next reported window.** The sample is quarantined instead of folded and the
×0.5 is held pending. The next window that carries a viewer report decides:
if its sends blocked (≥ `MIN_WINDOW_BLOCKED` of blocked time, the estimator's
own qualifying rule), the stall is CONFIRMED — the quarantined samples fold, the
×0.5 applies, P6 and the floor relief see what they always saw, one window
later than FR-35 applied it; if nothing blocked, the stall was a PAUSE — the
samples are discarded, the pending ×0.5 is dropped, and nothing else moves. A
window without a report (a gap) decides nothing; the quarantine waits.

What this is not. Not a new controller: every mover keeps its law, and only the
window in which a hard stall's evidence is READ moves by one. Not a switch: the
next window's own measurement gates it, which is the evidence FR-35 wanted and
did not have at the moment of the stall. The collapsed-pipe case FR-35 built the
halving for reacts one window later (≤ 2 s; the ordinary ×0.85 ladder on send-
channel occupancy still runs from the first frame). The thin-pipe cases FR-59
built the relief for are untouched: a thin pipe blocks sends in every window,
which is exactly the confirmation. Telemetry: `hard_stalls_paused` /
`hard_stalls_confirmed` on the heartbeat, so the field can read which of the two
a host's stalls were — and after a week of both counters, whether T1b's hold has
anything left to do.

Fail-first: `a_hard_stall_followed_by_a_clean_window_is_a_pause_and_cuts_nothing`
(governor unit test, the 2026-09-08 numbers: a 6.6 M learned ceiling, one send
blocked 2.9 s, then a clean reported window) against the shipped laws, then
against T2; `…_followed_by_a_blocked_window_is_confirmed_and_halves` is the
control that keeps FR-35's reaction.

### T2b — the stall's shadow covers the viewer's report too (2026-09-08)

T2's first field hour on 0.4.90 (§Field-verification log, 14:52) showed the same
root with a different input. A carrier demotion stalled the relay for six seconds;
the hold kept 7.45 M through three `transit-stalled` windows with 0 B in flight,
and T2 had nothing to defer because no send blocked for a second — the byte-budget
gate skipped frames instead. The cut came through the VIEWER: its arrival-rate
report for the stall (70 kbps arrived while its queue grew) landed in the first
window after the stalled ones, when the sender's queue read over budget and the
hold was therefore off, and FR-59 P3's arrival-rate clamp set the target to
834,800 from it; P6 abandoned the learned ceiling on the widened measurement in
the same tick. −89 % for a report that described the stall, not the pipe.

The rule is the same one, read one window wider: **a window in the shadow of a
`transit-stalled` window — the first one after it — is still the stall's, and the
viewer link report that lands there is not the pipe's rate.** The arrival-rate
clamp neither arms nor releases on it (exactly as on a held window); the window
after that is the pipe again, and a growing report there acts as before. The
trigger is T1a's own verdict, taken from the previous window before this one is
classified, so no new sensor and no threshold is added. Heartbeat
`stall_shadowed` counts the reports discarded this way.

Fail-first: `a_link_report_in_the_shadow_of_a_transit_stall_does_not_arm_the_clamp`
(the 14:52 numbers: three stalled windows, then a report of 70 kbps with a growing
queue in an over-budget window) arms the clamp on T2 and does not on T2b; the same
test then shows the clamp reading a growing report again two windows later.

## Phases

| Phase | What | Kill switch | Status |
|---|---|---|---|
| **T1a** | `encode::pipe_state` + heartbeat `pipe_state` + per-state counters; the B0 fixtures classified under the shipped-rule harness | `transit_classify` | **built 2026-09-05** ([#1366](https://github.com/jk-zhang-meta/MeshHarbor/pull/1366)), shadow only — AC1's sim/unit half met (see *What the T1a cell taught*); the fleet half (AC2) waits for the next agent release |
| **T1b** | the hold: no MD, no age-loop fire, clamp held on `TransitStalled` | `transit_hold` (default off) | **built 2026-09-05** — the verdict precedes every loop in the tick; ramp frozen, age loop masked + streak reset, clamp held, prior held, `transit_holds` in the heartbeat; default **off** |
| **T1c** | the cells: `finding4_transit_stall` in B0 (the law), then the corp-VPN DERP path (the field), each shown to FAIL with the hold off first | — | **sim half done 2026-09-05**: the FAIL recorded (`t1c_finding_4_cuts_the_rate_with_the_hold_off`), the hold's cell green (`t1b_finding_4_hold_keeps_the_rate`), the no-stall cells byte-identical with the hold on and off; the field half waits for the release |
| **T2** | a hard stall is a deferred verdict: a blocked send ≥ 1 s is quarantined and the ×0.5 held pending until the next REPORTED window — sends still blocking confirm it (fold + halve, one window late), nothing blocking is a pause (discard, no move) | — (the next window's own measurement gates it) | **built 2026-09-08**, test-first on the 12:15 numbers; field gate on the release carrying it |
| **T2b** | the stall's shadow: the first window after a `transit-stalled` one is still the stall's — the viewer link report landing there neither arms nor releases the arrival-rate clamp; heartbeat `stall_shadowed` | — (T1a's verdict gates it) | **built 2026-09-08**, test-first on the 14:52 numbers; field gate on the release carrying it |

## Acceptance criteria

- [x] **AC1** — the classifier locks in unit tests and on the B0 stall fixtures
      under the shipped-rule harness: every stall window is `TransitStalled`,
      every budget-gate window on the thin pipe is `Overproduced`, a decode
      backlog is `ViewerLate`, a pre-M0 window is `Unknown`. *(2026-09-05,
      T1a: `t1a_finding_4_stall_windows_classify_as_transit_stalled` — all
      four silent windows and the backlog window `TransitStalled`, none
      `Overproduced`, every window either side `Clear`;
      `t1a_thin_pipe_budget_windows_classify_as_overproduced`;
      `t1a_freeze_stalls_are_sender_visible`; `ViewerLate` and `Unknown` in
      the unit tests — the sim's viewer decodes instantly, so it cannot
      produce a decode backlog.)*
- [ ] **AC2** — one release of shadow classification across the fleet, reviewed
      from `agent_logs`: no constrained session classified `TransitStalled`
      while its send queue was over budget, and finding 4's shape classifies
      as `TransitStalled` in replay. *(First session read 2026-09-05 on
      0.4.67, CORPLAP-1 over a pinned TURN relay, `6a9c3933`, 90 windows:
      89 `clear`, 1 `overproduced` — the lock-screen transition burst that
      skipped 18 frames at the budget gate, the right verdict — and 1
      `transit-stalled`, which was the OPENING window, before the viewer's
      first report: a start-of-session false positive, fixed in this FR's
      third PR by requiring a prior report before silence counts as a gap.
      Nothing was classified stalled while over budget. The fleet-wide
      review still needs a release with the fix and a week of sessions.)*
      *(First fleet data, 2026-09-05 19:37 UTC, the operator's own sessions
      on 0.4.69 — hold off, start-gap fix in — read at 600 heartbeats each:
      CORPLAP-1, relay: `[2176 unknown, 0 clear, 3 overproduced, 35
      transit-stalled, 0 viewer-late]` — that viewer sent no split (an older
      bundle or a non-web client), so every reported window is `unknown` and
      the 35 stalls are all report gaps, ~1.6 % of windows, about one a
      minute. CORPLAP-2, relay: `[2, 2125, 0, 40, 1]` — split present, 40
      stalls (1.9 %), 1 viewer-late, 0 overproduced. CORPLAP-3, direct: all
      zero, the classifier runs only when constrained. AC2's condition still
      holds — nothing stalled while over budget — but the counters could not
      say how many of those stalls were gaps, and with the hold on a long
      relay session would take ~35–40 one-window holds per half hour. The
      heartbeat now carries `pipe_gap_stalls` (the gap subset of the
      transit-stalled count) so the week's review can count gap-holds and
      split-holds apart; whether the gap rule needs two consecutive silent
      windows is decided from that counter, not in advance.)*
      *(Day 1 with the counter, 2026-09-05 on 0.4.71: CORPLAP-2, the host
      whose viewer reports the split, read `[0, 2758, 1, 22, 0]` with
      `pipe_gap_stalls=22` over 93 minutes — every `transit-stalled` window
      was a report gap and the split rule fired zero times on a healthy
      relay; CORPLAP-1 read 4 of 4. So far the hold would only ever have
      acted on gaps.)*
- [ ] **AC3** — with `transit_hold` on, a repeat of finding 4 shows **no rate
      cut** during the stall and recovery within the stall's own length; the
      same cell with the hold off still cuts — the FAIL recorded first.
      *(Sim half met 2026-09-05: hold off — the AIMD cuts 1.98 → 1.5 Mbps on
      the backlog's second window; hold on — no window below the pre-stall
      target, seven windows held, first clear window 3.2 s after the stall
      lifted against a 4.8 s stall. The field half needs a release with the
      hold on and a repeat of finding 4's path.)*
      *(Field FAIL half recorded 2026-09-06, hold off, 0.4.75, CORPLAP-1
      over the relay: 09:03:26–35 overlay `REKEY_TIMEOUT` ×4 and
      make-before-break direct probes that "kept relay", then at 09:03:37 an
      8.4 s pump pass entirely in `other_ms` and, immediately after,
      `set_bitrate ceiling 3.0M target 1.5M` — the AIMD cut the rate for a
      transport stall; at 10:14:21–23 a `PC Disconnected → selected pair
      changed → Connected` re-nomination, a 5.5 s pass, the same cut. Finding
      4's class, recurring on its own. `transit_hold = true` is set on
      CORPLAP-1 from that day — effective at its next daemon restart — and
      the hold-on half waits for the next natural reconnection there.)*
      *(Field hold-on half 2026-09-08, 0.4.87, CORPLAP-1 on the Check Point VPN
      over the relay, `transit_hold` on, session `6a9fed1d`: **FAIL** — the
      repeat came at 12:15:18 (an overlay `REKEY_TIMEOUT` storm with
      make-before-break probes, two pump passes stalled entirely in `other`,
      2.9 s and 7.4 s) and the rate went 6.60 → 3.30 → 3.00 → 2.55 → 1.35 → 0.68 M
      in 36 s, back at 3.0 M only ~3 min later. The hold engaged on its three
      windows and prevented nothing: it masks the age loop on `transit-stalled`
      windows, and none of the four movers that cut is the age loop — the hard
      halving on a blocked send ≥ 1 s (`note_send_stall` → `apply_hard_md`),
      FR-59 P6's seed contradiction and P1's floor relief fed by the goodput
      measured FROM those blocked sends, and the over-budget ×0.85. See the
      field log and the open decision below.)*
- [ ] **AC4** — no regression on the LAN, direct and thin-pipe cells (peak
      paint, settle time, over-drive integral unchanged within noise).
      *(Sim half met 2026-09-05: the thin pipe, the LAN burst and the genuinely
      slow relay trace **byte-identical** with the hold on and off and hold
      nothing — `t1b_hold_is_inert_where_nothing_stalls`. Field half, first
      point, the same day on 0.4.68: a healthy pinned-relay session with the
      hold ON climbed 2.55 → 3.0 Mbps exactly as the hold-off session had,
      with one benign gap-hold — see the field log.)*
- [ ] **AC5** — FR-70's AC5 closes here, and FR-63 B1's controller consumes
      `PipeState` rather than re-deriving it.
- [ ] **AC6** — with T2 live, a repeat of the 2026-09-08 12:15 shape (a blocked send ≥ 1 s inside a rekey storm on the corp-VPN relay, the pipe intact after) shows `hard_stalls_paused` counting, no ×0.5, the learned ceiling kept and the floor unrelieved — and a genuinely thin pipe (the FR-59 hotspot cell or its B0 fixture) still confirms and halves one window late.


## Open decisions

- **Whether T1b's hold should be deleted, and what replaces it (2026-09-08).** The
  field's finding-4 shape on the corp-VPN host is not the simulated one (post-ack
  paint age with a tiny queue): it is a pump pass stalled in `other` by the overlay's
  rekey storm and probe waits, during which the DC send blocks for seconds — and
  the blocked send is then read as a MEASUREMENT of the pipe by four movers (the
  FR-35 hard halving, FR-59 P6's contradiction, FR-59 P1's floor relief, and the
  over-budget AIMD). The hold masks only the age loop, which never fired. On four
  days of fleet data the hold engaged 30+ times on one-window report gaps and
  prevented no cut. Direction that removes reasons for code rather than adding
  one: (a) ONE validity rule shared by every estimator — a blocked send that spans a
  pump STALL pass is not a measurement of the pipe (the goodput sink discards it), so
  P6, the floor relief and the hard halving see no false evidence; (b) FR-70 M3 for
  the stolen thread itself; (c) then delete `transit_hold` (T1b), keeping T1a's
  classifier as the instrument.
- Whether the viewer should report stalls directly (a gap in arrivals with a
  non-empty decode queue) so the agent does not infer them from the split alone.
- Whether `TransitStalled` should also suppress the FR-35 learner's decrease
  follow-through (a stall is not evidence the pair cannot carry the ceiling).
- How long a hold may last before it is treated as a real capacity change
  (`MAX_LIFETIME`-style bound, so a path that never recovers still converges).
- Whether a viewer *report gap* should be held on at all under T1b. T1a
  classifies it `TransitStalled` (the sender passed every check and kept
  sending), but a hidden tab produces the same gap; holding the rate is more
  conservative than today's climb either way, and AC2's fleet review is
  where the gap's real causes get counted before the hold ships.
- *(Live data on the report-gap question, 2026-09-05, 0.4.68 hold-on session
  `6a9c50e1`: a healthy relay session produced one report-gap window in ~45
  and the hold engaged on it — the cost was one skipped ramp step, taken the
  next window. Benign at that rate; the fleet review should count gap-holds
  separately from split-holds before the default flips.)*
- Whether the hold should also pause the AIMD's per-frame **additive
  increase**. During a transit stall the send queue is genuinely clear and no
  congestion sample arrives, so the increase keeps stepping (+160 kbps per
  window in the finding-4 cell); a marginal pipe backs the sender up and is
  `Overproduced`, not held, so the exposure is a fast pipe climbing during a
  stall it cannot see. Left running in T1b; the shadow's `transit_holds`
  beside `target_bps` in `agent_logs` is where the answer will come from.

## Out of scope

The relay itself — why DERP/TCP head-of-line blocks and how to leave the relay
(FR-19 peer relays, FR-64 remote control off the overlay); the media thread
(FR-70 M1–M5); the diag HUD rendering of the split.

## Related

FR-70 #1330 (M0's split is this FR's instrument; its T1 row now points here),
FR-59 #1163 (P3 link loop, P4 drain), FR-15 (age loop), FR-63 #1243 (B1
consumes `PipeState`), FR-64 #1244, FR-19 #805.

## Field-verification log

| when | build | cell | result |
|---|---|---|---|
| 2026-09-04 12:34 UTC | 0.4.59 | CORPLAP-3 → neo16, DERP path, session `6a9abaa8` | **the FAIL on record**: 4903 ms paint with a 1485-byte send queue; the rate was cut into a link that was never the limiter |
| 2026-09-05 | T1a branch (simulation, not the field) | `finding4_transit_stall` under `run_shipped` | classifier: windows 13–17 s `transit-stalled`, nothing `overproduced`, all others `clear`; the sender's queue stayed at 15 KB through the stall (finding 4's 1485 B) and the target **kept climbing** through it (1.82 → 1.98 Mbps — the AIMD's additive increase; the ramp had ended by 5 s) |
| 2026-09-05 | T1b branch (simulation, not the field) | `finding4_transit_stall` under `run_shipped` + `with_age_cut`, hold **off** | **AC3's FAIL, recorded**: with the post-ack backlog draining at the link's rate the paint age reads 4497 / 2652 / 446 ms over windows 17–19, the age loop fires on the second and the AIMD cuts 1.98 → 1.5 Mbps into an 8 Mbps link |
| 2026-09-05 | T1b branch (simulation, not the field) | the same cell, hold **on** | no window below the pre-stall target; 7 windows held (13–19 s); the P3 clamp and the prior untouched; first clear window at 20 s, 3.2 s after a 4.8 s stall lifted; windows 22–40 s clear. Thin pipe / LAN burst / genuinely-slow relay: traces byte-identical with the hold on and off, 0 held |
| 2026-09-05 15:46–15:48 UTC | **0.4.67** (`transit_classify` on, `transit_hold` off) | CORPLAP-1 → neo16, ICE pinned to a TURN relay (`ice_relay_tcp`, reverted after), session `6a9c3933`, HEVC 1920×1200, `c=true`, age 44–47 ms = 0.1 sender + 44 transit + 1–2 viewer | **the shadow's first live read**: `pipe_states=[0, 89, 1, 1, 0]` over 90 windows. The one `overproduced` window was the lock-screen transition (18 budget-gate skips, target 4.15 → 3.52 Mbps, goodput measured 22 Mbps on the burst) — correct. The one `transit-stalled` window was window 1, before the viewer's first report — a start-gap false positive, fixed the same day (silence counts as a gap only after a report). `transit_holds=0` (hold off). No window read `unknown`: the 0.4.67 viewer stamps every window |
| 2026-09-05 17:27–17:29 UTC | **0.4.68** (`transit_classify` on, **`transit_hold` on** — the first hold-on session), with the start-gap fix | CORPLAP-1 → neo16, ICE pinned to a TURN relay, the corp VPN up (the pill read `relay · VPN captures the host's LAN`), session `6a9c50e1`, HEVC 1920×1200, `c=true`, age 48–75 ms | window 1 now `unknown` (the start-gap fix, working). ~45 windows: one `overproduced` (the lock-screen click burst, 35 gate skips — correct), one `transit-stalled` at ~17:27:07 with **`transit_holds=1` — the hold engaged once**, on a viewer report gap (transit stayed 50–75 ms against a 200 ms slack, so the split rule did not fire; the gap rule did). What the hold cost: the ramp skipped that window's step and stepped the next (2.74 → 2.93 Mbps); target climbed 2.55 → 3.0 Mbps exactly as the hold-off session had. **AC4's field half on a healthy relay path: no regression with the hold on.** Reverted after (hold off, pin off, restart) |
| 2026-09-05 18:52–19:37 UTC | **0.4.69** (classify on, hold off), the operator's own sessions, read at 600 heartbeats | CORPLAP-1 relay `6a9c6658` · CORPLAP-2 relay `6a9c6688` · CORPLAP-3 direct `6a9c64d6` | **AC2's first fleet data**: CORPLAP-1 `pipe_states=[2176, 0, 3, 35, 0]` — no split from that viewer, so `unknown` throughout and the 35 stalls are report gaps (~1.6 %); CORPLAP-2 `[2, 2125, 0, 40, 1]` — 40 gap-or-split stalls (1.9 %), 1 viewer-late; CORPLAP-3 all zero (direct, unconstrained). Nothing stalled while over budget. The counters could not split gaps from real stalls — `pipe_gap_stalls` added the same evening |
| 2026-09-05 20:57–21:54 UTC | **0.4.71** (classify on, hold off, `pipe_gap_stalls` live), the operator's own sessions | CORPLAP-1 relay `6a9c8232` (~500 windows, viewer without split) · CORPLAP-2 relay `6a9c8430` (2781 windows, ~93 min, split present, age 60–80 ms) | **AC2 day 1 with the gap counter**: CORPLAP-1 `[497, 0, 4, 4, 0]`, `pipe_gap_stalls=4` — 4 of 4; CORPLAP-2 `[0, 2758, 1, 22, 0]`, `pipe_gap_stalls=22` — **22 of 22**. On the host whose viewer reports the split, the split rule produced ZERO `transit-stalled` verdicts in 93 minutes on a healthy relay; every stall was a report gap (0.8 % of windows, one per ~4 min). Nothing stalled while over budget. With the hold on, every hold on a healthy path would be a gap-hold — the two-consecutive-windows question now has its first number; the decision waits for the week and for a natural finding-4 repeat (AC3) |
| 2026-09-06 08:20 UTC | **0.4.71** (classify on, hold off), the operator's morning sessions | CORPLAP-1 relay `6a9d1d06` (~500 windows, no split) · CORPLAP-2 relay `6a9d1d9b` (~1140 windows, split present) | **AC2 day 2**: CORPLAP-1 `[1260, 0, 0, 19, 0]`, `pipe_gap_stalls=19` — 19 of 19; CORPLAP-2 `[1, 1126, 1, 10, 0]`, `pipe_gap_stalls=10` — 10 of 10, the split rule fired zero times again. Two days, four sessions, ~7000 windows: every `transit-stalled` verdict was a report gap |
| 2026-09-06 09:03 + 10:14 UTC | **0.4.75** (classify on, hold off), the operator's session | CORPLAP-1 relay `6a9d2bfa`, HEVC, `c=true` | **AC3's field FAIL, found naturally**: overlay `REKEY_TIMEOUT` ×4 + direct probes that kept the relay → an 8.4 s pump pass entirely in `other_ms` → `set_bitrate ceiling 3.0M target 1.5M`; then a `PC Disconnected → selected pair changed → Connected` re-nomination → a 5.5 s pass → the same cut. A re-nomination sends no frames, so the viewer goes silent and the classifier reads a **gap** — on these hosts a gap-hold may be the right action, which reframes the one-vs-two-silent-windows question. `transit_hold = true` set on CORPLAP-1 (effective at its next restart) for the hold-on half |
| 2026-09-07 (read 16:12 UTC) | **0.4.79** (classify on, hold off on this host), the operator's sessions | CORPLAP-2 relay, av1_nvenc, `constrained=true`: a 66-min session (3,816 windows) and a 7.8-min one (454) | **AC2 day 3**: 53 `transit-stalled` of 3,816, **52 report gaps**; 24 of 454, 20 gaps. The 4–5 non-gap stalls are viewer-age spikes (~50 → 390 ms) with the sender idle — inflight 0, send wait ≤ 0.7 ms — i.e. finding 4's shape beyond the ack point, and the target held 3.0 M through them: the split rule classified them and the AIMD did not cut. ⚠️ The heartbeat's `pipe_state` (current window) and the `pipe_states` histogram are offset by one window when read side by side — count from the histogram deltas. Days 1–3: gaps are 94 % of classified stalls. CORPLAP-1 (hold on) ran direct all day, so AC3's hold-on repeat still needs a relay day there. |
| 2026-09-08 07:48–09:13 UTC (read 09:20) | **0.4.85** (classify on, hold off on this host), the operator's sessions | CORPLAP-2 relay, hevc_nvenc, `constrained=true`: 8 sessions, six of 2.5–23 min (685 / 345 / 302 / 265 / 633 / 76 heartbeats) | **AC2 day 4**: 86 `transit-stalled` verdicts, **82 report gaps**, 4 by the split rule. Days 1–4: 209 of 218 (96 %) are gaps. **The split-rule verdicts include a natural repeat of finding 4 with the hold off** (`6a9fca12`, 08:48:11–21): age 50 → 127 → 368 ms with the sender idle (0 bytes in flight, send wait 0.03 ms; split transit 342 / viewer 26 ms), `transit-stalled` at :13 → the AIMD cut 3.0 → 2.55 M at :14; two silent windows (gaps); +187.5 k at :19 (the additive increase through the stall); then cuts to 2.33 M at :20.5 and 1.98 M at :21.5 on a second split-rule verdict (age 256 → 230, transit 229, still 0 in flight) — **−34 % in 7 s for a transit spike the classifier had named, and a 30 s climb back** (3.0 M again at 08:48:52). That is AC3's FAIL in the age-cut flavour, on the split-present host; with the hold on, each of those windows was a hold. Two side notes. `6a9fc69f` (08:26) opened **unconstrained** for 4 s (`c=false`, target 54.9 M) before the relay verdict set 3.0 M — the opening burst took 7.7 s to drain (age 7,679 ms, send wait max 434 ms) and the `overproduced` verdict cut, correctly: a transport-known-late class, one instance. And `6a9fca12` opened at 200 k from a pair remembered at 145 k (`5.9.157.226`), reached 3.0 M in 130 s, and closed the memory at 3.0 M (`rate_memory.json`, 08:49:50) — FR-70 P1's decay plus FR-35 P3's growth working; the seven neo16-pair sessions opened at 2.7–6.8 M and were at ≥ 2.9 M within 6 s. CORPLAP-1 (hold on) ran direct all day again. |
| 2026-09-08 12:15:18–12:16:03 UTC | **0.4.87** (classify on, **hold on**), my view-only session `6a9fed1d` (a hidden automation tab) | CORPLAP-1 on the Check Point VPN, HEVC hevc_qsv, pill `relay · VPN captures the host's LAN`, steady at age 50 ms with the learned ceiling at 6.60 M and 0 B in flight | **AC3's field repeat with the hold on — FAIL.** An overlay `REKEY_TIMEOUT` storm (≈20 lines 12:15:21–12:16:16) with make-before-break LAN probes waiting 8–12 s stalled two pump passes with every timed phase at 0 ms (`other_ms` 2,884 at :21 and 7,386 at :55); the send task's blocked sends read 2,900 / 7,404 / 1,872 ms; viewer age 1.5 s / 1.25 s / 2.2 s (8.7 s by the viewer's own report at :58); 170 frames skipped at the budget gate. The rate: 6.60 → **3.30 M** at :21 (a blocked send ≥ 1 s is a HARD stall — `note_send_stall` → `apply_hard_md`, ×0.5 at once, `deferred=false`) → **3.00 M** 16 ms later (FR-59 P6: the goodput measured FROM those blocked sends, 1.58 M, "contradicts the learned ceiling — abandoning it"; the learner's step-ups to 3.19 M at :32, :37 and :42 were each abandoned within 30 ms while that goodput stood) → 2.55 M at :46 (over-budget ×0.85) → **1,345,142** at :55 (the second hard halving, pinned at the RELIEVED FLOOR = 85 % of the same goodput, FR-59 P1) → **677,760** at :57 (a third blocked send ≥ 1 s) — **−90 % from 6.6 M in 36 s**, then +12.5 % per 5 s from 762 k, 3.0 M again only at ~12:19 and the 6.6 M ceiling gone for the rest of the session. The hold engaged on its three windows (`transit_holds` 24 → 27: one gap, two split verdicts with age 1,253 and 2,172 ms) and prevented nothing — every cut came from a mover the hold does not mask. Earlier in the same session and the one before it (10:41–12:15, both hold on): 35 report-gap verdicts, 35 holds, zero cuts from them; one −15 % age-loop cut at 10:59:46 on a 151 ms age blip with 0 B in flight, below the classifier's 200 ms stall rule, back in 15 s. |
| 2026-09-08 13:35–14:14 UTC | **0.4.90** | release | T2 (#1513 → `94003411`). The tag `agent-v0.4.90` is the FR-77 session's (bump #1514 → `283361e7`, tagged 13:45 UTC from a master that already carried T2; my own bump #1515 → `39617cfd` landed after it as a no-op duplicate). 28 assets, published 13:58. CORPLAP-3 self-updated at 14:01:31; CORPLAP-1 (pid 20528, 14:11:54) and CORPLAP-2 (pid 4604, 14:13:01) updated by the idle one-shot task while their pumps had been quiet for an hour. Field gate open (AC6): a rekey-storm repeat on CORPLAP-1 over the relay with `hard_stalls_paused` counting and no ×0.5. |
| 2026-09-08 14:52:37–14:53:25 UTC | **0.4.90 (T2 live, hold on)**, my view-only session `6aa01ab8` on auto (HEVC-DC, hevc_qsv, relay) | CORPLAP-1 on the Check Point VPN, steady at age 64 ms with the learned ceiling at 7.45 M and 0 B in flight | **AC6 read — FAIL, through a third input.** 14:52:37 the overlay demoted the carrier to the viewer's peer onto DERP ("following it onto DERP now"); :39 a gap, :41 age 2,135 ms (transit 2,134), :43 age 3,626 ms (transit 3,624) — three `transit-stalled` windows, all held, **the target stayed at 7.45 M through them** (T1b doing its job; on 12:15 the hard halving had cut here). No send blocked ≥ 1 s (max 278 ms; the byte-budget gate skipped 83 frames instead), so T2's deferral never engaged (`hard_stalls_paused`/`confirmed` 0). The cut came through the viewer: its link report at :43 read 70,340 bps of arrivals with a growing queue (`link_ceiling_bps=70340`, not yet congested), the next at :44.16 `link_congested=true link_ceiling_bps=834800`, and at :44.84 the P3 arrival-rate clamp set **834,800** (ceiling 7.45 M, `deferred=true`) — the :45 window's verdict was `overproduced` (250 frames skipped, inflight over budget), so the hold was off and `link_acts` went through; 30 ms later P6 abandoned the learned ceiling on the widened measurement (goodput 4.29 M from the drain vs 7.45 M). :45.85 target 1.5 M (the floor, once the clamp lifted with `link_ceiling_bps=20 M`), then +187.5 k per 5 s: 3.0 M at 14:53:25, the learner re-stepping from the nominal (3.19 → 3.39 → 3.60 M …), 3.82 M by 14:56, 4.06 M by 15:11 — **the 7.45 M ceiling lost for the session, −89 % for one report that described the stall.** T2b written from it. |
