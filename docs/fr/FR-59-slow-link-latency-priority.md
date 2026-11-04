# FR-59 — Slow-link latency priority: make delay the controlled variable

**Issue:** [#1163](https://github.com/gjovanov/roomler-ai/issues/1163) · **Status:** P1–P8 shipped (0.4.47 → 0.4.50); **0.4.47–0.4.49 regressed the fleet** — see "What the field regression taught"; AC4 open ·
**Parent/siblings:** FR-1 (drag smoothness), FR-14 (direct jitter), FR-15 (age feedback),
FR-17 (partial-reliability video), FR-35 (relay ceiling learns the pair)

## Goal

A remote-desktop session over a genuinely slow link (mobile hotspot, congested hotel/airport
Wi-Fi, throttled VPN) must stay **usable at low latency** rather than degrading into a
seconds-behind slideshow. Concretely: **frame age must track the path floor, not the queue**,
and every rate/queue/resolution decision must be denominated in what the pipe is MEASURED to
carry — not in a nominal band.

Today every controller optimises a *rate* and lets latency fall out. On a slow link that is
backwards, and the result is not merely "no latency priority": the controller **climbs while
the viewer is seconds behind**.

## Root cause — field evidence

Measured 2026-09-01 14:05 UTC, live session `6a96dac3cc1d845926aec5a8`, CORPLAP-3 → neo16,
viewer on a phone hotspot at Sofia airport. `av1_qsv`, 1920×1200, `constrained=true`,
14 consecutive `FFmpeg DC pump heartbeat` windows:

| signal | value |
|---|---|
| **measured pipe** (`goodput_bps`) | **64,850 → 395,122 bps** |
| **encoder target** (`target_bps`) | **1,500,000 → 1,816,834 → 2,133,668** *(climbing)* |
| FR-35 learned ceiling | **5,069,353** (12.8× the pipe) |
| **viewer paint age** | 597 · 655 · 795 · **2,284** · **7,095** ms (floor 110 ms) |
| agent send queue | `bytes_inflight` 1–4 KB, `send_wait_max_ms` **0.09–0.2 ms** |
| shed counters | `frames_dropped_backpressure=0`, `frames_skipped_backpressure=88` (static) |
| encode resolution | 1920×1200 constant, `avg_scale_ms=0.0` — no downscale |
| DataChannel | `dc_ordered=Some(true)` — reliable **and** ordered |
| age reports | `None` in 8 of 14 windows; `viewer_age_implausible=60` |

The agent pushed **1.5–2.1 Mbps into a 0.4 Mbps pipe**, its own queue read empty, and it
therefore **increased**.

### The six mechanisms

1. **A hard 1.5 Mbps bitrate floor.** `MIN_BITRATE_BPS = 1_500_000`
   (`agents/meshharbord/src/encode/mod.rs:202`); on a constrained path `area_min_bitrate_bps()`
   (`:215`) returns exactly it, and `governor.rs:317` passes it as the AIMD's `floor_bps`.
   **The encoder cannot be told to emit less than 1.5 Mbps, ever** — 3.8× the measured pipe at
   best, 23× in the worst window. Every other lever is downstream of a target the encoder is
   not allowed to reach.

2. **The measured-goodput clamp is off on exactly the path that needs it.**
   `governor.rs:299` — `if self.measured_ceiling && !constrained` — is DIRECT-only, disabled
   for relay on 2026-08-27 because lumpy TURN-TCP samples crashed the down-fast EWMA. So the
   relay path has **no rate anchor at all**. And `derived_ceiling_bps` is itself
   `.max(1_000_000)` (`goodput.rs:107`), so even re-enabled it could not describe a 395 kbps
   link.

3. **The AIMD's congestion signal is structurally blind here.** It observes send-channel
   occupancy (`aimd.rs`, module docs). Field: 1–4 KB in flight and 0.1 ms max send-wait *in the
   windows the viewer is 2.3 s behind* — the bytes leave the agent instantly and queue in the
   TURN relay and the carrier. After `AI_SETTLE` (5 s) of "all clear" it additively increases.
   **The loop makes the latency worse.**

4. **The queue budget is denominated in the nominal ceiling.**
   `constrained_queue_budget_bytes(relay_max_bps())` (`rate_profile.rs:360`, called once at
   `peer.rs:4791`) = 3,000,000 × 450 ms / 8000 = **168,750 bytes**. At 395 kbps that "450 ms"
   budget is **3.4 seconds** of standing queue. The gate never fired.

5. **The only true latency signal is silent, rejected, or toothless.** `viewer_age_ms=None` in
   8/14 windows; `viewer_age_implausible=60` (FR-15 P2's plausibility bound discards real
   samples when a mobile probe RTT swings); `AGE_OVER_WINDOWS=2` (`viewer_rate.rs:316`) needs
   *consecutive* over-windows, so the `None` gaps keep resetting the streak. When it does fire,
   `age_over` cuts **fps** and issues an AIMD MD — which stops at the 1.5 Mbps floor.

6. **Video rides a reliable + ordered DataChannel.** FR-17 stage B exists but is behind a
   viewer `localStorage` opt-in (`useRemoteControl.ts:3021`). On a lossy mobile link every lost
   chunk head-of-line-blocks the stream *and* burns scarce capacity retransmitting a frame that
   is already stale. `peer.rs:2872` still records "a gap cannot occur".

Aside, and load-bearing for P6: FR-35's rate memory keys on `nominated_remote_ip`
(`peer.rs:1539`) — on a TURN relay that is the **relay's** address, so a fast office day writes
`5_069_353` into a key a slow airport session inherits for `TTL` (7 days).

## Key design

**Make delay the controlled variable.** Three ideas, in dependency order:

- **A floor is an assumption about the band, not physics.** The 1.5 Mbps legibility floor is
  right for a 2–9 Mbps relay and wrong for a 0.4 Mbps one. It descends **only on evidence** —
  a held goodput measurement below it — never on a guess, and never below an absolute hard
  minimum.
- **Budgets are denominated in the MEASURED rate.** A queue budget in milliseconds is a lie
  unless the bits-per-second it divides by is the pipe's. ⚠️ Consuming a lumpy under-estimate
  for the *queue budget* is safe in a way that consuming it for the *ceiling* is not: an
  under-estimate makes the budget smaller ⇒ more shedding ⇒ **lower latency**, which is the
  direction this FR wants. That asymmetry is why P2 may use the signal that #2 above
  (correctly) refused to use for the ceiling.
- **The signal must come from where the queue is.** The agent cannot see a queue that lives in
  the relay and the carrier. Only the viewer can — and the two viewer-side quantities that need
  neither clock sync nor a plausibility bound are **received bytes per window** (a local byte
  count over a local interval) and the **age *trend*** (a slope; the clock offset cancels in a
  difference). P3.

## Phases

| # | Phase | What | Kill switch | Status |
|---|---|---|---|---|
| **P1** | Evidence-gated floor relief | The AIMD floor descends toward the measured pipe on constrained paths, clamped at `slow_link_min_bitrate_bps`. Evidence = the agent's goodput estimate OR the viewer's arrival rate, whichever is lower | `ROOMLERD_SLOW_LINK_FLOOR=0` / `slow_link_floor` | **implemented** (#1169) |
| **P2** | Budgets in measured rate | `constrained_queue_budget_bytes` re-derived per iteration; a measurement may only ever LOWER the reference | `ROOMLERD_CONSTRAINED_QUEUE_MEASURED=0` | **implemented** (#1169) |
| **P6** | Abandon a contradicted seed | A held measurement more than 2× below `learned_bps` resets the FR-35 learner to nominal | `ROOMLERD_SEED_CONTRADICTION=0` | **implemented** (#1169) |
| **P3** | A signal that can't be fooled | Viewer reports `rx_bps` + queue **growth**, the latter as `Σ(Δarrival − Δwire)` — a difference of intervals, so the clock offset cancels and no probe is needed. Sustained growth caps fps, feeds the AIMD a congestion sample, and bounds the ceiling at 90 % of the arrival rate | `ROOMLERD_VIEWER_RATE_CLAMP=0` | **implemented** (#1169) |
| **P4** | Drain, don't wait | P3's drift INTEGRATED into a depth estimate; past `DRAIN_THRESHOLD_MS` the pump stops producing for a bounded sub-second pause | `ROOMLERD_QUEUE_DRAIN=0` | **implemented** (#1169) |
| **P5** | Slow-link profile, engaged once | Below a measured threshold: resolution + fps capped **at pump start** (never as a mid-session rung — that is why `PRIORITY_RES_CAP` is off by default: an 865 ms blocking QSV rebuild), with a viewer badge | `ROOMLERD_SLOW_LINK_PROFILE=0` | **implemented** (#1169); ⚠️ without P8 it made things WORSE — see below |
| **P7** | Unordered video — the reorder buffer | **FR-17 stage C**: chunks assemble into slots in ANY order and the frame emits whole; a frame overtaken by a newer completed one is abandoned with a gap (→ IDR); partials bounded at 3 | existing `roomler-rc-unordered-video` | **buffer implemented** (#1169); **default flip deliberately NOT taken — see below** |
| **P8** | Reach the encoder | The `coarsen_bitrate` ladder extends below 1.5 M (it was a second copy of the pin P1 removed: every relieved target snapped back to the 1.5 M rung and `set_bitrate` returned without touching the encoder); the additive step is relative (`desired/8`) below the nominal floor so a probe does not overshoot a 300 kbps pipe by 43 % and pay an IDR for it; a pair remembered BELOW the nominal floor **opens at the remembered rate** (the FR-35 learner only ever RAISES the ceiling, so a slow memory never reached the opener) and seeds the floor relief; the idle-refine lift is held while the P5 profile is in force (it was the mid-session rung flip P5 exists to avoid — one native IDR each way, on every heartbeat) | `slow_link_floor` (the opener + the relative step ride on it); the ladder itself has none — it is a table | **implemented** (0.4.50) |
| **T1** | webrtc-sctp FORWARD-TSN parse | Found alongside, not an FR-59 phase: upstream `ChunkForwardTsn::unmarshal` bounded its stream loop by the PACKET buffer, so any chunk bundled after a FORWARD-TSN failed the whole packet — Chrome bundles FORWARD-TSN + SACK whenever it abandons a message on the unreliable `input` channel, i.e. on every viewer→agent loss while the mouse moves; each drop is a lost acknowledgement and the video stalls on an RTO. Vendored (`crates/vendored/webrtc-sctp`, canonical `.patch`, CI drift gate) | none — a parse fix | **implemented** (0.4.50) |

## P7 — why the default flip is not in this PR

The reorder buffer (FR-17 stage C) is done, and it is the half that was
*blocking*: with the strict in-order assembler, turning `{ordered:false}` on made
things **worse**, because chunk 2 arriving before chunk 1 is the common case on an
unordered channel and every such frame read as a break — a keyframe request per
frame, on the thinnest pipe. So the existing opt-in was, in practice, unusable.
It now works, which is what makes a field test of the flip possible at all.

The flip itself is deliberately still opt-in
(`localStorage['roomler-rc-unordered-video'] = '1'`), for three reasons:

1. **It cannot be scoped to slow links.** A DataChannel's ordering is fixed at
   creation, before ICE nominates a pair, so neither side knows yet whether the
   path will be constrained — FR-17 already recorded "constrained-only" as
   un-implementable for exactly this reason. Flipping the default means flipping
   it for every session, direct included.
2. **This FR's own AC4 is still outstanding.** Changing the transport for the
   whole fleet on the strength of unit tests is the "CI green ≠ done" mistake this
   repo has a standing rule against.
3. **The failure mode is silent-ish.** An unordered channel that mis-assembles
   does not error; it produces a keyframe storm, which on a slow link looks like
   the very problem this FR is fixing.

**The flip is one line** — `useRemoteControl.ts`'s `storedUnorderedVideo()` default
— and the criterion for taking it: an airport-class session with the opt-in ON
showing `chunkStragglers` climbing while `chunkGaps` stays flat and fps holds
(stragglers rising with steady fps is the transport working; gaps rising is real
loss costing an IDR each — FR-18's lesson that a counter nothing reads is not
evidence is why both are already in the stats).

## Acceptance criteria

- [ ] **AC1** — On a link measured below 1 Mbps, `target_bps` converges **below** the old
      1.5 Mbps floor and within 2× of `goodput_bps`.
- [ ] **AC2** — `constrained` queue budget in bytes tracks the measured rate: on a 400 kbps
      pipe the byte gate engages (`frames_skipped_backpressure` climbs) instead of standing at 0.
- [ ] **AC3** — A session opening with an FR-35 seed ≥2× above the first measured window logs
      the abandonment and does not run at the seeded ceiling.
- [ ] **AC4** — Field: viewer paint age on the airport-class link falls from the measured
      2,284–7,095 ms band to **under 600 ms sustained**, with the before/after heartbeats recorded.
- [ ] **AC5** — No regression on a healthy relay (CORPLAP-3 from the office LAN) or a direct
      path: `target_bps`, age and `frames_skipped_backpressure` unchanged within noise.
- [ ] **AC6** — Every phase's kill switch restores the prior behaviour, verified by unit test.
- [x] **AC7** (P8) — On a constrained session whose `target_bps` sits below 1.5 M, the encoder
      FOLLOWS it: `bytes_written` per encoded frame ≤ 1.5 × `target_bps` ÷ `target_fps` ÷ 8
      over any 10-window span (the 0.4.49 signature was exactly 1.5 M ÷ fps ÷ 8 per frame
      regardless of target), and a pair remembered below 1 Mbps opens with
      `opener_maxrate_bps` ≤ its remembered rate, not the 2.55 M relay cap.
      **Field-verified 2026-09-02 on 0.4.50** (CORPLAP-1 over the corp-VPN relay): ratio
      p50 0.90 / p90 1.01 against 4.88 / 7.51 on 0.4.49 the same hour; opened at 200 kbps
      from the remembered rate, no opener burst (0.4.49: 457 KB).
- [x] **AC8** (T1) — A session with continuous mouse input over a lossy link logs zero
      `unable to parse SCTP packet chunk too short` (0.4.49 field: 523 in one 4-minute
      LAN session on CORPLAP-3, 171 in a day on CORPLAP-1).
      **Field-verified 2026-09-02 on 0.4.50**: 0 in the AFTER session at 25 mouse events/s,
      against 24 in 2 minutes at 1.7 events/s on 0.4.49 the same hour, same path.

## What building P1–P4 + P6 changed about the design

Four things the plan did not anticipate, all now load-bearing:

1. **P3 is inert without P1.** `AimdController::set_ceiling` raises any ceiling back up to
   `floor_bps`, so the arrival-rate clamp would have been silently undone at 1.5 Mbps — on
   exactly the links it exists for. The two ship together, and the coupling is asserted.

2. **The age *trend* became a queue-growth measurement instead.** The plan said "slope of
   frame age". What shipped is `Σ(Δarrival − Δwire)` — the difference between how fast
   frames were produced and how fast they landed. Same intent, but it needs no `frameAgeMs`
   at all, so it works when the clock probe never locks; and being a difference of two
   intervals, the offset cancels rather than being estimated and bounded.

3. **P1's evidence had to widen.** The goodput estimator needs the agent's own sends to
   BLOCK, and on this link they do not (`send_wait_max_ms` 0.1 ms) — the queue is
   downstream. The floor now takes the LOWER of the agent's estimate and the viewer's
   arrival rate; either alone leaves a real case uncovered.

4. **P4 could not discard anything.** The plan said "discard the queue via `send_epoch`".
   The agent-side queue on this path is 1–4 KB; the queue that matters is in the relay and
   the carrier, already sent and unrecallable. So P4 is a production PAUSE, and — because a
   pause loses no frames — it deliberately does NOT force a keyframe on resume, which at
   these rates would itself be seconds of transit. The kill switch is therefore
   `ROOMLERD_QUEUE_DRAIN`, not the planned `ROOMLERD_AGE_DRAIN`.

## What the field regression taught (2026-09-02, 0.4.47 → 0.4.49)

The operator's report: viewing **CORPLAP-3 went over 3,000 ms** frame age and **CORPLAP-1 over
26,000 ms**. Both hosts were on 0.4.49; both were being viewed from neo16 at home. Read
against the per-session baseline pulled from the same hosts' own logs (p50 / p90 / max of
`viewer_age_ms`, every session since 08-27):

| host · path | before (08-27 → 09-01) | 09-02 on 0.4.49 |
|---|---|---|
| CORPLAP-1, `constrained=true` | p50 **51–95 ms**, p90 58–124 ms across 15 sessions (one 2-h session: p50 62 / p90 72 / max 3,602) | p50 114–542, p90 **2,314–11,220**, max **11,553–22,381** across 8 sessions |
| CORPLAP-3, `constrained=false` (LAN) | p50 **4–8 ms**, p90 16–42 (244 windows, 09-01 19:00 UTC) | p50 26–1,791, p90 1,026–7,450, max **32,584** across 14 sessions |

Two different failures, one per host, and neither was the clamp the handover suspected.

1. **The ladder was a second copy of the pin.** `BITRATE_LADDER_BPS` bottomed at 1,500,000.
   P1 lowered the AIMD floor and the heartbeat dutifully logged `target_bps=200000`, but every
   `set_bitrate` coarsened the target to the rung the encoder already ran at and returned. The
   11:58 session rebuilt its encoder **once**, to 1.5 M, then never again in 4½ minutes while
   the AIMD wandered between 200 k and 1.1 M with `deferred=false` on every line. On the wire:
   **every frame exactly 12,513 bytes** = 1.5 M ÷ 15 fps ÷ 8, into a pipe measuring 20–400
   kbps. ⚠️ This is the same class as design lesson 3 above ("a widening applied to one call
   site and not the other") one level down: the *AIMD* floor was relieved, the *encoder's* was
   not.

2. **P5 multiplied the damage by four.** At the pinned 1.5 M, halving the frame rate from 30 to
   15 fps doubled the bytes per frame; the profile's whole premise ("halving the frame rate
   doubles the per-frame budget") assumed the budget followed the target. 12.5 KB frames at
   8 fps = 800 kbps of 12.5 KB lumps into 300 kbps.

3. **P5 fought the idle refine.** The 11:55 session flipped **1280×800 ↔ 1920×1200 on every
   heartbeat**: the refine lifted the cap for "a crisp native IDR" whenever the scene went
   quiet, motion re-capped it, and on QSV each side of that is an encoder rebuild — one IDR
   each way, 40–78 KB apiece, 1–2 s of link time each. P5's own doc says the mid-session rung
   flip is the thing it was resolved once to avoid; the refine is exactly that flip.

4. **A slow memory never reached the opener.** `seed_bps=387500` was logged and the encoder
   still opened at the 2.55 M relay cap: `CeilingLearner::effective_ceiling` is
   `plan.max(learned)` — it only ever RAISES. So the opener burst 372 KB in 3 s into a ~300 kbps
   pipe (ten seconds of queue) before the first measurement existed, and the 11:53 session's
   4.68 M memory (a fast day carried onto a slow one) did 580 KB — the 26-second age.

5. **The LAN host was a different bug entirely — and it is not FR-59's.** CORPLAP-3's sessions
   were all `constrained=false`, where none of P1–P6 run. Its worst window logged
   `unable to parse SCTP packet chunk too short` **twice a second** while 189 KB sat unacked
   for 3 s on a LAN pair; 523 of them in that one session, 549 in the day, and the count on
   quiet days was 0. That error is webrtc-sctp 0.11.0's FORWARD-TSN parser reading past its
   own chunk (T1 above). The trigger is loss in the viewer→agent direction with mouse input in
   flight; the loss came from the viewer host, which spent the whole morning in an overlay
   net-change storm (below). The IDRs that each stall then had to push were the direct path's
   own: 44 bitrate-swap rebuilds that day against 4 the day before.

6. **The viewer host was not healthy, and that is a separate issue.** neo16's daemon logged
   ~100 overlay carrier revalidations per minute from 10:10 UTC on, triggered by 718 route
   evictions of `fd72:6f6f:6d6c::/96` (the derived-ULA v6 prefix) — 630 of them naming the
   PRIMARY `roomler` adapter as the "competing product", 88 naming `roomler-<org>`: the two org
   runtimes inside one multi-org daemon evicting each other's route, and every eviction a
   Windows route-change notification that pokes every peer. Both corp laptops show the same
   fight (filed as #1237). Chrome on neo16 also auto-updated 151 → 152 at 02:12 UTC that day.
   Neither is FR-59; both are recorded so the next reader does not attribute their effects to it.

What did **not** cause it: the P3 clamp. It latched onto stall-depressed `rx_bps` values
(51 kbps, 87 kbps) exactly as the handover feared, and it did not matter, because nothing below
1.5 M reached the encoder anyway. With P8 it will matter; the 200 kbps hard minimum bounds it,
and the release-on-age rule lets go within a window or two.

⚠️ **Why the harness missed all of it.** `tc netem` shapes downstream of the WSL agent's
socket: the byte gate never saw pressure, no QSV encoder was involved (the WSL agent runs
software), no FR-35 memory existed for the pair, and no packet was ever lost in the
viewer→agent direction. Every mechanism above needs at least one of those. The corp-VPN relay
with an Intel QSV encoder and a remembered pair is the configuration this FR exists for, and
it was the one configuration the A/B never ran on.

## Open decisions

- **Absolute hard minimum for P1.** 200 kbps is the working default. Below roughly this a
  1920×1200 frame cannot be legible at any QP and the honest answer is P5's resolution cap, not
  more bitrate shedding.
- **P3's transport for `received_bps`.** Piggy-backing `rc:decodestat` (as FR-15 did for age)
  keeps the cadence and costs no new message; the alternative is a dedicated report with its own
  interval. Leaning to the piggy-back.
- **P4's drain threshold and whether it is user-visible.** A deliberate 300 ms hitch that fixes
  a 2 s lag is a good trade, but it must not fire on a transient.

## Out of scope

- Corporate-VPN evasion or changing which carrier ICE picks (FR-33 territory).
- Server-side relay fan-out (named as future work in FR-44).
- Audio.

## Field-verification log

| date | version | host / path | result |
|---|---|---|---|
| 2026-09-01 | 0.4.45 | CORPLAP-3 → neo16, phone hotspot (Sofia airport) | **BEFORE**: goodput 65–395 kbps, `target_bps` 1.5–2.13 M climbing, age 597–7,095 ms, `bytes_inflight` 1–4 KB, `frames_dropped_backpressure=0`. The measurement this FR exists for. |
| 2026-09-02 | 0.4.49 | CORPLAP-1 → neo16, WebRTC over the overlay host pair (`100.65.0.5 ↔ 100.65.0.6`), carrier DERP through the corp VPN, `hevc_qsv` | **REGRESSION**: 8 sessions, p90 2.3–11.2 s, max 11.6–22.4 s. Encoder rebuilt once to 1.5 M then pinned (ladder floor); every frame 12,513 B at 15 fps; `target_bps` 200 k–1.1 M ignored; opener 372–580 KB at the 2.55–4.68 M cap; 1280×800 ↔ 1920×1200 refine flap with an IDR each way. |
| 2026-09-02 | 0.4.49 | CORPLAP-3 → neo16, LAN host pair (`192.168.0.24 ↔ 192.168.0.241`), `av1_qsv`, unconstrained | 14 sessions, p50 26–1,791 ms, max 32.6 s. Not an FR-59 path: 523 `chunk too short` (FORWARD-TSN parse, T1) in the worst session, 44 bitrate-swap IDRs of 120–190 KB, the viewer host in a route-eviction storm. Baseline the evening before: p50 4 ms over 244 windows. |
| 2026-09-02 13:24 | 0.4.49 | **BEFORE arm, controlled**: CORPLAP-1 → neo16 over the overlay host pair (carrier DERP through the corp VPN), `hevc_qsv`, ~1.7 synthetic mouse events/s, 60 windows (session `6a98238c`) | `seed_bps=200000` logged, opener at 2.55 M anyway: **457 KB burst**. Refine flap 1280↔1920 at :58, :00, :04, :06. Bytes-per-frame ÷ (target/fps/8): **p50 1.18, p90 5.21, max 7.51**, 26/58 windows over 1.5×. Age p50 102 / p90 1,074 / max 3,522 ms. **24 `chunk too short`** in 2 min. Viewer badge: `292 kbps · 3 fps`. |
| 2026-09-02 14:09 | **0.4.50** | **AFTER arm, same procedure**: CORPLAP-1 → neo16, same pair type, `hevc_qsv`, 25 synthetic mouse events/s (Worker-driven), 33 windows (session `6a982e0f`) | **Opened at 200 kbps** from the remembered rate (no burst). Bytes-per-frame ratio **p50 0.90, p90 1.01, max 2.09**, 2/32 over 1.5× — the encoder follows the target (**AC7 ✓**). Targets 200 k → 320 k by the relative additive step, MD back to 200 k on a path stall. No gate skips, no send stalls. Age p50 86 / **p90 851** / max 3,938 ms — the two spikes are DERP-path stalls (one per drain), not a standing queue. **0 `chunk too short`** with 15× the mouse traffic (**AC8 ✓** on this session). ⚠️ The session ended at 66 s because the laptop hard-rebooted (see below), not by the pump. |
| 2026-09-02 14:11 | 0.4.50 | CORPLAP-1, first 60 s after an unclean reboot | **Latent boot-window panic** (pre-existing, not P8): `Instant::now() - 60 s` at the pump's `last_motion_at` seed underflows on a host up for < 60 s — three sessions started 34–52 s after boot by the viewer's auto-reconnect all died with `overflow when subtracting duration from instant`; the one at +66 s ran. The crash recorder counted them with four 0.4.49 worker aborts and attempted a rollback (GitHub unreachable from the laptop, so it did not run); at +5 min 0.4.50 was promoted to last-known-good. Fixed by `clock::instant_before` at all six seed sites. |
| 2026-09-02 14:13–14:17 | 0.4.50 | CORPLAP-1 → neo16 on a LAN **direct** pair (the overlay latched LAN after the reboot), `hevc_qsv` 1920×1200@60 | Operator's own session: 114 windows, age p50 44 / p90 159 / max 886 ms, bytes-per-frame ratio p50 0.92 — 0.4.50 healthy on the direct path. |
