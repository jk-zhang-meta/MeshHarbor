# The media pipeline leaves the runtime — three planes, one owner each

**Status:** proposed, 2026-09-04 · **FR:** FR-70 · **Supersedes nothing; re-frames**
`rate-control-architecture` (FR-62 / FR-63 / FR-64) and FR-65.

## Why this plan exists

The operator's words, and they are the requirement: *"the whole thing feels like a
big patch work even though we said we will build proper architecture — no sync
processes (thread-offloaded) for relay-based connections, start and on-going,
and reduce the patch-work to minimum."*

That is a fair reading of the code. `encode/` carries **34 rate/quality
heuristics, 8 estimators of one quantity and 11 kill switches**, and every
FR-62/63/65 phase so far has added one more lever rather than removing the
reason a lever was needed. This plan states the structural change that makes the
levers unnecessary, and lists what gets **deleted** as its acceptance criterion.

## What the field actually shows (2026-09-04, all three CORPLAP hosts)

Four findings, and they do not have one cause. That is the point: a single
"latency" symptom has been absorbing four unrelated problems, which is exactly
how patch-work accumulates.

| # | finding | evidence |
|---|---|---|
| 1 | **The encoder open blocks every session's first frames** | `open_ms` 457/495/736/762 (CORPLAP-1), 912 (CORPLAP-2), 292–957 (CORPLAP-3). Every session, every host. |
| 2 | **Five regions between the loop top and capture were untimed** | `other_ms` 157–347 ms (CORPLAP-1 at drag onset); CORPLAP-2 passes of 662 and 782 ms with capture AND encode both zero |
| 3 | **CORPLAP-3 is encode-bound** | single frames at 221, 317, 322, 346, 502 ms |
| 4 | 🚨 **The worst excursion is TRANSPORT, not the pipeline** | see below |
| 5 | 🚨🚨 **A stale prior pins a healthy link at 1/30th of its capacity, overrides the operator's explicit resolution choice, and every metric reads green** | see below |

### Finding 4 in full, because it redirects the plan

CORPLAP-3, session `6a9abaa8`, the 4903 ms paint the operator reported:

```
12:33:56  age=None  inflight=5339   goodput=5.60M  iter_max=35.6  skips=1
12:33:58  age=2851  inflight=2377   goodput=5.60M  iter_max=26.9  skips=1
12:34:01  age=4903  inflight=1485   goodput=8.51M  iter_max=28.5  skips=24
12:34:03  age=57    inflight=694    goodput=8.51M  iter_max=323   skips=24
```

Read the row at 12:34:01: **frame age 4903 ms while the send queue holds 1485
bytes, the worst pump iteration is 28 ms and the encoder averages 14 ms.**
Nothing sender-side is wrong. Two windows reported `age=None` first — the viewer
sent no report at all — and 23 frames were skipped to backpressure in the same
window, meaning the sender *wanted* to send and could not. Then goodput jumps to
8.5 Mbps as the backlog drains at once and age returns to 57 ms.

That is a **head-of-line block on the DERP/TCP relay**, three to five seconds
long, surfacing as frame age. 🔑 **No encoder change, no rate-control change and
no threading change can fix it**, and the fact that the arc's instruments make it
*look* like a pipeline problem is itself a defect: `viewer_age_ms` conflates
sender latency, transit latency and viewer-side stalls into one number, so every
excursion arrives pointing at the pump.

### Finding 5, which is the clearest statement of the whole problem

Operator, live: *"CORPLAP-1 in relay also has blurred text and background at
1200×800 even though original resolution was selected. Something is totally
off."* The log says exactly what happened:

```
FFmpeg DC pump: agent-side relay resolution cap engaged
    user_target=Native   effective_target=Fixed { width: 1280, height: 800 }
    reason="priority-cap"   native_w=1920  native_h=1200

tgt=200000  gp=None  slf=Some(200000)  lc=170000  fps=15  age=66
```

The chain, every link of it a heuristic doing its job:

1. **`lc=170000`** — the FR-35 ceiling learner carries a remembered 170 kbps for
   this pair.
2. **`gp=None`** — there is **no live goodput measurement**, so nothing can
   contradict the prior. It is not an observation; it is a memory.
3. The ceiling (170 k) is **below the floor** (`slf=200000`, the absolute
   `slow_link_min_bitrate`), so the target pins at 200 kbps.
4. At 200 kbps, 1920×1200 is illegible at any QP, so the **relay resolution cap
   correctly** drops to 1280×800 — silently overriding an explicit `Native`.
5. 200 kbps at 1280×800 and 15 fps is **0.013 bits per pixel**. That is the
   blurred text.
6. **`age=66` ms.** The session is delivering its 200 kbps perfectly. Every
   health metric is green while the picture is unusable.

🔑 **This is the operator's complaint in one session.** No single heuristic is
wrong. Composed, they negotiated a multi-megabit link down to 1/30th of its
capacity, discarded a direct user instruction, and reported success. Nothing in
the system is able to notice, because *no component owns the question "is this
picture any good?"*

⚠️ FR-63's own design table already says **"a prior cannot pin"** — and here a
prior pins. The rule exists on paper and is violated in code, which is what a
patch-work architecture looks like from the inside.

## The diagnosis, stated structurally

**The media loop is a scheduling point for everything else.** One `tokio::spawn`ed
task runs, between consecutive frames: the encoder open/rebuild, two WebRTC stats
reads, the control-DataChannel lock and send, background-swap adoption, the
backpressure gate and its sleep, cadence pacing, then capture → scale → encode →
send. Every one of them delays the next frame, which is why the recurring fix has
been "wrap this site in `spawn_blocking`" — each site genuinely *is* the problem,
one at a time, forever.

**The rate decision is made where the frame is made, and that is why there are 34
heuristics.** The coarsen ladder, the deferred applies, the 15-second thrift, the
background swap, the settle-keyframe thrift, the refine-versus-cap fight, the
opener grace, the FlipTracker and kf_gate cooldowns — every one exists to ration
the cost of deciding *at frame time*. They are not bad code; they are the correct
local answer to a structural mistake.

⚠️ **And the expensive apply is not going away by itself.** FR-62 A0-QSV was
measured twice on real Iris Xe today and both explanations died: the driver
rejects the bitrate `Reset` outright. So on QSV the encoder cannot change rate
cheaply — *ever*. The ladder is permanent **if the frame path must wait for the
change**. Take the frame path out of the waiting and the constraint stops
mattering.

## The target architecture

Three planes. One owner each. No synchronous coupling between them.

### 1. Media plane — one dedicated OS thread per session

Owns the capturer, the scaler and the encoder — all three of which are `!Send`,
driver-affine, and happiest pinned. **It never awaits.** Its loop is:

```
read Plan (immutable snapshot) → capture → scale → encode → hand off → repeat
```

Nothing else. No stats reads, no control-channel sends, no policy.

🔑 **This is not a new pattern here — capture already does exactly it**, on every
backend, and capture is the one stage that measured clean (`scrap`, `drm` and
`system-context` hand work to a thread owning the `!Send` device and return a
oneshot; `wgc` uses a `Notify`). The encoder thread is precedent-following, and
it respects encoder thread-affinity (Windows MF per-thread COM/`MFStartup`, QSV
session affinity) instead of fighting it.

⚠️ **This is why it must be a thread and not `spawn_blocking` per frame**: an
arbitrary pool thread can break hardware encode outright.

### 2. Transport plane — the send task, plus honest arrival telemetry

Owns the DataChannel and the byte ledger. Reports one `PipeState` upward that
**distinguishes three things the current `viewer_age_ms` fuses into one**:

- **produced-too-much** — our queue is deep;
- **transit stalled** — our queue is empty and nothing is arriving (finding 4);
- **viewer-side** — arriving fine, decoding/painting late.

Without that split, every excursion is misattributed on arrival, and finding 4
proves it happens.

### 3. Control plane — the async runtime

Signalling, ICE/stats reads, policy, and **one** rate controller. It *publishes*
a `Plan`; it never reaches into the media loop. The stats reads that today sit
between two frames move here permanently.

## The invariant that removes the patch-work

> **The media thread never makes a rate or geometry decision. It reads a plan.**

and two rules the control plane owes in return, both of which finding 5 breaks:

> **A prior may open a session. It may never pin one.** An unmeasured belief
> (`gp=None`) must decay toward the measurable, not hold the rate at a floor.
>
> **An explicit operator choice is never silently overridden.** If policy must
> override `Native`, that is a reportable state the viewer shows, not a log line
> nobody reads.

Everything downstream follows. The plan is an immutable snapshot (rate, dims,
fps cap, chroma, keyframe request); the media thread adopts it when convenient,
and adopting is cheap because a replacement encoder can be built **on that same
thread while the current one keeps producing** — make-before-break, which is
FR-65 P1's actual goal and is impossible today because the open is an await point
in the frame path.

Once adopting is cheap and the decision is elsewhere, the heuristics have nothing
left to ration.

## Phases

Each ships independently, is individually verifiable, and carries a kill switch.

| # | phase | what | gate |
|---|---|---|---|
| **M0** | trustworthy measurement | phase-complete stall breakdown ✅ (#1327), `swaps` counter ✅ (#1327), split `viewer_age` into sender / transit / viewer ✅ (2026-09-04: heartbeat `age_split`, from an optional `arr_ms` on `rc:decodestat`; **field-verified 2026-09-05 on 0.4.66**: a 45 ms relay age read as 44 ms transit + 1–2 ms viewer + 0.1 ms sender) | an excursion is attributable to a plane without reading source — **met**; the diag HUD still shows the fused number |
| **M1** | the media thread | capture→scale→encode onto one dedicated thread per session; async keeps signalling + send; bounded channels both ways | frame cadence unchanged or better on all three hosts; kill switch restores today's loop |
| **M2** | make-before-break | the replacement encoder opens on the media thread while the current one produces | `open_ms` disappears from the *frame path*: first-frame latency drops by the open (0.29–0.96 s measured) |
| **M3** | the Plan handoff | control plane publishes an immutable plan; every in-loop decision site removed. **M3a built 2026-10-18** (the plan in SHADOW: `encode::plan`, a pure producer with every knob resolved once, compared per frame against the inline decisions, heartbeat `plan_divergences` + `plan_epoch`; no behaviour change, no switch); M3b flips the loop to read it once the counter reads fleet-zero | no rate/geometry decision remains in the media loop; **M3a's gate**: `plan_divergences` zero on every field, fleet-wide |
| **M4** | one controller | FR-63 B1 shadow → B2 live, now that adopting is cheap | the flip criterion already written on FR-63 |
| **M5** | the deletions | FR-62 A4 + FR-63 B3, **each gated on a counter being fleet-zero** | 34 heuristics → target ≤ 10; 11 kill switches → ≤ 4; 8 estimators → 1 |
| ~~**T1**~~ → **FR-71 #1362** | the transport answer | act on the sender/transit/viewer split: a transit stall is not an over-production signal and must not cut the rate — **moved to its own FR on 2026-09-05** (decided below) | a repeat of finding 4 is classified correctly and the rate is *not* cut — now FR-71's AC3 |
| **P1** | **priors decay, and overrides are visible** | a ceiling with no live measurement decays toward the band instead of pinning; an overridden `user_target` is surfaced to the viewer | finding 5 cannot recur silently: either the rate climbs off the stale prior, or the operator is told why their choice was refused |

⚠️ **P1 is first in value even though it is last in the table.** It is the one
the operator can see today, it needs no threading work, and it is the cheapest
of the lot. M0–M3 are the structural fix; P1 is the bleeding.

⚠️ **M5 is the acceptance criterion of the whole plan, not an afterthought.** If
the deletions do not happen, this is one more lever and the operator's complaint
stands. Every phase before it exists to make a deletion safe.

## Honest evaluation — read this before approving

**What it genuinely fixes:** the encoder open leaving the frame path at both
session start and every rebuild; the per-frame encode call; the capture open;
and the removal of the in-loop decision sites the heuristics exist to protect.

**What it does not fix, bluntly:**

- The worst number measured today — a **4903 ms paint with a 1485-byte send
  queue**, 28 ms iterations and a healthy multi-megabit link — is a relay
  head-of-line block. **No threading change touches it.**
- The most damaging finding — a remembered **170 kbps** ceiling with no live
  measurement pinning a healthy link at the 200 kbps floor, forcing the
  resolution cap to override an explicit `Native` and producing 0.013 bits per
  pixel of blurred text while frame age read 66 ms — is a **control-plane policy
  bug**. Threading does not touch that either.

⇒ Judged by *"does restructuring the pipeline fix what the operator sees
today"*, the answer is **partly no**. Two of the five findings need different
work, and saying so up front is the difference between a plan and a pitch.

**The risk of the proposal itself.** A dedicated thread per session is real
concurrency surface: handoff latency, backpressure across channels, teardown
ordering. ⚠️ **It could be a net loss if the channel handoff costs more than the
blocking it removes.** That must be measured with the stall watch before and
after — not assumed because the shape is nicer.

## How to keep this from becoming more patch-work

Three commitments, and they matter more than the design:

1. **Deletion is the acceptance criterion, not a follow-up.** 34 heuristics → ≤
   10, 11 kill switches → ≤ 4, 8 estimators → 1, each retirement gated on a
   counter measured fleet-zero. 🔑 **If a phase ships and nothing is deleted,
   that phase added a lever and the complaint stands.**
2. **Sequence by what unblocks deletion, not by what is most interesting.**
   Measurement first — nothing after it is verifiable otherwise. Then the
   thread, make-before-break, the plan handoff, one controller, the deletions.
   Each behind a kill switch, each with a before/after from the same instrument.
3. **Do the cheap visible thing first.** P1 — an unmeasured prior decaying
   instead of pinning, and an overridden resolution choice surfaced to the
   viewer — needs *no threading work at all*. It is the smallest change in the
   plan and it addresses what is on screen right now. ⚠️ Leading with the
   architecture while the blur persists would be the wrong order.

## The question this plan most wants challenged

**Does the transport classification (T1) belong in this FR, or its own?** It is
the largest measured harm (4903 ms) and it shares *nothing* with the threading
work except the instrument. The case for keeping it here is that the
sender/transit/viewer split is part of M0 and everything else depends on it; the
case for splitting is that T1's fix is a transport-plane design with its own
field cells, and bundling it lets the FR claim credit for work that has not
started. **Decide before M1 starts.**

**Decided 2026-09-05: its own FR — FR-71 (#1362).** M0 delivered the
instrument (the split, field-verified that morning), which made the split clean:
the instrument stays here, the response moves. M1 is unblocked on this plan's
own terms; FR-71's shadow classification runs beside it.

## What this explicitly does NOT claim

- ⚠️ **It does not fix finding 4 by itself.** M1–M3 are about the pipeline; the
  4903 ms excursion is transport and needs T1. Shipping M1 and declaring the drag
  problem solved would repeat the mistake this plan exists to stop.
- ⚠️ **It does not resurrect in-place QSV rate changes.** That is measured dead
  (twice, today). M2 makes it irrelevant rather than fixing it.
- ⚠️ **It is not a rewrite.** Capture already has this shape; the change is to
  give encode the same shape and move three call sites out of the loop.

## Relationship to the existing FRs

| FR | what it keeps | what this plan changes |
|---|---|---|
| **FR-62** encoder apply | A0/A1/A2 findings stand | A4's deletions become reachable, because M2 makes a rebuild free rather than rationed |
| **FR-63** one controller | B0 simulator, B-opener | B1/B2 become M4, and land *after* applies are cheap instead of fighting the ladder |
| **FR-64** RC never rides the overlay | unchanged | independent; a direct-path prerequisite for T1 |
| **FR-65** blocking work | P0 instrument ✅ | P1/P2 become M1/M2 — the structural form the FR already re-aimed to on 2026-09-04 |

## Verification

- **Unit:** the media thread's plan-adoption is pure and testable on the default
  build (the `encode::stall` / `encode::sim` precedent); `PipeState`
  classification gets fixture tests including the finding-4 shape.
- **Field:** the same three CORPLAP hosts, before/after on the same instrument
  (FR-65 AC7). ⚠️ **A field test must be shown to FAIL on the current deploy
  first** — record both runs.
- **Fleet:** heartbeat counters read via `meshharbor exec` after every roll.
