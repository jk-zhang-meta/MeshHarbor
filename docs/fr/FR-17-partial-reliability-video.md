# FR-17: Video rides a reliable + ordered DataChannel

Status: **stages A + B shipped, B not yet field-measured** (2026-08-28; proposed
2026-08-27). Tracking issue: `FR-17` (#799). Sibling of FR-16
(#798, the harness that must gate it); the architectural half of the FR-1 program.

## The measurement

Prod `agent_logs`, 2026-08-27, both hosts on 0.4.9, 1920×1200@30 over a DERP relay:

| host | encoder | `send_wait_max_ms` | `bytes_inflight` max | `avg_encode_ms` |
|---|---|---|---|---|
| CORPLAP-1 | hevc_qsv | **10 263** | 38 011 | 8–10 |
| CORPLAP-1 | vp9_qsv | **4 740** | 71 517 | 12–18 |
| CORPLAP-1 | h264_qsv | 1 870 | 3 800 | 9–12 |
| CORPLAP-3 | av1_qsv | 907 | 43 170 | 12 |

`send_wait` is the time a SINGLE frame spent inside the DataChannel send call — not
queued in our channel, not waiting on the encoder. Ten seconds. Encode was 8–12 ms and
our own queue held tens of KB throughout: **the agent is healthy and simply cannot hand
bytes to the wire.**

The contrast that sizes the prize: the same CORPLAP-1 on a **direct** carrier the same
afternoon ran 1920×1200@**60** at 12 Mbps with a **7 ms** end-to-end age.

## Root cause

`video-bytes` is created `{ ordered: true }` — fully reliable, fully ordered SCTP
(`ui/src/composables/useRemoteControl.ts`, `VP9_444_DC_OPTIONS`). The comment there
states the rationale: the channel is ordered because dropping a P-frame "would force
the worker to wait for the next IDR — far worse than a few ms of retransmit latency."

That reasoning is correct on a LAN and **falsified on a lossy 90–210 ms relay**, where
retransmit latency is not a few ms but seconds. Reliable + ordered means:

- nothing can be dropped in flight — every byte queues until delivered;
- one lost chunk **head-of-line blocks every frame behind it**;
- under sustained loss the backlog has no bound, which is why a same-desk pair reaches
  20 s of age.

It also explains the non-linear degradation with drag speed the operator reported
(60 ms slow / 300 ms fast): more motion ⇒ more bits ⇒ more chunks ⇒ more loss exposure
⇒ longer HOL stalls, on a transport that answers loss with waiting rather than
dropping. This is the structural difference from RustDesk, which owns its transport and
drops frames instead of queueing them.

## Viability: CONFIRMED in the stack we already ship (checked 2026-08-28)

The open risk in the first draft was whether our SCTP actually implements abandonment
on the SEND path — negotiating a partial-reliability channel type and then never
abandoning would fix head-of-line blocking at the receiver while leaving `send_wait`
exactly where it is. It does implement it:

- `webrtc-sctp-0.11.0` carries `Stream::set_reliability_params(unordered, rel_type,
  rel_val)`, `ReliabilityType::{Reliable, Rexmit, Timed}`, chunk-level `abandoned`
  flags shared across fragments, and `chunk/chunk_forward_tsn.rs`; the abandonment
  branch runs in `association_internal.rs` (~2022–2037).
- `webrtc-data-0.10.0` (`data_channel/mod.rs:352–359`) maps every DCEP channel type,
  including `PartialReliableTimedUnordered`, onto `set_reliability_params`.

So the browser sets it in `createDataChannel`, the DCEP OPEN carries it, and the agent
applies it automatically — **no agent-side transport change is needed at all.**

### This changes the recommended knob

Prefer **`maxPacketLifeTime`** (→ `ReliabilityType::Timed`) over `maxRetransmits`
(→ `Rexmit`). A deadline states the thing we actually mean — *this frame is worthless
if it has not arrived within N ms* — which is the same principle FR-18 applied one
layer down at the DERP queue, and it removes the guesswork in direction C.

It is also **self-scaling, which retires the constrained-only gating in direction B**:
on a 7 ms direct path nothing is ever abandoned, because delivery sits three orders of
magnitude inside the deadline; on a 90–210 ms relay it abandons exactly what is stale.
One setting, correct on both transports, no carrier plumbing.

⚠️ What remains genuinely hard is therefore NOT the transport — it is the RECEIVER. The
worker assembler assumes ordered, complete delivery, so stage A (framing + gap
detection) is the whole engineering cost and the whole risk.

## Design directions (staged, each behind its own kill switch)

**A. Explicit frame framing, still ordered — zero behaviour change.** ✅ **SHIPPED**
(PR #820). Add sequence + chunk index/count to the wire header so the receiver can
detect a gap at all. Landing this first lets the assembler's gap handling be validated
while the channel is still reliable, so stage B flips one property instead of debugging
two.

Wire, when negotiated: an 8-byte prefix per DataChannel message —
`frame_seq` u32 LE, `chunk_idx` u16 LE, `chunk_count` u16 LE, then the 16 KiB slice.
Cost 8 bytes on 16 KiB (0.05 %) and one small copy per message; **zero** otherwise.

**Negotiated, never assumed.** The agent advertises `chunk-framing` in the new
`AgentCaps.video`; the viewer sends `chunk_framing: true` in `rc:session.request` only
when the agent advertised it AND the session uses a DataChannel transport; the flag is
resolved immediately before the worker starts, because `init-canvas` carries it. An
unframed stream parsed as framed is garbage rather than a degraded picture, so the
request side and the parse side must not be able to move independently.

**Kill switch**: don't send `chunk_framing` — every layer defaults to the pre-FR-17
bare byte stream, and old agents/servers/viewers are byte-identical to today.

Two receive decisions worth stating, because the opposite reading is defensible until
you see the cost:
- A frame that starts while the previous one is still incomplete is **delivered**, with
  the truncation reported alongside it. Dropping it too would turn one lost chunk into
  two lost frames.
- A break is reported **once**, not once per discarded message. Each gap costs a
  keyframe request, so a long resync must not read as a burst of independent losses.

⚠️ The receive rule lives in ONE module (`ui/src/workers/rc-chunk-framing.ts`) shared by
both workers rather than copied into each. FR-10 shipped a spacing rule that lived in
one of its two call sites and silently wasn't in the other (#817), and FR-18 shipped a
counter that was incremented and never read (#804) — the same shape of hazard, closed
structurally this time.

**B. Unordered on framed sessions.** ✅ **SHIPPED** (PR #834), opt-in, default OFF.
`video-bytes` opens `{ ordered: false, maxRetransmits: 0 }`; the receiver discards an
incomplete frame and requests an IDR via the existing min-gap-clamped `rc:keyframe`
path.

**Stack verified rather than assumed**: `webrtc-data`'s `server()` adopts the browser's
DCEP `channel_type` and commits it to the SCTP stream; `webrtc-sctp` stamps `unordered`
per chunk on send with `abandoned` driving partial reliability. **The agent needs no
change** — the browser creates the channel and the agent's send path inherits its
guarantees.

⚠️ **Deviation from this plan, recorded**: "CONSTRAINED transports only" was NOT
implemented, because it is not implementable as written. The channel's ordering is fixed
at `createDataChannel`, which must happen before the offer — and whether the session is
relayed is only known after ICE nominates a pair. Doing it properly needs either a
second channel the agent selects at runtime, or a renegotiation; both are new failure
modes. Instead the flag is a per-viewer opt-in (`meshharbor-rc-unordered-video=1`) so the
relay pair can be measured first. Revisit once FR-16's harness can say what direct
carriers actually cost.

⚠️ **`maxRetransmits: 0` is coupled to the RECEIVER, not chosen for aggressiveness.**
Stage A's assembler treats a chunk-index jump as unrecoverable. That is right when a
lost chunk never arrives and WRONG once retransmits are allowed — a chunk arriving an
RTT late would be discarded as a gap, converting a recoverable frame into a lost one
plus a keyframe. **Stage C is therefore not just a bigger number** (see below).

⚠️ Two receiver defects exist ONLY under unordered delivery, both fixed in #834 and
unreachable while the channel is ordered:
- **Stragglers cascade.** Chunk 3 of frame N can arrive after chunk 0 of frame N+1. The
  stage-A rule broke N+1 on that, so one lost frame became TWO, each costing an IDR —
  precisely the storm this FR says to design against. Late chunks of a frame already
  passed are now discarded quietly, checked BEFORE the chunk-0 branch (a late chunk 0
  can restart assembly on a dead frame just as a late chunk 3 can break a live one).
- **An unbounded "older than what we have" rule DEADLOCKS.** If the sender's counter
  ever restarts at 1, every frame looks ancient, all are straggled, and the picture
  stops for good with NO gap reported and nothing in the logs. `STRAGGLER_WINDOW = 64`
  (~1 s at 60 fps) turns that into one resync.

⚠️ The unordered/framing pairing is enforced in ONE function (`videoDcOptions`): an
unframed stream delivered out of order is not a degraded picture, it is garbage the
decoder reports as corruption.

⚠️ Stage B **cannot engage until an agent advertising `chunk-framing` ships** — the
correct interlock, and why it is inert on merge.

**C. Measure the retransmit budget rather than assume it.** `maxRetransmits: 0` versus
1–2 is an empirical question on these paths; FR-16 answers it per pair.

⚠️ **Blocked on a reorder buffer, not on the harness.** Raising the retransmit count
without one makes things WORSE, not better: a retransmitted chunk arrives an RTT late,
stage A's assembler sees an index jump, and discards a frame that had in fact been
recovered — spending an IDR to reject data already paid for. The worker must buffer
out-of-order chunks within a frame before 1-2 is even testable.

⚠️ **The risk to design against is an IDR storm.** On a lossy path, "drop the frame and
ask for a keyframe" can cost more than the stall it replaces — each IDR is the largest
frame on the thinnest pipe (FR-10 measured ~300 KB ≈ 1.2–1.5 s at 2 Mbps). The recovery
rate must be bounded, and this is the point where **intra-refresh (spread-I)** stops
being an optional nicety: it converts recovery from one huge frame into a spread cost.

⚠️ The 16 KiB chunking currently relies on ordered delivery for reassembly. Stage A is
what makes the reassembler independent of that assumption.

## Acceptance criteria

- [x] Stage A ships with the assembler proving gap detection on a synthetic gap, and
      byte-identical behaviour on the wire otherwise. **Done** (PR #820): 3 agent-side
      tests (byte layout, reassembly transparent, empty frame = one chunk not zero) and
      7 viewer-side (in-order, gap-once, resync on chunk 0, truncated-then-new-frame,
      out-of-spec prefixes, single-chunk frames, `frame_seq` wrap). The single-chunk
      test caught a real bug pre-merge — a one-chunk frame left `expectSeq` set, so the
      NEXT frame's chunk 0 read as a truncation: a false gap plus an IDR request on
      every frame small enough to fit one message.
- [ ] On the CORPLAP-1 ↔ CORPLAP-3 relay pair under FR-16's deterministic fast-motion profile:
      `send_wait` p99 drops below 250 ms (was: 10 263 ms max), and age p99 drops below
      300 ms.
- [ ] No IDR-storm regression: keyframe rate under sustained loss stays bounded, and
      delivered fps does not fall below the pre-change baseline.
- [ ] Direct transports are unchanged (verified by an FR-16 direct cell, not by
      inspection).
- [ ] A field A/B against RustDesk on the same pair, since that is the standard the
      program set itself.

## Out of scope

- Replacing SCTP/WebRTC wholesale (MoQ, a custom UDP protocol). This changes ONE
  property of the existing channel; the transport stays.
- The base path latency itself — two machines on one desk relaying at 90–210 ms is a
  carrier problem (FR-9), not a transport-reliability problem. Both need fixing and
  they are independent.

## Field log

| date | build | result |
|---|---|---|
| 2026-08-27 | 0.4.9 | Baseline measurements above; FR filed. |
| 2026-08-28 | — | Stage A merged (#820). Inert by construction: the channel is still `{ ordered: true }`, so a gap cannot fire in production — that is the point of landing it first. **Not a field result**, and deliberately so; the measurable claim belongs to stage B. |
| 2026-08-28 | — | Stage B merged (#834). Also inert on merge: opt-in default OFF, and unable to engage until an agent advertising `chunk-framing` ships. **No measurement yet** — the acceptance criteria below stay unchecked, and the A/B needs an agent release rolled to the CORPLAP-1 ↔ CORPLAP-3 pair. |
