// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-17 stages A + C — the receive half of per-chunk framing, with a
 * bounded reorder buffer.
 *
 * The agent splits each frame into 16 KiB DataChannel messages. Before
 * FR-17 those messages were a bare byte stream: the receiver concatenated
 * them and trusted SCTP's reliable+ordered guarantee to deliver every one,
 * in order, forever. That guarantee is exactly what stage B gives up — an
 * unordered / partially-reliable channel is what stops one lost chunk from
 * head-of-line-blocking every frame behind it (`send_wait_max` hit
 * 10,263 ms in the field on a healthy agent).
 *
 * A byte stream cannot survive that, because a receiver has no way to tell
 * "the next 16 KiB of this frame" from "the first 16 KiB of the next one".
 * So each message carries an 8-byte prefix:
 *
 *   bytes [0..4)  frame_seq,   u32 little-endian
 *   bytes [4..6)  chunk_idx,   u16 little-endian
 *   bytes [6..8)  chunk_count, u16 little-endian
 *
 * ## Stage C — why in-order assembly was not enough (FR-59 P7)
 *
 * Stage A's assembler required chunk `n+1` to follow chunk `n`. Under an
 * ordered channel that is free; under stage B's UNORDERED one it is
 * wrong in the common case, not the rare one: chunk 2 of a frame routinely
 * arrives before chunk 1, and the strict rule read every such frame as a
 * break. The result was a keyframe request per frame — worse than the
 * head-of-line blocking stage B exists to remove. That is why the FR
 * recorded stage C as "blocked on a reorder buffer".
 *
 * So a frame is now assembled into SLOTS indexed by `chunk_idx`, in any
 * order, and emitted whole the moment every announced slot is filled.
 * Reordering within a frame is therefore invisible.
 *
 * ⚠️ Emission is whole-frame rather than per-chunk. That costs no latency:
 * the byte assembler downstream cannot decode a partial frame either, so
 * the decode still happens on the last chunk — the only difference is
 * where the bytes waited.
 *
 * ⚠️ A frame still incomplete when a NEWER one COMPLETES is abandoned,
 * with a gap reported. Holding it would re-introduce exactly the
 * head-of-line delay the unordered channel exists to remove, and it would
 * buy nothing: the codec is delta-chained, so a frame whose predecessor
 * never arrived is undecodable anyway and the gap is what asks for the IDR
 * that repairs the chain.
 *
 * ⚠️ At most [`MAX_PARTIAL_FRAMES`] frames are held. Unbounded buffering
 * on a lossy link is a memory leak with a slow fuse: every frame that
 * loses a chunk would be retained forever, on the exact link where frames
 * lose chunks.
 *
 * ⚠️ This module is deliberately SHARED by both workers rather than copied
 * into each. The rule "what counts as a gap" has to be one function: FR-10
 * shipped a spacing rule that lived in one of its two call sites and the
 * other one silently didn't have it, which is the defect this file's
 * existence is meant to prevent.
 */

/** Size of the per-message prefix, in bytes. Locked against the agent's
 *  `peer.rs::CHUNK_HEADER_BYTES` by tests on both sides. */
export const CHUNK_HEADER_BYTES = 8

/** How many partially-assembled frames may be held at once. Two is the
 *  reordering depth a 16 KiB-chunked stream actually needs (a frame and
 *  its successor overlapping); three leaves one spare so a brief burst
 *  does not evict a frame that was about to complete. */
export const MAX_PARTIAL_FRAMES = 3

/** One frame being assembled out of order. */
interface PartialFrame {
  /** Payloads by `chunk_idx`; `null` for a slot not yet arrived. */
  slots: (Uint8Array | null)[]
  /** How many slots are filled — cheaper than scanning, and the only
   *  completion test. */
  filled: number
  /** Total payload bytes held, so the emit does one allocation. */
  bytes: number
}

export interface ChunkFramingState {
  /** Frames being assembled, keyed by `frame_seq`. A `Map` because
   *  insertion order IS arrival order, which is what the eviction rule
   *  needs. */
  partials: Map<number, PartialFrame>
  /** `frame_seq` of the most recently COMPLETED (or abandoned) frame, so
   *  a late chunk of it is recognised as a straggler rather than mistaken
   *  for a new frame. */
  lastSeq: number | null
  /** Cumulative gap count, surfaced in the worker's stats so a field
   *  session can distinguish "the transport lost chunks" from "the
   *  decoder is unhappy". A counter nothing reads is not evidence. */
  gaps: number
  /** Cumulative count of messages that could not be placed. */
  discarded: number
  /** Cumulative count of late chunks belonging to a frame already moved
   *  past. Under an unordered channel these are expected; a rising count
   *  with steady fps is the transport working, not failing. */
  stragglers: number
  /** True between an unclassifiable message and the next one we can
   *  place. It exists so a run of garbage is reported as ONE break: each
   *  `gap` costs a keyframe request, and an IDR is the largest frame on
   *  the thinnest pipe. */
  resyncing: boolean
}

export function createChunkFraming(): ChunkFramingState {
  return {
    partials: new Map(),
    lastSeq: null,
    gaps: 0,
    discarded: 0,
    stragglers: 0,
    resyncing: false,
  }
}

export interface ChunkFramingResult {
  /** A COMPLETE frame's payload bytes, or null when this message did not
   *  complete one. */
  payload: Uint8Array | null
  /** True when this message revealed that a frame can no longer be
   *  completed. The caller must reset its byte assembler and request a
   *  keyframe. Reported ONCE per abandoned frame, not once per discarded
   *  message, so a long loss doesn't look like a burst of independent
   *  failures — each `gap` costs a keyframe request, and an IDR is the
   *  largest frame on the thinnest pipe. */
  gap: boolean
}

/** How far back a `frame_seq` may be and still count as a late chunk of a
 *  frame we have moved past, rather than the start of a new stream.
 *
 *  ⚠️ Bounded on purpose. "Older than what we have" is the natural rule,
 *  but an UNBOUNDED version deadlocks the moment the sender's counter
 *  restarts (a fresh send task begins again at 1): every subsequent frame
 *  would look ancient, be straggled, and the picture would stop for good
 *  with no gap reported and nothing in the logs. A window turns that
 *  failure into a single resync. 64 frames is ~1 s of video at 60 fps —
 *  far beyond any plausible reordering, far below a counter restart. */
const STRAGGLER_WINDOW = 64

/** Wrap-safe "`a` is newer than `b`". The agent advances `frame_seq` with
 *  `wrapping_add`, so 0 legitimately follows 0xffffffff — a plain `>`
 *  would read that wrap as a jump backwards. */
function isNewer(a: number, b: number): boolean {
  return ((a - b) >>> 0) > 0 && ((a - b) >>> 0) < 0x80000000
}

/** Wrap-safe "`seq` belongs to a frame we have already moved past, and
 *  recently enough that reordering explains it".
 *
 *  ⚠️ Includes `back === 0`, i.e. a late chunk of the frame we JUST
 *  completed. Stage A needed `back > 0` because a live frame and
 *  `lastSeq` shared one variable, so equality was the normal mid-frame
 *  case; here a live frame has its own entry in `partials` and this test
 *  is only reached when there is none — so equality can only mean "that
 *  frame is already gone". Without it, a re-delivered chunk of a
 *  delivered frame starts assembling it again, and the next real frame
 *  then evicts a ghost. */
function isStraggler(seq: number, lastSeq: number | null): boolean {
  if (lastSeq === null) return false
  return ((lastSeq - seq) >>> 0) <= STRAGGLER_WINDOW
}

/** Concatenate a completed frame's slots into one buffer. */
function assemble(p: PartialFrame): Uint8Array {
  const out = new Uint8Array(p.bytes)
  let at = 0
  for (const slot of p.slots) {
    if (slot === null) continue
    out.set(slot, at)
    at += slot.length
  }
  return out
}

/**
 * Validate and place one framed DataChannel message.
 *
 * Returns the COMPLETE frame when this message finished one, or `null`
 * otherwise; `gap` is set when a frame was abandoned.
 */
export function stripChunkPrefix(
  st: ChunkFramingState,
  bytes: Uint8Array,
): ChunkFramingResult {
  // A message too short to carry a prefix cannot be classified at all —
  // treat it as a break rather than guessing, since the alternative is
  // reading `chunk_idx` out of frame payload bytes.
  if (bytes.byteLength < CHUNK_HEADER_BYTES) {
    return abandonAll(st)
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, CHUNK_HEADER_BYTES)
  const seq = view.getUint32(0, true)
  const idx = view.getUint16(4, true)
  const count = view.getUint16(6, true)
  const payload = bytes.subarray(CHUNK_HEADER_BYTES)

  // `chunk_count` of zero is out of spec: the agent floors it at one so
  // that even a zero-length frame is announced as one chunk.
  if (count === 0 || idx >= count) {
    return abandonAll(st)
  }

  // ⚠️ A STRAGGLER: a chunk of a frame we have already completed or
  // abandoned. Under stage A's ordered channel this cannot happen; under
  // an unordered one it is routine. Treating it as a gap would let a late
  // chunk of an already-lost frame destroy the HEALTHY frame after it,
  // and that cascades — every dropped frame costs an IDR.
  if (!st.partials.has(seq) && isStraggler(seq, st.lastSeq)) {
    st.stragglers++
    return { payload: null, gap: false }
  }

  let partial = st.partials.get(seq)
  if (partial === undefined) {
    // Evict before inserting, so the map never exceeds its bound. The
    // oldest INSERTED entry goes: it has been waiting longest and is the
    // least likely to still complete.
    let evicted = false
    while (st.partials.size >= MAX_PARTIAL_FRAMES) {
      const oldest = st.partials.keys().next()
      if (oldest.done) break
      st.partials.delete(oldest.value)
      evicted = true
    }
    partial = { slots: new Array(count).fill(null), filled: 0, bytes: 0 }
    st.partials.set(seq, partial)
    if (evicted) {
      st.gaps++
      // The evicted frame is unrecoverable, but THIS one is still live —
      // report the loss and keep assembling, because dropping the new
      // frame too would turn one lost frame into two.
      placeChunk(st, partial, idx, payload)
      const { payload: done } = finish(st, seq, partial)
      return { payload: done, gap: true }
    }
  } else if (partial.slots.length !== count) {
    // The same seq announcing a different chunk_count is not a frame we
    // can trust; two different frames are colliding on one sequence
    // number, and guessing which is right would splice their bytes.
    st.partials.delete(seq)
    st.lastSeq = seq
    st.gaps++
    return { payload: null, gap: true }
  }

  if (partial.slots[idx] !== null) {
    // A duplicate slot: harmless under an unreliable channel, and not a
    // reason to touch the frame.
    st.stragglers++
    return { payload: null, gap: false }
  }
  placeChunk(st, partial, idx, payload)
  const { payload: done, abandoned } = finish(st, seq, partial)
  return { payload: done, gap: abandoned }
}

function placeChunk(
  st: ChunkFramingState,
  p: PartialFrame,
  idx: number,
  payload: Uint8Array,
): void {
  // Any message we can place ends the break episode: `resyncing` means
  // "we could not classify the last one", not "a frame was lost".
  st.resyncing = false
  p.slots[idx] = payload
  p.filled++
  p.bytes += payload.length
}

/** Emit `seq` if it is now complete, abandoning any OLDER partials — they
 *  can no longer be delivered in order, and the codec's delta chain is
 *  broken past them regardless. Returns the assembled bytes and whether any
 *  older incomplete frame was abandoned (so the caller can request resync). */
function finish(
  st: ChunkFramingState,
  seq: number,
  partial: PartialFrame,
): { payload: Uint8Array | null; abandoned: boolean } {
  if (partial.filled < partial.slots.length) return { payload: null, abandoned: false }
  const out = assemble(partial)
  st.partials.delete(seq)
  let abandoned = false
  for (const older of [...st.partials.keys()]) {
    if (!isNewer(older, seq)) {
      st.partials.delete(older)
      st.gaps++
      abandoned = true
    }
  }
  st.lastSeq = seq
  return { payload: out, abandoned }
}

/** An unclassifiable message: nothing in flight can be trusted.
 *
 *  Reported ONCE per break episode. A run of garbage is one loss, not
 *  one per message: each `gap` costs a keyframe request, and an IDR is
 *  the largest frame on the thinnest pipe — reporting per message would
 *  answer a burst of loss with a burst of the most expensive frames
 *  there are, on the link least able to carry them. */
function abandonAll(st: ChunkFramingState): ChunkFramingResult {
  const firstBreak = !st.resyncing
  st.resyncing = true
  st.partials.clear()
  if (firstBreak) {
    st.gaps++
    return { payload: null, gap: true }
  }
  st.discarded++
  return { payload: null, gap: false }
}
