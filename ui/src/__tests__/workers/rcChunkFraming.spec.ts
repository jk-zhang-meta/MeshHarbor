// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, it, expect } from 'vitest'
import {
  CHUNK_HEADER_BYTES,
  MAX_PARTIAL_FRAMES,
  createChunkFraming,
  stripChunkPrefix,
} from '@/workers/rc-chunk-framing'

/** Build one framed message the way `peer.rs::chunk_framed` does. The
 *  agent side locks the same layout in
 *  `video_bytes_wire_tests::chunk_prefix_layout_matches_worker_assembler`;
 *  these two tests are the two halves of one wire contract, and a change
 *  to either that isn't mirrored should fail here. */
function framed(seq: number, idx: number, count: number, payload: number[]): Uint8Array {
  const out = new Uint8Array(CHUNK_HEADER_BYTES + payload.length)
  const view = new DataView(out.buffer)
  view.setUint32(0, seq, true)
  view.setUint16(4, idx, true)
  view.setUint16(6, count, true)
  out.set(payload, CHUNK_HEADER_BYTES)
  return out
}

const bytes = (r: { payload: Uint8Array | null }) => [...(r.payload ?? [])]

describe('rc-chunk-framing', () => {
  it('emits the whole frame once, on its last chunk', () => {
    const st = createChunkFraming()
    const a = stripChunkPrefix(st, framed(1, 0, 3, [10, 11]))
    const b = stripChunkPrefix(st, framed(1, 1, 3, [12]))
    const c = stripChunkPrefix(st, framed(1, 2, 3, [13]))
    // ⚠️ Stage C changed WHERE the bytes wait, not how many arrive: the
    // frame is emitted whole rather than chunk by chunk, because an
    // out-of-order chunk cannot be appended to a stream.
    expect(a.payload).toBeNull()
    expect(b.payload).toBeNull()
    expect(bytes(c)).toEqual([10, 11, 12, 13])
    expect([a.gap, b.gap, c.gap]).toEqual([false, false, false])
    expect(st.gaps).toBe(0)
  })

  it('handles a single-chunk frame without leaving state behind', () => {
    const st = createChunkFraming()
    const r = stripChunkPrefix(st, framed(1, 0, 1, [42]))
    expect(bytes(r)).toEqual([42])
    expect(st.partials.size).toBe(0)
    // The very next single-chunk frame must not read as a gap.
    expect(stripChunkPrefix(st, framed(2, 0, 1, [43])).gap).toBe(false)
    expect(st.gaps).toBe(0)
  })

  it('treats an out-of-spec prefix as a break rather than guessing', () => {
    const st = createChunkFraming()
    // chunk_count of 0: the agent floors it at 1, so this cannot be ours.
    expect(stripChunkPrefix(st, framed(1, 0, 0, [1])).gap).toBe(true)
    const st2 = createChunkFraming()
    // idx >= count is unsatisfiable.
    expect(stripChunkPrefix(st2, framed(1, 5, 2, [1])).gap).toBe(true)
    const st3 = createChunkFraming()
    // Too short to even hold a prefix — reading chunk_idx out of payload
    // bytes would be worse than declaring a break.
    expect(stripChunkPrefix(st3, new Uint8Array([1, 2, 3])).gap).toBe(true)
  })

  it('reports a run of garbage as ONE break, not one per message', () => {
    // Each gap costs a keyframe request, and an IDR is the largest frame
    // on the thinnest pipe: reporting per message would answer a burst of
    // loss with a burst of the most expensive frames there are.
    const st = createChunkFraming()
    expect(stripChunkPrefix(st, new Uint8Array([1])).gap).toBe(true)
    expect(stripChunkPrefix(st, new Uint8Array([2])).gap).toBe(false)
    expect(stripChunkPrefix(st, new Uint8Array([3])).gap).toBe(false)
    expect(st.gaps).toBe(1)
    expect(st.discarded).toBe(2)
    // …and a placeable message ends the episode, so the NEXT break is
    // reported again rather than swallowed forever.
    stripChunkPrefix(st, framed(9, 0, 1, [1]))
    expect(st.resyncing).toBe(false)
    expect(stripChunkPrefix(st, new Uint8Array([4])).gap).toBe(true)
    expect(st.gaps).toBe(2)
  })

  it('survives frame_seq wrapping past u32', () => {
    const st = createChunkFraming()
    stripChunkPrefix(st, framed(0xffffffff, 0, 2, [1]))
    const r = stripChunkPrefix(st, framed(0xffffffff, 1, 2, [2]))
    expect(r.gap).toBe(false)
    expect(bytes(r)).toEqual([1, 2])
    // The agent wraps with `wrapping_add`, so 0 legitimately follows.
    expect(stripChunkPrefix(st, framed(0, 0, 1, [3])).gap).toBe(false)
  })
})

describe('rc-chunk-framing under UNORDERED delivery (FR-17 stages B + C)', () => {
  it('assembles a frame whose chunks arrive in ANY order', () => {
    // The case stage A got wrong: under an unordered channel this is the
    // COMMON path, not the rare one, and the strict rule read every such
    // frame as a break — a keyframe request per frame, worse than the
    // head-of-line blocking stage B removes.
    const st = createChunkFraming()
    expect(stripChunkPrefix(st, framed(7, 2, 4, [3])).payload).toBeNull()
    expect(stripChunkPrefix(st, framed(7, 0, 4, [1])).payload).toBeNull()
    expect(stripChunkPrefix(st, framed(7, 3, 4, [4])).payload).toBeNull()
    const done = stripChunkPrefix(st, framed(7, 1, 4, [2]))
    // Reassembled in INDEX order, not arrival order.
    expect(bytes(done)).toEqual([1, 2, 3, 4])
    expect(done.gap).toBe(false)
    expect(st.gaps).toBe(0)
  })

  it('interleaves two frames without either destroying the other', () => {
    const st = createChunkFraming()
    stripChunkPrefix(st, framed(1, 0, 2, [1]))
    stripChunkPrefix(st, framed(2, 0, 2, [10]))
    const one = stripChunkPrefix(st, framed(1, 1, 2, [2]))
    expect(bytes(one)).toEqual([1, 2])
    const two = stripChunkPrefix(st, framed(2, 1, 2, [11]))
    expect(bytes(two)).toEqual([10, 11])
    expect(st.gaps).toBe(0)
  })

  it('abandons a frame a NEWER completed one has overtaken, and says so', () => {
    // Holding it would re-introduce the head-of-line delay the unordered
    // channel exists to remove, and buy nothing: the codec is
    // delta-chained, so a frame whose predecessor never arrived is
    // undecodable anyway. The gap is what asks for the repairing IDR.
    const st = createChunkFraming()
    stripChunkPrefix(st, framed(1, 0, 3, [1])) // frame 1 loses chunks 1-2
    const r = stripChunkPrefix(st, framed(2, 0, 1, [9]))
    // The newer frame is still DELIVERED — dropping it too would turn one
    // lost frame into two — AND gap is signaled immediately so the worker
    // can request a repairing IDR on delta loss.
    expect(bytes(r)).toEqual([9])
    expect(r.gap).toBe(true)
    expect(st.gaps).toBe(1)
    expect(st.partials.size).toBe(0)
  })

  it('does not let a late chunk of a lost frame destroy the next one', () => {
    // The cascade this exists to prevent: frame 1 loses chunk 1, frame 2
    // completes, then frame 1's chunk 2 finally arrives. Without the
    // straggler rule that late chunk restarts assembly on a dead frame —
    // one lost frame becoming two, and each dropped frame costs an IDR.
    const st = createChunkFraming()
    stripChunkPrefix(st, framed(1, 0, 3, [1]))
    stripChunkPrefix(st, framed(2, 0, 1, [2])) // frame 2 completes, 1 abandoned
    expect(st.gaps).toBe(1)
    const late = stripChunkPrefix(st, framed(1, 2, 3, [9]))
    expect(late.gap).toBe(false)
    expect(late.payload).toBeNull()
    expect(st.stragglers).toBe(1)
    expect(st.gaps).toBe(1) // no second gap
  })

  it('treats a duplicate slot as a straggler, not a break', () => {
    const st = createChunkFraming()
    stripChunkPrefix(st, framed(5, 0, 2, [1]))
    const dup = stripChunkPrefix(st, framed(5, 0, 2, [1]))
    expect(dup.gap).toBe(false)
    expect(dup.payload).toBeNull()
    expect(st.stragglers).toBe(1)
    // The frame still completes on its real second chunk.
    expect(bytes(stripChunkPrefix(st, framed(5, 1, 2, [2])))).toEqual([1, 2])
    expect(st.gaps).toBe(0)
  })

  it('treats a late chunk of a COMPLETED frame as a straggler', () => {
    const st = createChunkFraming()
    stripChunkPrefix(st, framed(5, 0, 2, [1]))
    stripChunkPrefix(st, framed(5, 1, 2, [2])) // frame 5 complete
    const dup = stripChunkPrefix(st, framed(5, 1, 2, [2]))
    expect(dup.gap).toBe(false)
    expect(st.stragglers).toBe(1)
    expect(st.gaps).toBe(0)
  })

  it('bounds how many partial frames it will hold', () => {
    // Unbounded buffering on a lossy link is a memory leak with a slow
    // fuse: every frame that loses a chunk would be retained forever, on
    // the exact link where frames lose chunks.
    const st = createChunkFraming()
    for (let seq = 1; seq <= MAX_PARTIAL_FRAMES + 2; seq++) {
      stripChunkPrefix(st, framed(seq, 0, 2, [seq]))
      expect(st.partials.size).toBeLessThanOrEqual(MAX_PARTIAL_FRAMES)
    }
    // Each eviction is a real loss and is reported as one.
    expect(st.gaps).toBe(2)
  })

  it('classifies stragglers correctly across a u32 wrap', () => {
    // The agent advances frame_seq with `wrapping_add`, so 0 legitimately
    // follows 0xffffffff. A plain `<` comparison would read that wrap as
    // a jump backwards and mis-classify every chunk after it.
    const st = createChunkFraming()
    stripChunkPrefix(st, framed(0xfffffffe, 0, 1, [1])) // completes
    stripChunkPrefix(st, framed(0xffffffff, 0, 1, [2])) // completes
    // A re-delivered chunk from before the wrap is a straggler, NOT a
    // reason to start assembling a frame already moved past.
    const late = stripChunkPrefix(st, framed(0xfffffffe, 0, 1, [1]))
    expect(late.payload).toBeNull()
    expect(st.stragglers).toBe(1)
    // …and a fresh frame after the wrap is accepted, not straggled.
    const fresh = stripChunkPrefix(st, framed(0, 0, 1, [3]))
    expect(bytes(fresh)).toEqual([3])
  })

  it('resyncs instead of stalling forever if the sender restarts its counter', () => {
    // ⚠️ The failure an UNBOUNDED "older than what we have" rule would
    // cause: a fresh send task begins again at 1, every frame looks
    // ancient, is straggled, and the picture stops for good — with no gap
    // reported and nothing in the logs.
    const st = createChunkFraming()
    stripChunkPrefix(st, framed(5000, 0, 1, [1]))
    const restarted = stripChunkPrefix(st, framed(1, 0, 1, [2]))
    expect(bytes(restarted)).toEqual([2])
    expect(st.stragglers).toBe(0)
  })

  it('refuses a seq that changes its own chunk_count mid-frame', () => {
    // Two different frames colliding on one sequence number; guessing
    // which is right would splice their bytes together.
    const st = createChunkFraming()
    stripChunkPrefix(st, framed(3, 0, 4, [1]))
    const r = stripChunkPrefix(st, framed(3, 1, 2, [2]))
    expect(r.payload).toBeNull()
    expect(r.gap).toBe(true)
    expect(st.gaps).toBe(1)
    expect(st.partials.size).toBe(0)
  })
})
