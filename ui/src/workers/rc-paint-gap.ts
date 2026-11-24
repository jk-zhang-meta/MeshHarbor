// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-130 P1c (#3604) — a paint path's half of `rc.resume`'s `gap_ms`: how far
 * the first frame painted after a cut came after the last frame painted before
 * it.
 *
 * A held session's pixels never cross the server, so on a direct or TURN
 * carrier the picture should not notice a server roll at all, and AC2 reads
 * that as "no gap above 500 ms in the frames the viewer paints across the
 * roll". The cut is the moment the page starts to hold (its own socket's loss,
 * or `rc:session.detached`). Only the paint path knows when it painted, so each
 * keeps one of these: the data-channel worker and the RTP-transform worker,
 * each on its own `performance.now()`, and the page for the `<video>` path.
 *
 * | Message | Direction | Carries |
 * |---|---|---|
 * | {@link PAINT_GAP_MARK} | page → worker | the cut |
 * | {@link PAINT_GAP_MARKED} | worker → page, at once | `sinceMs`: how long before the cut the last frame was painted, `null` before any |
 * | {@link PAINT_GAP_CLOSED} | worker → page, at the first frame painted after the cut | `gapMs`: from the last frame before the cut to it, `null` when none came before |
 *
 * Both numbers are differences on the paint path's own clock, so a worker's
 * epoch is never compared with the page's (#3566).
 *
 * ⚠️ Record, never decide: nothing acts on these. A worker posts nothing
 * unless the page marked a cut, so a session that never holds sends exactly
 * what it sent before.
 */

/** page → worker: the cut. */
export const PAINT_GAP_MARK = 'paint-gap-mark'
/** worker → page, answering the mark: `{ sinceMs: number | null }`. */
export const PAINT_GAP_MARKED = 'paint-gap-marked'
/** worker → page, at the first frame painted after the mark: `{ gapMs: number | null }`. */
export const PAINT_GAP_CLOSED = 'paint-gap'

export interface PaintGapMark {
  /** The cut, at `nowMs`: how long before it the last frame was painted, `null` before any. */
  mark(nowMs: number): number | null
  /** A frame was painted at `nowMs`. The first one after a mark closes its
   *  gap and returns it (`gapMs` `null` when nothing was painted before the
   *  mark); every other frame returns `null`. */
  painted(nowMs: number): { gapMs: number | null } | null
  /** Forget every frame: a new session on the same paint path. */
  reset(): void
}

export function createPaintGapMark(): PaintGapMark {
  let lastPaintMs: number | null = null
  /** `undefined`: no mark armed. Otherwise the last paint before the mark. */
  let lastBeforeMark: number | null | undefined = undefined
  return {
    mark(nowMs) {
      lastBeforeMark = lastPaintMs
      return lastPaintMs === null ? null : nowMs - lastPaintMs
    },
    painted(nowMs) {
      let closed: { gapMs: number | null } | null = null
      if (lastBeforeMark !== undefined) {
        closed = { gapMs: lastBeforeMark === null ? null : nowMs - lastBeforeMark }
        lastBeforeMark = undefined
      }
      lastPaintMs = nowMs
      return closed
    },
    reset() {
      lastPaintMs = null
      lastBeforeMark = undefined
    },
  }
}
