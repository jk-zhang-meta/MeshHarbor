// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-130 P1c (#3604) — a paint path's half of `rc.resume`'s `gap_ms`: the
// decode workers and the page's `<video>` path keep one of these, the page
// marks the cut (`paint-gap-mark`), and the first frame painted after it says
// how far it came after the last one before it. Both stamps are on the paint
// path's own clock, so no clock is compared with another.
import { describe, expect, it } from 'vitest'
import {
  PAINT_GAP_MARK,
  PAINT_GAP_MARKED,
  PAINT_GAP_CLOSED,
  createPaintGapMark,
} from '@/workers/rc-paint-gap'

describe('createPaintGapMark', () => {
  it('says nothing about frames painted while no cut is marked', () => {
    const m = createPaintGapMark()
    expect(m.painted(100)).toBeNull()
    expect(m.painted(133)).toBeNull()
  })

  it('the mark says how long ago the last frame was painted; null before any', () => {
    const m = createPaintGapMark()
    expect(m.mark(50)).toBeNull()
    const n = createPaintGapMark()
    n.painted(100)
    n.painted(133)
    expect(n.mark(150)).toBe(17)
  })

  it('the first frame painted after the mark closes the gap, and only that one', () => {
    const m = createPaintGapMark()
    m.painted(100)
    m.painted(133)
    m.mark(150)
    expect(m.painted(166)).toEqual({ gapMs: 33 })
    expect(m.painted(199)).toBeNull()
  })

  it('a mark before any frame: the first frame after it has no gap to name', () => {
    const m = createPaintGapMark()
    m.mark(10)
    expect(m.painted(500)).toEqual({ gapMs: null })
  })

  it('a frozen picture: the gap spans the whole freeze', () => {
    const m = createPaintGapMark()
    m.painted(1_000)
    m.mark(1_050)
    expect(m.painted(3_436)).toEqual({ gapMs: 2_436 })
  })

  it('reset forgets the frames before it (a new session on the same page)', () => {
    const m = createPaintGapMark()
    m.painted(1_000)
    m.reset()
    expect(m.mark(1_050)).toBeNull()
    expect(m.painted(1_100)).toEqual({ gapMs: null })
  })

  it('names its messages once, for the page and both workers', () => {
    expect(PAINT_GAP_MARK).toBe('paint-gap-mark')
    expect(PAINT_GAP_MARKED).toBe('paint-gap-marked')
    expect(PAINT_GAP_CLOSED).toBe('paint-gap')
  })
})
