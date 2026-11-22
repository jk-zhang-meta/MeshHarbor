// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, expect, it } from 'vitest'
import { layoutTiles, pickMimeType } from '@/composables/useMeetingRecorder'

describe('FR-126 meeting recorder', () => {
  it('lays a grid out without overlap and inside the canvas', () => {
    for (const n of [1, 2, 3, 4, 5, 9, 10]) {
      const rects = layoutTiles(n, -1, 1280, 720)
      expect(rects).toHaveLength(n)
      for (const r of rects) {
        expect(r.x + r.w).toBeLessThanOrEqual(1280)
        expect(r.y + r.h).toBeLessThanOrEqual(720)
        expect(r.w).toBeGreaterThan(0)
      }
      const cells = new Set(rects.map((r) => `${r.x},${r.y}`))
      expect(cells.size).toBe(n)
    }
  })

  it('gives a screen share the stage and stacks the cameras beside it', () => {
    const rects = layoutTiles(4, 2, 1280, 720)
    expect(rects[2]).toEqual({ x: 0, y: 0, w: 998, h: 720 })
    for (const k of [0, 1, 3]) {
      expect(rects[k].x).toBe(998)
      expect(rects[k].y + rects[k].h).toBeLessThanOrEqual(720)
    }
    expect(layoutTiles(1, 0, 1280, 720)[0]).toEqual({ x: 0, y: 0, w: 1280, h: 720 })
    expect(layoutTiles(0, -1)).toEqual([])
  })

  it('picks the best WebM the browser records, or none', () => {
    expect(pickMimeType(() => true)).toBe('video/webm;codecs=vp9,opus')
    expect(pickMimeType((t) => t !== 'video/webm;codecs=vp9,opus')).toBe('video/webm;codecs=vp8,opus')
    expect(pickMimeType(() => false)).toBeNull()
  })
})
