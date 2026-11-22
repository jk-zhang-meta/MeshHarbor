// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, expect, it } from 'vitest'
import { BoardSync, liveCount } from '@/whiteboard/sync'

const el = (id: string, version: number, extra: Record<string, unknown> = {}) => ({
  id,
  version,
  versionNonce: 1,
  type: 'rectangle',
  ...extra,
})

describe('FR-126 whiteboard sync', () => {
  it('sends an element once per edit', () => {
    const s = new BoardSync()
    expect(s.outgoing([el('a', 1), el('b', 1)]).map((e) => e.id)).toEqual(['a', 'b'])
    // onChange fires for selection and pointer moves too: nothing new, nothing sent.
    expect(s.outgoing([el('a', 1), el('b', 1)])).toEqual([])
    expect(s.outgoing([el('a', 2), el('b', 1)]).map((e) => e.id)).toEqual(['a'])
  })

  it('never echoes what came from the meeting', () => {
    const s = new BoardSync()
    s.received([el('r', 5)])
    expect(s.outgoing([el('r', 5)])).toEqual([])
    expect(s.outgoing([el('r', 6)]).map((e) => e.version)).toEqual([6])
    // An older remote copy does not lower what this browser knows.
    s.received([el('r', 2)])
    expect(s.outgoing([el('r', 6)])).toEqual([])
  })

  it('sends deletions and never images', () => {
    const s = new BoardSync()
    s.outgoing([el('a', 1)])
    expect(s.outgoing([el('a', 2, { isDeleted: true })])).toHaveLength(1)
    expect(s.outgoing([el('img', 1, { type: 'image' })])).toEqual([])
  })

  it('counts live shapes only', () => {
    expect(liveCount([el('a', 1), el('b', 2, { isDeleted: true }), el('c', 1)])).toBe(2)
  })
})
