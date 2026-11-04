// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, it, expect, beforeEach } from 'vitest'
import { useSpotlightTour, TOURS } from '@/composables/useSpotlightTour'

// Read the sources through Vite's own glob rather than node:fs — the UI
// project has no @types/node, and adding a dependency to let one test list
// files is a poor trade.
const SOURCES = import.meta.glob('../../**/*.{vue,ts}', {
  eager: true,
  query: '?raw',
  import: 'default',
}) as Record<string, string>

/** Every `data-tour="…"` value rendered anywhere in the UI source. */
function anchorsInSource(): Set<string> {
  const found = new Set<string>()
  for (const [path, text] of Object.entries(SOURCES)) {
    // Skip the tests themselves: this very file contains the pattern.
    if (path.includes('__tests__')) continue
    for (const m of text.matchAll(/data-tour="([^"]+)"/g)) found.add(m[1])
  }
  return found
}

describe('useSpotlightTour', () => {
  beforeEach(() => {
    localStorage.clear()
    // The state is module-scoped (one overlay, many starters), so a test that
    // leaves a tour running would leak into the next one.
    useSpotlightTour().end(false)
  })

  it('every registered tour has an id matching its key and at least one step', () => {
    for (const [key, def] of Object.entries(TOURS)) {
      expect(def.id, `${key} declares a different id`).toBe(key)
      expect(def.steps.length, `${key} has no steps`).toBeGreaterThan(0)
      expect(def.routeName).toBeTruthy()
      for (const s of def.steps) {
        // ⚠️ Anchors are data-tour names, not CSS. A selector-shaped anchor
        // here would still "work" until markup moved, then silently point at
        // the wrong control.
        expect(s.anchor, `${key}: "${s.anchor}" looks like a CSS selector`).not.toMatch(/[.#\s>:[\]]/)
        expect(s.title).toBeTruthy()
        expect(s.body).toBeTruthy()
      }
    }
  })

  // 🔑 The failure this guards is silent: a tour whose anchor was renamed or
  // deleted dims the page, waits, finds nothing and skips the step — the user
  // sees a flicker and no explanation. Nothing throws, no test fails, and the
  // tour quietly stops teaching what it was written to teach.
  it('every tour anchor exists in the UI source', () => {
    const present = anchorsInSource()
    for (const [key, def] of Object.entries(TOURS)) {
      for (const s of def.steps) {
        expect(present.has(s.anchor), `tour "${key}" points at data-tour="${s.anchor}", which no component renders`).toBe(true)
      }
    }
  })

  it('refuses an unknown tour rather than opening an empty overlay', () => {
    const t = useSpotlightTour()
    expect(t.start('does-not-exist')).toBe(false)
    expect(t.active.value).toBe(false)
  })

  it('walks its steps and ends after the last one', () => {
    const t = useSpotlightTour()
    expect(t.start('enroll')).toBe(true)
    const n = TOURS.enroll.steps.length

    for (let i = 0; i < n - 1; i++) {
      expect(t.stepIndex.value).toBe(i)
      expect(t.isLast.value).toBe(i === n - 1)
      t.next()
    }
    expect(t.isLast.value).toBe(true)
    t.next()
    expect(t.active.value).toBe(false)
  })

  it('marks a tour seen whether it was finished or skipped', () => {
    const t = useSpotlightTour()
    t.start('enroll')
    t.end(false) // skipped
    expect(t.hasSeen('enroll')).toBe(true)

    // Re-offering something you dismissed is nagging; "seen" must not mean
    // "completed".
    localStorage.clear()
    t.start('viewer')
    while (t.active.value) t.next()
    expect(t.hasSeen('viewer')).toBe(true)
  })

  it('a missing anchor advances instead of stranding the overlay', () => {
    const t = useSpotlightTour()
    t.start('enroll')
    const n = TOURS.enroll.steps.length
    t.skipMissingStep()
    expect(t.stepIndex.value).toBe(1)

    // …and skipping the LAST step ends the tour rather than running off the end.
    for (let i = 1; i < n - 1; i++) t.skipMissingStep()
    expect(t.isLast.value).toBe(true)
    t.skipMissingStep()
    expect(t.active.value).toBe(false)
  })

  it('survives unreadable storage', () => {
    localStorage.setItem('meshharbor-tour-seen', '{not json')
    const t = useSpotlightTour()
    expect(t.hasSeen('enroll')).toBe(false)
    expect(t.start('enroll')).toBe(true)
  })
})
