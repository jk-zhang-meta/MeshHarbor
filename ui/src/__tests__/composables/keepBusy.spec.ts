// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, it, expect } from 'vitest'
import {
  KEEP_BUSY_PATTERNS,
  isKeepBusyPattern,
  keepBusyBriefTitle,
  keepBusyRefusalText,
  keepBusyResumesInS,
  keepBusySetMessage,
  keepBusyStatusLine,
  parseKeepBusyState,
  patternPoints,
  patternPreviewPath,
  type KeepBusyState,
} from '@/composables/keepBusy'

/** A state as the agent sends it (`agents/meshharbord/src/keep_busy/wire.rs`). */
function wire(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    t: 'rc:keep-busy.state',
    rev: 7,
    available: true,
    on: true,
    phase: 'running',
    reason: null,
    sentence: null,
    paused_by: null,
    resumes_in_ms: null,
    pattern: 'heart',
    size: 'l',
    speed: 'fast',
    resume_after_s: 60,
    auto_off_at_ms: null,
    set_by: 'Alice',
    set_at_ms: 1,
    detector: 'clock+cursor',
    warn: [],
    ...over,
  }
}

function parsed(over: Record<string, unknown> = {}, now = 1_000): KeepBusyState {
  const s = parseKeepBusyState(wire(over), now)
  if (!s) throw new Error('did not parse')
  return s
}

describe('parseKeepBusyState', () => {
  it('parses what the agent sends', () => {
    const s = parsed()
    expect(s.on).toBe(true)
    expect(s.phase).toBe('running')
    expect(s.pattern).toBe('heart')
    expect(s.size).toBe('l')
    expect(s.speed).toBe('fast')
    expect(s.resumeAfterS).toBe(60)
    expect(s.setBy).toBe('Alice')
    expect(s.refused).toBeNull()
  })

  it('is null for anything that is not a keep-busy state', () => {
    expect(parseKeepBusyState({ t: 'rc:host_locked', locked: true })).toBeNull()
    expect(parseKeepBusyState({ t: 'rc:keep-busy.state' })).toBeNull()
    expect(parseKeepBusyState({ t: 'rc:keep-busy.state', on: 'yes', available: true })).toBeNull()
  })

  it('degrades unknown values from a newer agent instead of failing', () => {
    const s = parsed({ pattern: 'hyperspiral', phase: 'teleporting', size: 'xl', speed: 'warp' })
    expect(s.pattern).toBe('circle')
    expect(s.phase).toBe('unavailable')
    expect(s.size).toBe('m')
    expect(s.speed).toBe('normal')
  })

  it('keeps only string warnings and carries a refusal', () => {
    const s = parsed({ warn: ['focus_follows_mouse', 7, null], refused: 'not_floor_holder' })
    expect(s.warn).toEqual(['focus_follows_mouse'])
    expect(s.refused).toBe('not_floor_holder')
  })
})

describe('keepBusySetMessage', () => {
  it('sends everything when turning on', () => {
    expect(
      keepBusySetMessage({ on: true, pattern: 'star', size: 's', speed: 'slow', resumeAfterS: 10, autoOffMin: 60 }),
    ).toEqual({
      t: 'rc:keep-busy.set',
      on: true,
      pattern: 'star',
      size: 's',
      speed: 'slow',
      resume_after_s: 10,
      auto_off_min: 60,
    })
  })

  it('sends never as null, and an off carries nothing else', () => {
    expect(keepBusySetMessage({ on: true, autoOffMin: 0 }).auto_off_min).toBeNull()
    expect(keepBusySetMessage({ on: false, pattern: 'star' })).toEqual({ t: 'rc:keep-busy.set', on: false })
  })
})

describe('keepBusyStatusLine', () => {
  it('says who turned it on and what it draws', () => {
    expect(keepBusyStatusLine(parsed())).toBe('Running: heart, turned on by Alice.')
  })

  it('counts a pause down locally from the agent figure', () => {
    const s = parsed(
      { phase: 'paused', reason: 'user_active', sentence: 'Paused: someone is using this computer.', resumes_in_ms: 23_000 },
      1_000,
    )
    expect(keepBusyResumesInS(s, 1_000)).toBe(23)
    expect(keepBusyResumesInS(s, 11_000)).toBe(13)
    expect(keepBusyStatusLine(s, 11_000)).toBe(
      'Paused: someone is using this computer. Resumes in 13 s if nothing else happens.',
    )
    // Past zero the person is still at it — say so, never a negative count.
    expect(keepBusyStatusLine(s, 60_000)).toBe('Paused: someone is using this computer. Resumes once they stop.')
  })

  it("uses the agent's own sentence when it cannot run", () => {
    const s = parsed({ available: false, on: false, phase: 'off', reason: 'org_denied', sentence: 'Disabled by your organization.' })
    expect(keepBusyStatusLine(s)).toBe('Disabled by your organization.')
  })

  it('says a local stop out loud, and a plain off plainly', () => {
    expect(
      keepBusyStatusLine(parsed({ on: false, phase: 'off', reason: 'stopped_locally', sentence: 'Turned off at this computer.' })),
    ).toBe('Turned off at this computer.')
    expect(
      keepBusyStatusLine(parsed({ on: false, phase: 'off', reason: 'stopped_by_controller', sentence: 'x' })),
    ).toBe('Off.')
  })
})

describe('keepBusyBriefTitle (FR-92 P5b)', () => {
  it('says what runs, who turned it on and the phase — only while on', () => {
    expect(
      keepBusyBriefTitle({ on: true, phase: 'paused', reason: 'user_active', pattern: 'heart', set_by: 'Alice' }),
    ).toBe('Keep busy is on: heart, turned on by Alice. Now paused (user active), as the device reports it.')
    expect(keepBusyBriefTitle({ on: true, phase: 'running' })).toBe(
      'Keep busy is on: a pattern. Now running, as the device reports it.',
    )
  })
  it('says nothing for off or unknown', () => {
    expect(keepBusyBriefTitle({ on: false, phase: 'off', reason: 'stopped_locally' })).toBe('')
    expect(keepBusyBriefTitle(undefined)).toBe('')
  })
})

describe('keepBusyRefusalText', () => {
  it('has a sentence for every refusal the agent sends', () => {
    for (const code of ['no_input_permission', 'not_floor_holder', 'org_denied', 'unsupported', 'bad_request']) {
      expect(keepBusyRefusalText(code)).not.toBe('The device did not apply the change.')
    }
    expect(keepBusyRefusalText('something_new')).toBe('The device did not apply the change.')
  })
})

describe('isKeepBusyPattern (FR-92 P8)', () => {
  it('knows every pattern by its exact id and nothing else', () => {
    for (const p of KEEP_BUSY_PATTERNS) expect(isKeepBusyPattern(p.id)).toBe(true)
    // Equality: no prefix, no case-fold, no other type.
    for (const v of ['hearts', 'hea', 'Heart', 'circle ', '', null, undefined, 3]) {
      expect(isKeepBusyPattern(v)).toBe(false)
    }
  })
})

describe('pattern previews', () => {
  it('draws every pattern, closed, inside the box', () => {
    for (const { id } of KEEP_BUSY_PATTERNS) {
      const d = patternPreviewPath(id, 48, 6)
      expect(d, id).toMatch(/^M/)
      expect(d.trim().endsWith('Z'), id).toBe(true)
      const nums = d.match(/-?\d+(\.\d+)?/g)?.map(Number) ?? []
      expect(nums.length, id).toBeGreaterThan(4)
      for (const n of nums) {
        expect(n, `${id}: ${n}`).toBeGreaterThanOrEqual(0)
        expect(n, `${id}: ${n}`).toBeLessThanOrEqual(48)
      }
    }
  })

  it('normalises each drawable shape to fill the box', () => {
    for (const { id } of KEEP_BUSY_PATTERNS.filter((p) => p.id !== 'subtle' && p.id !== 'shuffle')) {
      const d = patternPreviewPath(id, 100, 0)
      const xs = (d.match(/[ML](-?\d+(\.\d+)?)/g) ?? []).map((m) => Number(m.slice(1)))
      expect(Math.max(...xs) - Math.min(...xs), id).toBeGreaterThan(50)
    }
  })

  it('draws the same wander every time (a seeded preview)', () => {
    expect(patternPreviewPath('wander')).toBe(patternPreviewPath('wander'))
    expect(patternPoints('shuffle')).toHaveLength(3)
  })
})
