// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, expect, it } from 'vitest'
import { STALL_HOURS, updateStallChip, versionOrdinal, type AgentReleaseBrief } from '@/utils/updateStall'

const HOUR = 3_600_000
const NOW = Date.parse('2026-10-16T12:00:00Z')
const ago = (hours: number) => new Date(NOW - hours * HOUR).toISOString()
const rel = (v: string, hoursAgo: number, extra: Partial<AgentReleaseBrief> = {}): AgentReleaseBrief => ({
  tag_name: `agent-v${v}`,
  published_at: ago(hoursAgo),
  ...extra,
})
// Newest first, as the feed returns them: 0.4.139 two hours old, 0.4.138 twelve, 0.4.137 a day and more.
const FEED = [rel('0.4.139', 2), rel('0.4.138', 14), rel('0.4.137', 25), rel('0.4.136', 40), rel('0.4.135', 60)]

describe('versionOrdinal (FR-106)', () => {
  it('orders 0.4.N by N, puts every 0.3.0-rc before them, and refuses anything else', () => {
    expect(versionOrdinal('0.4.139')).toBe(139)
    expect(versionOrdinal('agent-v0.4.48')).toBe(48)
    expect(versionOrdinal('v0.4.7')).toBe(7)
    expect(versionOrdinal('0.3.0-rc.486')!).toBeLessThan(versionOrdinal('0.4.0')!)
    expect(versionOrdinal('0.4.1-1')).toBeNull()
    expect(versionOrdinal('garbage')).toBeNull()
    expect(versionOrdinal('')).toBeNull()
    expect(versionOrdinal(undefined)).toBeNull()
  })
})

describe('updateStallChip (FR-106)', () => {
  it('stays quiet for a healthy device: up to date, or behind only by releases younger than a day', () => {
    expect(updateStallChip('0.4.139', true, 'linux', FEED, NOW)).toBeNull()
    // Behind 0.4.139 (2 h) and 0.4.138 (14 h): the oldest missed is 14 h old.
    expect(updateStallChip('0.4.137', true, 'linux', FEED, NOW)).toBeNull()
  })

  it('measures from the OLDEST missed release, so a fresh release never hides an old stall', () => {
    // On 0.4.136 the first missed release, 0.4.137, has been out 25 h: a chip, whatever came since.
    const chip = updateStallChip('0.4.136', true, 'windows', FEED, NOW)
    expect(chip?.text).toBe('not updating')
    expect(chip?.color).toBe('warning')
    expect(chip?.tooltip).toContain('v0.4.136 is 3 releases behind')
    expect(chip?.tooltip).toContain('0.4.137 came out 1 d ago')
  })

  it('stays quiet for an offline device: it updates when it comes back', () => {
    expect(updateStallChip('0.4.48', false, 'linux', FEED, NOW)).toBeNull()
  })

  it('stays quiet when anything is unknown: no list, an empty list, an unparseable version', () => {
    expect(updateStallChip('0.4.48', true, 'linux', [], NOW)).toBeNull()
    expect(updateStallChip('0.4.48', true, 'linux', null, NOW)).toBeNull()
    expect(updateStallChip('0.4.48', true, 'linux', undefined, NOW)).toBeNull()
    expect(updateStallChip('', true, 'linux', FEED, NOW)).toBeNull()
    expect(updateStallChip('dev-build', true, 'linux', FEED, NOW)).toBeNull()
  })

  it('ignores drafts, prereleases and releases with no publish time', () => {
    const feed = [rel('0.4.140', 48, { draft: true }), rel('0.4.141', 48, { prerelease: true }), { tag_name: 'agent-v0.4.142' }]
    expect(updateStallChip('0.4.139', true, 'linux', feed, NOW)).toBeNull()
  })

  it('a device older than everything listed is "N+" behind, with the oldest listed release named', () => {
    const chip = updateStallChip('0.4.48', true, 'linux', FEED, NOW)
    expect(chip?.tooltip).toContain('v0.4.48 is 5+ releases behind')
    expect(chip?.tooltip).toContain('0.4.135 came out 2 d ago')
    expect(updateStallChip('0.3.0-rc.286', true, 'linux', FEED, NOW)?.tooltip).toContain('5+ releases behind')
  })

  it('names the per-user Linux remedy on Linux, and only the generic check elsewhere', () => {
    const linux = updateStallChip('0.4.136', true, 'linux', FEED, NOW)!.tooltip
    expect(linux).toContain('per-user Linux install made before 0.4.138')
    expect(linux).toContain('sudo apt install ./meshharbord.deb')
    expect(linux).toContain("'mh config ls'")
    for (const os of ['windows', 'macos']) {
      const other = updateStallChip('0.4.136', true, os, FEED, NOW)!.tooltip
      expect(other).not.toContain('per-user Linux')
      expect(other).toContain("'mh logs --grep update'")
    }
  })

  it('the threshold is exactly STALL_HOURS', () => {
    const edge = [rel('0.4.2', STALL_HOURS)]
    expect(updateStallChip('0.4.1', true, 'linux', edge, NOW)).not.toBeNull()
    const justUnder = [{ tag_name: 'agent-v0.4.2', published_at: new Date(NOW - STALL_HOURS * HOUR + 1000).toISOString() }]
    expect(updateStallChip('0.4.1', true, 'linux', justUnder, NOW)).toBeNull()
  })
})
