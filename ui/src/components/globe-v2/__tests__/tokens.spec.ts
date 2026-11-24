// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, expect, it } from 'vitest'
import {
  BOUNDARY_ATTRIBUTION,
  contrastRatio,
  DARK_TOKENS,
  formatNeutralRegionName,
  LIGHT_TOKENS,
  REGION_NAME_OVERRIDES,
} from '../tokens'

describe('globe-v2 visual tokens — WCAG 1.4.11 non-text contrast (>= 3:1)', () => {
  const statusAndLinkKeys = [
    'online',
    'direct',
    'stale',
    'relay',
    'derp',
    'tunnel',
    'offline',
    'blocked',
    'stalled',
    'centre',
    'focusRing',
  ] as const

  it('meets >= 3:1 contrast for all dark-theme status, link, and zone colors against land and ocean', () => {
    for (const key of statusAndLinkKeys) {
      const c = DARK_TOKENS[key]
      expect(contrastRatio(c, DARK_TOKENS.land), `dark.${key} vs land`).toBeGreaterThanOrEqual(3.0)
      expect(contrastRatio(c, DARK_TOKENS.ocean), `dark.${key} vs ocean`).toBeGreaterThanOrEqual(3.0)
    }
    DARK_TOKENS.zones.forEach((z, idx) => {
      expect(contrastRatio(z, DARK_TOKENS.land), `dark.zone${idx + 1} vs land`).toBeGreaterThanOrEqual(3.0)
      expect(contrastRatio(z, DARK_TOKENS.ocean), `dark.zone${idx + 1} vs ocean`).toBeGreaterThanOrEqual(3.0)
    })
  })

  it('meets >= 3:1 contrast for all light-theme status, link, and zone colors (incl. zone5 #8A7A00) against land and ocean', () => {
    expect(LIGHT_TOKENS.zones[4]).toBe('#8A7A00')
    for (const key of statusAndLinkKeys) {
      const c = LIGHT_TOKENS[key]
      expect(contrastRatio(c, LIGHT_TOKENS.land), `light.${key} vs land`).toBeGreaterThanOrEqual(3.0)
      expect(contrastRatio(c, LIGHT_TOKENS.ocean), `light.${key} vs ocean`).toBeGreaterThanOrEqual(3.0)
    }
    LIGHT_TOKENS.zones.forEach((z, idx) => {
      expect(contrastRatio(z, LIGHT_TOKENS.land), `light.zone${idx + 1} vs land`).toBeGreaterThanOrEqual(3.0)
      expect(contrastRatio(z, LIGHT_TOKENS.ocean), `light.zone${idx + 1} vs ocean`).toBeGreaterThanOrEqual(3.0)
    })
  })

  it('applies neutral TWN/HKG/MAC region overrides and carries bilingual attribution', () => {
    expect(REGION_NAME_OVERRIDES.TWN).toEqual({ zh: '台湾', en: 'Taiwan' })
    expect(REGION_NAME_OVERRIDES.HKG).toEqual({ zh: '香港', en: 'Hong Kong' })
    expect(REGION_NAME_OVERRIDES.MAC).toEqual({ zh: '澳门', en: 'Macau' })

    expect(formatNeutralRegionName('TW', 'Taiwan', 'zh-CN')).toBe('台湾')
    expect(formatNeutralRegionName('TWN', 'Taiwan', 'en')).toBe('Taiwan')
    expect(formatNeutralRegionName('HK', 'Hong Kong SAR', 'zh-CN')).toBe('香港')
    expect(formatNeutralRegionName('MO', 'Macao', 'en')).toBe('Macau')
    expect(BOUNDARY_ATTRIBUTION['zh-CN']).toContain('Natural Earth')
    expect(BOUNDARY_ATTRIBUTION['zh-CN']).toContain('geoBoundaries')
    expect(BOUNDARY_ATTRIBUTION.en).toContain('OpenStreetMap')
  })
})
