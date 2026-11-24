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
  relativeLuminance,
} from '../tokens'
import { buildGlobeStyle } from '../style'

describe('globe-v2 visual tokens — WCAG 1.4.11 non-text contrast (>= 3:1) & dark theme separation', () => {
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

  it('Fix #5: clearly separates dark land from dark ocean and gives crisp coastline luminance', () => {
    const lOcean = relativeLuminance(DARK_TOKENS.ocean)
    const lLand = relativeLuminance(DARK_TOKENS.land)
    const lCoast = relativeLuminance(DARK_TOKENS.coast)
    expect(lLand).toBeGreaterThan(lOcean * 2.0)
    expect(lCoast).toBeGreaterThan(lLand * 2.5)
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

  it('defines China 4-level boundaries (admin2-pref-chn z5, admin2-chn z8) and district labels (z9) below device labels', () => {
    const style = buildGlobeStyle('dark', 'zh-CN', '/geo/mh-boundaries-v1.pmtiles', false)
    const ids = style.layers.map((l) => l.id)
    const prefLayer = style.layers.find((l) => l.id === 'admin2-pref-chn') as {
      'source-layer'?: string
      minzoom?: number
    }
    const chnLayer = style.layers.find((l) => l.id === 'admin2-chn') as {
      'source-layer'?: string
      minzoom?: number
    }
    const otherLayer = style.layers.find((l) => l.id === 'admin2-other') as {
      'source-layer'?: string
      minzoom?: number
    }
    const label2 = style.layers.find((l) => l.id === 'label-admin2') as {
      'source-layer'?: string
      minzoom?: number
    }
    const labelPlace = style.layers.find((l) => l.id === 'label-place') as {
      'source-layer'?: string
      maxzoom?: number
    }
    expect(prefLayer?.['source-layer']).toBe('admin2_pref')
    expect(prefLayer?.minzoom).toBe(5)
    expect(chnLayer?.['source-layer']).toBe('admin2')
    expect(chnLayer?.minzoom).toBe(8)
    expect(otherLayer?.['source-layer']).toBe('admin2')
    expect(otherLayer?.minzoom).toBe(5)
    expect(label2?.['source-layer']).toBe('label_admin2')
    expect(label2?.minzoom).toBe(9)
    expect(labelPlace?.['source-layer']).toBe('label_place')
    expect(labelPlace?.maxzoom).toBe(8)

    // District labels MUST be below blocker and device/cluster label layers so app labels win collision
    expect(ids.indexOf('label-admin2')).toBeLessThan(ids.indexOf('mh-label-blockers'))
    expect(ids.indexOf('mh-label-blockers')).toBeLessThan(ids.indexOf('mh-marker-labels-center'))
    expect(ids.indexOf('mh-marker-labels-center')).toBeLessThan(ids.indexOf('mh-markers'))
  })
})
