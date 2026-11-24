// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { afterEach, describe, expect, it } from 'vitest'
import type { GlobeNode } from '@/components/globe/types'
import {
  getExternalGazetteer,
  resolveV2Location,
  setExternalGazetteer,
  type GazetteerV1,
} from '../locationResolver'

function makeNode(id: string, extra: Partial<GlobeNode> = {}): GlobeNode {
  return {
    id,
    name: id,
    online: true,
    presence: 'online',
    ...extra,
  }
}

afterEach(() => {
  setExternalGazetteer(null)
})

describe('locationResolver — all 5 S7 precision tiers, P1 gazetteer adapter, zero relay_home fallback', () => {
  it('Tier 1 (coords): consumes P6 lat/lon/accuracyRadiusKm/geoLevel when present', () => {
    const res = resolveV2Location(
      makeNode('p6-dev', {
        countryCode: 'JP',
        city: 'Tokyo',
        lat: 35.6895,
        lon: 139.6917,
        accuracyRadiusKm: 25,
        geoLevel: 'coords',
      }),
    )
    expect(res.precision).toBe('coords')
    expect(res.lon).toBeCloseTo(139.6917, 4)
    expect(res.lat).toBeCloseTo(35.6895, 4)
    expect(res.accuracyRadiusKm).toBe(25)
    expect(res.groupKey).toBe('coords:139.69,35.69')
    expect(res.placeEn).toBe('Tokyo')
    expect(res.placeZh).toBe('东京')
  })

  it('Tier 2 (city): uses injected P1 GazetteerV1 when loaded and falls back to built-in table', () => {
    const mockGaz: GazetteerV1 = {
      version: 1,
      countries: {
        IS: [-19.02, 64.96, 'Iceland', '冰岛'],
      },
      regions: {
        'DE:bavaria': [11.49, 48.79, 'Bavaria', '巴伐利亚'],
      },
      cities: {
        'IS:reykjavik': [-21.94, 64.15, 'Reykjavik', '雷克雅未克'],
      },
    }
    setExternalGazetteer(mockGaz)
    expect(getExternalGazetteer()).toBe(mockGaz)

    const hit = resolveV2Location(makeNode('is-1', { countryCode: 'IS', city: 'Reykjavik' }))
    expect(hit.precision).toBe('city')
    expect(hit.lon).toBeCloseTo(-21.94, 2)
    expect(hit.lat).toBeCloseTo(64.15, 2)
    expect(hit.placeEn).toBe('Reykjavik')
    expect(hit.placeZh).toBe('雷克雅未克')
    expect(hit.groupKey).toBe('city:-21.94,64.15')

    // Built-in fallback still works when city is not in mock gazetteer
    const sh = resolveV2Location(makeNode('cn-1', { countryCode: 'CN', city: '上海市' }))
    expect(sh.precision).toBe('city')
    expect(sh.placeZh).toBe('上海')
  })

  it('Tier 3 (region): resolves province/state centroid from gazetteer or built-in table', () => {
    const mockGaz: GazetteerV1 = {
      version: 1,
      countries: {},
      regions: { 'DE:bavaria': [11.49, 48.79, 'Bavaria', '巴伐利亚'] },
      cities: {},
    }
    const bav = resolveV2Location(
      makeNode('de-reg', { countryCode: 'DE', region: 'Bavaria' }),
      mockGaz,
    )
    expect(bav.precision).toBe('region')
    expect(bav.groupKey).toBe('region:11.49,48.79')
    expect(bav.placeZh).toBe('巴伐利亚')

    const gd = resolveV2Location(makeNode('cn-reg', { countryCode: 'CN', region: '广东省' }))
    expect(gd.precision).toBe('region')
    expect(gd.placeZh).toBe('广东省')
  })

  it('Tier 4 (country): resolves country/region label point with neutral TW/HK/MO naming', () => {
    const tw = resolveV2Location(makeNode('tw-1', { countryCode: 'TW' }))
    expect(tw.precision).toBe('country')
    expect(tw.placeZh).toBe('台湾')
    expect(tw.placeEn).toBe('Taiwan')

    const hk = resolveV2Location(makeNode('hk-1', { countryCode: 'HK' }))
    expect(hk.precision).toBe('country')
    expect(hk.placeZh).toBe('香港')
    expect(hk.placeEn).toBe('Hong Kong')

    const jp = resolveV2Location(makeNode('jp-1', { countryCode: 'JP' }))
    expect(jp.precision).toBe('country')
    expect(jp.placeZh).toBe('日本')
    expect(jp.placeEn).toBe('Japan')
  })

  it('Tier 5 (unknown): NEVER uses relayHome for placement', () => {
    const relayOnly = resolveV2Location(
      makeNode('relay-only', { relayHome: 'us-east', countryCode: null, city: null, region: null }),
    )
    expect(relayOnly.precision).toBe('unknown')
    expect(relayOnly.lon).toBeNull()
    expect(relayOnly.lat).toBeNull()
    expect(relayOnly.groupKey).toBeNull()

    const explicitUnknown = resolveV2Location(
      makeNode('explicit-unknown', {
        lat: 35.68,
        lon: 139.69,
        geoLevel: 'unknown',
        relayHome: 'jp',
      }),
    )
    expect(explicitUnknown.precision).toBe('unknown')
    expect(explicitUnknown.groupKey).toBeNull()
  })
})
