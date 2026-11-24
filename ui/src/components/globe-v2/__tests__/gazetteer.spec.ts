// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD

import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { gzipSync } from 'node:zlib'
import { describe, expect, it } from 'vitest'
import {
  ATTRIBUTION_TEXT,
  loadGazetteer,
  NEUTRAL_REGION_OVERRIDES,
  normalizeGeoKey,
  resolveFromGazetteer,
  type GazetteerV1,
} from '../gazetteer'

const GAZETTEER_PATH = resolve(__dirname, '../data/gazetteer-v1.json')
const MAX_GZIP_BYTES = 150 * 1024 // S11 budget: <= 150 KB gz

describe('globe-v2 lazy gazetteer (S4 / S6 / S11 / AC7)', () => {
  it('parses gazetteer-v1.json cleanly and stays within <= 150 KB gzip budget', async () => {
    const rawBuf = readFileSync(GAZETTEER_PATH)
    const gzBuf = gzipSync(rawBuf, { level: 9 })
    expect(gzBuf.byteLength).toBeLessThanOrEqual(MAX_GZIP_BYTES)

    const loaded = await loadGazetteer()
    expect(loaded.version).toBe(1)
    expect(Object.keys(loaded.countries).length).toBeGreaterThanOrEqual(200)
    expect(Object.keys(loaded.regions).length).toBeGreaterThanOrEqual(3000)
    expect(Object.keys(loaded.cities).length).toBeGreaterThanOrEqual(3000)

    // Subsequent calls return the same cached promise / object
    const loadedAgain = await loadGazetteer()
    expect(loadedAgain).toBe(loaded)
  })

  it('covers all key global and China countries, provinces, and cities (AC6 + cloud hubs)', async () => {
    const g = await loadGazetteer()

    const requiredCountries = [
      'CN', 'US', 'IN', 'DE', 'BR', 'JP', 'AU', 'RU', 'ZA',
      'TW', 'HK', 'MO', 'SG', 'GB', 'FR',
    ]
    for (const cc of requiredCountries) {
      const entry = g.countries[cc]
      expect(entry, `missing country ${cc}`).toBeDefined()
      expect(entry![0]).toBeGreaterThanOrEqual(-180)
      expect(entry![0]).toBeLessThanOrEqual(180)
      expect(entry![1]).toBeGreaterThanOrEqual(-85)
      expect(entry![1]).toBeLessThanOrEqual(85)
      expect(entry![2].length).toBeGreaterThan(0)
      expect(entry![3].length).toBeGreaterThan(0)
    }

    const cityProbes: Array<[string, string, string]> = [
      ['CN', '北京', 'Beijing'],
      ['CN', '上海市', 'Shanghai'],
      ['CN', '深圳', 'Shenzhen'],
      ['CN', '广州', 'Guangzhou'],
      ['CN', "Xi'an", "Xi'an"],
      ['CN', '成都', 'Chengdu'],
      ['CN', '杭州', 'Hangzhou'],
      ['US', 'Ashburn', 'Ashburn'],
      ['US', 'San Jose', 'San Jose'],
      ['US', 'New York', 'New York'],
      ['IN', 'Mumbai', 'Mumbai'],
      ['IN', 'Bengaluru', 'Bengaluru'],
      ['DE', 'Frankfurt', 'Frankfurt'],
      ['DE', 'Berlin', 'Berlin'],
      ['BR', 'São Paulo', 'Sao Paulo'],
      ['JP', '東京', 'Tokyo'],
      ['AU', 'Sydney', 'Sydney'],
      ['RU', 'Moscow', 'Moscow'],
      ['ZA', 'Johannesburg', 'Johannesburg'],
      ['TW', '臺北', 'Taipei'],
      ['TW', 'Kaohsiung', 'Kaohsiung'],
      ['HK', '香港特别行政区', 'Hong Kong'],
      ['MO', '澳門', 'Macau'],
      ['SG', 'Singapore', 'Singapore'],
      ['GB', 'London', 'London'],
      ['FR', 'Paris', 'Paris'],
    ]
    for (const [countryCode, city, expectedEn] of cityProbes) {
      const res = resolveFromGazetteer(g, { countryCode, city })
      expect(res, `city probe failed for ${countryCode}:${city}`).not.toBeNull()
      expect(res!.precision).toBe('city')
      expect(res!.labelEn).toBe(expectedEn)
    }

    // Province / region probes
    const regionProbes: Array<[string, string]> = [
      ['CN', '广东省'],
      ['CN', 'Guangdong'],
      ['CN', '浙江省'],
      ['CN', '四川省'],
      ['US', 'California'],
      ['US', 'CA'],
      ['DE', 'Bayern'],
      ['IN', 'Maharashtra'],
      ['JP', 'Osaka'],
      ['AU', 'New South Wales'],
      ['BR', 'São Paulo'],
      ['RU', 'Moscow'],
      ['ZA', 'Gauteng'],
      ['TW', 'Taichung'],
    ]
    for (const [countryCode, region] of regionProbes) {
      const res = resolveFromGazetteer(g, { countryCode, region })
      expect(res, `region probe failed for ${countryCode}:${region}`).not.toBeNull()
      expect(res!.precision).toBe('region')
    }
  })

  it('enforces neutral overrides for TW/HK/MO and never labels them as country or ROC (AC7)', async () => {
    const g = await loadGazetteer()

    expect(NEUTRAL_REGION_OVERRIDES.TW).toEqual({ en: 'Taiwan', zh: '台湾' })
    expect(NEUTRAL_REGION_OVERRIDES.HK).toEqual({ en: 'Hong Kong', zh: '香港' })
    expect(NEUTRAL_REGION_OVERRIDES.MO).toEqual({ en: 'Macau', zh: '澳门' })

    const tw = resolveFromGazetteer(g, { countryCode: 'TW' })
    const hk = resolveFromGazetteer(g, { countryCode: 'HK' })
    const mo = resolveFromGazetteer(g, { countryCode: 'MO' })

    expect(tw).toMatchObject({ precision: 'country', labelEn: 'Taiwan', labelZh: '台湾' })
    expect(hk).toMatchObject({ precision: 'country', labelEn: 'Hong Kong', labelZh: '香港' })
    expect(mo).toMatchObject({ precision: 'country', labelEn: 'Macau', labelZh: '澳门' })

    // Scan EVERY country entry in gazetteer-v1.json for prohibited wording
    const forbiddenEn = /(republic of china|china,\s*taiwan|\bcountry\b)/i
    const forbiddenZh = /(中华民国|中華民國|台湾国|台灣國|香港国|澳门国)/
    for (const [cc, [, , nameEn, nameZh]] of Object.entries(g.countries)) {
      expect(forbiddenEn.test(nameEn), `forbidden EN wording on ${cc}: ${nameEn}`).toBe(false)
      expect(forbiddenZh.test(nameZh), `forbidden ZH wording on ${cc}: ${nameZh}`).toBe(false)
    }

    // Even if raw data were ever tampered with, runtime overrides enforce neutral labels
    const tampered: GazetteerV1 = {
      version: 1,
      countries: {
        TW: [120.87, 23.65, 'Republic of China', '中华民国'],
        HK: [114.1, 22.45, 'Hong Kong country', '香港国'],
        MO: [113.56, 22.13, 'Macao country', '澳门国'],
      },
      regions: {},
      cities: {},
    }
    expect(resolveFromGazetteer(tampered, { countryCode: 'TW' })).toMatchObject({
      labelEn: 'Taiwan',
      labelZh: '台湾',
    })
    expect(resolveFromGazetteer(tampered, { countryCode: 'HK' })).toMatchObject({
      labelEn: 'Hong Kong',
      labelZh: '香港',
    })
    expect(resolveFromGazetteer(tampered, { countryCode: 'MO' })).toMatchObject({
      labelEn: 'Macau',
      labelZh: '澳门',
    })
  })

  it('resolves deterministically with city > region > country > null precedence, zero scatter, and zero relayHome use', async () => {
    const g = await loadGazetteer()

    // city beats region beats country
    const cityRes = resolveFromGazetteer(g, {
      countryCode: 'CN',
      region: '广东省',
      city: '深圳市',
    })
    const regionRes = resolveFromGazetteer(g, {
      countryCode: 'CN',
      region: '广东省',
      city: 'Nonexistent-Town-XYZ',
    })
    const countryRes = resolveFromGazetteer(g, {
      countryCode: 'CN',
      region: 'Nonexistent-Province-XYZ',
      city: 'Nonexistent-Town-XYZ',
    })
    const unknownRes = resolveFromGazetteer(g, {
      countryCode: '',
      country: '',
      region: '',
      city: '',
    })

    expect(cityRes?.precision).toBe('city')
    expect(regionRes?.precision).toBe('region')
    expect(countryRes?.precision).toBe('country')
    expect(unknownRes).toBeNull()

    // Zero scatter: repeated lookups for co-located devices return byte-identical coords
    const cityRes2 = resolveFromGazetteer(g, {
      countryCode: 'CN',
      region: 'Guangdong',
      city: 'Shenzhen',
    })
    expect(cityRes2).toEqual(cityRes)

    // Country scoping prevents cross-country city mismatch (e.g. US + unknown city "Paris" must not jump to France)
    const scopedFallback = resolveFromGazetteer(g, {
      countryCode: 'CN',
      region: '广东省',
      city: 'Tokyo',
    })
    expect(scopedFallback?.precision).toBe('region')
    expect(scopedFallback?.labelEn).toBe('Guangdong')

    // Never uses relayHome even if passed on an extra property at runtime
    const relayOnly = resolveFromGazetteer(g, {
      countryCode: null,
      country: null,
      region: null,
      city: null,
      ...({ relayHome: 'us-east-1' } as Record<string, unknown>),
    })
    expect(relayOnly).toBeNull()
  })

  it('normalizes accents, punctuation, Traditional CJK, and administrative suffixes consistently', () => {
    expect(normalizeGeoKey('广东省')).toBe('广东')
    expect(normalizeGeoKey('廣東省')).toBe('广东')
    expect(normalizeGeoKey('深圳市')).toBe('深圳')
    expect(normalizeGeoKey('香港特别行政区')).toBe('香港')
    expect(normalizeGeoKey('中国香港')).toBe('香港')
    expect(normalizeGeoKey('São Paulo')).toBe('sao paulo')
    expect(normalizeGeoKey("Xi'an City")).toBe('xian')
    expect(normalizeGeoKey('  —  ')).toBe('')
  })

  it('exports required bilingual attribution text citing Natural Earth, geoBoundaries, OSM, and UN OCHA', () => {
    expect(ATTRIBUTION_TEXT.en).toContain('Natural Earth')
    expect(ATTRIBUTION_TEXT.en).toContain('geoBoundaries')
    expect(ATTRIBUTION_TEXT.en).toContain('CC BY 4.0')
    expect(ATTRIBUTION_TEXT.en).toContain('OpenStreetMap')
    expect(ATTRIBUTION_TEXT.en).toContain('ODbL')
    expect(ATTRIBUTION_TEXT.en).toContain('UN OCHA')
    expect(ATTRIBUTION_TEXT.en).toContain('CC BY-IGO')

    expect(ATTRIBUTION_TEXT['zh-CN']).toContain('Natural Earth')
    expect(ATTRIBUTION_TEXT['zh-CN']).toContain('geoBoundaries')
    expect(ATTRIBUTION_TEXT['zh-CN']).toContain('CC BY 4.0')
    expect(ATTRIBUTION_TEXT['zh-CN']).toContain('OpenStreetMap')
    expect(ATTRIBUTION_TEXT['zh-CN']).toContain('ODbL')
    expect(ATTRIBUTION_TEXT['zh-CN']).toContain('UN OCHA')
    expect(ATTRIBUTION_TEXT['zh-CN']).toContain('CC BY-IGO')
  })
})
