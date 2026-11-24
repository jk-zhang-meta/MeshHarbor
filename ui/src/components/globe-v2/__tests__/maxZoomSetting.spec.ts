// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, expect, it } from 'vitest'
import {
  clampMaxZoom,
  DEFAULT_MAX_ZOOM,
  formatMaxZoomSpanHint,
  horizontalSpanKm,
  MAX_ALLOWED_MAX_ZOOM,
  MAX_ZOOM_STORAGE_KEY,
  MIN_ALLOWED_MAX_ZOOM,
  parseStoredMaxZoom,
  readStoredMaxZoom,
  writeStoredMaxZoom,
} from '../maxZoomSetting'

describe('maxZoomSetting — per-viewer max zoom preference (6..14, default 11)', () => {
  it('clamps finite values into [6, 14] and falls back to 11 for NaN / Infinity', () => {
    expect(DEFAULT_MAX_ZOOM).toBe(11)
    expect(MIN_ALLOWED_MAX_ZOOM).toBe(6)
    expect(MAX_ALLOWED_MAX_ZOOM).toBe(14)

    expect(clampMaxZoom(6)).toBe(6)
    expect(clampMaxZoom(11)).toBe(11)
    expect(clampMaxZoom(14)).toBe(14)
    expect(clampMaxZoom(2)).toBe(6)
    expect(clampMaxZoom(-10)).toBe(6)
    expect(clampMaxZoom(18)).toBe(14)
    expect(clampMaxZoom(10.6)).toBe(11)
    expect(clampMaxZoom(Number.NaN)).toBe(11)
    expect(clampMaxZoom(Number.POSITIVE_INFINITY)).toBe(11)
  })

  it('falls back cleanly to 11 on missing, NaN, or out-of-range stored values', () => {
    expect(parseStoredMaxZoom(null)).toBe(11)
    expect(parseStoredMaxZoom(undefined)).toBe(11)
    expect(parseStoredMaxZoom('')).toBe(11)
    expect(parseStoredMaxZoom('   ')).toBe(11)
    expect(parseStoredMaxZoom('not-a-number')).toBe(11)
    expect(parseStoredMaxZoom('NaN')).toBe(11)
    expect(parseStoredMaxZoom('5')).toBe(11)
    expect(parseStoredMaxZoom('15')).toBe(11)
    expect(parseStoredMaxZoom('999')).toBe(11)
    expect(parseStoredMaxZoom('-2')).toBe(11)

    expect(parseStoredMaxZoom('6')).toBe(6)
    expect(parseStoredMaxZoom('9')).toBe(9)
    expect(parseStoredMaxZoom('11')).toBe(11)
    expect(parseStoredMaxZoom('14')).toBe(14)
  })

  it('persists safely via localStorage and swallows storage read/write errors', () => {
    const map = new Map<string, string>()
    const memStorage = {
      getItem: (k: string) => map.get(k) ?? null,
      setItem: (k: string, v: string) => {
        map.set(k, v)
      },
    }

    expect(readStoredMaxZoom(memStorage)).toBe(11)
    expect(writeStoredMaxZoom(13, memStorage)).toBe(13)
    expect(map.get(MAX_ZOOM_STORAGE_KEY)).toBe('13')
    expect(readStoredMaxZoom(memStorage)).toBe(13)

    // Clamps on write
    expect(writeStoredMaxZoom(99, memStorage)).toBe(14)
    expect(readStoredMaxZoom(memStorage)).toBe(14)

    // Corrupt value falls back to 11
    map.set(MAX_ZOOM_STORAGE_KEY, 'corrupt')
    expect(readStoredMaxZoom(memStorage)).toBe(11)

    // Throwing storage never crashes
    const brokenStorage = {
      getItem: () => {
        throw new Error('SecurityError')
      },
      setItem: () => {
        throw new Error('QuotaExceededError')
      },
    }
    expect(readStoredMaxZoom(brokenStorage)).toBe(11)
    expect(writeStoredMaxZoom(12, brokenStorage)).toBe(12)
  })

  it('computes accurate latitude-aware horizontal span hints in zh-CN and en', () => {
    // At lat 30 deg, 1000px container:
    // z11 ~ 33 km, z9 ~ 132 km, z14 ~ 4 km
    const km11 = horizontalSpanKm(30, 11, 1000)
    const km9 = horizontalSpanKm(30, 9, 1000)
    const km14 = horizontalSpanKm(30, 14, 1000)
    expect(km11).toBeGreaterThan(25)
    expect(km11).toBeLessThan(45)
    expect(km9).toBeGreaterThan(100)
    expect(km9).toBeLessThan(170)
    expect(km14).toBeGreaterThan(2)
    expect(km14).toBeLessThan(8)
    // Higher latitude spans fewer km for same pixel width
    expect(horizontalSpanKm(60, 11, 1000)).toBeLessThan(horizontalSpanKm(0, 11, 1000))

    const zh11 = formatMaxZoomSpanHint(11, 30, 1000, 'zh-CN')
    const en11 = formatMaxZoomSpanHint(11, 30, 1000, 'en')
    expect(zh11).toContain('约 ')
    expect(zh11).toContain('km')
    expect(zh11).toContain('可见多个区')
    expect(en11).toContain('about ')
    expect(en11).toContain('km')
    expect(en11).toContain('several districts')

    expect(formatMaxZoomSpanHint(9, 30, 1000, 'zh-CN')).toContain('城市及周边')
    expect(formatMaxZoomSpanHint(9, 30, 1000, 'en')).toContain('city & surroundings')
    expect(formatMaxZoomSpanHint(7, 30, 1000, 'zh-CN')).toContain('省级/区域')
    expect(formatMaxZoomSpanHint(14, 30, 1000, 'zh-CN')).toContain('城区/街道细节')
  })
})
