// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD

/**
 * Shared location, public IP, and logical network zone formatting for device
 * rows across the Web Console (`AgentsSection.vue`, `DeviceZoneDialog.vue`).
 * Mirrors the exact logic in `agents/meshharbor-desktop/src/front/devices.js`
 * so both surfaces render `国家 · 省 · 市` + `public_ip` and logical zone badges
 * identically.
 */

export type GeoLevel = 'coords' | 'city' | 'region' | 'country' | 'unknown'

export interface GeoLocationFields {
  public_ip?: string | null
  country_code?: string | null
  country?: string | null
  region?: string | null
  city?: string | null
  lat?: number | null
  lon?: number | null
  accuracy_radius_km?: number | null
  geo_level?: GeoLevel | null
}

export interface DeviceZoneFields {
  pinned_zone_id?: string | null
  effective_zone_id?: string | null
  effective_zone_name?: string | null
}

export interface FormattedDeviceZone {
  /** Resolved logical zone slug (`effective_zone_id` or fallback `pinned_zone_id`), or `''`. */
  zoneId: string
  /** Resolved human zone name (`effective_zone_name || effective_zone_id || pinned_zone_id`), or `''`. */
  zoneLabel: string
  /** Display badge string (`<zoneLabel>`), or `''`. */
  badgeText: string
  /** True when the device is explicitly locked (`pinned_zone_id` is non-empty). */
  pinned: boolean
  /** True when a logical zone is resolved or pinned for this device. */
  hasZone: boolean
}

export interface FormattedDeviceLocation {
  /** Deduplicated `国家 · 省 · 市` string, or `''` when all segments are absent. */
  locationText: string
  /** Normalized uppercase 2-letter ISO country code (e.g. `CN`, `HK`, `US`), or `''`. */
  countryCode: string
  /** Trimmed public IP literal, or `''` when unknown. */
  publicIp: string
  /** True when at least one of locationText, countryCode, or publicIp is present. */
  hasAny: boolean
}

function sarStem(s: string): string {
  return s
    .replace(/特别行政区$/u, '')
    .replace(/特別行政區$/u, '')
    .replace(/\s+s\.?a\.?r\.?$/iu, '')
    .trim()
}

/**
 * Deduplicate `[country, region, city]` cleanly without collapsing genuinely
 * distinct administrative levels (e.g. `吉林省 · 吉林市` stays intact, while
 * `新加坡 · 新加坡` -> `新加坡`, `中国香港 · 香港` -> `中国香港`, and
 * `中国 · 北京 · 北京市` -> `中国 · 北京市`).
 */
export function dedupeLocationParts(parts: Array<string | null | undefined>): string[] {
  const kept: string[] = []
  for (const raw of parts) {
    const seg = typeof raw === 'string' ? raw.trim() : ''
    if (!seg || seg === '-' || seg === '—') continue
    const prev = kept[kept.length - 1]
    if (!prev) {
      kept.push(seg)
      continue
    }
    const pStem = sarStem(prev)
    const sStem = sarStem(seg)
    // Exact or SAR-stem match (e.g. "新加坡" + "新加坡", "Hong Kong SAR" + "Hong Kong").
    if (
      prev.toLowerCase() === seg.toLowerCase() ||
      (sStem.length > 0 && pStem.toLowerCase() === sStem.toLowerCase())
    ) {
      continue
    }
    // Greater China SAR / region prefix ("中国香港" + "香港", "中国澳门" + "澳门", "中国台湾" + "台湾").
    if (sStem.length >= 2 && (pStem === `中国${sStem}` || pStem === `中國${sStem}`)) {
      continue
    }
    // Direct-administered municipality ("北京" + "北京市" -> "北京市", "北京市" + "北京" -> "北京市").
    if (seg === `${prev}市`) {
      kept[kept.length - 1] = seg
      continue
    }
    if (prev === `${seg}市`) {
      continue
    }
    kept.push(seg)
  }
  return kept
}

function pickStr(a?: string | null, b?: string | null): string {
  const x = typeof a === 'string' ? a.trim() : ''
  if (x && x !== '-' && x !== '—') return x
  const y = typeof b === 'string' ? b.trim() : ''
  return y && y !== '-' && y !== '—' ? y : ''
}

export function formatDeviceLocation(
  primary?: GeoLocationFields | null,
  fallback?: GeoLocationFields | null,
): FormattedDeviceLocation {
  const country = pickStr(primary?.country, fallback?.country)
  const region = pickStr(primary?.region, fallback?.region)
  const city = pickStr(primary?.city, fallback?.city)
  const rawCode = pickStr(primary?.country_code, fallback?.country_code).toUpperCase()
  const countryCode = /^[A-Z]{2}$/.test(rawCode) ? rawCode : ''
  const publicIp = pickStr(primary?.public_ip, fallback?.public_ip)
  const locationText = dedupeLocationParts([country, region, city]).join(' · ')
  return {
    locationText,
    countryCode,
    publicIp,
    hasAny: Boolean(locationText || countryCode || publicIp),
  }
}

export function formatDeviceZone(
  primary?: DeviceZoneFields | null,
  fallback?: DeviceZoneFields | null,
  knownZoneName?: string | null,
): FormattedDeviceZone {
  const pinnedId = pickStr(primary?.pinned_zone_id, fallback?.pinned_zone_id)
  const effectiveId = pickStr(primary?.effective_zone_id, fallback?.effective_zone_id)
  const effectiveName =
    pickStr(primary?.effective_zone_name, fallback?.effective_zone_name) ||
    pickStr(knownZoneName, null)
  const pinned = Boolean(pinnedId)
  const zoneId = effectiveId || pinnedId
  const zoneLabel = effectiveName || effectiveId || pinnedId
  const hasZone = Boolean(zoneLabel)
  return {
    zoneId,
    zoneLabel,
    badgeText: hasZone ? zoneLabel : '',
    pinned,
    hasZone,
  }
}
