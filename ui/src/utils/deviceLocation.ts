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

export type ZoneSource =
  | 'pinned'
  | 'auto_physical'
  | 'auto_vpn_held'
  | 'auto_egress_ip'
  | 'auto_egress_fallback'

export interface GeoLocationFields {
  public_ip?: string | null
  physical_public_ip?: string | null
  physical_seen_at?: string | null
  default_route_vpn?: boolean | null
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
  zone_source?: ZoneSource | null
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
  /** FR-138 evidence source that decided the zone, or `''` on legacy payloads. */
  zoneSource: ZoneSource | ''
}

export interface FormattedDeviceLocation {
  /** Deduplicated `国家 · 省 · 市` string, or `''` when all segments are absent. */
  locationText: string
  /** Normalized uppercase 2-letter ISO country code (e.g. `CN`, `HK`, `US`), or `''`. */
  countryCode: string
  /** Trimmed current control-WS / egress public IP literal, or `''` when unknown. */
  publicIp: string
  /** Trimmed server-observed physical-uplink egress IP literal (FR-138), or `''` when unknown. */
  physicalIp: string
  /** RFC 3339 timestamp of the last physical-uplink observation, or `''`. */
  physicalSeenAt: string
  /** Whether the device reports its OS default route sits on a VPN/virtual interface. */
  defaultRouteVpn: boolean
  /** True when at least one of locationText, countryCode, publicIp, or physicalIp is present. */
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
  const physicalIp = pickStr(primary?.physical_public_ip, fallback?.physical_public_ip)
  const physicalSeenAt = pickStr(primary?.physical_seen_at, fallback?.physical_seen_at)
  const defaultRouteVpn = Boolean(primary?.default_route_vpn ?? fallback?.default_route_vpn)
  const locationText = dedupeLocationParts([country, region, city]).join(' · ')
  return {
    locationText,
    countryCode,
    publicIp,
    physicalIp,
    physicalSeenAt,
    defaultRouteVpn,
    hasAny: Boolean(locationText || countryCode || publicIp || physicalIp),
  }
}

const KNOWN_ZONE_SOURCES = new Set<ZoneSource>([
  'pinned',
  'auto_physical',
  'auto_vpn_held',
  'auto_egress_ip',
  'auto_egress_fallback',
])

function pickZoneSource(a?: string | null, b?: string | null): ZoneSource | '' {
  const raw = pickStr(a, b) as ZoneSource
  return KNOWN_ZONE_SOURCES.has(raw) ? raw : ''
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
  const zoneSource = pickZoneSource(primary?.zone_source, fallback?.zone_source)
  return {
    zoneId,
    zoneLabel,
    badgeText: hasZone ? zoneLabel : '',
    pinned,
    hasZone,
    zoneSource,
  }
}

type TranslateFn = (key: string, named?: Record<string, unknown>) => string

/**
 * FR-138 — format the zone chip display label including its decision source
 * when the server reported `zone_source` (preserves bare `zoneLabel` on legacy
 * rows without `zone_source`).
 */
export function formatZoneChipLabel(zone: FormattedDeviceZone, t: TranslateFn): string {
  if (!zone.hasZone) return ''
  switch (zone.zoneSource) {
    case 'pinned':
      return `${zone.zoneLabel} · ${t('mh.dev.zoneSourcePinned')}`
    case 'auto_physical':
      return `${zone.zoneLabel} · ${t('mh.dev.zoneSourcePhysical')}`
    case 'auto_vpn_held':
      return t('mh.dev.zoneSourceVpnHeld', { zone: zone.zoneLabel })
    case 'auto_egress_ip':
      return `${zone.zoneLabel} · ${t('mh.dev.zoneSourceEgress')}`
    case 'auto_egress_fallback':
      return `${zone.zoneLabel} · ${t('mh.dev.zoneSourceEgressFallback')}`
    default:
      return zone.badgeText
  }
}

/**
 * FR-138 — format the zone chip tooltip explaining which evidence decided the zone.
 */
export function formatZoneTooltip(zone: FormattedDeviceZone, t: TranslateFn): string {
  if (!zone.hasZone) return ''
  switch (zone.zoneSource) {
    case 'pinned':
      return t('mh.dev.zonePinnedTitle', { zone: zone.zoneLabel })
    case 'auto_physical':
      return t('mh.dev.zonePhysicalTitle', { zone: zone.zoneLabel })
    case 'auto_vpn_held':
      return t('mh.dev.zoneVpnHeldTitle', { zone: zone.zoneLabel })
    case 'auto_egress_ip':
      return t('mh.dev.zoneEgressTitle', { zone: zone.zoneLabel })
    case 'auto_egress_fallback':
      return t('mh.dev.zoneEgressFallbackTitle', { zone: zone.zoneLabel })
    default:
      return zone.pinned
        ? t('mh.dev.zonePinnedTitle', { zone: zone.zoneLabel })
        : t('mh.dev.zoneAutoTitle', { zone: zone.zoneLabel })
  }
}

export function zoneChipColor(zone: FormattedDeviceZone): string {
  if (zone.pinned || zone.zoneSource === 'pinned') return 'primary'
  if (zone.zoneSource === 'auto_vpn_held') return 'info'
  if (zone.zoneSource === 'auto_egress_fallback') return 'warning'
  return 'secondary'
}

export function zoneChipIcon(zone: FormattedDeviceZone): string {
  if (zone.pinned || zone.zoneSource === 'pinned') return 'mdi-pin-outline'
  if (zone.zoneSource === 'auto_vpn_held') return 'mdi-shield-lock-outline'
  if (zone.zoneSource === 'auto_physical') return 'mdi-ethernet'
  if (zone.zoneSource === 'auto_egress_fallback') return 'mdi-alert-circle-outline'
  return 'mdi-map-marker-radius-outline'
}
