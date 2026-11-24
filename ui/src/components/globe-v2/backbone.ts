// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// Pure S12 Zone Backbone Globe data builders (zero DOM/WebGL dependencies):
// - Deterministic S2 WCAG-verified zone colors (+ distinct centre zone teal accent).
// - Strict role separation: Centre vs Gateway (`serving_relay`) vs Entry (`entry_listening`) vs Server.
// - Honest location resolution via `resolveV2Location` (NEVER `relay_home`; unlocated Centre -> legend chip).
// - FR-134 Management path lines (gateway -> centre, 2 px solid zone color, screen offset when sharing a live link).
// - Backbone links (2.5 px active, 1.5 px gray dashed [2,2] disabled, R7 stalled dotted + ⚠, directional 120 px arrows).
// - Optional Devices overlay (3 px dots @ 35% opacity, grouped at true city coordinates, NO labels).

import type { GlobeArc, GlobeNode, GlobePresence } from '@/components/globe/types'
import type { BackboneZoneView } from '@/stores/serverTopology'
import { effectivePresence, groupNodesByLocation, resolveV2Location, type GazetteerV1, type V2GeoPrecision } from './grouping'
import { interpolateGreatCircle } from './links'
import { getGlobeTokens, type GlobeLang, type GlobeThemeMode } from './tokens'

// ── S12 Spec Constants (shared with icons.ts, style.ts, and unit tests) ───────

export const BACKBONE_CENTRE_DIAMOND_PX = 14
export const BACKBONE_GATEWAY_SQUARE_PX = 10
export const BACKBONE_GATEWAY_HALO_DIAMETER_PX = 22
export const BACKBONE_GATEWAY_HALO_STROKE_PX = 1
export const BACKBONE_GATEWAY_HALO_OPACITY = 0.5
export const BACKBONE_ENTRY_TRIANGLE_PX = 10
export const BACKBONE_SERVER_SQUARE_PX = 10
export const BACKBONE_MGMT_PATH_WIDTH_PX = 2
export const BACKBONE_LINK_WIDTH_PX = 2.5
export const BACKBONE_LINK_DISABLED_WIDTH_PX = 1.5
export const BACKBONE_LINK_OPACITY = 0.8
export const BACKBONE_ARROW_SPACING_PX = 120
export const BACKBONE_DEVICE_DOT_DIAMETER_PX = 3
export const BACKBONE_DEVICE_DOT_RADIUS_PX = BACKBONE_DEVICE_DOT_DIAMETER_PX / 2
export const BACKBONE_DEVICE_DOT_OPACITY = 0.35

/** Distinct WCAG >= 3:1 teal accent for the Centre zone (an ordinary zone with centre role). */
export const CENTRE_ZONE_COLOR_DARK = '#2DD4BF'
export const CENTRE_ZONE_COLOR_LIGHT = '#0F766E'

export type BackboneNodeKind = 'centre' | 'gateway' | 'entry' | 'server'

function hashZoneId(id: string): number {
  let h = 2166136261
  for (let i = 0; i < id.length; i++) {
    h ^= id.charCodeAt(i)
    h = Math.imul(h, 16777619)
  }
  return h >>> 0
}

/** Deterministic S2 zone colour: centre teal when `is_centre`, S2 Okabe–Ito `tokens.zones[0..5]` otherwise. */
export function resolveZoneColor(
  zone: Pick<BackboneZoneView, 'id' | 'is_centre'>,
  mode: GlobeThemeMode,
  nonCentreIndex?: number,
): string {
  if (zone.is_centre) {
    return mode === 'dark' ? CENTRE_ZONE_COLOR_DARK : CENTRE_ZONE_COLOR_LIGHT
  }
  const palette = getGlobeTokens(mode).zones
  const slot = nonCentreIndex != null ? nonCentreIndex : hashZoneId(zone.id)
  return palette[slot % palette.length]!
}

export function buildZoneColorMap(
  zones: readonly Pick<BackboneZoneView, 'id' | 'is_centre'>[],
  mode: GlobeThemeMode,
): Map<string, string> {
  const out = new Map<string, string>()
  let nonCentreIdx = 0
  for (const z of zones) {
    if (z.is_centre) {
      out.set(z.id, resolveZoneColor(z, mode))
    } else {
      out.set(z.id, resolveZoneColor(z, mode, nonCentreIdx++))
    }
  }
  return out
}

/**
 * Classify visual marker shape strictly per S12 & T7 Centre/Forwarder role separation:
 * - Centre (`isCentre` or `role === 'centre'`) -> 14×14 diamond
 * - Gateway (`isGateway` or `role === 'gateway'`) -> 10×10 zone-colored square + Ø22 halo
 * - Entry-only (`isEntry` or `role === 'entry'`) -> 10 px triangle
 * - Neutral server / fallback -> 10×10 neutral square
 */
export function classifyBackboneNodeKind(node: GlobeNode): BackboneNodeKind {
  if (node.isCentre || node.role === 'centre') return 'centre'
  if (node.isGateway || node.role === 'gateway') return 'gateway'
  if (node.isEntry || node.role === 'entry') return 'entry'
  return 'server'
}

export interface PlacedBackboneNode {
  id: string
  node: GlobeNode
  kind: BackboneNodeKind
  presence: GlobePresence
  lon: number
  lat: number
  precision: Exclude<V2GeoPrecision, 'unknown'>
  accuracyRadiusKm: number | null
  locationLabel: string
  placeEn: string
  placeZh: string
  countryCode: string
  zoneColor: string
  zoneName: string | null
  zoneDeviceCount: number | null
}

export interface ResolvedBackboneNodes {
  placed: PlacedBackboneNode[]
  placedById: Map<string, PlacedBackboneNode>
  /** Unlocated centre host(s): NEVER plotted on globe -> shown as clickable "控制中心"/"Centre" legend chip. */
  unlocatedCentres: GlobeNode[]
  /** Other unlocated gateways/servers -> shown in "Unknown location N" legend chip. */
  unlocatedOthers: GlobeNode[]
  zoneColors: Map<string, string>
}

export function resolveBackboneNodes(
  nodes: readonly GlobeNode[],
  zones: readonly BackboneZoneView[],
  mode: GlobeThemeMode,
  gazetteer?: GazetteerV1 | null,
): ResolvedBackboneNodes {
  const tokens = getGlobeTokens(mode)
  const zoneById = new Map(zones.map((z) => [z.id, z]))
  const zoneColors = buildZoneColorMap(zones, mode)

  const placed: PlacedBackboneNode[] = []
  const placedById = new Map<string, PlacedBackboneNode>()
  const unlocatedCentres: GlobeNode[] = []
  const unlocatedOthers: GlobeNode[] = []

  for (const node of nodes) {
    const res = resolveV2Location(node, gazetteer)
    const kind = classifyBackboneNodeKind(node)

    if (res.precision === 'unknown' || res.lon == null || res.lat == null) {
      if (kind === 'centre') unlocatedCentres.push(node)
      else unlocatedOthers.push(node)
      continue
    }

    const primaryZoneId = node.zoneId ?? node.zoneIds?.[0] ?? null
    const primaryZone = primaryZoneId ? zoneById.get(primaryZoneId) : undefined
    const zoneColor =
      (primaryZoneId ? zoneColors.get(primaryZoneId) : undefined) ??
      node.color ??
      (kind === 'centre'
        ? mode === 'dark'
          ? CENTRE_ZONE_COLOR_DARK
          : CENTRE_ZONE_COLOR_LIGHT
        : tokens.zones[0])

    const item: PlacedBackboneNode = {
      id: node.id,
      node,
      kind,
      presence: effectivePresence(node),
      lon: res.lon,
      lat: res.lat,
      precision: res.precision,
      accuracyRadiusKm: res.accuracyRadiusKm,
      locationLabel: res.locationLabel,
      placeEn: res.placeEn,
      placeZh: res.placeZh,
      countryCode: res.countryCode,
      zoneColor,
      zoneName: primaryZone?.name ?? node.zoneName ?? node.zoneNames?.[0] ?? null,
      zoneDeviceCount:
        typeof node.zoneDeviceCount === 'number'
          ? node.zoneDeviceCount
          : typeof primaryZone?.device_count === 'number'
            ? primaryZone.device_count
            : null,
    }
    placed.push(item)
    placedById.set(node.id, item)
  }

  // Deterministic priority: Centre first, then online gateways by zone device count desc, then name asc
  placed.sort((a, b) => {
    const rank = (k: BackboneNodeKind) => (k === 'centre' ? 0 : k === 'gateway' ? 1 : k === 'entry' ? 2 : 3)
    return (
      rank(a.kind) - rank(b.kind) ||
      (b.zoneDeviceCount ?? -1) - (a.zoneDeviceCount ?? -1) ||
      a.node.name.localeCompare(b.node.name)
    )
  })

  return { placed, placedById, unlocatedCentres, unlocatedOthers, zoneColors }
}

/**
 * Format crisp S12 gateway / centre / server label chip:
 * - Gateways with a zone + device count: `"CN 区 · 12 台"` / `"CN · 12 devices"` (or `"CN Mainland · 14 台"`).
 * - Country/region-only location ALWAYS prefixes `"≈ "` per S7/S12 (never fabricates city precision).
 */
export function formatBackboneNodeLabel(placed: PlacedBackboneNode, lang: GlobeLang): string {
  const approxPrefix =
    placed.precision === 'region' || placed.precision === 'country' ? '≈ ' : ''

  if (placed.kind === 'gateway' && placed.zoneName) {
    const rawZone = placed.zoneName.trim()
    const count = placed.zoneDeviceCount
    if (lang === 'zh-CN') {
      const zhZone =
        /^[A-Z]{2,3}$/.test(rawZone) ? `${rawZone} 区` : rawZone
      return count != null ? `${approxPrefix}${zhZone} · ${count} 台` : `${approxPrefix}${zhZone}`
    }
    if (count != null) {
      return `${approxPrefix}${rawZone} · ${count} ${count === 1 ? 'device' : 'devices'}`
    }
    return `${approxPrefix}${rawZone}`
  }

  if (placed.kind === 'centre') {
    const label = placed.zoneName && placed.zoneDeviceCount != null && placed.node.isGateway
      ? lang === 'zh-CN'
        ? `${placed.zoneName} · ${placed.zoneDeviceCount} 台`
        : `${placed.zoneName} · ${placed.zoneDeviceCount} ${placed.zoneDeviceCount === 1 ? 'device' : 'devices'}`
      : placed.node.name
    return `${approxPrefix}${label}`
  }

  return `${approxPrefix}${placed.node.name}`
}

export interface BackboneMgmtPathFeatureProps {
  key: string
  from: string
  to: string
  color: string
  width: number
  opacity: number
  offset: number
  zoneName: string
}

function unorderedPairKey(a: string, b: string): string {
  return a < b ? `${a}~${b}` : `${b}~${a}`
}

/**
 * Build FR-134 management path lines (S12: gateway -> centre, 2 px solid zone-color great circle).
 * Applies a subtle 3.5 px screen-space `line-offset` whenever a live gateway↔gateway backbone link
 * connects the exact same pair so neither line obscures the other.
 */
export function buildBackboneMgmtPathsGeoJson(
  placedNodes: readonly PlacedBackboneNode[],
  backboneArcs: readonly GlobeArc[],
  opts: {
    focusedNodeId?: string | null
    hasSelection?: boolean
  } = {},
): GeoJSON.FeatureCollection<GeoJSON.LineString, BackboneMgmtPathFeatureProps> {
  const centres = placedNodes.filter((p) => p.kind === 'centre')
  if (centres.length === 0) {
    return { type: 'FeatureCollection', features: [] }
  }
  const primaryCentre = centres[0]!

  const activeLinkPairs = new Set<string>()
  for (const arc of backboneArcs) {
    if (arc.kind === 'control' || arc.kind === 'mgmt_path') continue
    activeLinkPairs.add(unorderedPairKey(arc.from, arc.to))
  }

  const features: Array<GeoJSON.Feature<GeoJSON.LineString, BackboneMgmtPathFeatureProps>> = []
  for (const gw of placedNodes) {
    if (gw.id === primaryCentre.id) continue
    if (gw.kind !== 'gateway' && gw.kind !== 'entry') continue
    // Same exact coordinates -> no line
    if (Math.abs(gw.lon - primaryCentre.lon) < 1e-4 && Math.abs(gw.lat - primaryCentre.lat) < 1e-4) {
      continue
    }

    const coords = interpolateGreatCircle([gw.lon, gw.lat], [primaryCentre.lon, primaryCentre.lat], 16, 24)
    const sharesLiveLink = activeLinkPairs.has(unorderedPairKey(gw.id, primaryCentre.id))
    const isFocused =
      opts.focusedNodeId === gw.id || opts.focusedNodeId === primaryCentre.id
    const opacity = opts.hasSelection ? (isFocused ? 0.95 : 0.22) : 0.72

    features.push({
      type: 'Feature',
      geometry: { type: 'LineString', coordinates: coords },
      properties: {
        key: `mgmt:${gw.id}->${primaryCentre.id}`,
        from: gw.id,
        to: primaryCentre.id,
        color: gw.zoneColor,
        width: BACKBONE_MGMT_PATH_WIDTH_PX,
        opacity,
        offset: sharesLiveLink ? 3.5 : 0,
        zoneName: gw.zoneName ?? '',
      },
    })
  }

  return { type: 'FeatureCollection', features }
}

/** True when a backbone link is unidirectional (explicit flag or single-sided 1/2 report). */
export function isUnidirectionalBackboneArc(arc: GlobeArc): boolean {
  if (arc.directional === true) return true
  if (arc.directional === false) return false
  if (arc.reports === 1) return true
  if (arc.ends && arc.ends.length === 1) return true
  return false
}

export interface BackboneLinkFeatureProps {
  key: string
  from: string
  to: string
  state: 'active' | 'stalled' | 'disabled'
  directional: boolean
  width: number
  opacity: number
  rttMs: number | null
  crossZone: boolean
  carrier: string
}

export interface BackboneArrowFeatureProps {
  key: string
  arrowIcon: string
  opacity: number
}

export interface BackboneLinkBadgeProps {
  key: string
  badge: string
  colorKind: 'stalled' | 'blocked' | 'rtt' | 'mixed'
}

/**
 * Build GeoJSON for S12 backbone links:
 * - Active enabled links: 2.5 px (`#E6EDF6` dark / `#1F2937` light via style layer), opacity 0.8 (1.0 focused).
 * - Disabled (`enabled === false`): 1.5 px muted dashed `[2, 2]`.
 * - Stalled (`stalled === true`): R7 stalled dotted `[0, 2]` + midpoint `⚠` badge.
 * - Unidirectional links: oriented `reporter -> peer` and emitted into `arrows` for `symbol-placement: line` @ 120 px.
 */
export function buildBackboneLinksGeoJson(
  arcs: readonly GlobeArc[],
  placedById: ReadonlyMap<string, PlacedBackboneNode>,
  mode: GlobeThemeMode,
  opts: {
    hoveredLinkKey?: string | null
    selectedLinkKey?: string | null
    focusedNodeId?: string | null
  } = {},
): {
  lines: GeoJSON.FeatureCollection<GeoJSON.LineString, BackboneLinkFeatureProps>
  arrows: GeoJSON.FeatureCollection<GeoJSON.LineString, BackboneArrowFeatureProps>
  badges: GeoJSON.FeatureCollection<GeoJSON.Point, BackboneLinkBadgeProps>
} {
  const lineFeatures: Array<GeoJSON.Feature<GeoJSON.LineString, BackboneLinkFeatureProps>> = []
  const arrowFeatures: Array<GeoJSON.Feature<GeoJSON.LineString, BackboneArrowFeatureProps>> = []
  const badgeFeatures: Array<GeoJSON.Feature<GeoJSON.Point, BackboneLinkBadgeProps>> = []

  const hasFocus = Boolean(opts.focusedNodeId || opts.selectedLinkKey)

  for (const arc of arcs) {
    if (arc.kind === 'control' || arc.kind === 'mgmt_path') continue
    const pFrom = placedById.get(arc.from)
    const pTo = placedById.get(arc.to)
    if (!pFrom || !pTo) continue
    if (Math.abs(pFrom.lon - pTo.lon) < 1e-4 && Math.abs(pFrom.lat - pTo.lat) < 1e-4) continue

    const disabled = arc.enabled === false
    const stalled = !disabled && Boolean(arc.stalled || arc.ends?.some((e) => e.stalled))
    const state: 'active' | 'stalled' | 'disabled' = disabled
      ? 'disabled'
      : stalled
        ? 'stalled'
        : 'active'
    const directional = isUnidirectionalBackboneArc(arc)

    // Orient LineString along reported direction when unidirectional so line-placed arrows point accurately.
    let startNode = pFrom
    let endNode = pTo
    if (directional && arc.ends && arc.ends.length === 1) {
      const reporter = arc.ends[0]!.node
      if (reporter === arc.to) {
        startNode = pTo
        endNode = pFrom
      }
    }

    const coords = interpolateGreatCircle([startNode.lon, startNode.lat], [endNode.lon, endNode.lat], 16, 24)
    const midIdx = Math.floor((coords.length - 1) / 2)
    const midpoint = coords[midIdx]!
    let midLon = midpoint[0]
    while (midLon > 180) midLon -= 360
    while (midLon < -180) midLon += 360

    const isHighlighted =
      opts.hoveredLinkKey === arc.key || opts.selectedLinkKey === arc.key
    const touchesFocusedNode =
      opts.focusedNodeId != null && (arc.from === opts.focusedNodeId || arc.to === opts.focusedNodeId)
    const emphasized = isHighlighted || touchesFocusedNode

    const baseWidth = disabled ? BACKBONE_LINK_DISABLED_WIDTH_PX : BACKBONE_LINK_WIDTH_PX
    const width = isHighlighted ? baseWidth + 1 : baseWidth
    const baseOpacity = disabled ? 0.65 : BACKBONE_LINK_OPACITY
    const opacity = hasFocus ? (emphasized ? 1 : 0.2) : isHighlighted ? 1 : baseOpacity

    lineFeatures.push({
      type: 'Feature',
      geometry: { type: 'LineString', coordinates: coords },
      properties: {
        key: arc.key,
        from: startNode.id,
        to: endNode.id,
        state,
        directional,
        width,
        opacity,
        rttMs: arc.rttMs ?? null,
        crossZone: Boolean(arc.crossZone),
        carrier: arc.carrier,
      },
    })

    if (directional && !disabled) {
      arrowFeatures.push({
        type: 'Feature',
        geometry: { type: 'LineString', coordinates: coords },
        properties: {
          key: arc.key,
          arrowIcon: stalled ? `mh-bb-arrow-stalled-${mode}` : `mh-bb-arrow-active-${mode}`,
          opacity: Math.min(1, opacity + 0.15),
        },
      })
    }

    if (stalled) {
      const label = isHighlighted && arc.rttMs != null ? `⚠ ${arc.rttMs} ms` : '⚠'
      badgeFeatures.push({
        type: 'Feature',
        geometry: { type: 'Point', coordinates: [midLon, midpoint[1]] },
        properties: { key: arc.key, badge: label, colorKind: 'stalled' },
      })
    } else if (arc.blocked || arc.carrier === 'blocked') {
      badgeFeatures.push({
        type: 'Feature',
        geometry: { type: 'Point', coordinates: [midLon, midpoint[1]] },
        properties: { key: arc.key, badge: '×', colorKind: 'blocked' },
      })
    } else if (isHighlighted && arc.rttMs != null) {
      badgeFeatures.push({
        type: 'Feature',
        geometry: { type: 'Point', coordinates: [midLon, midpoint[1]] },
        properties: { key: arc.key, badge: `${arc.rttMs} ms`, colorKind: 'rtt' },
      })
    }
  }

  return {
    lines: { type: 'FeatureCollection', features: lineFeatures },
    arrows: { type: 'FeatureCollection', features: arrowFeatures },
    badges: { type: 'FeatureCollection', features: badgeFeatures },
  }
}

export interface BackboneDeviceDotFeatureProps {
  key: string
  presence: GlobePresence
  count: number
}

/**
 * S12 optional Devices overlay: grouped at true city coordinates (zero scatter, never `relay_home`),
 * rendered as subtle 3 px dots (`circle-radius: 1.5`) at 35% opacity with NO labels.
 */
export function buildBackboneDevicesOverlayGeoJson(
  deviceNodes: readonly GlobeNode[],
  gazetteer?: GazetteerV1 | null,
): GeoJSON.FeatureCollection<GeoJSON.Point, BackboneDeviceDotFeatureProps> {
  if (!deviceNodes.length) {
    return { type: 'FeatureCollection', features: [] }
  }
  const grouped = groupNodesByLocation(deviceNodes, gazetteer)
  const features: Array<GeoJSON.Feature<GeoJSON.Point, BackboneDeviceDotFeatureProps>> =
    grouped.groups.map((g) => {
      const presence: GlobePresence =
        g.onlineCount > 0 ? 'online' : g.staleCount > 0 ? 'stale' : 'offline'
      return {
        type: 'Feature',
        geometry: { type: 'Point', coordinates: [g.lon, g.lat] },
        properties: {
          key: g.key,
          presence,
          count: g.count,
        },
      }
    })
  return { type: 'FeatureCollection', features }
}
