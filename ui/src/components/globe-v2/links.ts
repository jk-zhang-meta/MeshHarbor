// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// Pure link aggregation, priority cap, ego network, great-circle interpolation,
// antimeridian unwrapping, and asymmetric midpoint splitting (S5 / AC9).

import type { GlobeArc } from '@/components/globe/types'
import { edgeSides } from '@/utils/mesh'
import type { DisplayCluster } from './grouping'

export type LinkCarrierClass = 'direct' | 'tunnel' | 'relay' | 'derp' | 'blocked'

export interface LinkFilterOptions {
  enabledCarriers?: ReadonlySet<string>
  onlyProblems?: boolean
  minRttMs?: number
  showBlocked?: boolean
  maxOverviewLinks?: number
}

export interface AggregatedLink {
  key: string
  fromDisplayId: string
  toDisplayId: string
  fromLonLat: readonly [number, number]
  toLonLat: readonly [number, number]
  count: number
  worstClass: LinkCarrierClass
  anyStalled: boolean
  blockedOnly: boolean
  medianRtt: number | null
  maxRtt: number | null
  carrierHistogram: Record<string, number>
  asymmetric: boolean
  fromClass: LinkCarrierClass
  toClass: LinkCarrierClass
  /** True when direct/tunnel and never stalled or blocked. */
  healthy: boolean
  arcs: GlobeArc[]
}

export interface LinkAggregationResult {
  displayed: AggregatedLink[]
  allAggregated: AggregatedLink[]
  overflowCount: number
  intraCityCountByGroup: Map<string, number>
  totalIntraCityLinks: number
}

/** Worst-class ranking per S5: derp > relay > tunnel > direct (stalled sorted above class). */
export function carrierSeverityRank(cls: string): number {
  switch (cls) {
    case 'derp':
      return 3
    case 'relay':
      return 2
    case 'tunnel':
      return 1
    case 'direct':
      return 0
    case 'blocked':
      return 2
    default:
      return 0
  }
}

export function normalizeCarrierClass(raw: string | null | undefined): LinkCarrierClass {
  const c = (raw ?? '').toLowerCase()
  if (c === 'derp' || c === 'relay' || c === 'tunnel' || c === 'blocked') return c
  return 'direct'
}

function pairKey(a: string, b: string): [string, string, string] {
  return a < b ? [a, b, `${a}~${b}`] : [b, a, `${b}~${a}`]
}

function computeMedian(values: number[]): number | null {
  if (!values.length) return null
  const sorted = [...values].sort((a, b) => a - b)
  const mid = Math.floor(sorted.length / 2)
  return sorted.length % 2 === 0
    ? Math.round((sorted[mid - 1]! + sorted[mid]!) / 2)
    : Math.round(sorted[mid]!)
}

/**
 * Aggregate peer links at the current display level (S5 R1–R4):
 * - R1: Never draw intra-group or intra-display links; tally intra-group counts.
 * - R2: Aggregate per unordered pair of display clusters.
 * - R3: Sort by `anyStalled > worstClass > count > key` and cap overview to 60.
 * - R4: Apply carrier, `onlyProblems`, and `minRttMs` filters.
 */
export function aggregateLinks(
  arcs: readonly GlobeArc[],
  displayIdByNodeId: ReadonlyMap<string, string>,
  groupKeyByNodeId: ReadonlyMap<string, string>,
  clusterById: ReadonlyMap<string, DisplayCluster>,
  opts: LinkFilterOptions = {},
): LinkAggregationResult {
  const maxOverview = opts.maxOverviewLinks ?? 60
  const showBlocked = opts.showBlocked ?? (opts.enabledCarriers ? opts.enabledCarriers.has('blocked') : false)
  const onlyProblems = Boolean(opts.onlyProblems)
  const minRttMs = opts.minRttMs ?? 0

  const intraCityCountByGroup = new Map<string, number>()
  let totalIntraCityLinks = 0

  interface Bucket {
    fromId: string
    toId: string
    key: string
    arcs: GlobeArc[]
    rtts: number[]
    histogram: Record<string, number>
    anyStalled: boolean
    worstNonBlocked: LinkCarrierClass | null
    hasBlocked: boolean
    fromWorst: LinkCarrierClass | null
    toWorst: LinkCarrierClass | null
  }

  const buckets = new Map<string, Bucket>()

  for (const arc of arcs) {
    if (arc.kind === 'control') continue
    const gFrom = groupKeyByNodeId.get(arc.from)
    const gTo = groupKeyByNodeId.get(arc.to)
    if (!gFrom || !gTo) continue

    // R1: Intra-city links are NEVER drawn on the globe
    if (gFrom === gTo) {
      intraCityCountByGroup.set(gFrom, (intraCityCountByGroup.get(gFrom) ?? 0) + 1)
      totalIntraCityLinks++
      continue
    }

    const dFrom = displayIdByNodeId.get(arc.from)
    const dTo = displayIdByNodeId.get(arc.to)
    if (!dFrom || !dTo || dFrom === dTo) continue

    const baseCls = normalizeCarrierClass(arc.carrier)
    if (baseCls === 'blocked' && !showBlocked) continue
    if (opts.enabledCarriers && !opts.enabledCarriers.has(baseCls)) continue

    const rtt = typeof arc.rttMs === 'number' && Number.isFinite(arc.rttMs) ? arc.rttMs : null
    if (minRttMs > 0 && (rtt == null || rtt < minRttMs)) continue

    const isStalled = Boolean(arc.stalled || arc.ends?.some((e) => e.stalled))
    if (onlyProblems && !isStalled && baseCls !== 'relay' && baseCls !== 'derp' && baseCls !== 'blocked') {
      continue
    }

    const [aId, bId, key] = pairKey(dFrom, dTo)
    const flipped = dFrom !== aId

    let bucket = buckets.get(key)
    if (!bucket) {
      bucket = {
        fromId: aId,
        toId: bId,
        key,
        arcs: [],
        rtts: [],
        histogram: {},
        anyStalled: false,
        worstNonBlocked: null,
        hasBlocked: false,
        fromWorst: null,
        toWorst: null,
      }
      buckets.set(key, bucket)
    }

    bucket.arcs.push(arc)
    bucket.histogram[baseCls] = (bucket.histogram[baseCls] ?? 0) + 1
    if (rtt != null) bucket.rtts.push(rtt)
    if (isStalled) bucket.anyStalled = true

    if (baseCls === 'blocked') {
      bucket.hasBlocked = true
    } else if (
      !bucket.worstNonBlocked ||
      carrierSeverityRank(baseCls) > carrierSeverityRank(bucket.worstNonBlocked)
    ) {
      bucket.worstNonBlocked = baseCls
    }

    // Track per-side carrier for R8 asymmetric midpoint colouring
    const sides = edgeSides(arc.ends, arc.from, arc.to)
    const sideFromCls = normalizeCarrierClass(sides.from?.carrier ?? arc.carrier)
    const sideToCls = normalizeCarrierClass(sides.to?.carrier ?? arc.carrier)
    const aCls = flipped ? sideToCls : sideFromCls
    const bCls = flipped ? sideFromCls : sideToCls
    if (!bucket.fromWorst || carrierSeverityRank(aCls) > carrierSeverityRank(bucket.fromWorst)) {
      bucket.fromWorst = aCls
    }
    if (!bucket.toWorst || carrierSeverityRank(bCls) > carrierSeverityRank(bucket.toWorst)) {
      bucket.toWorst = bCls
    }
  }

  const allAggregated: AggregatedLink[] = []
  for (const b of buckets.values()) {
    const cFrom = clusterById.get(b.fromId)
    const cTo = clusterById.get(b.toId)
    if (!cFrom || !cTo) continue
    const blockedOnly = b.hasBlocked && !b.worstNonBlocked
    const worstClass: LinkCarrierClass = blockedOnly ? 'blocked' : (b.worstNonBlocked ?? 'direct')
    const fromClass = b.fromWorst ?? worstClass
    const toClass = b.toWorst ?? worstClass
    const asymmetric = fromClass !== toClass
    const healthy = !b.anyStalled && (worstClass === 'direct' || worstClass === 'tunnel')

    allAggregated.push({
      key: b.key,
      fromDisplayId: b.fromId,
      toDisplayId: b.toId,
      fromLonLat: [cFrom.lon, cFrom.lat],
      toLonLat: [cTo.lon, cTo.lat],
      count: b.arcs.length,
      worstClass,
      anyStalled: b.anyStalled,
      blockedOnly,
      medianRtt: computeMedian(b.rtts),
      maxRtt: b.rtts.length ? Math.round(Math.max(...b.rtts)) : null,
      carrierHistogram: b.histogram,
      asymmetric,
      fromClass,
      toClass,
      healthy,
      arcs: b.arcs,
    })
  }

  // S5 R3 deterministic priority sort: anyStalled > worstClass > count > key
  allAggregated.sort(
    (a, b) =>
      Number(b.anyStalled) - Number(a.anyStalled) ||
      carrierSeverityRank(b.worstClass) - carrierSeverityRank(a.worstClass) ||
      b.count - a.count ||
      a.key.localeCompare(b.key),
  )

  const displayed = allAggregated.slice(0, maxOverview)
  const overflowCount = Math.max(0, allAggregated.length - displayed.length)

  return {
    displayed,
    allAggregated,
    overflowCount,
    intraCityCountByGroup,
    totalIntraCityLinks,
  }
}

/**
 * R5 Ego network: all links incident to a focused device or display cluster,
 * aggregated by remote display node.
 */
export function buildEgoNetwork(
  arcs: readonly GlobeArc[],
  focus: { nodeId?: string | null; displayId?: string | null },
  displayIdByNodeId: ReadonlyMap<string, string>,
  groupKeyByNodeId: ReadonlyMap<string, string>,
  clusterById: ReadonlyMap<string, DisplayCluster>,
  opts: Omit<LinkFilterOptions, 'maxOverviewLinks'> = {},
): AggregatedLink[] {
  const focusNodeId = focus.nodeId ?? null
  const focusDisplayId =
    focus.displayId ?? (focusNodeId ? displayIdByNodeId.get(focusNodeId) ?? null : null)
  if (!focusDisplayId) return []

  const filtered = arcs.filter((arc) => {
    if (arc.kind === 'control') return false
    if (focusNodeId) {
      return arc.from === focusNodeId || arc.to === focusNodeId
    }
    const dFrom = displayIdByNodeId.get(arc.from)
    const dTo = displayIdByNodeId.get(arc.to)
    return dFrom === focusDisplayId || dTo === focusDisplayId
  })

  return aggregateLinks(filtered, displayIdByNodeId, groupKeyByNodeId, clusterById, {
    ...opts,
    maxOverviewLinks: Number.MAX_SAFE_INTEGER,
  }).allAggregated
}

/** S3 stroke width in CSS px for an aggregated link count. */
export function aggregatedLinkWidth(count: number): number {
  if (count >= 15) return 2.5
  if (count >= 5) return 2.0
  if (count >= 2) return 1.5
  return 1.0
}

/**
 * Great-circle SLERP interpolation with antimeridian unwrapping (S5 R9).
 * Uses 12–24 segments scaled by angular distance (even count so exact midpoint exists).
 */
export function interpolateGreatCircle(
  fromLonLat: readonly [number, number],
  toLonLat: readonly [number, number],
  minSegments = 16,
  maxSegments = 24,
): Array<[number, number]> {
  const deg = Math.PI / 180
  const rad = 180 / Math.PI

  const toVec = (lon: number, lat: number): [number, number, number] => {
    const phi = lat * deg
    const lam = lon * deg
    const cp = Math.cos(phi)
    return [cp * Math.cos(lam), cp * Math.sin(lam), Math.sin(phi)]
  }

  const a = toVec(fromLonLat[0], fromLonLat[1])
  const b = toVec(toLonLat[0], toLonLat[1])
  const dot = Math.max(-1, Math.min(1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2]))
  const omega = Math.acos(dot)
  const omegaDeg = omega * rad

  // Choose an even segment count within [minSegments, maxSegments] so midpoint is exact.
  let segs = Math.round(Math.max(minSegments, Math.min(maxSegments, Math.ceil(omegaDeg / 5))))
  if (segs % 2 !== 0) segs = Math.min(maxSegments, segs + 1)
  if (segs < 2) segs = 2

  const sinO = Math.sin(omega)
  let perp: [number, number, number] | null = null
  if (omega > Math.PI - 1e-3) {
    const ref: [number, number, number] = Math.abs(a[2]) < 0.9 ? [0, 0, 1] : [1, 0, 0]
    const cx = a[1] * ref[2] - a[2] * ref[1]
    const cy = a[2] * ref[0] - a[0] * ref[2]
    const cz = a[0] * ref[1] - a[1] * ref[0]
    const m = Math.hypot(cx, cy, cz) || 1
    perp = [cx / m, cy / m, cz / m]
  }

  const rawCoords: Array<[number, number]> = []
  for (let i = 0; i <= segs; i++) {
    const t = i / segs
    let x: number
    let y: number
    let z: number
    if (omega < 1e-5) {
      x = a[0]
      y = a[1]
      z = a[2]
    } else if (perp) {
      const ang = t * Math.PI
      const ca = Math.cos(ang)
      const sa = Math.sin(ang)
      x = a[0] * ca + perp[0] * sa
      y = a[1] * ca + perp[1] * sa
      z = a[2] * ca + perp[2] * sa
    } else {
      const w0 = Math.sin((1 - t) * omega) / sinO
      const w1 = Math.sin(t * omega) / sinO
      x = w0 * a[0] + w1 * b[0]
      y = w0 * a[1] + w1 * b[1]
      z = w0 * a[2] + w1 * b[2]
    }
    const len = Math.hypot(x, y, z) || 1
    const lat = Math.asin(Math.max(-1, Math.min(1, z / len))) * rad
    const lon = Math.atan2(y, x) * rad
    rawCoords.push([lon, lat])
  }

  // Unwrap longitudes so consecutive vertices never jump > 180 deg across antimeridian.
  const unwrapped: Array<[number, number]> = [rawCoords[0]!]
  for (let i = 1; i < rawCoords.length; i++) {
    let lon = rawCoords[i]![0]
    const prevLon = unwrapped[i - 1]![0]
    while (lon - prevLon > 180) lon -= 360
    while (lon - prevLon < -180) lon += 360
    unwrapped.push([lon, rawCoords[i]![1]])
  }
  return unwrapped
}

/** R8 asymmetric split right at the exact great-circle midpoint. */
export function splitGreatCircleAtMidpoint(coords: ReadonlyArray<[number, number]>): {
  firstHalf: Array<[number, number]>
  secondHalf: Array<[number, number]>
  midpoint: [number, number]
} {
  if (coords.length < 2) {
    const pt: [number, number] = coords[0] ?? [0, 0]
    return { firstHalf: [pt, pt], secondHalf: [pt, pt], midpoint: pt }
  }
  const midIdx = Math.floor((coords.length - 1) / 2)
  if ((coords.length - 1) % 2 === 0) {
    const mid = coords[midIdx]!
    return {
      firstHalf: coords.slice(0, midIdx + 1) as Array<[number, number]>,
      secondHalf: coords.slice(midIdx) as Array<[number, number]>,
      midpoint: [mid[0], mid[1]],
    }
  }
  const p0 = coords[midIdx]!
  const p1 = coords[midIdx + 1]!
  const mid: [number, number] = [(p0[0] + p1[0]) / 2, (p0[1] + p1[1]) / 2]
  return {
    firstHalf: [...coords.slice(0, midIdx + 1), mid],
    secondHalf: [mid, ...coords.slice(midIdx + 1)],
    midpoint: mid,
  }
}

export interface LinkSegmentFeatureProps {
  key: string
  fromDisplayId: string
  toDisplayId: string
  carrier: LinkCarrierClass
  stalled: boolean
  count: number
  width: number
  opacity: number
  ego: boolean
  medianRtt: number | null
  asymmetric: boolean
}

export interface LinkBadgeFeatureProps {
  key: string
  badge: string
  colorKind: 'stalled' | 'blocked' | 'rtt'
}

export function buildLinkGeoJson(
  overviewLinks: readonly AggregatedLink[],
  egoLinks: readonly AggregatedLink[],
  opts: {
    hoveredLinkKey?: string | null
    selectedLinkKey?: string | null
    hasEgoFocus?: boolean
  } = {},
): {
  lines: GeoJSON.FeatureCollection<GeoJSON.LineString, LinkSegmentFeatureProps>
  badges: GeoJSON.FeatureCollection<GeoJSON.Point, LinkBadgeFeatureProps>
} {
  const features: Array<GeoJSON.Feature<GeoJSON.LineString, LinkSegmentFeatureProps>> = []
  const badgeFeatures: Array<GeoJSON.Feature<GeoJSON.Point, LinkBadgeFeatureProps>> = []
  const hasEgo = Boolean(opts.hasEgoFocus && egoLinks.length > 0)
  const egoKeySet = new Set(egoLinks.map((l) => l.key))
  const showAllEgoRtt = hasEgo && egoLinks.length <= 12

  const pushLink = (link: AggregatedLink, isEgo: boolean) => {
    const coords = interpolateGreatCircle(link.fromLonLat, link.toLonLat, 16, 24)
    const { firstHalf, secondHalf, midpoint } = splitGreatCircleAtMidpoint(coords)
    const isHighlighted =
      opts.hoveredLinkKey === link.key || opts.selectedLinkKey === link.key

    const baseWidth = isEgo ? 1.5 : aggregatedLinkWidth(link.count)
    const width = isHighlighted ? baseWidth + 1 : baseWidth
    const opacity = isHighlighted
      ? 1
      : isEgo
        ? 1
        : hasEgo
          ? 0.15
          : link.healthy
            ? 0.45
            : 0.9

    if (link.asymmetric && !link.anyStalled && !link.blockedOnly) {
      features.push({
        type: 'Feature',
        geometry: { type: 'LineString', coordinates: firstHalf },
        properties: {
          key: link.key,
          fromDisplayId: link.fromDisplayId,
          toDisplayId: link.toDisplayId,
          carrier: link.fromClass,
          stalled: false,
          count: link.count,
          width,
          opacity,
          ego: isEgo,
          medianRtt: link.medianRtt,
          asymmetric: true,
        },
      })
      features.push({
        type: 'Feature',
        geometry: { type: 'LineString', coordinates: secondHalf },
        properties: {
          key: link.key,
          fromDisplayId: link.fromDisplayId,
          toDisplayId: link.toDisplayId,
          carrier: link.toClass,
          stalled: false,
          count: link.count,
          width,
          opacity,
          ego: isEgo,
          medianRtt: link.medianRtt,
          asymmetric: true,
        },
      })
    } else {
      features.push({
        type: 'Feature',
        geometry: { type: 'LineString', coordinates: coords },
        properties: {
          key: link.key,
          fromDisplayId: link.fromDisplayId,
          toDisplayId: link.toDisplayId,
          carrier: link.worstClass,
          stalled: link.anyStalled,
          count: link.count,
          width,
          opacity,
          ego: isEgo,
          medianRtt: link.medianRtt,
          asymmetric: link.asymmetric,
        },
      })
    }

    // Wrap midpoint longitude back into [-180, 180] for symbol placement
    let midLon = midpoint[0]
    while (midLon > 180) midLon -= 360
    while (midLon < -180) midLon += 360

    if (link.anyStalled) {
      badgeFeatures.push({
        type: 'Feature',
        geometry: { type: 'Point', coordinates: [midLon, midpoint[1]] },
        properties: { key: link.key, badge: '⚠', colorKind: 'stalled' },
      })
    } else if (link.blockedOnly) {
      badgeFeatures.push({
        type: 'Feature',
        geometry: { type: 'Point', coordinates: [midLon, midpoint[1]] },
        properties: { key: link.key, badge: '×', colorKind: 'blocked' },
      })
    } else if ((isHighlighted || (isEgo && showAllEgoRtt)) && link.medianRtt != null) {
      const label =
        link.count > 1 ? `×${link.count} · ${link.medianRtt} ms` : `${link.medianRtt} ms`
      badgeFeatures.push({
        type: 'Feature',
        geometry: { type: 'Point', coordinates: [midLon, midpoint[1]] },
        properties: { key: link.key, badge: label, colorKind: 'rtt' },
      })
    }
  }

  for (const link of overviewLinks) {
    if (hasEgo && egoKeySet.has(link.key)) continue
    pushLink(link, false)
  }
  if (hasEgo) {
    for (const link of egoLinks) {
      pushLink(link, true)
    }
  }

  return {
    lines: { type: 'FeatureCollection', features },
    badges: { type: 'FeatureCollection', features: badgeFeatures },
  }
}
