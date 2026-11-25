// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// Pure one-city-one-point geographic grouping & integer-zoom pixel clustering (S4 / S7 / AC1 / AC14).
// - ZERO geographic scatter: co-located devices share the EXACT [lon, lat].
// - NEVER falls back to `relayHome` for placement.
// - Unlocated devices stay off-globe in `unlocated[]` for the legend chip.

import type { GlobeNode, GlobePresence } from '@/components/globe/types'
import type { GlobeLang } from './tokens'
import {
  COUNTRY_LONLAT,
  normalizePlaceName,
  resolveV2Location,
  type GazetteerV1,
  type ResolvedV2Location,
  type V2GeoPrecision,
} from './locationResolver'
import {
  classifyGroupInteraction,
  computeSpiderfyLayout,
  effectivePresence,
  effectiveSiteIp,
  LIST_PAGE_SIZE,
  sortSpiderfyMembers,
  SPIDERFY_CIRCLE_MAX,
  SPIDERFY_MAX_SITES,
  SPIDERFY_SPIRAL_MAX,
  type SpiderfyFoot,
  type SpiderfyLayout,
  type SpiderfyMode,
  type SpiderfySiteGroup,
  type SpiderfySiteLink,
} from './spiderfy'

export {
  classifyGroupInteraction,
  computeSpiderfyLayout,
  COUNTRY_LONLAT,
  effectivePresence,
  effectiveSiteIp,
  LIST_PAGE_SIZE,
  normalizePlaceName,
  resolveV2Location,
  sortSpiderfyMembers,
  SPIDERFY_CIRCLE_MAX,
  SPIDERFY_MAX_SITES,
  SPIDERFY_SPIRAL_MAX,
}
export type {
  GazetteerV1,
  ResolvedV2Location,
  SpiderfyFoot,
  SpiderfyLayout,
  SpiderfyMode,
  SpiderfySiteGroup,
  SpiderfySiteLink,
  V2GeoPrecision,
}

export interface CityGroup {
  key: string
  precision: Exclude<V2GeoPrecision, 'unknown'>
  lon: number
  lat: number
  accuracyRadiusKm: number | null
  placeEn: string
  placeZh: string
  countryCode: string
  nodes: GlobeNode[]
  count: number
  onlineCount: number
  staleCount: number
  offlineCount: number
  hasGateway: boolean
  hasEntry: boolean
  hasCentre: boolean
  hasProblem: boolean
}

export interface DisplayCluster {
  /** Stable identifier: single group key or `cluster:<anchorGroupKey>@z<zi>`. */
  id: string
  anchorGroupKey: string
  lon: number
  lat: number
  accuracyRadiusKm: number | null
  groups: CityGroup[]
  isMultiCity: boolean
  nodes: GlobeNode[]
  count: number
  onlineCount: number
  staleCount: number
  offlineCount: number
  hasGateway: boolean
  hasEntry: boolean
  hasCentre: boolean
  hasProblem: boolean
  precision: Exclude<V2GeoPrecision, 'unknown'>
  placeEn: string
  placeZh: string
  countryCode: string
}

export interface GroupedNodesResult {
  groups: CityGroup[]
  groupByKey: Map<string, CityGroup>
  groupKeyByNodeId: Map<string, string>
  resolvedByNodeId: Map<string, ResolvedV2Location>
  unlocated: GlobeNode[]
}

/**
 * Group devices into true-coordinate city/region/country/coords groups with ZERO scatter.
 * Unlocated devices (including those with only `relayHome`) are excluded from the globe
 * and returned in `unlocated`.
 */
export function groupNodesByLocation(
  nodes: readonly GlobeNode[],
  gazetteer?: GazetteerV1 | null,
): GroupedNodesResult {
  const bucketMap = new Map<
    string,
    { res: ResolvedV2Location; members: GlobeNode[]; maxAccuracyKm: number | null }
  >()
  const groupKeyByNodeId = new Map<string, string>()
  const resolvedByNodeId = new Map<string, ResolvedV2Location>()
  const unlocated: GlobeNode[] = []

  for (const node of nodes) {
    const res = resolveV2Location(node, gazetteer)
    resolvedByNodeId.set(node.id, res)
    if (res.precision === 'unknown' || res.lon == null || res.lat == null || !res.groupKey) {
      unlocated.push(node)
      continue
    }
    groupKeyByNodeId.set(node.id, res.groupKey)
    const bucket = bucketMap.get(res.groupKey)
    if (bucket) {
      bucket.members.push(node)
      if (
        res.accuracyRadiusKm != null &&
        (bucket.maxAccuracyKm == null || res.accuracyRadiusKm > bucket.maxAccuracyKm)
      ) {
        bucket.maxAccuracyKm = res.accuracyRadiusKm
      }
    } else {
      bucketMap.set(res.groupKey, {
        res,
        members: [node],
        maxAccuracyKm: res.accuracyRadiusKm,
      })
    }
  }

  const groups: CityGroup[] = []
  for (const [key, { res, members, maxAccuracyKm }] of bucketMap) {
    const sorted = sortSpiderfyMembers(members)
    let onlineCount = 0
    let staleCount = 0
    let offlineCount = 0
    let hasGateway = false
    let hasEntry = false
    let hasCentre = false

    for (const m of sorted) {
      const p: GlobePresence = effectivePresence(m)
      if (p === 'online') onlineCount++
      else if (p === 'stale') staleCount++
      else offlineCount++
      if (m.isGateway || m.role === 'gateway') hasGateway = true
      if (m.isEntry || m.role === 'entry') hasEntry = true
      if (m.isCentre || m.role === 'centre') hasCentre = true
    }

    groups.push({
      key,
      precision: res.precision as Exclude<V2GeoPrecision, 'unknown'>,
      lon: res.lon!,
      lat: res.lat!,
      accuracyRadiusKm: maxAccuracyKm,
      placeEn: res.placeEn,
      placeZh: res.placeZh,
      countryCode: res.countryCode,
      nodes: sorted,
      count: sorted.length,
      onlineCount,
      staleCount,
      offlineCount,
      hasGateway,
      hasEntry,
      hasCentre,
      hasProblem: staleCount > 0 || offlineCount > 0,
    })
  }

  // S4 deterministic ordering: count desc, then key asc
  groups.sort((a, b) => b.count - a.count || a.key.localeCompare(b.key))
  const groupByKey = new Map(groups.map((g) => [g.key, g]))

  return { groups, groupByKey, groupKeyByNodeId, resolvedByNodeId, unlocated }
}

/** Central angle in radians between two `[lon, lat]` points in degrees. */
export function centralAngleRad(
  a: readonly [number, number],
  b: readonly [number, number],
): number {
  const deg = Math.PI / 180
  const lat1 = a[1] * deg
  const lat2 = b[1] * deg
  const dLat = lat2 - lat1
  const dLon = (b[0] - a[0]) * deg
  const h =
    Math.sin(dLat / 2) ** 2 + Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLon / 2) ** 2
  return 2 * Math.asin(Math.min(1, Math.sqrt(Math.max(0, h))))
}

/** Approximate screen pixel distance at integer zoom `zi` (S4 formula). */
export function approxGlobePixelDistance(
  a: readonly [number, number],
  b: readonly [number, number],
  zi: number,
): number {
  return (centralAngleRad(a, b) * 512 * Math.pow(2, zi)) / (2 * Math.PI)
}

export interface ClusterMergeResult {
  zi: number
  clusters: DisplayCluster[]
  displayIdByGroupKey: Map<string, string>
  displayIdByNodeId: Map<string, string>
}

/**
 * Application-side pixel merge at integer zoom `zi = Math.floor(zoom)` (S4):
 * - No merging when `zi >= 9`.
 * - Groups processed in count-desc, key-asc order.
 * - Merged when `approxGlobePixelDistance < mergeRadiusPx` (default 40).
 * - Cluster anchor is ALWAYS the largest member group's true `[lon, lat]`.
 */
export function clusterGroupsForZoom(
  groups: readonly CityGroup[],
  zoom: number,
  mergeRadiusPx = 40,
): ClusterMergeResult {
  const zi = Math.floor(zoom)
  const ordered = [...groups].sort((a, b) => b.count - a.count || a.key.localeCompare(b.key))

  const clusters: DisplayCluster[] = []
  const displayIdByGroupKey = new Map<string, string>()
  const displayIdByNodeId = new Map<string, string>()

  const makeClusterFromGroup = (g: CityGroup): DisplayCluster => ({
    id: g.key,
    anchorGroupKey: g.key,
    lon: g.lon,
    lat: g.lat,
    accuracyRadiusKm: g.accuracyRadiusKm,
    groups: [g],
    isMultiCity: false,
    nodes: [...g.nodes],
    count: g.count,
    onlineCount: g.onlineCount,
    staleCount: g.staleCount,
    offlineCount: g.offlineCount,
    hasGateway: g.hasGateway,
    hasEntry: g.hasEntry,
    hasCentre: g.hasCentre,
    hasProblem: g.hasProblem,
    precision: g.precision,
    placeEn: g.placeEn,
    placeZh: g.placeZh,
    countryCode: g.countryCode,
  })

  if (zi >= 9) {
    for (const g of ordered) {
      const c = makeClusterFromGroup(g)
      clusters.push(c)
      displayIdByGroupKey.set(g.key, c.id)
      for (const n of g.nodes) displayIdByNodeId.set(n.id, c.id)
    }
    return { zi, clusters, displayIdByGroupKey, displayIdByNodeId }
  }

  for (const g of ordered) {
    let target: DisplayCluster | null = null
    if (!g.hasCentre) {
      for (const existing of clusters) {
        if (existing.hasCentre) continue
        const px = approxGlobePixelDistance([g.lon, g.lat], [existing.lon, existing.lat], zi)
        if (px < mergeRadiusPx) {
          target = existing
          break
        }
      }
    }

    if (target) {
      target.groups.push(g)
      target.isMultiCity = true
      target.nodes.push(...g.nodes)
      target.count += g.count
      target.onlineCount += g.onlineCount
      target.staleCount += g.staleCount
      target.offlineCount += g.offlineCount
      target.hasGateway ||= g.hasGateway
      target.hasEntry ||= g.hasEntry
      target.hasProblem ||= g.hasProblem
      displayIdByGroupKey.set(g.key, target.id)
      for (const n of g.nodes) displayIdByNodeId.set(n.id, target.id)
    } else {
      const c = makeClusterFromGroup(g)
      clusters.push(c)
      displayIdByGroupKey.set(g.key, c.id)
      for (const n of g.nodes) displayIdByNodeId.set(n.id, c.id)
    }
  }

  for (const c of clusters) {
    if (c.isMultiCity) {
      c.nodes = sortSpiderfyMembers(c.nodes)
    }
  }

  return { zi, clusters, displayIdByGroupKey, displayIdByNodeId }
}

/**
 * Find the smallest integer zoom (<= maxZoom) at which a multi-city cluster splits
 * into at least 2 display nodes (S4). Returns `null` if it still doesn't split at `maxZoom`.
 */
export function findClusterSplitZoom(
  cluster: DisplayCluster,
  allGroups: readonly CityGroup[],
  currentZoom: number,
  maxZoom = 9,
  mergeRadiusPx = 40,
): number | null {
  if (!cluster.isMultiCity) return null
  const memberKeys = new Set(cluster.groups.map((g) => g.key))
  const startZ = Math.max(Math.floor(currentZoom) + 1, 1)
  for (let z = startZ; z <= maxZoom; z++) {
    const res = clusterGroupsForZoom(allGroups, z, mergeRadiusPx)
    const distinctIds = new Set<string>()
    for (const k of memberKeys) {
      const id = res.displayIdByGroupKey.get(k)
      if (id) distinctIds.add(id)
    }
    if (distinctIds.size > 1) return z
  }
  return null
}

/** Format group/cluster label strictly per S7 (prefix "≈ " for region & country). */
export function formatClusterLabel(cluster: DisplayCluster, lang: GlobeLang): string {
  const place =
    lang === 'zh-CN' ? cluster.placeZh || cluster.placeEn : cluster.placeEn || cluster.placeZh
  const prefix = cluster.precision === 'region' || cluster.precision === 'country' ? '≈ ' : ''
  if (cluster.count === 1 && (cluster.precision === 'city' || cluster.precision === 'coords')) {
    return `${place || cluster.nodes[0]?.name || ''}`
  }
  if (cluster.count === 1) {
    return `${prefix}${place || cluster.nodes[0]?.name || ''}`
  }
  if (cluster.isMultiCity) {
    const extra = cluster.groups.length - 1
    return lang === 'zh-CN'
      ? `${prefix}${place}+${extra}城 · ${cluster.count}`
      : `${prefix}${place}+${extra} · ${cluster.count}`
  }
  return `${prefix}${place} · ${cluster.count}`
}
