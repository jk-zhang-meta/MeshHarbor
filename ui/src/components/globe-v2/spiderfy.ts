// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// Pure screen-space spiderfy geometry (S4 / AC4 + same-city egress-IP site grouping).
// Zero DOM dependencies.
// - n = 2..20 with 2..6 distinct egress-IP sites: site-grouped pods with inter-site live link arcs (`'sites'`)
// - n = 2..8 (single site / no IPs): circle starting at 12 o'clock (-pi/2)
// - n = 9..20 (single site / no IPs): Archimedean spiral starting at 12 o'clock (-pi/2)
// - n > 20: paginated list (50 per page), no spiderfy

import type { GlobeArc, GlobeNode, GlobePresence } from '@/components/globe/types'

export type SpiderfyMode = 'circle' | 'spiral' | 'sites' | 'list'
export type SpiderfySiteLabelKind = 'self' | 'site' | 'unknown'
export type SpiderfyLinkCarrier = 'direct' | 'tunnel' | 'relay' | 'derp' | 'blocked'

export interface SpiderfyFoot {
  node: GlobeNode
  index: number
  /** Screen-space offset in CSS px from the shared true city anchor. */
  dx: number
  dy: number
  /** Angle in radians from +X axis (top = -pi/2). */
  angle: number
  radius: number
  presence: GlobePresence
  shortLabel: string
  /** Populated in `'sites'` mode: owning site pod id and offset relative to pod body center. */
  siteId?: string
  localDx?: number
  localDy?: number
}

export interface SpiderfySiteGroup {
  id: string
  key: string
  labelKind: SpiderfySiteLabelKind
  siteIndex: number
  publicIp: string | null
  hasSelf: boolean
  onlineCount: number
  count: number
  /** Pod center offset in CSS px relative to the city anchor (0, 0). */
  cx: number
  cy: number
  width: number
  height: number
  headerHeight: number
  /** Point on the pod border closest to (0, 0) where the anchor leg terminates. */
  legX: number
  legY: number
  intraMinRttMs: number | null
  intraMaxRttMs: number | null
  feet: SpiderfyFoot[]
}

export interface SpiderfySiteLink {
  key: string
  fromSiteId: string
  toSiteId: string
  carrier: SpiderfyLinkCarrier
  stalled: boolean
  minRttMs: number | null
  count: number
  color: string
  x1: number
  y1: number
  x2: number
  y2: number
  ctrlX: number
  ctrlY: number
  midX: number
  midY: number
  pathD: string
}

export interface SpiderfyLayout {
  mode: SpiderfyMode
  feet: SpiderfyFoot[]
  sites: SpiderfySiteGroup[]
  siteLinks: SpiderfySiteLink[]
  maxRadius: number
  footSeparation: number
  coarse: boolean
}

export const SPIDERFY_CIRCLE_MAX = 8
export const SPIDERFY_SPIRAL_MAX = 20
export const SPIDERFY_MAX_SITES = 6
export const LIST_PAGE_SIZE = 50

const DEFAULT_CARRIER_COLORS: Readonly<Record<SpiderfyLinkCarrier, string>> = {
  direct: '#56B4E9',
  tunnel: '#2BB58A',
  relay: '#E69F00',
  derp: '#D98CB8',
  blocked: '#8C96A5',
}

export function effectivePresence(node: GlobeNode): GlobePresence {
  if (node.presence === 'online' || node.presence === 'stale' || node.presence === 'offline') {
    return node.presence
  }
  return node.online ? 'online' : 'offline'
}

/**
 * Resolve the effective egress-IP site key for a node.
 * FR-138 physical-uplink IP (`physicalPublicIp`) wins over `publicIp` so VPN-active
 * hosts on the same physical LAN stay grouped with their site peers.
 */
export function effectiveSiteIp(node: GlobeNode): string {
  const phys = typeof node.physicalPublicIp === 'string' ? node.physicalPublicIp.trim() : ''
  if (phys && phys !== '-' && phys !== '—') return phys
  const pub = typeof node.publicIp === 'string' ? node.publicIp.trim() : ''
  if (pub && pub !== '-' && pub !== '—') return pub
  return ''
}

/** S4 foot sort order: offline -> stale -> gateways -> remaining by name. */
export function sortSpiderfyMembers(nodes: readonly GlobeNode[]): GlobeNode[] {
  const rank = (n: GlobeNode): number => {
    const p = effectivePresence(n)
    if (p === 'offline') return 0
    if (p === 'stale') return 1
    if (n.isGateway || n.role === 'gateway') return 2
    if (n.isCentre || n.role === 'centre') return 3
    return 4
  }
  return [...nodes].sort(
    (a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name) || a.id.localeCompare(b.id),
  )
}

export function truncateFootLabel(name: string, maxChars = 14): string {
  if (name.length <= maxChars) return name
  return `${name.slice(0, maxChars - 1)}…`
}

export function classifyGroupInteraction(count: number): 'select-device' | SpiderfyMode {
  if (count <= 1) return 'select-device'
  if (count <= SPIDERFY_CIRCLE_MAX) return 'circle'
  if (count <= SPIDERFY_SPIRAL_MAX) return 'spiral'
  return 'list'
}

function normalizeSiteCarrier(raw: string | null | undefined): SpiderfyLinkCarrier {
  const c = (raw ?? '').trim().toLowerCase()
  if (c === 'tunnel' || c === 'relay' || c === 'derp' || c === 'blocked') return c
  if (c === 'org_relay') return 'relay'
  return 'direct'
}

/** Best-carrier preference for inter-site links: direct > tunnel > relay > derp > blocked. */
function carrierPreferenceRank(cls: SpiderfyLinkCarrier): number {
  switch (cls) {
    case 'direct':
      return 0
    case 'tunnel':
      return 1
    case 'relay':
      return 2
    case 'derp':
      return 3
    case 'blocked':
      return 4
  }
}

function round1(n: number): number {
  return Math.round(n * 10) / 10
}

/**
 * Ray-to-axis-aligned-rectangle border distance from a box center in unit direction `(ux, uy)`.
 */
function rectBorderDistance(w: number, h: number, ux: number, uy: number): number {
  const tx = Math.abs(ux) > 1e-6 ? w / 2 / Math.abs(ux) : Infinity
  const ty = Math.abs(uy) > 1e-6 ? h / 2 / Math.abs(uy) : Infinity
  return Math.min(tx, ty)
}

interface RawSiteBucket {
  key: string
  publicIp: string | null
  isUnknown: boolean
  nodes: GlobeNode[]
  hasSelf: boolean
  onlineCount: number
}

interface LocalPodPlacement {
  width: number
  height: number
  headerHeight: number
  localCoords: Array<{ x: number; y: number; angle: number; radius: number }>
}

function computePodLocalLayout(count: number, coarse: boolean): LocalPodPlacement {
  const headerHeight = coarse ? 42 : 38
  const padX = coarse ? 50 : 44
  const padTop = coarse ? 22 : 18
  const padBottom = coarse ? 28 : 26
  const minWidth = coarse ? 176 : 158
  const minBodyHeight = coarse ? 60 : 50

  const localCoords: Array<{ x: number; y: number; angle: number; radius: number }> = []

  if (count <= 1) {
    localCoords.push({ x: 0, y: -4, angle: -Math.PI / 2, radius: 0 })
  } else if (count === 2) {
    const r = coarse ? 42 : 34
    localCoords.push({ x: -r, y: -4, angle: Math.PI, radius: r })
    localCoords.push({ x: r, y: -4, angle: 0, radius: r })
  } else if (count <= SPIDERFY_CIRCLE_MAX) {
    const sep = coarse ? 50 : 38
    const rMin = coarse ? 34 : 28
    const r = Math.max(rMin, (count * sep) / (2 * Math.PI))
    for (let i = 0; i < count; i++) {
      const angle = -Math.PI / 2 + (2 * Math.PI * i) / count
      localCoords.push({
        x: Math.cos(angle) * r,
        y: Math.sin(angle) * r,
        angle,
        radius: r,
      })
    }
  } else {
    // 9..19 members in a single site pod: two compact concentric rings
    const innerCount = Math.min(6, Math.max(3, Math.floor(count / 3)))
    const outerCount = count - innerCount
    const rInner = coarse ? 30 : 24
    const sepOuter = coarse ? 38 : 28
    const rOuter = Math.max(rInner + (coarse ? 38 : 30), (outerCount * sepOuter) / (2 * Math.PI))
    for (let i = 0; i < innerCount; i++) {
      const angle = -Math.PI / 2 + (2 * Math.PI * i) / innerCount
      localCoords.push({
        x: Math.cos(angle) * rInner,
        y: Math.sin(angle) * rInner,
        angle,
        radius: rInner,
      })
    }
    for (let i = 0; i < outerCount; i++) {
      const angle = -Math.PI / 2 + Math.PI / outerCount + (2 * Math.PI * i) / outerCount
      localCoords.push({
        x: Math.cos(angle) * rOuter,
        y: Math.sin(angle) * rOuter,
        angle,
        radius: rOuter,
      })
    }
  }

  let maxAbsX = 0
  let minY = 0
  let maxY = 0
  for (const pt of localCoords) {
    if (Math.abs(pt.x) > maxAbsX) maxAbsX = Math.abs(pt.x)
    if (pt.y < minY) minY = pt.y
    if (pt.y > maxY) maxY = pt.y
  }

  // Re-center vertically inside the body area accounting for bottom label headroom
  const contentSpanY = maxY - minY
  const shiftY = -((minY + maxY) / 2) - (count <= SPIDERFY_CIRCLE_MAX ? 4 : 0)
  for (const pt of localCoords) {
    pt.y = round1(pt.y + shiftY)
    pt.x = round1(pt.x)
  }

  const width = Math.max(minWidth, Math.ceil((maxAbsX + padX) * 2))
  const bodyHeight = Math.max(minBodyHeight, Math.ceil(contentSpanY + padTop + padBottom))

  return {
    width,
    height: headerHeight + bodyHeight,
    headerHeight,
    localCoords,
  }
}

function buildSitesLayout(
  buckets: RawSiteBucket[],
  arcs: readonly GlobeArc[],
  coarse: boolean,
  footSeparation: number,
): SpiderfyLayout {
  const k = buckets.length

  // Step 1: Compute local geometry for every site pod
  const localPlacements = buckets.map((b) => computePodLocalLayout(b.nodes.length, coarse))

  // Step 2: Position pods around (0, 0) with mathematically guaranteed zero box overlap
  const centers: Array<{ cx: number; cy: number }> = []
  if (k === 2) {
    const gap = coarse ? 132 : 120
    const p0 = localPlacements[0]!
    const p1 = localPlacements[1]!
    centers.push({ cx: round1(-(gap / 2 + p0.width / 2)), cy: 0 })
    centers.push({ cx: round1(gap / 2 + p1.width / 2), cy: 0 })
  } else {
    const angles: number[] =
      k === 3
        ? [-Math.PI / 2, Math.PI / 6, (5 * Math.PI) / 6]
        : k === 4
          ? [-(3 * Math.PI) / 4, -Math.PI / 4, Math.PI / 4, (3 * Math.PI) / 4]
          : Array.from({ length: k }, (_, i) => -Math.PI / 2 + (2 * Math.PI * i) / k)

    const margin = coarse ? 58 : 50
    const centerClearance = coarse ? 34 : 28
    let ringR = coarse ? 120 : 104

    for (let i = 0; i < k; i++) {
      const pi = localPlacements[i]!
      const ci = Math.cos(angles[i]!)
      const si = Math.sin(angles[i]!)
      const reqCx = Math.abs(ci) > 1e-4 ? (pi.width / 2 + centerClearance) / Math.abs(ci) : Infinity
      const reqCy = Math.abs(si) > 1e-4 ? (pi.height / 2 + centerClearance) / Math.abs(si) : Infinity
      ringR = Math.max(ringR, Math.min(reqCx, reqCy))

      for (let j = i + 1; j < k; j++) {
        const pj = localPlacements[j]!
        const dc = Math.abs(ci - Math.cos(angles[j]!))
        const ds = Math.abs(si - Math.sin(angles[j]!))
        const reqX = dc > 1e-4 ? ((pi.width + pj.width) / 2 + margin) / dc : Infinity
        const reqY = ds > 1e-4 ? ((pi.height + pj.height) / 2 + margin) / ds : Infinity
        ringR = Math.max(ringR, Math.min(reqX, reqY))
      }
    }

    for (let i = 0; i < k; i++) {
      centers.push({
        cx: round1(Math.cos(angles[i]!) * ringR),
        cy: round1(Math.sin(angles[i]!) * ringR),
      })
    }
  }

  // Step 3: Materialize pods and flattened feet
  const sites: SpiderfySiteGroup[] = []
  const feet: SpiderfyFoot[] = []
  const siteByNodeId = new Map<string, { site: SpiderfySiteGroup; order: number }>()

  let knownSiteNum = 0
  let globalFootIdx = 0

  for (let i = 0; i < k; i++) {
    const bucket = buckets[i]!
    const local = localPlacements[i]!
    const center = centers[i]!
    const siteIndex = bucket.isUnknown ? 0 : ++knownSiteNum
    const id = bucket.isUnknown ? 'site-unknown' : `site-${siteIndex}`
    const labelKind: SpiderfySiteLabelKind = bucket.isUnknown
      ? 'unknown'
      : bucket.hasSelf
        ? 'self'
        : 'site'

    // Leg attachment point on pod border facing (0, 0)
    const distToOrigin = Math.hypot(center.cx, center.cy)
    let legX = center.cx
    let legY = center.cy
    if (distToOrigin > 1e-4) {
      const ux = -center.cx / distToOrigin
      const uy = -center.cy / distToOrigin
      const borderD = rectBorderDistance(local.width, local.height, ux, uy)
      legX = round1(center.cx + ux * borderD)
      legY = round1(center.cy + uy * borderD)
    }

    const podFeet: SpiderfyFoot[] = bucket.nodes.map((node, localIdx) => {
      const pt = local.localCoords[localIdx]!
      const dx = round1(center.cx + pt.x)
      const dy = round1(center.cy + local.headerHeight / 2 + pt.y)
      const foot: SpiderfyFoot = {
        node,
        index: globalFootIdx++,
        dx,
        dy,
        angle: Math.atan2(dy, dx),
        radius: Math.hypot(dx, dy),
        presence: effectivePresence(node),
        shortLabel: truncateFootLabel(node.name, 12),
        siteId: id,
        localDx: pt.x,
        localDy: pt.y,
      }
      feet.push(foot)
      return foot
    })

    const site: SpiderfySiteGroup = {
      id,
      key: bucket.key,
      labelKind,
      siteIndex,
      publicIp: bucket.publicIp,
      hasSelf: bucket.hasSelf,
      onlineCount: bucket.onlineCount,
      count: bucket.nodes.length,
      cx: center.cx,
      cy: center.cy,
      width: local.width,
      height: local.height,
      headerHeight: local.headerHeight,
      legX,
      legY,
      intraMinRttMs: null,
      intraMaxRttMs: null,
      feet: podFeet,
    }
    sites.push(site)
    for (const node of bucket.nodes) {
      siteByNodeId.set(node.id, { site, order: i })
    }
  }

  // Step 4: Aggregate intra-site RTTs and inter-site live links from `arcs`
  interface LinkBucket {
    fromSite: SpiderfySiteGroup
    toSite: SpiderfySiteGroup
    bestCarrier: SpiderfyLinkCarrier
    bestRank: number
    color: string
    minRttMs: number | null
    stalled: boolean
    count: number
  }

  const linkBuckets = new Map<string, LinkBucket>()

  for (const arc of arcs) {
    if (arc.kind === 'control' || arc.from === arc.to) continue
    const hitA = siteByNodeId.get(arc.from)
    const hitB = siteByNodeId.get(arc.to)
    if (!hitA || !hitB) continue

    const rtt =
      typeof arc.rttMs === 'number' && Number.isFinite(arc.rttMs) && arc.rttMs >= 0
        ? Math.round(arc.rttMs)
        : null

    if (hitA.site.id === hitB.site.id) {
      if (rtt != null) {
        if (hitA.site.intraMinRttMs == null || rtt < hitA.site.intraMinRttMs) {
          hitA.site.intraMinRttMs = rtt
        }
        if (hitA.site.intraMaxRttMs == null || rtt > hitA.site.intraMaxRttMs) {
          hitA.site.intraMaxRttMs = rtt
        }
      }
      continue
    }

    const [first, second] = hitA.order < hitB.order ? [hitA.site, hitB.site] : [hitB.site, hitA.site]
    const pairKey = `${first.id}~${second.id}`
    const carrier = normalizeSiteCarrier(arc.carrier)
    const rank = carrierPreferenceRank(carrier)
    const isStalled = Boolean(arc.stalled || arc.ends?.some((e) => e.stalled))
    const arcColor =
      typeof arc.color === 'string' && arc.color.trim().length > 0
        ? arc.color.trim()
        : DEFAULT_CARRIER_COLORS[carrier]

    let entry = linkBuckets.get(pairKey)
    if (!entry) {
      entry = {
        fromSite: first,
        toSite: second,
        bestCarrier: carrier,
        bestRank: rank,
        color: arcColor,
        minRttMs: rtt,
        stalled: isStalled,
        count: 1,
      }
      linkBuckets.set(pairKey, entry)
    } else {
      entry.count++
      if (isStalled) entry.stalled = true
      if (rtt != null && (entry.minRttMs == null || rtt < entry.minRttMs)) {
        entry.minRttMs = rtt
      }
      if (rank < entry.bestRank) {
        entry.bestCarrier = carrier
        entry.bestRank = rank
        entry.color = arcColor
      }
    }
  }

  // Step 5: Compute curved SVG link geometry between pod edges + pill midpoints
  const siteLinks: SpiderfySiteLink[] = []
  const orderedLinkKeys = [...linkBuckets.keys()].sort()
  for (const key of orderedLinkKeys) {
    const b = linkBuckets.get(key)!
    const a = b.fromSite
    const c = b.toSite
    const dx = c.cx - a.cx
    const dy = c.cy - a.cy
    const dist = Math.hypot(dx, dy) || 1
    const ux = dx / dist
    const uy = dy / dist

    const borderA = rectBorderDistance(a.width, a.height, ux, uy)
    const borderC = rectBorderDistance(c.width, c.height, -ux, -uy)
    const x1 = round1(a.cx + ux * borderA)
    const y1 = round1(a.cy + uy * borderA)
    const x2 = round1(c.cx - ux * borderC)
    const y2 = round1(c.cy - uy * borderC)

    const chordMidX = (x1 + x2) / 2
    const chordMidY = (y1 + y2) / 2
    const chordLen = Math.hypot(x2 - x1, y2 - y1)

    // Choose perpendicular normal that bows away from the center anchor (0, 0)
    let nx = -uy
    let ny = ux
    const midDistFromOrigin = Math.hypot(chordMidX, chordMidY)
    const passesOrigin = midDistFromOrigin < 16
    if (passesOrigin) {
      // Bow upward (negative Y) cleanly above the (0, 0) anchor; if vertical, bow right
      if (Math.abs(ny) > 1e-4) {
        if (ny > 0) {
          nx = -nx
          ny = -ny
        }
      } else if (nx < 0) {
        nx = -nx
        ny = -ny
      }
    } else {
      // Bow outward away from (0, 0) so pills never crowd the center anchor
      if (chordMidX * nx + chordMidY * ny < 0) {
        nx = -nx
        ny = -ny
      }
    }

    const bow = passesOrigin ? 36 : Math.min(26, Math.max(16, chordLen * 0.18))
    const ctrlX = round1(chordMidX + nx * bow * 2)
    const ctrlY = round1(chordMidY + ny * bow * 2)
    // Exact quadratic Bezier point at t = 0.5
    const midX = round1(chordMidX + nx * bow)
    const midY = round1(chordMidY + ny * bow)

    siteLinks.push({
      key,
      fromSiteId: a.id,
      toSiteId: c.id,
      carrier: b.bestCarrier,
      stalled: b.stalled,
      minRttMs: b.minRttMs,
      count: b.count,
      color: b.color,
      x1,
      y1,
      x2,
      y2,
      ctrlX,
      ctrlY,
      midX,
      midY,
      pathD: `M ${x1} ${y1} Q ${ctrlX} ${ctrlY} ${x2} ${y2}`,
    })
  }

  // Step 6: Compute full screen-space bounding radius covering every pod and link arc
  let maxRadius = 0
  for (const s of sites) {
    const cornerR = Math.hypot(Math.abs(s.cx) + s.width / 2, Math.abs(s.cy) + s.height / 2)
    if (cornerR > maxRadius) maxRadius = cornerR
  }
  for (const l of siteLinks) {
    const midR = Math.hypot(l.midX, l.midY) + 56
    const ctrlR = Math.hypot(l.ctrlX, l.ctrlY) + 16
    if (midR > maxRadius) maxRadius = midR
    if (ctrlR > maxRadius) maxRadius = ctrlR
  }

  return {
    mode: 'sites',
    feet,
    sites,
    siteLinks,
    maxRadius: Math.ceil(maxRadius),
    footSeparation,
    coarse,
  }
}

/**
 * Compute deterministic screen-space offsets for a co-located city group.
 * - For `n > 20`, returns `mode: 'list'` with an empty `feet` array.
 * - For `2 <= n <= 20` spanning 2..6 distinct egress-IP sites (preferring FR-138
 *   `physicalPublicIp`, falling back to `publicIp`), returns `mode: 'sites'` with
 *   non-overlapping site pods and aggregated inter-site links from `arcs`.
 * - Otherwise returns classic `'circle'` (2..8) or `'spiral'` (9..20).
 */
export function computeSpiderfyLayout(
  members: readonly GlobeNode[],
  coarse = false,
  arcs: readonly GlobeArc[] = [],
): SpiderfyLayout {
  const ordered = sortSpiderfyMembers(members)
  const n = ordered.length
  const s = coarse ? 44 : 28

  if (n > SPIDERFY_SPIRAL_MAX) {
    return {
      mode: 'list',
      feet: [],
      sites: [],
      siteLinks: [],
      maxRadius: 0,
      footSeparation: s,
      coarse,
    }
  }

  // Check for same-city multi-site egress-IP grouping (2..6 pods total, >= 2 known site IPs)
  if (n >= 2) {
    const bySiteKey = new Map<string, RawSiteBucket>()
    const unknownNodes: GlobeNode[] = []

    for (const node of ordered) {
      const ip = effectiveSiteIp(node)
      if (!ip) {
        unknownNodes.push(node)
        continue
      }
      const normKey = ip.toLowerCase()
      let bucket = bySiteKey.get(normKey)
      if (!bucket) {
        bucket = {
          key: normKey,
          publicIp: ip,
          isUnknown: false,
          nodes: [],
          hasSelf: false,
          onlineCount: 0,
        }
        bySiteKey.set(normKey, bucket)
      }
      bucket.nodes.push(node)
      if (node.isSelf) bucket.hasSelf = true
      if (effectivePresence(node) === 'online') bucket.onlineCount++
    }

    const totalPods = bySiteKey.size + (unknownNodes.length > 0 ? 1 : 0)
    if (bySiteKey.size >= 2 && totalPods <= SPIDERFY_MAX_SITES) {
      const knownBuckets = [...bySiteKey.values()].sort(
        (a, b) =>
          Number(b.hasSelf) - Number(a.hasSelf) ||
          b.nodes.length - a.nodes.length ||
          b.onlineCount - a.onlineCount ||
          a.key.localeCompare(b.key),
      )
      if (unknownNodes.length > 0) {
        knownBuckets.push({
          key: '__unknown__',
          publicIp: null,
          isUnknown: true,
          nodes: unknownNodes,
          hasSelf: unknownNodes.some((m) => Boolean(m.isSelf)),
          onlineCount: unknownNodes.filter((m) => effectivePresence(m) === 'online').length,
        })
      }
      return buildSitesLayout(knownBuckets, arcs, coarse, s)
    }
  }

  if (n <= SPIDERFY_CIRCLE_MAX) {
    const rMin = coarse ? 36 : 26
    const radius = Math.max(rMin, (n * s) / (2 * Math.PI))
    const feet: SpiderfyFoot[] = ordered.map((node, i) => {
      const angle = -Math.PI / 2 + (2 * Math.PI * i) / Math.max(1, n)
      return {
        node,
        index: i,
        dx: Math.cos(angle) * radius,
        dy: Math.sin(angle) * radius,
        angle,
        radius,
        presence: effectivePresence(node),
        shortLabel: truncateFootLabel(node.name, 14),
      }
    })
    return {
      mode: 'circle',
      feet,
      sites: [],
      siteLinks: [],
      maxRadius: radius,
      footSeparation: s,
      coarse,
    }
  }

  // Archimedean spiral (S4): r0 = 22 (30 coarse), k = 4 (6 coarse) px/rad,
  // theta_0 = 0 rotated to 12 o'clock (-pi/2), theta_{i+1} = theta_i + s / r_i,
  // r_{i+1} = r0 + k * theta_{i+1}.
  const r0 = coarse ? 30 : 22
  const k = coarse ? 6 : 4
  let theta = 0
  let r = r0
  let maxRadius = r0
  const feet: SpiderfyFoot[] = ordered.map((node, i) => {
    if (i > 0) {
      theta += s / r
      r = r0 + k * theta
    }
    const angle = -Math.PI / 2 + theta
    if (r > maxRadius) maxRadius = r
    return {
      node,
      index: i,
      dx: Math.cos(angle) * r,
      dy: Math.sin(angle) * r,
      angle,
      radius: r,
      presence: effectivePresence(node),
      shortLabel: truncateFootLabel(node.name, 14),
    }
  })

  return {
    mode: 'spiral',
    feet,
    sites: [],
    siteLinks: [],
    maxRadius,
    footSeparation: s,
    coarse,
  }
}
