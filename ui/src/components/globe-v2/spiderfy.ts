// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// Pure screen-space spiderfy geometry (S4 / AC4). Zero DOM dependencies.
// - n = 2..8: circle starting at 12 o'clock (-pi/2)
// - n = 9..20: Archimedean spiral starting at 12 o'clock (-pi/2)
// - n > 20: paginated list (50 per page), no spiderfy

import type { GlobeNode, GlobePresence } from '@/components/globe/types'

export type SpiderfyMode = 'circle' | 'spiral' | 'list'

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
}

export interface SpiderfyLayout {
  mode: SpiderfyMode
  feet: SpiderfyFoot[]
  maxRadius: number
  footSeparation: number
  coarse: boolean
}

export const SPIDERFY_CIRCLE_MAX = 8
export const SPIDERFY_SPIRAL_MAX = 20
export const LIST_PAGE_SIZE = 50

export function effectivePresence(node: GlobeNode): GlobePresence {
  if (node.presence === 'online' || node.presence === 'stale' || node.presence === 'offline') {
    return node.presence
  }
  return node.online ? 'online' : 'offline'
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

/**
 * Compute deterministic screen-space offsets for a co-located city group.
 * For `n > 20`, returns `mode: 'list'` with an empty `feet` array.
 */
export function computeSpiderfyLayout(
  members: readonly GlobeNode[],
  coarse = false,
): SpiderfyLayout {
  const ordered = sortSpiderfyMembers(members)
  const n = ordered.length
  const s = coarse ? 44 : 28

  if (n > SPIDERFY_SPIRAL_MAX) {
    return { mode: 'list', feet: [], maxRadius: 0, footSeparation: s, coarse }
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
    return { mode: 'circle', feet, maxRadius: radius, footSeparation: s, coarse }
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

  return { mode: 'spiral', feet, maxRadius, footSeparation: s, coarse }
}
