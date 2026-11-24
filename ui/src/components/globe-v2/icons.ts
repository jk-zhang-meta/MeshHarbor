// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// Retina Canvas2D constant-screen-size marker & city donut icon generator (S3 / AC2 / AC3).

import type { GlobePresence } from '@/components/globe/types'
import type { DisplayCluster } from './grouping'
import { getGlobeTokens, type GlobeThemeMode, type GlobeTokens } from './tokens'

export interface IconImageData {
  width: number
  height: number
  data: Uint8ClampedArray
}

/** S3 donut visible diameter in CSS px: 16 (2..9), 20 (10..49), 24 (>=50). */
export function donutDiameterForCount(count: number): 16 | 20 | 24 {
  if (count >= 50) return 24
  if (count >= 10) return 20
  return 16
}

/** S3 WCAG 2.5.8 hit-box half-size for queryRenderedFeatures: 12 (24px fine) / 22 (44px coarse). */
export function hitHalfBoxPx(coarse: boolean): 12 | 22 {
  return coarse ? 22 : 12
}

function presenceFillColor(presence: GlobePresence, tokens: GlobeTokens): string {
  if (presence === 'online') return tokens.online
  if (presence === 'stale') return tokens.stale
  return tokens.offline
}

function makeCanvas(cssWidth: number, cssHeight: number, dpr: number) {
  const canvas = document.createElement('canvas')
  canvas.width = Math.max(1, Math.round(cssWidth * dpr))
  canvas.height = Math.max(1, Math.round(cssHeight * dpr))
  const ctx = canvas.getContext('2d')!
  ctx.scale(dpr, dpr)
  return { canvas, ctx }
}

function toImageData(canvas: HTMLCanvasElement, ctx: CanvasRenderingContext2D): IconImageData {
  const img = ctx.getImageData(0, 0, canvas.width, canvas.height)
  return { width: img.width, height: img.height, data: img.data }
}

export function drawDeviceIcon(
  presence: GlobePresence,
  tokens: GlobeTokens,
  dpr: number,
  selected = false,
): IconImageData {
  const box = 24
  const cx = box / 2
  const cy = box / 2
  const { canvas, ctx } = makeCanvas(box, box, dpr)

  if (selected) {
    ctx.beginPath()
    ctx.arc(cx, cy, 7.5, 0, Math.PI * 2)
    ctx.strokeStyle = tokens.focusRing
    ctx.lineWidth = 1.5
    ctx.stroke()
  }

  if (presence === 'online') {
    // Solid circle Ø6 + 1px ocean outline
    ctx.beginPath()
    ctx.arc(cx, cy, 3, 0, Math.PI * 2)
    ctx.fillStyle = tokens.online
    ctx.fill()
    ctx.lineWidth = 1
    ctx.strokeStyle = tokens.ocean
    ctx.stroke()
  } else if (presence === 'stale') {
    // Ø7 left-half filled circle + 1.5px stale stroke (non-color cue)
    ctx.beginPath()
    ctx.arc(cx, cy, 3.5, 0, Math.PI * 2)
    ctx.fillStyle = tokens.ocean
    ctx.fill()
    ctx.beginPath()
    ctx.arc(cx, cy, 3.5, Math.PI / 2, (Math.PI * 3) / 2)
    ctx.closePath()
    ctx.fillStyle = tokens.stale
    ctx.fill()
    ctx.beginPath()
    ctx.arc(cx, cy, 3.5, 0, Math.PI * 2)
    ctx.lineWidth = 1.5
    ctx.strokeStyle = tokens.stale
    ctx.stroke()
  } else {
    // Ø7 hollow ring + 45° slash
    ctx.beginPath()
    ctx.arc(cx, cy, 3.5, 0, Math.PI * 2)
    ctx.fillStyle = tokens.ocean
    ctx.fill()
    ctx.lineWidth = 1.25
    ctx.strokeStyle = tokens.offline
    ctx.stroke()
    ctx.beginPath()
    ctx.moveTo(cx - 2.4, cy + 2.4)
    ctx.lineTo(cx + 2.4, cy - 2.4)
    ctx.stroke()
  }

  return toImageData(canvas, ctx)
}

export function drawGatewayIcon(
  presence: GlobePresence,
  tokens: GlobeTokens,
  dpr: number,
  selected = false,
): IconImageData {
  const box = 24
  const cx = box / 2
  const cy = box / 2
  const { canvas, ctx } = makeCanvas(box, box, dpr)

  if (selected) {
    ctx.beginPath()
    ctx.arc(cx, cy, 8.5, 0, Math.PI * 2)
    ctx.strokeStyle = tokens.focusRing
    ctx.lineWidth = 1.5
    ctx.stroke()
  }

  const size = 8
  const x = cx - size / 2
  const y = cy - size / 2
  const r = 2
  ctx.beginPath()
  ctx.moveTo(x + r, y)
  ctx.lineTo(x + size - r, y)
  ctx.quadraticCurveTo(x + size, y, x + size, y + r)
  ctx.lineTo(x + size, y + size - r)
  ctx.quadraticCurveTo(x + size, y + size, x + size - r, y + size)
  ctx.lineTo(x + r, y + size)
  ctx.quadraticCurveTo(x, y + size, x, y + size - r)
  ctx.lineTo(x, y + r)
  ctx.quadraticCurveTo(x, y, x + r, y)
  ctx.closePath()
  ctx.fillStyle = presenceFillColor(presence, tokens)
  ctx.fill()
  ctx.lineWidth = 1.5
  ctx.strokeStyle = tokens.ocean
  ctx.stroke()

  return toImageData(canvas, ctx)
}

export function drawEntryIcon(
  presence: GlobePresence,
  tokens: GlobeTokens,
  dpr: number,
  selected = false,
): IconImageData {
  const box = 24
  const cx = box / 2
  const cy = box / 2
  const { canvas, ctx } = makeCanvas(box, box, dpr)

  if (selected) {
    ctx.beginPath()
    ctx.arc(cx, cy, 9, 0, Math.PI * 2)
    ctx.strokeStyle = tokens.focusRing
    ctx.lineWidth = 1.5
    ctx.stroke()
  }

  const side = 9
  const h = (Math.sqrt(3) / 2) * side
  ctx.beginPath()
  ctx.moveTo(cx, cy - (h * 2) / 3)
  ctx.lineTo(cx + side / 2, cy + h / 3)
  ctx.lineTo(cx - side / 2, cy + h / 3)
  ctx.closePath()
  ctx.fillStyle = presenceFillColor(presence, tokens)
  ctx.fill()
  ctx.lineWidth = 1.5
  ctx.strokeStyle = tokens.ocean
  ctx.stroke()

  return toImageData(canvas, ctx)
}

export function drawCentreIcon(tokens: GlobeTokens, dpr: number, selected = false): IconImageData {
  const box = 28
  const cx = box / 2
  const cy = box / 2
  const { canvas, ctx } = makeCanvas(box, box, dpr)

  if (selected) {
    ctx.beginPath()
    ctx.arc(cx, cy, 10.5, 0, Math.PI * 2)
    ctx.strokeStyle = tokens.focusRing
    ctx.lineWidth = 1.5
    ctx.stroke()
  }

  const half = 6 // 12x12 diamond
  ctx.beginPath()
  ctx.moveTo(cx, cy - half)
  ctx.lineTo(cx + half, cy)
  ctx.lineTo(cx, cy + half)
  ctx.lineTo(cx - half, cy)
  ctx.closePath()
  ctx.fillStyle = tokens.centre
  ctx.fill()
  ctx.lineWidth = 1.5
  ctx.strokeStyle = tokens.ocean
  ctx.stroke()

  return toImageData(canvas, ctx)
}

export function drawAnchorIcon(tokens: GlobeTokens, dpr: number): IconImageData {
  const box = 16
  const cx = box / 2
  const cy = box / 2
  const { canvas, ctx } = makeCanvas(box, box, dpr)
  ctx.beginPath()
  ctx.arc(cx, cy, 2.2, 0, Math.PI * 2)
  ctx.fillStyle = tokens.focusRing
  ctx.fill()
  ctx.lineWidth = 1
  ctx.strokeStyle = tokens.ocean
  ctx.stroke()
  return toImageData(canvas, ctx)
}

export function drawDonutIcon(
  cluster: Pick<
    DisplayCluster,
    'count' | 'onlineCount' | 'staleCount' | 'offlineCount' | 'hasGateway' | 'hasCentre' | 'isMultiCity'
  >,
  tokens: GlobeTokens,
  dpr: number,
  selected = false,
): IconImageData {
  const diameter = donutDiameterForCount(cluster.count)
  const box = diameter + 16
  const cx = box / 2
  const cy = box / 2
  const outerR = diameter / 2
  const ringW = 3
  const { canvas, ctx } = makeCanvas(box, box, dpr)

  // Multi-city cluster hairline outer ring (+3 px)
  if (cluster.isMultiCity) {
    ctx.beginPath()
    ctx.arc(cx, cy, outerR + 3, 0, Math.PI * 2)
    ctx.strokeStyle = tokens.labelSecondary
    ctx.lineWidth = 1
    ctx.stroke()
  }

  // Selected focus ring (+4 px)
  if (selected) {
    ctx.beginPath()
    ctx.arc(cx, cy, outerR + 4, 0, Math.PI * 2)
    ctx.strokeStyle = tokens.focusRing
    ctx.lineWidth = 1.5
    ctx.stroke()
  }

  // Outer ocean halo for separation
  ctx.beginPath()
  ctx.arc(cx, cy, outerR + 1, 0, Math.PI * 2)
  ctx.fillStyle = tokens.ocean
  ctx.fill()

  // Donut segments clockwise from 12 o'clock: online, stale, offline
  const total = Math.max(1, cluster.count)
  const slices: Array<{ n: number; color: string }> = [
    { n: cluster.onlineCount, color: tokens.online },
    { n: cluster.staleCount, color: tokens.stale },
    { n: cluster.offlineCount, color: tokens.offline },
  ]
  let start = -Math.PI / 2
  for (const s of slices) {
    if (s.n <= 0) continue
    const sweep = (s.n / total) * Math.PI * 2
    ctx.beginPath()
    ctx.arc(cx, cy, outerR - ringW / 2, start, start + sweep)
    ctx.strokeStyle = s.color
    ctx.lineWidth = ringW
    ctx.stroke()
    start += sweep
  }

  // Inner hub fill
  ctx.beginPath()
  ctx.arc(cx, cy, outerR - ringW, 0, Math.PI * 2)
  ctx.fillStyle = tokens.hubFill
  ctx.fill()

  // Count text (10 / 11 / 12 px)
  const fontSize = diameter === 16 ? 10 : diameter === 20 ? 11 : 12
  ctx.font = `600 ${fontSize}px system-ui, -apple-system, "Segoe UI", sans-serif`
  ctx.fillStyle = tokens.hubText
  ctx.textAlign = 'center'
  ctx.textBaseline = 'middle'
  ctx.fillText(String(cluster.count), cx, cy + 0.5)

  // Gateway 5x5 top-right square badge
  if (cluster.hasGateway) {
    const bx = cx + outerR * 0.62 - 2.5
    const by = cy - outerR * 0.62 - 2.5
    ctx.fillStyle = tokens.online
    ctx.fillRect(bx, by, 5, 5)
    ctx.lineWidth = 1
    ctx.strokeStyle = tokens.ocean
    ctx.strokeRect(bx, by, 5, 5)
  }

  // Centre diamond outer frame
  if (cluster.hasCentre) {
    const d = outerR + 2.5
    ctx.beginPath()
    ctx.moveTo(cx, cy - d)
    ctx.lineTo(cx + d, cy)
    ctx.lineTo(cx, cy + d)
    ctx.lineTo(cx - d, cy)
    ctx.closePath()
    ctx.lineWidth = 1.5
    ctx.strokeStyle = tokens.centre
    ctx.stroke()
  }

  return toImageData(canvas, ctx)
}

export interface IconRegistryMap {
  hasImage(id: string): boolean
  addImage(id: string, image: IconImageData, options?: { pixelRatio?: number }): void
}

/** Register all fixed single-node & anchor icons for a given theme mode. */
export function ensureStaticIcons(
  map: IconRegistryMap,
  mode: GlobeThemeMode,
  dpr: number,
): void {
  const tokens = getGlobeTokens(mode)
  const presences: GlobePresence[] = ['online', 'stale', 'offline']
  for (const selected of [false, true]) {
    const selTag = selected ? '-sel' : ''
    for (const p of presences) {
      const devId = `mh-dev-${p}${selTag}-${mode}`
      if (!map.hasImage(devId)) {
        map.addImage(devId, drawDeviceIcon(p, tokens, dpr, selected), { pixelRatio: dpr })
      }
      const gwId = `mh-gw-${p}${selTag}-${mode}`
      if (!map.hasImage(gwId)) {
        map.addImage(gwId, drawGatewayIcon(p, tokens, dpr, selected), { pixelRatio: dpr })
      }
      const entryId = `mh-entry-${p}${selTag}-${mode}`
      if (!map.hasImage(entryId)) {
        map.addImage(entryId, drawEntryIcon(p, tokens, dpr, selected), { pixelRatio: dpr })
      }
    }
    const centreId = `mh-centre${selTag}-${mode}`
    if (!map.hasImage(centreId)) {
      map.addImage(centreId, drawCentreIcon(tokens, dpr, selected), { pixelRatio: dpr })
    }
  }
  const anchorId = `mh-anchor-${mode}`
  if (!map.hasImage(anchorId)) {
    map.addImage(anchorId, drawAnchorIcon(tokens, dpr), { pixelRatio: dpr })
  }
}

/** Resolve (and lazily register if donut) the icon id for a DisplayCluster. */
export function resolveClusterIconId(
  map: IconRegistryMap,
  cluster: DisplayCluster,
  mode: GlobeThemeMode,
  dpr: number,
  selected: boolean,
  spiderfied: boolean,
): string {
  if (spiderfied) return `mh-anchor-${mode}`
  const selTag = selected ? '-sel' : ''

  if (cluster.count === 1) {
    const n = cluster.nodes[0]!
    if (n.isCentre || n.role === 'centre') return `mh-centre${selTag}-${mode}`
    const p: GlobePresence =
      n.presence === 'online' || n.presence === 'stale' || n.presence === 'offline'
        ? n.presence
        : n.online
          ? 'online'
          : 'offline'
    if (n.isGateway || n.role === 'gateway') return `mh-gw-${p}${selTag}-${mode}`
    if (n.isEntry || n.role === 'entry') return `mh-entry-${p}${selTag}-${mode}`
    return `mh-dev-${p}${selTag}-${mode}`
  }

  const donutId =
    `mh-donut-${cluster.count}-${cluster.onlineCount}-${cluster.staleCount}-${cluster.offlineCount}` +
    `-${cluster.hasGateway ? 1 : 0}${cluster.hasCentre ? 1 : 0}${cluster.isMultiCity ? 1 : 0}` +
    `${selTag}-${mode}`
  if (!map.hasImage(donutId)) {
    const tokens = getGlobeTokens(mode)
    map.addImage(donutId, drawDonutIcon(cluster, tokens, dpr, selected), { pixelRatio: dpr })
  }
  return donutId
}
