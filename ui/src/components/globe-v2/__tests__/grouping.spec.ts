// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, expect, it } from 'vitest'
import type { GlobeNode } from '@/components/globe/types'
import {
  approxGlobePixelDistance,
  classifyGroupInteraction,
  clusterGroupsForZoom,
  computeSpiderfyLayout,
  findClusterSplitZoom,
  formatClusterLabel,
  groupNodesByLocation,
  resolveV2Location,
} from '../grouping'
import { donutDiameterForCount, hitHalfBoxPx } from '../icons'

function makeNode(id: string, extra: Partial<GlobeNode> = {}): GlobeNode {
  return {
    id,
    name: id,
    online: true,
    presence: 'online',
    ...extra,
  }
}

describe('globe-v2 grouping — one city = one point, zero scatter, honest location (S4/S7/AC1/AC14)', () => {
  it('maps co-located city devices to the exact same [lon, lat] with group key ${precision}:${lon.toFixed(2)},${lat.toFixed(2)}', () => {
    const nodes = [
      makeNode('device-shanghai-01', { countryCode: 'CN', city: '上海市' }),
      makeNode('device-shanghai-02', { countryCode: 'CN', city: 'Shanghai' }),
      makeNode('device-shanghai-03', { countryCode: 'CN', city: '上海' }),
    ]
    const res = groupNodesByLocation(nodes)
    expect(res.unlocated).toHaveLength(0)
    expect(res.groups).toHaveLength(1)

    const g = res.groups[0]!
    expect(g.count).toBe(3)
    expect(g.precision).toBe('city')
    expect(g.key).toBe(`city:${g.lon.toFixed(2)},${g.lat.toFixed(2)}`)
    // Every device maps to the exact same group key (0 px screen separation at all zooms)
    for (const n of nodes) {
      expect(res.groupKeyByNodeId.get(n.id)).toBe(g.key)
      const loc = res.resolvedByNodeId.get(n.id)!
      expect(loc.lon).toBe(g.lon)
      expect(loc.lat).toBe(g.lat)
    }
  })

  it('NEVER uses relayHome for placement and excludes unlocated devices from the globe', () => {
    const nodes = [
      makeNode('device-relay-only-01', { relayHome: 'cn-east' }),
      makeNode('device-unknown-02', {}),
      makeNode('device-tokyo-01', { countryCode: 'JP', city: 'Tokyo' }),
    ]
    const r0 = resolveV2Location(nodes[0]!)
    expect(r0.precision).toBe('unknown')
    expect(r0.lon).toBeNull()
    expect(r0.lat).toBeNull()

    const grouped = groupNodesByLocation(nodes)
    expect(grouped.groups).toHaveLength(1)
    expect(grouped.unlocated.map((n) => n.id)).toEqual([
      'device-relay-only-01',
      'device-unknown-02',
    ])
  })

  it('prefixes region and country precision labels with ≈ (S7)', () => {
    const grouped = groupNodesByLocation([
      makeNode('reg-1', { countryCode: 'CN', region: '广东省' }),
      makeNode('reg-2', { countryCode: 'CN', region: 'Guangdong' }),
      makeNode('ctry-1', { countryCode: 'JP' }),
      makeNode('ctry-2', { countryCode: 'JP' }),
    ])
    const merged = clusterGroupsForZoom(grouped.groups, 9)
    const regCluster = merged.clusters.find((c) => c.precision === 'region')!
    const ctryCluster = merged.clusters.find((c) => c.precision === 'country')!
    expect(formatClusterLabel(regCluster, 'zh-CN')).toBe('≈ 广东省 · 2')
    expect(formatClusterLabel(ctryCluster, 'zh-CN')).toBe('≈ 日本 · 2')
    expect(formatClusterLabel(ctryCluster, 'en')).toBe('≈ Japan · 2')
  })

  it('merges nearby cities within 40 px at low integer zoom and anchors at the largest group (never centroid), never merging at z >= 9', () => {
    const nodes = [
      // 10 devices in Shanghai, 2 in Suzhou (~85 km apart)
      ...Array.from({ length: 10 }, (_, i) =>
        makeNode(`sh-${i}`, { countryCode: 'CN', city: 'Shanghai' }),
      ),
      ...Array.from({ length: 2 }, (_, i) =>
        makeNode(`sz-${i}`, { countryCode: 'CN', city: 'Suzhou' }),
      ),
    ]
    const grouped = groupNodesByLocation(nodes)
    expect(grouped.groups).toHaveLength(2)
    const shGroup = grouped.groups[0]!
    expect(shGroup.placeEn).toBe('Shanghai')

    // At z=2 Shanghai and Suzhou are < 40 px apart -> merge into 1 multi-city cluster anchored at Shanghai
    const pxZ2 = approxGlobePixelDistance(
      [shGroup.lon, shGroup.lat],
      [grouped.groups[1]!.lon, grouped.groups[1]!.lat],
      2,
    )
    expect(pxZ2).toBeLessThan(40)

    const z2 = clusterGroupsForZoom(grouped.groups, 2, 40)
    expect(z2.clusters).toHaveLength(1)
    expect(z2.clusters[0]!.isMultiCity).toBe(true)
    expect(z2.clusters[0]!.count).toBe(12)
    expect(z2.clusters[0]!.lon).toBe(shGroup.lon)
    expect(z2.clusters[0]!.lat).toBe(shGroup.lat)

    // Split zoom finds the smallest integer zoom where they separate
    const splitZ = findClusterSplitZoom(z2.clusters[0]!, grouped.groups, 2, 9, 40)
    expect(splitZ).not.toBeNull()
    expect(splitZ!).toBeGreaterThan(2)
    expect(splitZ!).toBeLessThanOrEqual(9)

    // At z >= 9 never merges
    const z9 = clusterGroupsForZoom(grouped.groups, 9, 40)
    expect(z9.clusters).toHaveLength(2)
    expect(z9.clusters.every((c) => !c.isMultiCity)).toBe(true)
  })

  it('applies exact S4 spiderfy thresholds (2-8 circle, 9-20 Archimedean spiral, >20 list) and foot separation >= 28/44', () => {
    expect(classifyGroupInteraction(1)).toBe('select-device')
    expect(classifyGroupInteraction(2)).toBe('circle')
    expect(classifyGroupInteraction(8)).toBe('circle')
    expect(classifyGroupInteraction(9)).toBe('spiral')
    expect(classifyGroupInteraction(20)).toBe('spiral')
    expect(classifyGroupInteraction(21)).toBe('list')

    // Circle (5 devices) with mixed presence/gateway to verify sort order: offline -> stale -> gateway -> rest
    const five = [
      makeNode('dev-z', { presence: 'online', online: true }),
      makeNode('gw-a', { presence: 'online', online: true, isGateway: true }),
      makeNode('dev-stale', { presence: 'stale', online: false }),
      makeNode('dev-off', { presence: 'offline', online: false }),
      makeNode('dev-a', { presence: 'online', online: true }),
    ]
    const circle = computeSpiderfyLayout(five, false)
    expect(circle.mode).toBe('circle')
    expect(circle.feet).toHaveLength(5)
    expect(circle.feet.map((f) => f.node.id)).toEqual([
      'dev-off',
      'dev-stale',
      'gw-a',
      'dev-a',
      'dev-z',
    ])
    // Starts at 12 o'clock (-pi/2)
    expect(circle.feet[0]!.angle).toBeCloseTo(-Math.PI / 2, 6)
    // Foot spacing >= 28px on desktop
    const chord = Math.hypot(
      circle.feet[1]!.dx - circle.feet[0]!.dx,
      circle.feet[1]!.dy - circle.feet[0]!.dy,
    )
    expect(chord).toBeGreaterThanOrEqual(27)

    // Spiral (14 devices, desktop & coarse touch)
    const fourteen = Array.from({ length: 14 }, (_, i) => makeNode(`dev-${String(i).padStart(2, '0')}`))
    const spiralFine = computeSpiderfyLayout(fourteen, false)
    expect(spiralFine.mode).toBe('spiral')
    expect(spiralFine.feet).toHaveLength(14)
    expect(spiralFine.maxRadius).toBeLessThanOrEqual(75)

    const spiralCoarse = computeSpiderfyLayout(fourteen, true)
    expect(spiralCoarse.mode).toBe('spiral')
    expect(spiralCoarse.footSeparation).toBe(44)
    expect(spiralCoarse.maxRadius).toBeLessThanOrEqual(115)

    // >20 paginated list (28 devices)
    const twentyEight = Array.from({ length: 28 }, (_, i) => makeNode(`dev-${i}`))
    const listLayout = computeSpiderfyLayout(twentyEight, false)
    expect(listLayout.mode).toBe('list')
    expect(listLayout.feet).toHaveLength(0)

    // Icon size & hit-box helpers (S3 / AC2 / AC3)
    expect(donutDiameterForCount(5)).toBe(16)
    expect(donutDiameterForCount(14)).toBe(20)
    expect(donutDiameterForCount(55)).toBe(24)
    expect(hitHalfBoxPx(false) * 2).toBe(24)
    expect(hitHalfBoxPx(true) * 2).toBe(44)
  })
})
