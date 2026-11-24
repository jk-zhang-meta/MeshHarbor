// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, expect, it } from 'vitest'
import {
  buildGreatCircleArcPoints,
  computeArcVisualStates,
  computeClusterOffset,
  latLonToVec3,
  placeGlobeNodes,
  resolveNodeGeo,
  vec3ToLatLon,
} from '../geoLayout'
import type { GlobeArc, GlobeNode } from '../types'

describe('geoLayout — device resolution & deterministic placement', () => {
  it('resolves finest available location: coords > city > region > country > relay_home > unknown', () => {
    const withCoords = resolveNodeGeo({
      id: 'n1',
      name: 'device-coords',
      online: true,
      lat: 35.69,
      lon: 139.69,
      countryCode: 'JP',
    })
    expect(withCoords.precision).toBe('coords')
    expect(withCoords.lon).toBeCloseTo(139.69, 2)

    const withZhCity = resolveNodeGeo({
      id: 'n2',
      name: 'device-sz',
      online: true,
      countryCode: 'CN',
      country: '中国',
      region: '广东省',
      city: '深圳市',
    })
    expect(withZhCity.precision).toBe('city')
    expect(withZhCity.lat).toBeCloseTo(22.54, 1)
    expect(withZhCity.lon).toBeCloseTo(114.06, 1)
    expect(withZhCity.locationLabel).toBe('中国 · 广东省 · 深圳市')

    const withEnCity = resolveNodeGeo({
      id: 'n3',
      name: 'device-fra',
      online: true,
      countryCode: 'DE',
      country: 'Germany',
      city: 'Frankfurt',
    })
    expect(withEnCity.precision).toBe('city')
    expect(withEnCity.lat).toBeCloseTo(50.11, 1)

    const withRegion = resolveNodeGeo({
      id: 'n4',
      name: 'device-gd',
      online: true,
      countryCode: 'CN',
      country: '中国',
      region: '广东省',
      city: 'UnknownTown',
    })
    expect(withRegion.precision).toBe('region')
    expect(withRegion.lat).toBeCloseTo(23.13, 1)

    const withCountryOnly = resolveNodeGeo({
      id: 'n5',
      name: 'device-de',
      online: true,
      countryCode: 'DE',
    })
    expect(withCountryOnly.precision).toBe('country')
    expect(withCountryOnly.locationLabel).toBe('DE')

    const withRelayOnly = resolveNodeGeo({
      id: 'n6',
      name: 'device-relay',
      online: true,
      relayHome: 'us-east-1',
    })
    expect(withRelayOnly.precision).toBe('relay_home')
    expect(withRelayOnly.locationLabel).toBe('')
    expect(withRelayOnly.lon).toBeLessThan(-70)

    const unknown = resolveNodeGeo({
      id: 'n7',
      name: 'device-unknown',
      online: false,
    })
    expect(unknown.precision).toBe('unknown')
    expect(unknown.locationLabel).toBe('')
  })

  it('keeps a single device on its anchor and spreads co-located devices deterministically', () => {
    const cluster: GlobeNode[] = [
      { id: 'c', name: 'device-c', online: false, countryCode: 'CN', city: '深圳市' },
      { id: 'a', name: 'device-a', online: true, countryCode: 'CN', city: '深圳市' },
      { id: 'b', name: 'device-b', online: true, countryCode: 'CN', city: '深圳市' },
      { id: 'solo', name: 'device-solo', online: true, countryCode: 'SG', city: 'Singapore' },
    ]
    const first = placeGlobeNodes(cluster, null, 0)
    const reversed = placeGlobeNodes([...cluster].reverse(), null, 0)

    const solo = first.nodes.find((n) => n.id === 'solo')!
    expect(solo.lon).toBe(solo.baseLon)
    expect(solo.lat).toBe(solo.baseLat)
    expect(solo.clusterSize).toBe(1)

    // Deterministic regardless of input ordering
    for (const id of ['a', 'b', 'c']) {
      const p1 = first.nodes.find((n) => n.id === id)!
      const p2 = reversed.nodes.find((n) => n.id === id)!
      expect(p1.lon).toBeCloseTo(p2.lon, 6)
      expect(p1.lat).toBeCloseTo(p2.lat, 6)
      expect(p1.clusterSize).toBe(3)
    }

    // All three co-located devices get distinct coordinates
    const coords = new Set(
      ['a', 'b', 'c'].map((id) => {
        const p = first.nodes.find((n) => n.id === id)!
        return `${p.lon.toFixed(3)},${p.lat.toFixed(3)}`
      }),
    )
    expect(coords.size).toBe(3)
  })

  it('expands co-located cluster spread cleanly as zoom increases', () => {
    const [dLon0, dLat0] = computeClusterOffset(1, 6, 0, 22.5)
    const [dLonMid, dLatMid] = computeClusterOffset(1, 6, 0.5, 22.5)
    const [dLon1, dLat1] = computeClusterOffset(1, 6, 1, 22.5)

    const r0 = Math.hypot(dLon0, dLat0)
    const rMid = Math.hypot(dLonMid, dLatMid)
    const r1 = Math.hypot(dLon1, dLat1)

    expect(r0).toBeGreaterThan(0)
    expect(rMid).toBeGreaterThan(r0)
    expect(r1).toBeGreaterThan(rMid)
    expect(computeClusterOffset(0, 1, 1, 22.5)).toEqual([0, 0])
  })

  it('places the centre marker at its country when known, or as an orbital centroid hub otherwise', () => {
    const nodes: GlobeNode[] = [
      { id: 'n1', name: 'device-a', online: true, countryCode: 'CN', city: '深圳市' },
      { id: 'n2', name: 'device-b', online: true, countryCode: 'JP', city: 'Tokyo' },
    ]
    const orbital = placeGlobeNodes(nodes, { id: 'cp', name: 'centre.example.test' })
    expect(orbital.center?.orbital).toBe(true)
    expect(orbital.center!.lon).toBeGreaterThan(100)
    expect(orbital.center!.lat).toBeGreaterThan(15)

    const pinned = placeGlobeNodes(nodes, {
      id: 'cp',
      name: 'centre.example.test',
      countryCode: 'SG',
    })
    expect(pinned.center?.orbital).toBe(false)
    expect(pinned.center?.lat).toBeCloseTo(1.4, 1)
  })

  it('round-trips latLonToVec3 and vec3ToLatLon accurately', () => {
    for (const [lat, lon] of [
      [22.54, 114.06],
      [50.11, 8.68],
      [-33.87, 151.21],
      [39.04, -77.49],
    ]) {
      const v = latLonToVec3(lat!, lon!, 1)
      const back = vec3ToLatLon(v)
      expect(back.lat).toBeCloseTo(lat!, 3)
      expect(back.lon).toBeCloseTo(lon!, 3)
    }
  })
})

describe('geoLayout — great-circle SLERP arcs & density dimming', () => {
  it('builds elevated great-circle arcs that stay outside the sphere for normal, antipodal, and co-located pairs', () => {
    const longHaul = buildGreatCircleArcPoints(22.54, 114.06, 50.11, 8.68, 32)
    expect(longHaul).toHaveLength(33)
    const midR = Math.hypot(longHaul[16]!.x, longHaul[16]!.y, longHaul[16]!.z)
    const endR = Math.hypot(longHaul[0]!.x, longHaul[0]!.y, longHaul[0]!.z)
    expect(midR).toBeGreaterThan(endR + 0.1)

    // Exact antipodal endpoints must never dive through the sphere core
    const antipodal = buildGreatCircleArcPoints(30, 120, -30, -60, 32)
    for (const p of antipodal) {
      expect(Math.hypot(p.x, p.y, p.z)).toBeGreaterThanOrEqual(1.007)
    }

    // Co-located endpoints still get a readable mini-arch
    const colocated = buildGreatCircleArcPoints(22.54, 114.06, 22.54, 114.06, 16)
    const miniApex = Math.hypot(colocated[8]!.x, colocated[8]!.y, colocated[8]!.z)
    expect(miniApex).toBeGreaterThan(1.03)
  })

  it('prevents hairball clutter at 300 edges and highlights focused node/arc while dimming unrelated edges', () => {
    const arcs: GlobeArc[] = Array.from({ length: 300 }, (_, i) => ({
      key: `e-${i}`,
      from: i === 0 ? 'n-focus' : `n-${i % 25}`,
      to: i === 0 ? 'n-peer' : `n-${(i + 7) % 25}`,
      carrier: i === 1 ? 'blocked' : i === 2 ? 'derp' : 'direct',
      color: '#3CCB7F',
      stalled: i === 2,
      blocked: i === 1,
      kind: 'peer',
    }))

    // Idle state: low density-aware opacity prevents hairball
    const idle = computeArcVisualStates(arcs, {
      hoveredNodeId: null,
      selectedNodeId: null,
      hoveredArcKey: null,
      selectedArcKey: null,
    })
    expect(idle[0]!.opacity).toBeLessThanOrEqual(0.2)
    expect(idle[1]!.dashed).toBe(true)
    expect(idle[1]!.pulseStrength).toBe(0)
    expect(idle[2]!.dashed).toBe(true)

    // Focused node: incident arcs pop, unrelated arcs dim heavily
    const nodeFocus = computeArcVisualStates(arcs, {
      hoveredNodeId: 'n-focus',
      selectedNodeId: null,
      hoveredArcKey: null,
      selectedArcKey: null,
    })
    expect(nodeFocus[0]!.opacity).toBeGreaterThan(0.85)
    expect(nodeFocus[10]!.opacity).toBeLessThan(0.06)

    // Focused arc: only that arc pops
    const arcFocus = computeArcVisualStates(arcs, {
      hoveredNodeId: null,
      selectedNodeId: null,
      hoveredArcKey: null,
      selectedArcKey: 'e-2',
    })
    expect(arcFocus[2]!.opacity).toBeGreaterThan(0.95)
    expect(arcFocus[0]!.opacity).toBeLessThan(0.06)
  })
})
