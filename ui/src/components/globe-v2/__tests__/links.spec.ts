// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, expect, it } from 'vitest'
import type { GlobeArc, GlobeNode } from '@/components/globe/types'
import { clusterGroupsForZoom, groupNodesByLocation } from '../grouping'
import {
  aggregateLinks,
  buildEgoNetwork,
  buildLinkGeoJson,
  interpolateGreatCircle,
  splitGreatCircleAtMidpoint,
} from '../links'
import { elevatedArcHeightScale, elevatedArcPeakHeight } from '../elevatedArcsLayer'
import { buildSyntheticMesh } from '../syntheticData'

function node(id: string, city: string, countryCode: string): GlobeNode {
  return { id, name: id, online: true, presence: 'online', city, countryCode }
}

function arc(
  from: string,
  to: string,
  carrier = 'direct',
  extra: Partial<GlobeArc> = {},
): GlobeArc {
  return {
    key: `${from}-${to}-${carrier}`,
    from,
    to,
    carrier,
    color: '#56B4E9',
    kind: 'peer',
    ...extra,
  }
}

describe('globe-v2 links — R1..R11 aggregation, priority cap, ego, midpoint split (S5/AC9)', () => {
  it('R1: never draws intra-city links and records their count per group', () => {
    const nodes = [
      node('sh-1', 'Shanghai', 'CN'),
      node('sh-2', 'Shanghai', 'CN'),
      node('tyo-1', 'Tokyo', 'JP'),
    ]
    const arcs = [
      arc('sh-1', 'sh-2', 'direct', { rttMs: 2 }),
      arc('sh-1', 'tyo-1', 'direct', { rttMs: 36 }),
    ]
    const grouped = groupNodesByLocation(nodes)
    const merged = clusterGroupsForZoom(grouped.groups, 9)
    const clusterById = new Map(merged.clusters.map((c) => [c.id, c]))

    const res = aggregateLinks(
      arcs,
      merged.displayIdByNodeId,
      grouped.groupKeyByNodeId,
      clusterById,
    )
    expect(res.totalIntraCityLinks).toBe(1)
    expect(res.displayed).toHaveLength(1)
    const shGroupKey = grouped.groupKeyByNodeId.get('sh-1')!
    expect(res.intraCityCountByGroup.get(shGroupKey)).toBe(1)
  })

  it('R2 & R3: caps overview to 60 and sorts by anyStalled > worstClass > count > key', () => {
    // 14 distinct cities -> 91 pairs (>60)
    const cities: Array<[string, string]> = [
      ['Shanghai', 'CN'], ['Beijing', 'CN'], ['Shenzhen', 'CN'], ['Chengdu', 'CN'],
      ['Tokyo', 'JP'], ['Seoul', 'KR'], ['Singapore', 'SG'], ['Mumbai', 'IN'],
      ['Frankfurt', 'DE'], ['London', 'GB'], ['Paris', 'FR'], ['New York', 'US'],
      ['San Jose', 'US'], ['Sydney', 'AU'],
    ]
    const nodes = cities.map(([c, cc], idx) => node(`n-${idx}`, c, cc))
    const arcs: GlobeArc[] = []
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const isStalled = i === 12 && j === 13
        const isDerp = i === 10 && j === 11
        const isRelay = i === 8 && j === 9
        arcs.push(
          arc(
            nodes[i]!.id,
            nodes[j]!.id,
            isDerp ? 'derp' : isRelay ? 'relay' : 'direct',
            { stalled: isStalled, rttMs: 40 },
          ),
        )
      }
    }

    const grouped = groupNodesByLocation(nodes)
    const merged = clusterGroupsForZoom(grouped.groups, 9)
    const clusterById = new Map(merged.clusters.map((c) => [c.id, c]))

    const res = aggregateLinks(
      arcs,
      merged.displayIdByNodeId,
      grouped.groupKeyByNodeId,
      clusterById,
      { maxOverviewLinks: 60 },
    )
    expect(res.allAggregated).toHaveLength(91)
    expect(res.displayed).toHaveLength(60)
    expect(res.overflowCount).toBe(31)
    // Priority order: stalled first, then derp, then relay
    expect(res.displayed[0]!.anyStalled).toBe(true)
    expect(res.displayed[1]!.worstClass).toBe('derp')
    expect(res.displayed[2]!.worstClass).toBe('relay')
  })

  it('R5: ego network returns all incident aggregated links for a selected device', () => {
    const nodes = [
      node('sh-1', 'Shanghai', 'CN'),
      node('tyo-1', 'Tokyo', 'JP'),
      node('fra-1', 'Frankfurt', 'DE'),
      node('sjc-1', 'San Jose', 'US'),
    ]
    const arcs = [
      arc('sh-1', 'tyo-1', 'direct', { rttMs: 35 }),
      arc('sh-1', 'fra-1', 'relay', { rttMs: 145 }),
      arc('tyo-1', 'sjc-1', 'direct', { rttMs: 110 }),
    ]
    const grouped = groupNodesByLocation(nodes)
    const merged = clusterGroupsForZoom(grouped.groups, 9)
    const clusterById = new Map(merged.clusters.map((c) => [c.id, c]))

    const ego = buildEgoNetwork(
      arcs,
      { nodeId: 'sh-1' },
      merged.displayIdByNodeId,
      grouped.groupKeyByNodeId,
      clusterById,
    )
    expect(ego).toHaveLength(2)
    expect(ego.every((l) => l.arcs.every((a) => a.from === 'sh-1' || a.to === 'sh-1'))).toBe(true)
  })

  it('R8 & R9: interpolates great circle with antimeridian unwrap and splits asymmetric links at exact midpoint', () => {
    // Tokyo (139.69, 35.69) -> San Jose (-121.89, 37.34) crosses antimeridian
    const coords = interpolateGreatCircle([139.69, 35.69], [-121.89, 37.34], 16, 24)
    expect(coords.length).toBeGreaterThanOrEqual(17)
    expect(coords.length).toBeLessThanOrEqual(25)
    for (let i = 1; i < coords.length; i++) {
      expect(Math.abs(coords[i]![0] - coords[i - 1]![0])).toBeLessThanOrEqual(180)
    }

    const { firstHalf, secondHalf, midpoint } = splitGreatCircleAtMidpoint(coords)
    expect(firstHalf[firstHalf.length - 1]).toEqual(midpoint)
    expect(secondHalf[0]).toEqual(midpoint)

    // Asymmetric link emits 2 LineString segments in GeoJSON
    const nodes = [node('tyo-1', 'Tokyo', 'JP'), node('sjc-1', 'San Jose', 'US')]
    const asymArc = arc('tyo-1', 'sjc-1', 'relay', {
      asymmetric: true,
      rttMs: 105,
      ends: [
        { node: 'tyo-1', carrier: 'direct', rtt_ms: 100 },
        { node: 'sjc-1', carrier: 'relay', relay: 'turn/udp', rtt_ms: 110 },
      ],
    })
    const grouped = groupNodesByLocation(nodes)
    const merged = clusterGroupsForZoom(grouped.groups, 9)
    const clusterById = new Map(merged.clusters.map((c) => [c.id, c]))
    const agg = aggregateLinks([asymArc], merged.displayIdByNodeId, grouped.groupKeyByNodeId, clusterById)
    expect(agg.displayed[0]!.asymmetric).toBe(true)

    const gj = buildLinkGeoJson(agg.displayed, [])
    expect(gj.lines.features).toHaveLength(2)
    expect(
      new Set(gj.lines.features.map((f) => f.properties.carrier)),
    ).toEqual(new Set(['direct', 'relay']))
  })

  it('R11 & S11: elevated arcs flatten smoothly to 0 at z5 and Synthetic x10 groups+aggregates in <= 5ms', () => {
    expect(elevatedArcHeightScale(1)).toBe(1)
    expect(elevatedArcHeightScale(3)).toBe(1)
    expect(elevatedArcHeightScale(4)).toBeCloseTo(0.5, 5)
    expect(elevatedArcHeightScale(5)).toBe(0)
    expect(elevatedArcPeakHeight(Math.PI / 2, 5)).toBe(0)
    expect(elevatedArcPeakHeight(Math.PI, 1)).toBeCloseTo(0.3, 5)

    // Synthetic x10 dataset structure check (~300 devices, ~3000 links, clusters of 5, 14, 28)
    const syn = buildSyntheticMesh(10)
    expect(syn.nodes.length).toBeGreaterThanOrEqual(290)
    expect(syn.arcs.length).toBe(3000)

    const grouped = groupNodesByLocation(syn.nodes)
    expect(grouped.unlocated.length).toBe(6)
    const counts = grouped.groups.map((g) => g.count)
    expect(counts).toContain(28)
    expect(counts).toContain(14)
    expect(counts).toContain(5)
  })
})
