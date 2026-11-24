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
  linkCarrierBreakdown,
  pickMajorityCarrier,
  restingLinkWidth,
  splitGreatCircleAtMidpoint,
} from '../links'
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

describe('globe-v2 links — R1..R10 + Fix #6 majority carrier, calm rest vs ego, breakdown (S5/AC9)', () => {
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

  it('Fix #6: colors aggregated city pairs by majority carrier, sets isMixed + breakdown, calm rest (1-1.5px, 0.45) vs full-strength ego', () => {
    const nodes = [
      node('sh-1', 'Shanghai', 'CN'),
      node('sh-2', 'Shanghai', 'CN'),
      node('sh-3', 'Shanghai', 'CN'),
      node('tyo-1', 'Tokyo', 'JP'),
      node('tyo-2', 'Tokyo', 'JP'),
      node('tyo-3', 'Tokyo', 'JP'),
    ]
    // 5 direct + 2 relay (TURN) + 1 derp (stalled) between Shanghai and Tokyo
    const arcs: GlobeArc[] = [
      arc('sh-1', 'tyo-1', 'direct', { rttMs: 32 }),
      arc('sh-1', 'tyo-2', 'direct', { rttMs: 34 }),
      arc('sh-2', 'tyo-1', 'direct', { rttMs: 35 }),
      arc('sh-2', 'tyo-2', 'direct', { rttMs: 36 }),
      arc('sh-3', 'tyo-1', 'direct', { rttMs: 38 }),
      arc('sh-3', 'tyo-2', 'relay', { rttMs: 65 }),
      arc('sh-1', 'tyo-3', 'relay', { rttMs: 70 }),
      arc('sh-2', 'tyo-3', 'derp', { rttMs: 120, stalled: true }),
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
    expect(res.displayed).toHaveLength(1)
    const bundle = res.displayed[0]!
    expect(bundle.count).toBe(8)
    // Majority is direct (5 vs 2 relay vs 1 derp), NOT worst-case derp!
    expect(bundle.majorityClass).toBe('direct')
    expect(bundle.worstClass).toBe('derp')
    expect(bundle.isMixed).toBe(true)
    expect(bundle.stalledCount).toBe(1)

    const breakdown = linkCarrierBreakdown(bundle)
    expect(breakdown).toEqual([
      { key: 'direct', count: 5 },
      { key: 'relay', count: 2 },
      { key: 'derp', count: 1 },
      { key: 'stalled', count: 1 },
    ])

    // Deterministic tie-breaker check
    expect(pickMajorityCarrier({ direct: 2, relay: 2 })).toBe('direct')
    expect(pickMajorityCarrier({ relay: 3, derp: 1 })).toBe('relay')
    expect(pickMajorityCarrier({ blocked: 4 }, true)).toBe('blocked')

    // At rest: calm solid 1–1.5 px at 0.45 opacity, active: false, majority carrier color
    const restGj = buildLinkGeoJson(res.displayed, [])
    expect(restGj.lines.features).toHaveLength(1)
    const restProps = restGj.lines.features[0]!.properties
    expect(restProps.active).toBe(false)
    expect(restProps.carrier).toBe('direct')
    expect(restProps.width).toBeGreaterThanOrEqual(1.0)
    expect(restProps.width).toBeLessThanOrEqual(1.5)
    expect(restProps.opacity).toBeCloseTo(0.45, 2)
    expect(restingLinkWidth(1)).toBe(1.0)
    expect(restingLinkWidth(20)).toBe(1.5)

    // On selection / ego: full strength (active: true, opacity: 1)
    const egoGj = buildLinkGeoJson(res.displayed, res.displayed, {
      hasEgoFocus: true,
      selectedLinkKey: bundle.key,
    })
    expect(egoGj.lines.features[0]!.properties.active).toBe(true)
    expect(egoGj.lines.features[0]!.properties.opacity).toBe(1)
    expect(egoGj.lines.features[0]!.properties.width).toBeGreaterThan(1.5)
  })

  it('R2 & R3: caps overview to 60 and sorts by anyStalled > worstClass > count > key', () => {
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

  it('R8 & R9: interpolates great circle with antimeridian unwrap and splits active asymmetric links at exact midpoint', () => {
    const coords = interpolateGreatCircle([139.69, 35.69], [-121.89, 37.34], 16, 24)
    expect(coords.length).toBeGreaterThanOrEqual(17)
    expect(coords.length).toBeLessThanOrEqual(25)
    for (let i = 1; i < coords.length; i++) {
      expect(Math.abs(coords[i]![0] - coords[i - 1]![0])).toBeLessThanOrEqual(180)
    }

    const { firstHalf, secondHalf, midpoint } = splitGreatCircleAtMidpoint(coords)
    expect(firstHalf[firstHalf.length - 1]).toEqual(midpoint)
    expect(secondHalf[0]).toEqual(midpoint)

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

    // Active (hovered/selected/ego) asymmetric link emits 2 LineString segments split at midpoint
    const gj = buildLinkGeoJson(agg.displayed, agg.displayed, { hasEgoFocus: true })
    expect(gj.lines.features).toHaveLength(2)
    expect(new Set(gj.lines.features.map((f) => f.properties.carrier))).toEqual(
      new Set(['direct', 'relay']),
    )
  })

  it('S11: Synthetic x10 dataset structure and fast grouping + aggregation', () => {
    const syn = buildSyntheticMesh(10)
    expect(syn.nodes.length).toBeGreaterThanOrEqual(290)
    expect(syn.arcs.length).toBe(3000)

    const grouped = groupNodesByLocation(syn.nodes)
    expect(grouped.unlocated.length).toBe(6)
    const counts = grouped.groups.map((g) => g.count)
    expect(counts).toContain(28)
    expect(counts).toContain(14)
    expect(counts).toContain(5)

    const merged = clusterGroupsForZoom(grouped.groups, 2, 40)
    const clusterById = new Map(merged.clusters.map((c) => [c.id, c]))
    const agg = aggregateLinks(syn.arcs, merged.displayIdByNodeId, grouped.groupKeyByNodeId, clusterById)
    expect(agg.displayed.length).toBeLessThanOrEqual(60)
    expect(agg.displayed.some((l) => l.isMixed)).toBe(true)
  })
})
