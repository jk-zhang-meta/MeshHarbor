// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// Where the server-topology map puts each server and how it draws an edge.
import { describe, expect, it } from 'vitest'
import {
  COUNTRY_LONLAT,
  arcPath,
  edgeKey,
  lonLatOf,
  placeServers,
} from '@/components/admin/serverTopology'

// Equirectangular, 1 px per degree: easy to reason about in assertions.
const flat = (ll: readonly [number, number]) => [ll[0] + 180, 90 - ll[1]] as const

const srv = (agent_id: string, country: string | null) => ({ agent_id, country })

describe('lonLatOf', () => {
  it('places the small hubs servers live in, case-insensitively', () => {
    const [hkLon, hkLat] = lonLatOf('hk')!
    expect(hkLon).toBeCloseTo(114.1, 0)
    expect(hkLat).toBeCloseTo(22.4, 0)
    expect(lonLatOf('SG')).not.toBeNull()
  })

  it('uses the mainland, not an overseas territory', () => {
    // Australia once landed on Ashmore and Cartier Is., France would on
    // French Guiana: the table keeps each country's largest polygon.
    const [auLon, auLat] = lonLatOf('AU')!
    expect(auLon).toBeGreaterThan(125)
    expect(auLat).toBeLessThan(-20)
    const [frLon, frLat] = lonLatOf('FR')!
    expect(frLon).toBeGreaterThan(-5)
    expect(frLat).toBeGreaterThan(42)
  })

  it('has no place for an unknown or missing country', () => {
    expect(lonLatOf('ZZ')).toBeNull()
    expect(lonLatOf(null)).toBeNull()
    expect(lonLatOf('')).toBeNull()
  })

  it('covers the world', () => {
    expect(Object.keys(COUNTRY_LONLAT).length).toBeGreaterThan(200)
  })
})

describe('placeServers', () => {
  it('puts a lone server on its country and the rest aside', () => {
    const { placed, unplaced } = placeServers(
      [srv('a', 'CN'), srv('b', null), srv('c', 'ZZ')],
      flat,
    )
    const [lon, lat] = lonLatOf('CN')!
    expect(placed.get('a')).toEqual(flat([lon, lat]))
    expect(unplaced.map((s) => s.agent_id)).toEqual(['b', 'c'])
  })

  it('spreads servers of one country on a ring, each its own spot', () => {
    const { placed } = placeServers([srv('a', 'JP'), srv('b', 'jp'), srv('c', 'JP')], flat, 10)
    const center = flat(lonLatOf('JP')!)
    const spots = ['a', 'b', 'c'].map((id) => placed.get(id)!)
    for (const [x, y] of spots) {
      expect(Math.hypot(x - center[0], y - center[1])).toBeCloseTo(10, 6)
    }
    expect(new Set(spots.map((p) => p.join())).size).toBe(3)
  })

  it('leaves aside a server the projection cannot place', () => {
    const { placed, unplaced } = placeServers([srv('a', 'US')], () => null)
    expect(placed.size).toBe(0)
    expect(unplaced).toHaveLength(1)
  })
})

describe('edgeKey and arcPath', () => {
  it('names a pair the same whichever end comes first', () => {
    expect(edgeKey('b1', 'a2')).toBe(edgeKey('a2', 'b1'))
    expect(edgeKey('a2', 'b1')).toBe('a2:b1')
  })

  it('runs from one end to the other', () => {
    expect(arcPath([0, 0], [100, 0])).toMatch(/^M0,0 Q50,18 100,0$/)
  })
})
