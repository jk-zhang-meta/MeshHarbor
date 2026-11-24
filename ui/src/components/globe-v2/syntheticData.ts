// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// Deterministic synthetic datasets for T9 P0 prototyping & benchmarking.
// Strictly synthetic RFC 5737 TEST-NET IPs and city-based device names only.

import type { GlobeArc, GlobeCenter, GlobeNode } from '@/components/globe/types'

function mulberry32(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a |= 0
    a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

interface HubSeed {
  slug: string
  countryCode: string
  country: string
  region: string
  city: string
  count: number
  zoneId: string
  zoneName: string
  relayHome: string
  hasGateway?: boolean
  hasEntry?: boolean
  precision?: 'city' | 'region' | 'country'
}

// 300 devices total:
// - Shanghai: 28 devices (exercises >20 paginated list)
// - Beijing: 14 devices (exercises 9..20 Archimedean spiral spiderfy)
// - Hangzhou: 5 devices (exercises 2..8 circle spiderfy)
// - Remaining spread across mainland China + global hubs + region/country-only + 6 unknown
const SYNTHETIC_10X_HUBS: readonly HubSeed[] = [
  // Mainland China dense clusters & cities
  { slug: 'shanghai', countryCode: 'CN', country: '中国', region: '上海市', city: '上海市', count: 28, zoneId: 'cn-east', zoneName: 'CN East', relayHome: 'cn-east', hasGateway: true },
  { slug: 'beijing', countryCode: 'CN', country: '中国', region: '北京市', city: '北京市', count: 14, zoneId: 'cn-north', zoneName: 'CN North', relayHome: 'cn-north', hasGateway: true },
  { slug: 'hangzhou', countryCode: 'CN', country: '中国', region: '浙江省', city: '杭州市', count: 5, zoneId: 'cn-east', zoneName: 'CN East', relayHome: 'cn-east' },
  { slug: 'shenzhen', countryCode: 'CN', country: '中国', region: '广东省', city: '深圳市', count: 18, zoneId: 'cn-south', zoneName: 'CN South', relayHome: 'cn-south', hasGateway: true },
  { slug: 'guangzhou', countryCode: 'CN', country: '中国', region: '广东省', city: '广州市', count: 12, zoneId: 'cn-south', zoneName: 'CN South', relayHome: 'cn-south' },
  { slug: 'chengdu', countryCode: 'CN', country: '中国', region: '四川省', city: '成都市', count: 10, zoneId: 'cn-west', zoneName: 'CN West', relayHome: 'cn-south', hasEntry: true },
  { slug: 'wuhan', countryCode: 'CN', country: '中国', region: '湖北省', city: '武汉市', count: 8, zoneId: 'cn-east', zoneName: 'CN East', relayHome: 'cn-east' },
  { slug: 'nanjing', countryCode: 'CN', country: '中国', region: '江苏省', city: '南京市', count: 7, zoneId: 'cn-east', zoneName: 'CN East', relayHome: 'cn-east' },
  { slug: 'suzhou', countryCode: 'CN', country: '中国', region: '江苏省', city: '苏州市', count: 6, zoneId: 'cn-east', zoneName: 'CN East', relayHome: 'cn-east' },
  { slug: 'xian', countryCode: 'CN', country: '中国', region: '陕西省', city: '西安市', count: 6, zoneId: 'cn-west', zoneName: 'CN West', relayHome: 'cn-north' },
  { slug: 'chongqing', countryCode: 'CN', country: '中国', region: '重庆市', city: '重庆市', count: 6, zoneId: 'cn-west', zoneName: 'CN West', relayHome: 'cn-south' },
  { slug: 'tianjin', countryCode: 'CN', country: '中国', region: '天津市', city: '天津市', count: 5, zoneId: 'cn-north', zoneName: 'CN North', relayHome: 'cn-north' },
  { slug: 'qingdao', countryCode: 'CN', country: '中国', region: '山东省', city: '青岛市', count: 4, zoneId: 'cn-north', zoneName: 'CN North', relayHome: 'cn-north' },
  { slug: 'xiamen', countryCode: 'CN', country: '中国', region: '福建省', city: '厦门市', count: 4, zoneId: 'cn-south', zoneName: 'CN South', relayHome: 'cn-south' },
  { slug: 'changsha', countryCode: 'CN', country: '中国', region: '湖南省', city: '长沙市', count: 4, zoneId: 'cn-south', zoneName: 'CN South', relayHome: 'cn-south' },
  { slug: 'dalian', countryCode: 'CN', country: '中国', region: '辽宁省', city: '大连市', count: 3, zoneId: 'cn-north', zoneName: 'CN North', relayHome: 'cn-north' },
  // Region-only & country-only precision samples (S7)
  { slug: 'guangdong-reg', countryCode: 'CN', country: '中国', region: '广东省', city: '', count: 4, zoneId: 'cn-south', zoneName: 'CN South', relayHome: 'cn-south', precision: 'region' },
  { slug: 'sichuan-reg', countryCode: 'CN', country: '中国', region: '四川省', city: '', count: 3, zoneId: 'cn-west', zoneName: 'CN West', relayHome: 'cn-south', precision: 'region' },
  // East & Southeast Asia
  { slug: 'hongkong', countryCode: 'HK', country: '香港', region: '', city: 'Hong Kong', count: 14, zoneId: 'ap-east', zoneName: 'AP East', relayHome: 'hk', hasGateway: true },
  { slug: 'taipei', countryCode: 'TW', country: '台湾', region: '', city: 'Taipei', count: 8, zoneId: 'ap-east', zoneName: 'AP East', relayHome: 'tw' },
  { slug: 'tokyo', countryCode: 'JP', country: 'Japan', region: 'Tokyo', city: 'Tokyo', count: 16, zoneId: 'ap-ne', zoneName: 'AP Northeast', relayHome: 'jp', hasGateway: true },
  { slug: 'osaka', countryCode: 'JP', country: 'Japan', region: 'Osaka', city: 'Osaka', count: 5, zoneId: 'ap-ne', zoneName: 'AP Northeast', relayHome: 'jp' },
  { slug: 'seoul', countryCode: 'KR', country: 'South Korea', region: 'Seoul', city: 'Seoul', count: 8, zoneId: 'ap-ne', zoneName: 'AP Northeast', relayHome: 'kr' },
  { slug: 'singapore', countryCode: 'SG', country: 'Singapore', region: '', city: 'Singapore', count: 14, zoneId: 'ap-se', zoneName: 'AP Southeast', relayHome: 'sg', hasGateway: true },
  { slug: 'mumbai', countryCode: 'IN', country: 'India', region: 'Maharashtra', city: 'Mumbai', count: 6, zoneId: 'ap-south', zoneName: 'AP South', relayHome: 'ap-south' },
  // Europe
  { slug: 'frankfurt', countryCode: 'DE', country: 'Germany', region: 'Hesse', city: 'Frankfurt', count: 16, zoneId: 'eu-central', zoneName: 'EU Central', relayHome: 'eu-central', hasGateway: true },
  { slug: 'london', countryCode: 'GB', country: 'United Kingdom', region: 'England', city: 'London', count: 11, zoneId: 'eu-west', zoneName: 'EU West', relayHome: 'eu-west', hasEntry: true },
  { slug: 'amsterdam', countryCode: 'NL', country: 'Netherlands', region: 'North Holland', city: 'Amsterdam', count: 7, zoneId: 'eu-west', zoneName: 'EU West', relayHome: 'eu-west' },
  { slug: 'paris', countryCode: 'FR', country: 'France', region: 'Ile-de-France', city: 'Paris', count: 5, zoneId: 'eu-west', zoneName: 'EU West', relayHome: 'eu-west' },
  { slug: 'stockholm', countryCode: 'SE', country: 'Sweden', region: 'Stockholm', city: 'Stockholm', count: 4, zoneId: 'eu-north', zoneName: 'EU North', relayHome: 'eu-north' },
  { slug: 'de-country', countryCode: 'DE', country: 'Germany', region: '', city: '', count: 2, zoneId: 'eu-central', zoneName: 'EU Central', relayHome: 'eu-central', precision: 'country' },
  // Americas & Oceania & Africa
  { slug: 'sanjose', countryCode: 'US', country: 'United States', region: 'California', city: 'San Jose', count: 13, zoneId: 'us-west', zoneName: 'US West', relayHome: 'us-west', hasGateway: true },
  { slug: 'seattle', countryCode: 'US', country: 'United States', region: 'Washington', city: 'Seattle', count: 6, zoneId: 'us-west', zoneName: 'US West', relayHome: 'us-west' },
  { slug: 'newyork', countryCode: 'US', country: 'United States', region: 'New York', city: 'New York', count: 10, zoneId: 'us-east', zoneName: 'US East', relayHome: 'us-east', hasGateway: true },
  { slug: 'dallas', countryCode: 'US', country: 'United States', region: 'Texas', city: 'Dallas', count: 4, zoneId: 'us-central', zoneName: 'US Central', relayHome: 'us-central' },
  { slug: 'sydney', countryCode: 'AU', country: 'Australia', region: 'NSW', city: 'Sydney', count: 5, zoneId: 'ap-se', zoneName: 'AP Southeast', relayHome: 'au' },
  { slug: 'saopaulo', countryCode: 'BR', country: 'Brazil', region: 'Sao Paulo', city: 'Sao Paulo', count: 3, zoneId: 'sa-east', zoneName: 'SA East', relayHome: 'sa-east' },
  { slug: 'johannesburg', countryCode: 'ZA', country: 'South Africa', region: 'Gauteng', city: 'Johannesburg', count: 2, zoneId: 'eu-west', zoneName: 'Africa', relayHome: 'eu-west' },
]

export interface SyntheticMeshDataset {
  nodes: GlobeNode[]
  arcs: GlobeArc[]
  center: GlobeCenter
}

/**
 * Build the ~300-device / ~3,000-link deterministic "Synthetic ×10" dataset.
 * Also supports smaller fleet (`scale = 1`, ~32 devices, ~260 links) for quick comparisons.
 */
export function buildSyntheticMesh(scale: 1 | 10 = 10): SyntheticMeshDataset {
  const rng = mulberry32(scale === 10 ? 0x5439_0010 : 0x5439_0001)
  const nodes: GlobeNode[] = []
  const osList = ['linux', 'macos', 'windows'] as const
  const testNets = ['192.0.2', '198.51.100', '203.0.113'] as const

  let idx = 1
  for (const hub of SYNTHETIC_10X_HUBS) {
    const count =
      scale === 10
        ? hub.count
        : hub.slug === 'shanghai'
          ? 6
          : hub.slug === 'beijing'
            ? 4
            : hub.slug === 'shenzhen' || hub.slug === 'tokyo' || hub.slug === 'frankfurt' || hub.slug === 'sanjose' || hub.slug === 'singapore'
              ? 3
              : hub.slug === 'hangzhou' || hub.slug === 'hongkong' || hub.slug === 'london' || hub.slug === 'newyork'
                ? 2
                : 0
    for (let i = 0; i < count; i++) {
      const r = rng()
      const presence: 'online' | 'stale' | 'offline' =
        i === 0 ? 'online' : r < 0.78 ? 'online' : r < 0.9 ? 'stale' : 'offline'
      const isGateway = Boolean(hub.hasGateway && i === 0)
      const isEntry = Boolean(hub.hasEntry && i === 0)
      const prefix = isGateway ? 'gateway' : isEntry ? 'entry' : 'device'
      const num = String(i + 1).padStart(2, '0')
      const net = testNets[idx % testNets.length]!
      const host = (idx % 240) + 10
      nodes.push({
        id: `syn-${hub.slug}-${num}`,
        agentId: `agent-${hub.slug}-${num}`,
        name: `${prefix}-${hub.slug}-${num}`,
        online: presence === 'online',
        presence,
        role: isGateway ? 'gateway' : isEntry ? 'entry' : 'device',
        isGateway,
        isEntry,
        countryCode: hub.countryCode,
        country: hub.country,
        region: hub.region || null,
        city: hub.city || null,
        relayHome: hub.relayHome,
        os: osList[idx % osList.length],
        version: '0.4.210',
        lastSeenAt: '2026-11-24T06:00:00Z',
        overlayIp: `100.64.${Math.floor(idx / 250)}.${(idx % 250) + 1}`,
        publicIp: `${net}.${host}`,
        zoneId: hub.zoneId,
        zoneName: hub.zoneName,
        zonePinned: isGateway,
        managementPath: isGateway
          ? { mode: 'direct' }
          : { mode: 'gateway', gatewayName: `gateway-${hub.slug}-01` },
      })
      idx++
    }
  }

  // Add unlocated devices (some carrying relayHome ONLY — proves S4/AC14 never uses relayHome!)
  const unlocatedCount = scale === 10 ? 6 : 2
  for (let i = 0; i < unlocatedCount; i++) {
    const num = String(i + 1).padStart(2, '0')
    nodes.push({
      id: `syn-unlocated-${num}`,
      agentId: `agent-unlocated-${num}`,
      name: `device-unlocated-${num}`,
      online: i % 3 !== 2,
      presence: i % 3 === 0 ? 'online' : i % 3 === 1 ? 'stale' : 'offline',
      role: 'device',
      relayHome: i % 2 === 0 ? 'cn-east' : 'sg',
      os: 'linux',
      version: '0.4.210',
      lastSeenAt: '2026-11-24T05:50:00Z',
      overlayIp: `100.64.250.${i + 1}`,
    })
  }

  // Build deterministic peer mesh links (~3,000 for scale 10; ~240 for scale 1)
  const targetLinks = scale === 10 ? 3000 : 240
  const arcs: GlobeArc[] = []
  const seenPairs = new Set<string>()
  const n = nodes.length

  const carrierColorPlaceholder: Record<string, string> = {
    direct: '#56B4E9',
    tunnel: '#2BB58A',
    relay: '#E69F00',
    derp: '#D98CB8',
    blocked: '#8C96A5',
  }

  const pickCarrier = (sameRegion: boolean): string => {
    const r = rng()
    if (sameRegion) {
      if (r < 0.68) return 'direct'
      if (r < 0.84) return 'tunnel'
      if (r < 0.93) return 'relay'
      if (r < 0.98) return 'derp'
      return 'blocked'
    }
    if (r < 0.44) return 'direct'
    if (r < 0.64) return 'tunnel'
    if (r < 0.84) return 'relay'
    if (r < 0.96) return 'derp'
    return 'blocked'
  }

  let attempts = 0
  while (arcs.length < targetLinks && attempts < targetLinks * 8) {
    attempts++
    const i = Math.floor(rng() * n)
    const j = Math.floor(rng() * n)
    if (i === j) continue
    const a = nodes[i]!
    const b = nodes[j]!
    const pKey = a.id < b.id ? `${a.id}:${b.id}` : `${b.id}:${a.id}`
    if (seenPairs.has(pKey)) continue
    seenPairs.add(pKey)

    const sameCountry = Boolean(a.countryCode && a.countryCode === b.countryCode)
    const c1 = pickCarrier(sameCountry)
    const asymmetric = rng() < 0.14 && c1 !== 'blocked'
    const c2 = asymmetric ? (c1 === 'direct' ? 'relay' : 'direct') : c1
    const stalled = c1 !== 'blocked' && rng() < 0.008
    const baseRtt = sameCountry ? 12 + Math.floor(rng() * 48) : 65 + Math.floor(rng() * 190)
    const rtt2 = Math.max(5, baseRtt + Math.floor((rng() - 0.5) * 24))

    arcs.push({
      key: `${a.id}-${b.id}-${c1}`,
      from: a.id,
      to: b.id,
      carrier: c1,
      color: carrierColorPlaceholder[c1] ?? '#56B4E9',
      fromColor: carrierColorPlaceholder[c1] ?? '#56B4E9',
      toColor: carrierColorPlaceholder[c2] ?? '#56B4E9',
      asymmetric,
      stalled,
      blocked: c1 === 'blocked',
      dashed: stalled || c1 === 'blocked',
      rttMs: c1 === 'blocked' ? null : baseRtt,
      reports: 2,
      ends: [
        {
          node: a.id,
          carrier: c1,
          relay: c1 === 'relay' ? 'turn/udp' : c1 === 'derp' ? 'derp/tcp' : null,
          rtt_ms: c1 === 'blocked' ? null : baseRtt,
          stalled,
        },
        {
          node: b.id,
          carrier: c2,
          relay: c2 === 'relay' ? 'turn/udp' : c2 === 'derp' ? 'derp/tcp' : null,
          rtt_ms: c2 === 'blocked' ? null : rtt2,
          stalled: false,
        },
      ],
      kind: 'peer',
    })
  }

  const center: GlobeCenter = {
    id: 'control-centre',
    name: 'centre-sg-01',
    countryCode: 'SG',
    lat: 1.35,
    lon: 103.82,
    locationLabel: 'Singapore',
  }

  return { nodes, arcs, center }
}
