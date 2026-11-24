// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// Unit tests for T9 P4 (S12 Zone Backbone Globe on MapLibre v2):
// - S12 icon dimensions & tokens (14x14 Centre diamond, 10x10 Gateway square + Ø22 halo, 10px Entry/Server)
// - Deterministic S2 WCAG-verified zone colors (+ distinct Centre zone teal accent)
// - Strict Centre vs Gateway (`serving_relay`) vs Entry (`entry_listening`) role separation
// - Honest location resolution (NEVER `relay_home`; unlocated Centre -> legend chip; country/region "≈ ")
// - FR-134 Management path lines (gateway -> centre, 2 px solid zone color, screen offset when sharing a link)
// - Backbone links (2.5 px active, 1.5 px gray dashed [2,2] disabled, R7 stalled dotted + ⚠, directional 120 px arrows)
// - Optional Devices overlay (3 px dots @ 35% opacity, grouped at true city coordinates, NO labels)
import { describe, expect, it } from 'vitest'
import type { GlobeArc, GlobeNode } from '@/components/globe/types'
import type { BackboneGatewayView, BackboneLinkView, BackboneZoneView } from '@/stores/serverTopology'
import { buildBackboneGlobeData } from '@/components/admin/zoneBackbone'
import {
  BACKBONE_ARROW_SPACING_PX,
  BACKBONE_CENTRE_DIAMOND_PX,
  BACKBONE_DEVICE_DOT_DIAMETER_PX,
  BACKBONE_DEVICE_DOT_OPACITY,
  BACKBONE_DEVICE_DOT_RADIUS_PX,
  BACKBONE_ENTRY_TRIANGLE_PX,
  BACKBONE_GATEWAY_HALO_DIAMETER_PX,
  BACKBONE_GATEWAY_HALO_OPACITY,
  BACKBONE_GATEWAY_HALO_STROKE_PX,
  BACKBONE_GATEWAY_SQUARE_PX,
  BACKBONE_LINK_DISABLED_WIDTH_PX,
  BACKBONE_LINK_OPACITY,
  BACKBONE_LINK_WIDTH_PX,
  BACKBONE_MGMT_PATH_WIDTH_PX,
  BACKBONE_SERVER_SQUARE_PX,
  buildBackboneDevicesOverlayGeoJson,
  buildBackboneLinksGeoJson,
  buildBackboneMgmtPathsGeoJson,
  buildZoneColorMap,
  CENTRE_ZONE_COLOR_DARK,
  CENTRE_ZONE_COLOR_LIGHT,
  classifyBackboneNodeKind,
  formatBackboneNodeLabel,
  isUnidirectionalBackboneArc,
  resolveBackboneNodes,
} from '../backbone'
import {
  BACKBONE_DEVICES_OVERLAY_LAYER_ID,
  BACKBONE_LINK_LAYER_IDS,
  buildGlobeStyle,
} from '../style'
import { contrastRatio, DARK_TOKENS, LIGHT_TOKENS } from '../tokens'

const sampleZones: BackboneZoneView[] = [
  {
    id: 'centre',
    name: 'Centre',
    is_centre: true,
    is_default: false,
    cross_zone_mode: 'direct_preferred',
    auto_countries: [],
    gateway_relay_ids: ['gw-centre'],
    device_count: 2,
  },
  {
    id: 'cn',
    name: 'CN',
    is_centre: false,
    is_default: false,
    cross_zone_mode: 'router_only',
    auto_countries: ['CN'],
    gateway_relay_ids: ['gw-cn'],
    device_count: 12,
  },
  {
    id: 'eu',
    name: 'EU',
    is_centre: false,
    is_default: true,
    cross_zone_mode: 'direct_preferred',
    auto_countries: ['DE'],
    gateway_relay_ids: ['gw-eu'],
    device_count: 5,
  },
  {
    id: 'us',
    name: 'US',
    is_centre: false,
    is_default: false,
    cross_zone_mode: 'direct_preferred',
    auto_countries: ['US'],
    gateway_relay_ids: ['gw-us'],
    device_count: 8,
  },
]

const sampleGateways: BackboneGatewayView[] = [
  {
    agent_id: 'gw-centre',
    name: 'centre-hub',
    online: true,
    os: 'linux',
    agent_version: '0.4.212',
    last_seen_at: '2026-11-24T08:00:00Z',
    country_code: 'HK',
    country: 'Hong Kong',
    region: null,
    city: 'Hong Kong',
    relay_home: 'hk',
    public_ip: '192.0.2.10',
    zone_ids: ['centre'],
    is_centre: true,
    serving_relay: false,
    entry_listening: false,
    entry_port: null,
    entry_device_count: 0,
  },
  {
    agent_id: 'gw-cn',
    name: 'gw-shenzhen',
    online: true,
    os: 'linux',
    agent_version: '0.4.212',
    last_seen_at: '2026-11-24T08:00:00Z',
    country_code: 'CN',
    country: 'China',
    region: 'Guangdong',
    city: 'Shenzhen',
    relay_home: 'cn-south',
    public_ip: '203.0.113.50',
    zone_ids: ['cn'],
    is_centre: false,
    serving_relay: true,
    entry_listening: true,
    entry_port: 18443,
    entry_device_count: 11,
  },
  {
    agent_id: 'gw-eu',
    name: 'gw-frankfurt',
    online: false,
    os: 'linux',
    agent_version: '0.4.212',
    last_seen_at: '2026-11-24T07:00:00Z',
    country_code: 'DE',
    country: 'Germany',
    region: null,
    city: null, // country-only -> must prefix "≈ "
    relay_home: 'eu-central',
    public_ip: '198.51.100.20',
    zone_ids: ['eu'],
    is_centre: false,
    serving_relay: true,
    entry_listening: false,
    entry_port: null,
    entry_device_count: 0,
  },
  {
    agent_id: 'gw-us',
    name: 'gw-sanjose',
    online: true,
    os: 'linux',
    agent_version: '0.4.212',
    last_seen_at: '2026-11-24T08:00:00Z',
    country_code: 'US',
    country: 'United States',
    region: 'California',
    city: 'San Jose',
    relay_home: 'us-west',
    public_ip: '198.51.100.40',
    zone_ids: ['us'],
    is_centre: false,
    serving_relay: true,
    entry_listening: true,
    entry_port: 18443,
    entry_device_count: 6,
  },
]

const sampleLinks: BackboneLinkView[] = [
  {
    from_agent_id: 'gw-centre',
    to_agent_id: 'gw-cn',
    carrier: 'direct',
    rtt_ms: 14,
    stalled: false,
    reports: 2,
    cross_zone: true,
    ends: [
      { node: 'gw-centre', carrier: 'direct', relay: null, rtt_ms: 14, stalled: false },
      { node: 'gw-cn', carrier: 'direct', relay: null, rtt_ms: 15, stalled: false },
    ],
  },
  {
    from_agent_id: 'gw-cn',
    to_agent_id: 'gw-us',
    carrier: 'relay',
    rtt_ms: 162,
    stalled: false,
    reports: 1, // unidirectional -> arrows every 120 px, oriented gw-us -> gw-cn
    cross_zone: true,
    ends: [{ node: 'gw-us', carrier: 'relay', relay: 'org_relay', rtt_ms: 162, stalled: false }],
  },
  {
    from_agent_id: 'gw-eu',
    to_agent_id: 'gw-us',
    carrier: 'derp',
    rtt_ms: 210,
    stalled: true,
    reports: 2,
    cross_zone: true,
    ends: [
      { node: 'gw-eu', carrier: 'derp', relay: null, rtt_ms: 210, stalled: true },
      { node: 'gw-us', carrier: 'derp', relay: null, rtt_ms: 215, stalled: false },
    ],
  },
]

const carrierColors = {
  direct: '#56B4E9',
  org_relay: '#38BDF8',
  relay: '#E69F00',
  derp: '#D98CB8',
  tunnel: '#2BB58A',
  blocked: '#8C96A5',
  unknown: '#94A3B8',
}

describe('globe-v2 S12 Zone Backbone — visual specs, tokens, roles, links, and overlay', () => {
  it('enforces exact S12 marker/link/overlay pixel dimensions and WCAG >= 3:1 zone & centre contrast', () => {
    expect(BACKBONE_CENTRE_DIAMOND_PX).toBe(14)
    expect(BACKBONE_GATEWAY_SQUARE_PX).toBe(10)
    expect(BACKBONE_GATEWAY_HALO_DIAMETER_PX).toBe(22)
    expect(BACKBONE_GATEWAY_HALO_STROKE_PX).toBe(1)
    expect(BACKBONE_GATEWAY_HALO_OPACITY).toBe(0.5)
    expect(BACKBONE_ENTRY_TRIANGLE_PX).toBe(10)
    expect(BACKBONE_SERVER_SQUARE_PX).toBe(10)
    expect(BACKBONE_MGMT_PATH_WIDTH_PX).toBe(2)
    expect(BACKBONE_LINK_WIDTH_PX).toBe(2.5)
    expect(BACKBONE_LINK_DISABLED_WIDTH_PX).toBe(1.5)
    expect(BACKBONE_LINK_OPACITY).toBe(0.8)
    expect(BACKBONE_ARROW_SPACING_PX).toBe(120)
    expect(BACKBONE_DEVICE_DOT_DIAMETER_PX).toBe(3)
    expect(BACKBONE_DEVICE_DOT_RADIUS_PX).toBe(1.5)
    expect(BACKBONE_DEVICE_DOT_OPACITY).toBe(0.35)

    // Centre zone teal accent meets WCAG >= 3:1 on both land and ocean in dark & light themes
    expect(contrastRatio(CENTRE_ZONE_COLOR_DARK, DARK_TOKENS.land)).toBeGreaterThanOrEqual(3.0)
    expect(contrastRatio(CENTRE_ZONE_COLOR_DARK, DARK_TOKENS.ocean)).toBeGreaterThanOrEqual(3.0)
    expect(contrastRatio(CENTRE_ZONE_COLOR_LIGHT, LIGHT_TOKENS.land)).toBeGreaterThanOrEqual(3.0)
    expect(contrastRatio(CENTRE_ZONE_COLOR_LIGHT, LIGHT_TOKENS.ocean)).toBeGreaterThanOrEqual(3.0)

    const darkMap = buildZoneColorMap(sampleZones, 'dark')
    expect(darkMap.get('centre')).toBe(CENTRE_ZONE_COLOR_DARK)
    expect(darkMap.get('cn')).toBe(DARK_TOKENS.zones[0])
    expect(darkMap.get('eu')).toBe(DARK_TOKENS.zones[1])
    expect(darkMap.get('us')).toBe(DARK_TOKENS.zones[2])

    const lightMap = buildZoneColorMap(sampleZones, 'light')
    expect(lightMap.get('centre')).toBe(CENTRE_ZONE_COLOR_LIGHT)
    expect(lightMap.get('cn')).toBe(LIGHT_TOKENS.zones[0])
    expect(lightMap.get('eu')).toBe(LIGHT_TOKENS.zones[1])
    expect(lightMap.get('us')).toBe(LIGHT_TOKENS.zones[2])
  })

  it('keeps Centre role strictly separate from Gateway and Entry roles (serving_relay: false)', () => {
    const mapped = buildBackboneGlobeData(sampleZones, sampleGateways, sampleLinks, {
      isDark: true,
      carrierColors,
    })

    const centreNode = mapped.nodes.find((n) => n.id === 'gw-centre')!
    expect(centreNode.isCentre).toBe(true)
    expect(centreNode.isGateway).toBe(false)
    expect(centreNode.isEntry).toBe(false)
    expect(centreNode.managementEntry).toBeNull()
    expect(classifyBackboneNodeKind(centreNode)).toBe('centre')

    const cnGw = mapped.nodes.find((n) => n.id === 'gw-cn')!
    expect(cnGw.isCentre).toBe(false)
    expect(cnGw.isGateway).toBe(true)
    expect(cnGw.isEntry).toBe(true)
    expect(cnGw.zoneDeviceCount).toBe(12)
    expect(cnGw.managementEntry).toEqual({ listening: true, port: 18443, deviceCount: 11 })
    expect(classifyBackboneNodeKind(cnGw)).toBe('gateway')

    const entryOnly: GlobeNode = {
      id: 'entry-1',
      name: 'entry-sg',
      online: true,
      isEntry: true,
      isGateway: false,
      isCentre: false,
    }
    expect(classifyBackboneNodeKind(entryOnly)).toBe('entry')

    const neutralServer: GlobeNode = {
      id: 'srv-1',
      name: 'srv-tokyo',
      online: true,
      role: 'server',
    }
    expect(classifyBackboneNodeKind(neutralServer)).toBe('server')
  })

  it('formats S12 gateway zone labels ("CN 区 · 12 台" / "CN · 12 devices") and prefixes "≈ " for country-only precision', () => {
    const mapped = buildBackboneGlobeData(sampleZones, sampleGateways, sampleLinks, {
      isDark: true,
      carrierColors,
    })
    const resolved = resolveBackboneNodes(mapped.nodes, sampleZones, 'dark')

    const cn = resolved.placedById.get('gw-cn')!
    expect(cn.precision).toBe('city')
    expect(formatBackboneNodeLabel(cn, 'zh-CN')).toBe('CN 区 · 12 台')
    expect(formatBackboneNodeLabel(cn, 'en')).toBe('CN · 12 devices')

    const eu = resolved.placedById.get('gw-eu')!
    expect(eu.precision).toBe('country')
    expect(formatBackboneNodeLabel(eu, 'zh-CN')).toBe('≈ EU 区 · 5 台')
    expect(formatBackboneNodeLabel(eu, 'en')).toBe('≈ EU · 5 devices')
  })

  it('keeps unlocated Centre off the globe (never relay_home) and surfaces it in unlocatedCentres for legend chip', () => {
    const unlocatedCentre: GlobeNode = {
      id: 'centre-unlocated',
      name: 'centre-private',
      online: true,
      isCentre: true,
      isGateway: false,
      isEntry: false,
      countryCode: null,
      country: null,
      region: null,
      city: null,
      relayHome: 'hk', // MUST NEVER be used for placement!
    }
    const unlocatedGw: GlobeNode = {
      id: 'gw-unlocated',
      name: 'gw-unknown',
      online: true,
      isGateway: true,
      relayHome: 'cn-south',
    }
    const resolved = resolveBackboneNodes([unlocatedCentre, unlocatedGw], sampleZones, 'dark')
    expect(resolved.placed).toHaveLength(0)
    expect(resolved.unlocatedCentres.map((n) => n.id)).toEqual(['centre-unlocated'])
    expect(resolved.unlocatedOthers.map((n) => n.id)).toEqual(['gw-unlocated'])
  })

  it('builds FR-134 management path lines (2 px solid zone color) with screen offset when sharing a live link', () => {
    const mapped = buildBackboneGlobeData(sampleZones, sampleGateways, sampleLinks, {
      isDark: true,
      carrierColors,
    })
    const resolved = resolveBackboneNodes(mapped.nodes, sampleZones, 'dark')
    const mgmt = buildBackboneMgmtPathsGeoJson(resolved.placed, mapped.arcs)

    // 3 non-centre gateways (cn, eu, us) -> 3 management paths to gw-centre
    expect(mgmt.features).toHaveLength(3)
    const cnPath = mgmt.features.find((f) => f.properties.from === 'gw-cn')!
    const euPath = mgmt.features.find((f) => f.properties.from === 'gw-eu')!

    expect(cnPath.properties.to).toBe('gw-centre')
    expect(cnPath.properties.width).toBe(2)
    expect(cnPath.properties.color).toBe(DARK_TOKENS.zones[0])
    // gw-cn <-> gw-centre ALSO has a live backbone link, so management path gets screen offset
    expect(cnPath.properties.offset).toBeGreaterThan(0)

    // gw-eu has no direct backbone link to gw-centre, so offset is 0
    expect(euPath.properties.width).toBe(2)
    expect(euPath.properties.color).toBe(DARK_TOKENS.zones[1])
    expect(euPath.properties.offset).toBe(0)
  })

  it('builds backbone links with 2.5 px active, 1.5 px disabled, R7 stalled + ⚠ badge, and 120 px directional arrows', () => {
    const mapped = buildBackboneGlobeData(sampleZones, sampleGateways, sampleLinks, {
      isDark: true,
      carrierColors,
    })
    const disabledArc: GlobeArc = {
      key: 'gw-cn:gw-eu',
      from: 'gw-cn',
      to: 'gw-eu',
      carrier: 'direct',
      color: '#56B4E9',
      enabled: false,
      kind: 'backbone',
    }
    const allArcs = [...mapped.arcs, disabledArc]
    const resolved = resolveBackboneNodes(mapped.nodes, sampleZones, 'dark')
    const gj = buildBackboneLinksGeoJson(allArcs, resolved.placedById, 'dark')

    expect(gj.lines.features).toHaveLength(4)

    const activeFeat = gj.lines.features.find((f) => f.properties.key === 'gw-centre:gw-cn')!
    expect(activeFeat.properties.state).toBe('active')
    expect(activeFeat.properties.width).toBe(2.5)
    expect(activeFeat.properties.opacity).toBe(0.8)
    expect(activeFeat.properties.directional).toBe(false)

    const uniArc = mapped.arcs.find((a) => a.key === 'gw-cn:gw-us')!
    expect(isUnidirectionalBackboneArc(uniArc)).toBe(true)
    const uniFeat = gj.lines.features.find((f) => f.properties.key === 'gw-cn:gw-us')!
    expect(uniFeat.properties.directional).toBe(true)
    // Oriented from sole reporter (`gw-us`) -> peer (`gw-cn`)
    expect(uniFeat.properties.from).toBe('gw-us')
    expect(uniFeat.properties.to).toBe('gw-cn')

    // Only unidirectional enabled links emit arrow features
    expect(gj.arrows.features).toHaveLength(1)
    expect(gj.arrows.features[0]!.properties.key).toBe('gw-cn:gw-us')
    expect(gj.arrows.features[0]!.properties.arrowIcon).toBe('mh-bb-arrow-active-dark')

    const stalledFeat = gj.lines.features.find((f) => f.properties.key === 'gw-eu:gw-us')!
    expect(stalledFeat.properties.state).toBe('stalled')
    expect(gj.badges.features.some((b) => b.properties.key === 'gw-eu:gw-us' && b.properties.badge === '⚠')).toBe(true)

    const disabledFeat = gj.lines.features.find((f) => f.properties.key === 'gw-cn:gw-eu')!
    expect(disabledFeat.properties.state).toBe('disabled')
    expect(disabledFeat.properties.width).toBe(1.5)
  })

  it('builds optional grouped Devices overlay as 3 px @ 35% opacity dots with zero labels and configures MapLibre layers', () => {
    const deviceNodes: GlobeNode[] = [
      { id: 'd1', name: 'dev-sh-1', online: true, city: 'Shanghai', countryCode: 'CN' },
      { id: 'd2', name: 'dev-sh-2', online: true, city: 'Shanghai', countryCode: 'CN' },
      { id: 'd3', name: 'dev-tyo-1', online: false, city: 'Tokyo', countryCode: 'JP' },
      { id: 'd4', name: 'dev-unknown', online: true, relayHome: 'cn-south' }, // never plotted
    ]
    const overlay = buildBackboneDevicesOverlayGeoJson(deviceNodes)
    // 2 grouped city points (Shanghai x2, Tokyo x1); unlocated d4 excluded
    expect(overlay.features).toHaveLength(2)
    const sh = overlay.features.find((f) => f.properties.count === 2)!
    expect(sh.properties.presence).toBe('online')
    expect('label' in sh.properties).toBe(false)

    // Verify MapLibre style spec carries S12 backbone layers & exact paint specs
    const style = buildGlobeStyle('dark', 'zh-CN', '/geo/mh-boundaries-v1.pmtiles', false, 'backbone')
    const ids = style.layers.map((l) => l.id)
    for (const id of BACKBONE_LINK_LAYER_IDS) {
      expect(ids).toContain(id)
    }
    const overlayLayer = style.layers.find((l) => l.id === BACKBONE_DEVICES_OVERLAY_LAYER_ID) as {
      type: string
      layout?: Record<string, unknown>
      paint?: Record<string, unknown>
    }
    expect(overlayLayer.type).toBe('circle')
    expect(overlayLayer.layout?.visibility).toBe('none') // OFF by default!
    expect(overlayLayer.paint?.['circle-radius']).toBe(1.5) // 3 px diameter
    expect(overlayLayer.paint?.['circle-opacity']).toBe(0.35)

    const arrowLayer = style.layers.find((l) => l.id === 'mh-backbone-link-arrows') as {
      layout?: Record<string, unknown>
    }
    expect(arrowLayer.layout?.['symbol-placement']).toBe('line')
    expect(arrowLayer.layout?.['symbol-spacing']).toBe(120)

    const activeLineLayer = style.layers.find((l) => l.id === 'mh-backbone-links-active') as {
      paint?: Record<string, unknown>
    }
    expect(activeLineLayer.paint?.['line-color']).toBe('#E6EDF6')

    const lightStyle = buildGlobeStyle('light', 'en', '/geo/mh-boundaries-v1.pmtiles', false, 'backbone')
    const lightActiveLine = lightStyle.layers.find((l) => l.id === 'mh-backbone-links-active') as {
      paint?: Record<string, unknown>
    }
    expect(lightActiveLine.paint?.['line-color']).toBe('#1F2937')
  })
})
