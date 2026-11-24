// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-137 + T9 P4 Zone Backbone Globe & accessible summary tables: verifies data mapping
// (S2 WCAG zone colors, centre zone accent, strict Centre vs Gateway/Entry role separation,
// gateway management entry port & connected count, gateway↔gateway links), zone filter chips,
// optional "Show devices" toggle, graceful 404 unavailable fallback, WebGL2 fallback, and refresh.
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { reactive } from 'vue'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import type {
  BackboneGatewayView,
  BackboneLinkView,
  BackboneZoneView,
} from '@/stores/serverTopology'
import {
  CENTRE_ZONE_COLOR_DARK,
  CENTRE_ZONE_COLOR_LIGHT,
  buildBackboneGlobeData,
} from '@/components/admin/zoneBackbone'

const routerPush = vi.fn()
vi.mock('vue-router', async (importOriginal) => {
  const actual = await importOriginal<typeof import('vue-router')>()
  return {
    ...actual,
    useRouter: () => ({ push: routerPush }),
  }
})

const fetchAgents = vi.fn().mockResolvedValue(undefined)
const fetchMesh = vi.fn().mockResolvedValue(undefined)
vi.mock('@/stores/agents', () => ({
  useAgentStore: () => ({ agents: [], fetchAgents }),
}))
vi.mock('@/stores/stats', () => ({
  useStatsStore: () => ({ mesh: null, fetchMesh }),
}))

const store = vi.hoisted(() => ({
  state: null as unknown as {
    revision: number
    zones: BackboneZoneView[]
    gateways: BackboneGatewayView[]
    links: BackboneLinkView[]
    loading: boolean
    error: string | null
    unavailable: boolean
    fetchBackbone: ReturnType<typeof vi.fn>
    fetchTopology: ReturnType<typeof vi.fn>
  },
}))
vi.mock('@/stores/serverTopology', () => ({ useServerTopologyStore: () => store.state }))

import ServerTopologySection from '@/components/admin/ServerTopologySection.vue'

const vuetify = createVuetify({ components, directives })

beforeAll(() => {
  const g = globalThis as unknown as Record<string, unknown>
  if (!('ResizeObserver' in g)) {
    g.ResizeObserver = class {
      observe() {}
      unobserve() {}
      disconnect() {}
    }
  }
})

afterEach(() => {
  vi.clearAllMocks()
})

const sampleZones: BackboneZoneView[] = [
  {
    id: 'centre',
    name: 'Centre Hub',
    is_centre: true,
    is_default: false,
    cross_zone_mode: 'direct_preferred',
    auto_countries: [],
    gateway_relay_ids: ['gw-centre'],
    device_count: 2,
  },
  {
    id: 'cn',
    name: 'CN Mainland',
    is_centre: false,
    is_default: false,
    cross_zone_mode: 'router_only',
    auto_countries: ['CN'],
    gateway_relay_ids: ['gw-cn'],
    device_count: 14,
  },
  {
    id: 'eu',
    name: 'EU Region',
    is_centre: false,
    is_default: true,
    cross_zone_mode: 'direct_preferred',
    auto_countries: ['DE'],
    gateway_relay_ids: ['gw-eu'],
    device_count: 5,
  },
]

const sampleGateways: BackboneGatewayView[] = [
  {
    agent_id: 'gw-centre',
    name: 'gateway-centre',
    online: true,
    os: 'linux',
    agent_version: '0.4.212',
    last_seen_at: '2026-11-24T04:00:00Z',
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
    name: 'gateway-cn',
    online: true,
    os: 'linux',
    agent_version: '0.4.212',
    last_seen_at: '2026-11-24T04:00:00Z',
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
    name: 'gateway-eu',
    online: false,
    os: 'linux',
    agent_version: '0.4.212',
    last_seen_at: '2026-11-24T03:00:00Z',
    country_code: 'DE',
    country: 'Germany',
    region: null,
    city: 'Frankfurt',
    relay_home: 'eu-central',
    public_ip: '198.51.100.20',
    zone_ids: ['eu'],
    is_centre: false,
    serving_relay: true,
    entry_listening: false,
    entry_port: null,
    entry_device_count: 0,
  },
]

const sampleLinks: BackboneLinkView[] = [
  {
    from_agent_id: 'gw-centre',
    to_agent_id: 'gw-cn',
    carrier: 'relay',
    rtt_ms: 34,
    stalled: false,
    reports: 2,
    cross_zone: true,
    ends: [
      { node: 'gw-centre', carrier: 'relay', relay: 'org_relay', rtt_ms: 38, stalled: false },
      { node: 'gw-cn', carrier: 'direct', relay: null, rtt_ms: 34, stalled: false },
    ],
  },
]

function mountSection(overrides: Partial<typeof store.state> = {}) {
  const fetchBackbone = vi.fn()
  store.state = reactive({
    revision: 7,
    zones: sampleZones,
    gateways: sampleGateways,
    links: sampleLinks,
    loading: false,
    error: null,
    unavailable: false,
    fetchBackbone,
    fetchTopology: fetchBackbone,
    ...overrides,
  })
  return mount(ServerTopologySection, {
    props: { tenantId: 't1' },
    global: {
      plugins: [vuetify],
      stubs: {
        RouterLink: true,
      },
    },
  })
}

describe('buildBackboneGlobeData — pure mapping', () => {
  const carrierColors = {
    direct: '#1F9D57',
    org_relay: '#0284C7',
    relay: '#D97706',
    derp: '#0EA5E9',
    tunnel: '#6366F1',
    blocked: '#DC2626',
    unknown: '#64748B',
  }

  it('maps zones, centre accent, entry ports, device counts, and gateway↔gateway arcs', () => {
    const light = buildBackboneGlobeData(sampleZones, sampleGateways, sampleLinks, {
      isDark: false,
      carrierColors,
    })
    const dark = buildBackboneGlobeData(sampleZones, sampleGateways, sampleLinks, {
      isDark: true,
      carrierColors,
    })

    expect(light.zoneColors.get('centre')).toBe(CENTRE_ZONE_COLOR_LIGHT)
    expect(dark.zoneColors.get('centre')).toBe(CENTRE_ZONE_COLOR_DARK)
    expect(light.zoneColors.get('cn')).not.toBe(light.zoneColors.get('eu'))

    expect(light.nodes).toHaveLength(3)
    const cnNode = light.nodes.find((n) => n.id === 'gw-cn')!
    expect(cnNode.isGateway).toBe(true)
    expect(cnNode.isEntry).toBe(true)
    expect(cnNode.isCentre).toBe(false)
    expect(cnNode.zoneNames).toEqual(['CN Mainland'])
    expect(cnNode.zoneDeviceCount).toBe(14)
    expect(cnNode.managementEntry).toEqual({ listening: true, port: 18443, deviceCount: 11 })

    const centreNode = light.nodes.find((n) => n.id === 'gw-centre')!
    expect(centreNode.isCentre).toBe(true)
    expect(centreNode.isGateway).toBe(false)
    expect(centreNode.isEntry).toBe(false)
    expect(centreNode.managementEntry).toBeNull()
    expect(centreNode.role).toBe('centre')
    expect(centreNode.color).toBe(CENTRE_ZONE_COLOR_LIGHT)

    expect(light.arcs).toHaveLength(1)
    const arc = light.arcs[0]!
    expect(arc.carrier).toBe('org_relay')
    expect(arc.asymmetric).toBe(true)
    expect(arc.fromColor).toBe('#0284C7')
    expect(arc.toColor).toBe('#1F9D57')
    expect(arc.rttMs).toBe(34)
    expect(arc.crossZone).toBe(true)
    expect(arc.directional).toBe(false)
    expect(arc.kind).toBe('backbone')

    // Filtering by zone keeps only that zone's gateways and drops cross-zone arcs.
    const filtered = buildBackboneGlobeData(sampleZones, sampleGateways, sampleLinks, {
      selectedZoneId: 'cn',
      isDark: false,
      carrierColors,
    })
    expect(filtered.nodes.map((n) => n.id)).toEqual(['gw-cn'])
    expect(filtered.arcs).toHaveLength(0)
  })
})

describe('ServerTopologySection — MapLibre v2 Zone Backbone Globe', () => {
  it('fetches backbone on mount, shows WebGL2 fallback in jsdom, renders zone chips, Show devices toggle, and tables', async () => {
    const w = mountSection()
    await flushPromises()
    expect(store.state.fetchBackbone).toHaveBeenCalledWith('t1')

    expect(w.find('[data-testid="backbone-revision"]').text()).toBe('r7')
    expect(w.find('[data-testid="mesh-globe-root"]').attributes('data-globe-view')).toBe('backbone')
    expect(w.find('[data-testid="backbone-webgl-fallback"]').exists()).toBe(true)
    expect(w.find('[data-testid="backbone-show-devices-switch"]').exists()).toBe(true)
    expect(w.find('[data-testid="backbone-zone-chip-centre"]').text()).toContain('Centre Hub')
    expect(w.find('[data-testid="backbone-zone-chip-cn"]').text()).toContain('14')

    // Centre host with serving_relay: false shows Centre badge ONLY, never Gateway/Entry!
    expect(w.find('[data-testid="backbone-gw-centre-badge-gw-centre"]').exists()).toBe(true)
    expect(w.find('[data-testid="backbone-gw-gateway-badge-gw-centre"]').exists()).toBe(false)
    expect(w.find('[data-testid="backbone-gw-entry-badge-gw-centre"]').exists()).toBe(false)

    // CN gateway with serving_relay: true & entry_listening: true shows Gateway + Entry, NOT Centre
    expect(w.find('[data-testid="backbone-gw-centre-badge-gw-cn"]').exists()).toBe(false)
    expect(w.find('[data-testid="backbone-gw-gateway-badge-gw-cn"]').exists()).toBe(true)
    expect(w.find('[data-testid="backbone-gw-entry-badge-gw-cn"]').exists()).toBe(true)

    const gwTable = w.find('[data-testid="backbone-gateways-table"]').text()
    expect(gwTable).toContain('gateway-centre')
    expect(gwTable).toContain('gateway-cn')
    expect(gwTable).toContain('18443')
    expect(gwTable).toContain('11 connected')
    expect(gwTable).toContain('gateway-eu')
    expect(gwTable).toContain('Not listening')

    const linksTable = w.find('[data-testid="backbone-links-table"]').text()
    expect(linksTable).toContain('gateway-centre')
    expect(linksTable).toContain('gateway-cn')
    expect(linksTable).toContain('relay:org_relay')
    expect(linksTable).toContain('34 ms')
    expect(linksTable).toContain('Cross-zone')

    // No legacy click-to-add/remove manual editor controls remain
    expect(w.text()).not.toContain('Remove edge')
    expect(w.text()).not.toContain('business_isolation')
  })

  it('filters gateways and links when clicking a zone chip and navigates on Open device', async () => {
    const w = mountSection()
    await flushPromises()

    await w.find('[data-testid="backbone-zone-chip-cn"]').trigger('click')
    expect(w.find('[data-testid="backbone-gw-row-gw-cn"]').exists()).toBe(true)
    expect(w.find('[data-testid="backbone-gw-row-gw-centre"]').exists()).toBe(false)
    expect(w.find('[data-testid="backbone-no-links"]').exists()).toBe(true)

    await w.find('[data-testid="backbone-open-gw-gw-cn"]').trigger('click')
    expect(routerPush).toHaveBeenCalledWith('/tenant/t1/devices')

    await w.find('[data-testid="backbone-refresh-btn"]').trigger('click')
    expect(store.state.fetchBackbone).toHaveBeenCalledTimes(2)
  })

  it('keeps Show devices overlay OFF by default and lazily loads agents/mesh when toggled ON', async () => {
    const w = mountSection()
    await flushPromises()
    expect(fetchAgents).not.toHaveBeenCalled()
    expect(fetchMesh).not.toHaveBeenCalled()

    const input = w.find('[data-testid="backbone-show-devices-switch"] input')
    expect((input.element as HTMLInputElement).checked).toBe(false)
    await input.setValue(true)
    await flushPromises()
    expect(fetchAgents).toHaveBeenCalledWith('t1')
    expect(fetchMesh).toHaveBeenCalledWith('t1')
  })

  it('shows the empty state guiding admins to Network Zones when no zones exist', async () => {
    const w = mountSection({ revision: 0, zones: [], gateways: [], links: [] })
    await flushPromises()
    expect(w.find('[data-testid="backbone-empty-state"]').exists()).toBe(true)
    expect(w.text()).toContain('No logical network zones configured yet')
    expect(w.find('[data-testid="backbone-gateways-table"]').exists()).toBe(false)
  })

  it('renders a graceful non-crashing unavailable state when backend lacks /network-zones/backbone', async () => {
    const w = mountSection({ revision: 0, zones: [], gateways: [], links: [], unavailable: true })
    await flushPromises()
    expect(w.find('[data-testid="backbone-unavailable-state"]').exists()).toBe(true)
    expect(w.find('[data-testid="backbone-empty-state"]').exists()).toBe(false)
    expect(w.find('[data-testid="backbone-gateways-table"]').exists()).toBe(false)
  })
})
