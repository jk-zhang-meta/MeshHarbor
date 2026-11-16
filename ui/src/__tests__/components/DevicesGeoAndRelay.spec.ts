// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import {
  ADMINISTRATOR,
  DEFAULT_ADMIN,
  DEFAULT_MEMBER,
  canManageAgents,
  canManageRelays,
} from '@/utils/permissions'
import { useAgentStore, type Agent } from '@/stores/agents'
import { useAuthStore } from '@/stores/auth'
import { useDeviceStore, type DeviceRow } from '@/stores/devices'
import { useTenantStore } from '@/stores/tenant'
import { usePeerRelaysStore } from '@/stores/peerRelays'
import {
  buildCnNonCnPreset,
  useNetworkZonesStore,
  type NetworkZone,
} from '@/stores/networkZones'
import { useCapabilitiesStore } from '@/stores/capabilities'
import { createMemoryHistory, createRouter } from 'vue-router'
import AgentsSection from '@/components/admin/AgentsSection.vue'
import DeviceZoneDialog from '@/components/admin/DeviceZoneDialog.vue'
import NetworkZonesSection from '@/components/admin/NetworkZonesSection.vue'
import PeerRelaysSection from '@/components/admin/PeerRelaysSection.vue'
import PeerRelayPolicyDialog from '@/components/admin/PeerRelayPolicyDialog.vue'
import en from '@/locales/en.json'
import zhCN from '@/locales/zh-CN.json'

vi.mock('@/api/client', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    upload: vi.fn(),
  },
}))

import { api } from '@/api/client'
const mockApi = api as unknown as {
  get: ReturnType<typeof vi.fn>
  put: ReturnType<typeof vi.fn>
}

const vuetify = createVuetify({ components, directives })
const TID = '66f000000000000000000001'

beforeAll(() => {
  const g = globalThis as unknown as Record<string, unknown>
  if (!('ResizeObserver' in g)) {
    g.ResizeObserver = class {
      observe() {}
      unobserve() {}
      disconnect() {}
    }
  }
  if (!('visualViewport' in g)) {
    g.visualViewport = {
      width: 1280,
      height: 800,
      offsetLeft: 0,
      offsetTop: 0,
      pageLeft: 0,
      pageTop: 0,
      scale: 1,
      addEventListener() {},
      removeEventListener() {},
    }
  }
})

let wrapper: VueWrapper | null = null
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
  document.body.innerHTML = ''
})

function makeAgent(overrides: Partial<Agent> = {}): Agent {
  return {
    id: '66f000000000000000000045',
    tenant_id: TID,
    owner_user_id: 'u1',
    name: 'siat45',
    machine_id: 'm-siat45',
    os: 'linux',
    agent_version: '0.4.166',
    status: 'online',
    presence: 'online',
    is_online: true,
    last_seen_at: '2026-11-16T04:00:00Z',
    access_policy: {
      consent_mode: 'prompt',
      allowed_role_ids: [],
      allowed_user_ids: [],
      auto_terminate_idle_minutes: null,
    },
    public_ip: '218.17.152.45',
    country_code: 'CN',
    country: '中国',
    region: '广东省',
    city: '深圳市',
    pinned_zone_id: null,
    effective_zone_id: 'cn',
    effective_zone_name: 'CN 区',
    ...overrides,
  }
}

function makeDeviceRow(overrides: Partial<DeviceRow> = {}): DeviceRow {
  return {
    kind: 'agent',
    id: '66f000000000000000000045',
    owner_user_id: 'u1',
    name: 'siat45',
    machine_id: 'm-siat45',
    os: 'linux',
    version: '0.4.166',
    status: 'online',
    presence: 'online',
    is_online: true,
    last_seen_at: '2026-11-16T04:00:00Z',
    created_at: '2026-10-01T00:00:00Z',
    public_ip: '218.17.152.45',
    country_code: 'CN',
    country: '中国',
    region: '广东省',
    city: '深圳市',
    pinned_zone_id: null,
    effective_zone_id: 'cn',
    effective_zone_name: 'CN 区',
    ...overrides,
  }
}

describe('Logical Network Zones, Per-Device Zone Assignment & Admin-Only Relay Routers', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  it('gates zone mutations & Relay management strictly on ADMINISTRATOR / owner while allowing MANAGE_AGENTS to read zones and assign devices', () => {
    expect(canManageAgents(null, false)).toBe(false)
    expect(canManageAgents(DEFAULT_MEMBER, false)).toBe(false)
    expect(canManageAgents(DEFAULT_ADMIN, false)).toBe(true)
    expect(canManageAgents(ADMINISTRATOR, false)).toBe(true)
    expect(canManageAgents(0, true)).toBe(true)

    expect(canManageRelays(null, false)).toBe(false)
    expect(canManageRelays(DEFAULT_MEMBER, false)).toBe(false)
    // DEFAULT_ADMIN holds MANAGE_AGENTS, NOT ADMINISTRATOR -> must be false!
    expect(canManageRelays(DEFAULT_ADMIN, false)).toBe(false)
    expect(canManageRelays(ADMINISTRATOR, false)).toBe(true)
    expect(canManageRelays(0, true)).toBe(true)
  })

  it('designs zones effortlessly via One-Click CN / Non-CN Preset + custom zone addition and saves via PUT /tenant/{tid}/network-zones', async () => {
    const pinia = createPinia()
    setActivePinia(pinia)
    const tenantStore = useTenantStore()
    tenantStore.myPermissions = ADMINISTRATOR
    vi.spyOn(tenantStore, 'ensureMyMembership').mockResolvedValue()

    const agentStore = useAgentStore()
    const gzRelay = makeAgent({
      id: '66f000000000000000000101',
      name: 'gz-relay',
      country_code: 'CN',
      country: '中国',
      region: '广东省',
      city: '广州市',
    })
    const hkRelay = makeAgent({
      id: '66f000000000000000000102',
      name: 'hk-relay',
      country_code: 'HK',
      country: '中国香港',
      region: '香港',
      city: '香港',
    })
    const sgRelay = makeAgent({
      id: '66f000000000000000000103',
      name: 'sg-relay',
      country_code: 'SG',
      country: '新加坡',
      region: '新加坡',
      city: '新加坡',
    })
    agentStore.agents = [gzRelay, hkRelay, sgRelay]

    const peerRelayStore = usePeerRelaysStore()
    peerRelayStore.relays = [
      { id: gzRelay.id, name: 'gz-relay', status: 'online', serving: true, static_endpoints: [] },
      { id: hkRelay.id, name: 'hk-relay', status: 'online', serving: true, static_endpoints: [] },
      { id: sgRelay.id, name: 'sg-relay', status: 'online', serving: false, static_endpoints: [] },
    ]

    mockApi.get.mockImplementation(async (url: string) => {
      if (url === `/tenant/${TID}/network-zones`) {
        return { revision: 0, zones: [] }
      }
      if (url.startsWith(`/tenant/${TID}/agent?`)) {
        return { items: agentStore.agents, total: 3 }
      }
      if (url.startsWith(`/tenant/${TID}/device?`)) {
        return { items: [], total: 0, page: 1, per_page: 25, total_pages: 1 }
      }
      return { items: [] }
    })

    mockApi.put.mockImplementation(async (_url: string, body: { zones: NetworkZone[] }) => ({
      revision: 1,
      zones: body.zones,
    }))

    wrapper = mount(NetworkZonesSection, {
      props: { tenantId: TID },
      global: { plugins: [pinia, vuetify] },
      attachTo: document.body,
    })
    await flushPromises()

    expect(wrapper.find('[data-testid="zones-empty-state"]').exists()).toBe(true)

    // 1. Click One-Click Preset Button ("Preset CN & Non-CN Zones")
    await wrapper.find('[data-testid="zones-preset-cn-btn"]').trigger('click')
    await flushPromises()

    expect(wrapper.find('[data-testid="zone-card-cn"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="zone-card-non-cn"]').exists()).toBe(true)

    // 2. Add a custom zone ("SIAT Lab" -> auto-suggests slug "siat-lab")
    await wrapper.find('[data-testid="zones-add-btn"]').trigger('click')
    await flushPromises()

    const nameInput2 = wrapper.find('[data-testid="zone-name-input-2"] input')
    await nameInput2.setValue('SIAT Lab')
    await flushPromises()

    const idInput2 = wrapper.find('[data-testid="zone-id-input-2"] input')
    expect((idInput2.element as HTMLInputElement).value).toBe('siat-lab')

    // 3. Save all zones in a single PUT /tenant/{tid}/network-zones call
    await wrapper.find('[data-testid="zones-save-btn"]').trigger('click')
    await flushPromises()

    expect(mockApi.put).toHaveBeenCalledWith(`/tenant/${TID}/network-zones`, {
      zones: [
        {
          id: 'cn',
          name: 'CN Zone',
          auto_countries: ['CN'],
          is_default: false,
          gateway_relay_ids: [gzRelay.id],
          cross_zone_mode: 'router_only',
        },
        {
          id: 'non-cn',
          name: 'Non-CN Zone',
          auto_countries: [],
          is_default: true,
          gateway_relay_ids: [hkRelay.id, sgRelay.id],
          cross_zone_mode: 'router_only',
        },
        {
          id: 'siat-lab',
          name: 'SIAT Lab',
          auto_countries: [],
          is_default: false,
          gateway_relay_ids: [],
          cross_zone_mode: 'router_only',
        },
      ],
    })

    const zonesStore = useNetworkZonesStore()
    expect(zonesStore.revision).toBe(1)
    expect(zonesStore.zones).toHaveLength(3)

    // 4. Toggling Default fallback on SIAT Lab (idx 2) automatically clears non-cn (idx 1)
    const defaultToggle2 = wrapper.find('[data-testid="zone-default-toggle-2"] input')
    await defaultToggle2.setValue(true)
    await flushPromises()
    await wrapper.find('[data-testid="zones-save-btn"]').trigger('click')
    await flushPromises()

    const secondPut = mockApi.put.mock.calls[1]![1] as { zones: NetworkZone[] }
    expect(secondPut.zones.map((z) => ({ id: z.id, is_default: z.is_default }))).toEqual([
      { id: 'cn', is_default: false },
      { id: 'non-cn', is_default: false },
      { id: 'siat-lab', is_default: true },
    ])

    // 5. Fallback relay name matching when GeoIP country_code is not yet observed
    const fallbackPreset = buildCnNonCnPreset(
      [
        { id: 'r-gz', name: 'gz-edge-01' },
        { id: 'r-tokyo', name: 'tokyo-relay' },
      ],
      new Map(),
    )
    expect(fallbackPreset[0]!.gateway_relay_ids).toEqual(['r-gz'])
    expect(fallbackPreset[1]!.gateway_relay_ids).toEqual(['r-tokyo'])
  })

  it('hides NetworkZonesSection completely from non-ADMINISTRATOR users and blocks non-admin zone mutations', async () => {
    const pinia = createPinia()
    setActivePinia(pinia)
    const tenantStore = useTenantStore()
    tenantStore.myPermissions = DEFAULT_ADMIN // MANAGE_AGENTS without ADMINISTRATOR
    vi.spyOn(tenantStore, 'ensureMyMembership').mockResolvedValue()

    wrapper = mount(NetworkZonesSection, {
      props: { tenantId: TID },
      global: { plugins: [pinia, vuetify] },
    })
    await flushPromises()

    expect(wrapper.find('[data-testid="network-zones-section"]').exists()).toBe(false)
    expect(mockApi.get).not.toHaveBeenCalled()

    const zonesStore = useNetworkZonesStore()
    await expect(zonesStore.saveZones(TID, [])).rejects.toThrow(/Administrator/)
    expect(mockApi.put).not.toHaveBeenCalled()
  })

  it('saves per-device Zone Assignment (Pinned & Auto) via PUT /tenant/{tid}/agent/{id}/zone-assignment and patches both stores', async () => {
    const pinia = createPinia()
    setActivePinia(pinia)
    const tenantStore = useTenantStore()
    tenantStore.myPermissions = DEFAULT_ADMIN // MANAGE_AGENTS is sufficient
    vi.spyOn(tenantStore, 'ensureMyMembership').mockResolvedValue()

    const agentStore = useAgentStore()
    const deviceStore = useDeviceStore()
    const agent = makeAgent()
    const row = makeDeviceRow()
    agentStore.agents = [agent]
    deviceStore.items = [row]

    mockApi.get.mockResolvedValue({
      revision: 1,
      zones: [
        {
          id: 'cn',
          name: 'CN 区',
          auto_countries: ['CN'],
          is_default: false,
          gateway_relay_ids: [],
          cross_zone_mode: 'router_only',
        },
        {
          id: 'non-cn',
          name: '非 CN 区',
          auto_countries: [],
          is_default: true,
          gateway_relay_ids: [],
          cross_zone_mode: 'router_only',
        },
      ],
    })
    mockApi.put.mockResolvedValueOnce({
      agent_id: agent.id,
      pinned_zone_id: 'cn',
      effective_zone_id: 'cn',
      effective_zone_name: 'CN 区',
    })

    wrapper = mount(DeviceZoneDialog, {
      props: {
        modelValue: true,
        tenantId: TID,
        agent,
        row,
      },
      global: { plugins: [pinia, vuetify] },
      attachTo: document.body,
    })
    await flushPromises()

    const locBox = document.body.querySelector('[data-testid="zone-dialog-detected-location"]')
    expect(locBox?.textContent).toContain('CN')
    expect(locBox?.textContent).toContain('中国 · 广东省 · 深圳市')
    expect(locBox?.textContent).toContain('218.17.152.45')

    const pinCard = document.body.querySelector('[data-testid="zone-opt-pinned"]') as HTMLElement
    pinCard.click()
    await flushPromises()

    const saveBtn = document.body.querySelector(
      '[data-testid="zone-assignment-save"]',
    ) as HTMLButtonElement
    saveBtn.click()
    await flushPromises()

    expect(mockApi.put).toHaveBeenCalledWith(`/tenant/${TID}/agent/${agent.id}/zone-assignment`, {
      pinned_zone_id: 'cn',
    })
    expect(agentStore.agents[0]!.pinned_zone_id).toBe('cn')
    expect(agentStore.agents[0]!.effective_zone_id).toBe('cn')
    expect(agentStore.agents[0]!.effective_zone_name).toBe('CN 区')
    expect(deviceStore.items[0]!.pinned_zone_id).toBe('cn')
    expect(deviceStore.items[0]!.effective_zone_name).toBe('CN 区')

    // Re-open and switch back to Auto (pinned_zone_id: null)
    wrapper.unmount()
    document.body.innerHTML = ''
    mockApi.put.mockResolvedValueOnce({
      agent_id: agent.id,
      pinned_zone_id: null,
      effective_zone_id: 'cn',
      effective_zone_name: 'CN 区',
    })
    wrapper = mount(DeviceZoneDialog, {
      props: {
        modelValue: true,
        tenantId: TID,
        agent: agentStore.agents[0]!,
        row: deviceStore.items[0]!,
      },
      global: { plugins: [pinia, vuetify] },
      attachTo: document.body,
    })
    await flushPromises()

    const autoCard = document.body.querySelector('[data-testid="zone-opt-auto"]') as HTMLElement
    autoCard.click()
    await flushPromises()
    ;(document.body.querySelector('[data-testid="zone-assignment-save"]') as HTMLButtonElement).click()
    await flushPromises()

    expect(mockApi.put).toHaveBeenLastCalledWith(
      `/tenant/${TID}/agent/${agent.id}/zone-assignment`,
      { pinned_zone_id: null },
    )
    expect(agentStore.agents[0]!.pinned_zone_id).toBeNull()
    expect(deviceStore.items[0]!.pinned_zone_id).toBeNull()
  })

  it('hides PeerRelaysSection and sends zero /peer-relay requests for non-ADMINISTRATOR users', async () => {
    const pinia = createPinia()
    setActivePinia(pinia)
    const tenantStore = useTenantStore()
    tenantStore.myPermissions = DEFAULT_ADMIN // has MANAGE_AGENTS, NOT ADMINISTRATOR
    vi.spyOn(tenantStore, 'ensureMyMembership').mockResolvedValue()

    wrapper = mount(PeerRelaysSection, {
      props: { tenantId: TID },
      global: { plugins: [pinia, vuetify] },
    })
    await flushPromises()

    expect(wrapper.find('[data-testid="peer-relays-section"]').exists()).toBe(false)
    expect(mockApi.get).not.toHaveBeenCalled()
  })

  it('lets an ADMINISTRATOR view and update peer_relay_mode and per-device peer-relay-policy without manual relay_server_enabled copy', async () => {
    const pinia = createPinia()
    setActivePinia(pinia)
    const tenantStore = useTenantStore()
    tenantStore.myPermissions = ADMINISTRATOR
    vi.spyOn(tenantStore, 'ensureMyMembership').mockResolvedValue()

    const agentStore = useAgentStore()
    const gzRelay = makeAgent({
      id: '66f000000000000000000101',
      name: 'gz-relay',
      city: '广州市',
    })
    const hkRelay = makeAgent({
      id: '66f000000000000000000102',
      name: 'hk-relay',
      country_code: 'HK',
      country: '中国香港',
      region: '香港',
      city: '香港',
    })
    agentStore.agents = [gzRelay, hkRelay]

    mockApi.get.mockResolvedValue({
      mode: 'on',
      relays: [
        {
          id: hkRelay.id,
          name: 'hk-relay',
          status: 'online',
          serving: true,
          static_endpoints: [],
          approved_backbone_edges: [],
        },
      ],
    })
    mockApi.put.mockImplementation(async (_url: string, body: unknown) => body)

    const store = usePeerRelaysStore()
    await store.fetchSettings(TID)
    expect(mockApi.get).toHaveBeenCalledWith(`/tenant/${TID}/peer-relay`)
    expect(store.mode).toBe('on')
    expect(store.relays).toHaveLength(1)

    wrapper = mount(PeerRelayPolicyDialog, {
      props: {
        modelValue: true,
        tenantId: TID,
        agent: {
          ...gzRelay,
          peer_relay_policy: {
            serve: true,
            static_endpoints: ['120.79.10.20:3478'],
            approved_backbone_edges: [
              {
                relay_agent_id: hkRelay.id,
                endpoint: '10.99.0.2:3478',
                cross_border: true,
              },
            ],
          },
        },
      },
      global: { plugins: [pinia, vuetify] },
      attachTo: document.body,
    })
    await flushPromises()

    const infoText =
      document.body.querySelector('[data-testid="peer-relay-auto-activate-info"]')?.textContent ?? ''
    expect(infoText).toContain('automatically notifies')
    expect(infoText).not.toContain('relay_server_enabled')
    expect(JSON.stringify(en.mh.peerRelay)).not.toContain('relay_server_enabled')
    expect(JSON.stringify(zhCN.mh.peerRelay)).not.toContain('relay_server_enabled')

    const saveBtn = document.body.querySelector('[data-testid="peer-relay-save"]') as HTMLButtonElement
    saveBtn.click()
    await flushPromises()

    expect(mockApi.put).toHaveBeenCalledWith(
      `/tenant/${TID}/agent/${gzRelay.id}/peer-relay-policy`,
      {
        serve: true,
        static_endpoints: ['120.79.10.20:3478'],
        approved_backbone_edges: [
          {
            relay_agent_id: hkRelay.id,
            endpoint: '10.99.0.2:3478',
            cross_border: true,
          },
        ],
      },
    )
  })

  it('renders AgentsSection with per_page=50, Public IP & Location column, Pinned vs Auto zone badges, and Admin-only Relay badge', async () => {
    const pinia = createPinia()
    setActivePinia(pinia)
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [
        {
          path: '/tenant/:tenantId/agent/:agentId/remote',
          name: 'agent-remote',
          component: { template: '<div />' },
        },
        {
          path: '/tenant/:tenantId/tutorial',
          name: 'tutorial',
          component: { template: '<div />' },
        },
        { path: '/:pathMatch(.*)*', component: { template: '<div />' } },
      ],
    })

    const caps = useCapabilitiesStore()
    caps.modules = ['fleet', 'network', 'remote']

    const tenantStore = useTenantStore()
    tenantStore.myPermissions = ADMINISTRATOR
    vi.spyOn(tenantStore, 'ensureMyMembership').mockResolvedValue()

    const siat45 = makeAgent({
      pinned_zone_id: 'cn',
      effective_zone_id: 'cn',
      effective_zone_name: 'CN 区',
    })
    const sgRelay = makeAgent({
      id: '66f000000000000000000088',
      name: 'sg-relay',
      public_ip: '13.212.40.10',
      country_code: 'SG',
      country: '新加坡',
      region: '新加坡',
      city: '新加坡',
      pinned_zone_id: null,
      effective_zone_id: 'non-cn',
      effective_zone_name: '非 CN 区',
    })

    mockApi.get.mockImplementation(async (url: string) => {
      if (url.startsWith(`/tenant/${TID}/device?`)) {
        return {
          items: [
            makeDeviceRow({
              pinned_zone_id: 'cn',
              effective_zone_id: 'cn',
              effective_zone_name: 'CN 区',
            }),
            makeDeviceRow({
              id: sgRelay.id,
              name: 'sg-relay',
              public_ip: '13.212.40.10',
              country_code: 'SG',
              country: '新加坡',
              region: '新加坡',
              city: '新加坡',
              pinned_zone_id: null,
              effective_zone_id: 'non-cn',
              effective_zone_name: '非 CN 区',
            }),
          ],
          total: 2,
          page: 1,
          per_page: 50,
          total_pages: 1,
        }
      }
      if (url.startsWith(`/tenant/${TID}/agent?`)) {
        return { items: [siat45, sgRelay], total: 2 }
      }
      if (url === `/tenant/${TID}/peer-relay`) {
        return {
          mode: 'on',
          relays: [
            {
              id: sgRelay.id,
              name: 'sg-relay',
              status: 'online',
              serving: true,
              static_endpoints: [],
            },
          ],
        }
      }
      if (url === `/tenant/${TID}/network-zones`) {
        return {
          revision: 1,
          zones: [
            {
              id: 'cn',
              name: 'CN 区',
              auto_countries: ['CN'],
              is_default: false,
              gateway_relay_ids: [],
              cross_zone_mode: 'router_only',
            },
            {
              id: 'non-cn',
              name: '非 CN 区',
              auto_countries: [],
              is_default: true,
              gateway_relay_ids: [sgRelay.id],
              cross_zone_mode: 'router_only',
            },
          ],
        }
      }
      return { items: [] }
    })

    wrapper = mount(AgentsSection, {
      props: { tenantId: TID },
      global: { plugins: [pinia, vuetify, router] },
      attachTo: document.body,
    })
    await flushPromises()

    // Default page size is 50 so 22+ devices fit on page 1
    const deviceCalls = mockApi.get.mock.calls
      .map((c) => String(c[0]))
      .filter((u) => u.startsWith(`/tenant/${TID}/device?`))
    expect(deviceCalls.some((u) => u.includes('per_page=50'))).toBe(true)

    const locCells = wrapper.findAll('[data-testid="device-location-cell"]')
    expect(locCells.length).toBeGreaterThanOrEqual(2)
    expect(locCells[0]!.text()).toContain('CN')
    expect(locCells[0]!.text()).toContain('中国 · 广东省 · 深圳市')
    expect(locCells[0]!.text()).toContain('218.17.152.45')
    expect(locCells[1]!.text()).toContain('SG')
    expect(locCells[1]!.text()).toContain('新加坡')
    expect(locCells[1]!.text()).not.toContain('新加坡 · 新加坡')

    const zoneChips = wrapper.findAll('[data-testid="device-zone-chip"]')
    expect(zoneChips).toHaveLength(2)
    expect(zoneChips[0]!.text()).toBe('CN 区')
    expect(zoneChips[0]!.attributes('data-zone-pinned')).toBe('true')
    expect(zoneChips[1]!.text()).toBe('非 CN 区')
    expect(zoneChips[1]!.attributes('data-zone-pinned')).toBe('false')

    const relayChips = wrapper.findAll('[data-testid="device-relay-chip"]')
    expect(relayChips).toHaveLength(1)
    expect(relayChips[0]!.text()).toBe('Relay · active')

    // Flip caller to non-ADMINISTRATOR (DEFAULT_ADMIN) -> Relay badge disappears immediately while zone chips stay
    tenantStore.myPermissions = DEFAULT_ADMIN
    await flushPromises()
    expect(wrapper.findAll('[data-testid="device-relay-chip"]')).toHaveLength(0)
    expect(wrapper.findAll('[data-testid="device-zone-chip"]')).toHaveLength(2)
  })

  it('lets an ordinary device owner (DEFAULT_MEMBER without MANAGE_AGENTS) fetch zones and open Zone Assignment ONLY on their own device while hiding NetworkZonesSection', async () => {
    const pinia = createPinia()
    setActivePinia(pinia)
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [
        {
          path: '/tenant/:tenantId/agent/:agentId/remote',
          name: 'agent-remote',
          component: { template: '<div />' },
        },
        {
          path: '/tenant/:tenantId/tutorial',
          name: 'tutorial',
          component: { template: '<div />' },
        },
        { path: '/:pathMatch(.*)*', component: { template: '<div />' } },
      ],
    })

    const caps = useCapabilitiesStore()
    caps.modules = ['fleet', 'network', 'remote']

    const authStore = useAuthStore()
    authStore.user = {
      id: 'u-owner',
      email: 'owner@example.com',
      username: 'owner',
      display_name: 'Device Owner',
    }

    const tenantStore = useTenantStore()
    tenantStore.myPermissions = DEFAULT_MEMBER // NO MANAGE_AGENTS, NO ADMINISTRATOR!
    tenantStore.isOwner = false
    vi.spyOn(tenantStore, 'ensureMyMembership').mockResolvedValue()

    // 1. NetworkZonesSection remains completely hidden for DEFAULT_MEMBER.
    const secWrapper = mount(NetworkZonesSection, {
      props: { tenantId: TID },
      global: { plugins: [pinia, vuetify] },
    })
    await flushPromises()
    expect(secWrapper.find('[data-testid="network-zones-section"]').exists()).toBe(false)
    secWrapper.unmount()

    const ownAgent = makeAgent({
      id: '66f000000000000000000091',
      owner_user_id: 'u-owner',
      name: 'my-workstation',
      effective_zone_id: 'cn',
      effective_zone_name: 'CN 区',
    })
    const otherAgent = makeAgent({
      id: '66f000000000000000000092',
      owner_user_id: 'u-colleague',
      name: 'colleague-box',
      effective_zone_id: 'non-cn',
      effective_zone_name: '非 CN 区',
    })

    mockApi.get.mockImplementation(async (url: string) => {
      if (url === `/tenant/${TID}/network-zones`) {
        return {
          revision: 2,
          zones: [
            {
              id: 'cn',
              name: 'CN 区',
              auto_countries: ['CN'],
              is_default: false,
              gateway_relay_ids: [],
              cross_zone_mode: 'router_only',
            },
            {
              id: 'non-cn',
              name: '非 CN 区',
              auto_countries: [],
              is_default: true,
              gateway_relay_ids: [],
              cross_zone_mode: 'router_only',
            },
          ],
        }
      }
      if (url.startsWith(`/tenant/${TID}/device?`)) {
        return {
          items: [
            makeDeviceRow({
              id: ownAgent.id,
              owner_user_id: 'u-owner',
              name: 'my-workstation',
              effective_zone_id: 'cn',
              effective_zone_name: 'CN 区',
            }),
            makeDeviceRow({
              id: otherAgent.id,
              owner_user_id: 'u-colleague',
              name: 'colleague-box',
              effective_zone_id: 'non-cn',
              effective_zone_name: '非 CN 区',
            }),
          ],
          total: 2,
          page: 1,
          per_page: 50,
          total_pages: 1,
        }
      }
      if (url.startsWith(`/tenant/${TID}/agent?`)) {
        return { items: [ownAgent, otherAgent], total: 2 }
      }
      return { items: [] }
    })

    // 2. networkZonesStore.fetchZones succeeds for DEFAULT_MEMBER!
    const zonesStore = useNetworkZonesStore()
    const loaded = await zonesStore.fetchZones(TID)
    expect(loaded?.revision).toBe(2)
    expect(zonesStore.zones.map((z) => z.id)).toEqual(['cn', 'non-cn'])

    // 3. Mount AgentsSection: own row's action menu shows `menu-zone-assignment` and opens DeviceZoneDialog;
    //    colleague's row hides `menu-zone-assignment`!
    wrapper = mount(AgentsSection, {
      props: { tenantId: TID },
      global: { plugins: [pinia, vuetify, router] },
      attachTo: document.body,
    })
    await flushPromises()

    const menuButtons = wrapper.findAll('button[aria-label^="Actions for "]')
    expect(menuButtons).toHaveLength(2)

    // Colleague's device menu -> NO menu-zone-assignment!
    const colleagueBtn = menuButtons.find((b) =>
      b.attributes('aria-label')?.includes('colleague-box'),
    )!
    await colleagueBtn.trigger('click')
    await flushPromises()
    expect(document.body.querySelector('[data-testid="menu-zone-assignment"]')).toBeNull()

    // Close menu and open own device's menu -> HAS menu-zone-assignment and opens dialog with selectable zones!
    await colleagueBtn.trigger('click')
    await flushPromises()
    const ownBtn = menuButtons.find((b) =>
      b.attributes('aria-label')?.includes('my-workstation'),
    )!
    await ownBtn.trigger('click')
    await flushPromises()
    const zoneMenuItem = document.body.querySelector(
      '[data-testid="menu-zone-assignment"]',
    ) as HTMLElement | null
    expect(zoneMenuItem).not.toBeNull()
    zoneMenuItem!.click()
    await flushPromises()

    expect(document.body.querySelector('[data-testid="zone-opt-pinned"]')).not.toBeNull()
    expect(document.body.querySelector('[data-testid="zone-pinned-select"]')).not.toBeNull()
  })

  it('accepts server-valid zone slugs containing underscores and repeated/trailing hyphens (e.g. site_a)', async () => {
    const pinia = createPinia()
    setActivePinia(pinia)
    const tenantStore = useTenantStore()
    tenantStore.myPermissions = ADMINISTRATOR
    vi.spyOn(tenantStore, 'ensureMyMembership').mockResolvedValue()

    mockApi.get.mockImplementation(async (url: string) => {
      if (url === `/tenant/${TID}/network-zones`) {
        return {
          revision: 3,
          zones: [
            {
              id: 'site_a',
              name: 'Site A',
              auto_countries: ['JP'],
              is_default: true,
              gateway_relay_ids: [],
              cross_zone_mode: 'router_only',
            },
            {
              id: 'branch--1-',
              name: 'Branch 1',
              auto_countries: [],
              is_default: false,
              gateway_relay_ids: [],
              cross_zone_mode: 'router_only',
            },
          ],
        }
      }
      if (url === `/tenant/${TID}/peer-relay`) {
        return { mode: 'on', relays: [] }
      }
      return []
    })
    mockApi.put.mockImplementation(async (_url: string, body: unknown) => ({
      revision: 4,
      zones: (body as { zones: unknown[] }).zones,
    }))

    wrapper = mount(NetworkZonesSection, {
      props: { tenantId: TID },
      global: { plugins: [pinia, vuetify] },
    })
    await flushPromises()

    const nameInput = wrapper.find('[data-testid="zone-name-input-0"] input')
    expect(nameInput.exists()).toBe(true)
    await nameInput.setValue('Site A Renamed')
    await flushPromises()

    // Typing an underscore into zone-id-input-1 must also be preserved rather than stripped
    const idInput1 = wrapper.find('[data-testid="zone-id-input-1"] input')
    await idInput1.setValue('branch__1-')
    await flushPromises()
    expect((idInput1.element as HTMLInputElement).value).toBe('branch__1-')

    const saveBtn = wrapper.find('[data-testid="zones-save-btn"]')
    await saveBtn.trigger('click')
    await flushPromises()

    expect(mockApi.put).toHaveBeenCalledWith(
      `/tenant/${TID}/network-zones`,
      expect.objectContaining({
        zones: expect.arrayContaining([
          expect.objectContaining({ id: 'site_a', name: 'Site A Renamed' }),
          expect.objectContaining({ id: 'branch__1-', name: 'Branch 1' }),
        ]),
      }),
    )
  })

  it('clears previous tenant draft and blocks saving when switching to a tenant whose zone fetch fails', async () => {
    const TID_B = '66f000000000000000000099'
    const pinia = createPinia()
    setActivePinia(pinia)
    const tenantStore = useTenantStore()
    tenantStore.myPermissions = ADMINISTRATOR
    vi.spyOn(tenantStore, 'ensureMyMembership').mockResolvedValue()

    mockApi.get.mockImplementation(async (url: string) => {
      if (url === `/tenant/${TID}/network-zones`) {
        return {
          revision: 2,
          zones: [
            {
              id: 'tenant-a-only',
              name: 'Tenant A Zone',
              auto_countries: ['CN'],
              is_default: true,
              gateway_relay_ids: [],
              cross_zone_mode: 'router_only',
            },
          ],
        }
      }
      if (url === `/tenant/${TID_B}/network-zones`) {
        throw new Error('503 Service Unavailable')
      }
      if (url.endsWith('/peer-relay')) {
        return { mode: 'on', relays: [] }
      }
      return []
    })

    wrapper = mount(NetworkZonesSection, {
      props: { tenantId: TID },
      global: { plugins: [pinia, vuetify] },
    })
    await flushPromises()
    expect(wrapper.find('[data-testid="zone-card-tenant-a-only"]').exists()).toBe(true)

    // Switch to Tenant B whose GET /network-zones fails: Tenant A's zone card MUST disappear
    // and saving to Tenant B MUST be refused!
    await wrapper.setProps({ tenantId: TID_B })
    await flushPromises()

    expect(wrapper.find('[data-testid="zone-card-tenant-a-only"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="zones-error-alert"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="zones-save-btn"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="zones-add-btn"]').attributes('disabled')).toBeDefined()
    expect(wrapper.find('[data-testid="zones-preset-cn-btn"]').attributes('disabled')).toBeDefined()
    expect(mockApi.put).not.toHaveBeenCalled()

    const zonesStore = useNetworkZonesStore()
    expect(zonesStore.loadedTenantId).toBeNull()
    expect(zonesStore.zones).toEqual([])
    await expect(zonesStore.saveZones(TID_B, [])).rejects.toThrow(/failed to load/i)
    expect(mockApi.put).not.toHaveBeenCalled()
  })

  it('discards delayed obsolete saveZones completion after switching tenants so Tenant A draft cannot overwrite Tenant B', async () => {
    const TID_B = '66f000000000000000000099'
    const pinia = createPinia()
    setActivePinia(pinia)
    const tenantStore = useTenantStore()
    tenantStore.myPermissions = ADMINISTRATOR
    vi.spyOn(tenantStore, 'ensureMyMembership').mockResolvedValue()

    mockApi.get.mockImplementation(async (url: string) => {
      if (url === `/tenant/${TID}/network-zones`) {
        return {
          revision: 1,
          zones: [
            {
              id: 'zone-a',
              name: 'Zone A',
              auto_countries: ['CN'],
              is_default: true,
              gateway_relay_ids: [],
              cross_zone_mode: 'router_only',
            },
          ],
        }
      }
      if (url === `/tenant/${TID_B}/network-zones`) {
        return {
          revision: 5,
          zones: [
            {
              id: 'zone-b',
              name: 'Zone B',
              auto_countries: ['US'],
              is_default: true,
              gateway_relay_ids: [],
              cross_zone_mode: 'router_only',
            },
          ],
        }
      }
      if (url.endsWith('/peer-relay')) {
        return { mode: 'on', relays: [] }
      }
      return []
    })

    let resolvePutA!: (v: unknown) => void
    mockApi.put.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolvePutA = resolve
        }),
    )

    wrapper = mount(NetworkZonesSection, {
      props: { tenantId: TID },
      global: { plugins: [pinia, vuetify] },
    })
    await flushPromises()
    expect(wrapper.find('[data-testid="zone-card-zone-a"]').exists()).toBe(true)

    // Start saving Tenant A, then switch to Tenant B and finish loading Tenant B BEFORE Tenant A's PUT resolves!
    const nameInputA = wrapper.find('[data-testid="zone-name-input-0"] input')
    await nameInputA.setValue('Zone A Edited')
    await flushPromises()
    await wrapper.find('[data-testid="zones-save-btn"]').trigger('click')
    await flushPromises()
    expect(mockApi.put).toHaveBeenCalledTimes(1)

    await wrapper.setProps({ tenantId: TID_B })
    await flushPromises()
    expect(wrapper.find('[data-testid="zone-card-zone-b"]').exists()).toBe(true)

    // Now resolve the delayed Tenant A PUT: neither the shared store nor Tenant B's draft may adopt Zone A!
    resolvePutA({
      revision: 2,
      zones: [
        {
          id: 'zone-a',
          name: 'Zone A Edited',
          auto_countries: ['CN'],
          is_default: true,
          gateway_relay_ids: [],
          cross_zone_mode: 'router_only',
        },
      ],
    })
    await flushPromises()

    const zonesStore = useNetworkZonesStore()
    expect(zonesStore.loadedTenantId).toBe(TID_B)
    expect(zonesStore.zones.map((z) => z.id)).toEqual(['zone-b'])
    expect(wrapper.find('[data-testid="zone-card-zone-b"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="zone-card-zone-a"]').exists()).toBe(false)
  })

  it('disables Save and refuses updateZoneAssignment in DeviceZoneDialog when zone catalog fetch fails', async () => {
    const pinia = createPinia()
    setActivePinia(pinia)
    const tenantStore = useTenantStore()
    tenantStore.myPermissions = DEFAULT_ADMIN
    vi.spyOn(tenantStore, 'ensureMyMembership').mockResolvedValue()

    const agentStore = useAgentStore()
    const agent = makeAgent({ pinned_zone_id: 'cn', effective_zone_id: 'cn' })
    const row = makeDeviceRow({ pinned_zone_id: 'cn', effective_zone_id: 'cn' })
    agentStore.agents = [agent]

    mockApi.get.mockRejectedValue(new Error('502 Bad Gateway'))

    wrapper = mount(DeviceZoneDialog, {
      props: {
        modelValue: true,
        tenantId: TID,
        agent,
        row,
      },
      global: { plugins: [pinia, vuetify] },
      attachTo: document.body,
    })
    await flushPromises()

    // Switch to Auto mode and attempt to click Save despite failed catalog fetch:
    const autoCard = document.body.querySelector('[data-testid="zone-opt-auto"]') as HTMLElement
    autoCard.click()
    await flushPromises()

    const saveBtn = document.body.querySelector(
      '[data-testid="zone-assignment-save"]',
    ) as HTMLButtonElement
    expect(saveBtn.disabled).toBe(true)
    expect(document.body.querySelector('[data-testid="zone-dialog-error-alert"]')?.textContent).toContain(
      '502 Bad Gateway',
    )
    saveBtn.click()
    await flushPromises()

    expect(mockApi.put).not.toHaveBeenCalled()
  })

  it('preserves saved router_only policy in store and draft when a concurrent same-tenant fetchZones returns an older revision', async () => {
    const pinia = createPinia()
    setActivePinia(pinia)
    const tenantStore = useTenantStore()
    tenantStore.myPermissions = ADMINISTRATOR
    vi.spyOn(tenantStore, 'ensureMyMembership').mockResolvedValue()

    let getCount = 0
    let resolveConcurrentGet!: (v: unknown) => void
    let resolvePut!: (v: unknown) => void

    mockApi.get.mockImplementation((url: string) => {
      if (url === `/tenant/${TID}/network-zones`) {
        getCount += 1
        if (getCount === 1) {
          return Promise.resolve({
            revision: 1,
            zones: [
              {
                id: 'cn',
                name: 'CN Zone',
                auto_countries: ['CN'],
                is_default: true,
                gateway_relay_ids: [],
                cross_zone_mode: 'direct_preferred',
              },
            ],
          })
        }
        return new Promise((resolve) => {
          resolveConcurrentGet = resolve
        })
      }
      if (url.endsWith('/peer-relay')) {
        return Promise.resolve({ mode: 'on', relays: [] })
      }
      return Promise.resolve([])
    })

    mockApi.put.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolvePut = resolve
        }),
    )

    wrapper = mount(NetworkZonesSection, {
      props: { tenantId: TID },
      global: { plugins: [pinia, vuetify] },
    })
    await flushPromises()

    const zonesStore = useNetworkZonesStore()
    expect(zonesStore.revision).toBe(1)
    expect(zonesStore.zones[0]!.cross_zone_mode).toBe('direct_preferred')

    // Administrator changes mode to router_only and clicks Save:
    ;(wrapper.vm as unknown as { draftZones: Array<{ cross_zone_mode: string }> }).draftZones[0]!.cross_zone_mode =
      'router_only'
    await flushPromises()
    await wrapper.find('[data-testid="zones-save-btn"]').trigger('click')
    await flushPromises()
    expect(mockApi.put).toHaveBeenCalledTimes(1)

    // While PUT is pending, opening DeviceZoneDialog triggers a same-tenant GET that returns stale revision 1:
    const concurrentFetch = zonesStore.fetchZones(TID)
    await flushPromises()
    resolveConcurrentGet({
      revision: 1,
      zones: [
        {
          id: 'cn',
          name: 'CN Zone',
          auto_countries: ['CN'],
          is_default: true,
          gateway_relay_ids: [],
          cross_zone_mode: 'direct_preferred',
        },
      ],
    })
    await concurrentFetch
    await flushPromises()

    // Now PUT succeeds with authoritative revision 2 (router_only):
    resolvePut({
      revision: 2,
      zones: [
        {
          id: 'cn',
          name: 'CN Zone',
          auto_countries: ['CN'],
          is_default: true,
          gateway_relay_ids: [],
          cross_zone_mode: 'router_only',
        },
      ],
    })
    await flushPromises()

    expect(zonesStore.revision).toBe(2)
    expect(zonesStore.zones[0]!.cross_zone_mode).toBe('router_only')

    // Subsequent name-only edit must submit router_only, NEVER reverting to stale direct_preferred!
    mockApi.put.mockResolvedValueOnce({
      revision: 3,
      zones: [
        {
          id: 'cn',
          name: 'CN Zone Renamed',
          auto_countries: ['CN'],
          is_default: true,
          gateway_relay_ids: [],
          cross_zone_mode: 'router_only',
        },
      ],
    })
    const nameInput = wrapper.find('[data-testid="zone-name-input-0"] input')
    await nameInput.setValue('CN Zone Renamed')
    await flushPromises()
    await wrapper.find('[data-testid="zones-save-btn"]').trigger('click')
    await flushPromises()

    expect(mockApi.put).toHaveBeenLastCalledWith(`/tenant/${TID}/network-zones`, {
      zones: [
        expect.objectContaining({
          id: 'cn',
          name: 'CN Zone Renamed',
          cross_zone_mode: 'router_only',
        }),
      ],
    })
  })

  it('fences obsolete same-tenant membership/error/GET completions so loading never sticks and stale revisions never restore pre-save state', async () => {
    const pinia = createPinia()
    setActivePinia(pinia)
    const tenantStore = useTenantStore()
    tenantStore.myPermissions = ADMINISTRATOR

    // Part A: Delayed membership resolution on an older fetchZones must NEVER leave loading=true
    let membershipCall = 0
    let resolveFirstMembership!: () => void
    vi.spyOn(tenantStore, 'ensureMyMembership').mockImplementation(() => {
      membershipCall += 1
      if (membershipCall === 1) {
        return new Promise<void>((resolve) => {
          resolveFirstMembership = resolve
        })
      }
      return Promise.resolve()
    })

    mockApi.get.mockResolvedValueOnce({
      revision: 2,
      zones: [
        {
          id: 'cn',
          name: 'CN v2',
          auto_countries: ['CN'],
          is_default: true,
          gateway_relay_ids: [],
          cross_zone_mode: 'router_only',
        },
      ],
    })

    const zonesStore = useNetworkZonesStore()
    const staleFetch1 = zonesStore.fetchZones(TID)
    const newerFetch2 = zonesStore.fetchZones(TID)
    await newerFetch2
    expect(zonesStore.loading).toBe(false)
    expect(zonesStore.revision).toBe(2)

    // Now the older membership check resolves: it must return immediately without touching loading or api.get!
    resolveFirstMembership()
    await staleFetch1
    await flushPromises()
    expect(zonesStore.loading).toBe(false)
    expect(zonesStore.revision).toBe(2)
    expect(mockApi.get).toHaveBeenCalledTimes(1)

    // Part B: Delayed GET(rev 1) -> PUT(rev 3) -> later GET fails -> delayed GET(rev 1) must NOT install stale rev 1!
    let resolveDelayedRev1!: (v: unknown) => void
    mockApi.get.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolveDelayedRev1 = resolve
        }),
    )
    const delayedFetch = zonesStore.fetchZones(TID)
    await flushPromises()

    mockApi.put.mockResolvedValueOnce({
      revision: 3,
      zones: [
        {
          id: 'cn',
          name: 'CN v3 Saved',
          auto_countries: ['CN'],
          is_default: true,
          gateway_relay_ids: [],
          cross_zone_mode: 'router_only',
        },
      ],
    })
    await zonesStore.saveZones(TID, zonesStore.zones)
    expect(zonesStore.revision).toBe(3)

    // A subsequent GET fails and clears loadedTenantId:
    mockApi.get.mockRejectedValueOnce(new Error('503 Service Unavailable'))
    await zonesStore.fetchZones(TID)
    expect(zonesStore.loadedTenantId).toBeNull()
    expect(zonesStore.loading).toBe(false)

    // Now the delayed rev-1 GET resolves: neither obsolete fetchSeq nor lower revision may install rev 1!
    resolveDelayedRev1({
      revision: 1,
      zones: [
        {
          id: 'cn',
          name: 'Stale Rev 1',
          auto_countries: ['CN'],
          is_default: true,
          gateway_relay_ids: [],
          cross_zone_mode: 'direct_preferred',
        },
      ],
    })
    await delayedFetch
    await flushPromises()
    expect(zonesStore.loading).toBe(false)
    expect(zonesStore.loadedTenantId).toBeNull()
    expect(zonesStore.zones).toEqual([])
  })

  it('rejects a superseded PUT when a newer GET watermark was followed by a failed GET so draft never collapses to empty zones', async () => {
    const pinia = createPinia()
    setActivePinia(pinia)
    const tenantStore = useTenantStore()
    tenantStore.myPermissions = ADMINISTRATOR
    vi.spyOn(tenantStore, 'ensureMyMembership').mockResolvedValue()

    mockApi.get.mockImplementation((url: string) => {
      if (url === `/tenant/${TID}/network-zones`) {
        return Promise.resolve({
          revision: 1,
          zones: [
            {
              id: 'cn',
              name: 'CN v1',
              auto_countries: ['CN'],
              is_default: true,
              gateway_relay_ids: [],
              cross_zone_mode: 'router_only',
            },
          ],
        })
      }
      if (url.endsWith('/peer-relay')) {
        return Promise.resolve({ mode: 'on', relays: [] })
      }
      return Promise.resolve([])
    })

    let resolveDelayedPut!: (v: unknown) => void
    mockApi.put.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolveDelayedPut = resolve
        }),
    )

    wrapper = mount(NetworkZonesSection, {
      props: { tenantId: TID },
      global: { plugins: [pinia, vuetify] },
    })
    await flushPromises()

    const zonesStore = useNetworkZonesStore()
    expect(zonesStore.revision).toBe(1)

    // 1. Trigger PUT (will resolve later with rev 2)
    await wrapper.find('[data-testid="zones-save-btn"]').trigger('click')
    await flushPromises()
    expect(mockApi.put).toHaveBeenCalledTimes(1)

    // 2. Concurrent GET accepts newer authoritative revision 3
    mockApi.get.mockResolvedValueOnce({
      revision: 3,
      zones: [
        {
          id: 'cn',
          name: 'CN v3',
          auto_countries: ['CN'],
          is_default: true,
          gateway_relay_ids: [],
          cross_zone_mode: 'router_only',
        },
        {
          id: 'non-cn',
          name: 'Non-CN v3',
          auto_countries: [],
          is_default: false,
          gateway_relay_ids: [],
          cross_zone_mode: 'router_only',
        },
      ],
    })
    await zonesStore.fetchZones(TID)
    expect(zonesStore.revision).toBe(3)

    // 3. Another GET fails, clearing visible cache while watermark stays 3
    mockApi.get.mockRejectedValueOnce(new Error('503 Service Unavailable'))
    await zonesStore.fetchZones(TID)
    expect(zonesStore.loadedTenantId).toBeNull()

    // 4. Delayed PUT (rev 2 < watermark 3) resolves: must reject rather than adopting empty cleared cache!
    resolveDelayedPut({
      revision: 2,
      zones: [
        {
          id: 'cn',
          name: 'CN v2',
          auto_countries: ['CN'],
          is_default: true,
          gateway_relay_ids: [],
          cross_zone_mode: 'router_only',
        },
      ],
    })
    await flushPromises()

    // Draft must NOT become empty [] and Save must remain disabled against a cleared or superseded cache,
    // even after an external fetchZones restores revision 3!
    expect(wrapper.find('[data-testid="zones-error-alert"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="zones-save-btn"]').attributes('disabled')).toBeDefined()
    expect(wrapper.find('[data-testid="zone-card-cn"]').exists()).toBe(true)

    mockApi.get.mockResolvedValueOnce({
      revision: 3,
      zones: [
        {
          id: 'cn',
          name: 'CN v3',
          auto_countries: ['CN'],
          is_default: true,
          gateway_relay_ids: [],
          cross_zone_mode: 'router_only',
        },
        {
          id: 'non-cn',
          name: 'Non-CN v3',
          auto_countries: [],
          is_default: false,
          gateway_relay_ids: [],
          cross_zone_mode: 'router_only',
        },
      ],
    })
    await zonesStore.fetchZones(TID)
    await flushPromises()
    expect(zonesStore.revision).toBe(3)
    expect(zonesStore.zones).toHaveLength(2)
    expect(wrapper.find('[data-testid="zones-save-btn"]').attributes('disabled')).toBeDefined()
    await wrapper.find('[data-testid="zones-save-btn"]').trigger('click')
    await flushPromises()
    expect(mockApi.put).toHaveBeenCalledTimes(1)
  })
})
