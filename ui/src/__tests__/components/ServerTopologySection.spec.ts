// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// The server-topology map: servers by country, an edge per link, and the two
// clicks that add one. The links table carries the same edges as rows.
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { reactive } from 'vue'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'

const store = vi.hoisted(() => ({
  state: null as unknown as {
    servers: unknown[]
    links: { a: string; b: string; enabled: boolean }[]
    loading: boolean
    error: string | null
    fetchTopology: ReturnType<typeof vi.fn>
    setLink: ReturnType<typeof vi.fn>
    removeLink: ReturnType<typeof vi.fn>
  },
}))
vi.mock('@/stores/serverTopology', () => ({ useServerTopologyStore: () => store.state }))
// The land outline is decoration; the test does not need 50 KB of it.
vi.mock('world-atlas/land-110m.json', () => ({
  default: { type: 'Topology', objects: { land: { type: 'GeometryCollection', geometries: [] } }, arcs: [] },
}))

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

function render(links: { a: string; b: string; enabled: boolean }[] = []) {
  store.state = reactive({
    servers: [
      { agent_id: 'aa', name: 'hk-1', online: true, country: 'HK', zone: 'non_mainland' },
      { agent_id: 'bb', name: 'sh-1', online: true, country: 'CN', zone: 'mainland' },
      { agent_id: 'cc', name: 'lab', online: false, country: null, zone: null },
    ],
    links,
    loading: false,
    error: null,
    fetchTopology: vi.fn(),
    setLink: vi.fn().mockResolvedValue(true),
    removeLink: vi.fn().mockResolvedValue(true),
  })
  return mount(ServerTopologySection, {
    props: { tenantId: 't1' },
    global: { plugins: [vuetify] },
  })
}

describe('ServerTopologySection', () => {
  it('draws located servers on the map and lists the rest aside', async () => {
    const w = render()
    await flushPromises()
    expect(store.state.fetchTopology).toHaveBeenCalledWith('t1')
    const labels = w.findAll('.topo-server .topo-label').map((t) => t.text())
    expect(labels.sort()).toEqual(['hk-1', 'sh-1'])
    expect(w.find('.topo-server circle.zone-mainland').exists()).toBe(true)
    expect(w.text()).toContain('No known location:')
    expect(w.text()).toContain('lab')
    expect(w.text()).toContain('No edges')
  })

  it('adds an edge with two clicks, one per server', async () => {
    const w = render()
    await flushPromises()
    const [first, second] = w.findAll('.topo-server')
    await first.trigger('click')
    expect(w.text()).toContain('selected: click a second server')
    await second.trigger('click')
    await flushPromises()
    expect(store.state.setLink).toHaveBeenCalledTimes(1)
    const [tid, a, b, enabled] = store.state.setLink.mock.calls[0]
    expect([tid, [a, b].sort(), enabled]).toEqual(['t1', ['aa', 'bb'], true])
  })

  it('reaches a server with no location through its chip', async () => {
    const w = render()
    await flushPromises()
    await w.findAll('.topo-server')[0].trigger('click')
    const chip = w.findAll('.v-chip').find((c) => c.text() === 'lab')!
    await chip.trigger('click')
    await flushPromises()
    expect(store.state.setLink).toHaveBeenCalledWith('t1', expect.any(String), 'cc', true)
  })

  it('draws an edge per link, a disabled one dashed, and never re-adds one', async () => {
    const w = render([{ a: 'aa', b: 'bb', enabled: false }])
    await flushPromises()
    expect(w.findAll('path.topo-edge')).toHaveLength(1)
    expect(w.find('path.topo-edge.off').exists()).toBe(true)
    const [first, second] = w.findAll('.topo-server')
    await first.trigger('click')
    await second.trigger('click')
    await flushPromises()
    // The pair is already linked: the second click selects that edge.
    expect(store.state.setLink).not.toHaveBeenCalled()
    expect(w.text()).toContain('Remove edge')
  })
})
