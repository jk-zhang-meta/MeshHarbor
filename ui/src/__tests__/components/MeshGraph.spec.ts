// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import MeshGraph from '@/components/stats/MeshGraph.vue'

beforeAll(() => {
  if (!('ResizeObserver' in globalThis)) {
    ;(globalThis as Record<string, unknown>).ResizeObserver = class {
      observe() {}
      unobserve() {}
      disconnect() {}
    }
  }
})

const vuetify = createVuetify({ components, directives })

const nodes = [
  { id: 'n1', name: 'alpha', online: true },
  { id: 'n2', name: 'beta', online: true },
  { id: 'n3', name: 'gamma', online: false },
]
const edges = [
  { from: 'n1', to: 'n2', carrier: 'direct', rtt_ms: 12 },
  { from: 'n1', to: 'n3', carrier: 'derp', rtt_ms: 90, stalled: true },
  { from: 'n2', to: 'n3', carrier: 'relay', rtt_ms: 40, reports: 1 },
]

function mountGraph(props: Record<string, unknown> = {}) {
  return mount(MeshGraph, {
    props: { nodes, edges, ...props },
    global: { plugins: [vuetify] },
  })
}

describe('MeshGraph', () => {
  it('places every device on the ring and draws each carrier edge', () => {
    const w = mountGraph()
    expect(w.findAll('.mesh-node').length).toBe(3)
    // 3 chords + the ring guide is a <circle>, so count paths only.
    expect(w.findAll('path.mesh-edge').length).toBe(3)
    for (const p of w.findAll('path.mesh-edge')) {
      expect((p.attributes('d') ?? '').startsWith('M')).toBe(true)
    }
  })

  it('draws a control-plane spoke per visible device and can hide them', async () => {
    const w = mountGraph()
    expect(w.findAll('line.mesh-spoke').length).toBe(3)
    expect(w.find('circle.mesh-center').exists()).toBe(true)

    await w.setValue?.(false) // no-op guard for older utils
    const vm = w.vm as unknown as { showControlPlane: boolean }
    vm.showControlPlane = false
    await w.vm.$nextTick()
    expect(w.findAll('line.mesh-spoke').length).toBe(0)
    expect(w.find('circle.mesh-center').exists()).toBe(false)
  })

  it('hiding offline devices also drops the edges that touch them', async () => {
    const w = mountGraph()
    const vm = w.vm as unknown as { showOffline: boolean }
    vm.showOffline = false
    await w.vm.$nextTick()
    // gamma is offline: only the alpha↔beta edge survives.
    expect(w.findAll('.mesh-node').length).toBe(2)
    expect(w.findAll('path.mesh-edge').length).toBe(1)
  })

  it('carrier toggles filter edges without touching nodes', async () => {
    const w = mountGraph()
    const vm = w.vm as unknown as { shownCarriers: string[] }
    vm.shownCarriers = ['direct']
    await w.vm.$nextTick()
    expect(w.findAll('path.mesh-edge').length).toBe(1)
    expect(w.findAll('.mesh-node').length).toBe(3)
  })

  it('marks a stalled carrier as dashed', async () => {
    const w = mountGraph()
    const vm = w.vm as unknown as { shownCarriers: string[] }
    vm.shownCarriers = ['derp']
    await w.vm.$nextTick()
    const p = w.findAll('path.mesh-edge')[0]
    expect(p.attributes('stroke-dasharray')).toBeTruthy()
  })

  it('emits the node id when a device is clicked', async () => {
    const w = mountGraph()
    await w.findAll('.mesh-node')[0].trigger('click')
    expect(w.emitted('select')?.[0]).toBeTruthy()
  })

  it('shows the empty state with no devices', () => {
    const w = mountGraph({ nodes: [], edges: [] })
    expect(w.find('svg').exists()).toBe(false)
    expect(w.text()).toContain('No devices')
  })
})

// FR-120 P1 — a carrier's line (its carrier and round trip) was hover-only, on
// a 1.6 px stroke no finger can take. Each carrier gets a 14 px hit line; a tap
// pins its line in the tooltip, a tap on the graph unpins it. And the graph
// follows its box down to 200 px: a 320 px floor scrolled a phone sideways.
describe('MeshGraph — on a touch screen (FR-120 P1)', () => {
  it('gives each carrier a 14 px hit line over its drawn stroke', () => {
    const w = mountGraph()
    const hits = w.findAll('path.mesh-edge-hit')
    // Three carriers, three hit lines: counted, so an empty graph cannot pass.
    expect(hits).toHaveLength(3)
    expect(w.findAll('path.mesh-edge')).toHaveLength(3)
    expect(hits.every((h) => h.attributes('stroke-width') === '14')).toBe(true)
  })

  it('pins a carrier on a tap, keeps it with no hover, and unpins on a tap of the graph', async () => {
    const w = mountGraph()
    expect(w.find('.mesh-tooltip').exists()).toBe(false)
    await w.findAll('path.mesh-edge-hit')[0].trigger('click')
    expect(w.find('.mesh-tooltip').exists()).toBe(true)
    expect(w.findAll('path.mesh-edge')[0].attributes('stroke-width')).toBe('3')
    await w.find('svg').trigger('click')
    expect(w.find('.mesh-tooltip').exists()).toBe(false)
  })

  it("fits a phone's column: sized to its box down to 200 px", async () => {
    let report: ((entries: Array<{ contentRect: { width: number } }>) => void) | null = null
    vi.stubGlobal(
      'ResizeObserver',
      class {
        constructor(cb: typeof report) {
          report = cb
        }
        observe() {}
        unobserve() {}
        disconnect() {}
      },
    )
    try {
      const w = mountGraph()
      report!([{ contentRect: { width: 312 } }])
      await w.vm.$nextTick()
      expect(w.find('svg').attributes('width')).toBe('312')
    } finally {
      vi.unstubAllGlobals()
    }
  })
})
