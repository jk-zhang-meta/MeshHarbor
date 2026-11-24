// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'

vi.mock('@/components/globe-v2/MeshGlobeMap.vue', () => ({
  default: { name: 'MeshGlobeMapStub', template: '<div data-testid="globe-v2-stub" />' },
}))

import MeshGlobe from '../MeshGlobe.vue'
import MeshGraph from '@/components/stats/MeshGraph.vue'
import type { GlobeArc, GlobeNode } from '../types'
import en from '@/locales/en.json'
import zhCN from '@/locales/zh-CN.json'

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

const sampleNodes: GlobeNode[] = [
  {
    id: 'node-1',
    name: 'gateway-a',
    online: true,
    presence: 'online',
    role: 'gateway',
    isGateway: true,
    os: 'linux',
    version: '0.4.204',
    lastSeenAt: '2026-11-24T02:15:00Z',
    countryCode: 'CN',
    country: '中国',
    region: '广东省',
    city: '深圳市',
    lat: 22.54,
    lon: 114.06,
    publicIp: '192.0.2.10',
    overlayIp: '100.64.0.10',
    relayHome: 'cn-south',
    zoneId: 'cn',
    zoneName: 'CN Zone',
    zonePinned: true,
    managementPath: { mode: 'gateway', gatewayName: 'gateway-a' },
  },
  {
    id: 'node-2',
    name: 'device-b',
    online: true,
    presence: 'online',
    os: 'macos',
    version: '0.4.204',
    lat: 50.11,
    lon: 8.68,
    countryCode: 'DE',
    country: 'Germany',
    city: 'Frankfurt',
  },
]

const sampleArcs: GlobeArc[] = [
  {
    key: 'node-1-node-2-direct',
    from: 'node-1',
    to: 'node-2',
    carrier: 'direct',
    color: '#1F9D57',
    asymmetric: true,
    stalled: false,
    rttMs: 142,
    reports: 2,
    ends: [
      { node: 'node-1', carrier: 'direct', rtt_ms: 142 },
      { node: 'node-2', carrier: 'relay', relay: 'turn/udp', rtt_ms: 168, stalled: true },
    ],
    kind: 'peer',
  },
]

describe('MeshGlobe — MapLibre v2 engine & WebGL2 fallback', () => {
  it('renders the #fallback slot and emits fallback-active in environments without WebGL2', () => {
    const w = mount(MeshGlobe, {
      props: { nodes: sampleNodes, arcs: sampleArcs },
      slots: { fallback: '<div data-testid="ring-slot">2D Fallback</div>' },
      global: { plugins: [vuetify] },
    })
    expect(w.find('[data-testid="ring-slot"]').exists()).toBe(true)
    expect(w.emitted('fallback-active')?.[0]).toEqual(['webgl2-unavailable'])
    expect(w.find('[data-testid="mesh-globe-root"]').attributes('data-globe-engine')).toBe('fallback')
  })

  it('always uses MapLibre v2 when WebGL2 is available (for both devices and backbone views) and honors forceFallback', () => {
    vi.stubGlobal('WebGL2RenderingContext', class {})
    const spy = vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockImplementation(((kind: string) =>
      kind === 'webgl2'
        ? ({ getExtension: () => null } as unknown as WebGL2RenderingContext)
        : null) as typeof HTMLCanvasElement.prototype.getContext)
    try {
      const wDefault = mount(MeshGlobe, {
        props: { nodes: sampleNodes, arcs: sampleArcs },
        global: { plugins: [vuetify] },
      })
      expect(wDefault.find('[data-testid="mesh-globe-root"]').attributes('data-globe-engine')).toBe('v2')
      expect(wDefault.find('[data-testid="mesh-globe-root"]').attributes('data-globe-view')).toBe('devices')
      wDefault.unmount()

      const wBackbone = mount(MeshGlobe, {
        props: { viewMode: 'backbone', nodes: sampleNodes, arcs: sampleArcs },
        global: { plugins: [vuetify] },
      })
      expect(wBackbone.find('[data-testid="mesh-globe-root"]').attributes('data-globe-engine')).toBe('v2')
      expect(wBackbone.find('[data-testid="mesh-globe-root"]').attributes('data-globe-view')).toBe('backbone')
      wBackbone.unmount()

      const wForced = mount(MeshGlobe, {
        props: { nodes: sampleNodes, arcs: sampleArcs, forceFallback: true },
        slots: { fallback: '<div data-testid="ring-slot">2D Ring</div>' },
        global: { plugins: [vuetify] },
      })
      expect(wForced.find('[data-testid="mesh-globe-root"]').attributes('data-globe-engine')).toBe('fallback')
      expect(wForced.find('[data-testid="ring-slot"]').exists()).toBe(true)
      wForced.unmount()
    } finally {
      spy.mockRestore()
      vi.unstubAllGlobals()
    }
  })

  it('MeshGraph automatically falls back to the SVG radial ring when WebGL2 is unavailable', () => {
    const w = mount(MeshGraph, {
      props: {
        nodes: [
          { id: 'a', name: 'device-a', online: true, country_code: 'CN' },
          { id: 'b', name: 'device-b', online: false, country_code: 'DE' },
        ],
        edges: [{ from: 'a', to: 'b', carrier: 'direct', rtt_ms: 48 }],
        aclStatus: 'ACL: enforce',
      },
      global: { plugins: [vuetify] },
    })
    expect(w.find('[data-testid="mesh-ring-fallback"]').exists()).toBe(true)
    expect(w.find('svg.mesh-svg').exists()).toBe(true)
    expect(w.find('[data-testid="mesh-acl-status"]').text()).toContain('ACL: enforce')
    expect(w.text()).toContain('WebGL2 unavailable')
  })
})

describe('i18n parity for mh.mesh, mh.globeV2, and mh.backbone', () => {
  type Tree = { [k: string]: string | Tree }
  function leaves(tree: Tree, prefix = ''): string[] {
    return Object.entries(tree).flatMap(([k, v]) =>
      typeof v === 'string' ? [prefix + k] : leaves(v, `${prefix}${k}.`),
    )
  }

  it('keeps 100% key parity between en.json and zh-CN.json under mh.mesh, mh.globeV2, and mh.backbone', () => {
    const enMesh = leaves((en as unknown as { mh: { mesh: Tree } }).mh.mesh, 'mh.mesh.')
    const zhMesh = leaves((zhCN as unknown as { mh: { mesh: Tree } }).mh.mesh, 'mh.mesh.')
    expect(enMesh.length).toBeGreaterThan(30)
    expect(enMesh.filter((k) => !zhMesh.includes(k))).toEqual([])
    expect(zhMesh.filter((k) => !enMesh.includes(k))).toEqual([])

    const enV2 = leaves((en as unknown as { mh: { globeV2: Tree } }).mh.globeV2, 'mh.globeV2.')
    const zhV2 = leaves((zhCN as unknown as { mh: { globeV2: Tree } }).mh.globeV2, 'mh.globeV2.')
    expect(enV2.length).toBeGreaterThan(35)
    expect(enV2.filter((k) => !zhV2.includes(k))).toEqual([])
    expect(zhV2.filter((k) => !enV2.includes(k))).toEqual([])

    const enBb = leaves((en as unknown as { mh: { backbone: Tree } }).mh.backbone, 'mh.backbone.')
    const zhBb = leaves((zhCN as unknown as { mh: { backbone: Tree } }).mh.backbone, 'mh.backbone.')
    expect(enBb.length).toBeGreaterThan(35)
    expect(enBb.filter((k) => !zhBb.includes(k))).toEqual([])
    expect(zhBb.filter((k) => !enBb.includes(k))).toEqual([])
  })
})
