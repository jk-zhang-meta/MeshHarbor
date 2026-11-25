// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import type { GlobeArc, GlobeNode } from '@/components/globe/types'
import {
  computeSpiderfyLayout,
  effectiveSiteIp,
  SPIDERFY_MAX_SITES,
  type SpiderfySiteGroup,
} from '../spiderfy'
import { DARK_TOKENS, LIGHT_TOKENS } from '../tokens'
import SpiderfyOverlay from '../SpiderfyOverlay.vue'

function makeNode(id: string, extra: Partial<GlobeNode> = {}): GlobeNode {
  return {
    id,
    name: id,
    online: true,
    presence: 'online',
    ...extra,
  }
}

function makeArc(from: string, to: string, extra: Partial<GlobeArc> = {}): GlobeArc {
  return {
    key: `${from}-${to}-${extra.carrier ?? 'direct'}`,
    from,
    to,
    carrier: 'direct',
    color: '#56B4E9',
    rttMs: 25,
    kind: 'peer',
    ...extra,
  }
}

function boxesOverlap(a: SpiderfySiteGroup, b: SpiderfySiteGroup, minGap = 0): boolean {
  const dx = Math.abs(a.cx - b.cx)
  const dy = Math.abs(a.cy - b.cy)
  return dx < (a.width + b.width) / 2 + minGap && dy < (a.height + b.height) / 2 + minGap
}

describe('globe-v2 spiderfy — same-city egress-IP site grouping & inter-site links', () => {
  it('groups multi-site same-city devices into non-overlapping pods with physicalPublicIp precedence', () => {
    const nodes: GlobeNode[] = [
      // Site A (self LAN): 3 devices sharing physicalPublicIp 198.51.100.10 (one on VPN publicIp 203.0.113.99)
      makeNode('lab-1', { publicIp: '198.51.100.10', isSelf: true }),
      makeNode('lab-2', { publicIp: '203.0.113.99', physicalPublicIp: '198.51.100.10' }),
      makeNode('lab-3', { publicIp: '198.51.100.10', presence: 'offline', online: false }),
      // Site B: 2 devices sharing 192.0.2.20
      makeNode('office-1', { publicIp: '192.0.2.20', isGateway: true }),
      makeNode('office-2', { publicIp: '192.0.2.20' }),
    ]

    expect(effectiveSiteIp(nodes[1]!)).toBe('198.51.100.10')

    const layout = computeSpiderfyLayout(nodes, false, [])
    expect(layout.mode).toBe('sites')
    expect(layout.sites).toHaveLength(2)
    expect(layout.feet).toHaveLength(5)
    expect(layout.sites.reduce((sum, s) => sum + s.feet.length, 0)).toBe(5)

    // Self LAN sorts first as Site 1, placed left of center; Site 2 right of center
    const [site1, site2] = layout.sites
    expect(site1!.id).toBe('site-1')
    expect(site1!.labelKind).toBe('self')
    expect(site1!.siteIndex).toBe(1)
    expect(site1!.hasSelf).toBe(true)
    expect(site1!.publicIp).toBe('198.51.100.10')
    expect(site1!.count).toBe(3)
    expect(site1!.onlineCount).toBe(2)
    expect(site1!.cx).toBeLessThan(0)

    expect(site2!.id).toBe('site-2')
    expect(site2!.labelKind).toBe('site')
    expect(site2!.siteIndex).toBe(2)
    expect(site2!.hasSelf).toBe(false)
    expect(site2!.publicIp).toBe('192.0.2.20')
    expect(site2!.count).toBe(2)
    expect(site2!.cx).toBeGreaterThan(0)

    // Generous center gap (~120px) for inter-site pill & zero overlap
    const edgeGap = site2!.cx - site2!.width / 2 - (site1!.cx + site1!.width / 2)
    expect(edgeGap).toBeGreaterThanOrEqual(110)
    expect(boxesOverlap(site1!, site2!, 100)).toBe(false)

    // Deterministic across repeated calls with shuffled input
    const layoutReversed = computeSpiderfyLayout([...nodes].reverse(), false, [])
    expect(layoutReversed.sites.map((s) => ({ id: s.id, cx: s.cx, cy: s.cy }))).toEqual(
      layout.sites.map((s) => ({ id: s.id, cx: s.cx, cy: s.cy })),
    )
  })

  it('arranges 3 to 6 site pods (including an unknown-IP Other pod) with zero pairwise overlap', () => {
    for (const siteCount of [3, 4, 5, SPIDERFY_MAX_SITES]) {
      const nodes: GlobeNode[] = []
      const knownCount = siteCount === 4 ? 3 : siteCount
      for (let s = 0; s < knownCount; s++) {
        nodes.push(makeNode(`dev-${s}-a`, { publicIp: `198.51.100.${10 + s}` }))
        nodes.push(makeNode(`dev-${s}-b`, { publicIp: `198.51.100.${10 + s}` }))
      }
      if (siteCount === 4) {
        nodes.push(makeNode('dev-unknown-1'))
      }

      const layout = computeSpiderfyLayout(nodes, false, [])
      expect(layout.mode).toBe('sites')
      expect(layout.sites).toHaveLength(siteCount)
      expect(layout.feet).toHaveLength(nodes.length)

      if (siteCount === 4) {
        const other = layout.sites.find((s) => s.labelKind === 'unknown')
        expect(other).toBeDefined()
        expect(other!.id).toBe('site-unknown')
        expect(other!.publicIp).toBeNull()
      }

      // Every pair of pods must be cleanly separated with >= 40px gap
      for (let i = 0; i < layout.sites.length; i++) {
        for (let j = i + 1; j < layout.sites.length; j++) {
          expect(
            boxesOverlap(layout.sites[i]!, layout.sites[j]!, 40),
            `siteCount=${siteCount} pair (${i},${j})`,
          ).toBe(false)
        }
      }
    }
  })

  it('falls back cleanly to circle, spiral, or list for single-site, no-IP, >6 sites, or >20 devices', () => {
    // Single shared egress IP (5 nodes -> circle)
    const singleSiteFive = Array.from({ length: 5 }, (_, i) =>
      makeNode(`same-${i}`, { publicIp: '192.0.2.10' }),
    )
    const c1 = computeSpiderfyLayout(singleSiteFive, false)
    expect(c1.mode).toBe('circle')
    expect(c1.sites).toEqual([])
    expect(c1.siteLinks).toEqual([])
    expect(c1.feet).toHaveLength(5)

    // Single known IP + unknown IP members -> only 1 distinct known site -> circle
    const oneKnownPlusUnknown = [
      makeNode('known-1', { publicIp: '192.0.2.10' }),
      makeNode('known-2', { publicIp: '192.0.2.10' }),
      makeNode('noip-1'),
    ]
    expect(computeSpiderfyLayout(oneKnownPlusUnknown).mode).toBe('circle')

    // No IPs at all (12 nodes -> spiral)
    const noIpTwelve = Array.from({ length: 12 }, (_, i) => makeNode(`plain-${i}`))
    const sp = computeSpiderfyLayout(noIpTwelve, false)
    expect(sp.mode).toBe('spiral')
    expect(sp.feet).toHaveLength(12)

    // 7 distinct egress IPs (> SPIDERFY_MAX_SITES) -> falls back to circle/spiral
    const sevenSites = Array.from({ length: 7 }, (_, i) =>
      makeNode(`s-${i}`, { publicIp: `203.0.113.${i + 1}` }),
    )
    const fallbackSeven = computeSpiderfyLayout(sevenSites, false)
    expect(fallbackSeven.mode).toBe('circle')
    expect(fallbackSeven.sites).toEqual([])

    // 21 nodes across 2 sites (> SPIDERFY_SPIRAL_MAX) -> list
    const twentyOne = Array.from({ length: 21 }, (_, i) =>
      makeNode(`big-${i}`, { publicIp: i % 2 === 0 ? '192.0.2.1' : '198.51.100.1' }),
    )
    const listLayout = computeSpiderfyLayout(twentyOne, false)
    expect(listLayout.mode).toBe('list')
    expect(listLayout.feet).toEqual([])
    expect(listLayout.sites).toEqual([])
    expect(listLayout.siteLinks).toEqual([])
  })

  it('aggregates inter-site links by best carrier priority, min RTT, stalled flag, and intra-site RTTs', () => {
    const nodes: GlobeNode[] = [
      makeNode('a-1', { publicIp: '198.51.100.1', isSelf: true }),
      makeNode('a-2', { publicIp: '198.51.100.1' }),
      makeNode('b-1', { publicIp: '192.0.2.1' }),
      makeNode('b-2', { publicIp: '192.0.2.1' }),
      makeNode('c-1', { publicIp: '203.0.113.1' }),
    ]

    const arcs: GlobeArc[] = [
      // Intra-site links in Site 1: RTT 2ms and 5ms (should NOT create a self-link)
      makeArc('a-1', 'a-2', { carrier: 'direct', rttMs: 2 }),
      makeArc('a-2', 'a-1', { carrier: 'direct', rttMs: 5 }),
      // Site 1 <-> Site 2: derp (95ms), relay (52ms), direct (34ms) -> direct wins, minRtt 34
      makeArc('a-1', 'b-1', { carrier: 'derp', color: '#D98CB8', rttMs: 95 }),
      makeArc('a-2', 'b-1', { carrier: 'relay', color: '#E69F00', rttMs: 52 }),
      makeArc('a-1', 'b-2', { carrier: 'direct', color: '#56B4E9', rttMs: 34 }),
      // Site 2 <-> Site 3: blocked (null RTT) and org_relay (stalled, 68ms) -> relay wins + stalled flagged
      makeArc('b-1', 'c-1', { carrier: 'blocked', color: '#8C96A5', rttMs: null }),
      makeArc('b-2', 'c-1', { carrier: 'org_relay', color: '#E69F00', rttMs: 68, stalled: true }),
      // Control plane & out-of-cluster arcs must be ignored
      makeArc('a-1', 'c-1', { kind: 'control', carrier: 'direct', rttMs: 1 }),
      makeArc('a-1', 'remote-outside', { carrier: 'direct', rttMs: 12 }),
    ]

    const layout = computeSpiderfyLayout(nodes, false, arcs)
    expect(layout.mode).toBe('sites')

    const site1 = layout.sites.find((s) => s.id === 'site-1')!
    expect(site1.intraMinRttMs).toBe(2)
    expect(site1.intraMaxRttMs).toBe(5)

    expect(layout.siteLinks).toHaveLength(2)
    const link12 = layout.siteLinks.find((l) => l.key === 'site-1~site-2')!
    expect(link12.carrier).toBe('direct')
    expect(link12.minRttMs).toBe(34)
    expect(link12.stalled).toBe(false)
    expect(link12.count).toBe(3)
    expect(link12.color).toBe('#56B4E9')
    expect(link12.pathD).toMatch(/^M .+ Q .+/)
    expect(Math.hypot(link12.midX, link12.midY)).toBeGreaterThan(10)

    const link23 = layout.siteLinks.find((l) => l.key === 'site-2~site-3')!
    expect(link23.carrier).toBe('relay')
    expect(link23.minRttMs).toBe(68)
    expect(link23.stalled).toBe(true)
    expect(link23.count).toBe(2)
  })
})

describe('SpiderfyOverlay.vue — sites & circle rendering', () => {
  it('mounts in sites mode with pods, clickable feet, collapse anchor, and inter-site link pills (en & zh-CN)', async () => {
    const nodes: GlobeNode[] = [
      makeNode('device-a', { name: 'device-a', publicIp: '198.51.100.10', isSelf: true }),
      makeNode('device-b', { name: 'device-b', publicIp: '198.51.100.10' }),
      makeNode('device-c', { name: 'device-c', publicIp: '192.0.2.20', isGateway: true }),
      makeNode('device-d', { name: 'device-d', publicIp: '192.0.2.20', presence: 'stale', online: false }),
    ]
    const arcs: GlobeArc[] = [
      makeArc('device-a', 'device-b', { carrier: 'direct', rttMs: 3 }),
      makeArc('device-a', 'device-c', { carrier: 'direct', color: '#56B4E9', rttMs: 34 }),
    ]
    const layout = computeSpiderfyLayout(nodes, false, arcs)

    const wrapper = mount(SpiderfyOverlay, {
      props: {
        layout,
        tokens: DARK_TOKENS,
        lang: 'en',
        selectedNodeId: 'device-a',
      },
    })

    expect(wrapper.attributes('data-spiderfy-mode')).toBe('sites')
    const pod1 = wrapper.find('[data-testid="globe-spiderfy-site-site-1"]')
    const pod2 = wrapper.find('[data-testid="globe-spiderfy-site-site-2"]')
    expect(pod1.exists()).toBe(true)
    expect(pod2.exists()).toBe(true)
    expect(pod1.text()).toContain('Site 1 · This LAN (2)')
    expect(pod1.text()).toContain('3 ms')
    expect(pod1.text()).toContain('198.51.100.10')
    expect(pod2.text()).toContain('Site 2 (2)')
    expect(pod2.text()).toContain('192.0.2.20')

    // Inter-site link pill rendered with carrier & RTT
    const pill = wrapper.find('[data-testid="globe-spiderfy-site-link-site-1~site-2"]')
    expect(pill.exists()).toBe(true)
    expect(pill.text()).toContain('Direct · 34 ms')

    // Clicking a device foot emits select-node with exact GlobeNode
    const footC = wrapper.find('[data-testid="globe-spiderfy-foot-device-c"]')
    expect(footC.exists()).toBe(true)
    await footC.trigger('click')
    expect(wrapper.emitted('select-node')?.[0]?.[0]).toEqual(nodes[2])

    // Clicking center anchor emits collapse
    const anchor = wrapper.find('[data-testid="globe-spiderfy-anchor"]')
    expect(anchor.exists()).toBe(true)
    await anchor.trigger('click')
    expect(wrapper.emitted('collapse')).toHaveLength(1)

    // Switching to zh-CN + light theme updates labels live
    await wrapper.setProps({ lang: 'zh-CN', tokens: LIGHT_TOKENS })
    expect(pod1.text()).toContain('站点 1 · 本机局域网 (2)')
    expect(pod2.text()).toContain('站点 2 (2)')
    expect(pill.text()).toContain('直连 · 34 ms')
  })

  it('keeps classic circle mode rendering and events intact when no distinct site IPs exist', async () => {
    const nodes = [makeNode('node-1'), makeNode('node-2'), makeNode('node-3')]
    const layout = computeSpiderfyLayout(nodes, false)
    expect(layout.mode).toBe('circle')

    const wrapper = mount(SpiderfyOverlay, {
      props: {
        layout,
        tokens: DARK_TOKENS,
        lang: 'en',
      },
    })

    expect(wrapper.attributes('data-spiderfy-mode')).toBe('circle')
    expect(wrapper.findAll('[data-testid^="globe-spiderfy-site-"]')).toHaveLength(0)
    expect(wrapper.findAll('[data-testid^="globe-spiderfy-foot-"]')).toHaveLength(3)

    await wrapper.find('[data-testid="globe-spiderfy-foot-node-2"]').trigger('click')
    expect(wrapper.emitted('select-node')?.[0]?.[0]).toEqual(nodes[1])

    await wrapper.find('[data-testid="globe-spiderfy-anchor"]').trigger('click')
    expect(wrapper.emitted('collapse')).toHaveLength(1)
  })
})
