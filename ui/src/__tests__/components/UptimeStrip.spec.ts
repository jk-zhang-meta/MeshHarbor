// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import UptimeStrip from '@/components/stats/UptimeStrip.vue'

const vuetify = createVuetify({ components, directives })

const T0 = 1_700_000_000
const HOUR = 3600

function mountStrip(agents: unknown[]) {
  return mount(UptimeStrip, {
    props: { agents: agents as never },
    global: { plugins: [vuetify] },
  })
}

describe('UptimeStrip', () => {
  it('renders one row per agent with a segment per interval', () => {
    const w = mountStrip([
      {
        agent_id: 'aaaaaaaaaaaa111111111111',
        name: 'alpha',
        intervals: [
          { from: T0, to: T0 + HOUR, presence: 'online' },
          { from: T0 + HOUR, to: T0 + 2 * HOUR, presence: 'offline' },
        ],
      },
      {
        agent_id: 'bbbbbbbbbbbb222222222222',
        name: 'beta',
        intervals: [{ from: T0, to: T0 + 2 * HOUR, presence: 'online' }],
      },
    ])
    expect(w.findAll('.uptime-row').length).toBe(2)
    expect(w.findAll('.uptime-seg').length).toBe(3)
    expect(w.text()).toContain('alpha')
    expect(w.text()).toContain('beta')
  })

  it('computes online percentage and sorts the healthiest agent first', () => {
    const w = mountStrip([
      {
        agent_id: 'half',
        name: 'half',
        intervals: [
          { from: T0, to: T0 + HOUR, presence: 'online' },
          { from: T0 + HOUR, to: T0 + 2 * HOUR, presence: 'offline' },
        ],
      },
      {
        agent_id: 'full',
        name: 'full',
        intervals: [{ from: T0, to: T0 + 2 * HOUR, presence: 'online' }],
      },
    ])
    const pcts = w.findAll('.uptime-pct').map((n) => n.text())
    expect(pcts).toEqual(['100%', '50%'])
    // Sorted by uptime: 'full' before 'half'.
    const labels = w.findAll('.uptime-label').map((n) => n.text())
    expect(labels).toEqual(['full', 'half'])
  })

  it('positions segments proportionally across the shared window', () => {
    const w = mountStrip([
      {
        agent_id: 'x',
        name: 'x',
        intervals: [
          { from: T0, to: T0 + HOUR, presence: 'online' },
          { from: T0 + HOUR, to: T0 + 4 * HOUR, presence: 'stale' },
        ],
      },
    ])
    const segs = w.findAll('.uptime-seg')
    expect(segs[0].attributes('style')).toContain('left: 0%')
    expect(segs[0].attributes('style')).toContain('width: 25%')
    expect(segs[1].attributes('style')).toContain('left: 25%')
    expect(segs[1].attributes('style')).toContain('width: 75%')
  })

  it('shows the empty state when nothing was recorded', () => {
    const w = mountStrip([])
    expect(w.find('.uptime-row').exists()).toBe(false)
    expect(w.text()).toContain('No presence history yet')
  })

  it('tolerates an agent with no intervals without breaking the others', () => {
    const w = mountStrip([
      { agent_id: 'empty', name: 'empty', intervals: [] },
      {
        agent_id: 'ok',
        name: 'ok',
        intervals: [{ from: T0, to: T0 + HOUR, presence: 'online' }],
      },
    ])
    expect(w.findAll('.uptime-row').length).toBe(1)
    expect(w.text()).toContain('ok')
  })

  // FR-116 D4 — named as the device list names it.
  it("names a device by its friendly name, else by the machine's", () => {
    const w = mountStrip([
      {
        agent_id: 'named',
        name: 'build-01',
        display_name: 'Build server',
        intervals: [{ from: T0, to: T0 + 2 * HOUR, presence: 'online' }],
      },
      {
        agent_id: 'unnamed',
        name: 'kiosk-03',
        display_name: null,
        intervals: [{ from: T0, to: T0 + HOUR, presence: 'online' }],
      },
    ])
    const labels = w.findAll('.uptime-label').map((l) => l.text())
    expect(labels).toEqual(['Build server', 'kiosk-03'])
    expect(w.text()).not.toContain('build-01')
  })
})

// FR-120 P1 — a period's state and times were each segment's `title`, which a
// tap never shows (136 of them on Analytics at 360 px). The bar reports the
// period under a tap, a mouse pointing, or the arrow keys, in the line below.
describe('UptimeStrip — a period read by a tap (FR-120 P1)', () => {
  const ID = 'aaaaaaaaaaaa111111111111'
  const strip = () =>
    mountStrip([
      {
        agent_id: ID,
        name: 'alpha',
        intervals: [
          { from: T0, to: T0 + HOUR, presence: 'online' },
          { from: T0 + HOUR, to: T0 + 2 * HOUR, presence: 'offline' },
        ],
      },
    ])
  const bar = (w: ReturnType<typeof strip>) => w.find(`[data-testid="uptime-bar-${ID}"]`)
  const detail = (w: ReturnType<typeof strip>) => w.find('[data-testid="uptime-detail"]').text()

  it('carries no hover-only title on a segment, and says how to read one', () => {
    const w = strip()
    expect(w.findAll('.uptime-seg').every((s) => s.attributes('title') === undefined)).toBe(true)
    expect(detail(w)).toContain('Tap a bar')
  })

  it('reads the period a tap lands on, by where it lands', async () => {
    const w = strip()
    // Under jsdom a box has no size: give the bar 200 px, then tap each half.
    ;(bar(w).element as HTMLElement).getBoundingClientRect = () =>
      ({ left: 0, top: 0, width: 200, height: 14, right: 200, bottom: 14, x: 0, y: 0, toJSON: () => ({}) }) as DOMRect
    await bar(w).trigger('click', { clientX: 150 })
    expect(detail(w)).toMatch(/^alpha · offline · /)
    await bar(w).trigger('click', { clientX: 20 })
    expect(detail(w)).toMatch(/^alpha · online · /)
    expect(w.findAll('.uptime-seg')[0].classes()).toContain('uptime-seg--shown')
  })

  it('steps through the periods with the arrow keys', async () => {
    const w = strip()
    await bar(w).trigger('keydown', { key: 'ArrowRight' })
    expect(detail(w)).toMatch(/^alpha · online · /)
    await bar(w).trigger('keydown', { key: 'ArrowRight' })
    expect(detail(w)).toMatch(/^alpha · offline · /)
    await bar(w).trigger('keydown', { key: 'ArrowRight' })
    expect(detail(w)).toMatch(/^alpha · offline · /)
    await bar(w).trigger('keydown', { key: 'ArrowLeft' })
    expect(detail(w)).toMatch(/^alpha · online · /)
  })

  it('previews under a mouse, never under a finger, and keeps what a tap picked', async () => {
    const w = strip()
    await bar(w).trigger('pointermove', { pointerType: 'touch' })
    expect(detail(w)).toContain('Tap a bar')
    await bar(w).trigger('pointermove', { pointerType: 'mouse' })
    expect(detail(w)).toMatch(/^alpha · /)
    await bar(w).trigger('pointerleave')
    expect(detail(w)).toContain('Tap a bar')
    await bar(w).trigger('keydown', { key: 'ArrowLeft' })
    await bar(w).trigger('pointerleave')
    expect(detail(w)).toMatch(/^alpha · offline · /)
  })
})
