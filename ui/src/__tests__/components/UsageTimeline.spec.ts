// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-116 D4 — a person's usage names each device as the device list does: its
// friendly name (`agent_display_name`, sent beside the machine name since this
// change), else the machine's, else the id's tail. The lanes used the machine
// name alone, so a device renamed "Reception PC" came back as DESKTOP-….
import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'

import UsageTimeline from '@/components/stats/UsageTimeline.vue'
// The store's type, never one imported from the `.vue` file: the hosted image's
// build checks `.vue` imports through a shim with a default export only, so a
// named type from an SFC failed that build while local vue-tsc passed.
import type { UsageViewingWindow as ViewingWindow } from '@/stores/stats'

const vuetify = createVuetify({ components, directives })

const T0 = 1_700_000_000
const HOUR = 3600

function win(over: Partial<ViewingWindow>): ViewingWindow {
  return {
    session_id: 's1',
    agent_id: 'aaaaaaaaaaaaaaaaaaaa0001',
    tenant_id: 't1',
    started_at: T0 + HOUR,
    ended_at: T0 + 2 * HOUR,
    seconds: HOUR,
    role: 'controller',
    ...over,
  }
}

describe('UsageTimeline — device names (FR-116 D4)', () => {
  it("labels a lane by the friendly name, else the machine's, else the id's tail", async () => {
    const w = mount(UsageTimeline, {
      props: {
        from: T0,
        to: T0 + 4 * HOUR,
        windows: [
          win({ agent_id: 'aaaaaaaaaaaaaaaaaaaa0001', agent_name: 'build-01', agent_display_name: 'Build server', seconds: 3 * HOUR }),
          win({ session_id: 's2', agent_id: 'aaaaaaaaaaaaaaaaaaaa0002', agent_name: 'kiosk-03', agent_display_name: null, seconds: 2 * HOUR }),
          win({ session_id: 's3', agent_id: 'aaaaaaaaaaaaaaaaaaaa0003', seconds: HOUR }),
        ],
      },
      global: { plugins: [vuetify] },
    })
    const labels = w.findAll('.tl-label .text-body-2').map((l) => l.text())
    expect(labels).toEqual(['Build server', 'kiosk-03', 'aa0003'])
    // FR-120 P1 — a window's own text is read by a tap, into the detail line.
    await w.find('[data-testid="tl-track-aaaaaaaaaaaaaaaaaaaa0001"]').trigger('click')
    expect(w.find('[data-testid="tl-detail"]').text()).toContain('Controlled Build server')
  })
})

// FR-120 P1 — a viewing window's times, length and traffic were each bar's
// `title`, which a tap never shows. The track reports the window under a tap,
// a mouse pointing, or the arrow keys; no bar carries a hover-only title.
describe('UsageTimeline — a window read by a tap (FR-120 P1)', () => {
  const two = () =>
    mount(UsageTimeline, {
      props: {
        from: T0,
        to: T0 + 4 * HOUR,
        windows: [
          win({ agent_id: 'aaaaaaaaaaaaaaaaaaaa0001', agent_display_name: 'Build server', seconds: HOUR }),
          win({
            session_id: 's2',
            agent_id: 'aaaaaaaaaaaaaaaaaaaa0001',
            agent_display_name: 'Build server',
            role: 'watcher',
            started_at: T0 + 2 * HOUR,
            ended_at: T0 + 3 * HOUR,
            seconds: HOUR,
          }),
        ],
      },
      global: { plugins: [vuetify] },
    })
  const track = (w: ReturnType<typeof two>) => w.find('[data-testid="tl-track-aaaaaaaaaaaaaaaaaaaa0001"]')
  const detail = (w: ReturnType<typeof two>) => w.find('[data-testid="tl-detail"]').text()

  it('carries no hover-only title on a bar, and says how to read one', () => {
    const w = two()
    expect(w.findAll('.tl-bar').every((b) => b.attributes('title') === undefined)).toBe(true)
    expect(detail(w)).toContain('Tap a bar')
  })

  it('steps through the windows with the arrow keys, and marks the one it reads', async () => {
    const w = two()
    await track(w).trigger('keydown', { key: 'ArrowRight' })
    expect(detail(w)).toContain('Controlled Build server')
    await track(w).trigger('keydown', { key: 'ArrowRight' })
    expect(detail(w)).toContain('Watched Build server')
    expect(w.findAll('.tl-bar')[1].classes()).toContain('tl-bar--shown')
  })

  it('previews under a mouse, never under a finger', async () => {
    const w = two()
    await track(w).trigger('pointermove', { pointerType: 'touch' })
    expect(detail(w)).toContain('Tap a bar')
    await track(w).trigger('pointermove', { pointerType: 'mouse' })
    expect(detail(w)).toContain('Build server')
    await track(w).trigger('pointerleave')
    expect(detail(w)).toContain('Tap a bar')
  })
})
