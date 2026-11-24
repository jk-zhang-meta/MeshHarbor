// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-120 P1 — a chip whose meaning is a tap away. A chip's `title` reaches a
// mouse only; FactChip opens its explanation in a small menu on a tap or
// click, at every width, and keeps it as the hover title.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import FactChip from '@/components/common/FactChip.vue'

const vuetify = createVuetify({ components, directives })
const EXPLAIN = 'The device’s credential expires in 3 days — renew it from the device'

let opened: ReturnType<typeof mount> | null = null
function chip() {
  opened = mount(FactChip, {
    props: { explain: EXPLAIN },
    attrs: { size: 'x-small', color: 'warning', 'data-testid': 'credential-chip' },
    slots: { default: 'credential' },
    global: { plugins: [vuetify] },
    attachTo: document.body,
  })
  return opened
}

// A menu measures itself against the viewport; jsdom has neither of these.
beforeEach(() => {
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  )
  vi.stubGlobal('visualViewport', {
    width: 360,
    height: 780,
    offsetLeft: 0,
    offsetTop: 0,
    pageLeft: 0,
    pageTop: 0,
    scale: 1,
    addEventListener() {},
    removeEventListener() {},
  })
})

afterEach(() => {
  opened?.unmount()
  opened = null
  vi.unstubAllGlobals()
})

describe('FactChip (FR-120 P1)', () => {
  it('is the chip it wraps: its label, its attributes, and the explanation as its hover title', () => {
    const w = chip()
    const c = w.find('.v-chip')
    expect(c.text()).toBe('credential')
    expect(c.attributes('data-testid')).toBe('credential-chip')
    expect(c.classes()).toContain('v-chip--size-x-small')
    expect(c.attributes('title')).toBe(EXPLAIN)
  })

  it('opens its explanation on a tap', async () => {
    const w = chip()
    expect(document.body.querySelector('[data-testid="fact-chip-explain"]')).toBeNull()
    await w.find('.v-chip').trigger('click')
    await flushPromises()
    const shown = document.body.querySelector('[data-testid="fact-chip-explain"]')
    expect(shown?.textContent).toContain(EXPLAIN)
  })
})
