// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-92 — the Keep busy menu renders the device's state and asks for
// changes; it never decides anything itself.
import { beforeAll, describe, expect, it } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import KeepBusyMenu from '@/components/remote/KeepBusyMenu.vue'
import {
  parseKeepBusyState,
  type KeepBusyPattern,
  type KeepBusyRequest,
  type KeepBusyState,
} from '@/composables/keepBusy'

const vuetify = createVuetify({ components, directives })

beforeAll(() => {
  // Vuetify overlays measure themselves against the viewport; jsdom has
  // neither a ResizeObserver nor a visualViewport.
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

function state(over: Record<string, unknown> = {}): KeepBusyState {
  const s = parseKeepBusyState(
    {
      t: 'rc:keep-busy.state',
      rev: 1,
      available: true,
      on: false,
      phase: 'off',
      reason: null,
      sentence: null,
      pattern: 'circle',
      size: 'm',
      speed: 'normal',
      resume_after_s: 30,
      warn: [],
      ...over,
    },
    Date.now(),
  )
  if (!s) throw new Error('fixture did not parse')
  return s
}

function render(props: {
  state: KeepBusyState | null
  canControl: boolean
  agentId?: string
  defaultPattern?: KeepBusyPattern | null
}) {
  return mount(KeepBusyMenu, {
    props: { agentId: 'agent-1', ...props },
    global: { plugins: [vuetify] },
    attachTo: document.body,
  })
}

/** Change the org default on a mounted menu, as the late fetch does.
 *
 *  ⚠️ `setProps`' argument is typed from the component, and where vue-tsc
 *  resolves `.vue` through `env.d.ts`'s shim — the hosted image's build runs
 *  it in `oven/bun`, which has no `node` — the shim's props are `object`.
 *  An object literal naming a REAL prop then fails the excess-property check
 *  there and nowhere else (CI and local builds type it from the SFC). The
 *  prop is real; vitest exercises it at run time. */
function setDefaultPattern(w: ReturnType<typeof render>, defaultPattern: KeepBusyPattern | null) {
  return w.setProps({ defaultPattern } as unknown as Parameters<typeof w.setProps>[0])
}

/** Is the pattern tile `id` the chosen one in the open menu? */
function checked(id: string): boolean {
  return (
    document
      .querySelector(`[data-testid="rc-keep-busy-pattern-${id}"]`)
      ?.getAttribute('aria-checked') === 'true'
  )
}

describe('KeepBusyMenu (FR-92)', () => {
  it('is a plain button while keep busy is off', () => {
    const w = render({ state: state(), canControl: true })
    expect(w.find('[data-testid="rc-keep-busy-btn"]').exists()).toBe(true)
    expect(w.find('[data-testid="rc-keep-busy-chip"]').exists()).toBe(false)
    w.unmount()
  })

  it('shows a chip with what the device is drawing while it runs', () => {
    const w = render({ state: state({ on: true, phase: 'running', pattern: 'heart' }), canControl: true })
    expect(w.find('[data-testid="rc-keep-busy-chip"]').text()).toContain('Keep busy · heart')
    w.unmount()
  })

  it('counts a pause down in the chip', () => {
    const w = render({
      state: state({ on: true, phase: 'paused', reason: 'user_active', resumes_in_ms: 23_000 }),
      canControl: true,
    })
    expect(w.find('[data-testid="rc-keep-busy-chip"]').text()).toMatch(/Keep busy · paused 2[23]s/)
    w.unmount()
  })

  it('asks the device to turn it on with the chosen settings', async () => {
    const w = render({ state: state(), canControl: true })
    await w.find('[data-testid="rc-keep-busy-btn"]').trigger('click')
    await flushPromises()
    const star = document.querySelector<HTMLButtonElement>('[data-testid="rc-keep-busy-pattern-star"]')
    expect(star, 'the menu opened').not.toBeNull()
    star!.click()
    await flushPromises()
    // While off, choosing a pattern sends nothing.
    expect(w.emitted('set')).toBeUndefined()
    const input = document.querySelector<HTMLInputElement>('[data-testid="rc-keep-busy-switch"] input')
    input!.click()
    await flushPromises()
    const sent = w.emitted('set') as KeepBusyRequest[][]
    expect(sent).toHaveLength(1)
    expect(sent[0][0]).toMatchObject({ on: true, pattern: 'star', speed: 'normal', size: 'm', resumeAfterS: 30 })
    w.unmount()
  })

  it('lets a view-only session watch but not change it', async () => {
    const w = render({ state: state({ on: true, phase: 'running' }), canControl: false })
    await w.find('[data-testid="rc-keep-busy-chip"]').trigger('click')
    await flushPromises()
    const input = document.querySelector<HTMLInputElement>('[data-testid="rc-keep-busy-switch"] input')
    expect(input?.disabled).toBe(true)
    expect(document.body.textContent).toContain('view-only')
    w.unmount()
  })

  // ── FR-92 P8 — the org's default pattern ──────────────────────────

  const KEY = 'meshharbor-rc-keep-busy.v1:'

  it('P8: pre-selects the org default on a device nothing is remembered for', async () => {
    localStorage.removeItem(KEY + 'agent-fresh')
    const w = render({ state: state(), canControl: true, agentId: 'agent-fresh', defaultPattern: 'heart' })
    await w.find('[data-testid="rc-keep-busy-btn"]').trigger('click')
    await flushPromises()
    expect(checked('heart')).toBe(true)
    expect(checked('circle')).toBe(false)
    w.unmount()
  })

  it("P8: a person's remembered choice for the device wins over the org default", async () => {
    localStorage.setItem(KEY + 'agent-kept', JSON.stringify({ pattern: 'star' }))
    const w = render({ state: state(), canControl: true, agentId: 'agent-kept', defaultPattern: 'heart' })
    await w.find('[data-testid="rc-keep-busy-btn"]').trigger('click')
    await flushPromises()
    expect(checked('star')).toBe(true)
    expect(checked('heart')).toBe(false)
    w.unmount()
    localStorage.removeItem(KEY + 'agent-kept')
  })

  it('P8: the default arriving after the fetch fills the pattern — never once the person has chosen', async () => {
    localStorage.removeItem(KEY + 'agent-late')
    const w = render({ state: state(), canControl: true, agentId: 'agent-late', defaultPattern: null })
    await setDefaultPattern(w, 'wave')
    await w.find('[data-testid="rc-keep-busy-btn"]').trigger('click')
    await flushPromises()
    expect(checked('wave')).toBe(true)
    document.querySelector<HTMLButtonElement>('[data-testid="rc-keep-busy-pattern-star"]')!.click()
    await flushPromises()
    await setDefaultPattern(w, 'rose')
    await flushPromises()
    expect(checked('star')).toBe(true)
    expect(checked('rose')).toBe(false)
    w.unmount()
    localStorage.removeItem(KEY + 'agent-late')
  })

  it('P8: while it runs, the device’s own pattern shows, whatever the org default', async () => {
    localStorage.removeItem(KEY + 'agent-running')
    const w = render({
      state: state({ on: true, phase: 'running', pattern: 'spirograph' }),
      canControl: true,
      agentId: 'agent-running',
      defaultPattern: 'heart',
    })
    await w.find('[data-testid="rc-keep-busy-chip"]').trigger('click')
    await flushPromises()
    expect(checked('spirograph')).toBe(true)
    expect(checked('heart')).toBe(false)
    w.unmount()
  })
})
