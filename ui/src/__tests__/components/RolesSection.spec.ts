// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-116 P3c — roles on a touch screen.
//
// What a role grants was a hover tooltip and nothing else, so a phone could
// not read it: a tap (or Enter) now lists the grants under the count, at every
// width. And in the role editor a permission's description was a tooltip ON
// ITS LABEL — the tap meant to read it toggled the permission instead — so on
// a touch screen it is a hint under the box.
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'

const hoisted = vi.hoisted(() => ({
  roles: [
    { id: 'r1', name: 'Remote Operator', description: 'Support fleet', permissions: (1 << 24) | (1 << 25), position: 10, is_managed: false, is_default: false },
    { id: 'r2', name: 'Administrator', permissions: 1 << 23, position: 0, is_managed: true, is_default: false },
  ],
}))
vi.mock('@/stores/role', () => ({
  useRoleStore: () => ({
    roles: hoisted.roles,
    loading: false,
    error: null,
    colorHex: () => undefined,
    fetchRoles: vi.fn(),
  }),
}))

import RolesSection from '@/components/admin/RolesSection.vue'

const vuetify = createVuetify({ components, directives })
const realMatchMedia = window.matchMedia

beforeAll(() => {
  // Vuetify overlays measure themselves against the viewport; jsdom has
  // neither a ResizeObserver nor a visualViewport. (Without the latter the
  // editor never opens — and a "no hint" assertion would pass on nothing.)
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
      width: 390,
      height: 844,
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

/** RolesSection reads `(hover: none)` once, at setup — stub it before mounting. */
function screen(kind: 'touch' | 'mouse') {
  window.matchMedia = vi.fn((query: string) => ({
    matches: kind === 'touch' && query === '(hover: none)',
    media: query,
    onchange: null,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia
}

function mountRoles() {
  return mount(RolesSection, {
    props: { tenantId: 't1' },
    global: { plugins: [vuetify] },
    attachTo: document.body,
  })
}

afterEach(() => {
  window.matchMedia = realMatchMedia
  document.body.innerHTML = ''
})

describe('RolesSection — what a role grants (FR-116 P3c)', () => {
  it('a tap lists the grants under the count, a second tap hides them', async () => {
    screen('touch')
    const w = mountRoles()
    const toggle = w.find('[data-testid="role-grants-r1"]')
    expect(toggle.text()).toBe('2 permissions')
    expect(w.text()).not.toContain('Remote control')

    await toggle.trigger('click')
    expect(toggle.attributes('aria-expanded')).toBe('true')
    expect(w.text()).toContain('Manage devices')
    expect(w.text()).toContain('Remote control')

    await toggle.trigger('click')
    expect(w.text()).not.toContain('Remote control')
  })

  it('Enter opens them too — the count is a button', async () => {
    screen('mouse')
    const w = mountRoles()
    const toggle = w.find('[data-testid="role-grants-r1"]')
    expect(toggle.attributes('role')).toBe('button')
    await toggle.trigger('keydown', { key: 'Enter' })
    expect(w.text()).toContain('Remote control')
  })

  it('an administrator role says "all" and has nothing to expand', () => {
    screen('touch')
    const w = mountRoles()
    expect(w.text()).toContain('Administrator (all)')
    expect(w.find('[data-testid="role-grants-r2"]').exists()).toBe(false)
  })
})

describe('RolesSection — permission descriptions in the editor', () => {
  async function openEditor() {
    const w = mountRoles()
    // Sorted by position: [0] is the managed Administrator, not editable.
    await w.findAll('.mdi-pencil')[1]!.element.closest('button')!.click()
    await flushPromises()
    return w
  }
  const description = 'Bypasses ALL permission checks'

  it('on a touch screen: a hint under the box', async () => {
    screen('touch')
    await openEditor()
    const hints = [...document.querySelectorAll('.v-messages__message')].map((m) => m.textContent)
    expect(hints.some((h) => h?.includes(description))).toBe(true)
  })

  it('with a mouse: still the tooltip, no hint text', async () => {
    screen('mouse')
    await openEditor()
    // The editor IS open (its boxes are there) — so the absence is real.
    expect(document.body.textContent).toContain('Administrator')
    expect(document.querySelectorAll('.v-overlay__content .v-checkbox').length).toBeGreaterThan(10)
    const hints = [...document.querySelectorAll('.v-messages__message')].map((m) => m.textContent)
    expect(hints.some((h) => h?.includes(description))).toBe(false)
  })
})
