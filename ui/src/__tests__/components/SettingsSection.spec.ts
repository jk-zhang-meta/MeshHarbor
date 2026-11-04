// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-116 P3c — the organization Settings page on a phone.
//
// It was ~4 screens of warnings and captions before its last switch. Below
// 600 px each gate is now an expansion panel titled with the gate's current
// state, so the page reads as a list of decisions and a gate's explanation and
// controls open on demand. From 600 px up it stays the column of cards it
// always was. A summary is EMPTY while the state is unknown (not loaded, or
// not readable with the caller's rights) — never a guess.
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import type { Ref } from 'vue'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { createI18n } from 'vue-i18n'
import en from '@/locales/en.json'

const hoisted = vi.hoisted(() => ({
  // A real ref, created in the mock below: a template unwraps only refs, and
  // a plain `{ value }` object would read as truthy at every width.
  xs: null as unknown as Ref<boolean>,
  agent: {} as Record<string, unknown>,
}))

vi.mock('vuetify', async (importOriginal) => {
  const actual = await importOriginal<typeof import('vuetify')>()
  const { ref } = await import('vue')
  hoisted.xs = ref(true)
  return { ...actual, useDisplay: () => ({ xs: hoisted.xs }) }
})
vi.mock('@/stores/agents', () => ({ useAgentStore: () => hoisted.agent }))
vi.mock('@/stores/tenant', () => ({
  useTenantStore: () => ({ current: { name: 'Acme Labs', slug: 'acme-labs' } }),
}))

import SettingsSection from '@/components/admin/SettingsSection.vue'

const vuetify = createVuetify({ components, directives })
const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })

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

function agentState(over: Record<string, unknown> = {}) {
  const fetches = [
    'fetchOrgRcSessionLimits',
    'fetchOrgExecEnabled',
    'fetchOrgSshEnabled',
    'fetchOrgKeepBusyDenied',
    'fetchOrgRcSessionPolicy',
    'fetchOrgEphemeralKeysEnabled',
    'fetchExternalAccess',
  ]
  return {
    orgExecEnabled: true,
    orgExecRequireSystem: null,
    orgSshEnabled: false,
    orgExternalAccessEnabled: null, // unknown: no summary
    orgKeepBusyDenied: false,
    orgKeepBusyDefaultPattern: null,
    orgRcSessionPolicy: { clipboard: 'on', files: 'ask', audio: 'off' },
    orgEphemeralKeysEnabled: true,
    orgRcMaxSessionSecs: 3600,
    orgRcIdleSecs: null,
    ...Object.fromEntries(fetches.map((f) => [f, vi.fn()])),
    ...over,
  }
}

function mountAt(width: 'phone' | 'wide', agent: Record<string, unknown> = {}) {
  hoisted.xs.value = width === 'phone'
  hoisted.agent = agentState(agent)
  return mount(SettingsSection, {
    props: { tenantId: 't1' },
    global: { plugins: [vuetify, i18n], stubs: { KeepBusyHistorySection: true } },
    attachTo: document.body,
  })
}

/** Panel title → its summary text, NBSPs read as spaces. */
function summaries(w: ReturnType<typeof mountAt>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const t of w.findAll('.v-expansion-panel-title')) {
    const title = t.find('.font-weight-medium').text()
    const s = t.find('[data-testid="settings-gate-summary"]')
    out[title] = s.exists() ? s.text().replace(/ /g, ' ') : ''
  }
  return out
}

afterEach(() => {
  document.body.innerHTML = ''
})

describe('SettingsSection on a phone (FR-116 P3c)', () => {
  it('is one panel per gate, each titled with its current state', () => {
    const w = mountAt('phone')
    expect(summaries(w)).toEqual({
      'Workspace Settings': 'Acme Labs',
      'Remote command execution': 'On',
      'MeshHarbor SSH': 'Off',
      'External access': '', // not loaded / not readable: no guess
      'Keep busy': 'Allowed',
      'Remote session features': 'Files: ask · Audio: off',
      'Ephemeral enrollment keys': 'On',
      'Remote session limits': '1 hour max',
    })
    // Nothing of a gate's body until it is opened: that is the point.
    expect(w.findAll('.v-switch')).toHaveLength(0)
    expect(w.find('[data-testid="org-keep-busy-card"]').classes()).toContain('v-expansion-panel')
  })

  it('wraps a summary only between its parts', () => {
    const w = mountAt('phone')
    const s = w
      .findAll('.v-expansion-panel-title')
      .find((t) => t.text().includes('Remote session features'))!
      .find('[data-testid="settings-gate-summary"]')
      .text()
    expect(s).toBe('Files: ask · Audio: off')
  })

  it('says so when nothing is restricted or limited', () => {
    const w = mountAt('phone', {
      orgRcSessionPolicy: { clipboard: 'on', files: 'on', audio: 'on' },
      orgRcMaxSessionSecs: null,
      orgRcIdleSecs: 15 * 60,
      orgKeepBusyDenied: true,
    })
    const s = summaries(w)
    expect(s['Remote session features']).toBe('All on')
    expect(s['Remote session limits']).toBe('15 minutes idle')
    expect(s['Keep busy']).toBe('Not allowed')
  })

  it('opens a gate on demand, with its controls', async () => {
    const w = mountAt('phone')
    await w
      .findAll('.v-expansion-panel-title')
      .find((t) => t.text().includes('MeshHarbor SSH'))!
      .trigger('click')
    await flushPromises()
    expect(w.text()).toContain('Allow SSH sessions in this organization')
    expect(w.findAll('.v-switch')).toHaveLength(1)
  })
})

describe('SettingsSection from 600 px up', () => {
  it('stays the column of cards, every control in view, no summaries', () => {
    const w = mountAt('wide')
    expect(w.findAll('.v-expansion-panel')).toHaveLength(0)
    expect(w.findAll('.v-card')).toHaveLength(8)
    expect(w.find('[data-testid="settings-gate-summary"]').exists()).toBe(false)
    expect(w.find('[data-testid="org-keep-busy-card"]').classes()).toContain('v-card')
    expect(w.text()).toContain('Allow SSH sessions in this organization')
  })
})
