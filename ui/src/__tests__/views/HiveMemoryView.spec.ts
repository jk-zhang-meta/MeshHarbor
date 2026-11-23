// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-90 P1e — agent memory. Facts are listed by scope with each scope's
// budget; a device's facts appear once a device is chosen; a write reloads
// what the server now holds; and a refusal — over budget, or not yours to
// keep — is shown in the server's own words, with the draft kept.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { createI18n } from 'vue-i18n'
import en from '@/locales/en.json'

const hoisted = vi.hoisted(() => ({
  fetchBrain: vi.fn(),
  keepFact: vi.fn(),
  editFact: vi.fn(),
  archiveFact: vi.fn(),
  fetchDevices: vi.fn(),
}))
vi.mock('@/stores/hive', () => ({
  FACT_KINDS: ['convention', 'preference', 'path', 'gotcha', 'decision', 'warning'],
  MAX_FACT_CHARS: 500,
  useHiveStore: () => ({
    fetchBrain: hoisted.fetchBrain,
    keepFact: hoisted.keepFact,
    editFact: hoisted.editFact,
    archiveFact: hoisted.archiveFact,
  }),
}))
vi.mock('@/stores/devices', () => ({
  useDeviceStore: () => ({
    items: [
      { id: 'd1', kind: 'agent', name: 'build-01', display_name: 'Build box', presence: 'offline' },
      { id: 'b1', kind: 'browser', name: 'not-an-agent' },
    ],
    loading: false,
    fetchDevices: hoisted.fetchDevices,
  }),
}))
vi.mock('vue-router', () => ({ useRoute: () => ({ params: { tenantId: 't1' } }) }))

import HiveMemoryView from '@/views/hive/HiveMemoryView.vue'

const vuetify = createVuetify({ components, directives })

/** The dialog inline: its content is always there. */
const DialogStub = { props: ['modelValue'], template: '<div><slot /></div>' }
/** Choosing a device is one click: it picks `d1`. */
const PickDevice = {
  props: ['modelValue'],
  emits: ['update:modelValue'],
  template: '<button @click="$emit(\'update:modelValue\', \'d1\')" />',
}

const fact = (id: string, scope: string, text: string, extra: Record<string, unknown> = {}) => ({
  id,
  scope,
  text,
  kind: 'convention',
  version: 1,
  created_by: 'u1',
  created_at: '2026-10-08T00:00:00Z',
  updated_by: 'u1',
  updated_at: '2026-10-08T00:00:00Z',
  ...extra,
})

const orgOnly = {
  brain_rev: 3,
  facts: [fact('f1', 'org', 'Deploys go through promote.yml.'), fact('f2', 'user', 'I prefer short answers.')],
  budgets: [
    { scope: 'org', used: 2990, budget: 3000 },
    { scope: 'user', owner_id: 'u1', used: 23, budget: 1500 },
  ],
}

async function render() {
  hoisted.fetchBrain.mockResolvedValue(orgOnly)
  const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })
  const w = mount(HiveMemoryView, {
    global: { plugins: [vuetify, i18n], stubs: { VDialog: DialogStub, VAutocomplete: PickDevice } },
  })
  await flushPromises()
  return w
}

const scope = (w: Awaited<ReturnType<typeof render>>, s: string) => w.find(`[data-testid="hive-memory-scope-${s}"]`)

// jsdom has no ResizeObserver; an auto-growing textarea needs one.
beforeEach(() => {
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  )
})

afterEach(() => {
  vi.clearAllMocks()
  vi.unstubAllGlobals()
})

describe('HiveMemoryView (FR-90 P1e)', () => {
  it('lists the facts by scope, each scope with its budget', async () => {
    const w = await render()
    expect(hoisted.fetchBrain).toHaveBeenCalledWith('t1', undefined)
    expect(hoisted.fetchDevices).toHaveBeenCalledWith('t1', { kind: 'agent', perPage: 100 })
    expect(scope(w, 'org').findAll('[data-testid="hive-memory-fact"]').map((f) => f.text())).toEqual([
      expect.stringContaining('Deploys go through promote.yml.'),
    ])
    expect(scope(w, 'user').text()).toContain('I prefer short answers.')
    expect(scope(w, 'org').find('[data-testid="hive-memory-budget-org"]').text()).toContain('2990 of 3000 characters')
    expect(w.find('[data-testid="hive-memory-rev"]').text()).toContain('Revision 3')
    // No device chosen: the device scope offers the choice and nothing else.
    expect(scope(w, 'device').find('[data-testid="hive-memory-add-device"]').exists()).toBe(false)
  })

  it('keeps a fact in the scope it was written in, then shows what the server holds', async () => {
    const w = await render()
    await scope(w, 'org').find('[data-testid="hive-memory-text-org"] textarea').setValue('  Never restart the build box.  ')
    hoisted.keepFact.mockResolvedValue(fact('f3', 'org', 'Never restart the build box.'))
    await scope(w, 'org').find('[data-testid="hive-memory-add-org"]').trigger('click')
    await flushPromises()
    expect(hoisted.keepFact).toHaveBeenCalledWith('t1', {
      scope: 'org',
      owner_id: undefined,
      text: 'Never restart the build box.',
      kind: 'convention',
    })
    expect(hoisted.fetchBrain).toHaveBeenCalledTimes(2)
  })

  it('shows an over-budget refusal in the server’s words and keeps the draft', async () => {
    const w = await render()
    const text = scope(w, 'org').find('[data-testid="hive-memory-text-org"] textarea')
    await text.setValue('One fact too many.')
    const said = 'the organization memory holds 2990 of its 3000 characters; this needs 18 more'
    hoisted.keepFact.mockRejectedValue(new Error(said))
    await scope(w, 'org').find('[data-testid="hive-memory-add-org"]').trigger('click')
    await flushPromises()
    expect(scope(w, 'org').find('[data-testid="hive-memory-error-org"]').text()).toContain(said)
    expect((text.element as HTMLTextAreaElement).value).toBe('One fact too many.')
    // Nothing changed on the server, so nothing is re-read.
    expect(hoisted.fetchBrain).toHaveBeenCalledTimes(1)
  })

  it('shows a device’s facts once one is chosen, and keeps new ones for that device', async () => {
    const w = await render()
    hoisted.fetchBrain.mockResolvedValue({
      ...orgOnly,
      facts: [...orgOnly.facts, fact('f4', 'device', 'The repo lives in /srv/app.', { owner_id: 'd1' })],
      budgets: [...orgOnly.budgets, { scope: 'device', owner_id: 'd1', used: 26, budget: 800 }],
    })
    await scope(w, 'device').find('button').trigger('click')
    await flushPromises()
    expect(hoisted.fetchBrain).toHaveBeenLastCalledWith('t1', 'd1')
    expect(scope(w, 'device').text()).toContain('The repo lives in /srv/app.')
    expect(scope(w, 'device').find('[data-testid="hive-memory-budget-device"]').text()).toContain('26 of 800')

    await scope(w, 'device').find('[data-testid="hive-memory-text-device"] textarea').setValue('Builds need 8 GB.')
    hoisted.keepFact.mockResolvedValue(fact('f5', 'device', 'Builds need 8 GB.', { owner_id: 'd1' }))
    await scope(w, 'device').find('[data-testid="hive-memory-add-device"]').trigger('click')
    await flushPromises()
    expect(hoisted.keepFact).toHaveBeenCalledWith('t1', {
      scope: 'device',
      owner_id: 'd1',
      text: 'Builds need 8 GB.',
      kind: 'convention',
    })
  })

  it('edits a fact at the version it read, and archives one', async () => {
    const w = await render()
    await scope(w, 'org').find('[data-testid="hive-memory-edit"]').trigger('click')
    await w.find('[data-testid="hive-memory-edit-text"] textarea').setValue('Deploys go through promote.yml, never by hand.')
    hoisted.editFact.mockResolvedValue(fact('f1', 'org', 'x', { version: 2 }))
    await w.find('[data-testid="hive-memory-edit-save"]').trigger('click')
    await flushPromises()
    expect(hoisted.editFact).toHaveBeenCalledWith('t1', 'f1', {
      text: 'Deploys go through promote.yml, never by hand.',
      kind: 'convention',
      version: 1,
    })

    hoisted.archiveFact.mockResolvedValue({ archived: true })
    await scope(w, 'user').find('[data-testid="hive-memory-archive"]').trigger('click')
    await flushPromises()
    expect(hoisted.archiveFact).toHaveBeenCalledWith('t1', 'f2')
    expect(hoisted.fetchBrain).toHaveBeenCalledTimes(3)
  })
})

// FR-120 P2 — on a phone the three scopes stacked open were three screens;
// there each is a panel titled with how full it is, opened on demand.
describe('HiveMemoryView on a phone (FR-120 P2)', () => {
  /** Vuetify reads the window's width when the plugin is made. */
  async function renderAt(width: number) {
    window.innerWidth = width
    hoisted.fetchBrain.mockResolvedValue(orgOnly)
    const sized = createVuetify({ components, directives })
    const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })
    const w = mount(HiveMemoryView, {
      global: { plugins: [sized, i18n], stubs: { VDialog: DialogStub, VAutocomplete: PickDevice } },
    })
    await flushPromises()
    return w
  }

  afterEach(() => {
    window.innerWidth = 1024
  })

  it('shows each scope as a closed panel titled with how full it is', async () => {
    const w = await renderAt(360)
    expect(scope(w, 'org').classes()).toContain('v-expansion-panel')
    expect(scope(w, 'org').find('[data-testid="hive-memory-summary"]').text()).toBe('2990 of 3000 characters')
    expect(scope(w, 'user').find('[data-testid="hive-memory-summary"]').text()).toBe('23 of 1500 characters')
    // No device chosen, so no budget: the title claims nothing.
    expect(scope(w, 'device').find('[data-testid="hive-memory-summary"]').exists()).toBe(false)
    // Closed: the facts and the draft wait until they are asked for.
    expect(scope(w, 'org').find('[data-testid="hive-memory-text-org"]').exists()).toBe(false)
  })

  it('opens a scope on a tap, and keeps a fact from there as before', async () => {
    const w = await renderAt(360)
    await scope(w, 'org').find('.v-expansion-panel-title').trigger('click')
    await flushPromises()
    expect(scope(w, 'org').text()).toContain('Deploys go through promote.yml.')
    await scope(w, 'org').find('[data-testid="hive-memory-text-org"] textarea').setValue('Never restart the build box.')
    hoisted.keepFact.mockResolvedValue(fact('f3', 'org', 'Never restart the build box.'))
    await scope(w, 'org').find('[data-testid="hive-memory-add-org"]').trigger('click')
    await flushPromises()
    expect(hoisted.keepFact).toHaveBeenCalledWith(
      't1',
      expect.objectContaining({ scope: 'org', text: 'Never restart the build box.' }),
    )
  })

  it('keeps the row of open cards from 600 px up', async () => {
    const w = await renderAt(1024)
    expect(scope(w, 'org').classes()).toContain('v-card')
    expect(w.find('[data-testid="hive-memory-summary"]').exists()).toBe(false)
    expect(scope(w, 'org').find('[data-testid="hive-memory-text-org"]').exists()).toBe(true)
  })
})
