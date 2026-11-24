// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-120 P4 — the ephemeral enrollment keys on a phone. Six labelled blocks a
// key made the Devices page 2.5× its desktop height even with every device
// folded: a phone now shows one line a key (its label, its state, Revoke),
// opens it on a tap for its uses, expiry, device deadline and mint date, and
// shows 20 at a time. Wider screens keep the table. And the table and its Show
// more sit in ONE <template v-if>, so "No keys minted yet." never shows beside
// a list of keys (a v-else pairs with the nearest v-if: docs/ui.md).
import { describe, it, expect, vi, beforeAll, beforeEach, afterEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { mount, flushPromises } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'

beforeAll(() => {
  globalThis.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver
})

vi.mock('@/api/client', () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() },
}))

import EnrollKeysSection from '@/components/admin/EnrollKeysSection.vue'
import { useAgentStore, type EnrollmentKeyRow } from '@/stores/agents'

const realWidth = window.innerWidth

function key(i: number, over: Partial<EnrollmentKeyRow> = {}): EnrollmentKeyRow {
  return {
    id: `k${i}`,
    jti: `j${i}`,
    label: `fleet-${i}`,
    created_by: 'u1',
    max_uses: 100,
    uses: 3,
    expires_at: new Date(Date.now() + 86_400_000).toISOString(),
    created_at: new Date(Date.now() - i * 60_000).toISOString(),
    ...over,
  }
}

/** The section renders only once the org's switch reads true; the store's two
 *  fetches are stubbed so the test drives exactly what the server would say. */
async function mountAt(width: number, keys: EnrollmentKeyRow[]) {
  Object.defineProperty(window, 'innerWidth', { value: width, configurable: true })
  const store = useAgentStore()
  store.fetchOrgEphemeralKeysEnabled = vi.fn(async () => {
    store.orgEphemeralKeysEnabled = true
  }) as typeof store.fetchOrgEphemeralKeysEnabled
  store.listEnrollKeys = vi.fn(async () => keys) as typeof store.listEnrollKeys
  const w = mount(EnrollKeysSection, {
    props: { tenantId: 't1' },
    global: { plugins: [createVuetify({ components, directives })] },
  })
  await flushPromises()
  return w
}

beforeEach(() => {
  setActivePinia(createPinia())
})

afterEach(() => {
  Object.defineProperty(window, 'innerWidth', { value: realWidth, configurable: true })
})

describe('the enrollment keys on a phone (FR-120 P4)', () => {
  it('shows one line a key: its label, its state and Revoke', async () => {
    const w = await mountAt(360, [key(0), key(1, { revoked_at: new Date().toISOString() }), key(2, { uses: 100 })])
    const toggles = w.findAll('[data-testid="key-row-toggle"]')
    expect(toggles).toHaveLength(3)
    const lines: [string, string][] = [
      ['fleet-0', 'active'],
      ['fleet-1', 'revoked'],
      ['fleet-2', 'exhausted'],
    ]
    lines.forEach(([label, state], i) => {
      expect(toggles[i].get('.stack-toggle__text').text()).toBe(label)
      expect(toggles[i].get('.v-chip').text()).toBe(state)
    })
    const rows = w.findAll('tbody tr')
    // Revoke on the line itself, but never for a revoked key.
    expect(rows[0].find('[aria-label="Revoke key fleet-0"]').exists()).toBe(true)
    expect(rows[1].find('[aria-label^="Revoke key"]').exists()).toBe(false)
    // The rest are details, closed until tapped.
    for (const label of ['Minted', 'Uses', 'Expires', 'Device TTL']) {
      expect(rows[0].get(`td[data-label="${label}"]`).classes()).toContain('stack-detail')
    }
    expect(rows[0].find('td[data-label="State"]').exists()).toBe(false)
  })

  it('opens a key on a tap, each on its own', async () => {
    const w = await mountAt(360, [key(0), key(1)])
    await w.findAll('[data-testid="key-row-toggle"]')[0].trigger('click')
    const rows = w.findAll('tbody tr')
    expect(rows[0].classes()).toContain('stack-open')
    expect(rows[0].get('[data-testid="key-row-toggle"]').attributes('aria-expanded')).toBe('true')
    expect(rows[1].classes()).not.toContain('stack-open')
  })

  it('never says "No keys minted yet." beside a list of keys', async () => {
    const w = await mountAt(360, [key(0)])
    expect(w.text()).not.toContain('No keys minted yet.')
    const empty = await mountAt(360, [])
    expect(empty.text()).toContain('No keys minted yet.')
  })

  it('shows 20 at a time, then the rest', async () => {
    const w = await mountAt(360, Array.from({ length: 25 }, (_, i) => key(i)))
    expect(w.findAll('tbody tr')).toHaveLength(20)
    await w.get('[data-testid="keys-show-more"]').trigger('click')
    expect(w.findAll('tbody tr')).toHaveLength(25)
  })
})

describe('the enrollment keys on a wider screen', () => {
  it('keeps the table, with no phone line', async () => {
    const w = await mountAt(1300, [key(0)])
    expect(w.find('[data-testid="key-row-toggle"]').exists()).toBe(false)
    const labels = w.findAll('tbody tr td').map((td) => td.attributes('data-label') ?? '')
    expect(labels).toEqual(['', 'Uses', 'Expires', 'Device TTL', 'State', ''])
    expect(w.get('td[data-label="State"]').text()).toBe('active')
  })
})
