// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-120 P4 — the plans on a phone. Three plans × nine open limit rows made
// Billing 2.2× its desktop height at 360 px (FR-120 §2.1): a phone now shows
// each plan's three limits that tell the plans apart (users, devices, remote
// sessions at a time) and opens the other six on a tap. A wider screen keeps
// all nine, with no toggle.
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

import BillingView from '@/views/billing/BillingView.vue'
import { api } from '@/api/client'

const realWidth = window.innerWidth
const limits = {
  max_devices: 100,
  max_tunnel_clients: 10,
  overlay_mesh: true,
  exit_nodes: false,
  magic_dns: true,
  max_concurrent_sessions: 1,
  relay_bytes_per_month: 10_000_000_000,
  max_members: 10,
  max_channels: 10,
  max_message_history: 10_000,
  storage_bytes: 1_000_000_000,
  video_max_participants: 10,
  meeting_max_minutes: 60,
  cloud_integrations: false,
  recordings: false,
}
const plans = ['free', 'pro', 'business'].map((id, i) => ({
  id,
  name: id[0].toUpperCase() + id.slice(1),
  price_cents: i * 800,
  prices: i ? [{ interval: 'month', currency: 'usd', unit_amount: i * 800 }] : [],
  per_seat: i > 0,
  limits,
}))

async function mountAt(width: number) {
  Object.defineProperty(window, 'innerWidth', { value: width, configurable: true })
  vi.mocked(api.get).mockImplementation(async (url: string) => {
    if (url === '/stripe/plans') return plans as never
    throw new Error(`unexpected ${url}`)
  })
  const w = mount(BillingView, {
    global: { plugins: [createVuetify({ components, directives })], mocks: { $route: { query: {} } } },
  })
  await flushPromises()
  return w
}

const limitTitles = (card: ReturnType<typeof mount>) =>
  card.findAll('.v-list-item-title').map((t) => t.text())

beforeEach(() => {
  setActivePinia(createPinia())
  vi.clearAllMocks()
})

afterEach(() => {
  Object.defineProperty(window, 'innerWidth', { value: realWidth, configurable: true })
})

describe('the plans on a phone (FR-120 P4)', () => {
  it('shows three limits a plan, and the other six on a tap', async () => {
    const w = await mountAt(360)
    const card = w.get('[data-testid="plan-card-pro"]')
    expect(limitTitles(card as never)).toEqual(['Users', 'Devices', 'Remote sessions at a time'])
    const toggle = card.get('[data-testid="plan-limits-pro"]')
    expect(toggle.attributes('aria-expanded')).toBe('false')
    await toggle.trigger('click')
    expect(limitTitles(w.get('[data-testid="plan-card-pro"]') as never)).toHaveLength(9)
    expect(w.get('[data-testid="plan-limits-pro"]').attributes('aria-expanded')).toBe('true')
    // Each plan opens on its own.
    expect(limitTitles(w.get('[data-testid="plan-card-business"]') as never)).toHaveLength(3)
  })
})

describe('the plans on a wider screen', () => {
  it('keeps all nine limits, with no toggle', async () => {
    const w = await mountAt(1300)
    const card = w.get('[data-testid="plan-card-pro"]')
    expect(limitTitles(card as never)).toHaveLength(9)
    expect(w.find('[data-testid="plan-limits-pro"]').exists()).toBe(false)
  })
})
