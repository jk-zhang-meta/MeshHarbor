// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

vi.mock('@/api/client', () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() },
}))

import { stateColor, useNetInventoryStore, type InventorySummary } from '@/stores/netInventory'
import { api } from '@/api/client'

const mockApi = vi.mocked(api)
const TENANT_ID = '69a1dbbad2000f26adc875ce'
const AGENT_ID = '6a6f4a76719fbb3fcc7f8102'

function section(state: InventorySummary['routes']['state'], total: number, reported = total) {
  return { state, total, reported }
}

function mkSummary(over: Partial<InventorySummary> = {}): InventorySummary {
  return {
    agent_id: AGENT_ID,
    received_at: '2026-10-25T07:00:00Z',
    fresh: true,
    stale_after_secs: 900,
    observed_at_ms: 1792900000000,
    os: 'linux',
    namespaces: 'host_only',
    interfaces: section('complete', 8),
    routes: section('partial', 5000, 4096),
    rules: section('complete', 23),
    listeners: section('denied', 0),
    firewall_chains: section('unsupported', 0),
    firewall_rules: section('unsupported', 0),
    ...over,
  }
}

beforeEach(() => {
  setActivePinia(createPinia())
  vi.clearAllMocks()
})

describe('netInventory store', () => {
  it('lists the tenant summaries', async () => {
    mockApi.get.mockResolvedValue({ items: [mkSummary()] })
    const store = useNetInventoryStore()
    await store.fetchList(TENANT_ID)
    expect(mockApi.get).toHaveBeenCalledWith(`/tenant/${TENANT_ID}/net-inventory`)
    expect(store.items).toHaveLength(1)
    expect(store.items[0].routes).toEqual({ state: 'partial', total: 5000, reported: 4096 })
    expect(store.error).toBeNull()
  })

  it('keeps a failed list as an error, not an empty fleet', async () => {
    mockApi.get.mockRejectedValue(new Error('403 Forbidden'))
    const store = useNetInventoryStore()
    await store.fetchList(TENANT_ID)
    expect(store.error).toBe('403 Forbidden')
    expect(store.loading).toBe(false)
  })

  it('fetches one node in full, keyed by agent', async () => {
    mockApi.get.mockResolvedValue({ ...mkSummary(), inventory: { os: 'linux' } })
    const store = useNetInventoryStore()
    await store.fetchDetail(TENANT_ID, AGENT_ID)
    expect(mockApi.get).toHaveBeenCalledWith(`/tenant/${TENANT_ID}/net-inventory/${AGENT_ID}`)
    expect(store.details[AGENT_ID].inventory.os).toBe('linux')
  })

  it('only a complete section reads as the whole picture', () => {
    expect(stateColor('complete')).toBe('success')
    expect(stateColor('partial')).toBe('warning')
    expect(stateColor('error')).toBe('error')
    expect(stateColor('denied')).toBe('grey')
    expect(stateColor('unsupported')).toBe('grey')
  })
})
