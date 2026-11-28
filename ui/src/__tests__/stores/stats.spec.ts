// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

vi.mock('@/api/client', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
}))

import { api } from '@/api/client'
import { useStatsStore } from '@/stores/stats'

const mockApi = api as unknown as { get: ReturnType<typeof vi.fn> }

describe('stats store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  it('fetchOverview caches the payload and hits the tenant path', async () => {
    const payload = {
      enabled: true,
      machines: { online: 2, total: 5 },
      spark_machines: [{ t: 1_700_000_000, online: 2 }],
    }
    mockApi.get.mockResolvedValueOnce(payload)
    const store = useStatsStore()
    const out = await store.fetchOverview('t1')
    expect(mockApi.get).toHaveBeenCalledWith('/tenant/t1/stats/overview')
    expect(out).toEqual(payload)
    expect(store.overview?.machines?.online).toBe(2)
  })

  it('fetchOverview swallows errors into null (404 = hidden panel, never a throw into the dashboard)', async () => {
    mockApi.get.mockRejectedValueOnce(new Error('HTTP 404'))
    const store = useStatsStore()
    const out = await store.fetchOverview('t1')
    expect(out).toBeNull()
    expect(store.overview).toBeNull()
    expect(store.error).toContain('404')
  })

  it('range queries interpolate query params per client convention', async () => {
    mockApi.get.mockResolvedValue({ enabled: true, series: [] })
    const store = useStatsStore()
    await store.fetchMachines('t1', '7d')
    expect(mockApi.get).toHaveBeenCalledWith('/tenant/t1/stats/machines?range=7d')
    await store.fetchTunnels('t1', '30d')
    expect(mockApi.get).toHaveBeenCalledWith('/tenant/t1/stats/tunnels?range=30d')
    await store.fetchRelayHistory('us-east', '24h')
    expect(mockApi.get).toHaveBeenCalledWith('/admin/stats/relay/history?region=us-east&range=24h')
    await store.fetchAdminMachines('t9', '1y')
    expect(mockApi.get).toHaveBeenCalledWith('/admin/stats/machines?tenant_id=t9&range=1y')
  })

  it('fetchRelayCurrent caches for the realtime poll', async () => {
    const payload = {
      enabled: true,
      regions: [{ id: 'us-east', enabled: true, monitored: true, busy: false }],
    }
    mockApi.get.mockResolvedValueOnce(payload)
    const store = useStatsStore()
    await store.fetchRelayCurrent()
    expect(mockApi.get).toHaveBeenCalledWith('/admin/stats/relay/current')
    expect(store.relayCurrent?.regions?.[0]?.id).toBe('us-east')
  })
})
