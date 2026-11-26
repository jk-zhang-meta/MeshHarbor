// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import {
  cardExportCmd,
  cardFaultReasons,
  cardHasFault,
  cardHasWarning,
  cardRuntimeKind,
  hostHasFault,
  isCardEligibleFree,
  type GpuCardView,
  type GpuHostView,
} from '@/api/gpu'
import { useGpuStore } from '@/stores/gpu'

vi.mock('@/api/client', () => ({
  api: {
    get: vi.fn(),
    put: vi.fn(),
    post: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
  },
}))

import { api } from '@/api/client'

function makeCard(overrides: Partial<GpuCardView> = {}): GpuCardView {
  return {
    uuid: 'GPU-0001',
    idx: 0,
    name: 'NVIDIA A100-SXM4-80GB',
    state: 'free',
    mem_used_mb: 128,
    mem_total_mb: 81920,
    util_pct: 0,
    procs_state: 'ok',
    procs: [],
    ...overrides,
  }
}

function makeHost(overrides: Partial<GpuHostView> = {}): GpuHostView {
  return {
    agent_id: 'aid-1',
    name: 'gpu-node-01',
    os: 'linux',
    source: 'org',
    is_online: true,
    freshness: 'fresh',
    status: 'ok',
    backend: 'nvml',
    interval_ms: 2000,
    free_count: 1,
    busy_count: 0,
    held_idle_count: 0,
    total_count: 1,
    gpus: [makeCard()],
    ...overrides,
  }
}

describe('FR-139 canonical GPU fault, runtime, and free-eligibility helpers', () => {
  it('never classifies routine power_cap as a fault or warning', () => {
    const g = makeCard({ throttle: ['power_cap', 'sync_boost'] })
    expect(cardFaultReasons(g)).toEqual([])
    expect(cardHasFault(g)).toBe(false)
    expect(cardHasWarning(g)).toBe(false)
  })

  it('distinguishes warning reasons (thermal, app Xid 31, Ascend Warning) from critical faults (Xid 79, ECC, remap_pending, lost)', () => {
    expect(cardHasFault(makeCard({ throttle: ['thermal'] }))).toBe(false)
    expect(cardHasWarning(makeCard({ throttle: ['thermal'] }))).toBe(true)

    expect(cardHasFault(makeCard({ xid_errors: [31] }))).toBe(false)
    expect(cardHasWarning(makeCard({ xid_errors: [31] }))).toBe(true)

    expect(cardHasFault(makeCard({ xid_errors: [79] }))).toBe(true)
    expect(cardHasFault(makeCard({ ecc_uncorrected: 1 }))).toBe(true)
    expect(cardHasFault(makeCard({ remap_pending: true }))).toBe(true)
    expect(cardHasFault(makeCard({ lost: true }))).toBe(true)

    const ascendWarn = makeCard({ uuid: 'ASCEND-0-0', vendor_health: 'Warning' })
    expect(cardHasFault(ascendWarn)).toBe(false)
    expect(cardHasWarning(ascendWarn)).toBe(true)

    const ascendCrit = makeCard({ uuid: 'ASCEND-0-0', vendor_health: 'Critical' })
    expect(cardHasFault(ascendCrit)).toBe(true)
  })

  it('includes driver_missing online hosts in hostHasFault and excludes offline hosts', () => {
    const missing = makeHost({ status: 'driver_missing', host_fault_severity: 'critical', gpus: [] })
    expect(hostHasFault(missing)).toBe(true)

    const offline = makeHost({ is_online: false, freshness: 'offline', gpus: [makeCard({ lost: true })] })
    expect(hostHasFault(offline)).toBe(false)
  })

  it('blocks lagging/stale/presence-only/faulted cards from free eligibility and uses Ascend vendor_index', () => {
    const okHost = makeHost()
    expect(isCardEligibleFree(okHost, okHost.gpus[0])).toBe(true)

    const lagHost = makeHost({ lagging: true })
    expect(isCardEligibleFree(lagHost, lagHost.gpus[0])).toBe(false)

    const staleHost = makeHost({ freshness: 'stale' })
    expect(isCardEligibleFree(staleHost, staleHost.gpus[0])).toBe(false)

    const tpuCard = makeCard({ uuid: 'TPU-0000:00:04.0', backend: 'tpu', presence_only: true })
    expect(cardRuntimeKind(okHost, tpuCard)).toBe('tpu')
    expect(isCardEligibleFree(okHost, tpuCard)).toBe(false)
    expect(cardExportCmd(okHost, tpuCard)).toBeNull()

    const ascendCard = makeCard({ uuid: 'ASCEND-2-deadbeef', backend: 'ascend', idx: 6, vendor_index: 2 })
    expect(cardExportCmd(okHost, ascendCard)).toBe("export ASCEND_RT_VISIBLE_DEVICES='2'")
  })
})

describe('useGpuStore live changes, error persistence, and 503 vs 404', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  it('does not mark GPU monitoring disabled on transient 503 (only 404) and tracks live card deltas', async () => {
    const store = useGpuStore()
    const baseResp = {
      hosts: [
        makeHost({
          seq: 1,
          received_at_ms: 1000,
          gpus: [makeCard({ state: 'busy', util_pct: 40, mem_used_mb: 10240 })],
        }),
      ],
      summary: { hosts_total: 1, hosts_online: 1, gpus_total: 1, gpus_free: 0, gpus_busy: 1, gpus_held_idle: 0, gpus_fault: 0 },
      server_time_ms: 2000,
      live_interval_ms: 2000,
    }
    vi.mocked(api.get).mockResolvedValueOnce(baseResp)
    await store.refreshFleet('t1', true)
    expect(store.recentChanges).toHaveLength(0)

    // Next frame advances seq -> card becomes free + util drops 40% -> records delta and change!
    vi.mocked(api.get).mockResolvedValueOnce({
      ...baseResp,
      hosts: [
        makeHost({
          seq: 2,
          received_at_ms: 3000,
          gpus: [makeCard({ state: 'free', util_pct: 0, mem_used_mb: 128 })],
        }),
      ],
      server_time_ms: 4000,
    })
    await store.refreshFleet('t1', true)
    expect(store.cardDeltas['aid-1:GPU-0001']?.utilDelta).toBe(-40)
    expect(store.recentChanges[0]?.kind).toBe('card_state')
    expect(store.recentChanges[0]?.to).toBe('free')

    // Transient 503 sets error without flipping disabled = true
    vi.mocked(api.get).mockRejectedValueOnce(Object.assign(new Error('Service Unavailable'), { status: 503 }))
    await store.refreshFleet('t1', true)
    expect(store.disabled).toBe(false)
    expect(store.error).toContain('Service Unavailable')

    // 404 flips disabled = true
    vi.mocked(api.get).mockRejectedValueOnce(Object.assign(new Error('Not Found'), { status: 404 }))
    await store.refreshFleet('t1', true)
    expect(store.disabled).toBe(true)
  })
})
