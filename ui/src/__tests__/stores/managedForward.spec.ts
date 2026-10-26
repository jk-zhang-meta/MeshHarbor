// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

vi.mock('@/api/client', () => {
  class ApiError extends Error {
    constructor(
      public status: number,
      public data: unknown,
    ) {
      super((data as Record<string, string> | null)?.message || `API error ${status}`)
    }
  }
  return { api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() }, ApiError }
})

import {
  endpoint,
  useManagedForwardStore,
  verifiedColor,
  type ForwardView,
  type Plan,
} from '@/stores/managedForward'
import { api, ApiError } from '@/api/client'

const mockApi = vi.mocked(api)
const TENANT_ID = '69a1dbbad2000f26adc875ce'
const BASE = `/tenant/${TENANT_ID}/managed-forward`

function mkForward(over: Partial<ForwardView> = {}): ForwardView {
  return {
    id: '6adea4826f54090126229c55',
    revision: 2,
    spec: {
      name: 'db',
      ingress_agent_id: '6adea3706f54090126229c52',
      bind_addr: '100.64.0.2',
      port: 15432,
      proto: 'tcp',
      sources: ['100.64.0.0/10'],
      dest_agent_id: null,
      dest_addr: '10.0.0.5',
      dest_port: 5432,
      nat: 'masquerade',
      backend: 'nft',
      desired: 'enabled',
    },
    status: { desired: 'enabled', applied: 'applied', verified: 'verified' },
    created_at: '2026-10-26T00:53:23Z',
    updated_at: '2026-10-26T00:55:16Z',
    ...over,
  }
}

const refused: Plan = {
  ok: false,
  backend: 'nft',
  checks: [
    {
      name: 'ip forwarding',
      verdict: 'fail',
      detail: 'net.ipv4.ip_forward is off on the ingress; MeshHarbor reports it and does not change it',
    },
  ],
}

beforeEach(() => {
  setActivePinia(createPinia())
  vi.clearAllMocks()
})

describe('managedForward store', () => {
  it('lists, and a fetch failure lands in error', async () => {
    const store = useManagedForwardStore()
    mockApi.get.mockResolvedValueOnce({ items: [mkForward()] })
    await store.fetchList(TENANT_ID)
    expect(mockApi.get).toHaveBeenCalledWith(BASE)
    expect(store.items).toHaveLength(1)
    mockApi.get.mockRejectedValueOnce(new Error('boom'))
    await store.fetchList(TENANT_ID)
    expect(store.error).toBe('boom')
  })

  it('a refused create returns the plan and stores nothing', async () => {
    const store = useManagedForwardStore()
    mockApi.post.mockRejectedValueOnce(new ApiError(422, { forward: null, plan: refused }))
    const out = await store.create(TENANT_ID, mkForward().spec)
    expect(out).toEqual({ kind: 'refused', plan: refused })
    expect(store.items).toHaveLength(0)
  })

  it('an update names the revision it read; a stale one reloads the list', async () => {
    const store = useManagedForwardStore()
    const cur = mkForward()
    store.items = [cur]
    mockApi.put.mockResolvedValueOnce({ forward: mkForward({ revision: 3 }), plan: { ok: true, checks: [], backend: 'nft' } })
    const ok = await store.setDesired(TENANT_ID, cur, 'disabled')
    expect(mockApi.put).toHaveBeenCalledWith(`${BASE}/${cur.id}`, {
      expected_revision: 2,
      spec: { ...cur.spec, desired: 'disabled' },
    })
    expect(ok.kind).toBe('ok')
    expect(store.items[0]!.revision).toBe(3)

    mockApi.put.mockRejectedValueOnce(new ApiError(409, { error: 'Conflict', message: 'stale revision' }))
    mockApi.get.mockResolvedValueOnce({ items: [mkForward({ revision: 4 })] })
    const stale = await store.update(TENANT_ID, cur, cur.spec)
    expect(stale).toEqual({ kind: 'conflict', message: 'stale revision' })
    expect(mockApi.get).toHaveBeenCalledWith(BASE)
    expect(store.items[0]!.revision).toBe(4)
  })

  it('remove sends the expected revision and drops the row', async () => {
    const store = useManagedForwardStore()
    const cur = mkForward()
    store.items = [cur]
    mockApi.delete.mockResolvedValueOnce(undefined)
    expect(await store.remove(TENANT_ID, cur)).toBeNull()
    expect(mockApi.delete).toHaveBeenCalledWith(`${BASE}/${cur.id}?expected_revision=2`)
    expect(store.items).toHaveLength(0)
  })

  it('formats endpoints and layer colours', () => {
    expect(endpoint('10.0.0.5', 80)).toBe('10.0.0.5:80')
    expect(endpoint('fd00::5', 443)).toBe('[fd00::5]:443')
    expect(verifiedColor('verified')).toBe('success')
    expect(verifiedColor('drift')).toBe('error')
    expect(verifiedColor('unverified')).toBe('grey')
  })
})
