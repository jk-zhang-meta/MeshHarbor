// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// The URL's org wins over the org last picked in this browser — on a deep
// link and a reload too. Before this, only a CHANGE of the route param synced
// the store, so `/tenant/A/…` opened after picking B showed A's data under B's
// name (titles, Settings' workspace name, the switcher) until the user left
// A's pages and came back.
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { nextTick, reactive } from 'vue'
import { createPinia, setActivePinia } from 'pinia'

vi.mock('@/api/client', () => ({ api: { get: vi.fn(), post: vi.fn(), put: vi.fn() } }))

import { useTenantStore } from '@/stores/tenant'
import { useRouteTenantSync } from '@/composables/useRouteTenantSync'

const A = { id: 'aaaaaaaaaaaaaaaaaaaaaaaa', name: 'Org A', slug: 'org-a' }
const B = { id: 'bbbbbbbbbbbbbbbbbbbbbbbb', name: 'Org B', slug: 'org-b' }

type StoreTenant = ReturnType<typeof useTenantStore>['tenants'][number]

describe('useRouteTenantSync', () => {
  beforeEach(() => {
    localStorage.clear()
    setActivePinia(createPinia())
  })

  it('follows the URL when the org list lands after mount (a deep link or a reload)', async () => {
    const store = useTenantStore()
    const route = reactive({ params: { tenantId: A.id } as Record<string, string> })
    useRouteTenantSync(route)
    // fetchTenants(): the list arrives, and `current` is restored from the
    // org last picked in this browser — B.
    store.tenants = [A, B] as StoreTenant[]
    store.current = B as StoreTenant
    await nextTick()
    expect(store.current?.id).toBe(A.id)
    expect(localStorage.getItem('meshharbor-current-tenant')).toBe(A.id)
  })

  it('follows a change of the URL', async () => {
    const store = useTenantStore()
    store.tenants = [A, B] as StoreTenant[]
    const route = reactive({ params: { tenantId: A.id } as Record<string, string> })
    useRouteTenantSync(route)
    await nextTick()
    expect(store.current?.id).toBe(A.id)
    route.params.tenantId = B.id
    await nextTick()
    expect(store.current?.id).toBe(B.id)
  })

  it('leaves the store alone off the org pages, and for an org not in the list', async () => {
    const store = useTenantStore()
    store.tenants = [A, B] as StoreTenant[]
    store.current = B as StoreTenant
    const route = reactive({ params: {} as Record<string, string> })
    useRouteTenantSync(route)
    await nextTick()
    expect(store.current?.id).toBe(B.id)
    route.params.tenantId = 'cccccccccccccccccccccccc'
    await nextTick()
    expect(store.current?.id).toBe(B.id)
  })
})
