// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { watch } from 'vue'
import type { RouteLocationNormalizedLoaded } from 'vue-router'
import { useTenantStore } from '@/stores/tenant'

/**
 * Keep `tenantStore.current` on the org the URL names (`/tenant/:tenantId/…`).
 *
 * The route param wins over the store: every page reads its DATA by the URL's
 * tenant id, while titles, the workspace name in Settings, the org switcher,
 * the caller's permission mask (`fetchMyMembership`) and the socket's
 * tenant-affinity key read `current`. When the two disagree, a page shows one
 * org's data under another org's name.
 *
 * ⚠️ It watches the org LIST as well as the param, and runs at once. On a deep
 * link or a reload the param never changes, and the list arrives after the
 * shell mounts — `fetchTenants()` then sets `current` to the org last picked in
 * this browser (`meshharbor-current-tenant`). A watcher on the param alone never
 * fired in that case, so the page kept the other org's name until the user
 * happened to leave the org's pages and come back.
 */
export function useRouteTenantSync(route: Pick<RouteLocationNormalizedLoaded, 'params'>): void {
  const tenantStore = useTenantStore()
  watch(
    [() => route.params.tenantId, () => tenantStore.tenants],
    ([id]) => {
      if (typeof id !== 'string' || !id || id === tenantStore.current?.id) return
      const t = tenantStore.tenants.find((x) => x.id === id)
      if (t) tenantStore.setCurrent(t)
    },
    { immediate: true },
  )
}
