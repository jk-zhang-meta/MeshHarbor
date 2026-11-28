// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { api } from '@/api/client'

/** One org's unread slice from `GET /api/user/unread-summary`. */
export interface OrgUnreadSummary {
  tenant_id: string
  name: string
  notifications: number
  consents: number
}

/**
 * P4 — per-org activity badges for the org switcher.
 *
 * Two layers:
 *  - `summaries` — server truth from `/api/user/unread-summary`, refetched
 *    (debounced) on mount, `ws:reconnected`, switcher open and org switch.
 *  - live deltas — ws.ts routes events carrying a NON-active `tenant_id`
 *    here (`notification:new`, `device:presence`) so the
 *    badge moves in realtime between fetches. `deviceEvents` counts
 *    offline/stale transitions noticed while the user was parked on another
 *    org; it clears when they visit that org (it's an attention marker, not
 *    server state).
 *
 * There is no event replay in this app — a summary refetch is always the
 * convergence path; deltas only bridge the gap between fetches.
 */
export const useOrgBadgesStore = defineStore('orgBadges', () => {
  const summaries = ref<Record<string, OrgUnreadSummary>>({})
  const deviceEvents = ref<Record<string, number>>({})

  function ensure(tenantId: string): OrgUnreadSummary {
    let s = summaries.value[tenantId]
    if (!s) {
      s = {
        tenant_id: tenantId,
        name: '',
        notifications: 0,
        consents: 0,
      }
      summaries.value[tenantId] = s
    }
    return s
  }

  let fetchTimer: ReturnType<typeof setTimeout> | null = null
  let inflight: Promise<void> | null = null

  async function fetchSummaryNow() {
    try {
      const data = await api.get<{ tenants: OrgUnreadSummary[] }>('/user/unread-summary')
      const next: Record<string, OrgUnreadSummary> = {}
      for (const t of data.tenants) next[t.tenant_id] = t
      summaries.value = next
    } catch {
      // Non-critical: keep the last known badges.
    } finally {
      inflight = null
    }
  }

  /** Debounced refetch (2 s trailing) — reconnects and switcher opens can
   *  cluster, and the summary endpoint scans unread state per org. */
  function fetchSummary() {
    if (fetchTimer) clearTimeout(fetchTimer)
    fetchTimer = setTimeout(() => {
      fetchTimer = null
      inflight = inflight ?? fetchSummaryNow()
    }, 2000)
  }

  /** A `notification:new` for a non-active org. */
  function noteForeignNotification(tenantId: string, notificationType?: string) {
    const s = ensure(tenantId)
    s.notifications++
    if (notificationType === 'consent_request') s.consents++
  }

  /** `device:presence` transitions: offline/stale bump the attention dot
   *  (for any org — the active org's dot just never renders). */
  function noteDevicePresence(tenantId: string, agents: Array<{ presence: string }>) {
    const drops = agents.filter((a) => a.presence === 'offline' || a.presence === 'stale').length
    if (drops > 0) {
      deviceEvents.value[tenantId] = (deviceEvents.value[tenantId] || 0) + drops
    }
  }

  /** Visiting an org acknowledges its device-attention dot and re-syncs. */
  function clearForTenant(tenantId: string) {
    deviceEvents.value[tenantId] = 0
    fetchSummary()
  }

  /** Numeric badge for one org's switcher row (notifications). */
  function badgeCount(tenantId: string): number {
    const s = summaries.value[tenantId]
    if (!s) return 0
    return s.notifications
  }

  function hasDeviceEvents(tenantId: string): boolean {
    return (deviceEvents.value[tenantId] || 0) > 0
  }

  /** Whether ANY org except `activeTenantId` has activity (dot on the
   *  collapsed switcher activator). */
  const anyForeignActivity = computed(() => (activeTenantId: string | null) => {
    for (const [tid, s] of Object.entries(summaries.value)) {
      if (tid === activeTenantId) continue
      if (s.notifications > 0) return true
    }
    for (const [tid, n] of Object.entries(deviceEvents.value)) {
      if (tid === activeTenantId) continue
      if (n > 0) return true
    }
    return false
  })

  return {
    summaries,
    deviceEvents,
    fetchSummary,
    fetchSummaryNow,
    noteForeignNotification,
    noteDevicePresence,
    clearForTenant,
    badgeCount,
    hasDeviceEvents,
    anyForeignActivity,
  }
})
