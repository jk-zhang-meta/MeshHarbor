// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { ref } from 'vue'
import { defineStore } from 'pinia'
import { api } from '@/api/client'
import { mergeNameSync, type NameSync } from '@/utils/nameSync'

/**
 * The unified devices-grid feed (`GET /tenant/{tid}/device`): agents +
 * tunnel clients as one server-paginated / searched / sorted row set,
 * joined server-side to overlay nodes + the tenant's MagicDNS domain.
 *
 * This store is the grid's ROW SOURCE only. Actions (dialogs, policies,
 * update pushes) keep operating on the full `Agent` objects from
 * `useAgentStore` — the grid looks them up by id when it needs the rich
 * fields (consent selects, codec chips).
 */

export type DevicePresence = 'online' | 'stale' | 'offline'

export interface DeviceRow {
  kind: 'agent' | 'tunnel_client'
  id: string
  owner_user_id: string
  name: string
  name_sync?: NameSync
  display_name?: string
  tags?: string[]
  machine_id: string
  os: string
  version: string
  status: string
  presence: DevicePresence
  is_online: boolean
  last_seen_at: string
  created_at: string
  overlay_ip?: string
  overlay_node_id?: string
  magic_dns_name?: string
  magic_dns_fqdn?: string
  /** FR-40 — the node's overlay (WireGuard) PUBLIC key + epoch, so an operator
   *  can SEE a rotation land. */
  overlay_public_key?: string
  overlay_key_epoch?: number
  /** FR-51 — enrolled as temporary: reaped after silence, removed outright on
   *  a clean stop; a later enrollment is a NEW device. Present only when true. */
  ephemeral?: boolean
}

interface DeviceListResponse {
  items: DeviceRow[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

export interface DeviceFetchOpts {
  page?: number
  perPage?: number
  q?: string
  sort?: string
  dir?: 'asc' | 'desc'
  kind?: 'agent' | 'tunnel_client'
}

export const useDeviceStore = defineStore('devices', () => {
  const items = ref<DeviceRow[]>([])
  const total = ref(0)
  const page = ref(1)
  const perPage = ref(25)
  const totalPages = ref(1)
  const loading = ref(false)
  const error = ref<string | null>(null)
  // Monotonic guard: a slow page-1 response must not clobber page-2 rows.
  let fetchSeq = 0

  async function fetchDevices(tenantId: string, opts: DeviceFetchOpts = {}) {
    loading.value = true
    error.value = null
    const seq = ++fetchSeq
    try {
      const params = new URLSearchParams()
      params.set('page', String(opts.page ?? page.value))
      params.set('per_page', String(opts.perPage ?? perPage.value))
      const q = opts.q?.trim()
      if (q) params.set('q', q)
      if (opts.sort) params.set('sort', opts.sort)
      if (opts.dir) params.set('dir', opts.dir)
      if (opts.kind) params.set('kind', opts.kind)
      const data = await api.get<DeviceListResponse>(
        `/tenant/${tenantId}/device?${params.toString()}`,
      )
      if (seq !== fetchSeq) return // a newer fetch superseded this one
      items.value = data.items.map((incoming) => {
        const current = items.value.find((row) => row.id === incoming.id && row.kind === incoming.kind)
        return current ? mergeNameSync(current, incoming) : incoming
      })
      total.value = data.total
      page.value = data.page
      perPage.value = data.per_page
      totalPages.value = data.total_pages
    } catch (e) {
      if (seq === fetchSeq) error.value = (e as Error).message
      throw e
    } finally {
      if (seq === fetchSeq) loading.value = false
    }
  }

  /** Patch presence in place from the `device:presence` WS event (agents
   *  only — tunnel clients never appear in it). Unknown ids are ignored;
   *  the next fetch converges. */
  function applyPresence(updates?: Array<{ agent_id: string; presence?: DevicePresence }>) {
    if (!updates?.length) return
    for (const u of updates) {
      const row = items.value.find((r) => r.kind === 'agent' && r.id === u.agent_id)
      if (row && u.presence) {
        row.presence = u.presence
        row.is_online = u.presence === 'online'
      }
    }
  }

  /** Merge a fresh row (e.g. from an edit response) into the current page. */
  function patchRow(partial: Partial<DeviceRow> & { id: string }, unverifiedSave = false) {
    const row = items.value.find((r) => r.id === partial.id)
    if (row) {
      if (unverifiedSave) Object.assign(row, partial, { name_sync: undefined })
      else Object.assign(row, mergeNameSync(row, partial))
    }
  }

  return {
    items,
    total,
    page,
    perPage,
    totalPages,
    loading,
    error,
    fetchDevices,
    applyPresence,
    patchRow,
  }
})
