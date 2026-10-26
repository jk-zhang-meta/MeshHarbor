// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api/client'

// Matches `crates/modules/network/src/routes/server_link.rs`. Two devices
// whose central role is Server connect exactly when an ENABLED link names
// them, whatever their business zones (docs/business-isolation.md).

export type BusinessZone = 'mainland' | 'non_mainland'

export interface ServerView {
  agent_id: string
  name: string
  online: boolean
  /** ISO 3166-1 alpha-2 of its last observed connection; null when unknown. */
  country: string | null
  zone: BusinessZone | null
}

export interface LinkView {
  a: string
  b: string
  enabled: boolean
}

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

export const useServerTopologyStore = defineStore('serverTopology', () => {
  const servers = ref<ServerView[]>([])
  const links = ref<LinkView[]>([])
  const loading = ref(false)
  const error = ref<string | null>(null)

  const base = (tenantId: string) => `/tenant/${tenantId}/server-link`

  // Fetches swallow into `error` (stores/role.ts convention).
  async function fetchTopology(tenantId: string) {
    loading.value = true
    error.value = null
    try {
      const res = await api.get<{ servers: ServerView[]; links: LinkView[] }>(base(tenantId))
      servers.value = res.servers
      links.value = res.links
    } catch (e) {
      error.value = message(e)
    } finally {
      loading.value = false
    }
  }

  /** Add, enable or disable the edge a—b. False when the server refused. */
  async function setLink(tenantId: string, a: string, b: string, enabled: boolean) {
    try {
      await api.put(base(tenantId), { a, b, enabled })
      await fetchTopology(tenantId)
      return true
    } catch (e) {
      error.value = message(e)
      return false
    }
  }

  async function removeLink(tenantId: string, a: string, b: string) {
    try {
      await api.delete(`${base(tenantId)}/${a}/${b}`)
      await fetchTopology(tenantId)
      return true
    } catch (e) {
      error.value = message(e)
      return false
    }
  }

  return { servers, links, loading, error, fetchTopology, setLink, removeLink }
})
