// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api/client'

// Matches `crates/remote_control/src/net_inventory.rs` and the responses in
// `crates/modules/network/src/routes/net_inventory.rs` (MeshHarbor #19).
// Everything here is REPORTED configuration: what a node read from its own
// kernel. It is not an observed flow, a desired state or an ACL grant.

export type SectionState = 'complete' | 'partial' | 'unsupported' | 'denied' | 'error'

export interface SectionSummary {
  state: SectionState
  total: number
  reported: number
}

export interface Section<T> {
  state: SectionState
  total: number
  items: T[]
  note?: string
}

export interface NetInterface {
  name: string
  index: number
  kind?: string
  up: boolean
  mtu?: number
  addrs: string[]
}

export interface NetRoute {
  family: 'v4' | 'v6'
  table: string
  dst: string
  kind: string
  gateway?: string
  dev?: string
  protocol?: string
  metric?: number
}

export interface NetRule {
  family: 'v4' | 'v6'
  priority: number
  selector: string
  action: string
}

export interface NetListener {
  proto: 'tcp' | 'udp'
  addr: string
  port: number
  process?: string
}

export type FirewallOwner =
  | 'meshharbor'
  | 'docker'
  | 'firewalld'
  | 'fail2ban'
  | 'libvirt'
  | 'kubernetes'
  | 'unknown'

export interface FirewallChain {
  backend: string
  family: string
  table: string
  name: string
  hook?: string
  chain_type?: string
  priority?: number
  policy?: string
  owner: FirewallOwner
}

export interface FirewallRule {
  backend: string
  family: string
  table: string
  chain: string
  handle?: number
  matches: string
  verdict: string
  target?: string
  packets?: number
  bytes?: number
  owner: FirewallOwner
}

export interface NetInventory {
  os: string
  namespaces: string
  forwarding: { ipv4?: boolean; ipv6?: boolean }
  interfaces: Section<NetInterface>
  routes: Section<NetRoute>
  rules: Section<NetRule>
  listeners: Section<NetListener>
  firewall_chains: Section<FirewallChain>
  firewall_rules: Section<FirewallRule>
}

export const SECTIONS = [
  'interfaces',
  'routes',
  'rules',
  'listeners',
  'firewall_chains',
  'firewall_rules',
] as const
export type SectionName = (typeof SECTIONS)[number]

export type InventorySummary = {
  agent_id: string
  received_at: string
  /** The server's verdict: received inside its freshness window. */
  fresh: boolean
  stale_after_secs: number
  observed_at_ms: number
  os: string
  namespaces: string
} & Record<SectionName, SectionSummary>

export type InventoryDetail = InventorySummary & { inventory: NetInventory }

/** Vuetify colour for a section state: only `complete` is the whole picture. */
export function stateColor(s: SectionState): string {
  switch (s) {
    case 'complete':
      return 'success'
    case 'partial':
      return 'warning'
    case 'error':
      return 'error'
    default:
      return 'grey'
  }
}

export const useNetInventoryStore = defineStore('netInventory', () => {
  const items = ref<InventorySummary[]>([])
  const details = ref<Record<string, InventoryDetail>>({})
  const loading = ref(false)
  const error = ref<string | null>(null)

  // Fetches swallow into `error` (stores/role.ts convention).
  async function fetchList(tenantId: string) {
    loading.value = true
    error.value = null
    try {
      const res = await api.get<{ items: InventorySummary[] }>(`/tenant/${tenantId}/net-inventory`)
      items.value = res.items
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e)
    } finally {
      loading.value = false
    }
  }

  async function fetchDetail(tenantId: string, agentId: string) {
    try {
      details.value[agentId] = await api.get<InventoryDetail>(
        `/tenant/${tenantId}/net-inventory/${agentId}`,
      )
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e)
    }
  }

  return { items, details, loading, error, fetchList, fetchDetail }
})
