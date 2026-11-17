// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { ref } from 'vue'
import { defineStore } from 'pinia'
import { api } from '@/api/client'
import { useTenantStore } from '@/stores/tenant'
import { canManageRelays } from '@/utils/permissions'
import type { AgentStatusValue } from '@/stores/agents'

export type PeerRelayMode = 'off' | 'warn' | 'on' | 'auto'

export interface PeerRelayBackboneEdge {
  relay_agent_id: string
  endpoint: string
  cross_border?: boolean
}

export interface PeerRelayPolicy {
  serve: boolean
  static_endpoints: string[]
  approved_backbone_edges: PeerRelayBackboneEdge[]
}

export interface RelayDeviceView {
  id: string
  name: string
  status: AgentStatusValue
  serving: boolean
  static_endpoints: string[]
  approved_backbone_edges?: PeerRelayBackboneEdge[]
  country_code?: string | null
  pinned_zone_id?: string | null
  effective_zone_id?: string | null
  effective_zone_name?: string | null
  auto_zone_hint?: { zone_id: string | null; default_zone_id: string | null }
}

export interface PeerRelaySettings {
  mode: PeerRelayMode
  relays: RelayDeviceView[]
}

export const MAX_PEER_RELAY_BACKBONE_EDGES = 32

/**
 * Admin-only store for organization Peer Relay settings and per-device Relay
 * Node approvals (`GET/PUT /tenant/{tid}/peer-relay` and
 * `PUT /tenant/{tid}/agent/{aid}/peer-relay-policy`).
 *
 * Non-admin callers never issue requests here: `fetchSettings` awaits the
 * caller's membership and checks `canManageRelays` (`ADMINISTRATOR` / owner).
 */
export const usePeerRelaysStore = defineStore('peerRelays', () => {
  const mode = ref<PeerRelayMode | null>(null)
  const relays = ref<RelayDeviceView[]>([])
  const loading = ref(false)
  const error = ref<string | null>(null)

  async function mayManage(tenantId: string): Promise<boolean> {
    const tenants = useTenantStore()
    await tenants.ensureMyMembership(tenantId)
    return canManageRelays(tenants.myPermissions, tenants.isOwner)
  }

  async function fetchSettings(tenantId: string): Promise<PeerRelaySettings | null> {
    if (!(await mayManage(tenantId))) {
      mode.value = null
      relays.value = []
      return null
    }
    loading.value = true
    error.value = null
    try {
      const resp = await api.get<PeerRelaySettings>(`/tenant/${tenantId}/peer-relay`)
      mode.value = resp.mode
      relays.value = resp.relays ?? []
      return resp
    } catch (e) {
      error.value = e instanceof Error ? e.message : 'Failed to load relay settings'
      return null
    } finally {
      loading.value = false
    }
  }

  async function setMode(tenantId: string, nextMode: PeerRelayMode): Promise<PeerRelayMode> {
    if (!(await mayManage(tenantId))) {
      throw new Error('Administrator permission is required to modify relay settings.')
    }
    const resp = await api.put<{ mode: PeerRelayMode }>(`/tenant/${tenantId}/peer-relay`, {
      mode: nextMode,
    })
    mode.value = resp.mode
    return resp.mode
  }

  async function setDevicePolicy(
    tenantId: string,
    agentId: string,
    policy: PeerRelayPolicy,
  ): Promise<PeerRelayPolicy> {
    if (!(await mayManage(tenantId))) {
      throw new Error('Administrator permission is required to modify relay node policy.')
    }
    const payload: {
      serve: boolean
      static_endpoints?: string[]
      approved_backbone_edges?: PeerRelayBackboneEdge[]
    } = {
      serve: policy.serve,
      ...(policy.static_endpoints.length ? { static_endpoints: policy.static_endpoints } : {}),
      ...(policy.approved_backbone_edges.length
        ? {
            approved_backbone_edges: policy.approved_backbone_edges.map((e) => ({
              relay_agent_id: e.relay_agent_id,
              endpoint: e.endpoint,
              ...(e.cross_border ? { cross_border: true } : {}),
            })),
          }
        : {}),
    }
    const saved = await api.put<PeerRelayPolicy>(
      `/tenant/${tenantId}/agent/${agentId}/peer-relay-policy`,
      payload,
    )
    await fetchSettings(tenantId)
    return saved
  }

  function relayForAgent(agentId: string): RelayDeviceView | undefined {
    return relays.value.find((r) => r.id === agentId)
  }

  function syncAgentZone(
    agentId: string,
    zone: {
      pinned_zone_id: string | null
      country_code?: string | null
      effective_zone_id: string | null
      effective_zone_name: string | null
    },
    contradictedAutoCountry = false,
    autoZoneHint?: { zone_id: string | null; default_zone_id: string | null },
  ) {
    const r = relays.value.find((item) => item.id === agentId)
    if (r) {
      r.pinned_zone_id = zone.pinned_zone_id
      if (zone.country_code !== undefined) {
        r.country_code = zone.country_code
      } else if (contradictedAutoCountry) {
        r.country_code = null
      }
      r.auto_zone_hint = autoZoneHint
      r.effective_zone_id = zone.effective_zone_id
      r.effective_zone_name = zone.effective_zone_name
    }
  }

  return {
    mode,
    relays,
    loading,
    error,
    fetchSettings,
    setMode,
    setDevicePolicy,
    relayForAgent,
    syncAgentZone,
  }
})
