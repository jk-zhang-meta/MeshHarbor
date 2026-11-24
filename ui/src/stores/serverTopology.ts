// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api, ApiError } from '@/api/client'
import type { MeshEdgeEnd } from '@/utils/mesh'

// Matches `GET /api/tenant/{tenant_id}/network-zones/backbone`
// (`crates/modules/network/src/routes/network_zones.rs`, FR-137).

export type CrossZoneMode = 'direct_preferred' | 'router_only'

export interface BackboneZoneView {
  id: string
  name: string
  is_centre: boolean
  is_default: boolean
  cross_zone_mode: CrossZoneMode
  auto_countries: string[]
  gateway_relay_ids: string[]
  device_count: number
}

export interface BackboneGatewayView {
  agent_id: string
  name: string
  online: boolean
  os: string
  agent_version: string
  last_seen_at: string
  country_code?: string | null
  country?: string | null
  region?: string | null
  city?: string | null
  relay_home?: string | null
  public_ip?: string | null
  zone_ids: string[]
  is_centre: boolean
  serving_relay: boolean
  entry_listening: boolean
  entry_port?: number | null
  entry_device_count: number
}

export interface BackboneLinkView {
  from_agent_id: string
  to_agent_id: string
  carrier: string
  rtt_ms?: number | null
  stalled: boolean
  reports: number
  cross_zone: boolean
  ends: MeshEdgeEnd[]
}

export interface ZoneBackboneResponse {
  revision: number
  zones: BackboneZoneView[]
  gateways: BackboneGatewayView[]
  links: BackboneLinkView[]
}

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

function isEndpointUnavailableError(e: unknown): boolean {
  if (e instanceof ApiError) {
    return e.status === 404 || e.status === 405 || e.status === 501
  }
  const status = (e as { status?: number } | null)?.status
  return status === 404 || status === 405 || status === 501
}

export const useServerTopologyStore = defineStore('serverTopology', () => {
  const revision = ref(0)
  const zones = ref<BackboneZoneView[]>([])
  const gateways = ref<BackboneGatewayView[]>([])
  const links = ref<BackboneLinkView[]>([])
  const loading = ref(false)
  const error = ref<string | null>(null)
  /** True when the connected backend does not yet expose `/network-zones/backbone` (404/501). */
  const unavailable = ref(false)

  async function fetchBackbone(tenantId: string) {
    loading.value = true
    error.value = null
    unavailable.value = false
    try {
      const res = await api.get<ZoneBackboneResponse>(
        `/tenant/${tenantId}/network-zones/backbone`,
      )
      revision.value = res?.revision ?? 0
      zones.value = Array.isArray(res?.zones) ? res.zones : []
      gateways.value = Array.isArray(res?.gateways) ? res.gateways : []
      links.value = Array.isArray(res?.links) ? res.links : []
    } catch (e) {
      if (isEndpointUnavailableError(e)) {
        // Graceful fallback when UI runs ahead of the server release batch.
        revision.value = 0
        zones.value = []
        gateways.value = []
        links.value = []
        unavailable.value = true
      } else {
        error.value = message(e)
      }
    } finally {
      loading.value = false
    }
  }

  return {
    revision,
    zones,
    gateways,
    links,
    loading,
    error,
    unavailable,
    fetchBackbone,
    fetchTopology: fetchBackbone,
  }
})

export const useZoneBackboneStore = useServerTopologyStore
