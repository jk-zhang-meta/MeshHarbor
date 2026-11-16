// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { ref } from 'vue'
import { defineStore } from 'pinia'
import { api } from '@/api/client'
import { useTenantStore } from '@/stores/tenant'
import { canManageRelays } from '@/utils/permissions'

export type CrossZoneMode = 'router_only' | 'direct_preferred'

export interface NetworkZone {
  id: string // lowercase slug e.g. "cn", "non-cn", "siat", "jp"
  name: string // e.g. "CN 区", "非 CN 区"
  auto_countries: string[] // uppercase ISO-3166-1 alpha-2 e.g. ["CN"]
  is_default: boolean // fallback zone for unmatched Auto devices
  gateway_relay_ids: string[] // approved Relay agent IDs acting as this zone's routers
  cross_zone_mode: CrossZoneMode
}

export interface NetworkZonesResponse {
  revision: number
  zones: NetworkZone[]
}

export const ZONE_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{0,31}$/

/** Suggest a clean lowercase zone slug from a human zone name. */
export function suggestZoneSlug(rawName: string, fallbackIndex = 1): string {
  const trimmed = rawName.trim()
  if (!trimmed) return `zone-${fallbackIndex}`
  const lower = trimmed.toLowerCase()
  if (lower.includes('非') && lower.includes('cn')) return 'non-cn'
  const ascii = lower
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 32)
    .replace(/-+$/g, '')
  if (ascii) return ascii
  const knownMap: Array<[string, string]> = [
    ['香港', 'hk'],
    ['澳门', 'mo'],
    ['台湾', 'tw'],
    ['中国', 'cn'],
    ['大陆', 'cn'],
    ['境内', 'cn'],
    ['境外', 'non-cn'],
    ['海外', 'overseas'],
    ['新加坡', 'sg'],
    ['日本', 'jp'],
    ['韩国', 'kr'],
    ['美国', 'us'],
    ['欧洲', 'eu'],
    ['澳洲', 'au'],
    ['深圳', 'sz'],
    ['广州', 'gz'],
    ['北京', 'bj'],
    ['上海', 'sh'],
  ]
  for (const [kw, slug] of knownMap) {
    if (trimmed.includes(kw)) return slug
  }
  return `zone-${fallbackIndex}`
}

/** Classify an approved Relay Node as Mainland China vs Non-Mainland for the one-click CN / Non-CN preset. */
export function isMainlandRelayCandidate(
  relay: { id: string; name: string },
  agent?: { country_code?: string | null; display_name?: string | null } | null,
): boolean {
  const cc = (agent?.country_code ?? '').trim().toUpperCase()
  if (cc === 'CN') return true
  if (/^[A-Z]{2}$/.test(cc) && cc !== 'CN') return false
  const label = `${relay.name} ${agent?.display_name ?? ''}`.toLowerCase()
  if (label.includes('non-cn') || label.includes('non_cn')) return false
  return /(?:^|[-_\s])(?:cn|gz|sz|bj|sh|hz|cd|wh|guangzhou|shenzhen|beijing|shanghai|hangzhou)(?:$|[-_\s0-9])/i.test(
    label,
  )
}

export function buildCnNonCnPreset(
  relays: ReadonlyArray<{ id: string; name: string }>,
  agentsById: ReadonlyMap<string, { country_code?: string | null; display_name?: string | null }>,
  names: { cnName?: string; nonCnName?: string } = {},
): NetworkZone[] {
  const mainlandIds: string[] = []
  const nonMainlandIds: string[] = []
  const seen = new Set<string>()
  for (const r of relays) {
    if (!r.id || seen.has(r.id)) continue
    seen.add(r.id)
    if (isMainlandRelayCandidate(r, agentsById.get(r.id))) {
      mainlandIds.push(r.id)
    } else {
      nonMainlandIds.push(r.id)
    }
  }
  return [
    {
      id: 'cn',
      name: names.cnName ?? 'CN 区',
      auto_countries: ['CN'],
      is_default: false,
      gateway_relay_ids: mainlandIds,
      cross_zone_mode: 'router_only',
    },
    {
      id: 'non-cn',
      name: names.nonCnName ?? '非 CN 区',
      auto_countries: [],
      is_default: true,
      gateway_relay_ids: nonMainlandIds,
      cross_zone_mode: 'router_only',
    },
  ]
}

function normalizeZone(z: NetworkZone): NetworkZone {
  const seenCountries = new Set<string>()
  const auto_countries: string[] = []
  for (const raw of z.auto_countries ?? []) {
    const c = String(raw ?? '')
      .trim()
      .toUpperCase()
    if (/^[A-Z]{2}$/.test(c) && !seenCountries.has(c)) {
      seenCountries.add(c)
      auto_countries.push(c)
    }
  }
  const seenRelays = new Set<string>()
  const gateway_relay_ids: string[] = []
  for (const raw of z.gateway_relay_ids ?? []) {
    const id = String(raw ?? '').trim()
    if (id && !seenRelays.has(id)) {
      seenRelays.add(id)
      gateway_relay_ids.push(id)
    }
  }
  return {
    id: String(z.id ?? '')
      .trim()
      .toLowerCase(),
    name: String(z.name ?? '').trim(),
    auto_countries,
    is_default: Boolean(z.is_default),
    gateway_relay_ids,
    cross_zone_mode: z.cross_zone_mode === 'direct_preferred' ? 'direct_preferred' : 'router_only',
  }
}

/**
 * Store for tenant Logical Network Zones (`GET/PUT /tenant/{tid}/network-zones`).
 *
 * - Reading (`fetchZones`) is permitted for any authenticated member of `tid`
 *   (so ordinary device owners and `MANAGE_AGENTS` operators alike can select
 *   admin-defined zones in `DeviceZoneDialog`; backend redacts `gateway_relay_ids`
 *   for non-administrators).
 * - Writing (`saveZones`) requires `ADMINISTRATOR` / org owner (`canManageRelays`).
 */
export const useNetworkZonesStore = defineStore('networkZones', () => {
  const loadedTenantId = ref<string | null>(null)
  const revision = ref(0)
  const zones = ref<NetworkZone[]>([])
  const loading = ref(false)
  const error = ref<string | null>(null)
  let activeTenantId: string | null = null
  let tenantEpoch = 0
  let fetchSeq = 0
  let activeFetchId = 0
  let putGen = 0
  let minAcceptedRevision = 0

  async function mayRead(tenantId: string): Promise<boolean> {
    if (!tenantId) return false
    const tenants = useTenantStore()
    await tenants.ensureMyMembership(tenantId)
    return tenants.myPermissions !== null || tenants.isOwner
  }

  async function mayWrite(tenantId: string): Promise<boolean> {
    const tenants = useTenantStore()
    await tenants.ensureMyMembership(tenantId)
    return canManageRelays(tenants.myPermissions, tenants.isOwner)
  }

  async function fetchZones(tenantId: string): Promise<NetworkZonesResponse | null> {
    if (activeTenantId !== tenantId) {
      activeTenantId = tenantId
      tenantEpoch += 1
      activeFetchId = 0
      putGen = 0
      minAcceptedRevision = 0
      loadedTenantId.value = null
      revision.value = 0
      zones.value = []
      error.value = null
      loading.value = false
    }
    const myTenantEpoch = tenantEpoch
    const myFetchSeq = ++fetchSeq
    const myPutGen = putGen

    if (!(await mayRead(tenantId))) {
      if (myTenantEpoch === tenantEpoch && activeTenantId === tenantId && myFetchSeq === fetchSeq) {
        activeFetchId = 0
        loadedTenantId.value = null
        revision.value = 0
        zones.value = []
        loading.value = false
      }
      return null
    }
    if (
      myTenantEpoch !== tenantEpoch ||
      activeTenantId !== tenantId ||
      myFetchSeq !== fetchSeq
    ) {
      return null
    }
    activeFetchId = myFetchSeq
    loading.value = true
    error.value = null
    try {
      const resp = await api.get<NetworkZonesResponse>(`/tenant/${tenantId}/network-zones`)
      if (
        myTenantEpoch !== tenantEpoch ||
        activeTenantId !== tenantId ||
        myFetchSeq !== fetchSeq
      ) {
        return loadedTenantId.value === tenantId
          ? { revision: revision.value, zones: zones.value }
          : null
      }
      const incomingRev = resp.revision ?? 0
      const normalized = (resp.zones ?? []).map(normalizeZone)
      if (
        incomingRev < minAcceptedRevision ||
        (myPutGen !== putGen && incomingRev <= minAcceptedRevision)
      ) {
        return loadedTenantId.value === tenantId
          ? { revision: revision.value, zones: zones.value }
          : null
      }
      minAcceptedRevision = Math.max(minAcceptedRevision, incomingRev)
      loadedTenantId.value = tenantId
      error.value = null
      revision.value = incomingRev
      zones.value = normalized
      return { revision: revision.value, zones: zones.value }
    } catch (e) {
      if (
        myTenantEpoch === tenantEpoch &&
        activeTenantId === tenantId &&
        myFetchSeq === fetchSeq
      ) {
        if (!(loadedTenantId.value === tenantId && myPutGen !== putGen)) {
          loadedTenantId.value = null
          revision.value = 0
          zones.value = []
          error.value = e instanceof Error ? e.message : 'Failed to load network zones'
        }
      }
      return null
    } finally {
      if (activeFetchId === myFetchSeq) {
        activeFetchId = 0
        loading.value = false
      }
    }
  }

  async function saveZones(
    tenantId: string,
    nextZones: NetworkZone[],
  ): Promise<NetworkZonesResponse> {
    const myTenantEpoch = tenantEpoch
    if (!(await mayWrite(tenantId))) {
      throw new Error('Administrator permission is required to modify network zones.')
    }
    if (
      myTenantEpoch !== tenantEpoch ||
      activeTenantId !== tenantId ||
      loadedTenantId.value !== tenantId ||
      error.value !== null
    ) {
      throw new Error('Network zones for this organization failed to load; retry loading before saving.')
    }
    const payload = nextZones.map(normalizeZone)
    const resp = await api.put<NetworkZonesResponse>(`/tenant/${tenantId}/network-zones`, {
      zones: payload,
    })
    const normalized = (resp.zones ?? payload).map(normalizeZone)
    const nextRevision = resp.revision ?? Math.max(revision.value, minAcceptedRevision) + 1
    if (myTenantEpoch === tenantEpoch && activeTenantId === tenantId) {
      if (nextRevision >= minAcceptedRevision) {
        minAcceptedRevision = nextRevision
        loadedTenantId.value = tenantId
        error.value = null
        revision.value = nextRevision
        zones.value = normalized
        putGen += 1
        return { revision: revision.value, zones: zones.value }
      }
      if (
        loadedTenantId.value === tenantId &&
        error.value === null &&
        revision.value >= minAcceptedRevision
      ) {
        return { revision: revision.value, zones: zones.value }
      }
      throw new Error(
        error.value ||
          'A newer network zone revision exists on the server; reload network zones before editing.',
      )
    }
    throw new Error('Organization changed while saving network zones.')
  }

  function zoneById(id?: string | null, tenantId?: string): NetworkZone | undefined {
    if (tenantId && loadedTenantId.value !== tenantId) return undefined
    const clean = typeof id === 'string' ? id.trim() : ''
    if (!clean) return undefined
    return zones.value.find((z) => z.id === clean)
  }

  return {
    loadedTenantId,
    revision,
    zones,
    loading,
    error,
    fetchZones,
    saveZones,
    zoneById,
  }
})
