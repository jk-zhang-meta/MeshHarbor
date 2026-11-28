<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-container fluid class="pa-2 pa-md-4 pa-xl-6">
    <h1 class="text-h5 text-md-h4 mb-1 mb-md-2">{{ tenantStore.current?.name }}</h1>
    <p class="text-subtitle-2 text-md-subtitle-1 text-medium-emphasis mb-2 mb-md-4">{{ t('mh.dash.overview') }}</p>

    <!-- Fleet tiles: Devices online | Tunnels -->
    <v-row>
      <v-col v-if="caps.has('fleet')" cols="6" sm="6" md="4">
        <v-card :to="showFleet ? `/tenant/${tenantId}/devices` : undefined" :hover="showFleet">
          <v-card-text class="mh-stat">
            <span class="mh-stat__icon"><v-icon size="20">mdi-monitor-multiple</v-icon></span>
            <div class="mh-stat__value">{{ devicesOnlineLabel }}</div>
            <div class="mh-stat__label">{{ t('mh.dash.devicesOnline') }}</div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col v-if="caps.has('network')" cols="6" sm="6" md="4">
        <v-card
          :to="showFleet ? `/tenant/${tenantId}/devices?type=tunnel` : undefined"
          :hover="showFleet"
        >
          <v-card-text class="mh-stat">
            <span class="mh-stat__icon"><v-icon size="20">mdi-lan-pending</v-icon></span>
            <div class="mh-stat__value">{{ tunnelsLabel }}</div>
            <div class="mh-stat__label">{{ t('mh.dash.tunnels') }}</div>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>

    <!-- Insights (stats PR-4): the basic org graph, visible to every member. -->
    <template v-if="statsStore.overview?.enabled">
      <h2 class="text-h6 mt-4 mb-2">{{ t('mh.dash.insights') }}</h2>
      <v-row>
        <v-col cols="12" md="6">
          <v-card>
            <v-card-title class="text-subtitle-1 d-flex align-center">
              {{ t('mh.dash.machinesOnline') }}
              <v-spacer />
              <span class="text-h6">
                {{ statsStore.overview?.machines?.online ?? 0 }}/{{
                  statsStore.overview?.machines?.total ?? 0
                }}
              </span>
            </v-card-title>
            <v-card-text>
              <time-series-chart
                :points="statsStore.overview?.spark_machines ?? []"
                :series="[{ key: 'online', label: t('mh.dash.online') }]"
                :height="140"
                area
                :empty-text="t('mh.dash.noSamples')"
              />
            </v-card-text>
          </v-card>
        </v-col>
      </v-row>
    </template>

    <!-- Overlay mesh: how this org's devices actually reach the control plane and each other. -->
    <template v-if="meshNodes.length">
      <h2 class="text-h6 mt-4 mb-2">{{ t('mh.dash.network') }}</h2>
      <v-card>
        <v-card-text>
          <mesh-graph
            :nodes="meshNodes"
            :edges="meshEdges"
            :center-name="centerName"
            :center-country-code="centerCountryCode"
            @select="onMeshSelect"
          />
        </v-card-text>
      </v-card>
    </template>

    <!-- Manage: every subsystem reachable from the org hub. -->
    <h2 class="text-h6 mt-4 mb-2">{{ t('mh.dash.manage') }}</h2>
    <v-row>
      <v-col v-if="showFleet" cols="12" sm="6" md="3">
        <v-card :to="`/tenant/${tenantId}/devices`" hover>
          <v-card-text>
            <span class="mh-tile-icon mr-3"><v-icon size="18">mdi-monitor-multiple</v-icon></span>
            <span class="text-subtitle-1 font-weight-medium">{{ t('mh.dash.devices') }}</span>
            <div class="text-body-2 text-medium-emphasis mt-1">
              {{ t('mh.dash.devicesHint') }}
            </div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col v-if="showNetwork" cols="12" sm="6" md="3">
        <v-card :to="`/tenant/${tenantId}/network`" hover>
          <v-card-text>
            <span class="mh-tile-icon mr-3"><v-icon size="18">mdi-lan</v-icon></span>
            <span class="text-subtitle-1 font-weight-medium">{{ t('mh.dash.network') }}</span>
            <div class="text-body-2 text-medium-emphasis mt-1">
              {{ t('mh.dash.networkHint') }}
            </div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="12" sm="6" md="3">
        <v-card :to="`/tenant/${tenantId}/admin/members`" hover>
          <v-card-text>
            <span class="mh-tile-icon mr-3"><v-icon size="18">mdi-account-group</v-icon></span>
            <span class="text-subtitle-1 font-weight-medium">{{ t('mh.dash.membersRoles') }}</span>
            <div class="text-body-2 text-medium-emphasis mt-1">
              {{ t('mh.dash.membersHint') }}
            </div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col v-if="canInvite" cols="12" sm="6" md="3">
        <v-card :to="`/tenant/${tenantId}/invites`" hover>
          <v-card-text>
            <span class="mh-tile-icon mr-3"><v-icon size="18">mdi-email-plus</v-icon></span>
            <span class="text-subtitle-1 font-weight-medium">{{ t('mh.dash.invites') }}</span>
            <div class="text-body-2 text-medium-emphasis mt-1">
              {{ t('mh.dash.invitesHint') }}
            </div>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>

<script setup lang="ts">
import { computed, onMounted, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useTenantStore } from '@/stores/tenant'
import { useAgentStore } from '@/stores/agents'
import { useTunnelClientStore } from '@/stores/tunnelClients'
import { useStatsStore } from '@/stores/stats'
import { useCapabilitiesStore } from '@/stores/capabilities'
import { usePolling } from '@/composables/usePolling'
import { canManageInvites, canSeeFleetNav } from '@/utils/permissions'
import TimeSeriesChart from '@/components/stats/TimeSeriesChart.vue'
import MeshGraph, { type MeshNode } from '@/components/stats/MeshGraph.vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const route = useRoute()
const router = useRouter()
const tenantStore = useTenantStore()
const agentStore = useAgentStore()
const tunnelClientStore = useTunnelClientStore()
const statsStore = useStatsStore()
const caps = useCapabilitiesStore()

const tenantId = computed(() => route.params.tenantId as string)
const onlineDevices = computed(() => agentStore.agents.filter((a) => a.is_online).length)
const devicesOnlineLabel = computed(() => {
  const m = statsStore.overview?.machines
  if (m) return `${m.online}/${m.total}`
  return String(onlineDevices.value)
})
const tunnelsLabel = computed(() => {
  const online = tunnelClientStore.clients.filter((c) => c.status === 'online').length
  return `${online}/${tunnelClientStore.total}`
})
const showFleet = computed(
  () => caps.has('fleet') && canSeeFleetNav(tenantStore.myPermissions, tenantStore.isOwner),
)
const showNetwork = computed(() => showFleet.value && caps.has('network'))
const canInvite = computed(() =>
  canManageInvites(tenantStore.myPermissions, tenantStore.isOwner),
)

usePolling(async () => {
  if (!tenantId.value) return
  await statsStore.fetchOverview(tenantId.value)
  await statsStore.fetchMesh(tenantId.value)
}, 60_000)

const meshNodes = computed<MeshNode[]>(() => {
  const m = statsStore.mesh
  if (!m?.nodes) return []
  const meshAgentById = new Map((m.agents ?? []).map((a) => [a.id, a]))
  const fleetAgentById = new Map(agentStore.agents.map((a) => [a.id, a]))
  return m.nodes.map((n) => {
    const meshAgent = n.agent_id_hex ? meshAgentById.get(n.agent_id_hex) : undefined
    const fleetAgent = n.agent_id_hex ? fleetAgentById.get(n.agent_id_hex) : undefined
    const presence =
      fleetAgent?.presence ??
      (meshAgent?.last_presence === 'online'
        ? 'online'
        : meshAgent?.last_presence === 'stale'
          ? 'stale'
          : 'offline')
    const mp = meshAgent?.management_path
    return {
      id: n.id,
      agent_id: n.agent_id_hex ?? null,
      name:
        fleetAgent?.display_name ||
        meshAgent?.display_name ||
        fleetAgent?.name ||
        meshAgent?.name ||
        n.name ||
        n.overlay_ip ||
        n.id.slice(-6),
      online: fleetAgent ? fleetAgent.is_online : meshAgent?.last_presence === 'online',
      presence,
      relay_home: fleetAgent?.relay_home ?? meshAgent?.relay_home ?? n.relay_home ?? null,
      version: fleetAgent?.agent_version ?? meshAgent?.agent_version ?? null,
      os: fleetAgent?.os ?? meshAgent?.os ?? null,
      last_seen_at: fleetAgent?.last_seen_at ?? n.last_seen_at ?? null,
      overlay_ip: n.overlay_ip ?? null,
      public_ip: showFleet.value ? (fleetAgent?.public_ip ?? null) : null,
      physical_public_ip: showFleet.value ? (fleetAgent?.physical_public_ip ?? null) : null,
      country_code: fleetAgent?.country_code ?? null,
      country: fleetAgent?.country ?? null,
      region: fleetAgent?.region ?? null,
      city: fleetAgent?.city ?? null,
      lat: fleetAgent?.lat ?? null,
      lon: fleetAgent?.lon ?? null,
      accuracy_radius_km: fleetAgent?.accuracy_radius_km ?? null,
      geo_level: fleetAgent?.geo_level ?? null,
      zone_id: fleetAgent?.effective_zone_id ?? fleetAgent?.pinned_zone_id ?? null,
      zone_name: fleetAgent?.effective_zone_name ?? null,
      zone_pinned: Boolean(fleetAgent?.pinned_zone_id),
      is_gateway: Boolean(fleetAgent?.peer_relay_policy?.serve),
      management_path: mp
        ? { mode: mp.mode, gatewayName: mp.gateway_name ?? null, entries: mp.entries }
        : null,
    }
  })
})
const meshEdges = computed(() => statsStore.mesh?.edges ?? [])
const centerName = computed(() => statsStore.mesh?.center?.name ?? 'meshharbor.itachi.fans')
const centerCountryCode = computed(() => statsStore.mesh?.center?.country_code ?? null)

function onMeshSelect(nodeId: string) {
  const agentHex = statsStore.mesh?.nodes?.find((n) => n.id === nodeId)?.agent_id_hex
  if (agentHex && showFleet.value) {
    router.push(`/tenant/${tenantId.value}/devices`)
  }
}
watch(tenantId, (tid) => {
  if (tid) void statsStore.fetchOverview(tid)
})

onMounted(() => {
  if (tenantId.value) {
    if (showFleet.value) {
      agentStore.fetchAgents(tenantId.value).catch(() => {})
      if (caps.has('network')) tunnelClientStore.fetchTunnelClients(tenantId.value)
    }
  }
})
</script>
