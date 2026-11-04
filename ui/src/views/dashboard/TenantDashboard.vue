<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-container fluid class="pa-2 pa-md-4 pa-xl-6">
    <h1 class="text-h5 text-md-h4 mb-1 mb-md-2">{{ tenantStore.current?.name }}</h1>
    <p class="text-subtitle-2 text-md-subtitle-1 text-medium-emphasis mb-2 mb-md-4">{{ t('mh.dash.overview') }}</p>

    <!-- Devices-first (2026-08-26): the tile order leads with the fleet —
         Devices online | Tunnels | Rooms | Active calls | Messages. Five
         tiles wrap 1/2/5-up. Devices counts come from the server-side stats
         overview when available (accurate at any fleet size); the agents
         store — capped at its fetch page — is only the fallback. -->
    <v-row>
      <v-col v-if="caps.has('fleet')" cols="6" sm="4" md>
        <v-card :to="showFleet ? `/tenant/${tenantId}/devices` : undefined" :hover="showFleet">
          <v-card-text class="text-center">
            <v-icon size="48" color="warning">mdi-monitor-multiple</v-icon>
            <div class="text-h4 mt-2">{{ devicesOnlineLabel }}</div>
            <div class="text-subtitle-2">{{ t('mh.dash.devicesOnline') }}</div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col v-if="caps.has('network')" cols="6" sm="4" md>
        <!-- No `title` PROP here — on v-card it renders a whole title bar
             and made this tile taller than its siblings. Lands on the
             devices page pre-filtered to tunnels (?type=tunnel). -->
        <v-card
          :to="showFleet ? `/tenant/${tenantId}/devices?type=tunnel` : undefined"
          :hover="showFleet"
        >
          <v-card-text class="text-center">
            <v-icon size="48" color="info">mdi-lan-pending</v-icon>
            <div class="text-h4 mt-2">{{ tunnelsLabel }}</div>
            <div class="text-subtitle-2">{{ t('mh.dash.tunnels') }}</div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col v-if="showChat" cols="6" sm="4" md>
        <v-card :to="`/tenant/${tenantId}/rooms`" hover>
          <v-card-text class="text-center">
            <v-icon size="48" color="primary">mdi-pound</v-icon>
            <div class="text-h4 mt-2">{{ roomStore.rooms.length }}</div>
            <div class="text-subtitle-2">{{ t('mh.dash.rooms') }}</div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col v-if="showConference" cols="6" sm="4" md>
        <v-card>
          <v-card-text class="text-center">
            <v-icon size="48" color="secondary">mdi-video</v-icon>
            <div class="text-h4 mt-2">{{ activeCallCount }}</div>
            <div class="text-subtitle-2">{{ t('mh.dash.activeCalls') }}</div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col v-if="showChat" cols="6" sm="4" md>
        <v-card :to="`/tenant/${tenantId}/rooms`" hover>
          <v-card-text class="text-center">
            <v-icon size="48" color="accent">mdi-message-text</v-icon>
            <div class="text-h4 mt-2">{{ totalMessageCount }}</div>
            <div class="text-subtitle-2">{{ t('mh.dash.messages') }}</div>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>

    <!-- Insights (stats PR-4): the basic org graphs, visible to EVERY
         member — the overview endpoint is member-safe; deep queries live
         behind Analytics (org admins). Hidden entirely while stats are
         disabled server-side. -->
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
        <v-col v-if="showConference" cols="12" md="6">
          <v-card>
            <v-card-title class="text-subtitle-1 d-flex align-center">
              {{ t('mh.dash.callMinutes') }}
              <v-spacer />
              <span class="text-h6">
                {{ t('mh.dash.today', { n: Math.round(statsStore.overview?.calls?.minutes_today ?? 0) }) }}
              </span>
            </v-card-title>
            <v-card-text>
              <time-series-chart
                :points="statsStore.overview?.spark_minutes ?? []"
                :series="[{ key: 'minutes', label: t('mh.dash.minutes') }]"
                :height="140"
                area
                :empty-text="t('mh.dash.noCalls')"
              />
            </v-card-text>
          </v-card>
        </v-col>
      </v-row>
    </template>

    <!-- Overlay mesh (wave 2): how this org's devices actually reach the
         control plane and each other. Member-visible — carrier kind and
         latency only, no addresses. -->
    <template v-if="meshNodes.length">
      <h2 class="text-h6 mt-4 mb-2">{{ t('mh.dash.network') }}</h2>
      <v-card>
        <v-card-text>
          <mesh-graph
            :nodes="meshNodes"
            :edges="meshEdges"
            :center-name="centerName"
            @select="onMeshSelect"
          />
        </v-card-text>
      </v-card>
    </template>

    <!-- Quick actions -->
    <h2 v-if="showChat" class="text-h6 mt-4 mb-2">{{ t('mh.dash.quick') }}</h2>
    <v-row v-if="showChat">
      <v-col cols="12" sm="6" md="3">
        <v-btn block color="primary" prepend-icon="mdi-plus" :to="`/tenant/${tenantId}/rooms`">
          {{ t('mh.dash.newRoom') }}
        </v-btn>
      </v-col>
      <v-col v-if="showConference" cols="12" sm="6" md="3">
        <v-btn block color="secondary" prepend-icon="mdi-video-plus" @click="startCall">
          {{ t('mh.dash.startCall') }}
        </v-btn>
      </v-col>
      <v-col cols="12" sm="6" md="3">
        <v-btn block color="accent" prepend-icon="mdi-upload" :to="`/tenant/${tenantId}/files`">
          {{ t('mh.dash.uploadFile') }}
        </v-btn>
      </v-col>
      <v-col cols="12" sm="6" md="3">
        <v-btn block prepend-icon="mdi-compass" :to="`/tenant/${tenantId}/explore`">
          Explore
        </v-btn>
      </v-col>
    </v-row>

    <!-- Manage: every subsystem reachable from the org hub — the page used
         to dead-end at chat stats with no path to devices/network/admin. -->
    <h2 class="text-h6 mt-4 mb-2">{{ t('mh.dash.manage') }}</h2>
    <v-row>
      <v-col v-if="showFleet" cols="12" sm="6" md="3">
        <v-card :to="`/tenant/${tenantId}/devices`" hover>
          <v-card-text>
            <v-icon color="primary" class="mr-2">mdi-monitor-multiple</v-icon>
            <span class="text-subtitle-1 font-weight-medium">{{ t('mh.dash.devices') }}</span>
            <div class="text-body-2 text-medium-emphasis mt-1">
              {{ t('mh.dash.devicesHint') }}
            </div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col v-if="showNetwork" cols="12" sm="6" md="3">
        <!-- /network (the ACL landing) — /network/machines has been a
             redirect stub since the S4 fold-in. -->
        <v-card :to="`/tenant/${tenantId}/network`" hover>
          <v-card-text>
            <v-icon color="primary" class="mr-2">mdi-lan</v-icon>
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
            <v-icon color="primary" class="mr-2">mdi-account-group</v-icon>
            <span class="text-subtitle-1 font-weight-medium">{{ t('mh.dash.membersRoles') }}</span>
            <div class="text-body-2 text-medium-emphasis mt-1">
              {{ t('mh.dash.membersHint') }}
            </div>
          </v-card-text>
        </v-card>
      </v-col>
      <!-- Same FAIL-CLOSED gate as the sidebar item: the invites list needs
           INVITE_MEMBERS, so a member without it is not offered a tile whose
           page can only refuse them. (Was "and the api client logs out on
           GET 403" — no longer true, FR-82.) -->
      <v-col v-if="canInvite" cols="12" sm="6" md="3">
        <v-card :to="`/tenant/${tenantId}/invites`" hover>
          <v-card-text>
            <v-icon color="primary" class="mr-2">mdi-email-plus</v-icon>
            <span class="text-subtitle-1 font-weight-medium">{{ t('mh.dash.invites') }}</span>
            <div class="text-body-2 text-medium-emphasis mt-1">
              {{ t('mh.dash.invitesHint') }}
            </div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col v-if="showAnalytics" cols="12" sm="6" md="3">
        <v-card :to="`/tenant/${tenantId}/analytics`" hover>
          <v-card-text>
            <v-icon color="primary" class="mr-2">mdi-chart-areaspline</v-icon>
            <span class="text-subtitle-1 font-weight-medium">{{ t('mh.dash.analytics') }}</span>
            <div class="text-body-2 text-medium-emphasis mt-1">
              {{ t('mh.dash.analyticsHint') }}
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
import { useRoomStore } from '@/stores/rooms'
import { useAgentStore } from '@/stores/agents'
import { useTunnelClientStore } from '@/stores/tunnelClients'
import { useStatsStore } from '@/stores/stats'
import { useCapabilitiesStore } from '@/stores/capabilities'
import { usePolling } from '@/composables/usePolling'
import { canManageInvites, canQueryAnalytics, canSeeFleetNav } from '@/utils/permissions'
import TimeSeriesChart from '@/components/stats/TimeSeriesChart.vue'
import MeshGraph, { type MeshNode } from '@/components/stats/MeshGraph.vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const route = useRoute()
const router = useRouter()
const tenantStore = useTenantStore()
const roomStore = useRoomStore()
const agentStore = useAgentStore()
const tunnelClientStore = useTunnelClientStore()
const statsStore = useStatsStore()
// FR-69 P9 — the pillars THIS server mounts (fail-open until answered);
// the same predicate the navigation and the router guard read.
const caps = useCapabilitiesStore()
const showChat = computed(() => caps.has('chat'))
const showConference = computed(() => caps.has('conference'))

const tenantId = computed(() => route.params.tenantId as string)
const activeCallCount = computed(
  () => roomStore.rooms.filter((r) => r.conference_status === 'in_progress' && (r.participant_count || 0) > 0).length,
)
const totalMessageCount = computed(
  () => roomStore.rooms.reduce((sum, r) => sum + (r.message_count || 0), 0),
)
const onlineDevices = computed(() => agentStore.agents.filter((a) => a.is_online).length)
/** "online/total" from the server-side stats overview when it's on —
 *  accurate at any fleet size; the (page-capped) agents store is the
 *  fallback when stats are disabled. */
const devicesOnlineLabel = computed(() => {
  const m = statsStore.overview?.machines
  if (m) return `${m.online}/${m.total}`
  return String(onlineDevices.value)
})
/** Enrolled tunnel clients, online-by-stored-status/total. No liveness
 *  probe exists for tunnel clients (the tunnel.rs "T2" gap) — the tile's
 *  tooltip says so instead of pretending. */
const tunnelsLabel = computed(() => {
  const online = tunnelClientStore.clients.filter((c) => c.status === 'online').length
  return `${online}/${tunnelClientStore.total}`
})
const showFleet = computed(
  () => caps.has('fleet') && canSeeFleetNav(tenantStore.myPermissions, tenantStore.isOwner),
)
const showNetwork = computed(() => showFleet.value && caps.has('network'))
const showAnalytics = computed(() =>
  canQueryAnalytics(tenantStore.myPermissions, tenantStore.isOwner),
)
const canInvite = computed(() =>
  canManageInvites(tenantStore.myPermissions, tenantStore.isOwner),
)

// Insights panel: member-safe overview, refreshed every 60 s (paused
// while hidden). The store swallows 404s so a member of a stats-disabled
// deployment just sees no panel.
usePolling(async () => {
  if (!tenantId.value) return
  await statsStore.fetchOverview(tenantId.value)
  await statsStore.fetchMesh(tenantId.value)
}, 60_000)

// The mesh payload keys edges by OVERLAY node id while presence and
// version live on the agent row — join them here so the graph gets one
// flat node list. A device with no overlay node simply isn't in the mesh.
const meshNodes = computed<MeshNode[]>(() => {
  const m = statsStore.mesh
  if (!m?.nodes) return []
  const agentById = new Map((m.agents ?? []).map((a) => [a.id, a]))
  return m.nodes.map((n) => {
    const agent = n.agent_id_hex ? agentById.get(n.agent_id_hex) : undefined
    return {
      id: n.id,
      // FR-11: the operator's display name wins when set.
      name: agent?.display_name || agent?.name || n.name || n.overlay_ip || n.id.slice(-6),
      online: agent?.last_presence === 'online',
      relay_home: agent?.relay_home ?? n.relay_home ?? null,
      version: agent?.agent_version ?? null,
    }
  })
})
const meshEdges = computed(() => statsStore.mesh?.edges ?? [])
const centerName = computed(() => statsStore.mesh?.center?.name ?? 'meshharbor.itachi.fans')

function onMeshSelect(nodeId: string) {
  // Clicking a device jumps to the fleet page it belongs to — the graph
  // answers "who is reachable how", Devices answers "what do I do about it".
  const agentHex = statsStore.mesh?.nodes?.find((n) => n.id === nodeId)?.agent_id_hex
  if (agentHex && showFleet.value) {
    router.push(`/tenant/${tenantId.value}/devices`)
  }
}
watch(tenantId, (tid) => {
  if (tid) void statsStore.fetchOverview(tid)
})

async function startCall() {
  const now = new Date()
  const name = t('mh.dash.callName', { when: `${now.toLocaleDateString()} ${now.toLocaleTimeString()}` })
  const room = await roomStore.createRoom(tenantId.value, {
    name,
    has_media: true,
    is_open: true,
  })
  router.push({ name: 'room-call', params: { tenantId: tenantId.value, roomId: room.id } })
}

onMounted(() => {
  if (tenantId.value) {
    if (showChat.value) roomStore.fetchRooms(tenantId.value)
    if (showFleet.value) {
      agentStore.fetchAgents(tenantId.value).catch(() => {})
      // ⚠️ Tunnel clients are the `network` module's, not `fleet`'s. Gating
      // them on `showFleet` fired the fetch on a `remote` profile (fleet yes,
      // network no) at a route that correctly 404s. The store now refuses it
      // too — this line states the intent, the store enforces it. (FR-75.)
      if (caps.has('network')) tunnelClientStore.fetchTunnelClients(tenantId.value)
    }
  }
})
</script>
