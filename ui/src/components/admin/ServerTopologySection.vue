<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  FR-137 + T9 P4 (S12): Read-only Zone Backbone Globe powered by the shared MapLibre v2
  `MeshGlobe` component (`view-mode="backbone"`), with zone filter chips, optional grouped
  Devices overlay (3 px @ 35% opacity, OFF by default), graceful fallback if the server
  has not yet enabled `/network-zones/backbone`, non-WebGL2 `#fallback`, and responsive
  `table-stack-xs` Gateways & Links summary tables.
-->
<template>
  <v-card data-testid="zone-backbone-card">
    <v-card-title class="d-flex align-center flex-wrap ga-2">
      <v-icon icon="mdi-earth" color="primary" size="small" />
      <span>{{ $t('mh.backbone.title') }}</span>
      <v-chip
        v-if="store.revision > 0"
        size="x-small"
        variant="tonal"
        class="mh-mono"
        data-testid="backbone-revision"
      >
        r{{ store.revision }}
      </v-chip>
      <v-spacer />
      <div class="d-flex align-center flex-wrap ga-1">
        <v-btn
          prepend-icon="mdi-earth-box"
          variant="tonal"
          color="primary"
          size="small"
          :to="`/tenant/${tenantId}/devices`"
          data-testid="backbone-configure-zones-btn"
        >
          {{ $t('mh.backbone.configureZones') }}
        </v-btn>
        <v-btn
          prepend-icon="mdi-refresh"
          variant="text"
          size="small"
          :loading="store.loading"
          data-testid="backbone-refresh-btn"
          @click="refresh"
        >
          {{ $t('common.refresh') }}
        </v-btn>
      </div>
    </v-card-title>

    <v-card-text>
      <v-alert
        v-if="store.error"
        type="error"
        variant="tonal"
        closable
        class="mb-4"
        data-testid="backbone-error-alert"
        @click:close="store.error = null"
      >
        {{ store.error }}
      </v-alert>

      <v-sheet
        v-if="store.unavailable && !store.loading"
        border
        rounded
        class="pa-5 text-body-2 mb-4"
        data-testid="backbone-unavailable-state"
      >
        <div class="d-flex align-center ga-2 font-weight-medium mb-1">
          <v-icon icon="mdi-information-outline" color="info" size="small" />
          <span>{{ $t('mh.backbone.unavailableTitle') }}</span>
        </div>
        <div class="text-caption text-medium-emphasis">
          {{ $t('mh.backbone.unavailableHint') }}
        </div>
      </v-sheet>

      <p class="text-body-2 text-medium-emphasis mb-4">
        {{ $t('mh.backbone.intro') }}
      </p>

      <div
        v-if="store.loading && store.zones.length === 0 && store.gateways.length === 0"
        class="d-flex justify-center pa-8"
        data-testid="backbone-loading"
      >
        <v-progress-circular indeterminate />
      </div>

      <v-sheet
        v-else-if="!store.unavailable && (store.zones.length === 0 || store.gateways.length === 0)"
        border
        rounded
        class="pa-5 text-body-2"
        data-testid="backbone-empty-state"
      >
        <div class="font-weight-medium mb-1">
          {{ store.zones.length === 0 ? $t('mh.backbone.emptyZonesTitle') : $t('mh.backbone.emptyGatewaysTitle') }}
        </div>
        <div class="text-caption text-medium-emphasis mb-3">
          {{ store.zones.length === 0 ? $t('mh.backbone.emptyZonesHint') : $t('mh.backbone.emptyGatewaysHint') }}
        </div>
        <v-btn
          size="small"
          color="primary"
          variant="flat"
          prepend-icon="mdi-earth-box"
          :to="`/tenant/${tenantId}/devices`"
        >
          {{ $t('mh.backbone.configureZones') }}
        </v-btn>
      </v-sheet>

      <template v-else-if="!store.unavailable">
        <!-- Zone filter chips (Centre zone is an ordinary zone with distinct accent) & Devices overlay toggle -->
        <div class="backbone-toolbar mb-3">
          <div class="backbone-zones" role="group" :aria-label="$t('mh.backbone.zonesFilterAria')">
            <v-chip
              size="small"
              :variant="selectedZoneId === null ? 'flat' : 'outlined'"
              :color="selectedZoneId === null ? 'primary' : undefined"
              data-testid="backbone-zone-chip-all"
              @click="selectedZoneId = null"
            >
              {{ $t('mh.backbone.allZones') }}
              <span class="ml-1 text-caption opacity-80">({{ store.gateways.length }})</span>
            </v-chip>
            <v-chip
              v-for="z in store.zones"
              :key="z.id"
              size="small"
              :variant="selectedZoneId === z.id ? 'flat' : 'outlined'"
              :color="selectedZoneId === z.id ? (z.is_centre ? 'primary' : 'secondary') : undefined"
              :data-testid="`backbone-zone-chip-${z.id}`"
              @click="toggleZoneFilter(z.id)"
            >
              <span
                class="backbone-dot mr-1"
                :style="{ background: globeData.zoneColors.get(z.id) }"
                aria-hidden="true"
              />
              <span>{{ z.name }}</span>
              <v-icon
                v-if="z.is_centre"
                icon="mdi-star-four-points"
                size="12"
                class="ml-1"
                :aria-label="$t('mh.backbone.centreBadge')"
              />
              <span class="ml-1 text-caption opacity-80">
                · {{ $t('mh.backbone.deviceCountShort', { n: z.device_count }) }}
              </span>
            </v-chip>
          </div>

          <div class="backbone-controls">
            <v-switch
              v-model="showDevicesOverlay"
              density="compact"
              hide-details
              color="primary"
              class="backbone-switch"
              :label="$t('mh.backbone.showDevices')"
              data-testid="backbone-show-devices-switch"
            />
          </div>
        </div>

        <!-- Shared MapLibre v2 Zone Backbone Globe (NO Three.js dependency) -->
        <mesh-globe
          ref="globeRef"
          view-mode="backbone"
          :nodes="globeData.nodes"
          :arcs="globeData.arcs"
          :zones="store.zones"
          :overlay-devices="overlayDeviceNodes"
          :overlay-device-arcs="overlayDeviceArcs"
          :show-devices-overlay="showDevicesOverlay"
          :show-control-plane="false"
          :aria-label="$t('mh.backbone.globeAria')"
          @update:show-devices-overlay="onShowDevicesOverlayChange"
          @full-page-change="onFullPageChange"
          @open-device="openDevice"
          @fallback-active="webglFallback = true"
        >
          <template #fallback>
            <v-sheet
              border
              rounded
              class="pa-4 mb-2 text-body-2 d-flex align-center ga-3"
              data-testid="backbone-webgl-fallback"
            >
              <v-icon icon="mdi-earth-off" color="primary" />
              <div>
                <div class="font-weight-medium">{{ $t('mh.backbone.fallbackTitle') }}</div>
                <div class="text-caption text-medium-emphasis">
                  {{ $t('mh.backbone.fallbackHint') }}
                </div>
              </div>
            </v-sheet>
          </template>
        </mesh-globe>

        <div class="text-caption text-medium-emphasis mt-2 mb-4 text-center" data-testid="backbone-summary">
          {{
            $t('mh.backbone.summaryLine', {
              zones: store.zones.length,
              gateways: visibleGateways.length,
              links: visibleLinks.length,
            })
          }}
        </div>

        <!-- Accessible responsive Gateways summary table -->
        <div class="text-subtitle-2 font-weight-medium mb-2">
          {{ $t('mh.backbone.gatewaysHeading', { n: visibleGateways.length }) }}
        </div>
        <v-table density="compact" class="table-stack-xs mb-5" data-testid="backbone-gateways-table">
          <thead>
            <tr>
              <th>{{ $t('mh.backbone.col.gateway') }}</th>
              <th>{{ $t('mh.backbone.col.zones') }}</th>
              <th>{{ $t('mh.backbone.col.location') }}</th>
              <th>{{ $t('mh.backbone.col.entry') }}</th>
              <th class="text-right">{{ $t('mh.topo.col.actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="gw in visibleGateways"
              :key="gw.agent_id"
              class="backbone-row-clickable"
              :data-testid="`backbone-gw-row-${gw.agent_id}`"
              @click="focusGateway(gw.agent_id)"
            >
              <td :data-label="$t('mh.backbone.col.gateway')">
                <div class="d-flex align-center flex-wrap ga-2">
                  <span
                    class="mh-presence__dot"
                    :class="gw.online ? 'mh-presence--online' : 'mh-presence--offline'"
                    aria-hidden="true"
                  />
                  <span class="font-weight-medium">{{ gw.name }}</span>
                  <!-- Strict role separation: Centre vs Gateway (`serving_relay`) vs Entry (`serving_relay && entry_listening`) -->
                  <v-chip
                    v-if="gw.is_centre"
                    size="x-small"
                    color="warning"
                    variant="tonal"
                    density="comfortable"
                    :data-testid="`backbone-gw-centre-badge-${gw.agent_id}`"
                  >
                    {{ $t('mh.backbone.centreBadge') }}
                  </v-chip>
                  <v-chip
                    v-if="gw.serving_relay"
                    size="x-small"
                    color="primary"
                    variant="tonal"
                    density="comfortable"
                    :data-testid="`backbone-gw-gateway-badge-${gw.agent_id}`"
                  >
                    {{ $t('mh.mesh.role.gateway') }}
                  </v-chip>
                  <v-chip
                    v-if="gw.serving_relay && gw.entry_listening"
                    size="x-small"
                    color="info"
                    variant="tonal"
                    density="comfortable"
                    :data-testid="`backbone-gw-entry-badge-${gw.agent_id}`"
                  >
                    {{ $t('mh.mesh.role.entry') }}
                  </v-chip>
                  <span class="text-caption text-medium-emphasis">
                    {{ gw.online ? $t('mh.mesh.status.online') : $t('mh.mesh.status.offline') }}
                  </span>
                </div>
              </td>
              <td :data-label="$t('mh.backbone.col.zones')">
                <div class="d-flex flex-wrap ga-1">
                  <v-chip
                    v-for="zid in gw.zone_ids"
                    :key="zid"
                    size="x-small"
                    variant="outlined"
                    density="comfortable"
                  >
                    <span
                      class="backbone-dot mr-1"
                      :style="{ background: globeData.zoneColors.get(zid) }"
                      aria-hidden="true"
                    />
                    {{ zoneNameOf(zid) }}
                  </v-chip>
                </div>
              </td>
              <td :data-label="$t('mh.backbone.col.location')">
                <span v-if="locationTextOf(gw)">{{ locationTextOf(gw) }}</span>
                <span v-else class="text-medium-emphasis">{{ $t('mh.mesh.panel.locationUnknown') }}</span>
              </td>
              <td :data-label="$t('mh.backbone.col.entry')">
                <div v-if="gw.serving_relay || gw.entry_listening" class="d-flex align-center flex-wrap ga-2">
                  <v-chip
                    size="x-small"
                    :color="gw.entry_listening ? 'success' : undefined"
                    variant="tonal"
                    density="comfortable"
                    class="mh-mono"
                  >
                    {{
                      gw.entry_listening
                        ? gw.entry_port
                          ? $t('mh.mesh.panel.entryListeningPort', { port: gw.entry_port })
                          : $t('mh.mesh.panel.entryListening')
                        : $t('mh.mesh.panel.entryNotListening')
                    }}
                  </v-chip>
                  <span class="text-caption mh-tabular text-medium-emphasis">
                    {{ $t('mh.mesh.panel.entryDevicesCount', { n: gw.entry_device_count }) }}
                  </span>
                </div>
                <span v-else class="text-caption text-medium-emphasis">—</span>
              </td>
              <td class="text-right">
                <v-btn
                  size="x-small"
                  variant="text"
                  color="primary"
                  prepend-icon="mdi-open-in-new"
                  :data-testid="`backbone-open-gw-${gw.agent_id}`"
                  @click.stop="openDevice(gw.agent_id)"
                >
                  {{ $t('mh.mesh.panel.openDevice') }}
                </v-btn>
              </td>
            </tr>
          </tbody>
        </v-table>

        <!-- Accessible responsive Gateway↔Gateway Links summary table -->
        <div class="text-subtitle-2 font-weight-medium mb-2">
          {{ $t('mh.backbone.linksHeading', { n: visibleLinks.length }) }}
        </div>
        <v-table density="compact" class="table-stack-xs" data-testid="backbone-links-table">
          <thead>
            <tr>
              <th>{{ $t('mh.backbone.col.link') }}</th>
              <th>{{ $t('mh.backbone.col.carrier') }}</th>
              <th>{{ $t('mh.backbone.col.latency') }}</th>
              <th>{{ $t('mh.backbone.col.state') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="visibleLinks.length === 0">
              <td colspan="4" class="text-medium-emphasis" data-testid="backbone-no-links">
                {{ $t('mh.backbone.noLinks') }}
              </td>
            </tr>
            <tr
              v-for="l in visibleLinks"
              :key="`${l.from_agent_id}:${l.to_agent_id}`"
              class="backbone-row-clickable"
              :data-testid="`backbone-link-row-${l.from_agent_id}-${l.to_agent_id}`"
              @click="focusLink(`${l.from_agent_id}:${l.to_agent_id}`)"
            >
              <td :data-label="$t('mh.backbone.col.link')">
                <div class="d-flex align-center flex-wrap ga-2">
                  <span class="font-weight-medium">
                    {{ gatewayNameOf(l.from_agent_id) }}
                    {{ l.reports === 1 ? '→' : '↔' }}
                    {{ gatewayNameOf(l.to_agent_id) }}
                  </span>
                  <v-chip
                    v-if="l.cross_zone"
                    size="x-small"
                    variant="tonal"
                    color="secondary"
                    density="comfortable"
                  >
                    {{ $t('mh.backbone.crossZone') }}
                  </v-chip>
                </div>
              </td>
              <td :data-label="$t('mh.backbone.col.carrier')">
                <div class="d-flex align-center flex-wrap ga-1 mh-mono text-caption">
                  <span
                    class="backbone-dot"
                    :style="{ background: linkColorOf(l) }"
                    aria-hidden="true"
                  />
                  <span>{{ linkCarrierSummary(l) }}</span>
                </div>
              </td>
              <td :data-label="$t('mh.backbone.col.latency')" class="mh-mono text-caption">
                {{ l.rtt_ms != null ? `${l.rtt_ms} ms` : '—' }}
              </td>
              <td :data-label="$t('mh.backbone.col.state')">
                <div class="d-flex align-center flex-wrap ga-2">
                  <v-chip
                    size="x-small"
                    variant="tonal"
                    :color="l.stalled ? 'warning' : 'success'"
                    density="comfortable"
                  >
                    {{ l.stalled ? $t('mh.mesh.stalled') : $t('mh.backbone.healthy') }}
                  </v-chip>
                  <span class="text-caption text-medium-emphasis">
                    {{
                      l.reports === 1
                        ? $t('mh.mesh.panel.oneSided')
                        : $t('mh.mesh.panel.reportsCount', { n: l.reports })
                    }}
                  </span>
                </div>
              </td>
            </tr>
          </tbody>
        </v-table>
      </template>
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { useTheme } from 'vuetify'
import MeshGlobe from '@/components/globe/MeshGlobe.vue'
import type { GlobeArc, GlobeNode } from '@/components/globe/types'
import { useAgentStore } from '@/stores/agents'
import { useStatsStore } from '@/stores/stats'
import {
  useServerTopologyStore,
  type BackboneGatewayView,
  type BackboneLinkView,
} from '@/stores/serverTopology'
import { formatDeviceLocation } from '@/utils/deviceLocation'
import { qualifiedCarrier } from '@/utils/mesh'
import {
  backboneCarrierColor,
  buildBackboneGlobeData,
  effectiveBackboneCarrier,
  type BackboneCarrierColors,
} from './zoneBackbone'

const props = defineProps<{ tenantId: string }>()
const store = useServerTopologyStore()
const router = useRouter()
const { t } = useI18n()
const theme = useTheme()

// Optional lazy access to agents & mesh stats for S12 "Show devices" overlay + full-page view switch.
let agentStore: ReturnType<typeof useAgentStore> | null = null
let statsStore: ReturnType<typeof useStatsStore> | null = null
try {
  agentStore = useAgentStore()
  statsStore = useStatsStore()
} catch {
  // Isolated component tests without Pinia active stay unaffected.
  agentStore = null
  statsStore = null
}

const selectedZoneId = ref<string | null>(null)
const showDevicesOverlay = ref(false)
const devicesFetched = ref(false)
const webglFallback = ref(false)
const globeRef = ref<InstanceType<typeof MeshGlobe> | null>(null)

const isDark = computed(() => theme.current.value.dark)

const carrierColors = computed<BackboneCarrierColors>(() => {
  const c = theme.current.value.colors
  return {
    direct: c.success,
    org_relay: isDark.value ? '#38BDF8' : '#0284C7',
    relay: c.warning,
    derp: c.info,
    tunnel: c.primary,
    blocked: c.error,
    unknown: isDark.value ? '#94A3B8' : '#64748B',
  }
})

const globeData = computed(() =>
  buildBackboneGlobeData(store.zones, store.gateways, store.links, {
    selectedZoneId: selectedZoneId.value,
    isDark: isDark.value,
    carrierColors: carrierColors.value,
  }),
)

const overlayDeviceNodes = computed<GlobeNode[]>(() => {
  const agents = agentStore?.agents ?? []
  const meshNodes = statsStore?.mesh?.nodes ?? []
  if (meshNodes.length > 0) {
    const byAgent = new Map(agents.map((a) => [a.id, a]))
    const byMeshAgent = new Map((statsStore?.mesh?.agents ?? []).map((a) => [a.id, a]))
    return meshNodes.map((n) => {
      const fleet = n.agent_id_hex ? byAgent.get(n.agent_id_hex) : undefined
      const meshA = n.agent_id_hex ? byMeshAgent.get(n.agent_id_hex) : undefined
      const presence =
        fleet?.presence ??
        (meshA?.last_presence === 'online'
          ? 'online'
          : meshA?.last_presence === 'stale'
            ? 'stale'
            : 'offline')
      return {
        id: n.id,
        agentId: n.agent_id_hex ?? null,
        name:
          fleet?.display_name ||
          meshA?.display_name ||
          fleet?.name ||
          meshA?.name ||
          n.name ||
          n.id.slice(-6),
        online: fleet ? fleet.is_online : presence === 'online',
        presence,
        countryCode: fleet?.country_code ?? null,
        country: fleet?.country ?? null,
        region: fleet?.region ?? null,
        city: fleet?.city ?? null,
        lat: fleet?.lat ?? null,
        lon: fleet?.lon ?? null,
        accuracyRadiusKm: fleet?.accuracy_radius_km ?? null,
        geoLevel: fleet?.geo_level ?? null,
        os: fleet?.os ?? meshA?.os ?? null,
        version: fleet?.agent_version ?? meshA?.agent_version ?? null,
        lastSeenAt: fleet?.last_seen_at ?? n.last_seen_at ?? null,
        overlayIp: n.overlay_ip ?? null,
        publicIp: fleet?.public_ip ?? null,
        zoneId: fleet?.effective_zone_id ?? fleet?.pinned_zone_id ?? null,
        zoneName: fleet?.effective_zone_name ?? null,
        isGateway: Boolean(fleet?.peer_relay_policy?.serve),
      }
    })
  }
  return agents.map((a) => ({
    id: a.id,
    agentId: a.id,
    name: a.display_name || a.name,
    online: a.is_online,
    presence: a.presence ?? (a.is_online ? 'online' : 'offline'),
    countryCode: a.country_code ?? null,
    country: a.country ?? null,
    region: a.region ?? null,
    city: a.city ?? null,
    lat: a.lat ?? null,
    lon: a.lon ?? null,
    accuracyRadiusKm: a.accuracy_radius_km ?? null,
    geoLevel: a.geo_level ?? null,
    os: a.os ?? null,
    version: a.agent_version ?? null,
    lastSeenAt: a.last_seen_at ?? null,
    publicIp: a.public_ip ?? null,
    zoneId: a.effective_zone_id ?? a.pinned_zone_id ?? null,
    zoneName: a.effective_zone_name ?? null,
    isGateway: Boolean(a.peer_relay_policy?.serve),
  }))
})

const overlayDeviceArcs = computed<GlobeArc[]>(() => {
  const edges = statsStore?.mesh?.edges ?? []
  return edges.map((e) => ({
    key: `${e.from}-${e.to}-${e.carrier}`,
    from: e.from,
    to: e.to,
    carrier: e.carrier,
    color: backboneCarrierColor(e.carrier, carrierColors.value),
    stalled: Boolean(e.stalled),
    blocked: e.carrier === 'blocked',
    rttMs: e.rtt_ms ?? null,
    reports: e.reports,
    ends: e.ends,
    kind: 'peer',
  }))
})

async function ensureOverlayDevicesLoaded() {
  if (devicesFetched.value || !props.tenantId) return
  devicesFetched.value = true
  try {
    await Promise.allSettled([
      agentStore?.fetchAgents?.(props.tenantId),
      statsStore?.fetchMesh?.(props.tenantId),
    ])
  } catch {
    /* Optional overlay — never disrupts backbone view if agents/stats are unavailable. */
  }
}

watch(showDevicesOverlay, (show) => {
  if (show) void ensureOverlayDevicesLoaded()
})

function onShowDevicesOverlayChange(show: boolean) {
  showDevicesOverlay.value = show
}

function onFullPageChange(full: boolean) {
  if (full) void ensureOverlayDevicesLoaded()
}

const visibleGateways = computed(() => {
  if (!selectedZoneId.value) return store.gateways
  return store.gateways.filter((g) => g.zone_ids.includes(selectedZoneId.value!))
})

const visibleGatewayIds = computed(() => new Set(visibleGateways.value.map((g) => g.agent_id)))

const visibleLinks = computed(() =>
  store.links.filter(
    (l) => visibleGatewayIds.value.has(l.from_agent_id) && visibleGatewayIds.value.has(l.to_agent_id),
  ),
)

const zoneNameMap = computed(() => new Map(store.zones.map((z) => [z.id, z.name])))
const gatewayNameMap = computed(() => new Map(store.gateways.map((g) => [g.agent_id, g.name])))

function zoneNameOf(zoneId: string): string {
  return zoneNameMap.value.get(zoneId) ?? zoneId
}

function gatewayNameOf(agentId: string): string {
  return gatewayNameMap.value.get(agentId) ?? agentId.slice(-6)
}

function locationTextOf(gw: BackboneGatewayView): string {
  const loc = formatDeviceLocation({
    country_code: gw.country_code,
    country: gw.country,
    region: gw.region,
    city: gw.city,
  })
  return loc.locationText || loc.countryCode || ''
}

function linkColorOf(link: BackboneLinkView): string {
  const eff = effectiveBackboneCarrier(link.carrier, link.ends)
  return backboneCarrierColor(eff, carrierColors.value)
}

function linkCarrierSummary(link: BackboneLinkView): string {
  if (link.ends?.length) {
    const labels = [...new Set(link.ends.map((e) => qualifiedCarrier(e.carrier, e.relay)))]
    return labels.join(' / ')
  }
  const key = `mh.mesh.carriers.${link.carrier}`
  const translated = t(key)
  return translated === key ? link.carrier : translated
}

function toggleZoneFilter(zoneId: string) {
  selectedZoneId.value = selectedZoneId.value === zoneId ? null : zoneId
}

function scrollGlobeIntoView() {
  const el = globeRef.value?.$el as HTMLElement | undefined
  el?.scrollIntoView?.({ block: 'center' })
}

function focusGateway(agentId: string) {
  globeRef.value?.focusNodeById(agentId)
  scrollGlobeIntoView()
}

function focusLink(arcKey: string) {
  globeRef.value?.focusArcByKey(arcKey)
  scrollGlobeIntoView()
}

function openDevice(_agentId: string) {
  void router?.push?.(`/tenant/${props.tenantId}/devices`)
}

function refresh() {
  void store.fetchBackbone(props.tenantId)
}

watch(
  () => props.tenantId,
  (tid) => {
    selectedZoneId.value = null
    devicesFetched.value = false
    if (tid) void store.fetchBackbone(tid)
  },
)

onMounted(() => {
  refresh()
})
</script>

<style scoped>
.backbone-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 8px 14px;
}
.backbone-zones {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
}
.backbone-controls {
  display: flex;
  align-items: center;
  gap: 10px;
}
.backbone-switch :deep(.v-label) {
  font-size: 0.8rem;
  white-space: nowrap;
}
.backbone-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex: 0 0 auto;
}
.backbone-row-clickable {
  cursor: pointer;
}
</style>
