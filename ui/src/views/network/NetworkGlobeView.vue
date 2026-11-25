<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  T8b — Dedicated full-page 3D device mesh globe (`/tenant/:tenantId/network/globe`).
  - Supports `?embed=1` (hides AppLayout app bar & navigation drawer, fills 100vw × 100dvh).
  - Honours `?lang=en|zh-CN` (any `zh*` → `zh-CN`, `en*` → `en`) without clobbering stored locale.
  - Honours `?theme=light|dark|system` (reacting live to OS `prefers-color-scheme` changes).
  - Loads real tenant mesh + fleet agents (gracefully handling member vs admin permissions).
-->
<template>
  <div
    class="mh-network-globe-view"
    :class="{ 'mh-network-globe-view--embed': isEmbed }"
    :data-embed="isEmbed ? '1' : '0'"
    :data-theme="resolvedTheme"
    :data-lang="resolvedLang"
    data-testid="network-globe-view"
  >
    <div v-if="webglUnavailable" class="mh-network-globe-fallback" data-testid="network-globe-fallback">
      <p class="text-body-2 text-medium-emphasis">{{ $t('mh.mesh.webglFallbackHint') }}</p>
    </div>
    <mesh-globe-map
      v-else
      :nodes="globeNodes"
      :arcs="globeArcs"
      :center="globeCenter"
      :theme-mode="resolvedTheme"
      :lang="resolvedLang"
      :enabled-carriers="ALL_CARRIERS"
      :show-open-device-action="showFleet"
      :cooperative-gestures="false"
      :sync-url="false"
      standalone-full-page
      @open-device="onOpenDevice"
      @webgl-error="onWebglError"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useTheme } from 'vuetify'
import { useI18n } from 'vue-i18n'
import { setLocale } from '@/plugins/i18n'
import { useStatsStore } from '@/stores/stats'
import { useAgentStore } from '@/stores/agents'
import { useTenantStore } from '@/stores/tenant'
import { useCapabilitiesStore } from '@/stores/capabilities'
import { usePolling } from '@/composables/usePolling'
import { canSeeFleetNav } from '@/utils/permissions'
import { edgeSides } from '@/utils/mesh'
import { isWebGL2Supported } from '@/components/globe/webgl'
import type { GlobeArc, GlobeCenter, GlobeNode } from '@/components/globe/types'
import { getGlobeTokens, type GlobeLang, type GlobeThemeMode } from '@/components/globe-v2/tokens'
import MeshGlobeMap from '@/components/globe-v2/MeshGlobeMap.vue'
import {
  parseEmbedFlag,
  parseLangParam,
  parseThemeParam,
  resolveThemeMode,
} from './globeEmbedParams'

const ALL_CARRIERS = ['direct', 'relay', 'derp', 'tunnel', 'blocked'] as const

const route = useRoute()
const router = useRouter()
const vuetifyTheme = useTheme()
const { locale } = useI18n()
const statsStore = useStatsStore()
const agentStore = useAgentStore()
const tenantStore = useTenantStore()
const caps = useCapabilitiesStore()

const tenantId = computed(() => String(route.params.tenantId ?? ''))
const isEmbed = computed(() => parseEmbedFlag(route.query.embed))
const langParam = computed(() => parseLangParam(route.query.lang))
const themeParam = computed(() => parseThemeParam(route.query.theme))

const showFleet = computed(
  () => caps.has('fleet') && canSeeFleetNav(tenantStore.myPermissions, tenantStore.isOwner),
)

// Track OS color-scheme reactively so `?theme=system` updates live without reloading styles.
function readSystemDark(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return false
  return Boolean(window.matchMedia('(prefers-color-scheme: dark)').matches)
}

const systemPrefersDark = ref<boolean>(readSystemDark())
let colorSchemeQuery: MediaQueryList | null = null
function onColorSchemeChange(e: MediaQueryListEvent): void {
  systemPrefersDark.value = e.matches
}

onMounted(() => {
  if (typeof window !== 'undefined' && typeof window.matchMedia === 'function') {
    colorSchemeQuery = window.matchMedia('(prefers-color-scheme: dark)')
    systemPrefersDark.value = colorSchemeQuery.matches
    colorSchemeQuery.addEventListener?.('change', onColorSchemeChange)
  }
})

onBeforeUnmount(() => {
  colorSchemeQuery?.removeEventListener?.('change', onColorSchemeChange)
  colorSchemeQuery = null
})

const resolvedLang = computed<GlobeLang>(
  () => langParam.value ?? (String(locale.value) === 'zh-CN' ? 'zh-CN' : 'en'),
)

const resolvedTheme = computed<GlobeThemeMode>(() =>
  resolveThemeMode(themeParam.value, systemPrefersDark.value, vuetifyTheme.global.current.value.dark),
)

// Apply explicit `?lang=` immediately without overwriting the browser's saved locale.
watch(
  langParam,
  (next) => {
    if (next) setLocale(next, { persist: false })
  },
  { immediate: true },
)

// Apply explicit `?theme=light|dark|system` immediately to Vuetify without overwriting localStorage.
watch(
  [themeParam, systemPrefersDark],
  ([param]) => {
    if (param !== null) {
      vuetifyTheme.change(resolvedTheme.value)
    }
  },
  { immediate: true },
)

const webglUnavailable = ref<boolean>(!isWebGL2Supported())
function onWebglError(): void {
  webglUnavailable.value = true
}

function loadTenantData(tid: string): void {
  if (!tid) return
  void statsStore.fetchMesh(tid)
  if (showFleet.value) {
    void agentStore.fetchAgents(tid).catch(() => {})
  }
}

watch(
  tenantId,
  (tid) => {
    loadTenantData(tid)
  },
  { immediate: true },
)

watch(showFleet, (fleet) => {
  if (fleet && tenantId.value) {
    void agentStore.fetchAgents(tenantId.value).catch(() => {})
  }
})

usePolling(async () => {
  if (!tenantId.value) return
  await statsStore.fetchMesh(tenantId.value)
}, 60_000)

function carrierTokenColor(carrier: string): string {
  const tok = getGlobeTokens(resolvedTheme.value)
  switch (carrier) {
    case 'direct':
      return tok.direct
    case 'relay':
      return tok.relay
    case 'derp':
      return tok.derp
    case 'tunnel':
      return tok.tunnel
    case 'blocked':
      return tok.blocked
    default:
      return tok.direct
  }
}

// Join real tenant mesh payload + fleet agents (full parity with TenantDashboard.vue).
const globeNodes = computed<GlobeNode[]>(() => {
  const m = statsStore.mesh
  if (!m?.nodes?.length) return []
  const meshAgentById = new Map((m.agents ?? []).map((a) => [a.id, a]))
  const fleetAgentById = new Map(agentStore.agents.map((a) => [a.id, a]))
  return m.nodes.map((n) => {
    const ma = n.agent_id_hex ? meshAgentById.get(n.agent_id_hex) : undefined
    const fa = n.agent_id_hex ? fleetAgentById.get(n.agent_id_hex) : undefined
    const presence =
      fa?.presence ??
      (ma?.last_presence === 'online'
        ? 'online'
        : ma?.last_presence === 'stale'
          ? 'stale'
          : 'offline')
    const mp = ma?.management_path
    const isGateway = Boolean(fa?.peer_relay_policy?.serve)
    return {
      id: n.id,
      agentId: n.agent_id_hex ?? null,
      name:
        fa?.display_name ||
        ma?.display_name ||
        fa?.name ||
        ma?.name ||
        n.name ||
        n.overlay_ip ||
        n.id.slice(-6),
      online: fa ? fa.is_online : ma?.last_presence === 'online',
      presence,
      role: isGateway ? 'gateway' : 'device',
      isGateway,
      countryCode: fa?.country_code ?? null,
      country: fa?.country ?? null,
      region: fa?.region ?? null,
      city: fa?.city ?? null,
      lat: fa?.lat ?? null,
      lon: fa?.lon ?? null,
      accuracyRadiusKm: fa?.accuracy_radius_km ?? null,
      geoLevel: fa?.geo_level ?? null,
      relayHome: fa?.relay_home ?? ma?.relay_home ?? n.relay_home ?? null,
      os: fa?.os ?? ma?.os ?? null,
      version: fa?.agent_version ?? ma?.agent_version ?? null,
      lastSeenAt: fa?.last_seen_at ?? n.last_seen_at ?? null,
      overlayIp: n.overlay_ip ?? null,
      publicIp: showFleet.value ? (fa?.public_ip ?? null) : null,
      physicalPublicIp: showFleet.value ? (fa?.physical_public_ip ?? null) : null,
      zoneId: fa?.effective_zone_id ?? fa?.pinned_zone_id ?? null,
      zoneName: fa?.effective_zone_name ?? null,
      zonePinned: Boolean(fa?.pinned_zone_id),
      managementPath: mp
        ? { mode: mp.mode, gatewayName: mp.gateway_name ?? null, entries: mp.entries }
        : null,
    }
  })
})

const globeArcs = computed<GlobeArc[]>(() =>
  (statsStore.mesh?.edges ?? []).map((e) => {
    const sides = edgeSides(e.ends, e.from, e.to)
    const baseColor = carrierTokenColor(e.carrier)
    return {
      key: `${e.from}-${e.to}-${e.carrier}`,
      from: e.from,
      to: e.to,
      carrier: e.carrier,
      color: baseColor,
      fromColor: sides.asymmetric && sides.from ? carrierTokenColor(sides.from.carrier) : baseColor,
      toColor: sides.asymmetric && sides.to ? carrierTokenColor(sides.to.carrier) : baseColor,
      asymmetric: sides.asymmetric,
      stalled: Boolean(e.stalled),
      blocked: e.carrier === 'blocked',
      dashed: Boolean(e.stalled || e.carrier === 'blocked'),
      rttMs: e.rtt_ms ?? null,
      reports: e.reports,
      ends: e.ends,
      kind: 'peer',
    }
  }),
)

const globeCenter = computed<GlobeCenter | null>(() => {
  const c = statsStore.mesh?.center
  if (!c) return null
  return { id: c.id, name: c.name, countryCode: c.country_code ?? null }
})

function onOpenDevice(): void {
  if (tenantId.value && showFleet.value) {
    void router.push(`/tenant/${tenantId.value}/devices`)
  }
}
</script>

<style scoped>
.mh-network-globe-view {
  position: relative;
  flex: 1 1 0;
  min-height: 0;
  width: 100%;
  height: 100%;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}
.mh-network-globe-view--embed {
  width: 100vw;
  height: 100vh;
  height: 100dvh;
}
.mh-network-globe-fallback {
  flex: 1 1 0;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  text-align: center;
}
</style>
