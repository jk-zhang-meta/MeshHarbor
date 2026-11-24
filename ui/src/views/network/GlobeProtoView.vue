<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  Hidden signed-in P0 Prototype route (/tenant/:tenantId/network/globe-proto).
  NOT linked in the sidebar navigation. Evaluates MapLibre GL JS 6.19.0 +
  self-hosted PMTiles (Variant L surface lines vs Variant A elevated 3D arcs)
  against real tenant mesh data or the deterministic Synthetic ×10 stress set,
  plus side-by-side comparison with the legacy Three.js globe on the same data.
-->
<template>
  <div class="mh-proto-wrap" data-testid="globe-proto-view">
    <div class="mh-proto-header">
      <div>
        <h2 class="text-h6 mb-0">{{ $t('mh.globeV2.protoTitle') }}</h2>
        <div class="text-caption text-medium-emphasis">
          {{ $t('mh.globeV2.protoSubtitle', { nodes: activeNodes.length, links: activeArcs.length }) }}
        </div>
      </div>

      <div class="mh-proto-toolbar">
        <!-- Engine selector (v2 MapLibre vs Legacy Three.js on exact same dataset) -->
        <v-btn-toggle
          v-model="engineMode"
          mandatory
          density="compact"
          variant="outlined"
          class="mh-segmented"
          data-testid="proto-engine-toggle"
        >
          <v-btn value="v2" size="x-small">MapLibre v2</v-btn>
          <v-btn value="legacy" size="x-small">{{ $t('mh.globeV2.legacyEngine') }}</v-btn>
        </v-btn-toggle>

        <!-- Variant L vs A -->
        <v-btn-toggle
          v-if="engineMode === 'v2'"
          v-model="variant"
          mandatory
          density="compact"
          variant="outlined"
          class="mh-segmented"
          data-testid="proto-variant-toggle"
        >
          <v-btn value="L" size="x-small">{{ $t('mh.globeV2.variantL') }}</v-btn>
          <v-btn value="A" size="x-small">{{ $t('mh.globeV2.variantA') }}</v-btn>
        </v-btn-toggle>

        <!-- Dataset Real vs Synthetic x10 -->
        <v-btn-toggle
          v-model="datasetMode"
          mandatory
          density="compact"
          variant="outlined"
          class="mh-segmented"
          data-testid="proto-dataset-toggle"
        >
          <v-btn value="real" size="x-small">{{ $t('mh.globeV2.datasetReal') }}</v-btn>
          <v-btn value="synthetic10" size="x-small">{{ $t('mh.globeV2.datasetSynthetic10') }}</v-btn>
        </v-btn-toggle>

        <!-- Theme Dark vs Light -->
        <v-btn-toggle
          v-model="globeTheme"
          mandatory
          density="compact"
          variant="outlined"
          class="mh-segmented"
          data-testid="proto-theme-toggle"
        >
          <v-btn value="dark" size="x-small">{{ $t('mh.globeV2.themeDark') }}</v-btn>
          <v-btn value="light" size="x-small">{{ $t('mh.globeV2.themeLight') }}</v-btn>
        </v-btn-toggle>

        <!-- Language zh-CN vs en -->
        <v-btn-toggle
          v-model="globeLang"
          mandatory
          density="compact"
          variant="outlined"
          class="mh-segmented"
          data-testid="proto-lang-toggle"
        >
          <v-btn value="zh-CN" size="x-small">中文</v-btn>
          <v-btn value="en" size="x-small">EN</v-btn>
        </v-btn-toggle>

        <!-- Pixel ratio 1 / 1.5 / 2 -->
        <v-btn-toggle
          v-if="engineMode === 'v2'"
          v-model="pixelRatio"
          mandatory
          density="compact"
          variant="outlined"
          class="mh-segmented"
          data-testid="proto-dpr-toggle"
        >
          <v-btn :value="1" size="x-small">1×</v-btn>
          <v-btn :value="1.5" size="x-small">1.5×</v-btn>
          <v-btn :value="2" size="x-small">2×</v-btn>
        </v-btn-toggle>

        <!-- Runtime cooperativeGestures toggle -->
        <v-btn
          v-if="engineMode === 'v2'"
          size="x-small"
          :variant="coopGestures ? 'tonal' : 'outlined'"
          :color="coopGestures ? 'primary' : undefined"
          data-testid="proto-coop-toggle"
          @click="coopGestures = !coopGestures"
        >
          {{ $t('mh.globeV2.coopGestures') }}: {{ coopGestures ? 'ON' : 'OFF' }}
        </v-btn>

        <!-- Full-page button -->
        <v-btn
          v-if="engineMode === 'v2'"
          size="x-small"
          variant="outlined"
          prepend-icon="mdi-arrow-expand-all"
          data-testid="proto-fullpage-btn"
          @click="globeMapRef?.toggleFullPage()"
        >
          {{ $t('mh.globeV2.fullPage') }}
        </v-btn>
      </div>
    </div>

    <!-- Perf HUD bar -->
    <div v-if="engineMode === 'v2'" class="mh-proto-hud" data-testid="proto-perf-hud">
      <v-btn
        size="x-small"
        color="primary"
        :loading="perfRunning"
        prepend-icon="mdi-speedometer"
        data-testid="proto-run-perf"
        @click="runPerf"
      >
        {{ perfRunning ? $t('mh.globeV2.perfRunning') : $t('mh.globeV2.runPerf10s') }}
      </v-btn>
      <v-btn
        v-if="perfReport"
        size="x-small"
        variant="outlined"
        prepend-icon="mdi-content-copy"
        data-testid="proto-copy-json"
        @click="copyPerfJson"
      >
        {{ copiedJson ? $t('mh.globeV2.copied') : $t('mh.globeV2.copyJson') }}
      </v-btn>

      <div class="mh-proto-hud__metrics mh-mono">
        <span data-testid="hud-ctx-lost">ctxLost={{ liveMetrics.webglContextLost }}</span>
        <span data-testid="hud-style-reloads">styleReloads={{ liveMetrics.styleReloads }}</span>
        <span data-testid="hud-coop">coop={{ liveMetrics.cooperativeGesturesActive ? 'on' : 'off' }}</span>
        <span v-if="liveMetrics.firstFrameMs != null" data-testid="hud-first-frame">
          firstFrame={{ liveMetrics.firstFrameMs }}ms
        </span>
        <template v-if="perfReport">
          <span data-testid="hud-p50">p50={{ perfReport.p50 }}ms</span>
          <span data-testid="hud-p95">p95={{ perfReport.p95 }}ms</span>
          <span data-testid="hud-max">max={{ perfReport.maxFrameMs }}ms</span>
          <span data-testid="hud-over50">&gt;50ms={{ perfReport.framesOver50ms }}</span>
          <span data-testid="hud-tile-bytes">tiles={{ Math.round(perfReport.tileBytes / 1024) }}KB</span>
          <span data-testid="hud-idle-frames">idle1s={{ perfReport.idleFramesAfter1s }}</span>
        </template>
      </div>
    </div>

    <!-- Globe Stage -->
    <mesh-globe-map
      v-if="engineMode === 'v2'"
      ref="globeMapRef"
      :nodes="activeNodes"
      :arcs="activeArcs"
      :center="activeCenter"
      :variant="variant"
      :theme-mode="globeTheme"
      :lang="globeLang"
      :pixel-ratio="pixelRatio"
      :cooperative-gestures="coopGestures"
      :dataset-tag="datasetMode"
      :height="620"
      @open-device="onOpenDevice"
      @metrics-change="onMetricsChange"
    />

    <mesh-globe
      v-else
      :nodes="activeNodes"
      :arcs="activeArcs"
      :center="activeCenter"
      :height="620"
      @open-device="onOpenDevice"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useTheme } from 'vuetify'
import { useI18n } from 'vue-i18n'
import { setLocale } from '@/plugins/i18n'
import { useStatsStore } from '@/stores/stats'
import { useAgentStore } from '@/stores/agents'
import MeshGlobe from '@/components/globe/MeshGlobe.vue'
import type { GlobeArc, GlobeCenter, GlobeNode } from '@/components/globe/types'
import MeshGlobeMap, { type GlobePerfReport } from '@/components/globe-v2/MeshGlobeMap.vue'
import { buildSyntheticMesh } from '@/components/globe-v2/syntheticData'
import type { GlobeLang, GlobeThemeMode } from '@/components/globe-v2/tokens'

const route = useRoute()
const router = useRouter()
const vuetifyTheme = useTheme()
const { locale } = useI18n()
const statsStore = useStatsStore()
const agentStore = useAgentStore()

const tenantId = computed(() => String(route.params.tenantId ?? ''))

const initialQuery = route.query
const engineMode = ref<'v2' | 'legacy'>(initialQuery.engine === 'legacy' ? 'legacy' : 'v2')
const variant = ref<'L' | 'A'>(initialQuery.variant === 'A' ? 'A' : 'L')
const datasetMode = ref<'real' | 'synthetic10'>(
  initialQuery.dataset === 'synthetic10' ? 'synthetic10' : 'real',
)
const globeTheme = ref<GlobeThemeMode>(
  initialQuery.theme === 'light'
    ? 'light'
    : initialQuery.theme === 'dark'
      ? 'dark'
      : vuetifyTheme.global.current.value.dark
        ? 'dark'
        : 'light',
)
const globeLang = ref<GlobeLang>(
  initialQuery.lang === 'en'
    ? 'en'
    : initialQuery.lang === 'zh-CN'
      ? 'zh-CN'
      : String(locale.value) === 'zh-CN'
        ? 'zh-CN'
        : 'en',
)
const pixelRatio = ref<number>(
  initialQuery.dpr ? Math.max(1, Math.min(2, Number(initialQuery.dpr) || 2)) : 2,
)
const coopGestures = ref<boolean>(initialQuery.coop !== '0')

const globeMapRef = ref<InstanceType<typeof MeshGlobeMap> | null>(null)
const perfRunning = ref(false)
const perfReport = ref<GlobePerfReport | null>(null)
const copiedJson = ref(false)

const liveMetrics = ref({
  firstFrameMs: null as number | null,
  webglContextLost: 0,
  styleReloads: 0,
  cooperativeGesturesActive: true,
  zoom: 1.75,
  displayedLinks: 0,
  overflowLinks: 0,
  unlocatedCount: 0,
})

const synthetic10 = buildSyntheticMesh(10)

// Sync UI chrome theme & i18n locale when user flips prototype switches
watch(
  globeTheme,
  (mode) => {
    vuetifyTheme.change(mode)
  },
  { immediate: true },
)

watch(
  globeLang,
  (lang) => {
    setLocale(lang)
  },
  { immediate: true },
)

// Join real tenant mesh payload + fleet agents without adding backend calls
const realNodes = computed<GlobeNode[]>(() => {
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
    return {
      id: n.id,
      agentId: n.agent_id_hex ?? null,
      name: fa?.display_name || ma?.display_name || fa?.name || ma?.name || n.name || n.id.slice(-6),
      online: fa ? fa.is_online : ma?.last_presence === 'online',
      presence,
      role: fa?.peer_relay_policy?.serve ? 'gateway' : 'device',
      isGateway: Boolean(fa?.peer_relay_policy?.serve),
      countryCode: fa?.country_code ?? null,
      country: fa?.country ?? null,
      region: fa?.region ?? null,
      city: fa?.city ?? null,
      relayHome: fa?.relay_home ?? ma?.relay_home ?? n.relay_home ?? null,
      os: fa?.os ?? ma?.os ?? null,
      version: fa?.agent_version ?? ma?.agent_version ?? null,
      lastSeenAt: fa?.last_seen_at ?? n.last_seen_at ?? null,
      overlayIp: n.overlay_ip ?? null,
      publicIp: fa?.public_ip ?? null,
      zoneId: fa?.effective_zone_id ?? fa?.pinned_zone_id ?? null,
      zoneName: fa?.effective_zone_name ?? null,
      zonePinned: Boolean(fa?.pinned_zone_id),
    }
  })
})

const realArcs = computed<GlobeArc[]>(() =>
  (statsStore.mesh?.edges ?? []).map((e) => ({
    key: `${e.from}-${e.to}-${e.carrier}`,
    from: e.from,
    to: e.to,
    carrier: e.carrier,
    color: '#56B4E9',
    stalled: Boolean(e.stalled),
    blocked: e.carrier === 'blocked',
    dashed: Boolean(e.stalled || e.carrier === 'blocked'),
    rttMs: e.rtt_ms ?? null,
    reports: e.reports,
    ends: e.ends,
    kind: 'peer',
  })),
)

const realCenter = computed<GlobeCenter | null>(() => {
  const c = statsStore.mesh?.center
  if (!c) return null
  return { id: c.id, name: c.name, countryCode: c.country_code ?? null }
})

const activeNodes = computed(() =>
  datasetMode.value === 'synthetic10' ? synthetic10.nodes : realNodes.value,
)
const activeArcs = computed(() =>
  datasetMode.value === 'synthetic10' ? synthetic10.arcs : realArcs.value,
)
const activeCenter = computed(() =>
  datasetMode.value === 'synthetic10' ? synthetic10.center : realCenter.value,
)

function onMetricsChange(m: typeof liveMetrics.value): void {
  liveMetrics.value = m
}

function onOpenDevice(): void {
  if (tenantId.value) {
    void router.push(`/tenant/${tenantId.value}/devices`)
  }
}

async function runPerf(): Promise<void> {
  if (!globeMapRef.value || perfRunning.value) return
  perfRunning.value = true
  try {
    perfReport.value = await globeMapRef.value.runPerfBenchmark(10_000)
  } finally {
    perfRunning.value = false
  }
}

async function copyPerfJson(): Promise<void> {
  if (!perfReport.value) return
  const txt = JSON.stringify(perfReport.value, null, 2)
  try {
    await navigator.clipboard.writeText(txt)
    copiedJson.value = true
    setTimeout(() => {
      copiedJson.value = false
    }, 1800)
  } catch {
    /* clipboard may be blocked in headless mode */
  }
}

onMounted(() => {
  if (tenantId.value) {
    void statsStore.fetchMesh(tenantId.value)
    void agentStore.fetchAgents(tenantId.value).catch(() => {})
  }
  // Expose P0 debug handle on window for deterministic headless verification
  ;(window as unknown as Record<string, unknown>).__GLOBE_P0_API__ = {
    runPerf: (ms = 10_000) => globeMapRef.value?.runPerfBenchmark(ms),
    getDebugState: () => globeMapRef.value?.getDebugState(),
    triggerClusterByName: (q: string) => globeMapRef.value?.triggerClusterByName(q),
    setCamera: (center: [number, number], zoom: number) => globeMapRef.value?.setCamera(center, zoom),
    toggleFullPage: () => globeMapRef.value?.toggleFullPage(),
    exitFullPage: () => globeMapRef.value?.exitFullPage(),
    collapseSpiderfy: () => globeMapRef.value?.collapseSpiderfy(),
    closePanel: () => globeMapRef.value?.closePanel(),
    setVariant: (v: 'L' | 'A') => { variant.value = v },
    setTheme: (m: GlobeThemeMode) => { globeTheme.value = m },
    setLang: (l: GlobeLang) => { globeLang.value = l },
    setDataset: (d: 'real' | 'synthetic10') => { datasetMode.value = d },
    setEngine: (e: 'v2' | 'legacy') => { engineMode.value = e },
    setCoop: (v: boolean) => { coopGestures.value = v },
    getMap: () => globeMapRef.value?.getMap(),
  }
})
</script>

<style scoped>
.mh-proto-wrap {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.mh-proto-header {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}
.mh-proto-toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
}
.mh-proto-hud {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  padding: 6px 10px;
  border-radius: var(--mh-radius, 10px);
  border: 1px solid var(--mh-hairline);
  background: rgba(var(--v-theme-surface-light), 0.5);
  font-size: 12px;
}
.mh-proto-hud__metrics {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  font-size: 11px;
}
</style>
