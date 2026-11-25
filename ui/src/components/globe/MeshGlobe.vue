<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  Production 3D MeshGlobe wrapper (FR-136 + FR-137):
  - Single engine: lazily-loaded MapLibre GL JS v6 + self-hosted PMTiles (`MeshGlobeMap.vue`),
    powering BOTH Device Network (`view-mode="devices"`) and Zone Backbone (`view-mode="backbone"`)
    on one shared MapLibre Map component & instance.
  - Automatic WebGL2 fallback (AC16): renders `#fallback` slot whenever WebGL2 is unavailable,
    `forceFallback` is true, or lazy chunk load fails.
  - Zero main-entry bundle growth (S11): MapLibre + PMTiles load strictly via `defineAsyncComponent`.
-->
<template>
  <div
    class="mh-globe-root"
    data-testid="mesh-globe-root"
    :data-globe-engine="use3D ? 'v2' : 'fallback'"
    :data-globe-view="viewMode"
  >
    <component
      :is="AsyncGlobeMapV2"
      v-if="use3D"
      ref="innerRef"
      :view-mode="viewMode"
      :nodes="nodes"
      :arcs="arcs"
      :center="center"
      :zones="zones"
      :overlay-devices="overlayDevices"
      :overlay-device-arcs="overlayDeviceArcs"
      :backbone-nodes="backboneNodes"
      :backbone-arcs="backboneArcs"
      :show-devices-overlay="showDevicesOverlay"
      :theme-mode="globeThemeMode"
      :lang="globeLang"
      :enabled-carriers="enabledCarriers"
      :only-problems="onlyProblems"
      :min-rtt-ms="minRttMs"
      :show-control-plane="showControlPlane"
      :show-detail-panel="showDetailPanel"
      :show-open-device-action="showOpenDeviceAction"
      :height="height"
      :aria-label="ariaLabel"
      :sync-url="syncUrl"
      @node-click="emit('node-click', $event)"
      @arc-click="emit('arc-click', $event)"
      @open-device="emit('open-device', $event)"
      @update:view-mode="emit('update:view-mode', $event)"
      @update:show-devices-overlay="emit('update:show-devices-overlay', $event)"
      @full-page-change="emit('full-page-change', $event)"
      @webgl-error="onWebglError"
    />
    <slot v-else name="fallback" />
  </div>
</template>

<script setup lang="ts">
import { computed, defineAsyncComponent, h, ref } from 'vue'
import { useTheme } from 'vuetify'
import { useI18n } from 'vue-i18n'
import type { GlobeLang, GlobeThemeMode } from '@/components/globe-v2/tokens'
import type { BackboneZoneView } from '@/stores/serverTopology'
import type { GlobeArc, GlobeCenter, GlobeNode } from './types'
import { isWebGL2Supported } from './webgl'

const props = withDefaults(
  defineProps<{
    viewMode?: 'devices' | 'backbone'
    nodes: readonly GlobeNode[]
    arcs: readonly GlobeArc[]
    center?: GlobeCenter | null
    zones?: readonly BackboneZoneView[]
    overlayDevices?: readonly GlobeNode[]
    overlayDeviceArcs?: readonly GlobeArc[]
    backboneNodes?: readonly GlobeNode[]
    backboneArcs?: readonly GlobeArc[]
    showDevicesOverlay?: boolean
    showControlPlane?: boolean
    showDetailPanel?: boolean
    showOpenDeviceAction?: boolean
    enabledCarriers?: readonly string[]
    onlyProblems?: boolean
    minRttMs?: number
    height?: number
    ariaLabel?: string
    /** Explicit override (e.g. user picked 2D Ring or test forcing fallback). */
    forceFallback?: boolean
    /** Sync selection (`g_sel`), view (`g_view`), and full-page (`g_full=1`) to URL query. */
    syncUrl?: boolean
  }>(),
  {
    viewMode: 'devices',
    center: null,
    zones: () => [],
    overlayDevices: () => [],
    overlayDeviceArcs: () => [],
    backboneNodes: () => [],
    backboneArcs: () => [],
    showDevicesOverlay: false,
    showControlPlane: true,
    showDetailPanel: true,
    showOpenDeviceAction: true,
    enabledCarriers: () => ['direct', 'relay', 'derp', 'tunnel', 'blocked'],
    onlyProblems: false,
    minRttMs: 0,
    height: 0,
    ariaLabel: '',
    forceFallback: false,
    syncUrl: true,
  },
)

const emit = defineEmits<{
  (e: 'node-click', nodeId: string): void
  (e: 'arc-click', arcKey: string): void
  (e: 'open-device', nodeId: string): void
  (e: 'update:view-mode', mode: 'devices' | 'backbone'): void
  (e: 'update:show-devices-overlay', show: boolean): void
  (e: 'full-page-change', full: boolean): void
  (e: 'fallback-active', reason: string): void
}>()

// Safely read Vuetify theme and i18n locale for seamless live dark/light & zh-CN/en sync.
let vuetifyTheme: ReturnType<typeof useTheme> | null = null
try {
  vuetifyTheme = useTheme()
} catch {
  vuetifyTheme = null
}

let i18nLocale: { value: unknown } | null = null
try {
  i18nLocale = useI18n().locale
} catch {
  i18nLocale = null
}

const globeThemeMode = computed<GlobeThemeMode>(() =>
  vuetifyTheme?.global?.current?.value?.dark === false ? 'light' : 'dark',
)

const globeLang = computed<GlobeLang>(() =>
  String(i18nLocale?.value ?? 'en') === 'zh-CN' ? 'zh-CN' : 'en',
)

const webglFailed = ref(false)
const webglAvailable = isWebGL2Supported()

if (!webglAvailable) {
  emit('fallback-active', 'webgl2-unavailable')
}

const use3D = computed(() => !props.forceFallback && webglAvailable && !webglFailed.value)

function onWebglError(reason: string) {
  webglFailed.value = true
  emit('fallback-active', reason)
}

interface InnerGlobeHandle {
  focusNodeById?: (id: string) => boolean
  focusArcByKey?: (key: string) => boolean
  selectNodeById?: (id: string) => boolean
  toggleFullPage?: () => void
  setViewMode?: (mode: 'devices' | 'backbone') => void
}

const innerRef = ref<InnerGlobeHandle | null>(null)

function focusNodeById(id: string): boolean {
  if (innerRef.value?.focusNodeById) return innerRef.value.focusNodeById(id)
  if (innerRef.value?.selectNodeById) return innerRef.value.selectNodeById(id)
  return false
}

function focusArcByKey(key: string): boolean {
  if (innerRef.value?.focusArcByKey) return innerRef.value.focusArcByKey(key)
  return false
}

function toggleFullPage(): void {
  innerRef.value?.toggleFullPage?.()
}

defineExpose({
  focusNodeById,
  focusArcByKey,
  toggleFullPage,
})

const loadingStub = {
  render() {
    return h('div', { class: 'mh-globe-loading', 'data-testid': 'mesh-globe-loading' })
  },
}

// Lazy-loaded via dynamic import() so MapLibre GL JS + PMTiles NEVER enter the main SPA entry bundle.
const AsyncGlobeMapV2 = defineAsyncComponent({
  loader: () => import('@/components/globe-v2/MeshGlobeMap.vue'),
  delay: 120,
  loadingComponent: loadingStub,
  onError(_err, _retry, fail) {
    webglFailed.value = true
    emit('fallback-active', 'chunk-load-failed')
    fail()
  },
})
</script>

<style scoped>
.mh-globe-root {
  width: 100%;
}
.mh-globe-loading {
  width: 100%;
  min-height: 360px;
  border-radius: var(--mh-radius);
  border: 1px solid var(--mh-hairline);
  background: rgba(var(--v-theme-surface-light), 0.6);
}
</style>
