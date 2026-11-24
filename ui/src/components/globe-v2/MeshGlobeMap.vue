<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  MapLibre GL JS 6.19.0 + self-hosted PMTiles 4.5.0 globe engine (FR-136 P0/P2).
  - Same-origin worker via `maplibre-gl/dist/maplibre-gl-worker.mjs?url`.
  - Zero external CDN requests; style omits `glyphs` (system + CJK font stack).
  - North-up locked (maxPitch: 0, dragRotate: false, touchPitch: false, rotation disabled).
  - Zero auto-rotation; 0 rendered frames when idle.
  - Live dark/light and en/zh-CN switching with ZERO setStyle() reload.
  - Supports Variant L (native great-circle line layers) and Variant A (custom WebGL2
    elevated 3D SLERP arcs below z5, smoothly flattening to surface by z5).
-->
<template>
  <div ref="placeholderEl" class="mh-gv2-placeholder" :style="placeholderStyle">
    <Teleport to="body" :disabled="!fullPage.isFull.value">
      <div
        ref="shellEl"
        class="mh-gv2-shell"
        :class="[
          `mh-gv2-shell--${themeMode}`,
          {
            'mh-gv2-shell--full': fullPage.isFull.value,
            'mh-gv2-shell--mobile': isMobile,
          },
        ]"
        :style="shellStyle"
        data-testid="globe-v2-shell"
        :data-full-page="fullPage.isFull.value ? '1' : '0'"
      >
        <div
          ref="mapHostEl"
          class="mh-gv2-canvas"
          role="application"
          :aria-label="$t('mh.mesh.globeAria')"
          data-testid="globe-v2-canvas"
        />

        <!-- Hidden DOM host moved into MapLibre Marker when spiderfy is active -->
        <div ref="spiderfyHostEl" class="mh-gv2-spiderfy-host">
          <spiderfy-overlay
            v-if="activeSpiderfy"
            :layout="activeSpiderfy.layout"
            :tokens="tokens"
            :selected-node-id="selectedNode?.id ?? null"
            @select-node="onSelectSpiderfyNode"
            @hover-node="onHoverSpiderfyNode"
            @collapse="collapseSpiderfy"
          />
        </div>

        <!-- Top-right quick controls inside the globe shell (always visible in full-page/fullscreen) -->
        <div class="mh-gv2-top-actions" data-testid="globe-v2-actions">
          <button
            type="button"
            class="mh-gv2-icon-btn"
            :aria-label="$t('mh.mesh.controls.zoomIn')"
            :title="$t('mh.mesh.controls.zoomIn')"
            @click="zoomBy(1)"
          >
            <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true">
              <path d="M8 3.5v9M3.5 8h9" />
            </svg>
          </button>
          <button
            type="button"
            class="mh-gv2-icon-btn"
            :aria-label="$t('mh.mesh.controls.zoomOut')"
            :title="$t('mh.mesh.controls.zoomOut')"
            @click="zoomBy(-1)"
          >
            <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true">
              <path d="M3.5 8h9" />
            </svg>
          </button>
          <button
            type="button"
            class="mh-gv2-icon-btn"
            :aria-label="$t('mh.mesh.controls.reset')"
            :title="$t('mh.mesh.controls.reset')"
            @click="resetView"
          >
            <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" aria-hidden="true">
              <circle cx="8" cy="8" r="4.2" />
              <path d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2" />
            </svg>
          </button>
          <button
            v-if="fullPage.isFull.value && fullPage.fullscreenSupported.value"
            type="button"
            class="mh-gv2-icon-btn mh-gv2-icon-btn--wide"
            :aria-label="$t('mh.globeV2.browserFullscreen')"
            :title="$t('mh.globeV2.browserFullscreen')"
            data-testid="globe-v2-native-fullscreen"
            @click="fullPage.toggleNativeFullscreen()"
          >
            <svg v-if="!fullPage.isNativeFullscreen.value" viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M2.5 6V2.5H6M10 2.5h3.5V6M13.5 10v3.5H10M6 13.5H2.5V10" />
            </svg>
            <svg v-else viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M6 2.5V6H2.5M13.5 6H10V2.5M10 13.5V10h3.5M2.5 10H6v3.5" />
            </svg>
          </button>
          <button
            ref="fullTriggerEl"
            type="button"
            class="mh-gv2-icon-btn mh-gv2-icon-btn--wide"
            :aria-label="fullPage.isFull.value ? $t('mh.globeV2.exitFullPage') : $t('mh.globeV2.fullPage')"
            :title="fullPage.isFull.value ? $t('mh.globeV2.exitFullPage') : $t('mh.globeV2.fullPage')"
            data-testid="globe-v2-fullpage-toggle"
            @click="fullPage.toggleFullPage()"
          >
            <svg v-if="!fullPage.isFull.value" viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M9.5 2.5h4v4M6.5 13.5h-4v-4M13.5 2.5l-4.5 4.5M2.5 13.5l4.5-4.5" />
            </svg>
            <svg v-else viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true">
              <path d="M4 4l8 8M12 4l-8 8" />
            </svg>
          </button>
        </div>

        <!-- Hover card (desktop only, WCAG 1.4.13 hoverable/dismissible/persistent) -->
        <div
          v-if="!isMobile && hoverCard"
          class="mh-gv2-hover-card"
          :style="{ left: `${hoverCard.x}px`, top: `${hoverCard.y}px` }"
          role="status"
          data-testid="globe-v2-hover-card"
          @mouseenter="cancelHoverClose"
          @mouseleave="scheduleHoverClose"
        >
          <div class="mh-gv2-hover-card__title">{{ hoverCard.title }}</div>
          <div class="mh-gv2-hover-card__meta">{{ hoverCard.subtitle }}</div>
          <div v-if="hoverCard.extra" class="mh-gv2-hover-card__extra">{{ hoverCard.extra }}</div>
        </div>

        <!-- Bottom-left collapsible legend + unknown-location chip + overflow + attribution -->
        <div
          class="mh-gv2-legend"
          :class="{ 'mh-gv2-legend--collapsed': legendCollapsed }"
          data-testid="globe-v2-legend"
        >
          <div class="mh-gv2-legend__bar">
            <button
              type="button"
              class="mh-gv2-legend__toggle"
              @click="legendCollapsed = !legendCollapsed"
            >
              {{ $t('mh.globeV2.legend') }} {{ legendCollapsed ? '▸' : '▾' }}
            </button>
            <button
              v-if="grouped.unlocated.length > 0"
              type="button"
              class="mh-gv2-chip mh-gv2-chip--warn"
              data-testid="globe-v2-unknown-chip"
              @click="openUnknownList"
            >
              {{ $t('mh.globeV2.unknownLocation', { n: grouped.unlocated.length }) }}
            </button>
            <span
              v-if="linkAgg.overflowCount > 0"
              class="mh-gv2-chip"
              data-testid="globe-v2-overflow-chip"
            >
              {{ $t('mh.globeV2.linksOverflow', { n: linkAgg.overflowCount }) }}
            </span>
          </div>

          <div v-if="!legendCollapsed" class="mh-gv2-legend__body">
            <div class="mh-gv2-legend__row">
              <span class="mh-gv2-swatch-dot" :style="{ background: tokens.online }" />
              <span>{{ $t('mh.mesh.status.online') }}</span>
              <span class="mh-gv2-swatch-dot mh-gv2-swatch-dot--half" :style="{ '--c': tokens.stale, '--bg': tokens.ocean }" />
              <span>{{ $t('mh.mesh.status.stale') }}</span>
              <span class="mh-gv2-swatch-dot mh-gv2-swatch-dot--off" :style="{ borderColor: tokens.offline }" />
              <span>{{ $t('mh.mesh.status.offline') }}</span>
            </div>
            <div class="mh-gv2-legend__row">
              <span class="mh-gv2-swatch-line" :style="{ background: tokens.direct }" />
              <span>{{ $t('mh.mesh.carriers.direct') }}</span>
              <span class="mh-gv2-swatch-line mh-gv2-swatch-line--dash" :style="{ '--c': tokens.relay }" />
              <span>{{ $t('mh.mesh.carriers.relay') }}</span>
              <span class="mh-gv2-swatch-line mh-gv2-swatch-line--short" :style="{ '--c': tokens.derp }" />
              <span>{{ $t('mh.mesh.carriers.derp') }}</span>
              <span class="mh-gv2-swatch-line mh-gv2-swatch-line--dot" :style="{ '--c': tokens.stalled }" />
              <span>{{ $t('mh.mesh.stalled') }}</span>
            </div>
            <div class="mh-gv2-legend__attr" data-testid="globe-v2-attribution">
              {{ attributionText }}
            </div>
          </div>
        </div>

        <!-- Non-modal detail / paginated list panel (desktop right side; mobile bottom sheet) -->
        <aside
          v-if="panelOpen"
          class="mh-gv2-panel"
          :class="{
            'mh-gv2-panel--mobile': isMobile,
            [`mh-gv2-panel--snap-${mobileSnap}`]: isMobile,
          }"
          role="region"
          :aria-label="panelTitle"
          data-testid="globe-v2-panel"
          @click.stop
        >
          <div v-if="isMobile" class="mh-gv2-panel__grabber" @click="cycleMobileSnap">
            <span class="mh-gv2-panel__grabber-bar" />
          </div>

          <div class="mh-gv2-panel__head">
            <div class="mh-gv2-panel__title" :title="panelTitle">{{ panelTitle }}</div>
            <button
              type="button"
              class="mh-gv2-icon-btn"
              :aria-label="$t('mh.mesh.panel.close')"
              data-testid="globe-v2-panel-close"
              @click="closePanel"
            >
              ×
            </button>
          </div>

          <!-- Single device detail -->
          <div v-if="selectedNode" class="mh-gv2-panel__body">
            <dl class="mh-gv2-facts">
              <div class="mh-gv2-fact">
                <dt>{{ $t('mh.globeV2.statusLabel') }}</dt>
                <dd>{{ presenceLabel(selectedNode) }}</dd>
              </div>
              <div class="mh-gv2-fact">
                <dt>{{ $t('mh.globeV2.countryRegion') }}</dt>
                <dd>{{ selectedNodeRegionText }}</dd>
              </div>
              <div class="mh-gv2-fact">
                <dt>{{ $t('mh.globeV2.locationPrecision') }}</dt>
                <dd>{{ selectedNodePrecisionText }}</dd>
              </div>
              <div v-if="selectedNode.os || selectedNode.version" class="mh-gv2-fact">
                <dt>{{ $t('mh.mesh.panel.system') }}</dt>
                <dd class="mh-mono">
                  {{ [selectedNode.os, selectedNode.version ? `v${selectedNode.version}` : ''].filter(Boolean).join(' · ') }}
                </dd>
              </div>
              <div v-if="selectedNode.publicIp" class="mh-gv2-fact">
                <dt>{{ $t('mh.mesh.panel.publicIp') }}</dt>
                <dd class="mh-mono">{{ selectedNode.publicIp }}</dd>
              </div>
              <div v-if="selectedNode.overlayIp" class="mh-gv2-fact">
                <dt>{{ $t('mh.mesh.panel.overlayIp') }}</dt>
                <dd class="mh-mono">{{ selectedNode.overlayIp }}</dd>
              </div>
              <div v-if="selectedNode.zoneName || selectedNode.zoneId" class="mh-gv2-fact">
                <dt>{{ $t('mh.globeV2.zone') }}</dt>
                <dd>{{ selectedNode.zoneName || selectedNode.zoneId }}</dd>
              </div>
            </dl>

            <div v-if="egoLinks.length" class="mh-gv2-section">
              <div class="mh-gv2-section__title">
                {{ $t('mh.mesh.panel.peers', { n: egoLinks.length }) }}
              </div>
              <div class="mh-gv2-list">
                <button
                  v-for="l in egoLinks.slice(0, 20)"
                  :key="l.key"
                  type="button"
                  class="mh-gv2-list-row"
                  @click="selectAggregatedLink(l)"
                >
                  <span>{{ remoteClusterLabel(l, selectedNodeDisplayId) }}</span>
                  <span class="mh-mono">
                    {{ l.worstClass }}{{ l.medianRtt != null ? ` · ${l.medianRtt} ms` : '' }}
                  </span>
                </button>
              </div>
            </div>

            <button
              v-if="!selectedNode.isCentre"
              type="button"
              class="mh-gv2-primary-btn"
              @click="emit('open-device', selectedNode.id)"
            >
              {{ $t('mh.mesh.panel.openDevice') }}
            </button>
          </div>

          <!-- Aggregated link detail -->
          <div v-else-if="selectedLink" class="mh-gv2-panel__body">
            <dl class="mh-gv2-facts">
              <div class="mh-gv2-fact">
                <dt>{{ $t('mh.mesh.panel.carrier') }}</dt>
                <dd class="mh-mono">{{ selectedLink.worstClass }}</dd>
              </div>
              <div class="mh-gv2-fact">
                <dt>{{ $t('mh.globeV2.aggregatedCount') }}</dt>
                <dd class="mh-mono">{{ selectedLink.count }}</dd>
              </div>
              <div v-if="selectedLink.medianRtt != null" class="mh-gv2-fact">
                <dt>{{ $t('mh.globeV2.medianRtt') }}</dt>
                <dd class="mh-mono">{{ selectedLink.medianRtt }} ms</dd>
              </div>
              <div v-if="selectedLink.maxRtt != null" class="mh-gv2-fact">
                <dt>{{ $t('mh.globeV2.maxRtt') }}</dt>
                <dd class="mh-mono">{{ selectedLink.maxRtt }} ms</dd>
              </div>
              <div v-if="selectedLink.asymmetric" class="mh-gv2-fact">
                <dt>{{ $t('mh.mesh.asymmetricTag') }}</dt>
                <dd class="mh-mono">{{ selectedLink.fromClass }} / {{ selectedLink.toClass }}</dd>
              </div>
            </dl>
          </div>

          <!-- Paginated list (city group >20, multi-city cluster, or unknown location devices) -->
          <div v-else-if="listPanelNodes.length" class="mh-gv2-panel__body">
            <div v-if="selectedClusterIntraCity > 0" class="mh-gv2-note" data-testid="globe-v2-intracity-note">
              {{ $t('mh.globeV2.intraCityLinks', { n: selectedClusterIntraCity }) }}
            </div>
            <div v-if="listPanelPrecisionNote" class="mh-gv2-note">
              {{ listPanelPrecisionNote }}
            </div>
            <div class="mh-gv2-list" data-testid="globe-v2-paginated-list">
              <button
                v-for="item in pagedListNodes"
                :key="item.id"
                type="button"
                class="mh-gv2-list-row"
                @click="selectNodeFromList(item)"
              >
                <span class="mh-gv2-list-row__name">
                  <span
                    class="mh-gv2-swatch-dot"
                    :style="{
                      background:
                        effectivePresence(item) === 'online'
                          ? tokens.online
                          : effectivePresence(item) === 'stale'
                            ? tokens.stale
                            : tokens.offline,
                    }"
                  />
                  {{ item.name }}
                </span>
                <span class="mh-mono">{{ item.zoneName || presenceLabel(item) }}</span>
              </button>
            </div>
            <div v-if="listTotalPages > 1" class="mh-gv2-pager">
              <button
                type="button"
                class="mh-gv2-icon-btn"
                :disabled="listPage <= 1"
                @click="listPage--"
              >
                ‹
              </button>
              <span class="mh-mono">{{ listPage }} / {{ listTotalPages }}</span>
              <button
                type="button"
                class="mh-gv2-icon-btn"
                :disabled="listPage >= listTotalPages"
                @click="listPage++"
              >
                ›
              </button>
            </div>
          </div>
        </aside>

        <!-- Context-lost banner (AC13 / S11) -->
        <div v-if="contextLostActive" class="mh-gv2-context-lost" role="alert">
          {{ $t('mh.globeV2.contextLost') }}
        </div>
      </div>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import * as maplibregl from 'maplibre-gl'
import type { GeoJSONSource, Map as MapLibreMap, Marker } from 'maplibre-gl'
import 'maplibre-gl/dist/maplibre-gl.css'
import workerUrl from 'maplibre-gl/dist/maplibre-gl-worker.mjs?url'
import { Protocol } from 'pmtiles'
import { appPath } from '@/utils/deployment'
import type { GlobeArc, GlobeCenter, GlobeNode } from '@/components/globe/types'
import {
  BOUNDARY_ATTRIBUTION,
  CJK_FONT_STACK,
  formatNeutralRegionName,
  getGlobeTokens,
  type GlobeLang,
  type GlobeThemeMode,
} from './tokens'
import {
  classifyGroupInteraction,
  clusterGroupsForZoom,
  computeSpiderfyLayout,
  effectivePresence,
  findClusterSplitZoom,
  formatClusterLabel,
  groupNodesByLocation,
  LIST_PAGE_SIZE,
  type DisplayCluster,
} from './grouping'
import type { SpiderfyLayout } from './spiderfy'
import {
  aggregateLinks,
  buildEgoNetwork,
  buildLinkGeoJson,
  type AggregatedLink,
} from './links'
import { ensureStaticIcons, hitHalfBoxPx, resolveClusterIconId } from './icons'
import {
  applyLangToMap,
  applyThemeToMap,
  buildGlobeStyle,
  LINK_BADGES_SOURCE_ID,
  LINKS_SOURCE_ID,
  MARKERS_SOURCE_ID,
  setSurfaceLinksVisible,
  SURFACE_LINK_LAYER_IDS,
} from './style'
import { ElevatedArcsLayer, type ElevatedArcDrawEntry } from './elevatedArcsLayer'
import { useFullPage } from './useFullPage'
import SpiderfyOverlay from './SpiderfyOverlay.vue'

// Module-level once-only MapLibre worker + PMTiles protocol setup (S1).
let maplibreInitialized = false
function ensureMapLibreSetup(): void {
  if (maplibreInitialized) return
  maplibreInitialized = true
  maplibregl.setWorkerUrl(workerUrl)
  const protocol = new Protocol()
  maplibregl.addProtocol('pmtiles', protocol.tile)
}

export interface GlobePerfReport {
  variant: 'L' | 'A'
  pixelRatio: number
  dataset: string
  viewport: { width: number; height: number }
  renderer: string
  durationMs: number
  totalFrames: number
  avgFps: number
  p50: number
  p95: number
  maxFrameMs: number
  framesOver50ms: number
  tileBytes: number
  firstFrameMs: number | null
  idleFramesAfter1s: number
  webglContextLost: number
  styleReloads: number
  cooperativeGesturesSupported: boolean
  timestamp: string
}

const props = withDefaults(
  defineProps<{
    nodes: readonly GlobeNode[]
    arcs: readonly GlobeArc[]
    center?: GlobeCenter | null
    variant?: 'L' | 'A'
    themeMode?: GlobeThemeMode
    lang?: GlobeLang
    pixelRatio?: number
    cooperativeGestures?: boolean
    pmtilesPath?: string
    enabledCarriers?: readonly string[]
    onlyProblems?: boolean
    minRttMs?: number
    showControlPlane?: boolean
    height?: number
    datasetTag?: string
  }>(),
  {
    center: null,
    variant: 'L',
    themeMode: 'dark',
    lang: 'zh-CN',
    pixelRatio: 2,
    cooperativeGestures: true,
    pmtilesPath: '',
    enabledCarriers: () => ['direct', 'tunnel', 'relay', 'derp'],
    onlyProblems: false,
    minRttMs: 0,
    showControlPlane: true,
    height: 560,
    datasetTag: 'real',
  },
)

const emit = defineEmits<{
  (e: 'open-device', nodeId: string): void
  (e: 'full-page-change', full: boolean): void
  (
    e: 'metrics-change',
    metrics: {
      firstFrameMs: number | null
      webglContextLost: number
      styleReloads: number
      cooperativeGesturesActive: boolean
      zoom: number
      displayedLinks: number
      overflowLinks: number
      unlocatedCount: number
    },
  ): void
}>()

const { t } = useI18n()

const placeholderEl = ref<HTMLElement | null>(null)
const shellEl = ref<HTMLElement | null>(null)
const mapHostEl = ref<HTMLElement | null>(null)
const spiderfyHostEl = ref<HTMLElement | null>(null)
const fullTriggerEl = ref<HTMLElement | null>(null)

const mapRef = shallowRef<MapLibreMap | null>(null)
const elevatedLayerRef = shallowRef<ElevatedArcsLayer | null>(null)
const spiderfyMarkerRef = shallowRef<Marker | null>(null)
const styleReady = ref(false)

const currentZoom = ref(1.5)
const currentZi = ref(1)
const viewportWidth = ref(typeof window !== 'undefined' ? window.innerWidth : 1280)
const isMobile = computed(() => viewportWidth.value < 600)
const isCoarsePointer = computed(
  () =>
    isMobile.value ||
    (typeof window !== 'undefined' && Boolean(window.matchMedia?.('(pointer: coarse)').matches)),
)
const prefersReducedMotion = computed(
  () =>
    typeof window !== 'undefined' &&
    Boolean(window.matchMedia?.('(prefers-reduced-motion: reduce)').matches),
)

const tokens = computed(() => getGlobeTokens(props.themeMode))
const attributionText = computed(() => BOUNDARY_ATTRIBUTION[props.lang])
const resolvedPmtilesUrl = computed(() => props.pmtilesPath || appPath('/geo/mh-boundaries-v1.pmtiles'))

// Telemetry counters for P0 verification
const mountTime = typeof performance !== 'undefined' ? performance.now() : 0
const firstFrameMs = ref<number | null>(null)
const webglContextLostCount = ref(0)
const contextLostActive = ref(false)
const styleReloadCount = ref(0)
const cooperativeGesturesActive = ref(props.cooperativeGestures)
let renderEventCounter = 0

// Interactive state
const legendCollapsed = ref(false)
const selectedNode = ref<GlobeNode | null>(null)
const selectedCluster = ref<DisplayCluster | null>(null)
const selectedLink = ref<AggregatedLink | null>(null)
const showingUnknownList = ref(false)
const hoveredDisplayId = ref<string | null>(null)
const hoveredNode = ref<GlobeNode | null>(null)
const hoveredLinkKey = ref<string | null>(null)
const listPage = ref(1)
const mobileSnap = ref<'peek' | 'mid' | 'full'>('peek')

interface HoverCardState {
  x: number
  y: number
  title: string
  subtitle: string
  extra?: string
}
const hoverCard = ref<HoverCardState | null>(null)
let hoverShowTimer: ReturnType<typeof setTimeout> | null = null
let hoverCloseTimer: ReturnType<typeof setTimeout> | null = null

interface ActiveSpiderfy {
  cluster: DisplayCluster
  layout: SpiderfyLayout
  startZoom: number
}
const activeSpiderfy = ref<ActiveSpiderfy | null>(null)

const fullPage = useFullPage({
  containerRef: shellEl,
  triggerRef: fullTriggerEl,
  onToggle(full) {
    emit('full-page-change', full)
    syncCooperativeGestures()
    void nextTick(() => {
      mapRef.value?.resize()
    })
  },
})

const effectiveCooperativeGestures = computed(
  () => !fullPage.isFull.value && props.cooperativeGestures,
)

const placeholderStyle = computed(() => ({
  minHeight: isMobile.value ? 'min(56vh, 420px)' : `${props.height}px`,
}))

const shellStyle = computed(() =>
  fullPage.isFull.value
    ? {}
    : {
        height: isMobile.value ? 'min(56vh, 420px)' : `${props.height}px`,
      },
)

// All nodes including optional centre node (when located and control plane shown)
const allGlobeNodes = computed<GlobeNode[]>(() => {
  const list = [...props.nodes]
  if (props.showControlPlane && props.center) {
    const hasCoords =
      typeof props.center.lat === 'number' && typeof props.center.lon === 'number'
    if (hasCoords || props.center.countryCode) {
      list.push({
        id: props.center.id,
        name: props.center.name,
        online: true,
        presence: 'online',
        role: 'centre',
        isCentre: true,
        lat: props.center.lat ?? null,
        lon: props.center.lon ?? null,
        countryCode: props.center.countryCode ?? null,
        country: props.center.locationLabel ?? null,
      })
    }
  }
  return list
})

const grouped = computed(() => groupNodesByLocation(allGlobeNodes.value))

const merged = computed(() => clusterGroupsForZoom(grouped.value.groups, currentZi.value, 40))
const clusterById = computed(() => new Map(merged.value.clusters.map((c) => [c.id, c])))

const carrierSet = computed(() => new Set(props.enabledCarriers))

const linkAgg = computed(() =>
  aggregateLinks(
    props.arcs,
    merged.value.displayIdByNodeId,
    grouped.value.groupKeyByNodeId,
    clusterById.value,
    {
      enabledCarriers: carrierSet.value,
      showBlocked: carrierSet.value.has('blocked'),
      onlyProblems: props.onlyProblems,
      minRttMs: props.minRttMs,
      maxOverviewLinks: 60,
    },
  ),
)

const activeFocus = computed<{ nodeId?: string | null; displayId?: string | null } | null>(() => {
  if (hoveredNode.value) return { nodeId: hoveredNode.value.id }
  if (hoveredDisplayId.value) return { displayId: hoveredDisplayId.value }
  if (selectedNode.value) return { nodeId: selectedNode.value.id }
  if (selectedCluster.value) return { displayId: selectedCluster.value.id }
  if (activeSpiderfy.value) return { displayId: activeSpiderfy.value.cluster.id }
  return null
})

const egoLinks = computed<AggregatedLink[]>(() => {
  if (!activeFocus.value) return []
  return buildEgoNetwork(
    props.arcs,
    activeFocus.value,
    merged.value.displayIdByNodeId,
    grouped.value.groupKeyByNodeId,
    clusterById.value,
    {
      enabledCarriers: carrierSet.value,
      showBlocked: carrierSet.value.has('blocked'),
      onlyProblems: props.onlyProblems,
      minRttMs: props.minRttMs,
    },
  )
})

const selectedNodeDisplayId = computed(() =>
  selectedNode.value ? merged.value.displayIdByNodeId.get(selectedNode.value.id) ?? null : null,
)

const listPanelNodes = computed<GlobeNode[]>(() => {
  if (showingUnknownList.value) return grouped.value.unlocated
  if (selectedCluster.value) return selectedCluster.value.nodes
  return []
})

const listTotalPages = computed(() => Math.max(1, Math.ceil(listPanelNodes.value.length / LIST_PAGE_SIZE)))
const pagedListNodes = computed(() => {
  const start = (listPage.value - 1) * LIST_PAGE_SIZE
  return listPanelNodes.value.slice(start, start + LIST_PAGE_SIZE)
})

const selectedClusterIntraCity = computed(() => {
  if (!selectedCluster.value) return 0
  let sum = 0
  for (const g of selectedCluster.value.groups) {
    sum += linkAgg.value.intraCityCountByGroup.get(g.key) ?? 0
  }
  return sum
})

const listPanelPrecisionNote = computed(() => {
  if (showingUnknownList.value) return t('mh.globeV2.unknownExplain')
  if (!selectedCluster.value) return ''
  return precisionText(selectedCluster.value.precision)
})

const panelOpen = computed(
  () =>
    Boolean(selectedNode.value || selectedLink.value || showingUnknownList.value || selectedCluster.value),
)

const panelTitle = computed(() => {
  if (selectedNode.value) return selectedNode.value.name
  if (selectedLink.value) {
    const a = clusterById.value.get(selectedLink.value.fromDisplayId)
    const b = clusterById.value.get(selectedLink.value.toDisplayId)
    const la = a ? formatClusterLabel(a, props.lang) : selectedLink.value.fromDisplayId
    const lb = b ? formatClusterLabel(b, props.lang) : selectedLink.value.toDisplayId
    return `${la} ↔ ${lb}`
  }
  if (showingUnknownList.value) {
    return t('mh.globeV2.unknownLocation', { n: grouped.value.unlocated.length })
  }
  if (selectedCluster.value) {
    return formatClusterLabel(selectedCluster.value, props.lang)
  }
  return ''
})

const selectedNodeRegionText = computed(() => {
  const n = selectedNode.value
  if (!n) return '—'
  const res = grouped.value.resolvedByNodeId.get(n.id)
  if (!res || res.precision === 'unknown') return t('mh.mesh.panel.locationUnknown')
  return (
    formatNeutralRegionName(res.countryCode, res.locationLabel || res.placeEn, props.lang) ||
    t('mh.mesh.panel.locationUnknown')
  )
})

const selectedNodePrecisionText = computed(() => {
  const n = selectedNode.value
  if (!n) return ''
  const res = grouped.value.resolvedByNodeId.get(n.id)
  return precisionText(res?.precision ?? 'unknown')
})

function precisionText(precision: string): string {
  if (precision === 'coords') return t('mh.globeV2.precisionCoords')
  if (precision === 'city') return t('mh.globeV2.precisionCity')
  if (precision === 'region') return t('mh.globeV2.precisionRegion')
  if (precision === 'country') return t('mh.globeV2.precisionCountry')
  return t('mh.globeV2.precisionUnknown')
}

function presenceLabel(node: GlobeNode): string {
  const p = effectivePresence(node)
  return t(`mh.mesh.status.${p}`)
}

function remoteClusterLabel(link: AggregatedLink, selfDisplayId: string | null): string {
  const remoteId = link.fromDisplayId === selfDisplayId ? link.toDisplayId : link.fromDisplayId
  const c = clusterById.value.get(remoteId)
  return c ? formatClusterLabel(c, props.lang) : remoteId
}

function emitMetrics(): void {
  emit('metrics-change', {
    firstFrameMs: firstFrameMs.value,
    webglContextLost: webglContextLostCount.value,
    styleReloads: styleReloadCount.value,
    cooperativeGesturesActive: cooperativeGesturesActive.value,
    zoom: currentZoom.value,
    displayedLinks: linkAgg.value.displayed.length,
    overflowLinks: linkAgg.value.overflowCount,
    unlocatedCount: grouped.value.unlocated.length,
  })
}

function syncCooperativeGestures(): void {
  const map = mapRef.value
  if (!map || !map.cooperativeGestures) return
  if (effectiveCooperativeGestures.value) {
    map.cooperativeGestures.enable()
  } else {
    map.cooperativeGestures.disable()
  }
  cooperativeGesturesActive.value = map.cooperativeGestures.isEnabled()
  emitMetrics()
}

function syncVariantVisibility(): void {
  const map = mapRef.value
  const elev = elevatedLayerRef.value
  if (!map || !styleReady.value) return
  const useElevatedNow = props.variant === 'A' && map.getZoom() < 5
  elev?.setEnabled(props.variant === 'A')
  setSurfaceLinksVisible(map, !useElevatedNow)
  map.triggerRepaint()
}

function syncMapSources(): void {
  const map = mapRef.value
  if (!map || !styleReady.value) return

  const dpr = Math.max(1, Math.min(2, props.pixelRatio))
  ensureStaticIcons(map, props.themeMode, dpr)

  const hasSpiderfy = Boolean(activeSpiderfy.value)
  const spiderfyId = activeSpiderfy.value?.cluster.id ?? null
  const selClusterId = selectedCluster.value?.id ?? selectedNodeDisplayId.value ?? null
  const z = map.getZoom()

  // Sort markers for priority labeling (S5/S6): selected > centre > gateway > problem > top-6 city > rest
  const top6Ids = new Set(merged.value.clusters.slice(0, 6).map((c) => c.id))
  const markerFeatures: Array<GeoJSON.Feature<GeoJSON.Point>> = merged.value.clusters.map((c, idx) => {
    const isSel = c.id === selClusterId || (selectedNode.value != null && c.nodes.some((n) => n.id === selectedNode.value?.id))
    const isSpid = c.id === spiderfyId
    const icon = resolveClusterIconId(map, c, props.themeMode, dpr, isSel, isSpid)

    let sortKey = 600 + idx
    if (isSel) sortKey = 10
    else if (c.hasCentre) sortKey = 20
    else if (c.hasGateway) sortKey = 30
    else if (c.hasProblem) sortKey = 40
    else if (c.count >= 2) sortKey = 100 + idx

    // LOD label gating (S6 / S10)
    let showLabel = true
    if (isSpid) {
      showLabel = false
    } else if (z < 2.5) {
      showLabel = isSel || c.hasCentre || c.hasProblem || top6Ids.has(c.id)
    } else if (isMobile.value && z < 4) {
      showLabel = isSel || c.hasCentre || c.hasProblem || c.count >= 2
    }

    return {
      type: 'Feature',
      geometry: { type: 'Point', coordinates: [c.lon, c.lat] },
      properties: {
        id: c.id,
        icon,
        label: showLabel ? formatClusterLabel(c, props.lang) : '',
        sortKey,
        opacity: hasSpiderfy && !isSpid ? 0.3 : 1,
        count: c.count,
      },
    }
  })

  const markerSrc = map.getSource(MARKERS_SOURCE_ID) as GeoJSONSource | undefined
  markerSrc?.setData({ type: 'FeatureCollection', features: markerFeatures })

  const hasEgo = Boolean(activeFocus.value && egoLinks.value.length > 0)
  const { lines, badges } = buildLinkGeoJson(linkAgg.value.displayed, egoLinks.value, {
    hoveredLinkKey: hoveredLinkKey.value,
    selectedLinkKey: selectedLink.value?.key ?? null,
    hasEgoFocus: hasEgo,
  })

  const linksSrc = map.getSource(LINKS_SOURCE_ID) as GeoJSONSource | undefined
  linksSrc?.setData(lines)
  const badgesSrc = map.getSource(LINK_BADGES_SOURCE_ID) as GeoJSONSource | undefined
  badgesSrc?.setData(badges)

  // Sync Variant A custom layer data
  if (elevatedLayerRef.value) {
    const egoSet = new Set(egoLinks.value.map((l) => l.key))
    const entries: ElevatedArcDrawEntry[] = []
    for (const l of linkAgg.value.displayed) {
      if (hasEgo && egoSet.has(l.key)) continue
      entries.push({
        link: l,
        isEgo: false,
        highlighted: hoveredLinkKey.value === l.key || selectedLink.value?.key === l.key,
        dimmed: hasEgo || hasSpiderfy,
      })
    }
    if (hasEgo) {
      for (const l of egoLinks.value) {
        entries.push({
          link: l,
          isEgo: true,
          highlighted: hoveredLinkKey.value === l.key || selectedLink.value?.key === l.key,
          dimmed: false,
        })
      }
    }
    elevatedLayerRef.value.setTheme(props.themeMode)
    elevatedLayerRef.value.setLinks(entries)
  }

  syncVariantVisibility()
  emitMetrics()
}

function detachSpiderfyMarker(): void {
  if (spiderfyMarkerRef.value) {
    spiderfyMarkerRef.value.remove()
    spiderfyMarkerRef.value = null
  }
}

function collapseSpiderfy(): void {
  if (!activeSpiderfy.value) return
  activeSpiderfy.value = null
  hoveredNode.value = null
  detachSpiderfyMarker()
  syncMapSources()
}

async function openSpiderfyForCluster(cluster: DisplayCluster): Promise<void> {
  const map = mapRef.value
  if (!map || !spiderfyHostEl.value) return
  const mode = classifyGroupInteraction(cluster.count)
  if (mode === 'list') {
    collapseSpiderfy()
    selectedNode.value = null
    selectedLink.value = null
    showingUnknownList.value = false
    selectedCluster.value = cluster
    listPage.value = 1
    syncMapSources()
    return
  }

  // S4: If anchor is > 0.7 of globe screen radius from center, easeTo center first
  const pt = map.project([cluster.lon, cluster.lat])
  const rect = map.getContainer().getBoundingClientRect()
  const cx = rect.width / 2
  const cy = rect.height / 2
  const maxR = Math.min(rect.width, rect.height) * 0.35
  if (Math.hypot(pt.x - cx, pt.y - cy) > maxR && map.getZoom() < 4) {
    map.easeTo({
      center: [cluster.lon, cluster.lat],
      duration: prefersReducedMotion.value ? 0 : 300,
    })
  }

  const layout = computeSpiderfyLayout(cluster.nodes, isCoarsePointer.value)
  activeSpiderfy.value = {
    cluster,
    layout,
    startZoom: map.getZoom(),
  }
  await nextTick()

  detachSpiderfyMarker()
  const marker = new maplibregl.Marker({
    element: spiderfyHostEl.value,
    anchor: 'center',
    opacityWhenCovered: '0',
  })
    .setLngLat([cluster.lon, cluster.lat])
    .addTo(map)
  spiderfyMarkerRef.value = marker
  syncMapSources()
}

function onSelectSpiderfyNode(node: GlobeNode): void {
  selectedNode.value = node
  selectedLink.value = null
  showingUnknownList.value = false
  selectedCluster.value = null
  syncMapSources()
}

function onHoverSpiderfyNode(node: GlobeNode | null): void {
  hoveredNode.value = node
  syncMapSources()
}

function selectAggregatedLink(link: AggregatedLink): void {
  selectedLink.value = link
  selectedNode.value = null
  selectedCluster.value = null
  showingUnknownList.value = false
  syncMapSources()
}

function selectNodeFromList(node: GlobeNode): void {
  selectedNode.value = node
  selectedLink.value = null
  showingUnknownList.value = false
  selectedCluster.value = null
  syncMapSources()
}

function openUnknownList(): void {
  collapseSpiderfy()
  selectedNode.value = null
  selectedLink.value = null
  selectedCluster.value = null
  showingUnknownList.value = true
  listPage.value = 1
}

function closePanel(): void {
  selectedNode.value = null
  selectedCluster.value = null
  selectedLink.value = null
  showingUnknownList.value = false
  syncMapSources()
}

function cycleMobileSnap(): void {
  mobileSnap.value = mobileSnap.value === 'peek' ? 'mid' : mobileSnap.value === 'mid' ? 'full' : 'peek'
}

function cancelHoverClose(): void {
  if (hoverCloseTimer) {
    clearTimeout(hoverCloseTimer)
    hoverCloseTimer = null
  }
}

function scheduleHoverClose(): void {
  cancelHoverClose()
  hoverCloseTimer = setTimeout(() => {
    hoverCard.value = null
    hoveredDisplayId.value = null
    hoveredLinkKey.value = null
    syncMapSources()
  }, 150)
}

function pickNearestMarkerAt(map: MapLibreMap, x: number, y: number): DisplayCluster | null {
  const half = hitHalfBoxPx(isCoarsePointer.value)
  const feats = map.queryRenderedFeatures(
    [
      [x - half, y - half],
      [x + half, y + half],
    ],
    { layers: ['mh-markers'] },
  )
  if (!feats.length) return null
  let best: DisplayCluster | null = null
  let bestDist = Infinity
  let bestSort = Infinity
  for (const f of feats) {
    const id = String(f.properties?.id ?? '')
    const c = clusterById.value.get(id)
    if (!c) continue
    const p = map.project([c.lon, c.lat])
    const dist = Math.hypot(p.x - x, p.y - y)
    const sortKey = Number(f.properties?.sortKey ?? 999)
    if (dist < bestDist - 0.5 || (Math.abs(dist - bestDist) <= 0.5 && sortKey < bestSort)) {
      bestDist = dist
      bestSort = sortKey
      best = c
    }
  }
  return best
}

function pickLinkAt(map: MapLibreMap, x: number, y: number): AggregatedLink | null {
  const tol = isCoarsePointer.value ? 12 : 6
  if (props.variant === 'A' && map.getZoom() < 5 && elevatedLayerRef.value) {
    const hit = elevatedLayerRef.value.pickAtPoint(x, y, tol)
    if (hit) return hit
  }
  const activeSurfaceLayers = SURFACE_LINK_LAYER_IDS.filter((id) => Boolean(map.getLayer(id)))
  const feats = map.queryRenderedFeatures(
    [
      [x - tol, y - tol],
      [x + tol, y + tol],
    ],
    { layers: activeSurfaceLayers },
  )
  if (!feats.length) return null
  const key = String(feats[0]?.properties?.key ?? '')
  return (
    egoLinks.value.find((l) => l.key === key) ??
    linkAgg.value.displayed.find((l) => l.key === key) ??
    null
  )
}

function handleMapClick(e: maplibregl.MapMouseEvent): void {
  const map = mapRef.value
  if (!map) return
  const { x, y } = e.point

  const hitCluster = pickNearestMarkerAt(map, x, y)
  if (hitCluster) {
    if (hitCluster.isMultiCity) {
      collapseSpiderfy()
      const splitZ = findClusterSplitZoom(hitCluster, grouped.value.groups, map.getZoom(), 9, 40)
      if (splitZ != null) {
        map.easeTo({
          center: [hitCluster.lon, hitCluster.lat],
          zoom: Math.min(9, splitZ + 0.15),
          duration: prefersReducedMotion.value ? 0 : 600,
        })
      } else {
        selectedNode.value = null
        selectedLink.value = null
        showingUnknownList.value = false
        selectedCluster.value = hitCluster
        listPage.value = 1
        syncMapSources()
      }
      return
    }

    const mode = classifyGroupInteraction(hitCluster.count)
    if (mode === 'select-device') {
      collapseSpiderfy()
      selectedNode.value = hitCluster.nodes[0] ?? null
      selectedCluster.value = null
      selectedLink.value = null
      showingUnknownList.value = false
      syncMapSources()
    } else if (mode === 'circle' || mode === 'spiral') {
      void openSpiderfyForCluster(hitCluster)
    } else {
      collapseSpiderfy()
      selectedNode.value = null
      selectedLink.value = null
      showingUnknownList.value = false
      selectedCluster.value = hitCluster
      listPage.value = 1
      syncMapSources()
    }
    return
  }

  const hitLink = pickLinkAt(map, x, y)
  if (hitLink) {
    collapseSpiderfy()
    selectAggregatedLink(hitLink)
    return
  }

  // Click empty area: collapse spiderfy first, else clear selection
  if (activeSpiderfy.value) {
    collapseSpiderfy()
  } else if (panelOpen.value) {
    closePanel()
  }
}

function handleMapMouseMove(e: maplibregl.MapMouseEvent): void {
  if (isMobile.value) return
  const map = mapRef.value
  if (!map) return
  const { x, y } = e.point
  if (hoverShowTimer) clearTimeout(hoverShowTimer)

  hoverShowTimer = setTimeout(() => {
    const hitCluster = pickNearestMarkerAt(map, x, y)
    if (hitCluster) {
      cancelHoverClose()
      map.getCanvas().style.cursor = 'pointer'
      const rect = map.getContainer().getBoundingClientRect()
      hoverCard.value = {
        x: Math.min(x + 12, Math.max(12, rect.width - 272)),
        y: Math.min(y + 12, Math.max(12, rect.height - 96)),
        title: formatClusterLabel(hitCluster, props.lang),
        subtitle: t('mh.globeV2.clusterStatusCounts', {
          online: hitCluster.onlineCount,
          stale: hitCluster.staleCount,
          offline: hitCluster.offlineCount,
        }),
        extra: precisionText(hitCluster.precision),
      }
      if (hoveredDisplayId.value !== hitCluster.id || hoveredLinkKey.value !== null) {
        hoveredDisplayId.value = hitCluster.id
        hoveredLinkKey.value = null
        syncMapSources()
      }
      return
    }

    const hitLink = pickLinkAt(map, x, y)
    if (hitLink) {
      cancelHoverClose()
      map.getCanvas().style.cursor = 'pointer'
      const rect = map.getContainer().getBoundingClientRect()
      const a = clusterById.value.get(hitLink.fromDisplayId)
      const b = clusterById.value.get(hitLink.toDisplayId)
      hoverCard.value = {
        x: Math.min(x + 12, Math.max(12, rect.width - 272)),
        y: Math.min(y + 12, Math.max(12, rect.height - 96)),
        title: `${a ? formatClusterLabel(a, props.lang) : hitLink.fromDisplayId} ↔ ${b ? formatClusterLabel(b, props.lang) : hitLink.toDisplayId}`,
        subtitle: `×${hitLink.count} · ${hitLink.worstClass}${hitLink.medianRtt != null ? ` · ${hitLink.medianRtt} ms` : ''}`,
      }
      if (hoveredLinkKey.value !== hitLink.key || hoveredDisplayId.value !== null) {
        hoveredLinkKey.value = hitLink.key
        hoveredDisplayId.value = null
        syncMapSources()
      }
      return
    }

    map.getCanvas().style.cursor = ''
    if (hoverCard.value || hoveredDisplayId.value || hoveredLinkKey.value) {
      scheduleHoverClose()
    }
  }, 120)
}

function handleKeyDown(e: KeyboardEvent): void {
  if (e.key === 'Escape') {
    // S8 Esc chain: hover card -> spiderfy -> panel -> full-page
    if (hoverCard.value) {
      hoverCard.value = null
      hoveredDisplayId.value = null
      hoveredLinkKey.value = null
      syncMapSources()
      return
    }
    if (activeSpiderfy.value) {
      collapseSpiderfy()
      return
    }
    if (panelOpen.value) {
      closePanel()
      return
    }
    if (fullPage.isFull.value) {
      void fullPage.exitFullPage(false)
    }
  }
}

function zoomBy(delta: number): void {
  const map = mapRef.value
  if (!map) return
  const target = Math.max(0.6, Math.min(9, map.getZoom() + delta))
  map.easeTo({ zoom: target, duration: prefersReducedMotion.value ? 0 : 250 })
}

function resetView(): void {
  const map = mapRef.value
  if (!map) return
  collapseSpiderfy()
  map.easeTo({
    center: [108, 30],
    zoom: isMobile.value ? 1.15 : 1.75,
    bearing: 0,
    pitch: 0,
    duration: prefersReducedMotion.value ? 0 : 500,
  })
}

let ro: ResizeObserver | null = null

function handleResize(): void {
  viewportWidth.value = typeof window !== 'undefined' ? window.innerWidth : 1280
  mapRef.value?.resize()
}

function onContextLost(ev: Event): void {
  ev.preventDefault()
  webglContextLostCount.value++
  contextLostActive.value = true
  emitMetrics()
}

function onContextRestored(): void {
  contextLostActive.value = false
  syncMapSources()
  emitMetrics()
}

onMounted(() => {
  ensureMapLibreSetup()
  if (!mapHostEl.value) return

  const initialZoom = isMobile.value ? 1.15 : 1.75
  currentZoom.value = initialZoom
  currentZi.value = Math.floor(initialZoom)

  const map = new maplibregl.Map({
    container: mapHostEl.value,
    style: buildGlobeStyle(props.themeMode, props.lang, resolvedPmtilesUrl.value, isMobile.value),
    center: [108, 30],
    zoom: initialZoom,
    minZoom: 0.6,
    maxZoom: 9,
    maxPitch: 0,
    pitch: 0,
    bearing: 0,
    dragRotate: false,
    touchPitch: false,
    pitchWithRotate: false,
    renderWorldCopies: false,
    fadeDuration: 150,
    pixelRatio: Math.max(1, Math.min(2, props.pixelRatio)),
    cooperativeGestures: effectiveCooperativeGestures.value,
    localIdeographFontFamily: CJK_FONT_STACK,
    attributionControl: false,
  })

  // North-up locked (S1 / AC5)
  map.touchZoomRotate.disableRotation()
  cooperativeGesturesActive.value = Boolean(map.cooperativeGestures?.isEnabled())

  // Instrument setStyle so P0 can prove 0 style reloads on theme/lang switching
  const origSetStyle = map.setStyle.bind(map)
  map.setStyle = ((...args: Parameters<MapLibreMap['setStyle']>) => {
    styleReloadCount.value++
    emitMetrics()
    return origSetStyle(...args)
  }) as MapLibreMap['setStyle']

  const canvas = map.getCanvas()
  canvas.addEventListener('webglcontextlost', onContextLost)
  canvas.addEventListener('webglcontextrestored', onContextRestored)

  map.on('render', () => {
    renderEventCounter++
  })

  map.on('load', () => {
    styleReady.value = true
    if (firstFrameMs.value == null) {
      firstFrameMs.value = Math.round(performance.now() - mountTime)
    }
    const elevLayer = new ElevatedArcsLayer()
    elevLayer.setTheme(props.themeMode)
    elevLayer.setEnabled(props.variant === 'A')
    elevatedLayerRef.value = elevLayer
    // Insert elevated arcs right before basemap labels & markers
    map.addLayer(elevLayer, 'label-place')
    syncMapSources()
    emitMetrics()
  })

  map.on('zoom', () => {
    const z = map.getZoom()
    currentZoom.value = z
    const zi = Math.floor(z)
    if (zi !== currentZi.value) {
      currentZi.value = zi
      syncMapSources()
    } else if (props.variant === 'A') {
      syncVariantVisibility()
    }
    if (activeSpiderfy.value && Math.abs(z - activeSpiderfy.value.startZoom) > 0.3) {
      collapseSpiderfy()
    }
  })

  map.on('click', handleMapClick)
  map.on('mousemove', handleMapMouseMove)

  mapRef.value = map

  if (typeof ResizeObserver !== 'undefined' && shellEl.value) {
    ro = new ResizeObserver(() => map.resize())
    ro.observe(shellEl.value)
  }
  window.addEventListener('resize', handleResize)
  window.addEventListener('keydown', handleKeyDown)
})

onBeforeUnmount(() => {
  if (hoverShowTimer) clearTimeout(hoverShowTimer)
  if (hoverCloseTimer) clearTimeout(hoverCloseTimer)
  window.removeEventListener('resize', handleResize)
  window.removeEventListener('keydown', handleKeyDown)
  ro?.disconnect()
  detachSpiderfyMarker()
  const map = mapRef.value
  if (map) {
    const canvas = map.getCanvas()
    canvas.removeEventListener('webglcontextlost', onContextLost)
    canvas.removeEventListener('webglcontextrestored', onContextRestored)
    map.remove()
    mapRef.value = null
  }
})

// Live updates with ZERO setStyle() reload
watch(
  () => props.themeMode,
  (mode) => {
    const map = mapRef.value
    if (!map || !styleReady.value) return
    applyThemeToMap(map, mode)
    syncMapSources()
  },
)

watch(
  () => props.lang,
  (lang) => {
    const map = mapRef.value
    if (!map || !styleReady.value) return
    applyLangToMap(map, lang)
    syncMapSources()
  },
)

watch(
  () => props.variant,
  () => {
    syncMapSources()
  },
)

watch(
  () => props.pixelRatio,
  (pr) => {
    const map = mapRef.value
    if (!map) return
    map.setPixelRatio(Math.max(1, Math.min(2, pr)))
    syncMapSources()
  },
)

watch(
  () => props.cooperativeGestures,
  () => {
    syncCooperativeGestures()
  },
)

watch([allGlobeNodes, () => props.arcs, carrierSet, () => props.onlyProblems, () => props.minRttMs], () => {
  syncMapSources()
})

function measurePmtilesBytes(): number {
  if (typeof performance === 'undefined') return 0
  let total = 0
  for (const e of performance.getEntriesByType('resource')) {
    const res = e as PerformanceResourceTiming
    if (res.name.includes('.pmtiles')) {
      total += res.transferSize || res.encodedBodySize || 0
    }
  }
  return total
}

function getWebglRendererName(): string {
  const map = mapRef.value
  if (!map) return 'unknown'
  const gl = map.getCanvas().getContext('webgl2')
  if (!gl) return 'unknown'
  const ext = gl.getExtension('WEBGL_debug_renderer_info')
  if (!ext) return String(gl.getParameter(gl.RENDERER) ?? 'webgl2')
  return String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) ?? 'webgl2')
}

function percentile(sorted: number[], p: number): number {
  if (!sorted.length) return 0
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))
  return Math.round(sorted[idx]! * 100) / 100
}

/**
 * Deterministic 10s P0 Perf HUD benchmark (S14):
 * Rotates 180°, sweeps zoom 1 -> 6 -> 1, then checks idleFramesAfter1s === 0.
 */
async function runPerfBenchmark(durationMs = 10_000): Promise<GlobePerfReport> {
  const map = mapRef.value
  if (!map) throw new Error('Map not initialized')

  collapseSpiderfy()
  closePanel()

  const startLon = 20
  const startLat = 26
  map.jumpTo({ center: [startLon, startLat], zoom: 1, bearing: 0, pitch: 0 })

  const deltas: number[] = []
  const startTime = performance.now()
  let lastFrame = startTime

  await new Promise<void>((resolve) => {
    const tick = (now: number) => {
      const elapsed = now - startTime
      const progress = Math.min(1, elapsed / durationMs)
      if (deltas.length > 0 || elapsed > 0) {
        deltas.push(now - lastFrame)
      }
      lastFrame = now

      const lon = startLon + 180 * progress
      const zoom = 1 + 5 * Math.sin(progress * Math.PI)
      map.jumpTo({ center: [lon > 180 ? lon - 360 : lon, startLat], zoom, bearing: 0, pitch: 0 })

      if (progress < 1) {
        requestAnimationFrame(tick)
      } else {
        resolve()
      }
    }
    requestAnimationFrame(tick)
  })

  // Wait 1 s for rendering to settle, then count WebGL render frames over the next 1 s (S11 AC13).
  await new Promise((r) => setTimeout(r, 1000))
  const beforeIdle = renderEventCounter
  await new Promise((r) => setTimeout(r, 1000))
  const idleFramesAfter1s = renderEventCounter - beforeIdle

  const sorted = [...deltas].sort((a, b) => a - b)
  const framesOver50ms = deltas.filter((d) => d > 50).length
  const totalTime = deltas.reduce((s, d) => s + d, 0) || durationMs
  const rect = map.getContainer().getBoundingClientRect()

  const report: GlobePerfReport = {
    variant: props.variant,
    pixelRatio: props.pixelRatio,
    dataset: props.datasetTag,
    viewport: { width: Math.round(rect.width), height: Math.round(rect.height) },
    renderer: getWebglRendererName(),
    durationMs,
    totalFrames: deltas.length,
    avgFps: Math.round((deltas.length / (totalTime / 1000)) * 10) / 10,
    p50: percentile(sorted, 50),
    p95: percentile(sorted, 95),
    maxFrameMs: sorted.length ? Math.round(sorted[sorted.length - 1]! * 100) / 100 : 0,
    framesOver50ms,
    tileBytes: measurePmtilesBytes(),
    firstFrameMs: firstFrameMs.value,
    idleFramesAfter1s,
    webglContextLost: webglContextLostCount.value,
    styleReloads: styleReloadCount.value,
    cooperativeGesturesSupported: Boolean(map.cooperativeGestures),
    timestamp: new Date().toISOString(),
  }

  ;(window as unknown as Record<string, unknown>).__GLOBE_P0_PERF__ = report
  return report
}

/** Helper exposed for deterministic inspection & Playwright tests. */
async function triggerClusterByName(nameQuery: string): Promise<string | null> {
  const q = nameQuery.toLowerCase()
  const match = merged.value.clusters.find(
    (c) =>
      c.placeEn.toLowerCase().includes(q) ||
      c.placeZh.toLowerCase().includes(q) ||
      c.nodes.some((n) => n.name.toLowerCase().includes(q)),
  )
  if (!match) return null
  await openSpiderfyForCluster(match)
  return match.id
}

function setCamera(center: [number, number], zoom: number): void {
  mapRef.value?.jumpTo({ center, zoom, bearing: 0, pitch: 0 })
}

function getDebugState() {
  const map = mapRef.value
  return {
    loaded: styleReady.value,
    zoom: map?.getZoom() ?? 0,
    pitch: map?.getPitch() ?? 0,
    bearing: map?.getBearing() ?? 0,
    minZoom: map?.getMinZoom() ?? 0,
    maxZoom: map?.getMaxZoom() ?? 0,
    webglContextLost: webglContextLostCount.value,
    styleReloads: styleReloadCount.value,
    cooperativeGesturesEnabled: Boolean(map?.cooperativeGestures?.isEnabled()),
    isFullPage: fullPage.isFull.value,
    activeSpiderfyMode: activeSpiderfy.value?.layout.mode ?? null,
    activeSpiderfyFeet: activeSpiderfy.value?.layout.feet.length ?? 0,
    panelOpen: panelOpen.value,
    listPanelCount: listPanelNodes.value.length,
    unlocatedCount: grouped.value.unlocated.length,
    displayedLinks: linkAgg.value.displayed.length,
    overflowLinks: linkAgg.value.overflowCount,
    renderEventCounter,
  }
}

defineExpose({
  runPerfBenchmark,
  toggleFullPage: () => fullPage.toggleFullPage(),
  exitFullPage: () => fullPage.exitFullPage(false),
  triggerClusterByName,
  setCamera,
  resetView,
  collapseSpiderfy,
  closePanel,
  getDebugState,
  getMap: () => mapRef.value,
})
</script>

<style scoped>
.mh-gv2-placeholder {
  width: 100%;
  position: relative;
}
.mh-gv2-shell {
  position: relative;
  width: 100%;
  border-radius: var(--mh-radius, 10px);
  overflow: hidden;
  border: 1px solid var(--mh-hairline, rgba(128, 128, 128, 0.2));
  background: #070b14;
  font-family: var(--mh-font-sans, system-ui, sans-serif);
}
.mh-gv2-shell--light {
  background: #f5f7fa;
  color: #1f2937;
}
.mh-gv2-shell--dark {
  background: #070b14;
  color: #e6edf6;
}
.mh-gv2-shell--full {
  position: fixed;
  inset: 0;
  z-index: 2000;
  width: 100vw;
  height: 100vh;
  height: 100dvh;
  border-radius: 0;
  border: 0;
}
.mh-gv2-canvas {
  width: 100%;
  height: 100%;
}
/* Do NOT set position: relative here — MapLibre Marker owns position: absolute; top: 0; left: 0. */
.mh-gv2-spiderfy-host {
  pointer-events: none;
}
.mh-gv2-top-actions {
  position: absolute;
  top: calc(12px + env(safe-area-inset-top, 0px));
  right: calc(12px + env(safe-area-inset-right, 0px));
  display: flex;
  gap: 6px;
  z-index: 6;
}
.mh-gv2-icon-btn {
  min-width: 30px;
  height: 30px;
  padding: 0 8px;
  border-radius: 7px;
  border: 1px solid rgba(143, 163, 191, 0.35);
  background: rgba(11, 22, 38, 0.82);
  color: #e6edf6;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  backdrop-filter: blur(8px);
}
.mh-gv2-shell--light .mh-gv2-icon-btn {
  background: rgba(255, 255, 255, 0.88);
  color: #1f2937;
  border-color: rgba(74, 91, 112, 0.28);
}
.mh-gv2-icon-btn:disabled {
  opacity: 0.4;
  cursor: default;
}
.mh-gv2-icon-btn:focus-visible {
  outline: 2px solid #56b4e9;
  outline-offset: 2px;
}
.mh-gv2-hover-card {
  position: absolute;
  max-width: 260px;
  padding: 8px 10px;
  border-radius: 8px;
  background: rgba(11, 22, 38, 0.92);
  color: #e6edf6;
  border: 1px solid rgba(143, 163, 191, 0.35);
  font-size: 12px;
  z-index: 8;
  backdrop-filter: blur(8px);
}
.mh-gv2-shell--light .mh-gv2-hover-card {
  background: rgba(255, 255, 255, 0.95);
  color: #1f2937;
  border-color: rgba(74, 91, 112, 0.25);
}
.mh-gv2-hover-card__title {
  font-weight: 600;
  margin-bottom: 2px;
}
.mh-gv2-hover-card__meta,
.mh-gv2-hover-card__extra {
  font-size: 11px;
  opacity: 0.82;
}
.mh-gv2-legend {
  position: absolute;
  left: calc(12px + env(safe-area-inset-left, 0px));
  bottom: calc(12px + env(safe-area-inset-bottom, 0px));
  max-width: min(460px, calc(100% - 24px));
  padding: 8px 10px;
  border-radius: 8px;
  background: rgba(11, 22, 38, 0.84);
  color: #e6edf6;
  border: 1px solid rgba(143, 163, 191, 0.3);
  font-size: 11px;
  z-index: 5;
  backdrop-filter: blur(8px);
}
.mh-gv2-shell--light .mh-gv2-legend {
  background: rgba(255, 255, 255, 0.9);
  color: #1f2937;
  border-color: rgba(74, 91, 112, 0.24);
}
.mh-gv2-legend__bar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
}
.mh-gv2-legend__toggle {
  background: transparent;
  border: 0;
  color: inherit;
  font-weight: 600;
  font-size: 11px;
  cursor: pointer;
  padding: 0;
}
.mh-gv2-chip {
  display: inline-flex;
  align-items: center;
  padding: 2px 7px;
  border-radius: 999px;
  font-size: 11px;
  border: 1px solid rgba(143, 163, 191, 0.35);
  background: transparent;
  color: inherit;
}
.mh-gv2-chip--warn {
  cursor: pointer;
  border-color: #e69f00;
  color: #e69f00;
}
.mh-gv2-shell--light .mh-gv2-chip--warn {
  border-color: #a66300;
  color: #a66300;
}
.mh-gv2-legend__body {
  margin-top: 6px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.mh-gv2-legend__row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
}
.mh-gv2-legend__attr {
  margin-top: 2px;
  font-size: 10px;
  opacity: 0.72;
  line-height: 1.3;
}
.mh-gv2-swatch-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex: 0 0 auto;
}
.mh-gv2-swatch-dot--half {
  background: linear-gradient(90deg, var(--c) 50%, var(--bg) 50%);
  border: 1px solid var(--c);
}
.mh-gv2-swatch-dot--off {
  background: transparent;
  border: 1.5px solid;
}
.mh-gv2-swatch-line {
  display: inline-block;
  width: 14px;
  height: 2px;
  border-radius: 1px;
}
.mh-gv2-swatch-line--dash {
  background: repeating-linear-gradient(90deg, var(--c) 0 5px, transparent 5px 8px);
}
.mh-gv2-swatch-line--short {
  background: repeating-linear-gradient(90deg, var(--c) 0 3px, transparent 3px 6px);
}
.mh-gv2-swatch-line--dot {
  background: repeating-linear-gradient(90deg, var(--c) 0 2px, transparent 2px 5px);
}
.mh-gv2-panel {
  position: absolute;
  top: 52px;
  right: 12px;
  width: 340px;
  max-width: calc(100% - 24px);
  max-height: calc(100% - 68px);
  overflow-y: auto;
  padding: 12px 14px;
  border-radius: 10px;
  background: rgba(11, 22, 38, 0.94);
  color: #e6edf6;
  border: 1px solid rgba(143, 163, 191, 0.35);
  z-index: 7;
  font-size: 12px;
  backdrop-filter: blur(10px);
}
.mh-gv2-shell--light .mh-gv2-panel {
  background: rgba(255, 255, 255, 0.96);
  color: #1f2937;
  border-color: rgba(74, 91, 112, 0.24);
}
.mh-gv2-panel--mobile {
  top: auto;
  left: 8px;
  right: 8px;
  bottom: calc(8px + env(safe-area-inset-bottom, 0px));
  width: auto;
  max-width: none;
  border-radius: 14px;
}
.mh-gv2-panel--snap-peek {
  max-height: 35%;
}
.mh-gv2-panel--snap-mid {
  max-height: 60%;
}
.mh-gv2-panel--snap-full {
  max-height: 90%;
}
.mh-gv2-panel__grabber {
  display: flex;
  justify-content: center;
  padding: 4px 0 8px;
  cursor: pointer;
}
.mh-gv2-panel__grabber-bar {
  width: 36px;
  height: 4px;
  border-radius: 999px;
  background: rgba(143, 163, 191, 0.5);
}
.mh-gv2-panel__head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 8px;
}
.mh-gv2-panel__title {
  font-weight: 600;
  font-size: 13px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.mh-gv2-facts {
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 5px;
}
.mh-gv2-fact {
  display: flex;
  justify-content: space-between;
  gap: 10px;
  padding-top: 5px;
  border-top: 1px solid rgba(143, 163, 191, 0.2);
}
.mh-gv2-fact dt {
  opacity: 0.72;
  font-size: 11px;
}
.mh-gv2-fact dd {
  margin: 0;
  text-align: right;
  font-size: 12px;
}
.mh-gv2-section {
  margin-top: 10px;
  padding-top: 8px;
  border-top: 1px solid rgba(143, 163, 191, 0.22);
}
.mh-gv2-section__title {
  font-size: 11px;
  font-weight: 600;
  opacity: 0.78;
  margin-bottom: 6px;
}
.mh-gv2-note {
  font-size: 11px;
  opacity: 0.8;
  margin-bottom: 8px;
}
.mh-gv2-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
  max-height: 240px;
  overflow-y: auto;
}
.mh-gv2-list-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 5px 7px;
  border-radius: 6px;
  border: 1px solid transparent;
  background: rgba(143, 163, 191, 0.08);
  color: inherit;
  cursor: pointer;
  font-size: 11px;
  text-align: left;
}
.mh-gv2-list-row:hover {
  border-color: rgba(86, 180, 233, 0.45);
}
.mh-gv2-list-row__name {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.mh-gv2-pager {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  margin-top: 8px;
}
.mh-gv2-primary-btn {
  margin-top: 10px;
  width: 100%;
  padding: 7px 10px;
  border-radius: 7px;
  border: 0;
  background: #0a8f86;
  color: #ffffff;
  font-weight: 600;
  font-size: 12px;
  cursor: pointer;
}
.mh-gv2-context-lost {
  position: absolute;
  inset: 16px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: rgba(7, 11, 20, 0.85);
  color: #e6edf6;
  border-radius: 8px;
  z-index: 20;
  font-weight: 600;
}
</style>
