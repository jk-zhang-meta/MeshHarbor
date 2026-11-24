<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <div ref="wrap" class="mesh-wrap">
    <div v-if="!nodes.length" class="mesh-empty text-medium-emphasis text-body-2">
      {{ resolvedEmptyText }}
    </div>
    <template v-else>
      <!-- Toggles: which node classes are drawn, which carrier classes get an edge,
           and 3D Globe vs 2D Ring view. Pure view state — never refetches. -->
      <div class="mesh-controls">
        <v-chip-group v-model="shownCarriers" multiple column selected-class="text-primary" class="mesh-controls__carriers">
          <v-chip
            v-for="c in carrierItems"
            :key="c.key"
            :value="c.key"
            size="x-small"
            variant="outlined"
            filter
          >
            <span class="mesh-dot mr-1" :style="{ background: carrierColor(c.key) }" />
            {{ c.label }}
            <span class="ml-1 text-medium-emphasis">{{ edgeCounts[c.key] ?? 0 }}</span>
          </v-chip>
        </v-chip-group>
        <div class="mesh-controls__toggles">
          <v-chip
            v-if="aclStatus"
            size="x-small"
            variant="tonal"
            color="primary"
            data-testid="mesh-acl-status"
          >
            {{ aclStatus }}
          </v-chip>
          <v-switch
            v-model="showOffline"
            density="compact"
            hide-details
            color="primary"
            class="mesh-switch"
            :label="$t('mh.mesh.offlineDevices', { n: offlineCount })"
          />
          <v-switch
            v-model="showControlPlane"
            density="compact"
            hide-details
            color="primary"
            class="mesh-switch"
            :label="$t('mh.mesh.controlPlane')"
          />
          <v-btn-toggle
            v-if="webglCapable"
            v-model="viewMode"
            mandatory
            density="compact"
            variant="outlined"
            divided
            class="mh-segmented"
            :aria-label="$t('mh.mesh.viewModeAria')"
            data-testid="mesh-view-toggle"
          >
            <v-btn value="globe" size="x-small" prepend-icon="mdi-earth">
              {{ $t('mh.mesh.viewGlobe') }}
            </v-btn>
            <v-btn value="ring" size="x-small" prepend-icon="mdi-chart-donut">
              {{ $t('mh.mesh.viewRing') }}
            </v-btn>
          </v-btn-toggle>
        </div>
      </div>

      <!-- 3D Interactive WebGL2 Globe (lazy-loaded MapLibre v2; ?globe=legacy fallback) with automatic 2D Ring fallback -->
      <mesh-globe
        :nodes="globeNodes"
        :arcs="globeArcs"
        :center="globeCenter"
        :enabled-carriers="shownCarriers"
        :show-control-plane="showControlPlane"
        :force-fallback="viewMode === 'ring'"
        @open-device="emit('select', $event)"
        @fallback-active="onGlobeFallback"
      >
        <template #fallback>
          <div class="mesh-ring-stage" data-testid="mesh-ring-fallback">
            <svg :width="size" :height="size" role="img" class="mesh-svg" @click="pinnedEdge = null">
              <title>{{ $t('mh.mesh.svgTitle') }}</title>
              <defs>
                <!-- Asymmetric pairs: each half of the chord wears ITS end's
                     carrier colour (userSpaceOnUse maps the A→B line onto the
                     curved path well enough to read at a glance). -->
                <linearGradient
                  v-for="g in gradientDefs"
                  :id="g.id"
                  :key="g.id"
                  gradientUnits="userSpaceOnUse"
                  :x1="g.x1"
                  :y1="g.y1"
                  :x2="g.x2"
                  :y2="g.y2"
                >
                  <stop offset="0%" :stop-color="g.from" />
                  <stop offset="42%" :stop-color="g.from" />
                  <stop offset="58%" :stop-color="g.to" />
                  <stop offset="100%" :stop-color="g.to" />
                </linearGradient>
              </defs>
              <g :transform="`translate(${size / 2},${size / 2})`">
                <!-- Ring guide -->
                <circle :r="radius" class="mesh-ring" />

                <!-- Control-plane spokes -->
                <g v-if="showControlPlane">
                  <line
                    v-for="n in visibleNodes"
                    :key="`spoke-${n.id}`"
                    class="mesh-spoke"
                    :class="{ 'mesh-spoke--off': !n.online }"
                    :x1="0"
                    :y1="0"
                    :x2="n.x"
                    :y2="n.y"
                  />
                </g>

                <!-- Peer-to-peer carriers -->
                <path
                  v-for="e in visibleEdges"
                  :key="e.key"
                  class="mesh-edge"
                  :d="e.d"
                  :stroke="e.stroke"
                  :stroke-dasharray="e.stalled ? '4 3' : undefined"
                  :stroke-width="e.hovered ? 3 : 1.6"
                  :opacity="e.hovered ? 1 : 0.65"
                  fill="none"
                />
                <!-- FR-120 P1 — each carrier's 14 px invisible hit line, over the
                     drawn ones: a 1.6 px stroke takes no finger, and its carrier and
                     round trip were hover-only. A tap or click pins its line in the
                     tooltip; a tap on the empty graph unpins it. -->
                <path
                  v-for="e in visibleEdges"
                  :key="`hit-${e.key}`"
                  class="mesh-edge-hit"
                  :d="e.d"
                  stroke="transparent"
                  stroke-width="14"
                  pointer-events="stroke"
                  fill="none"
                  :data-testid="`mesh-edge-hit-${e.key}`"
                  @mouseenter="hoverEdge = e.key"
                  @mouseleave="hoverEdge = null"
                  @click.stop="pinnedEdge = pinnedEdge === e.key ? null : e.key"
                />

                <!-- Centre: the control plane -->
                <g v-if="showControlPlane">
                  <circle :r="18" class="mesh-center" />
                  <text class="mesh-center-label" text-anchor="middle" dy="34">
                    {{ centerName }}
                  </text>
                </g>

                <!-- Devices -->
                <g
                  v-for="n in visibleNodes"
                  :key="n.id"
                  :transform="`translate(${n.x},${n.y})`"
                  class="mesh-node"
                  @mouseenter="hoverNode = n.id"
                  @mouseleave="hoverNode = null"
                  @click="emit('select', n.id)"
                >
                  <circle
                    :r="hoverNode === n.id ? 11 : 8"
                    :class="['mesh-node-dot', n.online ? 'is-online' : 'is-offline']"
                  />
                  <text
                    class="mesh-node-label"
                    :text-anchor="n.x < -1 ? 'end' : 'start'"
                    :dx="n.x < -1 ? -13 : 13"
                    dy="4"
                  >
                    {{ n.name }}
                  </text>
                </g>
              </g>
            </svg>

            <div v-if="tooltip" class="mesh-tooltip text-caption">{{ tooltip }}</div>
          </div>
        </template>
      </mesh-globe>

      <div class="mesh-legend text-caption text-medium-emphasis">
        {{ $t('mh.mesh.legendSummary', { nodes: visibleNodes.length, edges: visibleEdges.length }) }}
        <template v-if="asymmetricCount > 0">
          · {{ $t('mh.mesh.legendAsymmetric', { n: asymmetricCount }) }}
          <span class="mesh-asym-swatch" aria-hidden="true" />
          <span>{{ $t('mh.mesh.legendTwoColor') }}</span>
        </template>
        <template v-if="!webglCapable || globeFallbackReason">
          · {{ $t('mh.mesh.webglFallbackHint') }}
        </template>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
// FR-136: Interactive 3D WebGL2 Globe (lazy-loaded via MeshGlobe.vue) with the
// preserved radial SVG ring graph as the automatic WebGL2 fallback and 2D toggle.
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { lineRadial, curveBundle } from 'd3-shape'
import { useI18n } from 'vue-i18n'
import { useTheme } from 'vuetify'
import MeshGlobe from '@/components/globe/MeshGlobe.vue'
import type { GlobeArc, GlobeCenter, GlobeManagementPath, GlobeNode, GlobePresence } from '@/components/globe/types'
import { isWebGL2Supported } from '@/components/globe/webgl'
import {
  edgeSides,
  participatingCarriers,
  qualifiedCarrier,
  type MeshEdgeEnd,
} from '@/utils/mesh'

export interface MeshNode {
  /** overlay node id (what edges are keyed by) */
  id: string
  agent_id?: string | null
  name: string
  online: boolean
  presence?: GlobePresence
  relay_home?: string | null
  version?: string | null
  os?: string | null
  last_seen_at?: string | null
  overlay_ip?: string | null
  /** Populated ONLY where the current UI already displays public IP (fleet view). */
  public_ip?: string | null
  country_code?: string | null
  country?: string | null
  region?: string | null
  city?: string | null
  /** P6 optional coordinates & precision fields when provided by newer servers. */
  lat?: number | null
  lon?: number | null
  accuracy_radius_km?: number | null
  geo_level?: 'coords' | 'city' | 'region' | 'country' | 'unknown' | null
  zone_id?: string | null
  zone_name?: string | null
  zone_pinned?: boolean
  is_gateway?: boolean
  is_entry?: boolean
  is_centre?: boolean
  management_path?: GlobeManagementPath | null
}
export interface MeshEdge {
  from: string
  to: string
  carrier: string
  rtt_ms?: number | null
  stalled?: boolean
  reports?: number
  /** Wave 4 — each end's own report; see `@/utils/mesh`. */
  ends?: MeshEdgeEnd[]
}

// Gradient ids must be document-unique; a per-instance prefix keeps two
// graphs on one page from cross-referencing each other's defs.
let instanceCounter = 0

const props = withDefaults(
  defineProps<{
    nodes: MeshNode[]
    edges: MeshEdge[]
    centerName?: string
    centerCountryCode?: string | null
    aclStatus?: string | null
    emptyText?: string
  }>(),
  {
    centerName: 'meshharbor.itachi.fans',
    centerCountryCode: null,
    aclStatus: null,
    emptyText: '',
  },
)
const emit = defineEmits<{ (e: 'select', nodeId: string): void }>()

const { t } = useI18n()
const resolvedEmptyText = computed(() => props.emptyText || t('mh.mesh.empty'))

const CARRIER_KEYS = ['direct', 'relay', 'derp', 'tunnel', 'blocked'] as const
const carrierItems = computed(() =>
  CARRIER_KEYS.map((key) => ({ key, label: t(`mh.mesh.carriers.${key}`) })),
)
const shownCarriers = ref<string[]>(['direct', 'relay', 'derp', 'tunnel', 'blocked'])
const showOffline = ref(true)
const showControlPlane = ref(true)
const webglCapable = ref(isWebGL2Supported())
const globeFallbackReason = ref<string | null>(null)
const viewMode = ref<'globe' | 'ring'>(webglCapable.value ? 'globe' : 'ring')

function onGlobeFallback(reason: string) {
  globeFallbackReason.value = reason
  if (reason !== 'manual') {
    webglCapable.value = false
    viewMode.value = 'ring'
  }
}

const hoverNode = ref<string | null>(null)
const hoverEdge = ref<string | null>(null)
/** FR-120 P1 — the carrier a tap or click pinned; a mouse's hover reads over it. */
const pinnedEdge = ref<string | null>(null)
const shownEdge = computed(() => hoverEdge.value ?? pinnedEdge.value)

const theme = useTheme()
function carrierColor(carrier: string): string {
  const c = theme.current.value.colors
  switch (carrier) {
    case 'direct':
      return c.success
    case 'relay':
      return c.warning
    case 'derp':
      return c.info
    case 'tunnel':
      return c.primary
    case 'blocked':
      return c.error
    default:
      return 'rgba(var(--v-theme-on-surface), 0.25)'
  }
}

const wrap = ref<HTMLElement | null>(null)
const size = ref(520)
// FR-120 P1 — the graph follows its box down to 200 px: a 320 px floor was
// wider than a 360 px phone's ~312 px column, so the card scrolled sideways.
const MIN_SIZE = 200
let ro: ResizeObserver | null = null
onMounted(() => {
  if (typeof ResizeObserver !== 'undefined' && wrap.value) {
    ro = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect?.width
      if (w && w > 200) size.value = Math.min(Math.max(w, MIN_SIZE), 720)
    })
    ro.observe(wrap.value)
  }
  if (wrap.value?.clientWidth) size.value = Math.min(Math.max(wrap.value.clientWidth, MIN_SIZE), 720)
})
onBeforeUnmount(() => ro?.disconnect())

// Leave room for the labels that hang outside the ring.
const radius = computed(() => size.value / 2 - 96)

const offlineCount = computed(() => props.nodes.filter((n) => !n.online).length)

interface PlacedNode extends MeshNode {
  angle: number
  x: number
  y: number
}
const placed = computed<PlacedNode[]>(() => {
  // Online first, then by name: a stable order means a device doesn't
  // jump around the ring between polls.
  const ordered = [...props.nodes].sort(
    (a, b) => Number(b.online) - Number(a.online) || a.name.localeCompare(b.name),
  )
  const n = ordered.length || 1
  return ordered.map((node, i) => {
    const angle = (i / n) * 2 * Math.PI - Math.PI / 2
    return {
      ...node,
      angle,
      x: Math.cos(angle) * radius.value,
      y: Math.sin(angle) * radius.value,
    }
  })
})
const visibleNodes = computed(() =>
  showOffline.value ? placed.value : placed.value.filter((n) => n.online),
)

// Per-class counts follow the same rule as visibility: an asymmetric edge
// counts toward BOTH its classes, so the chip numbers always match what
// toggling that chip affects.
const edgeCounts = computed<Record<string, number>>(() => {
  const out: Record<string, number> = {}
  for (const e of props.edges) {
    for (const c of participatingCarriers(e.carrier, e.ends)) {
      out[c] = (out[c] ?? 0) + 1
    }
  }
  return out
})

// Bundled radial chord: both endpoints plus a midpoint pulled toward the
// centre, so two edges between the same neighbours don't overlap.
const chord = lineRadial<{ a: number; r: number }>()
  .angle((d) => d.a)
  .radius((d) => d.r)
  .curve(curveBundle.beta(0.75))

interface EdgeGradient {
  id: string
  x1: number
  y1: number
  x2: number
  y2: number
  from: string
  to: string
}
interface DrawnEdge {
  key: string
  d: string
  stroke: string
  grad?: EdgeGradient
  asymmetric: boolean
  stalled: boolean
  hovered: boolean
  tip: string
  raw: MeshEdge
  fromColor: string
  toColor: string
}

const gradPrefix = `mesh-grad-${++instanceCounter}`

/** One tooltip line per reported direction, in the CLI's vocabulary. */
function directionLine(fromName: string, toName: string, end: MeshEdgeEnd): string {
  return (
    `${fromName} → ${toName}: ${qualifiedCarrier(end.carrier, end.relay)}` +
    (end.rtt_ms != null ? ` · ${end.rtt_ms} ms` : '') +
    (end.stalled ? ` · ${t('mh.mesh.stalled')}` : '')
  )
}

const visibleEdges = computed<DrawnEdge[]>(() => {
  const byId = new Map(visibleNodes.value.map((n) => [n.id, n]))
  const out: DrawnEdge[] = []
  for (const e of props.edges) {
    // Visible if ANY participating class is enabled: hiding "relay" must
    // not also hide the direct half of an asymmetric pair.
    if (!participatingCarriers(e.carrier, e.ends).some((c) => shownCarriers.value.includes(c)))
      continue
    const a = byId.get(e.from)
    const b = byId.get(e.to)
    if (!a || !b) continue // an endpoint is hidden (offline filter)
    const key = `${e.from}-${e.to}-${e.carrier}`
    // The radial generator wants angles measured from 12 o'clock, which
    // is the +π/2 the layout subtracted.
    const pts = [
      { a: a.angle + Math.PI / 2, r: radius.value },
      { a: (a.angle + b.angle) / 2 + Math.PI / 2, r: radius.value * 0.35 },
      { a: b.angle + Math.PI / 2, r: radius.value },
    ]
    const sides = edgeSides(e.ends, e.from, e.to)

    const baseColor = carrierColor(e.carrier)
    let stroke = baseColor
    let fromColor = baseColor
    let toColor = baseColor
    let grad: EdgeGradient | undefined
    if (sides.asymmetric && sides.from && sides.to) {
      fromColor = carrierColor(sides.from.carrier)
      toColor = carrierColor(sides.to.carrier)
      grad = {
        id: `${gradPrefix}-${out.length}`,
        x1: a.x,
        y1: a.y,
        x2: b.x,
        y2: b.y,
        from: fromColor,
        to: toColor,
      }
      stroke = `url(#${grad.id})`
    }

    // Per-direction tooltip when the ends are known; the legacy merged
    // line otherwise (old server payload, or an edge with no reports).
    const lines: string[] = []
    if (sides.from) lines.push(directionLine(a.name, b.name, sides.from))
    if (sides.to) lines.push(directionLine(b.name, a.name, sides.to))
    if (!lines.length) {
      lines.push(
        `${a.name} ↔ ${b.name} · ${e.carrier}` + (e.rtt_ms != null ? ` · ${e.rtt_ms} ms` : ''),
      )
    }
    if (e.stalled && !sides.from?.stalled && !sides.to?.stalled) lines.push(t('mh.mesh.stalled'))
    if (e.reports === 1) lines.push(t('mh.mesh.oneSidedTip'))

    out.push({
      key,
      d: chord(pts) ?? '',
      stroke,
      grad,
      asymmetric: sides.asymmetric,
      stalled: !!e.stalled,
      hovered: shownEdge.value === key,
      tip: lines.join('\n'),
      raw: e,
      fromColor,
      toColor,
    })
  }
  return out
})

// ── Shared Globe projections (derived cleanly from the same filtered nodes/edges)
const globeNodes = computed<GlobeNode[]>(() =>
  visibleNodes.value.map((n) => ({
    id: n.id,
    agentId: n.agent_id ?? null,
    name: n.name,
    online: n.online,
    presence: n.presence ?? (n.online ? 'online' : 'offline'),
    role: n.is_centre ? 'centre' : n.is_gateway ? 'gateway' : n.is_entry ? 'entry' : 'device',
    isGateway: n.is_gateway,
    isEntry: n.is_entry,
    isCentre: n.is_centre,
    countryCode: n.country_code,
    country: n.country,
    region: n.region,
    city: n.city,
    lat: n.lat ?? null,
    lon: n.lon ?? null,
    accuracyRadiusKm: n.accuracy_radius_km ?? null,
    geoLevel: n.geo_level ?? null,
    relayHome: n.relay_home,
    os: n.os,
    version: n.version,
    lastSeenAt: n.last_seen_at,
    overlayIp: n.overlay_ip,
    publicIp: n.public_ip,
    zoneId: n.zone_id,
    zoneName: n.zone_name,
    zonePinned: n.zone_pinned,
    managementPath: n.management_path ?? null,
  })),
)

const globeArcs = computed<GlobeArc[]>(() =>
  visibleEdges.value.map((e) => ({
    key: e.key,
    from: e.raw.from,
    to: e.raw.to,
    carrier: e.raw.carrier,
    color: carrierColor(e.raw.carrier),
    fromColor: e.fromColor,
    toColor: e.toColor,
    asymmetric: e.asymmetric,
    stalled: e.stalled,
    blocked: e.raw.carrier === 'blocked',
    dashed: e.stalled || e.raw.carrier === 'blocked',
    rttMs: e.raw.rtt_ms ?? null,
    reports: e.raw.reports,
    ends: e.raw.ends,
    kind: 'peer',
  })),
)

const globeCenter = computed<GlobeCenter>(() => ({
  id: 'control-plane',
  name: props.centerName,
  countryCode: props.centerCountryCode ?? null,
}))

const gradientDefs = computed<EdgeGradient[]>(() =>
  visibleEdges.value.flatMap((e) => (e.grad ? [e.grad] : [])),
)
const asymmetricCount = computed(() => visibleEdges.value.filter((e) => e.asymmetric).length)

const tooltip = computed(() => {
  if (shownEdge.value) {
    return visibleEdges.value.find((e) => e.key === shownEdge.value)?.tip ?? null
  }
  if (hoverNode.value) {
    const n = placed.value.find((x) => x.id === hoverNode.value)
    if (!n) return null
    const bits = [n.name, n.online ? t('mh.mesh.status.online') : t('mh.mesh.status.offline')]
    if (n.relay_home) bits.push(t('mh.mesh.homePrefix', { region: n.relay_home }))
    if (n.version) bits.push(`v${n.version}`)
    return bits.join(' · ')
  }
  return null
})
</script>

<style scoped>
.mesh-wrap {
  position: relative;
  width: 100%;
  display: flex;
  flex-direction: column;
  align-items: center;
}
.mesh-empty {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 160px;
}
.mesh-controls {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 8px 12px;
  width: 100%;
  margin-bottom: 8px;
}
.mesh-controls__toggles {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px 12px;
  margin-left: auto;
}
.mesh-switch :deep(.v-label) {
  font-size: 0.8rem;
  white-space: nowrap;
}
@media (max-width: 599.98px) {
  .mesh-controls__toggles {
    margin-left: 0;
    width: 100%;
  }
}
.mesh-ring-stage {
  position: relative;
  width: 100%;
  display: flex;
  justify-content: center;
}
.mesh-svg {
  overflow: visible;
}
.mesh-ring {
  fill: none;
  stroke: rgba(var(--v-border-color), var(--v-border-opacity));
  stroke-dasharray: 2 4;
}
.mesh-spoke {
  stroke: rgba(var(--v-theme-on-surface), 0.18);
  stroke-width: 1;
}
.mesh-spoke--off {
  stroke-dasharray: 2 4;
  opacity: 0.5;
}
.mesh-center {
  fill: rgb(var(--v-theme-primary));
}
.mesh-center-label,
.mesh-node-label {
  fill: rgba(var(--v-theme-on-surface), 0.75);
  font-size: 11px;
}
.mesh-node {
  cursor: pointer;
}
.mesh-edge-hit {
  cursor: pointer;
}
.mesh-node-dot.is-online {
  fill: rgb(var(--v-theme-success));
}
.mesh-node-dot.is-offline {
  fill: rgba(var(--v-theme-on-surface), 0.25);
}
.mesh-tooltip {
  position: absolute;
  top: 8px;
  left: 50%;
  transform: translateX(-50%);
  background: rgb(var(--v-theme-surface));
  border: 1px solid rgba(var(--v-border-color), var(--v-border-opacity));
  border-radius: 6px;
  padding: 4px 10px;
  pointer-events: none;
  /* One line per direction — an asymmetric edge reads as two claims. */
  white-space: pre-line;
  text-align: left;
  z-index: 2;
}
.mesh-asym-swatch {
  display: inline-block;
  width: 22px;
  height: 6px;
  border-radius: 3px;
  vertical-align: middle;
  margin: 0 4px;
  background: linear-gradient(
    to right,
    rgb(var(--v-theme-success)) 42%,
    rgb(var(--v-theme-warning)) 58%
  );
}
.mesh-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
}
.mesh-legend {
  margin-top: 6px;
  text-align: center;
}
</style>
