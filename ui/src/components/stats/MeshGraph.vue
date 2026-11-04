<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <div ref="wrap" class="mesh-wrap">
    <div v-if="!nodes.length" class="mesh-empty text-medium-emphasis text-body-2">
      {{ emptyText }}
    </div>
    <template v-else>
      <!-- Toggles: which node classes are drawn, and which carrier
           classes get an edge. Both are pure view state — the payload is
           unchanged, so flipping them never refetches. -->
      <div class="mesh-controls">
        <v-chip-group v-model="shownCarriers" multiple column selected-class="text-primary">
          <v-chip
            v-for="c in CARRIERS"
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
        <v-spacer />
        <v-switch
          v-model="showOffline"
          density="compact"
          hide-details
          color="primary"
          :label="`Offline devices (${offlineCount})`"
        />
        <v-switch
          v-model="showControlPlane"
          density="compact"
          hide-details
          color="primary"
          label="Control plane"
        />
      </div>

      <svg :width="size" :height="size" role="img" class="mesh-svg">
        <title>Overlay mesh: devices, their control-plane links and peer carriers</title>
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
            :d="e.d"
            :stroke="e.stroke"
            :stroke-dasharray="e.stalled ? '4 3' : undefined"
            :stroke-width="e.hovered ? 3 : 1.6"
            :opacity="e.hovered ? 1 : 0.65"
            fill="none"
            @mouseenter="hoverEdge = e.key"
            @mouseleave="hoverEdge = null"
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

      <div class="mesh-legend text-caption text-medium-emphasis">
        {{ visibleNodes.length }} devices · {{ visibleEdges.length }} links shown
        <template v-if="asymmetricCount > 0">
          · {{ asymmetricCount }} asymmetric
          <span class="mesh-asym-swatch" aria-hidden="true" />
          <span>two-colour = each side's own carrier</span>
        </template>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
// Radial layout: the control plane at the centre, devices evenly spaced
// on a ring, peer carriers drawn as chords bowed toward the middle so
// parallel edges stay distinguishable. d3 supplies the shape/scale math;
// Vue renders the SVG (no d3-selection), so it stays reactive and
// jsdom-testable — the same discipline as the other charts.
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { lineRadial, curveBundle } from 'd3-shape'
import { useTheme } from 'vuetify'
import {
  edgeSides,
  participatingCarriers,
  qualifiedCarrier,
  type MeshEdgeEnd,
} from '@/utils/mesh'

export interface MeshNode {
  /** overlay node id (what edges are keyed by) */
  id: string
  name: string
  online: boolean
  relay_home?: string | null
  version?: string | null
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
    emptyText?: string
  }>(),
  {
    centerName: 'meshharbor.itachi.fans',
    emptyText: 'No devices in this organization yet',
  },
)
const emit = defineEmits<{ (e: 'select', nodeId: string): void }>()

const CARRIERS = [
  { key: 'direct', label: 'Direct' },
  { key: 'relay', label: 'TURN relay' },
  { key: 'derp', label: 'DERP' },
  { key: 'tunnel', label: 'Tunnel' },
  { key: 'blocked', label: 'Blocked' },
]
const shownCarriers = ref<string[]>(['direct', 'relay', 'derp', 'tunnel', 'blocked'])
const showOffline = ref(true)
const showControlPlane = ref(true)
const hoverNode = ref<string | null>(null)
const hoverEdge = ref<string | null>(null)

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
      return c.secondary
    case 'blocked':
      return c.error
    default:
      return 'rgba(var(--v-theme-on-surface), 0.25)'
  }
}

const wrap = ref<HTMLElement | null>(null)
const size = ref(520)
let ro: ResizeObserver | null = null
onMounted(() => {
  if (typeof ResizeObserver !== 'undefined' && wrap.value) {
    ro = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect?.width
      if (w && w > 200) size.value = Math.min(Math.max(w, 320), 720)
    })
    ro.observe(wrap.value)
  }
  if (wrap.value?.clientWidth) size.value = Math.min(Math.max(wrap.value.clientWidth, 320), 720)
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
}

const gradPrefix = `mesh-grad-${++instanceCounter}`

/** One tooltip line per reported direction, in the CLI's vocabulary. */
function directionLine(fromName: string, toName: string, end: MeshEdgeEnd): string {
  return (
    `${fromName} → ${toName}: ${qualifiedCarrier(end.carrier, end.relay)}` +
    (end.rtt_ms != null ? ` · ${end.rtt_ms} ms` : '') +
    (end.stalled ? ' · stalled' : '')
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

    let stroke = carrierColor(e.carrier)
    let grad: EdgeGradient | undefined
    if (sides.asymmetric && sides.from && sides.to) {
      grad = {
        id: `${gradPrefix}-${out.length}`,
        x1: a.x,
        y1: a.y,
        x2: b.x,
        y2: b.y,
        from: carrierColor(sides.from.carrier),
        to: carrierColor(sides.to.carrier),
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
    if (e.stalled && !sides.from?.stalled && !sides.to?.stalled) lines.push('stalled')
    if (e.reports === 1) lines.push('one-sided — only one end reported')

    out.push({
      key,
      d: chord(pts) ?? '',
      stroke,
      grad,
      asymmetric: sides.asymmetric,
      stalled: !!e.stalled,
      hovered: hoverEdge.value === key,
      tip: lines.join('\n'),
    })
  }
  return out
})

const gradientDefs = computed<EdgeGradient[]>(() =>
  visibleEdges.value.flatMap((e) => (e.grad ? [e.grad] : [])),
)
const asymmetricCount = computed(() => visibleEdges.value.filter((e) => e.asymmetric).length)

const tooltip = computed(() => {
  if (hoverEdge.value) {
    return visibleEdges.value.find((e) => e.key === hoverEdge.value)?.tip ?? null
  }
  if (hoverNode.value) {
    const n = placed.value.find((x) => x.id === hoverNode.value)
    if (!n) return null
    const bits = [n.name, n.online ? 'online' : 'offline']
    if (n.relay_home) bits.push(`home ${n.relay_home}`)
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
  flex-wrap: wrap;
  gap: 12px;
  width: 100%;
  margin-bottom: 4px;
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
  margin-top: 2px;
}
</style>
