<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-card>
    <v-card-title class="d-flex align-center">
      <span>Server topology</span>
      <v-spacer />
      <v-btn
        prepend-icon="mdi-refresh"
        variant="text"
        size="small"
        :loading="store.loading"
        @click="refresh"
      >
        Refresh
      </v-btn>
    </v-card-title>

    <v-card-text>
      <v-alert
        v-if="store.error"
        type="error"
        variant="tonal"
        closable
        class="mb-4"
        @click:close="store.error = null"
      >
        {{ store.error }}
      </v-alert>

      <p class="text-medium-emphasis mb-4">
        Two servers connect directly exactly when an enabled edge joins them,
        whatever their business zones; without one they do not see each other,
        even in one zone. Click a server, then another, to add an edge; click
        an edge to switch it off or remove it. Clients are not drawn: they keep
        the zone rule. Edges are enforced under
        <code>business_isolation = enforce</code>; under <code>warn</code> they
        are only logged.
      </p>

      <div v-if="store.loading && store.servers.length === 0" class="d-flex justify-center pa-8">
        <v-progress-circular indeterminate />
      </div>

      <p v-else-if="store.servers.length === 0" class="text-medium-emphasis">
        No device has the central role Server yet. Approve one under Business
        authority first.
      </p>

      <template v-else>
        <div class="d-flex align-center flex-wrap ga-2 mb-2 text-caption">
          <span class="topo-key"><span class="topo-dot zone-mainland" /> Mainland</span>
          <span class="topo-key"><span class="topo-dot zone-non_mainland" /> Non-mainland</span>
          <span class="topo-key"><span class="topo-dot zone-none" /> Zone unknown</span>
          <span class="topo-key"><span class="topo-line" /> Edge on</span>
          <span class="topo-key"><span class="topo-line off" /> Edge off</span>
          <v-spacer />
          <span v-if="pending" class="text-primary">
            {{ nameOf(pending) }} selected: click a second server
            <v-btn size="x-small" variant="text" @click="pending = null">Cancel</v-btn>
          </span>
        </div>

        <svg
          :viewBox="`0 0 ${W} ${H}`"
          class="topo-svg"
          role="img"
          @click.self="clearSelection"
        >
          <title>Server topology: servers by country and the edges between them</title>
          <path :d="spherePath" class="topo-sphere" @click="clearSelection" />
          <path :d="landPath" class="topo-land" @click="clearSelection" />
          <g v-for="e in drawnEdges" :key="e.key">
            <path
              :d="e.d"
              class="topo-edge"
              :class="{ off: !e.link.enabled, selected: selected === e.key }"
            />
            <path
              :d="e.d"
              class="topo-edge-hit"
              @click.stop="selectEdge(e.key)"
            >
              <title>{{ nameOf(e.link.a) }} — {{ nameOf(e.link.b) }} ({{ e.link.enabled ? 'on' : 'off' }})</title>
            </path>
          </g>
          <g
            v-for="s in drawnServers"
            :key="s.agent_id"
            class="topo-server"
            :transform="`translate(${s.x},${s.y})`"
            @click.stop="clickServer(s.agent_id)"
          >
            <circle
              r="6"
              :class="[`zone-${s.zone ?? 'none'}`, { offline: !s.online, pending: pending === s.agent_id }]"
            />
            <text y="-10" class="topo-label">{{ s.name }}</text>
            <title>{{ s.name }} · {{ s.country ?? 'no country' }} · {{ s.online ? 'online' : 'offline' }}</title>
          </g>
        </svg>

        <div v-if="unplaced.length" class="mt-2 text-caption">
          <span class="text-medium-emphasis">No known location:</span>
          <v-chip
            v-for="s in unplaced"
            :key="s.agent_id"
            size="small"
            class="ml-1"
            :color="pending === s.agent_id ? 'primary' : undefined"
            :variant="pending === s.agent_id ? 'flat' : 'outlined'"
            @click="clickServer(s.agent_id)"
          >
            {{ s.name }}
          </v-chip>
        </div>

        <v-sheet v-if="selectedLink" border rounded class="d-flex align-center flex-wrap ga-3 pa-3 mt-3">
          <span class="font-weight-medium">
            {{ nameOf(selectedLink.a) }} — {{ nameOf(selectedLink.b) }}
          </span>
          <v-switch
            :model-value="selectedLink.enabled"
            :loading="busy"
            :disabled="busy"
            color="primary"
            density="compact"
            hide-details
            :label="selectedLink.enabled ? 'On' : 'Off'"
            @update:model-value="(v) => setEnabled(selectedLink!, v === true)"
          />
          <v-spacer />
          <v-btn
            color="error"
            variant="text"
            size="small"
            prepend-icon="mdi-delete"
            :disabled="busy"
            @click="remove(selectedLink)"
          >
            Remove edge
          </v-btn>
        </v-sheet>

        <!-- The same edges as rows: the map is for seeing, this list is for
             a phone and for a screen reader. -->
        <v-table density="compact" class="table-stack-xs mt-4">
          <thead>
            <tr>
              <th>Edge</th>
              <th>State</th>
              <th class="text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="store.links.length === 0">
              <td colspan="3" class="text-medium-emphasis">No edges: every server is on its own.</td>
            </tr>
            <tr
              v-for="l in store.links"
              :key="edgeKey(l.a, l.b)"
              :class="{ 'bg-surface-variant': selected === edgeKey(l.a, l.b) }"
            >
              <td data-label="Edge">{{ nameOf(l.a) }} — {{ nameOf(l.b) }}</td>
              <td data-label="State">
                <v-switch
                  :model-value="l.enabled"
                  :disabled="busy"
                  color="primary"
                  density="compact"
                  hide-details
                  :label="l.enabled ? 'On' : 'Off'"
                  @update:model-value="(v) => setEnabled(l, v === true)"
                />
              </td>
              <td class="text-right">
                <v-btn
                  icon="mdi-delete"
                  variant="text"
                  size="small"
                  :disabled="busy"
                  :aria-label="`Remove edge ${nameOf(l.a)} — ${nameOf(l.b)}`"
                  @click="remove(l)"
                />
              </td>
            </tr>
          </tbody>
        </v-table>
      </template>
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { geoNaturalEarth1, geoPath, type GeoPermissibleObjects } from 'd3-geo'
import { feature } from 'topojson-client'
import type { GeometryCollection, Topology } from 'topojson-specification'
import { useServerTopologyStore, type LinkView } from '@/stores/serverTopology'
import { arcPath, edgeKey, placeServers, type Point } from './serverTopology'

const props = defineProps<{ tenantId: string }>()
const store = useServerTopologyStore()

const W = 960
const H = 500
const projection = geoNaturalEarth1().fitSize([W, H], { type: 'Sphere' })
const path = geoPath(projection)
const spherePath = path({ type: 'Sphere' }) ?? ''
const landPath = ref('')

const pending = ref<string | null>(null)
const selected = ref<string | null>(null)
const busy = ref(false)

const layout = computed(() =>
  placeServers(store.servers, (ll) => projection([ll[0], ll[1]]) ?? null),
)
const unplaced = computed(() => layout.value.unplaced)
const drawnServers = computed(() =>
  store.servers.flatMap((s) => {
    const p = layout.value.placed.get(s.agent_id)
    return p ? [{ ...s, x: p[0], y: p[1] }] : []
  }),
)
// An edge is the great circle between its two dots (Tokyo–Virginia crosses
// the Pacific, split at the map's edge), from where each dot actually sits;
// a straight-ish screen arc only if a dot cannot be mapped back to the globe.
function edgePath(p: Point, q: Point): string {
  const a = projection.invert?.([p[0], p[1]])
  const b = projection.invert?.([q[0], q[1]])
  return (a && b && path({ type: 'LineString', coordinates: [a, b] })) || arcPath(p, q)
}
const drawnEdges = computed(() =>
  store.links.flatMap((link) => {
    const p = layout.value.placed.get(link.a)
    const q = layout.value.placed.get(link.b)
    return p && q ? [{ key: edgeKey(link.a, link.b), link, d: edgePath(p, q) }] : []
  }),
)
const selectedLink = computed(
  () => store.links.find((l) => edgeKey(l.a, l.b) === selected.value) ?? null,
)

function nameOf(agentId: string): string {
  return store.servers.find((s) => s.agent_id === agentId)?.name ?? agentId.slice(-6)
}

function clearSelection() {
  pending.value = null
  selected.value = null
}

function selectEdge(key: string) {
  pending.value = null
  selected.value = key
}

async function clickServer(agentId: string) {
  selected.value = null
  if (!pending.value || pending.value === agentId) {
    pending.value = pending.value === agentId ? null : agentId
    return
  }
  const [a, b] = [pending.value, agentId]
  pending.value = null
  const key = edgeKey(a, b)
  if (store.links.some((l) => edgeKey(l.a, l.b) === key)) {
    selected.value = key
    return
  }
  busy.value = true
  try {
    if (await store.setLink(props.tenantId, a, b, true)) selected.value = key
  } finally {
    busy.value = false
  }
}

async function setEnabled(link: LinkView, enabled: boolean) {
  busy.value = true
  try {
    await store.setLink(props.tenantId, link.a, link.b, enabled)
  } finally {
    busy.value = false
  }
}

async function remove(link: LinkView) {
  busy.value = true
  try {
    if (await store.removeLink(props.tenantId, link.a, link.b)) selected.value = null
  } finally {
    busy.value = false
  }
}

async function loadLand() {
  // ~50 KB of Natural Earth 1:110m land, fetched only on this page.
  const mod = await import('world-atlas/land-110m.json')
  const topo = (mod.default ?? mod) as unknown as Topology<{ land: GeometryCollection }>
  landPath.value = path(feature(topo, topo.objects.land) as GeoPermissibleObjects) ?? ''
}

function refresh() {
  void store.fetchTopology(props.tenantId)
}

onMounted(() => {
  refresh()
  void loadLand()
})
</script>

<style scoped>
.topo-svg {
  width: 100%;
  height: auto;
  display: block;
  user-select: none;
}
.topo-sphere {
  fill: rgba(var(--v-theme-primary), 0.04);
  stroke: rgba(var(--v-theme-on-surface), 0.15);
}
.topo-land {
  fill: rgba(var(--v-theme-on-surface), 0.1);
  stroke: rgba(var(--v-theme-on-surface), 0.18);
  stroke-width: 0.5;
}
.topo-edge {
  fill: none;
  stroke: rgb(var(--v-theme-primary));
  stroke-width: 2;
  pointer-events: none;
}
.topo-edge.off {
  stroke: rgba(var(--v-theme-on-surface), 0.45);
  stroke-dasharray: 5 4;
}
.topo-edge.selected {
  stroke-width: 4;
}
.topo-edge-hit {
  fill: none;
  stroke: transparent;
  stroke-width: 14;
  cursor: pointer;
}
.topo-server {
  cursor: pointer;
}
.topo-server circle {
  stroke: rgb(var(--v-theme-surface));
  stroke-width: 2;
}
.topo-server circle.offline {
  fill-opacity: 0.35;
}
.topo-server circle.pending {
  stroke: rgb(var(--v-theme-primary));
  stroke-width: 3;
}
.topo-label {
  font-size: 11px;
  text-anchor: middle;
  fill: rgb(var(--v-theme-on-surface));
  paint-order: stroke;
  stroke: rgb(var(--v-theme-surface));
  stroke-width: 3;
}
.zone-mainland {
  fill: rgb(var(--v-theme-error));
  background: rgb(var(--v-theme-error));
}
.zone-non_mainland {
  fill: rgb(var(--v-theme-info));
  background: rgb(var(--v-theme-info));
}
.zone-none {
  fill: rgba(var(--v-theme-on-surface), 0.5);
  background: rgba(var(--v-theme-on-surface), 0.5);
}
.topo-key {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.topo-dot {
  display: inline-block;
  width: 10px;
  height: 10px;
  border-radius: 50%;
}
.topo-line {
  display: inline-block;
  width: 18px;
  border-top: 2px solid rgb(var(--v-theme-primary));
}
.topo-line.off {
  border-top: 2px dashed rgba(var(--v-theme-on-surface), 0.45);
}
</style>
