<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <aside
    v-if="node || arc"
    class="mh-globe-panel"
    :class="{ 'mh-globe-panel--mobile': isMobile }"
    role="region"
    :aria-label="panelAriaLabel"
    data-testid="globe-detail-panel"
    @click.stop
  >
    <!-- Pinned Node (Device / Gateway / Centre) -->
    <template v-if="node">
      <div class="mh-globe-panel__head">
        <div class="mh-globe-panel__title-row">
          <span
            class="mh-presence__dot"
            :class="`mh-presence--${effectivePresence}`"
            aria-hidden="true"
          />
          <span class="mh-globe-panel__title" :title="node.name">{{ node.name }}</span>
        </div>
        <v-btn
          icon="mdi-close"
          size="x-small"
          variant="text"
          :aria-label="$t('mh.mesh.panel.close')"
          data-testid="globe-panel-close"
          @click="emit('close')"
        />
      </div>

      <div class="mh-globe-panel__badges">
        <v-chip
          size="x-small"
          variant="tonal"
          :color="presenceColor"
          density="comfortable"
        >
          {{ presenceText }}
        </v-chip>
        <v-chip
          v-if="node.isCentre || node.role === 'centre'"
          size="x-small"
          variant="tonal"
          color="primary"
          density="comfortable"
        >
          {{ $t('mh.mesh.role.centre') }}
        </v-chip>
        <v-chip
          v-if="node.isGateway || node.role === 'gateway'"
          size="x-small"
          variant="tonal"
          color="accent"
          density="comfortable"
        >
          {{ $t('mh.mesh.role.gateway') }}
        </v-chip>
        <v-chip
          v-if="node.isEntry || node.role === 'entry'"
          size="x-small"
          variant="tonal"
          color="info"
          density="comfortable"
        >
          {{ $t('mh.mesh.role.entry') }}
        </v-chip>
        <v-chip
          v-if="zoneDisplay"
          size="x-small"
          variant="outlined"
          density="comfortable"
          :prepend-icon="node.zonePinned ? 'mdi-pin' : undefined"
        >
          {{ zoneDisplay }}
        </v-chip>
      </div>

      <dl class="mh-globe-panel__facts">
        <div v-if="osVersionText" class="mh-globe-panel__fact">
          <dt>{{ $t('mh.mesh.panel.system') }}</dt>
          <dd class="mh-mono">{{ osVersionText }}</dd>
        </div>
        <div v-if="lastSeenText" class="mh-globe-panel__fact">
          <dt>{{ $t('mh.mesh.panel.lastSeen') }}</dt>
          <dd class="mh-tabular">{{ lastSeenText }}</dd>
        </div>
        <div class="mh-globe-panel__fact">
          <dt>{{ $t('mh.mesh.panel.location') }}</dt>
          <dd>
            <span v-if="node.locationLabel">{{ node.locationLabel }}</span>
            <span v-else class="text-medium-emphasis">{{ $t('mh.mesh.panel.locationUnknown') }}</span>
          </dd>
        </div>
        <div v-if="node.publicIp" class="mh-globe-panel__fact" data-testid="globe-panel-public-ip">
          <dt>{{ $t('mh.mesh.panel.publicIp') }}</dt>
          <dd class="mh-mono">{{ node.publicIp }}</dd>
        </div>
        <div v-if="node.overlayIp" class="mh-globe-panel__fact">
          <dt>{{ $t('mh.mesh.panel.overlayIp') }}</dt>
          <dd class="mh-mono">{{ node.overlayIp }}</dd>
        </div>
        <div v-if="node.relayHome" class="mh-globe-panel__fact">
          <dt>{{ $t('mh.mesh.panel.relayHome') }}</dt>
          <dd class="mh-mono">{{ node.relayHome }}</dd>
        </div>
        <div v-if="managementPathText" class="mh-globe-panel__fact" data-testid="globe-panel-mgmt-path">
          <dt>{{ $t('mh.mesh.panel.pathToCentre') }}</dt>
          <dd>{{ managementPathText }}</dd>
        </div>
      </dl>

      <!-- Connected peers -->
      <div v-if="peerRows.length" class="mh-globe-panel__section">
        <div class="mh-globe-panel__section-head">
          <span>{{ $t('mh.mesh.panel.peers', { n: peerRows.length }) }}</span>
        </div>
        <div class="mh-globe-panel__peers" data-testid="globe-panel-peers">
          <button
            v-for="p in peerRows"
            :key="p.arcKey"
            type="button"
            class="mh-globe-panel__peer"
            @click="emit('focus-arc', p.arcKey)"
          >
            <span class="mh-globe-panel__peer-name">{{ p.peerName }}</span>
            <span class="mh-globe-panel__peer-meta">
              <span class="mh-globe-dot" :style="{ background: p.color }" />
              <span class="mh-mono">{{ p.carrierLabel }}</span>
              <span v-if="p.rttMs != null" class="mh-mono text-medium-emphasis">{{ p.rttMs }} ms</span>
              <span v-if="p.stalled" class="text-warning">{{ $t('mh.mesh.stalled') }}</span>
            </span>
          </button>
        </div>
      </div>

      <div v-if="showOpenAction && !node.isCentre" class="mh-globe-panel__actions">
        <v-btn
          block
          size="small"
          color="primary"
          variant="tonal"
          prepend-icon="mdi-open-in-new"
          data-testid="globe-panel-open-device"
          @click="emit('open-device', node.id)"
        >
          {{ $t('mh.mesh.panel.openDevice') }}
        </v-btn>
      </div>
    </template>

    <!-- Pinned Link (Arc) -->
    <template v-else-if="arc">
      <div class="mh-globe-panel__head">
        <div class="mh-globe-panel__title-row">
          <span class="mh-globe-dot" :style="{ background: arc.color }" aria-hidden="true" />
          <span class="mh-globe-panel__title">
            {{ nameOf(arc.from) }} ↔ {{ nameOf(arc.to) }}
          </span>
        </div>
        <v-btn
          icon="mdi-close"
          size="x-small"
          variant="text"
          :aria-label="$t('mh.mesh.panel.close')"
          data-testid="globe-panel-close"
          @click="emit('close')"
        />
      </div>

      <div class="mh-globe-panel__badges">
        <v-chip size="x-small" variant="tonal" density="comfortable" :style="{ color: arc.color }">
          {{ carrierDisplay(arc.carrier) }}
        </v-chip>
        <v-chip v-if="arc.asymmetric" size="x-small" variant="outlined" density="comfortable">
          {{ $t('mh.mesh.asymmetricTag') }}
        </v-chip>
        <v-chip v-if="arc.stalled" size="x-small" variant="tonal" color="warning" density="comfortable">
          {{ $t('mh.mesh.stalled') }}
        </v-chip>
        <v-chip v-if="arc.blocked" size="x-small" variant="tonal" color="error" density="comfortable">
          {{ $t('mh.mesh.carriers.blocked') }}
        </v-chip>
      </div>

      <dl class="mh-globe-panel__facts">
        <template v-if="arcDirections.length">
          <div v-for="dir in arcDirections" :key="dir.label" class="mh-globe-panel__fact">
            <dt>{{ dir.label }}</dt>
            <dd class="mh-mono">
              {{ dir.carrier }}
              <template v-if="dir.rttMs != null"> · {{ dir.rttMs }} ms</template>
              <template v-if="dir.stalled"> · {{ $t('mh.mesh.stalled') }}</template>
            </dd>
          </div>
        </template>
        <template v-else>
          <div class="mh-globe-panel__fact">
            <dt>{{ $t('mh.mesh.panel.carrier') }}</dt>
            <dd class="mh-mono">{{ carrierDisplay(arc.carrier) }}</dd>
          </div>
          <div v-if="arc.rttMs != null" class="mh-globe-panel__fact">
            <dt>{{ $t('mh.mesh.panel.rtt') }}</dt>
            <dd class="mh-mono">{{ arc.rttMs }} ms</dd>
          </div>
        </template>
        <div v-if="arc.reports != null" class="mh-globe-panel__fact">
          <dt>{{ $t('mh.mesh.panel.reports') }}</dt>
          <dd>
            {{
              arc.reports === 1
                ? $t('mh.mesh.panel.oneSided')
                : $t('mh.mesh.panel.reportsCount', { n: arc.reports })
            }}
          </dd>
        </div>
      </dl>

      <div class="mh-globe-panel__endpoints">
        <v-btn
          size="x-small"
          variant="outlined"
          prepend-icon="mdi-crosshairs-gps"
          @click="emit('focus-node', arc.from)"
        >
          {{ nameOf(arc.from) }}
        </v-btn>
        <v-btn
          size="x-small"
          variant="outlined"
          prepend-icon="mdi-crosshairs-gps"
          @click="emit('focus-node', arc.to)"
        >
          {{ nameOf(arc.to) }}
        </v-btn>
      </div>
    </template>
  </aside>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { edgeSides, qualifiedCarrier } from '@/utils/mesh'
import type { GlobeArc, PlacedGlobeNode } from './types'

const props = withDefaults(
  defineProps<{
    node: PlacedGlobeNode | null
    arc: GlobeArc | null
    nodes: readonly PlacedGlobeNode[]
    arcs: readonly GlobeArc[]
    isMobile?: boolean
    showOpenAction?: boolean
  }>(),
  {
    isMobile: false,
    showOpenAction: true,
  },
)

const emit = defineEmits<{
  (e: 'close'): void
  (e: 'open-device', nodeId: string): void
  (e: 'focus-node', nodeId: string): void
  (e: 'focus-arc', arcKey: string): void
}>()

const { t, locale } = useI18n()

const nodeById = computed(() => new Map(props.nodes.map((n) => [n.id, n])))

function nameOf(id: string): string {
  return nodeById.value.get(id)?.name ?? id.slice(-6)
}

function carrierDisplay(carrier: string): string {
  const key = `mh.mesh.carriers.${carrier}`
  const translated = t(key)
  return translated === key ? carrier : translated
}

const effectivePresence = computed(() => {
  if (!props.node) return 'offline'
  return props.node.presence ?? (props.node.online ? 'online' : 'offline')
})

const presenceColor = computed(() => {
  if (effectivePresence.value === 'online') return 'success'
  if (effectivePresence.value === 'stale') return 'warning'
  return undefined
})

const presenceText = computed(() => {
  if (effectivePresence.value === 'online') return t('mh.mesh.status.online')
  if (effectivePresence.value === 'stale') return t('mh.mesh.status.stale')
  return t('mh.mesh.status.offline')
})

const zoneDisplay = computed(() => {
  if (!props.node) return ''
  if (props.node.zoneName) return props.node.zoneName
  if (props.node.zoneId) return props.node.zoneId
  if (props.node.zoneKind === 'mainland') return t('mh.topo.mainland')
  if (props.node.zoneKind === 'non_mainland') return t('mh.topo.nonMainland')
  return ''
})

const osVersionText = computed(() => {
  if (!props.node) return ''
  const parts: string[] = []
  if (props.node.os) parts.push(props.node.os)
  if (props.node.version) {
    parts.push(props.node.version.startsWith('v') ? props.node.version : `v${props.node.version}`)
  }
  return parts.join(' · ')
})

const lastSeenText = computed(() => {
  const raw = props.node?.lastSeenAt
  if (!raw) return ''
  const d = new Date(raw)
  if (Number.isNaN(d.getTime())) return raw
  try {
    return new Intl.DateTimeFormat(locale.value, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }).format(d)
  } catch {
    return d.toISOString().slice(0, 16).replace('T', ' ')
  }
})

const managementPathText = computed(() => {
  const mp = props.node?.managementPath
  if (!mp) return ''
  if (mp.mode === 'gateway') {
    return mp.gatewayName
      ? t('mh.mesh.panel.viaGateway', { name: mp.gatewayName })
      : t('mh.mesh.panel.viaGatewayGeneric')
  }
  if (mp.mode === 'last_resort_direct') return t('mh.mesh.panel.lastResortDirect')
  if (mp.mode === 'direct') return t('mh.mesh.panel.directToCentre')
  return mp.mode
})

const peerRows = computed(() => {
  const n = props.node
  if (!n) return []
  const rows: Array<{
    arcKey: string
    peerId: string
    peerName: string
    carrierLabel: string
    color: string
    rttMs: number | null
    stalled: boolean
  }> = []
  for (const a of props.arcs) {
    if (a.kind === 'control') continue
    if (a.from !== n.id && a.to !== n.id) continue
    const peerId = a.from === n.id ? a.to : a.from
    const sides = edgeSides(a.ends, a.from, a.to)
    const mine = a.from === n.id ? sides.from : sides.to
    const carrierLabel = mine
      ? qualifiedCarrier(mine.carrier, mine.relay)
      : carrierDisplay(a.carrier)
    rows.push({
      arcKey: a.key,
      peerId,
      peerName: nameOf(peerId),
      carrierLabel,
      color: a.color,
      rttMs: mine?.rtt_ms ?? a.rttMs ?? null,
      stalled: Boolean(mine?.stalled ?? a.stalled),
    })
  }
  rows.sort((x, y) => (x.rttMs ?? 99999) - (y.rttMs ?? 99999) || x.peerName.localeCompare(y.peerName))
  return rows
})

const arcDirections = computed(() => {
  const a = props.arc
  if (!a?.ends?.length) return []
  const sides = edgeSides(a.ends, a.from, a.to)
  const out: Array<{ label: string; carrier: string; rttMs: number | null; stalled: boolean }> = []
  if (sides.from) {
    out.push({
      label: `${nameOf(a.from)} → ${nameOf(a.to)}`,
      carrier: qualifiedCarrier(sides.from.carrier, sides.from.relay),
      rttMs: sides.from.rtt_ms ?? null,
      stalled: Boolean(sides.from.stalled),
    })
  }
  if (sides.to) {
    out.push({
      label: `${nameOf(a.to)} → ${nameOf(a.from)}`,
      carrier: qualifiedCarrier(sides.to.carrier, sides.to.relay),
      rttMs: sides.to.rtt_ms ?? null,
      stalled: Boolean(sides.to.stalled),
    })
  }
  return out
})

const panelAriaLabel = computed(() => {
  if (props.node) return t('mh.mesh.panel.deviceDetailsAria', { name: props.node.name })
  if (props.arc) {
    return t('mh.mesh.panel.linkDetailsAria', {
      a: nameOf(props.arc.from),
      b: nameOf(props.arc.to),
    })
  }
  return ''
})
</script>

<style scoped>
.mh-globe-panel {
  position: absolute;
  top: 12px;
  right: 12px;
  width: 300px;
  max-width: calc(100% - 24px);
  max-height: calc(100% - 24px);
  overflow-y: auto;
  background: rgba(var(--v-theme-surface), 0.94);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border: 1px solid var(--mh-hairline);
  border-radius: var(--mh-radius);
  box-shadow: var(--mh-overlay-shadow);
  padding: 12px 14px;
  z-index: 6;
  color: rgb(var(--v-theme-on-surface));
  font-size: 0.8125rem;
}
.mh-globe-panel--mobile {
  top: auto;
  right: 8px;
  left: 8px;
  bottom: 8px;
  width: auto;
  max-width: none;
  max-height: 60%;
  border-radius: 14px;
  padding: 10px 12px 0;
}
.mh-globe-panel--mobile .mh-globe-panel__actions {
  position: sticky;
  bottom: 0;
  margin: 8px -12px 0;
  padding: 8px 12px 10px;
  background: rgb(var(--v-theme-surface));
  border-top: 1px solid var(--mh-hairline);
}
.mh-globe-panel__head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 6px;
}
.mh-globe-panel__title-row {
  display: flex;
  align-items: center;
  gap: 7px;
  min-width: 0;
}
.mh-globe-panel__title {
  font-weight: 600;
  font-size: 0.875rem;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.mh-globe-panel__badges {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
  margin-bottom: 10px;
}
.mh-globe-panel__facts {
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 5px;
}
.mh-globe-panel__fact {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 10px;
  padding-top: 4px;
  border-top: 1px solid var(--mh-hairline);
}
.mh-globe-panel__fact dt {
  color: rgba(var(--v-theme-on-surface), var(--v-medium-emphasis-opacity));
  font-size: 0.75rem;
  flex: 0 0 auto;
}
.mh-globe-panel__fact dd {
  margin: 0;
  text-align: right;
  word-break: break-word;
  font-size: 0.78rem;
}
.mh-globe-panel__section {
  margin-top: 10px;
  padding-top: 8px;
  border-top: 1px solid var(--mh-hairline);
}
.mh-globe-panel__section-head {
  font-size: 0.72rem;
  font-weight: 600;
  color: rgba(var(--v-theme-on-surface), var(--v-medium-emphasis-opacity));
  margin-bottom: 6px;
}
.mh-globe-panel__peers {
  display: flex;
  flex-direction: column;
  gap: 3px;
  max-height: 148px;
  overflow-y: auto;
}
.mh-globe-panel__peer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  width: 100%;
  padding: 5px 7px;
  border: 1px solid transparent;
  border-radius: 6px;
  background: transparent;
  color: inherit;
  cursor: pointer;
  text-align: left;
  font-size: 0.75rem;
}
.mh-globe-panel__peer:hover,
.mh-globe-panel__peer:focus-visible {
  background: rgba(var(--v-theme-primary), 0.08);
  border-color: rgba(var(--v-theme-primary), 0.25);
  outline: none;
}
.mh-globe-panel__peer-name {
  font-weight: 500;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.mh-globe-panel__peer-meta {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  flex: 0 0 auto;
}
.mh-globe-panel__actions {
  margin-top: 10px;
}
.mh-globe-panel__endpoints {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 10px;
}
.mh-globe-dot {
  display: inline-block;
  width: 7px;
  height: 7px;
  border-radius: 50%;
  flex: 0 0 auto;
}
</style>
