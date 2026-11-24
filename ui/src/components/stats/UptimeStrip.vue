<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <div class="uptime-wrap">
    <div v-if="!rows.length" class="uptime-empty text-medium-emphasis text-body-2">
      {{ emptyText }}
    </div>
    <template v-else>
      <!-- FR-120 P1 — a period's state and times were each segment's `title`,
           which a tap never shows: a bar now reports the period under a tap or
           click (or a mouse pointing, or the arrow keys) in the line below. -->
      <div v-for="row in rows" :key="row.agent_id" class="uptime-row">
        <div class="uptime-label text-body-2" :title="row.name || row.agent_id">
          {{ row.name || row.agent_id.slice(-6) }}
        </div>
        <div
          class="uptime-bar"
          role="button"
          tabindex="0"
          :aria-label="$t('mh.phone.uptimeBarAria', { name: row.name || row.agent_id.slice(-6) })"
          :data-testid="`uptime-bar-${row.agent_id}`"
          @click="pick(row, $event)"
          @pointermove="point(row, $event)"
          @pointerleave="pointed = null"
          @keydown.left.prevent="step(row, -1)"
          @keydown.right.prevent="step(row, 1)"
        >
          <div
            v-for="(seg, i) in row.segments"
            :key="i"
            class="uptime-seg"
            :class="{ 'uptime-seg--shown': isShown(row, i) }"
            :style="{ left: seg.left, width: seg.width, background: seg.color }"
          />
        </div>
        <div class="uptime-pct text-caption" :title="`${row.onlinePct.toFixed(1)}% online`">
          {{ row.onlinePct.toFixed(0) }}%
        </div>
      </div>
      <div class="uptime-detail text-caption" aria-live="polite" data-testid="uptime-detail">
        <template v-if="detail">{{ detail }}</template>
        <span v-else class="text-medium-emphasis">{{ $t('mh.phone.uptimeHint') }}</span>
      </div>
      <div class="uptime-axis text-caption text-medium-emphasis">
        <span>{{ fmtAxis(windowFrom) }}</span>
        <span>now</span>
      </div>
      <div class="uptime-legend text-caption">
        <span v-for="p in LEGEND" :key="p.key" class="uptime-legend-item">
          <span class="uptime-dot" :style="{ background: colorFor(p.key) }" />{{ p.label }}
        </span>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
// Presence intervals → one horizontal bar per agent. Pure layout math on
// percentages (no d3 scales needed, and no measurement — jsdom-safe).
import { computed, ref } from 'vue'
import { timeFormat } from 'd3-time-format'
import { useTheme } from 'vuetify'

export interface UptimeInterval {
  from: number
  to: number
  presence: string
}
export interface UptimeAgent {
  agent_id: string
  name?: string
  /** FR-116 D4 — the admin's friendly name, shown before the machine's. */
  display_name?: string | null
  intervals: UptimeInterval[]
}

const props = withDefaults(
  defineProps<{
    agents: UptimeAgent[]
    emptyText?: string
  }>(),
  { emptyText: 'No presence history yet' },
)

const LEGEND = [
  { key: 'online', label: 'Online' },
  { key: 'stale', label: 'Stale' },
  { key: 'offline', label: 'Offline' },
  { key: 'unknown', label: 'No data' },
]

const theme = useTheme()
function colorFor(presence: string): string {
  const c = theme.current.value.colors
  switch (presence) {
    case 'online':
      return c.success
    // Stale = heartbeats stopped but the row hasn't aged out yet: a
    // degraded state, deliberately NOT a gap in the strip.
    case 'stale':
      return c.warning
    case 'offline':
      return c.error
    default:
      return 'rgba(var(--v-theme-on-surface), 0.12)'
  }
}

const windowFrom = computed(() =>
  Math.min(...props.agents.flatMap((a) => a.intervals.map((i) => i.from))),
)
const windowTo = computed(() =>
  Math.max(...props.agents.flatMap((a) => a.intervals.map((i) => i.to))),
)

const fmtTip = timeFormat('%b %d %H:%M')
function fmtAxis(t: number): string {
  return Number.isFinite(t) ? fmtTip(new Date(t * 1000)) : ''
}

interface Segment {
  left: string
  width: string
  /** The same position as numbers (percent of the window), to find a tap's period. */
  leftPct: number
  widthPct: number
  color: string
  title: string
}
interface Row {
  agent_id: string
  name?: string
  segments: Segment[]
  onlinePct: number
}

const rows = computed<Row[]>(() => {
  const t0 = windowFrom.value
  const t1 = windowTo.value
  const span = t1 - t0
  if (!Number.isFinite(span) || span <= 0) return []
  return props.agents
    .filter((a) => a.intervals.length > 0)
    .map((a) => {
      let onlineSecs = 0
      const segments = a.intervals.map((iv) => {
        const dur = Math.max(iv.to - iv.from, 0)
        if (iv.presence === 'online') onlineSecs += dur
        const leftPct = ((iv.from - t0) / span) * 100
        const widthPct = Math.max((dur / span) * 100, 0.4)
        return {
          left: `${leftPct}%`,
          width: `${widthPct}%`,
          leftPct,
          widthPct,
          color: colorFor(iv.presence),
          title: `${iv.presence} · ${fmtTip(new Date(iv.from * 1000))} → ${fmtTip(
            new Date(iv.to * 1000),
          )}`,
        }
      })
      return {
        agent_id: a.agent_id,
        // A device is named as the device list names it (FR-116 D4).
        name: a.display_name || a.name,
        segments,
        onlinePct: (onlineSecs / span) * 100,
      }
    })
    .sort((x, y) => y.onlinePct - x.onlinePct)
})

// FR-120 P1 — the period a tap or click picked stays in the detail line; a
// mouse pointing at a bar previews its period there, and leaving restores the
// picked one.
type Spot = { agent: string; seg: number }
const picked = ref<Spot | null>(null)
const pointed = ref<Spot | null>(null)
const shown = computed(() => pointed.value ?? picked.value)

/** The segment under the pointer, or the nearest one to it. */
function segAt(row: Row, ev: MouseEvent): number {
  const r = (ev.currentTarget as HTMLElement).getBoundingClientRect()
  if (!r.width) return row.segments.length ? 0 : -1
  const x = ((ev.clientX - r.left) / r.width) * 100
  let best = -1
  let bestGap = Infinity
  row.segments.forEach((s, i) => {
    const gap = x < s.leftPct ? s.leftPct - x : Math.max(x - (s.leftPct + s.widthPct), 0)
    if (gap < bestGap) {
      bestGap = gap
      best = i
    }
  })
  return best
}

function pick(row: Row, ev: MouseEvent): void {
  const seg = segAt(row, ev)
  if (seg >= 0) picked.value = { agent: row.agent_id, seg }
}

function point(row: Row, ev: PointerEvent): void {
  // A finger's moves are a scroll or the tap itself; only a mouse previews.
  if (ev.pointerType !== 'mouse') return
  const seg = segAt(row, ev)
  pointed.value = seg >= 0 ? { agent: row.agent_id, seg } : null
}

function step(row: Row, by: number): void {
  if (!row.segments.length) return
  const cur = picked.value?.agent === row.agent_id ? picked.value.seg : by > 0 ? -1 : row.segments.length
  picked.value = { agent: row.agent_id, seg: Math.min(Math.max(cur + by, 0), row.segments.length - 1) }
}

function isShown(row: Row, i: number): boolean {
  return shown.value?.agent === row.agent_id && shown.value.seg === i
}

const detail = computed(() => {
  const s = shown.value
  const row = s ? rows.value.find((r) => r.agent_id === s.agent) : undefined
  const seg = row && s ? row.segments[s.seg] : undefined
  return row && seg ? `${row.name || row.agent_id.slice(-6)} · ${seg.title}` : ''
})
</script>

<style scoped>
.uptime-wrap {
  width: 100%;
}
.uptime-empty {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100px;
}
.uptime-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 4px;
}
.uptime-label {
  flex: 0 0 140px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.uptime-bar {
  position: relative;
  flex: 1 1 auto;
  height: 14px;
  border-radius: 3px;
  overflow: hidden;
  background: rgba(var(--v-theme-on-surface), 0.06);
  cursor: pointer;
}
.uptime-bar:focus-visible {
  outline: 2px solid rgb(var(--v-theme-primary));
  outline-offset: 2px;
}
.uptime-seg {
  position: absolute;
  top: 0;
  bottom: 0;
}
/* The period the detail line reads, marked in its bar. */
.uptime-seg--shown {
  box-shadow: inset 0 0 0 2px rgb(var(--v-theme-on-surface));
}
.uptime-detail {
  min-height: 1.5em;
  margin-top: 2px;
}
.uptime-pct {
  flex: 0 0 38px;
  text-align: right;
  opacity: 0.75;
}
.uptime-axis {
  display: flex;
  justify-content: space-between;
  margin-left: 148px;
  margin-right: 46px;
}
.uptime-legend {
  display: flex;
  gap: 10px;
  margin-top: 6px;
  opacity: 0.75;
}
.uptime-legend-item {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.uptime-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
}
/* FR-120 P1 — on a phone the name and the percentage share a line and the
   bar takes the width below them: the fixed 140 px name column left the bar
   ~130 px at 360 px. */
@media (max-width: 599.98px) {
  .uptime-row {
    flex-wrap: wrap;
    row-gap: 2px;
  }
  .uptime-label {
    flex: 1 1 0;
    min-width: 0;
  }
  .uptime-pct {
    order: 2;
  }
  .uptime-bar {
    order: 3;
    flex: 1 1 100%;
  }
  .uptime-axis {
    margin-left: 0;
    margin-right: 0;
  }
}
</style>
