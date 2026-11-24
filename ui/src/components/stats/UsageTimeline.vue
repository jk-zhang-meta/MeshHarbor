<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <div class="tl-wrap">
    <div v-if="!lanes.length" class="tl-empty text-medium-emphasis text-body-2">
      {{ emptyText }}
    </div>
    <template v-else>
      <div v-for="lane in lanes" :key="lane.key" class="tl-row">
        <div class="tl-label" :title="lane.title">
          <div class="text-body-2 text-truncate">{{ lane.label }}</div>
          <div v-if="lane.sub" class="text-caption text-medium-emphasis text-truncate">
            {{ lane.sub }}
          </div>
        </div>
        <!-- FR-120 P1 — a window's times, length and traffic were each bar's
             `title`, which a tap never shows: the track now reports the window
             under a tap or click (or a mouse pointing, or the arrow keys) in
             the line below the lanes. -->
        <div
          class="tl-track"
          role="button"
          tabindex="0"
          :aria-label="$t('mh.phone.timelineBarAria', { name: lane.label })"
          :data-testid="`tl-track-${lane.key}`"
          @click="pick(lane, $event)"
          @pointermove="point(lane, $event)"
          @pointerleave="pointed = null"
          @keydown.left.prevent="step(lane, -1)"
          @keydown.right.prevent="step(lane, 1)"
        >
          <!-- Bars are absolutely positioned by percentage of the query
               window, so no measurement is needed and the component
               renders identically under jsdom. -->
          <div
            v-for="(bar, i) in lane.bars"
            :key="i"
            class="tl-bar"
            :class="{
              'tl-bar--watcher': bar.role === 'watcher',
              'tl-bar--open': bar.open,
              'tl-bar--shown': isShown(lane, i),
            }"
            :style="{ left: bar.left, width: bar.width, background: bar.color }"
          />
        </div>
        <div class="tl-total text-caption" :title="`${lane.label}: ${lane.totalLabel}`">
          {{ lane.totalLabel }}
        </div>
      </div>

      <div class="tl-detail text-caption" aria-live="polite" data-testid="tl-detail">
        <template v-if="detail">{{ detail }}</template>
        <span v-else class="text-medium-emphasis">{{ $t('mh.phone.timelineHint') }}</span>
      </div>

      <div class="tl-axis text-caption text-medium-emphasis">
        <span v-for="(tick, i) in ticks" :key="i" class="tl-tick" :style="{ left: tick.left }">
          {{ tick.label }}
        </span>
      </div>

      <div class="tl-legend text-caption">
        <span class="tl-legend-item">
          <span class="tl-dot" :style="{ background: controllerColor }" />Controlled
        </span>
        <span class="tl-legend-item">
          <span class="tl-dot tl-dot--watcher" :style="{ background: watcherColor }" />Watched
        </span>
        <span v-if="!watchersComplete" class="tl-legend-note text-medium-emphasis">
          watcher history only goes back 90 days
        </span>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
// One lane per DEVICE, one bar per viewing window — the direct answer to
// "from when till when did this user view that device's screen".
//
// Controller and watcher windows are visually distinct because they are
// different facts: the controller drove the session, a watcher only saw it.
// Bytes exist for controller windows only (the session's stats block counts
// the peer connection once; splitting it across watchers would be invented).
import { computed, ref } from 'vue'
import { scaleTime } from 'd3-scale'
import { timeFormat } from 'd3-time-format'
import { useDisplay, useTheme } from 'vuetify'
import { formatDuration, formatBytes } from '@/utils/format'

export interface ViewingWindow {
  session_id: string
  agent_id: string
  agent_name?: string
  /** FR-116 D4 — the admin's friendly name; null when the device has none. */
  agent_display_name?: string | null
  tenant_id: string
  tenant_name?: string
  /** unix seconds */
  started_at: number
  /** unix seconds; null = still open at query time */
  ended_at?: number | null
  seconds: number
  role: 'controller' | 'watcher'
  bytes?: number
  bytes_known?: boolean
}

const props = withDefaults(
  defineProps<{
    windows: ViewingWindow[]
    /** Query window bounds, unix seconds. Bars are clipped to these. */
    from: number
    to: number
    /** Show the org name under each device (platform scope). */
    showOrg?: boolean
    watchersComplete?: boolean
    emptyText?: string
  }>(),
  {
    showOrg: false,
    watchersComplete: true,
    emptyText: 'No screen-viewing sessions in this range',
  },
)

const theme = useTheme()
const { xs } = useDisplay()
const controllerColor = computed(() => theme.current.value.colors.primary)
const watcherColor = computed(() => theme.current.value.colors.info)

const fmtTip = timeFormat('%b %d %H:%M:%S')
const span = computed(() => Math.max(props.to - props.from, 1))

function pct(t: number): number {
  return ((t - props.from) / span.value) * 100
}

interface Bar {
  left: string
  width: string
  /** The same position as numbers (percent of the window), to find a tap's window. */
  leftPct: number
  widthPct: number
  color: string
  title: string
  role: string
  open: boolean
}
interface Lane {
  key: string
  label: string
  sub?: string
  title: string
  bars: Bar[]
  totalSecs: number
  totalLabel: string
}

const lanes = computed<Lane[]>(() => {
  const byDevice = new Map<string, ViewingWindow[]>()
  for (const w of props.windows) {
    const list = byDevice.get(w.agent_id)
    if (list) list.push(w)
    else byDevice.set(w.agent_id, [w])
  }

  const out: Lane[] = []
  for (const [agentId, list] of byDevice) {
    const first = list[0]
    // Named as the device list names it: the friendly name, else the
    // machine's (FR-116 D4).
    const device = first.agent_display_name || first.agent_name
    const bars: Bar[] = []
    let totalSecs = 0
    for (const w of list) {
      // Clip to the query window so a session that started earlier still
      // renders — as the visible part of itself, not off-canvas.
      const s = Math.max(w.started_at, props.from)
      const open = w.ended_at === null || w.ended_at === undefined
      const e = Math.min(open ? props.to : (w.ended_at as number), props.to)
      if (e <= s) continue
      totalSecs += w.seconds
      const byteNote =
        w.role === 'controller'
          ? w.bytes_known
            ? ` · ${formatBytes(w.bytes ?? 0)}`
            : ' · traffic not measured'
          : ''
      const orgNote = w.tenant_name ? ` · ${w.tenant_name}` : ''
      // Floor the width so a 5-second session is still clickable.
      const widthPct = Math.max(((e - s) / span.value) * 100, 0.35)
      bars.push({
        left: `${pct(s)}%`,
        width: `${widthPct}%`,
        leftPct: pct(s),
        widthPct,
        color: w.role === 'controller' ? controllerColor.value : watcherColor.value,
        role: w.role,
        open,
        title:
          `${w.role === 'controller' ? 'Controlled' : 'Watched'} ${device || agentId}` +
          `${orgNote}\n${fmtTip(new Date(w.started_at * 1000))} → ` +
          `${open ? 'still open' : fmtTip(new Date((w.ended_at as number) * 1000))}` +
          `\n${formatDuration(w.seconds)}${byteNote}`,
      })
    }
    if (!bars.length) continue
    out.push({
      key: agentId,
      label: device || agentId.slice(-6),
      sub: props.showOrg ? first.tenant_name : undefined,
      title: `${device || agentId}${first.tenant_name ? ` · ${first.tenant_name}` : ''}`,
      bars,
      totalSecs,
      totalLabel: formatDuration(totalSecs),
    })
  }
  return out.sort((a, b) => b.totalSecs - a.totalSecs)
})

const ticks = computed(() => {
  const scale = scaleTime().domain([new Date(props.from * 1000), new Date(props.to * 1000)])
  // Fewer ticks on a wide range keeps the labels from colliding — and on a
  // phone (FR-116), where seven "Oct 14" labels ran into each other.
  const fmt = span.value > 3 * 86_400 ? timeFormat('%b %d') : timeFormat('%H:%M')
  return scale.ticks(xs.value ? 3 : 5).map((d) => ({
    left: `${pct(d.getTime() / 1000)}%`,
    label: fmt(d),
  }))
})

// FR-120 P1 — the window a tap or click picked stays in the detail line; a
// mouse pointing at a track previews its window there, and leaving restores
// the picked one.
type Spot = { lane: string; bar: number }
const picked = ref<Spot | null>(null)
const pointed = ref<Spot | null>(null)
const shown = computed(() => pointed.value ?? picked.value)

/** The bar under the pointer, or the nearest one to it. */
function barAt(lane: Lane, ev: MouseEvent): number {
  const r = (ev.currentTarget as HTMLElement).getBoundingClientRect()
  if (!r.width) return lane.bars.length ? 0 : -1
  const x = ((ev.clientX - r.left) / r.width) * 100
  let best = -1
  let bestGap = Infinity
  lane.bars.forEach((b, i) => {
    const gap = x < b.leftPct ? b.leftPct - x : Math.max(x - (b.leftPct + b.widthPct), 0)
    if (gap < bestGap) {
      bestGap = gap
      best = i
    }
  })
  return best
}

function pick(lane: Lane, ev: MouseEvent): void {
  const bar = barAt(lane, ev)
  if (bar >= 0) picked.value = { lane: lane.key, bar }
}

function point(lane: Lane, ev: PointerEvent): void {
  // A finger's moves are a scroll or the tap itself; only a mouse previews.
  if (ev.pointerType !== 'mouse') return
  const bar = barAt(lane, ev)
  pointed.value = bar >= 0 ? { lane: lane.key, bar } : null
}

function step(lane: Lane, by: number): void {
  if (!lane.bars.length) return
  const cur = picked.value?.lane === lane.key ? picked.value.bar : by > 0 ? -1 : lane.bars.length
  picked.value = { lane: lane.key, bar: Math.min(Math.max(cur + by, 0), lane.bars.length - 1) }
}

function isShown(lane: Lane, i: number): boolean {
  return shown.value?.lane === lane.key && shown.value.bar === i
}

const detail = computed(() => {
  const s = shown.value
  const lane = s ? lanes.value.find((l) => l.key === s.lane) : undefined
  return lane && s ? (lane.bars[s.bar]?.title ?? '') : ''
})
</script>

<style scoped>
.tl-wrap {
  width: 100%;
}
.tl-empty {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 120px;
}
.tl-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
}
.tl-label {
  flex: 0 0 150px;
  overflow: hidden;
}
.tl-track {
  position: relative;
  flex: 1 1 auto;
  height: 18px;
  border-radius: 3px;
  overflow: hidden;
  background: rgba(var(--v-theme-on-surface), 0.06);
  cursor: pointer;
}
.tl-track:focus-visible {
  outline: 2px solid rgb(var(--v-theme-primary));
  outline-offset: 2px;
}
/* The window the detail line reads, marked in its lane. */
.tl-bar--shown {
  box-shadow: inset 0 0 0 2px rgb(var(--v-theme-on-surface));
}
/* Its text keeps the window's three lines: who and where, when, how long. */
.tl-detail {
  white-space: pre-line;
  min-height: 1.5em;
  margin: 2px 70px 4px 158px;
}
.tl-bar {
  position: absolute;
  top: 3px;
  bottom: 3px;
  border-radius: 2px;
  cursor: default;
}
.tl-bar--watcher {
  top: 6px;
  bottom: 6px;
  opacity: 0.85;
}
/* A session with no end yet gets a soft trailing edge rather than a hard
   stop, so "still open" doesn't read as "ended exactly at the window edge". */
.tl-bar--open {
  border-top-right-radius: 0;
  border-bottom-right-radius: 0;
  -webkit-mask-image: linear-gradient(to right, #000 82%, transparent 100%);
  mask-image: linear-gradient(to right, #000 82%, transparent 100%);
}
.tl-total {
  flex: 0 0 62px;
  text-align: right;
  opacity: 0.75;
}
.tl-axis {
  position: relative;
  height: 16px;
  margin-left: 158px;
  margin-right: 70px;
}
.tl-tick {
  position: absolute;
  transform: translateX(-50%);
  white-space: nowrap;
}
.tl-legend {
  display: flex;
  gap: 12px;
  margin-top: 6px;
  margin-left: 158px;
  opacity: 0.85;
  flex-wrap: wrap;
}
.tl-legend-item {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.tl-dot {
  display: inline-block;
  width: 10px;
  height: 8px;
  border-radius: 2px;
}
.tl-dot--watcher {
  height: 5px;
}
.tl-legend-note {
  font-style: italic;
}
/* FR-116 — on a phone the device's name takes a line of its own above its
   lane, so the track gets the width: beside a 150 px label and a 62 px total
   it was ~36 px, and every viewing window was a sliver. The axis and legend
   drop the label column's indent with it. */
@media (max-width: 599.98px) {
  .tl-row {
    flex-wrap: wrap;
    row-gap: 2px;
    margin-bottom: 10px;
  }
  .tl-label {
    flex: 1 1 100%;
  }
  .tl-axis,
  .tl-legend {
    margin-left: 0;
  }
  .tl-detail {
    margin-left: 0;
    margin-right: 0;
  }
}
</style>
