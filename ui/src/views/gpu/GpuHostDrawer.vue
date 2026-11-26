<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-navigation-drawer
    :model-value="modelValue"
    location="right"
    temporary
    :width="drawerWidth"
    @update:model-value="$emit('update:modelValue', $event)"
  >
    <template v-if="host">
      <div class="d-flex align-center pa-3 border-b">
        <div class="min-w-0">
          <div class="d-flex align-center flex-wrap ga-2">
            <span class="text-h6 font-weight-bold">{{ host.display_name || host.name }}</span>
            <v-chip size="x-small" :color="freshnessChipColor" variant="tonal" class="text-mono">
              {{ freshnessLabel }}
            </v-chip>
            <v-chip
              v-if="host.status !== 'ok'"
              size="x-small"
              :color="statusChipColor"
              variant="tonal"
            >
              {{ statusLabel }}
            </v-chip>
          </div>
          <div class="text-caption text-medium-emphasis text-mono">
            {{ host.os }} · {{ host.backend || '—' }}
            <template v-if="host.driver_version"> · drv {{ host.driver_version }}</template>
            <template v-if="host.interval_ms"> · {{ Math.max(1, Math.round(host.interval_ms / 1000)) }}s</template>
          </div>
        </div>
        <v-spacer />
        <v-btn icon="mdi-close" size="small" variant="text" @click="$emit('update:modelValue', false)" />
      </div>

      <div class="pa-3">
        <v-alert v-if="host.read_only" type="info" variant="tonal" density="compact" class="mb-3">
          {{ t('mh.gpu.drawer.sharedReadOnly') }}
        </v-alert>

        <v-alert
          v-if="diagMessage"
          :type="host.host_fault_severity === 'critical' ? 'error' : 'warning'"
          variant="tonal"
          density="compact"
          class="mb-3"
        >
          {{ diagMessage }}
        </v-alert>

        <!-- Host Load -->
        <v-card v-if="host.host" variant="tonal" class="pa-3 mb-3">
          <div class="text-subtitle-2 mb-1">{{ t('mh.gpu.drawer.hostLoad') }}</div>
          <div class="d-flex flex-wrap ga-3 text-caption text-mono">
            <span>CPU: {{ host.host.cpu_pct != null ? Math.round(host.host.cpu_pct) : '—' }}%</span>
            <span v-if="host.host.load1 != null">Load: {{ host.host.load1.toFixed(2) }}</span>
            <span v-if="host.host.mem_used_mb != null && host.host.mem_total_mb != null">
              RAM: {{ (host.host.mem_used_mb / 1024).toFixed(1) }}/{{ (host.host.mem_total_mb / 1024).toFixed(1) }} GiB
            </span>
            <span v-if="host.host.swap_total_mb">
              Swap: {{ ((host.host.swap_used_mb ?? 0) / 1024).toFixed(1) }}/{{ (host.host.swap_total_mb / 1024).toFixed(1) }} GiB
            </span>
            <span v-if="host.host.disk_root_used_gb != null && host.host.disk_root_total_gb != null && host.host.disk_root_total_gb > 0">
              Disk: {{ Math.round((host.host.disk_root_used_gb / host.host.disk_root_total_gb) * 100) }}%
              ({{ host.host.disk_root_used_gb.toFixed(0) }}/{{ host.host.disk_root_total_gb.toFixed(0) }}G)
            </span>
            <span v-if="host.host.net_rx_bps != null || host.host.net_tx_bps != null">
              Net: ↓{{ (((host.host.net_rx_bps ?? 0) * 8) / 1e6).toFixed(1) }} ↑{{ (((host.host.net_tx_bps ?? 0) * 8) / 1e6).toFixed(1) }} Mbps
            </span>
          </div>
        </v-card>

        <!-- History Charts (reuses TimeSeriesChart with true null-gap support) -->
        <v-card variant="outlined" class="pa-3 mb-3">
          <div class="d-flex flex-wrap align-center ga-2 mb-2">
            <span class="text-subtitle-2">{{ t('mh.gpu.drawer.history') }}</span>
            <v-spacer />
            <v-select
              v-model="selectedUuid"
              :items="gpuChoices"
              density="compact"
              variant="outlined"
              hide-details
              style="max-width: 190px"
            />
            <v-btn-toggle v-model="range" density="compact" mandatory color="primary" variant="outlined">
              <v-btn value="1h" size="x-small">1h</v-btn>
              <v-btn value="24h" size="x-small">24h</v-btn>
              <v-btn value="7d" size="x-small">7d</v-btn>
              <v-btn value="30d" size="x-small">30d</v-btn>
            </v-btn-toggle>
          </div>
          <v-progress-linear v-if="gpuStore.historyLoading" indeterminate class="mb-2" />
          <v-alert
            v-if="gpuStore.historyError"
            type="error"
            variant="tonal"
            density="compact"
            class="mb-2"
          >
            {{ gpuStore.historyError }}
          </v-alert>
          <TimeSeriesChart
            :points="utilPoints"
            :series="utilSeries"
            :height="170"
            area
            :y-format="(v) => `${Math.round(v)}%`"
            :empty-text="t('mh.gpu.drawer.noHistory')"
          />
          <TimeSeriesChart
            class="mt-3"
            :points="memPoints"
            :series="memSeries"
            :height="150"
            area
            :y-format="(v) => `${(v / 1024).toFixed(1)}G`"
            :empty-text="t('mh.gpu.drawer.noHistory')"
          />
        </v-card>

        <!-- Per-GPU Cards -->
        <div class="text-subtitle-2 mb-2">{{ t('mh.gpu.drawer.cards') }}</div>
        <v-card v-for="g in host.gpus" :key="g.uuid" variant="outlined" class="pa-3 mb-2">
          <div class="d-flex align-center ga-2 mb-1">
            <span class="font-weight-bold text-mono">{{ slotLabel(g) }}</span>
            <span class="font-weight-medium">{{ g.name || 'GPU' }}</span>
            <v-spacer />
            <v-chip size="x-small" variant="tonal">{{ t(`mh.gpu.state.${g.state}`) }}</v-chip>
          </div>
          <div class="text-caption text-mono text-medium-emphasis mb-2">
            {{ g.uuid }}
            <template v-if="g.pci_bus"> · {{ g.pci_bus }}</template>
            <template v-if="g.sm_clock_mhz"> · SM {{ g.sm_clock_mhz }} MHz</template>
            <template v-if="g.fan_pct != null"> · Fan {{ g.fan_pct }}%</template>
            <template v-if="g.vendor_health"> · {{ g.vendor_health }}</template>
          </div>
          <div
            v-if="cardFaultReasons(g).length || hasPowerCap(g)"
            class="d-flex flex-wrap ga-1 mb-2"
          >
            <v-chip
              v-for="(reason, rIdx) in cardFaultReasons(g)"
              :key="`${reason.code}-${rIdx}`"
              size="x-small"
              :color="reason.severity === 'critical' ? 'error' : 'warning'"
              variant="tonal"
            >
              {{ reason.summary }}
            </v-chip>
            <v-chip v-if="hasPowerCap(g)" size="x-small" variant="tonal">
              {{ t('mh.gpu.throttle.power_cap') }}
            </v-chip>
          </div>
          <div v-if="g.procs?.length">
            <div v-for="p in g.procs" :key="p.pid" class="text-caption text-mono">
              pid {{ p.pid }} · {{ p.user || '—' }} · {{ p.mem_mb != null ? `${p.mem_mb} MiB` : '—' }} · {{ p.name || '—' }}<template v-if="p.container"> [{{ p.container }}]</template>
            </div>
          </div>
        </v-card>
      </div>
    </template>
  </v-navigation-drawer>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useDisplay } from 'vuetify'
import { useI18n } from 'vue-i18n'
import TimeSeriesChart, { type SeriesDef, type SeriesPoint } from '@/components/stats/TimeSeriesChart.vue'
import { useGpuStore } from '@/stores/gpu'
import {
  cardFaultReasons,
  cardRuntimeKind,
  type GpuCardView,
  type GpuHostView,
  type GpuRange,
} from '@/api/gpu'

const props = defineProps<{
  modelValue: boolean
  tenantId: string
  host: GpuHostView | null
}>()

defineEmits<{ (e: 'update:modelValue', v: boolean): void }>()

const { t, te } = useI18n()
const { smAndDown } = useDisplay()
const gpuStore = useGpuStore()

const range = ref<GpuRange>('24h')
const selectedUuid = ref<string>('')
const drawerWidth = computed(() => (smAndDown.value ? 360 : 620))

let historyTimer: ReturnType<typeof setInterval> | null = null

const isAscendHost = computed(
  () =>
    props.host?.backend === 'ascend' ||
    (props.host?.gpus ?? []).some((g) => cardRuntimeKind(props.host, g) === 'ascend'),
)

function slotLabel(g: GpuCardView): string {
  const rt = cardRuntimeKind(props.host, g)
  if (rt === 'ascend') return `NPU${g.vendor_index ?? g.idx}`
  if (rt === 'tpu') return `TPU${g.idx}`
  return `#${g.idx}`
}

function hasPowerCap(g: GpuCardView): boolean {
  return Boolean(g.throttle?.some((x) => x.toLowerCase() === 'power_cap'))
}

const freshnessChipColor = computed(() => {
  const h = props.host
  if (!h || !h.is_online || h.freshness === 'offline') return 'default'
  if (h.freshness === 'stale' || h.lagging) return 'warning'
  return 'success'
})

const freshnessLabel = computed(() => {
  const h = props.host
  if (!h) return ''
  const ageS = h.age_ms != null && h.age_ms >= 0 ? Math.floor(h.age_ms / 1000) : null
  const fmt = (s: number) =>
    s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m` : s < 86400 ? `${Math.floor(s / 3600)}h` : `${Math.floor(s / 86400)}d`
  if (!h.is_online || h.freshness === 'offline') {
    return ageS != null ? t('mh.gpu.freshness.offlineAge', { age: fmt(ageS) }) : t('mh.gpu.freshness.offline')
  }
  if (h.freshness === 'stale') return t('mh.gpu.freshness.staleAge', { age: ageS != null ? fmt(ageS) : '—' })
  if (h.lagging) return t('mh.gpu.freshness.laggingAge', { age: ageS != null ? fmt(ageS) : '—' })
  return ageS != null ? t('mh.gpu.freshness.freshAge', { age: fmt(ageS) }) : t('mh.gpu.freshness.fresh')
})

const statusLabel = computed(() => {
  const s = props.host?.status ?? ''
  const key = `mh.gpu.hostStatus.${s}`
  return te(key) ? t(key) : s
})

const statusChipColor = computed(() => {
  const h = props.host
  if (!h) return 'default'
  if (h.host_fault_severity === 'critical' || h.status === 'driver_missing' || h.status === 'driver_hung' || h.status === 'unavailable') {
    return 'error'
  }
  if (h.host_fault_severity === 'warning' || h.status === 'limited' || h.status === 'driver_reboot_pending' || h.status === 'sampler_stalled') {
    return 'warning'
  }
  return 'default'
})

const diagMessage = computed(() => {
  const h = props.host
  if (!h || !h.is_online || h.freshness === 'offline') return null
  if (h.status === 'ok' && !h.status_detail && !h.fault_reasons?.length) return null
  const parts: string[] = []
  const key = `mh.gpu.diag.${h.status}`
  if (te(key)) parts.push(t(key))
  if (h.status_detail && !parts.includes(h.status_detail)) parts.push(h.status_detail)
  if (!parts.length && h.fault_reasons?.length) {
    parts.push(h.fault_reasons.map((r) => r.summary).join(' · '))
  }
  return parts.length ? parts.join(' — ') : null
})

const gpuChoices = computed(() => [
  { value: '', title: t('mh.gpu.drawer.allGpus') },
  ...(props.host?.gpus ?? []).map((g) => ({
    value: g.uuid,
    title: `${slotLabel(g)} ${g.name || g.uuid.slice(0, 12)}`,
  })),
])

const utilSeries = computed<SeriesDef[]>(() => [
  { key: 'util_avg', label: isAscendHost.value ? 'AICore avg' : t('mh.gpu.drawer.utilAvg'), color: '#0288d1' },
  { key: 'util_max', label: isAscendHost.value ? 'AICore max' : t('mh.gpu.drawer.utilMax'), color: '#f57c00' },
])

const memSeries = computed<SeriesDef[]>(() => [
  { key: 'mem_avg', label: isAscendHost.value ? 'HBM avg' : t('mh.gpu.drawer.vramAvg'), color: '#00897b' },
  { key: 'mem_max', label: isAscendHost.value ? 'HBM max' : t('mh.gpu.drawer.vramMax'), color: '#7b1fa2' },
])

const utilPoints = computed<SeriesPoint[]>(() =>
  gpuStore.hostHistory.map((p) => ({
    t: Math.floor(p.ts_ms / 1000),
    util_avg: p.util_avg ?? null,
    util_max: p.util_max,
  })),
)

const memPoints = computed<SeriesPoint[]>(() =>
  gpuStore.hostHistory.map((p) => ({
    t: Math.floor(p.ts_ms / 1000),
    mem_avg: p.mem_used_avg_mb ?? null,
    mem_max: p.mem_used_max_mb,
  })),
)

function stopHistoryTimer() {
  if (historyTimer !== null) {
    clearInterval(historyTimer)
    historyTimer = null
  }
}

watch(
  () => props.host?.agent_id,
  () => {
    selectedUuid.value = ''
  },
)

watch(
  [() => props.modelValue, () => props.host?.agent_id, range, selectedUuid],
  ([open, aid, r, uuid]) => {
    stopHistoryTimer()
    if (open && aid) {
      void gpuStore.loadHostHistory(props.tenantId, aid, r, uuid || undefined)
      historyTimer = setInterval(() => {
        if (document.visibilityState === 'visible' && props.modelValue && props.host?.agent_id === aid) {
          void gpuStore.loadHostHistory(props.tenantId, aid, range.value, selectedUuid.value || undefined)
        }
      }, 60_000)
    }
  },
)

onBeforeUnmount(() => {
  stopHistoryTimer()
})
</script>

<style scoped>
.text-mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}
</style>
