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
        <div>
          <div class="text-h6 font-weight-bold">{{ host.display_name || host.name }}</div>
          <div class="text-caption text-medium-emphasis">
            {{ host.os }} · {{ host.backend || '—' }}
            <template v-if="host.driver_version"> · drv {{ host.driver_version }}</template>
          </div>
        </div>
        <v-spacer />
        <v-btn icon="mdi-close" size="small" variant="text" @click="$emit('update:modelValue', false)" />
      </div>

      <div class="pa-3">
        <v-alert v-if="host.read_only" type="info" variant="tonal" density="compact" class="mb-3">
          {{ t('mh.gpu.drawer.sharedReadOnly') }}
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

        <!-- History Charts (reuses TimeSeriesChart) -->
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
              <v-btn value="24h" size="x-small">24h</v-btn>
              <v-btn value="7d" size="x-small">7d</v-btn>
              <v-btn value="30d" size="x-small">30d</v-btn>
            </v-btn-toggle>
          </div>
          <v-progress-linear v-if="gpuStore.historyLoading" indeterminate class="mb-2" />
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
            <span class="font-weight-bold text-mono">#{{ g.idx }}</span>
            <span class="font-weight-medium">{{ g.name || 'GPU' }}</span>
            <v-spacer />
            <v-chip size="x-small" variant="tonal">{{ t(`mh.gpu.state.${g.state}`) }}</v-chip>
          </div>
          <div class="text-caption text-mono text-medium-emphasis mb-2">
            {{ g.uuid }}
            <template v-if="g.pci_bus"> · {{ g.pci_bus }}</template>
            <template v-if="g.sm_clock_mhz"> · SM {{ g.sm_clock_mhz }} MHz</template>
            <template v-if="g.fan_pct != null"> · Fan {{ g.fan_pct }}%</template>
          </div>
          <div v-if="(g.throttle && g.throttle.length) || (g.ecc_uncorrected && g.ecc_uncorrected > 0) || (g.xid_errors && g.xid_errors.length)" class="d-flex flex-wrap ga-1 mb-2">
            <v-chip v-for="th in g.throttle || []" :key="th" size="x-small" color="warning" variant="tonal">
              {{ th }}
            </v-chip>
            <v-chip v-if="g.ecc_uncorrected" size="x-small" color="error" variant="tonal">
              ECC uncorr: {{ g.ecc_uncorrected }}
            </v-chip>
            <v-chip v-if="g.remapped_rows" size="x-small" color="warning" variant="tonal">
              Remapped: {{ g.remapped_rows }}
            </v-chip>
            <v-chip v-if="g.xid_errors?.length" size="x-small" color="error" variant="tonal">
              Xid: {{ g.xid_errors.join(', ') }}
            </v-chip>
          </div>
          <div v-if="g.procs?.length">
            <div v-for="p in g.procs" :key="p.pid" class="text-caption text-mono">
              pid {{ p.pid }} · {{ p.user || '—' }} · {{ p.mem_mb ?? 0 }} MiB · {{ p.name || '—' }}<template v-if="p.container"> [{{ p.container }}]</template>
            </div>
          </div>
        </v-card>
      </div>
    </template>
  </v-navigation-drawer>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useDisplay } from 'vuetify'
import { useI18n } from 'vue-i18n'
import TimeSeriesChart, { type SeriesDef, type SeriesPoint } from '@/components/stats/TimeSeriesChart.vue'
import { useGpuStore } from '@/stores/gpu'
import type { GpuHostView, GpuRange } from '@/api/gpu'

const props = defineProps<{
  modelValue: boolean
  tenantId: string
  host: GpuHostView | null
}>()

defineEmits<{ (e: 'update:modelValue', v: boolean): void }>()

const { t } = useI18n()
const { smAndDown } = useDisplay()
const gpuStore = useGpuStore()

const range = ref<GpuRange>('24h')
const selectedUuid = ref<string>('')
const drawerWidth = computed(() => (smAndDown.value ? 360 : 620))

const gpuChoices = computed(() => [
  { value: '', title: t('mh.gpu.drawer.allGpus') },
  ...(props.host?.gpus ?? []).map((g) => ({
    value: g.uuid,
    title: `#${g.idx} ${g.name || g.uuid.slice(0, 12)}`,
  })),
])

const isAscendHost = computed(
  () =>
    props.host?.backend === 'ascend' ||
    (props.host?.gpus ?? []).some((g) => g.uuid.startsWith('ASCEND-')),
)

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
    util_avg: p.util_avg ?? 0,
    util_max: p.util_max,
  })),
)

const memPoints = computed<SeriesPoint[]>(() =>
  gpuStore.hostHistory.map((p) => ({
    t: Math.floor(p.ts_ms / 1000),
    mem_avg: p.mem_used_avg_mb ?? 0,
    mem_max: p.mem_used_max_mb,
  })),
)

watch([() => props.host?.agent_id, range, selectedUuid], ([aid, r, uuid]) => {
  if (aid && props.modelValue) {
    void gpuStore.loadHostHistory(props.tenantId, aid, r, uuid || undefined)
  }
})
</script>

<style scoped>
.text-mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}
</style>
