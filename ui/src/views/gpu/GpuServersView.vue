<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-container fluid class="pa-2 pa-md-4 pa-xl-6 gpu-servers-view">
    <div class="d-flex flex-wrap align-center ga-2 mb-3">
      <div>
        <h1 class="text-h5 text-md-h4">{{ t('mh.gpu.title') }}</h1>
        <p class="text-body-2 text-medium-emphasis mb-0">{{ t('mh.gpu.subtitle') }}</p>
      </div>
      <v-spacer />
      <v-chip
        v-if="gpuStore.liveActive && !gpuStore.disabled"
        size="small"
        color="info"
        variant="tonal"
        prepend-icon="mdi-broadcast"
      >
        {{ t('mh.gpu.live2s') }}
      </v-chip>
      <v-btn
        color="primary"
        variant="tonal"
        size="small"
        prepend-icon="mdi-magnify"
        :disabled="!gpuStore.hosts.length"
        @click="findDialogOpen = true"
      >
        {{ t('mh.gpu.findFree') }}
      </v-btn>
      <v-btn
        variant="outlined"
        size="small"
        prepend-icon="mdi-refresh"
        :loading="gpuStore.loading"
        @click="refreshCurrentTab"
      >
        {{ t('common.refresh') }}
      </v-btn>
    </div>

    <v-alert v-if="gpuStore.disabled" type="info" variant="tonal" class="mb-4">
      {{ t('mh.gpu.disabledNotice') }}
    </v-alert>

    <template v-else>
      <!-- Summary strip -->
      <v-row dense class="mb-3">
        <v-col cols="6" sm="4" md="2">
          <v-card variant="tonal" class="pa-3">
            <div class="text-caption text-medium-emphasis">{{ t('mh.gpu.summary.hosts') }}</div>
            <div class="text-h6 font-weight-bold">
              {{ gpuStore.summary.hosts_online }} / {{ gpuStore.summary.hosts_total }}
            </div>
          </v-card>
        </v-col>
        <v-col cols="6" sm="4" md="2">
          <v-card variant="tonal" color="info" class="pa-3">
            <div class="text-caption">{{ t('mh.gpu.summary.free') }}</div>
            <div class="text-h6 font-weight-bold">
              {{ gpuStore.summary.gpus_free }} / {{ gpuStore.summary.gpus_total }}
            </div>
          </v-card>
        </v-col>
        <v-col cols="6" sm="4" md="2">
          <v-card variant="tonal" color="warning" class="pa-3">
            <div class="text-caption">{{ t('mh.gpu.summary.busy') }}</div>
            <div class="text-h6 font-weight-bold">{{ gpuStore.summary.gpus_busy }}</div>
          </v-card>
        </v-col>
        <v-col cols="6" sm="4" md="2">
          <v-card variant="tonal" color="deep-orange" class="pa-3">
            <div class="text-caption">{{ t('mh.gpu.summary.heldIdle') }}</div>
            <div class="text-h6 font-weight-bold">{{ gpuStore.summary.gpus_held_idle }}</div>
          </v-card>
        </v-col>
        <v-col cols="6" sm="4" md="2">
          <v-card variant="tonal" :color="gpuStore.summary.gpus_fault > 0 ? 'error' : undefined" class="pa-3">
            <div class="text-caption">{{ t('mh.gpu.summary.fault') }}</div>
            <div class="text-h6 font-weight-bold">{{ gpuStore.summary.gpus_fault }}</div>
          </v-card>
        </v-col>
      </v-row>

      <v-tabs v-model="tab" color="primary" class="mb-3">
        <v-tab value="fleet" prepend-icon="mdi-expansion-card">{{ t('mh.gpu.tabs.fleet') }}</v-tab>
        <v-tab value="users" prepend-icon="mdi-account-group-outline">{{ t('mh.gpu.tabs.users') }}</v-tab>
        <v-tab value="alerts" prepend-icon="mdi-bell-ring-outline">{{ t('mh.gpu.tabs.alerts') }}</v-tab>
      </v-tabs>

      <v-alert v-if="gpuStore.error" type="error" variant="tonal" density="compact" class="mb-3">
        {{ gpuStore.error }}
      </v-alert>

      <!-- Fleet Tab -->
      <template v-if="tab === 'fleet'">
        <div class="d-flex flex-wrap align-center ga-2 mb-3">
          <v-text-field
            v-model="search"
            density="compact"
            variant="outlined"
            hide-details
            clearable
            prepend-inner-icon="mdi-magnify"
            :placeholder="t('mh.gpu.searchPlaceholder')"
            style="min-width: 220px; max-width: 340px"
          />
          <v-chip-group v-model="stateFilter" mandatory selected-class="text-primary">
            <v-chip value="all" size="small" variant="outlined">{{ t('mh.gpu.filter.all') }}</v-chip>
            <v-chip value="free" size="small" variant="outlined">{{ t('mh.gpu.filter.free') }}</v-chip>
            <v-chip value="busy" size="small" variant="outlined">{{ t('mh.gpu.filter.busy') }}</v-chip>
            <v-chip value="held_idle" size="small" variant="outlined">{{ t('mh.gpu.filter.heldIdle') }}</v-chip>
            <v-chip value="fault" size="small" variant="outlined">{{ t('mh.gpu.filter.fault') }}</v-chip>
            <v-chip value="invited" size="small" variant="outlined">{{ t('mh.gpu.filter.invited') }}</v-chip>
            <v-chip value="shared" size="small" variant="outlined">{{ t('mh.gpu.filter.shared') }}</v-chip>
          </v-chip-group>
          <v-spacer />
          <v-select
            v-model="sortKey"
            :items="sortItems"
            density="compact"
            variant="outlined"
            hide-details
            style="max-width: 180px"
          />
        </div>

        <v-progress-linear v-if="gpuStore.loading && !gpuStore.hosts.length" indeterminate class="mb-3" />

        <v-card v-if="!gpuStore.loading && !gpuStore.hosts.length" variant="outlined" class="pa-6 text-center">
          <v-icon icon="mdi-expansion-card-variant" size="48" color="medium-emphasis" class="mb-2" />
          <div class="text-subtitle-1 font-weight-medium mb-1">{{ t('mh.gpu.emptyTitle') }}</div>
          <p class="text-body-2 text-medium-emphasis mb-4">{{ t('mh.gpu.emptyBody') }}</p>
          <v-btn color="primary" variant="tonal" :to="`/tenant/${tenantId}/devices`">
            {{ t('mh.gpu.goToDevices') }}
          </v-btn>
        </v-card>

        <div v-else class="d-flex flex-column ga-3">
          <v-card
            v-for="host in filteredHosts"
            :key="host.agent_id"
            variant="outlined"
            class="gpu-host-card"
            :data-testid="`gpu-host-${host.agent_id}`"
          >
            <v-card-title class="d-flex flex-wrap align-center ga-2 py-2 px-3 bg-surface-variant">
              <span class="font-weight-bold text-subtitle-1 cursor-pointer" @click="openDrawer(host)">
                {{ hostTitle(host) }}
              </span>
              <v-chip
                v-if="host.source === 'invited'"
                size="x-small"
                color="secondary"
                variant="tonal"
              >
                {{ t('mh.gpu.source.invited') }}
              </v-chip>
              <v-chip
                v-else-if="host.source === 'shared'"
                size="x-small"
                color="teal"
                variant="tonal"
              >
                {{ t('mh.gpu.source.sharedRo') }}
              </v-chip>
              <v-chip
                size="x-small"
                :color="freshnessColor(host.freshness)"
                variant="tonal"
              >
                {{ t(`mh.gpu.freshness.${host.freshness}`) }}
              </v-chip>
              <v-chip
                v-if="host.status !== 'ok'"
                size="x-small"
                color="error"
                variant="tonal"
              >
                {{ host.status }}
              </v-chip>
              <span class="text-caption text-medium-emphasis">
                {{ host.free_count }} / {{ host.total_count }} {{ t('mh.gpu.freeWord') }}
                <template v-if="host.driver_version"> · drv {{ host.driver_version }}</template>
                <template v-if="host.backend"> · {{ host.backend }}</template>
              </span>
              <v-spacer />
              <span v-if="host.host" class="text-caption text-medium-emphasis d-none d-sm-inline">
                CPU {{ host.host.cpu_pct != null ? Math.round(host.host.cpu_pct) : '—' }}%
                <template v-if="host.host.mem_used_mb != null && host.host.mem_total_mb != null">
                  · RAM {{ fmtGiB(host.host.mem_used_mb) }}/{{ fmtGiB(host.host.mem_total_mb) }}G
                </template>
                <template v-if="diskUsedPct(host.host) != null">
                  · Disk {{ diskUsedPct(host.host) }}%
                </template>
              </span>
              <v-btn
                size="x-small"
                variant="text"
                prepend-icon="mdi-chart-line"
                @click="openDrawer(host)"
              >
                {{ t('mh.gpu.details') }}
              </v-btn>
            </v-card-title>

            <v-card-text class="pa-0">
              <div v-if="!host.gpus.length" class="pa-3 text-body-2 text-medium-emphasis">
                {{ t('mh.gpu.noCardsYet') }}
              </div>
              <v-table v-else density="compact" class="gpu-cards-table">
                <thead>
                  <tr>
                    <th style="width: 48px">#</th>
                    <th>{{ t('mh.gpu.col.model') }}</th>
                    <th style="width: 100px">{{ t('mh.gpu.col.state') }}</th>
                    <th style="width: 165px">{{ t('mh.gpu.col.vram') }}</th>
                    <th style="width: 80px">{{ t('mh.gpu.col.util') }}</th>
                    <th style="width: 75px">{{ t('mh.gpu.col.temp') }}</th>
                    <th style="width: 105px">{{ t('mh.gpu.col.power') }}</th>
                    <th>{{ t('mh.gpu.col.processes') }}</th>
                    <th style="width: 48px"></th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="g in host.gpus" :key="g.uuid">
                    <td class="text-mono">{{ g.idx }}</td>
                    <td>
                      <div class="font-weight-medium">{{ g.name || 'GPU' }}</div>
                      <div class="text-caption text-medium-emphasis text-mono">
                        {{ g.uuid.slice(0, 18) }}
                        <span v-if="g.mig" class="ml-1">[MIG]</span>
                        <span v-if="g.unified" class="ml-1">[Unified]</span>
                      </div>
                    </td>
                    <td>
                      <v-chip
                        size="x-small"
                        :color="cardHasFault(g) ? 'purple' : stateColor(g.state)"
                        variant="flat"
                        class="font-weight-bold"
                      >
                        {{ cardHasFault(g) ? t('mh.gpu.state.fault') : stateLabel(g.state) }}
                      </v-chip>
                    </td>
                    <td>
                      <div class="text-caption text-mono mb-1">{{ fmtVram(g) }}</div>
                      <v-progress-linear
                        v-if="g.mem_total_mb && g.mem_used_mb != null"
                        :model-value="Math.min(100, (g.mem_used_mb / g.mem_total_mb) * 100)"
                        :color="cardHasFault(g) ? 'purple' : stateColor(g.state)"
                        height="5"
                        rounded
                      />
                    </td>
                    <td class="text-mono">{{ g.util_pct != null ? `${g.util_pct}%` : '—' }}</td>
                    <td class="text-mono">{{ g.temp_c != null ? `${g.temp_c}°C` : '—' }}</td>
                    <td class="text-mono">
                      <template v-if="g.power_w != null && g.power_limit_w != null">
                        {{ g.power_w }}/{{ g.power_limit_w }}W
                      </template>
                      <template v-else-if="g.power_w != null">{{ g.power_w }}W</template>
                      <template v-else>—</template>
                    </td>
                    <td>
                      <template v-if="g.procs && g.procs.length">
                        <div
                          v-for="p in g.procs.slice(0, 3)"
                          :key="p.pid"
                          class="text-caption text-mono"
                        >
                          <span class="font-weight-medium">{{ p.user || '—' }}</span>
                          <span class="text-medium-emphasis"> #{{ p.pid }}</span>
                          <span v-if="p.mem_mb != null"> {{ p.mem_mb }}M</span>
                          <span v-if="p.name" class="text-medium-emphasis"> {{ p.name }}</span>
                          <span v-if="p.container" class="text-medium-emphasis"> [{{ p.container }}]</span>
                        </div>
                        <div v-if="g.procs.length > 3" class="text-caption text-medium-emphasis">
                          +{{ g.procs.length - 3 }} {{ t('mh.gpu.moreProcs') }}
                        </div>
                      </template>
                      <span v-else-if="g.procs_state === 'off'" class="text-caption text-medium-emphasis">
                        {{ t('mh.gpu.procsOffLocal') }}
                      </span>
                      <span v-else class="text-caption text-medium-emphasis">—</span>
                    </td>
                    <td>
                      <v-btn
                        v-if="isSafeCudaUuid(g.uuid)"
                        :icon="copiedUuid === g.uuid ? 'mdi-check' : 'mdi-content-copy'"
                        size="x-small"
                        variant="text"
                        :color="copiedUuid === g.uuid ? 'success' : undefined"
                        :title="t('mh.gpu.copyCudaEnv')"
                        @click="copyCuda(g.uuid)"
                      />
                    </td>
                  </tr>
                </tbody>
              </v-table>
            </v-card-text>
          </v-card>
        </div>
      </template>

      <!-- Users Tab -->
      <GpuUsersTab v-else-if="tab === 'users'" :tenant-id="tenantId" />

      <!-- Alerts & Bots Tab -->
      <GpuAlertSettings v-else-if="tab === 'alerts'" :tenant-id="tenantId" />
    </template>

    <GpuHostDrawer
      v-model="drawerOpen"
      :tenant-id="tenantId"
      :host="gpuStore.selectedHost"
    />

    <GpuFindDialog
      v-model="findDialogOpen"
      :hosts="gpuStore.hosts"
    />
  </v-container>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { useGpuStore } from '@/stores/gpu'
import {
  cardHasFault,
  hostHasFault,
  isSafeCudaUuid,
  shellQuoteSingle,
  type GpuCardView,
  type GpuFreshness,
  type GpuHostLoad,
  type GpuHostView,
  type GpuState,
} from '@/api/gpu'
import GpuHostDrawer from './GpuHostDrawer.vue'
import GpuUsersTab from './GpuUsersTab.vue'
import GpuFindDialog from './GpuFindDialog.vue'
import GpuAlertSettings from './GpuAlertSettings.vue'

const { t } = useI18n()
const route = useRoute()
const gpuStore = useGpuStore()

const tenantId = computed(() => route.params.tenantId as string)
const tab = ref<'fleet' | 'users' | 'alerts'>('fleet')
const search = ref('')
const stateFilter = ref<'all' | 'free' | 'busy' | 'held_idle' | 'fault' | 'invited' | 'shared'>('all')
const sortKey = ref<'host' | 'free' | 'util' | 'mem'>('host')
const drawerOpen = ref(false)
const findDialogOpen = ref(false)
const copiedUuid = ref<string | null>(null)

const sortItems = computed(() => [
  { value: 'host', title: t('mh.gpu.sort.host') },
  { value: 'free', title: t('mh.gpu.sort.free') },
  { value: 'util', title: t('mh.gpu.sort.util') },
  { value: 'mem', title: t('mh.gpu.sort.vram') },
])

function hostTitle(h: GpuHostView): string {
  return h.display_name?.trim() || h.name
}

function fmtGiB(mb: number): string {
  return (mb / 1024).toFixed(1)
}

function fmtVram(g: GpuCardView): string {
  if (g.mem_used_mb != null && g.mem_total_mb != null) {
    return `${fmtGiB(g.mem_used_mb)} / ${fmtGiB(g.mem_total_mb)} GiB`
  }
  if (g.mem_used_mb != null) {
    return `${fmtGiB(g.mem_used_mb)} GiB${g.unified ? ' (unified)' : ''}`
  }
  return '—'
}

function diskUsedPct(load: GpuHostLoad): number | null {
  if (load.disk_root_used_gb != null && load.disk_root_total_gb != null && load.disk_root_total_gb > 0) {
    return Math.min(100, Math.max(0, Math.round((load.disk_root_used_gb / load.disk_root_total_gb) * 100)))
  }
  return null
}

// Color-blind-safe palette paired with explicit state words (never bare dots).
function stateColor(s: GpuState): string {
  switch (s) {
    case 'free':
      return 'info'
    case 'busy':
      return 'amber-darken-2'
    case 'held_idle':
    case 'unattributed':
      return 'deep-orange'
    default:
      return 'grey'
  }
}

function stateLabel(s: GpuState): string {
  return t(`mh.gpu.state.${s}`)
}

function freshnessColor(f: GpuFreshness): string {
  if (f === 'fresh') return 'info'
  if (f === 'stale') return 'warning'
  return 'grey'
}

const filteredHosts = computed(() => {
  const q = search.value.trim().toLowerCase()
  const list = gpuStore.hosts.filter((h) => {
    if (stateFilter.value === 'invited' && h.source !== 'invited') return false
    if (stateFilter.value === 'shared' && h.source !== 'shared') return false
    if (stateFilter.value === 'free' && !h.gpus.some((g) => g.state === 'free')) return false
    if (
      stateFilter.value === 'busy' &&
      !h.gpus.some((g) => g.state === 'busy' || g.state === 'unattributed')
    )
      return false
    if (stateFilter.value === 'held_idle' && !h.gpus.some((g) => g.state === 'held_idle')) return false
    if (stateFilter.value === 'fault' && !hostHasFault(h)) return false
    if (!q) return true
    if (hostTitle(h).toLowerCase().includes(q) || h.name.toLowerCase().includes(q)) return true
    return h.gpus.some(
      (g) =>
        (g.name || '').toLowerCase().includes(q) ||
        g.uuid.toLowerCase().includes(q) ||
        (g.procs || []).some(
          (p) =>
            (p.user || '').toLowerCase().includes(q) ||
            (p.name || '').toLowerCase().includes(q) ||
            (p.container || '').toLowerCase().includes(q),
        ),
    )
  })
  return [...list].sort((a, b) => {
    if (sortKey.value === 'free') return b.free_count - a.free_count || hostTitle(a).localeCompare(hostTitle(b))
    if (sortKey.value === 'util') {
      const ua = Math.max(0, ...a.gpus.map((g) => g.util_pct ?? 0))
      const ub = Math.max(0, ...b.gpus.map((g) => g.util_pct ?? 0))
      return ub - ua || hostTitle(a).localeCompare(hostTitle(b))
    }
    if (sortKey.value === 'mem') {
      const ma = Math.max(0, ...a.gpus.map((g) => g.mem_used_mb ?? 0))
      const mb = Math.max(0, ...b.gpus.map((g) => g.mem_used_mb ?? 0))
      return mb - ma || hostTitle(a).localeCompare(hostTitle(b))
    }
    return Number(b.is_online) - Number(a.is_online) || hostTitle(a).localeCompare(hostTitle(b))
  })
})

async function openDrawer(host: GpuHostView) {
  drawerOpen.value = true
  await gpuStore.openHostDetail(tenantId.value, host.agent_id)
}

async function copyCuda(uuid: string) {
  if (!isSafeCudaUuid(uuid)) return
  try {
    await navigator.clipboard.writeText(
      `export CUDA_DEVICE_ORDER=PCI_BUS_ID CUDA_VISIBLE_DEVICES=${shellQuoteSingle(uuid)}`,
    )
    copiedUuid.value = uuid
    setTimeout(() => {
      if (copiedUuid.value === uuid) copiedUuid.value = null
    }, 2000)
  } catch {
    /* clipboard may be blocked */
  }
}

function refreshCurrentTab() {
  if (tab.value === 'fleet') {
    void gpuStore.refreshFleet(tenantId.value, true)
  } else if (tab.value === 'users') {
    void gpuStore.loadUsers(tenantId.value)
  } else {
    void gpuStore.loadAlertSettings(tenantId.value)
  }
}

watch(
  tenantId,
  (tid) => {
    if (tid) gpuStore.startLivePolling(tid)
  },
  { immediate: true },
)

watch(tab, (next) => {
  if (!tenantId.value) return
  if (next === 'users') void gpuStore.loadUsers(tenantId.value)
  if (next === 'alerts') void gpuStore.loadAlertSettings(tenantId.value)
})

onMounted(() => {
  const hostQuery = route.query.host
  if (typeof hostQuery === 'string' && hostQuery) {
    void gpuStore.openHostDetail(tenantId.value, hostQuery).then(() => {
      if (gpuStore.selectedHost) drawerOpen.value = true
    })
  }
})

onBeforeUnmount(() => {
  gpuStore.stopLivePolling()
})
</script>

<style scoped>
.text-mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}
.cursor-pointer {
  cursor: pointer;
}
</style>
