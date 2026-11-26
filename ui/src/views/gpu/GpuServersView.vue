<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-container fluid class="pa-2 pa-md-4 pa-xl-5 gpu-servers-view">
    <!-- Top Header + Compact Telemetry Ribbon -->
    <div class="nvitop-topbar mb-3">
      <div class="nvitop-title-block">
        <div class="d-flex align-center ga-2">
          <h1 class="nvitop-heading">{{ t('mh.gpu.title') }}</h1>
          <span
            v-if="gpuStore.liveActive && !gpuStore.disabled"
            class="nvitop-live-pill"
          >
            <span class="nvitop-live-dot" />
            {{ t('mh.gpu.live2s') }}
          </span>
        </div>
        <p class="nvitop-sub">{{ t('mh.gpu.subtitle') }}</p>
      </div>

      <div class="nvitop-actions">
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
    </div>

    <v-alert v-if="gpuStore.disabled" type="info" variant="tonal" class="mb-4">
      {{ t('mh.gpu.disabledNotice') }}
    </v-alert>

    <template v-else>
      <!-- Compact Instrument Telemetry Ribbon -->
      <div class="nvitop-kpi-ribbon mb-3">
        <div class="nvitop-kpi">
          <span class="nvitop-kpi-lbl">{{ t('mh.gpu.summary.hosts') }}</span>
          <span class="nvitop-kpi-val text-mono">
            {{ gpuStore.summary.hosts_online }}<span class="nvitop-kpi-dim">/{{ gpuStore.summary.hosts_total }}</span>
          </span>
        </div>
        <div class="nvitop-kpi nvitop-kpi-free">
          <span class="nvitop-kpi-lbl">{{ t('mh.gpu.summary.free') }}</span>
          <span class="nvitop-kpi-val text-mono">
            {{ gpuStore.summary.gpus_free }}<span class="nvitop-kpi-dim">/{{ gpuStore.summary.gpus_total }}</span>
          </span>
        </div>
        <div class="nvitop-kpi nvitop-kpi-busy">
          <span class="nvitop-kpi-lbl">{{ t('mh.gpu.summary.busy') }}</span>
          <span class="nvitop-kpi-val text-mono">{{ gpuStore.summary.gpus_busy }}</span>
        </div>
        <div class="nvitop-kpi nvitop-kpi-held">
          <span class="nvitop-kpi-lbl">{{ t('mh.gpu.summary.heldIdle') }}</span>
          <span class="nvitop-kpi-val text-mono">{{ gpuStore.summary.gpus_held_idle }}</span>
        </div>
        <div class="nvitop-kpi" :class="{ 'nvitop-kpi-fault': gpuStore.summary.gpus_fault > 0 }">
          <span class="nvitop-kpi-lbl">{{ t('mh.gpu.summary.fault') }}</span>
          <span class="nvitop-kpi-val text-mono">{{ gpuStore.summary.gpus_fault }}</span>
        </div>
      </div>

      <v-tabs v-model="tab" color="primary" density="compact" class="mb-3">
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

        <div v-else class="nvitop-fleet">
          <section
            v-for="host in filteredHosts"
            :key="host.agent_id"
            class="nvitop-host"
            :class="{ 'nvitop-host-offline': !host.is_online || host.freshness === 'offline' }"
            :data-testid="`gpu-host-${host.agent_id}`"
          >
            <!-- Rack Bay Header -->
            <header class="nvitop-host-head">
              <div class="nvitop-host-id">
                <span
                  class="nvitop-status-dot"
                  :class="`dot-${host.freshness}`"
                  :title="t(`mh.gpu.freshness.${host.freshness}`)"
                />
                <button type="button" class="nvitop-host-name" @click="openDrawer(host)">
                  {{ hostTitle(host) }}
                </button>
                <span class="nvitop-pill nvitop-pill-vendor text-mono">
                  {{ vendorLabel(host) }}
                  <template v-if="host.driver_version"> · {{ host.driver_version }}</template>
                </span>
                <span v-if="host.source === 'invited'" class="nvitop-pill nvitop-pill-invited">
                  {{ t('mh.gpu.source.invited') }}
                </span>
                <span v-else-if="host.source === 'shared'" class="nvitop-pill nvitop-pill-shared">
                  {{ t('mh.gpu.source.sharedRo') }}
                </span>
                <span v-if="host.status !== 'ok'" class="nvitop-pill nvitop-pill-err text-mono">
                  {{ host.status }}
                </span>
              </div>

              <div class="nvitop-host-right">
                <span
                  class="nvitop-free-counter text-mono"
                  :class="{ 'has-free': host.free_count > 0 && host.is_online }"
                >
                  {{ host.free_count }}/{{ host.total_count }} {{ t('mh.gpu.freeWord') }}
                </span>
                <v-btn
                  v-if="hostFreeExportCmd(host)"
                  size="x-small"
                  variant="tonal"
                  color="success"
                  :prepend-icon="copiedHostId === host.agent_id ? 'mdi-check' : 'mdi-content-copy'"
                  @click="copyHostFree(host)"
                >
                  {{ copiedHostId === host.agent_id ? t('mh.gpu.find.copied') : t('mh.gpu.find.copy') }}
                </v-btn>
                <v-btn
                  size="x-small"
                  variant="text"
                  prepend-icon="mdi-chart-line"
                  @click="openDrawer(host)"
                >
                  {{ t('mh.gpu.details') }}
                </v-btn>
              </div>
            </header>

            <!-- Classic nvitop Host Resource Mini-Bars -->
            <div v-if="host.host" class="nvitop-host-strip text-mono">
              <div class="nvitop-mini-gauge">
                <span class="nvitop-mini-k">CPU</span>
                <div class="nvitop-mini-track">
                  <div
                    class="nvitop-mini-fill"
                    :class="loadTone(host.host.cpu_pct)"
                    :style="{ width: `${clampPct(host.host.cpu_pct)}%` }"
                  />
                </div>
                <span class="nvitop-mini-v">
                  {{ host.host.cpu_pct != null ? `${Math.round(host.host.cpu_pct)}%` : '—' }}
                  <template v-if="host.host.load1 != null"> · L {{ host.host.load1.toFixed(1) }}</template>
                </span>
              </div>

              <div
                v-if="host.host.mem_used_mb != null && host.host.mem_total_mb != null && host.host.mem_total_mb > 0"
                class="nvitop-mini-gauge"
              >
                <span class="nvitop-mini-k">MEM</span>
                <div class="nvitop-mini-track">
                  <div
                    class="nvitop-mini-fill"
                    :class="loadTone(memPct(host.host.mem_used_mb, host.host.mem_total_mb))"
                    :style="{ width: `${memPct(host.host.mem_used_mb, host.host.mem_total_mb)}%` }"
                  />
                </div>
                <span class="nvitop-mini-v">
                  {{ fmtGiB(host.host.mem_used_mb) }}/{{ fmtGiB(host.host.mem_total_mb) }}G
                </span>
              </div>

              <div
                v-if="host.host.swap_total_mb != null && host.host.swap_total_mb > 0"
                class="nvitop-mini-gauge"
              >
                <span class="nvitop-mini-k">SWP</span>
                <div class="nvitop-mini-track">
                  <div
                    class="nvitop-mini-fill"
                    :class="loadTone(memPct(host.host.swap_used_mb ?? 0, host.host.swap_total_mb))"
                    :style="{ width: `${memPct(host.host.swap_used_mb ?? 0, host.host.swap_total_mb)}%` }"
                  />
                </div>
                <span class="nvitop-mini-v">
                  {{ fmtGiB(host.host.swap_used_mb ?? 0) }}/{{ fmtGiB(host.host.swap_total_mb) }}G
                </span>
              </div>

              <div v-if="diskUsedPct(host.host) != null" class="nvitop-mini-gauge">
                <span class="nvitop-mini-k">DSK</span>
                <div class="nvitop-mini-track">
                  <div
                    class="nvitop-mini-fill"
                    :class="loadTone(diskUsedPct(host.host))"
                    :style="{ width: `${diskUsedPct(host.host)}%` }"
                  />
                </div>
                <span class="nvitop-mini-v">{{ diskUsedPct(host.host) }}%</span>
              </div>

              <div v-if="host.host.net_rx_bps != null || host.host.net_tx_bps != null" class="nvitop-mini-net">
                ↓{{ fmtRate(host.host.net_rx_bps ?? 0) }} ↑{{ fmtRate(host.host.net_tx_bps ?? 0) }}
              </div>
            </div>

            <!-- Per-Card nvitop Instrument Rows -->
            <div v-if="!host.gpus.length" class="nvitop-empty-host">
              {{ t('mh.gpu.noCardsYet') }}
            </div>
            <div v-else class="nvitop-cards">
              <div
                v-for="g in host.gpus"
                :key="g.uuid"
                class="nvitop-card"
                :class="[`state-${cardHasFault(g) ? 'fault' : g.state}`]"
              >
                <div class="nvitop-card-main">
                  <!-- Slot + Name + State -->
                  <div class="nvitop-card-id">
                    <span class="nvitop-idx text-mono">
                      {{ isAscendCard(host, g) ? `NPU${g.idx}` : `#${g.idx}` }}
                    </span>
                    <div class="nvitop-model-wrap">
                      <span class="nvitop-model">{{ shortModel(g.name) }}</span>
                      <span class="nvitop-submeta text-mono">
                        <template v-if="g.pci_bus">{{ g.pci_bus }}</template>
                        <template v-else>{{ g.uuid.slice(0, 14) }}</template>
                        <span v-if="g.mig" class="nvitop-tag">MIG</span>
                        <span v-if="g.unified" class="nvitop-tag">Unified</span>
                      </span>
                    </div>
                    <span
                      class="nvitop-state-badge text-mono"
                      :class="`badge-${cardHasFault(g) ? 'fault' : g.state}`"
                    >
                      {{ cardHasFault(g) ? t('mh.gpu.state.fault') : stateLabel(g.state) }}
                    </span>
                  </div>

                  <!-- Dual Segmented nvitop Progress Bars -->
                  <div class="nvitop-bars text-mono">
                    <!-- Memory / HBM Bar -->
                    <div class="nvitop-bar-group">
                      <span class="nvitop-bar-lbl">{{ isAscendCard(host, g) ? 'HBM' : 'MEM' }}</span>
                      <div class="nvitop-bar-track">
                        <div
                          class="nvitop-bar-fill"
                          :class="cardHasFault(g) ? 'tone-fault' : loadTone(vramPct(g))"
                          :style="{ width: `${vramPct(g) ?? 0}%` }"
                        />
                        <div class="nvitop-bar-ticks" aria-hidden="true" />
                        <span class="nvitop-bar-overlay">
                          <span>{{ fmtVramCompact(g) }}</span>
                          <span v-if="vramPct(g) != null">{{ vramPct(g) }}%</span>
                        </span>
                      </div>
                    </div>

                    <!-- Compute / AICore Bar -->
                    <div class="nvitop-bar-group nvitop-bar-util">
                      <span class="nvitop-bar-lbl">{{ isAscendCard(host, g) ? 'AIC' : 'GPU' }}</span>
                      <div class="nvitop-bar-track">
                        <div
                          class="nvitop-bar-fill"
                          :class="cardHasFault(g) ? 'tone-fault' : loadTone(g.util_pct)"
                          :style="{ width: `${clampPct(g.util_pct)}%` }"
                        />
                        <div class="nvitop-bar-ticks" aria-hidden="true" />
                        <span class="nvitop-bar-overlay nvitop-bar-overlay-end">
                          {{ g.util_pct != null ? `${g.util_pct}%` : '—' }}
                        </span>
                      </div>
                    </div>
                  </div>

                  <!-- Thermal / Power / Clock / Copy -->
                  <div class="nvitop-card-env text-mono">
                    <span class="nvitop-temp" :class="tempTone(g.temp_c)">
                      {{ g.temp_c != null ? `${g.temp_c}°C` : '—' }}
                    </span>
                    <span class="nvitop-power">
                      <template v-if="g.power_w != null && g.power_limit_w != null">
                        {{ g.power_w }}/{{ g.power_limit_w }}W
                      </template>
                      <template v-else-if="g.power_w != null">{{ g.power_w }}W</template>
                      <template v-else>—</template>
                    </span>
                    <span v-if="g.fan_pct != null" class="nvitop-fan" title="Fan">
                      {{ g.fan_pct }}%
                    </span>
                    <v-btn
                      v-if="isSafeCudaUuid(g.uuid)"
                      :icon="copiedUuid === g.uuid ? 'mdi-check' : 'mdi-content-copy'"
                      size="x-small"
                      variant="text"
                      density="compact"
                      :color="copiedUuid === g.uuid ? 'success' : undefined"
                      :title="cardExportCmd(host, g)"
                      @click="copyCardEnv(host, g)"
                    />
                  </div>
                </div>

                <!-- Compact Inline Process Sub-Rows -->
                <div v-if="g.procs && g.procs.length" class="nvitop-procs text-mono">
                  <div
                    v-for="p in visibleProcs(g)"
                    :key="p.pid"
                    class="nvitop-proc-row"
                    :class="{ 'is-graphics-idle': p.kind === 'graphics' && (p.mem_mb ?? 0) < 64 }"
                  >
                    <span class="nvitop-proc-branch">└</span>
                    <span class="nvitop-proc-dot" :style="{ background: userColor(p.user) }" />
                    <span class="nvitop-proc-user">{{ p.user || '—' }}</span>
                    <span class="nvitop-proc-pid">#{{ p.pid }}</span>
                    <span class="nvitop-proc-name">
                      {{ p.name || '—' }}
                      <span v-if="p.container" class="nvitop-proc-ctr">{{ p.container }}</span>
                    </span>
                    <div
                      v-if="p.mem_mb != null && g.mem_total_mb && g.mem_total_mb > 0"
                      class="nvitop-proc-bar"
                    >
                      <div
                        class="nvitop-proc-bar-fill"
                        :style="{
                          width: `${Math.min(100, Math.round((p.mem_mb / g.mem_total_mb) * 100))}%`,
                          background: userColor(p.user),
                        }"
                      />
                    </div>
                    <span class="nvitop-proc-mem">{{ fmtProcMem(p.mem_mb) }}</span>
                    <span class="nvitop-proc-age">{{ fmtProcAge(p.started_at) }}</span>
                  </div>
                  <button
                    v-if="g.procs.length > 3"
                    type="button"
                    class="nvitop-more-procs"
                    @click="toggleExpandProcs(g.uuid)"
                  >
                    {{
                      expandedProcs.has(g.uuid)
                        ? '−'
                        : `+${g.procs.length - 3} ${t('mh.gpu.moreProcs')}`
                    }}
                  </button>
                </div>
                <div v-else-if="g.procs_state === 'off'" class="nvitop-procs-note">
                  {{ t('mh.gpu.procsOffLocal') }}
                </div>
              </div>
            </div>
          </section>
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
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { useGpuStore } from '@/stores/gpu'
import {
  cardHasFault,
  hostHasFault,
  isSafeCudaUuid,
  shellQuoteSingle,
  type GpuCardView,
  type GpuHostLoad,
  type GpuHostView,
  type GpuProc,
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
const copiedHostId = ref<string | null>(null)
const expandedProcs = reactive(new Set<string>())

const sortItems = computed(() => [
  { value: 'host', title: t('mh.gpu.sort.host') },
  { value: 'free', title: t('mh.gpu.sort.free') },
  { value: 'util', title: t('mh.gpu.sort.util') },
  { value: 'mem', title: t('mh.gpu.sort.vram') },
])

function hostTitle(h: GpuHostView): string {
  return h.display_name?.trim() || h.name
}

function isAscendHost(h: GpuHostView): boolean {
  return (h.backend || '').toLowerCase().includes('ascend')
}

function isAscendCard(h: GpuHostView, g: GpuCardView): boolean {
  return isAscendHost(h) || g.uuid.startsWith('ASCEND-') || (g.name || '').toLowerCase().includes('ascend')
}

function vendorLabel(h: GpuHostView): string {
  const b = (h.backend || '').toLowerCase()
  if (b.includes('ascend')) return 'Ascend NPU'
  if (b.includes('nvml')) return 'NVIDIA'
  if (b.includes('amd')) return 'AMD'
  if (b.includes('intel')) return 'Intel'
  if (b.includes('apple')) return 'Apple'
  return h.backend || 'GPU'
}

function shortModel(name?: string | null): string {
  if (!name) return 'GPU'
  return name
    .replace(/^NVIDIA GeForce\s+/i, '')
    .replace(/^NVIDIA\s+/i, '')
    .replace(/\s+Ada Generation$/i, ' Ada')
    .trim()
}

function fmtGiB(mb: number): string {
  return (mb / 1024).toFixed(1)
}

function clampPct(v: number | null | undefined): number {
  if (v == null || !Number.isFinite(v)) return 0
  return Math.min(100, Math.max(0, Math.round(v)))
}

function memPct(used: number, total: number): number {
  if (!total || total <= 0) return 0
  return Math.min(100, Math.max(0, Math.round((used / total) * 100)))
}

function vramPct(g: GpuCardView): number | null {
  if (g.mem_used_mb == null || !g.mem_total_mb || g.mem_total_mb <= 0) return null
  return Math.min(100, Math.max(0, Math.round((g.mem_used_mb / g.mem_total_mb) * 100)))
}

function fmtVramCompact(g: GpuCardView): string {
  if (g.mem_used_mb != null && g.mem_total_mb != null) {
    return `${fmtGiB(g.mem_used_mb)}/${fmtGiB(g.mem_total_mb)}G`
  }
  if (g.mem_used_mb != null) {
    return `${fmtGiB(g.mem_used_mb)}G${g.unified ? ' uni' : ''}`
  }
  return '—'
}

function fmtProcMem(mb?: number | null): string {
  if (mb == null) return '—'
  if (mb >= 1024) return `${(mb / 1024).toFixed(1)}G`
  return `${mb}M`
}

function fmtProcAge(startedAt?: number | null): string {
  if (!startedAt || startedAt <= 0) return ''
  const nowS = Math.floor(Date.now() / 1000)
  const s = Math.max(0, nowS - startedAt)
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m`
  if (s < 86400) return `${Math.floor(s / 3600)}h`
  return `${Math.floor(s / 86400)}d`
}

function fmtRate(bps: number): string {
  if (bps >= 1024 * 1024 * 1024) return `${(bps / (1024 * 1024 * 1024)).toFixed(1)}G/s`
  if (bps >= 1024 * 1024) return `${(bps / (1024 * 1024)).toFixed(1)}M/s`
  if (bps >= 1024) return `${Math.round(bps / 1024)}K/s`
  return `${bps}B/s`
}

function diskUsedPct(load: GpuHostLoad): number | null {
  if (load.disk_root_used_gb != null && load.disk_root_total_gb != null && load.disk_root_total_gb > 0) {
    return Math.min(100, Math.max(0, Math.round((load.disk_root_used_gb / load.disk_root_total_gb) * 100)))
  }
  return null
}

function loadTone(pct: number | null | undefined): string {
  if (pct == null) return 'tone-idle'
  if (pct >= 80) return 'tone-hot'
  if (pct >= 50) return 'tone-warm'
  return 'tone-cool'
}

function tempTone(c: number | null | undefined): string {
  if (c == null) return ''
  if (c >= 85) return 'temp-hot'
  if (c >= 72) return 'temp-warm'
  return 'temp-cool'
}

const USER_PALETTE = ['#38bdf8', '#a78bfa', '#34d399', '#fbbf24', '#f472b6', '#fb923c', '#2dd4bf']
function userColor(user?: string | null): string {
  if (!user) return '#64748b'
  let hash = 0
  for (let i = 0; i < user.length; i++) hash = ((hash << 5) - hash + user.charCodeAt(i)) | 0
  return USER_PALETTE[Math.abs(hash) % USER_PALETTE.length]
}

function visibleProcs(g: GpuCardView): GpuProc[] {
  const list = g.procs || []
  return expandedProcs.has(g.uuid) ? list : list.slice(0, 3)
}

function toggleExpandProcs(uuid: string) {
  if (expandedProcs.has(uuid)) expandedProcs.delete(uuid)
  else expandedProcs.add(uuid)
}

function stateLabel(s: GpuState): string {
  return t(`mh.gpu.state.${s}`)
}

function cardExportCmd(h: GpuHostView, g: GpuCardView): string {
  if (isAscendCard(h, g)) {
    return `export ASCEND_RT_VISIBLE_DEVICES=${shellQuoteSingle(String(g.idx))}`
  }
  return `export CUDA_DEVICE_ORDER=PCI_BUS_ID CUDA_VISIBLE_DEVICES=${shellQuoteSingle(g.uuid)}`
}

function hostFreeExportCmd(h: GpuHostView): string | null {
  if (!h.is_online || h.freshness === 'offline') return null
  const free = h.gpus.filter((g) => g.state === 'free' && !cardHasFault(g) && isSafeCudaUuid(g.uuid))
  if (!free.length) return null
  if (isAscendHost(h) || free.every((g) => g.uuid.startsWith('ASCEND-'))) {
    return `export ASCEND_RT_VISIBLE_DEVICES=${shellQuoteSingle(free.map((g) => String(g.idx)).join(','))}`
  }
  return `export CUDA_DEVICE_ORDER=PCI_BUS_ID CUDA_VISIBLE_DEVICES=${shellQuoteSingle(free.map((g) => g.uuid).join(','))}`
}

async function copyCardEnv(h: GpuHostView, g: GpuCardView) {
  if (!isSafeCudaUuid(g.uuid)) return
  try {
    await navigator.clipboard.writeText(cardExportCmd(h, g))
    copiedUuid.value = g.uuid
    setTimeout(() => {
      if (copiedUuid.value === g.uuid) copiedUuid.value = null
    }, 2000)
  } catch {
    /* clipboard may be blocked */
  }
}

async function copyHostFree(h: GpuHostView) {
  const cmd = hostFreeExportCmd(h)
  if (!cmd) return
  try {
    await navigator.clipboard.writeText(cmd)
    copiedHostId.value = h.agent_id
    setTimeout(() => {
      if (copiedHostId.value === h.agent_id) copiedHostId.value = null
    }, 2000)
  } catch {
    /* clipboard may be blocked */
  }
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
    if ((h.backend || '').toLowerCase().includes(q)) return true
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
.gpu-servers-view {
  --nv-surface: rgb(var(--v-theme-surface));
  --nv-border: rgba(var(--v-border-color), var(--v-border-opacity));
  --nv-track: rgba(var(--v-theme-on-surface), 0.085);
  --nv-track-inset: inset 0 1px 2px rgba(0, 0, 0, 0.14);
  --nv-row-hover: rgba(var(--v-theme-on-surface), 0.03);
  --nv-muted: rgba(var(--v-theme-on-surface), 0.62);
  --nv-cool: #16a34a;
  --nv-cool-soft: rgba(22, 163, 74, 0.14);
  --nv-warm: #d97706;
  --nv-warm-soft: rgba(217, 119, 6, 0.16);
  --nv-hot: #dc2626;
  --nv-hot-soft: rgba(220, 38, 38, 0.16);
  --nv-held: #ea580c;
  --nv-fault: #9333ea;
}

.text-mono {
  font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-variant-numeric: tabular-nums;
}

.nvitop-topbar {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  justify-content: space-between;
  gap: 12px;
}

.nvitop-heading {
  font-size: 1.35rem;
  font-weight: 700;
  letter-spacing: -0.02em;
  line-height: 1.2;
  margin: 0;
}

.nvitop-sub {
  font-size: 0.82rem;
  color: var(--nv-muted);
  margin: 2px 0 0;
}

.nvitop-live-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 0.72rem;
  font-weight: 600;
  padding: 2px 9px;
  border-radius: 999px;
  background: var(--nv-cool-soft);
  color: var(--nv-cool);
  letter-spacing: 0.02em;
}

.nvitop-live-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--nv-cool);
  box-shadow: 0 0 0 3px rgba(22, 163, 74, 0.22);
}

.nvitop-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

/* Compact Instrument KPI Ribbon */
.nvitop-kpi-ribbon {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  border: 1px solid var(--nv-border);
  border-radius: 10px;
  background: var(--nv-surface);
  overflow: hidden;
}

.nvitop-kpi {
  padding: 9px 14px;
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 8px;
  border-right: 1px solid var(--nv-border);
}

.nvitop-kpi:last-child {
  border-right: none;
}

.nvitop-kpi-lbl {
  font-size: 0.72rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--nv-muted);
}

.nvitop-kpi-val {
  font-size: 1.15rem;
  font-weight: 700;
}

.nvitop-kpi-dim {
  font-size: 0.82rem;
  font-weight: 500;
  color: var(--nv-muted);
}

.nvitop-kpi-free .nvitop-kpi-val {
  color: var(--nv-cool);
}

.nvitop-kpi-busy .nvitop-kpi-val {
  color: var(--nv-warm);
}

.nvitop-kpi-held .nvitop-kpi-val {
  color: var(--nv-held);
}

.nvitop-kpi-fault .nvitop-kpi-val {
  color: var(--nv-fault);
}

/* Host Rack Bay */
.nvitop-fleet {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.nvitop-host {
  border: 1px solid var(--nv-border);
  border-radius: 10px;
  background: var(--nv-surface);
  overflow: hidden;
  transition: border-color 140ms ease;
}

.nvitop-host-offline {
  opacity: 0.68;
}

.nvitop-host-head {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 8px 12px;
  padding: 9px 14px;
  border-bottom: 1px solid var(--nv-border);
  background: rgba(var(--v-theme-on-surface), 0.025);
}

.nvitop-host-id {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}

.nvitop-status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}

.dot-fresh {
  background: var(--nv-cool);
  box-shadow: 0 0 6px rgba(22, 163, 74, 0.55);
}

.dot-stale {
  background: var(--nv-warm);
}

.dot-offline {
  background: #64748b;
}

.nvitop-host-name {
  font-size: 0.96rem;
  font-weight: 700;
  letter-spacing: -0.01em;
  background: none;
  border: none;
  padding: 0;
  color: inherit;
  cursor: pointer;
}

.nvitop-host-name:hover {
  text-decoration: underline;
}

.nvitop-pill {
  font-size: 0.7rem;
  font-weight: 600;
  padding: 2px 7px;
  border-radius: 5px;
  line-height: 1.3;
}

.nvitop-pill-vendor {
  background: rgba(var(--v-theme-on-surface), 0.07);
  color: var(--nv-muted);
}

.nvitop-pill-invited {
  background: rgba(99, 102, 241, 0.14);
  color: #6366f1;
}

.nvitop-pill-shared {
  background: rgba(20, 184, 166, 0.14);
  color: #0d9488;
}

.nvitop-pill-err {
  background: var(--nv-hot-soft);
  color: var(--nv-hot);
}

.nvitop-host-right {
  display: flex;
  align-items: center;
  gap: 8px;
}

.nvitop-free-counter {
  font-size: 0.78rem;
  font-weight: 700;
  padding: 2px 8px;
  border-radius: 6px;
  background: rgba(var(--v-theme-on-surface), 0.06);
  color: var(--nv-muted);
}

.nvitop-free-counter.has-free {
  background: var(--nv-cool-soft);
  color: var(--nv-cool);
}

/* Host Mini-Gauges Strip */
.nvitop-host-strip {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px 18px;
  padding: 6px 14px;
  border-bottom: 1px solid var(--nv-border);
  font-size: 0.74rem;
  color: var(--nv-muted);
}

.nvitop-mini-gauge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.nvitop-mini-k {
  font-weight: 700;
  font-size: 0.68rem;
  letter-spacing: 0.04em;
  min-width: 26px;
}

.nvitop-mini-track {
  width: 68px;
  height: 7px;
  border-radius: 3px;
  background: var(--nv-track);
  box-shadow: var(--nv-track-inset);
  overflow: hidden;
}

.nvitop-mini-fill {
  height: 100%;
  border-radius: 3px;
  transition: width 220ms ease;
}

.nvitop-mini-v {
  color: rgb(var(--v-theme-on-surface));
  opacity: 0.85;
}

.nvitop-mini-net {
  margin-left: auto;
  font-size: 0.72rem;
}

.nvitop-empty-host {
  padding: 14px;
  font-size: 0.84rem;
  color: var(--nv-muted);
}

/* Per-Card nvitop Rows */
.nvitop-cards {
  display: flex;
  flex-direction: column;
}

.nvitop-card {
  padding: 8px 14px;
  border-bottom: 1px solid var(--nv-border);
  border-left: 3px solid transparent;
  transition: background-color 120ms ease;
}

.nvitop-card:last-child {
  border-bottom: none;
}

.nvitop-card:hover {
  background: var(--nv-row-hover);
}

.nvitop-card.state-free {
  border-left-color: var(--nv-cool);
}

.nvitop-card.state-busy {
  border-left-color: var(--nv-warm);
}

.nvitop-card.state-held_idle,
.nvitop-card.state-unattributed {
  border-left-color: var(--nv-held);
}

.nvitop-card.state-fault {
  border-left-color: var(--nv-fault);
}

.nvitop-card-main {
  display: grid;
  grid-template-columns: minmax(215px, 1.1fr) minmax(300px, 2.2fr) minmax(168px, auto);
  align-items: center;
  gap: 10px 14px;
}

.nvitop-card-id {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

.nvitop-idx {
  font-size: 0.74rem;
  font-weight: 700;
  padding: 2px 6px;
  border-radius: 5px;
  background: rgba(var(--v-theme-on-surface), 0.08);
  flex-shrink: 0;
}

.nvitop-model-wrap {
  display: flex;
  flex-direction: column;
  min-width: 0;
  flex: 1;
}

.nvitop-model {
  font-size: 0.84rem;
  font-weight: 650;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.nvitop-submeta {
  font-size: 0.68rem;
  color: var(--nv-muted);
  display: flex;
  align-items: center;
  gap: 4px;
}

.nvitop-tag {
  font-size: 0.64rem;
  padding: 0 4px;
  border-radius: 3px;
  background: rgba(var(--v-theme-on-surface), 0.08);
}

.nvitop-state-badge {
  font-size: 0.68rem;
  font-weight: 700;
  padding: 2px 7px;
  border-radius: 5px;
  letter-spacing: 0.03em;
  text-transform: uppercase;
  flex-shrink: 0;
}

.badge-free {
  background: var(--nv-cool-soft);
  color: var(--nv-cool);
}

.badge-busy {
  background: var(--nv-warm-soft);
  color: var(--nv-warm);
}

.badge-held_idle,
.badge-unattributed {
  background: rgba(234, 88, 12, 0.16);
  color: var(--nv-held);
}

.badge-fault {
  background: rgba(147, 51, 234, 0.18);
  color: var(--nv-fault);
}

.badge-unknown {
  background: rgba(var(--v-theme-on-surface), 0.08);
  color: var(--nv-muted);
}

/* Signature nvitop Segmented Progress Bars */
.nvitop-bars {
  display: grid;
  grid-template-columns: minmax(185px, 1.55fr) minmax(115px, 1fr);
  gap: 10px;
  align-items: center;
}

.nvitop-bar-group {
  display: flex;
  align-items: center;
  gap: 6px;
  min-width: 0;
}

.nvitop-bar-lbl {
  font-size: 0.68rem;
  font-weight: 700;
  color: var(--nv-muted);
  letter-spacing: 0.04em;
  width: 28px;
  flex-shrink: 0;
}

.nvitop-bar-track {
  position: relative;
  flex: 1;
  height: 20px;
  border-radius: 5px;
  background: var(--nv-track);
  box-shadow: var(--nv-track-inset);
  overflow: hidden;
}

.nvitop-bar-fill {
  position: absolute;
  inset: 0 auto 0 0;
  border-radius: 4px;
  transition: width 260ms cubic-bezier(0.22, 1, 0.36, 1), background-color 220ms ease;
}

.nvitop-bar-ticks {
  position: absolute;
  inset: 0;
  pointer-events: none;
  background-image: repeating-linear-gradient(
    to right,
    transparent,
    transparent calc(10% - 1px),
    rgba(var(--v-theme-surface), 0.22) calc(10% - 1px),
    rgba(var(--v-theme-surface), 0.22) 10%
  );
}

.nvitop-bar-overlay {
  position: relative;
  z-index: 1;
  height: 100%;
  padding: 0 7px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
  font-size: 0.72rem;
  font-weight: 650;
  text-shadow: 0 0 6px rgba(var(--v-theme-surface), 0.85);
}

.nvitop-bar-overlay-end {
  justify-content: flex-end;
}

.tone-cool {
  background: linear-gradient(90deg, #16a34a 0%, #22c55e 100%);
}

.tone-warm {
  background: linear-gradient(90deg, #d97706 0%, #f59e0b 100%);
}

.tone-hot {
  background: linear-gradient(90deg, #dc2626 0%, #ef4444 100%);
}

.tone-fault {
  background: linear-gradient(90deg, #7e22ce 0%, #a855f7 100%);
}

.tone-idle {
  background: #64748b;
}

/* Thermal / Power Column */
.nvitop-card-env {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 10px;
  font-size: 0.76rem;
}

.nvitop-temp {
  min-width: 38px;
  text-align: right;
  font-weight: 600;
}

.temp-cool {
  color: var(--nv-cool);
}

.temp-warm {
  color: var(--nv-warm);
}

.temp-hot {
  color: var(--nv-hot);
  font-weight: 700;
}

.nvitop-power {
  min-width: 68px;
  text-align: right;
  color: var(--nv-muted);
}

.nvitop-fan {
  min-width: 32px;
  text-align: right;
  color: var(--nv-muted);
  font-size: 0.72rem;
}

/* Inline Process Sub-Rows */
.nvitop-procs {
  margin-top: 6px;
  padding-left: 10px;
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.nvitop-proc-row {
  display: grid;
  grid-template-columns: 12px 7px minmax(72px, 118px) 62px minmax(110px, 1fr) 64px 54px 36px;
  align-items: center;
  gap: 7px;
  font-size: 0.72rem;
  line-height: 1.35;
}

.nvitop-proc-row.is-graphics-idle {
  opacity: 0.52;
}

.nvitop-proc-branch {
  color: var(--nv-muted);
  opacity: 0.55;
}

.nvitop-proc-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
}

.nvitop-proc-user {
  font-weight: 650;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.nvitop-proc-pid {
  color: var(--nv-muted);
}

.nvitop-proc-name {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.nvitop-proc-ctr {
  margin-left: 5px;
  font-size: 0.66rem;
  padding: 0 5px;
  border-radius: 4px;
  background: rgba(var(--v-theme-on-surface), 0.07);
  color: var(--nv-muted);
}

.nvitop-proc-bar {
  height: 5px;
  border-radius: 3px;
  background: var(--nv-track);
  overflow: hidden;
}

.nvitop-proc-bar-fill {
  height: 100%;
  border-radius: 3px;
  opacity: 0.85;
}

.nvitop-proc-mem {
  text-align: right;
  font-weight: 600;
}

.nvitop-proc-age {
  text-align: right;
  color: var(--nv-muted);
}

.nvitop-more-procs {
  align-self: flex-start;
  margin-left: 20px;
  background: none;
  border: none;
  padding: 1px 4px;
  font-size: 0.7rem;
  color: var(--nv-muted);
  cursor: pointer;
}

.nvitop-more-procs:hover {
  text-decoration: underline;
}

.nvitop-procs-note {
  margin-top: 4px;
  padding-left: 14px;
  font-size: 0.72rem;
  color: var(--nv-muted);
}

@media (max-width: 960px) {
  .nvitop-kpi-ribbon {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
  .nvitop-card-main {
    grid-template-columns: 1fr;
    gap: 8px;
  }
  .nvitop-card-env {
    justify-content: flex-start;
  }
  .nvitop-proc-row {
    grid-template-columns: 12px 7px 90px 56px 1fr 52px;
  }
  .nvitop-proc-bar,
  .nvitop-proc-age {
    display: none;
  }
}

@media (max-width: 600px) {
  .nvitop-kpi-ribbon {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .nvitop-bars {
    grid-template-columns: 1fr;
  }
}
</style>
