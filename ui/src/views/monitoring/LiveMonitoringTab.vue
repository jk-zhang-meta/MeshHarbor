<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <div class="live-monitor">
    <!-- Section header mirroring GhostDesk live monitor -->
    <v-card variant="outlined" class="mb-4">
      <div class="live-monitor__header pa-3 px-4">
        <div class="d-flex align-center ga-3 flex-wrap">
          <span
            class="live-dot"
            :class="liveError ? 'live-dot--error' : 'live-dot--ok'"
            aria-hidden="true"
          />
          <span class="text-subtitle-1 font-weight-bold">
            {{ t('mh.monitoring.live.heading') }}
          </span>
          <v-chip size="small" color="success" variant="tonal" class="font-weight-bold">
            {{ counts.total }}
          </v-chip>
          <v-chip
            v-if="capabilities?.can_see_remote"
            size="x-small"
            variant="outlined"
            color="teal"
            prepend-icon="mdi-remote-desktop"
          >
            {{ t('mh.monitoring.kind.remote') }} {{ counts.remote }}
          </v-chip>
          <v-chip
            v-if="capabilities?.can_see_ssh"
            size="x-small"
            variant="outlined"
            color="primary"
            prepend-icon="mdi-console"
          >
            SSH {{ counts.ssh }}
          </v-chip>
          <span v-if="lastSyncedAt" class="text-caption text-medium-emphasis">
            {{ t('mh.monitoring.live.lastSync', { time: lastSyncedAt }) }}
          </span>
        </div>

        <div class="d-flex align-center ga-3 flex-wrap">
          <v-switch
            v-model="autoRefresh"
            :label="t('mh.monitoring.live.autoRefresh')"
            density="compact"
            color="primary"
            hide-details
          />
          <v-btn
            size="small"
            variant="tonal"
            prepend-icon="mdi-refresh"
            :loading="loading"
            @click="loadLive(true)"
          >
            {{ t('common.refresh') }}
          </v-btn>
        </div>
      </div>

      <v-divider />

      <!-- Filter toolbar -->
      <div class="d-flex align-center justify-space-between ga-3 flex-wrap pa-3 px-4">
        <v-chip-group v-model="kindFilter" mandatory color="primary" density="compact">
          <v-chip value="all" size="small" variant="tonal">
            {{ t('mh.monitoring.filter.all') }}
          </v-chip>
          <v-chip
            v-if="capabilities?.can_see_remote ?? true"
            value="remote"
            size="small"
            variant="tonal"
            prepend-icon="mdi-remote-desktop"
          >
            {{ t('mh.monitoring.kind.remote') }}
          </v-chip>
          <v-chip
            v-if="capabilities?.can_see_ssh ?? true"
            value="ssh"
            size="small"
            variant="tonal"
            prepend-icon="mdi-console"
          >
            SSH
          </v-chip>
        </v-chip-group>

        <v-text-field
          v-model="searchQuery"
          :placeholder="t('mh.monitoring.live.searchPlaceholder')"
          prepend-inner-icon="mdi-magnify"
          density="compact"
          variant="outlined"
          hide-details
          clearable
          style="max-width: 340px; min-width: 220px"
          @keyup.enter="loadLive(true)"
          @click:clear="loadLive(true)"
        />
      </div>
    </v-card>

    <v-alert
      v-if="liveError"
      type="error"
      variant="tonal"
      density="compact"
      class="mb-4"
    >
      {{ liveError }}
    </v-alert>

    <!-- Live connections table -->
    <v-card variant="outlined">
      <v-progress-linear v-if="loading && !items.length" indeterminate color="primary" />

      <v-table v-if="items.length" density="comfortable" class="live-table">
        <thead>
          <tr>
            <th style="width: 120px">{{ t('mh.monitoring.col.type') }}</th>
            <th>{{ t('mh.monitoring.col.initiator') }}</th>
            <th>{{ t('mh.monitoring.col.target') }}</th>
            <th style="width: 210px">{{ t('mh.monitoring.col.statusTelemetry') }}</th>
            <th style="width: 170px">{{ t('mh.monitoring.col.timeDuration') }}</th>
            <th class="text-right" style="width: 195px">{{ t('mh.monitoring.col.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in items" :key="`${row.kind}-${row.id}`">
            <td>
              <div class="d-flex flex-column ga-1 py-1">
                <v-chip
                  size="small"
                  variant="tonal"
                  :color="row.kind === 'remote' ? 'teal' : 'primary'"
                  :prepend-icon="row.kind === 'remote' ? 'mdi-remote-desktop' : 'mdi-console'"
                >
                  {{ row.kind === 'remote' ? t('mh.monitoring.kind.remote') : 'SSH' }}
                </v-chip>
                <span class="text-caption text-medium-emphasis">
                  {{ sourceLabel(row) }}
                </span>
              </div>
            </td>

            <td>
              <PartyAttributionCell :party="row.initiator" />
            </td>

            <td>
              <PartyAttributionCell :party="row.target" />
            </td>

            <td>
              <div class="d-flex flex-column ga-1 py-1">
                <div class="d-flex align-center ga-1 flex-wrap">
                  <v-chip
                    size="x-small"
                    variant="flat"
                    :color="phaseColor(row.phase)"
                  >
                    {{ phaseLabel(row.phase) }}
                  </v-chip>
                  <v-chip
                    v-if="row.admin_taken_over"
                    size="x-small"
                    color="warning"
                    variant="flat"
                    prepend-icon="mdi-shield-account"
                  >
                    {{ t('mh.monitoring.live.adminTakenOver') }}
                  </v-chip>
                  <v-chip
                    v-else-if="row.admin_watching"
                    size="x-small"
                    color="info"
                    variant="tonal"
                    prepend-icon="mdi-eye-outline"
                  >
                    {{ t('mh.monitoring.live.adminWatching', { count: row.admin_watcher_count || 1 }) }}
                  </v-chip>
                </div>

                <div v-if="row.kind === 'remote' && row.stats" class="text-caption text-medium-emphasis mono">
                  <span v-if="row.stats.peak_fps > 0">{{ Math.round(row.stats.peak_fps) }} fps</span>
                  <span v-if="row.stats.avg_rtt_ms > 0" class="ml-2">{{ Math.round(row.stats.avg_rtt_ms) }} ms</span>
                  <span class="ml-2">
                    ↑{{ formatMonitoringBytes(row.stats.bytes_sent) }}
                    ↓{{ formatMonitoringBytes(row.stats.bytes_recv) }}
                  </span>
                </div>

                <div v-if="row.kind === 'ssh'" class="text-caption text-medium-emphasis">
                  <span v-if="row.account_mode">{{ row.account_mode }}</span>
                  <span v-if="row.ran_as" class="ml-1">({{ row.ran_as }})</span>
                  <span v-if="row.resume_allowed" class="ml-1 text-primary">· PTY</span>
                  <span v-if="row.activity_count" class="ml-1">
                    · {{ t('mh.monitoring.activityCount', { count: row.activity_count }) }}
                  </span>
                </div>
              </div>
            </td>

            <td>
              <div class="d-flex flex-column py-1">
                <span class="text-body-2 font-weight-medium mono">
                  {{ formatMonitoringDuration(liveDurationSecs(row)) }}
                </span>
                <span class="text-caption text-medium-emphasis">
                  {{ formatTime(row.started_at) }}
                </span>
              </div>
            </td>

            <td class="text-right">
              <div class="d-flex justify-end align-center ga-1 flex-wrap">
                <v-btn
                  v-if="row.kind === 'remote' && row.can_watch_takeover"
                  size="small"
                  color="primary"
                  variant="tonal"
                  prepend-icon="mdi-monitor-eye"
                  :data-testid="`watch-rc-${row.id}`"
                  @click="openWatch(row)"
                >
                  {{ t('mh.monitoring.live.watchTakeover') }}
                </v-btn>

                <v-btn
                  v-if="row.can_disconnect"
                  size="small"
                  color="error"
                  variant="text"
                  prepend-icon="mdi-lan-disconnect"
                  :data-testid="`disconnect-${row.kind}-${row.id}`"
                  @click="askDisconnect(row)"
                >
                  {{ t('mh.monitoring.disconnectAction') }}
                </v-btn>
              </div>
            </td>
          </tr>
        </tbody>
      </v-table>

      <div v-else-if="!loading" class="text-center pa-10 text-medium-emphasis">
        <v-icon size="48" class="mb-2 opacity-50">mdi-radar</v-icon>
        <div class="text-body-1 font-weight-medium">
          {{ liveError ? t('mh.monitoring.live.unavailable') : t('mh.monitoring.live.emptyTitle') }}
        </div>
        <div class="text-caption mt-1">
          {{ t('mh.monitoring.live.emptyHint') }}
        </div>
      </div>
    </v-card>

    <!-- Active disconnect confirmation dialog -->
    <v-dialog v-model="disconnectDialog" max-width="440">
      <v-card v-if="pendingDisconnect">
        <v-card-title class="d-flex align-center ga-2">
          <v-icon color="error">mdi-lan-disconnect</v-icon>
          <span>{{ t('mh.monitoring.disconnectConfirmTitle') }}</span>
        </v-card-title>
        <v-card-text>
          <p class="text-body-2 mb-3">
            {{
              pendingDisconnect.kind === 'remote'
                ? t('mh.monitoring.live.disconnectRemoteConfirm')
                : t('mh.monitoring.live.disconnectSshConfirm')
            }}
          </p>
          <v-sheet border rounded class="pa-3 text-caption">
            <div>
              <strong>{{ t('mh.monitoring.col.initiator') }}:</strong>
              {{ pendingDisconnect.initiator.account_name || pendingDisconnect.initiator.device_name || '—' }}
            </div>
            <div class="mt-1">
              <strong>{{ t('mh.monitoring.col.target') }}:</strong>
              {{ pendingDisconnect.target.device_name || pendingDisconnect.agent_id }}
              <span v-if="pendingDisconnect.target.account_name">
                ({{ pendingDisconnect.target.account_name }})
              </span>
            </div>
          </v-sheet>
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="disconnectDialog = false">{{ t('common.cancel') }}</v-btn>
          <v-btn
            color="error"
            variant="flat"
            :loading="disconnecting"
            data-testid="confirm-disconnect-btn"
            @click="confirmDisconnectNow"
          >
            {{ t('mh.monitoring.disconnectAction') }}
          </v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import {
  disconnectLiveSession,
  fetchLiveMonitoring,
  formatMonitoringBytes,
  formatMonitoringDuration,
  type LiveMonitoringItem,
  type MonitoringCapabilities,
} from '@/api/monitoring'
import { useSnackbar } from '@/composables/useSnackbar'
import PartyAttributionCell from './PartyAttributionCell.vue'

const props = defineProps<{
  tenantId: string
}>()

const { t } = useI18n()
const router = useRouter()
const { showSuccess, showError } = useSnackbar()

const items = ref<LiveMonitoringItem[]>([])
const counts = ref({ total: 0, remote: 0, ssh: 0 })
const capabilities = ref<MonitoringCapabilities | null>(null)
const loading = ref(false)
const liveError = ref('')
const lastSyncedAt = ref('')
const autoRefresh = ref(true)
const kindFilter = ref<'all' | 'remote' | 'ssh'>('all')
const searchQuery = ref('')

// Anchored clock for smooth 1-second live duration ticking without drift.
const serverClockOffsetMs = ref(0)
const nowTickMs = ref(Date.now())

const disconnectDialog = ref(false)
const pendingDisconnect = ref<LiveMonitoringItem | null>(null)
const disconnecting = ref(false)

let pollTimer: ReturnType<typeof setInterval> | null = null
let tickTimer: ReturnType<typeof setInterval> | null = null
let inFlight = false

const effectiveTenantId = computed(() => props.tenantId)

function liveDurationSecs(row: LiveMonitoringItem): number {
  const estNow = nowTickMs.value + serverClockOffsetMs.value
  return Math.max(0, Math.floor((estNow - row.started_at_ms) / 1000))
}

function formatTime(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString()
}

function phaseColor(phase: string): string {
  switch (phase) {
    case 'active':
      return 'success'
    case 'negotiating':
    case 'granted':
      return 'info'
    case 'pending':
      return 'warning'
    default:
      return 'default'
  }
}

function phaseLabel(phase: string): string {
  const key = `mh.monitoring.phase.${phase}`
  const translated = t(key)
  return translated === key ? phase : translated
}

function sourceLabel(row: LiveMonitoringItem): string {
  const key = `mh.monitoring.source.${row.source}`
  const translated = t(key)
  return translated === key ? row.source : translated
}

async function loadLive(showSpinner = false) {
  if (!effectiveTenantId.value || inFlight) return
  inFlight = true
  if (showSpinner) loading.value = true
  try {
    const res = await fetchLiveMonitoring(effectiveTenantId.value, {
      kind: kindFilter.value,
      q: searchQuery.value,
    })
    items.value = res.items
    counts.value = res.counts
    capabilities.value = res.capabilities
    serverClockOffsetMs.value = res.server_time_ms - Date.now()
    liveError.value = ''
    lastSyncedAt.value = new Date().toLocaleTimeString()
  } catch (e) {
    items.value = []
    counts.value = { total: 0, remote: 0, ssh: 0 }
    liveError.value = e instanceof Error ? e.message : t('mh.monitoring.live.unavailable')
  } finally {
    loading.value = false
    inFlight = false
  }
}

function openWatch(row: LiveMonitoringItem) {
  const target = router.resolve({
    name: 'monitoring-watch',
    params: { tenantId: effectiveTenantId.value, agentId: row.agent_id },
    query: {
      sessionId: row.id,
      deviceName: row.target.device_name || '',
      controller: row.initiator.account_name || row.initiator.device_name || '',
    },
  })
  const popup = window.open(target.href, '_blank', 'noopener')
  if (!popup) {
    void router.push(target.fullPath)
  }
}

function askDisconnect(row: LiveMonitoringItem) {
  pendingDisconnect.value = row
  disconnectDialog.value = true
}

async function confirmDisconnectNow() {
  const row = pendingDisconnect.value
  if (!row || !effectiveTenantId.value) return
  disconnecting.value = true
  try {
    await disconnectLiveSession(effectiveTenantId.value, {
      kind: row.kind,
      id: row.id,
      agent_id: row.agent_id,
      shared_session_id: row.shared_session_id,
      reason: 'admin_disconnect',
    })
    disconnectDialog.value = false
    pendingDisconnect.value = null
    showSuccess(t('mh.monitoring.disconnectSuccess'))
    await loadLive(false)
  } catch (e) {
    showError(e instanceof Error ? e.message : t('mh.monitoring.disconnectFailed'))
  } finally {
    disconnecting.value = false
  }
}

function startPolling() {
  stopPolling()
  pollTimer = setInterval(() => {
    if (autoRefresh.value && document.visibilityState === 'visible') {
      void loadLive(false)
    }
  }, 2000)
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
}

function onVisibilityChange() {
  if (document.visibilityState === 'visible' && autoRefresh.value) {
    void loadLive(false)
  }
}

watch([() => props.tenantId, kindFilter], () => {
  void loadLive(true)
})

onMounted(() => {
  void loadLive(true)
  startPolling()
  tickTimer = setInterval(() => {
    nowTickMs.value = Date.now()
  }, 1000)
  document.addEventListener('visibilitychange', onVisibilityChange)
})

onBeforeUnmount(() => {
  stopPolling()
  if (tickTimer) clearInterval(tickTimer)
  document.removeEventListener('visibilitychange', onVisibilityChange)
})
</script>

<style scoped>
.live-monitor__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

.live-dot {
  display: inline-block;
  width: 10px;
  height: 10px;
  border-radius: 50%;
}

.live-dot--ok {
  background: #22c55e;
  box-shadow: 0 0 0 4px rgba(34, 197, 94, 0.2);
}

.live-dot--error {
  background: #ef4444;
  box-shadow: 0 0 0 4px rgba(239, 68, 68, 0.2);
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}

.live-table :deep(td) {
  vertical-align: top;
}
</style>
