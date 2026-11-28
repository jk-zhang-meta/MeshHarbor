<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <div class="history-monitor">
    <!-- Header & Summary -->
    <v-card variant="outlined" class="mb-4">
      <div class="d-flex align-center justify-space-between ga-3 flex-wrap pa-3 px-4">
        <div class="d-flex align-center ga-3 flex-wrap">
          <span class="history-dot" aria-hidden="true" />
          <span class="text-subtitle-1 font-weight-bold">
            {{ t('mh.monitoring.history.heading') }}
          </span>
          <v-chip size="small" color="primary" variant="tonal" class="font-weight-bold">
            {{ total }}
          </v-chip>
          <span class="text-caption text-medium-emphasis">
            {{
              t('mh.monitoring.history.summaryLine', {
                devices: groupedDevices.length,
                remote: summary.total_remote,
                ssh: summary.total_ssh,
                denied: summary.denied_ssh,
              })
            }}
          </span>
        </div>

        <div class="d-flex align-center ga-2 flex-wrap">
          <v-btn-toggle v-model="viewMode" density="compact" variant="outlined" color="primary" mandatory>
            <v-btn value="grouped" size="small" prepend-icon="mdi-group">
              {{ t('mh.monitoring.history.viewGrouped') }}
            </v-btn>
            <v-btn value="flat" size="small" prepend-icon="mdi-format-list-bulleted">
              {{ t('mh.monitoring.history.viewFlat') }}
            </v-btn>
          </v-btn-toggle>
          <v-btn
            size="small"
            variant="tonal"
            prepend-icon="mdi-refresh"
            :loading="loading"
            @click="loadHistory(true)"
          >
            {{ t('common.refresh') }}
          </v-btn>
        </div>
      </div>

      <v-divider />

      <!-- GhostDesk-style rich filter toolbar -->
      <div class="history-filters pa-3 px-4">
        <v-text-field
          v-model="searchQuery"
          :placeholder="t('mh.monitoring.history.searchPlaceholder')"
          prepend-inner-icon="mdi-magnify"
          density="compact"
          variant="outlined"
          hide-details
          clearable
          class="hf-search"
          @keyup.enter="applyFilters"
          @click:clear="applyFilters"
        />

        <v-select
          v-model="kindFilter"
          :items="kindOptions"
          :label="t('mh.monitoring.col.type')"
          density="compact"
          variant="outlined"
          hide-details
          class="hf-select"
          @update:model-value="applyFilters"
        />

        <v-select
          v-model="statusFilter"
          :items="statusOptions"
          :label="t('mh.monitoring.history.statusLabel')"
          density="compact"
          variant="outlined"
          hide-details
          class="hf-select"
          @update:model-value="applyFilters"
        />

        <div class="hf-range">
          <v-text-field
            v-model="dateFrom"
            type="date"
            :label="t('mh.monitoring.history.dateFrom')"
            density="compact"
            variant="outlined"
            hide-details
            class="hf-date"
            @change="applyFilters"
          />
          <span class="text-caption text-medium-emphasis">—</span>
          <v-text-field
            v-model="dateTo"
            type="date"
            :label="t('mh.monitoring.history.dateTo')"
            density="compact"
            variant="outlined"
            hide-details
            class="hf-date"
            @change="applyFilters"
          />
        </div>

        <div class="hf-range">
          <v-text-field
            v-model="minDuration"
            type="number"
            min="0"
            :label="t('mh.monitoring.history.minDuration')"
            density="compact"
            variant="outlined"
            hide-details
            class="hf-dur"
            @change="applyFilters"
          />
          <span class="text-caption text-medium-emphasis">—</span>
          <v-text-field
            v-model="maxDuration"
            type="number"
            min="0"
            :label="t('mh.monitoring.history.maxDuration')"
            density="compact"
            variant="outlined"
            hide-details
            class="hf-dur"
            @change="applyFilters"
          />
          <v-select
            v-model="durationUnit"
            :items="durationUnitOptions"
            density="compact"
            variant="outlined"
            hide-details
            class="hf-unit"
            @update:model-value="applyFilters"
          />
        </div>

        <div class="d-flex align-center ga-1 flex-wrap">
          <v-btn size="x-small" variant="tonal" @click="applyDateShortcut(7)">
            {{ t('mh.monitoring.history.last7d') }}
          </v-btn>
          <v-btn size="x-small" variant="tonal" @click="applyDateShortcut(14)">
            {{ t('mh.monitoring.history.last14d') }}
          </v-btn>
          <v-btn size="x-small" variant="tonal" @click="applyDateShortcut(30)">
            {{ t('mh.monitoring.history.last30d') }}
          </v-btn>
          <v-btn size="x-small" variant="text" @click="resetFilters">
            {{ t('mh.monitoring.history.resetFilters') }}
          </v-btn>
        </div>
      </div>
    </v-card>

    <v-alert
      v-if="historyError"
      type="error"
      variant="tonal"
      density="compact"
      class="mb-4"
    >
      {{ historyError }}
    </v-alert>

    <!-- Grouped by target device (GhostDesk default view) -->
    <v-card v-if="viewMode === 'grouped'" variant="outlined">
      <v-progress-linear v-if="loading && !items.length" indeterminate color="primary" />

      <div v-if="groupedDevices.length" class="grouped-list">
        <v-expansion-panels v-model="expandedGroups" multiple variant="accordion">
          <v-expansion-panel
            v-for="group in groupedDevices"
            :key="group.agentId"
            :value="group.agentId"
          >
            <v-expansion-panel-title>
              <div class="group-header">
                <PartyAttributionCell :party="group.target" />
                <div class="group-header__stats">
                  <v-chip size="x-small" color="primary" variant="tonal">
                    {{ t('mh.monitoring.history.sessionCount', { count: group.rows.length }) }}
                  </v-chip>
                  <v-chip v-if="group.remoteCount > 0" size="x-small" color="teal" variant="outlined">
                    {{ t('mh.monitoring.kind.remote') }} {{ group.remoteCount }}
                  </v-chip>
                  <v-chip v-if="group.sshCount > 0" size="x-small" color="primary" variant="outlined">
                    SSH {{ group.sshCount }}
                  </v-chip>
                  <span class="text-caption text-medium-emphasis mono">
                    {{ t('mh.monitoring.history.totalDuration', { dur: formatMonitoringDuration(group.totalDurationSecs) }) }}
                  </span>
                  <span class="text-caption text-medium-emphasis">
                    {{ formatTime(group.latestAt) }}
                  </span>
                </div>
              </div>
            </v-expansion-panel-title>

            <v-expansion-panel-text class="pa-0">
              <v-table density="compact" class="history-table">
                <thead>
                  <tr>
                    <th style="width: 110px">{{ t('mh.monitoring.col.type') }}</th>
                    <th>{{ t('mh.monitoring.col.initiator') }}</th>
                    <th style="width: 190px">{{ t('mh.monitoring.history.statusOutcome') }}</th>
                    <th style="width: 170px">{{ t('mh.monitoring.col.timeDuration') }}</th>
                    <th style="width: 190px">{{ t('mh.monitoring.history.details') }}</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="row in group.rows" :key="`${row.kind}-${row.id}`">
                    <td>
                      <v-chip
                        size="x-small"
                        variant="tonal"
                        :color="row.kind === 'remote' ? 'teal' : 'primary'"
                        :prepend-icon="row.kind === 'remote' ? 'mdi-remote-desktop' : 'mdi-console'"
                      >
                        {{ row.kind === 'remote' ? t('mh.monitoring.kind.remote') : 'SSH' }}
                      </v-chip>
                    </td>
                    <td>
                      <PartyAttributionCell :party="row.initiator" />
                    </td>
                    <td>
                      <div class="d-flex flex-column ga-1 py-1">
                        <v-chip size="x-small" variant="flat" :color="statusColor(row.status)" style="width: fit-content">
                          {{ statusLabel(row.status) }}
                        </v-chip>
                        <span v-if="row.end_reason" class="text-caption text-medium-emphasis">
                          {{ row.end_reason }}
                        </span>
                        <span v-if="row.denied_reason" class="text-caption text-error">
                          {{ row.denied_reason }}
                        </span>
                      </div>
                    </td>
                    <td>
                      <div class="d-flex flex-column py-1">
                        <span class="text-body-2 font-weight-medium mono">
                          {{ formatMonitoringDuration(row.duration_secs) }}
                        </span>
                        <span class="text-caption text-medium-emphasis">
                          {{ formatTime(row.started_at) }}
                        </span>
                      </div>
                    </td>
                    <td>
                      <div class="d-flex flex-column ga-1 py-1 text-caption">
                        <span v-if="row.kind === 'remote' && row.carrier" class="text-medium-emphasis">
                          {{ row.carrier }}
                        </span>
                        <span v-if="row.kind === 'remote' && row.stats" class="text-medium-emphasis mono">
                          ↑{{ formatMonitoringBytes(row.stats.bytes_sent) }}
                          ↓{{ formatMonitoringBytes(row.stats.bytes_recv) }}
                        </span>
                        <span v-if="row.kind === 'ssh' && row.account_mode" class="text-medium-emphasis">
                          {{ row.account_mode }}
                          <template v-if="row.ran_as">({{ row.ran_as }})</template>
                        </span>
                        <v-btn
                          v-if="row.kind === 'ssh' && row.grant_id"
                          size="x-small"
                          variant="text"
                          color="primary"
                          prepend-icon="mdi-timeline-text-outline"
                          class="px-1 align-self-start"
                          @click="openSshTimeline(row)"
                        >
                          {{
                            row.activity_count
                              ? t('mh.monitoring.history.viewSshActivitiesCount', { count: row.activity_count })
                              : t('mh.monitoring.history.viewSshActivities')
                          }}
                        </v-btn>
                      </div>
                    </td>
                  </tr>
                </tbody>
              </v-table>
            </v-expansion-panel-text>
          </v-expansion-panel>
        </v-expansion-panels>
      </div>

      <div v-else-if="!loading" class="text-center pa-10 text-medium-emphasis">
        <v-icon size="48" class="mb-2 opacity-50">mdi-history</v-icon>
        <div class="text-body-1 font-weight-medium">{{ t('mh.monitoring.history.emptyTitle') }}</div>
      </div>
    </v-card>

    <!-- Flat chronological table view -->
    <v-card v-else variant="outlined">
      <v-progress-linear v-if="loading && !items.length" indeterminate color="primary" />

      <v-table v-if="items.length" density="comfortable" class="history-table">
        <thead>
          <tr>
            <th style="width: 110px">{{ t('mh.monitoring.col.type') }}</th>
            <th>{{ t('mh.monitoring.col.initiator') }}</th>
            <th>{{ t('mh.monitoring.col.target') }}</th>
            <th style="width: 185px">{{ t('mh.monitoring.history.statusOutcome') }}</th>
            <th style="width: 170px">{{ t('mh.monitoring.col.timeDuration') }}</th>
            <th style="width: 185px">{{ t('mh.monitoring.history.details') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in items" :key="`${row.kind}-${row.id}`">
            <td>
              <v-chip
                size="x-small"
                variant="tonal"
                :color="row.kind === 'remote' ? 'teal' : 'primary'"
                :prepend-icon="row.kind === 'remote' ? 'mdi-remote-desktop' : 'mdi-console'"
              >
                {{ row.kind === 'remote' ? t('mh.monitoring.kind.remote') : 'SSH' }}
              </v-chip>
            </td>
            <td><PartyAttributionCell :party="row.initiator" /></td>
            <td><PartyAttributionCell :party="row.target" /></td>
            <td>
              <div class="d-flex flex-column ga-1 py-1">
                <v-chip size="x-small" variant="flat" :color="statusColor(row.status)" style="width: fit-content">
                  {{ statusLabel(row.status) }}
                </v-chip>
                <span v-if="row.end_reason" class="text-caption text-medium-emphasis">{{ row.end_reason }}</span>
                <span v-if="row.denied_reason" class="text-caption text-error">{{ row.denied_reason }}</span>
              </div>
            </td>
            <td>
              <div class="d-flex flex-column py-1">
                <span class="text-body-2 font-weight-medium mono">
                  {{ formatMonitoringDuration(row.duration_secs) }}
                </span>
                <span class="text-caption text-medium-emphasis">{{ formatTime(row.started_at) }}</span>
              </div>
            </td>
            <td>
              <div class="d-flex flex-column ga-1 py-1 text-caption">
                <span v-if="row.kind === 'remote' && row.carrier" class="text-medium-emphasis">{{ row.carrier }}</span>
                <span v-if="row.kind === 'remote' && row.stats" class="text-medium-emphasis mono">
                  ↑{{ formatMonitoringBytes(row.stats.bytes_sent) }}
                  ↓{{ formatMonitoringBytes(row.stats.bytes_recv) }}
                </span>
                <span v-if="row.kind === 'ssh' && row.account_mode" class="text-medium-emphasis">
                  {{ row.account_mode }}
                </span>
                <v-btn
                  v-if="row.kind === 'ssh' && row.grant_id"
                  size="x-small"
                  variant="text"
                  color="primary"
                  prepend-icon="mdi-timeline-text-outline"
                  class="px-1 align-self-start"
                  @click="openSshTimeline(row)"
                >
                  {{
                    row.activity_count
                      ? t('mh.monitoring.history.viewSshActivitiesCount', { count: row.activity_count })
                      : t('mh.monitoring.history.viewSshActivities')
                  }}
                </v-btn>
              </div>
            </td>
          </tr>
        </tbody>
      </v-table>

      <div v-else-if="!loading" class="text-center pa-10 text-medium-emphasis">
        <v-icon size="48" class="mb-2 opacity-50">mdi-history</v-icon>
        <div class="text-body-1 font-weight-medium">{{ t('mh.monitoring.history.emptyTitle') }}</div>
      </div>
    </v-card>

    <div v-if="totalPages > 1" class="d-flex justify-center mt-4">
      <v-pagination
        v-model="page"
        :length="totalPages"
        :total-visible="7"
        density="compact"
        @update:model-value="loadHistory(true)"
      />
    </div>

    <!-- Per-grant SSH Activity Timeline Dialog -->
    <v-dialog v-model="timelineDialog" max-width="680">
      <v-card>
        <v-card-title class="d-flex align-center justify-space-between">
          <span>{{ t('mh.monitoring.history.sshTimelineTitle') }}</span>
          <v-btn icon="mdi-close" size="small" variant="text" @click="timelineDialog = false" />
        </v-card-title>
        <v-divider />
        <v-card-text>
          <v-progress-linear v-if="timelineLoading" indeterminate color="primary" class="mb-3" />
          <v-alert v-if="timelineError" type="error" variant="tonal" density="compact" class="mb-3">
            {{ timelineError }}
          </v-alert>
          <v-table v-if="timelineItems.length" density="compact">
            <thead>
              <tr>
                <th style="width: 155px">{{ t('mh.monitoring.history.timelineAt') }}</th>
                <th style="width: 120px">{{ t('mh.monitoring.history.timelineKind') }}</th>
                <th>{{ t('mh.monitoring.history.timelineDetail') }}</th>
                <th style="width: 75px">{{ t('mh.monitoring.history.timelineResult') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="ev in timelineItems" :key="ev.id || `${ev.at}-${ev.kind}`">
                <td class="text-caption mono">{{ formatTime(ev.at) }}</td>
                <td>
                  <v-chip size="x-small" variant="tonal">{{ ev.kind }}</v-chip>
                </td>
                <td class="text-caption mono" style="word-break: break-all">
                  {{ ev.detail || '—' }}
                  <span v-if="ev.exit_code !== undefined" class="text-medium-emphasis ml-1">
                    (exit {{ ev.exit_code }})
                  </span>
                </td>
                <td>
                  <v-chip size="x-small" :color="ev.allowed ? 'success' : 'error'" variant="flat">
                    {{ ev.allowed ? 'OK' : 'DENY' }}
                  </v-chip>
                </td>
              </tr>
            </tbody>
          </v-table>
          <div v-else-if="!timelineLoading" class="text-center pa-6 text-medium-emphasis text-body-2">
            {{ t('mh.monitoring.history.sshTimelineEmpty') }}
          </div>
        </v-card-text>
      </v-card>
    </v-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import {
  fetchMonitoringHistory,
  fetchSshGrantActivities,
  formatMonitoringBytes,
  formatMonitoringDuration,
  type HistoryMonitoringItem,
  type PartyAttribution,
  type SshGrantActivityItem,
} from '@/api/monitoring'
import PartyAttributionCell from './PartyAttributionCell.vue'

const props = defineProps<{
  tenantId: string
}>()

const { t } = useI18n()

const items = ref<HistoryMonitoringItem[]>([])
const total = ref(0)
const totalPages = ref(1)
const page = ref(1)
const summary = ref({ total_remote: 0, total_ssh: 0, denied_ssh: 0 })
const loading = ref(false)
const historyError = ref('')

const viewMode = ref<'grouped' | 'flat'>('grouped')
const expandedGroups = ref<string[]>([])

const searchQuery = ref('')
const kindFilter = ref<'all' | 'remote' | 'ssh'>('all')
const statusFilter = ref<'all' | 'completed' | 'live' | 'denied'>('all')
const dateFrom = ref('')
const dateTo = ref('')
const minDuration = ref('')
const maxDuration = ref('')
const durationUnit = ref<'second' | 'minute' | 'hour'>('minute')

const timelineDialog = ref(false)
const timelineLoading = ref(false)
const timelineError = ref('')
const timelineItems = ref<SshGrantActivityItem[]>([])
let historySeq = 0

const kindOptions = computed(() => [
  { title: t('mh.monitoring.filter.all'), value: 'all' },
  { title: t('mh.monitoring.kind.remote'), value: 'remote' },
  { title: 'SSH', value: 'ssh' },
])

const statusOptions = computed(() => [
  { title: t('mh.monitoring.history.statusAll'), value: 'all' },
  { title: t('mh.monitoring.history.statusCompleted'), value: 'completed' },
  { title: t('mh.monitoring.history.statusLive'), value: 'live' },
  { title: t('mh.monitoring.history.statusDenied'), value: 'denied' },
])

const durationUnitOptions = computed(() => [
  { title: t('mh.monitoring.history.unitSec'), value: 'second' },
  { title: t('mh.monitoring.history.unitMin'), value: 'minute' },
  { title: t('mh.monitoring.history.unitHour'), value: 'hour' },
])

interface GroupedDeviceHistory {
  agentId: string
  target: PartyAttribution
  rows: HistoryMonitoringItem[]
  remoteCount: number
  sshCount: number
  totalDurationSecs: number
  latestAt: string
}

const groupedDevices = computed<GroupedDeviceHistory[]>(() => {
  const map = new Map<string, GroupedDeviceHistory>()
  for (const row of items.value) {
    let group = map.get(row.agent_id)
    if (!group) {
      group = {
        agentId: row.agent_id,
        target: row.target,
        rows: [],
        remoteCount: 0,
        sshCount: 0,
        totalDurationSecs: 0,
        latestAt: row.started_at,
      }
      map.set(row.agent_id, group)
    }
    group.rows.push(row)
    if (row.kind === 'remote') group.remoteCount++
    else group.sshCount++
    if (row.duration_secs && Number.isFinite(row.duration_secs)) {
      group.totalDurationSecs += row.duration_secs
    }
  }
  return Array.from(map.values())
})

function unitMultiplier(): number {
  if (durationUnit.value === 'hour') return 3600
  if (durationUnit.value === 'minute') return 60
  return 1
}

function toDurationSecs(raw: string): number | undefined {
  if (raw === '' || raw === null || raw === undefined) return undefined
  const n = Number(raw)
  if (!Number.isFinite(n) || n < 0) return undefined
  return Math.floor(n * unitMultiplier())
}

function formatTime(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString()
}

function statusColor(status: string): string {
  if (status === 'live') return 'success'
  if (status === 'denied') return 'error'
  return 'default'
}

function statusLabel(status: string): string {
  if (status === 'live') return t('mh.monitoring.history.statusLive')
  if (status === 'denied') return t('mh.monitoring.history.statusDenied')
  return t('mh.monitoring.history.statusCompleted')
}

function applyDateShortcut(days: number) {
  const end = new Date()
  const start = new Date(end.getTime() - days * 86400 * 1000)
  dateFrom.value = start.toISOString().slice(0, 10)
  dateTo.value = end.toISOString().slice(0, 10)
  applyFilters()
}

function resetFilters() {
  searchQuery.value = ''
  kindFilter.value = 'all'
  statusFilter.value = 'all'
  dateFrom.value = ''
  dateTo.value = ''
  minDuration.value = ''
  maxDuration.value = ''
  applyFilters()
}

function applyFilters() {
  page.value = 1
  void loadHistory(true)
}

async function loadHistory(showSpinner = false) {
  if (!props.tenantId) return
  const seq = ++historySeq
  if (showSpinner) loading.value = true
  try {
    const res = await fetchMonitoringHistory(props.tenantId, {
      kind: kindFilter.value,
      status: statusFilter.value,
      q: searchQuery.value,
      date_from: dateFrom.value || undefined,
      date_to: dateTo.value || undefined,
      min_duration_secs: toDurationSecs(minDuration.value),
      max_duration_secs: toDurationSecs(maxDuration.value),
      page: page.value,
      per_page: 50,
    })
    if (seq !== historySeq) return
    items.value = res.items
    total.value = res.total
    totalPages.value = res.total_pages
    summary.value = res.summary
    historyError.value = ''
    // Auto-expand the first group so operators see detail immediately.
    if (groupedDevices.value.length > 0 && expandedGroups.value.length === 0) {
      expandedGroups.value = [groupedDevices.value[0].agentId]
    }
  } catch (e) {
    if (seq !== historySeq) return
    items.value = []
    total.value = 0
    totalPages.value = 1
    summary.value = { total_remote: 0, total_ssh: 0, denied_ssh: 0 }
    historyError.value = e instanceof Error ? e.message : t('mh.monitoring.history.loadFailed')
  } finally {
    if (seq === historySeq) loading.value = false
  }
}

async function openSshTimeline(row: HistoryMonitoringItem) {
  if (!row.grant_id || !props.tenantId) return
  timelineDialog.value = true
  timelineLoading.value = true
  timelineError.value = ''
  timelineItems.value = []
  try {
    const res = await fetchSshGrantActivities(props.tenantId, row.grant_id)
    timelineItems.value = res.items
  } catch (e) {
    timelineError.value = e instanceof Error ? e.message : t('mh.monitoring.history.loadFailed')
  } finally {
    timelineLoading.value = false
  }
}

watch(
  () => props.tenantId,
  () => {
    items.value = []
    total.value = 0
    totalPages.value = 1
    summary.value = { total_remote: 0, total_ssh: 0, denied_ssh: 0 }
    page.value = 1
    expandedGroups.value = []
    timelineDialog.value = false
    void loadHistory(true)
  },
)

onMounted(() => {
  void loadHistory(true)
})
</script>

<style scoped>
.history-dot {
  display: inline-block;
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: #3b82f6;
  box-shadow: 0 0 0 4px rgba(59, 130, 246, 0.2);
}

.history-filters {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 10px;
}

.hf-search {
  min-width: 220px;
  flex: 1 1 240px;
}

.hf-select {
  width: 135px;
  flex: 0 0 auto;
}

.hf-range {
  display: flex;
  align-items: center;
  gap: 6px;
}

.hf-date {
  width: 145px;
}

.hf-dur {
  width: 96px;
}

.hf-unit {
  width: 92px;
}

.group-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  width: 100%;
  flex-wrap: wrap;
  padding-right: 12px;
}

.group-header__stats {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}

.history-table :deep(td) {
  vertical-align: top;
}
</style>
