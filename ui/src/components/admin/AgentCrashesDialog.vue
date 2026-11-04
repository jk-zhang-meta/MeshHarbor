<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-dialog v-model="open" max-width="900" scrollable :fullscreen="fullscreen">
    <v-card>
      <v-card-title class="d-flex align-center">
        <v-icon icon="mdi-alert-circle-outline" color="warning" class="mr-2" />
        <!-- The span shrinks with an ellipsis (min-width: 0), so the title's own
             buttons stay on screen: a title never wraps, and a long device name
             used to push Close or Refresh past the edge on a phone. -->
        <span class="text-truncate" style="min-width: 0">{{ t('mh.crash.title', { name: agentName }) }}</span>
        <v-spacer />
        <v-btn
          icon="mdi-refresh"
          size="small"
          variant="text"
          :loading="loading"
          @click="refresh"
          :aria-label="t('mh.crash.refresh')"
        />
        <v-btn
          icon="mdi-close"
          size="small"
          variant="text"
          @click="close"
          :aria-label="t('mh.common.close')"
        />
      </v-card-title>

      <v-card-text style="max-height: 70vh">
        <v-alert
          v-if="error"
          type="error"
          variant="tonal"
          density="compact"
          class="mb-3"
        >
          {{ error }}
        </v-alert>

        <div v-if="loading && crashes.length === 0" class="d-flex justify-center pa-8">
          <v-progress-circular indeterminate />
        </div>

        <div
          v-else-if="!loading && crashes.length === 0 && !error"
          class="text-center pa-6 text-medium-emphasis"
        >
          <v-icon size="48" color="grey-lighten-1" class="mb-2">mdi-check-circle-outline</v-icon>
          <p>{{ t('mh.crash.none') }}</p>
        </div>

        <v-table v-else density="compact" class="crashes-table">
          <thead>
            <tr>
              <th style="width: 32px"></th>
              <th>{{ t('mh.crash.col.when') }}</th>
              <th>{{ t('mh.crash.col.reason') }}</th>
              <th>{{ t('mh.crash.col.summary') }}</th>
            </tr>
          </thead>
          <tbody>
            <template v-for="c in crashes" :key="c.id">
              <tr class="crash-row" @click="toggleExpand(c.id)">
                <td>
                  <v-icon size="small">
                    {{ expandedId === c.id ? 'mdi-chevron-up' : 'mdi-chevron-down' }}
                  </v-icon>
                </td>
                <td class="text-caption" :title="fmtAbsolute(c.crashedAtUnix)">
                  {{ fmtRelative(c.crashedAtUnix) }}
                </td>
                <td>
                  <v-chip
                    size="x-small"
                    :color="reasonColor(c.reason)"
                    variant="flat"
                  >
                    {{ reasonLabel(c.reason) }}
                  </v-chip>
                </td>
                <td class="crash-summary">{{ c.summary }}</td>
              </tr>
              <tr v-if="expandedId === c.id" class="crash-detail-row">
                <td colspan="4" class="pa-3">
                  <!-- The summary in full, and the time as a date: the row
                       above clips the one and hides the other in a tooltip,
                       which a phone never shows. -->
                  <div class="text-body-2 mb-1 text-break">{{ c.summary }}</div>
                  <div class="text-caption mb-2">{{ fmtAbsolute(c.crashedAtUnix) }}</div>
                  <div class="text-caption text-medium-emphasis mb-2">
                    <strong>{{ t('mh.crash.host') }}</strong> {{ c.hostname }} ·
                    <strong>{{ t('mh.crash.agent') }}</strong> v{{ c.agentVersion }} ·
                    <strong>{{ t('mh.crash.os') }}</strong> {{ c.os }} ·
                    <strong>{{ t('mh.crash.pid') }}</strong> {{ c.pid }} ·
                    <strong>{{ t('mh.crash.reported') }}</strong> {{ fmtRelative(reportedAtUnix(c)) }}
                  </div>
                  <pre class="crash-log-tail bg-grey-lighten-4 pa-2 rounded">{{
                    c.logTail || t('mh.crash.noTail')
                  }}</pre>
                </td>
              </tr>
            </template>
          </tbody>
        </v-table>
      </v-card-text>

      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="close">{{ t('mh.common.close') }}</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useResponsiveDialog } from '@/composables/useResponsiveDialog'
import { useAgentStore, type AgentCrash } from '@/stores/agents'

const props = defineProps<{
  modelValue: boolean
  tenantId: string
  agentId: string
  agentName: string
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', v: boolean): void
}>()

const { t } = useI18n()
const { fullscreen } = useResponsiveDialog()
const open = computed({
  get: () => props.modelValue,
  set: (v) => emit('update:modelValue', v),
})

const agentStore = useAgentStore()
const crashes = ref<AgentCrash[]>([])
const loading = ref(false)
const error = ref<string | null>(null)
const expandedId = ref<string | null>(null)

async function load() {
  if (!props.tenantId || !props.agentId) return
  loading.value = true
  error.value = null
  try {
    crashes.value = await agentStore.fetchCrashes(props.tenantId, props.agentId)
  } catch (e) {
    error.value = (e as Error).message
    crashes.value = []
  } finally {
    loading.value = false
  }
}

function refresh() {
  expandedId.value = null
  void load()
}

function close() {
  open.value = false
}

function toggleExpand(id: string) {
  expandedId.value = expandedId.value === id ? null : id
}

// Re-fetch every time the dialog opens; no store-level caching so
// the operator always sees the latest after a fresh-host crash.
watch(open, (now) => {
  if (now) {
    expandedId.value = null
    void load()
  }
})

/** Snake_case crash-reason strings come from the Rust enum
 *  `CrashReason` in `crates/remote_control/src/models.rs`. Three
 *  colours: panic = red (something blew up), watchdog_stall =
 *  orange (something hung), supervisor_detected = yellow (process
 *  exited non-zero, root cause TBD). */
function reasonColor(r: AgentCrash['reason']): string {
  switch (r) {
    case 'panic':
      return 'error'
    case 'watchdog_stall':
      return 'warning'
    case 'supervisor_detected':
      return 'amber'
    default:
      return 'grey'
  }
}

function reasonLabel(r: AgentCrash['reason']): string {
  switch (r) {
    case 'panic':
      return t('mh.crash.reason.panic')
    case 'watchdog_stall':
      return t('mh.crash.reason.watchdog')
    case 'supervisor_detected':
      return t('mh.crash.reason.supervisor')
    default:
      return r
  }
}

function fmtAbsolute(unixSecs: number): string {
  if (!unixSecs) return '—'
  try {
    return new Date(unixSecs * 1000).toLocaleString()
  } catch {
    return String(unixSecs)
  }
}

function fmtRelative(unixSecs: number): string {
  if (!unixSecs) return '—'
  const ms = unixSecs * 1000
  const diff = Date.now() - ms
  if (diff < 0) return t('mh.ago.now')
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return t('mh.ago.now')
  if (mins < 60) return t('mh.ago.m', { n: mins })
  const hours = Math.floor(mins / 60)
  if (hours < 24) return t('mh.ago.h', { n: hours })
  const days = Math.floor(hours / 24)
  if (days < 30) return t('mh.ago.d', { n: days })
  const months = Math.floor(days / 30)
  if (months < 12) return t('mh.ago.mo', { n: months })
  return t('mh.ago.y', { n: Math.floor(months / 12) })
}

function reportedAtUnix(c: AgentCrash): number {
  if (!c.reportedAt) return 0
  const d = new Date(c.reportedAt)
  return Number.isNaN(d.getTime()) ? 0 : Math.floor(d.getTime() / 1000)
}
</script>

<style scoped>
.crash-row {
  cursor: pointer;
}
.crash-row:hover {
  background-color: rgba(0, 0, 0, 0.04);
}
.crash-summary {
  max-width: 0; /* lets the cell respect table-layout truncation */
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.crash-detail-row {
  background-color: rgba(0, 0, 0, 0.02);
}
.crash-log-tail {
  font-family: ui-monospace, 'Cascadia Code', 'Consolas', monospace;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 360px;
  overflow-y: auto;
}
</style>
