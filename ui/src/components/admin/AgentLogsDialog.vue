<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-dialog v-model="open" max-width="1100" scrollable :fullscreen="fullscreen">
    <v-card>
      <v-card-title class="d-flex align-center">
        <v-icon icon="mdi-text-box-search-outline" color="primary" class="mr-2" />
        <!-- The span shrinks with an ellipsis (min-width: 0), so the title's own
             buttons stay on screen: a title never wraps, and a long device name
             used to push Close or Refresh past the edge on a phone. -->
        <span class="text-truncate" style="min-width: 0">{{ t('mh.logs.title', { name: agentName }) }}</span>
        <v-spacer />
        <v-btn
          icon="mdi-refresh"
          size="small"
          variant="text"
          :loading="loading"
          @click="refresh"
          :aria-label="t('mh.logs.refresh')"
        />
        <v-btn
          icon="mdi-close"
          size="small"
          variant="text"
          @click="close"
          :aria-label="t('mh.common.close')"
        />
      </v-card-title>

      <!-- Filter toolbar: level + target substring + a quick "throughput
           only" toggle so an operator chasing a tunnel stall can isolate
           the per-flow throughput lines in one click. -->
      <!-- A plain block, not a v-card-subtitle: a subtitle dims its content, so
           the filters looked disabled. (`gap-2` was no class at all — ga-2.) -->
      <div class="px-4">
        <div class="d-flex align-center flex-wrap ga-2 py-2">
          <v-select
            v-model="minLevel"
            :items="levelOptions"
            :label="t('mh.logs.minLevel')"
            density="compact"
            variant="outlined"
            hide-details
            style="max-width: 140px"
          />
          <v-text-field
            v-model="targetFilter"
            :label="t('mh.logs.filter')"
            density="compact"
            variant="outlined"
            hide-details
            clearable
            style="max-width: 320px"
            prepend-inner-icon="mdi-filter-variant"
          />
          <v-chip
            :color="throughputOnly ? 'primary' : undefined"
            :variant="throughputOnly ? 'flat' : 'outlined'"
            size="small"
            @click="toggleThroughput"
          >
            <v-icon start size="small">mdi-speedometer</v-icon>
            {{ t('mh.logs.throughput') }}
          </v-chip>
          <v-spacer />
          <span class="text-caption text-medium-emphasis">
            {{ t('mh.logs.count', { shown: filteredLines.length, total: allLines.length }) }}
          </span>
        </div>
      </div>

      <v-card-text :style="fullscreen ? undefined : 'max-height: 70vh'">
        <v-alert
          v-if="error"
          type="error"
          variant="tonal"
          density="compact"
          class="mb-3"
        >
          {{ error }}
        </v-alert>

        <div v-if="loading && allLines.length === 0" class="d-flex justify-center pa-8">
          <v-progress-circular indeterminate />
        </div>

        <div
          v-else-if="!loading && allLines.length === 0 && !error"
          class="text-center pa-6 text-medium-emphasis"
        >
          <v-icon size="48" color="grey-lighten-1" class="mb-2">mdi-text-box-remove-outline</v-icon>
          <p>{{ t('mh.logs.none') }}</p>
          <p class="text-body-2">
            {{ t('mh.logs.noneHint') }}
          </p>
        </div>

        <div
          v-else-if="!loading && filteredLines.length === 0 && allLines.length > 0"
          class="text-center pa-6 text-medium-emphasis"
        >
          <v-icon size="48" color="grey-lighten-1" class="mb-2">mdi-filter-remove-outline</v-icon>
          <p>{{ t('mh.logs.noMatch') }}</p>
        </div>

        <div v-else class="log-view">
          <div
            v-for="(line, i) in filteredLines"
            :key="i"
            class="log-line"
            :class="`lvl-${line.level.toLowerCase()}`"
          >
            <span class="log-ts">{{ fmtTs(line.ts) }}</span>
            <span class="log-level" :class="`chip-${line.level.toLowerCase()}`">{{ line.level }}</span>
            <span class="log-target">{{ shortTarget(line.target) }}</span>
            <span class="log-msg">{{ line.msg }}{{ fmtFields(line.fields) }}</span>
          </div>
        </div>
      </v-card-text>

      <v-card-actions class="flex-wrap">
        <span class="text-caption text-medium-emphasis ml-2">
          {{ t('mh.logs.batches', { n: batches.length, age: newestBatchAge }) }}
        </span>
        <v-spacer />
        <v-btn variant="text" @click="copyVisible">{{ t('mh.logs.copy') }}</v-btn>
        <v-btn variant="text" @click="close">{{ t('mh.common.close') }}</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useResponsiveDialog } from '@/composables/useResponsiveDialog'
import { useAgentStore, type AgentLogBatch, type AgentLogLine } from '@/stores/agents'

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
const batches = ref<AgentLogBatch[]>([])
const loading = ref(false)
const error = ref<string | null>(null)

const minLevel = ref<'TRACE' | 'DEBUG' | 'INFO' | 'WARN' | 'ERROR'>('INFO')
const targetFilter = ref<string>('')
const throughputOnly = ref(false)

const levelOptions = ['TRACE', 'DEBUG', 'INFO', 'WARN', 'ERROR']
const LEVEL_RANK: Record<string, number> = {
  TRACE: 0,
  DEBUG: 1,
  INFO: 2,
  WARN: 3,
  ERROR: 4,
}

/** Flatten all batches into a single newest-first line list. The
 *  server returns batches newest-first; within a batch the agent
 *  appends lines oldest-first, so we reverse each batch's lines to
 *  keep the global view strictly newest-first. */
const allLines = computed<AgentLogLine[]>(() => {
  const out: AgentLogLine[] = []
  for (const b of batches.value) {
    for (let i = b.lines.length - 1; i >= 0; i--) {
      out.push(b.lines[i]!)
    }
  }
  return out
})

const filteredLines = computed<AgentLogLine[]>(() => {
  const minRank = LEVEL_RANK[minLevel.value] ?? 2
  const needle = (targetFilter.value || '').toLowerCase()
  return allLines.value.filter((l) => {
    if ((LEVEL_RANK[l.level] ?? 0) < minRank) return false
    if (throughputOnly.value && !l.msg.includes('tunnel flow throughput')) return false
    if (needle) {
      const hay = `${l.target} ${l.msg}`.toLowerCase()
      if (!hay.includes(needle)) return false
    }
    return true
  })
})

const newestBatchAge = computed(() => {
  if (batches.value.length === 0) return '—'
  return fmtRelative(batches.value[0]!.createdAt)
})

async function load() {
  if (!props.tenantId || !props.agentId) return
  loading.value = true
  error.value = null
  try {
    batches.value = await agentStore.fetchLogs(props.tenantId, props.agentId, 100)
  } catch (e) {
    error.value = (e as Error).message
    batches.value = []
  } finally {
    loading.value = false
  }
}

function refresh() {
  void load()
}

function close() {
  open.value = false
}

function toggleThroughput() {
  throughputOnly.value = !throughputOnly.value
}

async function copyVisible() {
  const text = filteredLines.value
    .map((l) => `${l.ts} ${l.level} ${l.target} ${l.msg}${fmtFields(l.fields)}`)
    .join('\n')
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    // clipboard blocked — no-op; operator can select manually
  }
}

// Re-fetch each time the dialog opens so the operator always sees the
// latest uploaded batches (no store caching).
watch(open, (now) => {
  if (now) void load()
})

/** Collapse `tracing` structured fields into a compact ` key=val`
 *  suffix so the throughput numbers (tcp_read_kbps=… etc.) render
 *  inline with the message. Empty / missing fields → no suffix. */
function fmtFields(fields: Record<string, unknown> | undefined): string {
  if (!fields || typeof fields !== 'object') return ''
  const entries = Object.entries(fields)
  if (entries.length === 0) return ''
  return (
    ' ' +
    entries
      .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : String(v)}`)
      .join(' ')
  )
}

/** Strip the leading module path so the target column stays narrow —
 *  e.g. `tunnel_core::forward` → `forward`, `meshharbord::tunnel::
 *  acceptor` → `acceptor`. Full target is still searchable via the
 *  filter box (which matches the un-shortened string). */
function shortTarget(target: string): string {
  const parts = target.split('::')
  return parts[parts.length - 1] || target
}

function fmtTs(iso: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  // HH:MM:SS.mmm — date is almost always "today" for live logs, so
  // the time-of-day is the useful part; full date on hover via title
  // isn't worth the column width.
  return d.toLocaleTimeString(undefined, { hour12: false }) + '.' +
    String(d.getMilliseconds()).padStart(3, '0')
}

function fmtRelative(iso: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const diff = Date.now() - d.getTime()
  if (diff < 0) return t('mh.ago.now')
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return t('mh.ago.now')
  if (mins < 60) return t('mh.ago.m', { n: mins })
  const hours = Math.floor(mins / 60)
  if (hours < 24) return t('mh.ago.h', { n: hours })
  const days = Math.floor(hours / 24)
  return t('mh.ago.d', { n: days })
}
</script>

<style scoped>
.log-view {
  font-family: ui-monospace, 'Cascadia Code', 'Consolas', monospace;
  font-size: 12px;
  line-height: 1.5;
}
.log-line {
  display: flex;
  gap: 8px;
  padding: 1px 4px;
  border-bottom: 1px solid rgba(0, 0, 0, 0.03);
  white-space: pre-wrap;
  word-break: break-word;
}
.log-line:hover {
  background-color: rgba(0, 0, 0, 0.04);
}
.log-ts {
  color: #888;
  flex: 0 0 auto;
  white-space: nowrap;
}
.log-level {
  flex: 0 0 auto;
  width: 46px;
  font-weight: 600;
}
.log-target {
  flex: 0 0 auto;
  width: 110px;
  color: #6c6e80;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.log-msg {
  flex: 1 1 auto;
}
/* A phone has no room for three fixed columns before the message (~270 px
   of a 264 px dialog left it 1–9 characters wide): time · level · target on
   one line, the message under it at full width. */
@media (max-width: 599.98px) {
  .log-line {
    flex-wrap: wrap;
  }
  .log-target {
    width: auto;
    flex: 1 1 0;
    min-width: 0;
  }
  .log-msg {
    flex-basis: 100%;
  }
}
.chip-trace { color: #9e9e9e; }
.chip-debug { color: #5c8aa8; }
.chip-info { color: #2e7d32; }
.chip-warn { color: #ef6c00; }
.chip-error { color: #c62828; }
.lvl-error { background-color: rgba(198, 40, 40, 0.06); }
.lvl-warn { background-color: rgba(239, 108, 0, 0.05); }
</style>
