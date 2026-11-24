<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  FR-92 P7 — the permanent keep-busy history, inside the org's keep-busy
  card. Two kinds of row share the list and are marked apart: the server's
  own record of an admin's change ("admin"), and what a device REPORTED on
  its heartbeats ("device-reported" — a claim, at the heartbeat's ~30 s
  resolution). Newest first; "Load more" pages by the last row's instant.
-->
<template>
  <div data-testid="keep-busy-history">
    <div class="d-flex align-center flex-wrap ga-2 mb-1">
      <span class="text-subtitle-2">{{ t('keepBusy.history.title') }}</span>
      <v-spacer />
      <v-select
        :model-value="agentFilter"
        :items="deviceItems"
        density="compact"
        hide-details
        variant="outlined"
        style="max-width: 260px"
        :aria-label="t('keepBusy.history.device')"
        data-testid="keep-busy-history-device"
        @update:model-value="onFilter"
      />
      <v-btn
        icon="mdi-refresh"
        size="small"
        variant="text"
        :loading="loading"
        :aria-label="t('keepBusy.history.refresh')"
        data-testid="keep-busy-history-refresh"
        @click="reload"
      />
    </div>
    <div class="text-caption text-medium-emphasis mb-2">{{ t('keepBusy.history.subtitle') }}</div>

    <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mb-2">
      {{ error }}
    </v-alert>

    <div
      v-if="!loading && !entries.length"
      class="text-medium-emphasis text-caption"
      data-testid="keep-busy-history-empty"
    >
      {{ t('keepBusy.history.empty') }}
    </div>

    <!-- FR-120 P4 — a card per entry below 600 px (table-stack-xs): the who
         sat past the right edge. The source chip says what it means on a tap
         (FactChip); its `title` reached a mouse only. -->
    <v-table v-else density="compact" class="table-stack-xs table-stack-xs--compact">
      <thead>
        <tr>
          <th>{{ t('keepBusy.history.when') }}</th>
          <th>{{ t('keepBusy.history.device') }}</th>
          <th>{{ t('keepBusy.history.what') }}</th>
          <th>{{ t('keepBusy.history.who') }}</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="e in entries" :key="e.id" data-testid="keep-busy-history-row">
          <td class="text-no-wrap" :data-label="t('keepBusy.history.when')">{{ fmtWhen(e.at) }}</td>
          <td class="text-no-wrap" :data-label="t('keepBusy.history.device')">{{ deviceLabel(e) }}</td>
          <td :data-label="t('keepBusy.history.what')">
            <span>{{ whatLabel(e) }}</span>
            <FactChip
              v-if="sourceHint(e)"
              size="x-small"
              variant="tonal"
              class="ml-2"
              :color="e.source === 'server' ? 'primary' : undefined"
              :explain="sourceHint(e)"
              :data-testid="`keep-busy-history-source-${e.source}`"
            >
              {{ sourceLabel(e) }}
            </FactChip>
            <v-chip
              v-else
              size="x-small"
              variant="tonal"
              class="ml-2"
              :color="e.source === 'server' ? 'primary' : undefined"
              :data-testid="`keep-busy-history-source-${e.source}`"
            >
              {{ sourceLabel(e) }}
            </v-chip>
          </td>
          <td class="text-no-wrap" :data-label="t('keepBusy.history.who')">{{ e.actor_name || '—' }}</td>
        </tr>
      </tbody>
    </v-table>

    <v-btn
      v-if="hasMore"
      variant="text"
      size="small"
      class="mt-1"
      :loading="loading"
      data-testid="keep-busy-history-more"
      @click="loadMore"
    >
      {{ t('keepBusy.history.loadMore') }}
    </v-btn>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAgentStore, type KeepBusyHistoryEntry } from '@/stores/agents'
import { patternLabel, type KeepBusyPattern } from '@/composables/keepBusy'
import FactChip from '@/components/common/FactChip.vue'

const props = defineProps<{ tenantId: string }>()

const { t, te } = useI18n()
const agentStore = useAgentStore()

/** One page. The server caps a request at 200. */
const PAGE = 50

const entries = ref<KeepBusyHistoryEntry[]>([])
const loading = ref(false)
const error = ref<string | null>(null)
/** `''` = every device: a `v-select` wants a value, not `undefined`. */
const agentFilter = ref('')
/** A full page means there may be more; a short one means that was it. */
const hasMore = ref(false)

const deviceItems = computed(() => [
  { title: t('keepBusy.history.allDevices'), value: '' },
  ...agentStore.agents.map((a) => ({ title: a.display_name || a.name, value: a.id })),
])

const deviceNames = computed(() => {
  const m: Record<string, string> = {}
  for (const a of agentStore.agents) m[a.id] = a.display_name || a.name
  return m
})

/** The name written on the row (it outlives the device), else the current
 *  name, else the id's head; an org row names the organization. */
function deviceLabel(e: KeepBusyHistoryEntry): string {
  if (!e.agent_id) return t('keepBusy.history.organization')
  return e.agent_name || deviceNames.value[e.agent_id] || e.agent_id.slice(0, 8)
}

function kindLabel(kind: string): string {
  const key = `keepBusy.history.kind.${kind}`
  // A word a newer server adds must still render, as itself.
  return te(key) ? t(key) : kind
}

function whatLabel(e: KeepBusyHistoryEntry): string {
  const base = kindLabel(e.kind)
  if (e.kind === 'on' && e.pattern) return `${base} · ${patternLabel(e.pattern as KeepBusyPattern).toLowerCase()}`
  if (e.kind === 'off' && e.reason) return `${base} · ${e.reason.replace(/_/g, ' ')}`
  if (e.kind === 'org_default_pattern') {
    return `${base} · ${e.pattern ? patternLabel(e.pattern as KeepBusyPattern).toLowerCase() : t('keepBusy.history.productDefault')}`
  }
  return base
}

function sourceLabel(e: KeepBusyHistoryEntry): string {
  const key = `keepBusy.history.source.${e.source}`
  return te(key) ? t(key) : e.source
}

function sourceHint(e: KeepBusyHistoryEntry): string {
  const key = `keepBusy.history.sourceHint.${e.source}`
  return te(key) ? t(key) : ''
}

function fmtWhen(at: string): string {
  const d = new Date(at)
  return Number.isNaN(d.getTime()) ? at : d.toLocaleString()
}

async function fetchPage(before?: string): Promise<KeepBusyHistoryEntry[]> {
  return agentStore.fetchKeepBusyHistory(props.tenantId, {
    agentId: agentFilter.value || undefined,
    before,
    limit: PAGE,
  })
}

async function reload() {
  loading.value = true
  error.value = null
  try {
    const page = await fetchPage()
    entries.value = page
    hasMore.value = page.length >= PAGE
  } catch (e) {
    // A 403 is an answer (FR-82): it shows here and ends nothing.
    error.value = (e as Error).message
    entries.value = []
    hasMore.value = false
  } finally {
    loading.value = false
  }
}

async function loadMore() {
  const last = entries.value.at(-1)
  if (!last) return reload()
  loading.value = true
  error.value = null
  try {
    const page = await fetchPage(last.at)
    entries.value = [...entries.value, ...page]
    hasMore.value = page.length >= PAGE
  } catch (e) {
    error.value = (e as Error).message
  } finally {
    loading.value = false
  }
}

function onFilter(v: string | null) {
  agentFilter.value = v ?? ''
  void reload()
}

onMounted(() => {
  void reload()
  if (!agentStore.agents.length) void agentStore.fetchAgents(props.tenantId)
})

defineExpose({ reload })
</script>
