<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-dialog
    :model-value="modelValue"
    max-width="640"
    @update:model-value="$emit('update:modelValue', $event)"
  >
    <v-card>
      <v-card-title>{{ t('mh.gpu.find.title') }}</v-card-title>
      <v-card-text>
        <div class="d-flex flex-wrap ga-3 mb-3">
          <v-text-field
            v-model.number="count"
            type="number"
            min="1"
            max="32"
            density="compact"
            variant="outlined"
            :label="t('mh.gpu.find.count')"
            style="max-width: 140px"
          />
          <v-text-field
            v-model.number="minFreeGb"
            type="number"
            min="0"
            density="compact"
            variant="outlined"
            :label="t('mh.gpu.find.minFreeGb')"
            style="max-width: 180px"
          />
          <v-checkbox
            v-model="sameHost"
            density="compact"
            :label="t('mh.gpu.find.sameHost')"
            hide-details
          />
        </div>

        <v-alert v-if="picks.length < wantCount" type="warning" variant="tonal" density="compact" class="mb-3">
          <template v-if="sameHost && totalQualifyingCount >= wantCount">
            {{ t('mh.gpu.find.notEnoughSameHost', { need: wantCount, total: totalQualifyingCount }) }}
          </template>
          <template v-else>
            {{ t('mh.gpu.find.notEnough', { need: wantCount, found: picks.length }) }}
          </template>
        </v-alert>

        <template v-if="picks.length">
          <v-list density="compact" class="mb-3 border rounded">
            <v-list-item v-for="p in picks" :key="`${p.agentId}-${p.uuid}`">
              <v-list-item-title class="text-mono text-body-2">
                {{ p.host }} · {{ p.slot }} · {{ p.name || 'GPU' }}
              </v-list-item-title>
              <v-list-item-subtitle class="text-mono text-caption">
                {{ p.freeGb != null ? `${p.freeGb} GiB free` : '—' }} · {{ p.uuid }}
              </v-list-item-subtitle>
            </v-list-item>
          </v-list>

          <div v-for="ex in exports" :key="ex.key" class="mb-2">
            <div class="text-caption font-weight-medium mb-1">{{ ex.host }}</div>
            <div class="d-flex align-center ga-2 pa-2 rounded bg-surface-variant">
              <code class="text-caption flex-grow-1 text-break">{{ ex.cmd }}</code>
              <v-btn
                size="x-small"
                variant="tonal"
                :prepend-icon="copiedKey === ex.key ? 'mdi-check' : 'mdi-content-copy'"
                @click="copyCmd(ex.key, ex.cmd)"
              >
                {{ copiedKey === ex.key ? t('mh.gpu.find.copied') : t('mh.gpu.find.copy') }}
              </v-btn>
            </div>
          </div>
        </template>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="$emit('update:modelValue', false)">{{ t('common.close') }}</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import {
  cardRuntimeKind,
  isCardEligibleFree,
  isExportableRuntime,
  isSafeCudaUuid,
  shellQuoteSingle,
  type GpuHostView,
  type GpuRuntimeKind,
} from '@/api/gpu'

const props = defineProps<{
  modelValue: boolean
  hosts: GpuHostView[]
}>()

defineEmits<{ (e: 'update:modelValue', v: boolean): void }>()

const { t } = useI18n()
const count = ref(1)
const minFreeGb = ref(0)
const sameHost = ref(true)
const copiedKey = ref<string | null>(null)

const wantCount = computed(() => Math.max(1, Math.floor(count.value || 1)))

interface Pick {
  agentId: string
  host: string
  idx: number
  vendorIndex: number
  runtime: GpuRuntimeKind
  slot: string
  uuid: string
  name?: string | null
  freeMb: number | null
  freeGb: string | null
}

const qualifyingByHost = computed(() => {
  const minMb = Math.max(0, (minFreeGb.value || 0) * 1024)
  const byHost: Array<{ agentId: string; host: string; cards: Pick[] }> = []

  for (const h of props.hosts) {
    const label = h.display_name?.trim() || h.name
    const cards: Pick[] = []
    for (const g of h.gpus) {
      const rt = cardRuntimeKind(h, g)
      if (!isCardEligibleFree(h, g) || !isSafeCudaUuid(g.uuid) || !isExportableRuntime(rt)) continue
      const freeMb =
        g.mem_total_mb != null && g.mem_used_mb != null
          ? Math.max(0, g.mem_total_mb - g.mem_used_mb)
          : null
      if (minMb > 0 && (freeMb ?? 0) < minMb) continue
      const vendorIndex = g.vendor_index ?? g.idx
      cards.push({
        agentId: h.agent_id,
        host: label,
        idx: g.idx,
        vendorIndex,
        runtime: rt,
        slot: rt === 'ascend' ? `NPU${vendorIndex}` : `#${g.idx}`,
        uuid: g.uuid,
        name: g.name,
        freeMb,
        freeGb: freeMb != null ? (freeMb / 1024).toFixed(1) : null,
      })
    }
    cards.sort((a, b) => a.idx - b.idx)
    if (cards.length) byHost.push({ agentId: h.agent_id, host: label, cards })
  }
  return byHost
})

const totalQualifyingCount = computed(() =>
  qualifyingByHost.value.reduce((acc, h) => acc + h.cards.length, 0),
)

const picks = computed<Pick[]>(() => {
  const want = wantCount.value
  const byHost = qualifyingByHost.value

  if (sameHost.value) {
    const eligible = byHost.filter((e) => e.cards.length >= want)
    eligible.sort((a, b) => a.cards.length - b.cards.length || a.host.localeCompare(b.host))
    return eligible[0]?.cards.slice(0, want) ?? []
  }

  return [...byHost]
    .sort((a, b) => a.host.localeCompare(b.host))
    .flatMap((e) => e.cards)
    .slice(0, want)
})

const exports = computed(() => {
  const nameToIds = new Map<string, Set<string>>()
  const map = new Map<string, { agentId: string; host: string; runtime: GpuRuntimeKind; tokens: string[] }>()
  for (const p of picks.value) {
    const ids = nameToIds.get(p.host) ?? new Set<string>()
    ids.add(p.agentId)
    nameToIds.set(p.host, ids)
    const key = `${p.agentId}:${p.runtime}`
    const token = p.runtime === 'ascend' || p.runtime === 'amd' ? String(p.vendorIndex) : p.uuid
    const entry = map.get(key) ?? { agentId: p.agentId, host: p.host, runtime: p.runtime, tokens: [] }
    entry.tokens.push(token)
    map.set(key, entry)
  }
  return Array.from(map.entries()).map(([key, { agentId, host, runtime, tokens }]) => {
    const ambiguous = (nameToIds.get(host)?.size ?? 0) > 1
    const label = ambiguous ? `${host} (${agentId.slice(0, 8)})` : host
    const joined = tokens.join(',')
    const cmd =
      runtime === 'ascend'
        ? `export ASCEND_RT_VISIBLE_DEVICES=${shellQuoteSingle(joined)}`
        : runtime === 'amd'
          ? `export ROCR_VISIBLE_DEVICES=${shellQuoteSingle(joined)}`
          : `export CUDA_DEVICE_ORDER=PCI_BUS_ID CUDA_VISIBLE_DEVICES=${shellQuoteSingle(joined)}`
    return {
      key,
      agentId,
      host: label,
      cmd,
    }
  })
})

async function copyCmd(key: string, cmd: string) {
  try {
    await navigator.clipboard.writeText(cmd)
    copiedKey.value = key
    setTimeout(() => {
      if (copiedKey.value === key) copiedKey.value = null
    }, 2000)
  } catch {
    /* ignore */
  }
}
</script>

<style scoped>
.text-mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}
</style>
