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

        <v-alert v-if="picks.length < count" type="warning" variant="tonal" density="compact" class="mb-3">
          {{ t('mh.gpu.find.notEnough', { need: count, found: picks.length }) }}
        </v-alert>

        <template v-if="picks.length">
          <v-list density="compact" class="mb-3 border rounded">
            <v-list-item v-for="p in picks" :key="`${p.agentId}-${p.uuid}`">
              <v-list-item-title class="text-mono text-body-2">
                {{ p.host }} · #{{ p.idx }} · {{ p.name || 'GPU' }}
              </v-list-item-title>
              <v-list-item-subtitle class="text-mono text-caption">
                {{ p.freeGb }} GiB free · {{ p.uuid }}
              </v-list-item-subtitle>
            </v-list-item>
          </v-list>

          <div v-for="ex in exports" :key="ex.agentId" class="mb-2">
            <div class="text-caption font-weight-medium mb-1">{{ ex.host }}</div>
            <div class="d-flex align-center ga-2 pa-2 rounded bg-surface-variant">
              <code class="text-caption flex-grow-1 text-break">{{ ex.cmd }}</code>
              <v-btn
                size="x-small"
                variant="tonal"
                :prepend-icon="copiedHost === ex.agentId ? 'mdi-check' : 'mdi-content-copy'"
                @click="copyCmd(ex.agentId, ex.cmd)"
              >
                {{ copiedHost === ex.agentId ? t('mh.gpu.find.copied') : t('mh.gpu.find.copy') }}
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
import { isSafeCudaUuid, shellQuoteSingle, type GpuHostView } from '@/api/gpu'

const props = defineProps<{
  modelValue: boolean
  hosts: GpuHostView[]
}>()

defineEmits<{ (e: 'update:modelValue', v: boolean): void }>()

const { t } = useI18n()
const count = ref(1)
const minFreeGb = ref(0)
const sameHost = ref(true)
const copiedHost = ref<string | null>(null)

interface Pick {
  agentId: string
  host: string
  idx: number
  uuid: string
  name?: string | null
  freeMb: number
  freeGb: string
}

const picks = computed<Pick[]>(() => {
  const minMb = Math.max(0, (minFreeGb.value || 0) * 1024)
  const want = Math.max(1, Math.floor(count.value || 1))
  const byHost: Array<{ agentId: string; host: string; cards: Pick[] }> = []

  for (const h of props.hosts) {
    if (!h.is_online || h.freshness === 'offline' || h.status !== 'ok') continue
    const label = h.display_name?.trim() || h.name
    const cards: Pick[] = []
    for (const g of h.gpus) {
      if (g.state !== 'free' || g.lost || !isSafeCudaUuid(g.uuid)) continue
      const freeMb =
        g.mem_total_mb != null && g.mem_used_mb != null
          ? Math.max(0, g.mem_total_mb - g.mem_used_mb)
          : 0
      if (minMb > 0 && freeMb < minMb) continue
      cards.push({
        agentId: h.agent_id,
        host: label,
        idx: g.idx,
        uuid: g.uuid,
        name: g.name,
        freeMb,
        freeGb: (freeMb / 1024).toFixed(1),
      })
    }
    cards.sort((a, b) => a.idx - b.idx)
    if (cards.length) byHost.push({ agentId: h.agent_id, host: label, cards })
  }

  if (sameHost.value) {
    const eligible = byHost.filter((e) => e.cards.length >= want)
    eligible.sort((a, b) => a.cards.length - b.cards.length || a.host.localeCompare(b.host))
    return eligible[0]?.cards.slice(0, want) ?? []
  }

  byHost.sort((a, b) => a.host.localeCompare(b.host))
  return byHost.flatMap((e) => e.cards).slice(0, want)
})

const exports = computed(() => {
  const nameToIds = new Map<string, Set<string>>()
  const map = new Map<string, { host: string; uuids: string[]; idxs: number[]; ascend: boolean }>()
  for (const p of picks.value) {
    const ids = nameToIds.get(p.host) ?? new Set<string>()
    ids.add(p.agentId)
    nameToIds.set(p.host, ids)
    const isAscend = p.uuid.startsWith('ASCEND-') || (p.name || '').toLowerCase().includes('ascend')
    const entry = map.get(p.agentId) ?? { host: p.host, uuids: [], idxs: [], ascend: isAscend }
    entry.uuids.push(p.uuid)
    entry.idxs.push(p.idx)
    entry.ascend = entry.ascend && isAscend
    map.set(p.agentId, entry)
  }
  return Array.from(map.entries()).map(([agentId, { host, uuids, idxs, ascend }]) => {
    const ambiguous = (nameToIds.get(host)?.size ?? 0) > 1
    const label = ambiguous ? `${host} (${agentId.slice(0, 8)})` : host
    const cmd = ascend
      ? `export ASCEND_RT_VISIBLE_DEVICES=${shellQuoteSingle(idxs.join(','))}`
      : `export CUDA_DEVICE_ORDER=PCI_BUS_ID CUDA_VISIBLE_DEVICES=${shellQuoteSingle(uuids.join(','))}`
    return {
      agentId,
      host: label,
      cmd,
    }
  })
})

async function copyCmd(host: string, cmd: string) {
  try {
    await navigator.clipboard.writeText(cmd)
    copiedHost.value = host
    setTimeout(() => {
      if (copiedHost.value === host) copiedHost.value = null
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
