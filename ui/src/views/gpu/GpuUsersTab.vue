<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-card variant="outlined">
    <v-card-title class="d-flex flex-wrap align-center ga-2">
      <span>{{ t('mh.gpu.users.title') }}</span>
      <v-spacer />
      <v-btn-toggle
        :model-value="gpuStore.usersRange"
        density="compact"
        mandatory
        color="primary"
        variant="outlined"
        @update:model-value="(r: GpuRange) => gpuStore.loadUsers(tenantId, r)"
      >
        <v-btn value="24h" size="small">24h</v-btn>
        <v-btn value="7d" size="small">7d</v-btn>
        <v-btn value="30d" size="small">30d</v-btn>
      </v-btn-toggle>
    </v-card-title>
    <v-card-text>
      <v-progress-linear v-if="gpuStore.usersLoading" indeterminate class="mb-2" />
      <v-table v-if="gpuStore.users.length" density="compact" class="table-stack-xs">
        <thead>
          <tr>
            <th>{{ t('mh.gpu.users.col.user') }}</th>
            <th class="text-right">{{ t('mh.gpu.users.col.heldHours') }}</th>
            <th class="text-right">{{ t('mh.gpu.users.col.busyHours') }}</th>
            <th class="text-right">{{ t('mh.gpu.users.col.liveGpus') }}</th>
            <th class="text-right">{{ t('mh.gpu.users.col.liveVram') }}</th>
            <th>{{ t('mh.gpu.users.col.hosts') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="u in gpuStore.users" :key="u.user">
            <td class="font-weight-medium text-mono">{{ u.user }}</td>
            <td class="text-right text-mono">{{ u.held_gpu_hours.toFixed(2) }}</td>
            <td class="text-right text-mono">{{ u.busy_gpu_hours.toFixed(2) }}</td>
            <td class="text-right text-mono">{{ u.live_gpus }}</td>
            <td class="text-right text-mono">{{ fmtVram(u.live_mem_mb) }}</td>
            <td>
              <v-chip v-for="h in u.hosts" :key="h" size="x-small" variant="tonal" class="mr-1">
                {{ h }}
              </v-chip>
            </td>
          </tr>
        </tbody>
      </v-table>
      <div v-else-if="!gpuStore.usersLoading" class="text-center pa-4 text-medium-emphasis">
        {{ t('mh.gpu.users.empty') }}
      </div>
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import { useGpuStore } from '@/stores/gpu'
import type { GpuRange } from '@/api/gpu'

defineProps<{ tenantId: string }>()

const { t } = useI18n()
const gpuStore = useGpuStore()

function fmtVram(mb: number): string {
  return mb >= 1024 ? `${(mb / 1024).toFixed(1)} GiB` : `${mb} MiB`
}
</script>

<style scoped>
.text-mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}
</style>
