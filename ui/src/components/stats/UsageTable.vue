<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <div>
    <div class="d-flex align-center flex-wrap mb-2" style="gap: 8px">
      <v-text-field
        v-model="search"
        density="compact"
        variant="outlined"
        hide-details
        clearable
        prepend-inner-icon="mdi-magnify"
        placeholder="Filter by user"
        :style="xs ? 'flex: 1 1 100%' : 'max-width: 260px'"
      />
      <v-spacer />
      <span v-if="rows.length" class="text-caption text-medium-emphasis">
        {{ rows.length }} {{ rows.length === 1 ? 'user' : 'users' }} active in this range<span
          v-if="xs"
        > · tap one for the breakdown</span>
      </span>
    </div>

    <v-data-table
      :headers="headers"
      :items="rows"
      :loading="loading"
      :search="search"
      :sort-by="[{ key: 'total_minutes', order: 'desc' }]"
      density="comfortable"
      hover
      @click:row="onRow"
    >
      <template #item.name="{ item }">
        <span class="text-body-2">{{ item.name || item.user_id.slice(-6) }}</span>
      </template>

      <template #item.rc_minutes="{ item }">
        {{ fmtMinutes(item.rc.minutes) }}
      </template>
      <template #item.rc_bytes="{ item }">
        <span :class="{ 'text-medium-emphasis': !item.rc.bytes_known }">
          {{ item.rc.bytes_known ? fmtBytes(item.rc.bytes) : '—' }}
        </span>
      </template>

      <template #item.tunnel_minutes="{ item }">
        {{ fmtMinutes(item.tunnel.minutes) }}
      </template>
      <!-- Reported by the flow's own endpoint since wave 3. Sessions that
           closed before then carry no count, so the em dash stays for
           those — "not measured" is not "no traffic". -->
      <template #item.tunnel_bytes="{ item }">
        <span
          :class="{ 'text-medium-emphasis': !item.tunnel.bytes_known }"
          :title="item.tunnel.bytes_known ? '' : 'Flows that closed before traffic accounting shipped'"
        >
          {{ item.tunnel.bytes_known ? fmtBytes(item.tunnel.bytes) : '—' }}
        </span>
      </template>

      <template #item.total_minutes="{ item }">
        <strong>{{ fmtMinutes(item.total_minutes) }}</strong>
      </template>

      <template #item.orgs="{ item }">
        <span class="text-caption">{{ orgLabel(item) }}</span>
      </template>

      <template #no-data>
        <div class="py-6 text-center text-medium-emphasis text-body-2">
          {{ emptyText }}
        </div>
      </template>
    </v-data-table>
  </div>
</template>

<script setup lang="ts">
// Per-user usage rows. Clicking a row opens that user's timeline — the
// table answers "who used what, how much", the timeline answers "when".
import { computed, ref } from 'vue'
import { useDisplay } from 'vuetify'
import { formatBytes, formatMinutes } from '@/utils/format'
import type { UsageUserRow } from '@/stores/stats'

const props = withDefaults(
  defineProps<{
    users: UsageUserRow[]
    loading?: boolean
    /** Platform scope — adds the org column. */
    showOrg?: boolean
    emptyText?: string
  }>(),
  { loading: false, showOrg: false, emptyText: 'No recorded activity in this range' },
)

const emit = defineEmits<{ (e: 'select', userId: string): void }>()

const search = ref('')
const { xs } = useDisplay()
const fmtBytes = formatBytes
const fmtMinutes = formatMinutes

const rows = computed(() => props.users)

const headers = computed(() => {
  // FR-116 — on a phone: who, and how much in total. Eight columns put
  // everything after the name behind a sideways scroll; the per-category
  // minutes and traffic are one tap away (a row opens the person's detail).
  if (xs.value) {
    return [
      { title: 'User', key: 'name', sortable: true },
      { title: 'Total', key: 'total_minutes' },
    ]
  }
  const base = [
    { title: 'User', key: 'name', sortable: true },
    { title: 'Remote desktop', key: 'rc_minutes', value: (i: UsageUserRow) => i.rc.minutes },
    { title: '', key: 'rc_bytes', value: (i: UsageUserRow) => i.rc.bytes, sortable: true },
    { title: 'Tunnel', key: 'tunnel_minutes', value: (i: UsageUserRow) => i.tunnel.minutes },
    { title: '', key: 'tunnel_bytes', value: (i: UsageUserRow) => i.tunnel.bytes, sortable: true },
    { title: 'Total', key: 'total_minutes' },
  ]
  if (props.showOrg) base.push({ title: 'Orgs', key: 'orgs', sortable: false })
  return base
})

function orgLabel(item: UsageUserRow): string {
  const names = (item.orgs ?? []).map((o) => o.name).filter(Boolean)
  if (!names.length) return '—'
  if (names.length <= 2) return names.join(', ')
  return `${names.slice(0, 2).join(', ')} +${names.length - 2}`
}

function onRow(_e: unknown, row: { item: UsageUserRow }) {
  emit('select', row.item.user_id)
}
</script>
