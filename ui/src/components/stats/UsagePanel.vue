<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <div>
    <v-alert
      v-if="payload && payload.enabled === false"
      type="info"
      variant="tonal"
      class="mb-3"
    >
      Usage collection is disabled on this deployment.
    </v-alert>

    <v-alert
      v-else-if="payload && payload.watchers_complete === false"
      type="info"
      variant="tonal"
      density="compact"
      class="mb-3"
    >
      Screen-watching history is kept for 90 days, so sessions older than that show only
      the person who drove them.
    </v-alert>

    <usage-table
      :users="payload?.users ?? []"
      :loading="loading"
      :show-org="scope === 'platform'"
      :empty-text="emptyText"
      @select="openUser"
    />

    <!-- Detail: the from-when-till-when view for one person. FR-116: full
         screen on a phone — centred, it left the timeline's track ~36 px. -->
    <v-dialog v-model="dialog" max-width="1100" scrollable :fullscreen="xs">
      <v-card v-if="detail">
        <v-card-title class="d-flex align-center flex-wrap" style="gap: 8px">
          <span class="text-h6">{{ detail.user?.name || 'User' }}</span>
          <v-chip size="small" variant="tonal">{{ range }}</v-chip>
          <v-spacer />
          <v-btn icon="mdi-close" variant="text" size="small" @click="dialog = false" />
        </v-card-title>

        <v-card-text>
          <v-row dense class="mb-2">
            <v-col cols="6" md="3">
              <div class="text-caption text-medium-emphasis">Remote desktop</div>
              <div class="text-h6">{{ fmtMinutes(detail.totals?.rc_minutes) }}</div>
              <div class="text-caption text-medium-emphasis">
                {{ detail.totals?.rc_bytes ? fmtBytes(detail.totals.rc_bytes) : '—' }}
              </div>
            </v-col>
            <v-col cols="6" md="3">
              <div class="text-caption text-medium-emphasis">Calls</div>
              <div class="text-h6">{{ fmtMinutes(detail.totals?.call_minutes) }}</div>
              <div class="text-caption text-medium-emphasis">
                {{ detail.totals?.call_bytes ? fmtBytes(detail.totals.call_bytes) : '—' }}
              </div>
            </v-col>
            <v-col cols="6" md="3">
              <div class="text-caption text-medium-emphasis">Tunnel</div>
              <div class="text-h6">{{ fmtMinutes(detail.totals?.tunnel_minutes) }}</div>
              <div class="text-caption text-medium-emphasis">
                {{ detail.totals?.tunnel_bytes ? fmtBytes(detail.totals.tunnel_bytes) : '—' }}
              </div>
            </v-col>
            <v-col cols="6" md="3">
              <div class="text-caption text-medium-emphasis">Devices viewed</div>
              <div class="text-h6">{{ devicesViewed }}</div>
            </v-col>
          </v-row>

          <v-divider class="my-3" />

          <div class="text-subtitle-1 mb-1">Screens viewed</div>
          <p class="text-caption text-medium-emphasis mb-2">
            One lane per device — when this person was looking at it, and for how long.
          </p>
          <usage-timeline
            :windows="detail.viewing ?? []"
            :from="windowFrom"
            :to="windowTo"
            :show-org="scope === 'platform'"
            :watchers-complete="detail.watchers_complete !== false"
          />

          <template v-if="(detail.calls ?? []).length">
            <v-divider class="my-4" />
            <div class="text-subtitle-1 mb-2">Calls</div>
            <!-- FR-120 P4 — a card per row below 600 px (table-stack-xs): the
                 duration and the traffic sat past the right edge. -->
            <v-table density="compact" class="table-stack-xs table-stack-xs--compact">
              <thead>
                <tr>
                  <th>Room</th>
                  <th v-if="scope === 'platform'">Org</th>
                  <th>From</th>
                  <th>Until</th>
                  <th class="text-right">Duration</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(c, i) in detail.calls" :key="i">
                  <td class="font-weight-medium">{{ c.room_name || c.room_id.slice(-6) }}</td>
                  <td v-if="scope === 'platform'" data-label="Org">{{ c.tenant_name || '—' }}</td>
                  <td data-label="From">{{ fmtTime(c.started_at) }}</td>
                  <td data-label="Until">{{ c.ended_at ? fmtTime(c.ended_at) : 'still in call' }}</td>
                  <td data-label="Duration" class="text-right">{{ fmtDuration(c.seconds) }}</td>
                </tr>
              </tbody>
            </v-table>
          </template>

          <template v-if="(detail.tunnels ?? []).length">
            <v-divider class="my-4" />
            <div class="text-subtitle-1 mb-2">Tunnel sessions</div>
            <v-table density="compact" class="table-stack-xs table-stack-xs--compact">
              <thead>
                <tr>
                  <th>Target device</th>
                  <th v-if="scope === 'platform'">Org</th>
                  <th>From</th>
                  <th>Until</th>
                  <th class="text-right">Duration</th>
                  <th class="text-right">Traffic</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(t, i) in detail.tunnels" :key="i">
                  <td class="font-weight-medium">{{ t.agent_display_name || t.agent_name || t.agent_id?.slice(-6) || '—' }}</td>
                  <td v-if="scope === 'platform'" data-label="Org">{{ t.tenant_name || '—' }}</td>
                  <td data-label="From">{{ fmtTime(t.started_at) }}</td>
                  <td data-label="Until">{{ fmtTime(t.ended_at) }}</td>
                  <td data-label="Duration" class="text-right">{{ fmtDuration(t.seconds) }}</td>
                  <td data-label="Traffic" class="text-right" :class="{ 'text-medium-emphasis': !t.bytes_known }">
                    {{ t.bytes_known ? fmtBytes(t.bytes ?? 0) : '—' }}
                  </td>
                </tr>
              </tbody>
            </v-table>
          </template>

          <v-alert v-if="detail.truncated" type="warning" variant="tonal" density="compact" class="mt-3">
            Showing the most recent sessions only — this range holds more than the view can list.
          </v-alert>
        </v-card-text>
      </v-card>
      <v-card v-else>
        <v-card-text class="py-8 text-center">
          <v-progress-circular indeterminate />
        </v-card-text>
      </v-card>
    </v-dialog>
  </div>
</template>

<script setup lang="ts">
// Per-user usage for one org (`scope="org"`) or the whole platform
// (`scope="platform"`). The two differ only in which endpoint answers and
// whether the org column/lane-subtitle is shown, so they share this panel.
import { computed, ref, watch } from 'vue'
import { useDisplay } from 'vuetify'
import { timeFormat } from 'd3-time-format'
import UsageTable from './UsageTable.vue'
import UsageTimeline from './UsageTimeline.vue'
import { useStatsStore } from '@/stores/stats'
import type { UsagePayload, UsageDetailPayload } from '@/stores/stats'
import { formatBytes, formatMinutes, formatDuration } from '@/utils/format'

const props = defineProps<{
  scope: 'org' | 'platform'
  range: string
  /** Required for org scope; narrows the platform view when set. */
  tenantId?: string
}>()

const statsStore = useStatsStore()
const { xs } = useDisplay()
const payload = ref<UsagePayload | null>(null)
const detail = ref<UsageDetailPayload | null>(null)
const loading = ref(false)
const dialog = ref(false)
const selected = ref<string | null>(null)

const fmtBytes = formatBytes
const fmtMinutes = formatMinutes
const fmtDuration = formatDuration
const fmtTimeFn = timeFormat('%b %d, %H:%M')
function fmtTime(unixSecs: number): string {
  return fmtTimeFn(new Date(unixSecs * 1000))
}

const emptyText = computed(() =>
  props.scope === 'platform'
    ? 'No recorded activity across any org in this range'
    : 'No recorded activity in this range',
)

// Range → window bounds for the timeline. Mirrors range_spec() server-side;
// keeping it client-side avoids a round-trip just to learn the floor.
const RANGE_SECS: Record<string, number> = {
  '24h': 86_400,
  '7d': 7 * 86_400,
  '30d': 30 * 86_400,
  '1y': 365 * 86_400,
}
const windowTo = ref(Math.floor(Date.now() / 1000))
const windowFrom = computed(() => windowTo.value - (RANGE_SECS[props.range] ?? 86_400))

const devicesViewed = computed(() => {
  const ids = new Set((detail.value?.viewing ?? []).map((v) => v.agent_id))
  return ids.size
})

async function load() {
  if (props.scope === 'org' && !props.tenantId) return
  loading.value = true
  try {
    payload.value =
      props.scope === 'org'
        ? await statsStore.fetchTenantUsage(props.tenantId as string, props.range)
        : await statsStore.fetchAdminUsage(props.range, props.tenantId)
  } catch {
    payload.value = null
  } finally {
    loading.value = false
  }
}

async function openUser(userId: string) {
  selected.value = userId
  detail.value = null
  dialog.value = true
  // Freeze the window at open time so the bars don't shift under the cursor.
  windowTo.value = Math.floor(Date.now() / 1000)
  try {
    detail.value =
      props.scope === 'org'
        ? await statsStore.fetchTenantUsageDetail(props.tenantId as string, userId, props.range)
        : await statsStore.fetchAdminUsageDetail(userId, props.range, props.tenantId)
  } catch {
    dialog.value = false
  }
}

watch(
  () => [props.range, props.tenantId, props.scope],
  () => {
    windowTo.value = Math.floor(Date.now() / 1000)
    load()
    // A range change invalidates the open detail; refetch it in place.
    if (dialog.value && selected.value) openUser(selected.value)
  },
  { immediate: true },
)

defineExpose({ reload: load })
</script>
