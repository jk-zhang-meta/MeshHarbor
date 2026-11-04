<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <!-- FR-102 P10 — the weekly roll-up: a stored ISO week (Mon–Sun, UTC),
       its headline against the week before and the trailing four, then
       the reports computed for that week. Every section is rendered by
       shape (growth-node): a `not_measured` cell is a muted chip, never
       a 0, and every string is text. -->
  <div>
    <div class="d-flex align-center flex-wrap mb-3" style="gap: 12px">
      <v-text-field
        v-model="week"
        label="ISO week (UTC)"
        placeholder="2026-W41"
        density="compact"
        hide-details
        style="max-width: 180px"
      />
      <v-btn size="small" variant="tonal" :loading="loading" @click="load">Load</v-btn>
      <v-btn size="small" variant="outlined" :loading="running" :disabled="!week" @click="recompute">
        Recompute (no send)
      </v-btn>
      <span v-if="list" class="text-caption text-medium-emphasis">
        {{ list.scheduled ? 'mailed every Monday after the digest hour' : 'the scheduler is off on this server (MESHHARBOR__GROWTH__WEEKLY_ENABLED)' }}
      </span>
    </div>

    <v-alert v-if="message" type="error" variant="tonal" density="compact" class="mb-3">
      {{ message }}
    </v-alert>

    <div v-if="list?.weeks.length" class="d-flex flex-wrap mb-3" style="gap: 6px">
      <v-chip
        v-for="w in list.weeks"
        :key="w.week"
        size="small"
        :variant="w.week === week ? 'elevated' : 'tonal'"
        :color="statusColor(w.status)"
        @click="pick(w.week)"
      >
        {{ w.week }} · {{ w.status }}
      </v-chip>
    </div>

    <template v-if="weekly?.sections">
      <div class="text-caption text-medium-emphasis mb-3">
        {{ weekly.status }} · computed {{ weekly.computed_at ?? '—' }} · sent {{ weekly.sent_at ?? '—' }} ·
        recipients {{ weekly.recipients }} · attempt {{ weekly.attempts }}
        <template v-if="weekly.error"> · {{ weekly.error }}</template>
        · excluded {{ weekly.excluded.users }} users, {{ weekly.excluded.tenants }} orgs
      </div>

      <v-card class="mb-3">
        <v-card-title class="text-subtitle-1">Headline — {{ headline?.week }} ({{ headline?.since }} → {{ headline?.until }})</v-card-title>
        <v-card-text>
          <div class="d-flex flex-wrap" style="gap: 24px">
            <div v-for="(f, label) in headlineFigures" :key="label">
              <div class="text-caption text-medium-emphasis">{{ label }}</div>
              <growth-not-measured v-if="isNotMeasured(f)" :reason="f.not_measured" />
              <span v-else-if="isWeekFigure(f)">
                <span class="text-h6">{{ f.week }}</span>
                <span class="text-caption text-medium-emphasis ml-1">{{ weekFigureLabel(f).replace(/^\d+ /, '') }}</span>
              </span>
            </div>
          </div>
        </v-card-text>
      </v-card>

      <v-row dense>
        <v-col v-for="(section, key) in otherSections" :key="key" cols="12">
          <v-card>
            <v-card-title class="text-subtitle-1">{{ humanKey(String(key)) }}</v-card-title>
            <v-card-text>
              <growth-node :value="section" />
            </v-card-text>
          </v-card>
        </v-col>
      </v-row>
    </template>
    <v-alert v-else-if="!loading" type="info" variant="tonal">
      No roll-up for that week yet. Recompute computes and stores it without mailing.
    </v-alert>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import {
  useGrowthStore,
  humanKey,
  isNotMeasured,
  isWeekFigure,
  weekFigureLabel,
  type DigestStatus,
  type NotMeasured,
  type WeekFigure,
  type Weekly,
  type WeeklyList,
} from '@/stores/growth'
import GrowthNode from '@/components/growth/GrowthNode.vue'
import GrowthNotMeasured from '@/components/growth/GrowthNotMeasured.vue'

const store = useGrowthStore()
const week = ref('')
const weekly = ref<Weekly | null>(null)
const list = ref<WeeklyList | null>(null)
const loading = ref(false)
const running = ref(false)
const message = ref<string | null>(null)

interface Headline {
  week: string
  since: string
  until: string
  signups: WeekFigure
  orgs_created: WeekFigure
  devices_enrolled: WeekFigure | NotMeasured
  active_orgs: WeekFigure | NotMeasured
  website: { visitors: WeekFigure; visits: WeekFigure; pageviews: WeekFigure; reads: WeekFigure } | NotMeasured
}

const headline = computed<Headline | null>(
  () => (weekly.value?.sections?.headline as Headline | undefined) ?? null,
)

const headlineFigures = computed<Record<string, WeekFigure | NotMeasured>>(() => {
  const h = headline.value
  if (!h) return {}
  const out: Record<string, WeekFigure | NotMeasured> = {
    'Sign-ups': h.signups,
    'Orgs created': h.orgs_created,
    'Devices enrolled': h.devices_enrolled,
    'Weekly active orgs': h.active_orgs,
  }
  if (isNotMeasured(h.website)) {
    out['Website'] = h.website
  } else {
    out['Website visitors'] = h.website.visitors
    out['Website pageviews'] = h.website.pageviews
    out['Website reads'] = h.website.reads
  }
  return out
})

const otherSections = computed<Record<string, unknown>>(() => {
  const s = weekly.value?.sections ?? {}
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(s)) if (k !== 'headline') out[k] = v
  return out
})

function statusColor(s: DigestStatus): string {
  if (s === 'sent') return 'success'
  if (s === 'failed') return 'error'
  if (s === 'computing') return 'warning'
  if (s === 'preview') return 'info'
  return 'grey'
}

async function load() {
  loading.value = true
  message.value = null
  try {
    weekly.value = await store.fetchWeekly(week.value || undefined)
    if (weekly.value && !week.value) week.value = weekly.value.week
  } catch (e) {
    message.value = e instanceof Error ? e.message : 'load failed'
  } finally {
    loading.value = false
  }
}

async function loadList() {
  try {
    list.value = await store.fetchWeeklies()
  } catch (e) {
    message.value = e instanceof Error ? e.message : 'list failed'
  }
}

async function recompute() {
  running.value = true
  message.value = null
  try {
    weekly.value = await store.runWeekly(week.value, false)
    await loadList()
  } catch (e) {
    message.value = e instanceof Error ? e.message : 'recompute failed'
  } finally {
    running.value = false
  }
}

async function pick(w: string) {
  week.value = w
  await load()
}

onMounted(async () => {
  await loadList()
  if (list.value?.weeks.length) week.value = list.value.weeks[0].week
  await load()
})
</script>
