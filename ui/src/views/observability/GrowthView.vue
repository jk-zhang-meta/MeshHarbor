<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-container fluid class="pa-2 pa-md-4 pa-xl-6">
    <div class="d-flex align-center flex-wrap mb-2 mb-md-4" style="gap: 12px">
      <div>
        <h1 class="text-h5 text-md-h4">Growth</h1>
        <p class="text-subtitle-2 text-medium-emphasis mb-0">
          Sign-up to value, joined by the campaign key and never by a person
        </p>
      </div>
      <v-spacer />
      <v-btn variant="text" size="small" :to="{ name: 'observability' }" prepend-icon="mdi-arrow-left">
        Observability
      </v-btn>
    </div>

    <v-alert v-if="!isPlatformAdmin" type="info" variant="tonal" class="mt-4">
      This page is limited to platform operators.
    </v-alert>

    <template v-else>
      <!-- FR-116: `show-arrows` — eleven tabs, and below 1280 px Vuetify hides
           the arrows unless asked, so a phone saw ~4 tabs and no sign of the
           rest. -->
      <v-tabs v-model="tab" density="compact" class="mb-3" show-arrows>
        <v-tab value="overview">Overview</v-tab>
        <v-tab value="campaigns">Campaigns</v-tab>
        <v-tab value="channels">Channels</v-tab>
        <v-tab value="content">Content</v-tab>
        <v-tab value="newsletter">Newsletter</v-tab>
        <v-tab value="orgs">Orgs</v-tab>
        <v-tab value="cohorts">Cohorts</v-tab>
        <v-tab value="revenue">Revenue</v-tab>
        <v-tab value="quality">Quality</v-tab>
        <v-tab value="digest">Digest</v-tab>
        <v-tab value="weekly">Weekly</v-tab>
      </v-tabs>

      <v-alert v-if="message" type="error" variant="tonal" density="compact" class="mb-3">
        {{ message }}
      </v-alert>

      <!-- FR-116: no swipe. A sideways swipe across a wide table (the funnel's
           breakdown, the cohort grid) switched the TAB instead of scrolling
           the table; the tabs above are the way to switch. -->
      <v-window v-model="tab" :touch="false">
        <!-- ── Overview ──────────────────────────────────────────────── -->
        <v-window-item value="overview">
          <!-- P10 — the alerts open now, and the ones cleared recently. -->
          <growth-alerts class="mb-3" />
          <v-row dense>
            <v-col cols="12" md="7">
              <v-card>
                <!-- FR-116: on a phone the caption and the number move into
                     the card's text — a title never wraps, so at 360 px the
                     caption pushed the north-star number off the card. -->
                <v-card-title class="text-subtitle-1 d-flex align-center">
                  Weekly active orgs
                  <span class="text-caption text-medium-emphasis ml-2 d-none d-sm-inline">north star · a value event in the week</span>
                  <v-spacer />
                  <span v-if="waoLatest" class="text-h6 d-none d-sm-inline">{{ waoLatest.active_orgs }}</span>
                </v-card-title>
                <v-card-text>
                  <div class="d-sm-none mb-2">
                    <span v-if="waoLatest" class="text-h6 mr-2">{{ waoLatest.active_orgs }}</span>
                    <span class="text-caption text-medium-emphasis">north star · a value event in the week</span>
                  </div>
                  <time-series-chart
                    v-if="waoPoints.length"
                    :points="waoPoints"
                    :series="[{ key: 'active_orgs', label: 'Active orgs' }]"
                    area
                    :height="180"
                    empty-text="No weeks yet"
                  />
                  <growth-not-measured v-else-if="cohorts?.not_measured" :reason="cohorts.not_measured" />
                  <span v-else class="text-medium-emphasis text-body-2">No weeks yet</span>
                </v-card-text>
              </v-card>
            </v-col>
            <v-col cols="12" md="5">
              <v-card class="fill-height">
                <v-card-title class="text-subtitle-1">Coverage</v-card-title>
                <v-card-text>
                  <template v-if="coverage">
                    <div class="text-h5">{{ coverageRatio }}</div>
                    <div class="text-caption text-medium-emphasis">
                      {{ coverage.purestat_signup_goals }} purestat sign-up goals ÷
                      {{ coverage.server_signups }} server sign-ups
                      <template v-if="coverage.ratio == null"> · n &lt; {{ coverage.n_floor }}, no ratio</template>
                    </div>
                  </template>
                  <growth-not-measured
                    v-else
                    :reason="coverageReason ?? 'the daily digest has not run yet'"
                  />
                </v-card-text>
              </v-card>
            </v-col>
          </v-row>

          <v-card class="mt-3">
            <v-card-title class="text-subtitle-1 d-flex align-center flex-wrap" style="gap: 8px">
              The account funnel
              <span v-if="funnel" class="text-caption text-medium-emphasis text-wrap">
                {{ shortDate(funnel.since) }} → {{ shortDate(funnel.until) }} · org ≤
                {{ funnel.windows.org_days }}d · device ≤ {{ funnel.windows.activation_days }}d · value ≤
                {{ funnel.windows.value_days }}d
              </span>
              <v-spacer />
              <v-select
                v-model="funnelBy"
                :items="dimensionItems"
                label="Break down by"
                density="compact"
                hide-details
                clearable
                style="max-width: 220px"
                @update:model-value="loadFunnel"
              />
            </v-card-title>
            <v-card-text>
              <div v-if="funnel" class="funnel-steps">
                <div v-for="s in funnelSteps" :key="s.name" class="funnel-step">
                  <div class="text-caption text-medium-emphasis">{{ s.label }}</div>
                  <template v-if="s.notMeasured">
                    <growth-not-measured :reason="s.notMeasured" />
                  </template>
                  <template v-else>
                    <div class="text-h5">{{ s.count }}</div>
                    <div class="text-caption text-medium-emphasis">
                      <template v-if="s.rate != null">{{ s.rate }}% of {{ s.settled }} settled</template>
                      <template v-else-if="s.settled != null">{{ s.settled }} settled · n &lt; 30</template>
                      <template v-if="s.pending"> · {{ s.pending }} pending</template>
                    </div>
                  </template>
                </div>
              </div>

              <div class="d-flex flex-wrap mt-4" style="gap: 24px">
                <div>
                  <div class="text-caption text-medium-emphasis">Sign-up → first device</div>
                  <growth-percentiles :p="funnel?.time_to_value.first_device ?? null" />
                </div>
                <div>
                  <div class="text-caption text-medium-emphasis">Sign-up → first value</div>
                  <growth-percentiles :p="funnel?.time_to_value.first_value ?? null" />
                </div>
              </div>

              <template v-if="funnel?.by && funnel.buckets.length">
                <v-divider class="my-3" />
                <div class="text-caption text-medium-emphasis mb-1">By {{ funnel.by }}</div>
                <v-table density="compact" class="growth-wide">
                  <thead>
                    <tr>
                      <th class="text-left">{{ funnel.by }}</th>
                      <th class="text-right">sign-ups</th>
                      <th class="text-right">orgs</th>
                      <th class="text-right">activated</th>
                      <th class="text-right">first value</th>
                      <th class="text-right">paid</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="b in funnel.buckets" :key="b.key ?? '(none)'">
                      <td>{{ b.key ?? '(none)' }}</td>
                      <td class="text-right">{{ b.signups }}</td>
                      <td class="text-right">{{ b.org_created.count }}</td>
                      <td class="text-right">{{ b.activated?.count ?? '—' }}</td>
                      <td class="text-right">{{ b.first_value?.count ?? '—' }}</td>
                      <td class="text-right">{{ b.paid?.count ?? '—' }}</td>
                    </tr>
                  </tbody>
                </v-table>
              </template>
            </v-card-text>
          </v-card>
        </v-window-item>

        <!-- ── Campaigns (P6) ────────────────────────────────────────── -->
        <!-- Lazily rendered: the component loads its own range on first open. -->
        <v-window-item value="campaigns">
          <growth-campaigns />
        </v-window-item>

        <!-- ── Channels (P8) ─────────────────────────────────────────── -->
        <v-window-item value="channels">
          <growth-channels />
        </v-window-item>

        <!-- ── Content (P7) ──────────────────────────────────────────── -->
        <!-- Lazily rendered: the component loads its own range on first open. -->
        <v-window-item value="content">
          <growth-content />
        </v-window-item>

        <!-- ── Newsletter (P5) ───────────────────────────────────────── -->
        <v-window-item value="newsletter">
          <growth-newsletter />
        </v-window-item>

        <!-- ── Orgs ──────────────────────────────────────────────────── -->
        <v-window-item value="orgs">
          <v-card>
            <v-card-text>
              <v-text-field
                v-model="orgSearch"
                label="Filter by name"
                density="compact"
                hide-details
                clearable
                prepend-inner-icon="mdi-magnify"
                class="mb-2"
                style="max-width: 320px"
              />
              <v-alert
                v-if="orgs?.not_measured"
                type="info"
                variant="tonal"
                density="compact"
                class="mb-2"
              >
                Weekly activity {{ orgs.not_measured }}.
              </v-alert>
              <!-- FR-120 P5 — a card per org below 600 px (table-stack-xs), so
                   `timeline`, the rightmost column, stays on screen. -->
              <v-table density="compact" class="growth-wide table-stack-xs table-stack-xs--compact">
                <thead>
                  <tr>
                    <th class="text-left">Org</th>
                    <th class="text-left">Channel</th>
                    <th class="text-left">Plan</th>
                    <th class="text-right">Devices</th>
                    <th class="text-left">Last value</th>
                    <th class="text-left">Activity (12w)</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="o in filteredOrgs" :key="o.tenant_id">
                    <td>
                      {{ o.name }}
                      <v-chip v-if="o.archived" size="x-small" variant="tonal" class="ml-1">archived</v-chip>
                      <v-chip v-if="o.at_risk" size="x-small" color="warning" class="ml-1">at risk</v-chip>
                    </td>
                    <td data-label="Channel">
                      {{ o.owner?.channel ?? 'unknown' }}
                      <span v-if="o.owner?.source" class="text-caption text-medium-emphasis">
                        / {{ o.owner.source }}
                      </span>
                    </td>
                    <td data-label="Plan">{{ o.plan }}<span v-if="o.billing_status" class="text-caption text-medium-emphasis"> · {{ o.billing_status }}</span></td>
                    <td class="text-right" data-label="Devices">
                      <template v-if="o.devices">{{ o.devices.live }}/{{ o.devices.enrolled }}</template>
                      <template v-else>—</template>
                    </td>
                    <td data-label="Last value">{{ o.last_value_day ?? '—' }}</td>
                    <td data-label="Activity (12w)">
                      <span class="activity-strip">
                        <span
                          v-for="(w, i) in o.weeks"
                          :key="i"
                          class="week-dot"
                          :class="{ active: w }"
                          :title="orgs?.weeks[i]"
                        />
                      </span>
                    </td>
                    <td class="text-right">
                      <v-btn size="x-small" variant="text" @click="openTimeline(o.tenant_id)">timeline</v-btn>
                    </td>
                  </tr>
                </tbody>
              </v-table>
              <div v-if="orgs?.truncated" class="text-caption text-medium-emphasis mt-1">
                Showing the first {{ orgs.limit }} orgs.
              </div>
            </v-card-text>
          </v-card>
        </v-window-item>

        <!-- ── Cohorts ───────────────────────────────────────────────── -->
        <v-window-item value="cohorts">
          <v-card>
            <v-card-title class="text-subtitle-1">
              Weekly retention — active orgs by weeks since creation
            </v-card-title>
            <v-card-text>
              <growth-not-measured v-if="cohorts?.not_measured" :reason="cohorts.not_measured" />
              <v-table v-else-if="cohorts?.cohorts?.length" density="compact" class="growth-wide cohort-grid">
                <thead>
                  <tr>
                    <th class="text-left">Cohort</th>
                    <th class="text-right">Size</th>
                    <th
                      v-for="k in cohorts.weeks_since + 1"
                      :key="k"
                      class="text-right"
                      :class="{ highlight: cohorts.highlight.includes(k - 1) }"
                    >
                      W{{ k - 1 }}
                    </th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="c in cohorts.cohorts" :key="c.week">
                    <td>{{ c.week }}</td>
                    <td class="text-right">{{ c.size }}</td>
                    <td
                      v-for="(cell, k) in c.active"
                      :key="k"
                      class="text-right cohort-cell"
                      :class="[{ highlight: cohorts.highlight.includes(k), open: k > c.closed_through && cell != null }]"
                      :style="cellStyle(cell, c.size)"
                    >
                      {{ cell == null ? '' : cell }}
                    </td>
                  </tr>
                </tbody>
              </v-table>
              <span v-else class="text-medium-emphasis text-body-2">No cohorts yet.</span>
            </v-card-text>
          </v-card>
        </v-window-item>

        <!-- ── Revenue (P4) ──────────────────────────────────────────── -->
        <v-window-item value="revenue">
          <growth-revenue />
        </v-window-item>

        <!-- ── Quality (P9a) ─────────────────────────────────────────── -->
        <!-- Lazily rendered: the component loads its own range on first open. -->
        <v-window-item value="quality">
          <growth-quality />
        </v-window-item>

        <!-- ── Digest (P1d) ──────────────────────────────────────────── -->
        <v-window-item value="digest">
          <div class="d-flex align-center flex-wrap mb-3" style="gap: 12px">
            <v-text-field
              v-model="day"
              type="date"
              label="Day (UTC)"
              density="compact"
              hide-details
              style="max-width: 200px"
              :max="yesterday"
            />
            <v-btn size="small" variant="tonal" :loading="loading" @click="loadDigest">Load</v-btn>
            <v-btn
              size="small"
              variant="outlined"
              :loading="running"
              :disabled="!day"
              @click="recompute"
            >
              Recompute (no send)
            </v-btn>
            <v-switch
              v-model="includeInternal"
              label="Include internal (live preview)"
              density="compact"
              hide-details
              color="warning"
              @update:model-value="loadDigest"
            />
          </div>

          <div v-if="store.digests.length" class="d-flex flex-wrap mb-3" style="gap: 6px">
            <v-chip
              v-for="dd in store.digests"
              :key="dd.day"
              size="small"
              :variant="dd.day === day ? 'elevated' : 'tonal'"
              :color="statusColor(dd.status)"
              @click="pickDay(dd.day)"
            >
              {{ dd.day }} · {{ dd.status }}
            </v-chip>
          </div>

          <template v-if="sections">
            <div class="text-caption text-medium-emphasis mb-3">
              <template v-if="digest && !preview">
                {{ digest.status }} · computed {{ digest.computed_at ?? '—' }} · sent
                {{ digest.sent_at ?? '—' }} · recipients {{ digest.recipients }} · attempt
                {{ digest.attempts }}
                <template v-if="digest.error"> · {{ digest.error }}</template>
              </template>
              <template v-else-if="preview">
                live preview{{ preview.include_internal ? ' — INTERNAL INCLUDED' : '' }} (not stored,
                not mailed)
              </template>
              · excluded {{ excluded?.users ?? 0 }} users, {{ excluded?.tenants ?? 0 }} orgs
            </div>

            <v-row dense>
              <v-col v-for="(section, key) in sections" :key="key" cols="12" :md="wide(key) ? 12 : 6">
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
            No digest for that day yet. Recompute computes and stores it without mailing.
          </v-alert>
        </v-window-item>

        <!-- ── Weekly (P10) ──────────────────────────────────────────── -->
        <!-- Lazily rendered: the component loads the stored weeks on first open. -->
        <v-window-item value="weekly">
          <growth-weekly />
        </v-window-item>
      </v-window>
    </template>

    <!-- The org timeline drawer. FR-116: full width on a phone, with a close
         button — at 440 px it covered a 390 px screen whole, leaving no scrim
         to tap and no way out. -->
    <v-navigation-drawer
      v-model="timelineOpen"
      location="right"
      temporary
      :width="xs ? displayWidth : 440"
    >
      <template v-if="timeline">
        <v-list-item :title="timeline.name" :subtitle="`${timeline.plan}${timeline.billing_status ? ' · ' + timeline.billing_status : ''}`">
          <template v-if="xs" #append>
            <v-btn icon="mdi-close" variant="text" size="small" aria-label="Close" @click="timelineOpen = false" />
          </template>
        </v-list-item>
        <v-divider />
        <v-timeline v-if="timeline.events.length" density="compact" side="end" class="pa-3">
          <v-timeline-item
            v-for="(e, i) in timeline.events"
            :key="i"
            size="x-small"
            :dot-color="eventColor(e.kind)"
          >
            <div class="text-body-2">{{ humanKey(e.kind) }}</div>
            <div class="text-caption text-medium-emphasis">{{ e.at }}</div>
            <div v-if="e.attribution" class="text-caption">
              {{ e.attribution.channel }}<span v-if="e.attribution.source"> / {{ e.attribution.source }}</span>
              <span v-if="e.attribution.campaign"> · {{ e.attribution.campaign }}</span>
            </div>
            <div v-if="e.os" class="text-caption">{{ e.os }}</div>
            <div v-if="e.value_kinds" class="text-caption">{{ e.value_kinds.join(', ') }}</div>
          </v-timeline-item>
        </v-timeline>
        <div class="pa-3 text-caption text-medium-emphasis">
          <div>{{ timeline.members }} members</div>
          <div v-if="timeline.totals">
            RC sessions {{ timeline.totals.rc_sessions }} · minutes {{ timeline.totals.rc_session_minutes }}
          </div>
          <div v-if="timeline.not_measured">Activity {{ timeline.not_measured }}.</div>
        </div>
        <!-- P4 — what Stripe said, oldest first. -->
        <div class="px-3 pb-3">
          <div class="text-caption text-medium-emphasis mb-1">Plan changes and invoices</div>
          <growth-not-measured v-if="planHistory.reason" :reason="planHistory.reason" />
          <template v-else-if="planHistory.rows.length">
            <div v-for="(p, i) in planHistory.rows" :key="i" class="text-caption">
              {{ p.at.slice(0, 10) }} · {{ humanKey(p.kind) }}
              <template v-if="p.plan"> · {{ p.plan }}</template>
              <template v-if="p.seats != null"> · {{ p.seats }} seats</template>
              <template v-if="p.amount_cents != null">
                · {{ (p.amount_cents / 100).toFixed(2) }} {{ (p.currency ?? '').toUpperCase() }}
              </template>
              <template v-if="p.status"> · {{ p.status }}</template>
            </div>
          </template>
          <span v-else class="text-caption text-medium-emphasis">None on record.</span>
        </div>
      </template>
      <div v-else class="pa-4"><v-progress-circular indeterminate size="24" /></div>
    </v-navigation-drawer>
  </v-container>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useDisplay } from 'vuetify'
import { useAuthStore } from '@/stores/auth'
import {
  useGrowthStore,
  humanKey,
  isNotMeasured,
  type Digest,
  type DigestPreview,
  type DigestStatus,
  type ExcludedCounts,
  type FunnelReport,
  type FunnelDimension,
  type CohortsReport,
  type OrgsReport,
  type OrgTimeline,
  type Percentiles,
  type PlanChange,
  rateIfEnough,
} from '@/stores/growth'
import GrowthAlerts from '@/components/growth/GrowthAlerts.vue'
import GrowthCampaigns from '@/components/growth/GrowthCampaigns.vue'
import GrowthChannels from '@/components/growth/GrowthChannels.vue'
import GrowthContent from '@/components/growth/GrowthContent.vue'
import GrowthNewsletter from '@/components/growth/GrowthNewsletter.vue'
import GrowthWeekly from '@/components/growth/GrowthWeekly.vue'
import GrowthNode from '@/components/growth/GrowthNode.vue'
import GrowthNotMeasured from '@/components/growth/GrowthNotMeasured.vue'
import GrowthPercentiles from '@/components/growth/GrowthPercentiles.vue'
import GrowthQuality from '@/components/growth/GrowthQuality.vue'
import GrowthRevenue from '@/components/growth/GrowthRevenue.vue'
import TimeSeriesChart from '@/components/stats/TimeSeriesChart.vue'

const authStore = useAuthStore()
const store = useGrowthStore()
// FR-116 — the phone layout: the north-star number under its title, and the
// org timeline drawer full width with its own close button.
const { xs, width: displayWidth } = useDisplay()
const isPlatformAdmin = computed(() => authStore.user?.is_platform_admin === true)

const tab = ref('overview')
const message = ref<string | null>(null)

// ── Overview + Cohorts + Orgs state ──────────────────────────────────────
const funnel = ref<FunnelReport | null>(null)
const funnelBy = ref<FunnelDimension | null>(null)
const cohorts = ref<CohortsReport | null>(null)
const orgs = ref<OrgsReport | null>(null)
const orgSearch = ref('')

const dimensionItems = [
  { title: 'Source', value: 'source' },
  { title: 'Medium', value: 'medium' },
  { title: 'Campaign', value: 'campaign' },
  { title: 'Content', value: 'content' },
  { title: 'Channel', value: 'channel' },
  { title: 'Self-reported', value: 'self_reported' },
  { title: 'Landing path', value: 'landing_path' },
]

const waoPoints = computed(() =>
  (cohorts.value?.wao ?? []).map((w) => ({
    t: Math.floor(new Date(`${w.start}T00:00:00Z`).getTime() / 1000),
    active_orgs: w.active_orgs,
  })),
)
const waoLatest = computed(() => cohorts.value?.wao?.[cohorts.value.wao.length - 1] ?? null)

const funnelSteps = computed(() => {
  const f = funnel.value
  if (!f) return []
  const row = (name: string, label: string, s: { count: number; pending: number; settled: number } | null) => ({
    name,
    label,
    notMeasured: s ? undefined : f.not_measured[name],
    count: s?.count ?? 0,
    pending: s?.pending ?? 0,
    settled: s?.settled ?? null,
    rate: s ? rateIfEnough(s.count, s.settled) : null,
  })
  return [
    { name: 'signup', label: 'Sign-ups', count: f.steps.signup, pending: 0, settled: null, rate: null, notMeasured: undefined },
    row('org_created', 'Org created (≤ 7d)', f.steps.org_created),
    row('activated', 'Activated (device ≤ 7d)', f.steps.activated),
    row('first_value', 'First value (≤ 14d)', f.steps.first_value),
    // P4 — no window: the orgs that have paid so far.
    row('paid', 'Paid (so far)', f.steps.paid),
  ]
})

// Coverage comes from the latest stored digest's headline.
const coverage = ref<{ purestat_signup_goals: number; server_signups: number; ratio: number | null; n_floor: number } | null>(null)
const coverageReason = ref<string | null>(null)
const coverageRatio = computed(() =>
  coverage.value?.ratio != null ? `${Math.round(coverage.value.ratio * 1000) / 10}%` : '—',
)

// ── Timeline drawer ───────────────────────────────────────────────────────
const timelineOpen = ref(false)
const timeline = ref<OrgTimeline | null>(null)

// P4 — the org's billing history, or why there is none to show.
const planHistory = computed<{ reason: string | null; rows: PlanChange[] }>(() => {
  const h = timeline.value?.plan_history
  if (!h) return { reason: null, rows: [] }
  if (isNotMeasured(h)) return { reason: h.not_measured, rows: [] }
  return { reason: null, rows: h }
})

const filteredOrgs = computed(() => {
  const list = orgs.value?.orgs ?? []
  const q = orgSearch.value.trim().toLowerCase()
  return q ? list.filter((o) => o.name.toLowerCase().includes(q)) : list
})

function shortDate(iso: string): string {
  return iso.slice(0, 10)
}

function cellStyle(cell: number | null, size: number): Record<string, string> {
  if (cell == null || size === 0) return {}
  const pct = cell / size
  return { background: `rgba(var(--v-theme-primary), ${(0.08 + pct * 0.5).toFixed(3)})` }
}

function eventColor(kind: string): string {
  if (kind === 'signup') return 'grey'
  if (kind === 'org_created') return 'info'
  if (kind === 'first_device') return 'primary'
  if (kind === 'first_value') return 'success'
  if (kind === 'first_paid') return 'amber'
  return 'grey'
}

async function openTimeline(tenantId: string) {
  timeline.value = null
  timelineOpen.value = true
  try {
    timeline.value = await store.fetchTimeline(tenantId)
  } catch (e) {
    message.value = e instanceof Error ? e.message : 'timeline failed'
    timelineOpen.value = false
  }
}

async function loadFunnel() {
  try {
    funnel.value = await store.fetchFunnel({ by: funnelBy.value ?? undefined })
  } catch (e) {
    message.value = e instanceof Error ? e.message : 'funnel failed'
  }
}

async function loadCohorts() {
  try {
    cohorts.value = await store.fetchCohorts()
  } catch (e) {
    message.value = e instanceof Error ? e.message : 'cohorts failed'
  }
}

async function loadOrgs() {
  try {
    orgs.value = await store.fetchOrgs()
  } catch (e) {
    message.value = e instanceof Error ? e.message : 'orgs failed'
  }
}

async function loadCoverage() {
  try {
    const d = await store.fetchDigest()
    const head = d?.sections?.headline as { coverage?: unknown } | undefined
    const cov = head?.coverage as Record<string, unknown> | undefined
    if (cov && typeof cov.server_signups === 'number') {
      coverage.value = cov as never
    } else if (cov && typeof cov.not_measured === 'string') {
      coverageReason.value = cov.not_measured
    }
  } catch {
    // Coverage is a convenience on the overview; its absence is not an error.
  }
}

// ── Digest tab (P1d) ──────────────────────────────────────────────────────
const yesterday = (() => {
  const d = new Date()
  d.setUTCDate(d.getUTCDate() - 1)
  return d.toISOString().slice(0, 10)
})()
const day = ref(yesterday)
const includeInternal = ref(false)
const loading = ref(false)
const running = ref(false)
const digest = ref<Digest | null>(null)
const preview = ref<DigestPreview | null>(null)

const sections = computed<Record<string, unknown> | null>(
  () => preview.value?.sections ?? digest.value?.sections ?? null,
)
const excluded = computed<ExcludedCounts | null>(
  () => preview.value?.excluded ?? digest.value?.excluded ?? null,
)

// `install` since P3b: the wizard steps table carries five figure columns;
// `quality` since P9a: the per-version table carries eight.
const WIDE = new Set(['signups', 'campaigns', 'website', 'blog', 'newsletter', 'revenue', 'install', 'quality'])
function wide(key: string | number): boolean {
  return WIDE.has(String(key))
}
function statusColor(s: DigestStatus): string {
  if (s === 'sent') return 'success'
  if (s === 'failed') return 'error'
  if (s === 'computing') return 'warning'
  if (s === 'preview') return 'info'
  return 'grey'
}

async function loadDigest() {
  if (!isPlatformAdmin.value) return
  loading.value = true
  message.value = null
  try {
    if (includeInternal.value) {
      digest.value = null
      preview.value = await store.fetchPreview(day.value, true)
    } else {
      preview.value = null
      digest.value = await store.fetchDigest(day.value)
    }
  } catch (e) {
    message.value = e instanceof Error ? e.message : 'load failed'
  } finally {
    loading.value = false
  }
}

async function recompute() {
  running.value = true
  message.value = null
  try {
    includeInternal.value = false
    preview.value = null
    digest.value = await store.runDigest(day.value, false)
    await store.fetchDigests()
  } catch (e) {
    message.value = e instanceof Error ? e.message : 'recompute failed'
  } finally {
    running.value = false
  }
}

async function pickDay(d: string) {
  day.value = d
  await loadDigest()
}

// Load each tab's data the first time it is opened. Watches the admin flag
// too: the shell renders before `/auth/me` answers (stores/auth.ts), so on a
// hard refresh or a deep link the first run met an unknown user, returned —
// and nothing ran it again until the tab changed, leaving the Overview empty.
const loaded = new Set<string>()
watch(
  [tab, isPlatformAdmin],
  async ([t]) => {
    if (!isPlatformAdmin.value || loaded.has(t)) return
    loaded.add(t)
    if (t === 'overview') {
      await Promise.all([loadFunnel(), cohorts.value ? Promise.resolve() : loadCohorts(), loadCoverage()])
    } else if (t === 'cohorts') {
      if (!cohorts.value) await loadCohorts()
    } else if (t === 'orgs') {
      await loadOrgs()
    } else if (t === 'digest') {
      await store.fetchDigests()
      if (store.digests.length) day.value = store.digests[0].day
      await loadDigest()
    }
  },
  { immediate: true },
)
</script>

<style scoped>
.funnel-steps {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
}
.funnel-step {
  flex: 1 1 140px;
  min-width: 120px;
  padding: 8px 12px;
  border: 1px solid rgba(var(--v-border-color), var(--v-border-opacity));
  border-radius: 6px;
}
.growth-wide {
  max-width: 100%;
  overflow-x: auto;
}
.cohort-grid th.highlight,
.cohort-cell.highlight {
  font-weight: 600;
}
.cohort-cell.open {
  opacity: 0.55;
}
.activity-strip {
  display: inline-flex;
  gap: 2px;
}
.week-dot {
  width: 8px;
  height: 14px;
  border-radius: 2px;
  background: rgba(var(--v-theme-on-surface), 0.12);
}
.week-dot.active {
  background: rgb(var(--v-theme-success));
}
</style>
