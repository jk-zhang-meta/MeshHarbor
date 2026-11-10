<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-container fluid class="pa-2 pa-md-4 pa-xl-6">
    <div class="d-flex align-center flex-wrap mb-2 mb-md-4" style="gap: 12px">
      <div>
        <h1 class="text-h5 text-md-h4">Observability</h1>
        <p class="text-subtitle-2 text-medium-emphasis mb-0">
          Relay cluster, orgs and calls — platform view
        </p>
      </div>
      <v-spacer />
      <v-btn
        v-if="isPlatformAdmin"
        variant="tonal"
        size="small"
        class="mr-2"
        append-icon="mdi-arrow-right"
        :to="{ name: 'observability-growth' }"
      >
        Growth
      </v-btn>
      <range-picker v-if="isPlatformAdmin" v-model="range" />
    </div>

    <v-alert v-if="!isPlatformAdmin" type="info" variant="tonal" class="mt-4">
      This page is limited to platform operators.
    </v-alert>

    <template v-else>
      <!-- ── Relay fleet ─────────────────────────────────────────────── -->
      <h2 class="text-h6 mb-2">Relay fleet (coturn + DERP)</h2>
      <v-row dense>
        <v-col
          v-for="r in regionCards"
          :key="r.id"
          cols="12"
          sm="6"
          md="4"
          lg="3"
        >
          <v-card
            :variant="r.id === selectedRegion ? 'tonal' : 'elevated'"
            hover
            @click="selectedRegion = r.id"
          >
            <v-card-text>
              <div class="d-flex align-center">
                <span class="text-subtitle-1 font-weight-medium">{{ r.id }}</span>
                <span v-if="r.workers > 1" class="text-caption text-medium-emphasis ml-2">
                  {{ r.workers }} workers
                </span>
                <v-spacer />
                <v-chip
                  v-if="!r.monitored"
                  size="x-small"
                  color="grey"
                  variant="tonal"
                >not monitored</v-chip>
                <v-chip
                  v-else-if="r.healthy === false"
                  size="x-small"
                  color="error"
                >down</v-chip>
                <v-chip v-else-if="r.busy" size="x-small" color="warning">busy</v-chip>
                <v-chip v-else size="x-small" color="success" variant="tonal">ok</v-chip>
              </div>
              <div class="text-caption text-medium-emphasis mt-1" style="min-height: 40px">
                <template v-if="r.monitored && r.latest">
                  load {{ fmt(r.latest.load1) }} · tx {{ fmt(r.latest.tx_mbps) }} Mbps · rx
                  {{ fmt(r.latest.rx_mbps) }} Mbps<br />
                  mem free {{ fmtPct(r.latest.mem_available_pct) }} · allocs
                  {{ fmt(r.latest.allocations) }} · derp {{ fmt(r.latest.derp_registrations) }}
                  <br />
                  poll rtt {{ fmt(r.latest.poll_rtt_ms) }} ms
                  <template v-if="r.agentRtt"> · fleet rtt {{ fmt(r.agentRtt) }} ms</template>
                </template>
                <template v-else-if="!r.monitored">
                  no /stats endpoint (central fleet) — TURN still served
                </template>
                <template v-else>no samples yet</template>
              </div>
            </v-card-text>
          </v-card>
        </v-col>
      </v-row>

      <v-row v-if="selectedRegion" class="mt-1">
        <v-col cols="12" md="6">
          <v-card>
            <v-card-title class="text-subtitle-1">
              {{ selectedRegion }} — availability &amp; latency
            </v-card-title>
            <v-card-text>
              <time-series-chart
                :points="history?.series ?? []"
                :series="[
                  { key: 'healthy_pct', label: 'Healthy %' },
                  { key: 'poll_rtt_ms', label: 'Poll RTT ms' },
                ]"
              />
            </v-card-text>
          </v-card>
        </v-col>
        <v-col cols="12" md="6">
          <v-card>
            <v-card-title class="text-subtitle-1">
              {{ selectedRegion }} — load &amp; traffic
            </v-card-title>
            <v-card-text>
              <time-series-chart
                :points="history?.series ?? []"
                :series="[
                  { key: 'load1', label: 'load1' },
                  { key: 'tx_mbps', label: 'TX Mbps' },
                  { key: 'rx_mbps', label: 'RX Mbps' },
                  { key: 'allocations', label: 'TURN allocs' },
                ]"
              />
            </v-card-text>
          </v-card>
        </v-col>
      </v-row>

      <!-- ── Cost & usage (FR-20 P5) ─────────────────────────────────── -->
      <div class="d-flex align-center mt-6 mb-2" style="gap: 12px">
        <h2 class="text-h6">Cost &amp; usage</h2>
        <span class="text-caption text-medium-emphasis">
          measured over {{ range }}
        </span>
      </div>

      <!--
        The two headline cards. Both are deliberately allowed to say "no data"
        instead of "0" — a fabricated zero here reads as "we relay nothing and
        it costs us nothing", which are the two most expensive claims on the
        page to get wrong.
      -->
      <v-row dense>
        <v-col cols="12" sm="6" md="4">
          <v-card>
            <v-card-text>
              <div class="text-caption text-medium-emphasis">Relayed connections</div>
              <div class="text-h5">
                <template v-if="relayedPct !== null">{{ relayedPct }}%</template>
                <span v-else class="text-medium-emphasis text-h6">no reporters</span>
              </div>
              <div class="text-caption text-medium-emphasis mt-1">
                share of peer links currently <em>on</em> a relay carrier.
                <strong>Connections, not bytes</strong> — direct traffic is
                deliberately never measured, so a byte share is not computable.
                Agent-reported, and it counts freshly-created pairs that
                start relayed and are still upgrading, so read the trend
                rather than the absolute. An alarm, not a bill.
              </div>
            </v-card-text>
          </v-card>
        </v-col>

        <v-col v-for="m in fleetMeters" :key="m.key" cols="12" sm="6" md="4">
          <v-card>
            <v-card-text>
              <div class="text-caption text-medium-emphasis">{{ m.label }}</div>
              <div v-if="!m.monitored" class="text-h6 text-medium-emphasis">
                not monitored
              </div>
              <div v-else class="text-h5">{{ m.total }}</div>
              <div class="text-caption text-medium-emphasis mt-1">
                <template v-if="!m.monitored">{{ m.why }}</template>
                <template v-else-if="m.cost !== null">{{ m.cost }} over {{ range }}</template>
                <template v-else>not priced — set it in config/relay-costs.toml</template>
              </div>
            </v-card-text>
          </v-card>
        </v-col>
      </v-row>

      <v-alert
        v-if="cost && cost.enabled && !cost.priced"
        type="info"
        variant="tonal"
        density="compact"
        class="mt-2"
      >
        No unit costs are configured, so every cost below reads
        <strong>not priced</strong> rather than 0.00. Set them in
        <code>config/relay-costs.toml</code> (or <code>MESHHARBOR__RELAY_COSTS__*</code>).
      </v-alert>

      <v-card class="mt-2">
        <v-data-table
          :headers="costHeaders"
          :items="costRows"
          :items-per-page="10"
          density="compact"
          class="text-body-2"
        >
          <template #item.relay="{ item }">{{ item.relay }}</template>
          <template #item.sfu="{ item }">{{ item.sfu }}</template>
          <template #item.cost="{ item }">
            <span :class="item.cost === null ? 'text-medium-emphasis' : ''">
              {{ item.cost === null ? 'not priced' : item.cost }}
            </span>
          </template>
          <template #item.mrr="{ item }">
            <span :title="item.mrrTitle">{{ item.mrr }}</span>
          </template>
          <template #item.margin="{ item }">
            <span
              :class="item.marginClass"
              :title="'list-price estimate over ' + range + ', not billed revenue'"
            >
              {{ item.margin }}
            </span>
          </template>
        </v-data-table>
      </v-card>
      <p class="text-caption text-medium-emphasis mt-1 mb-0">
        MRR and margin are <strong>list-price estimates</strong> (plan price x
        seats, pro-rated to {{ range }}), not billed revenue — Stripe holds the
        real amounts, and discounts, trials and annual terms are not reflected
        here. Cost counts only what we measured ourselves on our own relays.
      </p>

      <!-- ── Orgs ────────────────────────────────────────────────────── -->
      <div class="d-flex align-center mt-6 mb-2" style="gap: 12px">
        <h2 class="text-h6">Organizations</h2>
        <span class="text-caption text-medium-emphasis">
          {{ orgRows.length }} of {{ allOrgRows.length }}
        </span>
        <v-spacer />
        <v-switch
          v-model="showInactiveOrgs"
          density="compact"
          hide-details
          color="primary"
          :label="`Show inactive (${inactiveCount})`"
        />
      </div>
      <v-card>
        <v-table density="compact">
          <thead>
            <tr>
              <th>Org</th>
              <th class="text-right">Members</th>
              <th class="text-right">Machines online</th>
              <th class="text-right">Calls (30d)</th>
              <th class="text-right">Minutes (30d)</th>
              <th />
            </tr>
          </thead>
          <tbody>
            <tr v-for="o in orgRows" :key="o.id" :class="{ 'text-medium-emphasis': !o.active }">
              <td>
                {{ o.name }}
                <v-chip v-if="!o.active" size="x-small" variant="tonal" class="ml-2">idle</v-chip>
              </td>
              <td class="text-right">{{ o.members }}</td>
              <td class="text-right">{{ o.online }} / {{ o.total }}</td>
              <td class="text-right">{{ o.calls }}</td>
              <td class="text-right">{{ Math.round(o.minutes) }}</td>
              <td class="text-right">
                <v-btn
                  size="x-small"
                  variant="tonal"
                  @click="selectOrg(o.id)"
                >inspect</v-btn>
              </td>
            </tr>
            <tr v-if="orgRows.length === 0">
              <td colspan="6" class="text-medium-emphasis">
                {{
                  allOrgRows.length
                    ? 'No active organizations — toggle "Show inactive" to see the rest'
                    : 'No organizations yet'
                }}
              </td>
            </tr>
          </tbody>
        </v-table>
      </v-card>

      <v-row v-if="selectedOrg" class="mt-1">
        <v-col cols="12" md="6">
          <v-card>
            <v-card-title class="text-subtitle-1">
              {{ orgName(selectedOrg) }} — machines online
            </v-card-title>
            <v-card-text>
              <time-series-chart
                :points="orgMachines?.series ?? []"
                :series="[{ key: 'online', label: 'Online' }]"
                area
              />
            </v-card-text>
          </v-card>
        </v-col>
        <v-col cols="12" md="6">
          <v-card>
            <v-card-title class="text-subtitle-1">
              {{ orgName(selectedOrg) }} — participant-minutes
            </v-card-title>
            <v-card-text>
              <time-series-chart
                :points="orgCallMinutes"
                :series="[{ key: 'participant_minutes', label: 'Participant-minutes' }]"
                area
              />
            </v-card-text>
          </v-card>
        </v-col>
      </v-row>

      <!-- ── Users / sessions ────────────────────────────────────────── -->
      <h2 class="text-h6 mt-6 mb-2">Users &amp; sessions</h2>
      <v-row>
        <v-col cols="12" md="8">
          <v-card>
            <v-card-title class="text-subtitle-1">Connections</v-card-title>
            <v-card-text>
              <time-series-chart
                :points="users?.series ?? []"
                :series="[
                  { key: 'sessions', label: 'Sessions' },
                  { key: 'users', label: 'Distinct users' },
                ]"
                area
                empty-text="No sessions recorded in this range"
              />
            </v-card-text>
          </v-card>
        </v-col>
        <v-col cols="12" md="4">
          <v-card>
            <v-card-title class="text-subtitle-1">Session length</v-card-title>
            <v-card-text>
              <v-table density="compact">
                <tbody>
                  <tr v-for="d in durationRows" :key="d.label">
                    <td>{{ d.label }}</td>
                    <td class="text-right">{{ d.sessions }}</td>
                  </tr>
                  <tr v-if="!durationRows.length">
                    <td class="text-medium-emphasis">No sessions yet</td>
                  </tr>
                </tbody>
              </v-table>
            </v-card-text>
          </v-card>
        </v-col>
      </v-row>

      <v-row dense>
        <v-col v-for="b in breakdowns" :key="b.title" cols="12" sm="6" md="3">
          <v-card>
            <v-card-title class="text-subtitle-1">
              {{ b.title }}
              <span
                v-if="b.title === 'Countries' && users && users.geoip === false"
                class="text-caption text-medium-emphasis ml-2"
              >no GeoIP database</span>
            </v-card-title>
            <v-card-text class="pt-0">
              <v-table density="compact">
                <tbody>
                  <tr v-for="row in b.rows" :key="row.key">
                    <td>{{ row.key }}</td>
                    <td class="text-right">{{ row.sessions }}</td>
                  </tr>
                  <tr v-if="!b.rows.length">
                    <td class="text-medium-emphasis">—</td>
                  </tr>
                </tbody>
              </v-table>
              <!-- #1896: the country database's licence asks for this link on
                   the page that shows its results; geoipCredit() picks it from
                   the database the server actually loaded. -->
              <div
                v-if="b.title === 'Countries' && countryCredit"
                class="text-caption text-medium-emphasis mt-2"
              >
                <a :href="countryCredit.href" target="_blank" rel="noopener noreferrer">{{
                  countryCredit.text
                }}</a>
              </div>
            </v-card-text>
          </v-card>
        </v-col>
        <v-col cols="12" sm="6" md="3">
          <v-card>
            <v-card-title class="text-subtitle-1">Top pages</v-card-title>
            <v-card-text class="pt-0">
              <v-table density="compact">
                <tbody>
                  <tr v-for="p in users?.pages ?? []" :key="p.path">
                    <td class="text-truncate" style="max-width: 160px" :title="p.path">
                      {{ p.path }}
                    </td>
                    <td class="text-right">{{ p.views }}</td>
                  </tr>
                  <tr v-if="!(users?.pages ?? []).length">
                    <td class="text-medium-emphasis">—</td>
                  </tr>
                </tbody>
              </v-table>
            </v-card-text>
          </v-card>
        </v-col>
      </v-row>

      <!-- ── Calls (platform-wide) ───────────────────────────────────── -->
      <h2 class="text-h6 mt-6 mb-2">Calls — platform wide</h2>
      <v-row>
        <v-col cols="12" md="8">
          <v-card>
            <v-card-title class="text-subtitle-1">Participant-minutes</v-card-title>
            <v-card-text>
              <time-series-chart
                :points="globalCallMinutes"
                :series="[
                  { key: 'participant_minutes', label: 'Participant-minutes' },
                  { key: 'relayed_minutes', label: 'Relayed' },
                ]"
                area
              />
            </v-card-text>
          </v-card>
        </v-col>
        <v-col cols="12" md="4">
          <v-card>
            <v-card-text class="d-flex justify-space-around text-center">
              <div>
                <div class="text-h5">{{ Math.round(globalCalls?.totals?.calls ?? 0) }}</div>
                <div class="text-caption text-medium-emphasis">Calls</div>
              </div>
              <div>
                <div class="text-h5">{{ Math.round(globalCalls?.totals?.minutes ?? 0) }}</div>
                <div class="text-caption text-medium-emphasis">Minutes</div>
              </div>
            </v-card-text>
          </v-card>
        </v-col>
      </v-row>

      <!-- ── Per-user usage (every org) ──────────────────────────────── -->
      <h2 class="text-h6 mt-6 mb-2">Usage by person</h2>
      <v-card>
        <v-card-subtitle class="pt-3">
          Minutes and traffic per user across every org. Select someone to see when they
          viewed which machine, and where.
        </v-card-subtitle>
        <v-card-text>
          <usage-panel scope="platform" :range="range" />
        </v-card-text>
      </v-card>
    </template>
  </v-container>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useAuthStore } from '@/stores/auth'
import {
  useStatsStore,
  type CostPayload,
  type OrgsPayload,
  type SeriesPayload,
  type SeriesPoint,
  type UsersPayload,
} from '@/stores/stats'
import { usePolling } from '@/composables/usePolling'
import { geoipCredit } from '@/utils/geoipCredit'
import TimeSeriesChart from '@/components/stats/TimeSeriesChart.vue'
import UsagePanel from '@/components/stats/UsagePanel.vue'
import RangePicker, { type StatsRange } from '@/components/stats/RangePicker.vue'

const authStore = useAuthStore()
const statsStore = useStatsStore()

const isPlatformAdmin = computed(() => authStore.user?.is_platform_admin === true)

const range = ref<StatsRange>('24h')
const selectedRegion = ref<string | null>(null)
const selectedOrg = ref<string | null>(null)
const history = ref<SeriesPayload | null>(null)
const orgs = ref<OrgsPayload | null>(null)
const orgMachines = ref<SeriesPayload | null>(null)
const orgCalls = ref<SeriesPayload | null>(null)
const globalCalls = ref<SeriesPayload | null>(null)
const users = ref<UsersPayload | null>(null)

// Mongo's $bucket labels boundaries by their lower bound; name them.
const DURATION_LABELS: Record<string, string> = {
  '0': '< 1 min',
  '60': '1–5 min',
  '300': '5–15 min',
  '900': '15–60 min',
  '3600': '1–4 h',
  '14400': '4–24 h',
  '86400+': '> 24 h',
}
const durationRows = computed(() =>
  (users.value?.durations ?? []).map((d) => ({
    label: DURATION_LABELS[d.bucket] ?? d.bucket,
    sessions: d.sessions,
  })),
)
const breakdowns = computed(() => [
  { title: 'Browsers', rows: users.value?.browsers ?? [] },
  { title: 'Platforms', rows: users.value?.platforms ?? [] },
  { title: 'Countries', rows: users.value?.countries ?? [] },
])
// #1896: whose country data the Countries card shows, credited as its
// licence requires (DB-IP's CC BY 4.0 asks for a link back).
const countryCredit = computed(() => geoipCredit(users.value?.geoip_database))

// Realtime: 15 s poll of the current snapshot (reads the newest persisted
// buckets — cheap), paused while the tab is hidden.
async function loadRelayCurrent() {
  if (!isPlatformAdmin.value) return
  await statsStore.fetchRelayCurrent()
  if (!selectedRegion.value) {
    const first = regionCards.value.find((r) => r.monitored)
    if (first) selectedRegion.value = first.id
  }
}
usePolling(loadRelayCurrent, 15_000)
// First paint must not depend on the poll: at mount the auth flag may not
// have loaded yet (immediate call no-ops) and a background tab skips every
// tick — so ALSO fetch when isPlatformAdmin flips true, like the org
// watcher below. Field-found on the first prod render: orgs table filled,
// relay cards empty until the tab was focused for a poll interval.
watch(isPlatformAdmin, (v) => {
  if (v) void loadRelayCurrent()
})

interface RegionCard {
  id: string
  enabled: boolean
  monitored: boolean
  /** stats endpoints behind this region (multi-worker regions aggregate) */
  workers: number
  busy: boolean
  healthy?: boolean
  latest?: SeriesPoint & { healthy?: boolean }
  agentRtt?: number
}
const regionCards = computed<RegionCard[]>(() => {
  const cur = statsStore.relayCurrent
  if (!cur?.regions) return []
  const latestBy = new Map((cur.latest ?? []).map((l) => [String(l.region), l]))
  const rttBy = new Map((cur.agent_rtt ?? []).map((r) => [r.region, r.rtt_avg_ms]))
  return cur.regions.map((r) => {
    const latest = latestBy.get(r.id)
    return {
      id: r.id,
      enabled: r.enabled,
      monitored: r.monitored,
      workers: r.workers ?? 1,
      busy: r.busy,
      healthy: latest?.healthy,
      latest,
      agentRtt: rttBy.get(r.id),
    }
  })
})

watch(
  [selectedRegion, range, isPlatformAdmin],
  async () => {
    if (!isPlatformAdmin.value || !selectedRegion.value) return
    history.value = await statsStore
      .fetchRelayHistory(selectedRegion.value, range.value)
      .catch(() => null)
  },
  { immediate: true },
)

// ── Cost & usage (FR-20 P5) ────────────────────────────────────────────
//
// Every formatter below has one job beyond formatting: keep `null` visible.
// `null` means "we did not measure this" or "nobody priced this", and the
// moment it renders as 0 the page starts asserting things the server never
// said — that an org costs nothing to serve, or that the mesh is flawless.
const cost = ref<CostPayload | null>(null)

async function loadCost() {
  cost.value = await statsStore.fetchCost(range.value)
}

const currency = computed(() => cost.value?.currency ?? '')

/** Money, or `null` passed straight through. Never coerces. */
function money(v: number | null | undefined): string | null {
  if (v === null || v === undefined) return null
  // Sub-cent costs are normal at these unit prices, so show enough digits to
  // avoid rendering a real cost as 0.00 — which would be the same lie by
  // rounding that the null-handling above exists to prevent.
  // Below four decimals, fall back to a threshold rather than 0.0000: a row
  // of zeros reads as "free" just as convincingly as 0.00 does, which is the
  // lie this function exists to avoid. Measured on prod 2026-08-31: a live
  // org's 24h DERP cost was 0.0000024.
  if (v > 0 && v < 0.0001) return `< 0.0001 ${currency.value}`.trim()
  const digits = v > 0 && v < 0.01 ? 4 : 2
  return `${v.toFixed(digits)} ${currency.value}`.trim()
}

function gb(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return '—'
  return `${(bytes / 1e9).toFixed(2)} GB`
}

function hours(secs: number | null | undefined): string {
  if (secs === null || secs === undefined) return '—'
  return `${(secs / 3600).toFixed(1)} h`
}

const relayedPct = computed<number | null>(() => {
  const f = cost.value?.carrier_mix?.relayed_fraction
  return f === null || f === undefined ? null : Math.round(f * 1000) / 10
})

const METER_LABELS: Record<string, string> = {
  derp_bytes: 'DERP relayed',
  turn_bytes: 'TURN relayed',
  sfu_participant_seconds: 'SFU participant-hours',
}

const fleetMeters = computed(() =>
  Object.entries(cost.value?.meters ?? {}).map(([key, m]) => ({
    key,
    label: METER_LABELS[key] ?? key,
    monitored: m.monitored !== false,
    why: m.why ?? '',
    total: key === 'sfu_participant_seconds' ? hours(m.total) : gb(m.total),
    cost: money(m.cost),
  })),
)

const costHeaders = [
  { title: 'Org', key: 'name' },
  { title: 'Plan', key: 'plan' },
  { title: 'Seats', key: 'seats' },
  { title: 'DERP relayed', key: 'relay' },
  { title: 'SFU', key: 'sfu' },
  { title: 'Cost', key: 'cost' },
  { title: 'MRR (est.)', key: 'mrr' },
  { title: 'Margin (est.)', key: 'margin' },
]

const costRows = computed(() => {
  const p = cost.value
  if (!p?.orgs) return []
  // MRR is monthly; cost covers the requested window. Pro-rate the revenue to
  // the same window rather than comparing a month against a day.
  const share = (p.window_secs ?? 86_400) / (30 * 86_400)
  return p.orgs
    .map((o) => {
      const mrr = (o.mrr_cents / 100) * share
      const margin = o.cost === null ? null : mrr - o.cost
      return {
        name: o.name || o.slug || o.tenant_id,
        plan: o.plan ?? '—',
        seats: o.seats,
        relay: gb(o.meters?.derp_bytes?.total ?? 0),
        sfu: hours(o.meters?.sfu_participant_seconds?.total ?? 0),
        cost: money(o.cost),
        mrr: money(mrr),
        mrrTitle:
          `${(o.mrr_cents / 100).toFixed(2)} ${currency.value}/month list price` +
          (o.subscription_status ? ` — subscription ${o.subscription_status}` : ''),
        margin: money(margin),
        marginClass: margin !== null && margin < 0 ? 'text-error' : '',
        _sort: o.cost ?? -1,
      }
    })
    // Costliest first: the page exists to answer "who is expensive to serve".
    .sort((a, b) => b._sort - a._sort)
})

watch(
  [isPlatformAdmin, range],
  async () => {
    if (!isPlatformAdmin.value) return
    orgs.value = await statsStore.fetchOrgs().catch(() => null)
    // Same watcher as the orgs table: cost is range-scoped and platform-only,
    // and it must survive its own failure without blanking the page - a failed
    // fetch leaves `cost` null, which every formatter already renders as
    // "no data" rather than as zero.
    await loadCost().catch(() => {
      cost.value = null
    })
    globalCalls.value = await statsStore.fetchAdminCalls(range.value).catch(() => null)
    users.value = await statsStore.fetchUsers(range.value).catch(() => null)
    if (selectedOrg.value) await selectOrg(selectedOrg.value)
  },
  { immediate: true },
)

interface OrgRow {
  id: string
  name: string
  online: number
  total: number
  calls: number
  minutes: number
  members: number
  active: boolean
}

// A deployment accumulates test tenants (integration runs leave dozens
// of one-member orgs behind), and they drown the real ones. "Active" =
// it has devices, calls, or more than a lone creator. Presentation only
// — the rows are still one toggle away, because deleting tenant DATA is
// the operator's call, not this view's.
const showInactiveOrgs = ref(false)

const allOrgRows = computed<OrgRow[]>(() => {
  const o = orgs.value
  if (!o?.tenants) return []
  const m = new Map((o.machines ?? []).map((x) => [x.tenant_id, x]))
  const c = new Map((o.calls ?? []).map((x) => [x.tenant_id, x]))
  const mem = new Map((o.members ?? []).map((x) => [x.tenant_id, x]))
  return o.tenants
    .map((t) => {
      const total = m.get(t.id)?.total ?? 0
      const calls = c.get(t.id)?.calls_30d ?? 0
      const members = mem.get(t.id)?.members ?? 0
      return {
        id: t.id,
        name: t.name,
        online: m.get(t.id)?.online ?? 0,
        total,
        calls,
        minutes: c.get(t.id)?.minutes_30d ?? 0,
        members,
        // Devices or calls = real usage. Membership alone is a weak
        // signal: the integration seeder creates an admin + a member, so
        // "> 1" left every test org looking active (field-checked: 59 of
        // them, all with exactly 2). A third human is the cheapest line
        // that separates a workspace someone actually uses.
        active: total > 0 || calls > 0 || members > 2,
      }
    })
    .sort(
      (a, b) =>
        Number(b.active) - Number(a.active) ||
        b.online - a.online ||
        b.total - a.total ||
        b.minutes - a.minutes ||
        a.name.localeCompare(b.name),
    )
})
const inactiveCount = computed(() => allOrgRows.value.filter((o) => !o.active).length)
const orgRows = computed(() =>
  showInactiveOrgs.value ? allOrgRows.value : allOrgRows.value.filter((o) => o.active),
)
function orgName(id: string): string {
  return orgRows.value.find((o) => o.id === id)?.name ?? id
}
async function selectOrg(id: string) {
  selectedOrg.value = id
  const [m, c] = await Promise.all([
    statsStore.fetchAdminMachines(id, range.value).catch(() => null),
    statsStore.fetchAdminCalls(range.value, id).catch(() => null),
  ])
  orgMachines.value = m
  orgCalls.value = c
}

function toMinutes(series: SeriesPoint[] | undefined): SeriesPoint[] {
  return (series ?? []).map((p) => ({
    t: p.t,
    participant_minutes: num(p.participant_seconds) / 60,
    relayed_minutes: num(p.relayed_seconds) / 60,
  }))
}
const orgCallMinutes = computed(() => toMinutes(orgCalls.value?.series))
const globalCallMinutes = computed(() => toMinutes(globalCalls.value?.series))

function num(v: number | null | undefined): number {
  return typeof v === 'number' && Number.isFinite(v) ? v : 0
}
function fmt(v: number | null | undefined): string {
  return typeof v === 'number' && Number.isFinite(v) ? `${Math.round(v * 10) / 10}` : '—'
}
function fmtPct(v: number | null | undefined): string {
  return typeof v === 'number' && Number.isFinite(v) ? `${Math.round(v * 100)}%` : '—'
}

</script>
