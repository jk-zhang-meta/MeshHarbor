<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <!-- FR-102 P8 — the Channels table: per platform and per post published
       in the range, the platform's own reach (raw metric names, summed per
       snapshot age), then what each post's campaign key brought, and spend.
       Below it, the ingest keys the promotion pipeline pushes with. Every
       pushed string (ids, accounts, keys, URLs) is rendered as text; a URL
       becomes a link only when it is http(s). -->
  <div>
    <div class="d-flex align-center flex-wrap mb-3" style="gap: 12px">
      <v-text-field
        v-model="since"
        type="date"
        label="Published since (UTC)"
        density="compact"
        hide-details
        style="max-width: 200px"
        :max="until"
      />
      <v-text-field
        v-model="until"
        type="date"
        label="Until (UTC)"
        density="compact"
        hide-details
        style="max-width: 180px"
        :max="today"
      />
      <v-switch
        v-model="includeInternal"
        label="Include internal"
        density="compact"
        hide-details
        color="warning"
      />
      <v-btn size="small" variant="tonal" :loading="loading" @click="load">Load</v-btn>
    </div>

    <v-alert v-if="message" type="error" variant="tonal" density="compact" class="mb-3">
      {{ message }}
    </v-alert>

    <template v-if="report">
      <div class="d-flex flex-wrap mb-3" style="gap: 6px">
        <v-chip v-if="!report.ingest_mounted" size="small" color="warning" variant="tonal">
          the ingest routes are not mounted on this server (saas) — nothing new arrives
        </v-chip>
        <growth-not-measured
          v-if="report.web_not_measured"
          :reason="`web plane: ${report.web_not_measured.not_measured}`"
        />
        <growth-not-measured
          v-if="report.conversions"
          :reason="`conversions: ${report.conversions.not_measured}`"
        />
        <v-chip v-if="report.posts_truncated" size="small" color="warning" variant="tonal">
          more posts than one read loads — oldest only
        </v-chip>
        <span class="text-caption text-medium-emphasis align-self-center">
          {{ report.since }} → {{ report.until }} · excluded {{ report.excluded.users }} users,
          {{ report.excluded.tenants }} orgs · rates and costs from n ≥ {{ report.n_floor }}
        </span>
      </div>

      <v-card v-for="p in report.platforms" :key="p.platform" class="mb-3">
        <v-card-title class="text-subtitle-1 d-flex align-center flex-wrap" style="gap: 8px">
          {{ p.platform }}
          <v-chip v-if="p.retired" size="x-small" variant="tonal">retired</v-chip>
          <v-spacer />
          <growth-not-measured v-if="isNotMeasured(p.summary)" :reason="p.summary.not_measured" />
          <span v-else class="text-caption text-medium-emphasis">
            {{ p.summary.posts }} post{{ p.summary.posts === 1 ? '' : 's' }}
          </span>
        </v-card-title>
        <v-card-text v-if="!isNotMeasured(p.summary)">
          <div class="d-flex flex-wrap mb-2" style="gap: 20px">
            <div>
              <div class="text-caption text-medium-emphasis">Reach (the platform's own, per age)</div>
              <growth-not-measured v-if="isNotMeasured(p.summary.reach)" :reason="p.summary.reach.not_measured" />
              <template v-else>
                <div v-for="a in reachAges(p.summary.reach)" :key="a.snapshot" class="text-body-2">
                  {{ a.snapshot }} · {{ metricsLabel(a.metrics, 4) }}
                  <span class="text-caption text-medium-emphasis">({{ a.posts }} post{{ a.posts === 1 ? '' : 's' }})</span>
                </div>
              </template>
            </div>
            <div>
              <div class="text-caption text-medium-emphasis">Visitors (Σ keys)</div>
              <growth-not-measured v-if="isNotMeasured(p.summary.web)" :reason="p.summary.web.not_measured" />
              <div v-else class="text-h6">{{ p.summary.web.visitors }}</div>
            </div>
            <div>
              <div class="text-caption text-medium-emphasis">Sign-ups → activated → first value</div>
              <div class="text-h6">
                {{ p.summary.signups }} →
                {{ p.summary.activated ? p.summary.activated.count : 'n/m' }} →
                {{ p.summary.first_value ? p.summary.first_value.count : 'n/m' }}
              </div>
            </div>
            <div>
              <div class="text-caption text-medium-emphasis">Paid (so far)</div>
              <div v-if="p.summary.paid" class="text-h6">{{ p.summary.paid.count }}</div>
              <v-chip
                v-else
                size="x-small"
                variant="tonal"
                color="grey"
                :title="report.not_measured?.paid"
              >not measured</v-chip>
            </div>
            <div v-if="p.summary.spend">
              <div class="text-caption text-medium-emphasis">Spend</div>
              <div class="text-body-2">
                {{ centsLabel(p.summary.spend.cost_cents) }}
                <span class="text-caption text-medium-emphasis">({{ p.summary.spend.posts_with_cost }} paid posts)</span>
              </div>
              <div class="text-caption">{{ costLabel('per visitor', p.summary.spend.per_visitor) }}</div>
              <div class="text-caption">{{ costLabel('per sign-up', p.summary.spend.per_signup) }}</div>
            </div>
          </div>

          <v-table density="compact" class="growth-wide">
            <thead>
              <tr>
                <th class="text-left">Published</th>
                <th class="text-left">Account · format</th>
                <th class="text-left">Key</th>
                <th class="text-left">Reach (latest)</th>
                <th class="text-right">Visitors</th>
                <th class="text-right">Sign-ups</th>
                <th class="text-right">Activated</th>
                <th class="text-right">Cost</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="post in p.posts" :key="post.platform_id">
                <td>
                  <a
                    v-if="safeHref(post.url)"
                    :href="safeHref(post.url) ?? undefined"
                    target="_blank"
                    rel="noopener noreferrer"
                  >{{ post.published_at.slice(0, 10) }}</a>
                  <span v-else>{{ post.published_at.slice(0, 10) }}</span>
                </td>
                <td>{{ post.account }} · {{ post.format }}</td>
                <td>{{ campaignKeyLabel(post.key) }}</td>
                <td>
                  <v-chip
                    v-if="isNotMeasured(post.reach)"
                    size="x-small"
                    variant="tonal"
                    color="grey"
                    :title="post.reach.not_measured"
                  >not measured</v-chip>
                  <span v-else class="text-caption">
                    {{ post.reach.snapshot }} · {{ metricsLabel(post.reach.metrics) }}
                  </span>
                </td>
                <td class="text-right">
                  <v-chip
                    v-if="isNotMeasured(post.web)"
                    size="x-small"
                    variant="tonal"
                    color="grey"
                    :title="post.web.not_measured"
                  >not measured</v-chip>
                  <span v-else>{{ post.web.visitors }}</span>
                </td>
                <td class="text-right">{{ post.signups }}</td>
                <td class="text-right">{{ post.activated ? post.activated.count : 'n/m' }}</td>
                <td class="text-right">
                  <template v-if="post.spend">
                    {{ centsLabel(post.spend.cost_cents) }}
                    <div class="text-caption text-medium-emphasis">
                      {{ costLabel('/visitor', post.spend.per_visitor) }}
                    </div>
                  </template>
                  <span v-else class="text-medium-emphasis">—</span>
                </td>
              </tr>
            </tbody>
          </v-table>
        </v-card-text>
      </v-card>
    </template>
    <div v-else-if="loading" class="pa-4"><v-progress-circular indeterminate size="24" /></div>

    <!-- The machine keys (D12): only a hash is stored; a minted key is shown once. -->
    <v-card class="mt-4">
      <v-card-title class="text-subtitle-1">Machine keys</v-card-title>
      <v-card-text>
        <p class="text-caption text-medium-emphasis mb-2">
          An <strong>ingest</strong> key opens <code>POST /api/admin/growth/ingest/posts</code> and
          <code>…/snapshots</code> and nothing else; a <strong>read</strong> key (P10) opens the
          <code>GET /api/admin/growth/*</code> views and nothing else — never a write, never this
          list. Only a hash is stored: copy a key when it is shown.
        </p>
        <div class="d-flex align-center flex-wrap mb-2" style="gap: 8px">
          <v-select
            v-model="newKind"
            :items="kindItems"
            label="Kind"
            density="compact"
            hide-details
            style="max-width: 140px"
          />
          <v-text-field
            v-model="newLabel"
            label="Label"
            density="compact"
            hide-details
            style="max-width: 280px"
            maxlength="80"
          />
          <v-btn size="small" variant="tonal" :disabled="!newLabel.trim()" :loading="minting" @click="mint">
            Mint {{ newKind }} key
          </v-btn>
        </div>
        <v-alert v-if="minted" type="warning" variant="tonal" density="compact" class="mb-2">
          <div>Shown once — store it in the pipeline's secret store now.</div>
          <code class="minted-key">{{ minted }}</code>
          <v-btn size="x-small" variant="text" @click="copyMinted">copy</v-btn>
          <v-btn size="x-small" variant="text" @click="minted = null">done</v-btn>
        </v-alert>
        <!-- FR-120 P5 — a card per key below 600 px (table-stack-xs), so
             `revoke`, the rightmost column, stays on screen. -->
        <v-table v-if="keys.length" density="compact" class="table-stack-xs table-stack-xs--compact">
          <thead>
            <tr>
              <th class="text-left">Kind</th>
              <th class="text-left">Prefix</th>
              <th class="text-left">Label</th>
              <th class="text-left">Created</th>
              <th class="text-left">Last used</th>
              <th class="text-left">State</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="k in keys" :key="k.id">
              <td data-label="Kind">{{ k.kind }}</td>
              <td data-label="Prefix"><code>{{ k.prefix }}…</code></td>
              <td data-label="Label">{{ k.label }}</td>
              <td data-label="Created">{{ k.created_at.slice(0, 10) }}</td>
              <td data-label="Last used">{{ k.last_used_at ? k.last_used_at.slice(0, 16).replace('T', ' ') : '—' }}</td>
              <td data-label="State">
                <v-chip size="x-small" :color="k.live ? 'success' : 'grey'" variant="tonal">
                  {{ k.live ? 'live' : 'revoked' }}
                </v-chip>
              </td>
              <td class="text-right">
                <v-btn v-if="k.live" size="x-small" variant="text" color="error" @click="revoke(k.id)">
                  revoke
                </v-btn>
              </td>
            </tr>
          </tbody>
        </v-table>
        <span v-else class="text-caption text-medium-emphasis">No keys yet.</span>
      </v-card-text>
    </v-card>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import {
  useGrowthStore,
  campaignKeyLabel,
  centsLabel,
  isNotMeasured,
  metricsLabel,
  safeHref,
  type ChannelsReport,
  type CostRate,
  type GrowthKeyKind,
  type GrowthKeyRow,
  type Measured,
  type ReachAt,
} from '@/stores/growth'
import GrowthNotMeasured from './GrowthNotMeasured.vue'

const store = useGrowthStore()

function utcDay(offsetDays: number): string {
  const d = new Date()
  d.setUTCDate(d.getUTCDate() + offsetDays)
  return d.toISOString().slice(0, 10)
}

const today = utcDay(0)
const until = ref(utcDay(-1))
const since = ref(utcDay(-28))
const includeInternal = ref(false)
const loading = ref(false)
const message = ref<string | null>(null)
const report = ref<ChannelsReport | null>(null)

const keys = ref<GrowthKeyRow[]>([])
const newLabel = ref('')
const newKind = ref<GrowthKeyKind>('ingest')
const kindItems = [
  { title: 'ingest', value: 'ingest' },
  { title: 'read', value: 'read' },
]
const minting = ref(false)
const minted = ref<string | null>(null)

function reachAges(r: Measured<ReachAt[]>): ReachAt[] {
  return isNotMeasured(r) ? [] : r
}

/** `0.91 per visitor`, or the n it would need. */
function costLabel(unit: string, r: CostRate | null): string {
  if (!r) return `${unit}: not measured`
  return typeof r.cents === 'number'
    ? `${centsLabel(r.cents)} ${unit}`
    : `${unit}: n = ${r.n} < ${report.value?.n_floor ?? 30}`
}

async function load() {
  loading.value = true
  message.value = null
  try {
    report.value = await store.fetchChannels({
      since: since.value || undefined,
      until: until.value || undefined,
      includeInternal: includeInternal.value,
    })
  } catch (e) {
    message.value = e instanceof Error ? e.message : 'channels failed'
  } finally {
    loading.value = false
  }
}

async function loadKeys() {
  try {
    keys.value = (await store.fetchKeys()).keys
  } catch (e) {
    message.value = e instanceof Error ? e.message : 'keys failed'
  }
}

async function mint() {
  minting.value = true
  try {
    const k = await store.mintKey(newLabel.value.trim(), newKind.value)
    minted.value = k.key
    newLabel.value = ''
    await loadKeys()
  } catch (e) {
    message.value = e instanceof Error ? e.message : 'mint failed'
  } finally {
    minting.value = false
  }
}

async function revoke(id: string) {
  try {
    await store.revokeKey(id)
    await loadKeys()
  } catch (e) {
    message.value = e instanceof Error ? e.message : 'revoke failed'
  }
}

async function copyMinted() {
  if (minted.value) await navigator.clipboard?.writeText(minted.value)
}

onMounted(() => Promise.all([load(), loadKeys()]))
</script>

<style scoped>
.growth-wide {
  max-width: 100%;
  overflow-x: auto;
}
.minted-key {
  word-break: break-all;
}
</style>
