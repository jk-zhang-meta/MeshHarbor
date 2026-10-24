<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-container fluid class="pa-2 pa-md-4 pa-xl-6">
    <h1 class="text-h5 text-md-h4 font-weight-bold mb-2">Billing & Subscription</h1>
    <p class="text-body-1 text-medium-emphasis mb-4 mb-md-6">Manage your workspace's plan and billing</p>

    <v-alert v-if="$route.query.success" type="success" closable class="mb-4">
      Subscription updated successfully! Changes may take a moment to reflect.
    </v-alert>
    <v-alert v-if="$route.query.canceled" type="info" closable class="mb-4">
      Checkout was canceled. No changes were made.
    </v-alert>
    <v-alert
      v-if="errorMessage"
      type="error"
      closable
      class="mb-4"
      data-testid="billing-error"
      @click:close="errorMessage = ''"
    >
      {{ errorMessage }}
    </v-alert>

    <!-- Current Plan -->
    <v-card variant="outlined" class="mb-4 mb-md-6 pa-4 pa-md-6">
      <div class="d-flex align-center justify-space-between flex-wrap ga-4">
        <div>
          <div class="text-overline text-medium-emphasis">Current Plan</div>
          <div class="text-h5 font-weight-bold text-capitalize">{{ currentPlan }}</div>
          <div v-if="billing?.status" class="mt-1">
            <v-chip
              :color="billing.status === 'active' ? 'success' : 'warning'"
              size="small"
              variant="tonal"
            >
              {{ billing.status }}
            </v-chip>
            <span v-if="billing.cancel_at_period_end" class="text-body-2 text-warning ml-2">
              Cancels at period end
            </span>
          </div>
          <div class="text-body-2 text-medium-emphasis mt-1" data-testid="billing-seats">
            {{ seatsLine }}
          </div>
          <div v-if="billing?.current_period_end" class="text-body-2 text-medium-emphasis mt-1">
            Current period ends: {{ new Date(billing.current_period_end).toLocaleDateString() }}
          </div>
        </div>
        <v-btn
          v-if="billing?.customer_id"
          variant="outlined"
          @click="openPortal"
          :loading="portalLoading"
        >
          Manage Subscription
        </v-btn>
      </div>
    </v-card>

    <!-- Plans -->
    <div class="d-flex align-center flex-wrap ga-3 mb-2 mb-md-4">
      <h2 class="text-h6 text-md-h5 font-weight-bold">Available Plans</h2>
      <v-spacer />
      <v-btn-toggle
        v-if="annualOnSale"
        v-model="interval"
        mandatory
        density="comfortable"
        variant="outlined"
        divided
        data-testid="interval-toggle"
      >
        <v-btn value="month">Monthly</v-btn>
        <v-btn value="year">Annual · 2 months free</v-btn>
      </v-btn-toggle>
      <v-btn-toggle
        v-if="currenciesOnSale.length > 1"
        v-model="currency"
        mandatory
        density="comfortable"
        variant="outlined"
        divided
        :disabled="subscribed"
        data-testid="currency-toggle"
      >
        <v-btn value="usd">USD</v-btn>
        <v-btn value="eur">EUR</v-btn>
      </v-btn-toggle>
    </div>
    <v-row>
      <v-col v-for="plan in plans" :key="plan.id" cols="12" sm="6" md="4">
        <v-card
          :variant="plan.id === currentPlan ? 'elevated' : 'outlined'"
          :elevation="plan.id === currentPlan ? 4 : 0"
          class="pa-4 pa-md-6 h-100 d-flex flex-column"
          rounded="lg"
          :class="{ 'border-primary': plan.id === currentPlan }"
          :data-testid="`plan-card-${plan.id}`"
        >
          <div class="d-flex align-center flex-wrap ga-2">
            <div class="text-h6 font-weight-bold">{{ plan.name }}</div>
            <v-chip
              v-if="plan.id === 'free' && plan.commercial_use !== false"
              color="success"
              size="small"
              variant="tonal"
              data-testid="commercial-use"
            >
              Free for commercial use
            </v-chip>
          </div>
          <div class="my-4" :data-testid="`price-${plan.id}`">
            <span class="text-h4 font-weight-bold">{{ money(unitAmount(plan), shownCurrency) }}</span>
            <span v-if="unitAmount(plan) > 0" class="text-body-2 text-medium-emphasis">
              per user / {{ shownInterval(plan) === 'year' ? 'year' : 'month' }}
            </span>
            <span v-else class="text-body-2 text-medium-emphasis">forever</span>
            <div
              v-if="unitAmount(plan) > 0 && shownInterval(plan) === 'year'"
              class="text-body-2 text-medium-emphasis"
            >
              {{ money(Math.round(unitAmount(plan) / 12), shownCurrency) }} per user / month, two months free
            </div>
            <div v-if="unitAmount(plan) > 0" class="text-body-2 text-medium-emphasis">
              {{ seatsNow }} {{ seatsNow === 1 ? 'user' : 'users' }} in this organization:
              {{ money(unitAmount(plan) * seatsNow, shownCurrency) }} / {{ shownInterval(plan) === 'year' ? 'year' : 'month' }}
            </div>
          </div>
          <v-divider class="mb-4" />
          <v-list density="compact" class="flex-grow-1 bg-transparent">
            <v-list-item title="Users" :subtitle="usersText(plan)" prepend-icon="mdi-account-group" />
            <v-list-item title="Devices" :subtitle="count(plan.limits.max_devices)" prepend-icon="mdi-monitor-multiple" />
            <v-list-item title="Remote sessions at a time" :subtitle="sessionsText(plan)" prepend-icon="mdi-monitor-eye" />
            <v-list-item title="MagicDNS" :subtitle="plan.limits.magic_dns ? 'Yes' : 'No'" :prepend-icon="plan.limits.magic_dns ? 'mdi-check-circle' : 'mdi-close-circle'" />
            <v-list-item title="Exit Nodes" :subtitle="plan.limits.exit_nodes ? 'Yes' : 'Not yet'" :prepend-icon="plan.limits.exit_nodes ? 'mdi-check-circle' : 'mdi-close-circle'" />
            <v-list-item title="Relay at full speed" :subtitle="relayText(plan)" prepend-icon="mdi-swap-horizontal" />
            <v-list-item title="Meetings" :subtitle="meetingsText(plan)" prepend-icon="mdi-video" />
            <v-list-item title="Storage" :subtitle="storageText(plan)" prepend-icon="mdi-database" />
            <v-list-item title="Recordings" :subtitle="plan.limits.recordings ? 'Yes' : 'No'" :prepend-icon="plan.limits.recordings ? 'mdi-check-circle' : 'mdi-close-circle'" />
          </v-list>
          <v-btn
            v-if="isCurrent(plan)"
            color="primary"
            variant="tonal"
            block
            size="large"
            class="mt-4"
            disabled
          >
            Current Plan
          </v-btn>
          <v-btn
            v-else-if="plan.id !== 'free' && !subscribed"
            color="primary"
            block
            size="large"
            class="mt-4"
            @click="checkout(plan.id)"
            :loading="busy === plan.id"
          >
            Upgrade to {{ plan.name }}
          </v-btn>
          <v-btn
            v-else-if="plan.id !== 'free' && subscribed"
            color="primary"
            block
            size="large"
            class="mt-4"
            @click="askSwitch(plan)"
            :loading="busy === plan.id"
          >
            {{ plan.id === currentPlan ? `Switch to ${interval === 'year' ? 'annual' : 'monthly'}` : `Switch to ${plan.name}` }}
          </v-btn>
        </v-card>
      </v-col>
    </v-row>

    <v-dialog v-model="confirmOpen" max-width="460">
      <v-card>
        <v-card-title class="text-h6">Change plan</v-card-title>
        <v-card-text>
          Switch to <strong>{{ pending?.name }}</strong>, billed {{ interval === 'year' ? 'annually' : 'monthly' }}?
          Stripe prorates the change: the rest of this period is charged or credited on your next invoice.
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="confirmOpen = false">Cancel</v-btn>
          <v-btn color="primary" variant="flat" @click="confirmSwitch">Switch</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </v-container>
</template>

<script setup lang="ts">
import { appOrigin } from '@/utils/deployment'
import { ref, computed, onMounted, watch } from 'vue'
import { useTenantStore } from '@/stores/tenant'
import { api } from '@/api/client'
import {
  type Currency,
  annualOnSale as annualIn,
  currenciesOnSale as onSaleIn,
  shownCurrency as pickShownCurrency,
} from '@/utils/billingCurrency'

const tenantStore = useTenantStore()

type Interval = 'month' | 'year'

interface PlanPrice {
  interval: Interval
  currency: Currency
  unit_amount: number
}

interface PlanInfo {
  id: string
  name: string
  price_cents: number
  // FR-115 — per-seat prices for each interval and currency on sale.
  prices?: PlanPrice[]
  per_seat?: boolean
  commercial_use?: boolean
  features?: string[]
  limits: {
    // FR-115 — kept in lockstep with the server's Plan::limits +
    // billing_tests.rs + billing.spec.ts.
    max_devices: number
    max_tunnel_clients: number
    overlay_mesh: boolean
    exit_nodes: boolean
    magic_dns: boolean
    max_concurrent_sessions: number
    relay_bytes_per_month?: number
    max_members: number
    max_channels: number
    max_message_history: number
    storage_bytes: number
    video_max_participants: number
    meeting_max_minutes?: number
    cloud_integrations: boolean
    recordings: boolean
    per_seat?: boolean
  }
}

interface BillingSummary {
  plan: string
  seats_billed: number | null
  seats_now: number
  interval: Interval | null
  currency: Currency | null
  status: string | null
  current_period_end: string | null
  cancel_at_period_end: boolean
  subscribed: boolean
}

const UNLIMITED = 4294967295
const CURRENCY_KEY = 'roomler.billing.currency'

const plans = ref<PlanInfo[]>([])
const summary = ref<BillingSummary | null>(null)
const portalLoading = ref(false)
const busy = ref<string | null>(null)
const errorMessage = ref('')
const interval = ref<Interval>('month')
const currency = ref<Currency>(defaultCurrency())
const confirmOpen = ref(false)
const pending = ref<PlanInfo | null>(null)

const currentTenant = computed(() => tenantStore.current)
const currentPlan = computed(() => summary.value?.plan || currentTenant.value?.plan || 'free')
const billing = computed(() => currentTenant.value?.billing || {})
const subscribed = computed(() => summary.value?.subscribed === true)
const seatsNow = computed(() => Math.max(1, summary.value?.seats_now ?? 1))
/** A PAID plan sells annually here (`utils/billingCurrency`). */
const annualOnSale = computed(() => annualIn(plans.value))
/** The currencies on sale here (`stripe.currencies` on the server); the
 * toggle shows only when there is a choice. */
const currenciesOnSale = computed(() => onSaleIn(plans.value))
/** The currency shown and asked for at checkout (`utils/billingCurrency`). */
const shownCurrency = computed(() =>
  pickShownCurrency(currency.value, currenciesOnSale.value, subscribed.value ? summary.value?.currency : null),
)

const seatsLine = computed(() => {
  const s = summary.value
  if (!s) return ''
  const users = (n: number) => `${n} ${n === 1 ? 'user' : 'users'}`
  if (s.subscribed && s.seats_billed != null) {
    const how = [s.interval === 'year' ? 'annual' : s.interval === 'month' ? 'monthly' : '', s.currency?.toUpperCase() || '']
      .filter(Boolean)
      .join(', ')
    const pendingSync =
      s.seats_now !== s.seats_billed ? ` (${users(s.seats_now)} now; the subscription catches up within 15 minutes)` : ''
    return `Billed for ${users(s.seats_billed)}${how ? ` · ${how}` : ''}${pendingSync}`
  }
  return currentPlan.value === 'free'
    ? `${users(s.seats_now)} in this organization (Free covers up to 10)`
    : `${users(s.seats_now)} in this organization`
})

/** EUR for a browser in a European time zone, USD otherwise — a starting
 * point only; the toggle (remembered per browser) is the person's choice. */
function defaultCurrency(): Currency {
  try {
    const saved = localStorage.getItem(CURRENCY_KEY)
    if (saved === 'usd' || saved === 'eur') return saved
  } catch {
    /* storage unavailable: fall through */
  }
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone.startsWith('Europe/') ? 'eur' : 'usd'
  } catch {
    return 'usd'
  }
}

watch(currency, (c) => {
  try {
    localStorage.setItem(CURRENCY_KEY, c)
  } catch {
    /* not remembered: fine */
  }
})

function money(minor: number, cur: Currency): string {
  const whole = minor % 100 === 0
  return new Intl.NumberFormat(undefined, {
    style: 'currency',
    currency: cur.toUpperCase(),
    minimumFractionDigits: whole ? 0 : 2,
    maximumFractionDigits: whole ? 0 : 2,
  }).format(minor / 100)
}

/** The interval a card shows: the toggle's, unless the plan is not on sale
 * annually here (then monthly). */
function shownInterval(plan: PlanInfo): Interval {
  const prices = plan.prices || []
  if (interval.value === 'year' && prices.some((p) => p.interval === 'year')) return 'year'
  return 'month'
}

function unitAmount(plan: PlanInfo): number {
  const want = shownInterval(plan)
  const hit = (plan.prices || []).find((p) => p.interval === want && p.currency === shownCurrency.value)
  return hit ? hit.unit_amount : plan.price_cents
}

function count(n: number): string {
  return n >= UNLIMITED ? 'Unlimited' : n.toLocaleString()
}

function perSeat(plan: PlanInfo): boolean {
  return plan.per_seat ?? plan.limits.per_seat ?? false
}

function usersText(plan: PlanInfo): string {
  return plan.limits.max_members >= UNLIMITED ? 'Unlimited, billed per user' : `Up to ${plan.limits.max_members}`
}

function sessionsText(plan: PlanInfo): string {
  const n = plan.limits.max_concurrent_sessions
  if (n >= UNLIMITED) return 'Unlimited'
  return perSeat(plan) ? `${n} per user` : String(n)
}

function relayText(plan: PlanInfo): string {
  const b = plan.limits.relay_bytes_per_month
  if (b == null) return '—'
  const gb = Math.round(b / 1e9)
  return perSeat(plan) ? `${gb} GB per user / month` : `${gb} GB / month`
}

function meetingsText(plan: PlanInfo): string {
  const people = `${plan.limits.video_max_participants} people`
  const m = plan.limits.meeting_max_minutes
  return m != null && m < UNLIMITED ? `${people}, up to ${m} min` : people
}

function storageText(plan: PlanInfo): string {
  const gb = Math.round(plan.limits.storage_bytes / 1024 ** 3)
  return perSeat(plan) ? `${gb} GB per user` : `${gb} GB`
}

function isCurrent(plan: PlanInfo): boolean {
  if (plan.id !== currentPlan.value) return false
  if (plan.id === 'free' || !subscribed.value) return true
  // A paid plan is "current" only at the interval the subscription bills.
  return (summary.value?.interval || 'month') === shownInterval(plan)
}

function fail(e: unknown, what: string) {
  errorMessage.value = `${what}: ${(e as Error)?.message || String(e)}`
  console.error(what, e)
}

async function fetchPlans() {
  try {
    plans.value = await api.get<PlanInfo[]>('/stripe/plans')
  } catch (e) {
    console.error('Failed to fetch plans:', e)
  }
}

async function fetchSummary() {
  const id = currentTenant.value?.id
  if (!id) return
  try {
    summary.value = await api.get<BillingSummary>(`/stripe/summary?tenant_id=${encodeURIComponent(id)}`)
    if (summary.value.subscribed) {
      if (summary.value.currency) currency.value = summary.value.currency
      if (summary.value.interval) interval.value = summary.value.interval
    }
  } catch {
    // A member without MANAGE_TENANT sees the plans without the org's billing.
    summary.value = null
  }
}

async function checkout(planId: string) {
  if (!currentTenant.value?.id) return
  busy.value = planId
  errorMessage.value = ''
  try {
    const result = await api.post<{ url: string }>('/stripe/checkout', {
      tenant_id: currentTenant.value.id,
      plan: planId,
      interval: interval.value,
      currency: shownCurrency.value,
      success_url: `${appOrigin(window.location.origin)}/tenant/${currentTenant.value.id}/billing?success=true`,
      cancel_url: `${appOrigin(window.location.origin)}/tenant/${currentTenant.value.id}/billing?canceled=true`,
    })
    if (result.url) window.location.href = result.url
  } catch (e) {
    fail(e, 'Checkout failed')
  } finally {
    busy.value = null
  }
}

function askSwitch(plan: PlanInfo) {
  pending.value = plan
  confirmOpen.value = true
}

async function confirmSwitch() {
  const plan = pending.value
  confirmOpen.value = false
  if (!plan || !currentTenant.value?.id) return
  busy.value = plan.id
  errorMessage.value = ''
  try {
    summary.value = await api.post<BillingSummary>('/stripe/change-plan', {
      tenant_id: currentTenant.value.id,
      plan: plan.id,
      interval: interval.value,
    })
  } catch (e) {
    fail(e, 'Plan change failed')
  } finally {
    busy.value = null
  }
}

async function openPortal() {
  if (!currentTenant.value?.id) return
  portalLoading.value = true
  try {
    const result = await api.post<{ url: string }>('/stripe/portal', {
      tenant_id: currentTenant.value.id,
      return_url: `${appOrigin(window.location.origin)}/tenant/${currentTenant.value.id}/billing`,
    })
    if (result.url) window.location.href = result.url
  } catch (e) {
    fail(e, 'Could not open the billing portal')
  } finally {
    portalLoading.value = false
  }
}

watch(() => currentTenant.value?.id, fetchSummary)
onMounted(() => {
  fetchPlans()
  fetchSummary()
})
</script>
