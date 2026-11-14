<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Temporary devices: invite a machine for a while with an 8-digit code (no
     account on that side), make an enrolled device temporary, renew, end by
     hand — and the full history of every invitation, which is never deleted.

     The code is shown exactly ONCE, in the create response; the list can
     never return it. -->
<template>
  <v-card v-if="available" class="mt-4" data-testid="temp-devices">
    <v-card-title class="d-flex align-center flex-wrap ga-2">
      <v-icon icon="mdi-timer-sand" color="primary" class="mr-2" />
      {{ t('tempDevices.title') }}
      <v-spacer />
      <v-btn size="small" variant="tonal" prepend-icon="mdi-swap-horizontal" @click="openConvert">
        {{ t('tempDevices.convert') }}
      </v-btn>
      <v-btn color="primary" size="small" prepend-icon="mdi-account-plus" data-testid="temp-invite" @click="openCreate">
        {{ t('tempDevices.invite') }}
      </v-btn>
    </v-card-title>
    <v-card-text>
      <p class="text-body-2 text-medium-emphasis mb-3">{{ t('tempDevices.intro') }}</p>
      <v-btn-toggle v-model="filter" density="compact" mandatory class="mb-3" color="primary" variant="outlined">
        <v-btn value="active" size="small">{{ t('tempDevices.filter.active') }}</v-btn>
        <v-btn value="all" size="small">{{ t('tempDevices.filter.all') }}</v-btn>
      </v-btn-toggle>
      <v-table v-if="shown.length" density="compact" class="table-stack-xs">
        <thead>
          <tr>
            <th>{{ t('tempDevices.col.device') }}</th>
            <th>{{ t('tempDevices.col.state') }}</th>
            <th>{{ t('tempDevices.col.until') }}</th>
            <th>{{ t('tempDevices.col.history') }}</th>
            <th class="text-right">{{ t('tempDevices.col.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in shown" :key="r.id" :data-testid="`temp-row-${r.id}`">
            <td>
              <span class="font-weight-medium">{{ r.device_name || r.label || t('tempDevices.notJoined') }}</span>
              <v-chip v-if="r.converted" size="x-small" variant="outlined" class="ml-1">{{ t('tempDevices.converted') }}</v-chip>
              <div v-if="r.label && r.device_name" class="text-caption text-medium-emphasis">{{ r.label }}</div>
              <div v-if="r.device_os" class="text-caption text-medium-emphasis">{{ r.device_os }}</div>
            </td>
            <td :data-label="t('tempDevices.col.state')">
              <v-chip size="x-small" :color="stateColor(r)" variant="tonal">{{ stateText(r) }}</v-chip>
              <div v-if="r.state === 'ended'" class="text-caption text-medium-emphasis">
                {{ reasonText(r) }} · {{ fmt(r.ended_at_ms) }}
              </div>
            </td>
            <td :data-label="t('tempDevices.col.until')">
              {{ fmt(r.access_until_ms) }}
              <div v-if="r.state !== 'ended'" class="text-caption text-medium-emphasis">
                {{ t('tempDevices.left', { left: remaining(r.access_until_ms) }) }}
              </div>
            </td>
            <td :data-label="t('tempDevices.col.history')" class="text-caption">
              <div>{{ t('tempDevices.created', { when: fmt(r.created_at_ms) }) }}</div>
              <div v-if="r.redeemed_at_ms">{{ t('tempDevices.joined', { when: fmt(r.redeemed_at_ms) }) }}</div>
              <div v-for="(x, i) in r.renewals" :key="i">
                {{ t('tempDevices.renewedLine', { when: fmt(x.at_ms), until: fmt(x.until_ms) }) }}
              </div>
            </td>
            <td class="text-right text-no-wrap">
              <template v-if="r.state !== 'ended'">
                <v-btn size="x-small" variant="text" @click="openRenew(r)">{{ t('tempDevices.renew') }}</v-btn>
                <v-btn v-if="r.state === 'enrolled' && r.agent_id" size="x-small" variant="text" @click="makePermanent(r)">
                  {{ t('tempDevices.permanent') }}
                </v-btn>
                <v-btn size="x-small" variant="text" color="error" :data-testid="`temp-revoke-${r.id}`" @click="revoke(r)">
                  {{ t('tempDevices.revoke') }}
                </v-btn>
              </template>
            </td>
          </tr>
        </tbody>
      </v-table>
      <div v-else class="text-center pa-4 text-medium-emphasis">{{ t('tempDevices.empty') }}</div>
      <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mt-3">{{ error }}</v-alert>
    </v-card-text>
  </v-card>

  <!-- Create: the form, then the one-time code (not dismissible by a misclick). -->
  <v-dialog v-model="createOpen" max-width="560" :persistent="!!created" :fullscreen="fullscreen">
    <v-card>
      <v-card-title>{{ created ? t('tempDevices.codeTitle') : t('tempDevices.invite') }}</v-card-title>
      <v-card-text v-if="!created">
        <duration-fields v-model:amount="form.amount" v-model:unit="form.unit" :units="units" :label="t('tempDevices.duration')" />
        <v-text-field v-model="form.label" :label="t('tempDevices.label')" density="compact" class="mt-2" :hint="t('tempDevices.labelHint')" persistent-hint />
        <v-select
          v-model="form.roles"
          :items="roleItems"
          :label="t('tempDevices.roles')"
          :hint="t('tempDevices.rolesHint')"
          persistent-hint
          multiple
          chips
          density="compact"
          class="mt-2"
        />
        <v-alert v-if="formError" type="error" variant="tonal" density="compact" class="mt-3">{{ formError }}</v-alert>
      </v-card-text>
      <v-card-text v-else>
        <div class="code-big" data-testid="temp-code">{{ created.code }}</div>
        <p class="text-body-2 mt-3">{{ t('tempDevices.codeHow') }}</p>
        <p class="text-body-2">{{ t('tempDevices.codeCli') }} <code>{{ created.join_command }}</code></p>
        <v-alert type="info" variant="tonal" density="compact" class="mt-2">
          {{ t('tempDevices.codeOnce', { until: fmt(created.access_until_ms) }) }}
        </v-alert>
        <v-btn block class="mt-3" variant="tonal" :prepend-icon="copied ? 'mdi-check' : 'mdi-content-copy'" @click="copyCode">
          {{ copied ? t('tempDevices.copied') : t('tempDevices.copy') }}
        </v-btn>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn v-if="!created" variant="text" @click="createOpen = false">{{ t('common.cancel') }}</v-btn>
        <v-btn v-if="!created" color="primary" :loading="busy" @click="create">{{ t('tempDevices.create') }}</v-btn>
        <v-btn v-else color="primary" @click="closeCreate">{{ t('tempDevices.done') }}</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>

  <!-- Renew -->
  <v-dialog v-model="renewOpen" max-width="460">
    <v-card>
      <v-card-title>{{ t('tempDevices.renewTitle') }}</v-card-title>
      <v-card-text>
        <p class="text-body-2 mb-2">{{ t('tempDevices.renewFrom', { until: renewing ? fmt(renewing.access_until_ms) : '' }) }}</p>
        <duration-fields v-model:amount="renewForm.amount" v-model:unit="renewForm.unit" :units="units" :label="t('tempDevices.extendBy')" />
        <v-alert v-if="formError" type="error" variant="tonal" density="compact" class="mt-3">{{ formError }}</v-alert>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="renewOpen = false">{{ t('common.cancel') }}</v-btn>
        <v-btn color="primary" :loading="busy" @click="renew">{{ t('tempDevices.renew') }}</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>

  <!-- Make an enrolled device temporary -->
  <v-dialog v-model="convertOpen" max-width="560" :fullscreen="fullscreen">
    <v-card>
      <v-card-title>{{ t('tempDevices.convert') }}</v-card-title>
      <v-card-text>
        <v-alert type="warning" variant="tonal" density="compact" class="mb-3">{{ t('tempDevices.convertWarn') }}</v-alert>
        <v-autocomplete
          v-model="convertForm.agents"
          :items="deviceItems"
          :label="t('tempDevices.devices')"
          multiple
          chips
          closable-chips
          density="compact"
        />
        <duration-fields v-model:amount="convertForm.amount" v-model:unit="convertForm.unit" :units="units" :label="t('tempDevices.duration')" />
        <v-select
          v-model="convertForm.roles"
          :items="roleItems"
          :label="t('tempDevices.roles')"
          :hint="t('tempDevices.rolesHint')"
          persistent-hint
          multiple
          chips
          density="compact"
          class="mt-2"
        />
        <v-alert v-if="formError" type="error" variant="tonal" density="compact" class="mt-3">{{ formError }}</v-alert>
        <v-alert v-if="convertDone" type="success" variant="tonal" density="compact" class="mt-3">{{ convertDone }}</v-alert>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="convertOpen = false">{{ t('common.close') }}</v-btn>
        <v-btn color="primary" :loading="busy" :disabled="!convertForm.agents.length" @click="convert">{{ t('tempDevices.convertGo') }}</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { computed, defineComponent, h, onMounted, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { VSelect, VTextField } from 'vuetify/components'
import { api, ApiError } from '@/api/client'
import { useAgentStore } from '@/stores/agents'
import { useRoleStore } from '@/stores/role'
import { useResponsiveDialog } from '@/composables/useResponsiveDialog'

interface Renewal { at_ms: number; by: string; previous_until_ms: number; until_ms: number }
interface InviteRow {
  id: string
  inviter_user_id: string
  label: string
  allow_role_ids: string[]
  state: 'open' | 'redeemed' | 'enrolled' | 'ended'
  access_until_ms: number
  created_at_ms: number
  redeemed_at_ms: number | null
  agent_id: string | null
  device_name: string | null
  device_os: string | null
  ended_at_ms: number | null
  end_reason: string | null
  ended_by: string | null
  converted: boolean
  renewals: Renewal[]
}
interface Created extends InviteRow { code: string; join_command: string }

const props = defineProps<{ tenantId: string }>()
const { t } = useI18n()
const agentStore = useAgentStore()
const roleStore = useRoleStore()
const { fullscreen } = useResponsiveDialog()

/** Seconds per unit. A month is 30 days and a year 365, said in the UI. */
const UNIT_SECS: Record<string, number> = {
  minute: 60,
  hour: 3600,
  day: 86_400,
  week: 604_800,
  month: 2_592_000,
  year: 31_536_000,
}
const units = computed(() =>
  Object.keys(UNIT_SECS).map((u) => ({ value: u, title: t(`tempDevices.unit.${u}`) })),
)

/** Amount + unit, side by side. */
const DurationFields = defineComponent({
  props: { amount: Number, unit: String, units: Array, label: String },
  emits: ['update:amount', 'update:unit'],
  setup(p, { emit }) {
    return () =>
      h('div', { class: 'd-flex ga-2' }, [
        h(VTextField, {
          modelValue: p.amount,
          'onUpdate:modelValue': (v: string) => emit('update:amount', Number(v)),
          type: 'number',
          min: 1,
          label: p.label,
          density: 'compact',
          style: 'max-width: 160px',
        }),
        h(VSelect, {
          modelValue: p.unit,
          'onUpdate:modelValue': (v: string) => emit('update:unit', v),
          items: p.units as unknown[],
          density: 'compact',
        }),
      ])
  },
})

const available = ref(false)
const rows = ref<InviteRow[]>([])
const error = ref<string | null>(null)
const filter = ref<'active' | 'all'>('active')
const shown = computed(() => (filter.value === 'all' ? rows.value : rows.value.filter((r) => r.state !== 'ended')))
const busy = ref(false)
const formError = ref<string | null>(null)

const roleItems = computed(() => roleStore.roles.map((r) => ({ value: r.id, title: r.name })))
const temporaryAgents = computed(
  () => new Set(rows.value.filter((r) => r.state === 'enrolled' && r.agent_id).map((r) => r.agent_id as string)),
)
const deviceItems = computed(() =>
  agentStore.agents
    .filter((a) => !temporaryAgents.value.has(a.id))
    .map((a) => ({ value: a.id, title: (a as { display_name?: string }).display_name || a.name })),
)

function secs(amount: number, unit: string): number {
  return Math.round((amount || 0) * (UNIT_SECS[unit] || 0))
}
function fmt(ms: number | null | undefined): string {
  if (!ms) return ''
  return new Date(ms).toLocaleString()
}
function remaining(until: number): string {
  const s = Math.max(0, Math.floor((until - Date.now()) / 1000))
  const d = Math.floor(s / 86_400)
  const hh = Math.floor((s % 86_400) / 3600)
  const mm = Math.floor((s % 3600) / 60)
  if (d >= 1) return t('tempDevices.dh', { d, h: hh })
  if (hh >= 1) return t('tempDevices.hm', { h: hh, m: mm })
  return t('tempDevices.m', { m: Math.max(mm, s > 0 ? 1 : 0) })
}
function stateText(r: InviteRow): string {
  if (r.state === 'open' && r.access_until_ms <= Date.now()) return t('tempDevices.state.ended')
  return t(`tempDevices.state.${r.state}`)
}
function stateColor(r: InviteRow): string {
  return { open: 'info', redeemed: 'warning', enrolled: 'success', ended: undefined }[r.state] || ''
}
function reasonText(r: InviteRow): string {
  const key = (r.end_reason || '').replace(/^temporary_/, '')
  const known = ['expired', 'revoked', 'left', 'removed', 'unbound', 'made_permanent']
  return known.includes(key) ? t(`tempDevices.reason.${key}`) : r.end_reason || ''
}
function message(e: unknown): string {
  return e instanceof ApiError || e instanceof Error ? e.message : String(e)
}

async function refresh() {
  error.value = null
  try {
    const r = await api.get<{ items: InviteRow[] }>(`/tenant/${props.tenantId}/device-invite`)
    rows.value = r.items
    available.value = true
  } catch (e) {
    // 503: the server does not offer temporary devices; 403: no MANAGE_AGENTS.
    // Either way the section stays out of the way.
    const status = e instanceof ApiError ? e.status : 0
    if (status === 503 || status === 403 || status === 404) {
      available.value = false
    } else {
      available.value = true
      error.value = message(e)
    }
  }
}

// ─── create ───
const createOpen = ref(false)
const created = ref<Created | null>(null)
const copied = ref(false)
const form = reactive({ amount: 1, unit: 'hour', label: '', roles: [] as string[] })
function openCreate() {
  created.value = null
  formError.value = null
  copied.value = false
  createOpen.value = true
  void roleStore.fetchRoles(props.tenantId)
}
async function create() {
  busy.value = true
  formError.value = null
  try {
    created.value = await api.post<Created>(`/tenant/${props.tenantId}/device-invite`, {
      duration_secs: secs(form.amount, form.unit),
      label: form.label || undefined,
      allow_role_ids: form.roles,
    })
    void refresh()
  } catch (e) {
    formError.value = message(e)
  } finally {
    busy.value = false
  }
}
async function copyCode() {
  if (!created.value) return
  try {
    await navigator.clipboard.writeText(created.value.code)
    copied.value = true
  } catch {
    copied.value = false
  }
}
function closeCreate() {
  createOpen.value = false
  created.value = null
}

// ─── renew ───
const renewOpen = ref(false)
const renewing = ref<InviteRow | null>(null)
const renewForm = reactive({ amount: 1, unit: 'day' })
function openRenew(r: InviteRow) {
  renewing.value = r
  formError.value = null
  renewOpen.value = true
}
async function renew() {
  if (!renewing.value) return
  busy.value = true
  formError.value = null
  try {
    await api.post(`/tenant/${props.tenantId}/device-invite/${renewing.value.id}/renew`, {
      duration_secs: secs(renewForm.amount, renewForm.unit),
    })
    renewOpen.value = false
    void refresh()
  } catch (e) {
    formError.value = message(e)
  } finally {
    busy.value = false
  }
}

// ─── end by hand ───
async function revoke(r: InviteRow) {
  const name = r.device_name || r.label || r.id
  if (!window.confirm(t(r.agent_id ? 'tempDevices.revokeConfirmDevice' : 'tempDevices.revokeConfirm', { name }))) return
  try {
    await api.delete(`/tenant/${props.tenantId}/device-invite/${r.id}`)
    void refresh()
    void agentStore.fetchAgents(props.tenantId)
  } catch (e) {
    error.value = message(e)
  }
}

// ─── an ordinary device again (it stays enrolled) ───
async function makePermanent(r: InviteRow) {
  const name = r.device_name || r.id
  if (!window.confirm(t('tempDevices.permanentConfirm', { name }))) return
  try {
    await api.delete(`/tenant/${props.tenantId}/agent/${r.agent_id}/temporary`)
    void refresh()
  } catch (e) {
    error.value = message(e)
  }
}

// ─── make enrolled devices temporary ───
const convertOpen = ref(false)
const convertDone = ref<string | null>(null)
const convertForm = reactive({ agents: [] as string[], amount: 1, unit: 'year', roles: [] as string[] })
function openConvert() {
  formError.value = null
  convertDone.value = null
  convertForm.agents = []
  convertOpen.value = true
  void agentStore.fetchAgents(props.tenantId)
  void roleStore.fetchRoles(props.tenantId)
}
async function convert() {
  busy.value = true
  formError.value = null
  convertDone.value = null
  let ok = 0
  const failed: string[] = []
  for (const id of convertForm.agents) {
    try {
      await api.post(`/tenant/${props.tenantId}/agent/${id}/temporary`, {
        duration_secs: secs(convertForm.amount, convertForm.unit),
        allow_role_ids: convertForm.roles,
      })
      ok++
    } catch (e) {
      const name = deviceItems.value.find((d) => d.value === id)?.title || id
      failed.push(`${name}: ${message(e)}`)
    }
  }
  busy.value = false
  convertForm.agents = []
  if (ok) convertDone.value = t('tempDevices.convertedN', { n: ok })
  if (failed.length) formError.value = failed.join('\n')
  void refresh()
}

onMounted(refresh)
watch(() => props.tenantId, refresh)
</script>

<style scoped>
.code-big {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 2.4rem;
  letter-spacing: 0.15em;
  text-align: center;
  padding: 12px 0;
}
</style>
