<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- The other side of temporary devices: invitations that THIS organization's
     devices accepted from other people (other organizations), as each
     machine proved with the private proof its redemption handed it. Who
     invited, from which organization, until when, and the whole history —
     and the owner may end any of them: the owner's word wins.

     A machine that accepted an invitation while signed in nowhere appears
     here once it signs in to this organization. -->
<template>
  <v-card v-if="available && rows.length" class="mt-4" data-testid="accepted-invites">
    <v-card-title class="d-flex align-center flex-wrap ga-2">
      <v-icon icon="mdi-account-arrow-left" color="primary" class="mr-2" />
      {{ t('acceptedInvites.title') }}
    </v-card-title>
    <v-card-text>
      <p class="text-body-2 text-medium-emphasis mb-3">{{ t('acceptedInvites.intro') }}</p>
      <v-btn-toggle v-model="filter" density="compact" mandatory class="mb-3" color="primary" variant="outlined">
        <v-btn value="active" size="small">{{ t('tempDevices.filter.active') }}</v-btn>
        <v-btn value="all" size="small">{{ t('tempDevices.filter.all') }}</v-btn>
      </v-btn-toggle>
      <v-table v-if="shown.length" density="compact" class="table-stack-xs">
        <thead>
          <tr>
            <th>{{ t('acceptedInvites.col.device') }}</th>
            <th>{{ t('acceptedInvites.col.from') }}</th>
            <th>{{ t('tempDevices.col.state') }}</th>
            <th>{{ t('tempDevices.col.until') }}</th>
            <th>{{ t('tempDevices.col.history') }}</th>
            <th class="text-right">{{ t('tempDevices.col.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in shown" :key="r.id" :data-testid="`accepted-row-${r.id}`">
            <td class="font-weight-medium">{{ r.host_device_name || t('acceptedInvites.unknownDevice') }}</td>
            <td :data-label="t('acceptedInvites.col.from')">
              {{ r.inviter || t('acceptedInvites.someone') }}
              <div v-if="r.org" class="text-caption text-medium-emphasis">{{ r.org }}</div>
            </td>
            <td :data-label="t('tempDevices.col.state')">
              <v-chip size="x-small" :color="r.state === 'ended' ? undefined : 'success'" variant="tonal">
                {{ r.state === 'ended' ? t('tempDevices.state.ended') : t('acceptedInvites.inEffect') }}
              </v-chip>
              <div v-if="r.state === 'ended'" class="text-caption text-medium-emphasis">
                {{ reasonText(r.end_reason) }} · {{ fmt(r.ended_at_ms) }}
              </div>
            </td>
            <td :data-label="t('tempDevices.col.until')">
              {{ fmt(r.access_until_ms) }}
              <div v-if="r.state !== 'ended'" class="text-caption text-medium-emphasis">
                {{ t('tempDevices.left', { left: remaining(r.access_until_ms) }) }}
              </div>
            </td>
            <td :data-label="t('tempDevices.col.history')" class="text-caption">
              <div v-if="r.redeemed_at_ms">{{ t('acceptedInvites.accepted', { when: fmt(r.redeemed_at_ms) }) }}</div>
              <div v-for="(x, i) in r.renewals" :key="i">
                {{ t('tempDevices.renewedLine', { when: fmt(x.at_ms), until: fmt(x.until_ms) }) }}
              </div>
            </td>
            <td class="text-right text-no-wrap">
              <v-btn
                v-if="r.state !== 'ended'"
                size="x-small"
                variant="text"
                color="error"
                :data-testid="`accepted-end-${r.id}`"
                @click="end(r)"
              >
                {{ t('acceptedInvites.end') }}
              </v-btn>
            </td>
          </tr>
        </tbody>
      </v-table>
      <div v-else class="text-center pa-4 text-medium-emphasis">{{ t('acceptedInvites.noneActive') }}</div>
      <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mt-3">{{ error }}</v-alert>
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { api, ApiError } from '@/api/client'

interface Renewal { at_ms: number; previous_until_ms: number; until_ms: number }
interface GrantRow {
  id: string
  host_agent_id: string | null
  host_device_name: string | null
  inviter: string
  org: string
  state: 'open' | 'redeemed' | 'enrolled' | 'ended'
  access_until_ms: number
  created_at_ms: number
  redeemed_at_ms: number | null
  ended_at_ms: number | null
  end_reason: string | null
  renewals: Renewal[]
}

const props = defineProps<{ tenantId: string }>()
const { t } = useI18n()

const available = ref(false)
const rows = ref<GrantRow[]>([])
const error = ref<string | null>(null)
const filter = ref<'active' | 'all'>('active')
const shown = computed(() => (filter.value === 'all' ? rows.value : rows.value.filter((r) => r.state !== 'ended')))

function fmt(ms: number | null | undefined): string {
  return ms ? new Date(ms).toLocaleString() : ''
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
function reasonText(reason: string | null): string {
  const key = (reason || '').replace(/^temporary_/, '')
  const known = ['expired', 'revoked', 'left', 'removed', 'unbound', 'made_permanent', 'ended_by_owner']
  return known.includes(key) ? t(`tempDevices.reason.${key}`) : reason || ''
}
function message(e: unknown): string {
  return e instanceof ApiError || e instanceof Error ? e.message : String(e)
}

async function refresh() {
  error.value = null
  try {
    const r = await api.get<{ items: GrantRow[] }>(`/tenant/${props.tenantId}/device-grants`)
    rows.value = r.items
    available.value = true
  } catch (e) {
    // 503: not offered by this server; 403: no MANAGE_AGENTS. Stay out of the way.
    const status = e instanceof ApiError ? e.status : 0
    if (status === 503 || status === 403 || status === 404) {
      available.value = false
    } else {
      available.value = true
      error.value = message(e)
    }
  }
}

async function end(r: GrantRow) {
  const name = r.host_device_name || r.id
  if (!window.confirm(t('acceptedInvites.endConfirm', { name, who: r.inviter || t('acceptedInvites.someone') }))) return
  try {
    await api.delete(`/tenant/${props.tenantId}/device-grants/${r.id}`)
    void refresh()
  } catch (e) {
    error.value = message(e)
  }
}

onMounted(refresh)
watch(() => props.tenantId, refresh)
</script>
