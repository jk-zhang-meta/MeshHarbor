<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-card variant="outlined">
    <v-card-title class="d-flex align-center">
      <v-icon icon="mdi-console-network-outline" color="primary" class="mr-2" />
      <span>{{ t('mh.audit.ssh.title') }}</span>
      <v-spacer />
      <v-btn
        icon="mdi-refresh"
        size="small"
        variant="text"
        :loading="loading"
        :aria-label="t('mh.audit.refresh')"
        @click="load"
      />
    </v-card-title>

    <v-card-subtitle class="pb-2 text-wrap">
      {{ t('mh.audit.ssh.subtitle') }}
    </v-card-subtitle>

    <v-card-text>
      <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mb-3">
        {{ error }}
      </v-alert>

      <!-- Says plainly what a row is, because the natural reading of an "SSH
           audit" is a session log and this is not one. The server hands out a
           grant and then steps out of the way. -->
      <v-alert type="info" variant="tonal" density="compact" class="mb-3">
        <i18n-t keypath="mh.audit.ssh.info" tag="span" scope="global">
          <template #decisions><strong>{{ t('mh.audit.ssh.decisions') }}</strong></template>
        </i18n-t>
      </v-alert>

      <div v-if="!loading && !entries.length" class="text-medium-emphasis text-caption">
        {{ t('mh.audit.ssh.empty') }}
      </div>

      <!-- A card per entry below 600 px (table-stack-xs): the result and the
           command or detail sat about three screens to the right. Compact
           (labels beside short values) and 20 cards at a time. -->
      <template v-else>
        <v-table density="compact" class="table-stack-xs table-stack-xs--compact">
          <thead>
            <tr>
              <th>{{ t('mh.audit.col.when') }}</th>
              <th>{{ t('mh.audit.col.device') }}</th>
              <th>{{ t('mh.audit.col.who') }}</th>
              <th>{{ t('mh.audit.col.via') }}</th>
              <th>{{ t('mh.audit.col.as') }}</th>
              <th>{{ t('mh.audit.col.result') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(e, i) in visible" :key="e.id ?? `${e.at}-${i}`">
              <td :data-label="t('mh.audit.col.when')" class="text-no-wrap">{{ fmtWhen(e.at) }}</td>
              <td :data-label="t('mh.audit.col.device')" class="text-no-wrap">{{ deviceName(e.agent_id) }}</td>
              <td :data-label="t('mh.audit.col.who')" class="text-no-wrap">{{ userName(e.user_id) }}</td>
              <td :data-label="t('mh.audit.col.via')">
                <v-chip size="x-small" variant="tonal">{{ e.source }}</v-chip>
              </td>
              <td :data-label="t('mh.audit.col.as')" class="text-no-wrap">
                <v-chip
                  v-if="asChip(e)"
                  size="x-small"
                  :color="asChip(e)?.color"
                  :title="asChip(e)?.title"
                  variant="tonal"
                >
                  {{ asChip(e)?.label }}
                </v-chip>
                <span v-else class="text-medium-emphasis">—</span>
              </td>
              <td :data-label="t('mh.audit.col.result')" class="text-no-wrap">
                <!-- One v-if / v-else pair around the whole refusal: the
                     reason line must not sit between them, or a refusal
                     without a message also showed "granted". -->
                <template v-if="e.denied">
                  <v-tooltip :text="e.denied_message ?? ''" location="top">
                    <template #activator="{ props: tip }">
                      <v-chip v-bind="tip" size="x-small" color="error" variant="flat">
                        {{ denyLabel(e) }}
                      </v-chip>
                    </template>
                  </v-tooltip>
                  <!-- A touch screen never hovers: the server's own reason,
                       spelled out on the phone card. -->
                  <div v-if="e.denied_message" class="text-caption text-medium-emphasis d-sm-none">
                    {{ e.denied_message }}
                  </div>
                </template>
                <v-chip v-else size="x-small" color="success" variant="flat">{{ t('mh.audit.granted') }}</v-chip>
              </td>
            </tr>
          </tbody>
        </v-table>
        <div v-if="remaining" class="text-center mt-2">
          <v-btn variant="tonal" size="small" data-testid="audit-show-more" @click="showMore">
            {{ t('mh.audit.showMore', { n: nextCount }) }}
          </v-btn>
        </div>
      </template>
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useAgentStore, type SshAuditEntry } from '@/stores/agents'
import { deviceLabel } from '@/composables/useHideDeviceName'
import { usePhoneSlice } from '@/composables/usePhoneSlice'
import { sshAsChip, type SshAsChip } from '@/utils/sshIdentity'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const props = defineProps<{
  tenantId: string
  /** Narrow to one device's history; omit for the whole org. */
  agentId?: string
}>()

const agentStore = useAgentStore()
const entries = ref<SshAuditEntry[]>([])
// FR-116 P3d — a phone shows 20 cards at a time.
const { visible, remaining, nextCount, showMore } = usePhoneSlice(entries)
const loading = ref(false)
const error = ref<string | null>(null)

/** Short wording per refusal, so a reader learns WHICH gate said no at a
 *  glance. The server also sends the full sentence as `denied_message`, which
 *  the tooltip shows — this map is only for the chip, and an unknown reason
 *  falls through to the raw value rather than rendering blank. */
/** Refusal codes this UI names; any other is shown as sent. SSH words two of
 *  them its own way. */
const DENY_CODES = new Set([
  'org_disabled',
  'no_permission',
  'device_disabled',
  'caller_not_allowed',
  'origin_not_allowed',
  'unsupported',
  'offline',
  'no_overlay_address',
  'rate_limited',
  'bad_public_key',
  'grant_expired_on_arrival',
  'grant_refused',
  'grant_unconfirmed',
])
const SSH_DENY_CODES = new Set(['agent_disabled', 'claim_refused'])

const deviceNames = computed(() => {
  const m: Record<string, string> = {}
  for (const a of agentStore.agents) m[a.id] = deviceLabel(a)
  return m
})

const userNames = computed(() => {
  const m: Record<string, string> = {}
  for (const u of agentStore.tenantMembers) m[u.user_id] = u.display_name || u.nickname || u.user_id
  return m
})

function deviceName(id: string): string {
  return deviceNames.value[id] ?? id.slice(0, 8)
}

/** FR-105 — a device's SYSTEM service claiming a grant that is not pending
 *  for it (a forged ring) is recorded with no person behind it: the server
 *  writes the all-zero id, which would otherwise render as "00000000". */
const NO_USER = '000000000000000000000000'

function userName(id: string): string {
  if (id === NO_USER) return t('mh.audit.deviceService')
  return userNames.value[id] ?? id.slice(0, 8)
}

function denyLabel(e: SshAuditEntry): string {
  if (!e.denied) return t('mh.audit.denied')
  if (SSH_DENY_CODES.has(e.denied)) return t(`mh.audit.sshDeny.${e.denied}`)
  return DENY_CODES.has(e.denied) ? t(`mh.audit.deny.${e.denied}`) : e.denied
}

/** FR-105 — the account the session ran as, from what the grant asked for AND
 *  where the server sent it. `daemon` on the agent's own process is not
 *  "SYSTEM / root" everywhere: on an attended Windows install it is the
 *  signed-in user. SYSTEM-level identities keep the warning colour: they are
 *  worth a second's attention in a list of otherwise ordinary rows. */
function asChip(e: SshAuditEntry): SshAsChip | null {
  return sshAsChip(e.account_mode, e.ran_as)
}

function fmtWhen(at: string): string {
  const d = new Date(at)
  return Number.isNaN(d.getTime()) ? at : d.toLocaleString()
}

async function load() {
  loading.value = true
  error.value = null
  try {
    const res = await agentStore.fetchSshAudit(props.tenantId, {
      agentId: props.agentId,
      perPage: 100,
    })
    entries.value = res.items
  } catch (e) {
    error.value = (e as Error).message
    entries.value = []
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  void load()
  if (!agentStore.tenantMembers.length) {
    void agentStore.fetchTenantMembers(props.tenantId)
  }
})

defineExpose({ load })
</script>
