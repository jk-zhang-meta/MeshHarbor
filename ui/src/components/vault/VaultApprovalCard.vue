<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  FR-90 P3-4e-3 — the answer to a vault approval card. The vault posts the
  card into a session's room as a message (P3-4e-1); this sits under that
  message's text: where the approval stands, and Approve / Deny for a driver
  who may answer it now.

  The vault decides everything. Who may answer (`may_answer`) and whether the
  policy would take this person's yes (`may_approve`) come from
  `GET …/vault/approval/{id}`, and an answer the server refuses is shown in
  its own words. The card's text is the message above, which every chat
  client renders, so nothing here repeats what was asked.
-->
<template>
  <div
    v-if="approval"
    class="vault-approval d-flex align-center flex-wrap ga-2"
    data-testid="vault-approval"
    :data-status="approval.status"
  >
    <v-chip size="small" variant="tonal" :color="color" data-testid="vault-approval-status">
      {{ $t(`vault.approval.status.${statusKey}`) }}
    </v-chip>
    <span
      v-if="approval.status === 'pending'"
      class="text-caption text-medium-emphasis"
      data-testid="vault-approval-deadline"
    >
      {{ $t('vault.approval.answerBy', { time: deadline }) }}
    </span>
    <v-spacer />
    <template v-if="approval.may_answer">
      <v-btn
        size="small"
        variant="text"
        :loading="busy === 'deny'"
        :disabled="busy !== null"
        data-testid="vault-approval-deny"
        @click="answer('deny')"
      >
        {{ $t('vault.approval.deny') }}
      </v-btn>
      <v-btn
        size="small"
        variant="tonal"
        color="primary"
        :loading="busy === 'approve'"
        :disabled="busy !== null || !approval.may_approve"
        :title="approval.may_approve ? undefined : $t('vault.approval.notAccepted')"
        data-testid="vault-approval-approve"
        @click="answer('approve')"
      >
        {{ $t('vault.approval.approve') }}
      </v-btn>
      <!-- FR-120 P1b — a greyed Approve says why, as text: its `title`
           reached no one, a disabled button taking no pointer events. -->
      <span
        v-if="!approval.may_approve"
        class="text-caption text-medium-emphasis w-100 text-right"
        data-testid="vault-approval-why"
      >
        {{ $t('vault.approval.notAccepted') }}
      </span>
    </template>
    <v-alert
      v-if="refusal"
      type="warning"
      variant="tonal"
      density="compact"
      class="w-100"
      data-testid="vault-approval-refused"
    >
      {{ refusal }}
    </v-alert>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { api } from '@/api/client'

/** What `GET …/vault/approval/{id}` answers, as far as this card reads it. */
interface Approval {
  id: string
  status: string
  expires_at: string
  may_answer: boolean
  may_approve: boolean
}

const props = defineProps<{
  tenantId: string
  approvalId: string
  /** The card message's `updated_at`: the vault edits the message whenever
   *  the approval moves on, so a new stamp is the cue to read it again. */
  stamp?: string
}>()

const approval = ref<Approval | null>(null)
const busy = ref<'approve' | 'deny' | null>(null)
const refusal = ref('')

const STATUSES = ['pending', 'approved', 'denied', 'used', 'expired', 'withdrawn']
const statusKey = computed(() =>
  approval.value && STATUSES.includes(approval.value.status) ? approval.value.status : 'unknown',
)
const color = computed(() => {
  switch (approval.value?.status) {
    case 'pending':
      return 'warning'
    case 'approved':
    case 'used':
      return 'success'
    case 'denied':
      return 'error'
    default:
      return undefined
  }
})
const deadline = computed(() =>
  approval.value
    ? new Date(approval.value.expires_at).toLocaleTimeString(undefined, {
        hour: '2-digit',
        minute: '2-digit',
      })
    : '',
)

const path = computed(() => `/tenant/${props.tenantId}/vault/approval/${props.approvalId}`)

async function load() {
  try {
    approval.value = await api.get<Approval>(path.value)
  } catch {
    // A card this person cannot read (a 404, as for an id that names
    // nothing), or no vault mounted: the message above still says what it
    // is, and there is nothing to answer.
    approval.value = null
  }
}

async function answer(which: 'approve' | 'deny') {
  busy.value = which
  refusal.value = ''
  try {
    approval.value = await api.post<Approval>(path.value, { answer: which })
  } catch (e) {
    // The server's own words: not a driver now, a yes the policy does not
    // take, or answered, expired or withdrawn meanwhile.
    refusal.value = (e as Error).message
    await load()
  } finally {
    busy.value = null
  }
}

watch(() => [props.tenantId, props.approvalId, props.stamp], load, { immediate: true })
</script>
