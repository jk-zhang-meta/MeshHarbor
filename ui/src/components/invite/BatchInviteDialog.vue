<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-dialog
    :model-value="modelValue"
    max-width="700"
    :fullscreen="fullscreen"
    @update:model-value="$emit('update:modelValue', $event)"
  >
    <v-card>
      <v-card-title class="d-flex align-center">
        <v-icon class="mr-2">mdi-email-multiple</v-icon>
        {{ t('mh.invite.batch') }}
      </v-card-title>

      <v-card-text>
        <p class="text-body-2 text-medium-emphasis mb-4">
          {{ t('mh.invite.batchIntro') }}
        </p>

        <!-- Invite rows. FR-116: on a phone the email takes a line of its
             own — beside a 180 px role picker it was ~60 px wide. -->
        <div
          v-for="(row, idx) in rows"
          :key="idx"
          class="d-flex align-center ga-3 mb-3"
          :class="{ 'flex-wrap': fullscreen }"
        >
          <v-text-field
            v-model="row.email"
            :label="t('mh.invite.emailShort')"
            type="email"
            density="compact"
            hide-details
            :rules="[emailRule]"
            class="flex-grow-1"
            :style="fullscreen ? 'flex-basis: 100%' : undefined"
          />
          <v-select
            v-model="row.role_id"
            :items="assignableRoles"
            item-title="name"
            item-value="id"
            :label="t('mh.invite.role')"
            density="compact"
            hide-details
            :style="fullscreen ? undefined : 'max-width: 180px'"
          />
          <v-btn
            icon
            size="small"
            variant="text"
            color="error"
            :disabled="rows.length <= 1"
            @click="removeRow(idx)"
          >
            <v-icon>mdi-close</v-icon>
          </v-btn>
        </div>

        <v-btn
          variant="text"
          size="small"
          prepend-icon="mdi-plus"
          @click="addRow"
        >
          {{ t('mh.invite.addAnother') }}
        </v-btn>

        <!-- Shared settings -->
        <v-divider class="my-4" />
        <v-text-field
          v-model.number="expiresInHours"
          :label="t('mh.invite.expires')"
          type="number"
          min="1"
          density="compact"
          :hint="t('mh.invite.defaultHint')"
          persistent-hint
        />

        <!-- Results -->
        <v-alert v-if="resultMessage" :type="resultType" variant="tonal" class="mt-4">
          {{ resultMessage }}
        </v-alert>

        <div v-if="results.length > 0" class="mt-3">
          <div v-for="(r, i) in results" :key="i" class="d-flex align-center text-body-2 mb-1">
            <v-icon
              :color="r.error ? 'error' : 'success'"
              size="small"
              class="mr-2"
            >
              {{ r.error ? 'mdi-close-circle' : 'mdi-check-circle' }}
            </v-icon>
            <span>{{ r.target_email || t('mh.invite.nth', { n: i + 1 }) }}</span>
            <span v-if="r.error" class="text-error ml-2">— {{ r.error }}</span>
          </div>
        </div>
      </v-card-text>

      <v-card-actions>
        <v-spacer />
        <v-btn @click="close">
          {{ results.length > 0 ? t('mh.invite.done') : t('common.cancel') }}
        </v-btn>
        <v-btn
          v-if="results.length === 0"
          color="primary"
          :loading="sending"
          :disabled="!isValid"
          @click="send"
        >
          {{ t('mh.invite.sendAll', { n: validRows.length }) }}
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useInviteStore } from '@/stores/invite'
import { useSnackbar } from '@/composables/useSnackbar'
import { useResponsiveDialog } from '@/composables/useResponsiveDialog'
import type { Role } from '@/stores/role'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

interface InviteRow {
  email: string
  role_id: string
}

interface ResultItem {
  target_email?: string
  error?: string
}

const props = defineProps<{
  modelValue: boolean
  tenantId: string
  roles: Role[]
}>()

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
}>()

const inviteStore = useInviteStore()
const { showSuccess, showError } = useSnackbar()
const { fullscreen } = useResponsiveDialog()

const rows = ref<InviteRow[]>([{ email: '', role_id: '' }])
const expiresInHours = ref<number | undefined>(undefined)
const sending = ref(false)
const results = ref<ResultItem[]>([])
const resultMessage = ref('')
const resultType = ref<'success' | 'error' | 'warning'>('success')

const assignableRoles = computed(() =>
  props.roles.filter((r) => !r.is_managed || r.name === 'member'),
)

const emailRule = (v: string) => {
  if (!v) return true // empty rows are filtered out
  return /.+@.+\..+/.test(v) || t('mh.invite.invalidEmail')
}

const validRows = computed(() =>
  rows.value.filter((r) => r.email && /.+@.+\..+/.test(r.email)),
)

const isValid = computed(() => validRows.value.length > 0)

function addRow() {
  rows.value.push({ email: '', role_id: '' })
}

function removeRow(idx: number) {
  rows.value.splice(idx, 1)
}

async function send() {
  sending.value = true
  results.value = []
  resultMessage.value = ''
  try {
    const params = validRows.value.map((row) => ({
      target_email: row.email,
      expires_in_hours: expiresInHours.value,
      assign_role_ids: row.role_id ? [row.role_id] : [],
    }))

    const response = await inviteStore.batchCreateInvites(props.tenantId, params)
    results.value = response.results.map((r) => ({
      target_email: r.target_email,
      error: r.error,
    }))

    // "Sent" is a claim about EMAILS, not rows — for months the batch route
    // created rows and dispatched nothing while this dialog said "N sent".
    // Count what the server says it actually dispatched (absent on an old
    // server ⇒ 0 ⇒ the honest created-only wording).
    const emailsSent = response.results.filter((r) => r.invite?.email_sent).length
    const sentNote =
      emailsSent === response.created
        ? ''
        : emailsSent > 0
          ? ` ${t(emailsSent === 1 ? 'mh.invite.emailOne' : 'mh.invite.emailMany', { n: emailsSent })}`
          : ` ${t('mh.invite.noEmails')}`
    if (response.failed === 0) {
      resultType.value = emailsSent === response.created ? 'success' : 'warning'
      resultMessage.value = `${t('mh.invite.allCreated', { n: response.created })}${sentNote}`
      showSuccess(
        emailsSent === response.created
          ? t('mh.invite.nSent', { n: response.created })
          : t('mh.invite.nCreated', { n: response.created }),
      )
    } else if (response.created === 0) {
      resultType.value = 'error'
      resultMessage.value = t('mh.invite.allFailed', { n: response.failed })
      showError(t('mh.invite.allFailedShort'))
    } else {
      resultType.value = 'warning'
      resultMessage.value = `${t('mh.invite.mixed', { created: response.created, failed: response.failed })}${sentNote}`
    }
  } catch {
    resultType.value = 'error'
    resultMessage.value = t('mh.invite.batchFailed')
    showError(t('mh.invite.batchFailedShort'))
  } finally {
    sending.value = false
  }
}

function close() {
  results.value = []
  resultMessage.value = ''
  rows.value = [{ email: '', role_id: '' }]
  expiresInHours.value = undefined
  emit('update:modelValue', false)
}
</script>
