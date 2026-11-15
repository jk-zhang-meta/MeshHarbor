<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<template>
  <v-card variant="outlined" class="mt-6" data-testid="email-account-change">
    <v-card-title>{{ t('auth.emailChange.title') }}</v-card-title>
    <v-card-text>
      <p class="text-body-2 mb-3">{{ t('auth.emailChange.intro') }}</p>
      <p class="text-body-2 mb-4">{{ t('auth.emailChange.current', { email: auth.user?.email ?? '—' }) }}</p>
      <v-alert v-if="sent" type="success" class="mb-3" role="status">{{ t('auth.emailChange.sent', { email: sent }) }}</v-alert>
      <v-alert v-if="error" type="error" class="mb-3" role="alert">{{ error }}</v-alert>
      <v-form ref="form" @submit.prevent="request">
        <v-text-field v-model="email" :disabled="busy" type="email" inputmode="email" autocomplete="email" autocapitalize="none" autocorrect="off" :label="t('auth.emailChange.newEmail')" :rules="[rules.required, rules.email]" />
        <v-text-field v-model="currentPassword" :disabled="busy" type="password" autocomplete="current-password" :label="t('auth.emailChange.currentPassword')" :rules="[rules.required]" />
        <v-text-field v-model="newPassword" :disabled="busy" type="password" autocomplete="new-password" :label="t('auth.emailChange.newPassword')" :hint="t('auth.emailChange.passwordHint')" persistent-hint />
        <v-text-field v-model="repeatPassword" :disabled="busy" type="password" autocomplete="new-password" :label="t('auth.emailChange.repeatPassword')" :rules="[value => value === newPassword || t('auth.emailChange.passwordMismatch')]" />
        <v-btn type="submit" color="primary" :disabled="busy" :loading="busy">{{ t('auth.emailChange.send') }}</v-btn>
      </v-form>
    </v-card-text>
  </v-card>
</template>
<script setup lang="ts">
import { onUnmounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { useValidation } from '@/composables/useValidation'
const { t } = useI18n()
const auth = useAuthStore()
const { rules } = useValidation()
const form = ref<{ validate: () => Promise<{ valid: boolean }> }>()
const email = ref('')
const currentPassword = ref('')
const newPassword = ref('')
const repeatPassword = ref('')
const busy = ref(false)
const sent = ref('')
const error = ref('')
let generation = 0
function clearSensitive() { currentPassword.value = ''; newPassword.value = ''; repeatPassword.value = '' }
watch(() => auth.user?.id, () => { generation++; busy.value = false; sent.value = ''; email.value = ''; error.value = ''; clearSensitive() })
onUnmounted(() => { generation++; clearSensitive() })
async function request() {
  if (busy.value) return
  const mine = generation
  busy.value = true
  error.value = ''
  sent.value = ''
  try {
    if (!(await form.value?.validate())?.valid || mine !== generation) return
    const requestedEmail = email.value.trim().toLowerCase()
    const result = await api.post<{ message: string; email: string }>('/auth/email-change/request', {
      email: requestedEmail, current_password: currentPassword.value,
      ...(newPassword.value ? { new_password: newPassword.value } : {}),
    })
    if (mine !== generation) return
    if (result.message !== 'verification_sent' || result.email !== requestedEmail) throw new Error(t('auth.emailChange.failed'))
    sent.value = result.email
    clearSensitive()
  } catch (e) { if (mine === generation) { error.value = (e as Error).message; clearSensitive() } }
  finally { if (mine === generation) busy.value = false }
}
</script>
