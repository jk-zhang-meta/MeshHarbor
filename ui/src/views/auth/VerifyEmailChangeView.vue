<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<template>
  <v-container class="py-8" data-testid="email-change-confirm">
    <v-card max-width="600" class="mx-auto pa-5">
      <h1 class="text-h5 mb-3">{{ t('auth.emailChange.confirmTitle') }}</h1>
      <p class="mb-4">{{ t('auth.emailChange.confirmIntro') }}</p>
      <v-alert v-if="success" type="success" role="status">{{ t('auth.emailChange.complete', { email: success }) }}</v-alert>
      <v-alert v-else-if="error" type="error" role="alert">{{ error }}</v-alert>
      <v-btn v-if="!success && !submitted" color="primary" class="mt-4" :disabled="!ready || busy" :loading="busy" @click="confirm">{{ t('auth.emailChange.confirm') }}</v-btn>
      <v-btn v-if="success || submitted" :to="{ name: 'login' }" variant="text" class="mt-4">{{ t('auth.login') }}</v-btn>
    </v-card>
  </v-container>
</template>
<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { useWsStore } from '@/stores/ws'
const route = useRoute()
const router = useRouter()
const { t } = useI18n()
const auth = useAuthStore()
const ws = useWsStore()
const requestId = ref('')
let token = ''
let generation = 0
let initialized = false
const busy = ref(false)
const submitted = ref(false)
const success = ref('')
const error = ref('')
const ready = computed(() => !!requestId.value && !error.value)
watch(() => [route.query.request_id, route.hash] as const, ([rawId, hash]) => {
  const id = typeof rawId === 'string' ? rawId : ''
  // Our own fragment cleanup must not discard the in-memory one-use proof.
  if (initialized && id === requestId.value && !hash) return
  initialized = true
  generation++
  token = ''
  busy.value = false
  submitted.value = false
  success.value = ''
  error.value = ''
  requestId.value = id
  const proof = new URLSearchParams(hash.replace(/^#/, '')).get('token')
  if (!id || id.length > 128 || !proof || proof.length > 2048) error.value = t('auth.emailChange.invalidLink')
  else token = proof
  if (hash || route.query.token) void router.replace({ name: 'verify-email-change', query: id ? { request_id: id } : {} })
}, { immediate: true })
onUnmounted(() => { generation++; token = '' })
async function confirm() {
  if (busy.value || submitted.value || !ready.value || !token) return
  const mine = generation
  const proof = token
  token = ''
  busy.value = true
  submitted.value = true
  try {
    const result = await api.post<{ email: string; email_verified: boolean }>('/auth/email-change/confirm', { request_id: requestId.value, token: proof })
    if (mine !== generation) return
    if (!result.email || result.email_verified !== true) throw new Error('unconfirmed')
    auth.forgetLocalSession()
    ws.disconnect()
    success.value = result.email
  } catch { if (mine === generation) error.value = t('auth.emailChange.confirmFailed') }
  finally { if (mine === generation) busy.value = false }
}
</script>
