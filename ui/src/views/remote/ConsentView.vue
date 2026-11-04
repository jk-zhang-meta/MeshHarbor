<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-container class="d-flex align-center justify-center" style="min-height: 100vh">
    <v-card max-width="440" width="100%" class="pa-2">
      <v-card-title>{{ t('mh.consent.title') }}</v-card-title>
      <v-card-text>
        <template v-if="state === 'idle'">
          <p class="mb-4">
            {{ t('mh.consent.body') }}
          </p>
          <div class="d-flex justify-end ga-2">
            <v-btn
              variant="text"
              color="error"
              :loading="busy && pending === false"
              :disabled="busy"
              @click="decide(false)"
            >
              {{ t('mh.consent.deny') }}
            </v-btn>
            <v-btn
              variant="flat"
              color="primary"
              :loading="busy && pending === true"
              :disabled="busy"
              @click="decide(true)"
            >
              {{ t('mh.consent.approve') }}
            </v-btn>
          </div>
        </template>

        <v-alert v-else-if="state === 'done'" :type="granted ? 'success' : 'info'" variant="tonal">
          {{
            granted
              ? t('mh.consent.approved')
              : t('mh.consent.denied')
          }}
        </v-alert>

        <v-alert v-else type="error" variant="tonal">{{ error }}</v-alert>
      </v-card-text>
    </v-card>
  </v-container>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '@/api/client'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const route = useRoute()
const token = String(route.params.token || '')

type State = 'idle' | 'done' | 'error'
const state = ref<State>('idle')
const busy = ref(false)
// Which button is in flight (drives the per-button spinner).
const pending = ref<boolean | null>(null)
const granted = ref(false)
const error = ref('')

async function decide(approve: boolean) {
  if (busy.value) return
  busy.value = true
  pending.value = approve
  try {
    await api.post(`/consent/${token}/${approve ? 'approve' : 'deny'}`)
    granted.value = approve
    state.value = 'done'
  } catch (e) {
    error.value =
      (e as Error).message ||
      t('mh.consent.failed')
    state.value = 'error'
  } finally {
    busy.value = false
  }
}
</script>
