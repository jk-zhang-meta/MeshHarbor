<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  FR-58 follow-up — the confirm PAGE. The email links here, and the button's
  POST is what confirms. Field-proven necessity: Gmail's link scanner followed
  the old confirming GET and burned the very first real subscriber's
  single-use token before any human clicked. A prefetcher can load this page
  all day; only the deliberate POST flips the row.

  No meta.auth / meta.guest (the consent-route shape); raw fetch rather than
  the api client so an anonymous visitor can never be bounced through the
  401-refresh-logout chain.
-->
<template>
  <v-container class="fill-height pa-2 pa-md-4 pa-xl-6" fluid>
    <v-row align="center" justify="center">
      <v-col cols="12" sm="8" md="6" class="text-center">
        <template v-if="phase === 'ready' || phase === 'busy'">
          <v-icon icon="mdi-email-check-outline" color="primary" size="72" class="mb-6" />
          <h1 class="text-h5 text-md-h4 font-weight-bold mb-4">{{ t('mh.nl.confirmTitle') }}</h1>
          <p class="text-body-1 text-medium-emphasis mb-8">
            {{ t('mh.nl.confirmBody') }}
          </p>
          <v-btn color="primary" size="large" :loading="phase === 'busy'" @click="confirm">
            {{ t('mh.nl.confirmBtn') }}
          </v-btn>
        </template>

        <template v-else-if="phase === 'done'">
          <v-icon icon="mdi-email-check-outline" color="success" size="72" class="mb-6" />
          <h1 class="text-h5 text-md-h4 font-weight-bold mb-4">{{ t('mh.nl.onList') }}</h1>
          <p class="text-body-1 text-medium-emphasis mb-8">
            {{ t('mh.nl.onListBody') }}
          </p>
          <v-btn color="primary" size="large" to="/">{{ t('mh.nl.home') }}</v-btn>
        </template>

        <template v-else-if="phase === 'invalid'">
          <v-icon icon="mdi-link-off" color="warning" size="72" class="mb-6" />
          <h1 class="text-h5 text-md-h4 font-weight-bold mb-4">{{ t('mh.nl.badLink') }}</h1>
          <p class="text-body-1 text-medium-emphasis mb-8">
            {{ t('mh.nl.badLinkBody') }}
          </p>
          <v-btn color="primary" size="large" to="/">{{ t('mh.nl.home') }}</v-btn>
        </template>

        <template v-else>
          <v-icon icon="mdi-wifi-off" color="warning" size="72" class="mb-6" />
          <h1 class="text-h5 text-md-h4 font-weight-bold mb-4">{{ t('mh.nl.noServer') }}</h1>
          <p class="text-body-1 text-medium-emphasis mb-8">
            {{ t('mh.nl.noServerBody') }}
          </p>
          <v-btn color="primary" size="large" @click="confirm">{{ t('mh.nl.retry') }}</v-btn>
        </template>
      </v-col>
    </v-row>
  </v-container>
</template>

<script setup lang="ts">
import { appPath } from '@/utils/deployment'
import { ref } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

type Phase = 'ready' | 'busy' | 'done' | 'invalid' | 'error'

const route = useRoute()
const phase = ref<Phase>('ready')

async function confirm() {
  const token = String(route.params.token ?? '')
  phase.value = 'busy'
  try {
    const r = await fetch(appPath(`/api/subscribe/confirm/${encodeURIComponent(token)}`), {
      method: 'POST',
    })
    if (!r.ok) {
      phase.value = 'error'
      return
    }
    const body = (await r.json()) as { confirmed?: boolean }
    // Only an explicit true is success — an unknown or already-used token
    // must not be told an action happened.
    phase.value = body.confirmed === true ? 'done' : 'invalid'
  } catch {
    phase.value = 'error'
  }
}
</script>
