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
          <h1 class="text-h5 text-md-h4 font-weight-bold mb-4">One click to confirm</h1>
          <p class="text-body-1 text-medium-emphasis mb-8">
            Confirm you want Roomler product updates at this address.
            Never more than monthly, one-click unsubscribe in every email.
          </p>
          <v-btn color="primary" size="large" :loading="phase === 'busy'" @click="confirm">
            Confirm my subscription
          </v-btn>
        </template>

        <template v-else-if="phase === 'done'">
          <v-icon icon="mdi-email-check-outline" color="success" size="72" class="mb-6" />
          <h1 class="text-h5 text-md-h4 font-weight-bold mb-4">You're on the list</h1>
          <p class="text-body-1 text-medium-emphasis mb-8">
            Thanks for confirming. Product updates only, never more than monthly —
            and a one-click unsubscribe in every email.
          </p>
          <v-btn color="primary" size="large" to="/">Go to roomler.ai</v-btn>
        </template>

        <template v-else-if="phase === 'invalid'">
          <v-icon icon="mdi-link-off" color="warning" size="72" class="mb-6" />
          <h1 class="text-h5 text-md-h4 font-weight-bold mb-4">That link didn't work</h1>
          <p class="text-body-1 text-medium-emphasis mb-8">
            It may already have been used — if you confirmed before, you're set.
            Otherwise you can sign up again from the home page.
          </p>
          <v-btn color="primary" size="large" to="/">Go to roomler.ai</v-btn>
        </template>

        <template v-else>
          <v-icon icon="mdi-wifi-off" color="warning" size="72" class="mb-6" />
          <h1 class="text-h5 text-md-h4 font-weight-bold mb-4">Could not reach the server</h1>
          <p class="text-body-1 text-medium-emphasis mb-8">
            Nothing was changed. Check your connection and try again.
          </p>
          <v-btn color="primary" size="large" @click="confirm">Try again</v-btn>
        </template>
      </v-col>
    </v-row>
  </v-container>
</template>

<script setup lang="ts">
import { appPath } from '@/utils/deployment'
import { ref } from 'vue'
import { useRoute } from 'vue-router'

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
