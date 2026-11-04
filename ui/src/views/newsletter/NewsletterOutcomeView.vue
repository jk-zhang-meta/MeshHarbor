<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  FR-58 — the public landing spots for the subscribe confirm / unsubscribe
  links. The API 303s here with `?status=ok|invalid`; one component serves
  both routes via a static `kind` prop.

  The routes carry NO meta.auth and NO meta.guest, deliberately: a signed-in
  user clicking unsubscribe in their mail client must see this outcome, not
  their dashboard. The previous target (`/?subscribe=…`) was auth-gated, so
  no human ever saw either message — FR-58 field evidence 2.
-->
<template>
  <v-container class="fill-height pa-2 pa-md-4 pa-xl-6" fluid>
    <v-row align="center" justify="center">
      <v-col cols="12" sm="8" md="6" class="text-center">
        <v-icon :icon="view.icon" :color="view.color" size="72" class="mb-6" />
        <h1 class="text-h5 text-md-h4 font-weight-bold mb-4">{{ view.title }}</h1>
        <p class="text-body-1 text-medium-emphasis mb-8">{{ view.body }}</p>
        <v-btn color="primary" size="large" to="/">{{ t('mh.nl.home') }}</v-btn>
      </v-col>
    </v-row>
  </v-container>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const props = defineProps<{ kind: 'confirmed' | 'unsubscribed' }>()
const route = useRoute()

const view = computed(() => {
  // Only an explicit `status=ok` is success. A missing or unknown status is
  // someone arriving without a real link, and claiming success for it would
  // tell them an action happened that didn't.
  if (route.query.status !== 'ok') {
    return {
      icon: 'mdi-link-off',
      color: 'warning',
      title: t('mh.nl.badLink'),
      body: t('mh.nl.invalidBody'),
    }
  }
  return props.kind === 'confirmed'
    ? {
        icon: 'mdi-email-check-outline',
        color: 'success',
        title: t('mh.nl.onList'),
        body: t('mh.nl.onListBody'),
      }
    : {
        icon: 'mdi-email-off-outline',
        color: 'success',
        title: t('mh.nl.unsubscribed'),
        body: t('mh.nl.unsubscribedBody'),
      }
})
</script>
