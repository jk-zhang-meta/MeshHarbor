<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-container class="fill-height pa-2 pa-md-4 pa-xl-6" fluid>
    <v-row align="center" justify="center">
      <v-col cols="12" sm="8" md="6" class="text-center">
        <h1 class="text-h2 text-md-h1 font-weight-bold text-primary mb-4">404</h1>
        <h2 class="text-h6 text-md-h5 mb-4">{{ t('mh.notFound.title') }}</h2>
        <p class="text-body-1 text-medium-emphasis mb-8">
          {{ t('mh.notFound.body') }}
        </p>
        <v-btn color="primary" size="large" to="/">
          {{ t('mh.notFound.home') }}
        </v-btn>
      </v-col>
    </v-row>
  </v-container>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n'

const { t } = useI18n()
</script>
