<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!-- FR-120 P2 — one scope of agent memory (the organization's, yours, a
     device's) on the memory page.

     From 600 px up it renders exactly the card each scope always was, in its
     own column of the page's row. On a phone the three scopes stacked open
     were three screens of budgets, lists and drafts, so there each scope is an
     expansion panel whose title carries how full it is (`summary`), and its
     hint, facts and draft open on demand — FR-116's settings gates
     (`SettingsGate.vue`), applied to memory.

     On `xs` it must sit inside a `v-expansion-panels`, and from 600 px up
     inside a `v-row` — HiveMemoryView's root is the one or the other.
     Attributes (`data-testid`) land on the card or the panel. -->
<template>
  <v-expansion-panel v-if="xs" v-bind="$attrs">
    <v-expansion-panel-title>
      <div class="d-flex align-center ga-2 w-100" style="min-width: 0">
        <span class="font-weight-medium" style="min-width: 0">{{ title }}</span>
        <v-spacer />
        <span
          v-if="summary"
          class="text-caption text-medium-emphasis text-right mr-2"
          data-testid="hive-memory-summary"
        >{{ summary }}</span>
      </div>
    </v-expansion-panel-title>
    <v-expansion-panel-text>
      <p class="text-body-2 text-medium-emphasis mb-2">{{ hint }}</p>
      <slot />
    </v-expansion-panel-text>
  </v-expansion-panel>
  <v-col v-else cols="12" lg="4">
    <v-card variant="outlined" v-bind="$attrs">
      <v-card-title class="text-subtitle-1">{{ title }}</v-card-title>
      <v-card-subtitle class="text-wrap">{{ hint }}</v-card-subtitle>
      <v-card-text>
        <slot />
      </v-card-text>
    </v-card>
  </v-col>
</template>

<script setup lang="ts">
import { useDisplay } from 'vuetify'

defineOptions({ inheritAttrs: false })
defineProps<{
  title: string
  hint: string
  /** How full the scope is, for the collapsed panel on a phone ("23 of 1500
   *  characters"). Empty while there is no budget to show — the device scope
   *  before a device is chosen. */
  summary?: string
}>()

const { xs } = useDisplay()
</script>
