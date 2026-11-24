<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!-- FR-120 P1 — a chip whose explanation is a tap away.

     A chip's `title` reaches only a mouse: on a touch screen a tap does not
     show it, so what the chip means ("needs a person, and why") was
     unreachable on a phone. This chip opens its explanation in a small menu on
     a tap or click, at every width, and keeps the `title` for a mouse's hover.

     Attributes (size, colour, variant, prepend-icon, data-testid, class) land
     on the chip. A chip whose tap already does something (opens a dialog that
     explains) stays a plain `v-chip`: its tap path is that action. -->
<template>
  <v-menu location="bottom start" max-width="320" :close-on-content-click="true">
    <template #activator="{ props: menu }">
      <span
        v-if="plain"
        v-bind="mergeProps($attrs, menu)"
        :title="explain"
        class="fact-chip--plain"
        role="button"
        tabindex="0"
      >
        <slot />
      </span>
      <v-chip v-else v-bind="mergeProps($attrs, menu)" :title="explain">
        <slot />
      </v-chip>
    </template>
    <v-card class="pa-3 text-body-2 text-wrap" data-testid="fact-chip-explain">{{ explain }}</v-card>
  </v-menu>
</template>

<script setup lang="ts">
import { mergeProps } from 'vue'

defineOptions({ inheritAttrs: false })
defineProps<{
  /** What the chip means, in a sentence: shown on a tap, and as the hover title. */
  explain: string
  /** Not a chip: a bare span (the flat theme's presence dot and word) that opens the same menu. */
  plain?: boolean
}>()
</script>

<style scoped>
.fact-chip--plain {
  cursor: pointer;
}
</style>
