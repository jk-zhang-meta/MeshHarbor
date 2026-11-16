<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-app>
    <router-view />
    <v-snackbar
      v-model="snackbar.state.show"
      :color="snackbar.state.color"
      :timeout="snackbar.state.timeout"
      :attach="fullscreenEl"
      location="bottom right"
    >
      {{ snackbar.state.text }}
      <template #actions>
        <v-btn variant="text" @click="snackbar.hideSnackbar()">{{ t('common.close') }}</v-btn>
      </template>
    </v-snackbar>
  </v-app>
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useSnackbar } from '@/composables/useSnackbar'
import { PRODUCT_TITLE } from '@/utils/product'
import { onDeviceLoginPageHide, onDeviceLoginRouteChanged } from '@/utils/deviceLoginPresence'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()
const route = useRoute()

const snackbar = useSnackbar()

/**
 * FR-22 — the element a snackbar must render INSIDE while the page is
 * fullscreen.
 *
 * The remote-control viewer calls `requestFullscreen()` on its own
 * container. A fullscreen element renders only its own subtree, so a
 * snackbar teleported to `<body>` — the Vuetify default — is present in
 * the DOM, believes it is visible, and is seen by nobody. That made the
 * FR-22 connect verdict invisible in exactly the session where it had
 * something to say.
 *
 * `undefined` (not `false`) keeps Vuetify's default body-teleport when
 * nothing is fullscreen, so normal pages are unchanged.
 */
const fullscreenEl = ref<HTMLElement | undefined>(undefined)

function syncFullscreenTarget() {
  fullscreenEl.value = (document.fullscreenElement as HTMLElement | null) ?? undefined
}

function handlePageHide() {
  onDeviceLoginPageHide(route?.fullPath)
}

watch(
  () => route?.fullPath,
  (fullPath) => {
    if (fullPath) onDeviceLoginRouteChanged(fullPath)
  },
  { immediate: true },
)

onMounted(() => {
  document.title = PRODUCT_TITLE
  document.addEventListener('fullscreenchange', syncFullscreenTarget)
  window.addEventListener('pagehide', handlePageHide)
  syncFullscreenTarget()
})
onBeforeUnmount(() => {
  document.removeEventListener('fullscreenchange', syncFullscreenTarget)
  window.removeEventListener('pagehide', handlePageHide)
})
</script>
