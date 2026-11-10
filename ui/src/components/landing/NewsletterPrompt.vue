<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  FR-58 — the deferred landing auto-ask. A dismissible card that appears once
  ever, after real engagement (60% scroll or ~20 s), never a blocking modal.

  Latch rules (the useTutorialProgress house style):
  - flat key `meshharbor-newsletter-dismissed` — an anonymous visitor has no
    user id to scope by;
  - every storage access try/caught;
  - unreadable storage ⇒ treated as dismissed — failing that way means we
    never re-ask someone we can't remember having asked.
-->
<template>
  <v-slide-y-reverse-transition>
    <v-card
      v-if="visible"
      class="newsletter-prompt"
      elevation="12"
      rounded="lg"
      role="dialog"
      :aria-label="t('mh.nl.signup')"
    >
      <v-btn
        icon="mdi-close"
        variant="text"
        size="small"
        class="prompt-close"
        :aria-label="t('mh.nl.dismiss')"
        @click="dismiss"
      />
      <v-card-text class="pt-5 pb-4 px-5">
        <div class="text-subtitle-1 font-weight-bold mb-1">
          {{ t('mh.nl.promptTitle') }}
        </div>
        <!-- hide-lede: the card title above already says it — the field pass
             caught the double text on the live page (FR-58 P6). -->
        <StayInTouch variant="light" source="landing-prompt" hide-lede @subscribed="onSubscribed" />
      </v-card-text>
    </v-card>
  </v-slide-y-reverse-transition>
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import StayInTouch from '@/components/landing/StayInTouch.vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const LATCH_KEY = 'meshharbor-newsletter-dismissed'
const SHOW_AFTER_MS = 20_000
const SHOW_AFTER_SCROLL = 0.6

const visible = ref(false)
let timer: ReturnType<typeof setTimeout> | undefined
let armed = false

function latched(): boolean {
  try {
    return localStorage.getItem(LATCH_KEY) !== null
  } catch {
    // Unreadable storage ⇒ behave as already-dismissed: we can't remember
    // having asked, so we must not risk asking on every visit.
    return true
  }
}

function latch() {
  try {
    localStorage.setItem(LATCH_KEY, new Date().toISOString())
  } catch {
    // Nothing to do — worst case the prompt shows again next visit.
  }
}

function trigger() {
  if (!armed || visible.value) return
  armed = false
  visible.value = true
  window.removeEventListener('scroll', onScroll)
  if (timer) clearTimeout(timer)
}

function onScroll() {
  const doc = document.documentElement
  const max = doc.scrollHeight - window.innerHeight
  if (max > 0 && window.scrollY / max >= SHOW_AFTER_SCROLL) trigger()
}

function dismiss() {
  visible.value = false
  latch()
}

function onSubscribed() {
  // Subscribing IS the answer — never ask again, and let the inline
  // "check your inbox" confirmation linger briefly before sliding away.
  latch()
  timer = setTimeout(() => {
    visible.value = false
  }, 4000)
}

onMounted(() => {
  if (latched()) return
  armed = true
  timer = setTimeout(trigger, SHOW_AFTER_MS)
  window.addEventListener('scroll', onScroll, { passive: true })
})

onBeforeUnmount(() => {
  if (timer) clearTimeout(timer)
  window.removeEventListener('scroll', onScroll)
})
</script>

<style scoped>
.newsletter-prompt {
  position: fixed;
  right: 16px;
  bottom: 16px;
  z-index: 90; /* under the fixed landing nav (100) */
  width: min(420px, calc(100vw - 32px));
}
.prompt-close {
  position: absolute;
  top: 6px;
  right: 6px;
}
</style>
