<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  FR-12 P2 — the spotlight overlay.

  Four dimming panels around the target rather than an SVG mask: the panels are
  plain divs, so the cut-out cannot be clipped by a stacking context the way a
  mask can, and the highlighted control stays fully interactive underneath.
-->
<template>
  <div v-if="active && rect" class="spotlight-root">
    <div class="spot-dim" :style="{ top: 0, left: 0, width: '100vw', height: rect.top + 'px' }" @click="onDismiss" />
    <div class="spot-dim" :style="{ top: rect.bottom + 'px', left: 0, width: '100vw', bottom: 0 }" @click="onDismiss" />
    <div class="spot-dim" :style="{ top: rect.top + 'px', left: 0, width: rect.left + 'px', height: rect.height + 'px' }" @click="onDismiss" />
    <div class="spot-dim" :style="{ top: rect.top + 'px', left: rect.right + 'px', right: 0, height: rect.height + 'px' }" @click="onDismiss" />

    <div
      class="spot-ring"
      :style="{ top: rect.top - 4 + 'px', left: rect.left - 4 + 'px', width: rect.width + 8 + 'px', height: rect.height + 8 + 'px' }"
    />

    <v-card class="spot-card" :style="cardStyle" elevation="8" max-width="360">
      <v-card-title class="text-subtitle-1 font-weight-medium pb-1">{{ step?.title }}</v-card-title>
      <v-card-text class="text-body-2 pb-2">{{ step?.body }}</v-card-text>
      <v-card-actions class="pt-0">
        <span class="text-caption text-medium-emphasis ml-2">{{ stepIndex + 1 }} / {{ total }}</span>
        <v-spacer />
        <v-btn size="small" variant="text" @click="onDismiss">{{ t('mh.tour.skip') }}</v-btn>
        <v-btn size="small" color="primary" variant="flat" @click="next">
          {{ isLast ? t('mh.tour.done') : t('mh.tour.next') }}
        </v-btn>
      </v-card-actions>
    </v-card>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, onMounted, onBeforeUnmount, nextTick, computed } from 'vue'
import { useSpotlightTour } from '@/composables/useSpotlightTour'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const { active, step, stepIndex, total, isLast, next, end, skipMissingStep } = useSpotlightTour()

interface Rect { top: number; left: number; right: number; bottom: number; width: number; height: number }
const rect = ref<Rect | null>(null)

/** How long to wait for an anchor that has not rendered yet. Pages fetch, so
 *  the control a step points at may legitimately appear a beat late. */
const ANCHOR_WAIT_MS = 1500
let waitTimer: number | undefined

function measure() {
  const anchor = step.value?.anchor
  if (!anchor) { rect.value = null; return false }
  const el = document.querySelector(`[data-tour="${anchor}"]`)
  if (!el) { rect.value = null; return false }
  const r = el.getBoundingClientRect()
  if (r.width === 0 && r.height === 0) { rect.value = null; return false }
  rect.value = { top: r.top, left: r.left, right: r.right, bottom: r.bottom, width: r.width, height: r.height }
  return true
}

async function locate() {
  window.clearTimeout(waitTimer)
  await nextTick()
  if (measure()) {
    document
      .querySelector(`[data-tour="${step.value?.anchor}"]`)
      ?.scrollIntoView({ block: 'center', behavior: 'smooth' })
    // Re-measure once the scroll settles, or the ring sits where the target used to be.
    window.setTimeout(measure, 350)
    return
  }
  // ⚠️ Never strand the user on an overlay pointing at nothing: if the anchor
  // does not turn up, move on rather than dimming the page with no ring.
  waitTimer = window.setTimeout(() => {
    if (!measure()) skipMissingStep()
  }, ANCHOR_WAIT_MS)
}

const cardStyle = computed(() => {
  const r = rect.value
  if (!r) return {}
  const spaceBelow = window.innerHeight - r.bottom
  const top = spaceBelow > 220 ? r.bottom + 12 : Math.max(12, r.top - 220)
  const left = Math.min(Math.max(12, r.left), Math.max(12, window.innerWidth - 372))
  return { top: `${top}px`, left: `${left}px` }
})

function onDismiss() {
  end(false)
}

watch(
  () => [active.value, step.value?.anchor],
  () => {
    if (active.value) locate()
    else rect.value = null
  },
  { immediate: true },
)

const onViewportChange = () => {
  if (active.value) measure()
}
onMounted(() => {
  window.addEventListener('resize', onViewportChange)
  window.addEventListener('scroll', onViewportChange, true)
})
onBeforeUnmount(() => {
  window.clearTimeout(waitTimer)
  window.removeEventListener('resize', onViewportChange)
  window.removeEventListener('scroll', onViewportChange, true)
})
</script>

<style scoped>
.spotlight-root { position: fixed; inset: 0; z-index: 2400; pointer-events: none; }
.spot-dim { position: fixed; background: rgba(0, 0, 0, 0.55); pointer-events: auto; }
.spot-ring {
  position: fixed;
  border: 2px solid rgb(var(--v-theme-primary));
  border-radius: 6px;
  box-shadow: 0 0 0 3px rgba(var(--v-theme-primary), 0.25);
  pointer-events: none;
}
.spot-card { position: fixed; pointer-events: auto; }
</style>
