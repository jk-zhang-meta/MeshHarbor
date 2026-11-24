<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <div class="mh-globe-root" data-testid="mesh-globe-root">
    <component
      :is="AsyncGlobeCanvas"
      v-if="use3D"
      :nodes="nodes"
      :arcs="arcs"
      :center="center"
      :show-control-plane="showControlPlane"
      :show-detail-panel="showDetailPanel"
      :show-open-device-action="showOpenDeviceAction"
      :height="height"
      :aria-label="ariaLabel"
      @node-click="emit('node-click', $event)"
      @arc-click="emit('arc-click', $event)"
      @open-device="emit('open-device', $event)"
      @webgl-error="onWebglError"
    />
    <slot v-else name="fallback" />
  </div>
</template>

<script setup lang="ts">
import { computed, defineAsyncComponent, h, ref } from 'vue'
import type { GlobeArc, GlobeCenter, GlobeNode } from './types'
import { isWebGL2Supported } from './webgl'

const props = withDefaults(
  defineProps<{
    nodes: readonly GlobeNode[]
    arcs: readonly GlobeArc[]
    center?: GlobeCenter | null
    showControlPlane?: boolean
    showDetailPanel?: boolean
    showOpenDeviceAction?: boolean
    height?: number
    ariaLabel?: string
    /** Explicit override (e.g. user picked 2D Ring or test forcing fallback). */
    forceFallback?: boolean
  }>(),
  {
    center: null,
    showControlPlane: true,
    showDetailPanel: true,
    showOpenDeviceAction: true,
    height: 0,
    ariaLabel: '',
    forceFallback: false,
  },
)

const emit = defineEmits<{
  (e: 'node-click', nodeId: string): void
  (e: 'arc-click', arcKey: string): void
  (e: 'open-device', nodeId: string): void
  (e: 'fallback-active', reason: string): void
}>()

const webglFailed = ref(false)
const webglAvailable = isWebGL2Supported()

if (!webglAvailable) {
  emit('fallback-active', 'webgl2-unavailable')
}

const use3D = computed(() => !props.forceFallback && webglAvailable && !webglFailed.value)

function onWebglError(reason: string) {
  webglFailed.value = true
  emit('fallback-active', reason)
}

// Lazy-loaded via dynamic import() so Three.js + Natural Earth 1:50m never enter
// the main SPA entry bundle.
const AsyncGlobeCanvas = defineAsyncComponent({
  loader: () => import('./MeshGlobeCanvas.vue'),
  delay: 120,
  loadingComponent: {
    render() {
      return h('div', { class: 'mh-globe-loading', 'data-testid': 'mesh-globe-loading' })
    },
  },
  onError(_err, _retry, fail) {
    webglFailed.value = true
    emit('fallback-active', 'chunk-load-failed')
    fail()
  },
})
</script>

<style scoped>
.mh-globe-root {
  width: 100%;
}
.mh-globe-loading {
  width: 100%;
  min-height: 360px;
  border-radius: var(--mh-radius);
  border: 1px solid var(--mh-hairline);
  background: rgba(var(--v-theme-surface-light), 0.6);
}
</style>
