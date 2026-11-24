<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  Screen-space spiderfy overlay (S3/S4/AC4) anchored at the exact projected city point
  via a MapLibre Marker (opacityWhenCovered: '0'). Renders 1.25px SVG legs, Ø4 center
  anchor, and accessible <button> feet for circle (2..8) and spiral (9..20) layouts.
-->
<template>
  <div
    ref="rootEl"
    class="mh-spiderfy"
    :class="[`mh-spiderfy--${tokens.mode}`, { 'mh-spiderfy--coarse': layout.coarse }]"
    :style="{ '--mh-spiderfy-r': `${Math.ceil(layout.maxRadius + 24)}px` }"
    data-testid="globe-spiderfy-overlay"
    :data-spiderfy-mode="layout.mode"
  >
    <svg
      class="mh-spiderfy__legs"
      :width="svgSize"
      :height="svgSize"
      :viewBox="`${-halfSvg} ${-halfSvg} ${svgSize} ${svgSize}`"
      aria-hidden="true"
    >
      <line
        v-for="foot in layout.feet"
        :key="`leg-${foot.node.id}`"
        x1="0"
        y1="0"
        :x2="foot.dx"
        :y2="foot.dy"
        :stroke="tokens.leg"
        stroke-width="1.25"
        stroke-linecap="round"
      />
    </svg>

    <button
      type="button"
      class="mh-spiderfy__anchor"
      :style="{ background: tokens.focusRing, borderColor: tokens.ocean }"
      :aria-label="$t('mh.globeV2.collapseSpiderfy')"
      data-testid="globe-spiderfy-anchor"
      @click.stop="emit('collapse')"
    />

    <button
      v-for="foot in layout.feet"
      :key="foot.node.id"
      type="button"
      class="mh-spiderfy__foot"
      :class="{
        'mh-spiderfy__foot--selected': selectedNodeId === foot.node.id,
        'mh-spiderfy__foot--coarse': layout.coarse,
      }"
      :style="{
        transform: `translate(${foot.dx}px, ${foot.dy}px) translate(-50%, -50%)`,
      }"
      :aria-label="`${foot.node.name} (${foot.presence})`"
      :data-testid="`globe-spiderfy-foot-${foot.node.id}`"
      @click.stop="emit('select-node', foot.node)"
      @mouseenter="emit('hover-node', foot.node)"
      @mouseleave="emit('hover-node', null)"
      @focus="emit('hover-node', foot.node)"
      @blur="emit('hover-node', null)"
    >
      <span
        class="mh-spiderfy__dot"
        :class="[
          `mh-spiderfy__dot--${foot.presence}`,
          {
            'mh-spiderfy__dot--gateway': foot.node.isGateway || foot.node.role === 'gateway',
            'mh-spiderfy__dot--selected': selectedNodeId === foot.node.id,
          },
        ]"
        :style="dotStyle(foot.presence)"
      />
      <span
        v-if="!layout.coarse && layout.mode === 'circle'"
        class="mh-spiderfy__label"
        :class="foot.dx < -4 ? 'mh-spiderfy__label--left' : 'mh-spiderfy__label--right'"
        :style="{ color: tokens.labelPrimary, background: tokens.labelHalo }"
      >
        {{ foot.shortLabel }}
      </span>
    </button>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import type { GlobeNode, GlobePresence } from '@/components/globe/types'
import type { SpiderfyLayout } from './spiderfy'
import type { GlobeTokens } from './tokens'

const props = defineProps<{
  layout: SpiderfyLayout
  tokens: GlobeTokens
  selectedNodeId?: string | null
}>()

const emit = defineEmits<{
  (e: 'select-node', node: GlobeNode): void
  (e: 'hover-node', node: GlobeNode | null): void
  (e: 'collapse'): void
}>()

const rootEl = ref<HTMLElement | null>(null)
defineExpose({ rootEl })

const halfSvg = computed(() => Math.ceil(props.layout.maxRadius + 24))
const svgSize = computed(() => halfSvg.value * 2)

function dotStyle(presence: GlobePresence): Record<string, string> {
  if (presence === 'online') {
    return { background: props.tokens.online, borderColor: props.tokens.ocean }
  }
  if (presence === 'stale') {
    return {
      background: `linear-gradient(90deg, ${props.tokens.stale} 50%, ${props.tokens.ocean} 50%)`,
      borderColor: props.tokens.stale,
    }
  }
  return {
    background: props.tokens.ocean,
    borderColor: props.tokens.offline,
    color: props.tokens.offline,
  }
}
</script>

<style scoped>
.mh-spiderfy {
  position: relative;
  width: 0;
  height: 0;
  pointer-events: none;
  z-index: 4;
}
.mh-spiderfy__legs {
  position: absolute;
  left: 0;
  top: 0;
  transform: translate(-50%, -50%);
  pointer-events: none;
  overflow: visible;
}
.mh-spiderfy__anchor {
  position: absolute;
  left: 0;
  top: 0;
  transform: translate(-50%, -50%);
  width: 14px;
  height: 14px;
  padding: 0;
  border: 5px solid transparent;
  border-radius: 50%;
  background-clip: padding-box;
  cursor: pointer;
  pointer-events: auto;
}
.mh-spiderfy__foot {
  position: absolute;
  left: 0;
  top: 0;
  width: 24px;
  height: 24px;
  padding: 0;
  border: 0;
  background: transparent;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  pointer-events: auto;
  border-radius: 50%;
}
.mh-spiderfy__foot--coarse {
  width: 44px;
  height: 44px;
}
.mh-spiderfy__foot:focus-visible {
  outline: 2px solid currentColor;
  outline-offset: 1px;
}
.mh-spiderfy__dot {
  position: relative;
  display: inline-block;
  width: 10px;
  height: 10px;
  border-radius: 50%;
  border: 1.5px solid;
  box-sizing: border-box;
}
.mh-spiderfy__dot--gateway {
  border-radius: 2px;
}
.mh-spiderfy__dot--offline::after {
  content: '';
  position: absolute;
  left: 50%;
  top: 50%;
  width: 8px;
  height: 1.25px;
  background: currentColor;
  transform: translate(-50%, -50%) rotate(-45deg);
}
.mh-spiderfy__dot--selected {
  box-shadow: 0 0 0 2px #ffffff;
}
.mh-spiderfy__label {
  position: absolute;
  top: 50%;
  transform: translateY(-50%);
  font-size: 11px;
  font-weight: 500;
  line-height: 1.2;
  padding: 1px 4px;
  border-radius: 4px;
  white-space: nowrap;
  pointer-events: none;
}
.mh-spiderfy__label--right {
  left: 20px;
}
.mh-spiderfy__label--left {
  right: 20px;
}
</style>
