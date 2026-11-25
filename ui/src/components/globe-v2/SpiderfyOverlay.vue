<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  Screen-space spiderfy overlay (S3/S4/AC4 + same-city site-grouped pods) anchored at the
  exact projected city point via a MapLibre Marker (opacityWhenCovered: '0').
  - Classic `'circle'` (2..8) and `'spiral'` (9..20): 1.25px SVG legs, Ø4 center anchor,
    accessible <button> feet.
  - Multi-site `'sites'` (2..6 egress-IP pods, <=20 devices): non-overlapping site cards,
    mini-radial clickable feet, curved inter-site live link arcs & carrier/RTT pill badges.
-->
<template>
  <div
    ref="rootEl"
    class="mh-spiderfy"
    :class="[
      `mh-spiderfy--${tokens.mode}`,
      `mh-spiderfy--mode-${layout.mode}`,
      { 'mh-spiderfy--coarse': layout.coarse },
    ]"
    :style="{ '--mh-spiderfy-r': `${Math.ceil(layout.maxRadius + 24)}px` }"
    data-testid="globe-spiderfy-overlay"
    :data-spiderfy-mode="layout.mode"
  >
    <!-- Classic single-site circle / spiral spiderfy -->
    <template v-if="layout.mode !== 'sites'">
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
        :aria-label="tr('mh.globeV2.collapseSpiderfy')"
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
              'mh-spiderfy__dot--self': Boolean(foot.node.isSelf),
            },
          ]"
          :style="dotStyle(foot.presence, Boolean(foot.node.isSelf), selectedNodeId === foot.node.id)"
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
    </template>

    <!-- Same-city multi-site egress-IP grouped spiderfy -->
    <template v-else>
      <!-- Subtle dashed anchor legs from (0, 0) to each site pod border -->
      <svg
        class="mh-spiderfy__legs"
        :width="svgSize"
        :height="svgSize"
        :viewBox="`${-halfSvg} ${-halfSvg} ${svgSize} ${svgSize}`"
        aria-hidden="true"
      >
        <line
          v-for="site in layout.sites"
          :key="`site-leg-${site.id}`"
          x1="0"
          y1="0"
          :x2="site.legX"
          :y2="site.legY"
          :stroke="tokens.leg"
          stroke-width="1.25"
          stroke-dasharray="3 3"
          stroke-linecap="round"
        />
      </svg>

      <!-- Site pod cards -->
      <section
        v-for="site in layout.sites"
        :key="site.id"
        class="mh-spiderfy__site"
        :class="{
          'mh-spiderfy__site--self': site.hasSelf,
          'mh-spiderfy__site--unknown': site.labelKind === 'unknown',
        }"
        :style="sitePodStyle(site)"
        role="group"
        :aria-label="siteHeaderText(site)"
        :data-testid="`globe-spiderfy-site-${site.id}`"
        @click.stop
      >
        <header
          class="mh-spiderfy__site-head"
          :style="{
            height: `${site.headerHeight}px`,
            borderBottomColor: siteHeaderBorderColor(site),
          }"
        >
          <div class="mh-spiderfy__site-title-row">
            <span
              class="mh-spiderfy__site-pip"
              :style="{
                background: site.hasSelf ? tokens.selfRing : site.onlineCount > 0 ? tokens.online : tokens.offline,
              }"
              aria-hidden="true"
            />
            <span
              class="mh-spiderfy__site-title"
              :style="{ color: tokens.labelPrimary }"
            >
              {{ siteHeaderText(site) }}
            </span>
          </div>
          <div
            class="mh-spiderfy__site-sub"
            :style="{ color: tokens.labelSecondary }"
          >
            {{ siteSubtitleText(site) }}
          </div>
        </header>

        <div class="mh-spiderfy__site-body">
          <button
            v-for="foot in site.feet"
            :key="foot.node.id"
            type="button"
            class="mh-spiderfy__foot mh-spiderfy__foot--site"
            :class="{
              'mh-spiderfy__foot--selected': selectedNodeId === foot.node.id,
              'mh-spiderfy__foot--coarse': layout.coarse,
            }"
            :style="{
              transform: `translate(${foot.localDx ?? 0}px, ${foot.localDy ?? 0}px) translate(-50%, -50%)`,
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
                  'mh-spiderfy__dot--self': Boolean(foot.node.isSelf),
                },
              ]"
              :style="dotStyle(foot.presence, Boolean(foot.node.isSelf), selectedNodeId === foot.node.id)"
            />
            <span
              v-if="!layout.coarse && site.feet.length <= 8"
              class="mh-spiderfy__site-foot-label"
              :style="{ color: tokens.labelPrimary }"
            >
              {{ foot.shortLabel }}
            </span>
          </button>
        </div>
      </section>

      <!-- Curved inter-site live link arcs rendered cleanly above pod borders -->
      <svg
        v-if="layout.siteLinks.length > 0"
        class="mh-spiderfy__links"
        :width="svgSize"
        :height="svgSize"
        :viewBox="`${-halfSvg} ${-halfSvg} ${svgSize} ${svgSize}`"
        aria-hidden="true"
      >
        <g v-for="link in layout.siteLinks" :key="`site-arc-${link.key}`">
          <path
            :d="link.pathD"
            fill="none"
            :stroke="tokens.ocean"
            stroke-width="4"
            stroke-linecap="round"
            opacity="0.72"
          />
          <path
            :d="link.pathD"
            fill="none"
            :stroke="siteLinkStroke(link)"
            stroke-width="2"
            :stroke-dasharray="siteLinkDashArray(link)"
            stroke-linecap="round"
          />
          <circle
            :cx="link.x1"
            :cy="link.y1"
            r="2.5"
            :fill="siteLinkStroke(link)"
          />
          <circle
            :cx="link.x2"
            :cy="link.y2"
            r="2.5"
            :fill="siteLinkStroke(link)"
          />
        </g>
      </svg>

      <!-- Inter-site carrier + RTT pill badges -->
      <div
        v-for="link in layout.siteLinks"
        :key="`site-pill-${link.key}`"
        class="mh-spiderfy__link-pill"
        :class="{ 'mh-spiderfy__link-pill--stalled': link.stalled }"
        :style="siteLinkPillStyle(link)"
        :aria-label="tr('mh.globeV2.spiderfyInterSiteLinkAria', { carrier: siteLinkLabel(link) })"
        :data-testid="`globe-spiderfy-site-link-${link.key}`"
      >
        <span
          class="mh-spiderfy__link-dot"
          :style="{ background: siteLinkStroke(link) }"
          aria-hidden="true"
        />
        <span class="mh-spiderfy__link-text">{{ siteLinkLabel(link) }}</span>
      </div>

      <!-- Center white anchor button to collapse spiderfy -->
      <button
        type="button"
        class="mh-spiderfy__anchor mh-spiderfy__anchor--sites"
        :style="{ background: tokens.focusRing, borderColor: tokens.ocean }"
        :aria-label="tr('mh.globeV2.collapseSpiderfy')"
        data-testid="globe-spiderfy-anchor"
        @click.stop="emit('collapse')"
      />
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { GlobeNode, GlobePresence } from '@/components/globe/types'
import type { SpiderfyLayout, SpiderfySiteGroup, SpiderfySiteLink } from './spiderfy'
import type { GlobeLang, GlobeTokens } from './tokens'

const props = defineProps<{
  layout: SpiderfyLayout
  tokens: GlobeTokens
  lang?: GlobeLang
  selectedNodeId?: string | null
}>()

const emit = defineEmits<{
  (e: 'select-node', node: GlobeNode): void
  (e: 'hover-node', node: GlobeNode | null): void
  (e: 'collapse'): void
}>()

const { t } = useI18n()

function tr(key: string, named?: Record<string, unknown>): string {
  if (props.lang) {
    return t(key, named ?? {}, { locale: props.lang })
  }
  return named ? t(key, named) : t(key)
}

const rootEl = ref<HTMLElement | null>(null)
defineExpose({ rootEl })

const halfSvg = computed(() => Math.ceil(props.layout.maxRadius + 32))
const svgSize = computed(() => halfSvg.value * 2)

function dotStyle(
  presence: GlobePresence,
  isSelf = false,
  isSelected = false,
): Record<string, string> {
  const base: Record<string, string> =
    presence === 'online'
      ? { background: props.tokens.online, borderColor: props.tokens.ocean }
      : presence === 'stale'
        ? {
            background: `linear-gradient(90deg, ${props.tokens.stale} 50%, ${props.tokens.ocean} 50%)`,
            borderColor: props.tokens.stale,
          }
        : {
            background: props.tokens.ocean,
            borderColor: props.tokens.offline,
            color: props.tokens.offline,
          }

  if (isSelected && isSelf) {
    base.boxShadow = `0 0 0 2px ${props.tokens.selfRing}, 0 0 0 4px ${props.tokens.focusRing}`
  } else if (isSelected) {
    base.boxShadow = `0 0 0 2px ${props.tokens.focusRing}`
  } else if (isSelf) {
    base.boxShadow = `0 0 0 2px ${props.tokens.selfRing}`
  }
  return base
}

function sitePodStyle(site: SpiderfySiteGroup): Record<string, string> {
  const isDark = props.tokens.mode === 'dark'
  const bg = isDark ? 'rgba(8, 19, 30, 0.93)' : 'rgba(250, 251, 252, 0.96)'
  const borderColor = site.hasSelf
    ? props.tokens.selfRing
    : isDark
      ? 'rgba(143, 163, 191, 0.42)'
      : 'rgba(74, 91, 112, 0.34)'
  return {
    transform: `translate(${site.cx}px, ${site.cy}px) translate(-50%, -50%)`,
    width: `${site.width}px`,
    height: `${site.height}px`,
    background: bg,
    borderColor,
    borderWidth: site.hasSelf ? '1.5px' : '1px',
  }
}

function siteHeaderBorderColor(site: SpiderfySiteGroup): string {
  if (site.hasSelf) {
    return props.tokens.mode === 'dark'
      ? 'rgba(43, 181, 138, 0.32)'
      : 'rgba(0, 120, 90, 0.24)'
  }
  return props.tokens.mode === 'dark'
    ? 'rgba(143, 163, 191, 0.22)'
    : 'rgba(74, 91, 112, 0.18)'
}

function siteHeaderText(site: SpiderfySiteGroup): string {
  if (site.labelKind === 'self') {
    return tr('mh.globeV2.spiderfySiteSelf', { index: site.siteIndex, count: site.count })
  }
  if (site.labelKind === 'unknown') {
    return tr('mh.globeV2.spiderfySiteOther', { count: site.count })
  }
  return tr('mh.globeV2.spiderfySite', { index: site.siteIndex, count: site.count })
}

function siteSubtitleText(site: SpiderfySiteGroup): string {
  const parts: string[] = []
  if (site.intraMinRttMs != null) {
    if (site.intraMaxRttMs != null && site.intraMaxRttMs !== site.intraMinRttMs) {
      parts.push(`${site.intraMinRttMs}–${site.intraMaxRttMs} ms`)
    } else {
      parts.push(`${site.intraMinRttMs} ms`)
    }
  }
  if (site.publicIp) {
    parts.push(site.publicIp)
  }
  if (!parts.length) {
    return tr('mh.globeV2.spiderfySiteOnline', {
      online: site.onlineCount,
      total: site.count,
    })
  }
  return parts.join(' · ')
}

function siteLinkStroke(link: SpiderfySiteLink): string {
  if (link.stalled) return props.tokens.stalled
  switch (link.carrier) {
    case 'direct':
      return props.tokens.direct
    case 'tunnel':
      return props.tokens.tunnel
    case 'relay':
      return props.tokens.relay
    case 'derp':
      return props.tokens.derp
    case 'blocked':
      return props.tokens.blocked
    default:
      return link.color || props.tokens.direct
  }
}

function siteLinkDashArray(link: SpiderfySiteLink): string | undefined {
  if (link.stalled) return '4 3'
  if (link.carrier === 'relay') return '6 4'
  if (link.carrier === 'derp') return '2 3'
  if (link.carrier === 'blocked') return '3 3'
  return undefined
}

function siteLinkLabel(link: SpiderfySiteLink): string {
  const carrierKey = `mh.mesh.carriers.${link.carrier}`
  const localized = tr(carrierKey)
  const carrierText = localized === carrierKey ? link.carrier : localized
  const parts: string[] = [carrierText]
  if (link.minRttMs != null) {
    parts.push(`${link.minRttMs} ms`)
  }
  if (link.stalled) {
    parts.push('⚠')
  }
  return parts.join(' · ')
}

function siteLinkPillStyle(link: SpiderfySiteLink): Record<string, string> {
  const isDark = props.tokens.mode === 'dark'
  return {
    transform: `translate(${link.midX}px, ${link.midY}px) translate(-50%, -50%)`,
    background: isDark ? 'rgba(8, 19, 30, 0.96)' : 'rgba(250, 251, 252, 0.98)',
    borderColor: siteLinkStroke(link),
    color: props.tokens.labelPrimary,
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
  z-index: 1;
}
.mh-spiderfy__links {
  position: absolute;
  left: 0;
  top: 0;
  transform: translate(-50%, -50%);
  pointer-events: none;
  overflow: visible;
  z-index: 3;
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
  z-index: 5;
}
.mh-spiderfy__anchor--sites {
  width: 16px;
  height: 16px;
  border-width: 4px;
}
.mh-spiderfy__anchor:focus-visible {
  outline: 2px solid currentColor;
  outline-offset: 2px;
}
.mh-spiderfy__site {
  position: absolute;
  left: 0;
  top: 0;
  border-style: solid;
  border-radius: 10px;
  display: flex;
  flex-direction: column;
  box-sizing: border-box;
  pointer-events: auto;
  z-index: 2;
  box-shadow: 0 4px 14px rgba(0, 0, 0, 0.24);
  transition: opacity 140ms ease, transform 140ms ease;
}
.mh-spiderfy--light .mh-spiderfy__site {
  box-shadow: 0 4px 12px rgba(15, 23, 42, 0.12);
}
.mh-spiderfy__site-head {
  flex: 0 0 auto;
  display: flex;
  flex-direction: column;
  justify-content: center;
  padding: 4px 9px;
  border-bottom: 1px solid transparent;
  box-sizing: border-box;
  min-width: 0;
}
.mh-spiderfy__site-title-row {
  display: flex;
  align-items: center;
  gap: 5px;
  min-width: 0;
}
.mh-spiderfy__site-pip {
  flex: 0 0 auto;
  width: 6px;
  height: 6px;
  border-radius: 50%;
}
.mh-spiderfy__site-title {
  font-size: 11px;
  font-weight: 600;
  line-height: 1.25;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.mh-spiderfy__site-sub {
  font-size: 10px;
  line-height: 1.2;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  margin-top: 1px;
  padding-left: 11px;
}
.mh-spiderfy__site-body {
  position: relative;
  flex: 1 1 0;
  min-height: 0;
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
  transition: transform 120ms ease;
}
.mh-spiderfy__foot--site {
  left: 50%;
  top: 50%;
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
.mh-spiderfy__site-foot-label {
  position: absolute;
  top: calc(50% + 7px);
  left: 50%;
  transform: translateX(-50%);
  max-width: 72px;
  font-size: 10px;
  font-weight: 500;
  line-height: 1.15;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  pointer-events: none;
}
.mh-spiderfy__link-pill {
  position: absolute;
  left: 0;
  top: 0;
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 2px 8px;
  border-radius: 999px;
  border: 1px solid;
  font-size: 10.5px;
  font-weight: 600;
  line-height: 1.3;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
  pointer-events: none;
  z-index: 4;
  box-shadow: 0 2px 6px rgba(0, 0, 0, 0.22);
}
.mh-spiderfy--light .mh-spiderfy__link-pill {
  box-shadow: 0 2px 6px rgba(15, 23, 42, 0.1);
}
.mh-spiderfy__link-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  flex: 0 0 auto;
}
.mh-spiderfy__link-text {
  white-space: nowrap;
}

@media (prefers-reduced-motion: reduce) {
  .mh-spiderfy__site,
  .mh-spiderfy__foot {
    transition: none;
  }
}
</style>
