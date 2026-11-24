<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  Production MapLibre GL JS 6.19.0 + self-hosted PMTiles 4.5.0 device mesh globe (FR-136 P2/P3).
  - Variant L surface lines ONLY (Variant A dropped per G4 decision).
  - Same-origin worker via `maplibre-gl/dist/maplibre-gl-worker.mjs?url` (emitted as `.js` by Vite).
  - Zero external CDN requests; style omits `glyphs` (local system + CJK font stack).
  - North-up locked (`maxPitch: 0`, `dragRotate: false`, `touchPitch: false`, rotation disabled).
  - Zero auto-rotation; 0 rendered WebGL frames when idle.
  - Live dark/light and en/zh-CN switching with ZERO `setStyle()` reload.
  - Implements all 6 production fixes:
    1. Fit globe dynamically to ~87.5% of `min(width, height)` in card & full-page.
    2. Native ±44 px collision blocker layer (`mh-label-blockers`) prevents duplicate basemap labels.
    3. Edge-aware symbol layers (`extend-right` / `extend-left` / `extend-both`) eliminate label clipping on 390 px+.
    4. Phone legend (<600 px) collapsed by default to ONE compact chip; dismisses on outside tap or Esc.
    5. Crisp dark land/ocean contrast + coastline + symmetrical 360° Fresnel rim glow SVG.
    6. Calm resting links (1–1.5 px, 0.45 opacity, majority-carrier solid) vs full-strength patterned ego/hover links + mixed mark & breakdown.
-->
<template>
  <div
    ref="placeholderEl"
    class="mh-gv2-placeholder"
    :class="{ 'mh-gv2-placeholder--standalone': standaloneFullPage }"
    :style="placeholderStyle"
  >
    <Teleport to="body" :disabled="standaloneFullPage || !fullPage.isFull.value">
      <div
        ref="shellEl"
        class="mh-gv2-shell"
        :class="[
          `mh-gv2-shell--${themeMode}`,
          {
            'mh-gv2-shell--full': !standaloneFullPage && fullPage.isFull.value,
            'mh-gv2-shell--standalone': standaloneFullPage,
            'mh-gv2-shell--mobile': isMobile,
            'mh-gv2-shell--tablet': isTablet,
          },
        ]"
        :style="shellStyle"
        data-testid="globe-v2-shell"
        :data-full-page="isFullLayout ? '1' : '0'"
        :data-view-mode="activeViewMode"
      >
        <div
          ref="mapHostEl"
          class="mh-gv2-canvas"
          role="application"
          tabindex="0"
          :aria-label="ariaLabel || $t('mh.mesh.globeAria')"
          data-testid="globe-v2-canvas"
          @keydown="handleCanvasKeyDown"
        />

        <!-- Fix #5: Symmetrical 360° Fresnel rim glow synced to projected globe center & radius (0 WebGL redraws) -->
        <svg
          ref="fresnelSvgEl"
          class="mh-gv2-fresnel"
          aria-hidden="true"
          data-testid="globe-v2-fresnel-rim"
        >
          <defs>
            <radialGradient :id="fresnelOuterId" cx="50%" cy="50%" r="50%">
              <stop offset="84%" :stop-color="fresnelColors.outerPeak" stop-opacity="0" />
              <stop offset="87.5%" :stop-color="fresnelColors.outerPeak" :stop-opacity="fresnelColors.outerPeakOp" />
              <stop offset="93%" :stop-color="fresnelColors.outerMid" :stop-opacity="fresnelColors.outerMidOp" />
              <stop offset="100%" :stop-color="fresnelColors.outerMid" stop-opacity="0" />
            </radialGradient>
            <radialGradient :id="fresnelInnerId" cx="50%" cy="50%" r="50%">
              <stop offset="0%" :stop-color="fresnelColors.inner" stop-opacity="0" />
              <stop offset="78%" :stop-color="fresnelColors.inner" stop-opacity="0" />
              <stop offset="91%" :stop-color="fresnelColors.inner" :stop-opacity="fresnelColors.innerMidOp" />
              <stop offset="98.5%" :stop-color="fresnelColors.innerPeak" :stop-opacity="fresnelColors.innerPeakOp" />
              <stop offset="100%" :stop-color="fresnelColors.innerPeak" :stop-opacity="fresnelColors.rimEdgeOp" />
            </radialGradient>
          </defs>
          <circle ref="fresnelOuterEl" :fill="`url(#${fresnelOuterId})`" />
          <circle ref="fresnelInnerEl" :fill="`url(#${fresnelInnerId})`" />
          <circle
            ref="fresnelStrokeEl"
            fill="none"
            :stroke="fresnelColors.stroke"
            stroke-width="1.15"
          />
        </svg>

        <!-- Hidden DOM host moved into MapLibre Marker when spiderfy is active -->
        <div ref="spiderfyHostEl" class="mh-gv2-spiderfy-host">
          <spiderfy-overlay
            v-if="activeSpiderfy"
            :layout="activeSpiderfy.layout"
            :tokens="tokens"
            :selected-node-id="selectedNode?.id ?? null"
            @select-node="onSelectSpiderfyNode"
            @hover-node="onHoverSpiderfyNode"
            @collapse="collapseSpiderfy"
          />
        </div>

        <!-- Hidden DOM host moved into MapLibre Marker for S3 CSS-only selection pulse (0 WebGL frames) -->
        <div ref="pulseHostEl" class="mh-gv2-pulse-host">
          <div
            v-if="pulseKey > 0 && !prefersReducedMotion"
            :key="pulseKey"
            class="mh-gv2-pulse-ring"
            :style="{ borderColor: tokens.focusRing }"
            aria-hidden="true"
          />
        </div>

        <!-- Mobile Full-Page 48px Top Bar (S10 / S12) -->
        <header
          v-if="isMobile && isFullLayout"
          class="mh-gv2-mobile-topbar"
          data-testid="globe-v2-mobile-topbar"
        >
          <div
            v-if="canSwitchView"
            class="mh-gv2-segmented"
            role="tablist"
            data-testid="globe-v2-view-switcher"
          >
            <button
              type="button"
              role="tab"
              :aria-selected="!isBackboneView"
              class="mh-gv2-seg-btn"
              :class="{ 'mh-gv2-seg-btn--active': !isBackboneView }"
              data-testid="globe-v2-view-devices"
              @click="switchViewMode('devices')"
            >
              {{ $t('mh.backbone.viewDevices') }}
            </button>
            <button
              type="button"
              role="tab"
              :aria-selected="isBackboneView"
              class="mh-gv2-seg-btn"
              :class="{ 'mh-gv2-seg-btn--active': isBackboneView }"
              data-testid="globe-v2-view-backbone"
              @click="switchViewMode('backbone')"
            >
              {{ $t('mh.backbone.viewBackbone') }}
            </button>
          </div>
          <span v-else class="mh-gv2-mobile-topbar__title">
            {{ isBackboneView ? $t('mh.backbone.title') : $t('mh.globeV2.deviceNetworkTitle') }}
          </span>
          <div class="mh-gv2-mobile-topbar__actions">
            <button
              type="button"
              class="mh-gv2-chip-btn"
              data-testid="globe-v2-mobile-open-filters"
              @click="openMobileSheetTab('filters')"
            >
              {{ $t('mh.globeV2.tabFilters') }}
            </button>
            <button
              type="button"
              class="mh-gv2-chip-btn"
              data-testid="globe-v2-mobile-open-list"
              @click="openMobileSheetTab('list')"
            >
              {{ $t('mh.globeV2.tabList') }}
            </button>
            <button
              type="button"
              class="mh-gv2-icon-btn"
              :aria-label="$t('mh.globeV2.displaySettings')"
              :aria-expanded="settingsOpen"
              data-testid="globe-v2-settings-btn"
              @click.stop="settingsOpen = !settingsOpen"
            >
              <svg viewBox="0 0 24 24" width="15" height="15" fill="currentColor" aria-hidden="true">
                <path d="M12,15.5A3.5,3.5 0 0,1 8.5,12A3.5,3.5 0 0,1 12,8.5A3.5,3.5 0 0,1 15.5,12A3.5,3.5 0 0,1 12,15.5M19.43,12.97C19.47,12.65 19.5,12.33 19.5,12C19.5,11.67 19.47,11.34 19.43,11L21.54,9.37C21.73,9.22 21.78,8.95 21.66,8.73L19.66,5.27C19.54,5.05 19.27,4.96 19.05,5.05L16.56,6.05C16.04,5.66 15.5,5.32 14.87,5.07L14.5,2.42C14.46,2.18 14.25,2 14,2H10C9.75,2 9.54,2.18 9.5,2.42L9.13,5.07C8.5,5.32 7.96,5.66 7.44,6.05L4.95,5.05C4.73,4.96 4.46,5.05 4.34,5.27L2.34,8.73C2.21,8.95 2.27,9.22 2.46,9.37L4.57,11C4.53,11.34 4.5,11.67 4.5,12C4.5,12.33 4.53,12.65 4.57,12.97L2.46,14.63C2.27,14.78 2.21,15.05 2.34,15.27L4.34,18.73C4.46,18.95 4.73,19.03 4.95,18.95L7.44,17.94C7.96,18.34 8.5,18.68 9.13,18.93L9.5,21.58C9.54,21.82 9.75,22 10,22H14C14.25,22 14.46,21.82 14.5,21.58L14.87,18.93C15.5,18.67 16.04,18.34 16.56,17.94L19.05,18.95C19.27,19.03 19.54,18.95 19.66,18.73L21.66,15.27C21.78,15.05 21.73,14.78 21.54,14.63L19.43,12.97Z" />
              </svg>
            </button>
            <button
              v-if="fullPage.fullscreenSupported.value"
              type="button"
              class="mh-gv2-icon-btn"
              :aria-label="$t('mh.globeV2.browserFullscreen')"
              data-testid="globe-v2-native-fullscreen"
              @click="fullPage.toggleNativeFullscreen()"
            >
              <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path v-if="!fullPage.isNativeFullscreen.value" d="M2.5 6V2.5H6M10 2.5h3.5V6M13.5 10v3.5H10M6 13.5H2.5V10" />
                <path v-else d="M6 2.5V6H2.5M13.5 6H10V2.5M10 13.5V10h3.5M2.5 10H6v3.5" />
              </svg>
            </button>
            <button
              v-if="!standaloneFullPage"
              type="button"
              class="mh-gv2-icon-btn"
              :aria-label="$t('mh.globeV2.exitFullPage')"
              data-testid="globe-v2-fullpage-exit"
              @click="fullPage.exitFullPage(false)"
            >
              <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true">
                <path d="M4 4l8 8M12 4l-8 8" />
              </svg>
            </button>
          </div>
        </header>

        <!-- Desktop Full-Page Top-Left Title / Segmented View Switcher & Filters (S9 / S12) -->
        <div
          v-if="!isMobile && isFullLayout"
          class="mh-gv2-full-left"
          data-testid="globe-v2-full-toolbar"
        >
          <div
            v-if="canSwitchView"
            class="mh-gv2-segmented"
            role="tablist"
            data-testid="globe-v2-view-switcher"
          >
            <button
              type="button"
              role="tab"
              :aria-selected="!isBackboneView"
              class="mh-gv2-seg-btn"
              :class="{ 'mh-gv2-seg-btn--active': !isBackboneView }"
              data-testid="globe-v2-view-devices"
              @click="switchViewMode('devices')"
            >
              {{ $t('mh.backbone.viewDevices') }}
            </button>
            <button
              type="button"
              role="tab"
              :aria-selected="isBackboneView"
              class="mh-gv2-seg-btn"
              :class="{ 'mh-gv2-seg-btn--active': isBackboneView }"
              data-testid="globe-v2-view-backbone"
              @click="switchViewMode('backbone')"
            >
              {{ $t('mh.backbone.viewBackbone') }}
            </button>
          </div>
          <span v-else class="mh-gv2-full-left__title">
            {{ isBackboneView ? $t('mh.backbone.title') : $t('mh.globeV2.deviceNetworkTitle') }}
          </span>

          <!-- Device view filters -->
          <template v-if="!isBackboneView">
            <button
              type="button"
              class="mh-gv2-chip-btn"
              :class="{ 'mh-gv2-chip-btn--active': effectiveOnlyProblems }"
              data-testid="globe-v2-filter-problems"
              @click="localOnlyProblems = !effectiveOnlyProblems"
            >
              {{ $t('mh.globeV2.onlyProblems') }}
            </button>
            <label class="mh-gv2-rtt-filter">
              <span class="mh-mono">{{ $t('mh.globeV2.minRtt', { ms: effectiveMinRttMs }) }}</span>
              <input
                type="range"
                min="0"
                max="500"
                step="5"
                :value="effectiveMinRttMs"
                data-testid="globe-v2-filter-rtt"
                @input="localMinRttMs = Number(($event.target as HTMLInputElement).value)"
              />
            </label>
            <button
              type="button"
              class="mh-gv2-chip-btn"
              :class="{ 'mh-gv2-chip-btn--active': showingAllDevicesList }"
              data-testid="globe-v2-open-all-list"
              @click="toggleAllDevicesList"
            >
              {{ $t('mh.globeV2.deviceList') }} ({{ activeListNodes.length }})
            </button>
          </template>

          <!-- Backbone view controls (S12: optional Show devices toggle + Gateways list) -->
          <template v-else>
            <button
              type="button"
              class="mh-gv2-chip-btn"
              :class="{ 'mh-gv2-chip-btn--active': showDevices }"
              :aria-pressed="showDevices"
              data-testid="globe-v2-show-devices-toggle"
              @click="setShowDevicesOverlay(!showDevices)"
            >
              {{ $t('mh.backbone.showDevices') }}
            </button>
            <button
              type="button"
              class="mh-gv2-chip-btn"
              :class="{ 'mh-gv2-chip-btn--active': showingAllDevicesList }"
              data-testid="globe-v2-open-all-list"
              @click="toggleAllDevicesList"
            >
              {{ $t('mh.backbone.gatewayList') }} ({{ activeListNodes.length }})
            </button>
          </template>
        </div>

        <!-- Top-right quick controls (embedded mobile card shows ONLY full-page button per S10!) -->
        <div
          v-if="!(isMobile && isFullLayout)"
          class="mh-gv2-top-actions"
          data-testid="globe-v2-actions"
        >
          <template v-if="!isMobile">
            <button
              type="button"
              class="mh-gv2-icon-btn"
              :aria-label="$t('mh.mesh.controls.zoomIn')"
              :title="$t('mh.mesh.controls.zoomIn')"
              @click="zoomBy(1)"
            >
              <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true">
                <path d="M8 3.5v9M3.5 8h9" />
              </svg>
            </button>
            <button
              type="button"
              class="mh-gv2-icon-btn"
              :aria-label="$t('mh.mesh.controls.zoomOut')"
              :title="$t('mh.mesh.controls.zoomOut')"
              @click="zoomBy(-1)"
            >
              <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true">
                <path d="M3.5 8h9" />
              </svg>
            </button>
            <button
              type="button"
              class="mh-gv2-icon-btn"
              :aria-label="$t('mh.mesh.controls.reset')"
              :title="$t('mh.mesh.controls.reset')"
              data-testid="globe-v2-reset-btn"
              @click="resetView"
            >
              <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" aria-hidden="true">
                <circle cx="8" cy="8" r="4.2" />
                <path d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2" />
              </svg>
            </button>
            <button
              v-if="isFullLayout && fullPage.fullscreenSupported.value"
              type="button"
              class="mh-gv2-icon-btn mh-gv2-icon-btn--wide"
              :aria-label="$t('mh.globeV2.browserFullscreen')"
              :title="$t('mh.globeV2.browserFullscreen')"
              data-testid="globe-v2-native-fullscreen"
              @click="fullPage.toggleNativeFullscreen()"
            >
              <svg v-if="!fullPage.isNativeFullscreen.value" viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M2.5 6V2.5H6M10 2.5h3.5V6M13.5 10v3.5H10M6 13.5H2.5V10" />
              </svg>
              <svg v-else viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M6 2.5V6H2.5M13.5 6H10V2.5M10 13.5V10h3.5M2.5 10H6v3.5" />
              </svg>
            </button>
          </template>

          <button
            type="button"
            class="mh-gv2-icon-btn"
            :aria-label="$t('mh.globeV2.displaySettings')"
            :title="$t('mh.globeV2.displaySettings')"
            :aria-expanded="settingsOpen"
            data-testid="globe-v2-settings-btn"
            @click.stop="settingsOpen = !settingsOpen"
          >
            <svg viewBox="0 0 24 24" width="15" height="15" fill="currentColor" aria-hidden="true">
              <path d="M12,15.5A3.5,3.5 0 0,1 8.5,12A3.5,3.5 0 0,1 12,8.5A3.5,3.5 0 0,1 15.5,12A3.5,3.5 0 0,1 12,15.5M19.43,12.97C19.47,12.65 19.5,12.33 19.5,12C19.5,11.67 19.47,11.34 19.43,11L21.54,9.37C21.73,9.22 21.78,8.95 21.66,8.73L19.66,5.27C19.54,5.05 19.27,4.96 19.05,5.05L16.56,6.05C16.04,5.66 15.5,5.32 14.87,5.07L14.5,2.42C14.46,2.18 14.25,2 14,2H10C9.75,2 9.54,2.18 9.5,2.42L9.13,5.07C8.5,5.32 7.96,5.66 7.44,6.05L4.95,5.05C4.73,4.96 4.46,5.05 4.34,5.27L2.34,8.73C2.21,8.95 2.27,9.22 2.46,9.37L4.57,11C4.53,11.34 4.5,11.67 4.5,12C4.5,12.33 4.53,12.65 4.57,12.97L2.46,14.63C2.27,14.78 2.21,15.05 2.34,15.27L4.34,18.73C4.46,18.95 4.73,19.03 4.95,18.95L7.44,17.94C7.96,18.34 8.5,18.68 9.13,18.93L9.5,21.58C9.54,21.82 9.75,22 10,22H14C14.25,22 14.46,21.82 14.5,21.58L14.87,18.93C15.5,18.67 16.04,18.34 16.56,17.94L19.05,18.95C19.27,19.03 19.54,18.95 19.66,18.73L21.66,15.27C21.78,15.05 21.73,14.78 21.54,14.63L19.43,12.97Z" />
            </svg>
          </button>

          <button
            v-if="!standaloneFullPage"
            ref="fullTriggerEl"
            type="button"
            class="mh-gv2-icon-btn mh-gv2-icon-btn--wide"
            :aria-label="fullPage.isFull.value ? $t('mh.globeV2.exitFullPage') : $t('mh.globeV2.fullPage')"
            :title="fullPage.isFull.value ? $t('mh.globeV2.exitFullPage') : $t('mh.globeV2.fullPage')"
            data-testid="globe-v2-fullpage-toggle"
            @click="fullPage.toggleFullPage()"
          >
            <!-- mdi-arrow-expand-all geometry when collapsed, close × when full -->
            <svg v-if="!fullPage.isFull.value" viewBox="0 0 24 24" width="15" height="15" fill="currentColor" aria-hidden="true">
              <path d="M10,21V19H6.41L10.91,14.5L9.5,13.09L5,17.59V14H3V21H10M14.5,10.91L19,6.41V10H21V3H14V5H17.59L13.09,9.5L14.5,10.91Z" />
            </svg>
            <svg v-else viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true">
              <path d="M4 4l8 8M12 4l-8 8" />
            </svg>
          </button>
        </div>

        <!-- Per-viewer Display Settings popover inside globe container (NO body portal!) -->
        <div
          v-if="settingsOpen"
          class="mh-gv2-settings-popover"
          :class="{ 'mh-gv2-settings-popover--mobile-full': isMobile && isFullLayout }"
          role="dialog"
          :aria-label="$t('mh.globeV2.displaySettings')"
          data-testid="globe-v2-settings-popover"
          @click.stop
        >
          <div class="mh-gv2-settings-popover__head">
            <label for="mh-gv2-max-zoom-input" class="mh-gv2-settings-popover__label">
              {{ $t('mh.globeV2.maxZoomLabel') }}
            </label>
            <span class="mh-mono mh-gv2-settings-popover__val" data-testid="globe-v2-max-zoom-val">
              z{{ maxZoomSetting }}
            </span>
          </div>
          <input
            id="mh-gv2-max-zoom-input"
            type="range"
            class="mh-gv2-settings-popover__slider"
            :min="MIN_ALLOWED_MAX_ZOOM"
            :max="MAX_ALLOWED_MAX_ZOOM"
            step="1"
            :value="maxZoomSetting"
            data-testid="globe-v2-max-zoom-slider"
            @input="onMaxZoomInput"
          />
          <div class="mh-gv2-settings-popover__scale mh-mono">
            <span>z{{ MIN_ALLOWED_MAX_ZOOM }}</span>
            <span>z{{ MAX_ALLOWED_MAX_ZOOM }}</span>
          </div>
          <div class="mh-gv2-settings-popover__hint" data-testid="globe-v2-max-zoom-hint">
            {{ maxZoomSpanHint }}
          </div>
        </div>

        <!-- Hover card (desktop >=600px ONLY; WCAG 1.4.13 hoverable, 120ms delay, max 260px, 8px offset) -->
        <div
          v-if="!isMobile && hoverCard"
          class="mh-gv2-hover-card"
          :style="{ left: `${hoverCard.x}px`, top: `${hoverCard.y}px` }"
          role="status"
          data-testid="globe-v2-hover-card"
          @mouseenter="cancelHoverClose"
          @mouseleave="scheduleHoverClose"
        >
          <div class="mh-gv2-hover-card__head">
            <span class="mh-gv2-hover-card__title">{{ hoverCard.title }}</span>
            <span v-if="hoverCard.badge" class="mh-gv2-badge-mixed">{{ hoverCard.badge }}</span>
            <span v-else-if="hoverCard.mixed" class="mh-gv2-badge-mixed">{{ $t('mh.globeV2.mixedTag') }}</span>
          </div>
          <div class="mh-gv2-hover-card__meta">{{ hoverCard.subtitle }}</div>
          <div v-if="hoverCard.breakdown" class="mh-gv2-hover-card__breakdown mh-mono">
            {{ hoverCard.breakdown }}
          </div>
          <div v-if="hoverCard.extra" class="mh-gv2-hover-card__extra">{{ hoverCard.extra }}</div>
        </div>

        <!-- Bottom-left legend (collapsed on card, open in desktop full-page, collapsed on mobile; S12 backbone aware) -->
        <div
          ref="legendEl"
          class="mh-gv2-legend"
          :class="{
            'mh-gv2-legend--collapsed': legendCollapsed,
            'mh-gv2-legend--mobile': isMobile,
            'mh-gv2-legend--above-sheet': isMobile && isFullLayout && mobileSheetOpen,
          }"
          data-testid="globe-v2-legend"
          @click.stop
        >
          <!-- Mobile expanded popover (floats compactly above the Legend chip) -->
          <div
            v-if="isMobile && !legendCollapsed"
            class="mh-gv2-legend-popover"
            data-testid="globe-v2-legend-popover"
          >
            <template v-if="!isBackboneView">
              <div class="mh-gv2-legend__row">
                <span class="mh-gv2-swatch-dot" :style="{ background: tokens.online }" />
                <span>{{ $t('mh.mesh.status.online') }}</span>
                <span class="mh-gv2-swatch-dot mh-gv2-swatch-dot--half" :style="{ '--c': tokens.stale, '--bg': tokens.ocean }" />
                <span>{{ $t('mh.mesh.status.stale') }}</span>
                <span class="mh-gv2-swatch-dot mh-gv2-swatch-dot--off" :style="{ borderColor: tokens.offline }" />
                <span>{{ $t('mh.mesh.status.offline') }}</span>
              </div>
              <div class="mh-gv2-legend__row">
                <span class="mh-gv2-swatch-line" :style="{ background: tokens.direct }" />
                <span>{{ $t('mh.mesh.carriers.direct') }}</span>
                <span class="mh-gv2-swatch-line mh-gv2-swatch-line--dash" :style="{ '--c': tokens.relay }" />
                <span>{{ $t('mh.mesh.carriers.relay') }}</span>
                <span class="mh-gv2-swatch-line mh-gv2-swatch-line--short" :style="{ '--c': tokens.derp }" />
                <span>{{ $t('mh.mesh.carriers.derp') }}</span>
                <span class="mh-gv2-swatch-line mh-gv2-swatch-line--dot" :style="{ '--c': tokens.stalled }" />
                <span>{{ $t('mh.mesh.stalled') }}</span>
                <span class="mh-gv2-swatch-mixed" :style="{ color: tokens.labelSecondary }">◆</span>
                <span>{{ $t('mh.globeV2.mixedLegend') }}</span>
              </div>
            </template>
            <template v-else>
              <div class="mh-gv2-legend__row">
                <span class="mh-gv2-swatch-diamond" :style="{ background: tokens.centre }" />
                <span>{{ $t('mh.backbone.legendCentre') }}</span>
                <span class="mh-gv2-swatch-gw" :style="{ '--c': tokens.zones[0] }" />
                <span>{{ $t('mh.backbone.legendGateway') }}</span>
                <span class="mh-gv2-swatch-line" :style="{ background: tokens.zones[0] }" />
                <span>{{ $t('mh.backbone.legendMgmtPath') }}</span>
              </div>
              <div class="mh-gv2-legend__row">
                <span class="mh-gv2-swatch-line" :style="{ background: tokens.labelPrimary, height: '2.5px' }" />
                <span>{{ $t('mh.backbone.legendBackboneLink') }}</span>
                <span class="mh-gv2-swatch-arrow" :style="{ color: tokens.labelPrimary }">▸</span>
                <span>{{ $t('mh.backbone.legendUnidirectional') }}</span>
                <span class="mh-gv2-swatch-line mh-gv2-swatch-line--short" :style="{ '--c': tokens.offline }" />
                <span>{{ $t('mh.backbone.legendDisabled') }}</span>
                <span class="mh-gv2-swatch-line mh-gv2-swatch-line--dot" :style="{ '--c': tokens.stalled }" />
                <span>{{ $t('mh.mesh.stalled') }}</span>
              </div>
              <div v-if="zones.length > 0" class="mh-gv2-legend__row">
                <span v-for="z in zones" :key="z.id" class="mh-gv2-legend__zone">
                  <span class="mh-gv2-swatch-dot" :style="{ background: backboneResolved.zoneColors.get(z.id) }" />
                  <span>{{ z.name }}</span>
                </span>
              </div>
            </template>
            <div
              v-if="unlocatedCentres.length > 0 || unknownNodesForView.length > 0 || (!isBackboneView && linkAgg.overflowCount > 0)"
              class="mh-gv2-legend__chips"
            >
              <button
                v-for="cNode in unlocatedCentres"
                :key="cNode.id"
                type="button"
                class="mh-gv2-chip mh-gv2-chip--centre"
                data-testid="globe-v2-unlocated-centre-chip"
                @click="openUnlocatedCentre(cNode)"
              >
                ◆ {{ $t('mh.backbone.unlocatedCentreChip') }}
              </button>
              <button
                v-if="unknownNodesForView.length > 0"
                type="button"
                class="mh-gv2-chip mh-gv2-chip--warn"
                data-testid="globe-v2-unknown-chip"
                @click="openUnknownList"
              >
                {{ $t('mh.globeV2.unknownLocation', { n: unknownNodesForView.length }) }}
              </button>
              <span
                v-if="!isBackboneView && linkAgg.overflowCount > 0"
                class="mh-gv2-chip"
                data-testid="globe-v2-overflow-chip"
              >
                {{ $t('mh.globeV2.linksOverflow', { n: linkAgg.overflowCount }) }}
              </span>
            </div>
            <div class="mh-gv2-legend__attr" data-testid="globe-v2-attribution">
              {{ attributionText }}
            </div>
          </div>

          <!-- Compact chip bar -->
          <div class="mh-gv2-legend__bar">
            <button
              type="button"
              class="mh-gv2-legend__toggle"
              :aria-expanded="!legendCollapsed"
              data-testid="globe-v2-legend-toggle"
              @click="legendCollapsed = !legendCollapsed"
            >
              <span>{{ $t('mh.globeV2.legend') }}</span>
              <span
                v-if="isMobile && legendCollapsed && (unknownNodesForView.length > 0 || unlocatedCentres.length > 0)"
                class="mh-gv2-legend__dot-warn"
                :title="$t('mh.globeV2.unknownLocation', { n: unknownNodesForView.length + unlocatedCentres.length })"
              />
              <span class="mh-gv2-legend__caret">{{ legendCollapsed ? '▸' : '▾' }}</span>
            </button>
            <template v-if="!isMobile">
              <button
                v-for="cNode in unlocatedCentres"
                :key="cNode.id"
                type="button"
                class="mh-gv2-chip mh-gv2-chip--centre"
                data-testid="globe-v2-unlocated-centre-chip"
                @click="openUnlocatedCentre(cNode)"
              >
                ◆ {{ $t('mh.backbone.unlocatedCentreChip') }}
              </button>
              <button
                v-if="unknownNodesForView.length > 0"
                type="button"
                class="mh-gv2-chip mh-gv2-chip--warn"
                data-testid="globe-v2-unknown-chip"
                @click="openUnknownList"
              >
                {{ $t('mh.globeV2.unknownLocation', { n: unknownNodesForView.length }) }}
              </button>
              <span
                v-if="!isBackboneView && linkAgg.overflowCount > 0"
                class="mh-gv2-chip"
                data-testid="globe-v2-overflow-chip"
              >
                {{ $t('mh.globeV2.linksOverflow', { n: linkAgg.overflowCount }) }}
              </span>
            </template>
          </div>

          <!-- Desktop expanded legend body -->
          <div v-if="!isMobile && !legendCollapsed" class="mh-gv2-legend__body">
            <template v-if="!isBackboneView">
              <div class="mh-gv2-legend__row">
                <span class="mh-gv2-swatch-dot" :style="{ background: tokens.online }" />
                <span>{{ $t('mh.mesh.status.online') }}</span>
                <span class="mh-gv2-swatch-dot mh-gv2-swatch-dot--half" :style="{ '--c': tokens.stale, '--bg': tokens.ocean }" />
                <span>{{ $t('mh.mesh.status.stale') }}</span>
                <span class="mh-gv2-swatch-dot mh-gv2-swatch-dot--off" :style="{ borderColor: tokens.offline }" />
                <span>{{ $t('mh.mesh.status.offline') }}</span>
              </div>
              <div class="mh-gv2-legend__row">
                <span class="mh-gv2-swatch-line" :style="{ background: tokens.direct }" />
                <span>{{ $t('mh.mesh.carriers.direct') }}</span>
                <span class="mh-gv2-swatch-line mh-gv2-swatch-line--dash" :style="{ '--c': tokens.relay }" />
                <span>{{ $t('mh.mesh.carriers.relay') }}</span>
                <span class="mh-gv2-swatch-line mh-gv2-swatch-line--short" :style="{ '--c': tokens.derp }" />
                <span>{{ $t('mh.mesh.carriers.derp') }}</span>
                <span class="mh-gv2-swatch-line mh-gv2-swatch-line--dot" :style="{ '--c': tokens.stalled }" />
                <span>{{ $t('mh.mesh.stalled') }}</span>
                <span class="mh-gv2-swatch-mixed" :style="{ color: tokens.labelSecondary }">◆</span>
                <span>{{ $t('mh.globeV2.mixedLegend') }}</span>
              </div>
            </template>
            <template v-else>
              <div class="mh-gv2-legend__row">
                <span class="mh-gv2-swatch-diamond" :style="{ background: tokens.centre }" />
                <span>{{ $t('mh.backbone.legendCentre') }}</span>
                <span class="mh-gv2-swatch-gw" :style="{ '--c': tokens.zones[0] }" />
                <span>{{ $t('mh.backbone.legendGateway') }}</span>
                <span class="mh-gv2-swatch-line" :style="{ background: tokens.zones[0] }" />
                <span>{{ $t('mh.backbone.legendMgmtPath') }}</span>
              </div>
              <div class="mh-gv2-legend__row">
                <span class="mh-gv2-swatch-line" :style="{ background: tokens.labelPrimary, height: '2.5px' }" />
                <span>{{ $t('mh.backbone.legendBackboneLink') }}</span>
                <span class="mh-gv2-swatch-arrow" :style="{ color: tokens.labelPrimary }">▸</span>
                <span>{{ $t('mh.backbone.legendUnidirectional') }}</span>
                <span class="mh-gv2-swatch-line mh-gv2-swatch-line--short" :style="{ '--c': tokens.offline }" />
                <span>{{ $t('mh.backbone.legendDisabled') }}</span>
                <span class="mh-gv2-swatch-line mh-gv2-swatch-line--dot" :style="{ '--c': tokens.stalled }" />
                <span>{{ $t('mh.mesh.stalled') }}</span>
              </div>
              <div v-if="zones.length > 0" class="mh-gv2-legend__row">
                <span v-for="z in zones" :key="z.id" class="mh-gv2-legend__zone">
                  <span class="mh-gv2-swatch-dot" :style="{ background: backboneResolved.zoneColors.get(z.id) }" />
                  <span>{{ z.name }}</span>
                </span>
              </div>
            </template>
            <div class="mh-gv2-legend__attr" data-testid="globe-v2-attribution">
              {{ attributionText }}
            </div>
          </div>
        </div>

        <!-- Non-modal detail / list / mobile 3-snap bottom sheet panel (S8 / S10) -->
        <aside
          v-if="showDetailPanel && (panelOpen || (isMobile && isFullLayout && mobileSheetOpen))"
          ref="panelEl"
          class="mh-gv2-panel"
          :class="{
            'mh-gv2-panel--mobile': isMobile,
            'mh-gv2-panel--tablet': isTablet,
            [`mh-gv2-panel--snap-${mobileSnap}`]: isMobile,
          }"
          :style="mobileSheetDynamicStyle"
          role="region"
          :aria-label="panelTitle || $t('mh.globeV2.tabDetails')"
          :data-testid="isMobile ? 'globe-v2-mobile-sheet' : 'globe-v2-panel'"
          :data-mobile-snap="isMobile ? mobileSnap : undefined"
          @click.stop
        >
          <!-- Draggable 3-snap handle on mobile (<600px: 30% / 60% / 92% dvh, min 160px) -->
          <div
            v-if="isMobile"
            class="mh-gv2-panel__grabber"
            role="button"
            tabindex="0"
            :aria-label="$t('mh.globeV2.sheetHandleAria')"
            data-testid="globe-v2-sheet-handle"
            @pointerdown="onSheetDragStart"
            @click="onSheetHandleClick"
            @keydown.enter.prevent="cycleMobileSnap"
            @keydown.space.prevent="cycleMobileSnap"
          >
            <span class="mh-gv2-panel__grabber-bar" />
          </div>

          <!-- Mobile full-page 3 tabs: Details / Filters / List (S10) -->
          <div
            v-if="isMobile && isFullLayout"
            class="mh-gv2-sheet-tabs"
            role="tablist"
            data-testid="globe-v2-mobile-tabs"
          >
            <button
              type="button"
              role="tab"
              :aria-selected="mobileTab === 'details'"
              class="mh-gv2-sheet-tab"
              :class="{ 'mh-gv2-sheet-tab--active': mobileTab === 'details' }"
              data-testid="globe-v2-tab-details"
              @click="mobileTab = 'details'"
            >
              {{ $t('mh.globeV2.tabDetails') }}
            </button>
            <button
              type="button"
              role="tab"
              :aria-selected="mobileTab === 'filters'"
              class="mh-gv2-sheet-tab"
              :class="{ 'mh-gv2-sheet-tab--active': mobileTab === 'filters' }"
              data-testid="globe-v2-tab-filters"
              @click="mobileTab = 'filters'"
            >
              {{ $t('mh.globeV2.tabFilters') }}
            </button>
            <button
              type="button"
              role="tab"
              :aria-selected="mobileTab === 'list'"
              class="mh-gv2-sheet-tab"
              :class="{ 'mh-gv2-sheet-tab--active': mobileTab === 'list' }"
              data-testid="globe-v2-tab-list"
              @click="mobileTab = 'list'"
            >
              {{ $t('mh.globeV2.tabList') }} ({{ activeListNodes.length }})
            </button>
            <button
              type="button"
              class="mh-gv2-icon-btn mh-gv2-sheet-close"
              :aria-label="$t('mh.mesh.panel.close')"
              data-testid="globe-v2-panel-close"
              @click="closePanel"
            >
              ×
            </button>
          </div>

          <!-- Mobile Filters Tab Content -->
          <div
            v-if="isMobile && isFullLayout && mobileTab === 'filters'"
            class="mh-gv2-panel__body"
            data-testid="globe-v2-mobile-filters-body"
          >
            <template v-if="isBackboneView">
              <div class="mh-gv2-section">
                <label class="mh-gv2-toggle-row">
                  <input
                    type="checkbox"
                    :checked="showDevices"
                    data-testid="globe-v2-mobile-show-devices"
                    @change="setShowDevicesOverlay(($event.target as HTMLInputElement).checked)"
                  />
                  <span>{{ $t('mh.backbone.showDevices') }}</span>
                </label>
              </div>
            </template>
            <template v-else>
              <div class="mh-gv2-section__title">{{ $t('mh.globeV2.carriersLabel') }}</div>
              <div class="mh-gv2-carrier-checks">
                <button
                  v-for="cls in ALL_CARRIERS"
                  :key="cls"
                  type="button"
                  class="mh-gv2-chip-btn"
                  :class="{ 'mh-gv2-chip-btn--active': activeCarrierSet.has(cls) }"
                  @click="toggleLocalCarrier(cls)"
                >
                  <span class="mh-gv2-swatch-dot" :style="{ background: carrierTokenColor(cls) }" />
                  {{ carrierLabel(cls) }}
                </button>
              </div>

              <div class="mh-gv2-section">
                <label class="mh-gv2-toggle-row">
                  <input
                    type="checkbox"
                    :checked="effectiveOnlyProblems"
                    @change="localOnlyProblems = ($event.target as HTMLInputElement).checked"
                  />
                  <span>{{ $t('mh.globeV2.onlyProblems') }}</span>
                </label>
                <label class="mh-gv2-rtt-filter mh-gv2-rtt-filter--block">
                  <span class="mh-mono">{{ $t('mh.globeV2.minRtt', { ms: effectiveMinRttMs }) }}</span>
                  <input
                    type="range"
                    min="0"
                    max="500"
                    step="5"
                    :value="effectiveMinRttMs"
                    @input="localMinRttMs = Number(($event.target as HTMLInputElement).value)"
                  />
                </label>
                <button type="button" class="mh-gv2-chip-btn mt-2" @click="resetLocalFilters">
                  {{ $t('mh.globeV2.resetFilters') }}
                </button>
              </div>
            </template>
          </div>

          <!-- Mobile List Tab Content -->
          <div
            v-else-if="isMobile && isFullLayout && mobileTab === 'list'"
            class="mh-gv2-panel__body"
            data-testid="globe-v2-mobile-list-body"
          >
            <div class="mh-gv2-list">
              <button
                v-for="item in pagedAllNodes"
                :key="item.id"
                type="button"
                class="mh-gv2-list-row"
                @click="selectNodeFromList(item)"
              >
                <span class="mh-gv2-list-row__name">
                  <span
                    class="mh-gv2-swatch-dot"
                    :style="{ background: presenceTokenColor(item) }"
                  />
                  {{ item.name }}
                </span>
                <span class="mh-mono">{{ isBackboneView ? (item.zoneName || nodeCityShort(item)) : nodeCityShort(item) }}</span>
              </button>
            </div>
            <div v-if="allListTotalPages > 1" class="mh-gv2-pager">
              <button type="button" class="mh-gv2-icon-btn" :disabled="allListPage <= 1" @click="allListPage--">‹</button>
              <span class="mh-mono">{{ allListPage }} / {{ allListTotalPages }}</span>
              <button type="button" class="mh-gv2-icon-btn" :disabled="allListPage >= allListTotalPages" @click="allListPage++">›</button>
            </div>
          </div>

          <!-- Details / Selected Content (Desktop always; Mobile when tab === 'details') -->
          <template v-else>
            <div v-if="!(isMobile && isFullLayout)" class="mh-gv2-panel__head">
              <div class="mh-gv2-panel__title-row">
                <span
                  v-if="selectedNode"
                  class="mh-gv2-swatch-dot"
                  :style="{ background: presenceTokenColor(selectedNode) }"
                  aria-hidden="true"
                />
                <span
                  v-else-if="selectedLink"
                  class="mh-gv2-swatch-dot"
                  :style="{ background: carrierTokenColor(selectedLink.majorityClass) }"
                  aria-hidden="true"
                />
                <span
                  v-else-if="selectedBackboneArc"
                  class="mh-gv2-swatch-dot"
                  :style="{ background: selectedBackboneArc.stalled ? tokens.stalled : tokens.labelPrimary }"
                  aria-hidden="true"
                />
                <div class="mh-gv2-panel__title" :title="panelTitle">{{ panelTitle }}</div>
              </div>
              <button
                type="button"
                class="mh-gv2-icon-btn"
                :aria-label="$t('mh.mesh.panel.close')"
                data-testid="globe-v2-panel-close"
                @click="closePanel"
              >
                ×
              </button>
            </div>

            <!-- Single node detail (Device / Gateway / Centre — strictly separated role badges + S12 backbone fields) -->
            <div v-if="selectedNode" class="mh-gv2-panel__body" data-testid="globe-v2-device-detail">
              <div class="mh-gv2-badges">
                <span class="mh-gv2-badge" :style="{ borderColor: presenceTokenColor(selectedNode), color: presenceTokenColor(selectedNode) }">
                  {{ presenceLabel(selectedNode) }}
                </span>
                <span
                  v-if="selectedNode.isCentre || selectedNode.role === 'centre'"
                  class="mh-gv2-badge mh-gv2-badge--centre"
                  data-testid="globe-v2-role-centre"
                >
                  {{ $t('mh.mesh.role.centre') }}
                </span>
                <span
                  v-if="selectedNode.isGateway || selectedNode.role === 'gateway'"
                  class="mh-gv2-badge mh-gv2-badge--gateway"
                  data-testid="globe-v2-role-gateway"
                >
                  {{ $t('mh.mesh.role.gateway') }}
                </span>
                <span
                  v-if="selectedNode.isEntry || selectedNode.role === 'entry'"
                  class="mh-gv2-badge mh-gv2-badge--entry"
                  data-testid="globe-v2-role-entry"
                >
                  {{ $t('mh.mesh.role.entry') }}
                </span>
                <template v-if="selectedNodeZoneChips.length">
                  <span
                    v-for="zc in selectedNodeZoneChips"
                    :key="zc.key"
                    class="mh-gv2-badge"
                    data-testid="globe-v2-zone-chip"
                  >
                    <span
                      v-if="zc.color"
                      class="mh-gv2-swatch-dot"
                      style="width: 6px; height: 6px; margin-right: 4px"
                      :style="{ background: zc.color }"
                      aria-hidden="true"
                    />
                    <svg v-if="selectedNode.zonePinned" viewBox="0 0 16 16" width="10" height="10" fill="currentColor" style="margin-right: 3px" aria-hidden="true">
                      <path d="M9.8 1.5l4.7 4.7-1.1 1.1-1.3-.4-2.6 2.6.5 2.4-1 1-2.5-2.5-3.4 3.4-.9-.9 3.4-3.4L3.1 7l1-1 2.4.5 2.6-2.6-.4-1.3z" />
                    </svg>{{ zc.name }}
                  </span>
                </template>
              </div>

              <dl class="mh-gv2-facts">
                <div v-if="selectedNodeOsVersion" class="mh-gv2-fact">
                  <dt>{{ $t('mh.mesh.panel.system') }}</dt>
                  <dd class="mh-mono">{{ selectedNodeOsVersion }}</dd>
                </div>
                <div v-if="selectedNodeLastSeen" class="mh-gv2-fact">
                  <dt>{{ $t('mh.mesh.panel.lastSeen') }}</dt>
                  <dd class="mh-mono">{{ selectedNodeLastSeen }}</dd>
                </div>
                <div v-if="selectedNode.zoneDeviceCount != null" class="mh-gv2-fact" data-testid="globe-v2-zone-devices">
                  <dt>{{ $t('mh.backbone.zoneDevicesLabel') }}</dt>
                  <dd class="mh-mono">{{ $t('mh.backbone.deviceCountShort', { n: selectedNode.zoneDeviceCount }) }}</dd>
                </div>
                <div v-if="selectedNode.managementEntry" class="mh-gv2-fact" data-testid="globe-v2-mgmt-entry">
                  <dt>{{ $t('mh.mesh.panel.managementEntry') }}</dt>
                  <dd class="mh-mono">
                    {{
                      selectedNode.managementEntry.listening
                        ? selectedNode.managementEntry.port
                          ? $t('mh.mesh.panel.entryListeningPort', { port: selectedNode.managementEntry.port })
                          : $t('mh.mesh.panel.entryListening')
                        : $t('mh.mesh.panel.entryNotListening')
                    }}
                    · {{ $t('mh.mesh.panel.entryDevicesCount', { n: selectedNode.managementEntry.deviceCount }) }}
                  </dd>
                </div>
                <div v-if="selectedNodeMgmtPathText" class="mh-gv2-fact" data-testid="globe-v2-mgmt-path">
                  <dt>{{ isBackboneView ? $t('mh.backbone.mgmtPathLabel') : $t('mh.mesh.panel.pathToCentre') }}</dt>
                  <dd>{{ selectedNodeMgmtPathText }}</dd>
                </div>
                <div class="mh-gv2-fact">
                  <dt>{{ $t('mh.globeV2.countryRegion') }}</dt>
                  <dd>{{ selectedNodeRegionText }}</dd>
                </div>
                <div class="mh-gv2-fact" data-testid="globe-v2-precision-row">
                  <dt>{{ $t('mh.globeV2.locationPrecision') }}</dt>
                  <dd>{{ selectedNodePrecisionText }}</dd>
                </div>
                <div v-if="selectedNode.publicIp" class="mh-gv2-fact" data-testid="globe-v2-public-ip">
                  <dt>{{ $t('mh.mesh.panel.publicIp') }}</dt>
                  <dd class="mh-mono">{{ selectedNode.publicIp }}</dd>
                </div>
                <div v-if="selectedNode.overlayIp" class="mh-gv2-fact">
                  <dt>{{ $t('mh.mesh.panel.overlayIp') }}</dt>
                  <dd class="mh-mono">{{ selectedNode.overlayIp }}</dd>
                </div>
                <div v-if="selectedNode.relayHome" class="mh-gv2-fact">
                  <dt>{{ $t('mh.mesh.panel.relayHome') }}</dt>
                  <dd class="mh-mono">{{ selectedNode.relayHome }}</dd>
                </div>
              </dl>

              <!-- Backbone incident links (when in backbone view) -->
              <div v-if="isBackboneView && selectedNodeBackboneLinks.length" class="mh-gv2-section" data-testid="globe-v2-backbone-node-links">
                <div class="mh-gv2-section__title">
                  {{ $t('mh.backbone.linksHeading', { n: selectedNodeBackboneLinks.length }) }}
                </div>
                <div class="mh-gv2-list">
                  <button
                    v-for="bl in selectedNodeBackboneLinks"
                    :key="bl.arc.key"
                    type="button"
                    class="mh-gv2-list-row"
                    @click="selectBackboneLink(bl.arc)"
                  >
                    <span class="mh-gv2-list-row__name">
                      <span
                        class="mh-gv2-swatch-dot"
                        :style="{ background: bl.arc.stalled ? tokens.stalled : tokens.labelPrimary }"
                      />
                      <span>{{ bl.peerName }}</span>
                    </span>
                    <span class="mh-mono mh-gv2-list-row__meta">
                      {{ carrierLabel(bl.arc.carrier) }}<template v-if="bl.arc.rttMs != null"> · {{ bl.arc.rttMs }} ms</template><template v-if="bl.arc.stalled"> · ⚠</template>
                    </span>
                  </button>
                </div>
              </div>

              <!-- Same-city devices (Devices view only, paginated 50/page) -->
              <div v-if="!isBackboneView && sameCityDevices.length > 1" class="mh-gv2-section" data-testid="globe-v2-same-city-section">
                <div class="mh-gv2-section__title">
                  {{ $t('mh.globeV2.sameCityDevices', { n: sameCityDevices.length }) }}
                </div>
                <div v-if="selectedNodeIntraCityCount > 0" class="mh-gv2-note">
                  {{ $t('mh.globeV2.intraCityLinks', { n: selectedNodeIntraCityCount }) }}
                </div>
                <div class="mh-gv2-list mh-gv2-list--compact">
                  <button
                    v-for="mate in pagedSameCityDevices"
                    :key="mate.id"
                    type="button"
                    class="mh-gv2-list-row"
                    :class="{ 'mh-gv2-list-row--active': mate.id === selectedNode.id }"
                    @click="selectNodeFromList(mate)"
                  >
                    <span class="mh-gv2-list-row__name">
                      <span class="mh-gv2-swatch-dot" :style="{ background: presenceTokenColor(mate) }" />
                      {{ mate.name }}
                    </span>
                    <span class="mh-mono">{{ presenceLabel(mate) }}</span>
                  </button>
                </div>
                <div v-if="sameCityTotalPages > 1" class="mh-gv2-pager">
                  <button type="button" class="mh-gv2-icon-btn" :disabled="sameCityPage <= 1" @click="sameCityPage--">‹</button>
                  <span class="mh-mono">{{ sameCityPage }} / {{ sameCityTotalPages }}</span>
                  <button type="button" class="mh-gv2-icon-btn" :disabled="sameCityPage >= sameCityTotalPages" @click="sameCityPage++">›</button>
                </div>
              </div>

              <!-- Links grouped by remote city (Devices view only) -->
              <div v-if="!isBackboneView && egoLinks.length" class="mh-gv2-section" data-testid="globe-v2-remote-links">
                <div class="mh-gv2-section__title">
                  {{ $t('mh.globeV2.linksByRemoteCity', { n: egoLinks.length }) }}
                </div>
                <div class="mh-gv2-list">
                  <button
                    v-for="l in egoLinks.slice(0, 30)"
                    :key="l.key"
                    type="button"
                    class="mh-gv2-list-row"
                    @click="selectAggregatedLink(l)"
                  >
                    <span class="mh-gv2-list-row__name">
                      <span class="mh-gv2-swatch-dot" :style="{ background: carrierTokenColor(l.majorityClass) }" />
                      <span>{{ remoteClusterLabel(l, selectedNodeDisplayId) }}</span>
                    </span>
                    <span class="mh-mono mh-gv2-list-row__meta">
                      {{ carrierLabel(l.majorityClass) }}<template v-if="l.isMixed"> · {{ $t('mh.globeV2.mixedTag') }}</template><template v-if="l.medianRtt != null"> · {{ l.medianRtt }} ms</template>
                    </span>
                  </button>
                </div>
              </div>

              <button
                v-if="showOpenDeviceAction && (selectedNode.agentId || !selectedNode.isCentre)"
                type="button"
                class="mh-gv2-primary-btn"
                data-testid="globe-v2-open-device-btn"
                @click="emit('open-device', selectedNode.id)"
              >
                {{ $t('mh.globeV2.openDevicePage') }}
              </button>
            </div>

            <!-- Backbone Link detail (S12 / FR-137) -->
            <div v-else-if="selectedBackboneArc" class="mh-gv2-panel__body" data-testid="globe-v2-backbone-link-detail">
              <div class="mh-gv2-badges">
                <span class="mh-gv2-badge">
                  {{ carrierLabel(selectedBackboneArc.carrier) }}
                </span>
                <span
                  v-if="selectedBackboneArc.crossZone"
                  class="mh-gv2-badge mh-gv2-badge--accent"
                  data-testid="globe-v2-cross-zone-badge"
                >
                  {{ $t('mh.backbone.crossZone') }}
                </span>
                <span class="mh-gv2-badge">
                  {{
                    isUnidirectionalBackboneArc(selectedBackboneArc)
                      ? $t('mh.backbone.unidirectional')
                      : $t('mh.backbone.bidirectional')
                  }}
                </span>
                <span
                  v-if="selectedBackboneArc.enabled === false"
                  class="mh-gv2-badge"
                  :style="{ borderColor: tokens.offline, color: tokens.offline }"
                >
                  {{ $t('mh.backbone.disabled') }}
                </span>
                <span
                  v-else-if="selectedBackboneArc.stalled"
                  class="mh-gv2-badge"
                  :style="{ borderColor: tokens.stalled, color: tokens.stalled }"
                >
                  {{ $t('mh.mesh.stalled') }}
                </span>
              </div>

              <dl class="mh-gv2-facts">
                <div class="mh-gv2-fact">
                  <dt>{{ backboneNodeName(selectedBackboneArc.from) }}</dt>
                  <dd>{{ backboneNodeZonesText(selectedBackboneArc.from) || '—' }}</dd>
                </div>
                <div class="mh-gv2-fact">
                  <dt>{{ backboneNodeName(selectedBackboneArc.to) }}</dt>
                  <dd>{{ backboneNodeZonesText(selectedBackboneArc.to) || '—' }}</dd>
                </div>
                <template v-if="selectedBackboneLinkDirections.length">
                  <div v-for="dir in selectedBackboneLinkDirections" :key="dir.label" class="mh-gv2-fact">
                    <dt>{{ dir.label }}</dt>
                    <dd class="mh-mono">
                      {{ dir.carrier }}<template v-if="dir.rttMs != null"> · {{ dir.rttMs }} ms</template><template v-if="dir.stalled"> · {{ $t('mh.mesh.stalled') }}</template>
                    </dd>
                  </div>
                </template>
                <template v-else>
                  <div class="mh-gv2-fact">
                    <dt>{{ $t('mh.mesh.panel.carrier') }}</dt>
                    <dd class="mh-mono">{{ carrierLabel(selectedBackboneArc.carrier) }}</dd>
                  </div>
                  <div v-if="selectedBackboneArc.rttMs != null" class="mh-gv2-fact">
                    <dt>{{ $t('mh.mesh.panel.rtt') }}</dt>
                    <dd class="mh-mono">{{ selectedBackboneArc.rttMs }} ms</dd>
                  </div>
                </template>
                <div v-if="selectedBackboneArc.reports != null" class="mh-gv2-fact">
                  <dt>{{ $t('mh.mesh.panel.reports') }}</dt>
                  <dd>
                    {{
                      selectedBackboneArc.reports === 1
                        ? $t('mh.mesh.panel.oneSided')
                        : $t('mh.mesh.panel.reportsCount', { n: selectedBackboneArc.reports })
                    }}
                  </dd>
                </div>
                <div class="mh-gv2-fact">
                  <dt>{{ $t('mh.backbone.directionLabel') }}</dt>
                  <dd>
                    {{
                      isUnidirectionalBackboneArc(selectedBackboneArc)
                        ? $t('mh.backbone.unidirectional')
                        : $t('mh.backbone.bidirectional')
                    }}
                  </dd>
                </div>
              </dl>

              <div class="mh-gv2-endpoints">
                <button
                  type="button"
                  class="mh-gv2-chip-btn"
                  @click="focusNodeById(selectedBackboneArc.from)"
                >
                  {{ backboneNodeName(selectedBackboneArc.from) }}
                </button>
                <button
                  type="button"
                  class="mh-gv2-chip-btn"
                  @click="focusNodeById(selectedBackboneArc.to)"
                >
                  {{ backboneNodeName(selectedBackboneArc.to) }}
                </button>
              </div>
            </div>

            <!-- Aggregated link detail (Fix #6: majority carrier, mixed badge, full per-carrier breakdown) -->
            <div v-else-if="selectedLink" class="mh-gv2-panel__body" data-testid="globe-v2-link-detail">
              <div class="mh-gv2-badges">
                <span
                  class="mh-gv2-badge"
                  :style="{
                    borderColor: carrierTokenColor(selectedLink.majorityClass),
                    color: carrierTokenColor(selectedLink.majorityClass),
                  }"
                >
                  {{ carrierLabel(selectedLink.majorityClass) }}
                </span>
                <span v-if="selectedLink.isMixed" class="mh-gv2-badge-mixed" data-testid="globe-v2-link-mixed-badge">
                  {{ $t('mh.globeV2.mixedTag') }}
                </span>
                <span v-if="selectedLink.asymmetric" class="mh-gv2-badge">
                  {{ $t('mh.mesh.asymmetricTag') }}
                </span>
                <span
                  v-if="selectedLink.anyStalled"
                  class="mh-gv2-badge"
                  :style="{ borderColor: tokens.stalled, color: tokens.stalled }"
                >
                  {{ $t('mh.mesh.stalled') }} ({{ selectedLink.stalledCount }})
                </span>
              </div>

              <dl class="mh-gv2-facts">
                <div class="mh-gv2-fact">
                  <dt>{{ $t('mh.globeV2.majorityCarrier') }}</dt>
                  <dd class="mh-mono">{{ carrierLabel(selectedLink.majorityClass) }}</dd>
                </div>
                <div class="mh-gv2-fact" data-testid="globe-v2-link-breakdown">
                  <dt>{{ $t('mh.globeV2.carrierBreakdown') }}</dt>
                  <dd class="mh-mono">{{ formatBreakdownText(selectedLink) }}</dd>
                </div>
                <div class="mh-gv2-fact">
                  <dt>{{ $t('mh.globeV2.aggregatedCount') }}</dt>
                  <dd class="mh-mono">{{ selectedLink.count }}</dd>
                </div>
                <div v-if="selectedLink.medianRtt != null" class="mh-gv2-fact">
                  <dt>{{ $t('mh.globeV2.medianRtt') }}</dt>
                  <dd class="mh-mono">{{ selectedLink.medianRtt }} ms</dd>
                </div>
                <div v-if="selectedLink.maxRtt != null" class="mh-gv2-fact">
                  <dt>{{ $t('mh.globeV2.maxRtt') }}</dt>
                  <dd class="mh-mono">{{ selectedLink.maxRtt }} ms</dd>
                </div>
                <div v-if="selectedLink.asymmetric" class="mh-gv2-fact">
                  <dt>{{ $t('mh.mesh.asymmetricTag') }}</dt>
                  <dd class="mh-mono">
                    {{ carrierLabel(selectedLink.fromClass) }} / {{ carrierLabel(selectedLink.toClass) }}
                  </dd>
                </div>
              </dl>

              <div class="mh-gv2-endpoints">
                <button
                  type="button"
                  class="mh-gv2-chip-btn"
                  @click="focusClusterById(selectedLink.fromDisplayId)"
                >
                  {{ clusterLabelById(selectedLink.fromDisplayId) }}
                </button>
                <button
                  type="button"
                  class="mh-gv2-chip-btn"
                  @click="focusClusterById(selectedLink.toDisplayId)"
                >
                  {{ clusterLabelById(selectedLink.toDisplayId) }}
                </button>
              </div>
            </div>

            <!-- Paginated list (city group >20, multi-city cluster, unknown location, or all devices) -->
            <div v-else-if="listPanelNodes.length" class="mh-gv2-panel__body">
              <div v-if="selectedClusterIntraCity > 0" class="mh-gv2-note" data-testid="globe-v2-intracity-note">
                {{ $t('mh.globeV2.intraCityLinks', { n: selectedClusterIntraCity }) }}
              </div>
              <div v-if="listPanelPrecisionNote" class="mh-gv2-note">
                {{ listPanelPrecisionNote }}
              </div>
              <div class="mh-gv2-list" data-testid="globe-v2-paginated-list">
                <button
                  v-for="item in pagedListNodes"
                  :key="item.id"
                  type="button"
                  class="mh-gv2-list-row"
                  @click="selectNodeFromList(item)"
                >
                  <span class="mh-gv2-list-row__name">
                    <span class="mh-gv2-swatch-dot" :style="{ background: presenceTokenColor(item) }" />
                    {{ item.name }}
                  </span>
                  <span class="mh-mono">{{ item.zoneName || presenceLabel(item) }}</span>
                </button>
              </div>
              <div v-if="listTotalPages > 1" class="mh-gv2-pager">
                <button type="button" class="mh-gv2-icon-btn" :disabled="listPage <= 1" @click="listPage--">‹</button>
                <span class="mh-mono">{{ listPage }} / {{ listTotalPages }}</span>
                <button type="button" class="mh-gv2-icon-btn" :disabled="listPage >= listTotalPages" @click="listPage++">›</button>
              </div>
            </div>

            <!-- Empty prompt inside mobile full-page Details tab when nothing selected yet -->
            <div v-else class="mh-gv2-panel__body">
              <p class="mh-gv2-note">{{ $t('mh.globeV2.emptySelection') }}</p>
            </div>
          </template>
        </aside>

        <!-- Context-lost banner (AC13 / S11) -->
        <div v-if="contextLostActive" class="mh-gv2-context-lost" role="alert">
          {{ $t('mh.globeV2.contextLost') }}
        </div>
      </div>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { computed, inject, nextTick, onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue'
import { routeLocationKey, routerKey, type RouteLocationNormalizedLoaded, type Router } from 'vue-router'
import { useI18n } from 'vue-i18n'
import * as maplibregl from 'maplibre-gl'
import type { GeoJSONSource, Map as MapLibreMap, Marker } from 'maplibre-gl'
import 'maplibre-gl/dist/maplibre-gl.css'
import workerUrl from 'maplibre-gl/dist/maplibre-gl-worker.mjs?url'
import { Protocol } from 'pmtiles'
import { appPath } from '@/utils/deployment'
import { edgeSides, qualifiedCarrier } from '@/utils/mesh'
import type { GlobeArc, GlobeCenter, GlobeNode } from '@/components/globe/types'
import type { BackboneZoneView } from '@/stores/serverTopology'
import {
  BOUNDARY_ATTRIBUTION,
  CJK_FONT_STACK,
  formatNeutralRegionName,
  getGlobeTokens,
  type GlobeLang,
  type GlobeThemeMode,
} from './tokens'
import {
  loadGazetteerIfPresent,
  resolveV2Location,
  type GazetteerV1,
} from './locationResolver'
import {
  accuracyCircleRadiusPx,
  assignMarkerEdgePlacement,
  buildAccuracyCircleRing,
  computeFitGlobeZoom,
  computeGlobeScreenCircle,
  DEFAULT_GLOBE_CENTER,
  DEFAULT_TARGET_DIAMETER_RATIO,
  MIN_GLOBE_ZOOM,
} from './globeViewport'
import {
  formatMaxZoomSpanHint,
  MAX_ALLOWED_MAX_ZOOM,
  MIN_ALLOWED_MAX_ZOOM,
  readStoredMaxZoom,
  writeStoredMaxZoom,
} from './maxZoomSetting'
import {
  centralAngleRad,
  classifyGroupInteraction,
  clusterGroupsForZoom,
  computeSpiderfyLayout,
  effectivePresence,
  findClusterSplitZoom,
  formatClusterLabel,
  groupNodesByLocation,
  LIST_PAGE_SIZE,
  type DisplayCluster,
} from './grouping'
import type { SpiderfyLayout } from './spiderfy'
import {
  aggregateLinks,
  buildEgoNetwork,
  buildLinkGeoJson,
  linkCarrierBreakdown,
  type AggregatedLink,
  type LinkCarrierClass,
} from './links'
import {
  buildBackboneDevicesOverlayGeoJson,
  buildBackboneLinksGeoJson,
  buildBackboneMgmtPathsGeoJson,
  formatBackboneNodeLabel,
  isUnidirectionalBackboneArc,
  resolveBackboneNodes,
  type PlacedBackboneNode,
} from './backbone'
import {
  ensureBackboneStaticIcons,
  ensureStaticIcons,
  hitHalfBoxPx,
  resolveBackboneNodeIconId,
  resolveClusterIconId,
} from './icons'
import {
  ACCURACY_CIRCLES_SOURCE_ID,
  applyLangToMap,
  applyThemeToMap,
  applyViewModeLayerVisibility,
  BACKBONE_ARROWS_SOURCE_ID,
  BACKBONE_DEVICES_SOURCE_ID,
  BACKBONE_LINK_LAYER_IDS,
  BACKBONE_LINKS_SOURCE_ID,
  BACKBONE_MGMT_PATHS_SOURCE_ID,
  buildGlobeStyle,
  LINK_BADGES_SOURCE_ID,
  LINKS_SOURCE_ID,
  MARKER_LABEL_LAYER_IDS,
  MARKERS_SOURCE_ID,
  SURFACE_LINK_LAYER_IDS,
} from './style'
import { useFullPage } from './useFullPage'
import SpiderfyOverlay from './SpiderfyOverlay.vue'

// Module-level once-only MapLibre worker + PMTiles protocol setup (S1).
let maplibreInitialized = false
function ensureMapLibreSetup(): void {
  if (maplibreInitialized) return
  maplibreInitialized = true
  maplibregl.setWorkerUrl(workerUrl)
  const protocol = new Protocol()
  maplibregl.addProtocol('pmtiles', protocol.tile)
}

let uidCounter = 0

const ALL_CARRIERS: readonly LinkCarrierClass[] = ['direct', 'tunnel', 'relay', 'derp', 'blocked']

export interface GlobePerfReport {
  variant: 'L'
  pixelRatio: number
  dataset: string
  viewport: { width: number; height: number }
  renderer: string
  durationMs: number
  totalFrames: number
  avgFps: number
  p50: number
  p95: number
  maxFrameMs: number
  framesOver50ms: number
  tileBytes: number
  firstFrameMs: number | null
  idleFramesAfter1s: number
  webglContextLost: number
  styleReloads: number
  cooperativeGesturesSupported: boolean
  timestamp: string
}

const props = withDefaults(
  defineProps<{
    viewMode?: 'devices' | 'backbone'
    nodes: readonly GlobeNode[]
    arcs: readonly GlobeArc[]
    center?: GlobeCenter | null
    zones?: readonly BackboneZoneView[]
    overlayDevices?: readonly GlobeNode[]
    overlayDeviceArcs?: readonly GlobeArc[]
    backboneNodes?: readonly GlobeNode[]
    backboneArcs?: readonly GlobeArc[]
    showDevicesOverlay?: boolean
    themeMode?: GlobeThemeMode
    lang?: GlobeLang
    pixelRatio?: number
    cooperativeGestures?: boolean
    pmtilesPath?: string
    enabledCarriers?: readonly string[]
    onlyProblems?: boolean
    minRttMs?: number
    showControlPlane?: boolean
    showDetailPanel?: boolean
    showOpenDeviceAction?: boolean
    height?: number
    ariaLabel?: string
    datasetTag?: string
    syncUrl?: boolean
    /** Render permanently in full-page layout filling the parent viewport (no expand/exit toggle, no body teleport). */
    standaloneFullPage?: boolean
  }>(),
  {
    viewMode: 'devices',
    center: null,
    zones: () => [],
    overlayDevices: () => [],
    overlayDeviceArcs: () => [],
    backboneNodes: () => [],
    backboneArcs: () => [],
    showDevicesOverlay: false,
    themeMode: 'dark',
    lang: 'zh-CN',
    pixelRatio: 2,
    cooperativeGestures: true,
    pmtilesPath: '',
    enabledCarriers: () => ['direct', 'tunnel', 'relay', 'derp'],
    onlyProblems: false,
    minRttMs: 0,
    showControlPlane: true,
    showDetailPanel: true,
    showOpenDeviceAction: true,
    height: 560,
    ariaLabel: '',
    datasetTag: 'real',
    syncUrl: false,
    standaloneFullPage: false,
  },
)

const emit = defineEmits<{
  (e: 'node-click', nodeId: string): void
  (e: 'arc-click', arcKey: string): void
  (e: 'open-device', nodeId: string): void
  (e: 'update:view-mode', mode: 'devices' | 'backbone'): void
  (e: 'update:show-devices-overlay', show: boolean): void
  (e: 'full-page-change', full: boolean): void
  (e: 'webgl-error', reason: string): void
  (
    e: 'metrics-change',
    metrics: {
      firstFrameMs: number | null
      webglContextLost: number
      styleReloads: number
      cooperativeGesturesActive: boolean
      zoom: number
      displayedLinks: number
      overflowLinks: number
      unlocatedCount: number
    },
  ): void
}>()

const { t, locale } = useI18n()
const injectedRouter = inject<Router | null>(routerKey, null)
const injectedRoute = inject<RouteLocationNormalizedLoaded | null>(routeLocationKey, null)

const instanceUid = ++uidCounter
const fresnelOuterId = `mh-fresnel-outer-${instanceUid}`
const fresnelInnerId = `mh-fresnel-inner-${instanceUid}`

const placeholderEl = ref<HTMLElement | null>(null)
const shellEl = ref<HTMLElement | null>(null)
const mapHostEl = ref<HTMLElement | null>(null)
const fresnelSvgEl = ref<SVGSVGElement | null>(null)
const fresnelOuterEl = ref<SVGCircleElement | null>(null)
const fresnelInnerEl = ref<SVGCircleElement | null>(null)
const fresnelStrokeEl = ref<SVGCircleElement | null>(null)
const spiderfyHostEl = ref<HTMLElement | null>(null)
const pulseHostEl = ref<HTMLElement | null>(null)
const fullTriggerEl = ref<HTMLElement | null>(null)
const legendEl = ref<HTMLElement | null>(null)
const panelEl = ref<HTMLElement | null>(null)

const mapRef = shallowRef<MapLibreMap | null>(null)
const spiderfyMarkerRef = shallowRef<Marker | null>(null)
const pulseMarkerRef = shallowRef<Marker | null>(null)
const loadedGazetteer = shallowRef<GazetteerV1 | null>(null)
const styleReady = ref(false)

const currentZoom = ref(1.5)
const currentZi = ref(1)
const viewportWidth = ref(typeof window !== 'undefined' ? window.innerWidth : 1280)
const isMobile = computed(() => viewportWidth.value < 600)
const isTablet = computed(() => viewportWidth.value >= 600 && viewportWidth.value < 960)
const isCoarsePointer = computed(
  () =>
    isMobile.value ||
    (typeof window !== 'undefined' && Boolean(window.matchMedia?.('(pointer: coarse)').matches)),
)
const prefersReducedMotion = computed(
  () =>
    typeof window !== 'undefined' &&
    Boolean(window.matchMedia?.('(prefers-reduced-motion: reduce)').matches),
)

const tokens = computed(() => getGlobeTokens(props.themeMode))
const attributionText = computed(() => BOUNDARY_ATTRIBUTION[props.lang])
const resolvedPmtilesUrl = computed(() => props.pmtilesPath || appPath('/geo/mh-boundaries-v1.pmtiles'))

// Fix #5: Symmetrical 360° Fresnel rim glow colors per theme
const fresnelColors = computed(() =>
  props.themeMode === 'dark'
    ? {
        outerPeak: '#3EB8EC',
        outerMid: '#1C6DA8',
        outerPeakOp: 0.28,
        outerMidOp: 0.11,
        inner: '#4BC0F0',
        innerPeak: '#8EE0FF',
        innerMidOp: 0.1,
        innerPeakOp: 0.28,
        rimEdgeOp: 0.44,
        stroke: 'rgba(130, 216, 252, 0.50)',
      }
    : {
        outerPeak: '#7EB2E0',
        outerMid: '#A9CBE8',
        outerPeakOp: 0.22,
        outerMidOp: 0.08,
        inner: '#7BB0DF',
        innerPeak: '#5B98CF',
        innerMidOp: 0.06,
        innerPeakOp: 0.14,
        rimEdgeOp: 0.24,
        stroke: 'rgba(116, 156, 194, 0.44)',
      },
)

// Telemetry counters
const mountTime = typeof performance !== 'undefined' ? performance.now() : 0
const firstFrameMs = ref<number | null>(null)
const webglContextLostCount = ref(0)
const contextLostActive = ref(false)
const styleReloadCount = ref(0)
const cooperativeGesturesActive = ref(props.cooperativeGestures)
let renderEventCounter = 0
let userManuallyZoomed = false
let lastMarkerLayoutSig = ''
let lastGlobeRadiusPx = 0

// Interactive state — start legend collapsed on card (both desktop & mobile) so it never covers the globe;
// desktop full-page (and standaloneFullPage on desktop) opens it automatically.
const legendCollapsed = ref(isMobile.value || !props.standaloneFullPage)
const settingsOpen = ref(false)
const maxZoomSetting = ref<number>(readStoredMaxZoom())
const currentCenterLat = ref<number>(DEFAULT_GLOBE_CENTER[1])
const stageWidthPx = ref<number>(typeof window !== 'undefined' ? Math.min(window.innerWidth, 1200) : 960)
const maxZoomSpanHint = computed(() =>
  formatMaxZoomSpanHint(maxZoomSetting.value, currentCenterLat.value, stageWidthPx.value, props.lang),
)
const selectedNode = ref<GlobeNode | null>(null)
const selectedCluster = ref<DisplayCluster | null>(null)
const selectedLink = ref<AggregatedLink | null>(null)
const selectedBackboneArc = ref<GlobeArc | null>(null)
const showingUnknownList = ref(false)
const showingAllDevicesList = ref(false)
const hoveredDisplayId = ref<string | null>(null)
const hoveredNode = ref<GlobeNode | null>(null)
const hoveredBackboneNodeId = ref<string | null>(null)
const hoveredLinkKey = ref<string | null>(null)
const listPage = ref(1)
const sameCityPage = ref(1)
const allListPage = ref(1)
const pulseKey = ref(0)

// S12 Shared MapLibre view mode (`devices` | `backbone`) + optional Devices overlay toggle
const activeViewMode = ref<'devices' | 'backbone'>(props.viewMode)
const isBackboneView = computed(() => activeViewMode.value === 'backbone')
const showDevices = ref<boolean>(props.showDevicesOverlay)

// Full-page / mobile local filter overrides
const localOnlyProblems = ref<boolean | null>(null)
const localMinRttMs = ref<number | null>(null)
const localCarriers = ref<string[] | null>(null)

const effectiveOnlyProblems = computed(() => localOnlyProblems.value ?? props.onlyProblems)
const effectiveMinRttMs = computed(() => localMinRttMs.value ?? props.minRttMs)
const activeCarrierSet = computed(() => new Set(localCarriers.value ?? props.enabledCarriers))

// Mobile 3-snap draggable bottom sheet state (S10 / AC12)
type MobileSnap = 'peek' | 'mid' | 'full'
const mobileSnap = ref<MobileSnap>('peek')
const mobileSheetOpen = ref(false)
const mobileTab = ref<'details' | 'filters' | 'list'>('details')
const dragHeightPx = ref<number | null>(null)
let dragStartY = 0
let dragStartH = 0
let dragMoved = false

interface HoverCardState {
  x: number
  y: number
  title: string
  subtitle: string
  badge?: string
  breakdown?: string
  mixed?: boolean
  extra?: string
}
const hoverCard = ref<HoverCardState | null>(null)
let hoverShowTimer: ReturnType<typeof setTimeout> | null = null
let hoverCloseTimer: ReturnType<typeof setTimeout> | null = null

// S5 R10 optional <=10s flowing dash animation timer on selection
let flowInterval: ReturnType<typeof setInterval> | null = null
let flowStopTimer: ReturnType<typeof setTimeout> | null = null
let flowStep = 0

interface ActiveSpiderfy {
  cluster: DisplayCluster
  layout: SpiderfyLayout
  startZoom: number
}
const activeSpiderfy = ref<ActiveSpiderfy | null>(null)

const fullPage = useFullPage({
  containerRef: shellEl,
  triggerRef: fullTriggerEl,
  router: injectedRouter,
  route: injectedRoute,
  syncQuery: props.syncUrl && !props.standaloneFullPage,
  standalone: props.standaloneFullPage,
  onToggle(full) {
    settingsOpen.value = false
    emit('full-page-change', full)
    if (!full) {
      mobileSheetOpen.value = false
      showingAllDevicesList.value = false
    } else if (isMobile.value && panelOpen.value) {
      mobileSheetOpen.value = true
      mobileTab.value = 'details'
    }
    syncCooperativeGestures()
    void nextTick(() => {
      const map = mapRef.value
      if (!map) return
      map.resize()
      // Fix #1: Re-fit globe cleanly to 85–90% diameter on entering/exiting full-page!
      userManuallyZoomed = false
      fitCameraToActiveNodes(false)
      applyCameraPadding(false)
      syncFresnelRim()
      refreshMarkerEdgePlacements()
    })
  },
})

const isFullLayout = computed(() => props.standaloneFullPage || fullPage.isFull.value)

const effectiveCooperativeGestures = computed(
  () => !isFullLayout.value && props.cooperativeGestures,
)

const placeholderStyle = computed(() =>
  props.standaloneFullPage
    ? {}
    : {
        minHeight: isMobile.value ? 'min(56vh, 420px)' : `${props.height}px`,
      },
)

const shellStyle = computed(() =>
  isFullLayout.value
    ? {}
    : {
        height: isMobile.value ? 'min(56vh, 420px)' : `${props.height}px`,
      },
)

const mobileSheetDynamicStyle = computed(() => {
  if (!isMobile.value || dragHeightPx.value == null) return {}
  return {
    height: `${dragHeightPx.value}px`,
    maxHeight: `${dragHeightPx.value}px`,
    transition: 'none',
  }
})

// Separate view datasets so switching `devices` <-> `backbone` never recreates the MapLibre Map
const deviceDatasetNodes = computed<readonly GlobeNode[]>(() =>
  props.viewMode === 'devices' ? props.nodes : props.overlayDevices,
)
const deviceDatasetArcs = computed<readonly GlobeArc[]>(() =>
  props.viewMode === 'devices' ? props.arcs : props.overlayDeviceArcs,
)
const activeBackboneNodes = computed<readonly GlobeNode[]>(() =>
  props.viewMode === 'backbone' ? props.nodes : props.backboneNodes,
)
const activeBackboneArcs = computed<readonly GlobeArc[]>(() =>
  props.viewMode === 'backbone' ? props.arcs : props.backboneArcs,
)
const canSwitchView = computed(
  () => deviceDatasetNodes.value.length > 0 && activeBackboneNodes.value.length > 0,
)

// All device-view nodes including optional centre node (when located and control plane shown)
const allGlobeNodes = computed<GlobeNode[]>(() => {
  const list = [...deviceDatasetNodes.value]
  if (props.showControlPlane && props.center) {
    const hasCoords =
      typeof props.center.lat === 'number' && typeof props.center.lon === 'number'
    if (hasCoords || props.center.countryCode) {
      list.push({
        id: props.center.id,
        name: props.center.name,
        online: true,
        presence: 'online',
        role: 'centre',
        isCentre: true,
        lat: props.center.lat ?? null,
        lon: props.center.lon ?? null,
        countryCode: props.center.countryCode ?? null,
        country: props.center.locationLabel ?? null,
      })
    }
  }
  return list
})

const grouped = computed(() => groupNodesByLocation(allGlobeNodes.value, loadedGazetteer.value))
const merged = computed(() => clusterGroupsForZoom(grouped.value.groups, currentZi.value, 40))
const clusterById = computed(() => new Map(merged.value.clusters.map((c) => [c.id, c])))

// S12 Backbone resolved nodes, zones, and unlocated chips
const backboneResolved = computed(() =>
  resolveBackboneNodes(activeBackboneNodes.value, props.zones, props.themeMode, loadedGazetteer.value),
)
const backboneNodeById = computed(() => new Map(activeBackboneNodes.value.map((n) => [n.id, n])))
const activeListNodes = computed<readonly GlobeNode[]>(() =>
  isBackboneView.value ? activeBackboneNodes.value : allGlobeNodes.value,
)
const unknownNodesForView = computed<readonly GlobeNode[]>(() =>
  isBackboneView.value ? backboneResolved.value.unlocatedOthers : grouped.value.unlocated,
)
const unlocatedCentres = computed<readonly GlobeNode[]>(() =>
  isBackboneView.value ? backboneResolved.value.unlocatedCentres : [],
)

const linkAgg = computed(() =>
  aggregateLinks(
    deviceDatasetArcs.value,
    merged.value.displayIdByNodeId,
    grouped.value.groupKeyByNodeId,
    clusterById.value,
    {
      enabledCarriers: activeCarrierSet.value,
      showBlocked: activeCarrierSet.value.has('blocked'),
      onlyProblems: effectiveOnlyProblems.value,
      minRttMs: effectiveMinRttMs.value,
      maxOverviewLinks: 60,
    },
  ),
)

const activeFocus = computed<{ nodeId?: string | null; displayId?: string | null } | null>(() => {
  if (hoveredNode.value) return { nodeId: hoveredNode.value.id }
  if (hoveredDisplayId.value) return { displayId: hoveredDisplayId.value }
  if (selectedNode.value) return { nodeId: selectedNode.value.id }
  if (selectedCluster.value) return { displayId: selectedCluster.value.id }
  if (activeSpiderfy.value) return { displayId: activeSpiderfy.value.cluster.id }
  return null
})

const egoLinks = computed<AggregatedLink[]>(() => {
  if (!activeFocus.value || isBackboneView.value) return []
  return buildEgoNetwork(
    deviceDatasetArcs.value,
    activeFocus.value,
    merged.value.displayIdByNodeId,
    grouped.value.groupKeyByNodeId,
    clusterById.value,
    {
      enabledCarriers: activeCarrierSet.value,
      showBlocked: activeCarrierSet.value.has('blocked'),
      onlyProblems: effectiveOnlyProblems.value,
      minRttMs: effectiveMinRttMs.value,
    },
  )
})

const selectedNodeDisplayId = computed(() =>
  selectedNode.value ? merged.value.displayIdByNodeId.get(selectedNode.value.id) ?? null : null,
)

const selectedNodeGroup = computed(() => {
  if (!selectedNode.value || isBackboneView.value) return null
  const key = grouped.value.groupKeyByNodeId.get(selectedNode.value.id)
  return key ? grouped.value.groupByKey.get(key) ?? null : null
})

const sameCityDevices = computed(() => selectedNodeGroup.value?.nodes ?? [])
const sameCityTotalPages = computed(() =>
  Math.max(1, Math.ceil(sameCityDevices.value.length / LIST_PAGE_SIZE)),
)
const pagedSameCityDevices = computed(() => {
  const start = (sameCityPage.value - 1) * LIST_PAGE_SIZE
  return sameCityDevices.value.slice(start, start + LIST_PAGE_SIZE)
})

const selectedNodeIntraCityCount = computed(() => {
  const key = selectedNodeGroup.value?.key
  return key ? linkAgg.value.intraCityCountByGroup.get(key) ?? 0 : 0
})

const listPanelNodes = computed<readonly GlobeNode[]>(() => {
  if (showingUnknownList.value) return unknownNodesForView.value
  if (showingAllDevicesList.value) return activeListNodes.value
  if (selectedCluster.value) return selectedCluster.value.nodes
  return []
})

const listTotalPages = computed(() =>
  Math.max(1, Math.ceil(listPanelNodes.value.length / LIST_PAGE_SIZE)),
)
const pagedListNodes = computed(() => {
  const start = (listPage.value - 1) * LIST_PAGE_SIZE
  return listPanelNodes.value.slice(start, start + LIST_PAGE_SIZE)
})

const allListTotalPages = computed(() =>
  Math.max(1, Math.ceil(activeListNodes.value.length / LIST_PAGE_SIZE)),
)
const pagedAllNodes = computed(() => {
  const start = (allListPage.value - 1) * LIST_PAGE_SIZE
  return activeListNodes.value.slice(start, start + LIST_PAGE_SIZE)
})

const selectedClusterIntraCity = computed(() => {
  if (!selectedCluster.value) return 0
  let sum = 0
  for (const g of selectedCluster.value.groups) {
    sum += linkAgg.value.intraCityCountByGroup.get(g.key) ?? 0
  }
  return sum
})

const listPanelPrecisionNote = computed(() => {
  if (showingUnknownList.value) return t('mh.globeV2.unknownExplain')
  if (showingAllDevicesList.value || !selectedCluster.value) return ''
  return precisionText(selectedCluster.value.precision, selectedCluster.value.accuracyRadiusKm)
})

const panelOpen = computed(() =>
  Boolean(
    selectedNode.value ||
      selectedLink.value ||
      selectedBackboneArc.value ||
      showingUnknownList.value ||
      showingAllDevicesList.value ||
      selectedCluster.value,
  ),
)

const panelTitle = computed(() => {
  if (selectedNode.value) return selectedNode.value.name
  if (selectedBackboneArc.value) {
    const arrow = isUnidirectionalBackboneArc(selectedBackboneArc.value) ? '→' : '↔'
    return `${backboneNodeName(selectedBackboneArc.value.from)} ${arrow} ${backboneNodeName(selectedBackboneArc.value.to)}`
  }
  if (selectedLink.value) {
    return `${clusterLabelById(selectedLink.value.fromDisplayId)} ↔ ${clusterLabelById(selectedLink.value.toDisplayId)}`
  }
  if (showingUnknownList.value) {
    return t('mh.globeV2.unknownLocation', { n: unknownNodesForView.value.length })
  }
  if (showingAllDevicesList.value) {
    const heading = isBackboneView.value ? t('mh.backbone.gatewayList') : t('mh.globeV2.deviceList')
    return `${heading} (${activeListNodes.value.length})`
  }
  if (selectedCluster.value) {
    return formatClusterLabel(selectedCluster.value, props.lang)
  }
  return ''
})

const selectedNodeZoneChips = computed(() => {
  const n = selectedNode.value
  if (!n) return [] as Array<{ key: string; name: string; color?: string }>
  if (n.zoneIds?.length) {
    const zoneById = new Map(props.zones.map((z) => [z.id, z]))
    return n.zoneIds.map((zid, idx) => ({
      key: zid,
      name: zoneById.get(zid)?.name ?? n.zoneNames?.[idx] ?? zid,
      color: backboneResolved.value.zoneColors.get(zid) ?? n.color,
    }))
  }
  if (n.zoneNames?.length) {
    return n.zoneNames.map((name, idx) => ({
      key: `${name}-${idx}`,
      name,
      color: n.color,
    }))
  }
  if (n.zoneName) return [{ key: n.zoneId ?? n.zoneName, name: n.zoneName, color: n.color }]
  if (n.zoneId) return [{ key: n.zoneId, name: n.zoneId, color: n.color }]
  if (n.zoneKind === 'mainland') return [{ key: 'mainland', name: t('mh.topo.mainland') }]
  if (n.zoneKind === 'non_mainland') return [{ key: 'non_mainland', name: t('mh.topo.nonMainland') }]
  return []
})

const selectedNodeBackboneLinks = computed(() => {
  const n = selectedNode.value
  if (!n || !isBackboneView.value) return [] as Array<{ arc: GlobeArc; peerName: string }>
  return activeBackboneArcs.value
    .filter((a) => a.kind !== 'control' && a.kind !== 'mgmt_path' && (a.from === n.id || a.to === n.id))
    .map((arc) => {
      const peerId = arc.from === n.id ? arc.to : arc.from
      return { arc, peerName: backboneNodeName(peerId) }
    })
})

const selectedBackboneLinkDirections = computed(() => {
  const a = selectedBackboneArc.value
  if (!a?.ends?.length) return [] as Array<{ label: string; carrier: string; rttMs: number | null; stalled: boolean }>
  const sides = edgeSides(a.ends, a.from, a.to)
  const out: Array<{ label: string; carrier: string; rttMs: number | null; stalled: boolean }> = []
  if (sides.from) {
    out.push({
      label: `${backboneNodeName(a.from)} → ${backboneNodeName(a.to)}`,
      carrier: qualifiedCarrier(sides.from.carrier, sides.from.relay),
      rttMs: sides.from.rtt_ms ?? null,
      stalled: Boolean(sides.from.stalled),
    })
  }
  if (sides.to) {
    out.push({
      label: `${backboneNodeName(a.to)} → ${backboneNodeName(a.from)}`,
      carrier: qualifiedCarrier(sides.to.carrier, sides.to.relay),
      rttMs: sides.to.rtt_ms ?? null,
      stalled: Boolean(sides.to.stalled),
    })
  }
  return out
})

const selectedNodeOsVersion = computed(() => {
  const n = selectedNode.value
  if (!n) return ''
  const parts: string[] = []
  if (n.os) parts.push(n.os)
  if (n.version) parts.push(n.version.startsWith('v') ? n.version : `v${n.version}`)
  return parts.join(' · ')
})

const selectedNodeLastSeen = computed(() => {
  const raw = selectedNode.value?.lastSeenAt
  if (!raw) return ''
  const d = new Date(raw)
  if (Number.isNaN(d.getTime())) return raw
  try {
    return new Intl.DateTimeFormat(String(locale.value), {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }).format(d)
  } catch {
    return d.toISOString().slice(0, 16).replace('T', ' ')
  }
})

const selectedNodeRegionText = computed(() => {
  const n = selectedNode.value
  if (!n) return '—'
  const res = isBackboneView.value
    ? resolveV2Location(n, loadedGazetteer.value)
    : grouped.value.resolvedByNodeId.get(n.id) ?? resolveV2Location(n, loadedGazetteer.value)
  if (!res || res.precision === 'unknown') return t('mh.mesh.panel.locationUnknown')
  return (
    formatNeutralRegionName(res.countryCode, res.locationLabel || res.placeEn, props.lang) ||
    t('mh.mesh.panel.locationUnknown')
  )
})

const selectedNodePrecisionText = computed(() => {
  const n = selectedNode.value
  if (!n) return ''
  const res = isBackboneView.value
    ? resolveV2Location(n, loadedGazetteer.value)
    : grouped.value.resolvedByNodeId.get(n.id) ?? resolveV2Location(n, loadedGazetteer.value)
  return precisionText(res?.precision ?? 'unknown', res?.accuracyRadiusKm ?? null)
})

const selectedNodeMgmtPathText = computed(() => {
  const mp = selectedNode.value?.managementPath
  if (!mp) return ''
  if (mp.mode === 'centre_host') return t('mh.backbone.mgmtPathCentre')
  if (mp.mode === 'gateway_entry_ready') {
    const port = selectedNode.value?.managementEntry?.port
    return port
      ? t('mh.backbone.mgmtPathReadyPort', { port })
      : t('mh.backbone.mgmtPathReady')
  }
  if (mp.mode === 'gateway_relay_only') return t('mh.backbone.mgmtPathRelayOnly')
  if (mp.mode === 'gateway') {
    return mp.gatewayName
      ? t('mh.mesh.panel.viaGateway', { name: mp.gatewayName })
      : t('mh.mesh.panel.viaGatewayGeneric')
  }
  if (mp.mode === 'last_resort_direct') return t('mh.mesh.panel.lastResortDirect')
  if (mp.mode === 'direct') {
    return isBackboneView.value ? t('mh.backbone.mgmtPathDirectCentre') : t('mh.mesh.panel.directToCentre')
  }
  return mp.mode
})

function backboneNodeName(id: string): string {
  return backboneNodeById.value.get(id)?.name ?? id.slice(-6)
}

function backboneNodeZonesText(id: string): string {
  const n = backboneNodeById.value.get(id)
  if (!n) return ''
  if (n.zoneNames?.length) return n.zoneNames.join(', ')
  return n.zoneName ?? ''
}

function precisionText(precision: string, accuracyRadiusKm: number | null = null): string {
  if (precision === 'coords') {
    return accuracyRadiusKm != null && accuracyRadiusKm > 0
      ? t('mh.globeV2.precisionCoordsRadius', { km: accuracyRadiusKm })
      : t('mh.globeV2.precisionCoords')
  }
  if (precision === 'city') return t('mh.globeV2.precisionCity')
  if (precision === 'region') return t('mh.globeV2.precisionRegion')
  if (precision === 'country') return t('mh.globeV2.precisionCountry')
  return t('mh.globeV2.precisionUnknown')
}

function presenceLabel(node: GlobeNode): string {
  return t(`mh.mesh.status.${effectivePresence(node)}`)
}

function presenceTokenColor(node: GlobeNode): string {
  const p = effectivePresence(node)
  return p === 'online' ? tokens.value.online : p === 'stale' ? tokens.value.stale : tokens.value.offline
}

function carrierTokenColor(cls: string): string {
  switch (cls) {
    case 'direct':
      return tokens.value.direct
    case 'tunnel':
      return tokens.value.tunnel
    case 'relay':
    case 'org_relay':
      return tokens.value.relay
    case 'derp':
      return tokens.value.derp
    case 'blocked':
      return tokens.value.blocked
    case 'stalled':
      return tokens.value.stalled
    default:
      return tokens.value.direct
  }
}

function carrierLabel(cls: string): string {
  if (cls === 'stalled') return t('mh.mesh.stalled')
  const key = `mh.mesh.carriers.${cls}`
  const tr = t(key)
  return tr === key ? cls : tr
}

function formatBreakdownText(link: AggregatedLink): string {
  return linkCarrierBreakdown(link)
    .map((item) => `${carrierLabel(item.key)}: ${item.count}`)
    .join(' · ')
}

function nodeCityShort(node: GlobeNode): string {
  const res = isBackboneView.value
    ? resolveV2Location(node, loadedGazetteer.value)
    : grouped.value.resolvedByNodeId.get(node.id)
  if (!res || res.precision === 'unknown') return t('mh.mesh.panel.locationUnknown')
  return props.lang === 'zh-CN' ? res.placeZh || res.placeEn : res.placeEn || res.placeZh
}

function clusterLabelById(id: string): string {
  const c = clusterById.value.get(id)
  return c ? formatClusterLabel(c, props.lang) : id
}

function remoteClusterLabel(link: AggregatedLink, selfDisplayId: string | null): string {
  const remoteId = link.fromDisplayId === selfDisplayId ? link.toDisplayId : link.fromDisplayId
  return clusterLabelById(remoteId)
}

function applyMaxZoom(nextVal: number): number {
  const clamped = writeStoredMaxZoom(nextVal)
  maxZoomSetting.value = clamped
  const map = mapRef.value
  if (map) {
    map.setMaxZoom(clamped)
    if (map.getZoom() > clamped) {
      map.easeTo({ zoom: clamped, duration: prefersReducedMotion.value ? 0 : 250 })
    }
  }
  return clamped
}

function onMaxZoomInput(e: Event): void {
  const target = e.target as HTMLInputElement | null
  if (!target) return
  applyMaxZoom(Number(target.value))
}

function toggleLocalCarrier(cls: LinkCarrierClass): void {
  const cur = new Set(activeCarrierSet.value)
  if (cur.has(cls)) cur.delete(cls)
  else cur.add(cls)
  localCarriers.value = [...cur]
}

function resetLocalFilters(): void {
  localOnlyProblems.value = null
  localMinRttMs.value = null
  localCarriers.value = null
}

function toggleAllDevicesList(): void {
  if (showingAllDevicesList.value) {
    showingAllDevicesList.value = false
  } else {
    collapseSpiderfy()
    selectedNode.value = null
    selectedLink.value = null
    selectedCluster.value = null
    showingUnknownList.value = false
    showingAllDevicesList.value = true
    listPage.value = 1
  }
  syncSelectionUrl()
  applyCameraPadding(true)
  syncMapSources()
}

function openMobileSheetTab(tab: 'details' | 'filters' | 'list'): void {
  mobileTab.value = tab
  mobileSheetOpen.value = true
  if (mobileSnap.value === 'peek' && tab !== 'details') {
    mobileSnap.value = 'mid'
  }
  applyCameraPadding(true)
}

// ── Fit Globe (Fix #1) & 360° Fresnel Rim Sync (Fix #5) ───────────────────────

function getStageDimensions(): { width: number; height: number } {
  const rect = mapHostEl.value?.getBoundingClientRect()
  if (rect && rect.width > 40 && rect.height > 40) {
    return { width: rect.width, height: rect.height }
  }
  const fallbackW = isMobile.value ? Math.max(300, viewportWidth.value - 24) : 1080
  const fallbackH = isFullLayout.value
    ? typeof window !== 'undefined'
      ? window.innerHeight
      : 800
    : isMobile.value
      ? 380
      : props.height
  return { width: fallbackW, height: fallbackH }
}

function fitGlobeToContainer(animate = false, center?: [number, number]): void {
  const map = mapRef.value
  if (!map) return
  const { width, height } = getStageDimensions()
  const lat = center ? center[1] : map.getCenter().lat
  const zoom = computeFitGlobeZoom(width, height, lat, DEFAULT_TARGET_DIAMETER_RATIO)
  const opts = {
    ...(center ? { center } : {}),
    zoom,
    bearing: 0,
    pitch: 0,
  }
  if (animate && !prefersReducedMotion.value) {
    map.easeTo({ ...opts, duration: 500 })
  } else {
    map.jumpTo(opts)
  }
  currentZoom.value = zoom
  currentZi.value = Math.floor(zoom)
}

function computeBackboneCenter(): [number, number] {
  const pts = backboneResolved.value.placed
  if (!pts.length) return [DEFAULT_GLOBE_CENTER[0], DEFAULT_GLOBE_CENTER[1]]
  let sx = 0
  let sy = 0
  let sz = 0
  const deg = Math.PI / 180
  for (const p of pts) {
    const phi = p.lat * deg
    const lam = p.lon * deg
    sx += Math.cos(phi) * Math.cos(lam)
    sy += Math.cos(phi) * Math.sin(lam)
    sz += Math.sin(phi)
  }
  const len = Math.hypot(sx, sy, sz)
  if (len < 1e-5) return [DEFAULT_GLOBE_CENTER[0], DEFAULT_GLOBE_CENTER[1]]
  const lat = Math.max(-55, Math.min(55, (Math.asin(sz / len) * 180) / Math.PI))
  const lon = (Math.atan2(sy, sx) * 180) / Math.PI
  return [lon, lat]
}

function fitCameraToActiveNodes(animate = false): void {
  if (isBackboneView.value) {
    fitGlobeToContainer(animate, computeBackboneCenter())
  } else {
    fitGlobeToContainer(animate)
  }
}

function syncViewUrl(mode: 'devices' | 'backbone'): void {
  if (!props.syncUrl) return
  if (injectedRouter && injectedRoute) {
    if (injectedRoute.query.g_view === mode) return
    const nextQuery = { ...injectedRoute.query, g_view: mode }
    void injectedRouter.replace({ query: nextQuery }).catch(() => {})
  } else if (typeof window !== 'undefined' && window.history?.replaceState) {
    const url = new URL(window.location.href)
    url.searchParams.set('g_view', mode)
    window.history.replaceState(window.history.state, '', url.toString())
  }
}

function switchViewMode(nextMode: 'devices' | 'backbone'): void {
  if (activeViewMode.value === nextMode) return
  collapseSpiderfy()
  selectedNode.value = null
  selectedCluster.value = null
  selectedLink.value = null
  selectedBackboneArc.value = null
  showingUnknownList.value = false
  showingAllDevicesList.value = false
  hoverCard.value = null
  hoveredDisplayId.value = null
  hoveredNode.value = null
  hoveredBackboneNodeId.value = null
  hoveredLinkKey.value = null
  stopFlowingDash()
  detachPulseMarker()

  activeViewMode.value = nextMode
  emit('update:view-mode', nextMode)
  syncViewUrl(nextMode)
  syncSelectionUrl()

  const map = mapRef.value
  if (map && styleReady.value) {
    applyViewModeLayerVisibility(map, nextMode, showDevices.value)
    lastMarkerLayoutSig = ''
    userManuallyZoomed = false
    fitCameraToActiveNodes(true)
    applyCameraPadding(true)
    syncMapSources()
  }
}

function setShowDevicesOverlay(next: boolean): void {
  if (showDevices.value === next) return
  showDevices.value = next
  emit('update:show-devices-overlay', next)
  const map = mapRef.value
  if (map && styleReady.value) {
    applyViewModeLayerVisibility(map, activeViewMode.value, next)
    syncMapSources()
  }
}

function computeDesiredPadding(): { top: number; right: number; bottom: number; left: number } {
  if (!props.showDetailPanel) return { top: 0, right: 0, bottom: 0, left: 0 }
  if (isMobile.value) {
    if (isFullLayout.value) {
      const sheetH = mobileSheetOpen.value ? currentMobileSheetHeightPx() : 0
      return { top: 48, right: 0, bottom: sheetH, left: 0 }
    }
    if (panelOpen.value) {
      return { top: 0, right: 0, bottom: 160, left: 0 }
    }
    return { top: 0, right: 0, bottom: 0, left: 0 }
  }
  if (panelOpen.value) {
    return { top: 0, right: isTablet.value ? 332 : 372, bottom: 0, left: 0 }
  }
  return { top: 0, right: 0, bottom: 0, left: 0 }
}

function currentMobileSheetHeightPx(): number {
  if (dragHeightPx.value != null) return dragHeightPx.value
  const h = typeof window !== 'undefined' ? window.innerHeight : 844
  const pct = mobileSnap.value === 'full' ? 0.92 : mobileSnap.value === 'mid' ? 0.6 : 0.3
  return Math.max(160, Math.round(h * pct))
}

function applyCameraPadding(animate = true): void {
  const map = mapRef.value
  if (!map || !styleReady.value) return
  const padding = computeDesiredPadding()
  if (animate && !prefersReducedMotion.value) {
    map.easeTo({ padding, duration: 250 })
  } else {
    map.setPadding(padding)
  }
  syncFresnelRim()
}

function syncFresnelRim(): void {
  const map = mapRef.value
  const svg = fresnelSvgEl.value
  const outer = fresnelOuterEl.value
  const inner = fresnelInnerEl.value
  const stroke = fresnelStrokeEl.value
  if (!map || !svg || !outer || !inner || !stroke) return

  const rect = mapHostEl.value?.getBoundingClientRect()
  if (!rect || rect.width < 10 || rect.height < 10) return

  const pad = map.getPadding()
  const circle = computeGlobeScreenCircle(
    rect.width,
    rect.height,
    map.getZoom(),
    map.getCenter().lat,
    pad,
  )
  lastGlobeRadiusPx = circle.radius

  svg.style.opacity = String(circle.rimOpacity)
  if (circle.rimOpacity <= 0.001) return

  const cx = circle.cx.toFixed(1)
  const cy = circle.cy.toFixed(1)
  const r = circle.radius
  outer.setAttribute('cx', cx)
  outer.setAttribute('cy', cy)
  outer.setAttribute('r', (r * 1.15).toFixed(1))

  inner.setAttribute('cx', cx)
  inner.setAttribute('cy', cy)
  inner.setAttribute('r', r.toFixed(1))

  stroke.setAttribute('cx', cx)
  stroke.setAttribute('cy', cy)
  stroke.setAttribute('r', r.toFixed(1))
}

// ── Mobile 3-Snap Sheet Pointer Drag (S10) ────────────────────────────────────

function onSheetDragStart(e: PointerEvent): void {
  if (!isMobile.value) return
  dragStartY = e.clientY
  dragStartH = panelEl.value?.getBoundingClientRect().height ?? currentMobileSheetHeightPx()
  dragMoved = false

  const onMove = (ev: PointerEvent) => {
    const dy = dragStartY - ev.clientY
    if (Math.abs(dy) > 6) dragMoved = true
    const maxH = Math.round((window.innerHeight || 844) * 0.94)
    dragHeightPx.value = Math.max(160, Math.min(maxH, Math.round(dragStartH + dy)))
  }

  const onUp = () => {
    window.removeEventListener('pointermove', onMove)
    window.removeEventListener('pointerup', onUp)
    window.removeEventListener('pointercancel', onUp)
    if (dragHeightPx.value != null) {
      const vh = window.innerHeight || 844
      const ratio = dragHeightPx.value / vh
      if (ratio < 0.45) mobileSnap.value = 'peek'
      else if (ratio < 0.76) mobileSnap.value = 'mid'
      else mobileSnap.value = 'full'
      dragHeightPx.value = null
      applyCameraPadding(true)
    }
  }

  window.addEventListener('pointermove', onMove)
  window.addEventListener('pointerup', onUp)
  window.addEventListener('pointercancel', onUp)
}

function onSheetHandleClick(): void {
  if (dragMoved) {
    dragMoved = false
    return
  }
  cycleMobileSnap()
}

function cycleMobileSnap(): void {
  mobileSnap.value = mobileSnap.value === 'peek' ? 'mid' : mobileSnap.value === 'mid' ? 'full' : 'peek'
  applyCameraPadding(true)
}

// ── URL Query Sync (`g_sel`, `g_view`) (S8 / S12) ─────────────────────────────

function currentSelectionQueryValue(): string | null {
  if (selectedNode.value) return `dev:${selectedNode.value.id}`
  if (selectedCluster.value) return `grp:${selectedCluster.value.id}`
  if (selectedBackboneArc.value) return `lnk:${selectedBackboneArc.value.key}`
  if (selectedLink.value) return `lnk:${selectedLink.value.key}`
  return null
}

function syncSelectionUrl(): void {
  if (!props.syncUrl) return
  const val = currentSelectionQueryValue()
  if (injectedRouter && injectedRoute) {
    const cur = injectedRoute.query.g_sel
    if ((val ?? undefined) === cur) return
    const nextQuery = { ...injectedRoute.query }
    if (val) nextQuery.g_sel = val
    else delete nextQuery.g_sel
    void injectedRouter.replace({ query: nextQuery }).catch(() => {})
  } else if (typeof window !== 'undefined' && window.history?.replaceState) {
    const url = new URL(window.location.href)
    if (val) url.searchParams.set('g_sel', val)
    else url.searchParams.delete('g_sel')
    window.history.replaceState(window.history.state, '', url.toString())
  }
}

function hydrateSelectionFromUrl(): void {
  if (!props.syncUrl || typeof window === 'undefined') return
  const rawView = injectedRoute
    ? typeof injectedRoute.query.g_view === 'string'
      ? injectedRoute.query.g_view
      : null
    : new URLSearchParams(window.location.search).get('g_view')
  if ((rawView === 'devices' || rawView === 'backbone') && rawView !== activeViewMode.value) {
    if (
      (rawView === 'devices' && deviceDatasetNodes.value.length > 0) ||
      (rawView === 'backbone' && activeBackboneNodes.value.length > 0)
    ) {
      activeViewMode.value = rawView
      const map = mapRef.value
      if (map && styleReady.value) {
        applyViewModeLayerVisibility(map, rawView, showDevices.value)
        syncMapSources()
      }
    }
  }

  const raw = injectedRoute
    ? typeof injectedRoute.query.g_sel === 'string'
      ? injectedRoute.query.g_sel
      : null
    : new URLSearchParams(window.location.search).get('g_sel')
  if (!raw) return
  if (raw.startsWith('dev:')) {
    const id = raw.slice(4)
    focusNodeById(id)
  } else if (raw.startsWith('grp:') && !isBackboneView.value) {
    const key = raw.slice(4)
    const c = clusterById.value.get(key)
    if (c) {
      selectedCluster.value = c
      listPage.value = 1
      applyCameraPadding(false)
      syncMapSources()
    }
  } else if (raw.startsWith('lnk:')) {
    const key = raw.slice(4)
    focusArcByKey(key)
  }
}

// ── S3 CSS Selection Pulse Marker & S5 R10 <=10s Flowing Dash on Selection ────

function detachPulseMarker(): void {
  if (pulseMarkerRef.value) {
    pulseMarkerRef.value.remove()
    pulseMarkerRef.value = null
  }
}

function triggerSelectionPulse(lonLat: readonly [number, number] | null): void {
  detachPulseMarker()
  const map = mapRef.value
  if (!map || !pulseHostEl.value || !lonLat || prefersReducedMotion.value) return
  pulseKey.value++
  void nextTick(() => {
    if (!mapRef.value || !pulseHostEl.value) return
    pulseMarkerRef.value = new maplibregl.Marker({
      element: pulseHostEl.value,
      anchor: 'center',
      opacityWhenCovered: '0',
    })
      .setLngLat([lonLat[0], lonLat[1]])
      .addTo(mapRef.value)
  })
}

function stopFlowingDash(): void {
  if (flowInterval) {
    clearInterval(flowInterval)
    flowInterval = null
  }
  if (flowStopTimer) {
    clearTimeout(flowStopTimer)
    flowStopTimer = null
  }
  const map = mapRef.value
  if (map && styleReady.value) {
    if (map.getLayer('mh-links-active-relay')) {
      map.setPaintProperty('mh-links-active-relay', 'line-dasharray', [4, 3])
    }
    if (map.getLayer('mh-links-active-derp')) {
      map.setPaintProperty('mh-links-active-derp', 'line-dasharray', [2, 2])
    }
  }
}

function startFlowingDashOnSelection(): void {
  stopFlowingDash()
  if (prefersReducedMotion.value || !styleReady.value || !mapRef.value) return
  const hasPinnedSelection = Boolean(selectedLink.value || selectedNode.value || selectedCluster.value)
  if (!hasPinnedSelection) return

  const relayFrames: number[][] = [
    [4, 3],
    [0.5, 3, 3.5, 0],
    [1.5, 3, 2.5, 0],
    [2.5, 3, 1.5, 0],
    [3.5, 3, 0.5, 0],
  ]
  const derpFrames: number[][] = [
    [2, 2],
    [0.5, 2, 1.5, 0],
    [1, 2, 1, 0],
    [1.5, 2, 0.5, 0],
  ]
  flowStep = 0
  flowInterval = setInterval(() => {
    const map = mapRef.value
    if (!map || !styleReady.value) {
      stopFlowingDash()
      return
    }
    flowStep++
    if (map.getLayer('mh-links-active-relay')) {
      map.setPaintProperty(
        'mh-links-active-relay',
        'line-dasharray',
        relayFrames[flowStep % relayFrames.length]!,
      )
    }
    if (map.getLayer('mh-links-active-derp')) {
      map.setPaintProperty(
        'mh-links-active-derp',
        'line-dasharray',
        derpFrames[flowStep % derpFrames.length]!,
      )
    }
  }, 80)

  // S5 R10: stop automatically after <= 10 seconds -> 0 idle WebGL frames thereafter
  flowStopTimer = setTimeout(() => {
    stopFlowingDash()
  }, 10_000)
}

// ── Map Data Synchronization (Markers, Edge Placement, Accuracy Circles, Links) ─

function emitMetrics(): void {
  emit('metrics-change', {
    firstFrameMs: firstFrameMs.value,
    webglContextLost: webglContextLostCount.value,
    styleReloads: styleReloadCount.value,
    cooperativeGesturesActive: cooperativeGesturesActive.value,
    zoom: currentZoom.value,
    displayedLinks: linkAgg.value.displayed.length,
    overflowLinks: linkAgg.value.overflowCount,
    unlocatedCount: grouped.value.unlocated.length,
  })
}

function syncCooperativeGestures(): void {
  const map = mapRef.value
  if (!map || !map.cooperativeGestures) return
  if (effectiveCooperativeGestures.value) {
    map.cooperativeGestures.enable()
  } else {
    map.cooperativeGestures.disable()
  }
  cooperativeGesturesActive.value = map.cooperativeGestures.isEnabled()
  emitMetrics()
}

function buildBackboneMarkerFeatures(map: MapLibreMap): {
  features: Array<GeoJSON.Feature<GeoJSON.Point>>
  layoutSig: string
} {
  const dpr = Math.max(1, Math.min(2, props.pixelRatio))
  ensureStaticIcons(map, props.themeMode, dpr)
  ensureBackboneStaticIcons(map, props.themeMode, dpr)

  const z = map.getZoom()
  const center = map.getCenter()
  const rect = mapHostEl.value?.getBoundingClientRect()
  const stageW = rect?.width || 800
  const stageH = rect?.height || props.height

  const selNodeId = selectedNode.value?.id ?? null
  const selArc = selectedBackboneArc.value
  const hasFocus = Boolean(selNodeId || selArc)
  const sigParts: string[] = []

  const features: Array<GeoJSON.Feature<GeoJSON.Point>> = backboneResolved.value.placed.map((p, idx) => {
    const isSel = p.id === selNodeId
    const isArcEnd = Boolean(selArc && (selArc.from === p.id || selArc.to === p.id))
    const icon = resolveBackboneNodeIconId(map, p, props.themeMode, dpr, isSel)

    let sortKey = 60 + idx
    if (isSel) sortKey = 10
    else if (p.kind === 'centre') sortKey = 20
    else if (p.kind === 'gateway') sortKey = 30
    else if (p.kind === 'entry') sortKey = 40
    else sortKey = 50 + idx

    const pt = map.project([p.lon, p.lat])
    const rawLabel = formatBackboneNodeLabel(p, props.lang)
    let edgePlacement: 'extend-both' | 'extend-right' | 'extend-left' | 'hide' = 'hide'

    if (rawLabel) {
      const ang = centralAngleRad([p.lon, p.lat], [center.lng, center.lat])
      if (z >= 4 || ang < Math.PI * 0.48) {
        edgePlacement = assignMarkerEdgePlacement(pt.x, pt.y, stageW, stageH, rawLabel)
      }
    }

    const finalLabel = edgePlacement === 'hide' ? '' : rawLabel
    const opacity = hasFocus ? (isSel || isArcEnd ? 1 : 0.45) : 1
    sigParts.push(`bb:${p.id}:${icon}:${edgePlacement}:${finalLabel}:${opacity}`)

    return {
      type: 'Feature',
      geometry: { type: 'Point', coordinates: [p.lon, p.lat] },
      properties: {
        id: p.id,
        icon,
        label: finalLabel,
        edgePlacement,
        sortKey,
        opacity,
        count: p.zoneDeviceCount ?? 1,
      },
    }
  })

  return { features, layoutSig: sigParts.join('|') }
}

function buildMarkerFeatures(map: MapLibreMap): {
  features: Array<GeoJSON.Feature<GeoJSON.Point>>
  layoutSig: string
} {
  if (isBackboneView.value) {
    return buildBackboneMarkerFeatures(map)
  }

  const dpr = Math.max(1, Math.min(2, props.pixelRatio))
  ensureStaticIcons(map, props.themeMode, dpr)

  const hasSpiderfy = Boolean(activeSpiderfy.value)
  const spiderfyId = activeSpiderfy.value?.cluster.id ?? null
  const selClusterId = selectedCluster.value?.id ?? selectedNodeDisplayId.value ?? null
  const z = map.getZoom()
  const center = map.getCenter()
  const rect = mapHostEl.value?.getBoundingClientRect()
  const stageW = rect?.width || 800
  const stageH = rect?.height || props.height

  // Pre-project visible clusters so we can suppress duplicate co-located place labels
  // (e.g., control-centre country point overlapping a same-city Singapore cluster — Fix #2).
  const projected = merged.value.clusters.map((c) => ({
    cluster: c,
    pt: map.project([c.lon, c.lat]),
    placeNorm: (c.placeEn || c.placeZh || '').trim().toLowerCase(),
  }))

  // Sort markers for priority labeling (S5/S6): selected > centre > gateway > problem > top-6 city > rest
  const top6Ids = new Set(merged.value.clusters.slice(0, 6).map((c) => c.id))
  const sigParts: string[] = []

  const features: Array<GeoJSON.Feature<GeoJSON.Point>> = projected.map(({ cluster: c, pt, placeNorm }, idx) => {
    const isSel =
      c.id === selClusterId ||
      (selectedNode.value != null && c.nodes.some((n) => n.id === selectedNode.value?.id))
    const isSpid = c.id === spiderfyId
    const icon = resolveClusterIconId(map, c, props.themeMode, dpr, isSel, isSpid)

    let sortKey = 600 + idx
    if (isSel) sortKey = 10
    else if (c.hasCentre) sortKey = 20
    else if (c.hasGateway) sortKey = 30
    else if (c.hasProblem) sortKey = 40
    else if (c.count >= 2) sortKey = 100 + idx

    // LOD label gating (S6 / S10)
    let showLabel = true
    if (isSpid) {
      showLabel = false
    } else if (z < 2.5) {
      showLabel = isSel || c.hasCentre || c.hasProblem || top6Ids.has(c.id)
    } else if (isMobile.value && z < 4) {
      showLabel = isSel || c.hasCentre || c.hasProblem || c.count >= 2
    }

    // Fix #2: Suppress redundant same-place / overlapping label when a larger cluster sits within 40 px
    // (e.g., control-centre at SG country point right next to "新加坡 · 14").
    if (showLabel && !isSel) {
      const shadowedByLarger = projected.some(
        (other) =>
          other.cluster.id !== c.id &&
          (other.cluster.count > c.count || (other.cluster.count === c.count && other.cluster.id < c.id)) &&
          Math.hypot(other.pt.x - pt.x, other.pt.y - pt.y) < 40 &&
          (other.placeNorm === placeNorm || (c.hasCentre && c.count === 1)),
      )
      if (shadowedByLarger) showLabel = false
    }

    const rawLabel = showLabel
      ? c.hasCentre && c.count === 1
        ? c.nodes[0]?.name || formatClusterLabel(c, props.lang)
        : formatClusterLabel(c, props.lang)
      : ''
    let edgePlacement: 'extend-both' | 'extend-right' | 'extend-left' | 'hide' = 'hide'

    if (rawLabel) {
      const ang = centralAngleRad([c.lon, c.lat], [center.lng, center.lat])
      if (z >= 4 || ang < Math.PI * 0.48) {
        edgePlacement = assignMarkerEdgePlacement(pt.x, pt.y, stageW, stageH, rawLabel)
      }
    }

    const finalLabel = edgePlacement === 'hide' ? '' : rawLabel
    sigParts.push(`${c.id}:${icon}:${edgePlacement}:${finalLabel}:${hasSpiderfy && !isSpid ? 0 : 1}`)

    return {
      type: 'Feature',
      geometry: { type: 'Point', coordinates: [c.lon, c.lat] },
      properties: {
        id: c.id,
        icon,
        label: finalLabel,
        edgePlacement,
        sortKey,
        opacity: hasSpiderfy && !isSpid ? 0.3 : 1,
        count: c.count,
      },
    }
  })

  return { features, layoutSig: sigParts.join('|') }
}

function refreshMarkerEdgePlacements(): void {
  const map = mapRef.value
  if (!map || !styleReady.value) return
  const { features, layoutSig } = buildMarkerFeatures(map)
  if (layoutSig === lastMarkerLayoutSig) return
  lastMarkerLayoutSig = layoutSig
  const markerSrc = map.getSource(MARKERS_SOURCE_ID) as GeoJSONSource | undefined
  markerSrc?.setData({ type: 'FeatureCollection', features })
}

function syncAccuracyCircles(map: MapLibreMap): void {
  const src = map.getSource(ACCURACY_CIRCLES_SOURCE_ID) as GeoJSONSource | undefined
  if (!src) return
  const z = map.getZoom()
  if (isBackboneView.value || z < 3) {
    src.setData({ type: 'FeatureCollection', features: [] })
    return
  }
  const features: Array<GeoJSON.Feature<GeoJSON.LineString>> = []
  for (const g of grouped.value.groups) {
    if (g.precision !== 'coords' || !g.accuracyRadiusKm || g.accuracyRadiusKm <= 0) continue
    if (accuracyCircleRadiusPx(g.accuracyRadiusKm, z, g.lat) < 6) continue
    features.push({
      type: 'Feature',
      geometry: {
        type: 'LineString',
        coordinates: buildAccuracyCircleRing(g.lon, g.lat, g.accuracyRadiusKm, 64),
      },
      properties: { key: g.key, radiusKm: g.accuracyRadiusKm },
    })
  }
  src.setData({ type: 'FeatureCollection', features })
}

const EMPTY_GEOJSON: GeoJSON.FeatureCollection = { type: 'FeatureCollection', features: [] }

let lastBackboneStats = {
  mgmtPaths: 0,
  links: 0,
  arrows: 0,
  overlayDevices: 0,
}

function syncMapSources(): void {
  const map = mapRef.value
  if (!map || !styleReady.value) return

  applyViewModeLayerVisibility(map, activeViewMode.value, showDevices.value)

  const { features, layoutSig } = buildMarkerFeatures(map)
  lastMarkerLayoutSig = layoutSig
  const markerSrc = map.getSource(MARKERS_SOURCE_ID) as GeoJSONSource | undefined
  markerSrc?.setData({ type: 'FeatureCollection', features })

  syncAccuracyCircles(map)

  const linksSrc = map.getSource(LINKS_SOURCE_ID) as GeoJSONSource | undefined
  const badgesSrc = map.getSource(LINK_BADGES_SOURCE_ID) as GeoJSONSource | undefined
  const bbMgmtSrc = map.getSource(BACKBONE_MGMT_PATHS_SOURCE_ID) as GeoJSONSource | undefined
  const bbLinksSrc = map.getSource(BACKBONE_LINKS_SOURCE_ID) as GeoJSONSource | undefined
  const bbArrowsSrc = map.getSource(BACKBONE_ARROWS_SOURCE_ID) as GeoJSONSource | undefined
  const bbDevicesSrc = map.getSource(BACKBONE_DEVICES_SOURCE_ID) as GeoJSONSource | undefined

  if (isBackboneView.value) {
    linksSrc?.setData(EMPTY_GEOJSON)

    const focusedNodeId = hoveredBackboneNodeId.value ?? selectedNode.value?.id ?? null
    const hasSelection = Boolean(selectedNode.value || selectedBackboneArc.value)

    const mgmtPaths = buildBackboneMgmtPathsGeoJson(
      backboneResolved.value.placed,
      activeBackboneArcs.value,
      { focusedNodeId, hasSelection },
    )
    bbMgmtSrc?.setData(mgmtPaths)

    const { lines, arrows, badges } = buildBackboneLinksGeoJson(
      activeBackboneArcs.value,
      backboneResolved.value.placedById,
      props.themeMode,
      {
        hoveredLinkKey: hoveredLinkKey.value,
        selectedLinkKey: selectedBackboneArc.value?.key ?? null,
        focusedNodeId,
      },
    )
    bbLinksSrc?.setData(lines)
    bbArrowsSrc?.setData(arrows)
    badgesSrc?.setData(badges)

    const devOverlay = showDevices.value
      ? buildBackboneDevicesOverlayGeoJson(deviceDatasetNodes.value, loadedGazetteer.value)
      : EMPTY_GEOJSON
    bbDevicesSrc?.setData(devOverlay)

    lastBackboneStats = {
      mgmtPaths: mgmtPaths.features.length,
      links: lines.features.length,
      arrows: arrows.features.length,
      overlayDevices: devOverlay.features.length,
    }
  } else {
    bbMgmtSrc?.setData(EMPTY_GEOJSON)
    bbLinksSrc?.setData(EMPTY_GEOJSON)
    bbArrowsSrc?.setData(EMPTY_GEOJSON)
    bbDevicesSrc?.setData(EMPTY_GEOJSON)
    lastBackboneStats = { mgmtPaths: 0, links: 0, arrows: 0, overlayDevices: 0 }

    const hasSpiderfy = Boolean(activeSpiderfy.value)
    const hasEgo = Boolean(activeFocus.value && egoLinks.value.length > 0)
    const { lines, badges } = buildLinkGeoJson(linkAgg.value.displayed, egoLinks.value, {
      hoveredLinkKey: hoveredLinkKey.value,
      selectedLinkKey: selectedLink.value?.key ?? null,
      hasEgoFocus: hasEgo,
      dimAll: hasSpiderfy && !hasEgo,
    })

    linksSrc?.setData(lines)
    badgesSrc?.setData(badges)
  }

  emitMetrics()
}

// ── Spiderfy & Selection Handlers ─────────────────────────────────────────────

function detachSpiderfyMarker(): void {
  if (spiderfyMarkerRef.value) {
    spiderfyMarkerRef.value.remove()
    spiderfyMarkerRef.value = null
  }
}

function collapseSpiderfy(): void {
  if (!activeSpiderfy.value) return
  activeSpiderfy.value = null
  hoveredNode.value = null
  detachSpiderfyMarker()
  syncMapSources()
}

async function openSpiderfyForCluster(cluster: DisplayCluster): Promise<void> {
  const map = mapRef.value
  if (!map || !spiderfyHostEl.value) return
  const mode = classifyGroupInteraction(cluster.count)
  if (mode === 'list') {
    collapseSpiderfy()
    selectedNode.value = null
    selectedLink.value = null
    showingUnknownList.value = false
    showingAllDevicesList.value = false
    selectedCluster.value = cluster
    listPage.value = 1
    if (isMobile.value && isFullLayout.value) {
      mobileSheetOpen.value = true
      mobileTab.value = 'details'
      mobileSnap.value = 'peek'
    }
    syncSelectionUrl()
    applyCameraPadding(true)
    triggerSelectionPulse([cluster.lon, cluster.lat])
    syncMapSources()
    startFlowingDashOnSelection()
    return
  }

  // S4: If anchor is > 0.7 of globe screen radius from center, easeTo center first
  const pt = map.project([cluster.lon, cluster.lat])
  const rect = map.getContainer().getBoundingClientRect()
  const cx = rect.width / 2
  const cy = rect.height / 2
  const maxR = Math.min(rect.width, rect.height) * 0.35
  if (Math.hypot(pt.x - cx, pt.y - cy) > maxR && map.getZoom() < 4) {
    map.easeTo({
      center: [cluster.lon, cluster.lat],
      duration: prefersReducedMotion.value ? 0 : 300,
    })
  }

  const layout = computeSpiderfyLayout(cluster.nodes, isCoarsePointer.value)
  activeSpiderfy.value = {
    cluster,
    layout,
    startZoom: map.getZoom(),
  }
  await nextTick()

  detachSpiderfyMarker()
  const marker = new maplibregl.Marker({
    element: spiderfyHostEl.value,
    anchor: 'center',
    opacityWhenCovered: '0',
  })
    .setLngLat([cluster.lon, cluster.lat])
    .addTo(map)
  spiderfyMarkerRef.value = marker
  syncMapSources()
}

function onSelectSpiderfyNode(node: GlobeNode): void {
  selectedNode.value = node
  selectedLink.value = null
  showingUnknownList.value = false
  showingAllDevicesList.value = false
  selectedCluster.value = null
  sameCityPage.value = 1
  if (isMobile.value && isFullLayout.value) {
    mobileSheetOpen.value = true
    mobileTab.value = 'details'
    mobileSnap.value = 'peek'
  }
  emit('node-click', node.id)
  syncSelectionUrl()
  applyCameraPadding(true)
  const res = grouped.value.resolvedByNodeId.get(node.id)
  if (res?.lon != null && res?.lat != null) triggerSelectionPulse([res.lon, res.lat])
  syncMapSources()
  startFlowingDashOnSelection()
}

function onHoverSpiderfyNode(node: GlobeNode | null): void {
  hoveredNode.value = node
  syncMapSources()
}

function selectAggregatedLink(link: AggregatedLink): void {
  selectedLink.value = link
  selectedBackboneArc.value = null
  selectedNode.value = null
  selectedCluster.value = null
  showingUnknownList.value = false
  showingAllDevicesList.value = false
  if (isMobile.value && isFullLayout.value) {
    mobileSheetOpen.value = true
    mobileTab.value = 'details'
    mobileSnap.value = 'peek'
  }
  emit('arc-click', link.key)
  syncSelectionUrl()
  applyCameraPadding(true)
  detachPulseMarker()
  syncMapSources()
  startFlowingDashOnSelection()
}

function selectBackboneLink(arc: GlobeArc): void {
  selectedBackboneArc.value = arc
  selectedLink.value = null
  selectedNode.value = null
  selectedCluster.value = null
  showingUnknownList.value = false
  showingAllDevicesList.value = false
  if (isMobile.value && fullPage.isFull.value) {
    mobileSheetOpen.value = true
    mobileTab.value = 'details'
    mobileSnap.value = 'peek'
  }
  emit('arc-click', arc.key)
  syncSelectionUrl()
  applyCameraPadding(true)
  detachPulseMarker()
  syncMapSources()
}

function openUnlocatedCentre(node: GlobeNode): void {
  collapseSpiderfy()
  if (isMobile.value) legendCollapsed.value = true
  selectedNode.value = node
  selectedBackboneArc.value = null
  selectedLink.value = null
  selectedCluster.value = null
  showingUnknownList.value = false
  showingAllDevicesList.value = false
  if (isMobile.value && fullPage.isFull.value) {
    mobileSheetOpen.value = true
    mobileTab.value = 'details'
    mobileSnap.value = 'mid'
  }
  emit('node-click', node.id)
  syncSelectionUrl()
  applyCameraPadding(true)
  detachPulseMarker()
  syncMapSources()
}

function selectNodeFromList(node: GlobeNode): void {
  selectedNode.value = node
  selectedLink.value = null
  selectedBackboneArc.value = null
  showingUnknownList.value = false
  showingAllDevicesList.value = false
  selectedCluster.value = null
  sameCityPage.value = 1
  if (isMobile.value && isFullLayout.value) {
    mobileSheetOpen.value = true
    mobileTab.value = 'details'
    mobileSnap.value = 'peek'
  }
  emit('node-click', node.id)
  syncSelectionUrl()
  applyCameraPadding(true)
  const placedBb = isBackboneView.value ? backboneResolved.value.placedById.get(node.id) : null
  const res = placedBb ?? grouped.value.resolvedByNodeId.get(node.id)
  if (res?.lon != null && res?.lat != null) {
    triggerSelectionPulse([res.lon, res.lat])
    mapRef.value?.easeTo({
      center: [res.lon, res.lat],
      duration: prefersReducedMotion.value ? 0 : 450,
    })
  } else {
    detachPulseMarker()
  }
  syncMapSources()
  if (!isBackboneView.value) startFlowingDashOnSelection()
}

function focusClusterById(displayId: string): void {
  const c = clusterById.value.get(displayId)
  if (!c) return
  mapRef.value?.easeTo({
    center: [c.lon, c.lat],
    duration: prefersReducedMotion.value ? 0 : 450,
  })
  if (c.count === 1 && c.nodes[0]) {
    selectNodeFromList(c.nodes[0])
  } else {
    selectedNode.value = null
    selectedLink.value = null
    selectedBackboneArc.value = null
    showingUnknownList.value = false
    showingAllDevicesList.value = false
    selectedCluster.value = c
    listPage.value = 1
    syncSelectionUrl()
    applyCameraPadding(true)
    triggerSelectionPulse([c.lon, c.lat])
    syncMapSources()
    startFlowingDashOnSelection()
  }
}

function openUnknownList(): void {
  collapseSpiderfy()
  if (isMobile.value) legendCollapsed.value = true
  selectedNode.value = null
  selectedLink.value = null
  selectedBackboneArc.value = null
  selectedCluster.value = null
  showingAllDevicesList.value = false
  showingUnknownList.value = true
  listPage.value = 1
  if (isMobile.value && isFullLayout.value) {
    mobileSheetOpen.value = true
    mobileTab.value = 'details'
    mobileSnap.value = 'mid'
  }
  syncSelectionUrl()
  applyCameraPadding(true)
}

function closePanel(): void {
  selectedNode.value = null
  selectedCluster.value = null
  selectedLink.value = null
  selectedBackboneArc.value = null
  showingUnknownList.value = false
  showingAllDevicesList.value = false
  mobileSheetOpen.value = false
  stopFlowingDash()
  detachPulseMarker()
  syncSelectionUrl()
  applyCameraPadding(true)
  syncMapSources()
}

function cancelHoverClose(): void {
  if (hoverCloseTimer) {
    clearTimeout(hoverCloseTimer)
    hoverCloseTimer = null
  }
}

function scheduleHoverClose(): void {
  cancelHoverClose()
  hoverCloseTimer = setTimeout(() => {
    hoverCard.value = null
    hoveredDisplayId.value = null
    hoveredBackboneNodeId.value = null
    hoveredLinkKey.value = null
    syncMapSources()
  }, 150)
}

function pickNearestBackboneNodeAt(map: MapLibreMap, x: number, y: number): PlacedBackboneNode | null {
  const half = hitHalfBoxPx(isCoarsePointer.value)
  const feats = map.queryRenderedFeatures(
    [
      [x - half, y - half],
      [x + half, y + half],
    ],
    { layers: ['mh-markers'] },
  )
  if (!feats.length) return null
  let best: PlacedBackboneNode | null = null
  let bestDist = Infinity
  let bestSort = Infinity
  for (const f of feats) {
    const id = String(f.properties?.id ?? '')
    const p = backboneResolved.value.placedById.get(id)
    if (!p) continue
    const pt = map.project([p.lon, p.lat])
    const dist = Math.hypot(pt.x - x, pt.y - y)
    const sortKey = Number(f.properties?.sortKey ?? 999)
    if (dist < bestDist - 0.5 || (Math.abs(dist - bestDist) <= 0.5 && sortKey < bestSort)) {
      bestDist = dist
      bestSort = sortKey
      best = p
    }
  }
  return best
}

function pickBackboneLinkAt(map: MapLibreMap, x: number, y: number): GlobeArc | null {
  const tol = isCoarsePointer.value ? 12 : 6
  const activeBbLayers = BACKBONE_LINK_LAYER_IDS.filter((id) => Boolean(map.getLayer(id)))
  if (!activeBbLayers.length) return null
  const feats = map.queryRenderedFeatures(
    [
      [x - tol, y - tol],
      [x + tol, y + tol],
    ],
    { layers: activeBbLayers },
  )
  if (!feats.length) return null
  const key = String(feats[0]?.properties?.key ?? '')
  return activeBackboneArcs.value.find((a) => a.key === key) ?? null
}

function pickNearestMarkerAt(map: MapLibreMap, x: number, y: number): DisplayCluster | null {
  const half = hitHalfBoxPx(isCoarsePointer.value)
  const feats = map.queryRenderedFeatures(
    [
      [x - half, y - half],
      [x + half, y + half],
    ],
    { layers: ['mh-markers'] },
  )
  if (!feats.length) return null
  let best: DisplayCluster | null = null
  let bestDist = Infinity
  let bestSort = Infinity
  for (const f of feats) {
    const id = String(f.properties?.id ?? '')
    const c = clusterById.value.get(id)
    if (!c) continue
    const p = map.project([c.lon, c.lat])
    const dist = Math.hypot(p.x - x, p.y - y)
    const sortKey = Number(f.properties?.sortKey ?? 999)
    if (dist < bestDist - 0.5 || (Math.abs(dist - bestDist) <= 0.5 && sortKey < bestSort)) {
      bestDist = dist
      bestSort = sortKey
      best = c
    }
  }
  return best
}

function pickLinkAt(map: MapLibreMap, x: number, y: number): AggregatedLink | null {
  const tol = isCoarsePointer.value ? 12 : 6
  const activeSurfaceLayers = SURFACE_LINK_LAYER_IDS.filter((id) => Boolean(map.getLayer(id)))
  const feats = map.queryRenderedFeatures(
    [
      [x - tol, y - tol],
      [x + tol, y + tol],
    ],
    { layers: activeSurfaceLayers },
  )
  if (!feats.length) return null
  const key = String(feats[0]?.properties?.key ?? '')
  return (
    egoLinks.value.find((l) => l.key === key) ??
    linkAgg.value.displayed.find((l) => l.key === key) ??
    null
  )
}

function handleMapClick(e: maplibregl.MapMouseEvent): void {
  const map = mapRef.value
  if (!map) return

  // Fix #4 & settings popover: outside tap closes popovers cleanly
  if (settingsOpen.value) {
    settingsOpen.value = false
  }
  if (isMobile.value && !legendCollapsed.value) {
    legendCollapsed.value = true
  }

  const { x, y } = e.point

  if (isBackboneView.value) {
    const hitBbNode = pickNearestBackboneNodeAt(map, x, y)
    if (hitBbNode) {
      selectedNode.value = hitBbNode.node
      selectedBackboneArc.value = null
      selectedCluster.value = null
      selectedLink.value = null
      showingUnknownList.value = false
      showingAllDevicesList.value = false
      if (isMobile.value && fullPage.isFull.value) {
        mobileSheetOpen.value = true
        mobileTab.value = 'details'
        mobileSnap.value = 'peek'
      }
      emit('node-click', hitBbNode.id)
      syncSelectionUrl()
      applyCameraPadding(true)
      triggerSelectionPulse([hitBbNode.lon, hitBbNode.lat])
      syncMapSources()
      return
    }
    const hitBbLink = pickBackboneLinkAt(map, x, y)
    if (hitBbLink) {
      selectBackboneLink(hitBbLink)
      return
    }
    if (panelOpen.value || mobileSheetOpen.value) {
      closePanel()
    }
    return
  }

  const hitCluster = pickNearestMarkerAt(map, x, y)
  if (hitCluster) {
    if (hitCluster.isMultiCity) {
      collapseSpiderfy()
      const splitLimit = Math.min(maxZoomSetting.value, 9)
      const splitZ = findClusterSplitZoom(hitCluster, grouped.value.groups, map.getZoom(), splitLimit, 40)
      if (splitZ != null) {
        userManuallyZoomed = true
        map.easeTo({
          center: [hitCluster.lon, hitCluster.lat],
          zoom: Math.min(maxZoomSetting.value, splitZ + 0.15),
          duration: prefersReducedMotion.value ? 0 : 600,
        })
      } else {
        selectedNode.value = null
        selectedLink.value = null
        selectedBackboneArc.value = null
        showingUnknownList.value = false
        showingAllDevicesList.value = false
        selectedCluster.value = hitCluster
        listPage.value = 1
        if (isMobile.value && isFullLayout.value) {
          mobileSheetOpen.value = true
          mobileTab.value = 'details'
          mobileSnap.value = 'peek'
        }
        syncSelectionUrl()
        applyCameraPadding(true)
        triggerSelectionPulse([hitCluster.lon, hitCluster.lat])
        syncMapSources()
        startFlowingDashOnSelection()
      }
      return
    }

    const mode = classifyGroupInteraction(hitCluster.count)
    if (mode === 'select-device') {
      collapseSpiderfy()
      const targetNode = hitCluster.nodes[0] ?? null
      selectedNode.value = targetNode
      selectedCluster.value = null
      selectedLink.value = null
      selectedBackboneArc.value = null
      showingUnknownList.value = false
      showingAllDevicesList.value = false
      sameCityPage.value = 1
      if (isMobile.value && isFullLayout.value) {
        mobileSheetOpen.value = true
        mobileTab.value = 'details'
        mobileSnap.value = 'peek'
      }
      if (targetNode) emit('node-click', targetNode.id)
      syncSelectionUrl()
      applyCameraPadding(true)
      triggerSelectionPulse([hitCluster.lon, hitCluster.lat])
      syncMapSources()
      startFlowingDashOnSelection()
    } else if (mode === 'circle' || mode === 'spiral') {
      void openSpiderfyForCluster(hitCluster)
    } else {
      collapseSpiderfy()
      selectedNode.value = null
      selectedLink.value = null
      selectedBackboneArc.value = null
      showingUnknownList.value = false
      showingAllDevicesList.value = false
      selectedCluster.value = hitCluster
      listPage.value = 1
      if (isMobile.value && isFullLayout.value) {
        mobileSheetOpen.value = true
        mobileTab.value = 'details'
        mobileSnap.value = 'peek'
      }
      syncSelectionUrl()
      applyCameraPadding(true)
      triggerSelectionPulse([hitCluster.lon, hitCluster.lat])
      syncMapSources()
      startFlowingDashOnSelection()
    }
    return
  }

  const hitLink = pickLinkAt(map, x, y)
  if (hitLink) {
    collapseSpiderfy()
    selectAggregatedLink(hitLink)
    return
  }

  // Click empty area: collapse spiderfy first, else clear selection
  if (activeSpiderfy.value) {
    collapseSpiderfy()
  } else if (panelOpen.value || mobileSheetOpen.value) {
    closePanel()
  }
}

function handleMapMouseMove(e: maplibregl.MapMouseEvent): void {
  if (isMobile.value) return
  const map = mapRef.value
  if (!map) return
  const { x, y } = e.point
  if (hoverShowTimer) clearTimeout(hoverShowTimer)

  // S8: 120 ms hover delay, max-width 260 px, 8 px offset
  hoverShowTimer = setTimeout(() => {
    if (isBackboneView.value) {
      const hitBb = pickNearestBackboneNodeAt(map, x, y)
      if (hitBb) {
        cancelHoverClose()
        map.getCanvas().style.cursor = 'pointer'
        const rect = map.getContainer().getBoundingClientRect()
        const roles: string[] = []
        if (hitBb.node.isCentre) roles.push(t('mh.mesh.role.centre'))
        if (hitBb.node.isGateway) roles.push(t('mh.mesh.role.gateway'))
        if (hitBb.node.isEntry) roles.push(t('mh.mesh.role.entry'))
        const zoneBits: string[] = []
        if (hitBb.zoneName) zoneBits.push(hitBb.zoneName)
        if (hitBb.zoneDeviceCount != null) {
          zoneBits.push(t('mh.backbone.deviceCountShort', { n: hitBb.zoneDeviceCount }))
        }
        const entry = hitBb.node.managementEntry
        const entryTip = entry
          ? entry.listening
            ? entry.port
              ? t('mh.mesh.panel.entryTipListeningPort', { port: entry.port, n: entry.deviceCount })
              : t('mh.mesh.panel.entryTipListening', { n: entry.deviceCount })
            : t('mh.mesh.panel.entryTipOff')
          : ''
        hoverCard.value = {
          x: Math.min(x + 8, Math.max(8, rect.width - 268)),
          y: Math.min(y + 8, Math.max(8, rect.height - 116)),
          title: hitBb.node.name,
          badge: roles.join(' · ') || undefined,
          subtitle: zoneBits.join(' · ') || presenceLabel(hitBb.node),
          breakdown: entryTip || undefined,
          extra: precisionText(hitBb.precision, hitBb.accuracyRadiusKm),
        }
        if (hoveredBackboneNodeId.value !== hitBb.id || hoveredLinkKey.value !== null) {
          hoveredBackboneNodeId.value = hitBb.id
          hoveredLinkKey.value = null
          syncMapSources()
        }
        return
      }

      const hitBbLink = pickBackboneLinkAt(map, x, y)
      if (hitBbLink) {
        cancelHoverClose()
        map.getCanvas().style.cursor = 'pointer'
        const rect = map.getContainer().getBoundingClientRect()
        const uni = isUnidirectionalBackboneArc(hitBbLink)
        const arrow = uni ? '→' : '↔'
        const subBits = [carrierLabel(hitBbLink.carrier)]
        if (hitBbLink.rttMs != null) subBits.push(`${hitBbLink.rttMs} ms`)
        if (hitBbLink.enabled === false) subBits.push(t('mh.backbone.disabled'))
        else if (hitBbLink.stalled) subBits.push(t('mh.mesh.stalled'))
        hoverCard.value = {
          x: Math.min(x + 8, Math.max(8, rect.width - 268)),
          y: Math.min(y + 8, Math.max(8, rect.height - 116)),
          title: `${backboneNodeName(hitBbLink.from)} ${arrow} ${backboneNodeName(hitBbLink.to)}`,
          badge: hitBbLink.crossZone ? t('mh.backbone.crossZone') : undefined,
          subtitle: subBits.join(' · '),
          extra: uni ? t('mh.backbone.unidirectional') : t('mh.backbone.bidirectional'),
        }
        if (hoveredLinkKey.value !== hitBbLink.key || hoveredBackboneNodeId.value !== null) {
          hoveredLinkKey.value = hitBbLink.key
          hoveredBackboneNodeId.value = null
          syncMapSources()
        }
        return
      }

      map.getCanvas().style.cursor = ''
      if (hoverCard.value || hoveredBackboneNodeId.value || hoveredLinkKey.value) {
        scheduleHoverClose()
      }
      return
    }

    const hitCluster = pickNearestMarkerAt(map, x, y)
    if (hitCluster) {
      cancelHoverClose()
      map.getCanvas().style.cursor = 'pointer'
      const rect = map.getContainer().getBoundingClientRect()
      hoverCard.value = {
        x: Math.min(x + 8, Math.max(8, rect.width - 268)),
        y: Math.min(y + 8, Math.max(8, rect.height - 104)),
        title: formatClusterLabel(hitCluster, props.lang),
        subtitle: t('mh.globeV2.clusterStatusCounts', {
          online: hitCluster.onlineCount,
          stale: hitCluster.staleCount,
          offline: hitCluster.offlineCount,
        }),
        extra: precisionText(hitCluster.precision, hitCluster.accuracyRadiusKm),
      }
      if (hoveredDisplayId.value !== hitCluster.id || hoveredLinkKey.value !== null) {
        hoveredDisplayId.value = hitCluster.id
        hoveredLinkKey.value = null
        syncMapSources()
      }
      return
    }

    const hitLink = pickLinkAt(map, x, y)
    if (hitLink) {
      cancelHoverClose()
      map.getCanvas().style.cursor = 'pointer'
      const rect = map.getContainer().getBoundingClientRect()
      hoverCard.value = {
        x: Math.min(x + 8, Math.max(8, rect.width - 268)),
        y: Math.min(y + 8, Math.max(8, rect.height - 116)),
        title: `${clusterLabelById(hitLink.fromDisplayId)} ↔ ${clusterLabelById(hitLink.toDisplayId)}`,
        subtitle: `×${hitLink.count} · ${carrierLabel(hitLink.majorityClass)}${hitLink.medianRtt != null ? ` · ${hitLink.medianRtt} ms` : ''}`,
        breakdown: formatBreakdownText(hitLink),
        mixed: hitLink.isMixed,
      }
      if (hoveredLinkKey.value !== hitLink.key || hoveredDisplayId.value !== null) {
        hoveredLinkKey.value = hitLink.key
        hoveredDisplayId.value = null
        syncMapSources()
      }
      return
    }

    map.getCanvas().style.cursor = ''
    if (hoverCard.value || hoveredDisplayId.value || hoveredLinkKey.value) {
      scheduleHoverClose()
    }
  }, 120)
}

function handleKeyDown(e: KeyboardEvent): void {
  if (e.key === 'Escape') {
    // S8 + Fix #4 Esc chain: settings popover -> mobile legend popover -> hover card -> spiderfy -> panel -> full-page
    if (settingsOpen.value) {
      settingsOpen.value = false
      return
    }
    if (isMobile.value && !legendCollapsed.value) {
      legendCollapsed.value = true
      return
    }
    if (hoverCard.value) {
      hoverCard.value = null
      hoveredDisplayId.value = null
      hoveredBackboneNodeId.value = null
      hoveredLinkKey.value = null
      syncMapSources()
      return
    }
    if (activeSpiderfy.value) {
      collapseSpiderfy()
      return
    }
    if (panelOpen.value || mobileSheetOpen.value) {
      closePanel()
      return
    }
    if (!props.standaloneFullPage && fullPage.isFull.value) {
      void fullPage.exitFullPage(false)
    }
  }
}

function handleCanvasKeyDown(e: KeyboardEvent): void {
  const map = mapRef.value
  if (!map) return
  if (e.key === '+' || e.key === '=') {
    e.preventDefault()
    zoomBy(0.75)
  } else if (e.key === '-' || e.key === '_') {
    e.preventDefault()
    zoomBy(-0.75)
  } else if (e.key === 'ArrowLeft') {
    e.preventDefault()
    map.panBy([-90, 0], { duration: prefersReducedMotion.value ? 0 : 180 })
  } else if (e.key === 'ArrowRight') {
    e.preventDefault()
    map.panBy([90, 0], { duration: prefersReducedMotion.value ? 0 : 180 })
  } else if (e.key === 'ArrowUp') {
    e.preventDefault()
    map.panBy([0, -90], { duration: prefersReducedMotion.value ? 0 : 180 })
  } else if (e.key === 'ArrowDown') {
    e.preventDefault()
    map.panBy([0, 90], { duration: prefersReducedMotion.value ? 0 : 180 })
  }
}

function zoomBy(delta: number): void {
  const map = mapRef.value
  if (!map) return
  userManuallyZoomed = true
  const target = Math.max(MIN_GLOBE_ZOOM, Math.min(maxZoomSetting.value, map.getZoom() + delta))
  map.easeTo({ zoom: target, duration: prefersReducedMotion.value ? 0 : 250 })
}

function resetView(): void {
  const map = mapRef.value
  if (!map) return
  collapseSpiderfy()
  userManuallyZoomed = false
  if (isBackboneView.value) {
    fitCameraToActiveNodes(true)
  } else {
    fitGlobeToContainer(true, [DEFAULT_GLOBE_CENTER[0], DEFAULT_GLOBE_CENTER[1]])
  }
}

let ro: ResizeObserver | null = null
let initialBackboneFitted = false

function handleResize(): void {
  viewportWidth.value = typeof window !== 'undefined' ? window.innerWidth : 1280
  mapRef.value?.resize()
  syncFresnelRim()
}

function onContextLost(ev: Event): void {
  ev.preventDefault()
  webglContextLostCount.value++
  contextLostActive.value = true
  emitMetrics()
}

function onContextRestored(): void {
  contextLostActive.value = false
  syncMapSources()
  emitMetrics()
}

onMounted(() => {
  ensureMapLibreSetup()
  if (!mapHostEl.value) return

  // Lazily load P1 gazetteer if present
  void loadGazetteerIfPresent().then((g) => {
    if (g) {
      loadedGazetteer.value = g
      syncMapSources()
    }
  })

  const { width: initW, height: initH } = getStageDimensions()
  stageWidthPx.value = initW
  const initCenter = isBackboneView.value
    ? computeBackboneCenter()
    : ([DEFAULT_GLOBE_CENTER[0], DEFAULT_GLOBE_CENTER[1]] as [number, number])
  const initialZoom = computeFitGlobeZoom(
    initW,
    initH,
    initCenter[1],
    DEFAULT_TARGET_DIAMETER_RATIO,
  )
  currentZoom.value = initialZoom
  currentZi.value = Math.floor(initialZoom)

  let map: MapLibreMap
  try {
    map = new maplibregl.Map({
      container: mapHostEl.value,
      style: buildGlobeStyle(
        props.themeMode,
        props.lang,
        resolvedPmtilesUrl.value,
        isMobile.value,
        activeViewMode.value,
      ),
      center: initCenter,
      zoom: initialZoom,
      minZoom: MIN_GLOBE_ZOOM,
      maxZoom: maxZoomSetting.value,
      maxPitch: 0,
      pitch: 0,
      bearing: 0,
      dragRotate: false,
      touchPitch: false,
      pitchWithRotate: false,
      renderWorldCopies: false,
      fadeDuration: 150,
      pixelRatio: Math.max(1, Math.min(2, props.pixelRatio)),
      cooperativeGestures: effectiveCooperativeGestures.value,
      localIdeographFontFamily: CJK_FONT_STACK,
      attributionControl: false,
    })
  } catch {
    emit('webgl-error', 'maplibre-init-failed')
    return
  }

  // North-up locked (S1 / AC5)
  map.touchZoomRotate.disableRotation()
  cooperativeGesturesActive.value = Boolean(map.cooperativeGestures?.isEnabled())

  // Instrument setStyle so automated checks prove 0 style reloads on theme/lang/view switch
  const origSetStyle = map.setStyle.bind(map)
  map.setStyle = ((...args: Parameters<MapLibreMap['setStyle']>) => {
    styleReloadCount.value++
    emitMetrics()
    return origSetStyle(...args)
  }) as MapLibreMap['setStyle']

  const canvas = map.getCanvas()
  canvas.addEventListener('webglcontextlost', onContextLost)
  canvas.addEventListener('webglcontextrestored', onContextRestored)

  map.on('render', () => {
    renderEventCounter++
    syncFresnelRim()
  })

  map.on('zoomstart', (ev) => {
    if (ev.originalEvent) userManuallyZoomed = true
  })

  map.on('load', () => {
    styleReady.value = true
    if (firstFrameMs.value == null) {
      firstFrameMs.value = Math.round(performance.now() - mountTime)
    }
    if (!userManuallyZoomed) {
      fitCameraToActiveNodes(false)
      if (isBackboneView.value && backboneResolved.value.placed.length > 0) {
        initialBackboneFitted = true
      }
    }
    syncMapSources()
    syncFresnelRim()
    hydrateSelectionFromUrl()
    emitMetrics()
  })

  map.on('zoom', () => {
    const z = map.getZoom()
    currentZoom.value = z
    const zi = Math.floor(z)
    if (zi !== currentZi.value) {
      currentZi.value = zi
      syncMapSources()
    }
    if (activeSpiderfy.value && Math.abs(z - activeSpiderfy.value.startZoom) > 0.3) {
      collapseSpiderfy()
    }
  })

  map.on('moveend', () => {
    currentCenterLat.value = map.getCenter().lat
    syncFresnelRim()
    refreshMarkerEdgePlacements()
    syncAccuracyCircles(map)
  })

  map.on('click', handleMapClick)
  map.on('mousemove', handleMapMouseMove)

  mapRef.value = map

  if (typeof ResizeObserver !== 'undefined' && shellEl.value) {
    ro = new ResizeObserver(() => {
      map.resize()
      const rect = mapHostEl.value?.getBoundingClientRect()
      if (rect && rect.width > 40) stageWidthPx.value = rect.width
      if (styleReady.value && !userManuallyZoomed && !activeSpiderfy.value) {
        fitCameraToActiveNodes(false)
      }
      syncFresnelRim()
      refreshMarkerEdgePlacements()
    })
    ro.observe(shellEl.value)
  }

  // Expose read-only debug accessor directly on the shell DOM element for Playwright checks
  if (shellEl.value) {
    ;(shellEl.value as unknown as Record<string, unknown>).__mhGlobeDebug = () => getDebugState()
    ;(shellEl.value as unknown as Record<string, unknown>).__mhGlobeMap = () => mapRef.value
  }

  window.addEventListener('resize', handleResize)
  window.addEventListener('keydown', handleKeyDown)
})

onBeforeUnmount(() => {
  stopFlowingDash()
  if (hoverShowTimer) clearTimeout(hoverShowTimer)
  if (hoverCloseTimer) clearTimeout(hoverCloseTimer)
  window.removeEventListener('resize', handleResize)
  window.removeEventListener('keydown', handleKeyDown)
  ro?.disconnect()
  detachSpiderfyMarker()
  detachPulseMarker()
  const map = mapRef.value
  if (map) {
    const canvas = map.getCanvas()
    canvas.removeEventListener('webglcontextlost', onContextLost)
    canvas.removeEventListener('webglcontextrestored', onContextRestored)
    map.remove()
    mapRef.value = null
  }
})

// Auto-collapse legend when entering mobile (<600px)
watch(isMobile, (mobile) => {
  if (mobile) legendCollapsed.value = true
  applyCameraPadding(false)
})

// Desktop card keeps legend collapsed by default; desktop full-page opens it cleanly
watch(
  isFullLayout,
  (isFull) => {
    if (isMobile.value) {
      legendCollapsed.value = true
    } else {
      legendCollapsed.value = !isFull
    }
  },
)

watch(
  () => props.viewMode,
  (next) => {
    if (next !== activeViewMode.value) {
      switchViewMode(next)
    }
  },
)

watch(
  () => props.showDevicesOverlay,
  (next) => {
    if (next !== showDevices.value) {
      showDevices.value = next
      const map = mapRef.value
      if (map && styleReady.value) {
        applyViewModeLayerVisibility(map, activeViewMode.value, next)
        syncMapSources()
      }
    }
  },
)

// Live updates with ZERO setStyle() reload (S6 / AC10)
watch(
  () => props.themeMode,
  (mode) => {
    const map = mapRef.value
    if (!map || !styleReady.value) return
    applyThemeToMap(map, mode)
    syncMapSources()
  },
)

watch(
  () => props.lang,
  (lang) => {
    const map = mapRef.value
    if (!map || !styleReady.value) return
    applyLangToMap(map, lang)
    syncMapSources()
  },
)

watch(
  () => props.pixelRatio,
  (pr) => {
    const map = mapRef.value
    if (!map) return
    map.setPixelRatio(Math.max(1, Math.min(2, pr)))
    syncMapSources()
  },
)

watch(
  () => props.cooperativeGestures,
  () => {
    syncCooperativeGestures()
  },
)

watch(
  [
    allGlobeNodes,
    deviceDatasetArcs,
    activeBackboneNodes,
    activeBackboneArcs,
    () => props.zones,
    activeCarrierSet,
    effectiveOnlyProblems,
    effectiveMinRttMs,
    showDevices,
  ],
  () => {
    if (
      isBackboneView.value &&
      !initialBackboneFitted &&
      !userManuallyZoomed &&
      styleReady.value &&
      backboneResolved.value.placed.length > 0
    ) {
      initialBackboneFitted = true
      fitCameraToActiveNodes(false)
    }
    syncMapSources()
  },
)

function measurePmtilesBytes(): number {
  if (typeof performance === 'undefined') return 0
  let total = 0
  for (const e of performance.getEntriesByType('resource')) {
    const res = e as PerformanceResourceTiming
    if (res.name.includes('.pmtiles')) {
      total += res.transferSize || res.encodedBodySize || 0
    }
  }
  return total
}

function getWebglRendererName(): string {
  const map = mapRef.value
  if (!map) return 'unknown'
  const gl = map.getCanvas().getContext('webgl2')
  if (!gl) return 'unknown'
  const ext = gl.getExtension('WEBGL_debug_renderer_info')
  if (!ext) return String(gl.getParameter(gl.RENDERER) ?? 'webgl2')
  return String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) ?? 'webgl2')
}

function percentile(sorted: number[], p: number): number {
  if (!sorted.length) return 0
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))
  return Math.round(sorted[idx]! * 100) / 100
}

/**
 * Deterministic 10s Perf HUD benchmark (S14):
 * Rotates 180°, sweeps zoom 1 -> 6 -> 1, then checks idleFramesAfter1s === 0.
 */
async function runPerfBenchmark(durationMs = 10_000): Promise<GlobePerfReport> {
  const map = mapRef.value
  if (!map) throw new Error('Map not initialized')

  collapseSpiderfy()
  closePanel()

  const startLon = 20
  const startLat = 26
  map.jumpTo({ center: [startLon, startLat], zoom: 1, bearing: 0, pitch: 0 })

  const deltas: number[] = []
  const startTime = performance.now()
  let lastFrame = startTime

  await new Promise<void>((resolve) => {
    const tick = (now: number) => {
      const elapsed = now - startTime
      const progress = Math.min(1, elapsed / durationMs)
      if (deltas.length > 0 || elapsed > 0) {
        deltas.push(now - lastFrame)
      }
      lastFrame = now

      const lon = startLon + 180 * progress
      const zoom = 1 + 5 * Math.sin(progress * Math.PI)
      map.jumpTo({ center: [lon > 180 ? lon - 360 : lon, startLat], zoom, bearing: 0, pitch: 0 })

      if (progress < 1) {
        requestAnimationFrame(tick)
      } else {
        resolve()
      }
    }
    requestAnimationFrame(tick)
  })

  // Wait 1 s for rendering to settle, then count WebGL render frames over the next 1 s (S11 AC13).
  await new Promise((r) => setTimeout(r, 1000))
  const beforeIdle = renderEventCounter
  await new Promise((r) => setTimeout(r, 1000))
  const idleFramesAfter1s = renderEventCounter - beforeIdle

  const sorted = [...deltas].sort((a, b) => a - b)
  const framesOver50ms = deltas.filter((d) => d > 50).length
  const totalTime = deltas.reduce((s, d) => s + d, 0) || durationMs
  const rect = map.getContainer().getBoundingClientRect()

  const report: GlobePerfReport = {
    variant: 'L',
    pixelRatio: props.pixelRatio,
    dataset: props.datasetTag,
    viewport: { width: Math.round(rect.width), height: Math.round(rect.height) },
    renderer: getWebglRendererName(),
    durationMs,
    totalFrames: deltas.length,
    avgFps: Math.round((deltas.length / (totalTime / 1000)) * 10) / 10,
    p50: percentile(sorted, 50),
    p95: percentile(sorted, 95),
    maxFrameMs: sorted.length ? Math.round(sorted[sorted.length - 1]! * 100) / 100 : 0,
    framesOver50ms,
    tileBytes: measurePmtilesBytes(),
    firstFrameMs: firstFrameMs.value,
    idleFramesAfter1s,
    webglContextLost: webglContextLostCount.value,
    styleReloads: styleReloadCount.value,
    cooperativeGesturesSupported: Boolean(map.cooperativeGestures),
    timestamp: new Date().toISOString(),
  }

  ;(window as unknown as Record<string, unknown>).__GLOBE_P0_PERF__ = report
  return report
}

/** Helpers exposed for deterministic inspection & Playwright verification. */
async function triggerClusterByName(nameQuery: string): Promise<string | null> {
  const q = nameQuery.toLowerCase()
  const match = merged.value.clusters.find(
    (c) =>
      c.placeEn.toLowerCase().includes(q) ||
      c.placeZh.toLowerCase().includes(q) ||
      c.nodes.some((n) => n.name.toLowerCase().includes(q)),
  )
  if (!match) return null
  await openSpiderfyForCluster(match)
  return match.id
}

function selectNodeById(id: string): boolean {
  const pool = isBackboneView.value ? activeBackboneNodes.value : allGlobeNodes.value
  const found = pool.find((n) => n.id === id)
  if (!found) return false
  selectNodeFromList(found)
  return true
}

function focusNodeById(id: string): boolean {
  return selectNodeById(id)
}

function focusArcByKey(key: string): boolean {
  if (isBackboneView.value) {
    const found = activeBackboneArcs.value.find((a) => a.key === key)
    if (!found) return false
    selectBackboneLink(found)
    const pFrom = backboneResolved.value.placedById.get(found.from)
    const pTo = backboneResolved.value.placedById.get(found.to)
    if (pFrom && pTo) {
      mapRef.value?.easeTo({
        center: [(pFrom.lon + pTo.lon) / 2, (pFrom.lat + pTo.lat) / 2],
        duration: prefersReducedMotion.value ? 0 : 450,
      })
    }
    return true
  }
  const found = linkAgg.value.allAggregated.find((x) => x.key === key)
  if (!found) return false
  selectAggregatedLink(found)
  return true
}

function selectFirstLink(): string | null {
  if (isBackboneView.value) {
    const first = activeBackboneArcs.value[0]
    if (!first) return null
    selectBackboneLink(first)
    return first.key
  }
  const first = linkAgg.value.displayed[0]
  if (!first) return null
  selectAggregatedLink(first)
  return first.key
}

function setCamera(center: [number, number], zoom: number): void {
  userManuallyZoomed = true
  mapRef.value?.jumpTo({ center, zoom, bearing: 0, pitch: 0 })
  syncFresnelRim()
  refreshMarkerEdgePlacements()
}

function getDebugState() {
  const map = mapRef.value
  const rect = mapHostEl.value?.getBoundingClientRect()
  const minDim = rect ? Math.min(rect.width, rect.height) : 1
  const globeDiameterRatio = minDim > 0 ? Math.round(((lastGlobeRadiusPx * 2) / minDim) * 1000) / 1000 : 0

  // Inspect rendered label features for Fix #2 & Fix #3 programmatic audits
  let renderedMarkerLabels: Array<{ text: string; x: number; y: number; edgePlacement: string }> = []
  let renderedBasemapLabels: Array<{ layer: string; text: string; x: number; y: number }> = []
  if (map && styleReady.value) {
    const mLayers = MARKER_LABEL_LAYER_IDS.filter((id) => Boolean(map.getLayer(id)))
    const mFeats = map.queryRenderedFeatures(undefined, { layers: mLayers })
    const seenM = new Set<string>()
    for (const f of mFeats) {
      const id = String(f.properties?.id ?? '')
      const text = String(f.properties?.label ?? '')
      if (!text || seenM.has(id)) continue
      seenM.add(id)
      const coords = (f.geometry as GeoJSON.Point).coordinates
      const p = map.project([coords[0]!, coords[1]!])
      renderedMarkerLabels.push({
        text,
        x: Math.round(p.x * 10) / 10,
        y: Math.round(p.y * 10) / 10,
        edgePlacement: String(f.properties?.edgePlacement ?? ''),
      })
    }

    const bLayers = ['label-admin0', 'label-admin1', 'label-place'].filter((id) => Boolean(map.getLayer(id)))
    const bFeats = map.queryRenderedFeatures(undefined, { layers: bLayers })
    const seenB = new Set<string>()
    for (const f of bFeats) {
      const text = String(
        f.properties?.name_zh_override ||
          (props.lang === 'zh-CN' ? f.properties?.name_zh || f.properties?.name_en : f.properties?.name_en) ||
          '',
      )
      const coords = (f.geometry as GeoJSON.Point).coordinates
      if (!text || !Array.isArray(coords)) continue
      const p = map.project([coords[0]!, coords[1]!])
      const key = `${f.layer.id}:${text}:${Math.round(p.x)}:${Math.round(p.y)}`
      if (seenB.has(key)) continue
      seenB.add(key)
      renderedBasemapLabels.push({
        layer: f.layer.id,
        text,
        x: Math.round(p.x * 10) / 10,
        y: Math.round(p.y * 10) / 10,
      })
    }
  }

  return {
    loaded: styleReady.value,
    viewMode: activeViewMode.value,
    canSwitchView: canSwitchView.value,
    showDevicesOverlay: showDevices.value,
    zoom: map?.getZoom() ?? 0,
    pitch: map?.getPitch() ?? 0,
    bearing: map?.getBearing() ?? 0,
    minZoom: map?.getMinZoom() ?? 0,
    maxZoom: map?.getMaxZoom() ?? 0,
    maxZoomSetting: maxZoomSetting.value,
    maxZoomSpanHint: maxZoomSpanHint.value,
    stageWidth: rect ? Math.round(rect.width) : 0,
    stageHeight: rect ? Math.round(rect.height) : 0,
    globeRadiusPx: Math.round(lastGlobeRadiusPx * 10) / 10,
    globeDiameterRatio,
    legendCollapsed: legendCollapsed.value,
    webglContextLost: webglContextLostCount.value,
    styleReloads: styleReloadCount.value,
    cooperativeGesturesEnabled: Boolean(map?.cooperativeGestures?.isEnabled()),
    isFullPage: isFullLayout.value,
    activeSpiderfyMode: activeSpiderfy.value?.layout.mode ?? null,
    activeSpiderfyFeet: activeSpiderfy.value?.layout.feet.length ?? 0,
    panelOpen: panelOpen.value,
    mobileSheetOpen: mobileSheetOpen.value,
    mobileSnap: mobileSnap.value,
    listPanelCount: listPanelNodes.value.length,
    unlocatedCount: unknownNodesForView.value.length,
    unlocatedCentreCount: unlocatedCentres.value.length,
    backbonePlacedCount: backboneResolved.value.placed.length,
    backboneMgmtPathCount: lastBackboneStats.mgmtPaths,
    backboneLinkCount: lastBackboneStats.links,
    backboneArrowLinkCount: lastBackboneStats.arrows,
    backboneOverlayDeviceCount: lastBackboneStats.overlayDevices,
    displayedLinks: isBackboneView.value ? lastBackboneStats.links : linkAgg.value.displayed.length,
    overflowLinks: isBackboneView.value ? 0 : linkAgg.value.overflowCount,
    restingMixedLinks: linkAgg.value.displayed.filter((l) => l.isMixed).length,
    renderedMarkerLabels,
    renderedBasemapLabels,
    renderEventCounter,
  }
}

defineExpose({
  runPerfBenchmark,
  toggleFullPage: () => fullPage.toggleFullPage(),
  exitFullPage: () => fullPage.exitFullPage(false),
  setViewMode: switchViewMode,
  setShowDevicesOverlay,
  triggerClusterByName,
  selectNodeById,
  focusNodeById,
  focusArcByKey,
  selectFirstLink,
  setMaxZoom: applyMaxZoom,
  setCamera,
  resetView,
  collapseSpiderfy,
  closePanel,
  getDebugState,
  getMap: () => mapRef.value,
})
</script>

<style scoped>
.mh-gv2-placeholder {
  width: 100%;
  position: relative;
}
.mh-gv2-placeholder--standalone {
  width: 100%;
  height: 100%;
  min-height: 0;
  flex: 1 1 0;
}
.mh-gv2-shell {
  position: relative;
  width: 100%;
  border-radius: var(--mh-radius, 10px);
  overflow: hidden;
  border: 1px solid var(--mh-hairline, rgba(128, 128, 128, 0.2));
  background: #060b13;
  font-family: var(--mh-font-sans, system-ui, sans-serif);
}
.mh-gv2-shell--standalone {
  width: 100%;
  height: 100%;
  border-radius: 0;
  border: 0;
}
.mh-gv2-shell--light {
  background: #f5f7fa;
  color: #1f2937;
}
.mh-gv2-shell--dark {
  background: #060b13;
  color: #e6edf6;
}
.mh-gv2-shell--full {
  position: fixed;
  inset: 0;
  z-index: 2000;
  width: 100vw;
  height: 100vh;
  height: 100dvh;
  border-radius: 0;
  border: 0;
}
.mh-gv2-canvas {
  width: 100%;
  height: 100%;
  outline: none;
}
.mh-gv2-fresnel {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  pointer-events: none;
  z-index: 2;
  transition: opacity 150ms ease;
}
/* Do NOT set position: relative here — MapLibre Marker owns position: absolute; top: 0; left: 0. */
.mh-gv2-spiderfy-host,
.mh-gv2-pulse-host {
  pointer-events: none;
}
.mh-gv2-pulse-ring {
  width: 24px;
  height: 24px;
  border-radius: 50%;
  border: 2px solid;
  transform: translate(-50%, -50%) scale(0.45);
  opacity: 0;
  animation: mh-gv2-pulse 900ms cubic-bezier(0.2, 0, 0, 1) 2;
}
@keyframes mh-gv2-pulse {
  0% {
    transform: translate(-50%, -50%) scale(0.45);
    opacity: 0.9;
  }
  100% {
    transform: translate(-50%, -50%) scale(1.65);
    opacity: 0;
  }
}
@media (prefers-reduced-motion: reduce) {
  .mh-gv2-pulse-ring {
    animation: none;
    display: none;
  }
}
/* Mobile full-page 48px top bar (S10) */
.mh-gv2-mobile-topbar {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: calc(48px + env(safe-area-inset-top, 0px));
  padding: env(safe-area-inset-top, 0px) 10px 0 14px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  z-index: 9;
  background: rgba(8, 19, 30, 0.88);
  border-bottom: 1px solid rgba(143, 163, 191, 0.25);
  backdrop-filter: blur(10px);
}
.mh-gv2-shell--light .mh-gv2-mobile-topbar {
  background: rgba(255, 255, 255, 0.92);
  border-bottom-color: rgba(74, 91, 112, 0.2);
}
.mh-gv2-mobile-topbar__title {
  font-weight: 600;
  font-size: 14px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.mh-gv2-mobile-topbar__actions {
  display: flex;
  align-items: center;
  gap: 6px;
}
/* Desktop full-page top-left controls (S9) */
.mh-gv2-full-left {
  position: absolute;
  top: calc(12px + env(safe-area-inset-top, 0px));
  left: calc(12px + env(safe-area-inset-left, 0px));
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  padding: 5px 10px;
  border-radius: 9px;
  background: rgba(8, 19, 30, 0.84);
  border: 1px solid rgba(143, 163, 191, 0.3);
  backdrop-filter: blur(8px);
  z-index: 6;
}
.mh-gv2-shell--light .mh-gv2-full-left {
  background: rgba(255, 255, 255, 0.92);
  border-color: rgba(74, 91, 112, 0.24);
}
.mh-gv2-full-left__title {
  font-weight: 600;
  font-size: 13px;
  padding-right: 4px;
}
.mh-gv2-rtt-filter {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 11px;
}
.mh-gv2-rtt-filter--block {
  display: flex;
  justify-content: space-between;
  margin-top: 8px;
}
.mh-gv2-rtt-filter input[type='range'] {
  width: 96px;
  accent-color: #56b4e9;
}
.mh-gv2-top-actions {
  position: absolute;
  top: calc(12px + env(safe-area-inset-top, 0px));
  right: calc(12px + env(safe-area-inset-right, 0px));
  display: flex;
  gap: 6px;
  z-index: 6;
}
.mh-gv2-icon-btn {
  min-width: 30px;
  height: 30px;
  padding: 0 8px;
  border-radius: 7px;
  border: 1px solid rgba(143, 163, 191, 0.35);
  background: rgba(8, 19, 30, 0.84);
  color: #e6edf6;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  backdrop-filter: blur(8px);
}
.mh-gv2-shell--light .mh-gv2-icon-btn {
  background: rgba(255, 255, 255, 0.9);
  color: #1f2937;
  border-color: rgba(74, 91, 112, 0.28);
}
.mh-gv2-icon-btn:disabled {
  opacity: 0.4;
  cursor: default;
}
.mh-gv2-icon-btn:focus-visible,
.mh-gv2-chip-btn:focus-visible,
.mh-gv2-legend__toggle:focus-visible {
  outline: 2px solid #56b4e9;
  outline-offset: 2px;
}
.mh-gv2-chip-btn {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  height: 26px;
  padding: 0 9px;
  border-radius: 999px;
  border: 1px solid rgba(143, 163, 191, 0.35);
  background: transparent;
  color: inherit;
  font-size: 11px;
  font-weight: 500;
  cursor: pointer;
}
.mh-gv2-chip-btn--active {
  border-color: #56b4e9;
  background: rgba(86, 180, 233, 0.16);
}
.mh-gv2-shell--light .mh-gv2-chip-btn--active {
  border-color: #0072b2;
  background: rgba(0, 114, 178, 0.12);
}
.mh-gv2-settings-popover {
  position: absolute;
  top: calc(48px + env(safe-area-inset-top, 0px));
  right: calc(12px + env(safe-area-inset-right, 0px));
  width: 228px;
  padding: 10px 12px;
  border-radius: 9px;
  background: rgba(8, 19, 30, 0.95);
  color: #e6edf6;
  border: 1px solid rgba(143, 163, 191, 0.35);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.36);
  z-index: 10;
  font-size: 12px;
  backdrop-filter: blur(10px);
}
.mh-gv2-settings-popover--mobile-full {
  top: calc(54px + env(safe-area-inset-top, 0px));
}
.mh-gv2-shell--light .mh-gv2-settings-popover {
  background: rgba(255, 255, 255, 0.97);
  color: #1f2937;
  border-color: rgba(74, 91, 112, 0.25);
}
.mh-gv2-settings-popover__head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 6px;
}
.mh-gv2-settings-popover__label {
  font-weight: 600;
  font-size: 12px;
}
.mh-gv2-settings-popover__val {
  font-size: 12px;
  font-weight: 600;
  font-variant-numeric: tabular-nums;
}
.mh-gv2-settings-popover__slider {
  width: 100%;
  accent-color: #56b4e9;
  cursor: pointer;
}
.mh-gv2-settings-popover__scale {
  display: flex;
  justify-content: space-between;
  font-size: 10px;
  opacity: 0.7;
  margin-top: 1px;
}
.mh-gv2-settings-popover__hint {
  margin-top: 6px;
  font-size: 11px;
  opacity: 0.85;
  line-height: 1.35;
}
.mh-gv2-hover-card {
  position: absolute;
  max-width: 260px;
  padding: 8px 10px;
  border-radius: 8px;
  background: rgba(8, 19, 30, 0.94);
  color: #e6edf6;
  border: 1px solid rgba(143, 163, 191, 0.35);
  font-size: 12px;
  z-index: 8;
  backdrop-filter: blur(8px);
}
.mh-gv2-shell--light .mh-gv2-hover-card {
  background: rgba(255, 255, 255, 0.96);
  color: #1f2937;
  border-color: rgba(74, 91, 112, 0.25);
}
.mh-gv2-hover-card__head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
  margin-bottom: 2px;
}
.mh-gv2-hover-card__title {
  font-weight: 600;
}
.mh-gv2-hover-card__meta,
.mh-gv2-hover-card__extra {
  font-size: 11px;
  opacity: 0.84;
}
.mh-gv2-hover-card__breakdown {
  margin-top: 3px;
  font-size: 10.5px;
  opacity: 0.92;
}
.mh-gv2-badge-mixed {
  display: inline-flex;
  align-items: center;
  padding: 1px 6px;
  border-radius: 999px;
  font-size: 10px;
  font-weight: 600;
  border: 1px solid rgba(169, 182, 200, 0.45);
  background: rgba(169, 182, 200, 0.14);
}
/* Bottom-left legend */
.mh-gv2-legend {
  position: absolute;
  left: calc(12px + env(safe-area-inset-left, 0px));
  bottom: calc(12px + env(safe-area-inset-bottom, 0px));
  max-width: min(460px, calc(100% - 24px));
  padding: 7px 10px;
  border-radius: 8px;
  background: rgba(8, 19, 30, 0.84);
  color: #e6edf6;
  border: 1px solid rgba(143, 163, 191, 0.3);
  font-size: 11px;
  z-index: 5;
  backdrop-filter: blur(8px);
}
.mh-gv2-legend--mobile.mh-gv2-legend--collapsed {
  padding: 4px 10px;
  border-radius: 999px;
}
.mh-gv2-legend--mobile {
  padding: 4px 10px;
  border-radius: 999px;
}
.mh-gv2-legend--above-sheet {
  display: none;
}
.mh-gv2-legend-popover {
  position: absolute;
  left: 0;
  bottom: calc(100% + 8px);
  width: min(320px, calc(100vw - 24px));
  padding: 10px 12px;
  border-radius: 10px;
  background: rgba(8, 19, 30, 0.95);
  color: #e6edf6;
  border: 1px solid rgba(143, 163, 191, 0.35);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.38);
  display: flex;
  flex-direction: column;
  gap: 6px;
  z-index: 10;
  backdrop-filter: blur(10px);
}
.mh-gv2-shell--light .mh-gv2-legend,
.mh-gv2-shell--light .mh-gv2-legend-popover {
  background: rgba(255, 255, 255, 0.92);
  color: #1f2937;
  border-color: rgba(74, 91, 112, 0.24);
}
.mh-gv2-legend__bar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
}
.mh-gv2-legend__toggle {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  background: transparent;
  border: 0;
  color: inherit;
  font-weight: 600;
  font-size: 11px;
  cursor: pointer;
  padding: 2px 0;
}
.mh-gv2-legend__dot-warn {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #e69f00;
}
.mh-gv2-legend__caret {
  opacity: 0.78;
}
.mh-gv2-legend__chips {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 2px;
}
.mh-gv2-chip {
  display: inline-flex;
  align-items: center;
  padding: 2px 7px;
  border-radius: 999px;
  font-size: 11px;
  border: 1px solid rgba(143, 163, 191, 0.35);
  background: transparent;
  color: inherit;
}
.mh-gv2-chip--warn {
  cursor: pointer;
  border-color: #e69f00;
  color: #e69f00;
}
.mh-gv2-shell--light .mh-gv2-chip--warn {
  border-color: #a66300;
  color: #a66300;
}
.mh-gv2-legend__body {
  margin-top: 6px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.mh-gv2-legend__row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
}
.mh-gv2-legend__attr {
  margin-top: 2px;
  font-size: 10px;
  opacity: 0.72;
  line-height: 1.3;
}
.mh-gv2-swatch-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex: 0 0 auto;
}
.mh-gv2-swatch-dot--half {
  background: linear-gradient(90deg, var(--c) 50%, var(--bg) 50%);
  border: 1px solid var(--c);
}
.mh-gv2-swatch-dot--off {
  background: transparent;
  border: 1.5px solid;
}
.mh-gv2-swatch-line {
  display: inline-block;
  width: 14px;
  height: 2px;
  border-radius: 1px;
}
.mh-gv2-swatch-line--dash {
  background: repeating-linear-gradient(90deg, var(--c) 0 5px, transparent 5px 8px);
}
.mh-gv2-swatch-line--short {
  background: repeating-linear-gradient(90deg, var(--c) 0 3px, transparent 3px 6px);
}
.mh-gv2-swatch-line--dot {
  background: repeating-linear-gradient(90deg, var(--c) 0 2px, transparent 2px 5px);
}
.mh-gv2-swatch-mixed {
  font-size: 9px;
  line-height: 1;
}
/* Non-modal right panel (360px desktop, 320px tablet 600–959px, margin 12px) */
.mh-gv2-panel {
  position: absolute;
  top: 52px;
  right: 12px;
  width: 360px;
  max-width: calc(100% - 24px);
  max-height: calc(100% - 68px);
  overflow-y: auto;
  padding: 12px 14px;
  border-radius: 10px;
  background: rgba(8, 19, 30, 0.94);
  color: #e6edf6;
  border: 1px solid rgba(143, 163, 191, 0.35);
  z-index: 7;
  font-size: 12px;
  backdrop-filter: blur(10px);
}
.mh-gv2-panel--tablet {
  width: 320px;
}
.mh-gv2-shell--light .mh-gv2-panel {
  background: rgba(255, 255, 255, 0.96);
  color: #1f2937;
  border-color: rgba(74, 91, 112, 0.24);
}
/* Mobile 3-snap non-modal bottom sheet (S10: 30%, 60%, 92% dvh, min 160px) */
.mh-gv2-panel--mobile {
  top: auto;
  left: 0;
  right: 0;
  bottom: 0;
  width: auto;
  max-width: none;
  min-height: 160px;
  border-radius: 14px 14px 0 0;
  border-bottom: 0;
  padding: 6px 14px calc(12px + env(safe-area-inset-bottom, 0px));
  transition: height 200ms cubic-bezier(0.2, 0, 0, 1);
}
.mh-gv2-panel--snap-peek {
  height: max(160px, 30vh);
  height: max(160px, 30dvh);
  max-height: 30dvh;
}
.mh-gv2-panel--snap-mid {
  height: max(160px, 60vh);
  height: max(160px, 60dvh);
  max-height: 60dvh;
}
.mh-gv2-panel--snap-full {
  height: 92vh;
  height: 92dvh;
  max-height: 92dvh;
}
.mh-gv2-panel__grabber {
  display: flex;
  justify-content: center;
  padding: 6px 0 8px;
  cursor: ns-resize;
  touch-action: none;
}
.mh-gv2-panel__grabber-bar {
  width: 38px;
  height: 4px;
  border-radius: 999px;
  background: rgba(143, 163, 191, 0.55);
}
.mh-gv2-sheet-tabs {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-bottom: 10px;
  border-bottom: 1px solid rgba(143, 163, 191, 0.2);
  padding-bottom: 6px;
}
.mh-gv2-sheet-tab {
  background: transparent;
  border: 0;
  color: inherit;
  opacity: 0.72;
  font-size: 12px;
  font-weight: 600;
  padding: 4px 8px;
  border-radius: 6px;
  cursor: pointer;
}
.mh-gv2-sheet-tab--active {
  opacity: 1;
  background: rgba(86, 180, 233, 0.16);
}
.mh-gv2-sheet-close {
  margin-left: auto;
}
.mh-gv2-panel__head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 8px;
}
.mh-gv2-panel__title-row {
  display: flex;
  align-items: center;
  gap: 7px;
  min-width: 0;
}
.mh-gv2-panel__title {
  font-weight: 600;
  font-size: 13px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.mh-gv2-badges {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
  margin-bottom: 8px;
}
.mh-gv2-badge {
  display: inline-flex;
  align-items: center;
  padding: 1px 7px;
  border-radius: 999px;
  font-size: 10.5px;
  font-weight: 600;
  border: 1px solid rgba(143, 163, 191, 0.35);
}
.mh-gv2-facts {
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 5px;
}
.mh-gv2-fact {
  display: flex;
  justify-content: space-between;
  gap: 10px;
  padding-top: 5px;
  border-top: 1px solid rgba(143, 163, 191, 0.2);
}
.mh-gv2-fact dt {
  opacity: 0.72;
  font-size: 11px;
  flex: 0 0 auto;
}
.mh-gv2-fact dd {
  margin: 0;
  text-align: right;
  font-size: 11.5px;
  word-break: break-word;
}
.mh-gv2-section {
  margin-top: 10px;
  padding-top: 8px;
  border-top: 1px solid rgba(143, 163, 191, 0.22);
}
.mh-gv2-section__title {
  font-size: 11px;
  font-weight: 600;
  opacity: 0.78;
  margin-bottom: 6px;
}
.mh-gv2-note {
  font-size: 11px;
  opacity: 0.8;
  margin-bottom: 8px;
}
.mh-gv2-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
  max-height: 220px;
  overflow-y: auto;
}
.mh-gv2-list--compact {
  max-height: 140px;
}
.mh-gv2-list-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 5px 7px;
  border-radius: 6px;
  border: 1px solid transparent;
  background: rgba(143, 163, 191, 0.08);
  color: inherit;
  cursor: pointer;
  font-size: 11px;
  text-align: left;
}
.mh-gv2-list-row--active {
  border-color: rgba(86, 180, 233, 0.55);
  background: rgba(86, 180, 233, 0.14);
}
.mh-gv2-list-row:hover {
  border-color: rgba(86, 180, 233, 0.45);
}
.mh-gv2-list-row__name {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.mh-gv2-list-row__meta {
  flex: 0 0 auto;
  font-size: 10.5px;
  opacity: 0.9;
}
.mh-gv2-endpoints {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 10px;
}
.mh-gv2-carrier-checks {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.mh-gv2-toggle-row {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  cursor: pointer;
}
.mh-gv2-pager {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  margin-top: 8px;
}
.mh-gv2-primary-btn {
  margin-top: 10px;
  width: 100%;
  padding: 7px 10px;
  border-radius: 7px;
  border: 0;
  background: #0a8f86;
  color: #ffffff;
  font-weight: 600;
  font-size: 12px;
  cursor: pointer;
}
.mh-gv2-context-lost {
  position: absolute;
  inset: 16px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: rgba(6, 11, 19, 0.85);
  color: #e6edf6;
  border-radius: 8px;
  z-index: 20;
  font-weight: 600;
}
/* S12 Segmented Devices / Backbone Switcher */
.mh-gv2-segmented {
  display: inline-flex;
  align-items: center;
  border-radius: 999px;
  border: 1px solid rgba(143, 163, 191, 0.35);
  padding: 2px;
  gap: 2px;
}
.mh-gv2-seg-btn {
  border: 0;
  background: transparent;
  color: inherit;
  font-size: 11px;
  font-weight: 600;
  padding: 3px 9px;
  border-radius: 999px;
  cursor: pointer;
  opacity: 0.78;
}
.mh-gv2-seg-btn--active {
  opacity: 1;
  background: rgba(86, 180, 233, 0.22);
}
.mh-gv2-shell--light .mh-gv2-seg-btn--active {
  background: rgba(0, 114, 178, 0.16);
}
/* S12 Backbone Legend Swatches & Role Badges */
.mh-gv2-chip--centre {
  cursor: pointer;
  border-color: #f59e0b;
  color: #fbbf24;
  font-weight: 600;
}
.mh-gv2-shell--light .mh-gv2-chip--centre {
  border-color: #b45309;
  color: #b45309;
}
.mh-gv2-legend__zone {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.mh-gv2-swatch-diamond {
  display: inline-block;
  width: 8px;
  height: 8px;
  transform: rotate(45deg);
  flex: 0 0 auto;
}
.mh-gv2-swatch-gw {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 2px;
  background: var(--c);
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--c) 45%, transparent);
  margin: 0 2px;
  flex: 0 0 auto;
}
.mh-gv2-swatch-arrow {
  font-size: 11px;
  line-height: 1;
  font-weight: 700;
}
.mh-gv2-badge--centre {
  border-color: #f59e0b;
  color: #fbbf24;
  background: rgba(245, 158, 11, 0.14);
}
.mh-gv2-shell--light .mh-gv2-badge--centre {
  border-color: #b45309;
  color: #92400e;
  background: rgba(217, 119, 6, 0.12);
}
.mh-gv2-badge--gateway {
  border-color: #56b4e9;
  color: #56b4e9;
}
.mh-gv2-shell--light .mh-gv2-badge--gateway {
  border-color: #0072b2;
  color: #0072b2;
}
.mh-gv2-badge--entry {
  border-color: #2bb58a;
  color: #2bb58a;
}
.mh-gv2-shell--light .mh-gv2-badge--entry {
  border-color: #00785a;
  color: #00785a;
}
.mh-gv2-badge--accent {
  border-color: #d98cb8;
  color: #d98cb8;
}
.mh-gv2-shell--light .mh-gv2-badge--accent {
  border-color: #a3527f;
  color: #a3527f;
}
</style>
