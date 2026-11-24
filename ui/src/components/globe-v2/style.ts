// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// MapLibre GL JS v6 style builder and live theme/language updaters (S1/S2/S5/S6 + Fixes #2/#3/#5/#6).
// - Variant L only (Variant A dropped per G4 decision).
// - Omits `glyphs` completely (uses local system + CJK font stack; zero external URLs).
// - Live theme and language switching mutate paint/layout/sky in place with ZERO setStyle().
// - Fix #2: `mh-label-blockers` sits directly below app marker labels and above basemap labels
//   with `icon-allow-overlap: true`, `icon-ignore-placement: false`, `icon-padding: 44`, natively
//   suppressing any basemap label within ~44 px of a cluster or device!
// - Fix #3: Edge-aware marker label layers (`extend-right`, `extend-left`, `extend-both`) ensure
//   0 label pixels clip outside `[4, W-4]`, even on 390 px phones.
// - Fix #5: Crisp coastline + raised dark land fill + `atmosphere-blend: 0` (replaced by a
//   symmetrical 360° Fresnel rim halo synced to globe screen geometry).
// - Fix #6: Calm resting solid links (`mh-links-rest`, 1–1.5 px, 0.45 opacity, majority carrier)
//   vs full-strength carrier-patterned active/ego links (`mh-links-active-*`).

import type { ExpressionSpecification, Map as MapLibreMap, StyleSpecification } from 'maplibre-gl'
import {
  BACKBONE_ARROW_SPACING_PX,
  BACKBONE_DEVICE_DOT_OPACITY,
  BACKBONE_DEVICE_DOT_RADIUS_PX,
} from './backbone'
import { LABEL_BLOCKER_ICON_ID } from './icons'
import {
  getGlobeTokens,
  MAPLIBRE_LOCAL_TEXT_FONT,
  type GlobeLang,
  type GlobeThemeMode,
  type GlobeTokens,
} from './tokens'

export const BOUNDARY_SOURCE_ID = 'mhb'
export const ACCURACY_CIRCLES_SOURCE_ID = 'mh-accuracy-circles'
export const LINKS_SOURCE_ID = 'mh-links'
export const LINK_BADGES_SOURCE_ID = 'mh-link-badges'
export const MARKERS_SOURCE_ID = 'mh-markers'
export const BACKBONE_DEVICES_SOURCE_ID = 'mh-backbone-devices'
export const BACKBONE_MGMT_PATHS_SOURCE_ID = 'mh-backbone-mgmt-paths'
export const BACKBONE_LINKS_SOURCE_ID = 'mh-backbone-links'
export const BACKBONE_ARROWS_SOURCE_ID = 'mh-backbone-arrows'

export const SURFACE_LINK_LAYER_IDS = [
  'mh-links-rest',
  'mh-links-active-direct',
  'mh-links-active-tunnel',
  'mh-links-active-relay',
  'mh-links-active-derp',
  'mh-links-active-blocked',
  'mh-links-active-stalled',
] as const

export const BACKBONE_LINK_LAYER_IDS = [
  'mh-backbone-links-active',
  'mh-backbone-links-disabled',
  'mh-backbone-links-stalled',
] as const

export const DEVICE_VIEW_ONLY_LAYER_IDS = [
  'mh-accuracy-circles',
  ...SURFACE_LINK_LAYER_IDS,
] as const

export const BACKBONE_VIEW_ONLY_LAYER_IDS = [
  'mh-backbone-mgmt-paths',
  ...BACKBONE_LINK_LAYER_IDS,
  'mh-backbone-link-arrows',
] as const

export const BACKBONE_DEVICES_OVERLAY_LAYER_ID = 'mh-backbone-devices-overlay'

export const MARKER_LABEL_LAYER_IDS = [
  'mh-marker-labels-right',
  'mh-marker-labels-left',
  'mh-marker-labels-center',
] as const

export function buildSkySpec(tokens: GlobeTokens) {
  return {
    'sky-color': tokens.space,
    'horizon-color': tokens.horizon,
    'fog-color': tokens.ocean,
    // Keep MapLibre's directional sun-lit atmosphere off so the globe has ZERO harsh top-left glare;
    // a symmetrical 360° Fresnel rim glow SVG synced to the globe silhouette handles the limb halo (Fix #5).
    'atmosphere-blend': 0,
  }
}

export function buildAdmin0TextField(lang: GlobeLang): ExpressionSpecification {
  if (lang === 'zh-CN') {
    return ['coalesce', ['get', 'name_zh_override'], ['get', 'name_zh'], ['get', 'name_en']]
  }
  return ['coalesce', ['get', 'name_en_override'], ['get', 'name_en']]
}

export function buildSubLabelTextField(lang: GlobeLang): ExpressionSpecification {
  if (lang === 'zh-CN') {
    return ['coalesce', ['get', 'name_zh'], ['get', 'name_en']]
  }
  return ['coalesce', ['get', 'name_en'], ['get', 'name_zh']]
}

function buildRestLinkColorExpr(t: GlobeTokens): ExpressionSpecification {
  return [
    'case',
    ['==', ['get', 'stalled'], true],
    t.stalled,
    [
      'match',
      ['get', 'carrier'],
      'direct',
      t.direct,
      'tunnel',
      t.tunnel,
      'relay',
      t.relay,
      'derp',
      t.derp,
      'blocked',
      t.blocked,
      t.direct,
    ],
  ]
}

function buildLinkBadgeColorExpr(t: GlobeTokens): ExpressionSpecification {
  return [
    'match',
    ['get', 'colorKind'],
    'stalled',
    t.stalled,
    'blocked',
    t.blocked,
    'mixed',
    t.labelSecondary,
    t.labelPrimary,
  ]
}

function buildBackboneDeviceColorExpr(t: GlobeTokens): ExpressionSpecification {
  return [
    'match',
    ['get', 'presence'],
    'online',
    t.online,
    'stale',
    t.stale,
    t.offline,
  ]
}

const EMPTY_FC: GeoJSON.FeatureCollection = { type: 'FeatureCollection', features: [] }

export function buildGlobeStyle(
  theme: GlobeThemeMode,
  lang: GlobeLang,
  pmtilesUrl: string,
  isMobile = false,
  initialViewMode: 'devices' | 'backbone' = 'devices',
): StyleSpecification {
  const t = getGlobeTokens(theme)
  const [op0, op1, op2] = t.borderOpacity
  const coastOpacity = theme === 'dark' ? 0.82 : 0.85
  const devVis: 'visible' | 'none' = initialViewMode === 'devices' ? 'visible' : 'none'
  const bbVis: 'visible' | 'none' = initialViewMode === 'backbone' ? 'visible' : 'none'

  return {
    version: 8,
    name: 'meshharbor-globe-v2',
    projection: { type: 'globe' },
    sky: buildSkySpec(t),
    // NOTE: `glyphs` is intentionally OMITTED (S1/S2 — MapLibre 5.11+/6.x uses local system fonts).
    sources: {
      [BOUNDARY_SOURCE_ID]: {
        type: 'vector',
        url: `pmtiles://${pmtilesUrl}`,
      },
      [ACCURACY_CIRCLES_SOURCE_ID]: {
        type: 'geojson',
        data: EMPTY_FC,
      },
      [BACKBONE_DEVICES_SOURCE_ID]: {
        type: 'geojson',
        data: EMPTY_FC,
      },
      [LINKS_SOURCE_ID]: {
        type: 'geojson',
        data: EMPTY_FC,
      },
      [BACKBONE_MGMT_PATHS_SOURCE_ID]: {
        type: 'geojson',
        data: EMPTY_FC,
      },
      [BACKBONE_LINKS_SOURCE_ID]: {
        type: 'geojson',
        data: EMPTY_FC,
      },
      [BACKBONE_ARROWS_SOURCE_ID]: {
        type: 'geojson',
        data: EMPTY_FC,
      },
      [LINK_BADGES_SOURCE_ID]: {
        type: 'geojson',
        data: EMPTY_FC,
      },
      [MARKERS_SOURCE_ID]: {
        type: 'geojson',
        data: EMPTY_FC,
      },
    },
    layers: [
      {
        id: 'background',
        type: 'background',
        paint: { 'background-color': t.ocean },
      },
      {
        id: 'land-low',
        type: 'fill',
        source: BOUNDARY_SOURCE_ID,
        'source-layer': 'land_low',
        maxzoom: 3,
        paint: { 'fill-color': t.land, 'fill-antialias': true },
      },
      {
        id: 'land-high',
        type: 'fill',
        source: BOUNDARY_SOURCE_ID,
        'source-layer': 'land_high',
        minzoom: 3,
        paint: { 'fill-color': t.land, 'fill-antialias': true },
      },
      {
        id: 'coast-low',
        type: 'line',
        source: BOUNDARY_SOURCE_ID,
        'source-layer': 'coast_low',
        maxzoom: 3,
        paint: {
          'line-color': t.coast,
          'line-opacity': coastOpacity,
          'line-width': ['interpolate', ['linear'], ['zoom'], 0, 0.75, 4, 0.9, 14, 1.1],
        },
      },
      {
        id: 'coast-high',
        type: 'line',
        source: BOUNDARY_SOURCE_ID,
        'source-layer': 'coast_high',
        minzoom: 3,
        paint: {
          'line-color': t.coast,
          'line-opacity': coastOpacity,
          'line-width': ['interpolate', ['linear'], ['zoom'], 0, 0.75, 4, 0.9, 14, 1.1],
        },
      },
      // Admin-2 non-China (z5.5->6.5 fade, crisp overzoom to z14)
      {
        id: 'admin2-other',
        type: 'line',
        source: BOUNDARY_SOURCE_ID,
        'source-layer': 'admin2',
        minzoom: 5,
        filter: ['!=', ['get', 'cc'], 'CHN'],
        paint: {
          'line-color': t.border,
          'line-opacity': ['interpolate', ['linear'], ['zoom'], 5.5, 0, 6.5, op2],
          'line-width': ['interpolate', ['linear'], ['zoom'], 5, 0.35, 8, 0.55, 11, 0.75, 14, 0.9],
        },
      },
      // China 4-level boundaries: district/county (区县界) fades in z8->9; thin overzoom to z14
      {
        id: 'admin2-chn',
        type: 'line',
        source: BOUNDARY_SOURCE_ID,
        'source-layer': 'admin2',
        minzoom: 8,
        filter: ['==', ['get', 'cc'], 'CHN'],
        paint: {
          'line-color': t.border,
          'line-opacity': ['interpolate', ['linear'], ['zoom'], 8, 0, 9, op2],
          'line-width': ['interpolate', ['linear'], ['zoom'], 8, 0.35, 10, 0.5, 12, 0.65, 14, 0.75],
        },
      },
      // China 4-level boundaries: prefecture-level city (市界) fades in z5->6.5 above county lines
      {
        id: 'admin2-pref-chn',
        type: 'line',
        source: BOUNDARY_SOURCE_ID,
        'source-layer': 'admin2_pref',
        minzoom: 5,
        paint: {
          'line-color': t.border,
          'line-opacity': ['interpolate', ['linear'], ['zoom'], 5, 0, 6.5, Math.min(1, op2 * 1.45)],
          'line-width': ['interpolate', ['linear'], ['zoom'], 5, 0.45, 8, 0.65, 11, 0.85, 14, 1.0],
        },
      },
      // Admin-1 internal shared lines (z2->3 fade)
      {
        id: 'admin1',
        type: 'line',
        source: BOUNDARY_SOURCE_ID,
        'source-layer': 'admin1',
        minzoom: 2,
        paint: {
          'line-color': t.border,
          'line-opacity': ['interpolate', ['linear'], ['zoom'], 2, 0, 3, op1],
          'line-width': ['interpolate', ['linear'], ['zoom'], 0, 0.4, 4, 0.6, 9, 0.9, 14, 1.1],
        },
      },
      // Admin-0 de facto international / disputed / limit lines (drawn above admin1 & admin2)
      {
        id: 'admin0-intl',
        type: 'line',
        source: BOUNDARY_SOURCE_ID,
        'source-layer': 'admin0',
        filter: ['==', ['get', 'cls'], 'intl'],
        paint: {
          'line-color': t.border,
          'line-opacity': op0,
          'line-width': ['interpolate', ['linear'], ['zoom'], 0, 0.6, 4, 0.9, 9, 1.3, 14, 1.6],
        },
      },
      {
        id: 'admin0-disputed',
        type: 'line',
        source: BOUNDARY_SOURCE_ID,
        'source-layer': 'admin0',
        filter: ['==', ['get', 'cls'], 'disputed'],
        paint: {
          'line-color': t.border,
          'line-opacity': op0,
          'line-width': ['interpolate', ['linear'], ['zoom'], 0, 0.6, 4, 0.9, 9, 1.3, 14, 1.6],
          'line-dasharray': [3, 2],
        },
      },
      {
        id: 'admin0-limit',
        type: 'line',
        source: BOUNDARY_SOURCE_ID,
        'source-layer': 'admin0',
        minzoom: 3,
        filter: ['==', ['get', 'cls'], 'limit'],
        layout: { 'line-cap': 'round' },
        paint: {
          'line-color': t.border,
          'line-opacity': op0 * 0.8,
          'line-width': ['interpolate', ['linear'], ['zoom'], 3, 0.6, 9, 0.9, 14, 1.1],
          'line-dasharray': [0, 2],
        },
      },
      // S7 coords accuracy circles (z >= 3, 1 px, 25% opacity dashed 64-gon)
      {
        id: 'mh-accuracy-circles',
        type: 'line',
        source: ACCURACY_CIRCLES_SOURCE_ID,
        minzoom: 3,
        layout: { visibility: devVis },
        paint: {
          'line-color': t.online,
          'line-width': 1,
          'line-opacity': 0.25,
          'line-dasharray': [3, 3],
        },
      },
      // S12 optional Devices overlay (OFF by default; 3 px dot @ 35% opacity, NO labels)
      {
        id: BACKBONE_DEVICES_OVERLAY_LAYER_ID,
        type: 'circle',
        source: BACKBONE_DEVICES_SOURCE_ID,
        layout: { visibility: 'none' },
        paint: {
          'circle-radius': BACKBONE_DEVICE_DOT_RADIUS_PX,
          'circle-opacity': BACKBONE_DEVICE_DOT_OPACITY,
          'circle-color': buildBackboneDeviceColorExpr(t),
          'circle-stroke-width': 0,
        },
      },
      // Fix #6: Calm resting peer links (1–1.5 px, ~0.45 opacity, solid, majority-carrier color)
      {
        id: 'mh-links-rest',
        type: 'line',
        source: LINKS_SOURCE_ID,
        filter: ['==', ['get', 'active'], false],
        layout: { visibility: devVis, 'line-cap': 'round', 'line-join': 'round' },
        paint: {
          'line-color': buildRestLinkColorExpr(t),
          'line-width': ['get', 'width'],
          'line-opacity': ['get', 'opacity'],
        },
      },
      // Fix #6 / S5: Full-strength carrier-patterned layers for hover / selection / ego network ONLY
      {
        id: 'mh-links-active-direct',
        type: 'line',
        source: LINKS_SOURCE_ID,
        filter: [
          'all',
          ['==', ['get', 'active'], true],
          ['==', ['get', 'carrier'], 'direct'],
          ['!', ['get', 'stalled']],
        ],
        layout: { visibility: devVis, 'line-cap': 'round', 'line-join': 'round' },
        paint: {
          'line-color': t.direct,
          'line-width': ['get', 'width'],
          'line-opacity': ['get', 'opacity'],
        },
      },
      {
        id: 'mh-links-active-tunnel',
        type: 'line',
        source: LINKS_SOURCE_ID,
        filter: [
          'all',
          ['==', ['get', 'active'], true],
          ['==', ['get', 'carrier'], 'tunnel'],
          ['!', ['get', 'stalled']],
        ],
        layout: { visibility: devVis, 'line-cap': 'round', 'line-join': 'round' },
        paint: {
          'line-color': t.tunnel,
          'line-width': 0.75,
          'line-gap-width': 1.5,
          'line-opacity': ['get', 'opacity'],
        },
      },
      {
        id: 'mh-links-active-relay',
        type: 'line',
        source: LINKS_SOURCE_ID,
        filter: [
          'all',
          ['==', ['get', 'active'], true],
          ['==', ['get', 'carrier'], 'relay'],
          ['!', ['get', 'stalled']],
        ],
        layout: { visibility: devVis, 'line-cap': 'butt', 'line-join': 'round' },
        paint: {
          'line-color': t.relay,
          'line-width': ['get', 'width'],
          'line-opacity': ['get', 'opacity'],
          'line-dasharray': [4, 3],
        },
      },
      {
        id: 'mh-links-active-derp',
        type: 'line',
        source: LINKS_SOURCE_ID,
        filter: [
          'all',
          ['==', ['get', 'active'], true],
          ['==', ['get', 'carrier'], 'derp'],
          ['!', ['get', 'stalled']],
        ],
        layout: { visibility: devVis, 'line-cap': 'butt', 'line-join': 'round' },
        paint: {
          'line-color': t.derp,
          'line-width': ['get', 'width'],
          'line-opacity': ['get', 'opacity'],
          'line-dasharray': [2, 2],
        },
      },
      {
        id: 'mh-links-active-blocked',
        type: 'line',
        source: LINKS_SOURCE_ID,
        filter: [
          'all',
          ['==', ['get', 'active'], true],
          ['==', ['get', 'carrier'], 'blocked'],
          ['!', ['get', 'stalled']],
        ],
        layout: { visibility: devVis, 'line-cap': 'round', 'line-join': 'round' },
        paint: {
          'line-color': t.blocked,
          'line-width': ['get', 'width'],
          'line-opacity': ['get', 'opacity'],
          'line-dasharray': [0, 2.5],
        },
      },
      {
        id: 'mh-links-active-stalled',
        type: 'line',
        source: LINKS_SOURCE_ID,
        filter: ['all', ['==', ['get', 'active'], true], ['==', ['get', 'stalled'], true]],
        layout: { visibility: devVis, 'line-cap': 'round', 'line-join': 'round' },
        paint: {
          'line-color': t.stalled,
          'line-width': ['get', 'width'],
          'line-opacity': ['get', 'opacity'],
          'line-dasharray': [0, 2],
        },
      },
      // S12 FR-134 Management path: gateway -> centre, 2 px solid zone-color great-circle line
      {
        id: 'mh-backbone-mgmt-paths',
        type: 'line',
        source: BACKBONE_MGMT_PATHS_SOURCE_ID,
        layout: { visibility: bbVis, 'line-cap': 'round', 'line-join': 'round' },
        paint: {
          'line-color': ['get', 'color'],
          'line-width': ['get', 'width'],
          'line-opacity': ['get', 'opacity'],
          'line-offset': ['get', 'offset'],
        },
      },
      // S12 Backbone disabled links: 1.5 px muted dashed [2, 2]
      {
        id: 'mh-backbone-links-disabled',
        type: 'line',
        source: BACKBONE_LINKS_SOURCE_ID,
        filter: ['==', ['get', 'state'], 'disabled'],
        layout: { visibility: bbVis, 'line-cap': 'butt', 'line-join': 'round' },
        paint: {
          'line-color': t.offline,
          'line-width': ['get', 'width'],
          'line-opacity': ['get', 'opacity'],
          'line-dasharray': [2, 2],
        },
      },
      // S12 Backbone active links: 2.5 px #E6EDF6 dark / #1F2937 light @ 0.8 opacity
      {
        id: 'mh-backbone-links-active',
        type: 'line',
        source: BACKBONE_LINKS_SOURCE_ID,
        filter: ['==', ['get', 'state'], 'active'],
        layout: { visibility: bbVis, 'line-cap': 'round', 'line-join': 'round' },
        paint: {
          'line-color': t.labelPrimary,
          'line-width': ['get', 'width'],
          'line-opacity': ['get', 'opacity'],
        },
      },
      // S12 Backbone stalled links: R7 stalled dotted [0, 2] round cap
      {
        id: 'mh-backbone-links-stalled',
        type: 'line',
        source: BACKBONE_LINKS_SOURCE_ID,
        filter: ['==', ['get', 'state'], 'stalled'],
        layout: { visibility: bbVis, 'line-cap': 'round', 'line-join': 'round' },
        paint: {
          'line-color': t.stalled,
          'line-width': ['get', 'width'],
          'line-opacity': ['get', 'opacity'],
          'line-dasharray': [0, 2],
        },
      },
      // S12 Unidirectional backbone link arrows every 120 px along the line
      {
        id: 'mh-backbone-link-arrows',
        type: 'symbol',
        source: BACKBONE_ARROWS_SOURCE_ID,
        layout: {
          visibility: bbVis,
          'symbol-placement': 'line',
          'symbol-spacing': BACKBONE_ARROW_SPACING_PX,
          'icon-image': ['get', 'arrowIcon'],
          'icon-rotation-alignment': 'map',
          'icon-allow-overlap': true,
          'icon-ignore-placement': true,
        },
        paint: {
          'icon-opacity': ['get', 'opacity'],
        },
      },
      // Basemap labels — rendered BELOW `mh-label-blockers` and `mh-marker-labels-*` so
      // MapLibre's reverse-order collision engine gives cluster/device labels 100% priority (Fix #2).
      // District/county names (z9-11+): lowest priority basemap symbol layer
      {
        id: 'label-admin2',
        type: 'symbol',
        source: BOUNDARY_SOURCE_ID,
        'source-layer': 'label_admin2',
        minzoom: 9,
        layout: {
          'text-field': buildSubLabelTextField(lang),
          'text-font': MAPLIBRE_LOCAL_TEXT_FONT,
          'text-size': 10,
          'text-padding': 6,
          'text-allow-overlap': false,
        },
        paint: {
          'text-color': t.labelMuted,
          'text-halo-color': t.labelHalo,
          'text-halo-width': 1.5,
        },
      },
      // Place labels below z8 only so they never sit next to admin labels (e.g. "北京市" + "北京") at z8-10
      {
        id: 'label-place',
        type: 'symbol',
        source: BOUNDARY_SOURCE_ID,
        'source-layer': 'label_place',
        minzoom: isMobile ? 5 : 4,
        maxzoom: 8,
        filter: ['<=', ['-', ['get', 'min_zoom'], 1], ['zoom']],
        layout: {
          'text-field': buildSubLabelTextField(lang),
          'text-font': MAPLIBRE_LOCAL_TEXT_FONT,
          'text-size': 10,
          'text-padding': 6,
          'symbol-sort-key': ['*', -1, ['coalesce', ['get', 'pop'], 0]],
        },
        paint: {
          'text-color': t.labelMuted,
          'text-halo-color': t.labelHalo,
          'text-halo-width': 1.5,
        },
      },
      {
        id: 'label-admin1',
        type: 'symbol',
        source: BOUNDARY_SOURCE_ID,
        'source-layer': 'label_admin1',
        minzoom: 3.5,
        layout: {
          'text-field': buildSubLabelTextField(lang),
          'text-font': MAPLIBRE_LOCAL_TEXT_FONT,
          'text-size': 10,
          'text-padding': 6,
        },
        paint: {
          'text-color': t.labelMuted,
          'text-halo-color': t.labelHalo,
          'text-halo-width': 1.5,
        },
      },
      {
        id: 'label-admin0',
        type: 'symbol',
        source: BOUNDARY_SOURCE_ID,
        'source-layer': 'label_admin0',
        minzoom: 0.6,
        maxzoom: 6.5,
        filter: ['<=', ['-', ['get', 'min_label'], 1], ['zoom']],
        layout: {
          'text-field': buildAdmin0TextField(lang),
          'text-font': MAPLIBRE_LOCAL_TEXT_FONT,
          'text-size': 11,
          'text-padding': 6,
          'symbol-sort-key': ['*', -1, ['coalesce', ['get', 'pop'], 0]],
        },
        paint: {
          'text-color': t.labelSecondary,
          'text-halo-color': t.labelHalo,
          'text-halo-width': 1.5,
        },
      },
      // Link midpoint badges (⚠ stalled, × blocked, ◆ mixed, hover/ego RTT)
      {
        id: 'mh-link-badges',
        type: 'symbol',
        source: LINK_BADGES_SOURCE_ID,
        layout: {
          'text-field': ['get', 'badge'],
          'text-font': MAPLIBRE_LOCAL_TEXT_FONT,
          'text-size': ['match', ['get', 'colorKind'], 'mixed', 8, 10],
          'text-padding': 4,
          'text-allow-overlap': false,
          'text-ignore-placement': false,
        },
        paint: {
          'text-color': buildLinkBadgeColorExpr(t),
          'text-opacity': ['match', ['get', 'colorKind'], 'mixed', 0.65, 1],
          'text-halo-color': t.labelHalo,
          'text-halo-width': 1.5,
        },
      },
      // Fix #2: Invisible ±44 px collision reservation around EVERY cluster/device marker.
      // Placed AFTER app marker labels in reverse-order placement, BEFORE basemap labels:
      // never blocks app markers/labels, ALWAYS suppresses basemap labels within ~44 px!
      {
        id: 'mh-label-blockers',
        type: 'symbol',
        source: MARKERS_SOURCE_ID,
        layout: {
          'icon-image': LABEL_BLOCKER_ICON_ID,
          'icon-allow-overlap': true,
          'icon-ignore-placement': false,
          'icon-padding': 44,
        },
        paint: {
          'icon-opacity': 0,
        },
      },
      // Fix #3: Edge-aware marker text label layers (never clip off left/right viewport edge).
      {
        id: 'mh-marker-labels-right',
        type: 'symbol',
        source: MARKERS_SOURCE_ID,
        filter: ['all', ['==', ['get', 'edgePlacement'], 'extend-right'], ['!=', ['get', 'label'], '']],
        layout: {
          'text-field': ['get', 'label'],
          'text-font': MAPLIBRE_LOCAL_TEXT_FONT,
          'text-size': 11,
          'text-variable-anchor': ['left', 'top-left', 'bottom-left'],
          'text-radial-offset': 1.55,
          'text-padding': 8,
          'text-allow-overlap': false,
          'text-optional': false,
          'symbol-sort-key': ['get', 'sortKey'],
        },
        paint: {
          'text-opacity': ['get', 'opacity'],
          'text-color': t.labelPrimary,
          'text-halo-color': t.labelHalo,
          'text-halo-width': 1.6,
        },
      },
      {
        id: 'mh-marker-labels-left',
        type: 'symbol',
        source: MARKERS_SOURCE_ID,
        filter: ['all', ['==', ['get', 'edgePlacement'], 'extend-left'], ['!=', ['get', 'label'], '']],
        layout: {
          'text-field': ['get', 'label'],
          'text-font': MAPLIBRE_LOCAL_TEXT_FONT,
          'text-size': 11,
          'text-variable-anchor': ['right', 'top-right', 'bottom-right'],
          'text-radial-offset': 1.55,
          'text-padding': 8,
          'text-allow-overlap': false,
          'text-optional': false,
          'symbol-sort-key': ['get', 'sortKey'],
        },
        paint: {
          'text-opacity': ['get', 'opacity'],
          'text-color': t.labelPrimary,
          'text-halo-color': t.labelHalo,
          'text-halo-width': 1.6,
        },
      },
      {
        id: 'mh-marker-labels-center',
        type: 'symbol',
        source: MARKERS_SOURCE_ID,
        filter: ['all', ['==', ['get', 'edgePlacement'], 'extend-both'], ['!=', ['get', 'label'], '']],
        layout: {
          'text-field': ['get', 'label'],
          'text-font': MAPLIBRE_LOCAL_TEXT_FONT,
          'text-size': 11,
          'text-variable-anchor': [
            'left',
            'right',
            'top',
            'bottom',
            'top-left',
            'top-right',
            'bottom-left',
            'bottom-right',
          ],
          'text-radial-offset': 1.55,
          'text-padding': 8,
          'text-allow-overlap': false,
          'text-optional': false,
          'symbol-sort-key': ['get', 'sortKey'],
        },
        paint: {
          'text-opacity': ['get', 'opacity'],
          'text-color': t.labelPrimary,
          'text-halo-color': t.labelHalo,
          'text-halo-width': 1.6,
        },
      },
      // Tight ±12 px icon reservation ABOVE marker labels so labels flip cleanly around neighboring donuts!
      {
        id: 'mh-marker-icon-blockers',
        type: 'symbol',
        source: MARKERS_SOURCE_ID,
        layout: {
          'icon-image': LABEL_BLOCKER_ICON_ID,
          'icon-allow-overlap': true,
          'icon-ignore-placement': false,
          'icon-padding': 11,
        },
        paint: {
          'icon-opacity': 0,
        },
      },
      // Application marker icons (topmost; never hidden by symbol collision per S3)
      {
        id: 'mh-markers',
        type: 'symbol',
        source: MARKERS_SOURCE_ID,
        layout: {
          'icon-image': ['get', 'icon'],
          'icon-allow-overlap': true,
          'icon-ignore-placement': true,
          'symbol-sort-key': ['get', 'sortKey'],
        },
        paint: {
          'icon-opacity': ['get', 'opacity'],
        },
      },
    ],
  }
}

/**
 * Live theme switch via setPaintProperty + setSky with ZERO setStyle() reload (S6 / AC10).
 */
export function applyThemeToMap(map: MapLibreMap, theme: GlobeThemeMode): void {
  const t = getGlobeTokens(theme)
  const [op0, op1, op2] = t.borderOpacity
  const coastOpacity = theme === 'dark' ? 0.82 : 0.85

  map.setSky(buildSkySpec(t))
  map.setPaintProperty('background', 'background-color', t.ocean)
  map.setPaintProperty('land-low', 'fill-color', t.land)
  map.setPaintProperty('land-high', 'fill-color', t.land)
  map.setPaintProperty('coast-low', 'line-color', t.coast)
  map.setPaintProperty('coast-low', 'line-opacity', coastOpacity)
  map.setPaintProperty('coast-high', 'line-color', t.coast)
  map.setPaintProperty('coast-high', 'line-opacity', coastOpacity)

  map.setPaintProperty('admin2-other', 'line-color', t.border)
  map.setPaintProperty('admin2-other', 'line-opacity', ['interpolate', ['linear'], ['zoom'], 5.5, 0, 6.5, op2])
  map.setPaintProperty('admin2-chn', 'line-color', t.border)
  map.setPaintProperty('admin2-chn', 'line-opacity', ['interpolate', ['linear'], ['zoom'], 8, 0, 9, op2])
  if (map.getLayer('admin2-pref-chn')) {
    map.setPaintProperty('admin2-pref-chn', 'line-color', t.border)
    map.setPaintProperty('admin2-pref-chn', 'line-opacity', [
      'interpolate',
      ['linear'],
      ['zoom'],
      5,
      0,
      6.5,
      Math.min(1, op2 * 1.45),
    ])
  }
  map.setPaintProperty('admin1', 'line-color', t.border)
  map.setPaintProperty('admin1', 'line-opacity', ['interpolate', ['linear'], ['zoom'], 2, 0, 3, op1])
  map.setPaintProperty('admin0-intl', 'line-color', t.border)
  map.setPaintProperty('admin0-intl', 'line-opacity', op0)
  map.setPaintProperty('admin0-disputed', 'line-color', t.border)
  map.setPaintProperty('admin0-disputed', 'line-opacity', op0)
  map.setPaintProperty('admin0-limit', 'line-color', t.border)
  map.setPaintProperty('admin0-limit', 'line-opacity', op0 * 0.8)

  if (map.getLayer('mh-accuracy-circles')) {
    map.setPaintProperty('mh-accuracy-circles', 'line-color', t.online)
  }
  if (map.getLayer(BACKBONE_DEVICES_OVERLAY_LAYER_ID)) {
    map.setPaintProperty(BACKBONE_DEVICES_OVERLAY_LAYER_ID, 'circle-color', buildBackboneDeviceColorExpr(t))
  }

  map.setPaintProperty('mh-links-rest', 'line-color', buildRestLinkColorExpr(t))
  map.setPaintProperty('mh-links-active-direct', 'line-color', t.direct)
  map.setPaintProperty('mh-links-active-tunnel', 'line-color', t.tunnel)
  map.setPaintProperty('mh-links-active-relay', 'line-color', t.relay)
  map.setPaintProperty('mh-links-active-derp', 'line-color', t.derp)
  map.setPaintProperty('mh-links-active-blocked', 'line-color', t.blocked)
  map.setPaintProperty('mh-links-active-stalled', 'line-color', t.stalled)

  if (map.getLayer('mh-backbone-links-active')) {
    map.setPaintProperty('mh-backbone-links-active', 'line-color', t.labelPrimary)
  }
  if (map.getLayer('mh-backbone-links-disabled')) {
    map.setPaintProperty('mh-backbone-links-disabled', 'line-color', t.offline)
  }
  if (map.getLayer('mh-backbone-links-stalled')) {
    map.setPaintProperty('mh-backbone-links-stalled', 'line-color', t.stalled)
  }

  if (map.getLayer('label-admin2')) {
    map.setPaintProperty('label-admin2', 'text-color', t.labelMuted)
    map.setPaintProperty('label-admin2', 'text-halo-color', t.labelHalo)
  }
  map.setPaintProperty('label-place', 'text-color', t.labelMuted)
  map.setPaintProperty('label-place', 'text-halo-color', t.labelHalo)
  map.setPaintProperty('label-admin1', 'text-color', t.labelMuted)
  map.setPaintProperty('label-admin1', 'text-halo-color', t.labelHalo)
  map.setPaintProperty('label-admin0', 'text-color', t.labelSecondary)
  map.setPaintProperty('label-admin0', 'text-halo-color', t.labelHalo)

  map.setPaintProperty('mh-link-badges', 'text-color', buildLinkBadgeColorExpr(t))
  map.setPaintProperty('mh-link-badges', 'text-halo-color', t.labelHalo)

  for (const id of MARKER_LABEL_LAYER_IDS) {
    if (map.getLayer(id)) {
      map.setPaintProperty(id, 'text-color', t.labelPrimary)
      map.setPaintProperty(id, 'text-halo-color', t.labelHalo)
    }
  }
}

/**
 * Switch layer visibility between `'devices'` and `'backbone'` on the SAME MapLibre Map
 * instance with ZERO `setStyle()` reload (S12).
 */
export function applyViewModeLayerVisibility(
  map: MapLibreMap,
  viewMode: 'devices' | 'backbone',
  showDevicesOverlay = false,
): void {
  const devVis = viewMode === 'devices' ? 'visible' : 'none'
  const bbVis = viewMode === 'backbone' ? 'visible' : 'none'
  const overlayVis = viewMode === 'backbone' && showDevicesOverlay ? 'visible' : 'none'

  for (const id of DEVICE_VIEW_ONLY_LAYER_IDS) {
    if (map.getLayer(id)) map.setLayoutProperty(id, 'visibility', devVis)
  }
  for (const id of BACKBONE_VIEW_ONLY_LAYER_IDS) {
    if (map.getLayer(id)) map.setLayoutProperty(id, 'visibility', bbVis)
  }
  if (map.getLayer(BACKBONE_DEVICES_OVERLAY_LAYER_ID)) {
    map.setLayoutProperty(BACKBONE_DEVICES_OVERLAY_LAYER_ID, 'visibility', overlayVis)
  }
}

/**
 * Live language switch via setLayoutProperty with ZERO setStyle() reload (S6 / AC10).
 */
export function applyLangToMap(map: MapLibreMap, lang: GlobeLang): void {
  map.setLayoutProperty('label-admin0', 'text-field', buildAdmin0TextField(lang))
  map.setLayoutProperty('label-admin1', 'text-field', buildSubLabelTextField(lang))
  map.setLayoutProperty('label-place', 'text-field', buildSubLabelTextField(lang))
  if (map.getLayer('label-admin2')) {
    map.setLayoutProperty('label-admin2', 'text-field', buildSubLabelTextField(lang))
  }
}
