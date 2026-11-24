// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// MapLibre GL JS v6 style builder and live theme/language updaters (S1/S2/S5/S6).
// - Omits `glyphs` completely (uses local system + CJK font stack; zero external URLs).
// - Live theme and language switching mutate paint/layout/sky in place with ZERO setStyle().

import type { ExpressionSpecification, Map as MapLibreMap, StyleSpecification } from 'maplibre-gl'
import {
  getGlobeTokens,
  MAPLIBRE_LOCAL_TEXT_FONT,
  type GlobeLang,
  type GlobeThemeMode,
  type GlobeTokens,
} from './tokens'

export const BOUNDARY_SOURCE_ID = 'mhb'
export const LINKS_SOURCE_ID = 'mh-links'
export const LINK_BADGES_SOURCE_ID = 'mh-link-badges'
export const MARKERS_SOURCE_ID = 'mh-markers'

export const SURFACE_LINK_LAYER_IDS = [
  'mh-links-direct',
  'mh-links-tunnel',
  'mh-links-relay',
  'mh-links-derp',
  'mh-links-blocked',
  'mh-links-stalled',
] as const

export function buildSkySpec(tokens: GlobeTokens) {
  return {
    'sky-color': tokens.space,
    'horizon-color': tokens.horizon,
    'fog-color': tokens.ocean,
    'atmosphere-blend': ['interpolate', ['linear'], ['zoom'], 0, 1, 4, 1, 6, 0] as ExpressionSpecification,
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

const EMPTY_FC: GeoJSON.FeatureCollection = { type: 'FeatureCollection', features: [] }

export function buildGlobeStyle(
  theme: GlobeThemeMode,
  lang: GlobeLang,
  pmtilesUrl: string,
  isMobile = false,
): StyleSpecification {
  const t = getGlobeTokens(theme)
  const [op0, op1, op2] = t.borderOpacity

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
      [LINKS_SOURCE_ID]: {
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
          'line-width': ['interpolate', ['linear'], ['zoom'], 0, 0.5, 4, 0.7, 9, 0.9],
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
          'line-width': ['interpolate', ['linear'], ['zoom'], 0, 0.5, 4, 0.7, 9, 0.9],
        },
      },
      // Admin-2 (non-China fades z5->6; China fades z6->7 per S6 top-level zoom expression rule)
      {
        id: 'admin2-other',
        type: 'line',
        source: BOUNDARY_SOURCE_ID,
        'source-layer': 'admin2',
        minzoom: 5,
        filter: ['!=', ['get', 'cc'], 'CHN'],
        paint: {
          'line-color': t.border,
          'line-opacity': ['interpolate', ['linear'], ['zoom'], 5, 0, 6, op2],
          'line-width': ['interpolate', ['linear'], ['zoom'], 5, 0.35, 7, 0.5, 9, 0.7],
        },
      },
      {
        id: 'admin2-chn',
        type: 'line',
        source: BOUNDARY_SOURCE_ID,
        'source-layer': 'admin2',
        minzoom: 5,
        filter: ['==', ['get', 'cc'], 'CHN'],
        paint: {
          'line-color': t.border,
          'line-opacity': ['interpolate', ['linear'], ['zoom'], 6, 0, 7, op2],
          'line-width': ['interpolate', ['linear'], ['zoom'], 5, 0.35, 7, 0.5, 9, 0.7],
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
          'line-width': ['interpolate', ['linear'], ['zoom'], 0, 0.4, 4, 0.6, 9, 0.9],
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
          'line-width': ['interpolate', ['linear'], ['zoom'], 0, 0.6, 4, 0.9, 9, 1.3],
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
          'line-width': ['interpolate', ['linear'], ['zoom'], 0, 0.6, 4, 0.9, 9, 1.3],
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
          'line-width': ['interpolate', ['linear'], ['zoom'], 3, 0.6, 9, 0.9],
          'line-dasharray': [0, 2],
        },
      },
      // Application peer link layers (Variant L; hidden below z5 when Variant A elevated arcs are active)
      {
        id: 'mh-links-direct',
        type: 'line',
        source: LINKS_SOURCE_ID,
        filter: ['all', ['==', ['get', 'carrier'], 'direct'], ['!', ['get', 'stalled']]],
        layout: { 'line-cap': 'round', 'line-join': 'round' },
        paint: {
          'line-color': t.direct,
          'line-width': ['get', 'width'],
          'line-opacity': ['get', 'opacity'],
        },
      },
      {
        id: 'mh-links-tunnel',
        type: 'line',
        source: LINKS_SOURCE_ID,
        filter: ['all', ['==', ['get', 'carrier'], 'tunnel'], ['!', ['get', 'stalled']]],
        layout: { 'line-cap': 'round', 'line-join': 'round' },
        paint: {
          'line-color': t.tunnel,
          'line-width': 0.75,
          'line-gap-width': 1.5,
          'line-opacity': ['get', 'opacity'],
        },
      },
      {
        id: 'mh-links-relay',
        type: 'line',
        source: LINKS_SOURCE_ID,
        filter: ['all', ['==', ['get', 'carrier'], 'relay'], ['!', ['get', 'stalled']]],
        layout: { 'line-cap': 'butt', 'line-join': 'round' },
        paint: {
          'line-color': t.relay,
          'line-width': ['get', 'width'],
          'line-opacity': ['get', 'opacity'],
          'line-dasharray': [4, 3],
        },
      },
      {
        id: 'mh-links-derp',
        type: 'line',
        source: LINKS_SOURCE_ID,
        filter: ['all', ['==', ['get', 'carrier'], 'derp'], ['!', ['get', 'stalled']]],
        layout: { 'line-cap': 'butt', 'line-join': 'round' },
        paint: {
          'line-color': t.derp,
          'line-width': ['get', 'width'],
          'line-opacity': ['get', 'opacity'],
          'line-dasharray': [2, 2],
        },
      },
      {
        id: 'mh-links-blocked',
        type: 'line',
        source: LINKS_SOURCE_ID,
        filter: ['all', ['==', ['get', 'carrier'], 'blocked'], ['!', ['get', 'stalled']]],
        layout: { 'line-cap': 'round', 'line-join': 'round' },
        paint: {
          'line-color': t.blocked,
          'line-width': ['get', 'width'],
          'line-opacity': ['get', 'opacity'],
          'line-dasharray': [0, 2.5],
        },
      },
      {
        id: 'mh-links-stalled',
        type: 'line',
        source: LINKS_SOURCE_ID,
        filter: ['==', ['get', 'stalled'], true],
        layout: { 'line-cap': 'round', 'line-join': 'round' },
        paint: {
          'line-color': t.stalled,
          'line-width': ['get', 'width'],
          'line-opacity': ['get', 'opacity'],
          'line-dasharray': [0, 2],
        },
      },
      // Basemap labels (rendered below application markers so app labels win collision!)
      {
        id: 'label-place',
        type: 'symbol',
        source: BOUNDARY_SOURCE_ID,
        'source-layer': 'label_place',
        minzoom: isMobile ? 5 : 4,
        filter: ['<=', ['-', ['get', 'min_zoom'], 1], ['zoom']],
        layout: {
          'text-field': buildSubLabelTextField(lang),
          'text-font': MAPLIBRE_LOCAL_TEXT_FONT,
          'text-size': 10,
          'text-padding': 3,
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
          'text-padding': 3,
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
          'text-padding': 3,
          'symbol-sort-key': ['*', -1, ['coalesce', ['get', 'pop'], 0]],
        },
        paint: {
          'text-color': t.labelSecondary,
          'text-halo-color': t.labelHalo,
          'text-halo-width': 1.5,
        },
      },
      // Link midpoint badges (⚠ stalled, × blocked, hover/ego RTT)
      {
        id: 'mh-link-badges',
        type: 'symbol',
        source: LINK_BADGES_SOURCE_ID,
        layout: {
          'text-field': ['get', 'badge'],
          'text-font': MAPLIBRE_LOCAL_TEXT_FONT,
          'text-size': 10,
          'text-padding': 4,
          'text-allow-overlap': false,
          'text-ignore-placement': false,
        },
        paint: {
          'text-color': [
            'match',
            ['get', 'colorKind'],
            'stalled',
            t.stalled,
            'blocked',
            t.blocked,
            t.labelPrimary,
          ],
          'text-halo-color': t.labelHalo,
          'text-halo-width': 1.5,
        },
      },
      // Application markers & city group labels (highest priority, icons never collide-hidden)
      {
        id: 'mh-markers',
        type: 'symbol',
        source: MARKERS_SOURCE_ID,
        layout: {
          'icon-image': ['get', 'icon'],
          'icon-allow-overlap': true,
          'icon-ignore-placement': true,
          'text-field': ['get', 'label'],
          'text-font': MAPLIBRE_LOCAL_TEXT_FONT,
          'text-size': 11,
          'text-variable-anchor': ['right', 'left', 'top', 'bottom'],
          'text-radial-offset': 1.25,
          'text-padding': 4,
          'text-optional': true,
          'symbol-sort-key': ['get', 'sortKey'],
        },
        paint: {
          'icon-opacity': ['get', 'opacity'],
          'text-opacity': ['get', 'opacity'],
          'text-color': t.labelPrimary,
          'text-halo-color': t.labelHalo,
          'text-halo-width': 1.5,
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

  map.setSky(buildSkySpec(t))
  map.setPaintProperty('background', 'background-color', t.ocean)
  map.setPaintProperty('land-low', 'fill-color', t.land)
  map.setPaintProperty('land-high', 'fill-color', t.land)
  map.setPaintProperty('coast-low', 'line-color', t.coast)
  map.setPaintProperty('coast-high', 'line-color', t.coast)

  map.setPaintProperty('admin2-other', 'line-color', t.border)
  map.setPaintProperty('admin2-other', 'line-opacity', ['interpolate', ['linear'], ['zoom'], 5, 0, 6, op2])
  map.setPaintProperty('admin2-chn', 'line-color', t.border)
  map.setPaintProperty('admin2-chn', 'line-opacity', ['interpolate', ['linear'], ['zoom'], 6, 0, 7, op2])
  map.setPaintProperty('admin1', 'line-color', t.border)
  map.setPaintProperty('admin1', 'line-opacity', ['interpolate', ['linear'], ['zoom'], 2, 0, 3, op1])
  map.setPaintProperty('admin0-intl', 'line-color', t.border)
  map.setPaintProperty('admin0-intl', 'line-opacity', op0)
  map.setPaintProperty('admin0-disputed', 'line-color', t.border)
  map.setPaintProperty('admin0-disputed', 'line-opacity', op0)
  map.setPaintProperty('admin0-limit', 'line-color', t.border)
  map.setPaintProperty('admin0-limit', 'line-opacity', op0 * 0.8)

  map.setPaintProperty('mh-links-direct', 'line-color', t.direct)
  map.setPaintProperty('mh-links-tunnel', 'line-color', t.tunnel)
  map.setPaintProperty('mh-links-relay', 'line-color', t.relay)
  map.setPaintProperty('mh-links-derp', 'line-color', t.derp)
  map.setPaintProperty('mh-links-blocked', 'line-color', t.blocked)
  map.setPaintProperty('mh-links-stalled', 'line-color', t.stalled)

  map.setPaintProperty('label-place', 'text-color', t.labelMuted)
  map.setPaintProperty('label-place', 'text-halo-color', t.labelHalo)
  map.setPaintProperty('label-admin1', 'text-color', t.labelMuted)
  map.setPaintProperty('label-admin1', 'text-halo-color', t.labelHalo)
  map.setPaintProperty('label-admin0', 'text-color', t.labelSecondary)
  map.setPaintProperty('label-admin0', 'text-halo-color', t.labelHalo)

  map.setPaintProperty('mh-link-badges', 'text-color', [
    'match',
    ['get', 'colorKind'],
    'stalled',
    t.stalled,
    'blocked',
    t.blocked,
    t.labelPrimary,
  ])
  map.setPaintProperty('mh-link-badges', 'text-halo-color', t.labelHalo)

  map.setPaintProperty('mh-markers', 'text-color', t.labelPrimary)
  map.setPaintProperty('mh-markers', 'text-halo-color', t.labelHalo)
}

/**
 * Live language switch via setLayoutProperty with ZERO setStyle() reload (S6 / AC10).
 */
export function applyLangToMap(map: MapLibreMap, lang: GlobeLang): void {
  map.setLayoutProperty('label-admin0', 'text-field', buildAdmin0TextField(lang))
  map.setLayoutProperty('label-admin1', 'text-field', buildSubLabelTextField(lang))
  map.setLayoutProperty('label-place', 'text-field', buildSubLabelTextField(lang))
}

/** Toggle visibility of MapLibre native surface link layers (Variant L vs Variant A < z5). */
export function setSurfaceLinksVisible(map: MapLibreMap, visible: boolean): void {
  const v = visible ? 'visible' : 'none'
  for (const id of SURFACE_LINK_LAYER_IDS) {
    if (map.getLayer(id)) {
      map.setLayoutProperty(id, 'visibility', v)
    }
  }
}
