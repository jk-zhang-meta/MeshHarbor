// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
/*
 * T12 — Inline MapLibre GL JS 6.x + PMTiles 4.x 3D Network Map for the Desktop Companion.
 *
 * - Zero external CDNs: loads local UMD/IIFE vendor scripts (`vendor/maplibre-gl.js`,
 *   `vendor/maplibre-gl-csp-worker.js`, `vendor/pmtiles.js`) and omits `glyphs` so MapLibre
 *   renders labels using local system + CJK fonts.
 * - Zero iframes: renders directly inside `#dv-globe-card` on the Devices / Network view,
 *   alongside the Enlarge button (`#dv-open-globe`) that opens the full standalone globe.
 * - Routes PMTiles HTTP Range requests through Tauri IPC (`cmd_pmtiles_range`) so CORS,
 *   deployment base paths, FR-134 management entries, and FR-135 proxy rules are honoured.
 * - Live theme (`dark` / `light`) and language (`en` / `zh-CN`) switching in place with
 *   ZERO `setStyle()` reload.
 * - Clean WebGL2 detection + runtime context-loss fallback to a plain, XSS-safe device list.
 */
(function (root) {
  'use strict';

  const SVG_NS = 'http://www.w3.org/2000/svg';
  const PMTILES_KEY = 'mh-boundaries-v1';
  const WORKER_URL = './vendor/maplibre-gl-csp-worker.js';
  const BOUNDARY_SOURCE_ID = 'mhb';
  const LINKS_SOURCE_ID = 'mh-links';
  const MARKERS_SOURCE_ID = 'mh-markers';
  const LABEL_BLOCKER_ICON_ID = 'mh-blocker-1px';
  const DEFAULT_CENTER = [108, 28];
  const DEFAULT_FOV_DEG = 36.87;
  const MIN_GLOBE_ZOOM = 0.6;
  const MAX_GLOBE_ZOOM = 12;
  const SPIDERFY_CIRCLE_MAX = 8;
  const SPIDERFY_SPIRAL_MAX = 20;
  const SPIDERFY_MAX_SITES = 6;
  const SPIDERFY_MIN_OPEN_ZOOM = 2.6;
  const SPIDERFY_ZOOM_COLLAPSE_DELTA = 0.85;

  const EMPTY_FC = { type: 'FeatureCollection', features: [] };

  const MAPLIBRE_LOCAL_TEXT_FONT = [
    'Noto Sans CJK SC',
    'PingFang SC',
    'Microsoft YaHei',
    'Noto Sans',
    'sans-serif',
  ];

  // Visual tokens matching ui/src/components/globe-v2/tokens.ts
  const DARK_TOKENS = {
    mode: 'dark',
    space: '#060B13',
    ocean: '#08131E',
    land: '#172A3C',
    coast: '#335975',
    border: '#8FA3BF',
    borderOpacity: [0.58, 0.30, 0.16],
    horizon: '#2A7AB0',
    labelPrimary: '#E6EDF6',
    labelSecondary: '#A9B6C8',
    labelMuted: '#7889A0',
    labelHalo: 'rgba(8, 19, 30, 0.92)',
    online: '#56B4E9',
    direct: '#56B4E9',
    stale: '#E69F00',
    relay: '#E69F00',
    derp: '#D98CB8',
    tunnel: '#2BB58A',
    offline: '#8C96A5',
    blocked: '#8C96A5',
    stalled: '#F0703A',
    selfRing: '#3CC7B9',
    focusRing: '#FFFFFF',
    leg: 'rgba(169, 182, 200, 0.6)',
    hubFill: '#08131E',
    hubText: '#E6EDF6',
  };

  const LIGHT_TOKENS = {
    mode: 'light',
    space: '#F5F7FA',
    ocean: '#DCE6F0',
    land: '#FAFBFC',
    coast: '#B9C6D4',
    border: '#4A5B70',
    borderOpacity: [0.60, 0.32, 0.18],
    horizon: '#BFD8F0',
    labelPrimary: '#1F2937',
    labelSecondary: '#4B5563',
    labelMuted: '#6B7280',
    labelHalo: 'rgba(250, 251, 252, 0.90)',
    online: '#0072B2',
    direct: '#0072B2',
    stale: '#A66300',
    relay: '#A66300',
    derp: '#A3527F',
    tunnel: '#00785A',
    offline: '#6B7280',
    blocked: '#6B7280',
    stalled: '#C24A00',
    selfRing: '#0A8F86',
    focusRing: '#111827',
    leg: 'rgba(75, 85, 99, 0.6)',
    hubFill: '#FFFFFF',
    hubText: '#1F2937',
  };

  function getTokens(mode) {
    return mode === 'dark' ? DARK_TOKENS : LIGHT_TOKENS;
  }

  function t(key, params, fallback) {
    if (root && root.MeshHarborI18n && typeof root.MeshHarborI18n.t === 'function') {
      return root.MeshHarborI18n.t(key, params);
    }
    if (!params) return fallback || key;
    return String(fallback || key).replace(/\{([a-zA-Z0-9_]+)\}/g, (_, k) =>
      Object.prototype.hasOwnProperty.call(params, k) ? String(params[k]) : '{' + k + '}',
    );
  }

  function currentLang() {
    if (root && root.MeshHarborI18n && typeof root.MeshHarborI18n.getLang === 'function') {
      return root.MeshHarborI18n.getLang() === 'zh-CN' ? 'zh-CN' : 'en';
    }
    if (typeof document !== 'undefined' && /^zh\b/i.test(document.documentElement.lang || '')) {
      return 'zh-CN';
    }
    return 'en';
  }

  function resolveCompanionTheme() {
    if (typeof document !== 'undefined') {
      const html = document.documentElement;
      if (html.classList.contains('theme-dark') || html.dataset.theme === 'dark') return 'dark';
      if (html.classList.contains('theme-light') || html.dataset.theme === 'light') return 'light';
    }
    if (typeof window !== 'undefined' && typeof window.matchMedia === 'function') {
      try {
        if (window.matchMedia('(prefers-color-scheme: dark)').matches) return 'dark';
      } catch (_) {
        /* ignore */
      }
    }
    return 'light';
  }

  /* ── WebGL2 capability probe ─────────────────────────────────────── */

  function isWebGL2Available() {
    if (root && root.__MH_FORCE_NO_WEBGL2__) return false;
    if (typeof document === 'undefined' || typeof WebGL2RenderingContext === 'undefined') {
      return false;
    }
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl2', { failIfMajorPerformanceCaveat: false });
      if (!gl) return false;
      const ext = gl.getExtension && gl.getExtension('WEBGL_lose_context');
      if (ext && typeof ext.loseContext === 'function') ext.loseContext();
      return true;
    } catch (_) {
      return false;
    }
  }

  /* ── Base64 + PMTiles Tauri IPC Source ───────────────────────────── */

  function decodeBase64ToArrayBuffer(b64) {
    const clean = String(b64 || '');
    if (!clean) return new ArrayBuffer(0);
    if (typeof atob === 'function') {
      const bin = atob(clean);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i += 1) {
        bytes[i] = bin.charCodeAt(i);
      }
      return bytes.buffer;
    }
    if (typeof Buffer !== 'undefined') {
      const buf = Buffer.from(clean, 'base64');
      return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
    }
    throw new Error('Base64 decoder unavailable');
  }

  function makeAbortError() {
    if (typeof DOMException === 'function') {
      return new DOMException('The operation was aborted.', 'AbortError');
    }
    const err = new Error('The operation was aborted.');
    err.name = 'AbortError';
    return err;
  }

  function normalizeStrongEtag(raw) {
    if (typeof raw !== 'string') return undefined;
    const s = raw.trim();
    if (!s || s.startsWith('W/') || s.startsWith('w/')) return undefined;
    return s;
  }

  function createIpcPmTilesSource(invokeFn, pmtilesNs) {
    return {
      getKey() {
        return PMTILES_KEY;
      },
      async getBytes(offset, length, signal, etag) {
        if (signal && signal.aborted) throw makeAbortError();
        const reqEtag = normalizeStrongEtag(etag);
        let reply;
        try {
          reply = await invokeFn('cmd_pmtiles_range', {
            offset: Math.max(0, Math.floor(Number(offset) || 0)),
            length: Math.max(0, Math.floor(Number(length) || 0)),
            etag: reqEtag || null,
          });
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err || '');
          if (msg.indexOf('ETAG_MISMATCH') !== -1 && pmtilesNs && pmtilesNs.EtagMismatch) {
            throw new pmtilesNs.EtagMismatch(msg);
          }
          throw err;
        }
        if (signal && signal.aborted) throw makeAbortError();
        const replyEtag = normalizeStrongEtag(reply && reply.etag);
        if (reqEtag && replyEtag && replyEtag !== reqEtag && pmtilesNs && pmtilesNs.EtagMismatch) {
          throw new pmtilesNs.EtagMismatch('PMTiles ETag changed');
        }
        const data = decodeBase64ToArrayBuffer(reply && reply.data_b64);
        return {
          data,
          etag: replyEtag,
          cacheControl: (reply && reply.cache_control) || undefined,
          expires: (reply && reply.expires) || undefined,
        };
      },
    };
  }

  let protocolRegistered = false;
  function ensureMapLibreProtocol(maplibregl, pmtilesNs, invokeFn) {
    if (protocolRegistered) return;
    protocolRegistered = true;
    if (typeof maplibregl.setWorkerUrl === 'function') {
      maplibregl.setWorkerUrl(WORKER_URL);
    }
    const protocol = new pmtilesNs.Protocol();
    const source = createIpcPmTilesSource(invokeFn, pmtilesNs);
    protocol.add(new pmtilesNs.PMTiles(source));
    maplibregl.addProtocol('pmtiles', protocol.tile);
  }

  /* ── Style builder & live theme/language mutators ────────────────── */

  function buildSkySpec(tok) {
    return {
      'sky-color': tok.space,
      'horizon-color': tok.horizon,
      'fog-color': tok.ocean,
      'atmosphere-blend': 0,
    };
  }

  function buildAdmin0TextField(lang) {
    if (lang === 'zh-CN') {
      return ['coalesce', ['get', 'name_zh_override'], ['get', 'name_zh'], ['get', 'name_en']];
    }
    return ['coalesce', ['get', 'name_en_override'], ['get', 'name_en']];
  }

  function buildSubLabelTextField(lang) {
    if (lang === 'zh-CN') {
      return ['coalesce', ['get', 'name_zh'], ['get', 'name_en']];
    }
    return ['coalesce', ['get', 'name_en'], ['get', 'name_zh']];
  }

  function buildStyle(theme, lang) {
    const tok = getTokens(theme);
    const [op0, op1, op2] = tok.borderOpacity;
    const coastOpacity = theme === 'dark' ? 0.82 : 0.85;

    return {
      version: 8,
      name: 'meshharbor-companion-globe',
      projection: { type: 'globe' },
      sky: buildSkySpec(tok),
      // `glyphs` intentionally omitted — MapLibre 6.x renders labels with local system + CJK fonts.
      sources: {
        [BOUNDARY_SOURCE_ID]: {
          type: 'vector',
          url: 'pmtiles://' + PMTILES_KEY,
        },
        [LINKS_SOURCE_ID]: {
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
          paint: { 'background-color': tok.ocean },
        },
        {
          id: 'land-low',
          type: 'fill',
          source: BOUNDARY_SOURCE_ID,
          'source-layer': 'land_low',
          maxzoom: 3,
          paint: { 'fill-color': tok.land, 'fill-antialias': true },
        },
        {
          id: 'land-high',
          type: 'fill',
          source: BOUNDARY_SOURCE_ID,
          'source-layer': 'land_high',
          minzoom: 3,
          paint: { 'fill-color': tok.land, 'fill-antialias': true },
        },
        {
          id: 'coast-low',
          type: 'line',
          source: BOUNDARY_SOURCE_ID,
          'source-layer': 'coast_low',
          maxzoom: 3,
          paint: {
            'line-color': tok.coast,
            'line-opacity': coastOpacity,
            'line-width': ['interpolate', ['linear'], ['zoom'], 0, 0.75, 4, 0.9, 12, 1.1],
          },
        },
        {
          id: 'coast-high',
          type: 'line',
          source: BOUNDARY_SOURCE_ID,
          'source-layer': 'coast_high',
          minzoom: 3,
          paint: {
            'line-color': tok.coast,
            'line-opacity': coastOpacity,
            'line-width': ['interpolate', ['linear'], ['zoom'], 0, 0.75, 4, 0.9, 12, 1.1],
          },
        },
        {
          id: 'admin2-other',
          type: 'line',
          source: BOUNDARY_SOURCE_ID,
          'source-layer': 'admin2',
          minzoom: 5,
          filter: ['!=', ['get', 'cc'], 'CHN'],
          paint: {
            'line-color': tok.border,
            'line-opacity': ['interpolate', ['linear'], ['zoom'], 5.5, 0, 6.5, op2],
            'line-width': ['interpolate', ['linear'], ['zoom'], 5, 0.35, 8, 0.55, 11, 0.75],
          },
        },
        {
          id: 'admin2-chn',
          type: 'line',
          source: BOUNDARY_SOURCE_ID,
          'source-layer': 'admin2',
          minzoom: 8,
          filter: ['==', ['get', 'cc'], 'CHN'],
          paint: {
            'line-color': tok.border,
            'line-opacity': ['interpolate', ['linear'], ['zoom'], 8, 0, 9, op2],
            'line-width': ['interpolate', ['linear'], ['zoom'], 8, 0.35, 10, 0.5, 12, 0.65],
          },
        },
        {
          id: 'admin2-pref-chn',
          type: 'line',
          source: BOUNDARY_SOURCE_ID,
          'source-layer': 'admin2_pref',
          minzoom: 5,
          paint: {
            'line-color': tok.border,
            'line-opacity': ['interpolate', ['linear'], ['zoom'], 5, 0, 6.5, Math.min(1, op2 * 1.45)],
            'line-width': ['interpolate', ['linear'], ['zoom'], 5, 0.45, 8, 0.65, 11, 0.85],
          },
        },
        {
          id: 'admin1',
          type: 'line',
          source: BOUNDARY_SOURCE_ID,
          'source-layer': 'admin1',
          minzoom: 2,
          paint: {
            'line-color': tok.border,
            'line-opacity': ['interpolate', ['linear'], ['zoom'], 2, 0, 3, op1],
            'line-width': ['interpolate', ['linear'], ['zoom'], 0, 0.4, 4, 0.6, 9, 0.9],
          },
        },
        {
          id: 'admin0-intl',
          type: 'line',
          source: BOUNDARY_SOURCE_ID,
          'source-layer': 'admin0',
          filter: ['==', ['get', 'cls'], 'intl'],
          paint: {
            'line-color': tok.border,
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
            'line-color': tok.border,
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
            'line-color': tok.border,
            'line-opacity': op0 * 0.8,
            'line-width': ['interpolate', ['linear'], ['zoom'], 3, 0.6, 9, 0.9],
            'line-dasharray': [0, 2],
          },
        },
        // Geodesic peer links (matching carrier palette from tokens.ts)
        {
          id: 'mh-links-direct',
          type: 'line',
          source: LINKS_SOURCE_ID,
          filter: ['all', ['==', ['get', 'carrier'], 'direct'], ['!', ['get', 'stalled']]],
          layout: { 'line-cap': 'round', 'line-join': 'round' },
          paint: {
            'line-color': tok.direct,
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
            'line-color': tok.tunnel,
            'line-width': ['get', 'width'],
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
            'line-color': tok.relay,
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
            'line-color': tok.derp,
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
            'line-color': tok.blocked,
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
            'line-color': tok.stalled,
            'line-width': ['get', 'width'],
            'line-opacity': ['get', 'opacity'],
            'line-dasharray': [0, 2],
          },
        },
        // Basemap labels below marker blockers & labels
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
            'text-color': tok.labelMuted,
            'text-halo-color': tok.labelHalo,
            'text-halo-width': 1.5,
          },
        },
        {
          id: 'label-place',
          type: 'symbol',
          source: BOUNDARY_SOURCE_ID,
          'source-layer': 'label_place',
          minzoom: 4,
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
            'text-color': tok.labelMuted,
            'text-halo-color': tok.labelHalo,
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
            'text-color': tok.labelMuted,
            'text-halo-color': tok.labelHalo,
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
            'text-color': tok.labelSecondary,
            'text-halo-color': tok.labelHalo,
            'text-halo-width': 1.5,
          },
        },
        // Suppress basemap labels around device markers so device labels stay clean
        {
          id: 'mh-label-blockers',
          type: 'symbol',
          source: MARKERS_SOURCE_ID,
          layout: {
            'icon-image': LABEL_BLOCKER_ICON_ID,
            'icon-allow-overlap': true,
            'icon-ignore-placement': false,
            'icon-padding': 32,
          },
          paint: { 'icon-opacity': 0 },
        },
        // Device / cluster labels
        {
          id: 'mh-marker-labels',
          type: 'symbol',
          source: MARKERS_SOURCE_ID,
          filter: ['!=', ['get', 'label'], ''],
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
            'text-radial-offset': 1.3,
            'text-padding': 6,
            'text-allow-overlap': false,
            'symbol-sort-key': ['get', 'sortKey'],
          },
          paint: {
            'text-color': tok.labelPrimary,
            'text-halo-color': tok.labelHalo,
            'text-halo-width': 1.6,
          },
        },
        // Device & cluster marker icons (always visible on top)
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
          paint: { 'icon-opacity': 1 },
        },
      ],
    };
  }

  function applyThemeToMap(map, theme) {
    if (!map || !map.isStyleLoaded || !map.isStyleLoaded()) return;
    const tok = getTokens(theme);
    const [op0, op1, op2] = tok.borderOpacity;
    const coastOpacity = theme === 'dark' ? 0.82 : 0.85;

    if (typeof map.setSky === 'function') map.setSky(buildSkySpec(tok));
    const paint = (id, prop, val) => {
      if (map.getLayer(id)) map.setPaintProperty(id, prop, val);
    };
    paint('background', 'background-color', tok.ocean);
    paint('land-low', 'fill-color', tok.land);
    paint('land-high', 'fill-color', tok.land);
    paint('coast-low', 'line-color', tok.coast);
    paint('coast-low', 'line-opacity', coastOpacity);
    paint('coast-high', 'line-color', tok.coast);
    paint('coast-high', 'line-opacity', coastOpacity);

    paint('admin2-other', 'line-color', tok.border);
    paint('admin2-other', 'line-opacity', ['interpolate', ['linear'], ['zoom'], 5.5, 0, 6.5, op2]);
    paint('admin2-chn', 'line-color', tok.border);
    paint('admin2-chn', 'line-opacity', ['interpolate', ['linear'], ['zoom'], 8, 0, 9, op2]);
    paint('admin2-pref-chn', 'line-color', tok.border);
    paint('admin2-pref-chn', 'line-opacity', [
      'interpolate',
      ['linear'],
      ['zoom'],
      5,
      0,
      6.5,
      Math.min(1, op2 * 1.45),
    ]);
    paint('admin1', 'line-color', tok.border);
    paint('admin1', 'line-opacity', ['interpolate', ['linear'], ['zoom'], 2, 0, 3, op1]);
    paint('admin0-intl', 'line-color', tok.border);
    paint('admin0-intl', 'line-opacity', op0);
    paint('admin0-disputed', 'line-color', tok.border);
    paint('admin0-disputed', 'line-opacity', op0);
    paint('admin0-limit', 'line-color', tok.border);
    paint('admin0-limit', 'line-opacity', op0 * 0.8);

    paint('mh-links-direct', 'line-color', tok.direct);
    paint('mh-links-tunnel', 'line-color', tok.tunnel);
    paint('mh-links-relay', 'line-color', tok.relay);
    paint('mh-links-derp', 'line-color', tok.derp);
    paint('mh-links-blocked', 'line-color', tok.blocked);
    paint('mh-links-stalled', 'line-color', tok.stalled);

    paint('label-admin2', 'text-color', tok.labelMuted);
    paint('label-admin2', 'text-halo-color', tok.labelHalo);
    paint('label-place', 'text-color', tok.labelMuted);
    paint('label-place', 'text-halo-color', tok.labelHalo);
    paint('label-admin1', 'text-color', tok.labelMuted);
    paint('label-admin1', 'text-halo-color', tok.labelHalo);
    paint('label-admin0', 'text-color', tok.labelSecondary);
    paint('label-admin0', 'text-halo-color', tok.labelHalo);
    paint('mh-marker-labels', 'text-color', tok.labelPrimary);
    paint('mh-marker-labels', 'text-halo-color', tok.labelHalo);
  }

  function applyLangToMap(map, lang) {
    if (!map || !map.isStyleLoaded || !map.isStyleLoaded()) return;
    const layout = (id, prop, val) => {
      if (map.getLayer(id)) map.setLayoutProperty(id, prop, val);
    };
    layout('label-admin0', 'text-field', buildAdmin0TextField(lang));
    layout('label-admin1', 'text-field', buildSubLabelTextField(lang));
    layout('label-place', 'text-field', buildSubLabelTextField(lang));
    layout('label-admin2', 'text-field', buildSubLabelTextField(lang));
  }

  /* ── Viewport & great-circle math (matching globeViewport.ts & links.ts) ── */

  function planetScaleAtLatitude(latDeg) {
    const clamped = Math.min(Math.abs(Number(latDeg) || 0), 85.051129);
    return Math.cos((clamped * Math.PI) / 180);
  }

  function cameraFocalDistancePx(height, fovDeg) {
    const halfFovRad = (((fovDeg || DEFAULT_FOV_DEG) * 0.5) * Math.PI) / 180;
    return Math.max(1, height) / (2 * Math.tan(halfFovRad));
  }

  function globeScreenRadiusPx(width, height, zoom, latDeg, fovDeg) {
    const f = cameraFocalDistancePx(height, fovDeg);
    const worldSize = 512 * Math.pow(2, zoom);
    const rWorld = worldSize / (2 * Math.PI * planetScaleAtLatitude(latDeg));
    return (f * rWorld) / Math.sqrt(f * f + 2 * f * rWorld);
  }

  function computeFitGlobeZoom(width, height, latDeg, targetRatio, fovDeg) {
    const w = Math.max(120, Number(width) || 640);
    const h = Math.max(120, Number(height) || 580);
    const ratio = targetRatio || 0.86;
    const desiredR = (Math.min(w, h) * ratio) / 2;
    const f = cameraFocalDistancePx(h, fovDeg);
    const rWorld = (desiredR * desiredR + desiredR * Math.sqrt(desiredR * desiredR + f * f)) / f;
    const worldSize = rWorld * 2 * Math.PI * planetScaleAtLatitude(latDeg == null ? DEFAULT_CENTER[1] : latDeg);
    const z = Math.log2(worldSize / 512);
    return Math.max(MIN_GLOBE_ZOOM, Math.min(4.2, Math.round(z * 1000) / 1000));
  }

  function computeGlobeScreenCircle(width, height, zoom, latDeg) {
    const cx = width / 2;
    const cy = height / 2;
    const radius = globeScreenRadiusPx(width, height, zoom, latDeg, DEFAULT_FOV_DEG);
    let rimOpacity = 1;
    if (zoom >= 4.8) rimOpacity = 0;
    else if (zoom > 3.2) {
      const u = (zoom - 3.2) / (4.8 - 3.2);
      rimOpacity = Math.max(0, Math.min(1, 1 - u * u * (3 - 2 * u)));
    }
    return { cx, cy, radius, rimOpacity };
  }

  function interpolateGreatCircle(fromLonLat, toLonLat, minSegs, maxSegs) {
    const deg = Math.PI / 180;
    const rad = 180 / Math.PI;
    const minS = minSegs || 16;
    const maxS = maxSegs || 24;

    const toVec = (lon, lat) => {
      const phi = lat * deg;
      const lam = lon * deg;
      const cp = Math.cos(phi);
      return [cp * Math.cos(lam), cp * Math.sin(lam), Math.sin(phi)];
    };

    const a = toVec(fromLonLat[0], fromLonLat[1]);
    const b = toVec(toLonLat[0], toLonLat[1]);
    const dot = Math.max(-1, Math.min(1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2]));
    const omega = Math.acos(dot);
    const omegaDeg = omega * rad;

    let segs = Math.round(Math.max(minS, Math.min(maxS, Math.ceil(omegaDeg / 5))));
    if (segs % 2 !== 0) segs = Math.min(maxS, segs + 1);
    if (segs < 2) segs = 2;

    const sinO = Math.sin(omega);
    let perp = null;
    if (omega > Math.PI - 1e-3) {
      const ref = Math.abs(a[2]) < 0.9 ? [0, 0, 1] : [1, 0, 0];
      const cx = a[1] * ref[2] - a[2] * ref[1];
      const cy = a[2] * ref[0] - a[0] * ref[2];
      const cz = a[0] * ref[1] - a[1] * ref[0];
      const m = Math.hypot(cx, cy, cz) || 1;
      perp = [cx / m, cy / m, cz / m];
    }

    const raw = [];
    for (let i = 0; i <= segs; i += 1) {
      const u = i / segs;
      let x, y, z;
      if (omega < 1e-5) {
        x = a[0];
        y = a[1];
        z = a[2];
      } else if (perp) {
        const ang = u * Math.PI;
        const ca = Math.cos(ang);
        const sa = Math.sin(ang);
        x = a[0] * ca + perp[0] * sa;
        y = a[1] * ca + perp[1] * sa;
        z = a[2] * ca + perp[2] * sa;
      } else {
        const w0 = Math.sin((1 - u) * omega) / sinO;
        const w1 = Math.sin(u * omega) / sinO;
        x = w0 * a[0] + w1 * b[0];
        y = w0 * a[1] + w1 * b[1];
        z = w0 * a[2] + w1 * b[2];
      }
      const len = Math.hypot(x, y, z) || 1;
      raw.push([Math.atan2(y, x) * rad, Math.asin(Math.max(-1, Math.min(1, z / len))) * rad]);
    }

    const unwrapped = [raw[0]];
    for (let i = 1; i < raw.length; i += 1) {
      let lon = raw[i][0];
      const prevLon = unwrapped[i - 1][0];
      while (lon - prevLon > 180) lon -= 360;
      while (lon - prevLon < -180) lon += 360;
      unwrapped.push([lon, raw[i][1]]);
    }
    return unwrapped;
  }

  /* ── Pure device projection, clustering, and link builders ───────── */

  function cleanText(v) {
    const s = typeof v === 'string' ? v.trim() : '';
    return s && s !== '-' && s !== '—' ? s : '';
  }

  function formatLocationFallback(row) {
    if (root && root.MeshHarborDevices && typeof root.MeshHarborDevices.formatDeviceLocation === 'function') {
      return root.MeshHarborDevices.formatDeviceLocation(row).locationText;
    }
    const parts = [cleanText(row && row.country), cleanText(row && row.region), cleanText(row && row.city)];
    const kept = [];
    for (const seg of parts) {
      if (!seg) continue;
      if (kept.length && kept[kept.length - 1].toLowerCase() === seg.toLowerCase()) continue;
      kept.push(seg);
    }
    return kept.join(' · ');
  }

  function formatZoneFallback(row) {
    if (root && root.MeshHarborDevices && typeof root.MeshHarborDevices.formatDeviceZone === 'function') {
      return root.MeshHarborDevices.formatDeviceZone(row);
    }
    const pinnedId = cleanText(row && row.pinned_zone_id);
    const effectiveName = cleanText(row && row.effective_zone_name);
    const effectiveId = cleanText(row && row.effective_zone_id);
    const zoneLabel = effectiveName || effectiveId || pinnedId;
    return {
      zoneId: effectiveId || pinnedId,
      zoneLabel,
      pinned: Boolean(pinnedId),
      hasZone: Boolean(zoneLabel),
    };
  }

  function isValidCoord(lat, lon, geoLevel) {
    if (typeof lat !== 'number' || typeof lon !== 'number') return false;
    if (!Number.isFinite(lat) || !Number.isFinite(lon)) return false;
    if (lat < -90 || lat > 90 || lon < -180 || lon > 180) return false;
    if (lat === 0 && lon === 0 && geoLevel !== 'coords') return false;
    return true;
  }

  function normalizeCarrier(raw) {
    const c = String(raw || '').toLowerCase();
    if (c === 'direct' || c === 'relay' || c === 'derp' || c === 'tunnel' || c === 'blocked') {
      return c;
    }
    return 'offline';
  }

  function shortId(id) {
    const s = String(id || '');
    return s.length > 10 ? s.slice(0, 8) + '…' : s;
  }

  function projectDevices(rows, liveCtx) {
    const list = Array.isArray(rows) ? rows : [];
    const items = [];
    const locatedItems = [];
    let onlineCount = 0;

    for (const row of list) {
      if (!row || typeof row !== 'object') continue;
      const peer = liveCtx && typeof liveCtx.peerFor === 'function' ? liveCtx.peerFor(row) : null;
      let presence = 'offline';
      if (row.is_self) {
        presence = liveCtx && liveCtx.selfConnected === false ? 'stale' : 'online';
      } else if (peer) {
        presence = peer.online ? 'online' : 'offline';
      } else if (row.presence === 'online' || row.presence === 'stale' || row.presence === 'offline') {
        presence = row.presence;
      }
      if (presence === 'online') onlineCount += 1;

      const connKey = peer ? normalizeCarrier(peer.connection) : 'offline';
      const stalled = Boolean(peer && peer.stalled && (connKey === 'direct' || connKey === 'relay'));
      const rttMs =
        peer && typeof peer.rtt_ms === 'number' && Number.isFinite(peer.rtt_ms)
          ? Math.round(peer.rtt_ms)
          : null;

      const lat = typeof row.lat === 'number' ? row.lat : null;
      const lon = typeof row.lon === 'number' ? row.lon : null;
      const geoLevel = cleanText(row.geo_level) || null;
      const located = isValidCoord(lat, lon, geoLevel);
      const zone = formatZoneFallback(row);
      const name = cleanText(row.display_name) || cleanText(row.name) || shortId(row.id);

      const item = {
        id: String(row.id || row.overlay_node_id || name),
        overlayNodeId: cleanText(row.overlay_node_id) || null,
        agentId: row.kind === 'agent' ? cleanText(row.id) || null : null,
        name,
        isSelf: Boolean(row.is_self),
        presence,
        connection: connKey,
        stalled,
        rttMs,
        locationText: formatLocationFallback(row),
        countryCode: cleanText(row.country_code).toUpperCase(),
        city: cleanText(row.city),
        region: cleanText(row.region),
        country: cleanText(row.country),
        publicIp: cleanText(row.public_ip),
        physicalPublicIp: cleanText(row.physical_public_ip),
        zoneLabel: zone.zoneLabel || '',
        zonePinned: Boolean(zone.pinned),
        lat,
        lon,
        geoLevel,
        accuracyRadiusKm:
          typeof row.accuracy_radius_km === 'number' && Number.isFinite(row.accuracy_radius_km)
            ? row.accuracy_radius_km
            : null,
        located,
      };
      items.push(item);
      if (located) locatedItems.push(item);
    }

    const presRank = { online: 0, stale: 1, offline: 2 };
    items.sort(
      (a, b) =>
        Number(b.isSelf) - Number(a.isSelf) ||
        (presRank[a.presence] ?? 3) - (presRank[b.presence] ?? 3) ||
        a.name.localeCompare(b.name),
    );

    return {
      items,
      locatedItems,
      unlocatedCount: items.length - locatedItems.length,
      onlineCount,
      totalCount: items.length,
    };
  }

  function clusterLocatedDevices(locatedItems) {
    const groups = new Map();
    for (const item of locatedItems || []) {
      const key = Math.round(item.lat * 100) + ':' + Math.round(item.lon * 100);
      let g = groups.get(key);
      if (!g) {
        g = {
          id: 'c:' + key,
          latSum: 0,
          lonSum: 0,
          items: [],
          onlineCount: 0,
          staleCount: 0,
          offlineCount: 0,
          hasSelf: false,
        };
        groups.set(key, g);
      }
      g.latSum += item.lat;
      g.lonSum += item.lon;
      g.items.push(item);
      if (item.presence === 'online') g.onlineCount += 1;
      else if (item.presence === 'stale') g.staleCount += 1;
      else g.offlineCount += 1;
      if (item.isSelf) g.hasSelf = true;
    }

    const clusters = [];
    const presRank = { online: 0, stale: 1, offline: 2 };
    for (const g of groups.values()) {
      g.items.sort(
        (a, b) =>
          Number(b.isSelf) - Number(a.isSelf) ||
          (presRank[a.presence] ?? 3) - (presRank[b.presence] ?? 3) ||
          a.name.localeCompare(b.name),
      );
      const count = g.items.length;
      const first = g.items[0];
      const cityLabel = first.city || first.region || first.country || first.name;
      clusters.push({
        id: g.id,
        lat: g.latSum / count,
        lon: g.lonSum / count,
        count,
        onlineCount: g.onlineCount,
        staleCount: g.staleCount,
        offlineCount: g.offlineCount,
        hasSelf: g.hasSelf,
        label: count === 1 ? first.name : cityLabel,
        locationText: first.locationText,
        items: g.items,
      });
    }
    return clusters;
  }

  function carrierPriority(carrier, stalled) {
    if (stalled) return 5;
    if (carrier === 'blocked') return 4;
    if (carrier === 'derp') return 3;
    if (carrier === 'relay') return 2;
    if (carrier === 'tunnel') return 1;
    return 0;
  }

  function buildLinkFeatures(clusters, meshView, livePeers) {
    const byNode = new Map();
    const byAgent = new Map();
    let selfCluster = null;

    for (const c of clusters || []) {
      if (c.hasSelf) selfCluster = c;
      for (const item of c.items) {
        if (item.overlayNodeId) byNode.set(item.overlayNodeId, c);
        if (item.agentId) byAgent.set(item.agentId, c);
        if (item.id) {
          if (!byNode.has(item.id)) byNode.set(item.id, c);
          if (!byAgent.has(item.id)) byAgent.set(item.id, c);
        }
      }
    }

    const pairs = new Map();
    const addEdge = (cA, cB, carrier, stalled, rttMs) => {
      if (!cA || !cB || cA.id === cB.id) return;
      if (carrier === 'offline') return;
      const [first, second] = cA.id < cB.id ? [cA, cB] : [cB, cA];
      const key = first.id + '~' + second.id;
      const prev = pairs.get(key);
      if (!prev) {
        pairs.set(key, {
          key,
          from: first,
          to: second,
          carrier,
          stalled: Boolean(stalled),
          rttMs: typeof rttMs === 'number' && Number.isFinite(rttMs) ? Math.round(rttMs) : null,
          count: 1,
        });
      } else {
        prev.count += 1;
        if (carrierPriority(carrier, stalled) > carrierPriority(prev.carrier, prev.stalled)) {
          prev.carrier = carrier;
          prev.stalled = Boolean(stalled);
        }
        if (typeof rttMs === 'number' && Number.isFinite(rttMs)) {
          prev.rttMs = prev.rttMs == null ? Math.round(rttMs) : Math.min(prev.rttMs, Math.round(rttMs));
        }
      }
    };

    // 1. Org-wide peer edges from cmd_mesh
    const edges = (meshView && Array.isArray(meshView.edges) && meshView.edges) || [];
    for (const e of edges) {
      const cFrom = byNode.get(e.from);
      const cTo = byNode.get(e.to);
      if (!cFrom || !cTo) continue;
      addEdge(cFrom, cTo, normalizeCarrier(e.carrier), Boolean(e.stalled), e.rtt_ms);
    }

    // 2. Supplement with live peers from cmd_device_view so self links appear even without stats
    if (selfCluster && Array.isArray(livePeers)) {
      for (const p of livePeers) {
        if (!p || !p.online) continue;
        const target = (p.node_id && byNode.get(p.node_id)) || (p.agent_id && byAgent.get(p.agent_id));
        if (!target || target.id === selfCluster.id) continue;
        const [a, b] = selfCluster.id < target.id ? [selfCluster, target] : [target, selfCluster];
        const key = a.id + '~' + b.id;
        if (pairs.has(key)) continue;
        const conn = normalizeCarrier(p.connection);
        const stalled = Boolean(p.stalled && (conn === 'direct' || conn === 'relay'));
        addEdge(selfCluster, target, conn, stalled, p.rtt_ms);
      }
    }

    const features = [];
    for (const link of pairs.values()) {
      const coords = interpolateGreatCircle([link.from.lon, link.from.lat], [link.to.lon, link.to.lat], 16, 24);
      const width = link.count >= 5 ? 2.2 : link.count >= 2 ? 1.8 : 1.5;
      const opacity = link.stalled || link.carrier === 'blocked' ? 0.9 : 0.78;
      features.push({
        type: 'Feature',
        geometry: { type: 'LineString', coordinates: coords },
        properties: {
          key: link.key,
          carrier: link.carrier,
          stalled: link.stalled,
          count: link.count,
          rttMs: link.rttMs,
          width,
          opacity,
        },
      });
    }
    return { type: 'FeatureCollection', features };
  }

  /* ── Plan B: Same-city egress-IP site-grouped Spiderfy + radial fallback ── */

  function effectiveSiteKey(item) {
    if (!item || typeof item !== 'object') return '';
    return cleanText(item.physicalPublicIp) || cleanText(item.publicIp) || '';
  }

  function truncateFootLabel(name, maxChars) {
    const s = String(name || '');
    const limit = maxChars || 14;
    if (s.length <= limit) return s;
    return s.slice(0, limit - 1) + '…';
  }

  function sortClusterItems(items) {
    const presRank = { online: 0, stale: 1, offline: 2 };
    return (items || []).slice().sort(
      (a, b) =>
        Number(b.isSelf) - Number(a.isSelf) ||
        (presRank[a.presence] ?? 3) - (presRank[b.presence] ?? 3) ||
        String(a.name || '').localeCompare(String(b.name || '')) ||
        String(a.id || '').localeCompare(String(b.id || '')),
    );
  }

  // Inter-site carrier priority: stalled surfaces faults; otherwise best active path
  // (direct > tunnel > relay > derp > blocked).
  function siteLinkCarrierPriority(carrier, stalled) {
    if (stalled) return 5;
    if (carrier === 'direct') return 4;
    if (carrier === 'tunnel') return 3;
    if (carrier === 'relay') return 2;
    if (carrier === 'derp') return 1;
    if (carrier === 'blocked') return 0;
    return -1;
  }

  function pointHitsSiteHeader(px, py, sites) {
    for (const s of sites) {
      const halfW = 66;
      const topY = s.cy - s.podRadius - 40;
      const botY = s.cy - s.podRadius + 4;
      if (px >= s.cx - halfW && px <= s.cx + halfW && py >= topY && py <= botY) {
        return true;
      }
    }
    return false;
  }

  function computeSpiderfyLayout(cluster, meshView, livePeers) {
    if (!cluster || !Array.isArray(cluster.items)) return null;
    const count = cluster.items.length;
    if (count <= 1) return null;

    const orderedAll = sortClusterItems(cluster.items);
    if (count > SPIDERFY_SPIRAL_MAX) {
      return {
        mode: 'list',
        items: orderedAll,
        sites: [],
        feet: [],
        siteLinks: [],
        maxRadius: 0,
        maxRadiusX: 0,
        maxRadiusY: 0,
      };
    }

    // Group devices by effective egress IP (physicalPublicIp overrides publicIp).
    const buckets = new Map();
    const unknownItems = [];
    for (const item of orderedAll) {
      const key = effectiveSiteKey(item);
      if (!key) {
        unknownItems.push(item);
      } else {
        let arr = buckets.get(key);
        if (!arr) {
          arr = [];
          buckets.set(key, arr);
        }
        arr.push(item);
      }
    }

    const distinctIpCount = buckets.size;
    const totalPods = distinctIpCount + (unknownItems.length > 0 ? 1 : 0);

    if (distinctIpCount >= 2 && totalPods <= SPIDERFY_MAX_SITES) {
      const sites = [];
      const addSite = (key, items, isUnknown) => {
        const sorted = sortClusterItems(items);
        let onlineCount = 0;
        let staleCount = 0;
        let offlineCount = 0;
        let hasSelf = false;
        for (const it of sorted) {
          if (it.presence === 'online') onlineCount += 1;
          else if (it.presence === 'stale') staleCount += 1;
          else offlineCount += 1;
          if (it.isSelf) hasSelf = true;
        }
        sites.push({
          id: isUnknown ? 'site-unknown' : 'site-' + key,
          key: isUnknown ? '' : key,
          isUnknown,
          labelCode: '',
          hasSelf,
          items: sorted,
          count: sorted.length,
          onlineCount,
          staleCount,
          offlineCount,
          intraMinRttMs: null,
          cx: 0,
          cy: 0,
          podRadius: 26,
          feet: [],
        });
      };

      for (const [key, items] of buckets.entries()) {
        addSite(key, items, false);
      }
      if (unknownItems.length > 0) {
        addSite('', unknownItems, true);
      }

      sites.sort(
        (a, b) =>
          Number(b.hasSelf) - Number(a.hasSelf) ||
          b.onlineCount - a.onlineCount ||
          b.count - a.count ||
          Number(a.isUnknown) - Number(b.isUnknown) ||
          a.key.localeCompare(b.key),
      );

      const siteLetters = ['A', 'B', 'C', 'D', 'E', 'F'];
      const compact = sites.length >= 4;
      const siteById = new Map();
      const itemByNode = new Map();
      const itemByAgent = new Map();
      const siteOfItemId = new Map();
      let selfItem = null;

      for (let idx = 0; idx < sites.length; idx += 1) {
        const site = sites[idx];
        site.labelCode = siteLetters[idx] || String(idx + 1);
        siteById.set(site.id, site);
        for (const item of site.items) {
          siteOfItemId.set(item.id, site);
          if (item.isSelf) selfItem = item;
          if (item.overlayNodeId) itemByNode.set(item.overlayNodeId, item);
          if (item.agentId) itemByAgent.set(item.agentId, item);
          if (item.id) {
            if (!itemByNode.has(item.id)) itemByNode.set(item.id, item);
            if (!itemByAgent.has(item.id)) itemByAgent.set(item.id, item);
          }
        }

        // Local mini-radial (or mini-spiral if >= 9 in one site) foot geometry.
        const m = site.items.length;
        if (m === 1) {
          site.podRadius = compact ? 22 : 25;
          site._localFeet = [{ item: site.items[0], localDx: 0, localDy: 0, angle: -Math.PI / 2, hideLabel: false }];
        } else if (m <= SPIDERFY_CIRCLE_MAX) {
          const sep = compact ? 24 : 33;
          const rMin = compact ? 18 : 26;
          const ringR = Math.max(rMin, (m * sep) / (2 * Math.PI));
          site.podRadius = Math.ceil(ringR + (compact ? 14 : 18));
          site._localFeet = site.items.map((item, i) => {
            const angle = -Math.PI / 2 + (2 * Math.PI * i) / m;
            return {
              item,
              localDx: Math.cos(angle) * ringR,
              localDy: Math.sin(angle) * ringR,
              angle,
              hideLabel: false,
            };
          });
        } else {
          const r0 = 15;
          const k = 3.0;
          const sep = 21;
          let theta = 0;
          let r = r0;
          let maxR = r0;
          site._localFeet = site.items.map((item, i) => {
            if (i > 0) {
              theta += sep / r;
              r = r0 + k * theta;
            }
            const angle = -Math.PI / 2 + theta;
            if (r > maxR) maxR = r;
            return {
              item,
              localDx: Math.cos(angle) * r,
              localDy: Math.sin(angle) * r,
              angle,
              hideLabel: true,
            };
          });
          site.podRadius = Math.ceil(maxR + 14);
        }
      }

      // Position site pods cleanly around (0, 0) inside the tall inline stage.
      if (sites.length === 2) {
        const halfSpan = Math.max(150, Math.ceil((sites[0].podRadius + sites[1].podRadius + 176) / 2));
        sites[0].cx = -halfSpan;
        sites[0].cy = 0;
        sites[1].cx = halfSpan;
        sites[1].cy = 0;
      } else if (sites.length === 3) {
        const maxPod = Math.max(sites[0].podRadius, sites[1].podRadius, sites[2].podRadius);
        const rx = Math.max(122, maxPod * 2 + 56);
        const ry = Math.max(76, Math.min(96, Math.ceil(maxPod + 48)));
        const triAngles = [-Math.PI / 2, Math.PI / 6, (5 * Math.PI) / 6];
        for (let i = 0; i < 3; i += 1) {
          sites[i].cx = Math.round(Math.cos(triAngles[i]) * rx);
          sites[i].cy = Math.round(Math.sin(triAngles[i]) * ry);
        }
      } else if (sites.length === 4) {
        const maxPod = Math.max(...sites.map((s) => s.podRadius));
        const rx = Math.max(134, Math.ceil(maxPod * 1.9 + 76));
        const ry = Math.max(84, Math.min(102, Math.ceil(maxPod * 1.45 + 46)));
        const quadAngles = [(-3 * Math.PI) / 4, -Math.PI / 4, Math.PI / 4, (3 * Math.PI) / 4];
        for (let i = 0; i < 4; i += 1) {
          sites[i].cx = Math.round(Math.cos(quadAngles[i]) * rx);
          sites[i].cy = Math.round(Math.sin(quadAngles[i]) * ry);
        }
      } else {
        const maxPod = Math.max(...sites.map((s) => s.podRadius));
        const rx = Math.max(
          150,
          Math.ceil(((sites.length * (maxPod * 2 + 26)) / (2 * Math.PI)) * 1.15),
        );
        const ry = Math.max(96, Math.min(116, Math.ceil(rx * 0.64)));
        for (let i = 0; i < sites.length; i += 1) {
          const ang = -Math.PI / 2 + (2 * Math.PI * i) / sites.length;
          sites[i].cx = Math.round(Math.cos(ang) * rx);
          sites[i].cy = Math.round(Math.sin(ang) * ry);
        }
      }

      // Finalize screen-space foot coordinates.
      const allFeet = [];
      let footIndex = 0;
      for (const site of sites) {
        const localFeet = site._localFeet || [];
        delete site._localFeet;
        for (const lf of localFeet) {
          const dx = Math.round((site.cx + lf.localDx) * 10) / 10;
          const dy = Math.round((site.cy + lf.localDy) * 10) / 10;
          let labelSide;
          if (site.count === 1) {
            labelSide = site.cx < -4 ? 'left' : 'right';
          } else if (Math.abs(lf.localDx) > 4) {
            labelSide = lf.localDx < 0 ? 'left' : 'right';
          } else {
            labelSide = site.cx < -4 ? 'left' : 'right';
          }
          const foot = {
            item: lf.item,
            siteId: site.id,
            index: footIndex,
            dx,
            dy,
            localDx: Math.round(lf.localDx * 10) / 10,
            localDy: Math.round(lf.localDy * 10) / 10,
            angle: lf.angle,
            presence: lf.item.presence,
            shortLabel: truncateFootLabel(lf.item.name, 14),
            labelSide,
            hideLabel: Boolean(lf.hideLabel),
          };
          footIndex += 1;
          site.feet.push(foot);
          allFeet.push(foot);
        }
      }

      // Aggregate intra-site min RTT and inter-site live links from meshView.edges + livePeers.
      const sitePairMap = new Map();
      const seenDevicePairs = new Set();

      const recordPair = (itemA, itemB, carrier, stalled, rawRtt, fromMesh) => {
        if (!itemA || !itemB || itemA.id === itemB.id) return;
        if (carrier === 'offline') return;
        const siteA = siteOfItemId.get(itemA.id);
        const siteB = siteOfItemId.get(itemB.id);
        if (!siteA || !siteB) return;
        const rttMs =
          typeof rawRtt === 'number' && Number.isFinite(rawRtt) ? Math.round(rawRtt) : null;
        const devKey = itemA.id < itemB.id ? itemA.id + '~' + itemB.id : itemB.id + '~' + itemA.id;
        const alreadySeen = seenDevicePairs.has(devKey);
        if (fromMesh) seenDevicePairs.add(devKey);

        if (siteA.id === siteB.id) {
          if (rttMs != null) {
            siteA.intraMinRttMs =
              siteA.intraMinRttMs == null ? rttMs : Math.min(siteA.intraMinRttMs, rttMs);
          }
          return;
        }

        const [first, second] = siteA.id < siteB.id ? [siteA, siteB] : [siteB, siteA];
        const pairKey = first.id + '~' + second.id;
        const prev = sitePairMap.get(pairKey);
        if (!prev) {
          sitePairMap.set(pairKey, {
            key: pairKey,
            fromSite: first,
            toSite: second,
            carrier,
            stalled: Boolean(stalled),
            rttMs,
            count: 1,
          });
        } else {
          if (!alreadySeen) {
            prev.count += 1;
            if (
              siteLinkCarrierPriority(carrier, stalled) >
              siteLinkCarrierPriority(prev.carrier, prev.stalled)
            ) {
              prev.carrier = carrier;
              prev.stalled = Boolean(stalled);
            }
          }
          if (rttMs != null) {
            prev.rttMs = prev.rttMs == null ? rttMs : Math.min(prev.rttMs, rttMs);
          }
        }
      };

      const edges = (meshView && Array.isArray(meshView.edges) && meshView.edges) || [];
      for (const e of edges) {
        if (!e) continue;
        const fromItem = itemByNode.get(e.from) || itemByAgent.get(e.from);
        const toItem = itemByNode.get(e.to) || itemByAgent.get(e.to);
        if (!fromItem || !toItem) continue;
        recordPair(fromItem, toItem, normalizeCarrier(e.carrier), Boolean(e.stalled), e.rtt_ms, true);
      }

      if (selfItem && Array.isArray(livePeers)) {
        for (const p of livePeers) {
          if (!p || !p.online) continue;
          const target =
            (p.node_id && itemByNode.get(p.node_id)) ||
            (p.agent_id && itemByAgent.get(p.agent_id));
          if (!target || target.id === selfItem.id) continue;
          const conn = normalizeCarrier(p.connection);
          const stalled = Boolean(p.stalled && (conn === 'direct' || conn === 'relay'));
          recordPair(selfItem, target, conn, stalled, p.rtt_ms, false);
        }
      }

      // Compute clean curved SVG paths + non-overlapping midpoint pills for inter-site links.
      const siteLinks = [];
      let linkIdx = 0;
      for (const entry of sitePairMap.values()) {
        const sA = entry.fromSite;
        const sB = entry.toSite;
        let sx, sy, ex, ey, ctrlX, ctrlY, pillX, pillY;

        if (sites.length === 2) {
          const [leftSite, rightSite] = sA.cx <= sB.cx ? [sA, sB] : [sB, sA];
          sx = leftSite.cx + leftSite.podRadius * 0.78;
          sy = leftSite.cy + leftSite.podRadius * 0.62;
          ex = rightSite.cx - rightSite.podRadius * 0.78;
          ey = rightSite.cy + rightSite.podRadius * 0.62;
          ctrlX = (sx + ex) / 2;
          ctrlY = Math.max(66, Math.max(leftSite.podRadius, rightSite.podRadius) + 32);
          pillX = 0.25 * sx + 0.5 * ctrlX + 0.25 * ex;
          pillY = 0.25 * sy + 0.5 * ctrlY + 0.25 * ey;
        } else {
          const dx = sB.cx - sA.cx;
          const dy = sB.cy - sA.cy;
          const dist = Math.hypot(dx, dy) || 1;
          const ux = dx / dist;
          const uy = dy / dist;
          sx = sA.cx + ux * (sA.podRadius + 4);
          sy = sA.cy + uy * (sA.podRadius + 4);
          ex = sB.cx - ux * (sB.podRadius + 4);
          ey = sB.cy - uy * (sB.podRadius + 4);
          const mx = (sx + ex) / 2;
          const my = (sy + ey) / 2;
          let nx = -uy;
          let ny = ux;
          if (Math.hypot(mx, my) >= 16) {
            if (mx * nx + my * ny < 0) {
              nx = -nx;
              ny = -ny;
            }
          } else if (linkIdx % 2 === 1) {
            nx = -nx;
            ny = -ny;
          }
          const bow = Math.min(40, Math.max(22, dist * 0.2));
          ctrlX = mx + nx * bow;
          ctrlY = my + ny * bow;
          pillX = 0.25 * sx + 0.5 * ctrlX + 0.25 * ex;
          pillY = 0.25 * sy + 0.5 * ctrlY + 0.25 * ey;

          if (pointHitsSiteHeader(pillX, pillY, sites)) {
            nx = -nx;
            ny = -ny;
            ctrlX = mx + nx * bow;
            ctrlY = my + ny * bow;
            pillX = 0.25 * sx + 0.5 * ctrlX + 0.25 * ex;
            pillY = 0.25 * sy + 0.5 * ctrlY + 0.25 * ey;
          }

          for (let attempt = 0; attempt < 3; attempt += 1) {
            const collides = siteLinks.some((o) => Math.hypot(pillX - o.pillX, pillY - o.pillY) < 26);
            if (!collides) break;
            ctrlX += nx * 18;
            ctrlY += ny * 18;
            pillX = 0.25 * sx + 0.5 * ctrlX + 0.25 * ex;
            pillY = 0.25 * sy + 0.5 * ctrlY + 0.25 * ey;
          }
        }

        const r1 = (v) => Math.round(v * 10) / 10;
        const pathD =
          'M ' +
          r1(sx) +
          ' ' +
          r1(sy) +
          ' Q ' +
          r1(ctrlX) +
          ' ' +
          r1(ctrlY) +
          ' ' +
          r1(ex) +
          ' ' +
          r1(ey);
        siteLinks.push({
          key: entry.key,
          fromSiteId: sA.id,
          toSiteId: sB.id,
          carrier: entry.carrier,
          stalled: entry.stalled,
          rttMs: entry.rttMs,
          count: entry.count,
          sx: r1(sx),
          sy: r1(sy),
          ctrlX: r1(ctrlX),
          ctrlY: r1(ctrlY),
          ex: r1(ex),
          ey: r1(ey),
          pillX: r1(pillX),
          pillY: r1(pillY),
          pathD,
        });
        linkIdx += 1;
      }

      let maxRadiusX = 90;
      let maxRadiusY = 70;
      for (const s of sites) {
        maxRadiusX = Math.max(maxRadiusX, Math.abs(s.cx) + s.podRadius + 24);
        maxRadiusY = Math.max(maxRadiusY, Math.abs(s.cy) + s.podRadius + 46);
      }
      for (const l of siteLinks) {
        maxRadiusX = Math.max(maxRadiusX, Math.abs(l.pillX) + 52);
        maxRadiusY = Math.max(maxRadiusY, Math.abs(l.pillY) + 22);
      }

      return {
        mode: 'sites',
        sites,
        feet: allFeet,
        siteLinks,
        maxRadius: Math.max(maxRadiusX, maxRadiusY),
        maxRadiusX,
        maxRadiusY,
      };
    }

    // Classic radial Spiderfy fallback (matching Web spiderfy.ts: 2..8 circle, 9..20 spiral).
    const sep = 28;
    if (count <= SPIDERFY_CIRCLE_MAX) {
      const rMin = 28;
      const radius = Math.max(rMin, (count * sep) / (2 * Math.PI));
      const feet = orderedAll.map((item, i) => {
        const angle = -Math.PI / 2 + (2 * Math.PI * i) / count;
        const dx = Math.round(Math.cos(angle) * radius * 10) / 10;
        const dy = Math.round(Math.sin(angle) * radius * 10) / 10;
        return {
          item,
          siteId: null,
          index: i,
          dx,
          dy,
          angle,
          radius,
          presence: item.presence,
          shortLabel: truncateFootLabel(item.name, 14),
          labelSide: dx < -4 ? 'left' : 'right',
          hideLabel: false,
        };
      });
      return {
        mode: 'circle',
        sites: [],
        feet,
        siteLinks: [],
        maxRadius: radius,
        maxRadiusX: radius,
        maxRadiusY: radius,
      };
    }

    const r0 = 22;
    const k = 4;
    let theta = 0;
    let r = r0;
    let maxRadius = r0;
    const feet = orderedAll.map((item, i) => {
      if (i > 0) {
        theta += sep / r;
        r = r0 + k * theta;
      }
      const angle = -Math.PI / 2 + theta;
      if (r > maxRadius) maxRadius = r;
      const dx = Math.round(Math.cos(angle) * r * 10) / 10;
      const dy = Math.round(Math.sin(angle) * r * 10) / 10;
      return {
        item,
        siteId: null,
        index: i,
        dx,
        dy,
        angle,
        radius: r,
        presence: item.presence,
        shortLabel: truncateFootLabel(item.name, 14),
        labelSide: dx < -4 ? 'left' : 'right',
        hideLabel: true,
      };
    });
    return {
      mode: 'spiral',
      sites: [],
      feet,
      siteLinks: [],
      maxRadius,
      maxRadiusX: maxRadius,
      maxRadiusY: maxRadius,
    };
  }

  function computeInitialView(locatedItems, width, height) {
    const list = Array.isArray(locatedItems) ? locatedItems : [];
    let centerLon = DEFAULT_CENTER[0];
    let centerLat = DEFAULT_CENTER[1];
    if (list.length === 1) {
      centerLon = list[0].lon;
      centerLat = list[0].lat;
    } else if (list.length > 1) {
      // Circular mean for longitude handles trans-Pacific fleets cleanly
      let sinSum = 0;
      let cosSum = 0;
      let latSum = 0;
      for (const item of list) {
        const rad = (item.lon * Math.PI) / 180;
        sinSum += Math.sin(rad);
        cosSum += Math.cos(rad);
        latSum += item.lat;
      }
      if (Math.hypot(sinSum, cosSum) > 1e-4) {
        centerLon = (Math.atan2(sinSum, cosSum) * 180) / Math.PI;
      } else {
        centerLon = list[0].lon;
      }
      centerLat = Math.max(-45, Math.min(55, latSum / list.length));
    }
    const zoom = computeFitGlobeZoom(width || 640, height || 580, centerLat, 0.86);
    return { center: [centerLon, centerLat], zoom };
  }

  /* ── Canvas2D Retina icon renderer ───────────────────────────────── */

  function makeCanvas(cssW, cssH, dpr) {
    const canvas = document.createElement('canvas');
    canvas.width = Math.max(1, Math.round(cssW * dpr));
    canvas.height = Math.max(1, Math.round(cssH * dpr));
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    return { canvas, ctx };
  }

  function canvasToImageData(canvas, ctx) {
    const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
    return { width: img.width, height: img.height, data: img.data };
  }

  function drawSingleDeviceIcon(presence, isSelf, tok, dpr) {
    const box = 28;
    const cx = box / 2;
    const cy = box / 2;
    const { canvas, ctx } = makeCanvas(box, box, dpr);

    if (isSelf) {
      ctx.beginPath();
      ctx.arc(cx, cy, 9.5, 0, Math.PI * 2);
      ctx.fillStyle = tok.mode === 'dark' ? 'rgba(60, 199, 185, 0.18)' : 'rgba(10, 143, 134, 0.16)';
      ctx.fill();
      ctx.lineWidth = 1.75;
      ctx.strokeStyle = tok.selfRing;
      ctx.stroke();
    }

    if (presence === 'online') {
      ctx.beginPath();
      ctx.arc(cx, cy, 4.5, 0, Math.PI * 2);
      ctx.fillStyle = tok.online;
      ctx.fill();
      ctx.lineWidth = 1.4;
      ctx.strokeStyle = tok.ocean;
      ctx.stroke();
    } else if (presence === 'stale') {
      ctx.beginPath();
      ctx.arc(cx, cy, 4.8, 0, Math.PI * 2);
      ctx.fillStyle = tok.ocean;
      ctx.fill();
      ctx.beginPath();
      ctx.arc(cx, cy, 4.8, Math.PI / 2, (Math.PI * 3) / 2);
      ctx.closePath();
      ctx.fillStyle = tok.stale;
      ctx.fill();
      ctx.beginPath();
      ctx.arc(cx, cy, 4.8, 0, Math.PI * 2);
      ctx.lineWidth = 1.5;
      ctx.strokeStyle = tok.stale;
      ctx.stroke();
    } else {
      ctx.beginPath();
      ctx.arc(cx, cy, 4.8, 0, Math.PI * 2);
      ctx.fillStyle = tok.ocean;
      ctx.fill();
      ctx.lineWidth = 1.4;
      ctx.strokeStyle = tok.offline;
      ctx.stroke();
      ctx.beginPath();
      ctx.moveTo(cx - 3.2, cy + 3.2);
      ctx.lineTo(cx + 3.2, cy - 3.2);
      ctx.stroke();
    }
    return canvasToImageData(canvas, ctx);
  }

  function drawDonutIcon(cluster, tok, dpr) {
    const diameter = cluster.count >= 50 ? 26 : cluster.count >= 10 ? 22 : 18;
    const box = diameter + 14;
    const cx = box / 2;
    const cy = box / 2;
    const outerR = diameter / 2;
    const ringW = 3;
    const { canvas, ctx } = makeCanvas(box, box, dpr);

    if (cluster.hasSelf) {
      ctx.beginPath();
      ctx.arc(cx, cy, outerR + 3.5, 0, Math.PI * 2);
      ctx.strokeStyle = tok.selfRing;
      ctx.lineWidth = 1.6;
      ctx.stroke();
    }

    ctx.beginPath();
    ctx.arc(cx, cy, outerR + 1.2, 0, Math.PI * 2);
    ctx.fillStyle = tok.ocean;
    ctx.fill();

    const total = Math.max(1, cluster.count);
    const slices = [
      { n: cluster.onlineCount, color: tok.online },
      { n: cluster.staleCount, color: tok.stale },
      { n: cluster.offlineCount, color: tok.offline },
    ];
    let start = -Math.PI / 2;
    for (const s of slices) {
      if (s.n <= 0) continue;
      const sweep = (s.n / total) * Math.PI * 2;
      ctx.beginPath();
      ctx.arc(cx, cy, outerR - ringW / 2, start, start + sweep);
      ctx.strokeStyle = s.color;
      ctx.lineWidth = ringW;
      ctx.stroke();
      start += sweep;
    }

    ctx.beginPath();
    ctx.arc(cx, cy, outerR - ringW, 0, Math.PI * 2);
    ctx.fillStyle = tok.hubFill;
    ctx.fill();

    const fontSize = diameter >= 26 ? 11.5 : diameter >= 22 ? 10.5 : 10;
    ctx.font = '600 ' + fontSize + 'px system-ui, -apple-system, "Segoe UI", sans-serif';
    ctx.fillStyle = tok.hubText;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(String(cluster.count), cx, cy + 0.5);

    return canvasToImageData(canvas, ctx);
  }

  function ensureStaticIcons(map, mode, dpr) {
    if (!map.hasImage(LABEL_BLOCKER_ICON_ID)) {
      map.addImage(
        LABEL_BLOCKER_ICON_ID,
        { width: 2, height: 2, data: new Uint8ClampedArray(2 * 2 * 4) },
        { pixelRatio: 1 },
      );
    }
    const tok = getTokens(mode);
    for (const p of ['online', 'stale', 'offline']) {
      for (const isSelf of [false, true]) {
        const id = 'nm-dev-' + p + (isSelf ? '-self' : '') + '-' + mode;
        if (!map.hasImage(id)) {
          map.addImage(id, drawSingleDeviceIcon(p, isSelf, tok, dpr), { pixelRatio: dpr });
        }
      }
    }
  }

  function resolveClusterIconId(map, cluster, mode, dpr) {
    if (cluster.count === 1) {
      const item = cluster.items[0];
      return 'nm-dev-' + item.presence + (item.isSelf ? '-self' : '') + '-' + mode;
    }
    const id =
      'nm-donut-' +
      cluster.count +
      '-' +
      cluster.onlineCount +
      '-' +
      cluster.staleCount +
      '-' +
      cluster.offlineCount +
      '-' +
      (cluster.hasSelf ? '1' : '0') +
      '-' +
      mode;
    if (map && !map.hasImage(id)) {
      map.addImage(id, drawDonutIcon(cluster, getTokens(mode), dpr), { pixelRatio: dpr });
    }
    return id;
  }

  function buildMarkerFeatures(clusters, map, mode, dpr, hiddenClusterId) {
    const features = [];
    for (const c of clusters || []) {
      if (hiddenClusterId && c.id === hiddenClusterId) continue;
      const icon = map
        ? resolveClusterIconId(map, c, mode, dpr)
        : c.count === 1
          ? 'nm-dev-' + c.items[0].presence + (c.items[0].isSelf ? '-self' : '') + '-' + mode
          : 'nm-donut-' + c.count + '-' + mode;
      const sortKey = c.hasSelf ? 0 : c.count > 1 ? 10 - Math.min(9, c.count) : c.onlineCount > 0 ? 20 : 30;
      features.push({
        type: 'Feature',
        geometry: { type: 'Point', coordinates: [c.lon, c.lat] },
        properties: {
          clusterId: c.id,
          label: c.label || '',
          count: c.count,
          onlineCount: c.onlineCount,
          hasSelf: c.hasSelf,
          icon,
          sortKey,
        },
      });
    }
    return { type: 'FeatureCollection', features };
  }

  /* ── Symmetrical 360° Fresnel rim SVG ────────────────────────────── */

  function makeFresnelDom(svgEl) {
    if (!svgEl) return null;
    const uid = 'nm-fr-' + Math.random().toString(36).slice(2, 8);
    const outerId = uid + '-outer';
    const innerId = uid + '-inner';
    const defs = document.createElementNS(SVG_NS, 'defs');

    const outerGrad = document.createElementNS(SVG_NS, 'radialGradient');
    outerGrad.setAttribute('id', outerId);
    outerGrad.setAttribute('cx', '50%');
    outerGrad.setAttribute('cy', '50%');
    outerGrad.setAttribute('r', '50%');
    const os0 = document.createElementNS(SVG_NS, 'stop');
    os0.setAttribute('offset', '84%');
    os0.setAttribute('stop-opacity', '0');
    const os1 = document.createElementNS(SVG_NS, 'stop');
    os1.setAttribute('offset', '87.5%');
    const os2 = document.createElementNS(SVG_NS, 'stop');
    os2.setAttribute('offset', '93%');
    const os3 = document.createElementNS(SVG_NS, 'stop');
    os3.setAttribute('offset', '100%');
    os3.setAttribute('stop-opacity', '0');
    outerGrad.append(os0, os1, os2, os3);

    const innerGrad = document.createElementNS(SVG_NS, 'radialGradient');
    innerGrad.setAttribute('id', innerId);
    innerGrad.setAttribute('cx', '50%');
    innerGrad.setAttribute('cy', '50%');
    innerGrad.setAttribute('r', '50%');
    const is0 = document.createElementNS(SVG_NS, 'stop');
    is0.setAttribute('offset', '0%');
    is0.setAttribute('stop-opacity', '0');
    const is1 = document.createElementNS(SVG_NS, 'stop');
    is1.setAttribute('offset', '78%');
    is1.setAttribute('stop-opacity', '0');
    const is2 = document.createElementNS(SVG_NS, 'stop');
    is2.setAttribute('offset', '91%');
    const is3 = document.createElementNS(SVG_NS, 'stop');
    is3.setAttribute('offset', '98.5%');
    const is4 = document.createElementNS(SVG_NS, 'stop');
    is4.setAttribute('offset', '100%');
    innerGrad.append(is0, is1, is2, is3, is4);

    defs.append(outerGrad, innerGrad);
    const outerCircle = document.createElementNS(SVG_NS, 'circle');
    outerCircle.setAttribute('fill', 'url(#' + outerId + ')');
    const innerCircle = document.createElementNS(SVG_NS, 'circle');
    innerCircle.setAttribute('fill', 'url(#' + innerId + ')');
    const strokeCircle = document.createElementNS(SVG_NS, 'circle');
    strokeCircle.setAttribute('fill', 'none');
    strokeCircle.setAttribute('stroke-width', '1.15');

    svgEl.replaceChildren(defs, outerCircle, innerCircle, strokeCircle);

    function applyTheme(mode) {
      const dark = mode === 'dark';
      const outerPeak = dark ? '#2A7AB0' : '#93B8DC';
      const outerMid = dark ? '#1C5A85' : '#BFD8F0';
      const inner = dark ? '#2A7AB0' : '#93B8DC';
      const innerPeak = dark ? '#56B4E9' : '#6E9CC7';
      os0.setAttribute('stop-color', outerPeak);
      os1.setAttribute('stop-color', outerPeak);
      os1.setAttribute('stop-opacity', dark ? '0.28' : '0.20');
      os2.setAttribute('stop-color', outerMid);
      os2.setAttribute('stop-opacity', dark ? '0.10' : '0.08');
      os3.setAttribute('stop-color', outerMid);

      is0.setAttribute('stop-color', inner);
      is1.setAttribute('stop-color', inner);
      is2.setAttribute('stop-color', inner);
      is2.setAttribute('stop-opacity', dark ? '0.08' : '0.05');
      is3.setAttribute('stop-color', innerPeak);
      is3.setAttribute('stop-opacity', dark ? '0.22' : '0.14');
      is4.setAttribute('stop-color', innerPeak);
      is4.setAttribute('stop-opacity', dark ? '0.28' : '0.18');
      strokeCircle.setAttribute(
        'stroke',
        dark ? 'rgba(86, 180, 233, 0.34)' : 'rgba(74, 91, 112, 0.24)',
      );
    }

    function sync(width, height, zoom, latDeg) {
      const g = computeGlobeScreenCircle(width, height, zoom, latDeg);
      if (g.rimOpacity <= 0.01 || g.radius <= 1) {
        svgEl.style.opacity = '0';
        return;
      }
      svgEl.style.opacity = String(g.rimOpacity);
      const cx = g.cx.toFixed(1);
      const cy = g.cy.toFixed(1);
      outerCircle.setAttribute('cx', cx);
      outerCircle.setAttribute('cy', cy);
      outerCircle.setAttribute('r', (g.radius * 1.14).toFixed(1));
      innerCircle.setAttribute('cx', cx);
      innerCircle.setAttribute('cy', cy);
      innerCircle.setAttribute('r', g.radius.toFixed(1));
      strokeCircle.setAttribute('cx', cx);
      strokeCircle.setAttribute('cy', cy);
      strokeCircle.setAttribute('r', g.radius.toFixed(1));
    }

    return { applyTheme, sync };
  }

  /* ── Shared badge / DOM helpers (strictly textContent, zero innerHTML) ── */

  function connBadgeLabel(conn, stalled) {
    if (stalled) return t('dv.conn.stalled', null, 'Stalled');
    if (conn === 'derp') return t('dv.mesh.carrier.derp', null, 'DERP');
    if (conn === 'direct') return t('dv.conn.direct', null, 'Direct');
    if (conn === 'relay') return t('dv.conn.relay', null, 'Relay');
    if (conn === 'tunnel') return t('dv.conn.tunnel', null, 'Tunnel');
    if (conn === 'blocked') return t('dv.conn.blocked', null, 'Blocked');
    return t('dv.conn.offline', null, 'Offline');
  }

  function connBadgeClass(conn, stalled) {
    if (stalled) return 'badge badge-blocked';
    if (conn === 'derp') return 'badge badge-relay';
    if (conn === 'direct' || conn === 'relay' || conn === 'tunnel' || conn === 'blocked') {
      return 'badge badge-' + conn;
    }
    return 'badge badge-offline';
  }

  function dotClassForPresence(presence) {
    if (presence === 'online') return 'dot dot-on';
    if (presence === 'stale') return 'dot dot-warn';
    return 'dot dot-off';
  }

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }

  /* ── WebGL2 fallback: clean plain device list ────────────────────── */

  function renderFallbackList(container, projected) {
    if (!container) return;
    const notice = el(
      'p',
      'nm-fallback-notice',
      t(
        'dv.globe.fallbackNotice',
        null,
        '3D map requires WebGL2, which is unavailable on this display. Showing device list instead — you can still click Enlarge to open the standalone map.',
      ),
    );
    const items = (projected && projected.items) || [];
    if (!items.length) {
      const empty = el(
        'p',
        'nm-fallback-empty',
        t('dv.globe.fallbackEmpty', null, 'No devices to display yet.'),
      );
      container.replaceChildren(notice, empty);
      return;
    }

    const ul = el('ul', 'nm-fallback-list');
    for (const item of items) {
      const li = el('li', 'nm-fallback-item');
      const main = el('div', 'nm-fallback-main');
      main.appendChild(el('span', dotClassForPresence(item.presence)));
      main.appendChild(el('span', 'nm-fallback-name', item.name));
      if (item.isSelf) {
        main.appendChild(el('span', 'chip chip-self', t('dv.chip.thisDevice', null, 'this device')));
      }
      if (item.zoneLabel) {
        main.appendChild(
          el('span', 'chip dv-chip-zone' + (item.zonePinned ? ' is-pinned' : ''), item.zoneLabel),
        );
      }
      const locLabel = item.locationText || t('dv.globe.noLocation', null, 'Location unavailable');
      main.appendChild(el('span', 'nm-fallback-loc', locLabel));

      const meta = el('div', 'nm-fallback-meta');
      if (item.isSelf) {
        meta.appendChild(el('span', 'muted small', t('dv.chip.thisDevice', null, 'this device')));
      } else if (item.connection && item.connection !== 'offline') {
        meta.appendChild(
          el('span', connBadgeClass(item.connection, item.stalled), connBadgeLabel(item.connection, item.stalled)),
        );
        if (item.rttMs != null) {
          meta.appendChild(el('span', 'muted small mono', item.rttMs + ' ms'));
        }
      } else {
        const presText =
          item.presence === 'online'
            ? t('dv.presence.online', null, 'online')
            : item.presence === 'stale'
              ? t('dv.presence.stale', null, 'stale')
              : t('dv.presence.offline', null, 'offline');
        meta.appendChild(el('span', 'muted small', presText));
      }

      li.append(main, meta);
      ul.appendChild(li);
    }
    container.replaceChildren(notice, ul);
  }

  /* ── Tooltip & Spiderfy DOM builders (strictly textContent, zero innerHTML) ── */

  function populateDeviceTooltip(tipEl, item) {
    if (!tipEl || !item) return;
    const nodes = [];
    const head = el('div', 'nm-tip-head');
    head.append(el('span', dotClassForPresence(item.presence)), el('span', null, item.name));
    if (item.isSelf) {
      head.appendChild(el('span', 'chip chip-self', t('dv.chip.thisDevice', null, 'this device')));
    }
    nodes.push(head);

    const locRow = el('div', 'nm-tip-row');
    locRow.appendChild(
      el('span', null, item.locationText || t('dv.globe.noLocation', null, 'Location unavailable')),
    );
    if (item.zoneLabel) {
      locRow.appendChild(
        el('span', 'chip dv-chip-zone' + (item.zonePinned ? ' is-pinned' : ''), item.zoneLabel),
      );
    }
    nodes.push(locRow);

    const egressIp = effectiveSiteKey(item);
    if (egressIp) {
      const ipRow = el('div', 'nm-tip-row nm-tip-ip');
      ipRow.appendChild(
        el('span', 'mono', t('dv.globe.egressIp', { ip: egressIp }, 'Egress ' + egressIp)),
      );
      nodes.push(ipRow);
    }

    if (!item.isSelf && item.connection && item.connection !== 'offline') {
      const connRow = el('div', 'nm-tip-row');
      connRow.appendChild(
        el('span', connBadgeClass(item.connection, item.stalled), connBadgeLabel(item.connection, item.stalled)),
      );
      if (item.rttMs != null) {
        connRow.appendChild(el('span', 'mono', item.rttMs + ' ms'));
      }
      nodes.push(connRow);
    }
    tipEl.replaceChildren(...nodes);
  }

  function populateTooltip(tipEl, cluster) {
    if (!tipEl || !cluster) return;
    if (cluster.count === 1) {
      populateDeviceTooltip(tipEl, cluster.items[0]);
      return;
    }
    const nodes = [];
    const head = el('div', 'nm-tip-head');
    head.appendChild(el('span', null, cluster.locationText || cluster.label));
    nodes.push(head);
    nodes.push(
      el(
        'div',
        'nm-tip-row',
        t(
          'dv.globe.clusterCount',
          { count: cluster.count, online: cluster.onlineCount },
          cluster.count + ' devices · ' + cluster.onlineCount + ' online',
        ),
      ),
    );
    const list = el('ul', 'nm-tip-list');
    const visible = cluster.items.slice(0, 5);
    for (const item of visible) {
      const li = el('li');
      const left = el('span', 'nm-tip-list-left');
      left.append(el('span', dotClassForPresence(item.presence)), el('span', null, item.name));
      li.appendChild(left);
      if (item.isSelf) {
        li.appendChild(el('span', 'chip chip-self', t('dv.chip.thisDevice', null, 'this device')));
      } else if (item.rttMs != null) {
        li.appendChild(el('span', 'muted mono', item.rttMs + ' ms'));
      }
      list.appendChild(li);
    }
    if (cluster.items.length > visible.length) {
      const more = el(
        'li',
        'muted',
        t(
          'dv.globe.clusterMore',
          { n: cluster.items.length - visible.length },
          '+' + (cluster.items.length - visible.length) + ' more',
        ),
      );
      list.appendChild(more);
    }
    nodes.push(list);
    nodes.push(
      el('div', 'nm-tip-hint', t('dv.globe.clickToExpand', null, 'Click to expand')),
    );
    tipEl.replaceChildren(...nodes);
  }

  function spiderfyLinkStroke(link, tok) {
    if (link.stalled) return { color: tok.stalled, dash: '2 3' };
    if (link.carrier === 'direct') return { color: tok.direct, dash: null };
    if (link.carrier === 'tunnel') return { color: tok.tunnel, dash: null };
    if (link.carrier === 'relay') return { color: tok.relay, dash: '5 3' };
    if (link.carrier === 'derp') return { color: tok.derp, dash: '2.5 2.5' };
    return { color: tok.blocked, dash: '1.5 3' };
  }

  function renderSpiderfyDom(cluster, layout, opts) {
    if (!cluster || !layout) return null;
    const o = opts || {};
    const theme = o.theme === 'dark' ? 'dark' : 'light';
    const tok = getTokens(theme);
    const selectedId = o.selectedDeviceId || null;
    const stopEv = (ev) => {
      if (ev && typeof ev.stopPropagation === 'function') ev.stopPropagation();
    };

    const rootEl = el('div', 'nm-spiderfy nm-spiderfy--' + layout.mode);
    rootEl.dataset.spiderfyMode = layout.mode;
    rootEl.dataset.clusterId = cluster.id || '';

    if (layout.mode === 'list') {
      const pop = el('div', 'nm-spiderfy-list');
      pop.addEventListener('click', stopEv);
      pop.addEventListener('mousedown', stopEv);
      pop.addEventListener('wheel', stopEv);
      pop.addEventListener('dblclick', stopEv);

      const head = el('div', 'nm-spiderfy-list-head');
      const titleBox = el('div', 'nm-spiderfy-list-title');
      titleBox.append(
        el('div', 'nm-spiderfy-list-city', cluster.locationText || cluster.label || ''),
        el(
          'div',
          'nm-spiderfy-list-sub',
          t(
            'dv.globe.clusterCount',
            { count: cluster.count, online: cluster.onlineCount },
            cluster.count + ' devices · ' + cluster.onlineCount + ' online',
          ),
        ),
      );
      const closeBtn = el('button', 'nm-spiderfy-list-close', '×');
      closeBtn.setAttribute('type', 'button');
      const collapseLabel = t('dv.globe.spiderfyCollapse', null, 'Collapse expanded cluster');
      closeBtn.setAttribute('aria-label', collapseLabel);
      closeBtn.setAttribute('title', collapseLabel);
      closeBtn.addEventListener('click', (ev) => {
        stopEv(ev);
        if (typeof o.onCollapse === 'function') o.onCollapse();
      });
      head.append(titleBox, closeBtn);

      const ul = el('ul', 'nm-spiderfy-list-items');
      for (const item of layout.items || []) {
        const li = el('li');
        const isSel = Boolean(selectedId && selectedId === item.id);
        const rowBtn = el('button', 'nm-spiderfy-list-row' + (isSel ? ' is-selected' : ''));
        rowBtn.setAttribute('type', 'button');
        rowBtn.dataset.deviceId = item.id;

        const left = el('span', 'nm-spiderfy-list-row-left');
        left.append(el('span', dotClassForPresence(item.presence)), el('span', 'nm-spiderfy-list-name', item.name));
        if (item.isSelf) {
          left.appendChild(el('span', 'chip chip-self', t('dv.chip.thisDevice', null, 'this device')));
        }

        const meta = el('span', 'nm-spiderfy-list-meta');
        if (!item.isSelf && item.connection && item.connection !== 'offline') {
          meta.appendChild(
            el('span', connBadgeClass(item.connection, item.stalled), connBadgeLabel(item.connection, item.stalled)),
          );
          if (item.rttMs != null) {
            meta.appendChild(el('span', 'mono', item.rttMs + ' ms'));
          }
        } else {
          const siteIp = effectiveSiteKey(item);
          if (siteIp) meta.appendChild(el('span', 'mono', siteIp));
        }

        rowBtn.append(left, meta);
        rowBtn.addEventListener('click', (ev) => {
          stopEv(ev);
          if (typeof o.onSelectDevice === 'function') o.onSelectDevice(item, null, ev);
        });
        li.appendChild(rowBtn);
        ul.appendChild(li);
      }

      pop.append(head, ul);
      rootEl.appendChild(pop);
      return rootEl;
    }

    // Shared foot button builder for sites / circle / spiral modes.
    const buildFootButton = (foot) => {
      const item = foot.item;
      const isSel = Boolean(selectedId && selectedId === item.id);
      const btn = el('button', 'nm-spiderfy-foot' + (isSel ? ' is-selected' : ''));
      btn.setAttribute('type', 'button');
      btn.dataset.deviceId = item.id;
      btn.style.transform = 'translate(' + foot.dx + 'px, ' + foot.dy + 'px) translate(-50%, -50%)';
      btn.setAttribute('aria-label', item.name + ' (' + foot.presence + ')');

      const dotCls =
        'nm-spiderfy-dot is-' +
        foot.presence +
        (item.isSelf ? ' is-self' : '') +
        (isSel ? ' is-selected' : '');
      btn.appendChild(el('span', dotCls));

      if (!foot.hideLabel) {
        btn.appendChild(el('span', 'nm-spiderfy-label is-' + (foot.labelSide || 'right'), foot.shortLabel));
      }

      btn.addEventListener('click', (ev) => {
        stopEv(ev);
        if (typeof o.onSelectDevice === 'function') o.onSelectDevice(item, foot, ev);
      });
      btn.addEventListener('mouseenter', (ev) => {
        if (typeof o.onHoverDevice === 'function') o.onHoverDevice(item, foot, ev);
      });
      btn.addEventListener('mouseleave', (ev) => {
        if (typeof o.onHoverDevice === 'function') o.onHoverDevice(null, null, ev);
      });
      btn.addEventListener('focus', (ev) => {
        if (typeof o.onHoverDevice === 'function') o.onHoverDevice(item, foot, ev);
      });
      btn.addEventListener('blur', (ev) => {
        if (typeof o.onHoverDevice === 'function') o.onHoverDevice(null, null, ev);
      });
      return btn;
    };

    const halfW = Math.ceil((layout.maxRadiusX || layout.maxRadius || 120) + 32);
    const halfH = Math.ceil((layout.maxRadiusY || layout.maxRadius || 120) + 32);
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('class', 'nm-spiderfy-legs');
    svg.setAttribute('width', String(halfW * 2));
    svg.setAttribute('height', String(halfH * 2));
    svg.setAttribute('viewBox', -halfW + ' ' + -halfH + ' ' + halfW * 2 + ' ' + halfH * 2);
    svg.setAttribute('aria-hidden', 'true');

    if (layout.mode === 'sites') {
      // 1. Subtle radial tethers from city anchor (0, 0) to each site pod perimeter.
      for (const site of layout.sites) {
        const dist = Math.hypot(site.cx, site.cy) || 1;
        const endDist = Math.max(0, dist - site.podRadius);
        const tx = (site.cx / dist) * endDist;
        const ty = (site.cy / dist) * endDist;
        const tether = document.createElementNS(SVG_NS, 'line');
        tether.setAttribute('x1', '0');
        tether.setAttribute('y1', '0');
        tether.setAttribute('x2', tx.toFixed(1));
        tether.setAttribute('y2', ty.toFixed(1));
        tether.setAttribute('stroke', tok.leg);
        tether.setAttribute('stroke-width', '1');
        tether.setAttribute('stroke-dasharray', '2 3');
        tether.setAttribute('opacity', '0.75');
        svg.appendChild(tether);

        // Mini-radial legs inside multi-device pods.
        if (site.count >= 2) {
          for (const foot of site.feet) {
            const leg = document.createElementNS(SVG_NS, 'line');
            leg.setAttribute('x1', String(site.cx));
            leg.setAttribute('y1', String(site.cy));
            leg.setAttribute('x2', String(foot.dx));
            leg.setAttribute('y2', String(foot.dy));
            leg.setAttribute('stroke', tok.leg);
            leg.setAttribute('stroke-width', '1.1');
            leg.setAttribute('stroke-linecap', 'round');
            svg.appendChild(leg);
          }
        }
      }

      // 2. Curved inter-site live link arcs.
      for (const link of layout.siteLinks) {
        const st = spiderfyLinkStroke(link, tok);
        const path = document.createElementNS(SVG_NS, 'path');
        path.setAttribute('d', link.pathD);
        path.setAttribute('fill', 'none');
        path.setAttribute('stroke', st.color);
        path.setAttribute('stroke-width', '2');
        path.setAttribute('stroke-linecap', 'round');
        if (st.dash) path.setAttribute('stroke-dasharray', st.dash);
        svg.appendChild(path);
      }
      rootEl.appendChild(svg);

      // 3. Compact city banner cleanly above the topmost site header.
      let minTopY = -80;
      for (const s of layout.sites) {
        const headerTop = s.cy - s.podRadius - 44;
        if (headerTop < minTopY) minTopY = headerTop;
      }
      const cityName = cluster.label || cluster.locationText || '';
      const banner = el(
        'div',
        'nm-spiderfy-banner',
        t(
          'dv.globe.spiderfyCityBanner',
          { city: cityName, sites: layout.sites.length, count: cluster.count },
          cityName + ' · ' + layout.sites.length + ' sites · ' + cluster.count + ' devices',
        ),
      );
      banner.style.top = Math.round(minTopY - 6) + 'px';
      rootEl.appendChild(banner);

      // 4. Site pod backdrops + headers + subtitles.
      for (const site of layout.sites) {
        const podCls =
          'nm-spiderfy-site' +
          (site.hasSelf ? ' is-self' : '') +
          (site.isUnknown ? ' is-unknown' : '');
        const pod = el('div', podCls);
        pod.dataset.siteId = site.id;
        pod.style.left = site.cx + 'px';
        pod.style.top = site.cy + 'px';
        pod.style.width = site.podRadius * 2 + 'px';
        pod.style.height = site.podRadius * 2 + 'px';

        let headText;
        if (site.hasSelf && site.key) {
          headText = t('dv.globe.siteLocal', { ip: site.key }, 'Local site · ' + site.key);
        } else if (site.hasSelf) {
          headText = t('dv.globe.siteLocalNoIp', null, 'Local site');
        } else if (!site.isUnknown) {
          headText = t(
            'dv.globe.siteNamed',
            { label: site.labelCode, ip: site.key },
            'Site ' + site.labelCode + ' · ' + site.key,
          );
        } else {
          headText = t('dv.globe.siteOther', null, 'Other devices');
        }

        let subText;
        if (site.count === 1) {
          subText = t('dv.globe.siteSubSingle', null, '1 device');
        } else if (site.intraMinRttMs != null) {
          subText = t(
            'dv.globe.siteSubIntra',
            { count: site.count, rtt: site.intraMinRttMs },
            site.count + ' devices · ' + site.intraMinRttMs + ' ms LAN',
          );
        } else {
          subText = t(
            'dv.globe.siteSubCount',
            { count: site.count, online: site.onlineCount },
            site.count + ' devices · ' + site.onlineCount + ' online',
          );
        }

        const meta = el('div', 'nm-spiderfy-site-meta');
        meta.append(el('div', 'nm-spiderfy-site-head', headText), el('div', 'nm-spiderfy-site-sub', subText));
        pod.appendChild(meta);
        rootEl.appendChild(pod);
      }

      // 5. Inter-site carrier + RTT midpoint pills cleanly outside pod headers.
      for (const link of layout.siteLinks) {
        const pillKey = link.stalled ? 'stalled' : link.carrier;
        const pillText =
          connBadgeLabel(link.carrier, link.stalled) +
          (link.rttMs != null ? ' · ' + link.rttMs + ' ms' : '');
        const pill = el('div', 'nm-spiderfy-link-pill is-' + pillKey, pillText);
        pill.dataset.linkKey = link.key;
        pill.style.left = link.pillX + 'px';
        pill.style.top = link.pillY + 'px';
        rootEl.appendChild(pill);
      }
    } else {
      // Classic circle (2..8) or spiral (9..20) radial legs.
      for (const foot of layout.feet) {
        const leg = document.createElementNS(SVG_NS, 'line');
        leg.setAttribute('x1', '0');
        leg.setAttribute('y1', '0');
        leg.setAttribute('x2', String(foot.dx));
        leg.setAttribute('y2', String(foot.dy));
        leg.setAttribute('stroke', tok.leg);
        leg.setAttribute('stroke-width', '1.25');
        leg.setAttribute('stroke-linecap', 'round');
        svg.appendChild(leg);
      }
      rootEl.appendChild(svg);
    }

    // Center collapse anchor button.
    const anchor = el('button', 'nm-spiderfy-anchor');
    anchor.setAttribute('type', 'button');
    const collapseLabel = t('dv.globe.spiderfyCollapse', null, 'Collapse expanded cluster');
    anchor.setAttribute('aria-label', collapseLabel);
    anchor.setAttribute('title', collapseLabel);
    anchor.addEventListener('click', (ev) => {
      stopEv(ev);
      if (typeof o.onCollapse === 'function') o.onCollapse();
    });
    rootEl.appendChild(anchor);

    // Device feet.
    for (const foot of layout.feet) {
      rootEl.appendChild(buildFootButton(foot));
    }

    return rootEl;
  }

  /* ── Controller factory ──────────────────────────────────────────── */

  function create(opts) {
    const stageEl = opts.stage;
    const canvasEl = opts.canvas;
    const fresnelEl = opts.fresnel;
    const fallbackEl = opts.fallback;
    const summaryEl = opts.summary;
    const unlocatedEl = opts.unlocated;
    const footEl = opts.foot;
    const statusEl = opts.status;
    const tooltipEl = opts.tooltip;
    const zoomInBtn = opts.zoomIn;
    const zoomOutBtn = opts.zoomOut;
    const resetBtn = opts.reset;
    const invokeFn = opts.invoke || (root.MeshHarbor && root.MeshHarbor.invoke);

    const state = {
      active: false,
      fallback: false,
      theme: resolveCompanionTheme(),
      lang: currentLang(),
      rows: [],
      liveCtx: null,
      livePeers: [],
      meshView: null,
      projected: { items: [], locatedItems: [], unlocatedCount: 0, onlineCount: 0, totalCount: 0 },
      clusters: [],
      clusterById: new Map(),
      framed: false,
      pinnedClusterId: null,
      hoveredClusterId: null,
      spiderfyClusterId: null,
      spiderfyOpenZoom: null,
      selectedDeviceId: null,
      hoveredDeviceId: null,
      tilesError: false,
    };

    let map = null;
    let mapLoaded = false;
    let fresnel = null;
    let resizeObs = null;
    let themeObs = null;
    let mediaQuery = null;
    let spiderfyMarker = null;
    let spiderfyEl = null;
    let spiderfyLayout = null;
    let spiderfyEaseActive = false;
    let spiderfyEaseTimer = null;
    let docKeydownHandler = null;

    function updateStageThemeClass() {
      if (stageEl) stageEl.classList.toggle('is-dark', state.theme === 'dark');
    }

    function updateChrome() {
      const p = state.projected;
      if (summaryEl) {
        if (p.totalCount === 0) {
          summaryEl.hidden = true;
          summaryEl.textContent = '';
        } else {
          summaryEl.hidden = false;
          summaryEl.textContent =
            !state.fallback && p.locatedItems.length > 0
              ? t(
                  'dv.globe.summary',
                  { located: p.locatedItems.length, online: p.onlineCount },
                  p.locatedItems.length + ' mapped · ' + p.onlineCount + ' online',
                )
              : t(
                  'dv.globe.summaryTotal',
                  { total: p.totalCount, online: p.onlineCount },
                  p.totalCount + ' devices · ' + p.onlineCount + ' online',
                );
        }
      }
      if (unlocatedEl) {
        if (!state.fallback && p.unlocatedCount > 0) {
          unlocatedEl.hidden = false;
          unlocatedEl.textContent =
            p.unlocatedCount === 1
              ? t('dv.globe.unlocatedOne', null, '1 device has no coordinates yet')
              : t(
                  'dv.globe.unlocatedMany',
                  { n: p.unlocatedCount },
                  p.unlocatedCount + ' devices have no coordinates yet',
                );
        } else {
          unlocatedEl.hidden = true;
          unlocatedEl.textContent = '';
        }
      }
      if (footEl) {
        footEl.hidden = state.fallback;
      }
      if (statusEl) {
        if (state.tilesError && !state.fallback) {
          statusEl.textContent = t(
            'dv.globe.tilesUnavailable',
            null,
            'Map tiles unavailable — showing device coordinates',
          );
          statusEl.hidden = false;
        } else {
          statusEl.hidden = true;
          statusEl.textContent = '';
        }
      }
    }

    function hideTooltip() {
      if (!tooltipEl) return;
      tooltipEl.hidden = true;
    }

    function positionTooltip(point, optsPos) {
      if (!tooltipEl || !stageEl) return;
      const sw = stageEl.clientWidth || 640;
      const sh = stageEl.clientHeight || 580;
      const tw = tooltipEl.offsetWidth || 210;
      const th = tooltipEl.offsetHeight || 78;
      const px = point ? point.x : sw / 2;
      const py = point ? point.y : sh / 2;
      const avoidFoot = Boolean(optsPos && optsPos.avoidFoot);
      const pad = 10;

      if (!avoidFoot) {
        let left = px + 14;
        let top = py - 16;
        if (left + tw > sw - pad) left = Math.max(pad, px - tw - 14);
        if (top + th > sh - pad) top = Math.max(pad, sh - th - pad);
        if (top < pad) top = pad;
        tooltipEl.style.left = Math.round(left) + 'px';
        tooltipEl.style.top = Math.round(top) + 'px';
        return;
      }

      // Position cleanly inside #dv-map-stage without covering the selected/hovered foot.
      const gap = 18;
      const footClear = 14;
      const clampX = (x) => Math.max(pad, Math.min(sw - tw - pad, x));
      const clampY = (y) => Math.max(pad, Math.min(sh - th - pad, y));
      const overlapsFoot = (l, tp) =>
        l < px + footClear && l + tw > px - footClear && tp < py + footClear && tp + th > py - footClear;
      const fitsInStage = (l, tp) => l >= pad && l + tw <= sw - pad && tp >= pad && tp + th <= sh - pad;

      const preferLeft = optsPos && optsPos.preferSide === 'left';
      const rightCand = { left: px + gap, top: clampY(py - th / 2) };
      const leftCand = { left: px - tw - gap, top: clampY(py - th / 2) };
      const belowCand = { left: clampX(px - tw / 2), top: py + gap };
      const aboveCand = { left: clampX(px - tw / 2), top: py - th - gap };
      const candidates = preferLeft
        ? [leftCand, rightCand, aboveCand, belowCand]
        : [rightCand, leftCand, aboveCand, belowCand];

      let chosen = null;
      for (const c of candidates) {
        if (fitsInStage(c.left, c.top) && !overlapsFoot(c.left, c.top)) {
          chosen = c;
          break;
        }
      }
      if (!chosen) {
        for (const c of candidates) {
          const cl = clampX(c.left);
          const ct = clampY(c.top);
          if (!overlapsFoot(cl, ct)) {
            chosen = { left: cl, top: ct };
            break;
          }
        }
      }
      if (!chosen) {
        const useAbove = py > sh / 2;
        chosen = {
          left: clampX(px - tw / 2),
          top: useAbove ? Math.max(pad, py - th - gap) : Math.min(sh - th - pad, py + gap),
        };
      }
      tooltipEl.style.left = Math.round(chosen.left) + 'px';
      tooltipEl.style.top = Math.round(chosen.top) + 'px';
    }

    function showTooltipAt(cluster, point) {
      if (!tooltipEl || !stageEl || !cluster) return;
      populateTooltip(tooltipEl, cluster);
      tooltipEl.hidden = false;
      positionTooltip(point, { avoidFoot: false });
    }

    function footScreenPoint(cluster, foot) {
      if (!cluster) return null;
      let anchorPt = null;
      if (map && typeof map.project === 'function') {
        try {
          anchorPt = map.project([cluster.lon, cluster.lat]);
        } catch (_) {
          anchorPt = null;
        }
      }
      const sw = (stageEl && stageEl.clientWidth) || 640;
      const sh = (stageEl && stageEl.clientHeight) || 580;
      const ax = anchorPt && Number.isFinite(anchorPt.x) ? anchorPt.x : sw / 2;
      const ay = anchorPt && Number.isFinite(anchorPt.y) ? anchorPt.y : sh / 2;
      return {
        x: ax + (foot ? foot.dx : 0),
        y: ay + (foot ? foot.dy : 0),
      };
    }

    function showDeviceTooltip(item, cluster, foot) {
      if (!tooltipEl || !stageEl || !item) return;
      populateDeviceTooltip(tooltipEl, item);
      tooltipEl.hidden = false;
      const pt = footScreenPoint(cluster, foot);
      // Open away from the foot's text label when possible.
      const preferSide = foot && foot.labelSide === 'right' ? 'left' : 'right';
      positionTooltip(pt, { avoidFoot: true, preferSide });
    }

    function findFootInLayout(layout, deviceId) {
      if (!layout || !deviceId || !Array.isArray(layout.feet)) return null;
      for (const f of layout.feet) {
        if (f.item && f.item.id === deviceId) return f;
      }
      return null;
    }

    function clearSpiderfyEaseGuard() {
      spiderfyEaseActive = false;
      if (spiderfyEaseTimer != null) {
        clearTimeout(spiderfyEaseTimer);
        spiderfyEaseTimer = null;
      }
    }

    function renderSpiderfyInPlace() {
      if (!state.spiderfyClusterId || !spiderfyEl) return;
      const cluster = state.clusterById.get(state.spiderfyClusterId);
      if (!cluster || cluster.count <= 1) {
        collapseSpiderfy();
        return;
      }
      spiderfyLayout = computeSpiderfyLayout(cluster, state.meshView, state.livePeers);
      if (!spiderfyLayout) {
        collapseSpiderfy();
        return;
      }

      if (state.selectedDeviceId && !cluster.items.some((it) => it.id === state.selectedDeviceId)) {
        state.selectedDeviceId = null;
        hideTooltip();
      }

      const inner = renderSpiderfyDom(cluster, spiderfyLayout, {
        theme: state.theme,
        selectedDeviceId: state.selectedDeviceId,
        onCollapse: collapseSpiderfy,
        onSelectDevice: (item, foot) => {
          state.selectedDeviceId = item.id;
          state.hoveredDeviceId = null;
          renderSpiderfyInPlace();
          const activeCluster = state.clusterById.get(state.spiderfyClusterId) || cluster;
          const activeFoot = foot || findFootInLayout(spiderfyLayout, item.id);
          showDeviceTooltip(item, activeCluster, activeFoot);
        },
        onHoverDevice: (item, foot) => {
          if (state.selectedDeviceId) return;
          if (item) {
            state.hoveredDeviceId = item.id;
            showDeviceTooltip(item, cluster, foot);
          } else if (state.hoveredDeviceId) {
            state.hoveredDeviceId = null;
            hideTooltip();
          }
        },
      });
      if (inner) {
        spiderfyEl.replaceChildren(inner);
      }
      if (spiderfyMarker && typeof spiderfyMarker.setLngLat === 'function') {
        spiderfyMarker.setLngLat([cluster.lon, cluster.lat]);
      }
      if (state.selectedDeviceId) {
        const selItem = cluster.items.find((it) => it.id === state.selectedDeviceId);
        if (selItem) {
          showDeviceTooltip(selItem, cluster, findFootInLayout(spiderfyLayout, selItem.id));
        }
      }
    }

    function collapseSpiderfy(optsCollapse) {
      const skipSourceSync = Boolean(optsCollapse && optsCollapse.skipSourceSync);
      clearSpiderfyEaseGuard();
      const wasOpen = Boolean(state.spiderfyClusterId || spiderfyMarker);
      state.spiderfyClusterId = null;
      state.spiderfyOpenZoom = null;
      state.selectedDeviceId = null;
      state.hoveredDeviceId = null;
      spiderfyLayout = null;
      if (spiderfyMarker) {
        try {
          spiderfyMarker.remove();
        } catch (_) {
          /* ignore */
        }
        spiderfyMarker = null;
      }
      spiderfyEl = null;
      if (wasOpen) {
        hideTooltip();
        if (!skipSourceSync && !state.fallback) {
          syncSourcesToMap();
        }
      }
    }

    function openSpiderfy(cluster) {
      if (!cluster || cluster.count <= 1 || !map) return;
      if (state.spiderfyClusterId === cluster.id && spiderfyMarker && spiderfyEl) {
        renderSpiderfyInPlace();
        return;
      }
      collapseSpiderfy({ skipSourceSync: true });
      state.pinnedClusterId = null;
      state.hoveredClusterId = null;
      hideTooltip();

      const layout = computeSpiderfyLayout(cluster, state.meshView, state.livePeers);
      if (!layout) return;

      state.spiderfyClusterId = cluster.id;
      spiderfyLayout = layout;
      spiderfyEl = el('div', 'nm-spiderfy-marker');

      const MarkerCtor = root.maplibregl && root.maplibregl.Marker;
      if (MarkerCtor) {
        spiderfyMarker = new MarkerCtor({
          element: spiderfyEl,
          anchor: 'center',
          opacityWhenCovered: '0',
        })
          .setLngLat([cluster.lon, cluster.lat])
          .addTo(map);
      }

      renderSpiderfyInPlace();
      syncSourcesToMap();

      const curZoom = typeof map.getZoom === 'function' ? map.getZoom() : SPIDERFY_MIN_OPEN_ZOOM;
      state.spiderfyOpenZoom = curZoom;

      // Smoothly ease camera if cluster is near viewport edge or zoom < 2.6 so pods fit inside 380px card.
      const sw = (stageEl && stageEl.clientWidth) || 640;
      const sh = (stageEl && stageEl.clientHeight) || 580;
      let pt = null;
      if (typeof map.project === 'function') {
        try {
          pt = map.project([cluster.lon, cluster.lat]);
        } catch (_) {
          pt = null;
        }
      }
      const padX =
        layout.mode === 'sites'
          ? Math.min(sw * 0.36, (layout.maxRadiusX || 170) + 32)
          : Math.min(sw * 0.3, (layout.maxRadius || 72) + 48);
      const padY =
        layout.mode === 'sites'
          ? Math.min(sh * 0.42, (layout.maxRadiusY || 110) + 26)
          : Math.min(sh * 0.35, (layout.maxRadius || 72) + 36);
      const nearEdge = !pt || pt.x < padX || pt.x > sw - padX || pt.y < padY || pt.y > sh - padY;
      const tooZoomedOut = curZoom < SPIDERFY_MIN_OPEN_ZOOM;

      if ((nearEdge || tooZoomedOut) && typeof map.easeTo === 'function') {
        const targetZoom = tooZoomedOut ? SPIDERFY_MIN_OPEN_ZOOM : curZoom;
        state.spiderfyOpenZoom = targetZoom;
        spiderfyEaseActive = true;
        const finishEase = () => {
          if (!spiderfyEaseActive) return;
          clearSpiderfyEaseGuard();
          if (map && typeof map.getZoom === 'function' && state.spiderfyClusterId) {
            state.spiderfyOpenZoom = map.getZoom();
          }
          if (state.spiderfyClusterId && state.selectedDeviceId) {
            const c = state.clusterById.get(state.spiderfyClusterId);
            const item = c && c.items.find((it) => it.id === state.selectedDeviceId);
            if (c && item) showDeviceTooltip(item, c, findFootInLayout(spiderfyLayout, item.id));
          }
        };
        if (typeof map.once === 'function') map.once('moveend', finishEase);
        spiderfyEaseTimer = setTimeout(finishEase, 520);
        map.easeTo({
          center: [cluster.lon, cluster.lat],
          zoom: targetZoom,
          duration: 380,
        });
      }
    }

    function syncSelectedSpiderfyTooltip() {
      if (!state.spiderfyClusterId || !state.selectedDeviceId) return;
      const cluster = state.clusterById.get(state.spiderfyClusterId);
      if (!cluster) return;
      const item = cluster.items.find((it) => it.id === state.selectedDeviceId);
      if (!item) return;
      showDeviceTooltip(item, cluster, findFootInLayout(spiderfyLayout, item.id));
    }

    function enterFallback() {
      collapseSpiderfy({ skipSourceSync: true });
      state.fallback = true;
      if (map) {
        try {
          map.remove();
        } catch (_) {
          /* ignore */
        }
        map = null;
        mapLoaded = false;
      }
      if (stageEl) stageEl.hidden = true;
      if (fallbackEl) {
        fallbackEl.hidden = false;
        renderFallbackList(fallbackEl, state.projected);
      }
      hideTooltip();
      updateChrome();
    }

    function syncFresnel() {
      if (!fresnel || !map || !stageEl) return;
      const w = stageEl.clientWidth;
      const h = stageEl.clientHeight;
      if (w <= 0 || h <= 0) return;
      const c = map.getCenter();
      fresnel.sync(w, h, map.getZoom(), c ? c.lat : DEFAULT_CENTER[1]);
    }

    function syncSourcesToMap() {
      if (!map || !mapLoaded) return;
      const dpr = Math.min(2, (typeof window !== 'undefined' && window.devicePixelRatio) || 1);
      ensureStaticIcons(map, state.theme, dpr);
      const markersSrc = map.getSource(MARKERS_SOURCE_ID);
      if (markersSrc && typeof markersSrc.setData === 'function') {
        markersSrc.setData(
          buildMarkerFeatures(state.clusters, map, state.theme, dpr, state.spiderfyClusterId),
        );
      }
      const linksSrc = map.getSource(LINKS_SOURCE_ID);
      if (linksSrc && typeof linksSrc.setData === 'function') {
        linksSrc.setData(buildLinkFeatures(state.clusters, state.meshView, state.livePeers));
      }
      if (!state.framed && state.projected.locatedItems.length > 0) {
        state.framed = true;
        frameInitialView(false);
      }
    }

    function frameInitialView(animate) {
      if (!map || !stageEl) return;
      const w = stageEl.clientWidth || 640;
      const h = stageEl.clientHeight || 580;
      const view = computeInitialView(state.projected.locatedItems, w, h);
      const optsCam = { center: view.center, zoom: view.zoom, bearing: 0, pitch: 0 };
      if (animate && typeof map.easeTo === 'function') {
        map.easeTo(Object.assign({ duration: 450 }, optsCam));
      } else if (typeof map.jumpTo === 'function') {
        map.jumpTo(optsCam);
      }
      syncFresnel();
    }

    function recompute() {
      state.projected = projectDevices(state.rows, state.liveCtx);
      state.clusters = clusterLocatedDevices(state.projected.locatedItems);
      state.clusterById = new Map(state.clusters.map((c) => [c.id, c]));
      updateChrome();
      if (state.fallback) {
        renderFallbackList(fallbackEl, state.projected);
        return;
      }
      syncSourcesToMap();
      if (state.spiderfyClusterId) {
        renderSpiderfyInPlace();
      } else if (state.pinnedClusterId) {
        const c = state.clusterById.get(state.pinnedClusterId);
        if (c && map) {
          populateTooltip(tooltipEl, c);
        } else {
          state.pinnedClusterId = null;
          hideTooltip();
        }
      }
    }

    function queryClusterAt(point) {
      if (!map || !mapLoaded || !point) return null;
      const pad = 12;
      let hits = [];
      try {
        hits = map.queryRenderedFeatures(
          [
            [point.x - pad, point.y - pad],
            [point.x + pad, point.y + pad],
          ],
          { layers: ['mh-markers'] },
        );
      } catch (_) {
        return null;
      }
      if (!hits || !hits.length) return null;
      const cid = hits[0].properties && hits[0].properties.clusterId;
      return cid ? state.clusterById.get(cid) || null : null;
    }

    function initMap() {
      if (map || state.fallback || !canvasEl || !stageEl) return;
      updateStageThemeClass();
      if (!isWebGL2Available()) {
        enterFallback();
        return;
      }
      const maplibregl = root.maplibregl;
      const pmtilesNs = root.pmtiles;
      if (!maplibregl || !pmtilesNs || typeof invokeFn !== 'function') {
        enterFallback();
        return;
      }

      try {
        ensureMapLibreProtocol(maplibregl, pmtilesNs, invokeFn);
        const w = stageEl.clientWidth || 640;
        const h = stageEl.clientHeight || 580;
        const initial = computeInitialView(state.projected.locatedItems, w, h);

        map = new maplibregl.Map({
          container: canvasEl,
          style: buildStyle(state.theme, state.lang),
          center: initial.center,
          zoom: initial.zoom,
          minZoom: MIN_GLOBE_ZOOM,
          maxZoom: MAX_GLOBE_ZOOM,
          maxPitch: 0,
          dragRotate: false,
          touchPitch: false,
          pitchWithRotate: false,
          attributionControl: false,
          preserveDrawingBuffer: false,
          pixelRatio: Math.min(2, (typeof window !== 'undefined' && window.devicePixelRatio) || 1),
        });
        if (map.touchZoomRotate && typeof map.touchZoomRotate.disableRotation === 'function') {
          map.touchZoomRotate.disableRotation();
        }
      } catch (_) {
        enterFallback();
        return;
      }

      if (fresnelEl) {
        fresnel = makeFresnelDom(fresnelEl);
        fresnel.applyTheme(state.theme);
      }

      const webglCanvas = map.getCanvas && map.getCanvas();
      if (webglCanvas) {
        webglCanvas.addEventListener(
          'webglcontextlost',
          (ev) => {
            if (ev && typeof ev.preventDefault === 'function') ev.preventDefault();
            enterFallback();
          },
          false,
        );
      }

      map.on('load', () => {
        mapLoaded = true;
        if (state.projected.locatedItems.length > 0) state.framed = true;
        syncSourcesToMap();
        syncFresnel();
      });

      map.on('sourcedata', (ev) => {
        if (ev && ev.sourceId === BOUNDARY_SOURCE_ID && ev.isSourceLoaded && state.tilesError) {
          state.tilesError = false;
          updateChrome();
        }
      });

      map.on('error', (ev) => {
        const msg = String((ev && ev.error && ev.error.message) || '');
        if (/webgl/i.test(msg)) {
          enterFallback();
          return;
        }
        if ((ev && ev.sourceId === BOUNDARY_SOURCE_ID) || /pmtiles|range|tile/i.test(msg)) {
          state.tilesError = true;
          updateChrome();
        }
      });

      map.on('move', () => {
        syncFresnel();
        syncSelectedSpiderfyTooltip();
      });
      map.on('zoom', () => {
        syncFresnel();
        if (
          state.spiderfyClusterId &&
          !spiderfyEaseActive &&
          state.spiderfyOpenZoom != null &&
          typeof map.getZoom === 'function' &&
          Math.abs(map.getZoom() - state.spiderfyOpenZoom) >= SPIDERFY_ZOOM_COLLAPSE_DELTA
        ) {
          collapseSpiderfy();
        }
      });
      map.on('resize', () => {
        syncFresnel();
        syncSelectedSpiderfyTooltip();
      });

      map.on('mousemove', (ev) => {
        const cluster = queryClusterAt(ev.point);
        if (webglCanvas) webglCanvas.style.cursor = cluster ? 'pointer' : '';
        if (state.pinnedClusterId || state.selectedDeviceId || state.hoveredDeviceId) return;
        if (cluster && cluster.id !== state.spiderfyClusterId) {
          state.hoveredClusterId = cluster.id;
          showTooltipAt(cluster, ev.point);
        } else if (state.hoveredClusterId) {
          state.hoveredClusterId = null;
          hideTooltip();
        }
      });

      map.on('mouseleave', () => {
        if (!state.pinnedClusterId && !state.selectedDeviceId && !state.hoveredDeviceId) {
          state.hoveredClusterId = null;
          hideTooltip();
        }
      });

      map.on('click', (ev) => {
        const cluster = queryClusterAt(ev.point);
        if (cluster) {
          if (cluster.count >= 2) {
            openSpiderfy(cluster);
          } else {
            collapseSpiderfy();
            state.pinnedClusterId = cluster.id;
            showTooltipAt(cluster, ev.point);
            if (map.getZoom() < 3.2) {
              map.easeTo({
                center: [cluster.lon, cluster.lat],
                zoom: Math.max(map.getZoom(), 2.8),
                duration: 420,
              });
            }
          }
        } else {
          if (state.spiderfyClusterId) {
            collapseSpiderfy();
          }
          if (state.pinnedClusterId) {
            state.pinnedClusterId = null;
            hideTooltip();
          }
        }
      });

      if (canvasEl) {
        canvasEl.addEventListener('keydown', (ev) => {
          if (ev && ev.key === 'Escape') {
            if (state.spiderfyClusterId) {
              collapseSpiderfy();
            } else if (state.pinnedClusterId) {
              state.pinnedClusterId = null;
              hideTooltip();
            }
          }
        });
      }
    }

    if (typeof document !== 'undefined' && typeof document.addEventListener === 'function') {
      docKeydownHandler = (ev) => {
        if (!ev || ev.key !== 'Escape') return;
        if (state.spiderfyClusterId) {
          collapseSpiderfy();
        } else if (state.pinnedClusterId) {
          state.pinnedClusterId = null;
          hideTooltip();
        }
      };
      document.addEventListener('keydown', docKeydownHandler);
    }

    // Wire toolbar buttons
    if (zoomInBtn) {
      zoomInBtn.addEventListener('click', () => {
        if (map) map.zoomTo(Math.min(MAX_GLOBE_ZOOM, map.getZoom() + 1), { duration: 240 });
      });
    }
    if (zoomOutBtn) {
      zoomOutBtn.addEventListener('click', () => {
        if (map) map.zoomTo(Math.max(MIN_GLOBE_ZOOM, map.getZoom() - 1), { duration: 240 });
      });
    }
    if (resetBtn) {
      resetBtn.addEventListener('click', () => {
        collapseSpiderfy();
        state.pinnedClusterId = null;
        hideTooltip();
        frameInitialView(true);
      });
    }

    // Observe container resize
    if (typeof ResizeObserver !== 'undefined' && stageEl) {
      resizeObs = new ResizeObserver(() => {
        if (!state.active || state.fallback) return;
        if (map) {
          map.resize();
          syncFresnel();
          syncSelectedSpiderfyTooltip();
        }
      });
      resizeObs.observe(stageEl);
    }

    // Live theme observation (prefers-color-scheme + html class/data-theme overrides)
    function handleThemeMaybeChanged() {
      const next = resolveCompanionTheme();
      if (next === state.theme) return;
      state.theme = next;
      updateStageThemeClass();
      if (fresnel) fresnel.applyTheme(next);
      if (map && mapLoaded) {
        applyThemeToMap(map, next);
        syncSourcesToMap();
      }
      if (state.spiderfyClusterId) renderSpiderfyInPlace();
    }

    if (typeof window !== 'undefined' && typeof window.matchMedia === 'function') {
      try {
        mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
        if (typeof mediaQuery.addEventListener === 'function') {
          mediaQuery.addEventListener('change', handleThemeMaybeChanged);
        }
      } catch (_) {
        /* ignore */
      }
    }
    if (typeof MutationObserver !== 'undefined' && typeof document !== 'undefined') {
      themeObs = new MutationObserver(handleThemeMaybeChanged);
      themeObs.observe(document.documentElement, {
        attributes: true,
        attributeFilter: ['class', 'data-theme'],
      });
    }

    updateStageThemeClass();

    return {
      setDevices(rows) {
        state.rows = Array.isArray(rows) ? rows : [];
        recompute();
      },
      setLiveContext(ctx, peers) {
        state.liveCtx = ctx || null;
        state.livePeers = Array.isArray(peers) ? peers : [];
        recompute();
      },
      setMesh(meshView) {
        state.meshView = meshView || null;
        if (!state.fallback) {
          syncSourcesToMap();
          if (state.spiderfyClusterId) renderSpiderfyInPlace();
        }
      },
      setActive(isActive) {
        state.active = Boolean(isActive);
        if (!state.active) {
          collapseSpiderfy();
          hideTooltip();
          state.pinnedClusterId = null;
          return;
        }
        if (!map && !state.fallback) {
          initMap();
        }
        if (map) {
          // Wait one animation frame after section becomes un-hidden so clientWidth/Height settle
          const resizeNow = () => {
            if (!map) return;
            map.resize();
            if (!state.framed && state.projected.locatedItems.length > 0) {
              state.framed = true;
              frameInitialView(false);
            } else {
              syncFresnel();
            }
          };
          if (typeof requestAnimationFrame === 'function') requestAnimationFrame(resizeNow);
          else resizeNow();
        } else if (state.fallback) {
          renderFallbackList(fallbackEl, state.projected);
        }
      },
      setLang(lang) {
        const next = lang === 'zh-CN' ? 'zh-CN' : 'en';
        state.lang = next;
        if (map && mapLoaded) applyLangToMap(map, next);
        updateChrome();
        if (state.fallback) {
          renderFallbackList(fallbackEl, state.projected);
        } else if (state.spiderfyClusterId) {
          renderSpiderfyInPlace();
        } else if (state.pinnedClusterId) {
          const c = state.clusterById.get(state.pinnedClusterId);
          if (c) populateTooltip(tooltipEl, c);
        }
      },
      setTheme(theme) {
        const next = theme === 'dark' ? 'dark' : 'light';
        if (next === state.theme) return;
        state.theme = next;
        updateStageThemeClass();
        if (fresnel) fresnel.applyTheme(next);
        if (map && mapLoaded) {
          applyThemeToMap(map, next);
          syncSourcesToMap();
        }
        if (state.spiderfyClusterId) renderSpiderfyInPlace();
      },
      resetView() {
        collapseSpiderfy();
        state.pinnedClusterId = null;
        hideTooltip();
        frameInitialView(true);
      },
      resetOrg() {
        collapseSpiderfy({ skipSourceSync: true });
        state.rows = [];
        state.meshView = null;
        state.framed = false;
        state.pinnedClusterId = null;
        hideTooltip();
        recompute();
      },
      destroy() {
        collapseSpiderfy({ skipSourceSync: true });
        if (
          docKeydownHandler &&
          typeof document !== 'undefined' &&
          typeof document.removeEventListener === 'function'
        ) {
          document.removeEventListener('keydown', docKeydownHandler);
          docKeydownHandler = null;
        }
        if (resizeObs) resizeObs.disconnect();
        if (themeObs) themeObs.disconnect();
        if (mediaQuery && typeof mediaQuery.removeEventListener === 'function') {
          mediaQuery.removeEventListener('change', handleThemeMaybeChanged);
        }
        if (map) {
          try {
            map.remove();
          } catch (_) {
            /* ignore */
          }
          map = null;
          mapLoaded = false;
        }
      },
      getState() {
        return {
          active: state.active,
          fallback: state.fallback,
          theme: state.theme,
          lang: state.lang,
          totalCount: state.projected.totalCount,
          locatedCount: state.projected.locatedItems.length,
          unlocatedCount: state.projected.unlocatedCount,
          clusterCount: state.clusters.length,
          mapLoaded,
          tilesError: state.tilesError,
          spiderfyClusterId: state.spiderfyClusterId,
          selectedDeviceId: state.selectedDeviceId,
        };
      },
    };
  }

  const api = {
    PMTILES_KEY,
    WORKER_URL,
    SPIDERFY_CIRCLE_MAX,
    SPIDERFY_SPIRAL_MAX,
    SPIDERFY_MAX_SITES,
    DARK_TOKENS,
    LIGHT_TOKENS,
    MAPLIBRE_LOCAL_TEXT_FONT,
    getTokens,
    resolveCompanionTheme,
    isWebGL2Available,
    decodeBase64ToArrayBuffer,
    createIpcPmTilesSource,
    buildStyle,
    applyThemeToMap,
    applyLangToMap,
    computeFitGlobeZoom,
    computeGlobeScreenCircle,
    computeInitialView,
    interpolateGreatCircle,
    isValidCoord,
    projectDevices,
    clusterLocatedDevices,
    buildLinkFeatures,
    buildMarkerFeatures,
    effectiveSiteKey,
    computeSpiderfyLayout,
    populateDeviceTooltip,
    populateTooltip,
    renderSpiderfyDom,
    renderFallbackList,
    create,
  };

  if (root) {
    root.MeshHarborNetworkMap = api;
    if (root.MeshHarbor) root.MeshHarbor.NetworkMap = api;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
})(typeof window !== 'undefined' ? window : globalThis);
