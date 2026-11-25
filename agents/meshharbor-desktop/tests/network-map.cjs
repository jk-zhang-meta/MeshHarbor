// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//
// Headless unit, DOM, fallback, IPC-source, and asset-hygiene tests for T12
// (inline MapLibre 3D network map + Enlarge button inside meshharbor-desktop).
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const DESKTOP_DIR = path.join(REPO_ROOT, 'agents', 'meshharbor-desktop');
const FRONT_DIR = path.join(DESKTOP_DIR, 'src', 'front');
const VENDOR_DIR = path.join(FRONT_DIR, 'vendor');

const i18n = require(path.join(FRONT_DIR, 'i18n.js'));

/* ── 1. Hygiene & static structure checks ──────────────────────────── */

function listFilesRecursive(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...listFilesRecursive(full));
    else out.push(full);
  }
  return out;
}

const frontFiles = listFilesRecursive(FRONT_DIR);
const mjsFiles = frontFiles.filter((f) => f.endsWith('.mjs'));
assert.deepEqual(mjsFiles, [], 'ZERO .mjs files allowed under agents/meshharbor-desktop/src/front/');

for (const requiredVendor of [
  'maplibre-gl.js',
  'maplibre-gl-csp-worker.js',
  'maplibre-gl.css',
  'pmtiles.js',
]) {
  const p = path.join(VENDOR_DIR, requiredVendor);
  assert.ok(fs.existsSync(p), `Missing local vendor asset: vendor/${requiredVendor}`);
  assert.ok(fs.statSync(p).size > 10_000, `Vendor asset vendor/${requiredVendor} looks truncated`);
}

// Verify ZERO third-party CDN URLs and ZERO <iframe> across HTML + network-map.js + vendor CSS.
const indexHtml = fs.readFileSync(path.join(FRONT_DIR, 'index.html'), 'utf8');
const networkMapSrc = fs.readFileSync(path.join(FRONT_DIR, 'network-map.js'), 'utf8');
const vendorCss = fs.readFileSync(path.join(VENDOR_DIR, 'maplibre-gl.css'), 'utf8');

assert.equal(/<iframe\b/i.test(indexHtml), false, 'index.html must not contain an <iframe>');
assert.equal(/<iframe\b|createElement\(\s*['"]iframe['"]\s*\)/i.test(networkMapSrc), false, 'network-map.js must not create an iframe');
assert.equal(/innerHTML\s*=/.test(networkMapSrc), false, 'network-map.js must never assign innerHTML (textContent only)');
assert.equal(
  /<(?:link|script|img|iframe)\b[^>]*\b(?:href|src)\s*=\s*["']https?:\/\//i.test(indexHtml),
  false,
  'index.html must not reference external HTTP(S) assets',
);

// Allow only standard XML SVG namespace in network-map.js / vendor CSS; zero third-party URLs.
const externalUrlsInNetworkMap = (networkMapSrc.match(/https?:\/\/[^\s'"`)]+/gi) || []).filter(
  (u) => u !== 'http://www.w3.org/2000/svg',
);
assert.deepEqual(externalUrlsInNetworkMap, [], 'network-map.js must not contain third-party HTTP(S) URLs');

const externalUrlsInVendorCss = (vendorCss.match(/https?:\/\/[^\s'"`)]+/gi) || []).filter(
  (u) => !u.startsWith('http://www.w3.org/2000/svg'),
);
assert.deepEqual(externalUrlsInVendorCss, [], 'vendor/maplibre-gl.css must not contain external CDN URLs');

// Verify unified #dv-globe-card DOM structure, 3D Globe / 2D Ring switcher, & Enlarge button.
assert.ok(indexHtml.includes('id="dv-globe-card"'), 'index.html missing #dv-globe-card');
assert.equal(indexHtml.includes('id="dv-mesh-card"'), false, 'mesh graph must live inside #dv-globe-card, not a second stacked card');
assert.ok(indexHtml.includes('id="dv-viz-switch"'), 'index.html missing #dv-viz-switch');
assert.ok(indexHtml.includes('id="dv-viz-globe"'), 'index.html missing #dv-viz-globe');
assert.ok(indexHtml.includes('id="dv-viz-mesh"'), 'index.html missing #dv-viz-mesh');
assert.ok(indexHtml.includes('id="dv-panel-globe"'), 'index.html missing #dv-panel-globe');
assert.ok(indexHtml.includes('id="dv-panel-mesh"'), 'index.html missing #dv-panel-mesh');
assert.ok(indexHtml.includes('id="dv-map-stage"'), 'index.html missing #dv-map-stage');
assert.ok(indexHtml.includes('id="dv-map-canvas"'), 'index.html missing #dv-map-canvas');
assert.ok(indexHtml.includes('id="dv-map-fallback"'), 'index.html missing #dv-map-fallback');
assert.ok(indexHtml.includes('id="dv-open-globe"'), 'index.html missing #dv-open-globe Enlarge button');
assert.ok(indexHtml.includes('href="vendor/maplibre-gl.css"'), 'index.html missing local vendor/maplibre-gl.css');
assert.ok(indexHtml.includes('src="vendor/maplibre-gl.js"'), 'index.html missing local vendor/maplibre-gl.js');
assert.ok(indexHtml.includes('src="vendor/pmtiles.js"'), 'index.html missing local vendor/pmtiles.js');
assert.ok(indexHtml.includes('src="network-map.js"'), 'index.html missing network-map.js');

assert.equal(i18n.MESSAGES.en['dv.globe.title'], 'Network map');
assert.equal(i18n.MESSAGES['zh-CN']['dv.globe.title'], '网络地图');
assert.equal(i18n.MESSAGES.en['dv.globe.openBtn'], 'Enlarge');
assert.equal(i18n.MESSAGES['zh-CN']['dv.globe.openBtn'], '放大');
assert.equal(i18n.MESSAGES.en['dv.viz.globe'], '3D Globe');
assert.equal(i18n.MESSAGES['zh-CN']['dv.viz.globe'], '3D 地球');
assert.equal(i18n.MESSAGES.en['dv.viz.mesh'], '2D Ring');
assert.equal(i18n.MESSAGES['zh-CN']['dv.viz.mesh'], '2D 环形图');

// Verify strict CSP in tauri.conf.json allows local worker + blob without weakening default-src.
const tauriConf = JSON.parse(fs.readFileSync(path.join(DESKTOP_DIR, 'tauri.conf.json'), 'utf8'));
const csp = tauriConf.app.security.csp;
assert.ok(csp.includes("default-src 'self'"), 'CSP must keep default-src self');
assert.ok(csp.includes("worker-src 'self' blob:"), 'CSP must allow local & blob worker-src for MapLibre');
assert.ok(csp.includes("img-src 'self' data: blob:"), 'CSP must allow local/data/blob img-src');
assert.equal(/https?:\/\/(?!asset\.localhost)/i.test(csp), false, 'CSP must not allow third-party hosts');

/* ── 2. Minimal DOM harness to test pure helpers, IPC source, fallback, & Enlarge ── */

function makeFakeElement(tag) {
  const el = {
    tagName: String(tag || 'div').toUpperCase(),
    className: '',
    textContent: '',
    hidden: false,
    disabled: false,
    style: {},
    dataset: {},
    children: [],
    attrs: {},
    listeners: {},
    appendChild(child) {
      this.children.push(child);
      return child;
    },
    append(...nodes) {
      for (const n of nodes) this.children.push(n);
    },
    replaceChildren(...nodes) {
      this.children = [...nodes];
    },
    setAttribute(k, v) {
      this.attrs[k] = String(v);
    },
    getAttribute(k) {
      return this.attrs[k] ?? null;
    },
    addEventListener(type, fn) {
      if (!this.listeners[type]) this.listeners[type] = [];
      this.listeners[type].push(fn);
    },
    async trigger(type, ev) {
      for (const fn of this.listeners[type] || []) {
        await fn(ev || {});
      }
    },
    querySelector(sel) {
      if (sel === '.globe-btn-label') {
        return this.children.find((c) => c.className === 'globe-btn-label') || null;
      }
      return null;
    },
    classList: {
      set: new Set(),
      add(cls) {
        this.set.add(cls);
      },
      remove(cls) {
        this.set.delete(cls);
      },
      toggle(cls, on) {
        if (on) this.set.add(cls);
        else this.set.delete(cls);
      },
      contains(cls) {
        return this.set.has(cls);
      },
    },
  };
  return el;
}

function collectText(node) {
  if (!node) return '';
  if (typeof node === 'string') return node;
  let out = node.textContent || '';
  for (const c of node.children || []) out += ' ' + collectText(c);
  return out;
}

function createRealm() {
  const docListeners = {};
  const byId = {};
  const document = {
    readyState: 'complete',
    documentElement: {
      lang: 'en',
      dataset: { theme: 'dark' },
      classList: { contains: (c) => c === 'theme-dark' },
    },
    createElement: (tag) => makeFakeElement(tag),
    createElementNS: (_ns, tag) => makeFakeElement(tag),
    createTextNode: (text) => ({ nodeType: 3, textContent: String(text), children: [] }),
    getElementById: (id) => byId[id] || null,
    addEventListener(type, fn) {
      if (!docListeners[type]) docListeners[type] = [];
      docListeners[type].push(fn);
    },
    removeEventListener(type, fn) {
      if (!docListeners[type]) return;
      docListeners[type] = docListeners[type].filter((f) => f !== fn);
    },
    dispatchEvent(ev) {
      for (const fn of docListeners[ev.type] || []) fn(ev);
    },
  };
  const invoked = [];
  const realm = {
    window: null,
    globalThis: null,
    document,
    console,
    Buffer,
    Uint8Array,
    Uint8ClampedArray,
    ArrayBuffer,
    DataView,
    Map,
    Set,
    Math,
    Number,
    Error,
    Promise,
    CustomEvent: function CustomEvent(type, init) {
      this.type = type;
      this.detail = init && init.detail;
    },
    setTimeout,
    clearTimeout,
    atob: (b64) => Buffer.from(b64, 'base64').toString('binary'),
    __byId: byId,
    __invoked: invoked,
  };
  realm.window = realm;
  realm.globalThis = realm;
  realm.MeshHarborI18n = i18n;
  realm.MeshHarbor = {
    invoke: async (name, payload) => {
      invoked.push({ name, payload });
      if (name === 'cmd_pmtiles_range') {
        const sample = Buffer.from('PMTilesTestBytes');
        return {
          data_b64: sample.toString('base64'),
          etag: '"v1-abc"',
          cache_control: 'public, max-age=86400',
          expires: null,
        };
      }
      return 'window';
    },
  };
  vm.runInNewContext(networkMapSrc, realm);
  return realm;
}

const realm = createRealm();
const NM = realm.MeshHarborNetworkMap;
assert.ok(NM, 'MeshHarborNetworkMap should be exported');

/* ── 3. Style spec & zero-glyphs verification ──────────────────────── */

const darkStyle = NM.buildStyle('dark', 'zh-CN');
assert.equal(darkStyle.projection.type, 'globe');
assert.equal(Object.prototype.hasOwnProperty.call(darkStyle, 'glyphs'), false, 'style must omit glyphs');
assert.equal(darkStyle.sources.mhb.url, 'pmtiles://mh-boundaries-v1');
assert.equal(darkStyle.sky['atmosphere-blend'], 0);

const layerIds = new Set(darkStyle.layers.map((l) => l.id));
for (const expectedLayer of [
  'background',
  'land-low',
  'land-high',
  'coast-low',
  'coast-high',
  'admin0-intl',
  'admin0-disputed',
  'admin1',
  'admin2-other',
  'admin2-chn',
  'admin2-pref-chn',
  'label-admin0',
  'label-admin1',
  'label-admin2',
  'mh-links-direct',
  'mh-links-relay',
  'mh-links-tunnel',
  'mh-links-blocked',
  'mh-links-stalled',
  'mh-markers',
]) {
  assert.ok(layerIds.has(expectedLayer), `style missing layer ${expectedLayer}`);
}

/* ── 4. Device projection with P6 lat/lon/geo_level + unlocated count ── */

const sampleRows = [
  {
    id: '65f000000000000000000001',
    overlay_node_id: 'node-self',
    kind: 'agent',
    name: 'device-a',
    display_name: 'Device A',
    is_self: true,
    presence: 'online',
    country_code: 'CN',
    country: '中国',
    region: '广东省',
    city: '深圳市',
    lat: 22.5431,
    lon: 114.0579,
    geo_level: 'city',
    accuracy_radius_km: 20,
    effective_zone_id: 'cn',
    effective_zone_name: 'CN 区',
  },
  {
    id: '65f000000000000000000002',
    overlay_node_id: 'node-b',
    kind: 'agent',
    name: 'device-b',
    is_self: false,
    presence: 'online',
    country_code: 'SG',
    country: 'Singapore',
    region: 'Singapore',
    city: 'Singapore',
    lat: 1.3521,
    lon: 103.8198,
    geo_level: 'city',
    effective_zone_id: 'non-cn',
    effective_zone_name: 'Global',
  },
  {
    id: '65f000000000000000000003',
    overlay_node_id: 'node-c',
    kind: 'agent',
    name: 'device-c',
    is_self: false,
    presence: 'stale',
    country_code: 'DE',
    country: 'Germany',
    region: 'Hesse',
    city: 'Frankfurt',
    lat: 50.1109,
    lon: 8.6821,
    geo_level: 'city',
  },
  {
    id: '65f000000000000000000004',
    overlay_node_id: 'node-d',
    kind: 'agent',
    name: 'device-d',
    is_self: false,
    presence: 'offline',
    lat: null,
    lon: null,
    geo_level: 'unknown',
  },
  {
    id: '65f000000000000000000005',
    overlay_node_id: 'node-e',
    kind: 'agent',
    name: 'device-e',
    is_self: false,
    presence: 'online',
    country: '中国',
    region: '广东省',
    city: '深圳市',
    lat: 22.5431,
    lon: 114.0579,
    geo_level: 'city',
  },
];

const livePeers = [
  { node_id: 'node-b', agent_id: '65f000000000000000000002', online: true, connection: 'direct', rtt_ms: 32 },
  { node_id: 'node-c', agent_id: '65f000000000000000000003', online: true, connection: 'relay', rtt_ms: 178 },
];

const liveCtx = {
  selfConnected: true,
  peerFor(row) {
    return livePeers.find((p) => p.node_id === row.overlay_node_id) || null;
  },
};

const projected = NM.projectDevices(sampleRows, liveCtx);
assert.equal(projected.totalCount, 5);
assert.equal(projected.locatedItems.length, 4);
assert.equal(projected.unlocatedCount, 1);
assert.equal(projected.onlineCount, 4);
assert.equal(NM.isValidCoord(0, 0, 'city'), false, '(0,0) rejected unless geo_level=coords');
assert.equal(NM.isValidCoord(0, 0, 'coords'), true, '(0,0) accepted when geo_level=coords');
assert.equal(NM.isValidCoord(91, 0, 'city'), false);
assert.equal(NM.isValidCoord(22.5, 181, 'city'), false);

// Co-located devices in Shenzhen cluster into 1 donut (count=2, hasSelf=true).
const clusters = NM.clusterLocatedDevices(projected.locatedItems);
assert.equal(clusters.length, 3, '4 located devices across 3 cities should form 3 clusters');
const szCluster = clusters.find((c) => c.hasSelf);
assert.ok(szCluster);
assert.equal(szCluster.count, 2);
assert.equal(szCluster.onlineCount, 2);

/* ── 5. Peer link GeoJSON construction (direct, relay, tunnel, blocked, stalled) ── */

const meshView = {
  enabled: true,
  edges: [
    { from: 'node-self', to: 'node-b', carrier: 'direct', rtt_ms: 32, stalled: false },
    { from: 'node-b', to: 'node-c', carrier: 'tunnel', rtt_ms: 155, stalled: false },
    { from: 'node-self', to: 'node-c', carrier: 'relay', rtt_ms: 178, stalled: true },
  ],
};
const linkFc = NM.buildLinkFeatures(clusters, meshView, livePeers);
assert.equal(linkFc.type, 'FeatureCollection');
assert.equal(linkFc.features.length, 3);
const carriers = Array.from(linkFc.features, (f) => f.properties.carrier).sort();
assert.deepEqual(carriers, ['direct', 'relay', 'tunnel']);
const stalledEdge = linkFc.features.find((f) => f.properties.carrier === 'relay');
assert.equal(stalledEdge.properties.stalled, true);
assert.ok(stalledEdge.geometry.coordinates.length >= 17, 'great-circle arc should be interpolated');

// Trans-Pacific antimeridian unwrapping check (Tokyo 139.7E -> San Francisco -122.4W).
const transPac = NM.interpolateGreatCircle([139.69, 35.68], [-122.42, 37.77]);
for (let i = 1; i < transPac.length; i += 1) {
  assert.ok(
    Math.abs(transPac[i][0] - transPac[i - 1][0]) < 180,
    'unwrapped great circle must never jump >= 180 degrees across antimeridian',
  );
}

/* ── 6. PMTiles IPC Source round-trip & ETag mismatch handling ─────── */

async function testIpcSource() {
  class MockEtagMismatch extends Error {}
  const src = NM.createIpcPmTilesSource(realm.MeshHarbor.invoke, { EtagMismatch: MockEtagMismatch });
  assert.equal(src.getKey(), 'mh-boundaries-v1');
  const res = await src.getBytes(0, 16384, null, null);
  assert.equal(Buffer.from(res.data).toString('utf8'), 'PMTilesTestBytes');
  assert.equal(res.etag, '"v1-abc"');
  assert.equal(res.cacheControl, 'public, max-age=86400');

  const lastCall = realm.__invoked[realm.__invoked.length - 1];
  assert.equal(lastCall.name, 'cmd_pmtiles_range');
  assert.deepEqual(JSON.parse(JSON.stringify(lastCall.payload)), { offset: 0, length: 16384, etag: null });

  const mismatchSrc = NM.createIpcPmTilesSource(
    async () => {
      throw new Error('ETAG_MISMATCH: archive updated');
    },
    { EtagMismatch: MockEtagMismatch },
  );
  await assert.rejects(() => mismatchSrc.getBytes(128, 256, null, '"old"'), MockEtagMismatch);
}

/* ── 7. WebGL2 fallback plain device list rendering (XSS-safe textContent) ── */

function testWebglFallback() {
  realm.__MH_FORCE_NO_WEBGL2__ = true;
  assert.equal(NM.isWebGL2Available(), false);

  const stage = makeFakeElement('div');
  const canvas = makeFakeElement('div');
  const fallback = makeFakeElement('div');
  fallback.hidden = true;
  const summary = makeFakeElement('span');
  const unlocated = makeFakeElement('span');
  const foot = makeFakeElement('div');

  const ctrl = NM.create({
    stage,
    canvas,
    fallback,
    summary,
    unlocated,
    foot,
    invoke: realm.MeshHarbor.invoke,
  });

  const xssRows = [
    {
      id: '65f000000000000000000099',
      overlay_node_id: 'node-xss',
      kind: 'agent',
      name: '<img src=x onerror=alert(1)>',
      is_self: false,
      presence: 'online',
      country: '<script>evil()</script>',
      city: 'TestCity',
      effective_zone_name: '<b>Zone</b>',
    },
    ...sampleRows,
  ];

  ctrl.setLiveContext(liveCtx, livePeers);
  ctrl.setDevices(xssRows);
  ctrl.setActive(true);

  const st = ctrl.getState();
  assert.equal(st.fallback, true, 'must enter fallback mode when WebGL2 is unavailable');
  assert.equal(stage.hidden, true, 'WebGL stage must be hidden in fallback mode');
  assert.equal(fallback.hidden, false, 'plain device list fallback must be visible');

  const fallbackText = collectText(fallback);
  assert.ok(fallbackText.includes('WebGL2'), 'fallback notice should mention WebGL2');
  assert.ok(fallbackText.includes('<img src=x onerror=alert(1)>'), 'untrusted device name rendered verbatim as textContent');
  assert.ok(fallbackText.includes('Device A'), 'device rows rendered in fallback list');
  assert.ok(fallbackText.includes('32 ms'), 'live peer RTT rendered in fallback list');

  // Switch language to zh-CN and confirm fallback list re-renders in Chinese.
  i18n.setLang('zh-CN', { syncNative: false });
  ctrl.setLang('zh-CN');
  assert.ok(collectText(fallback).includes('WebGL2'), 'zh-CN fallback notice rendered');
  assert.ok(collectText(fallback).includes('本机'), 'zh-CN this-device chip rendered');
  i18n.setLang('en', { syncNative: false });
  delete realm.__MH_FORCE_NO_WEBGL2__;
}

/* ── 8. Enlarge button (#dv-open-globe) invokes open_network_globe ──── */

async function testEnlargeButton() {
  const meshSrc = fs.readFileSync(path.join(FRONT_DIR, 'mesh.js'), 'utf8');
  const btn = makeFakeElement('button');
  const label = makeFakeElement('span');
  label.className = 'globe-btn-label';
  label.textContent = 'Enlarge';
  btn.appendChild(label);
  const errEl = makeFakeElement('p');
  errEl.hidden = true;
  realm.__byId['dv-open-globe'] = btn;
  realm.__byId['dv-globe-error'] = errEl;

  const beforeCalls = realm.__invoked.length;
  vm.runInNewContext(meshSrc, realm);
  await btn.trigger('click');

  const call = realm.__invoked[beforeCalls];
  assert.ok(call, 'clicking Enlarge button must invoke open_network_globe');
  assert.equal(call.name, 'open_network_globe');
  assert.deepEqual(JSON.parse(JSON.stringify(call.payload)), { lang: 'en', theme: 'dark' });
  assert.equal(label.textContent, 'Enlarge', 'Enlarge button label restored after open');
  assert.equal(errEl.hidden, true);
}

/* ── 9. Unified 3D Globe / 2D Ring click & keyboard toggle (devices.js) ── */

async function testVizModeToggle() {
  const devicesSrc = fs.readFileSync(path.join(FRONT_DIR, 'devices.js'), 'utf8');
  const ids = [
    'devices-unavailable',
    'devices-content',
    'dv-grid',
    'dv-search',
    'dv-org',
    'dv-page-size',
    'dv-cols-btn',
    'dv-cols-dialog',
    'dv-refresh',
    'dv-prev',
    'dv-next',
    'dv-pager-range',
    'dv-total',
    'dv-grid-status',
    'dv-grid-error',
    'dv-globe-card',
    'dv-viz-icon-globe',
    'dv-viz-icon-mesh',
    'dv-viz-title',
    'dv-map-summary',
    'dv-mesh-meta',
    'dv-viz-switch',
    'dv-viz-globe',
    'dv-viz-mesh',
    'dv-panel-globe',
    'dv-panel-mesh',
    'dv-map-stage',
    'dv-map-canvas',
    'dv-map-fresnel',
    'dv-map-fallback',
    'dv-map-unlocated',
    'dv-map-foot',
    'dv-map-status',
    'dv-map-tooltip',
    'dv-map-zoom-in',
    'dv-map-zoom-out',
    'dv-map-reset',
    'dv-mesh-note',
    'dv-mesh-body',
    'dv-mesh-controls',
    'dv-mesh-wrap',
    'dv-mesh',
    'dv-mesh-tip',
    'dv-mesh-legend',
  ];
  const byId = {};
  for (const id of ids) {
    const el = makeFakeElement('div');
    el.value = '';
    el.focus = () => {
      el.__focused = true;
    };
    byId[id] = el;
  }
  byId['dv-panel-mesh'].hidden = true;
  byId['dv-viz-icon-mesh'].hidden = true;

  const docListeners = {};
  const storage = new Map();
  const nmActiveCalls = [];
  let graphRerenders = 0;
  let meshRenders = 0;

  const dvState = {
    available: true,
    status: { connected: true, orgs: [{ label: 'primary', primary: true, enabled: true, connected: true }] },
    peers: [],
  };

  const doc = {
    visibilityState: 'visible',
    activeElement: null,
    documentElement: { lang: 'en', dataset: {}, classList: { contains: () => false } },
    getElementById: (id) => byId[id] || null,
    createElement: (tag) => makeFakeElement(tag),
    createElementNS: (_ns, tag) => makeFakeElement(tag),
    createTextNode: (text) => ({ nodeType: 3, textContent: String(text), children: [] }),
    querySelectorAll: () => [],
    addEventListener(type, fn) {
      if (!docListeners[type]) docListeners[type] = [];
      docListeners[type].push(fn);
    },
    removeEventListener(type, fn) {
      if (!docListeners[type]) return;
      docListeners[type] = docListeners[type].filter((f) => f !== fn);
    },
    dispatchEvent(ev) {
      for (const fn of docListeners[ev.type] || []) fn(ev);
    },
  };

  const dvRealm = {
    window: null,
    globalThis: null,
    document: doc,
    console,
    Map,
    Set,
    Math,
    Number,
    Date,
    Error,
    Promise,
    Element: function Element() {},
    setTimeout: () => 1,
    clearTimeout: () => {},
    requestAnimationFrame: (fn) => fn(),
    localStorage: {
      getItem: (k) => (storage.has(k) ? storage.get(k) : null),
      setItem: (k, v) => storage.set(k, String(v)),
    },
    addEventListener: () => {},
    MeshHarborI18n: i18n,
    MeshHarbor: {
      $: (id) => byId[id] || null,
      invoke: async (name) => {
        if (name === 'cmd_mesh') return { enabled: true, acl_mode: 'warn', nodes: [{ id: 'n1', label: 'device-a' }], edges: [] };
        if (name === 'cmd_devices') return { items: [], total: 0, page: 1, per_page: 25 };
        return null;
      },
      show: (el) => {
        if (el) el.hidden = false;
      },
      hide: (el) => {
        if (el) el.hidden = true;
      },
      fmtRelative: () => 'now',
      on: () => {},
      get: (k) => (k === 'deviceView' ? dvState : null),
      currentView: () => 'devices',
      Grid: {
        create: () => ({
          render: () => {},
          patchLive: () => {},
          setSort: () => {},
          setStorageKey: () => {},
          openChooser: () => {},
          customized: () => false,
          relayout: () => {},
        }),
      },
      Mesh: {
        create: () => ({
          render: () => {
            meshRenders += 1;
          },
          rerender: () => {
            graphRerenders += 1;
          },
        }),
      },
      NetworkMap: {
        create: () => ({
          setActive: (v) => nmActiveCalls.push(v),
          setDevices: () => {},
          setLiveContext: () => {},
          setMesh: () => {},
          setLang: () => {},
          resetOrg: () => {},
        }),
      },
    },
  };
  dvRealm.window = dvRealm;
  dvRealm.globalThis = dvRealm;

  i18n.setLang('en', { syncNative: false });
  vm.runInNewContext(devicesSrc, dvRealm);
  assert.equal(dvRealm.MeshHarborDevices.normalizeVizMode('mesh'), 'mesh');
  assert.equal(dvRealm.MeshHarborDevices.normalizeVizMode('globe'), 'globe');
  assert.equal(dvRealm.MeshHarborDevices.normalizeVizMode('invalid'), 'globe');

  doc.dispatchEvent({ type: 'DOMContentLoaded' });
  doc.dispatchEvent({ type: 'meshharbor:view', detail: 'devices' });
  await new Promise((r) => setImmediate(r));

  // Initial state: 3D Globe active, 2D Ring hidden.
  assert.equal(byId['dv-globe-card'].dataset.viz, 'globe');
  assert.equal(byId['dv-panel-globe'].hidden, false);
  assert.equal(byId['dv-panel-mesh'].hidden, true);
  assert.equal(byId['dv-viz-title'].textContent, 'Network map');
  assert.equal(byId['dv-viz-globe'].getAttribute('aria-pressed'), 'true');
  assert.equal(byId['dv-viz-mesh'].getAttribute('aria-pressed'), 'false');
  assert.ok(meshRenders >= 1, 'mesh view fetched in background for globe links');

  // Click 2D Ring: alternates card to mesh ring, pauses globe, persists choice, re-measures SVG.
  const rerendersBefore = graphRerenders;
  await byId['dv-viz-mesh'].trigger('click');
  assert.equal(byId['dv-globe-card'].dataset.viz, 'mesh');
  assert.equal(byId['dv-panel-globe'].hidden, true);
  assert.equal(byId['dv-panel-mesh'].hidden, false);
  assert.equal(byId['dv-viz-title'].textContent, 'Mesh');
  assert.equal(byId['dv-viz-globe'].getAttribute('aria-pressed'), 'false');
  assert.equal(byId['dv-viz-mesh'].getAttribute('aria-pressed'), 'true');
  assert.equal(nmActiveCalls[nmActiveCalls.length - 1], false);
  assert.ok(graphRerenders > rerendersBefore, 'switching to 2D Ring must trigger SVG rerender');
  assert.equal(storage.get('meshharbor-desktop:devices-viz-mode'), 'mesh');

  // Switch language to zh-CN while on 2D Ring -> title updates to 组网拓扑.
  i18n.setLang('zh-CN', { syncNative: false });
  doc.dispatchEvent({ type: 'meshharbor:lang' });
  assert.equal(byId['dv-viz-title'].textContent, '组网拓扑');

  // Keyboard ArrowLeft cycles back to 3D Globe -> title updates to 网络地图 & globe activates.
  let prevented = false;
  await byId['dv-viz-switch'].trigger('keydown', {
    key: 'ArrowLeft',
    preventDefault: () => {
      prevented = true;
    },
  });
  assert.equal(prevented, true);
  assert.equal(byId['dv-globe-card'].dataset.viz, 'globe');
  assert.equal(byId['dv-panel-globe'].hidden, false);
  assert.equal(byId['dv-panel-mesh'].hidden, true);
  assert.equal(byId['dv-viz-title'].textContent, '网络地图');
  assert.equal(byId['dv-viz-globe'].__focused, true);
  assert.equal(nmActiveCalls[nmActiveCalls.length - 1], true);
  assert.equal(storage.get('meshharbor-desktop:devices-viz-mode'), 'globe');

  i18n.setLang('en', { syncNative: false });
}

/* ── 10. Plan B Spiderfy: effectiveSiteKey, site-grouped layout, radial fallback, XSS DOM, & lifecycle ── */

function findAllNodes(node, pred, out = []) {
  if (!node || typeof node !== 'object') return out;
  if (pred(node)) out.push(node);
  for (const c of node.children || []) findAllNodes(c, pred, out);
  return out;
}

function testSpiderfyLayoutAndDom() {
  // 10a. effectiveSiteKey: physicalPublicIp overrides publicIp; dashes/blanks normalized.
  assert.equal(
    NM.effectiveSiteKey({ physicalPublicIp: '198.51.100.10', publicIp: '203.0.113.20' }),
    '198.51.100.10',
    'physicalPublicIp must override publicIp',
  );
  assert.equal(
    NM.effectiveSiteKey({ physicalPublicIp: '', publicIp: '203.0.113.20' }),
    '203.0.113.20',
  );
  assert.equal(NM.effectiveSiteKey({ physicalPublicIp: '—', publicIp: ' - ' }), '');
  assert.equal(NM.effectiveSiteKey(null), '');

  // 10b. projectDevices keeps publicIp and physicalPublicIp.
  const multiSiteRows = [
    {
      id: 'dev-self',
      overlay_node_id: 'n-self',
      kind: 'agent',
      name: 'lab-1',
      is_self: true,
      presence: 'online',
      country: 'Testland',
      city: 'Harbor City',
      lat: 22.54,
      lon: 114.06,
      geo_level: 'city',
      public_ip: '203.0.113.99',
      physical_public_ip: '198.51.100.10',
      effective_zone_name: 'Zone-A',
    },
    {
      id: 'dev-a2',
      overlay_node_id: 'n-a2',
      kind: 'agent',
      name: 'lab-2',
      is_self: false,
      presence: 'online',
      country: 'Testland',
      city: 'Harbor City',
      lat: 22.54,
      lon: 114.06,
      geo_level: 'city',
      public_ip: '198.51.100.10',
    },
    {
      id: 'dev-b1',
      overlay_node_id: 'n-b1',
      kind: 'agent',
      name: 'office-1',
      is_self: false,
      presence: 'online',
      country: 'Testland',
      city: 'Harbor City',
      lat: 22.54,
      lon: 114.06,
      geo_level: 'city',
      public_ip: '203.0.113.20',
    },
    {
      id: 'dev-b2',
      overlay_node_id: 'n-b2',
      kind: 'agent',
      name: 'office-2',
      is_self: false,
      presence: 'stale',
      country: 'Testland',
      city: 'Harbor City',
      lat: 22.54,
      lon: 114.06,
      geo_level: 'city',
      public_ip: '203.0.113.20',
    },
    {
      id: 'dev-b3',
      overlay_node_id: 'n-b3',
      kind: 'agent',
      name: 'office-3',
      is_self: false,
      presence: 'offline',
      country: 'Testland',
      city: 'Harbor City',
      lat: 22.54,
      lon: 114.06,
      geo_level: 'city',
      public_ip: '203.0.113.20',
    },
    {
      id: 'dev-c1',
      overlay_node_id: 'n-c1',
      kind: 'agent',
      name: 'remote-1',
      is_self: false,
      presence: 'online',
      country: 'Testland',
      city: 'Harbor City',
      lat: 22.54,
      lon: 114.06,
      geo_level: 'city',
      public_ip: '192.0.2.30',
    },
    {
      id: 'dev-u1',
      overlay_node_id: 'n-u1',
      kind: 'agent',
      name: 'unmapped-ip-dev',
      is_self: false,
      presence: 'offline',
      country: 'Testland',
      city: 'Harbor City',
      lat: 22.54,
      lon: 114.06,
      geo_level: 'city',
    },
  ];
  const sitePeers = [
    { node_id: 'n-a2', agent_id: 'dev-a2', online: true, connection: 'direct', rtt_ms: 2.3 },
    { node_id: 'n-b1', agent_id: 'dev-b1', online: true, connection: 'direct', rtt_ms: 14.2 },
    { node_id: 'n-c1', agent_id: 'dev-c1', online: true, connection: 'relay', rtt_ms: 48.6, stalled: true },
  ];
  const siteProj = NM.projectDevices(multiSiteRows, {
    selfConnected: true,
    peerFor: (r) => sitePeers.find((p) => p.node_id === r.overlay_node_id) || null,
  });
  const selfItem = siteProj.items.find((it) => it.id === 'dev-self');
  assert.equal(selfItem.publicIp, '203.0.113.99');
  assert.equal(selfItem.physicalPublicIp, '198.51.100.10');
  assert.equal(NM.effectiveSiteKey(selfItem), '198.51.100.10');

  const multiClusters = NM.clusterLocatedDevices(siteProj.locatedItems);
  assert.equal(multiClusters.length, 1);
  const cityCluster = multiClusters[0];

  // Single-item cluster returns null.
  assert.equal(
    NM.computeSpiderfyLayout({ id: 'c:1', count: 1, items: [siteProj.items[0]] }, null, []),
    null,
  );

  // 10c. Multi-IP same-city cluster -> mode 'sites', sorted hasSelf first -> onlineCount desc -> count desc -> key asc.
  const siteMesh = {
    edges: [
      { from: 'n-self', to: 'n-a2', carrier: 'direct', rtt_ms: 2, stalled: false },
      { from: 'n-a2', to: 'n-b1', carrier: 'relay', rtt_ms: 28, stalled: false },
      { from: 'n-self', to: 'n-b1', carrier: 'direct', rtt_ms: 14, stalled: false },
      { from: 'n-b1', to: 'n-c1', carrier: 'tunnel', rtt_ms: 22, stalled: false },
    ],
  };
  const sitesLayout = NM.computeSpiderfyLayout(cityCluster, siteMesh, sitePeers);
  assert.equal(sitesLayout.mode, 'sites');
  assert.equal(sitesLayout.sites.length, 4, '3 distinct IPs + 1 unknown pod = 4 sites');
  assert.equal(sitesLayout.sites[0].key, '198.51.100.10', 'site containing isSelf sorts first');
  assert.equal(sitesLayout.sites[0].hasSelf, true);
  assert.equal(sitesLayout.sites[0].intraMinRttMs, 2, 'intra-site min RTT computed');
  assert.equal(sitesLayout.sites[1].key, '203.0.113.20', 'next by onlineCount/count desc');
  assert.equal(sitesLayout.sites[2].key, '192.0.2.30', 'next by onlineCount desc');
  assert.equal(sitesLayout.sites[3].isUnknown, true, 'no-IP devices placed in optional unknown pod');
  assert.equal(sitesLayout.feet.length, 7);

  // Inter-site carrier priority: direct beats relay (site A <-> B), stalled beats all (site A <-> C), tunnel kept (B <-> C).
  assert.equal(sitesLayout.siteLinks.length, 3);
  const linkAB = sitesLayout.siteLinks.find(
    (l) => l.key.includes('198.51.100.10') && l.key.includes('203.0.113.20'),
  );
  assert.ok(linkAB, 'link between site A and site B present');
  assert.equal(linkAB.carrier, 'direct', 'direct beats relay on inter-site aggregation');
  assert.equal(linkAB.stalled, false);
  assert.equal(linkAB.rttMs, 14, 'min RTT across parallel inter-site links');
  assert.ok(linkAB.pathD.startsWith('M ') && linkAB.pathD.includes(' Q '), 'curved quadratic SVG path');

  const linkAC = sitesLayout.siteLinks.find(
    (l) => l.key.includes('198.51.100.10') && l.key.includes('192.0.2.30'),
  );
  assert.ok(linkAC, 'livePeers supplements inter-site link A <-> C');
  assert.equal(linkAC.stalled, true, 'stalled flag surfaced');
  assert.equal(linkAC.rttMs, 49);

  // Verify no site link pill sits inside any site pod header bounding box.
  for (const l of sitesLayout.siteLinks) {
    for (const s of sitesLayout.sites) {
      const inHeader =
        l.pillX >= s.cx - 60 &&
        l.pillX <= s.cx + 60 &&
        l.pillY >= s.cy - s.podRadius - 36 &&
        l.pillY <= s.cy - s.podRadius;
      assert.equal(inHeader, false, `link pill ${l.key} must stay outside site ${s.id} header`);
    }
  }

  // 10d. Single-site (all share 1 egress IP) -> circle (2..8) & spiral (9..20); >20 -> list.
  const makeSameIpCluster = (n, withIp) => {
    const rows = [];
    for (let i = 0; i < n; i += 1) {
      rows.push({
        id: 'dev-' + i,
        overlay_node_id: 'n-' + i,
        kind: 'agent',
        name: 'node-' + String(i).padStart(2, '0'),
        is_self: i === 0,
        presence: i % 3 === 0 ? 'online' : i % 3 === 1 ? 'stale' : 'offline',
        city: 'Port Town',
        lat: 31.23,
        lon: 121.47,
        geo_level: 'city',
        public_ip: withIp ? '198.51.100.55' : '',
      });
    }
    const p = NM.projectDevices(rows, null);
    return NM.clusterLocatedDevices(p.locatedItems)[0];
  };

  const circleLayout = NM.computeSpiderfyLayout(makeSameIpCluster(5, true), null, []);
  assert.equal(circleLayout.mode, 'circle', '5 devices sharing 1 egress IP -> circle fallback');
  assert.equal(circleLayout.sites.length, 0);
  assert.equal(circleLayout.feet.length, 5);
  assert.equal(circleLayout.feet[0].item.isSelf, true, 'self device placed first at 12 o clock');
  assert.ok(circleLayout.feet[0].dy < 0 && Math.abs(circleLayout.feet[0].dx) < 0.1);

  const spiralLayout = NM.computeSpiderfyLayout(makeSameIpCluster(12, false), null, []);
  assert.equal(spiralLayout.mode, 'spiral', '12 no-IP devices -> Archimedean spiral fallback');
  assert.equal(spiralLayout.feet.length, 12);
  assert.ok(spiralLayout.feet[11].radius > spiralLayout.feet[0].radius, 'spiral radius grows monotonically');

  const listLayout = NM.computeSpiderfyLayout(makeSameIpCluster(25, true), null, []);
  assert.equal(listLayout.mode, 'list', '> 20 devices -> scrollable list popover');
  assert.equal(listLayout.items.length, 25, 'list mode retains all 25 devices without truncating at 5');

  // 10e. XSS-safe DOM rendering (textContent only, dark/light + en/zh-CN).
  const xssCityRows = [
    {
      id: 'x1',
      overlay_node_id: 'nx1',
      kind: 'agent',
      name: '<img src=x onerror=alert(1)>',
      is_self: true,
      presence: 'online',
      city: '<script>city()</script>',
      lat: 35.68,
      lon: 139.69,
      geo_level: 'city',
      public_ip: '198.51.100.1',
    },
    {
      id: 'x2',
      overlay_node_id: 'nx2',
      kind: 'agent',
      name: 'device-b',
      is_self: false,
      presence: 'online',
      city: '<script>city()</script>',
      lat: 35.68,
      lon: 139.69,
      geo_level: 'city',
      public_ip: '203.0.113.2',
    },
  ];
  const xssCluster = NM.clusterLocatedDevices(NM.projectDevices(xssCityRows, null).locatedItems)[0];
  const xssLayout = NM.computeSpiderfyLayout(
    xssCluster,
    { edges: [{ from: 'nx1', to: 'nx2', carrier: 'direct', rtt_ms: 9 }] },
    [],
  );
  assert.equal(xssLayout.mode, 'sites');

  let collapsedCount = 0;
  let selectedId = null;
  i18n.setLang('en', { syncNative: false });
  const domEn = NM.renderSpiderfyDom(xssCluster, xssLayout, {
    theme: 'dark',
    selectedDeviceId: 'x1',
    onCollapse: () => {
      collapsedCount += 1;
    },
    onSelectDevice: (item) => {
      selectedId = item.id;
    },
  });
  assert.equal(domEn.dataset.spiderfyMode, 'sites');
  const enText = collectText(domEn);
  assert.ok(enText.includes('Local site · 198.51.100.1'));
  assert.ok(enText.includes('Site B · 203.0.113.2'));
  assert.ok(enText.includes('Direct · 9 ms'));
  assert.ok(enText.includes('<script>city()</script>'), 'untrusted city name rendered via textContent');
  const feetBtns = findAllNodes(domEn, (n) => String(n.className).includes('nm-spiderfy-foot'));
  assert.equal(feetBtns.length, 2);
  assert.ok(feetBtns[0].className.includes('is-selected'), 'selected foot receives .is-selected');
  feetBtns[1].trigger('click', { stopPropagation() {} });
  assert.equal(selectedId, 'x2');

  const anchorBtn = findAllNodes(domEn, (n) => String(n.className).includes('nm-spiderfy-anchor'))[0];
  assert.ok(anchorBtn, 'center collapse anchor rendered');
  anchorBtn.trigger('click', { stopPropagation() {} });
  assert.equal(collapsedCount, 1);

  // Re-render in zh-CN + light mode -> localized site headings & link pill.
  i18n.setLang('zh-CN', { syncNative: false });
  const domZh = NM.renderSpiderfyDom(xssCluster, xssLayout, { theme: 'light' });
  const zhText = collectText(domZh);
  assert.ok(zhText.includes('本机站点 · 198.51.100.1'), 'zh-CN local site label rendered');
  assert.ok(zhText.includes('站点 B · 203.0.113.2'), 'zh-CN named site label rendered');
  assert.ok(zhText.includes('直连 · 9 ms'), 'zh-CN link pill rendered');
  const linkPathLight = findAllNodes(domZh, (n) => n.tagName === 'PATH')[0];
  assert.equal(linkPathLight.getAttribute('stroke'), NM.LIGHT_TOKENS.direct, 'light theme link arc stroke');

  // Render dense >20 list popover and verify all 25 rows exist.
  const denseCluster = makeSameIpCluster(25, true);
  const denseDom = NM.renderSpiderfyDom(denseCluster, NM.computeSpiderfyLayout(denseCluster, null, []), {
    theme: 'dark',
  });
  const listRows = findAllNodes(
    denseDom,
    (n) => n.tagName === 'BUTTON' && String(n.className).includes('nm-spiderfy-list-row'),
  );
  assert.equal(listRows.length, 25, 'list popover renders all 25 items without truncation');

  i18n.setLang('en', { syncNative: false });
}

function testSpiderfyControllerLifecycle() {
  // Mock MapLibre Map + Marker + WebGL2 inside an isolated realm.
  const r2 = createRealm();
  r2.WebGL2RenderingContext = function WebGL2RenderingContext() {};
  const origCreateEl = r2.document.createElement;
  r2.document.createElement = (tag) => {
    const node = origCreateEl(tag);
    if (tag === 'canvas') {
      node.getContext = (type) => {
        if (type === 'webgl2') return { getExtension: () => ({ loseContext() {} }) };
        return {
          scale() {},
          beginPath() {},
          arc() {},
          fill() {},
          stroke() {},
          closePath() {},
          moveTo() {},
          lineTo() {},
          fillText() {},
          getImageData: () => ({ width: 4, height: 4, data: new Uint8ClampedArray(64) }),
        };
      };
    }
    return node;
  };

  let mockMap = null;
  let activeMarkers = [];
  let easeCalls = [];
  let markerDataHistory = [];

  class MockMarker {
    constructor(opts) {
      this.element = opts.element;
      this.opts = opts;
      this.lngLat = null;
      this.removed = false;
    }
    setLngLat(ll) {
      this.lngLat = ll;
      return this;
    }
    addTo() {
      activeMarkers.push(this);
      return this;
    }
    remove() {
      this.removed = true;
      activeMarkers = activeMarkers.filter((m) => m !== this);
    }
  }

  class MockMap {
    constructor(opts) {
      this._handlers = {};
      this._once = {};
      this._zoom = opts.zoom || 1.4;
      this._center = { lng: opts.center[0], lat: opts.center[1] };
      this._images = new Set();
      this._canvas = makeFakeElement('canvas');
      this._sources = {
        'mh-markers': {
          setData: (fc) => markerDataHistory.push(fc),
        },
        'mh-links': { setData: () => {} },
      };
      this._hits = [];
      mockMap = this;
    }
    on(ev, fn) {
      if (!this._handlers[ev]) this._handlers[ev] = [];
      this._handlers[ev].push(fn);
    }
    once(ev, fn) {
      if (!this._once[ev]) this._once[ev] = [];
      this._once[ev].push(fn);
    }
    emit(ev, payload) {
      for (const fn of this._handlers[ev] || []) fn(payload);
      const onceList = this._once[ev] || [];
      this._once[ev] = [];
      for (const fn of onceList) fn(payload);
    }
    isStyleLoaded() {
      return true;
    }
    getLayer() {
      return {};
    }
    setPaintProperty() {}
    setLayoutProperty() {}
    setSky() {}
    hasImage(id) {
      return this._images.has(id);
    }
    addImage(id) {
      this._images.add(id);
    }
    getSource(id) {
      return this._sources[id] || null;
    }
    getCanvas() {
      return this._canvas;
    }
    getCenter() {
      return this._center;
    }
    getZoom() {
      return this._zoom;
    }
    project() {
      return { x: 320, y: 190 };
    }
    queryRenderedFeatures() {
      return this._hits;
    }
    easeTo(o) {
      easeCalls.push(o);
      if (typeof o.zoom === 'number') this._zoom = o.zoom;
      this.emit('zoom');
      this.emit('moveend');
    }
    jumpTo(o) {
      if (typeof o.zoom === 'number') this._zoom = o.zoom;
    }
    zoomTo(z) {
      this._zoom = z;
      this.emit('zoom');
    }
    resize() {}
    remove() {}
  }

  r2.maplibregl = {
    Map: MockMap,
    Marker: MockMarker,
    setWorkerUrl() {},
    addProtocol() {},
  };
  r2.pmtiles = {
    Protocol: function Protocol() {
      this.add = () => {};
      this.tile = () => {};
    },
    PMTiles: function PMTiles() {},
  };

  const stage = makeFakeElement('div');
  stage.clientWidth = 640;
  stage.clientHeight = 380;
  const canvas = makeFakeElement('div');
  const fallback = makeFakeElement('div');
  const tooltip = makeFakeElement('div');
  tooltip.hidden = true;
  tooltip.offsetWidth = 210;
  tooltip.offsetHeight = 84;
  const resetBtn = makeFakeElement('button');

  const ctrl = r2.MeshHarborNetworkMap.create({
    stage,
    canvas,
    fallback,
    tooltip,
    reset: resetBtn,
    invoke: r2.MeshHarbor.invoke,
  });

  const rows = [
    {
      id: 'd1',
      overlay_node_id: 'nd1',
      kind: 'agent',
      name: 'lab-1',
      is_self: true,
      presence: 'online',
      city: 'Harbor City',
      country: 'Testland',
      lat: 22.54,
      lon: 114.06,
      geo_level: 'city',
      public_ip: '198.51.100.10',
    },
    {
      id: 'd2',
      overlay_node_id: 'nd2',
      kind: 'agent',
      name: 'office-1',
      is_self: false,
      presence: 'online',
      city: 'Harbor City',
      country: 'Testland',
      lat: 22.54,
      lon: 114.06,
      geo_level: 'city',
      public_ip: '203.0.113.20',
    },
  ];
  const peers = [{ node_id: 'nd2', agent_id: 'd2', online: true, connection: 'direct', rtt_ms: 11 }];
  ctrl.setLiveContext({ selfConnected: true, peerFor: (r) => peers.find((p) => p.node_id === r.overlay_node_id) || null }, peers);
  ctrl.setDevices(rows);
  ctrl.setActive(true);
  mockMap.emit('load');

  // Set low zoom so clicking multi-device cluster triggers easeTo >= 2.6.
  mockMap._zoom = 1.6;
  const clusterId = markerDataHistory[markerDataHistory.length - 1].features[0].properties.clusterId;
  mockMap._hits = [{ properties: { clusterId } }];
  mockMap.emit('click', { point: { x: 320, y: 190 } });

  assert.equal(ctrl.getState().spiderfyClusterId, clusterId, 'clicking multi-device cluster opens Spiderfy');
  assert.equal(activeMarkers.length, 1, 'MapLibre Marker mounted with opacityWhenCovered=0');
  assert.equal(activeMarkers[0].opts.opacityWhenCovered, '0');
  assert.ok(easeCalls.some((e) => e.zoom >= 2.6), 'camera eases toward cluster when zoom < 2.6');
  assert.equal(
    markerDataHistory[markerDataHistory.length - 1].features.length,
    0,
    'expanded cluster donut hidden while Spiderfy is open',
  );

  // Click second device foot -> selects device & shows detail tooltip with egress IP & RTT, without covering foot.
  const feet = findAllNodes(activeMarkers[0].element, (n) => String(n.className).includes('nm-spiderfy-foot'));
  assert.equal(feet.length, 2);
  feet[1].trigger('click', { stopPropagation() {} });
  assert.equal(ctrl.getState().selectedDeviceId, 'd2');
  assert.equal(tooltip.hidden, false);
  const tipText = collectText(tooltip);
  assert.ok(tipText.includes('office-1') && tipText.includes('203.0.113.20') && tipText.includes('11 ms'));
  const tipLeft = parseFloat(tooltip.style.left);
  const tipTop = parseFloat(tooltip.style.top);
  assert.ok(tipLeft >= 10 && tipLeft + tooltip.offsetWidth <= stage.clientWidth - 10, 'tooltip fits horizontally in stage');
  assert.ok(tipTop >= 10 && tipTop + tooltip.offsetHeight <= stage.clientHeight - 10, 'tooltip fits vertically in stage');

  // Live language + theme switches re-render open Spiderfy in place without unmounting Marker.
  i18n.setLang('zh-CN', { syncNative: false });
  ctrl.setLang('zh-CN');
  ctrl.setTheme('light');
  assert.equal(activeMarkers.length, 1);
  assert.ok(collectText(activeMarkers[0].element).includes('本机站点 · 198.51.100.10'));
  assert.ok(collectText(tooltip).includes('出口 203.0.113.20'));

  // Escape collapses Spiderfy and restores cluster marker.
  r2.document.dispatchEvent({ type: 'keydown', key: 'Escape' });
  assert.equal(ctrl.getState().spiderfyClusterId, null);
  assert.equal(activeMarkers.length, 0);
  assert.equal(tooltip.hidden, true);
  assert.equal(markerDataHistory[markerDataHistory.length - 1].features.length, 1);

  // Re-open and confirm empty map click collapses Spiderfy.
  mockMap.emit('click', { point: { x: 320, y: 190 } });
  assert.equal(ctrl.getState().spiderfyClusterId, clusterId);
  mockMap._hits = [];
  mockMap.emit('click', { point: { x: 20, y: 20 } });
  assert.equal(ctrl.getState().spiderfyClusterId, null, 'clicking empty map background collapses Spiderfy');
  mockMap._hits = [{ properties: { clusterId } }];

  // Re-open and confirm Reset button collapses Spiderfy.
  mockMap.emit('click', { point: { x: 320, y: 190 } });
  assert.equal(ctrl.getState().spiderfyClusterId, clusterId);
  resetBtn.trigger('click');
  assert.equal(ctrl.getState().spiderfyClusterId, null, 'clicking Reset view collapses Spiderfy');

  // Re-open and confirm significant zoom collapses Spiderfy cleanly.
  mockMap.emit('click', { point: { x: 320, y: 190 } });
  assert.equal(ctrl.getState().spiderfyClusterId, clusterId);
  mockMap.zoomTo(mockMap.getZoom() + 1.2);
  assert.equal(ctrl.getState().spiderfyClusterId, null, 'significant zoom collapses Spiderfy');

  // Re-open and confirm setActive(false) collapses Spiderfy cleanly.
  mockMap.emit('click', { point: { x: 320, y: 190 } });
  assert.equal(ctrl.getState().spiderfyClusterId, clusterId);
  ctrl.setActive(false);
  assert.equal(ctrl.getState().spiderfyClusterId, null, 'switching tab/view collapses Spiderfy');

  ctrl.destroy();
  i18n.setLang('en', { syncNative: false });
}

(async () => {
  await testIpcSource();
  testWebglFallback();
  await testEnlargeButton();
  await testVizModeToggle();
  testSpiderfyLayoutAndDom();
  testSpiderfyControllerLifecycle();
  console.log('desktop network-map checks passed: hygiene, style, P6 coords, links, IPC source, WebGL2 fallback, Enlarge button, 3D/2D viz switcher, Plan B Spiderfy');
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
