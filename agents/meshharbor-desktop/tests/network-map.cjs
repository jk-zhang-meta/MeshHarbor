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

// Verify #dv-globe-card DOM structure & Enlarge button in index.html + i18n en & zh-CN.
assert.ok(indexHtml.includes('id="dv-globe-card"'), 'index.html missing #dv-globe-card');
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

(async () => {
  await testIpcSource();
  testWebglFallback();
  await testEnlargeButton();
  console.log('desktop network-map checks passed: hygiene, style, P6 coords, links, IPC source, WebGL2 fallback, Enlarge button');
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
