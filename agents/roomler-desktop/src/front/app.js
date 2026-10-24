// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
/*
 * App shell: shared helpers + central pollers + the hash router.
 *
 * No bundler — Tauri 2 serves these files directly (frontendDist points
 * at this folder). Pure ES2020. `window.__TAURI__.core.invoke` is
 * exposed because tauri.conf.json has `withGlobalTauri: true`.
 *
 * Views are sections of index.html (`#view-<name>`), one visible at a
 * time. Routes are `#/overview`, `#/devices`, `#/tunnels`, `#/recordings`,
 * `#/settings`, `#/onboarding`, `#/welcome`; tray.rs navigates by evaluating
 * `location.hash`. FR-84 D6: the view the app was LAUNCHED on (`--view=`,
 * `--first-run`, a first run's Welcome) comes from `cmd_launch_intent`, read
 * once before the first route is applied — an eval from Rust during setup can
 * run before this page exists and be lost.
 *
 * Central pollers (one LocalAPI/status source instead of one per view):
 *   - `cmd_status` every 10 s      → store key `status`
 *   - `cmd_device_view` every 2 s  → store key `deviceView`
 * View files subscribe via `Roomler.on(key, cb)` and re-render; per-view
 * data (routes/flows) stays in the view file, gated on visibility.
 */
window.Roomler = (function () {
  'use strict';

  const invoke = (name, payload) => window.__TAURI__.core.invoke(name, payload || {});

  function $(id) { return document.getElementById(id); }
  function show(el) { if (el) el.hidden = false; }
  function hide(el) { if (el) el.hidden = true; }
  function setText(id, text) {
    const el = $(id);
    if (el) el.textContent = text;
  }

  /* ── formatting helpers ─────────────────────────────────────────── */

  function fmtBytes(n) {
    if (n == null) return '—';
    let v = Number(n);
    if (!Number.isFinite(v)) return '—';
    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    let u = 0;
    while (v >= 1024 && u < units.length - 1) { v /= 1024; u += 1; }
    return (u === 0 ? String(v) : v.toFixed(1)) + ' ' + units[u];
  }

  // Relative age from an epoch-ms timestamp ("12s ago" / "5m ago" / …).
  function fmtRelative(epochMs) {
    if (epochMs == null) return '—';
    const delta = Math.max(0, Date.now() - Number(epochMs));
    const s = Math.round(delta / 1000);
    if (s < 5) return 'now';
    if (s < 60) return s + 's ago';
    const m = Math.round(s / 60);
    if (m < 60) return m + 'm ago';
    const h = Math.round(m / 60);
    if (h < 48) return h + 'h ago';
    return Math.round(h / 24) + 'd ago';
  }

  /* ── store + pollers ────────────────────────────────────────────── */

  const state = { status: null, deviceView: null };
  const listeners = { status: [], deviceView: [] };

  function on(key, cb) {
    listeners[key].push(cb);
    if (state[key] !== null) {
      try { cb(state[key]); } catch (e) { console.error(e); }
    }
  }

  function emit(key, value) {
    state[key] = value;
    for (const cb of listeners[key]) {
      try { cb(value); } catch (e) { console.error('view render failed', e); }
    }
  }

  async function pollStatus() {
    try { emit('status', await invoke('cmd_status')); }
    catch (e) { console.error('cmd_status failed', e); }
  }

  async function pollDeviceView() {
    try { emit('deviceView', await invoke('cmd_device_view')); }
    catch (e) { console.error('cmd_device_view failed', e); }
  }

  /* ── router ─────────────────────────────────────────────────────── */

  const VIEWS = ['overview', 'devices', 'account', 'tunnels', 'recordings', 'settings', 'onboarding', 'welcome'];
  // The pre-overhaul front was one page per file and tray.rs navigated by
  // filename hash; map those so any stale caller still lands somewhere sane.
  const LEGACY = {
    '#index.html': 'overview',
    '#enrollment.html': 'onboarding',
    '#settings.html': 'settings',
  };

  function currentView() {
    const h = window.location.hash;
    if (LEGACY[h]) return LEGACY[h];
    const m = /^#\/([a-z]+)$/.exec(h);
    if (m && VIEWS.includes(m[1])) return m[1];
    return 'overview';
  }

  function navigate(view) {
    if (!VIEWS.includes(view)) view = 'overview';
    const target = '#/' + view;
    if (window.location.hash === target) applyRoute();
    else window.location.hash = target;
  }

  function applyRoute() {
    const view = currentView();
    for (const v of VIEWS) {
      const section = $('view-' + v);
      if (section) section.hidden = v !== view;
    }
    document.querySelectorAll('#nav a[data-view]').forEach((a) => {
      a.classList.toggle('active', a.dataset.view === view);
    });
    // Views listen for this to kick an immediate refresh on entry.
    document.dispatchEvent(new CustomEvent('roomler:view', { detail: view }));
  }

  /* ── sidebar chrome ─────────────────────────────────────────────── */

  function paintConnIndicator() {
    const dot = $('conn-dot');
    const label = $('conn-label');
    if (!dot || !label) return;
    const dv = state.deviceView;
    if (!dv || !dv.available) {
      dot.className = 'dot dot-off';
      label.textContent = 'Service offline';
      return;
    }
    const connected = !!(dv.status && dv.status.connected);
    dot.className = 'dot ' + (connected ? 'dot-on' : 'dot-warn');
    label.textContent = connected ? 'Connected' : 'Server unreachable';
  }

  function paintChrome() {
    const s = state.status;
    if (s) {
      setText('brand-version', 'v' + s.agent_version);
      // A fresh install: spotlight Onboarding, since nothing works before it.
      const onboardNav = document.querySelector('#nav a[data-view="onboarding"]');
      if (onboardNav) onboardNav.classList.toggle('nav-onboard', !s.enrolled);
    }
    paintConnIndicator();
  }

  /* ── boot ───────────────────────────────────────────────────────── */

  /* FR-84 D6 — the view this process was launched on, asked for ONCE. An
   * older/absent command (a stale front against a newer shell, or the test
   * harness) just means "no intent". */
  async function applyLaunchIntent() {
    try {
      const intent = await invoke('cmd_launch_intent');
      if (intent && typeof intent.view === 'string' && VIEWS.includes(intent.view)) {
        const target = '#/' + intent.view;
        if (window.location.hash !== target) {
          // replaceState: the launch view is where the app starts, not a
          // step a Back gesture should undo.
          history.replaceState(null, '', target);
        }
      }
    } catch (e) {
      console.debug('no launch intent', e);
    }
  }

  document.addEventListener('DOMContentLoaded', async () => {
    window.addEventListener('hashchange', applyRoute);
    await applyLaunchIntent();
    applyRoute();

    on('status', paintChrome);
    on('deviceView', paintConnIndicator);

    void pollStatus();
    void pollDeviceView();
    setInterval(pollStatus, 10000);
    // Peers/carriers move quickly; 2 s over the local pipe is cheap.
    setInterval(pollDeviceView, 2000);
  });

  return {
    invoke,
    $,
    show,
    hide,
    setText,
    fmtBytes,
    fmtRelative,
    on,
    get(key) { return state[key]; },
    navigate,
    currentView,
    refreshStatus: pollStatus,
    // FR-84 D6 — the Welcome's "waiting for an address" loop asks for a fresh
    // device view instead of waiting out the 2 s poll.
    refreshDeviceView: pollDeviceView,
  };
})();
