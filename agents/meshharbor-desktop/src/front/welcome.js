// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
/*
 * FR-84 D6 — the Welcome tour, and the "Start at login" card in Settings.
 *
 * Six steps, one at a time: this device · the private network · who may view
 * this screen · where received files land · start at login · done. The tour
 * opens by itself until the person finishes or skips it (`first_run_done` in
 * the per-user desktop state, owned by the Rust side); after that it is
 * reachable from the tray's "Welcome tour" and from Settings.
 *
 * Every choice is saved the moment it is made (cmd_config_set), so quitting
 * half-way loses nothing. Keys the daemon applies only at a restart join the
 * app's ONE pending set (Settings' restart bar shows the same keys) and are
 * applied together by ONE service restart — through the ONE restart flow,
 * `window.Roomler.restartDaemon` (settings.js, FR-84 D3): the
 * private-network step restarts at once (it has to, to show the address it
 * gets), and anything chosen after that is applied from the last step.
 *
 * Received files use FR-84 D4's own commands (`cmd_files_dir_view`,
 * `cmd_pick_files_dir`, `cmd_open_files_dir`, `cmd_files_dir_default`), and
 * the service's refusals are shown verbatim.
 *
 * All dynamic text goes in through textContent.
 */
(function () {
  'use strict';
  const { $, invoke, show, hide, setText, on, get, navigate, refreshStatus } = window.Roomler;

  const STEPS = ['device', 'network', 'consent', 'files', 'login', 'done'];
  const OVERLAY_WAIT_MS = 60000;
  const POLL_MS = 1000;
  // Userspace mode's SOCKS front: probed upward from here, never 1080 —
  // a declared route tends to hold exactly that one.
  const SOCKS_PORT_BASE = 41080;

  let step = 0;
  let busy = false;
  // Keys waiting for a service restart: the app's one set, Settings' restart
  // bar included (settings.js). A local stand-in only if that is absent.
  const localPending = new Set();
  const pending = {
    add(key) {
      const shared = window.Roomler.settingsPendingRestart;
      if (shared) shared.add(key);
      else localPending.add(key);
    },
    size() {
      const shared = window.Roomler.settingsPendingRestart;
      return shared ? shared.keys().length : localPending.size;
    },
    keys() {
      const shared = window.Roomler.settingsPendingRestart;
      return shared ? shared.keys() : [...localPending];
    },
    has(key) {
      return this.keys().includes(key);
    },
    clear() {
      const shared = window.Roomler.settingsPendingRestart;
      if (shared) shared.clear();
      localPending.clear();
    },
  };
  // Last config entries read, keyed by key.
  let entries = new Map();
  // What the tour did, for the summary.
  const outcome = { network: null, consent: null, login: null };
  // From cmd_desktop_state: the platform, and on a Mac whether the privileged
  // half (which owns the mesh there) is installed.
  const platform = { name: null, macosPrivilegedHalf: false };

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function el(id) {
    return $(id);
  }

  function say(id, text, kind) {
    const node = el(id);
    if (!node) return;
    node.textContent = text;
    node.classList.toggle('error', kind === 'error');
    node.classList.toggle('ok', kind === 'ok');
    node.hidden = !text;
  }

  function entryValue(key) {
    const e = entries.get(key);
    return e ? e.value : undefined;
  }

  async function loadEntries() {
    try {
      const list = await invoke('cmd_config_entries');
      entries = new Map(list.map((e) => [e.key, e]));
    } catch (e) {
      console.warn('welcome: config entries unavailable', e);
    }
  }

  /* Machine-wide service (it can add a network adapter) or a per-user one
   * (it cannot: no admin). The Windows flavour probe is authoritative; else
   * the config file the running daemon loaded says it — /etc (Linux, macOS)
   * or ProgramData (Windows) is a machine-wide service. */
  function installScope() {
    const s = get('status');
    if (s && s.service_kind === 'scmService') return 'machine';
    if (s && s.service_kind === 'scheduledTask') return 'user';
    const dv = get('deviceView');
    const cp = dv && dv.status && dv.status.config_path;
    if (cp) {
      if (/^\/etc\//.test(cp) || /programdata/i.test(cp)) return 'machine';
      return 'user';
    }
    return 'unknown';
  }

  /* ── service restart: the app's one flow (settings.js, FR-84 D3) ──── */

  /* {ok:true} once a NEW daemon answers; {ok:false, message} when it refused
   * (the service's own words) or did not come back; {manual:true} when the
   * service predates "Apply now" — or this page has no restart flow at all. */
  async function restartService(reason, progress) {
    const R = window.Roomler;
    if (typeof R.restartDaemon === 'function') {
      return R.restartDaemon(reason, progress);
    }
    return { ok: false, manual: true };
  }

  function manualRestartHint() {
    return installScope() === 'user'
      ? 'Saved. It takes effect the next time the Roomler service starts — sign out and back in, or restart it from Settings → Background service.'
      : 'Saved. It takes effect the next time the Roomler service starts — for example after the next restart of this computer.';
  }

  /* ── step rendering ─────────────────────────────────────────────── */

  function paintProgress() {
    document.querySelectorAll('#wl-progress li').forEach((li, i) => {
      li.classList.toggle('active', i === step);
      li.classList.toggle('done', i < step);
    });
    document.querySelectorAll('#view-welcome .wl-step').forEach((node) => {
      node.hidden = node.dataset.step !== STEPS[step];
    });
    const back = el('wl-btn-back');
    const next = el('wl-btn-next');
    const skip = el('wl-btn-skip');
    if (back) back.hidden = step === 0;
    if (skip) skip.hidden = step === STEPS.length - 1;
    if (next) {
      next.textContent = step === STEPS.length - 1 ? 'Go to Overview' : 'Next';
      next.disabled = busy;
    }
  }

  function paintDevice() {
    const s = get('status');
    const dv = get('deviceView');
    const enrolled = !!(s && s.enrolled);
    el('wl-dev-enrolled').hidden = !enrolled;
    el('wl-dev-unenrolled').hidden = enrolled || !s;
    if (enrolled) {
      const liveName = dv && dv.available && dv.status && dv.status.name;
      setText('wl-dev-name', liveName || s.device_name || '—');
      setText('wl-dev-server', s.server_url || '—');
    }
    el('wl-dev-offline').hidden = !dv || dv.available;
  }

  function networkState() {
    if (platform.name === 'macos') {
      return platform.macosPrivilegedHalf
        ? "Run by Roomler's system service on this Mac"
        : 'Not installed on this Mac';
    }
    const dv = get('deviceView');
    const on = entryValue('overlay_enabled') === 'true';
    if (!dv || !dv.available) {
      return on ? 'On (the service is not running right now)' : 'Off';
    }
    const ip = dv.status && dv.status.overlay_ip;
    if (ip) return 'On — this computer is ' + ip;
    if (on && pending.has('overlay_enabled')) return 'On after the service restarts';
    if (on) return 'On, but not connected yet';
    return 'Off';
  }

  function paintNetwork() {
    const btn = el('wl-btn-net-enable');
    const userBox = el('wl-net-user');
    // A Mac is two enrollments: this app talks to the per-user (capture)
    // half, and the mesh belongs to the privileged half. Offering to put THIS
    // half on the mesh as well would make the Mac two nodes.
    if (platform.name === 'macos') {
      setText('wl-net-state', networkState());
      setText('wl-net-user-title', 'On a Mac');
      setText(
        'wl-net-user-text',
        platform.macosPrivilegedHalf
          ? "The private network runs in Roomler's system service, which has its own " +
              'enrollment (it appears among your devices with "-daemon" after its name). ' +
              'There is nothing to turn on here.'
          : "On a Mac the private network runs in Roomler's system service, which the " +
              'installer adds when given a second enrollment token (install.sh --daemon-token). ' +
              'Screen sharing works without it.',
      );
      userBox.hidden = false;
      btn.hidden = true;
      return;
    }
    setText('wl-net-state', networkState());
    setText('wl-net-user-title', 'Per-user installation');
    const scope = installScope();
    const dv = get('deviceView');
    const hasIp = !!(dv && dv.available && dv.status && dv.status.overlay_ip);
    const multiOrg = entryValue('overlay_multi_org') === 'true';
    userBox.hidden = scope !== 'user';
    if (scope === 'user') {
      if (multiOrg) {
        setText(
          'wl-net-user-text',
          'This is a per-user installation, and this computer is set to join several ' +
            "organisations' networks at once (overlay_multi_org). Userspace mode can serve only " +
            'one, so the private network here needs the machine-wide Roomler service (installed ' +
            'by an administrator).',
        );
      } else {
        setText(
          'wl-net-user-text',
          'Roomler was installed for your account only, so it cannot add a network adapter ' +
            '(that needs an administrator). It can join in userspace mode instead: remote desktop ' +
            'works as usual, and other apps reach your devices through a local SOCKS5 proxy on ' +
            'this computer.',
        );
      }
    }
    btn.textContent = scope === 'user' ? 'Turn on in userspace mode' : 'Turn on the private network';
    btn.hidden = hasIp || (scope === 'user' && multiOrg);
    btn.disabled = busy || !(get('status') && get('status').enrolled);
  }

  function paintConsent() {
    const box = el('wl-consent-ask');
    if (box && !box.matches(':focus')) {
      // auto_grant_session = false ⇔ "ask me".
      box.checked = entryValue('auto_grant_session') === 'false';
    }
  }

  /* Received files — FR-84 D4's `cmd_files_dir_view`: where the next file
   * lands (`effective`), what is configured, and whether this service knows
   * the setting at all. */
  let filesView = null;
  let filesBusy = false;

  async function refreshFiles() {
    try {
      filesView = await invoke('cmd_files_dir_view');
    } catch (e) {
      filesView = { available: false, reason: String(e) };
    }
    paintFiles();
  }

  function paintFiles() {
    const v = filesView;
    const actions = el('wl-files-actions');
    const useDefault = el('wl-btn-files-default');
    if (!v) {
      setText('wl-files-path', '…');
      actions.hidden = true;
      return;
    }
    if (!v.available) {
      setText('wl-files-path', '—');
      setText(
        'wl-files-note',
        v.reason === 'daemon_unreachable'
          ? 'The Roomler service is not running, so the folder cannot be shown or changed right now.'
          : 'Could not read the setting: ' + (v.reason || 'unknown error'),
      );
      actions.hidden = true;
      return;
    }
    setText('wl-files-path', v.effective || 'your Downloads folder');
    if (!v.supported) {
      setText(
        'wl-files-note',
        'This version of the Roomler service always uses your Downloads folder; updating it lets you choose.',
      );
      actions.hidden = true;
      return;
    }
    actions.hidden = false;
    useDefault.hidden = !v.configured;
    setText(
      'wl-files-note',
      v.configured
        ? 'Your choice: ' + v.configured +
            (v.configured.startsWith('~') ? ' (inside the profile of whoever is signed in)' : '') +
            '. The Overview shows the same folder.'
        : "The default: the signed-in user's Downloads folder. You can pick another folder here or later on the Overview.",
    );
  }

  async function filesAction(run) {
    if (filesBusy) return;
    filesBusy = true;
    say('wl-files-result', '');
    try {
      const text = await run();
      if (text) say('wl-files-result', text, 'ok');
    } catch (e) {
      // The service's own words: a refusal names the rule it applied.
      say('wl-files-result', String(e), 'error');
    } finally {
      filesBusy = false;
      await refreshFiles();
    }
  }

  function filesSavedText(entry, value) {
    const where = value || (entry && entry.value) || 'the default folder';
    return (
      'Saved: ' +
      where +
      (entry && entry.restart_required
        ? ' — takes effect after the service restarts.'
        : ' — in effect now, for the next file.')
    );
  }

  async function paintLogin() {
    await paintAutostart('wl-login-toggle', 'wl-login-note', 'wl-login-label');
  }

  function paintDone() {
    setText('wl-sum-network', outcome.network || networkState());
    setText(
      'wl-sum-consent',
      entryValue('auto_grant_session') === 'false'
        ? 'You are asked before someone connects'
        : 'People in your organisation can connect without asking',
    );
    const loginBox = el('wl-login-toggle');
    setText(
      'wl-sum-login',
      outcome.login || (loginBox && loginBox.checked ? 'On' : 'Off'),
    );
    const n = pending.size();
    el('wl-pending').hidden = n === 0;
    if (n > 0) {
      setText(
        'wl-pending-text',
        n === 1
          ? '1 setting takes effect after the Roomler service restarts.'
          : n + ' settings take effect after the Roomler service restarts.',
      );
    }
  }

  async function paintStep() {
    paintProgress();
    const name = STEPS[step];
    if (name === 'device') paintDevice();
    else if (name === 'network') paintNetwork();
    else if (name === 'consent') paintConsent();
    else if (name === 'files') await refreshFiles();
    else if (name === 'login') await paintLogin();
    else if (name === 'done') paintDone();
  }

  /* ── the private network ─────────────────────────────────────────── */

  async function setKey(key, value) {
    const entry = await invoke('cmd_config_set', { key, value });
    entries.set(key, entry);
    if (entry.restart_required) pending.add(key);
    return entry;
  }

  async function waitForOverlayIp(deadlineMs) {
    const until = Date.now() + deadlineMs;
    while (Date.now() < until) {
      await window.Roomler.refreshDeviceView();
      const dv = get('deviceView');
      const ip = dv && dv.available && dv.status && dv.status.overlay_ip;
      if (ip) return ip;
      await sleep(POLL_MS);
    }
    return null;
  }

  /* Why no address came: the server's refusal if there is one, the link to
   * the server, else the last overlay warning in the service log. */
  async function whyNoAddress() {
    const dv = get('deviceView');
    if (!dv || !dv.available) {
      return 'The Roomler service did not come back. Settings → Service log says why.';
    }
    const st = dv.status || {};
    if (st.join_refusal && (st.join_refusal.detail || st.join_refusal.reason)) {
      return 'The server did not add this computer to the network: ' +
        (st.join_refusal.detail || st.join_refusal.reason);
    }
    if (!st.connected) {
      return 'The service is not connected to the Roomler server yet, so it has no address to join with.';
    }
    try {
      const tail = await invoke('cmd_tail_log', { source: 'daemon', maxBytes: 32768 });
      const lines = (tail.content || '').split('\n').filter(
        (l) => /overlay|wintun|\btun\b|netstack/i.test(l) && /\b(WARN|ERROR)\b/.test(l),
      );
      if (lines.length) {
        return 'No address after a minute. The service log says: ' + lines[lines.length - 1].trim();
      }
    } catch (e) {
      console.debug('welcome: no log tail', e);
    }
    return 'No address after a minute. Settings → Service log has the details.';
  }

  async function freeSocksPort() {
    let exclude = [];
    try {
      const tv = await invoke('cmd_tunnels_view');
      if (tv && tv.available) {
        exclude = (tv.routes || []).map((r) => r.route && r.route.local).filter((p) => p);
      }
    } catch (e) {
      console.debug('welcome: routes unavailable for the port probe', e);
    }
    return invoke('cmd_free_port', { preferred: SOCKS_PORT_BASE, exclude });
  }

  async function enableNetwork() {
    if (busy) return;
    busy = true;
    paintNetwork();
    paintProgress();
    const scope = installScope();
    let socksPort = null;
    try {
      say('wl-net-result', 'Saving…');
      if (scope === 'user') {
        socksPort = await freeSocksPort();
        await setKey('netstack_socks_port', String(socksPort));
      }
      await setKey('overlay_enabled', 'true');

      const r = await restartService('welcome: private network', (text) => say('wl-net-result', text));
      if (r.manual) {
        outcome.network = 'On after the service restarts';
        say('wl-net-result', r.message ? 'Saved. ' + r.message : manualRestartHint());
        return;
      }
      if (!r.ok) {
        // The flow's own words: a refusal verbatim, or why it did not come back.
        outcome.network = 'On after the service restarts';
        say('wl-net-result', r.message || 'The service was not restarted.', 'error');
        return;
      }
      pending.clear();
      say('wl-net-result', 'Waiting for this computer to get its address (up to a minute)…');
      const ip = await waitForOverlayIp(OVERLAY_WAIT_MS);
      if (ip) {
        outcome.network = 'On — ' + ip;
        let text = 'Connected. This computer is ' + ip + ' on your private network.';
        if (socksPort) {
          text += ' Apps reach your devices through SOCKS5 127.0.0.1:' + socksPort +
            '; remote desktop needs nothing.';
        }
        say('wl-net-result', text, 'ok');
      } else {
        outcome.network = 'On, but not connected';
        say('wl-net-result', await whyNoAddress(), 'error');
      }
    } catch (e) {
      say('wl-net-result', 'Could not turn it on: ' + e, 'error');
    } finally {
      busy = false;
      await loadEntries();
      paintNetwork();
      paintProgress();
      void refreshStatus();
    }
  }

  /* ── consent ─────────────────────────────────────────────────────── */

  async function setConsent(ask) {
    try {
      const entry = await setKey('auto_grant_session', ask ? 'false' : 'true');
      outcome.consent = ask ? 'ask' : 'auto';
      say(
        'wl-consent-result',
        entry.restart_required
          ? 'Saved — applies when the Roomler service restarts (you can do that at the end of this tour).'
          : 'Saved.',
      );
    } catch (e) {
      say('wl-consent-result', 'Could not save: ' + e, 'error');
      paintConsent();
    }
  }

  /* ── start at login (shared with the Settings card) ──────────────── */

  let autostartState = null;

  function autostartNote(s) {
    if (!s || !s.supported) {
      return (s && s.note) || 'This platform manages login items itself.';
    }
    return s.note || '';
  }

  async function paintAutostart(toggleId, noteId, labelId) {
    const toggle = el(toggleId);
    if (!toggle) return;
    try {
      autostartState = await invoke('cmd_autostart_get');
    } catch (e) {
      autostartState = { supported: false, enabled: false, note: 'Unavailable: ' + e };
    }
    toggle.checked = !!autostartState.enabled;
    toggle.disabled = !autostartState.supported;
    const label = el(labelId);
    if (label) label.classList.toggle('disabled', !autostartState.supported);
    setText(noteId, autostartNote(autostartState));
  }

  async function setAutostart(enabled, resultId, toggleId, noteId, labelId) {
    try {
      autostartState = await invoke('cmd_autostart_set', { enabled });
      outcome.login = autostartState.enabled ? 'On' : 'Off';
      say(resultId, enabled ? 'Roomler starts when you sign in.' : 'Roomler no longer starts when you sign in.');
    } catch (e) {
      say(resultId, 'Could not change it: ' + e, 'error');
    }
    await paintAutostart(toggleId, noteId, labelId);
  }

  /* ── pending restart from the last step ──────────────────────────── */

  async function applyPending() {
    const btn = el('wl-btn-apply');
    btn.disabled = true;
    const r = await restartService(
      'welcome: ' + pending.keys().join(', '),
      (text) => say('wl-pending-result', text),
    );
    if (r.manual) {
      say('wl-pending-result', r.message ? 'Saved. ' + r.message : manualRestartHint());
    } else if (r.ok) {
      pending.clear();
      say('wl-pending-result', 'Done — your choices are in effect.', 'ok');
      await loadEntries();
      paintDone();
    } else {
      say('wl-pending-result', r.message || 'The service was not restarted.', 'error');
    }
    btn.disabled = false;
  }

  /* ── navigation ──────────────────────────────────────────────────── */

  async function finish() {
    try {
      await invoke('cmd_first_run_done');
    } catch (e) {
      console.warn('welcome: could not record the finished tour', e);
    }
    window.Roomler.welcomePending = false;
    navigate('overview');
  }

  async function go(delta) {
    if (busy) return;
    const nextStep = step + delta;
    if (nextStep >= STEPS.length) {
      await finish();
      return;
    }
    step = Math.max(0, Math.min(STEPS.length - 1, nextStep));
    await paintStep();
  }

  async function enter() {
    step = 0;
    await loadEntries();
    await paintStep();
  }

  async function refreshWelcomePending() {
    try {
      const st = await invoke('cmd_desktop_state');
      window.Roomler.welcomePending = !st.first_run_done;
      platform.name = st.platform || null;
      platform.macosPrivilegedHalf = !!st.macos_privileged_half;
    } catch (e) {
      window.Roomler.welcomePending = false;
    }
  }

  document.addEventListener('roomler:view', (ev) => {
    if (ev.detail === 'welcome') void enter();
    if (ev.detail === 'settings') {
      void paintAutostart('st-autostart-toggle', 'st-autostart-note', 'st-autostart-label');
    }
  });

  document.addEventListener('DOMContentLoaded', () => {
    void refreshWelcomePending();

    // Live state keeps the visible step honest (an enrollment that lands, an
    // address that arrives while the person reads).
    on('status', () => {
      if (window.Roomler.currentView() !== 'welcome') return;
      if (STEPS[step] === 'device') paintDevice();
      if (STEPS[step] === 'network' && !busy) paintNetwork();
    });
    on('deviceView', (dv) => {
      if (window.Roomler.currentView() !== 'welcome') return;
      if (STEPS[step] === 'device') paintDevice();
      if (STEPS[step] === 'network' && !busy) setText('wl-net-state', networkState());
      // The daemon's effective folder moved (a change made elsewhere, a
      // refusal at use time): read the view again, as the Overview does.
      const st = dv && dv.available && dv.status;
      if (
        STEPS[step] === 'files' &&
        !filesBusy &&
        st &&
        st.files_dir &&
        filesView &&
        filesView.available &&
        st.files_dir !== filesView.effective
      ) {
        void refreshFiles();
      }
    });

    el('wl-btn-next').addEventListener('click', () => void go(1));
    el('wl-btn-back').addEventListener('click', () => void go(-1));
    el('wl-btn-skip').addEventListener('click', () => void finish());
    el('wl-btn-enroll').addEventListener('click', () => navigate('onboarding'));
    el('wl-btn-net-enable').addEventListener('click', () => void enableNetwork());
    el('wl-consent-ask').addEventListener('change', (ev) => void setConsent(ev.target.checked));
    el('wl-btn-apply').addEventListener('click', () => void applyPending());
    el('wl-login-toggle').addEventListener('change', (ev) =>
      void setAutostart(ev.target.checked, 'wl-login-result', 'wl-login-toggle', 'wl-login-note', 'wl-login-label'),
    );

    // FR-84 D4's folder commands; the service's refusals shown verbatim.
    el('wl-btn-files-open').addEventListener('click', () =>
      filesAction(async () => {
        await invoke('cmd_open_files_dir');
        return '';
      }),
    );
    el('wl-btn-files-change').addEventListener('click', () =>
      filesAction(async () => {
        const r = await invoke('cmd_pick_files_dir');
        return r.cancelled ? '' : filesSavedText(r.entry, r.value);
      }),
    );
    el('wl-btn-files-default').addEventListener('click', () =>
      filesAction(async () => {
        const entry = await invoke('cmd_files_dir_default');
        return entry.restart_required
          ? 'Back to the default folder after the service restarts.'
          : 'Back to the default folder — in effect now.';
      }),
    );

    // The Settings card.
    const stToggle = el('st-autostart-toggle');
    if (stToggle) {
      stToggle.addEventListener('change', (ev) =>
        void setAutostart(ev.target.checked, 'st-autostart-result', 'st-autostart-toggle', 'st-autostart-note', 'st-autostart-label'),
      );
    }
    const tour = el('btn-welcome-tour');
    if (tour) tour.addEventListener('click', () => navigate('welcome'));
  });
})();
