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
 * `window.MeshHarbor.restartDaemon` (settings.js, FR-84 D3): the
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
  const { $, invoke, show, hide, setText, on, get, navigate, refreshStatus } = window.MeshHarbor;
  const t = (key, params, fallback) =>
    window.MeshHarborI18n ? window.MeshHarborI18n.t(key, params) : fallback;

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
      const shared = window.MeshHarbor.settingsPendingRestart;
      if (shared) shared.add(key);
      else localPending.add(key);
    },
    size() {
      const shared = window.MeshHarbor.settingsPendingRestart;
      return shared ? shared.keys().length : localPending.size;
    },
    keys() {
      const shared = window.MeshHarbor.settingsPendingRestart;
      return shared ? shared.keys() : [...localPending];
    },
    has(key) {
      return this.keys().includes(key);
    },
    clear() {
      const shared = window.MeshHarbor.settingsPendingRestart;
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
    const R = window.MeshHarbor;
    if (typeof R.restartDaemon === 'function') {
      return R.restartDaemon(reason, progress);
    }
    return { ok: false, manual: true };
  }

  function manualRestartHint() {
    return installScope() === 'user'
      ? t(
          'wl.manualHintUser',
          null,
          'Saved. It takes effect the next time the MeshHarbor service starts — sign out and back in, or restart it from Settings → Background service.',
        )
      : t(
          'wl.manualHintMachine',
          null,
          'Saved. It takes effect the next time the MeshHarbor service starts — for example after the next restart of this computer.',
        );
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
      next.textContent = step === STEPS.length - 1
        ? t('wl.gotoOverview', null, 'Go to Overview')
        : t('common.next', null, 'Next');
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
        ? t('wl.net.stateMacPriv', null, "Run by MeshHarbor's system service on this Mac")
        : t('wl.net.stateMacNone', null, 'Not installed on this Mac');
    }
    const dv = get('deviceView');
    const on = entryValue('overlay_enabled') === 'true';
    if (!dv || !dv.available) {
      return on
        ? t('wl.net.stateOnOffline', null, 'On (the service is not running right now)')
        : t('common.enabledOff', null, 'Off');
    }
    const ip = dv.status && dv.status.overlay_ip;
    if (ip) return t('wl.net.stateOnIp', { ip }, 'On — this computer is ' + ip);
    if (on && pending.has('overlay_enabled')) {
      return t('wl.net.stateAfterRestart', null, 'On after the service restarts');
    }
    if (on) return t('wl.net.stateNotConnected', null, 'On, but not connected yet');
    return t('common.enabledOff', null, 'Off');
  }

  function paintNetwork() {
    const btn = el('wl-btn-net-enable');
    const userBox = el('wl-net-user');
    // A Mac is two enrollments: this app talks to the per-user (capture)
    // half, and the mesh belongs to the privileged half. Offering to put THIS
    // half on the mesh as well would make the Mac two nodes.
    if (platform.name === 'macos') {
      setText('wl-net-state', networkState());
      setText('wl-net-user-title', t('wl.net.macTitle', null, 'On a Mac'));
      setText(
        'wl-net-user-text',
        platform.macosPrivilegedHalf
          ? t(
              'wl.net.macPrivDesc',
              null,
              'The private network runs in MeshHarbor\'s system service, which has its own ' +
                'enrollment (it appears among your devices with "-daemon" after its name). ' +
                'There is nothing to turn on here.',
            )
          : t(
              'wl.net.macNoPrivDesc',
              null,
              "On a Mac the private network runs in MeshHarbor's system service, which the " +
                'installer adds when given a second enrollment token (install.sh --daemon-token). ' +
                'Screen sharing works without it.',
            ),
      );
      userBox.hidden = false;
      btn.hidden = true;
      return;
    }
    setText('wl-net-state', networkState());
    setText('wl-net-user-title', t('wl.net.userTitle', null, 'Per-user installation'));
    const scope = installScope();
    const dv = get('deviceView');
    const hasIp = !!(dv && dv.available && dv.status && dv.status.overlay_ip);
    const multiOrg = entryValue('overlay_multi_org') === 'true';
    userBox.hidden = scope !== 'user';
    if (scope === 'user') {
      if (multiOrg) {
        setText(
          'wl-net-user-text',
          t(
            'wl.net.userMultiOrg',
            null,
            'This is a per-user installation, and this computer is set to join several ' +
              "organisations' networks at once (overlay_multi_org). Userspace mode can serve only " +
              'one, so the private network here needs the machine-wide MeshHarbor service (installed ' +
              'by an administrator).',
          ),
        );
      } else {
        setText(
          'wl-net-user-text',
          t(
            'wl.net.userUserspace',
            null,
            'MeshHarbor was installed for your account only, so it cannot add a network adapter ' +
              '(that needs an administrator). It can join in userspace mode instead: remote desktop ' +
              'works as usual, and other apps reach your devices through a local SOCKS5 proxy on ' +
              'this computer.',
          ),
        );
      }
    }
    btn.textContent = scope === 'user'
      ? t('wl.net.btnEnableUserspace', null, 'Turn on in userspace mode')
      : t('wl.net.btnEnable', null, 'Turn on the private network');
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
      const reason = v.reason || t('common.unknownError', null, 'unknown error');
      setText(
        'wl-files-note',
        v.reason === 'daemon_unreachable'
          ? t('wl.files.noteOffline', null, 'The MeshHarbor service is not running, so the folder cannot be shown or changed right now.')
          : t('ov.files.noteError', { reason }, 'Could not read the setting: ' + reason),
      );
      actions.hidden = true;
      return;
    }
    setText('wl-files-path', v.effective || t('wl.files.downloads', null, 'your Downloads folder'));
    if (!v.supported) {
      setText(
        'wl-files-note',
        t(
          'wl.files.noteUnsupported',
          null,
          'This version of the MeshHarbor service always uses your Downloads folder; updating it lets you choose.',
        ),
      );
      actions.hidden = true;
      return;
    }
    actions.hidden = false;
    useDefault.hidden = !v.configured;
    const suffix = v.configured && v.configured.startsWith('~')
      ? t('ov.files.perUserSuffix', null, ' (inside the profile of whoever is signed in)')
      : '';
    setText(
      'wl-files-note',
      v.configured
        ? t('wl.files.noteChosen', { path: v.configured, suffix }, 'Your choice: ' + v.configured + suffix + '. The Overview shows the same folder.')
        : t(
            'wl.files.noteSystemDefault',
            null,
            "The default: the signed-in user's Downloads folder. You can pick another folder here or later on the Overview.",
          ),
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
    const where = value || (entry && entry.value) || t('ov.files.defaultFolderWord', null, 'the default folder');
    return entry && entry.restart_required
      ? t('ov.files.savedRestart', { where }, 'Saved: ' + where + ' — takes effect after the service restarts.')
      : t('wl.files.savedLive', { where }, 'Saved: ' + where + ' — in effect now, for the next file.');
  }

  async function paintLogin() {
    await paintAutostart('wl-login-toggle', 'wl-login-note', 'wl-login-label');
  }

  function networkOutcomeText() {
    if (!outcome.network) return networkState();
    if (outcome.network.kind === 'afterRestart') {
      return t('wl.net.stateAfterRestart', null, 'On after the service restarts');
    }
    if (outcome.network.kind === 'ip') {
      return t('wl.net.outcomeIp', { ip: outcome.network.ip }, 'On — ' + outcome.network.ip);
    }
    if (outcome.network.kind === 'notConnected') {
      return t('wl.net.outcomeNotConn', null, 'On, but not connected');
    }
    return networkState();
  }

  function paintDone() {
    setText('wl-sum-network', networkOutcomeText());
    setText(
      'wl-sum-consent',
      entryValue('auto_grant_session') === 'false'
        ? t('wl.done.sumAsk', null, 'You are asked before someone connects')
        : t('wl.done.sumAuto', null, 'People in your organisation can connect without asking'),
    );
    const loginBox = el('wl-login-toggle');
    const loginOn = outcome.login != null ? outcome.login : !!(loginBox && loginBox.checked);
    setText(
      'wl-sum-login',
      loginOn ? t('common.enabledOn', null, 'On') : t('common.enabledOff', null, 'Off'),
    );
    const n = pending.size();
    el('wl-pending').hidden = n === 0;
    if (n > 0) {
      setText(
        'wl-pending-text',
        n === 1
          ? t('wl.done.pendingOne', null, '1 setting takes effect after the MeshHarbor service restarts.')
          : t('wl.done.pendingMany', { n }, n + ' settings take effect after the MeshHarbor service restarts.'),
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
      await window.MeshHarbor.refreshDeviceView();
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
      return t('wl.net.noIpServiceDown', null, 'The MeshHarbor service did not come back. Settings → Service log says why.');
    }
    const st = dv.status || {};
    if (st.join_refusal && (st.join_refusal.detail || st.join_refusal.reason)) {
      const why = st.join_refusal.detail || st.join_refusal.reason;
      return t('wl.net.noIpRefused', { why }, 'The server did not add this computer to the network: ' + why);
    }
    if (!st.connected) {
      return t(
        'wl.net.noIpNotConnected',
        null,
        'The service is not connected to the MeshHarbor server yet, so it has no address to join with.',
      );
    }
    try {
      const tail = await invoke('cmd_tail_log', { source: 'daemon', maxBytes: 32768 });
      const lines = (tail.content || '').split('\n').filter(
        (l) => /overlay|wintun|\btun\b|netstack/i.test(l) && /\b(WARN|ERROR)\b/.test(l),
      );
      if (lines.length) {
        const line = lines[lines.length - 1].trim();
        return t('wl.net.noIpLogLine', { line }, 'No address after a minute. The service log says: ' + line);
      }
    } catch (e) {
      console.debug('welcome: no log tail', e);
    }
    return t('wl.net.noIpTimeout', null, 'No address after a minute. Settings → Service log has the details.');
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
      say('wl-net-result', t('wl.net.saving', null, 'Saving…'));
      if (scope === 'user') {
        socksPort = await freeSocksPort();
        await setKey('netstack_socks_port', String(socksPort));
      }
      await setKey('overlay_enabled', 'true');

      const r = await restartService('welcome: private network', (text) => say('wl-net-result', text));
      if (r.manual) {
        outcome.network = { kind: 'afterRestart' };
        say('wl-net-result', r.message ? t('wl.savedPrefix', { msg: r.message }, 'Saved. ' + r.message) : manualRestartHint());
        return;
      }
      if (!r.ok) {
        // The flow's own words: a refusal verbatim, or why it did not come back.
        outcome.network = { kind: 'afterRestart' };
        say('wl-net-result', r.message || t('wl.net.notRestarted', null, 'The service was not restarted.'), 'error');
        return;
      }
      pending.clear();
      say('wl-net-result', t('wl.net.waitingIp', null, 'Waiting for this computer to get its address (up to a minute)…'));
      const ip = await waitForOverlayIp(OVERLAY_WAIT_MS);
      if (ip) {
        outcome.network = { kind: 'ip', ip };
        let text = t('wl.net.connected', { ip }, 'Connected. This computer is ' + ip + ' on your private network.');
        if (socksPort) {
          text += t(
            'wl.net.connectedSocks',
            { port: socksPort },
            ' Apps reach your devices through SOCKS5 127.0.0.1:' + socksPort + '; remote desktop needs nothing.',
          );
        }
        say('wl-net-result', text, 'ok');
      } else {
        outcome.network = { kind: 'notConnected' };
        say('wl-net-result', await whyNoAddress(), 'error');
      }
    } catch (e) {
      say('wl-net-result', t('wl.net.enableFailed', { err: e }, 'Could not turn it on: ' + e), 'error');
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
          ? t(
              'wl.consent.savedRestart',
              null,
              'Saved — applies when the MeshHarbor service restarts (you can do that at the end of this tour).',
            )
          : t('wl.consent.saved', null, 'Saved.'),
      );
    } catch (e) {
      say('wl-consent-result', t('wl.consent.saveFailed', { err: e }, 'Could not save: ' + e), 'error');
      paintConsent();
    }
  }

  /* ── start at login (shared with the Settings card) ──────────────── */

  let autostartState = null;

  function autostartNote(s) {
    if (!s || !s.supported) {
      return (s && s.note) || t('wl.login.platformDefault', null, 'This platform manages login items itself.');
    }
    return s.note || '';
  }

  async function paintAutostart(toggleId, noteId, labelId) {
    const toggle = el(toggleId);
    if (!toggle) return;
    try {
      autostartState = await invoke('cmd_autostart_get');
    } catch (e) {
      autostartState = { supported: false, enabled: false, note: t('wl.login.unavailable', { err: e }, 'Unavailable: ' + e) };
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
      outcome.login = !!autostartState.enabled;
      say(
        resultId,
        enabled
          ? t('wl.login.enabledMsg', null, 'MeshHarbor starts when you sign in.')
          : t('wl.login.disabledMsg', null, 'MeshHarbor no longer starts when you sign in.'),
      );
    } catch (e) {
      say(resultId, t('wl.login.changeFailed', { err: e }, 'Could not change it: ' + e), 'error');
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
      say('wl-pending-result', r.message ? t('wl.savedPrefix', { msg: r.message }, 'Saved. ' + r.message) : manualRestartHint());
    } else if (r.ok) {
      pending.clear();
      say('wl-pending-result', t('wl.done.applied', null, 'Done — your choices are in effect.'), 'ok');
      await loadEntries();
      paintDone();
    } else {
      say('wl-pending-result', r.message || t('wl.net.notRestarted', null, 'The service was not restarted.'), 'error');
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
    window.MeshHarbor.welcomePending = false;
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
      window.MeshHarbor.welcomePending = !st.first_run_done;
      platform.name = st.platform || null;
      platform.macosPrivilegedHalf = !!st.macos_privileged_half;
    } catch (e) {
      window.MeshHarbor.welcomePending = false;
    }
  }

  document.addEventListener('meshharbor:view', (ev) => {
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
      if (window.MeshHarbor.currentView() !== 'welcome') return;
      if (STEPS[step] === 'device') paintDevice();
      if (STEPS[step] === 'network' && !busy) paintNetwork();
    });
    on('deviceView', (dv) => {
      if (window.MeshHarbor.currentView() !== 'welcome') return;
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
          ? t('ov.files.backDefaultRestart', null, 'Back to the default folder after the service restarts.')
          : t('ov.files.backDefaultLive', null, 'Back to the default folder — in effect now.');
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

    document.addEventListener('meshharbor:lang', () => {
      if (window.MeshHarbor.currentView() === 'welcome') {
        void paintStep();
      }
      if (autostartState) {
        setText('st-autostart-note', autostartNote(autostartState));
      }
    });
  });
})();
