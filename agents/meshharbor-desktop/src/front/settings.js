// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
/*
 * Settings view: device rename, background-service management, split-config
 * cleanup and file locations (re-enrollment moved to Onboarding in S1b).
 * Status data comes from the central store; mutations go through the
 * matching cmd_* commands. Results are rendered with textContent (no
 * innerHTML) into the shared banner slot.
 */
(function () {
  'use strict';
  const { $, invoke, show, hide, setText, on, navigate, refreshStatus } = window.Roomler;

  function showResult(text, isError) {
    const el = $('settings-result');
    el.hidden = false;
    el.textContent = text;
    el.className = 'banner ' + (isError ? 'banner-error' : 'banner-ok');
  }

  function paintStatus(s) {
    const rename = $('rename-input');
    if (rename && !rename.matches(':focus') && s.device_name && !rename.value) {
      rename.value = s.device_name;
    }
    setText(
      'st-service',
      s.service_kind === 'scmService'
        ? 'System service' + (s.service_running ? ' · running' : ' · stopped')
        : s.service_kind === 'scheduledTask'
          ? 'Per-user auto-start' + (s.service_running ? ' · running' : '')
          : 'not installed',
    );
    setText('st-log-dir', s.log_dir);
    setText('st-config-dir', s.config_dir);
    if (s.config_split) show($('st-split-banner'));
    else hide($('st-split-banner'));
    // S1b: when the daemon is reachable it reports the config file it
    // actually LOADED — authoritative over the flavour-guess above.
    const dv = window.Roomler.get && window.Roomler.get('deviceView');
    if (dv && dv.available && dv.status && dv.status.config_path) {
      setText('st-config-dir', dv.status.config_path);
    }
    // Rename/re-enroll write the machine-wide config under an SCM install,
    // which an unelevated desktop app can't do — say so up front instead of
    // only failing on submit.
    const isScm = s.service_kind === 'scmService';
    document.querySelectorAll('.scm-hint').forEach((el) => { el.hidden = !isScm; });
  }

  /* ── S2: device configuration editor ──────────────────────────────
   * Rows come from cmd_config_entries (the daemon's editable surface);
   * each row's editor is keyed on the entry's `kind` contract:
   *   bool / tribool / enum:<a|b|c> → a <select>, applied on change;
   *   string / list / json          → text input or textarea + Save.
   * Everything is built with createElement + textContent (no innerHTML).
   *
   * FR-84 D2: an entry also carries `group` / `group_label` / `tier` /
   * `default`, and a per-key `restart_required` that is the daemon's own
   * truth (before D2 this file kept a LIVE_KEYS set of its own — a copy
   * that would have gone stale the day a third key went live). With the
   * metadata the page renders an Essentials section (open) and one
   * collapsible section per group, in the order the daemon lists them;
   * without it — a daemon older than D2 — it renders the flat list.
   */
  let cfgLoaded = false;

  /* Which sections the person left open, remembered per user. No record
   * yet = the defaults: Essentials open, every group collapsed. */
  const OPEN_GROUPS_KEY = 'meshharbor-desktop:settings:open-groups';
  const ESSENTIALS_ID = '__essentials';

  function readOpenGroups() {
    try {
      const raw = localStorage.getItem(OPEN_GROUPS_KEY);
      if (raw === null) return null;
      const arr = JSON.parse(raw);
      return new Set(Array.isArray(arr) ? arr.filter((s) => typeof s === 'string') : []);
    } catch {
      return null;
    }
  }

  function writeOpenGroups(set) {
    try { localStorage.setItem(OPEN_GROUPS_KEY, JSON.stringify([...set])); } catch {}
  }

  function defaultOpen(id) {
    const remembered = readOpenGroups();
    return remembered ? remembered.has(id) : id === ESSENTIALS_ID;
  }

  /* `toggle` fires (asynchronously) for programmatic open/close too — a
   * search opening the sections it matched, the initial render — and none
   * of those is a preference. Count the programmatic changes and release
   * the guard on a later task, which runs after the queued toggle events. */
  let programmaticToggles = 0;
  function withProgrammaticToggles(fn) {
    programmaticToggles += 1;
    try { fn(); } finally {
      setTimeout(() => { programmaticToggles -= 1; }, 0);
    }
  }

  /* Keys saved this session whose change waits for a service restart. The
   * sticky bar above the cards counts them. FR-84 D3 mounts its "Apply
   * now" control in `actionsSlot()` and calls `clear()` once the daemon is
   * back — the hook is `window.Roomler.settingsPendingRestart`. */
  const pendingRestart = new Set();

  function paintRestartBar() {
    const bar = $('cfg-restart-bar');
    if (!bar) return;
    const n = pendingRestart.size;
    if (n === 0) { hide(bar); return; }
    setText(
      'cfg-restart-text',
      n === 1
        ? '1 change takes effect after the service restarts.'
        : n + ' changes take effect after the service restarts.',
    );
    show(bar);
  }

  window.Roomler.settingsPendingRestart = {
    keys: () => [...pendingRestart],
    add(key) { pendingRestart.add(key); paintRestartBar(); },
    clear() { pendingRestart.clear(); paintRestartBar(); },
    actionsSlot: () => $('cfg-restart-actions'),
  };

  /* ── FR-84 D3: Apply now — the daemon restarts itself under its supervisor
   *
   * `cmd_restart_daemon` asks; the DAEMON decides. It refuses when it cannot
   * prove a supervisor (an orphan `roomlerd run` would go offline rather
   * than restart), when `local_restart_enabled` is off, while a recording
   * runs, or within 30 s of its last restart — and every refusal is shown
   * verbatim. Accepted, the old process keeps answering for a moment, so
   * `cmd_restart_wait` waits for a DIFFERENT process rather than for
   * "reachable", and when the answer says `restart_by: 'caller'` (the Windows Scheduled
   * Task) it runs `roomlerd service start` itself whenever nothing answers.
   * Once the new daemon is up, the pending set clears and the entries reload
   * from the file the new process read. */
  let applying = false;

  function restartRefusalText(r) {
    if (r.predates) {
      return 'This service predates Apply now — restart it from Background service.';
    }
    return 'Not restarted — ' + r.refusal;
  }

  /* Wait for the relaunched daemon (≤ 60 s, Rust side): its pid, or throws.
   * "Relaunched" = another PROCESS (pid + start time — Windows may hand the
   * new daemon the old pid), never merely "reachable". */
  async function waitForDaemon(r) {
    return invoke('cmd_restart_wait', {
      oldPid: r.pid,
      oldStartedAtMs: r.started_at_ms,
      restartBy: r.restart_by,
      // #1684 — wait as long as the supervisor says the relaunch may take
      // (systemd: TimeoutStopSec + RestartSec). null/undefined ⇒ the 60 s
      // floor, i.e. today's behaviour.
      restartWithinS: r.restart_within_s ?? null,
    });
  }

  /* The ONE restart flow in the app — Settings' Apply now and the Welcome
   * tour (FR-84 D6) both call it, as `window.Roomler.restartDaemon`. Ask,
   * then wait for a DIFFERENT process. Resolves (never rejects):
   *   {ok: true}                               the new daemon answers;
   *   {ok: false, stage, message}              refused ('refused', verbatim),
   *                                            not asked ('ask'), or not back
   *                                            ('wait');
   *   {ok: false, manual: true, stage, message} the service predates the verb.
   * `progress(text)` receives each stage for the caller's status line. On
   * success every key that was waiting for a restart is in force, so the
   * shared pending set clears here, whoever asked. */
  async function restartDaemon(reason, progress) {
    const say = typeof progress === 'function' ? progress : () => {};
    say('Asking the service to restart…');
    let r;
    try {
      r = await invoke('cmd_restart_daemon', { reason });
    } catch (e) {
      return { ok: false, stage: 'ask', message: 'Could not ask the service to restart: ' + e };
    }
    if (!r.started) {
      return {
        ok: false,
        manual: !!r.predates,
        stage: 'refused',
        message: restartRefusalText(r),
      };
    }
    say(
      r.restart_by === 'caller'
        ? 'Restarting the service — starting it again…'
        : 'Restarting the service (' + r.supervisor + ')…',
    );
    try {
      await waitForDaemon(r);
    } catch (e) {
      void refreshStatus();
      return {
        ok: false,
        stage: 'wait',
        message: 'The service has not come back: ' + e + ' — check Background service.',
      };
    }
    window.Roomler.settingsPendingRestart.clear();
    void refreshStatus();
    return { ok: true };
  }
  window.Roomler.restartDaemon = restartDaemon;

  async function applyNow(btn) {
    if (applying) return;
    applying = true;
    const keys = window.Roomler.settingsPendingRestart.keys();
    btn.disabled = true;
    try {
      const res = await restartDaemon(
        keys.length ? 'settings: ' + keys.join(', ') : 'settings',
        (text) => setText('cfg-restart-text', text),
      );
      if (!res.ok) {
        setText('cfg-restart-text', res.message);
        return;
      }
      await loadCfg(true);
      showResult('Service restarted — your changes are in effect.', false);
    } finally {
      applying = false;
      btn.disabled = false;
    }
  }

  function mountApplyNow() {
    const slot = window.Roomler.settingsPendingRestart.actionsSlot();
    if (!slot || $('btn-apply-now')) return;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.id = 'btn-apply-now';
    btn.textContent = 'Apply now';
    btn.title = 'Restart the device service so the saved changes take effect';
    btn.addEventListener('click', () => void applyNow(btn));
    slot.appendChild(btn);
  }

  function cfgRowStatus(row) {
    return row.querySelector('.cfg-row-status');
  }

  /* "Modified" = the value differs from the built-in default the daemon
   * reports. `default` is absent both for a key that is unset by default
   * (the tribools) and from a daemon older than D2 — so the claim is only
   * made once `group` says the metadata is there at all. */
  function isModified(entry) {
    if (!entry.group) return false;
    const v = entry.value == null ? null : String(entry.value);
    const d = entry.default == null ? null : String(entry.default);
    return v !== d;
  }

  function paintModified(row, entry) {
    const chip = row.querySelector('.cfg-row-mod');
    if (!chip) return;
    chip.hidden = !isModified(entry);
    const group = row.closest('details.cfg-group');
    if (group) refreshGroupBadge(group);
  }

  function refreshGroupBadge(group) {
    const changed = group.querySelectorAll('.cfg-row-mod:not([hidden])').length;
    const badge = group.querySelector('.cfg-group-changed');
    if (!badge) return;
    badge.hidden = changed === 0;
    badge.textContent = changed + ' changed';
  }

  async function applyCfg(key, raw, row) {
    // Empty text/selection = clear the key back to its default. The
    // bool/enum selects never produce '' — only tribool/text kinds do.
    const value = raw === '' ? null : raw;
    const status = cfgRowStatus(row);
    try {
      const entry = await invoke('cmd_config_set', { key, value });
      // The daemon says per key whether the change is in force already
      // (the gate-4 flags it re-seeds from the file it just wrote,
      // docs/remote-config.md §7b) or waits for a restart. Saying "restart"
      // for a live key would be wrong in the direction that matters: the
      // person switching one OFF would believe their refusal is not in
      // force yet, and either restart a healthy daemon for nothing or
      // assume they are still exposed.
      if (entry.restart_required) {
        status.textContent = 'Saved — takes effect after the service restarts.';
        window.Roomler.settingsPendingRestart.add(key);
      } else {
        status.textContent = 'Saved — in effect now, no restart needed.';
      }
      status.classList.remove('error');
      paintModified(row, entry);
      return entry;
    } catch (e) {
      status.textContent = String(e);
      status.classList.add('error');
      return null;
    }
  }

  function makeSelect(options, current) {
    const sel = document.createElement('select');
    for (const opt of options) {
      const o = document.createElement('option');
      o.value = opt.value;
      o.textContent = opt.label;
      sel.appendChild(o);
    }
    sel.value = current;
    return sel;
  }

  function cfgRow(entry) {
    const row = document.createElement('div');
    row.className = 'cfg-row';
    row.style.margin = '10px 0 0';
    row.dataset.key = entry.key;
    // What the search box matches against: the key and the description.
    row.dataset.search = (entry.key + ' ' + (entry.description || '')).toLowerCase();

    const head = document.createElement('div');
    const key = document.createElement('span');
    key.className = 'mono small';
    key.textContent = entry.key;
    head.appendChild(key);
    const mod = document.createElement('span');
    mod.className = 'chip cfg-chip-mod cfg-row-mod';
    mod.textContent = 'modified';
    mod.hidden = !isModified(entry);
    head.appendChild(mod);
    row.appendChild(head);

    const desc = document.createElement('p');
    desc.className = 'muted small';
    desc.style.margin = '2px 0 4px';
    desc.textContent = entry.description;
    row.appendChild(desc);

    const controls = document.createElement('div');
    controls.className = 'actions';
    const val = entry.value == null ? '' : entry.value;

    if (entry.kind === 'bool') {
      const sel = makeSelect(
        [
          { value: 'true', label: 'on' },
          { value: 'false', label: 'off' },
        ],
        val || 'false',
      );
      sel.addEventListener('change', () => void applyCfg(entry.key, sel.value, row));
      controls.appendChild(sel);
    } else if (entry.kind === 'tribool') {
      const sel = makeSelect(
        [
          { value: '', label: 'default' },
          { value: 'true', label: 'on' },
          { value: 'false', label: 'off' },
        ],
        val,
      );
      sel.addEventListener('change', () => void applyCfg(entry.key, sel.value, row));
      controls.appendChild(sel);
    } else if (entry.kind.startsWith('enum:')) {
      const opts = entry.kind
        .slice('enum:'.length)
        .split('|')
        .map((v) => ({ value: v, label: v }));
      const sel = makeSelect(opts, val || opts[0].value);
      sel.addEventListener('change', () => void applyCfg(entry.key, sel.value, row));
      controls.appendChild(sel);
    } else if (entry.kind === 'json') {
      const ta = document.createElement('textarea');
      ta.rows = 4;
      ta.spellcheck = false;
      ta.className = 'mono small';
      ta.style.width = '100%';
      try {
        ta.value = val ? JSON.stringify(JSON.parse(val), null, 2) : '';
      } catch {
        ta.value = val;
      }
      const save = document.createElement('button');
      save.type = 'button';
      save.textContent = 'Save';
      save.addEventListener('click', async () => {
        save.disabled = true;
        const entryBack = await applyCfg(entry.key, ta.value.trim(), row);
        if (entryBack && entryBack.value) {
          try { ta.value = JSON.stringify(JSON.parse(entryBack.value), null, 2); } catch {}
        }
        save.disabled = false;
      });
      const wrap = document.createElement('div');
      wrap.style.width = '100%';
      wrap.appendChild(ta);
      controls.appendChild(wrap);
      controls.appendChild(save);
    } else {
      // string / list — one-line text input + Save.
      const input = document.createElement('input');
      input.type = 'text';
      input.spellcheck = false;
      input.className = 'mono small';
      input.value = val;
      input.style.flex = '1';
      if (entry.kind === 'list') input.placeholder = 'e.g. 192.168.1.0/24, 10.0.0.0/8';
      const save = document.createElement('button');
      save.type = 'button';
      save.textContent = 'Save';
      const submit = async () => {
        save.disabled = true;
        const entryBack = await applyCfg(entry.key, input.value.trim(), row);
        if (entryBack) input.value = entryBack.value == null ? '' : entryBack.value;
        save.disabled = false;
      };
      save.addEventListener('click', submit);
      input.addEventListener('keydown', (ev) => {
        if (ev.key === 'Enter') { ev.preventDefault(); void submit(); }
      });
      controls.appendChild(input);
      controls.appendChild(save);
    }
    row.appendChild(controls);

    const status = document.createElement('p');
    status.className = 'muted small cfg-row-status';
    status.style.margin = '2px 0 0';
    row.appendChild(status);
    return row;
  }

  /* One collapsible section. `entries` are rendered in the order given —
   * the daemon's display order — and the summary carries the key count and
   * a "N changed" badge. */
  function cfgGroup(id, label, entries, open, hint) {
    const det = document.createElement('details');
    det.className = 'cfg-group';
    det.dataset.group = id;

    const sum = document.createElement('summary');
    const name = document.createElement('span');
    name.className = 'cfg-group-name';
    name.textContent = label;
    const count = document.createElement('span');
    count.className = 'muted small cfg-group-count';
    count.textContent = entries.length + (entries.length === 1 ? ' key' : ' keys');
    const changed = document.createElement('span');
    changed.className = 'chip cfg-chip-mod cfg-group-changed';
    changed.hidden = true;
    sum.append(name, count, changed);
    det.appendChild(sum);

    if (hint) {
      const p = document.createElement('p');
      p.className = 'muted small';
      p.style.margin = '0';
      p.textContent = hint;
      det.appendChild(p);
    }
    const body = document.createElement('div');
    body.className = 'cfg-group-body';
    for (const entry of entries) body.appendChild(cfgRow(entry));
    det.appendChild(body);
    refreshGroupBadge(det);

    det.addEventListener('toggle', () => {
      if (programmaticToggles > 0) return;
      const set = readOpenGroups() || new Set([ESSENTIALS_ID]);
      if (det.open) set.add(id);
      else set.delete(id);
      writeOpenGroups(set);
    });
    withProgrammaticToggles(() => { det.open = open; });
    return det;
  }

  function renderCfg(entries) {
    const container = $('cfg-rows');
    const searchWrap = $('cfg-search-wrap');
    container.replaceChildren();
    const grouped = entries.some((e) => e.group);
    if (!grouped) {
      // A daemon older than FR-84 D2 names no groups: the flat list, as before.
      hide(searchWrap);
      for (const entry of entries) container.appendChild(cfgRow(entry));
      return;
    }
    show(searchWrap);

    // Essentials first and open: the handful of keys a person decides on.
    const essentials = entries.filter((e) => e.tier === 'essential');
    container.appendChild(
      cfgGroup(
        ESSENTIALS_ID,
        'Essentials',
        essentials,
        defaultOpen(ESSENTIALS_ID),
        'The switches most people decide on. Everything else is below, grouped.',
      ),
    );

    // Then one section per group, collapsed, in the order the daemon lists
    // them (it emits the surface in its display order, so no order table
    // lives here). Essentials are not repeated inside their group.
    const groups = new Map();
    for (const e of entries) {
      if (e.tier === 'essential') continue;
      if (!groups.has(e.group)) groups.set(e.group, { label: e.group_label || e.group, entries: [] });
      groups.get(e.group).entries.push(e);
    }
    for (const [id, g] of groups) {
      container.appendChild(cfgGroup(id, g.label, g.entries, defaultOpen(id)));
    }
    applySearch();
  }

  /* Filters rows by key + description across every section, opens the
   * sections that hold a match and hides the ones that don't; clearing the
   * box brings every row back and restores the remembered open state. */
  let searching = false;

  function applySearch() {
    const input = $('cfg-search');
    const container = $('cfg-rows');
    if (!input || !container) return;
    const q = input.value.trim().toLowerCase();
    const wasSearching = searching;
    searching = q !== '';
    const groups = container.querySelectorAll('details.cfg-group');
    if (!searching) {
      withProgrammaticToggles(() => {
        for (const det of groups) {
          det.hidden = false;
          for (const row of det.querySelectorAll('.cfg-row')) row.hidden = false;
          if (wasSearching) det.open = defaultOpen(det.dataset.group);
        }
      });
      setText('cfg-search-count', '');
      return;
    }
    let total = 0;
    withProgrammaticToggles(() => {
      for (const det of groups) {
        let hits = 0;
        for (const row of det.querySelectorAll('.cfg-row')) {
          const hit = (row.dataset.search || '').includes(q);
          row.hidden = !hit;
          if (hit) hits += 1;
        }
        det.hidden = hits === 0;
        if (hits > 0) det.open = true;
        total += hits;
      }
    });
    setText(
      'cfg-search-count',
      total === 0 ? 'No keys match.' : total + (total === 1 ? ' key matches' : ' keys match'),
    );
  }

  async function loadCfg(force) {
    if (cfgLoaded && !force) return;
    const container = $('cfg-rows');
    if (!container) return;
    try {
      const entries = await invoke('cmd_config_entries');
      renderCfg(entries);
      cfgLoaded = true;
    } catch (e) {
      container.replaceChildren();
      const p = document.createElement('p');
      p.className = 'muted small';
      p.textContent = 'Could not load the configuration: ' + e;
      const retry = document.createElement('button');
      retry.type = 'button';
      retry.textContent = 'Retry';
      retry.addEventListener('click', () => void loadCfg(true));
      container.appendChild(p);
      container.appendChild(retry);
    }
  }

  /* ── S2: log viewer — bounded TailLog polls, client-side filter ──── */
  let logTimer = null;

  async function refreshLog() {
    const sourceEl = $('log-source');
    const view = $('log-view');
    if (!sourceEl || !view) return;
    try {
      const r = await invoke('cmd_tail_log', { source: sourceEl.value, maxBytes: 32768 });
      setText('log-path', r.path + ' · ' + r.size + ' bytes');
      const filter = ($('log-filter').value || '').trim().toLowerCase();
      const lines = r.content.split('\n');
      const shown = filter
        ? lines.filter((l) => l.toLowerCase().includes(filter))
        : lines;
      // Keep the view pinned to the tail unless the operator scrolled up.
      const atBottom = view.scrollHeight - view.scrollTop - view.clientHeight < 32;
      view.textContent = shown.join('\n').trim() || '(no matching lines)';
      if (atBottom) view.scrollTop = view.scrollHeight;
    } catch (e) {
      setText('log-path', '—');
      view.textContent = 'Could not read the log: ' + e;
    }
  }

  function setLogFollow(onOff) {
    if (logTimer) { clearInterval(logTimer); logTimer = null; }
    if (onOff) logTimer = setInterval(() => void refreshLog(), 3000);
  }

  document.addEventListener('roomler:view', (ev) => {
    if (ev.detail === 'settings') {
      void loadCfg(false);
    } else {
      // Leaving Settings pauses a running follow (checkbox state stays).
      setLogFollow(false);
      const follow = $('log-follow');
      if (follow) follow.checked = false;
    }
  });

  document.addEventListener('DOMContentLoaded', () => {
    on('status', paintStatus);

    $('rename-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const name = $('rename-input').value.trim();
      if (!name) return;
      try {
        await invoke('cmd_set_device_name', { name });
        showResult('Device name updated to “' + name + '”.', false);
        void refreshStatus();
      } catch (e) {
        showResult('Rename failed: ' + e, true);
      }
    });

    // S1b: enrollment consolidated into Onboarding — this card just links.
    $('btn-goto-onboarding').addEventListener('click', () => navigate('onboarding'));

    // S1b: the split-config banner's cleanup action — the DAEMON archives
    // the stale copy (identity-guarded, never deletes).
    $('btn-config-cleanup').addEventListener('click', async () => {
      const btn = $('btn-config-cleanup');
      btn.disabled = true;
      try {
        const detail = await invoke('cmd_config_cleanup');
        showResult('Cleaned up: ' + detail, false);
        void refreshStatus();
      } catch (e) {
        showResult('Cleanup not performed: ' + e, true);
      } finally {
        btn.disabled = false;
      }
    });

    $('btn-service-install').addEventListener('click', async () => {
      // false = per-user auto-start (Scheduled Task on Windows). Machine-wide
      // SCM installs are the Roomler Setup installer's job, not the desktop's.
      try {
        await invoke('cmd_service_install', { asService: false });
        showResult('Auto-start installed.', false);
        void refreshStatus();
      } catch (e) {
        showResult('Install failed: ' + e, true);
      }
    });

    $('btn-service-uninstall').addEventListener('click', async () => {
      try {
        await invoke('cmd_service_uninstall', { asService: false });
        showResult('Auto-start removed.', false);
        void refreshStatus();
      } catch (e) {
        showResult('Removal failed: ' + e, true);
      }
    });

    $('btn-open-logs').addEventListener('click', async () => {
      try {
        await invoke('cmd_open_log_dir');
      } catch (e) {
        showResult('Could not open the logs folder: ' + e, true);
      }
    });

    $('btn-open-config').addEventListener('click', async () => {
      try {
        await invoke('cmd_open_config_dir');
      } catch (e) {
        showResult('Could not open the config folder: ' + e, true);
      }
    });

    // FR-84 D3 — "Apply now" lives in the restart bar, which shows itself
    // only while a saved change waits for a restart.
    mountApplyNow();

    // FR-84 D2 — the configuration search box (shown once a daemon with
    // grouped entries has answered).
    const search = $('cfg-search');
    if (search) {
      search.addEventListener('input', applySearch);
      search.addEventListener('keydown', (ev) => {
        if (ev.key === 'Escape') { search.value = ''; applySearch(); }
      });
    }

    // S2 — log viewer wiring.
    $('btn-log-refresh').addEventListener('click', () => void refreshLog());
    $('log-source').addEventListener('change', () => void refreshLog());
    $('log-filter').addEventListener('change', () => void refreshLog());
    $('log-follow').addEventListener('change', (ev) => {
      setLogFollow(ev.target.checked);
      if (ev.target.checked) void refreshLog();
    });
  });
})();
