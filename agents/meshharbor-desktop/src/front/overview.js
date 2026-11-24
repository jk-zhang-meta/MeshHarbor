// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
/*
 * Overview view: this device's identity + health at a glance, the exit-node
 * card (P5), what this device can encode and where dropped files land
 * (FR-84 D4), and the update check/apply flow.
 *
 * Renders from the central store (app.js polls `cmd_status` + `cmd_device_view`).
 * The one poll of its own is the encoder card's, and only while the service
 * has not probed yet. All dynamic strings land via textContent.
 */
(function () {
  'use strict';
  const { $, invoke, show, hide, setText, on, get, navigate, currentView } = window.MeshHarbor;
  const t = (key, params, fallback) =>
    window.MeshHarborI18n ? window.MeshHarborI18n.t(key, params) : fallback;

  let routesActive = null; // painted by tunnels.js via the shared event below
  let grantHintActive = false;

  function serviceKindLabel(s) {
    if (s.service_kind === 'scmService') {
      return s.service_running
        ? t('ov.device.serviceSystemRunning', null, 'System service · running')
        : t('ov.device.serviceSystemStopped', null, 'System service · stopped');
    }
    if (s.service_kind === 'scheduledTask') {
      return s.service_running
        ? t('ov.device.serviceUserRunning', null, 'Per-user auto-start · running')
        : t('ov.device.serviceUser', null, 'Per-user auto-start');
    }
    return t('ov.device.serviceNotInstalled', null, 'not installed');
  }

  function paintStatus(s) {
    if (!s) return;
    // Banners.
    if (s.enrolled) hide($('ov-not-enrolled'));
    else show($('ov-not-enrolled'));
    if (s.attention) {
      show($('ov-attention'));
      // S1b: show WHAT needs attention, not just where the sentinel sits.
      setText(
        'ov-attention-msg',
        s.attention_message || t('ov.attention.noDetails', null, '(no details recorded)'),
      );
      setText('ov-attention-path', s.attention);
      // Re-enrolling fixes every reason except a failed rollback (that one
      // needs an operator to sort the broken-binary state out first).
      const reenroll = $('ov-attention-reenroll');
      if (reenroll) reenroll.hidden = s.attention_reason === 'rollback_failed';
    } else {
      hide($('ov-attention'));
    }

    const chip = $('ov-enrolled-chip');
    if (chip) {
      chip.textContent = s.enrolled
        ? t('ov.device.enrolled', null, 'Enrolled')
        : t('ov.device.notEnrolled', null, 'Not enrolled');
      chip.className = 'chip ' + (s.enrolled ? 'chip-ok' : 'chip-warn');
    }

    setText('ov-server', s.server_url || '—');
    setText('ov-app-version', s.agent_version);
    setText('ov-service', serviceKindLabel(s));
    // Config-file identity is a fallback for the fields the live daemon
    // fills in below when it's reachable.
    if (!get('deviceView') || !get('deviceView').available) {
      setText('ov-name', s.device_name || '—');
    }
  }

  function paintDeviceView(dv) {
    if (!dv) return;
    if (!dv.available) {
      setText('ov-link', t('ov.device.linkOffline', null, 'service offline'));
      setText('ov-daemon-version', '—');
      setText('ov-ip', '—');
      paintDns(null);
      paintCounts(dv);
      return;
    }
    const st = dv.status || {};
    setText('ov-name', st.name || '—');
    setText('ov-daemon-version', st.version || '—');
    setText(
      'ov-link',
      st.connected
        ? t('ov.device.linkConnected', null, 'connected')
        : t('ov.device.linkDisconnected', null, 'disconnected'),
    );
    setText(
      'ov-ip',
      st.overlay_ip
        ? st.overlay_ip6
          ? st.overlay_ip + ' · ' + st.overlay_ip6
          : st.overlay_ip
        : t('ov.device.noOverlayIp', null, '(no overlay IP)'),
    );
    paintExit(st.exit_node);
    paintDns(st.dns);
    paintCounts(dv);
  }

  // S2 — MagicDNS status: hidden unless the overlay publishes a magic
  // domain; the two failure states (resolver down / OS steer failed) are
  // spelled out so name-resolution complaints never need log spelunking.
  function paintDns(dns) {
    const label = $('ov-dns-label');
    const dd = $('ov-dns');
    if (!label || !dd) return;
    if (!dns) {
      label.hidden = true;
      dd.hidden = true;
      return;
    }
    label.hidden = false;
    dd.hidden = false;
    // FR-97 P3h — a steer the host's own resolver never asks is not active.
    const health = !dns.resolver_bound
      ? t('ov.device.dnsResolverDown', null, 'resolver DOWN')
      : !dns.os_steer_active
        ? t('ov.device.dnsSteerFailed', null, 'OS steer failed')
        : dns.os_steer_bypassed
          ? t('ov.device.dnsBypassed', { why: dns.os_steer_bypassed }, 'steered but bypassed: ' + dns.os_steer_bypassed)
          : t('ov.device.dnsActive', null, 'active');
    dd.textContent =
      dns.magic_domain +
      ' · ' +
      health +
      (dns.answer_aaaa ? '' : t('ov.device.dnsAaaaOff', null, ' · AAAA off'));
  }

  function paintCounts(dv) {
    const peers = (dv && dv.peers) || [];
    const online = peers.filter((p) => p.online).length;
    let text = t(
      'ov.device.counts',
      { online, total: peers.length },
      online + ' of ' + peers.length + ' devices online',
    );
    if (routesActive !== null) {
      text += t(
        'ov.device.countsRoutes',
        { routes: routesActive },
        ' · ' + routesActive + ' routes active',
      );
    }
    setText('ov-counts', peers.length ? text : '—');
  }

  // P5 exit-node status: only rendered when this node is configured as an
  // exit-node client; the withheld_reason / v6 / DNS caveats surface the
  // fail-closed states so a "why is my traffic not moving" never needs logs.
  function paintExit(exit) {
    const card = $('ov-exit-card');
    if (!exit) { hide(card); return; }
    show(card);
    setText('ov-exit-selector', exit.selector || '—');
    const chip = $('ov-exit-chip');
    if (chip) {
      chip.textContent = exit.active
        ? t('ov.exit.active', null, 'Active')
        : t('ov.exit.withheld', null, 'Withheld');
      chip.className = 'chip ' + (exit.active ? 'chip-ok' : 'chip-warn');
    }
    let detail;
    if (exit.active && exit.socks5_port) {
      // FR-97 P0c-3 — a netstack node installs no OS routes: only what its
      // SOCKS5 front dials rides the exit, so the v6/DNS caveats below (which
      // describe a host whose traffic all goes through it) would mislead.
      detail = t(
        'ov.exit.socksOnly',
        { port: exit.socks5_port },
        'only SOCKS5 clients of 127.0.0.1:' +
          exit.socks5_port +
          ' use the exit (IPv4 destinations) · nothing else on this device does',
      );
    } else if (exit.active) {
      const caveats = [];
      if (!exit.v6_active) caveats.push(t('ov.exit.v6Blackholed', null, 'IPv6 blackholed (exit is v4-only)'));
      if (!exit.dns_steered) caveats.push(t('ov.exit.dnsNotSteered', null, 'DNS not steered — queries may leak locally'));
      detail = caveats.length
        ? t('ov.exit.routingCaveats', { caveats: caveats.join(' · ') }, 'routing active · ' + caveats.join(' · '))
        : t('ov.exit.routingAll', null, 'all traffic routes via the exit node');
    } else {
      detail = exit.withheld_reason || t('ov.exit.notActive', null, 'not active');
    }
    setText('ov-exit-status', detail);
  }

  function pushOutput(text) {
    const el = $('action-output');
    if (!el) return;
    el.textContent = text;
    show(el);
  }

  /* ── FR-84 D4: what this device can encode ─────────────────────────
   *
   * `cmd_encoder_caps` reads the service's CACHED probe; the service probes
   * at its first server connection, never because this card asked. Before
   * that the answer is `not_probed`, and only then does the card poll (5 s),
   * stopping as soon as the answer can no longer change by itself. It is
   * re-read when the service comes back or changes (version / node).
   */

  const CODEC_ROWS = [
    ['h264', 'H.264'],
    ['hevc', 'HEVC'],
    ['vp9', 'VP9'],
    ['av1', 'AV1'],
  ];
  const BACKEND_ORDER = [
    'nvenc', 'qsv', 'amf', 'vaapi', 'd3d12', 'vulkan', 'videotoolbox', 'mf', 'openh264', 'libvpx',
  ];
  const BACKEND_LABEL = {
    nvenc: 'NVENC',
    qsv: 'Quick Sync',
    amf: 'AMF',
    vaapi: 'VA-API',
    d3d12: 'D3D12',
    vulkan: 'Vulkan',
    videotoolbox: 'VideoToolbox',
    mf: 'Media Foundation',
    openh264: 'OpenH264',
    libvpx: 'libvpx',
  };
  const CHROMA_LABEL = { yuv420: '4:2:0', yuv444: '4:4:4' };
  const ENC_POLL_MS = 5000;

  let encTimer = null;
  let encInflight = false;
  let encLast = null;
  let lastDaemonKey = null;

  // The answer can still change by itself only before the first probe.
  function encPending(view) {
    return !!(view && view.available && view.caps && view.caps.state === 'not_probed');
  }

  function stopEncPoll() {
    if (encTimer !== null) {
      clearTimeout(encTimer);
      encTimer = null;
    }
  }

  async function refreshEncoderCaps() {
    if (encInflight) return;
    encInflight = true;
    stopEncPoll();
    let view;
    try {
      view = await invoke('cmd_encoder_caps');
    } catch (e) {
      view = { available: false, reason: String(e) };
    } finally {
      encInflight = false;
    }
    encLast = view;
    paintEncoderCaps(view);
    // Poll only while nothing has been probed AND someone is looking; the
    // tray-resident window keeps its timers running when hidden, and a
    // service that cannot reach its server can stay unprobed for days.
    if (encPending(view)) {
      encTimer = setTimeout(() => {
        encTimer = null;
        if (currentView() === 'overview' && !document.hidden) void refreshEncoderCaps();
      }, ENC_POLL_MS);
    }
  }

  function encChip(text, cls) {
    const chip = $('ov-enc-chip');
    if (!chip) return;
    chip.textContent = text;
    chip.className = 'chip ' + cls;
  }

  function encNote(text) {
    const note = $('ov-enc-note');
    if (!note) return;
    note.textContent = text || '';
    note.hidden = !text;
  }

  function paintEncoderCaps(view) {
    if (!view) return;
    const matrix = $('ov-enc-matrix');
    const foot = $('ov-enc-foot');
    const deniedLine = $('ov-enc-denied');
    const raw = $('ov-enc-raw');
    hide(matrix);
    hide(foot);
    hide(deniedLine);
    hide(raw);

    if (!view.available) {
      if (view.reason === 'old_daemon') {
        encChip(t('ov.enc.chipUnavailable', null, 'Unavailable'), 'chip-muted');
        encNote(t('ov.enc.noteOldDaemon', null, 'The device service predates this view — update the service to see this.'));
      } else if (view.reason === 'daemon_unreachable') {
        encChip(t('ov.enc.chipOffline', null, 'Offline'), 'chip-muted');
        encNote(t('ov.enc.noteOffline', null, 'The device service is not running.'));
      } else {
        encChip(t('ov.enc.chipError', null, 'Error'), 'chip-warn');
        const reason = view.reason || t('common.unknownError', null, 'unknown error');
        encNote(t('ov.enc.noteError', { reason }, 'Could not read the encoders: ' + reason));
      }
      return;
    }
    const caps = view.caps || {};
    if (caps.state === 'unsupported') {
      encChip(t('ov.enc.chipNone', null, 'None'), 'chip-muted');
      encNote(t('ov.enc.noteUnsupported', null, 'This build of the device service has no video encoders (signalling only).'));
      return;
    }
    if (caps.state === 'not_probed') {
      encChip(t('ov.enc.chipNotProbed', null, 'Not probed yet'), 'chip-muted');
      encNote(
        t(
          'ov.enc.noteNotProbed',
          { secs: ENC_POLL_MS / 1000 },
          'The service tests its encoders when it first connects to the server. Checking again every ' +
            ENC_POLL_MS / 1000 +
            ' s.',
        ),
      );
      return;
    }
    if (caps.state !== 'ready') {
      encChip(t('ov.enc.chipUnknown', null, 'Unknown'), 'chip-muted');
      encNote(
        t(
          'ov.enc.noteUnknown',
          { state: caps.state },
          'The service answered with a state this app does not know (' + caps.state + ').',
        ),
      );
      return;
    }

    const cells = caps.cells || [];
    const hwCount = cells.filter((c) => c.hardware).length;
    encChip(
      hwCount
        ? t('ov.enc.chipHardware', null, 'Hardware')
        : cells.length
          ? t('ov.enc.chipSoftwareOnly', null, 'Software only')
          : t('ov.enc.chipNoEncoder', null, 'No encoder'),
      hwCount ? 'chip-ok' : 'chip-warn',
    );
    encNote(
      cells.length
        ? ''
        : t('ov.enc.noteNoEncoder', null, 'No encoder opened on this device — remote sessions cannot stream video.'),
    );
    if (cells.length) paintMatrix(cells, view.denied_cells || []);
    paintEncFooter(caps);
  }

  function paintMatrix(cells, deniedCells) {
    // Columns: the backends the probe opened something on, in a fixed order
    // (unknown future backends last, alphabetically).
    const present = new Set(cells.map((c) => c.backend));
    const backends = BACKEND_ORDER.filter((b) => present.has(b)).concat(
      [...present].filter((b) => !BACKEND_ORDER.includes(b)).sort(),
    );
    const head = $('ov-enc-head');
    head.textContent = '';
    const corner = document.createElement('th');
    corner.textContent = t('ov.enc.codecCol', null, 'Codec');
    head.appendChild(corner);
    for (const b of backends) {
      const th = document.createElement('th');
      th.textContent = BACKEND_LABEL[b] || b;
      head.appendChild(th);
    }

    const rows = $('ov-enc-rows');
    rows.textContent = '';
    for (const [codec, label] of CODEC_ROWS) {
      const tr = document.createElement('tr');
      const name = document.createElement('td');
      name.textContent = label;
      tr.appendChild(name);
      for (const b of backends) {
        const td = document.createElement('td');
        const cell = cells.find((c) => c.codec === codec && c.backend === b);
        const opened = new Set((cell && cell.chroma) || []);
        for (const chroma of (cell && cell.chroma) || []) {
          const span = document.createElement('span');
          span.className = 'enc-cell ' + (cell.hardware ? 'enc-hw' : 'enc-sw');
          span.textContent = CHROMA_LABEL[chroma] || chroma;
          const backend = BACKEND_LABEL[b] || b;
          span.title = cell.hardware
            ? t('ov.enc.cellTipHw', { codec, backend }, 'Hardware ' + codec + ' on ' + backend)
            : t('ov.enc.cellTipSw', { codec, backend }, 'Software ' + codec + ' on ' + backend);
          td.appendChild(span);
        }
        // A denied cell is never opened, so it is not in `cells`: struck
        // through where the probe would otherwise have tried it.
        for (const d of deniedCells) {
          if (d.codec !== codec || d.backend !== b || opened.has(d.chroma)) continue;
          const span = document.createElement('span');
          span.className = 'enc-cell enc-denied';
          span.textContent = CHROMA_LABEL[d.chroma] || d.chroma;
          span.title = t(
            'ov.enc.cellTipDenied',
            { entry: d.entry },
            'Denied by encoder_cells_deny (' + d.entry + ') — never opened',
          );
          td.appendChild(span);
        }
        if (!td.childNodes.length) {
          td.textContent = '—';
          td.className = 'muted';
        }
        tr.appendChild(td);
      }
      rows.appendChild(tr);
    }
    show($('ov-enc-matrix'));
  }

  function paintEncFooter(caps) {
    const parts = [];
    if (caps.probe_ms != null) {
      parts.push(t('ov.enc.probedIn', { ms: caps.probe_ms }, 'probed in ' + caps.probe_ms + ' ms'));
    }
    parts.push(
      caps.probe_cached
        ? t('ov.enc.probeCached', null, 'from the probe cache')
        : t('ov.enc.probeFresh', null, 'fresh probe'),
    );
    if (caps.encoder_preference) {
      parts.push(
        t('ov.enc.preference', { pref: caps.encoder_preference }, 'preference: ' + caps.encoder_preference),
      );
    }
    const foot = $('ov-enc-foot');
    foot.textContent = parts.join(' · ');
    show(foot);

    const denied = caps.denied || [];
    const deniedLine = $('ov-enc-denied');
    deniedLine.textContent = denied.length
      ? t('ov.enc.deniedList', { list: denied.join(', ') }, 'Denied by encoder_cells_deny: ' + denied.join(', '))
      : t('ov.enc.deniedNone', null, 'encoder_cells_deny: nothing denied');
    show(deniedLine);

    setText('ov-enc-hw', (caps.hw_encoders || []).join(', ') || '—');
    setText('ov-enc-codecs', (caps.codecs || []).join(', ') || '—');
    show($('ov-enc-raw'));
  }

  // Re-read both D4 cards when the service appears, disappears, or is a
  // different process (an update changes the version, a re-enroll the node);
  // between those, keep the drop folder current from the 2 s poll.
  function watchDaemon(dv) {
    const st = (dv && dv.available && dv.status) || null;
    const key = st ? (st.version || '') + '|' + (st.node_id || '') : 'offline';
    if (key !== lastDaemonKey) {
      lastDaemonKey = key;
      void refreshEncoderCaps();
      void refreshFilesDir();
      return;
    }
    if (st && filesView && filesView.available && st.files_dir && st.files_dir !== filesView.effective) {
      filesView.effective = st.files_dir;
      paintFilesDir();
    }
  }

  /* ── FR-84 D4: where dropped files land ─────────────────────────────
   *
   * `cmd_files_dir_view` = the service's effective folder + the configured
   * value, read on entry and after a change; the 2 s device-view poll keeps
   * the effective folder current in between. Every change goes through the
   * service (it knows whom it writes as); its refusals show verbatim.
   */

  let filesView = null;
  let filesBusy = false;

  // Windows paths compare case- and separator-insensitively; POSIX ones
  // exactly (a trailing separator aside).
  function samePath(a, b) {
    if (!a || !b) return false;
    const windows = /^[A-Za-z]:|^\\\\/.test(a);
    const norm = (s) => {
      const tStr = s.replace(/[\\/]+$/, '');
      return windows ? tStr.replace(/\//g, '\\').toLowerCase() : tStr;
    };
    return norm(a) === norm(b);
  }

  function filesMsg(text, isError) {
    const el = $('ov-files-msg');
    if (!el) return;
    el.textContent = text || '';
    el.hidden = !text;
    el.classList.toggle('error', !!isError);
  }

  function setFilesButtons(enabled) {
    for (const id of ['ov-files-open', 'ov-files-change', 'ov-files-default']) {
      const b = $(id);
      if (b) b.disabled = !enabled || filesBusy;
    }
  }

  async function refreshFilesDir() {
    try {
      filesView = await invoke('cmd_files_dir_view');
    } catch (e) {
      filesView = { available: false, reason: String(e) };
    }
    paintFilesDir();
  }

  function paintFilesDir() {
    const v = filesView;
    const chip = $('ov-files-chip');
    const note = $('ov-files-note');
    const actions = $('ov-files-actions');
    const setChip = (text, cls) => {
      if (!chip) return;
      chip.textContent = text;
      chip.className = 'chip ' + cls;
    };
    const setNote = (text) => {
      if (!note) return;
      note.textContent = text || '';
      note.hidden = !text;
    };
    if (!v) return;
    if (!v.available) {
      setChip(
        v.reason === 'daemon_unreachable'
          ? t('ov.files.chipOffline', null, 'Offline')
          : t('ov.files.chipError', null, 'Error'),
        'chip-muted',
      );
      setText('ov-files-path', '—');
      setText('ov-files-setting', '—');
      const reason = v.reason || t('common.unknownError', null, 'unknown error');
      setNote(
        v.reason === 'daemon_unreachable'
          ? t('ov.files.noteOffline', null, 'The device service is not running.')
          : t('ov.files.noteError', { reason }, 'Could not read the setting: ' + reason),
      );
      setFilesButtons(false);
      return;
    }
    if (!v.supported) {
      setChip(t('ov.files.chipUnavailable', null, 'Unavailable'), 'chip-muted');
      setText('ov-files-path', v.effective || '—');
      setText('ov-files-setting', '—');
      setNote(
        t(
          'ov.files.noteUnsupported',
          null,
          'The device service predates this setting — update the service to choose where incoming files land.',
        ),
      );
      hide(actions);
      return;
    }
    show(actions);
    setText('ov-files-path', v.effective || '…');
    if (!v.configured) {
      setChip(t('ov.files.chipDefault', null, 'Default'), 'chip-muted');
      setText(
        'ov-files-setting',
        t('ov.files.settingDefault', null, "Default — the signed-in user's Downloads folder"),
      );
      setNote('');
    } else {
      const perUser = v.configured.startsWith('~');
      setText(
        'ov-files-setting',
        v.configured +
          (perUser ? t('ov.files.perUserSuffix', null, ' (inside the profile of whoever is signed in)') : ''),
      );
      if (v.effective && v.configured_resolved && !samePath(v.effective, v.configured_resolved)) {
        setChip(t('ov.files.chipNotInUse', null, 'Not in use'), 'chip-warn');
        setNote(
          t(
            'ov.files.noteNotInUse',
            null,
            'The chosen folder cannot be used right now, so files land in the default folder instead. The service log says why.',
          ),
        );
      } else {
        setChip(t('ov.files.chipCustom', null, 'Custom'), 'chip-ok');
        setNote('');
      }
    }
    setFilesButtons(true);
  }

  async function filesAction(run) {
    if (filesBusy) return;
    filesBusy = true;
    setFilesButtons(false);
    filesMsg('');
    try {
      const text = await run();
      if (text) filesMsg(text, false);
    } catch (e) {
      // The service's own words: a refusal names the rule it applied.
      filesMsg(String(e), true);
    } finally {
      filesBusy = false;
      await refreshFilesDir();
    }
  }

  function savedText(entry, value) {
    const where =
      value ||
      (entry && entry.value) ||
      t('ov.files.defaultFolderWord', null, 'the default folder');
    return entry && entry.restart_required
      ? t('ov.files.savedRestart', { where }, 'Saved: ' + where + ' — takes effect after the service restarts.')
      : t('ov.files.savedLive', { where }, 'Saved: ' + where + ' — in effect now, for the next file dropped.');
  }

  /*
   * macOS permission banner.
   *
   * Re-read on every window focus rather than polled: the grant is made in
   * System Settings, in another app, and the user comes straight back here to
   * see whether it took. Polling would either lag that or burn a timer on a
   * question whose answer only changes when the user leaves and returns.
   */
  async function refreshPermissions() {
    let p;
    try {
      p = await invoke('cmd_permissions');
    } catch {
      return; // never let a probe failure break the overview
    }
    const banner = $('ov-permissions');
    if (!banner) return;
    if (!p.applicable || (p.screen_recording && p.accessibility)) {
      hide(banner);
      return;
    }
    const screenRow = $('ov-perm-screen');
    const inputRow = $('ov-perm-input');
    if (screenRow) screenRow.hidden = p.screen_recording;
    if (inputRow) inputRow.hidden = p.accessibility;
    show(banner);
  }

  /*
   * "Grant administrator rights": a personal device that runs as the signed-in
   * user although that user is an OS administrator (signed in before sign-in
   * promoted, or the prompt was declined). Re-asked at most every 30 s off the
   * status poll, and on focus; never while a grant is running.
   */
  let grantBusy = false;
  let grantAskedAt = 0;
  function grantHintText() {
    return t(
      'ov.grantSystem.hint',
      null,
      'Sign in to your account from the tray menu ("Sign in…"): signing in grants these rights too.',
    );
  }

  async function refreshGrant(force) {
    if (grantBusy || (!force && Date.now() - grantAskedAt < 30000)) return;
    grantAskedAt = Date.now();
    let g;
    try {
      g = await invoke('cmd_system_grant_state');
    } catch {
      return;
    }
    const card = $('ov-grant-system');
    if (!card) return;
    card.hidden = !g.offered;
    const btn = $('ov-btn-grant-system');
    if (btn) btn.hidden = !g.signed_in;
    // The sign-in hint comes and goes with the session; an error from a failed
    // grant stays until the next attempt.
    if (g.offered && !g.signed_in) {
      grantHintActive = true;
      grantMsg(grantHintText(), false);
    } else if (grantHintActive) {
      grantHintActive = false;
      grantMsg('', false);
    }
  }

  function grantMsg(text, isError) {
    const el = $('ov-grant-system-msg');
    if (!el) return;
    el.textContent = text;
    el.className = 'small' + (isError ? ' error' : ' muted');
    el.hidden = !text;
  }

  async function grantSystem() {
    const btn = $('ov-btn-grant-system');
    grantBusy = true;
    grantHintActive = false;
    btn.disabled = true;
    grantMsg(t('ov.grantSystem.waiting', null, 'Waiting for your operating system to approve…'), false);
    try {
      await invoke('cmd_grant_system');
      grantMsg('', false);
      hide($('ov-grant-system'));
      window.MeshHarbor.refreshStatus();
    } catch (e) {
      const text = String(e);
      grantMsg(
        text.includes('no_account_session')
          ? t(
              'ov.grantSystem.needSignIn',
              null,
              'Sign in to your account first: tray menu → "Sign in…". Signing in grants these rights too.',
            )
          : t('ov.grantSystem.notGranted', { err: text }, 'Not granted: ' + text),
        true,
      );
    } finally {
      grantBusy = false;
      btn.disabled = false;
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    on('status', () => void refreshGrant(false));
    $('ov-btn-grant-system').addEventListener('click', () => void grantSystem());
    window.addEventListener('focus', () => void refreshGrant(true));
    on('status', paintStatus);
    on('deviceView', paintDeviceView);
    // FR-84 D4 — the encoder matrix and the drop folder.
    on('deviceView', watchDaemon);
    document.addEventListener('meshharbor:lang', () => {
      paintStatus(get('status'));
      paintDeviceView(get('deviceView'));
      paintEncoderCaps(encLast);
      paintFilesDir();
      if (grantHintActive) grantMsg(grantHintText(), false);
    });
    document.addEventListener('meshharbor:view', (ev) => {
      if (ev.detail !== 'overview' || lastDaemonKey === null) return;
      // A change made on the Settings page shows up on the way back, and a
      // matrix still waiting for the first probe resumes its poll.
      void refreshFilesDir();
      if (encPending(encLast) && encTimer === null) void refreshEncoderCaps();
    });
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden && currentView() === 'overview' && encPending(encLast) && encTimer === null) {
        void refreshEncoderCaps();
      }
    });
    $('ov-files-open').addEventListener('click', () =>
      filesAction(async () => {
        await invoke('cmd_open_files_dir');
        return '';
      }),
    );
    $('ov-files-change').addEventListener('click', () =>
      filesAction(async () => {
        const r = await invoke('cmd_pick_files_dir');
        return r.cancelled ? '' : savedText(r.entry, r.value);
      }),
    );
    $('ov-files-default').addEventListener('click', () =>
      filesAction(async () => {
        const entry = await invoke('cmd_files_dir_default');
        return entry.restart_required
          ? t('ov.files.backDefaultRestart', null, 'Back to the default folder after the service restarts.')
          : t('ov.files.backDefaultLive', null, 'Back to the default folder — in effect now.');
      }),
    );

    refreshPermissions();
    window.addEventListener('focus', refreshPermissions);
    for (const [id, which] of [
      ['ov-btn-perm-screen', 'screen'],
      ['ov-btn-perm-input', 'input'],
    ]) {
      const btn = $(id);
      if (!btn) continue;
      btn.addEventListener('click', async () => {
        try {
          await invoke('cmd_request_permission', { which });
        } catch (e) {
          pushOutput(t('ov.perms.openFailed', { err: e }, 'Could not open the permission pane: ' + e));
        }
      });
    }

    $('ov-btn-onboard').addEventListener('click', () => navigate('onboarding'));
    $('ov-attention-reenroll').addEventListener('click', () => navigate('onboarding'));

    // S7 — the embedded MeshHarbor web window (WebView2 on Windows).
    $('ov-btn-open-web').addEventListener('click', async () => {
      try {
        await invoke('cmd_open_meshharbor');
      } catch (e) {
        pushOutput(t('ov.device.openWebFailed', { err: e }, 'Could not open MeshHarbor: ' + e));
      }
    });

    $('btn-check-update').addEventListener('click', async () => {
      pushOutput(t('ov.updates.checking', null, 'Checking for updates…'));
      try {
        const out = await invoke('cmd_check_update');
        pushOutput(out);
        if (out.toLowerCase().includes('update available')) {
          show($('btn-apply-update'));
        }
      } catch (e) {
        pushOutput(t('common.errorPrefix', { err: e }, 'Error: ' + e));
      }
    });

    $('btn-apply-update').addEventListener('click', async () => {
      pushOutput(t('ov.updates.applying', null, 'Applying update…'));
      try {
        // FR-27 — the daemon now tells us what it actually did, and on macOS
        // that is the whole answer: a non-root invocation queues the ROOT
        // update helper and says where to watch. Discarding it made the
        // button look inert on the platform where it worked correctly.
        const out = await invoke('cmd_apply_update');
        pushOutput(out || t('ov.updates.started', null, 'Update started.'));
      } catch (e) {
        pushOutput(t('common.errorPrefix', { err: e }, 'Error: ' + e));
      }
    });

    // Tray's "Check for Updates" menu item evals a global + dispatches this
    // event (tray.rs) — surface the result where it's visible.
    window.addEventListener('meshharbor-update-check', () => {
      const r = window.__meshharbor_check_update_result;
      if (r && r.check) {
        navigate('overview');
        pushOutput(r.check);
        if (r.check.toLowerCase().includes('update available')) {
          show($('btn-apply-update'));
        }
      }
    });

    // tunnels.js broadcasts its route list; the overview only needs the count.
    document.addEventListener('meshharbor:routes', (ev) => {
      const routes = ev.detail || [];
      routesActive = routes.filter(
        (r) => r.state && r.state.state === 'active',
      ).length;
      paintCounts(get('deviceView'));
    });
  });
})();
