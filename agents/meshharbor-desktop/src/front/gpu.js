// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
/*
 * GPU Servers view (FR-139) for the MeshHarbor Desktop Client.
 *
 * Reads live GPU telemetry via LocalAPI (`cmd_gpu_fleet` / `cmd_gpu_users`)
 * with strict visibility-gated 2 s polling, sequence guarding, exponential
 * backoff on failure, stale-while-error preservation, and 100% `textContent`
 * DOM construction (ZERO `innerHTML`).
 */
(function (root) {
  'use strict';

  const UUID_RE = /^[A-Za-z0-9._:-]{1,128}$/;
  const LIVE_POLL_MS = 2000;
  const CACHED_POLL_MS = 15000;
  const BACKOFF_MS = [10000, 30000, 60000];

  function isValidGpuUuid(uuid) {
    return typeof uuid === 'string' && UUID_RE.test(uuid);
  }

  function posixSingleQuote(val) {
    return "'" + String(val).replace(/'/g, "'\"'\"'") + "'";
  }

  function buildFreeExportCommand(host) {
    if (!host || !Array.isArray(host.gpus)) return null;
    const uuids = host.gpus
      .filter((g) => g && g.state === 'free' && !cardHasFault(g) && isValidGpuUuid(g.uuid))
      .map((g) => g.uuid);
    if (!uuids.length) return null;
    return 'export CUDA_VISIBLE_DEVICES=' + posixSingleQuote(uuids.join(','));
  }

  function cardHasFault(g) {
    if (!g) return false;
    if (g.lost === true) return true;
    if (typeof g.ecc_uncorrected === 'number' && g.ecc_uncorrected > 0) return true;
    if (Array.isArray(g.xid_errors) && g.xid_errors.length > 0) return true;
    if (
      Array.isArray(g.throttle) &&
      g.throttle.some((r) => typeof r === 'string' && /thermal|hw|power/i.test(r))
    ) {
      return true;
    }
    return false;
  }

  function fmtMemGiB(mb) {
    if (typeof mb !== 'number' || !Number.isFinite(mb)) return '—';
    return (mb / 1024).toFixed(1) + 'G';
  }

  function fmtVram(g) {
    if (g.unified) {
      return g.mem_used_mb != null ? fmtMemGiB(g.mem_used_mb) + ' unified' : 'unified';
    }
    if (g.mem_used_mb != null && g.mem_total_mb != null && g.mem_total_mb > 0) {
      return (g.mem_used_mb / 1024).toFixed(1) + ' / ' + (g.mem_total_mb / 1024).toFixed(1) + ' GiB';
    }
    if (g.mem_used_mb != null) return fmtMemGiB(g.mem_used_mb);
    return '—';
  }

  function fmtNetBps(bps) {
    if (typeof bps !== 'number' || !Number.isFinite(bps)) return null;
    if (bps >= 1024 * 1024 * 1024) return (bps / (1024 * 1024 * 1024)).toFixed(1) + ' GB/s';
    if (bps >= 1024 * 1024) return (bps / (1024 * 1024)).toFixed(1) + ' MB/s';
    if (bps >= 1024) return (bps / 1024).toFixed(0) + ' KB/s';
    return bps + ' B/s';
  }

  function fmtProcAge(startedAt, nowS) {
    if (typeof startedAt !== 'number' || startedAt <= 0 || nowS < startedAt) return '—';
    const s = Math.max(0, Math.floor(nowS - startedAt));
    if (s < 60) return s + 's';
    if (s < 3600) return Math.floor(s / 60) + 'm';
    if (s < 86400) return Math.floor(s / 3600) + 'h';
    return Math.floor(s / 86400) + 'd';
  }

  function hostDisplayName(h) {
    if (h.display_name && String(h.display_name).trim()) return String(h.display_name).trim();
    return h.name || h.agent_id || '—';
  }

  function filterHosts(hosts, filter, query) {
    const q = (query || '').trim().toLowerCase();
    return (hosts || []).filter((h) => {
      if (filter === 'free' && !(h.free_count > 0 && h.is_online && h.freshness !== 'offline')) {
        return false;
      }
      if (filter === 'busy' && !((h.gpus || []).some((g) => g.state === 'busy' || g.state === 'unattributed'))) {
        return false;
      }
      if (filter === 'held_idle' && !((h.gpus || []).some((g) => g.state === 'held_idle'))) {
        return false;
      }
      if (filter === 'fault' && !((h.gpus || []).some((g) => cardHasFault(g)))) {
        return false;
      }
      if (filter === 'offline' && h.is_online && h.freshness !== 'offline') {
        return false;
      }
      if (!q) return true;
      if (hostDisplayName(h).toLowerCase().includes(q)) return true;
      if ((h.name || '').toLowerCase().includes(q)) return true;
      if ((h.driver_version || '').toLowerCase().includes(q)) return true;
      return (h.gpus || []).some((g) => {
        if ((g.name || '').toLowerCase().includes(q)) return true;
        if ((g.uuid || '').toLowerCase().includes(q)) return true;
        return (g.procs || []).some(
          (p) =>
            (p.user || '').toLowerCase().includes(q) ||
            (p.name || '').toLowerCase().includes(q) ||
            (p.container || '').toLowerCase().includes(q),
        );
      });
    });
  }

  // Export pure helpers for Node tests.
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
      isValidGpuUuid,
      posixSingleQuote,
      buildFreeExportCommand,
      cardHasFault,
      filterHosts,
    };
  }

  if (typeof document === 'undefined' || !root || !root.MeshHarbor) return;

  const R = root.MeshHarbor;
  const { $, invoke, show, hide, currentView } = R;
  const t = (key, params, fallback) =>
    root.MeshHarborI18n ? root.MeshHarborI18n.t(key, params) : (fallback || key);

  const st = {
    tab: 'fleet', // 'fleet' | 'users'
    filter: 'all',
    search: '',
    live: true,
    userRange: '24h',
    lastFleet: null,
    lastUsers: null,
    lastGoodAt: 0,
    fleetSeq: 0,
    usersSeq: 0,
    failures: 0,
    timer: null,
    copyTimer: null,
  };

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = String(text);
    return node;
  }

  function parseErr(err) {
    if (typeof err === 'string') {
      try {
        const parsed = JSON.parse(err);
        if (parsed && parsed.message) return parsed.message;
      } catch (_) {
        /* plain string */
      }
      return err;
    }
    return err && err.message ? err.message : t('common.unknownError', null, 'unknown error');
  }

  function setError(msg) {
    const banner = $('gpu-error');
    const text = $('gpu-error-msg');
    if (!banner || !text) return;
    if (!msg) {
      hide(banner);
      text.textContent = '';
    } else {
      text.textContent = msg;
      show(banner);
    }
  }

  function showCopyToast(cmd) {
    const banner = $('gpu-copy-toast');
    const msg = $('gpu-copy-toast-msg');
    if (!banner || !msg) return;
    msg.textContent = t('gpu.copiedCmd', { cmd }, 'Copied: ' + cmd);
    show(banner);
    if (st.copyTimer) clearTimeout(st.copyTimer);
    st.copyTimer = setTimeout(() => hide(banner), 3500);
  }

  function copyText(text) {
    if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
      navigator.clipboard.writeText(text).then(
        () => showCopyToast(text),
        () => showCopyToast(text),
      );
    } else {
      showCopyToast(text);
    }
  }

  function sourceBadgeInfo(h) {
    if (h.source === 'shared') {
      return { cls: 'gpu-badge gpu-badge-shared', label: t('gpu.source.shared', null, 'Shared · read-only') };
    }
    if (h.source === 'invited') {
      return { cls: 'gpu-badge gpu-badge-invited', label: t('gpu.source.invited', null, 'Invited') };
    }
    return null;
  }

  function statusBadgeInfo(h) {
    if (!h.is_online || h.freshness === 'offline') {
      return { cls: 'gpu-badge gpu-badge-offline', label: t('gpu.freshness.offline', null, 'Offline') };
    }
    if (h.freshness === 'stale') {
      return { cls: 'gpu-badge gpu-badge-warn', label: t('gpu.freshness.stale', null, 'Stale') };
    }
    if (h.status && h.status !== 'ok') {
      return {
        cls: 'gpu-badge gpu-badge-warn',
        label: t('gpu.hostStatus.' + h.status, null, h.status),
      };
    }
    return { cls: 'gpu-badge gpu-badge-fresh', label: t('gpu.freshness.fresh', null, 'Live') };
  }

  function gpuStateBadge(g) {
    if (cardHasFault(g)) {
      return { cls: 'gpu-state gpu-state-fault', label: t('gpu.state.fault', null, 'Fault') };
    }
    const key = g.state || 'unknown';
    const labels = {
      free: t('gpu.state.free', null, 'Free'),
      busy: t('gpu.state.busy', null, 'Busy'),
      held_idle: t('gpu.state.heldIdle', null, 'Held idle'),
      unattributed: t('gpu.state.unattributed', null, 'Unattributed'),
      unknown: t('gpu.state.unknown', null, 'Unknown'),
    };
    return {
      cls: 'gpu-state gpu-state-' + key.replace(/[^a-z_]/g, ''),
      label: labels[key] || key,
    };
  }

  function renderSummary(summary) {
    const s = summary || {
      hosts_online: 0,
      hosts_total: 0,
      gpus_free: 0,
      gpus_total: 0,
      gpus_busy: 0,
      gpus_held_idle: 0,
      gpus_fault: 0,
    };
    const set = (id, v) => {
      const node = $(id);
      if (node) node.textContent = String(v);
    };
    set('gpu-kpi-hosts', s.hosts_online + ' / ' + s.hosts_total);
    set('gpu-kpi-free', s.gpus_free + ' / ' + s.gpus_total);
    set('gpu-kpi-busy', s.gpus_busy);
    set('gpu-kpi-held', s.gpus_held_idle);
    set('gpu-kpi-fault', s.gpus_fault);
  }

  function renderHostCard(h, nowS) {
    const card = el('div', 'card gpu-host-card');
    if (!h.is_online || h.freshness === 'offline') {
      card.classList.add('gpu-host-offline');
    }

    // Header row
    const head = el('div', 'gpu-host-head');
    const titleWrap = el('div', 'gpu-host-title-wrap');
    titleWrap.appendChild(el('strong', 'gpu-host-name', hostDisplayName(h)));
    const sb = sourceBadgeInfo(h);
    if (sb) titleWrap.appendChild(el('span', sb.cls, sb.label));
    const stBadge = statusBadgeInfo(h);
    titleWrap.appendChild(el('span', stBadge.cls, stBadge.label));
    if (h.driver_version) {
      titleWrap.appendChild(el('span', 'gpu-meta-pill mono', 'drv ' + h.driver_version));
    }
    head.appendChild(titleWrap);

    const right = el('div', 'gpu-host-right');
    right.appendChild(
      el(
        'span',
        'gpu-free-pill mono',
        t('gpu.hostFreeCount', { free: h.free_count || 0, total: h.total_count || 0 }, (h.free_count || 0) + '/' + (h.total_count || 0) + ' free'),
      ),
    );
    const exportCmd = buildFreeExportCommand(h);
    if (exportCmd && h.is_online && h.freshness !== 'offline') {
      const btn = el('button', 'gpu-copy-btn', t('gpu.copyFree', null, 'Copy free GPUs'));
      btn.type = 'button';
      btn.title = exportCmd;
      btn.addEventListener('click', () => copyText(exportCmd));
      right.appendChild(btn);
    }
    head.appendChild(right);
    card.appendChild(head);

    // Host load strip
    if (h.host) {
      const strip = el('div', 'gpu-host-load mono');
      const parts = [];
      if (typeof h.host.cpu_pct === 'number') {
        parts.push('CPU ' + Math.round(h.host.cpu_pct) + '%');
      }
      if (typeof h.host.load1 === 'number') {
        parts.push('load ' + h.host.load1.toFixed(2));
      }
      if (typeof h.host.mem_used_mb === 'number' && typeof h.host.mem_total_mb === 'number' && h.host.mem_total_mb > 0) {
        parts.push('RAM ' + (h.host.mem_used_mb / 1024).toFixed(1) + '/' + (h.host.mem_total_mb / 1024).toFixed(1) + ' GiB');
      }
      if (typeof h.host.disk_root_used_gb === 'number' && typeof h.host.disk_root_total_gb === 'number' && h.host.disk_root_total_gb > 0) {
        const pct = Math.min(100, Math.max(0, Math.round((h.host.disk_root_used_gb / h.host.disk_root_total_gb) * 100)));
        parts.push('/ ' + pct + '%');
      }
      const rx = fmtNetBps(h.host.net_rx_bps);
      const tx = fmtNetBps(h.host.net_tx_bps);
      if (rx && tx) parts.push('Net ↓' + rx + ' ↑' + tx);
      if (parts.length) {
        strip.textContent = parts.join('  ·  ');
        card.appendChild(strip);
      }
    }

    // GPU cards
    const gpus = Array.isArray(h.gpus) ? h.gpus : [];
    if (!gpus.length) {
      card.appendChild(
        el(
          'p',
          'muted small',
          h.status === 'off_local'
            ? t('gpu.hostOffLocal', null, 'GPU telemetry is disabled locally on this host.')
            : t('gpu.noTelemetry', null, 'No GPU telemetry reported yet.'),
        ),
      );
      return card;
    }

    const list = el('div', 'gpu-card-list');
    for (const g of gpus) {
      const row = el('div', 'gpu-card-row');
      const top = el('div', 'gpu-card-top');

      const left = el('div', 'gpu-card-id');
      left.appendChild(el('span', 'gpu-idx mono', '#' + g.idx));
      left.appendChild(el('span', 'gpu-model', g.name || 'GPU'));
      const badge = gpuStateBadge(g);
      left.appendChild(el('span', badge.cls, badge.label));
      if (g.mig_mode) left.appendChild(el('span', 'gpu-meta-pill mono', 'MIG'));
      if (g.lost) left.appendChild(el('span', 'gpu-fault-pill', 'LOST'));
      if (typeof g.ecc_uncorrected === 'number' && g.ecc_uncorrected > 0) {
        left.appendChild(el('span', 'gpu-fault-pill mono', 'ECC ' + g.ecc_uncorrected));
      }
      if (Array.isArray(g.xid_errors) && g.xid_errors.length > 0) {
        left.appendChild(el('span', 'gpu-fault-pill mono', 'Xid ' + g.xid_errors.join(',')));
      }
      top.appendChild(left);

      const metrics = el('div', 'gpu-card-metrics mono');
      const utilPct = typeof g.util_pct === 'number' ? Math.max(0, Math.min(100, g.util_pct)) : null;
      const vramPct =
        !g.unified && typeof g.mem_used_mb === 'number' && typeof g.mem_total_mb === 'number' && g.mem_total_mb > 0
          ? Math.max(0, Math.min(100, Math.round((g.mem_used_mb / g.mem_total_mb) * 100)))
          : null;

      // Util meter
      const utilBox = el('div', 'gpu-meter');
      utilBox.appendChild(el('span', 'gpu-meter-lbl', 'SM ' + (utilPct != null ? utilPct + '%' : '—')));
      const utilBar = el('div', 'gpu-bar');
      const utilFill = el('div', 'gpu-bar-fill gpu-bar-util');
      utilFill.style.width = (utilPct != null ? utilPct : 0) + '%';
      utilBar.appendChild(utilFill);
      utilBox.appendChild(utilBar);
      metrics.appendChild(utilBox);

      // VRAM meter
      const vramBox = el('div', 'gpu-meter gpu-meter-wide');
      vramBox.appendChild(el('span', 'gpu-meter-lbl', fmtVram(g)));
      if (vramPct != null) {
        const vramBar = el('div', 'gpu-bar');
        const vramFill = el('div', 'gpu-bar-fill gpu-bar-vram');
        vramFill.style.width = vramPct + '%';
        vramBar.appendChild(vramFill);
        vramBox.appendChild(vramBar);
      }
      metrics.appendChild(vramBox);

      // Temp / power / fan
      const envParts = [];
      if (typeof g.temp_c === 'number') envParts.push(g.temp_c + '°C');
      if (typeof g.power_w === 'number') {
        envParts.push(g.power_limit_w != null ? g.power_w + '/' + g.power_limit_w + 'W' : g.power_w + 'W');
      }
      if (typeof g.fan_pct === 'number') envParts.push('fan ' + g.fan_pct + '%');
      metrics.appendChild(el('span', 'gpu-env', envParts.length ? envParts.join(' · ') : '—'));

      top.appendChild(metrics);
      row.appendChild(top);

      // L1 process attribution rows
      if (Array.isArray(g.procs) && g.procs.length > 0) {
        const plist = el('div', 'gpu-procs mono');
        for (const p of g.procs) {
          const pline = el('div', 'gpu-proc-row');
          pline.appendChild(el('span', 'gpu-proc-pid', 'pid ' + p.pid));
          pline.appendChild(el('span', 'gpu-proc-user', p.user || '—'));
          const procLabel = p.container ? (p.name || '—') + ' [' + p.container + ']' : (p.name || '—');
          pline.appendChild(el('span', 'gpu-proc-name', procLabel));
          pline.appendChild(el('span', 'gpu-proc-mem', p.mem_mb != null ? p.mem_mb + ' MiB' : '—'));
          pline.appendChild(el('span', 'gpu-proc-age', fmtProcAge(p.started_at, nowS)));
          plist.appendChild(pline);
        }
        row.appendChild(plist);
      } else if (g.procs_state === 'off') {
        row.appendChild(
          el('div', 'gpu-proc-note muted small', t('gpu.procsOff', null, 'Process list disabled locally on this host')),
        );
      }

      list.appendChild(row);
    }

    card.appendChild(list);
    return card;
  }

  function renderFleet() {
    const page = st.lastFleet;
    renderSummary(page ? page.summary : null);
    const hostsEl = $('gpu-hosts');
    const emptyEl = $('gpu-empty');
    if (!hostsEl || !emptyEl) return;
    hostsEl.textContent = '';

    if (!page || !Array.isArray(page.hosts) || page.hosts.length === 0) {
      const title = $('gpu-empty-title');
      const body = $('gpu-empty-body');
      if (title) title.textContent = t('gpu.empty.title', null, 'No marked GPU servers');
      if (body) {
        body.textContent = t(
          'gpu.empty.body',
          null,
          'Mark any device as a GPU server in the web console (or via an enrollment token, key, or temporary invite) to see live cards here.',
        );
      }
      show(emptyEl);
      return;
    }

    const filtered = filterHosts(page.hosts, st.filter, st.search);
    if (!filtered.length) {
      const title = $('gpu-empty-title');
      const body = $('gpu-empty-body');
      if (title) title.textContent = t('gpu.empty.filteredTitle', null, 'No matching GPU servers');
      if (body) body.textContent = t('gpu.empty.filteredBody', null, 'Try clearing the search query or state filter.');
      show(emptyEl);
      return;
    }

    hide(emptyEl);
    const nowS = page.server_time_ms > 0 ? Math.floor(page.server_time_ms / 1000) : Math.floor(Date.now() / 1000);
    for (const h of filtered) {
      hostsEl.appendChild(renderHostCard(h, nowS));
    }
  }

  function renderUsers() {
    const page = st.lastUsers;
    const emptyEl = $('gpu-users-empty');
    const table = $('gpu-users-table');
    const tbody = $('gpu-users-tbody');
    if (!emptyEl || !table || !tbody) return;
    tbody.textContent = '';

    const rows = page && Array.isArray(page.users) ? page.users : [];
    if (!rows.length) {
      hide(table);
      show(emptyEl);
      return;
    }
    hide(emptyEl);
    show(table);

    for (const u of rows) {
      const tr = document.createElement('tr');
      tr.appendChild(el('td', 'mono', u.user || '—'));
      tr.appendChild(el('td', 'num mono', Number(u.held_gpu_hours || 0).toFixed(2)));
      tr.appendChild(el('td', 'num mono', Number(u.busy_gpu_hours || 0).toFixed(2)));
      tr.appendChild(el('td', 'num mono', String(u.live_gpus || 0)));
      tr.appendChild(
        el(
          'td',
          'num mono',
          u.live_mem_mb >= 1024 ? (u.live_mem_mb / 1024).toFixed(1) + ' GiB' : (u.live_mem_mb || 0) + ' MiB',
        ),
      );
      tr.appendChild(el('td', 'muted small', Array.isArray(u.hosts) ? u.hosts.join(', ') : '—'));
      tbody.appendChild(tr);
    }
  }

  function updateTimestamp() {
    const node = $('gpu-updated');
    if (!node) return;
    if (!st.lastGoodAt) {
      node.textContent = '';
      return;
    }
    node.textContent = t('gpu.updatedAt', { time: R.fmtRelative(st.lastGoodAt) }, 'Updated ' + R.fmtRelative(st.lastGoodAt));
  }

  function clearTimer() {
    if (st.timer) {
      clearTimeout(st.timer);
      st.timer = null;
    }
  }

  function scheduleNext() {
    clearTimer();
    if (currentView() !== 'gpu' || document.hidden) return;
    let delay;
    if (st.failures > 0) {
      delay = BACKOFF_MS[Math.min(st.failures - 1, BACKOFF_MS.length - 1)];
    } else if (st.tab === 'users') {
      delay = CACHED_POLL_MS;
    } else {
      delay = st.live ? LIVE_POLL_MS : CACHED_POLL_MS;
    }
    st.timer = setTimeout(() => {
      if (st.tab === 'users') void fetchUsers();
      else void fetchFleet(false);
    }, delay);
  }

  async function fetchFleet(forceWait) {
    const seq = ++st.fleetSeq;
    try {
      const page = await invoke('cmd_gpu_fleet', {
        org: '',
        live: st.live,
        wait_ms: forceWait && st.live ? 1200 : 0,
        hosts: [],
      });
      if (seq !== st.fleetSeq) return;
      st.lastFleet = page;
      st.lastGoodAt = Date.now();
      st.failures = 0;
      setError(null);
      renderFleet();
      updateTimestamp();
    } catch (err) {
      if (seq !== st.fleetSeq) return;
      st.failures += 1;
      setError(t('gpu.loadError', { err: parseErr(err) }, 'GPU telemetry unavailable: ' + parseErr(err)));
    } finally {
      scheduleNext();
    }
  }

  async function fetchUsers() {
    const seq = ++st.usersSeq;
    try {
      const page = await invoke('cmd_gpu_users', {
        org: '',
        range: st.userRange,
      });
      if (seq !== st.usersSeq) return;
      st.lastUsers = page;
      st.lastGoodAt = Date.now();
      st.failures = 0;
      setError(null);
      renderUsers();
      updateTimestamp();
    } catch (err) {
      if (seq !== st.usersSeq) return;
      st.failures += 1;
      setError(t('gpu.loadError', { err: parseErr(err) }, 'GPU usage unavailable: ' + parseErr(err)));
    } finally {
      scheduleNext();
    }
  }

  function switchTab(next) {
    st.tab = next === 'users' ? 'users' : 'fleet';
    document.querySelectorAll('.gpu-tab').forEach((btn) => {
      const active = btn.dataset.gpuTab === st.tab;
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-selected', active ? 'true' : 'false');
    });
    if (st.tab === 'users') {
      hide($('gpu-panel-fleet'));
      show($('gpu-panel-users'));
      void fetchUsers();
    } else {
      hide($('gpu-panel-users'));
      show($('gpu-panel-fleet'));
      void fetchFleet(true);
    }
  }

  function wire() {
    const liveToggle = $('gpu-live-toggle');
    if (liveToggle) {
      liveToggle.checked = st.live;
      liveToggle.addEventListener('change', () => {
        st.live = liveToggle.checked;
        if (currentView() === 'gpu' && st.tab === 'fleet') void fetchFleet(true);
      });
    }

    const refreshBtn = $('gpu-btn-refresh');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', () => {
        if (st.tab === 'users') void fetchUsers();
        else void fetchFleet(true);
      });
    }

    const webBtn = $('gpu-btn-open-web');
    if (webBtn) {
      webBtn.addEventListener('click', () => {
        invoke('cmd_open_gpu_web').catch((e) => setError(parseErr(e)));
      });
    }

    const search = $('gpu-search');
    if (search) {
      search.addEventListener('input', () => {
        st.search = search.value || '';
        renderFleet();
      });
    }

    document.querySelectorAll('#gpu-filters .gpu-filter').forEach((btn) => {
      btn.addEventListener('click', () => {
        st.filter = btn.dataset.gpuFilter || 'all';
        document.querySelectorAll('#gpu-filters .gpu-filter').forEach((b) => {
          b.classList.toggle('active', b === btn);
        });
        renderFleet();
      });
    });

    document.querySelectorAll('.gpu-tab').forEach((btn) => {
      btn.addEventListener('click', () => switchTab(btn.dataset.gpuTab));
    });

    document.querySelectorAll('#gpu-user-ranges .gpu-filter').forEach((btn) => {
      btn.addEventListener('click', () => {
        st.userRange = btn.dataset.gpuRange || '24h';
        document.querySelectorAll('#gpu-user-ranges .gpu-filter').forEach((b) => {
          b.classList.toggle('active', b === btn);
        });
        void fetchUsers();
      });
    });

    document.addEventListener('meshharbor:view', (ev) => {
      if (ev.detail === 'gpu') {
        if (st.tab === 'users') void fetchUsers();
        else void fetchFleet(true);
      } else {
        clearTimer();
      }
    });

    document.addEventListener('visibilitychange', () => {
      if (document.hidden) clearTimer();
      else if (currentView() === 'gpu') {
        if (st.tab === 'users') void fetchUsers();
        else void fetchFleet(false);
      }
    });

    document.addEventListener('meshharbor:lang', () => {
      renderFleet();
      renderUsers();
      updateTimestamp();
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', wire);
  } else {
    wire();
  }
})(typeof window !== 'undefined' ? window : globalThis);
