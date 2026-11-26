// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
/*
 * GPU Servers view (FR-139) for the MeshHarbor Desktop Client.
 *
 * Reads live GPU telemetry via LocalAPI (`cmd_gpu_fleet` / `cmd_gpu_users`)
 * with strict visibility-gated 2 s polling, sequence guarding, exponential
 * backoff on failure, stale-while-error preservation, keyed DOM reconciliation,
 * live state/metric delta tracking, canonical fault explanations, and
 * 100% `textContent` DOM construction (ZERO `innerHTML`).
 */
(function (root) {
  'use strict';

  const UUID_RE = /^[A-Za-z0-9._:-]{1,128}$/;
  const LIVE_POLL_MS = 2000;
  const CACHED_POLL_MS = 15000;
  const BACKOFF_MS = [10000, 30000, 60000];
  const DELTA_TTL_MS = 4500;
  const MAX_RECENT_CHANGES = 8;
  const APP_LEVEL_XIDS = [13, 31, 43, 45];
  const FAULT_HOST_STATUSES = [
    'driver_missing',
    'driver_reboot_pending',
    'driver_hung',
    'sampler_stalled',
    'unavailable',
  ];
  const XID_DESCRIPTIONS = {
    13: 'Graphics engine exception',
    31: 'GPU memory page fault',
    32: 'Corrupted command stream',
    43: 'GPU stopped processing',
    45: 'Preemptive cleanup after prior fault',
    48: 'Double-bit ECC error (DBE)',
    62: 'Internal micro-controller halt',
    63: 'ECC row remapping event',
    64: 'ECC row remapper failure',
    74: 'NVLink error',
    79: 'GPU fell off the bus',
    92: 'High single-bit ECC rate',
    94: 'Contained ECC error',
    95: 'Uncontained ECC error (reset required)',
    119: 'GSP RPC timeout',
    120: 'GSP error',
  };

  function isValidGpuUuid(uuid) {
    return typeof uuid === 'string' && UUID_RE.test(uuid);
  }

  function posixSingleQuote(val) {
    return "'" + String(val).replace(/'/g, "'\"'\"'") + "'";
  }

  function cardRuntimeKind(host, g) {
    const b = String((g && g.backend) || (host && host.backend) || '').toLowerCase();
    const uuid = String((g && g.uuid) || '');
    const name = String((g && g.name) || '').toLowerCase();
    if (b === 'ascend' || uuid.startsWith('ASCEND-') || name.includes('ascend')) return 'ascend';
    if (b === 'tpu' || uuid.startsWith('TPU-') || name.includes('tpu')) return 'tpu';
    if (b === 'pci' || uuid.startsWith('PCI-')) return 'pci';
    if (b === 'amd' || b === 'rocm') return 'amd';
    if (b === 'intel') return 'intel';
    if (b === 'apple') return 'apple';
    return 'nvidia';
  }

  function isAscendHost(host) {
    return typeof (host && host.backend) === 'string' && host.backend.toLowerCase().includes('ascend');
  }

  function isAscendCard(host, g) {
    return cardRuntimeKind(host, g) === 'ascend';
  }

  function decodeNvidiaXid(code) {
    return XID_DESCRIPTIONS[code] || null;
  }

  function cardFaultReasons(g) {
    if (!g) return [];
    if (Array.isArray(g.fault_reasons) && g.fault_reasons.length > 0) {
      return g.fault_reasons;
    }
    const reasons = [];
    if (g.lost === true) {
      reasons.push({ scope: 'card', severity: 'critical', code: 'lost', summary: 'Accelerator fell off the bus (lost)' });
    }
    if (Array.isArray(g.xid_errors) && g.xid_errors.length > 0) {
      const anyHw = g.xid_errors.some((x) => !APP_LEVEL_XIDS.includes(x));
      const summary = g.xid_errors
        .map((c) => (decodeNvidiaXid(c) ? 'Xid ' + c + ' (' + decodeNvidiaXid(c) + ')' : 'Xid ' + c))
        .join(', ');
      reasons.push({
        scope: 'card',
        severity: anyHw ? 'critical' : 'warning',
        code: anyHw ? 'xid' : 'xid_app',
        summary,
      });
    }
    if (typeof g.ecc_uncorrected === 'number' && g.ecc_uncorrected > 0) {
      reasons.push({
        scope: 'card',
        severity: 'critical',
        code: 'ecc_uncorrected',
        summary: 'Uncorrected ECC: ' + g.ecc_uncorrected,
      });
    }
    if (g.remap_failure === true) {
      reasons.push({ scope: 'card', severity: 'critical', code: 'remap_failure', summary: 'Row remapping failed (RMA)' });
    } else if (g.remap_pending === true) {
      reasons.push({ scope: 'card', severity: 'critical', code: 'remap_pending', summary: 'Row remapping pending (reset)' });
    } else if (typeof g.remapped_rows === 'number' && g.remapped_rows > 0) {
      reasons.push({
        scope: 'card',
        severity: 'warning',
        code: 'remapped_rows',
        summary: 'Remapped rows: ' + g.remapped_rows,
      });
    }
    if (typeof g.vendor_health === 'string' && g.vendor_health.trim() && g.vendor_health.trim().toLowerCase() !== 'ok') {
      const low = g.vendor_health.toLowerCase();
      const crit = /crit|fatal|error|alarm|fail|general/.test(low);
      reasons.push({
        scope: 'card',
        severity: crit ? 'critical' : 'warning',
        code: 'vendor_health',
        summary: 'Health: ' + g.vendor_health,
      });
    }
    if (Array.isArray(g.throttle)) {
      for (const raw of g.throttle) {
        const low = String(raw || '').toLowerCase();
        if (low === 'thermal' || low === 'sw_thermal') {
          reasons.push({ scope: 'card', severity: 'warning', code: 'thermal_throttle', summary: 'Thermal throttling' });
        } else if (low === 'hw_slowdown') {
          reasons.push({ scope: 'card', severity: 'warning', code: 'hw_slowdown', summary: 'Hardware slowdown' });
        } else if (low === 'power_brake') {
          reasons.push({ scope: 'card', severity: 'warning', code: 'power_brake', summary: 'Power brake throttling' });
        }
      }
    }
    return reasons;
  }

  // Canonical critical-fault check: power_cap is NEVER a fault!
  function cardHasFault(g) {
    if (!g) return false;
    if (typeof g.fault_severity === 'string') {
      return g.fault_severity === 'critical';
    }
    return cardFaultReasons(g).some((r) => r.severity === 'critical');
  }

  function cardHasWarning(g) {
    if (!g) return false;
    if (typeof g.fault_severity === 'string') {
      return g.fault_severity === 'warning';
    }
    const reasons = cardFaultReasons(g);
    return !reasons.some((r) => r.severity === 'critical') && reasons.some((r) => r.severity === 'warning');
  }

  function hostHasFault(h) {
    if (!h) return false;
    if (h.is_online === false || h.freshness === 'offline') return false;
    if (h.host_fault_severity === 'critical' || h.host_fault_severity === 'warning') return true;
    if (typeof h.fault_count === 'number' && h.fault_count > 0) return true;
    if (typeof h.status === 'string' && FAULT_HOST_STATUSES.includes(h.status)) return true;
    return (h.gpus || []).some((g) => cardHasFault(g));
  }

  function hostHasWarning(h) {
    if (!h) return false;
    if (h.is_online === false || h.freshness === 'offline') return false;
    if (h.host_fault_severity === 'warning' || h.lagging === true || h.freshness === 'stale') return true;
    return (h.gpus || []).some((g) => cardHasWarning(g));
  }

  function buildFreeExportCommand(host) {
    if (!host || !Array.isArray(host.gpus)) return null;
    if (host.is_online === false || host.freshness === 'offline' || host.freshness === 'stale' || host.lagging === true) {
      return null;
    }
    if (host.host_fault_severity === 'critical') return null;
    if (typeof host.status === 'string' && host.status !== '' && host.status !== 'ok' && host.status !== 'limited') {
      return null;
    }
    const free = host.gpus.filter((g) => {
      if (!g || g.state !== 'free' || g.stale === true || g.presence_only === true) return false;
      if (cardHasFault(g) || !isValidGpuUuid(g.uuid)) return false;
      const rt = cardRuntimeKind(host, g);
      return rt === 'nvidia' || rt === 'ascend' || rt === 'amd';
    });
    if (!free.length) return null;
    const ascendCards = free.filter((g) => cardRuntimeKind(host, g) === 'ascend');
    if (ascendCards.length === free.length) {
      const ids = ascendCards.map((g) => String(g.vendor_index != null ? g.vendor_index : g.idx));
      return 'export ASCEND_RT_VISIBLE_DEVICES=' + posixSingleQuote(ids.join(','));
    }
    const amdCards = free.filter((g) => cardRuntimeKind(host, g) === 'amd');
    if (amdCards.length === free.length) {
      const ids = amdCards.map((g) => String(g.vendor_index != null ? g.vendor_index : g.idx));
      return 'export ROCR_VISIBLE_DEVICES=' + posixSingleQuote(ids.join(','));
    }
    const cudaCards = free.filter((g) => cardRuntimeKind(host, g) === 'nvidia');
    if (cudaCards.length > 0) {
      return (
        'export CUDA_DEVICE_ORDER=PCI_BUS_ID CUDA_VISIBLE_DEVICES=' +
        posixSingleQuote(cudaCards.map((g) => g.uuid).join(','))
      );
    }
    return null;
  }

  function loadToneClass(pct) {
    if (typeof pct !== 'number' || !Number.isFinite(pct)) return 'gpu-tone-idle';
    if (pct >= 80) return 'gpu-tone-hot';
    if (pct >= 50) return 'gpu-tone-warm';
    return 'gpu-tone-cool';
  }

  function tempToneClass(c) {
    if (typeof c !== 'number' || !Number.isFinite(c)) return '';
    if (c >= 85) return 'gpu-temp-hot';
    if (c >= 72) return 'gpu-temp-warm';
    return 'gpu-temp-cool';
  }

  function shortCardModel(name) {
    if (!name) return 'GPU';
    return String(name)
      .replace(/^NVIDIA GeForce\s+/i, '')
      .replace(/^NVIDIA\s+/i, '')
      .replace(/\s+Ada Generation$/i, ' Ada')
      .trim();
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

  function fmtAgeSecs(sec) {
    if (typeof sec !== 'number' || !Number.isFinite(sec) || sec < 0) return '—';
    const s = Math.floor(sec);
    if (s < 60) return s + 's';
    if (s < 3600) return Math.floor(s / 60) + 'm';
    if (s < 86400) return Math.floor(s / 3600) + 'h';
    return Math.floor(s / 86400) + 'd';
  }

  function fmtProcAge(startedAt, nowS) {
    if (typeof startedAt !== 'number' || startedAt <= 0 || nowS < startedAt) return '—';
    return fmtAgeSecs(Math.max(0, Math.floor(nowS - startedAt)));
  }

  function hostDisplayName(h) {
    if (h.display_name && String(h.display_name).trim()) return String(h.display_name).trim();
    return h.name || h.agent_id || '—';
  }

  function cardSlotLabel(host, g) {
    const rt = cardRuntimeKind(host, g);
    if (rt === 'ascend') return 'NPU' + (g.vendor_index != null ? g.vendor_index : g.idx);
    if (rt === 'tpu') return 'TPU' + g.idx;
    return '#' + g.idx;
  }

  function filterHosts(hosts, filter, query) {
    const q = (query || '').trim().toLowerCase();
    return (hosts || []).filter((h) => {
      const online = h.is_online && h.freshness !== 'offline';
      if (filter === 'free' && !(h.free_count > 0 && online && h.freshness === 'fresh' && !h.lagging)) {
        return false;
      }
      if (filter === 'busy' && !(online && (h.gpus || []).some((g) => g.state === 'busy' || g.state === 'unattributed'))) {
        return false;
      }
      if (filter === 'held_idle' && !(online && (h.gpus || []).some((g) => g.state === 'held_idle'))) {
        return false;
      }
      if (filter === 'fault' && !hostHasFault(h)) {
        return false;
      }
      if (filter === 'warning' && !hostHasWarning(h)) {
        return false;
      }
      if (filter === 'offline' && online) {
        return false;
      }
      if (!q) return true;
      if (hostDisplayName(h).toLowerCase().includes(q)) return true;
      if ((h.name || '').toLowerCase().includes(q)) return true;
      if ((h.driver_version || '').toLowerCase().includes(q)) return true;
      if ((h.status || '').toLowerCase().includes(q)) return true;
      if ((h.status_detail || '').toLowerCase().includes(q)) return true;
      return (h.gpus || []).some((g) => {
        if ((g.name || '').toLowerCase().includes(q)) return true;
        if ((g.uuid || '').toLowerCase().includes(q)) return true;
        if (cardFaultReasons(g).some((r) => (r.summary || '').toLowerCase().includes(q) || (r.code || '').toLowerCase().includes(q))) {
          return true;
        }
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
      cardRuntimeKind,
      cardFaultReasons,
      buildFreeExportCommand,
      cardHasFault,
      cardHasWarning,
      hostHasFault,
      hostHasWarning,
      filterHosts,
    };
  }

  if (typeof document === 'undefined' || !root || !root.MeshHarbor) return;

  const R = root.MeshHarbor;
  const { $, invoke, show, hide, currentView } = R;
  const t = (key, params, fallback) => {
    if (!root.MeshHarborI18n) return fallback || key;
    const val = root.MeshHarborI18n.t(key, params);
    return val === key && fallback ? fallback : val;
  };

  const st = {
    tab: 'fleet', // 'fleet' | 'users'
    filter: 'all',
    search: '',
    live: true,
    userRange: '24h',
    lastFleet: null,
    lastUsers: null,
    lastFleetOkAt: 0,
    lastUsersOkAt: 0,
    fleetFailures: 0,
    usersFailures: 0,
    fleetNextRetryAt: 0,
    usersNextRetryAt: 0,
    fleetError: null,
    usersError: null,
    fleetSeq: 0,
    usersSeq: 0,
    timer: null,
    tickTimer: null,
    copyTimer: null,
    prevHosts: new Map(), // agent_id -> snapshot summary for diffing
    cardDeltas: new Map(), // agent_id:uuid -> { utilDelta, memDeltaMb, stateChanged, at }
    recentChanges: [], // [{ at, cls, text }]
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

  function renderErrorBanner() {
    const msg = st.tab === 'users' ? st.usersError : st.fleetError;
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

  function showCopyToast(text, isError) {
    const banner = $('gpu-copy-toast');
    const msg = $('gpu-copy-toast-msg');
    if (!banner || !msg) return;
    banner.classList.toggle('banner-warn', Boolean(isError));
    banner.classList.toggle('banner-ok', !isError);
    msg.textContent = text;
    show(banner);
    if (st.copyTimer) clearTimeout(st.copyTimer);
    st.copyTimer = setTimeout(() => hide(banner), 3500);
  }

  function copyText(text) {
    if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
      navigator.clipboard.writeText(text).then(
        () => showCopyToast(t('gpu.copiedCmd', { cmd: text }, 'Copied: ' + text), false),
        () => showCopyToast(t('gpu.copyFailed', null, 'Clipboard copy failed'), true),
      );
    } else {
      showCopyToast(t('gpu.copyFailed', null, 'Clipboard copy failed'), true);
    }
  }

  function stateLabel(state) {
    const labels = {
      free: t('gpu.state.free', null, 'Free'),
      busy: t('gpu.state.busy', null, 'Busy'),
      held_idle: t('gpu.state.heldIdle', null, 'Held idle'),
      unattributed: t('gpu.state.unattributed', null, 'Unattributed'),
      unknown: t('gpu.state.unknown', null, 'Unknown'),
    };
    return labels[state] || state || t('gpu.state.unknown', null, 'Unknown');
  }

  function hostAgeSecs(h, pageServerMs) {
    if (typeof h.age_ms === 'number' && Number.isFinite(h.age_ms) && h.age_ms >= 0) {
      const elapsedSinceFetch = st.lastFleetOkAt > 0 ? Math.max(0, Date.now() - st.lastFleetOkAt) : 0;
      return Math.floor((h.age_ms + elapsedSinceFetch) / 1000);
    }
    if (typeof h.received_at_ms === 'number' && h.received_at_ms > 0) {
      const refMs = pageServerMs > 0 ? pageServerMs + Math.max(0, Date.now() - st.lastFleetOkAt) : Date.now();
      return Math.max(0, Math.floor((refMs - h.received_at_ms) / 1000));
    }
    return null;
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

  function freshnessBadgeInfo(h, pageServerMs) {
    const ageS = hostAgeSecs(h, pageServerMs);
    const ageTxt = ageS != null ? fmtAgeSecs(ageS) : null;
    if (!h.is_online || h.freshness === 'offline') {
      return {
        cls: 'gpu-badge gpu-badge-offline mono',
        label: ageTxt
          ? t('gpu.freshness.offlineAge', { age: ageTxt }, 'Offline ' + ageTxt)
          : t('gpu.freshness.offline', null, 'Offline'),
      };
    }
    if (h.freshness === 'stale') {
      return {
        cls: 'gpu-badge gpu-badge-warn mono',
        label: t('gpu.freshness.stale', { age: ageTxt || '—' }, 'Stale ' + (ageTxt || '—')),
      };
    }
    if (h.lagging) {
      return {
        cls: 'gpu-badge gpu-badge-warn mono',
        label: t('gpu.freshness.lagging', { age: ageTxt || '—' }, 'Lagging ' + (ageTxt || '—')),
      };
    }
    return {
      cls: 'gpu-badge gpu-badge-fresh mono',
      label: ageTxt
        ? t('gpu.freshness.freshAge', { age: ageTxt }, ageTxt)
        : t('gpu.freshness.fresh', null, 'Fresh'),
    };
  }

  function hostStatusBadgeInfo(h) {
    if (!h.status || h.status === 'ok') return null;
    const label = t('gpu.hostStatus.' + h.status, null, h.status);
    let cls = 'gpu-badge gpu-badge-offline';
    if (h.host_fault_severity === 'critical' || h.status === 'driver_missing' || h.status === 'driver_hung' || h.status === 'unavailable') {
      cls = 'gpu-badge gpu-badge-fault';
    } else if (h.host_fault_severity === 'warning' || h.status === 'driver_reboot_pending' || h.status === 'sampler_stalled' || h.status === 'limited') {
      cls = 'gpu-badge gpu-badge-warn';
    }
    return { cls, label };
  }

  function gpuStateBadge(g) {
    const key = g.state || 'unknown';
    return {
      cls: 'gpu-state gpu-state-' + key.replace(/[^a-z_]/g, ''),
      label: stateLabel(key),
    };
  }

  function pushChange(cls, text) {
    st.recentChanges.unshift({ at: Date.now(), cls, text });
    if (st.recentChanges.length > MAX_RECENT_CHANGES) {
      st.recentChanges.length = MAX_RECENT_CHANGES;
    }
  }

  function trackFleetChanges(page) {
    if (!page || !Array.isArray(page.hosts)) return;
    const now = Date.now();
    // Prune expired deltas
    for (const [k, d] of st.cardDeltas.entries()) {
      if (now - d.at > DELTA_TTL_MS) st.cardDeltas.delete(k);
    }

    const nextHosts = new Map();
    for (const h of page.hosts) {
      const prev = st.prevHosts.get(h.agent_id);
      const hName = hostDisplayName(h);
      const curGpus = new Map();
      for (const g of h.gpus || []) {
        curGpus.set(g.uuid, {
          state: g.state,
          util_pct: g.util_pct,
          mem_used_mb: g.mem_used_mb,
          fault_severity: g.fault_severity || (cardHasFault(g) ? 'critical' : cardHasWarning(g) ? 'warning' : null),
          firstReason: cardFaultReasons(g)[0]?.summary || '',
        });
      }
      nextHosts.set(h.agent_id, {
        seq: h.seq || 0,
        received_at_ms: h.received_at_ms || 0,
        is_online: Boolean(h.is_online && h.freshness !== 'offline'),
        status: h.status || 'unknown',
        gpus: curGpus,
      });

      if (!prev) continue;
      const nowOnline = Boolean(h.is_online && h.freshness !== 'offline');
      if (prev.is_online !== nowOnline) {
        pushChange(
          nowOnline ? 'gpu-change-free' : 'gpu-change-warn',
          nowOnline
            ? t('gpu.changes.hostOnline', { host: hName }, hName + ' came online')
            : t('gpu.changes.hostOffline', { host: hName }, hName + ' went offline'),
        );
      } else if (prev.status !== (h.status || 'unknown')) {
        const statusTxt = t('gpu.hostStatus.' + h.status, null, h.status);
        pushChange(
          h.host_fault_severity === 'critical' ? 'gpu-change-fault' : 'gpu-change-warn',
          t('gpu.changes.hostStatus', { host: hName, status: statusTxt }, hName + ' status: ' + statusTxt),
        );
      }

      // Compute card deltas ONLY when telemetry frame actually advanced.
      const advanced =
        (h.seq && h.seq !== prev.seq) ||
        (h.received_at_ms && h.received_at_ms !== prev.received_at_ms);
      if (!advanced) continue;

      for (const g of h.gpus || []) {
        const pg = prev.gpus.get(g.uuid);
        if (!pg) continue;
        const utilDelta =
          typeof g.util_pct === 'number' && typeof pg.util_pct === 'number' ? g.util_pct - pg.util_pct : 0;
        const memDeltaMb =
          typeof g.mem_used_mb === 'number' && typeof pg.mem_used_mb === 'number'
            ? g.mem_used_mb - pg.mem_used_mb
            : 0;
        const curSev = g.fault_severity || (cardHasFault(g) ? 'critical' : cardHasWarning(g) ? 'warning' : null);
        const stateChanged = pg.state !== g.state || pg.fault_severity !== curSev;
        if (Math.abs(utilDelta) >= 2 || Math.abs(memDeltaMb) >= 128 || stateChanged) {
          st.cardDeltas.set(h.agent_id + ':' + g.uuid, {
            utilDelta: Math.abs(utilDelta) >= 2 ? utilDelta : 0,
            memDeltaMb: Math.abs(memDeltaMb) >= 128 ? memDeltaMb : 0,
            stateChanged,
            at: now,
          });
        }
        const slot = cardSlotLabel(h, g);
        if (pg.fault_severity !== 'critical' && curSev === 'critical') {
          const reason = cardFaultReasons(g)[0]?.summary || 'Fault';
          pushChange(
            'gpu-change-fault',
            t('gpu.changes.faultDetected', { host: hName, slot, reason }, hName + ' ' + slot + ' fault: ' + reason),
          );
        } else if (pg.fault_severity === 'critical' && curSev !== 'critical') {
          pushChange(
            'gpu-change-free',
            t('gpu.changes.faultCleared', { host: hName, slot }, hName + ' ' + slot + ' fault cleared'),
          );
        } else if (pg.state !== g.state) {
          pushChange(
            g.state === 'free' ? 'gpu-change-free' : 'gpu-change-item',
            t(
              'gpu.changes.cardState',
              { host: hName, slot, from: stateLabel(pg.state), to: stateLabel(g.state) },
              hName + ' ' + slot + ': ' + stateLabel(pg.state) + ' → ' + stateLabel(g.state),
            ),
          );
        }
      }
    }
    st.prevHosts = nextHosts;
  }

  function renderRecentChanges() {
    const box = $('gpu-changes');
    const list = $('gpu-changes-list');
    if (!box || !list) return;
    if (!st.recentChanges.length) {
      hide(box);
      list.textContent = '';
      return;
    }
    show(box);
    list.textContent = '';
    const now = Date.now();
    for (const item of st.recentChanges) {
      const chip = el('span', 'gpu-change-item ' + (item.cls || ''));
      const age = fmtAgeSecs(Math.max(0, Math.floor((now - item.at) / 1000)));
      chip.appendChild(el('span', '', item.text));
      chip.appendChild(el('span', 'muted', '· ' + age));
      list.appendChild(chip);
    }
  }

  function setFilter(next) {
    st.filter = next || 'all';
    document.querySelectorAll('#gpu-filters .gpu-filter').forEach((b) => {
      b.classList.toggle('active', b.dataset.gpuFilter === st.filter);
    });
    document.querySelectorAll('#gpu-summary .gpu-kpi').forEach((k) => {
      k.setAttribute('aria-pressed', k.dataset.gpuKpiFilter === st.filter ? 'true' : 'false');
    });
    renderFleet();
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
      gpus_warning: 0,
      fault_hosts: 0,
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

    const faultCard = $('gpu-kpi-fault-card');
    const hasFault = (s.gpus_fault || 0) > 0 || (s.fault_hosts || 0) > 0;
    if (faultCard) faultCard.classList.toggle('gpu-kpi-has-fault', hasFault);

    const sub = $('gpu-kpi-fault-sub');
    if (sub) {
      const parts = [];
      if (s.fault_hosts > 0) {
        parts.push(t('gpu.kpi.faultHosts', { n: s.fault_hosts }, 'on ' + s.fault_hosts + ' host(s)'));
      }
      if (s.gpus_warning > 0) {
        parts.push(t('gpu.kpi.warnCount', { n: s.gpus_warning }, s.gpus_warning + ' warn'));
      }
      sub.textContent = parts.join(' · ');
    }
  }

  function buildCardRow(h, g, nowS) {
    const row = el('div', 'gpu-card-row');
    row.dataset.uuid = g.uuid;

    const top = el('div', 'gpu-card-top');
    const left = el('div', 'gpu-card-id');
    const idxEl = el('span', 'gpu-idx mono');
    const modelEl = el('span', 'gpu-model');
    const stateEl = el('span', 'gpu-state');
    const tagsEl = el('span', 'gpu-card-tags');
    left.appendChild(idxEl);
    left.appendChild(modelEl);
    left.appendChild(stateEl);
    left.appendChild(tagsEl);
    top.appendChild(left);

    const metrics = el('div', 'gpu-card-metrics mono');

    // VRAM / HBM bar
    const vramBox = el('div', 'gpu-nvbar-group gpu-nvbar-mem');
    const vramLbl = el('span', 'gpu-nvbar-lbl');
    const vramTrack = el('div', 'gpu-nvbar-track');
    const vramFill = el('div', 'gpu-nvbar-fill');
    const vramOverlay = el('div', 'gpu-nvbar-overlay');
    const vramText = el('span', '');
    const vramPctEl = el('span', '');
    vramOverlay.appendChild(vramText);
    vramOverlay.appendChild(vramPctEl);
    vramTrack.appendChild(vramFill);
    vramTrack.appendChild(el('div', 'gpu-nvbar-ticks'));
    vramTrack.appendChild(vramOverlay);
    vramBox.appendChild(vramLbl);
    vramBox.appendChild(vramTrack);
    metrics.appendChild(vramBox);

    // Util / AICore bar
    const utilBox = el('div', 'gpu-nvbar-group gpu-nvbar-util');
    const utilLbl = el('span', 'gpu-nvbar-lbl');
    const utilTrack = el('div', 'gpu-nvbar-track');
    const utilFill = el('div', 'gpu-nvbar-fill');
    const utilOverlay = el('div', 'gpu-nvbar-overlay gpu-nvbar-overlay-end');
    const utilText = el('span', '');
    const utilDeltaEl = el('span', 'gpu-delta');
    utilOverlay.appendChild(utilText);
    utilOverlay.appendChild(utilDeltaEl);
    utilTrack.appendChild(utilFill);
    utilTrack.appendChild(el('div', 'gpu-nvbar-ticks'));
    utilTrack.appendChild(utilOverlay);
    utilBox.appendChild(utilLbl);
    utilBox.appendChild(utilTrack);
    metrics.appendChild(utilBox);

    const envWrap = el('div', 'gpu-env');
    metrics.appendChild(envWrap);
    top.appendChild(metrics);
    row.appendChild(top);

    const faultBar = el('div', 'gpu-fault-bar');
    faultBar.hidden = true;
    row.appendChild(faultBar);

    const procsWrap = el('div', '');
    row.appendChild(procsWrap);

    row._refs = {
      idxEl,
      modelEl,
      stateEl,
      tagsEl,
      vramLbl,
      vramFill,
      vramText,
      vramPctEl,
      utilLbl,
      utilFill,
      utilText,
      utilDeltaEl,
      envWrap,
      faultBar,
      procsWrap,
    };
    updateCardRow(row, h, g, nowS);
    return row;
  }

  function updateCardRow(row, h, g, nowS) {
    const r = row._refs;
    const rt = cardRuntimeKind(h, g);
    const ascend = rt === 'ascend';
    const fault = cardHasFault(g);
    const rowState = fault ? 'fault' : String(g.state || 'unknown').replace(/[^a-z_]/g, '');
    const delta = st.cardDeltas.get(h.agent_id + ':' + g.uuid);
    const freshDelta = delta && Date.now() - delta.at <= DELTA_TTL_MS ? delta : null;

    row.className =
      'gpu-card-row gpu-row-' +
      rowState +
      (g.stale ? ' gpu-row-stale' : '') +
      (freshDelta ? ' gpu-row-changed' : '');

    r.idxEl.textContent = cardSlotLabel(h, g);
    r.modelEl.textContent = shortCardModel(g.name);
    const badge = gpuStateBadge(g);
    r.stateEl.className = badge.cls;
    r.stateEl.textContent = badge.label;

    r.tagsEl.textContent = '';
    if (g.mig_mode || g.mig) r.tagsEl.appendChild(el('span', 'gpu-meta-pill mono', 'MIG'));
    if (g.presence_only) {
      r.tagsEl.appendChild(el('span', 'gpu-info-pill', t('gpu.presenceOnly', null, 'Presence only')));
    }

    const utilPct = typeof g.util_pct === 'number' ? Math.max(0, Math.min(100, Math.round(g.util_pct))) : null;
    const vramPct =
      !g.unified && typeof g.mem_used_mb === 'number' && typeof g.mem_total_mb === 'number' && g.mem_total_mb > 0
        ? Math.max(0, Math.min(100, Math.round((g.mem_used_mb / g.mem_total_mb) * 100)))
        : null;

    r.vramLbl.textContent = ascend ? 'HBM' : 'MEM';
    r.vramFill.className = 'gpu-nvbar-fill ' + (fault ? 'gpu-tone-fault' : loadToneClass(vramPct));
    r.vramFill.style.width = (vramPct != null ? vramPct : 0) + '%';
    let memLabel = fmtVram(g).replace(' GiB', 'G');
    if (freshDelta && freshDelta.memDeltaMb) {
      const sign = freshDelta.memDeltaMb > 0 ? '▲' : '▼';
      memLabel += ' ' + sign + (Math.abs(freshDelta.memDeltaMb) / 1024).toFixed(1) + 'G';
    }
    r.vramText.textContent = memLabel;
    r.vramPctEl.textContent = vramPct != null ? vramPct + '%' : '';

    r.utilLbl.textContent = ascend ? 'AIC' : rt === 'tpu' ? 'TPU' : 'GPU';
    r.utilFill.className = 'gpu-nvbar-fill ' + (fault ? 'gpu-tone-fault' : loadToneClass(utilPct));
    r.utilFill.style.width = (utilPct != null ? utilPct : 0) + '%';
    r.utilText.textContent = utilPct != null ? utilPct + '%' : '—';
    if (freshDelta && freshDelta.utilDelta) {
      r.utilDeltaEl.hidden = false;
      r.utilDeltaEl.className =
        'gpu-delta ' + (freshDelta.utilDelta > 0 ? 'gpu-delta-up' : 'gpu-delta-down');
      r.utilDeltaEl.textContent = (freshDelta.utilDelta > 0 ? '▲' : '▼') + Math.abs(freshDelta.utilDelta) + '%';
    } else {
      r.utilDeltaEl.hidden = true;
      r.utilDeltaEl.textContent = '';
    }

    r.envWrap.textContent = '';
    if (typeof g.temp_c === 'number') {
      r.envWrap.appendChild(el('span', 'gpu-temp ' + tempToneClass(g.temp_c), g.temp_c + '°C'));
    }
    if (typeof g.power_w === 'number') {
      r.envWrap.appendChild(
        el('span', 'gpu-power', g.power_limit_w != null ? g.power_w + '/' + g.power_limit_w + 'W' : g.power_w + 'W'),
      );
    }
    if (typeof g.fan_pct === 'number') {
      r.envWrap.appendChild(el('span', 'gpu-fan', g.fan_pct + '%'));
    }
    if (!r.envWrap.childNodes.length) r.envWrap.textContent = '—';

    // Inline canonical fault + warning + power_cap info pills
    r.faultBar.textContent = '';
    const reasons = cardFaultReasons(g);
    for (const reason of reasons) {
      const cls = reason.severity === 'critical' ? 'gpu-fault-pill' : 'gpu-warn-pill';
      const pill = el('span', cls, reason.summary);
      pill.title = reason.code + ': ' + reason.summary;
      r.faultBar.appendChild(pill);
    }
    if (Array.isArray(g.throttle) && g.throttle.some((x) => String(x).toLowerCase() === 'power_cap')) {
      r.faultBar.appendChild(el('span', 'gpu-info-pill', t('gpu.throttle.power_cap', null, 'Power cap')));
    }
    r.faultBar.hidden = r.faultBar.childNodes.length === 0;

    // L1 process attribution rows
    r.procsWrap.textContent = '';
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
      r.procsWrap.appendChild(plist);
    } else if (g.procs_state === 'off') {
      r.procsWrap.appendChild(
        el('div', 'gpu-proc-note muted small', t('gpu.procsOff', null, 'Process list disabled locally on this host')),
      );
    }
  }

  function buildHostCard(h, nowS, pageServerMs) {
    const card = el('div', 'card gpu-host-card');
    card.dataset.agentId = h.agent_id;

    const head = el('div', 'gpu-host-head');
    const titleWrap = el('div', 'gpu-host-title-wrap');
    const nameEl = el('strong', 'gpu-host-name');
    const badgesWrap = el('span', 'gpu-host-title-wrap');
    titleWrap.appendChild(nameEl);
    titleWrap.appendChild(badgesWrap);
    head.appendChild(titleWrap);

    const right = el('div', 'gpu-host-right');
    const freePill = el('span', 'gpu-free-pill mono');
    const copyBtn = el('button', 'gpu-copy-btn');
    copyBtn.type = 'button';
    copyBtn.addEventListener('click', () => {
      if (card._exportCmd) copyText(card._exportCmd);
    });
    right.appendChild(freePill);
    right.appendChild(copyBtn);
    head.appendChild(right);
    card.appendChild(head);

    const diagBanner = el('div', 'gpu-host-diag');
    diagBanner.hidden = true;
    card.appendChild(diagBanner);

    const loadStrip = el('div', 'gpu-host-load mono');
    loadStrip.hidden = true;
    card.appendChild(loadStrip);

    const emptyMsg = el('p', 'muted small');
    emptyMsg.hidden = true;
    card.appendChild(emptyMsg);

    const list = el('div', 'gpu-card-list');
    card.appendChild(list);

    card._refs = {
      nameEl,
      badgesWrap,
      freePill,
      copyBtn,
      diagBanner,
      loadStrip,
      emptyMsg,
      list,
      rowsByUuid: new Map(),
      miniFills: {},
    };
    updateHostCard(card, h, nowS, pageServerMs);
    return card;
  }

  function ensureMiniGauge(strip, refs, key, label) {
    if (!refs.miniFills[key]) {
      const box = el('div', 'gpu-mini-gauge');
      box.appendChild(el('span', 'gpu-mini-k', label));
      const track = el('div', 'gpu-mini-track');
      const fill = el('div', 'gpu-mini-fill');
      track.appendChild(fill);
      const val = el('span', 'gpu-mini-v');
      box.appendChild(track);
      box.appendChild(val);
      strip.appendChild(box);
      refs.miniFills[key] = { box, fill, val };
    }
    return refs.miniFills[key];
  }

  function updateHostCard(card, h, nowS, pageServerMs) {
    const r = card._refs;
    const isOffline = !h.is_online || h.freshness === 'offline';
    card.classList.toggle('gpu-host-offline', isOffline);

    r.nameEl.textContent = hostDisplayName(h);
    r.badgesWrap.textContent = '';
    const sb = sourceBadgeInfo(h);
    if (sb) r.badgesWrap.appendChild(el('span', sb.cls, sb.label));
    const fb = freshnessBadgeInfo(h, pageServerMs);
    r.badgesWrap.appendChild(el('span', fb.cls, fb.label));
    const stB = hostStatusBadgeInfo(h);
    if (stB) r.badgesWrap.appendChild(el('span', stB.cls, stB.label));
    if (h.driver_version) {
      r.badgesWrap.appendChild(el('span', 'gpu-meta-pill mono', 'drv ' + h.driver_version));
    }

    r.freePill.textContent = t(
      'gpu.hostFreeCount',
      { free: h.free_count || 0, total: h.total_count || 0 },
      (h.free_count || 0) + '/' + (h.total_count || 0) + ' free',
    );
    const exportCmd = buildFreeExportCommand(h);
    card._exportCmd = exportCmd;
    if (exportCmd) {
      r.copyBtn.hidden = false;
      r.copyBtn.textContent = t('gpu.copyFree', null, 'Copy free GPUs');
      r.copyBtn.title = exportCmd;
    } else {
      r.copyBtn.hidden = true;
    }

    // Host diagnostic banner (non-ok status, status_detail, or host fault reasons)
    const showDiag =
      !isOffline &&
      ((h.status && h.status !== 'ok') ||
        Boolean(h.status_detail) ||
        (Array.isArray(h.fault_reasons) && h.fault_reasons.length > 0));
    if (showDiag) {
      const sevCls =
        h.host_fault_severity === 'critical'
          ? 'gpu-host-diag-critical'
          : h.host_fault_severity === 'warning' || h.status === 'limited'
            ? 'gpu-host-diag-warn'
            : 'gpu-host-diag-info';
      r.diagBanner.className = 'gpu-host-diag ' + sevCls;
      const parts = [];
      const guide = t('gpu.diag.' + h.status, null, '');
      if (guide) parts.push(guide);
      if (h.status_detail && h.status_detail !== guide) parts.push(h.status_detail);
      if (!parts.length && Array.isArray(h.fault_reasons) && h.fault_reasons.length) {
        parts.push(h.fault_reasons.map((x) => x.summary).join(' · '));
      }
      r.diagBanner.textContent = parts.join(' — ');
      r.diagBanner.hidden = !r.diagBanner.textContent;
    } else {
      r.diagBanner.hidden = true;
    }

    // Host resource mini-bars (reused DOM for smooth CSS transitions)
    if (h.host) {
      let anyGauge = false;
      if (typeof h.host.cpu_pct === 'number') {
        const g = ensureMiniGauge(r.loadStrip, r, 'cpu', 'CPU');
        g.box.hidden = false;
        g.fill.className = 'gpu-mini-fill ' + loadToneClass(h.host.cpu_pct);
        g.fill.style.width = Math.max(0, Math.min(100, Math.round(h.host.cpu_pct))) + '%';
        const loadTxt = typeof h.host.load1 === 'number' ? ' · L ' + h.host.load1.toFixed(1) : '';
        g.val.textContent = Math.round(h.host.cpu_pct) + '%' + loadTxt;
        anyGauge = true;
      } else if (r.miniFills.cpu) {
        r.miniFills.cpu.box.hidden = true;
      }
      if (typeof h.host.mem_used_mb === 'number' && typeof h.host.mem_total_mb === 'number' && h.host.mem_total_mb > 0) {
        const mp = Math.round((h.host.mem_used_mb / h.host.mem_total_mb) * 100);
        const g = ensureMiniGauge(r.loadStrip, r, 'mem', 'MEM');
        g.box.hidden = false;
        g.fill.className = 'gpu-mini-fill ' + loadToneClass(mp);
        g.fill.style.width = Math.max(0, Math.min(100, mp)) + '%';
        g.val.textContent = (h.host.mem_used_mb / 1024).toFixed(1) + '/' + (h.host.mem_total_mb / 1024).toFixed(1) + 'G';
        anyGauge = true;
      } else if (r.miniFills.mem) {
        r.miniFills.mem.box.hidden = true;
      }
      if (typeof h.host.disk_root_used_gb === 'number' && typeof h.host.disk_root_total_gb === 'number' && h.host.disk_root_total_gb > 0) {
        const dp = Math.min(100, Math.max(0, Math.round((h.host.disk_root_used_gb / h.host.disk_root_total_gb) * 100)));
        const g = ensureMiniGauge(r.loadStrip, r, 'dsk', 'DSK');
        g.box.hidden = false;
        g.fill.className = 'gpu-mini-fill ' + loadToneClass(dp);
        g.fill.style.width = dp + '%';
        g.val.textContent = dp + '%';
        anyGauge = true;
      } else if (r.miniFills.dsk) {
        r.miniFills.dsk.box.hidden = true;
      }
      const rx = fmtNetBps(h.host.net_rx_bps);
      const tx = fmtNetBps(h.host.net_tx_bps);
      if (rx && tx) {
        if (!r.miniFills.net) {
          const netEl = el('span', 'gpu-mini-net');
          r.loadStrip.appendChild(netEl);
          r.miniFills.net = netEl;
        }
        r.miniFills.net.hidden = false;
        r.miniFills.net.textContent = '↓' + rx + ' ↑' + tx;
        anyGauge = true;
      } else if (r.miniFills.net) {
        r.miniFills.net.hidden = true;
      }
      r.loadStrip.hidden = !anyGauge;
    } else {
      r.loadStrip.hidden = true;
    }

    // Reconcile per-GPU rows by UUID
    const gpus = Array.isArray(h.gpus) ? h.gpus : [];
    if (!gpus.length) {
      r.list.textContent = '';
      r.rowsByUuid.clear();
      r.emptyMsg.hidden = false;
      r.emptyMsg.textContent =
        h.status === 'off_local'
          ? t('gpu.hostOffLocal', null, 'GPU telemetry is disabled locally on this host.')
          : t('gpu.noTelemetry', null, 'No GPU telemetry reported yet.');
      return;
    }
    r.emptyMsg.hidden = true;

    const nextUuids = new Set(gpus.map((g) => g.uuid));
    for (const [uuid, node] of r.rowsByUuid.entries()) {
      if (!nextUuids.has(uuid)) {
        node.remove();
        r.rowsByUuid.delete(uuid);
      }
    }
    let prevNode = null;
    for (const g of gpus) {
      let row = r.rowsByUuid.get(g.uuid);
      if (!row) {
        row = buildCardRow(h, g, nowS);
        r.rowsByUuid.set(g.uuid, row);
      } else {
        updateCardRow(row, h, g, nowS);
      }
      const expectedNext = prevNode ? prevNode.nextSibling : r.list.firstChild;
      if (row !== expectedNext) {
        r.list.insertBefore(row, expectedNext);
      }
      prevNode = row;
    }
  }

  const hostNodesById = new Map();

  function renderFleet() {
    const page = st.lastFleet;
    renderSummary(page ? page.summary : null);
    renderRecentChanges();

    const hostsEl = $('gpu-hosts');
    const emptyEl = $('gpu-empty');
    const resetBtn = $('gpu-empty-reset');
    if (!hostsEl || !emptyEl) return;

    if (!page || !Array.isArray(page.hosts) || page.hosts.length === 0) {
      hostsEl.textContent = '';
      hostNodesById.clear();
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
      if (resetBtn) hide(resetBtn);
      show(emptyEl);
      return;
    }

    const filtered = filterHosts(page.hosts, st.filter, st.search);
    if (!filtered.length) {
      hostsEl.textContent = '';
      hostNodesById.clear();
      const title = $('gpu-empty-title');
      const body = $('gpu-empty-body');
      if (title) title.textContent = t('gpu.empty.filteredTitle', null, 'No matching GPU servers');
      if (body) body.textContent = t('gpu.empty.filteredBody', null, 'Try clearing the search query or state filter.');
      if (resetBtn) show(resetBtn);
      show(emptyEl);
      return;
    }

    hide(emptyEl);
    const nowS = page.server_time_ms > 0 ? Math.floor(page.server_time_ms / 1000) : Math.floor(Date.now() / 1000);
    const serverMs = page.server_time_ms || 0;
    const nextIds = new Set(filtered.map((h) => h.agent_id));
    for (const [id, node] of hostNodesById.entries()) {
      if (!nextIds.has(id)) {
        node.remove();
        hostNodesById.delete(id);
      }
    }
    let prevNode = null;
    for (const h of filtered) {
      let card = hostNodesById.get(h.agent_id);
      if (!card) {
        card = buildHostCard(h, nowS, serverMs);
        hostNodesById.set(h.agent_id, card);
      } else {
        updateHostCard(card, h, nowS, serverMs);
      }
      const expectedNext = prevNode ? prevNode.nextSibling : hostsEl.firstChild;
      if (card !== expectedNext) {
        hostsEl.insertBefore(card, expectedNext);
      }
      prevNode = card;
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
    const failures = st.tab === 'users' ? st.usersFailures : st.fleetFailures;
    const nextRetryAt = st.tab === 'users' ? st.usersNextRetryAt : st.fleetNextRetryAt;
    const okAt = st.tab === 'users' ? st.lastUsersOkAt : st.lastFleetOkAt;
    if (failures > 0 && nextRetryAt > Date.now()) {
      const sec = Math.max(1, Math.ceil((nextRetryAt - Date.now()) / 1000));
      node.textContent = t('gpu.pollFailed', { sec }, 'Poll failed · retrying in ' + sec + 's');
      return;
    }
    if (!okAt) {
      node.textContent = '';
      return;
    }
    node.textContent = t('gpu.updatedAt', { time: R.fmtRelative(okAt) }, 'Poll ok ' + R.fmtRelative(okAt));
  }

  function clearTimer() {
    if (st.timer) {
      clearTimeout(st.timer);
      st.timer = null;
    }
  }

  function ensureTickTimer() {
    if (st.tickTimer) return;
    st.tickTimer = setInterval(() => {
      if (currentView() !== 'gpu' || document.hidden) return;
      updateTimestamp();
      if (st.tab === 'fleet' && st.recentChanges.length) renderRecentChanges();
    }, 1000);
  }

  function stopTickTimer() {
    if (st.tickTimer) {
      clearInterval(st.tickTimer);
      st.tickTimer = null;
    }
  }

  function scheduleNext() {
    clearTimer();
    if (currentView() !== 'gpu' || document.hidden) return;
    const failures = st.tab === 'users' ? st.usersFailures : st.fleetFailures;
    let delay;
    if (failures > 0) {
      delay = BACKOFF_MS[Math.min(failures - 1, BACKOFF_MS.length - 1)];
    } else if (st.tab === 'users') {
      delay = CACHED_POLL_MS;
    } else {
      delay = st.live ? LIVE_POLL_MS : CACHED_POLL_MS;
    }
    if (st.tab === 'users') st.usersNextRetryAt = failures > 0 ? Date.now() + delay : 0;
    else st.fleetNextRetryAt = failures > 0 ? Date.now() + delay : 0;
    updateTimestamp();
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
        waitMs: forceWait && st.live ? 1200 : 0,
        hosts: [],
      });
      if (seq !== st.fleetSeq) return;
      trackFleetChanges(page);
      st.lastFleet = page;
      st.lastFleetOkAt = Date.now();
      st.fleetFailures = 0;
      st.fleetNextRetryAt = 0;
      st.fleetError = null;
      renderErrorBanner();
      renderFleet();
      updateTimestamp();
    } catch (err) {
      if (seq !== st.fleetSeq) return;
      st.fleetFailures += 1;
      st.fleetError = t('gpu.loadError', { err: parseErr(err) }, 'GPU telemetry unavailable: ' + parseErr(err));
      renderErrorBanner();
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
      st.lastUsersOkAt = Date.now();
      st.usersFailures = 0;
      st.usersNextRetryAt = 0;
      st.usersError = null;
      renderErrorBanner();
      renderUsers();
      updateTimestamp();
    } catch (err) {
      if (seq !== st.usersSeq) return;
      st.usersFailures += 1;
      st.usersError = t('gpu.loadError', { err: parseErr(err) }, 'GPU usage unavailable: ' + parseErr(err));
      renderErrorBanner();
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
    const liveWrap = $('gpu-live-wrap');
    if (liveWrap) liveWrap.hidden = st.tab === 'users';
    renderErrorBanner();
    updateTimestamp();
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
        invoke('cmd_open_gpu_web').catch((e) => {
          if (st.tab === 'users') st.usersError = parseErr(e);
          else st.fleetError = parseErr(e);
          renderErrorBanner();
        });
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
      btn.addEventListener('click', () => setFilter(btn.dataset.gpuFilter || 'all'));
    });

    document.querySelectorAll('#gpu-summary .gpu-kpi').forEach((kpi) => {
      kpi.addEventListener('click', () => {
        const target = kpi.dataset.gpuKpiFilter || 'all';
        setFilter(st.filter === target && target !== 'all' ? 'all' : target);
      });
    });

    const resetBtn = $('gpu-empty-reset');
    if (resetBtn) {
      resetBtn.addEventListener('click', () => {
        st.search = '';
        if (search) search.value = '';
        setFilter('all');
      });
    }

    const clearChangesBtn = $('gpu-changes-clear');
    if (clearChangesBtn) {
      clearChangesBtn.addEventListener('click', () => {
        st.recentChanges = [];
        renderRecentChanges();
      });
    }

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
        ensureTickTimer();
        if (st.tab === 'users') void fetchUsers();
        else void fetchFleet(true);
      } else {
        clearTimer();
        stopTickTimer();
      }
    });

    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        clearTimer();
      } else if (currentView() === 'gpu') {
        ensureTickTimer();
        if (st.tab === 'users') void fetchUsers();
        else void fetchFleet(false);
      }
    });

    document.addEventListener('meshharbor:lang', () => {
      renderFleet();
      renderUsers();
      renderErrorBanner();
      updateTimestamp();
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', wire);
  } else {
    wire();
  }
})(typeof window !== 'undefined' ? window : globalThis);
