// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
/*
 * Devices view (FR-84 D5c): the devices THIS device's private network lets it
 * see — itself included — as the org's server lists them, and how this device
 * reaches each of them right now.
 *
 * Two sources, merged:
 *   - the SERVER's list (`cmd_devices` → LocalAPI `Devices` → the daemon asks
 *     `/api/agent/self/devices` with the org's agent token): display names,
 *     OS, version, presence, MagicDNS, tags. Searched, sorted and paged on the
 *     server — the grid only renders a page. Asked every 30 s, and only while
 *     this view is on screen and the window is visible; at once on entering
 *     the view and on every search / sort / page / size / org change and after
 *     a Ping; after a failure the next ask backs off 30 → 60 → 120 s.
 *   - THIS node's live peer view (`cmd_device_view`, polled every 2 s by
 *     app.js): only the connection / RTT / online-dot / IPv6 cells are patched
 *     from it (a device's overlay node id ↔ PeerInfo.node_id, else its agent
 *     id ↔ PeerInfo.agent_id).
 *
 * Failure is a STATE, never an empty list:
 *   - a failed refresh keeps the last good page and says "showing data from
 *     N min ago — reason" (stale-while-error), with a sequence guard so a slow
 *     answer never overwrites a newer one;
 *   - a service older than the list (`unsupported_daemon`) or a server older
 *     than the route (`unsupported_server`) falls back to the pre-FR-84 table
 *     — the peers this device reaches directly — with a one-line "update the
 *     service/server" note, and keeps asking at the slowest cadence so the
 *     page upgrades itself once the service or server does;
 *   - any other failure with no page yet shows those same peers, plus the
 *     reason.
 *
 * The mesh graph (mesh.js) is fed from `cmd_mesh` on its own 60 s cadence.
 *
 * Every string here came from another device or the server: textContent
 * only, never innerHTML.
 */
(function () {
  'use strict';
  const R = window.Roomler;
  const { $, invoke, show, hide, fmtRelative, on, get, currentView } = R;

  // ConnectionType (snake_case) → label; the badge class is `badge-<key>`.
  const CONN = {
    direct: 'Direct',
    relay: 'Relay',
    tunnel: 'Tunnel',
    blocked: 'Blocked',
    offline: 'Offline',
  };
  const PAGE_SIZES = [10, 25, 50, 100];
  const REFRESH_MS = 30000;
  const BACKOFF_MS = [30000, 60000, 120000];
  const MESH_MS = 60000;
  const SEARCH_DEBOUNCE_MS = 300;
  const PRIMARY = 'primary';
  const PREF_PAGE_SIZE = 'meshharbor-desktop:devices-per-page';
  // The two causes that mean "this cannot work until something is updated":
  // fall back to the peers table and name what to update.
  const LEGACY = { unsupported_daemon: 'device service', unsupported_server: 'server' };

  const st = {
    org: null, // the enrollment label on screen
    page: 1,
    perPage: 25,
    q: '',
    sort: null, // a server sort key, or null = online first, then name
    dir: 'asc',
    mode: 'server', // 'server' | 'legacy'
    lastPage: null, // the last GOOD page for this org + query
    lastGoodAt: 0,
    lastAskAt: 0,
    error: null, // {code, message, status} of the last failed ask
    failures: 0,
    seq: 0,
    applied: 0,
    inFlight: 0,
    nextAt: 0,
    timer: null,
  };
  const mesh = {
    view: null,
    error: null,
    failures: 0,
    lastGoodAt: 0,
    lastAskAt: 0,
    seq: 0,
    applied: 0,
    inFlight: 0,
    timer: null,
  };
  // Last Ping outcome per target, so a result survives row patches.
  const pingResults = new Map();

  let grid = null;
  let graph = null;
  let searchTimer = null;

  /* ── small helpers ──────────────────────────────────────────────── */

  function setText(el, text) {
    if (el && el.textContent !== text) el.textContent = text;
  }
  function setClass(el, cls) {
    if (el && el.getAttribute('class') !== cls) el.setAttribute('class', cls);
  }
  function storageGet(key) {
    try {
      return window.localStorage.getItem(key);
    } catch (_) {
      return null;
    }
  }
  function storageSet(key, value) {
    try {
      window.localStorage.setItem(key, value);
    } catch (_) {
      /* blocked storage: the setting lasts for this run only */
    }
  }
  function shortId(id) {
    const s = String(id || '');
    return s.length > 10 ? s.slice(0, 8) + '…' : s;
  }
  function isHex24(s) {
    return /^[0-9a-f]{24}$/i.test(String(s || ''));
  }
  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  /** "less than a minute ago" / "N min ago" / "N h ago" — how old the data
   *  on screen is. */
  function agoText(epochMs) {
    const s = Math.max(0, (Date.now() - epochMs) / 1000);
    if (s < 60) return 'less than a minute ago';
    const m = Math.round(s / 60);
    if (m < 60) return m + ' min ago';
    return Math.round(m / 60) + ' h ago';
  }

  /** On screen: the Devices view is current and the window is visible. */
  function active() {
    return currentView() === 'devices' && document.visibilityState === 'visible';
  }

  /** A rejected cmd_devices / cmd_mesh carries `{code, message, status?}`. */
  function parseFailure(err) {
    const text = String(err);
    try {
      const v = JSON.parse(text);
      if (v && typeof v.code === 'string') {
        return { code: v.code, message: String(v.message || v.code), status: v.status };
      }
    } catch (_) {
      /* not JSON — a bridge-level rejection */
    }
    return { code: 'error', message: text };
  }

  /* ── orgs ───────────────────────────────────────────────────────── */

  function orgRows() {
    const dv = get('deviceView');
    return (dv && dv.status && dv.status.orgs) || [];
  }
  function primaryLabel() {
    const p = orgRows().find((o) => o.primary);
    return (p && p.label) || PRIMARY;
  }
  function isPrimary(label) {
    return !label || label === PRIMARY || label === primaryLabel();
  }
  /** What the commands get: nothing for the primary, else the label. */
  function orgArg() {
    return isPrimary(st.org) ? null : st.org;
  }
  function prefKey() {
    return 'meshharbor-desktop:grid-cols:' + (st.org || PRIMARY) + ':devices';
  }

  /** This device's live peers for the org on screen. A single-org daemon
   *  stamps no org on its peers — those are the primary's. */
  function orgPeers(dv) {
    const peers = (dv && dv.peers) || [];
    const primary = isPrimary(st.org);
    return peers.filter((p) => (p.org ? p.org === st.org : primary));
  }

  /* ── the live merge ─────────────────────────────────────────────── */

  function liveContext() {
    const dv = get('deviceView');
    const byNode = new Map();
    const byAgent = new Map();
    for (const p of orgPeers(dv)) {
      if (p.node_id) byNode.set(p.node_id, p);
      if (p.agent_id) byAgent.set(p.agent_id, p);
    }
    const orgRow = orgRows().find((o) => o.label === st.org);
    const connected = orgRow
      ? !!orgRow.connected
      : !!(dv && dv.status && dv.status.connected);
    return {
      peerFor(row) {
        if (row.is_self) return null;
        return (
          (row.overlay_node_id && byNode.get(row.overlay_node_id)) ||
          (row.kind === 'agent' && row.id && byAgent.get(row.id)) ||
          null
        );
      },
      selfConnected: connected,
    };
  }

  /* ── columns ────────────────────────────────────────────────────── */
  // Mirrors the web grid's catalog (ui/src/components/admin/AgentsSection.vue)
  // with the same server sort keys (crates/api/src/routes/device.rs
  // SORT_KEYS), plus the two columns only this device can fill: its live
  // Connection (+RTT) and a Ping. Actions stay leftmost, as on the web, so
  // they never fall off the right edge of a narrow window.

  function textCol(key, title, sort, value, cls) {
    return {
      key,
      title,
      sort,
      cls,
      build(td) {
        return { td };
      },
      update(s, row) {
        setText(s.td, value(row) || '—');
      },
    };
  }

  const COLUMNS = [
    {
      key: 'actions',
      title: '',
      chooserTitle: 'Actions',
      cls: 'dv-col-actions',
      build(td) {
        const s = { agentId: null };
        const btn = el('button', 'sm', 'View screen');
        btn.type = 'button';
        btn.title = 'Open the remote-control viewer in your browser (sign-in required)';
        btn.addEventListener('click', async () => {
          if (!s.agentId) return;
          btn.disabled = true;
          try {
            await invoke('cmd_open_remote', { agentId: s.agentId, org: orgArg() });
            btn.classList.remove('is-error');
          } catch (err) {
            btn.title = String(err);
            btn.classList.add('is-error');
          } finally {
            btn.disabled = false;
          }
        });
        td.appendChild(btn);
        s.btn = btn;
        return s;
      },
      update(s, row) {
        // Agents only (a tunnel client has no screen), never this device.
        const ok = row.kind === 'agent' && !row.is_self && isHex24(row.id);
        s.agentId = ok ? row.id : null;
        s.btn.hidden = !ok;
      },
    },
    {
      key: 'name',
      title: 'Name',
      sort: 'name',
      live: true,
      cls: 'dv-col-name',
      build(td) {
        const line = el('div', 'dv-name-line');
        const dot = el('span', 'dot dot-off');
        const title = el('span', 'dv-name-title');
        const chips = el('span', 'dv-chips');
        line.append(dot, title, chips);
        const sub = el('div', 'muted small dv-sub');
        sub.hidden = true;
        td.append(line, sub);
        return { dot, title, chips, sub, chipKey: null };
      },
      update(s, row, ctx) {
        // The dot is THIS node's live view when it has the peer; otherwise
        // the server's presence (stale = amber).
        const peer = ctx.peerFor(row);
        let cls;
        let tip;
        if (row.is_self) {
          cls = ctx.selfConnected ? 'dot dot-on' : 'dot dot-warn';
          tip = ctx.selfConnected ? 'connected to the server' : 'not connected to the server';
        } else if (peer) {
          cls = peer.online ? 'dot dot-on' : 'dot dot-off';
          tip = peer.online ? 'reachable on the private network' : 'not reachable right now';
        } else {
          cls =
            row.presence === 'online' ? 'dot dot-on' : row.presence === 'stale' ? 'dot dot-warn' : 'dot dot-off';
          tip = row.presence ? 'server: ' + row.presence : '';
        }
        setClass(s.dot, cls);
        if (s.dot.title !== tip) s.dot.title = tip;
        setText(s.title, row.display_name || row.name || shortId(row.id));
        // The machine's own name, muted, when an admin label replaces it.
        const showSub = !!(row.display_name && row.name && row.display_name !== row.name);
        setText(s.sub, showSub ? row.name : '');
        s.sub.hidden = !showSub;
        const chipKey = (row.is_self ? 's' : '') + (row.ephemeral ? 'e' : '');
        if (chipKey !== s.chipKey) {
          const chips = [];
          if (row.is_self) chips.push(el('span', 'chip chip-self', 'this device'));
          if (row.ephemeral) {
            const c = el('span', 'chip chip-warn', 'ephemeral');
            c.title = 'Removes itself after inactivity or on a clean shutdown; removal is final';
            chips.push(c);
          }
          s.chips.replaceChildren(...chips);
          s.chipKey = chipKey;
        }
      },
    },
    {
      key: 'connection',
      title: 'Connection',
      live: true,
      cls: 'dv-col-conn',
      build(td) {
        const badge = el('span', 'badge badge-offline');
        const rtt = el('span', 'muted small');
        const note = el('span', 'muted small');
        td.append(badge, rtt, note);
        return { badge, rtt, note };
      },
      update(s, row, ctx) {
        if (row.is_self) {
          s.badge.hidden = true;
          setText(s.rtt, '');
          setText(s.note, 'this device');
          return;
        }
        const p = ctx.peerFor(row);
        if (!p) {
          s.badge.hidden = true;
          setText(s.rtt, '');
          setText(s.note, '—');
          s.note.title = 'Not in this device’s live peer list';
          return;
        }
        const key = String(p.connection || 'offline').toLowerCase();
        const stalled = p.stalled && (key === 'direct' || key === 'relay');
        s.badge.hidden = false;
        setClass(s.badge, 'badge badge-' + (stalled ? 'blocked' : key));
        setText(s.badge, stalled ? 'Stalled' : CONN[key] || key);
        // For a relayed peer, which relay and both endpoints (same-vs-cross
        // worker triage), as the CLI's CONN column says it.
        const kind = p.relay_kind ? p.relay_kind + (p.relay_transport ? '/' + p.relay_transport : '') : '';
        const tip =
          p.relay_local || p.relay_dst
            ? 'relay' + (kind ? ' ' + kind : '') + ' ' + (p.relay_local || '?') + ' → ' + (p.relay_dst || '?')
            : kind;
        if (s.badge.title !== tip) s.badge.title = tip;
        setText(s.rtt, p.rtt_ms != null ? ' · ' + p.rtt_ms + ' ms' : '');
        setText(s.note, '');
      },
    },
    {
      key: 'ping',
      title: 'Ping',
      live: true,
      cls: 'ping-cell',
      build(td) {
        const btn = el('button', 'sm', 'Ping');
        btn.type = 'button';
        const out = el('span', 'ping-result');
        const s = { btn, out, target: null, busy: false };
        btn.addEventListener('click', () => void runPing(s));
        td.append(btn, document.createTextNode(' '), out);
        return s;
      },
      update(s, row, ctx) {
        const p = ctx.peerFor(row);
        s.target = row.is_self ? null : (p && p.overlay_ip) || row.overlay_ip || null;
        s.btn.hidden = !!row.is_self;
        if (s.busy) return;
        s.btn.disabled = !s.target;
        s.btn.title = s.target ? 'Ping ' + s.target + ' over the private network' : 'No overlay address to ping';
        paintPing(s.out, s.target ? pingResults.get(s.target) : null);
      },
    },
    {
      key: 'status',
      title: 'Status',
      sort: 'status',
      build(td) {
        const chip = el('span', 'chip chip-muted');
        td.appendChild(chip);
        return { chip };
      },
      update(s, row) {
        const pres = row.presence || '';
        const cls = pres === 'online' ? 'chip chip-ok' : pres === 'stale' ? 'chip chip-warn' : 'chip chip-muted';
        setClass(s.chip, cls);
        setText(s.chip, pres || '—');
      },
    },
    textCol('os', 'OS', 'os', (r) => r.os),
    textCol('version', 'Version', 'version', (r) => r.version, 'mono'),
    {
      key: 'overlay_ip',
      title: 'Overlay IP',
      sort: 'overlay_ip',
      live: true,
      cls: 'mono',
      build(td) {
        const v4 = document.createTextNode('');
        const v6 = el('div', 'muted small mono');
        v6.hidden = true;
        td.append(v4, v6);
        return { v4, v6 };
      },
      update(s, row, ctx) {
        const text = row.overlay_ip || '—';
        if (s.v4.data !== text) s.v4.data = text;
        const p = ctx.peerFor(row);
        const six = (p && p.overlay_ip6) || '';
        setText(s.v6, six);
        s.v6.hidden = !six;
      },
    },
    textCol('magic_dns', 'MagicDNS', 'magic_dns', (r) => r.magic_dns_fqdn || r.magic_dns_name, 'mono small'),
    {
      key: 'tags',
      title: 'Tags',
      build(td) {
        return { td, sig: null };
      },
      update(s, row) {
        const tags = Array.isArray(row.tags) ? row.tags : [];
        const sig = tags.join('\u0000');
        if (sig === s.sig) return;
        s.sig = sig;
        if (!tags.length) {
          s.td.replaceChildren(document.createTextNode('—'));
          return;
        }
        s.td.replaceChildren(...tags.map((t) => el('span', 'tag-chip', t)));
      },
    },
    textCol('kind', 'Kind', 'kind', (r) => (r.kind === 'tunnel_client' ? 'tunnel' : r.kind ? 'device' : '')),
    {
      key: 'last_seen_at',
      title: 'Last seen',
      sort: 'last_seen_at',
      cls: 'small',
      build(td) {
        return { td };
      },
      update(s, row) {
        const t = row.last_seen_at ? Date.parse(row.last_seen_at) : NaN;
        setText(s.td, Number.isFinite(t) ? fmtRelative(t) : '—');
        const title = Number.isFinite(t) ? new Date(t).toLocaleString() : '';
        if (s.td.title !== title) s.td.title = title;
      },
    },
  ];

  function rowKey(row) {
    return row.legacy ? 'peer:' + (row.overlay_node_id || row.id) : (row.kind || 'agent') + ':' + row.id;
  }

  /* ── Ping ───────────────────────────────────────────────────────── */

  function paintPing(out, result) {
    out.className = 'ping-result' + (result ? (result.ok ? ' ok' : ' err') : '');
    setText(out, result ? result.text : '');
    if (result && result.title) out.title = result.title;
    else out.removeAttribute('title');
  }

  async function runPing(s) {
    const target = s.target;
    if (!target || s.busy) return;
    s.busy = true;
    s.btn.disabled = true;
    const label = s.btn.textContent;
    s.btn.textContent = '…';
    paintPing(s.out, null);
    try {
      const r = await invoke('cmd_ping', { target });
      pingResults.set(target, { ok: true, text: Number(r.rtt_ms).toFixed(1) + ' ms' });
    } catch (err) {
      // A short reason inline, the whole of it on hover.
      const msg = String(err);
      const short = msg.length > 60 ? msg.slice(0, 57) + '…' : msg;
      pingResults.set(target, { ok: false, text: 'failed — ' + short, title: msg });
    } finally {
      s.busy = false;
      s.btn.textContent = label;
      s.btn.disabled = false;
      paintPing(s.out, pingResults.get(target));
      // A ping is a person asking "is it there?" — ask the server too.
      void refresh({ force: true });
    }
  }

  /* ── the list: ask, apply, schedule ─────────────────────────────── */

  async function refresh(opts) {
    if (!active() || !st.org || !grid) return;
    const force = !!(opts && opts.force);
    // A poll tick never stacks behind a slow ask; a person's change does.
    if (st.inFlight > 0 && !force) return;
    clearTimeout(st.timer);
    const org = st.org;
    const mine = ++st.seq;
    st.inFlight += 1;
    if (opts && opts.loading) $('dv-grid').classList.add('is-loading');
    let page = null;
    let failure = null;
    try {
      page = await invoke('cmd_devices', {
        org: orgArg(),
        page: st.page,
        perPage: st.perPage,
        q: st.q || null,
        sort: st.sort,
        dir: st.sort ? st.dir : null,
      });
    } catch (err) {
      failure = parseFailure(err);
    } finally {
      st.inFlight -= 1;
      if (st.inFlight === 0) $('dv-grid').classList.remove('is-loading');
    }
    // Another org, or a newer ask already answered: this one is history.
    if (org !== st.org || mine < st.applied) return;
    st.applied = mine;
    st.lastAskAt = Date.now();
    if (page) {
      // The list shrank under a later page (a search, a removal): step back.
      if ((page.items || []).length === 0 && page.total > 0 && st.page > 1) {
        st.page = Math.max(1, Number(page.total_pages) || 1);
        void refresh({ force: true });
        return;
      }
      st.mode = 'server';
      st.lastPage = page;
      st.lastGoodAt = Date.now();
      st.error = null;
      st.failures = 0;
    } else {
      st.error = failure;
      st.failures += 1;
      if (LEGACY[failure.code]) {
        st.mode = 'legacy';
        st.lastPage = null;
      }
    }
    schedule();
    paint();
  }

  function schedule() {
    clearTimeout(st.timer);
    if (!active()) return;
    let delay = REFRESH_MS;
    if (st.mode === 'legacy') delay = BACKOFF_MS[BACKOFF_MS.length - 1];
    else if (st.error) delay = BACKOFF_MS[Math.min(st.failures, BACKOFF_MS.length - 1)];
    st.nextAt = Date.now() + delay;
    st.timer = setTimeout(() => void refresh(), delay);
  }

  /* ── the list: what to show ─────────────────────────────────────── */

  /** The pre-FR-84 table as rows: this device, then the peers it reaches
   *  directly — the fallback when the server list is not available. */
  function legacyRows(dv) {
    const s = (dv && dv.status) || {};
    const orgRow = orgRows().find((o) => o.label === st.org);
    const out = [
      {
        legacy: true,
        kind: 'agent',
        id: (orgRow && orgRow.agent_id) || s.node_id || 'self',
        name: s.name || 'this device',
        display_name: null,
        os: '',
        version: s.version || '',
        presence: (orgRow ? orgRow.connected : s.connected) ? 'online' : 'offline',
        overlay_ip: isPrimary(st.org) ? s.overlay_ip || null : null,
        overlay_node_id: null,
        tags: [],
        is_self: true,
      },
    ];
    for (const p of orgPeers(dv)) {
      out.push({
        legacy: true,
        kind: p.agent_id ? 'agent' : 'tunnel_client',
        id: p.agent_id || p.node_id,
        name: p.name || '',
        display_name: null,
        os: '',
        version: '',
        presence: p.online ? 'online' : 'offline',
        last_seen_at: p.last_seen_ms ? new Date(p.last_seen_ms).toISOString() : '',
        overlay_ip: p.overlay_ip || null,
        overlay_node_id: p.node_id,
        magic_dns_name: null,
        tags: [],
        is_self: false,
      });
    }
    return out;
  }

  const PRESENCE_RANK = { online: 0, stale: 1, offline: 2 };

  function ipKey(ip) {
    const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip || '');
    return m ? ((+m[1] * 256 + +m[2]) * 256 + +m[3]) * 256 + +m[4] : null;
  }

  function localCompare(a, b, key) {
    const name = (r) => String(r.display_name || r.name || '').toLowerCase();
    switch (key) {
      case 'status':
        return (PRESENCE_RANK[a.presence] ?? 3) - (PRESENCE_RANK[b.presence] ?? 3);
      case 'overlay_ip': {
        const x = ipKey(a.overlay_ip);
        const y = ipKey(b.overlay_ip);
        if (x === y) return 0;
        if (x === null) return 1; // no address sorts last, as on the server
        if (y === null) return -1;
        return x - y;
      }
      case 'magic_dns':
        return String(a.magic_dns_fqdn || a.magic_dns_name || '').localeCompare(
          String(b.magic_dns_fqdn || b.magic_dns_name || ''),
        );
      case 'kind':
      case 'os':
      case 'version':
      case 'last_seen_at':
        return String(a[key] || '').localeCompare(String(b[key] || ''));
      default:
        return name(a).localeCompare(name(b));
    }
  }

  /** Search + sort + page the fallback rows here, by the server's rules. */
  function localQuery(rows) {
    const q = st.q.trim().toLowerCase();
    const hay = (r) =>
      [r.name, r.display_name, r.os, r.version, r.overlay_ip, r.magic_dns_name, r.magic_dns_fqdn]
        .concat(r.tags || [])
        .filter(Boolean)
        .map((v) => String(v).toLowerCase());
    const out = q ? rows.filter((r) => hay(r).some((v) => v.includes(q))) : rows.slice();
    out.sort((a, b) => {
      let o;
      if (!st.sort) {
        o = (PRESENCE_RANK[a.presence] ?? 3) - (PRESENCE_RANK[b.presence] ?? 3) || localCompare(a, b, 'name');
      } else {
        o = localCompare(a, b, st.sort);
        if (st.dir === 'desc') o = -o;
      }
      return o || String(a.id).localeCompare(String(b.id));
    });
    return out;
  }

  function currentRows(dv) {
    if (st.mode === 'server' && st.lastPage) {
      const p = st.lastPage;
      return {
        rows: p.items || [],
        total: Number(p.total) || 0,
        page: Number(p.page) || st.page,
        totalPages: Math.max(1, Number(p.total_pages) || 1),
        perPage: Number(p.per_page) || st.perPage,
        source: 'server',
        envelope: p,
      };
    }
    // Before the first answer (and while it has not failed), show nothing
    // rather than a list that is about to be replaced.
    if (st.mode === 'server' && !st.error) {
      return { rows: [], total: 0, page: 1, totalPages: 1, perPage: st.perPage, source: 'loading' };
    }
    const all = localQuery(legacyRows(dv));
    const totalPages = Math.max(1, Math.ceil(all.length / st.perPage));
    const page = Math.min(Math.max(1, st.page), totalPages);
    st.page = page; // a search that shrank the list must not strand the pager
    const start = (page - 1) * st.perPage;
    return {
      rows: all.slice(start, start + st.perPage),
      total: all.length,
      page,
      totalPages,
      perPage: st.perPage,
      source: 'peers',
    };
  }

  /** Why a server list is short, from its envelope. */
  function overlayNote(p, searched) {
    switch (p.overlay) {
      case 'no_node':
        return 'This device isn’t on your private network, so it lists only itself. Turn the private network on (Settings → overlay_enabled) to see the devices it can reach.';
      case 'no_network':
        return 'Your organization has no private network yet, so only this device is listed.';
      case 'unavailable':
        return 'This server has no private-network module, so only this device is listed.';
      default:
        if (searched || (Number(p.total) || 0) > 1) return null;
        return p.acl_mode === 'enforce'
          ? 'Your organization’s access rules (ACL enforce) let this device see no other device.'
          : 'No other devices are on your private network yet.';
    }
  }

  /** Why the mesh graph has nothing to draw (the envelope's `overlay`). */
  function emptyMeshNote(overlay) {
    switch (overlay) {
      case 'no_node':
        return 'This device isn’t on your private network, so there is no mesh to draw.';
      case 'no_network':
        return 'Your organization has no private network yet, so there is no mesh to draw.';
      case 'unavailable':
        return 'This server has no private-network module, so there is no mesh to draw.';
      default:
        return 'No devices on your private network yet.';
    }
  }

  function paintNotes(v) {
    const status = $('dv-grid-status');
    const error = $('dv-grid-error');
    let note = null;
    let warn = null;
    const searched = !!st.q.trim();
    if (v.source === 'loading') {
      note = 'Loading the device list…';
    } else if (st.mode === 'legacy' && st.error) {
      note =
        'Showing only the devices this one reaches directly — update the ' +
        LEGACY[st.error.code] +
        ' to see every device your private network lets it see.';
    } else if (v.source === 'server') {
      note = overlayNote(v.envelope, searched);
      if (st.error) {
        warn = 'Showing data from ' + agoText(st.lastGoodAt) + ' — ' + st.error.message + retryText();
      }
    } else if (st.error) {
      warn =
        'Couldn’t get the device list — ' +
        st.error.message +
        '. Showing the devices this one reaches directly' +
        retryText();
    }
    setText(status, note || '');
    status.hidden = !note;
    setText(error, warn || '');
    error.hidden = !warn;
  }

  function retryText() {
    if (!st.nextAt) return '.';
    const secs = Math.max(0, Math.round((st.nextAt - Date.now()) / 1000));
    return secs > 0 ? ' (retrying in ' + secs + ' s).' : '.';
  }

  function paintPager(v) {
    const from = v.total === 0 || !v.rows.length ? 0 : (v.page - 1) * v.perPage + 1;
    const to = from === 0 ? 0 : from + v.rows.length - 1;
    setText($('dv-pager-range'), v.source === 'loading' ? '' : from + '–' + to + ' of ' + v.total);
    $('dv-prev').disabled = v.page <= 1;
    $('dv-next').disabled = v.page >= v.totalPages;
    const noun = v.total === 1 ? ' device' : ' devices';
    setText($('dv-total'), v.source === 'loading' ? '' : v.total + noun);
  }

  function paintOrgs(dv) {
    const rows = (dv && dv.status && dv.status.orgs) || [];
    const labels = rows.map((o) => o.label);
    // The first time, and when the org on screen went away: the primary.
    if (!st.org || (labels.length && !labels.includes(st.org))) {
      setOrg(primaryLabel());
    }
    const sel = $('dv-org');
    if (rows.length <= 1) {
      hide(sel);
      return;
    }
    show(sel);
    const sig = rows.map((o) => o.label + (o.enabled ? '' : '~')).join('|');
    // Never rebuild a dropdown someone has open.
    if (sel.dataset.sig !== sig && document.activeElement !== sel) {
      sel.replaceChildren(
        ...rows.map((o) => {
          const opt = document.createElement('option');
          opt.value = o.label;
          opt.textContent =
            o.label + (o.primary && o.label !== PRIMARY ? ' (primary)' : '') + (o.enabled ? '' : ' — disabled');
          return opt;
        }),
      );
      sel.dataset.sig = sig;
    }
    if (document.activeElement !== sel && sel.value !== st.org) sel.value = st.org;
  }

  function paint() {
    const dv = get('deviceView');
    if (!dv) return;
    if (!dv.available) {
      // The service is not running: the page has nothing to ask.
      show($('devices-unavailable'));
      hide($('devices-content'));
      return;
    }
    hide($('devices-unavailable'));
    show($('devices-content'));
    paintOrgs(dv);
    const v = currentRows(dv);
    grid.render(v.rows);
    paintPager(v);
    paintNotes(v);
  }

  /* ── the mesh ───────────────────────────────────────────────────── */

  async function refreshMesh(opts) {
    if (!active() || !st.org || !graph) return;
    const force = !!(opts && opts.force);
    if (mesh.inFlight > 0 && !force) return;
    clearTimeout(mesh.timer);
    const org = st.org;
    const mine = ++mesh.seq;
    mesh.inFlight += 1;
    let view = null;
    let failure = null;
    try {
      view = await invoke('cmd_mesh', { org: orgArg() });
    } catch (err) {
      failure = parseFailure(err);
    } finally {
      mesh.inFlight -= 1;
    }
    if (org !== st.org || mine < mesh.applied) return;
    mesh.applied = mine;
    mesh.lastAskAt = Date.now();
    if (view) {
      mesh.view = view;
      mesh.error = null;
      mesh.failures = 0;
      mesh.lastGoodAt = Date.now();
    } else {
      mesh.error = failure;
      mesh.failures += 1;
    }
    scheduleMesh();
    paintMesh();
  }

  function scheduleMesh() {
    clearTimeout(mesh.timer);
    if (!active()) return;
    const delay = mesh.error ? Math.max(MESH_MS, BACKOFF_MS[Math.min(mesh.failures, BACKOFF_MS.length - 1)]) : MESH_MS;
    mesh.timer = setTimeout(() => void refreshMesh(), delay);
  }

  function paintMesh() {
    const note = $('dv-mesh-note');
    const body = $('dv-mesh-body');
    const v = mesh.view;
    const e = mesh.error;
    let text = null;
    let draw = false;
    if (e && LEGACY[e.code]) {
      text = 'The mesh graph needs a newer ' + LEGACY[e.code] + '.';
    } else if (v && !v.enabled) {
      // Statistics off on the server: data, not a failure.
      text = 'This server has usage statistics turned off, so there is no mesh graph to show.';
    } else if (v && !(v.nodes || []).length) {
      text = emptyMeshNote(v.overlay);
    } else if (v) {
      draw = true;
      if (e) text = 'Showing the graph from ' + agoText(mesh.lastGoodAt) + ' — ' + e.message;
    } else if (e) {
      text = 'Couldn’t load the mesh graph — ' + e.message;
    } else {
      text = 'Loading the mesh graph…';
    }
    if (draw) {
      show(body);
      graph.render(v);
    } else {
      hide(body);
    }
    setText(note, text || '');
    note.hidden = !text;
    const meta = v && v.enabled && v.acl_mode ? 'ACL ' + v.acl_mode : '';
    setText($('dv-mesh-meta'), meta);
  }

  /* ── controls ───────────────────────────────────────────────────── */

  function setOrg(label) {
    if (label === st.org) return;
    st.org = label;
    st.page = 1;
    st.lastPage = null;
    st.error = null;
    st.failures = 0;
    st.mode = 'server';
    st.nextAt = 0;
    mesh.view = null;
    mesh.error = null;
    mesh.failures = 0;
    if (grid) grid.setStorageKey(prefKey());
    void refresh({ force: true, loading: true });
    void refreshMesh({ force: true });
  }

  /** A person changed the question: page 1 (unless paging), ask at once. */
  function requery(resetPage) {
    if (resetPage) st.page = 1;
    grid.setSort(st.sort, st.dir);
    paint(); // the fallback rows re-query locally; a server page stays until the answer
    void refresh({ force: true, loading: true });
  }

  function wireControls() {
    const search = $('dv-search');
    search.addEventListener('input', () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(() => {
        const q = search.value.trim();
        if (q === st.q) return;
        st.q = q;
        requery(true);
      }, SEARCH_DEBOUNCE_MS);
    });

    const size = $('dv-page-size');
    size.value = String(st.perPage);
    size.addEventListener('change', () => {
      const n = parseInt(size.value, 10);
      if (!PAGE_SIZES.includes(n)) return;
      st.perPage = n;
      storageSet(PREF_PAGE_SIZE, String(n));
      requery(true);
    });

    $('dv-org').addEventListener('change', () => setOrg($('dv-org').value));

    $('dv-prev').addEventListener('click', () => {
      if (st.page <= 1) return;
      st.page -= 1;
      requery(false);
    });
    $('dv-next').addEventListener('click', () => {
      st.page += 1;
      requery(false);
    });

    $('dv-refresh').addEventListener('click', () => {
      void refresh({ force: true, loading: true });
      void refreshMesh({ force: true });
    });

    const dialog = $('dv-cols-dialog');
    $('dv-cols-btn').addEventListener('click', () => grid.openChooser(dialog));
  }

  /** The Columns button says when this org's columns are customised. */
  function paintColsButton() {
    if (grid) $('dv-cols-btn').classList.toggle('is-custom', grid.customized());
  }

  function onSort(next) {
    st.sort = next.key;
    st.dir = next.dir;
    requery(true);
  }

  /* ── boot ───────────────────────────────────────────────────────── */

  document.addEventListener('DOMContentLoaded', () => {
    const saved = parseInt(storageGet(PREF_PAGE_SIZE) || '', 10);
    if (PAGE_SIZES.includes(saved)) st.perPage = saved;

    grid = R.Grid.create({
      table: $('dv-grid'),
      catalog: COLUMNS,
      storageKey: prefKey(),
      keyOf: rowKey,
      context: liveContext,
      onSort,
      onPrefs: paintColsButton,
    });
    graph = R.Mesh.create({
      wrap: $('dv-mesh-wrap'),
      svg: $('dv-mesh'),
      tip: $('dv-mesh-tip'),
      legend: $('dv-mesh-legend'),
      controls: $('dv-mesh-controls'),
    });
    wireControls();
    paintColsButton();

    // The 2 s peer poll: patch the live cells in place; the fallback rows ARE
    // the peers, so those re-derive.
    on('deviceView', (dv) => {
      if (!dv) return;
      if (!dv.available || st.mode === 'legacy' || !st.lastPage) {
        paint();
        return;
      }
      paintOrgs(dv);
      grid.patchLive();
      paintNotes(currentRows(dv)); // keeps "N min ago" / "retrying in" current
    });

    document.addEventListener('roomler:view', (ev) => {
      if (ev.detail === 'devices') {
        paint();
        void refresh({ force: true });
        void refreshMesh({ force: true });
      } else {
        clearTimeout(st.timer);
        clearTimeout(mesh.timer);
      }
    });

    document.addEventListener('visibilitychange', () => {
      if (!active()) {
        clearTimeout(st.timer);
        clearTimeout(mesh.timer);
        return;
      }
      // Back on screen: ask again if the last answer is older than a cycle.
      if (Date.now() - st.lastAskAt >= REFRESH_MS) void refresh({ force: true });
      else schedule();
      if (Date.now() - mesh.lastAskAt >= MESH_MS) void refreshMesh({ force: true });
      else scheduleMesh();
    });
  });
})();
