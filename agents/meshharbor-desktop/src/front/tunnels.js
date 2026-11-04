// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
/*
 * Tunnels view: declared, daemon-supervised routes (P6) + the live-forwards
 * table (per-forward transport, connection count and byte counters). Both
 * come from ONE `cmd_tunnels_view` call — one LocalAPI connection per
 * refresh (FR-84 D1) — polled only while this view is visible; the route
 * list is also broadcast (`roomler:routes`) so the Overview can show an
 * active-count without polling again.
 *
 * FR-84 D1 — the page holds still:
 *   - an error is never painted as data. A failed refresh keeps the last
 *     good routes/flows on screen and shows ONE status line ("live data
 *     unavailable since HH:MM:SS · N failures · reason"); it clears on the
 *     next success. Before this, any error became `[]`, and `[]` hid the
 *     table and showed "no routes yet" every few seconds.
 *   - a sequence guard drops a response that is older than the newest one
 *     already applied (a slow pipe answering after a faster later call).
 *   - rows are keyed by route id / flow id and patched in place — cells via
 *     textContent, a row added or removed only when the SET changes — so a
 *     button never moves under the cursor.
 *   - a declared route can be EDITED: the action pre-fills the add form,
 *     which then saves through `cmd_route_update` (an atomic replace in the
 *     daemon; an invalid edit leaves the old route running).
 *
 * #1685 — the State column is the port's truth: `active` only once the
 * route's listener is bound and serving; `connecting` while its first
 * session attempt is in flight; `retrying (N, next in Ss) — <error>` while
 * the tunnel session toward the node keeps failing, with `· device offline`
 * appended when the Devices data already knows why. A state word this build
 * does not know (a newer daemon) is shown as its word, never as an error.
 *
 * The add-route form offers a picker of known agent peers (from the central
 * device view — PeerInfo.agent_id is the join key) with a free-text escape
 * hatch for an id that isn't in the mesh list.
 *
 * Conventions match devices.js: every daemon-supplied string (ids, error
 * reasons, names) is written with textContent only — never innerHTML.
 */
(function () {
  'use strict';
  const { $, invoke, show, hide, fmtBytes, on, get, currentView } = window.Roomler;

  let busy = false;            // one mutation in flight at a time
  let lastRoutes = [];         // last GOOD data — what the tables show
  let lastFlows = [];
  let seq = 0;                 // refresh requests issued
  let applied = 0;             // the newest response applied to the page
  let inFlight = 0;            // refreshes awaiting the daemon (a count: a
                               // forced refresh can overlap a stalled poll)
  let failures = 0;            // consecutive failed refreshes
  let unavailableSince = null; // Date of the first failure of the streak
  let editing = null;          // the RouteDescriptor the form is editing, or null

  const routeRows = new Map(); // route id → row handle
  const flowRows = new Map();  // flow id → row handle

  const CUSTOM = '__custom__';

  function visible() { return currentView() === 'tunnels'; }

  /* ── refresh ────────────────────────────────────────────────────── */

  // `force` — a mutation or a view entry always runs; a poll tick never
  // stacks behind a stalled pipe (each stacked call is one more open).
  async function refresh(opts) {
    if (!visible()) return;
    const force = !!(opts && opts.force);
    if (inFlight > 0 && !force) return;
    const mine = ++seq;
    inFlight += 1;
    let view;
    try {
      view = await invoke('cmd_tunnels_view');
    } catch (err) {
      // The command never rejects by contract; if the bridge itself does,
      // that is a failure like any other — shown, never painted as data.
      view = { available: false, reason: 'cmd_tunnels_view rejected: ' + String(err) };
    } finally {
      // A count, not a flag: a forced refresh that finishes while a stalled
      // poll is still waiting must not re-open the gate for the next tick.
      inFlight -= 1;
    }
    // Sequence guard: a response older than the newest already applied is
    // dropped, not painted.
    if (mine < applied) return;
    applied = mine;

    if (!view || !view.available) {
      noteUnavailable(view && view.reason ? view.reason : 'no response');
      return;
    }
    noteAvailable();
    lastRoutes = Array.isArray(view.routes) ? view.routes : [];
    lastFlows = Array.isArray(view.flows) ? view.flows : [];
    paintRoutes(lastRoutes);
    paintFlows(lastFlows);
    document.dispatchEvent(new CustomEvent('roomler:routes', { detail: lastRoutes }));
  }

  function fmtClock(d) {
    return d.toLocaleTimeString([], { hour12: false });
  }

  function noteUnavailable(reason) {
    failures += 1;
    if (!unavailableSince) unavailableSince = new Date();
    const line = $('tn-stale');
    if (!line) return;
    line.textContent =
      'live data unavailable since ' + fmtClock(unavailableSince) +
      ' · ' + failures + (failures === 1 ? ' failure' : ' failures') +
      ' · ' + reason;
    show(line);
  }

  function noteAvailable() {
    failures = 0;
    unavailableSince = null;
    hide($('tn-stale'));
  }

  /* ── peer lookups ───────────────────────────────────────────────── */

  function agentPeers() {
    const dv = get('deviceView');
    return ((dv && dv.peers) || []).filter((p) => p.agent_id);
  }

  // agent-id (24-hex) → display name, for the routes/flows Device columns.
  function peerName(agentId) {
    if (!agentId) return null;
    const hit = agentPeers().find((p) => p.agent_id === agentId);
    return hit ? hit.name || null : null;
  }

  function deviceLabel(agentId) {
    const name = peerName(agentId);
    if (name) return name;
    if (!agentId) return '—';
    return agentId.length > 10 ? agentId.slice(0, 8) + '…' : agentId;
  }

  // true / false when the mesh view knows the device, null when it does not.
  function peerOnline(agentId) {
    if (!agentId) return null;
    const hit = agentPeers().find((p) => p.agent_id === agentId);
    return hit ? !!hit.online : null;
  }

  /* ── row plumbing ───────────────────────────────────────────────── */

  function td(text, cls) {
    const el = document.createElement('td');
    el.textContent = text;
    if (cls) el.className = cls;
    return el;
  }

  // Patch helpers: touch the DOM only when the value changed, so a steady
  // page does zero mutations per tick.
  function setText(el, text) { if (el.textContent !== text) el.textContent = text; }
  function setClass(el, cls) { if (el.className !== cls) el.className = cls; }

  // Sync `body`'s children to `order` (an array of <tr>), moving a row only
  // when its position changed and never touching a row already in place.
  function syncOrder(body, order) {
    order.forEach((tr, idx) => {
      const at = body.children[idx];
      if (at !== tr) body.insertBefore(tr, at || null);
    });
  }

  function actionBtn(label, danger, onClick) {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = label;
    b.className = danger ? 'sm danger' : 'sm';
    b.style.marginRight = '6px';
    b.addEventListener('click', async () => {
      if (busy) return;
      busy = true;
      b.disabled = true;
      try {
        await onClick();
      } catch (err) {
        // Mutation errors are actionable — surface them on the form slot.
        const slot = $('tn-form-error');
        if (slot) { slot.textContent = String(err); show(slot); }
      } finally {
        busy = false;
        b.disabled = false;
        await refresh({ force: true });
      }
    });
    return b;
  }

  /* ── declared routes ────────────────────────────────────────────── */

  // Compact human word for a RouteState (adjacently tagged on `state`).
  // #1685 — a flow that exists but does not serve carries its `flow_id`: on
  // `pending` its first session attempt is in flight; on `backoff` the tunnel
  // session toward the node is what keeps failing, as opposed to a `backoff`
  // without one, where the local port could not be bound. A daemon older
  // than #1685 sends neither field and renders exactly as before.
  function stateLabel(s) {
    switch (s.state) {
      case 'disabled': return { text: 'disabled', cls: 'muted' };
      case 'pending':
        return s.flow_id ? { text: 'connecting', cls: 'muted' } : { text: 'pending', cls: 'muted' };
      case 'active': return { text: 'active', cls: 'ok' };
      case 'backoff': {
        if (s.flow_id) {
          const n = s.attempts > 0 ? s.attempts : 1;
          const next = s.next_retry_secs > 0 ? ', next in ' + s.next_retry_secs + 's' : '';
          return { text: 'retrying (' + n + next + ') — ' + s.last_error, cls: 'warn' };
        }
        return { text: 'retrying in ' + s.next_retry_secs + 's: ' + s.last_error, cls: 'warn' };
      }
      case 'failed':
        return { text: 'FAILED: ' + s.reason, cls: 'err' };
      // A newer daemon's state word: shown as-is, never an error.
      default: return { text: s.state || '—', cls: 'muted' };
    }
  }

  // #1685 — say WHY a route is not serving when the Devices data already
  // knows: its target device is offline.
  function stateText(r) {
    const st = stateLabel(r.state);
    const s = r.state || {};
    if ((s.state === 'pending' || s.state === 'backoff') && peerOnline(r.route.node) === false) {
      return { text: st.text + ' · device offline', cls: st.cls };
    }
    return st;
  }

  // The flow backing an active route, for its live Traffic column.
  function flowForRoute(state) {
    if (!state || state.state !== 'active' || !state.flow_id) return null;
    return lastFlows.find((f) => f.id === state.flow_id) || null;
  }

  function buildRouteRow(id) {
    const tr = document.createElement('tr');
    const cells = {
      id: td(id, 'mono'),
      kind: td(''),
      local: td('', 'mono'),
      remote: td('', 'mono'),
      device: td(''),
      state: td(''),
    };
    // The state cell holds a text node + the live-traffic span, so the text
    // can be patched without dropping the span.
    const stateText = document.createTextNode('');
    const traffic = document.createElement('span');
    traffic.className = 'muted small';
    traffic.hidden = true;
    cells.state.append(stateText, traffic);
    tr.append(cells.id, cells.kind, cells.local, cells.remote, cells.device, cells.state);

    const row = { tr, cells, stateText, traffic, route: null };
    const actions = document.createElement('td');
    // The handlers read `row.route` at click time, so the buttons are
    // created once and never re-created by a repaint.
    row.toggle = actionBtn('Disable', false, () =>
      invoke('cmd_route_set_enabled', { id, enabled: !(row.route && row.route.enabled) }));
    row.edit = actionBtn('Edit', false, () => beginEdit(row.route));
    row.remove = actionBtn('Remove', true, () => invoke('cmd_route_remove', { id }));
    actions.append(row.toggle, row.edit, row.remove);
    tr.appendChild(actions);
    return row;
  }

  function updateRouteRow(row, r) {
    const d = r.route;
    row.route = d;
    setText(row.cells.kind, d.kind);
    setText(row.cells.local, '127.0.0.1:' + d.local);
    setText(row.cells.remote, d.remote || '—');
    setText(row.cells.device, deviceLabel(d.node));
    const st = stateText(r);
    if (row.stateText.data !== st.text) row.stateText.data = st.text;
    setClass(row.cells.state, st.cls || '');
    // Live traffic rides in the state cell ("active · ↓ 2 MiB ↑ 1 MiB") —
    // one column fewer keeps the table inside a narrow window.
    const flow = flowForRoute(r.state);
    if (flow) {
      setText(row.traffic, ' · ↓ ' + fmtBytes(flow.bytes_in) + ' ↑ ' + fmtBytes(flow.bytes_out));
      row.traffic.hidden = false;
    } else {
      row.traffic.hidden = true;
    }
    setText(row.toggle, d.enabled ? 'Disable' : 'Enable');
  }

  function paintRoutes(routes) {
    const empty = $('tn-empty');
    const table = $('tn-table');
    const body = $('tn-body');
    if (!body) return;

    if (!routes.length) {
      // Real data saying "no routes" — never reached from an error path.
      show(empty); hide(table);
      body.replaceChildren();
      routeRows.clear();
      return;
    }
    hide(empty); show(table);

    const seen = new Set();
    const order = [];
    for (const r of routes) {
      const id = r.route.id;
      seen.add(id);
      let row = routeRows.get(id);
      if (!row) {
        row = buildRouteRow(id);
        routeRows.set(id, row);
      }
      updateRouteRow(row, r);
      order.push(row.tr);
    }
    for (const [id, row] of routeRows) {
      if (!seen.has(id)) { row.tr.remove(); routeRows.delete(id); }
    }
    syncOrder(body, order);
  }

  /* ── live flows ─────────────────────────────────────────────────── */

  function buildFlowRow() {
    const tr = document.createElement('tr');
    const cells = {
      kind: td(''),
      local: td('', 'mono'),
      target: td('', 'mono'),
      device: td(''),
      transport: td(''),
      conns: td(''),
      traffic: td('', 'small'),
    };
    tr.append(cells.kind, cells.local, cells.target, cells.device,
      cells.transport, cells.conns, cells.traffic);
    return { tr, cells };
  }

  function updateFlowRow(row, f) {
    setText(row.cells.kind, f.kind);
    setText(row.cells.local, f.local_addr);
    setText(row.cells.target, f.target || '—');
    setText(row.cells.device, deviceLabel(f.node));
    setText(row.cells.transport, f.transport);
    setText(row.cells.conns, String(f.active_flows));
    setText(row.cells.traffic, '↓ ' + fmtBytes(f.bytes_in) + ' ↑ ' + fmtBytes(f.bytes_out));
  }

  function paintFlows(flows) {
    const card = $('tn-flows-card');
    const body = $('tn-flows-body');
    if (!body) return;
    if (!flows.length) {
      // Real data: no live forwards right now.
      hide(card);
      body.replaceChildren();
      flowRows.clear();
      return;
    }
    show(card);
    const seen = new Set();
    const order = [];
    for (const f of flows) {
      seen.add(f.id);
      let row = flowRows.get(f.id);
      if (!row) {
        row = buildFlowRow();
        flowRows.set(f.id, row);
      }
      updateFlowRow(row, f);
      order.push(row.tr);
    }
    for (const [id, row] of flowRows) {
      if (!seen.has(id)) { row.tr.remove(); flowRows.delete(id); }
    }
    syncOrder(body, order);
  }

  /* ── add / edit form ────────────────────────────────────────────── */

  function paintNodeOptions() {
    const sel = $('tn-node');
    if (!sel) return;
    // Don't yank a dropdown the operator has open — the 2 s repaint would
    // close it mid-pick.
    if (document.activeElement === sel) return;
    const prev = sel.value;
    const opts = [];
    for (const p of agentPeers()) {
      const o = document.createElement('option');
      o.value = p.agent_id;
      o.textContent = (p.name || p.agent_id.slice(0, 8) + '…') + (p.online ? '' : ' (offline)');
      opts.push(o);
    }
    const custom = document.createElement('option');
    custom.value = CUSTOM;
    custom.textContent = 'Other device (enter agent id)…';
    opts.push(custom);
    sel.replaceChildren(...opts);
    // Keep the operator's selection stable across the 2 s repaint.
    if (prev && [...sel.options].some((o) => o.value === prev)) sel.value = prev;
    $('tn-custom-node').hidden = sel.value !== CUSTOM;
  }

  function selectedNode() {
    const sel = $('tn-node');
    if (!sel || !sel.value) return '';
    if (sel.value === CUSTOM) return $('tn-custom-node').value.trim();
    return sel.value;
  }

  // Add mode vs edit mode: the same form, different title, submit label,
  // a Cancel button, and a read-only id (the id is what the update is
  // keyed by — renaming is remove + add).
  function setFormMode() {
    const title = $('tn-form-title');
    const submit = $('tn-submit');
    const cancel = $('tn-cancel');
    const idInput = $('tn-id');
    if (editing) {
      if (title) title.textContent = 'Edit route ' + editing.id;
      if (submit) submit.textContent = 'Save changes';
      show(cancel);
      if (idInput) idInput.readOnly = true;
    } else {
      if (title) title.textContent = 'Add route…';
      if (submit) submit.textContent = 'Add route';
      hide(cancel);
      if (idInput) idInput.readOnly = false;
    }
  }

  function beginEdit(d) {
    if (!d) return;
    editing = d;
    const sel = $('tn-node');
    const custom = $('tn-custom-node');
    paintNodeOptions();
    if ([...sel.options].some((o) => o.value === d.node)) {
      sel.value = d.node;
      custom.value = '';
      custom.hidden = true;
    } else {
      sel.value = CUSTOM;
      custom.value = d.node;
      custom.hidden = false;
    }
    $('tn-local').value = d.local;
    $('tn-remote').value = d.remote || '';
    $('tn-transport').value = d.transport === 'auto' ? '' : (d.transport || '');
    $('tn-id').value = d.id;
    hide($('tn-form-error'));
    setFormMode();
    const details = $('tn-add');
    if (details) details.open = true;
    $('tn-local').focus();
  }

  function endEdit(form) {
    editing = null;
    form.reset();
    // An error from a rejected Save belongs to the edit being left; it must
    // not stay under a form that now says "Add route".
    hide($('tn-form-error'));
    $('tn-custom-node').hidden = true;
    setFormMode();
  }

  function wireForm() {
    const form = $('tn-form');
    if (!form) return;

    $('tn-node').addEventListener('change', () => {
      $('tn-custom-node').hidden = $('tn-node').value !== CUSTOM;
    });

    const cancel = $('tn-cancel');
    if (cancel) cancel.addEventListener('click', () => endEdit(form));

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (busy) return;
      const errSlot = $('tn-form-error');
      hide(errSlot);

      const node = selectedNode();
      if (!node) {
        errSlot.textContent = 'Pick a target device (or enter its agent id).';
        show(errSlot);
        return;
      }
      const local = parseInt($('tn-local').value, 10);
      const remoteRaw = $('tn-remote').value.trim();
      const transport = $('tn-transport').value;
      const id = editing ? editing.id : $('tn-id').value.trim();

      const route = {
        id: id,
        kind: remoteRaw ? 'forward' : 'socks5',
        node: node,
        local: local,
        transport: transport,
        // An edit keeps the route's enabled state and org; an add is live.
        enabled: editing ? !!editing.enabled : true,
      };
      if (remoteRaw) route.remote = remoteRaw;
      if (editing && editing.org) route.org = editing.org;

      busy = true;
      try {
        if (editing) {
          await invoke('cmd_route_update', { route });
          endEdit(form);
        } else {
          await invoke('cmd_route_add', { route });
          form.reset();
          $('tn-custom-node').hidden = true;
        }
      } catch (err) {
        errSlot.textContent = String(err);
        show(errSlot);
      } finally {
        busy = false;
        await refresh({ force: true });
      }
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    wireForm();
    setFormMode();
    on('deviceView', paintNodeOptions);
    // Refresh immediately when the view is entered; poll only while visible.
    document.addEventListener('roomler:view', (ev) => {
      if (ev.detail === 'tunnels') void refresh({ force: true });
    });
    void refresh({ force: true });
    setInterval(() => void refresh(), 2000);
  });
})();
