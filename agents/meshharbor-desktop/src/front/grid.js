// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
/*
 * FR-84 D5c — a keyed, column-configurable table (`window.Roomler.Grid`).
 *
 * The web app's device grid lets each person hide and reorder columns
 * (ui/src/composables/useGridColumns.ts); this is that logic, ported to the
 * companion's plain JS, plus the two things a table here must do that
 * Vuetify did for the web:
 *
 *   - Rows are KEYED (`tr[data-key]`) and cells are PATCHED IN PLACE through
 *     each column's `update`, touching the DOM only when a value changed — a
 *     row is added or removed only when the SET of rows changes, so a button
 *     never moves under the cursor while the list refreshes (the FR-84 D1
 *     lesson from the Routes page).
 *   - The column chooser is a <dialog> with a checkbox, an HTML5 drag handle
 *     AND ▲/▼ buttons per column. Drag-and-drop is unreliable in WebKitGTK
 *     (the Linux companion), so it is never the only way to reorder.
 *
 * Preferences persist in localStorage as `{order, hidden}` — the web's
 * shape — under a key the caller chooses (the Devices page scopes it per
 * org). The saved order comes first; a catalog key it does not mention (a
 * column shipped later) is spliced back at its catalog position, not dumped
 * at the end. `name` and `actions` can never be hidden. Storage can throw
 * (a private profile, blocked storage): every access is guarded, and the
 * grid then simply forgets between runs.
 *
 * create(opts): { table, catalog, storageKey, keyOf(row), context()?,
 *   onSort({key, dir})?, onPrefs()? } — `onPrefs` runs after every
 *   preference change (and a storage-key switch).
 *
 * Column definition: { key, title, chooserTitle?, sort?, live?, cls?, width?,
 *   build(td) → state, update(state, row, ctx, td) }
 *   - `sort` is the SERVER's sort key; a column without one is not sortable.
 *   - `live` columns are re-run by `patchLive()` (the 2 s local peer merge)
 *     without touching the rest of the row.
 *
 * Every value a cell shows is written with textContent — never innerHTML —
 * because every one of them came from another device or the server.
 */
(function () {
  'use strict';

  /** Columns a person cannot hide: the row's identity and its actions. */
  const NEVER_HIDE = new Set(['name', 'actions']);

  /* ── preferences: a port of useGridColumns.ts ───────────────────── */

  function readPref(storageKey) {
    try {
      const raw = window.localStorage.getItem(storageKey);
      const parsed = raw ? JSON.parse(raw) : null;
      const strings = (v) => (Array.isArray(v) ? v.filter((k) => typeof k === 'string') : []);
      return {
        order: strings(parsed && parsed.order),
        hidden: strings(parsed && parsed.hidden),
      };
    } catch (_) {
      return { order: [], hidden: [] };
    }
  }

  function writePref(storageKey, pref) {
    try {
      if (!pref.order.length && !pref.hidden.length) window.localStorage.removeItem(storageKey);
      else window.localStorage.setItem(storageKey, JSON.stringify(pref));
    } catch (_) {
      /* blocked / private storage — the grid still works, it forgets */
    }
  }

  /** Catalog keys in the person's order: the saved order first (keys the
   *  catalog no longer has dropped), then each catalog key it does not name,
   *  inserted before the first saved key that comes later in the catalog. */
  function orderedKeys(catalog, savedOrder) {
    const saved = savedOrder.filter((k) => catalog.includes(k));
    const out = saved.slice();
    for (const k of catalog) {
      if (saved.includes(k)) continue;
      const catIdx = catalog.indexOf(k);
      let insertAt = out.length;
      for (let i = 0; i < out.length; i++) {
        if (catalog.indexOf(out[i]) > catIdx) {
          insertAt = i;
          break;
        }
      }
      out.splice(insertAt, 0, k);
    }
    return out;
  }

  function visibleKeys(catalog, pref) {
    const hidden = new Set(pref.hidden.filter((k) => !NEVER_HIDE.has(k)));
    return orderedKeys(catalog, pref.order).filter((k) => !hidden.has(k));
  }

  /* ── the grid ───────────────────────────────────────────────────── */

  function create(opts) {
    const table = opts.table;
    const thead = table.tHead || table.createTHead();
    const tbody = table.tBodies[0] || table.createTBody();
    const byKey = new Map(opts.catalog.map((c) => [c.key, c]));
    const catalogKeys = opts.catalog.map((c) => c.key);

    let storageKey = opts.storageKey;
    let pref = readPref(storageKey);
    let columns = [];
    let rows = new Map(); // row key → { tr, cells: Map(colKey → {td, st}), row }
    let lastRows = [];
    let sort = { key: null, dir: 'asc' };

    function ctx() {
      return opts.context ? opts.context() : {};
    }

    /* header */

    // asc → desc → the server's default order (online first, then name).
    function nextSort(key) {
      if (sort.key !== key) return { key, dir: 'asc' };
      if (sort.dir === 'asc') return { key, dir: 'desc' };
      return { key: null, dir: 'asc' };
    }

    function renderHead() {
      const tr = document.createElement('tr');
      for (const col of columns) {
        const th = document.createElement('th');
        th.dataset.key = col.key;
        if (col.width) th.style.width = col.width;
        const label = document.createElement('span');
        label.textContent = col.title;
        th.appendChild(label);
        if (col.sort && opts.onSort) {
          th.classList.add('sortable');
          th.tabIndex = 0;
          th.title = 'Sort by ' + (col.chooserTitle || col.title).toLowerCase();
          const ind = document.createElement('span');
          ind.className = 'sort-ind';
          if (sort.key === col.sort) {
            ind.textContent = sort.dir === 'desc' ? '▼' : '▲';
            th.setAttribute('aria-sort', sort.dir === 'desc' ? 'descending' : 'ascending');
            th.classList.add('sorted');
          }
          th.appendChild(ind);
          const cycle = () => opts.onSort(nextSort(col.sort));
          th.addEventListener('click', cycle);
          th.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              cycle();
            }
          });
        }
        tr.appendChild(th);
      }
      thead.replaceChildren(tr);
    }

    /* rows */

    function buildRow(key) {
      const tr = document.createElement('tr');
      tr.dataset.key = key;
      const cells = new Map();
      for (const col of columns) {
        const td = document.createElement('td');
        td.dataset.col = col.key;
        if (col.cls) td.className = col.cls;
        const st = col.build ? col.build(td) : {};
        cells.set(col.key, { td, st });
        tr.appendChild(td);
      }
      return { tr, cells, row: null };
    }

    function updateRow(h, c, liveOnly) {
      for (const col of columns) {
        if (liveOnly && !col.live) continue;
        const cell = h.cells.get(col.key);
        if (cell && col.update) col.update(cell.st, h.row, c, cell.td);
      }
    }

    /** Show `list`: patch the rows that stay, add and remove only what
     *  changed, and fix the order with the fewest moves. */
    function render(list) {
      lastRows = list;
      const c = ctx();
      const seen = new Set();
      const order = [];
      for (const row of list) {
        const key = opts.keyOf(row);
        if (seen.has(key)) continue; // a duplicate key would steal a row
        seen.add(key);
        let h = rows.get(key);
        if (!h) {
          h = buildRow(key);
          rows.set(key, h);
        }
        h.row = row;
        updateRow(h, c, false);
        order.push(h.tr);
      }
      for (const [key, h] of rows) {
        if (!seen.has(key)) {
          h.tr.remove();
          rows.delete(key);
        }
      }
      order.forEach((tr, idx) => {
        const at = tbody.children[idx];
        if (at !== tr) tbody.insertBefore(tr, at || null);
      });
    }

    /** Re-run only the `live` columns of the rows on screen. */
    function patchLive() {
      const c = ctx();
      rows.forEach((h) => updateRow(h, c, true));
    }

    /** The visible column set or order changed: every row's cells change
     *  shape, so rebuild them from the last data. */
    function layout() {
      columns = visibleKeys(catalogKeys, pref).map((k) => byKey.get(k));
      renderHead();
      rows.forEach((h) => h.tr.remove());
      rows = new Map();
      render(lastRows);
    }

    function setSort(key, dir) {
      sort = { key: key || null, dir: dir === 'desc' ? 'desc' : 'asc' };
      renderHead();
    }

    function setStorageKey(key) {
      if (key === storageKey) return;
      storageKey = key;
      pref = readPref(storageKey);
      layout();
      if (opts.onPrefs) opts.onPrefs();
    }

    /* preferences */

    function save(next) {
      pref = next;
      writePref(storageKey, pref);
      layout();
      // Told at once, not on the dialog's `close` event — Chromium delays
      // that event in a hidden window, and the page's "customized" marker
      // must not wait on it.
      if (opts.onPrefs) opts.onPrefs();
    }

    function entries() {
      return orderedKeys(catalogKeys, pref.order).map((k) => {
        const col = byKey.get(k);
        const locked = NEVER_HIDE.has(k);
        return {
          key: k,
          title: col.chooserTitle || col.title || k,
          visible: locked || !pref.hidden.includes(k),
          locked,
        };
      });
    }

    function toggle(key) {
      if (NEVER_HIDE.has(key)) return;
      const hidden = new Set(pref.hidden);
      if (hidden.has(key)) hidden.delete(key);
      else hidden.add(key);
      save({ order: pref.order, hidden: [...hidden] });
    }

    function move(key, dir) {
      const order = orderedKeys(catalogKeys, pref.order);
      const idx = order.indexOf(key);
      const to = idx + dir;
      if (idx === -1 || to < 0 || to >= order.length) return;
      order.splice(idx, 1);
      order.splice(to, 0, key);
      save({ order, hidden: pref.hidden });
    }

    /** Drag and drop: persist the whole order in one write. */
    function reorder(keys) {
      const current = orderedKeys(catalogKeys, pref.order);
      const known = new Set(current);
      const order = keys.filter((k) => known.has(k));
      for (const k of current) if (!order.includes(k)) order.push(k);
      save({ order, hidden: pref.hidden });
    }

    function reset() {
      save({ order: [], hidden: [] });
    }

    function customized() {
      return pref.order.length > 0 || pref.hidden.length > 0;
    }

    /* the chooser */

    function smallButton(text, label, onClick) {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'sm cols-move';
      b.textContent = text;
      b.setAttribute('aria-label', label);
      b.title = label;
      b.addEventListener('click', onClick);
      return b;
    }

    /** Fill and open `dialog` (it holds a `[data-role=list]` <ul> and a
     *  `[data-role=reset]` button). */
    function openChooser(dialog) {
      const list = dialog.querySelector('[data-role=list]');
      const resetBtn = dialog.querySelector('[data-role=reset]');

      function paint() {
        const all = entries();
        const items = all.map((e, i) => {
          const li = document.createElement('li');
          li.className = 'cols-item';
          li.dataset.key = e.key;
          li.draggable = true;

          const handle = document.createElement('span');
          handle.className = 'drag-handle';
          handle.textContent = '⋮⋮';
          handle.title = 'Drag to reorder';

          const label = document.createElement('label');
          const cb = document.createElement('input');
          cb.type = 'checkbox';
          cb.checked = e.visible;
          cb.disabled = e.locked;
          cb.addEventListener('change', () => {
            toggle(e.key);
            paint();
          });
          label.appendChild(cb);
          label.appendChild(document.createTextNode(' ' + e.title));
          if (e.locked) {
            const note = document.createElement('span');
            note.className = 'muted small';
            note.textContent = ' (always shown)';
            label.appendChild(note);
          }

          const up = smallButton('▲', 'Move ' + e.title + ' up', () => {
            move(e.key, -1);
            paint();
          });
          up.disabled = i === 0;
          const down = smallButton('▼', 'Move ' + e.title + ' down', () => {
            move(e.key, 1);
            paint();
          });
          down.disabled = i === all.length - 1;

          li.addEventListener('dragstart', (ev) => {
            ev.dataTransfer.setData('text/plain', e.key);
            ev.dataTransfer.effectAllowed = 'move';
            li.classList.add('dragging');
          });
          li.addEventListener('dragend', () => li.classList.remove('dragging'));
          li.addEventListener('dragover', (ev) => {
            ev.preventDefault();
            li.classList.add('drag-over');
          });
          li.addEventListener('dragleave', () => li.classList.remove('drag-over'));
          li.addEventListener('drop', (ev) => {
            ev.preventDefault();
            li.classList.remove('drag-over');
            const from = ev.dataTransfer.getData('text/plain');
            if (!from || from === e.key) return;
            const keys = entries()
              .map((x) => x.key)
              .filter((k) => k !== from);
            // Lower half of the target row = after it, upper half = before.
            const rect = li.getBoundingClientRect();
            const after = ev.clientY > rect.top + rect.height / 2;
            keys.splice(keys.indexOf(e.key) + (after ? 1 : 0), 0, from);
            reorder(keys);
            paint();
          });

          const moves = document.createElement('span');
          moves.className = 'cols-moves';
          moves.append(up, down);
          li.append(handle, label, moves);
          return li;
        });
        list.replaceChildren(...items);
        if (resetBtn) resetBtn.disabled = !customized();
      }

      if (resetBtn) {
        resetBtn.onclick = () => {
          reset();
          paint();
        };
      }
      paint();
      if (typeof dialog.showModal === 'function') {
        if (!dialog.open) dialog.showModal();
      } else {
        dialog.setAttribute('open', '');
      }
    }

    layout();
    return {
      render,
      patchLive,
      setSort,
      setStorageKey,
      entries,
      toggle,
      move,
      reorder,
      reset,
      customized,
      openChooser,
      visibleKeys: () => columns.map((c) => c.key),
    };
  }

  window.Roomler.Grid = { create, orderedKeys, visibleKeys, NEVER_HIDE };
})();
