// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
/*
 * Recordings view (FR-85): record this screen, choose where recordings are
 * saved, and manage the saved ones.
 *
 * Every refresh is ONE LocalAPI connection (`cmd_recordings_view`): every
 * second while a recording runs, every 5 s otherwise, and only while the
 * view is visible. A failed refresh keeps the last good data on screen and
 * says why (the FR-84 D1 rule). Saved recordings are keyed rows patched in
 * place, so a button never moves under the cursor. Everything is built with
 * createElement + textContent (no innerHTML).
 *
 * The daemon decides everything that matters: who may record (the console
 * user), where files go (`record_dir`, validated there), and what a name may
 * be. This page only asks.
 */
(function () {
  'use strict';
  const { $, invoke, show, hide, setText, fmtBytes } = window.Roomler;

  /* ── pure helpers (exported for the unit tests) ─────────────────── */

  // `m:ss`, or `h:mm:ss` past the hour.
  function fmtDuration(ms) {
    const s = Math.floor(Math.max(0, Number(ms) || 0) / 1000);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const ss = String(s % 60).padStart(2, '0');
    return h > 0 ? h + ':' + String(m).padStart(2, '0') + ':' + ss : m + ':' + ss;
  }

  // One phrase per closed stop reason (`sidecar.rs` StopReason) and per
  // refusal code. A code this page has never heard of (a newer service)
  // reads as itself rather than as nothing.
  const ENDINGS = {
    requested: 'stopped',
    host_stopped: 'stopped on this device',
    session_ended: 'the remote session ended',
    session_changed: 'the signed-in user changed',
    display_changed: 'the display changed size',
    disk_low: 'the disk was nearly full',
    max_duration: 'it reached the maximum length',
    encoder_failed: 'the video encoder failed',
    capture_failed: 'screen capture failed',
    gate_revoked: 'remote recording was switched off',
    parent_gone: 'the device service stopped',
    interrupted: 'it was cut off, and recovered afterwards',
    recorder_exited: 'the recorder exited unexpectedly',
    start_timeout: 'the recorder did not start in time',
    no_frame: 'no picture came from the screen',
    encoder_unavailable: 'no video encoder could be opened',
    folder_unwritable: 'the folder could not be written',
    audio_unavailable: 'this device cannot record audio',
    system_audio_unavailable: 'computer audio could not be captured on this device',
    mic_unavailable: 'the microphone could not be opened',
    audio_failed: 'the audio failed, and the rest was recorded without it',
  };

  function describeEnding(reason) {
    return ENDINGS[reason] || String(reason || 'unknown');
  }

  // How the last recording ended, in one sentence.
  function describeLast(last) {
    if (!last) return '';
    const head = last.path
      ? 'Last recording: ' + fmtDuration(last.duration_ms) + ', ' + fmtBytes(last.bytes)
      : 'The last recording did not start';
    const why = last.reason === 'requested' ? '' : ' — ' + describeEnding(last.reason);
    const detail = last.detail ? ' (' + last.detail + ')' : '';
    return head + why + detail + '.';
  }

  function fmtWhen(rfc3339) {
    if (!rfc3339) return '—';
    const d = new Date(rfc3339);
    return Number.isNaN(d.getTime()) ? String(rfc3339) : d.toLocaleString();
  }

  function errorText(e) {
    return String(e && e.message ? e.message : e);
  }

  /* ── state ──────────────────────────────────────────────────────── */

  let lastGood = null; // the last view that rendered
  let inFlight = 0; // refreshes outstanding — a count, not a flag (FR-84 D1)
  let lastRefreshAt = 0;
  let busy = false; // a start / stop / folder change in flight
  let pendingDelete = null; // the name whose Delete was clicked once
  const rows = new Map(); // name → { tr, cells, del }

  function visible() {
    const s = $('view-recordings');
    return !!s && !s.hidden;
  }

  function isActive(view) {
    return !!(view && view.state && view.state.active);
  }

  // #1760 — why this device's service cannot record what the computer plays
  // (a Mac, until ScreenCaptureKit; a service built without audio capture),
  // said by the service ahead of any start; null where it can, and from a
  // service older than the field.
  function systemAudioUnavailable(view) {
    const st = (view && view.state) || {};
    return st.system_audio_unavailable_reason ? String(st.system_audio_unavailable_reason) : null;
  }

  /* ── render ─────────────────────────────────────────────────────── */

  function setControlsEnabled(enabled) {
    for (const id of ['rec-start', 'rec-stop', 'rec-fps', 'rec-encoder', 'rec-folder-change', 'rec-folder-default', 'rec-folder-open']) {
      const el = $(id);
      if (el) el.disabled = !enabled;
    }
  }

  function renderControl(view) {
    const st = view.state || {};
    const rec = isActive(view);
    if (rec) {
      setText('rec-live-time', fmtDuration(st.duration_ms));
      show($('rec-live'));
      const parts = [fmtDuration(st.duration_ms), fmtBytes(st.bytes)];
      if (st.encoder) parts.push(st.encoder);
      if (st.system_audio || st.microphone) {
        parts.push(
          st.system_audio && st.microphone
            ? 'computer audio + microphone'
            : st.system_audio
              ? 'computer audio'
              : 'microphone',
        );
      }
      if (st.width && st.height) parts.push(st.width + '×' + st.height + ' @ ' + st.fps + ' fps');
      // FR-85 P3b — a remote controller's recording says whose it is.
      const lead = st.remote_controller
        ? 'Recording for ' + st.remote_controller + ' (remote)'
        : 'Recording';
      setText('rec-status', lead + ' — ' + parts.join(', '));
    } else {
      hide($('rec-live'));
      setText('rec-status', 'Not recording.');
    }
    // A service that cannot record here says why ahead of time (no recorder
    // in this build; SYSTEM/root until the recorder runs as you): Start is
    // greyed out with the reason beside it, never a button that only fails.
    const can = st.available !== false;
    const why = $('rec-unavailable');
    if (!can && !rec) {
      why.textContent = 'Recording is not available here: ' + (st.unavailable_reason || 'no reason given') + '.';
      show(why);
    } else {
      hide(why);
    }
    $('rec-start').hidden = rec;
    $('rec-stop').hidden = !rec;
    $('rec-start').disabled = busy || !can;
    $('rec-stop').disabled = busy;
    // The options apply to the NEXT recording; locked while one runs.
    $('rec-fps').disabled = rec || busy || !can;
    $('rec-encoder').disabled = rec || busy || !can;
    // #1760 — where the service cannot record what the computer plays, the
    // box is greyed out, unticked, with the words beside it: never a box
    // that only fails (the recorder would refuse `system_audio_unavailable`
    // and the person would learn why only from the last-recording line).
    const noSystemAudio = systemAudioUnavailable(view);
    const sys = $('rec-system-audio');
    sys.disabled = rec || busy || !can || !!noSystemAudio;
    if (noSystemAudio) sys.checked = false;
    const sysWhy = $('rec-system-audio-unavailable');
    if (noSystemAudio) {
      sysWhy.textContent = 'Computer audio is not available here: ' + noSystemAudio + '.';
      show(sysWhy);
    } else {
      hide(sysWhy);
    }
    $('rec-microphone').disabled = rec || busy || !can;
    const lastEl = $('rec-last');
    if (!rec && st.last) {
      lastEl.textContent = describeLast(st.last);
      show(lastEl);
    } else {
      hide(lastEl);
    }
  }

  function renderFolder(view) {
    const listing = view.listing || {};
    setText('rec-folder', listing.dir || '—');
    const chosen = view.record_dir || null;
    setText('rec-folder-note', chosen ? 'A folder you chose.' : 'The default folder.');
    show($('rec-folder-note'));
    $('rec-folder-default').hidden = !chosen;
    $('rec-folder-change').disabled = busy;
    $('rec-folder-default').disabled = busy;
    $('rec-folder-open').disabled = false;
    const reason = $('rec-folder-reason');
    if (listing.folder_reason) {
      reason.textContent = 'Not the usual folder: ' + listing.folder_reason + '.';
      show(reason);
    } else {
      hide(reason);
    }
  }

  /* ── FR-85 P3b — the remote-recording gates ─────────────────────── */

  let remoteBusy = false;

  function renderRemote(view) {
    const card = $('rec-remote');
    const g = view.remote;
    if (!g) {
      hide(card);
      return;
    }
    show(card);
    const en = $('rec-remote-enabled');
    const au = $('rec-remote-audio');
    // #1760 — where the service cannot record what the computer plays, the
    // effective gate is OFF whatever the key says (the device never
    // advertises `remote-audio` there), so the toggle is greyed out,
    // unticked, with the words: switching it on would change nothing.
    const noSystemAudio = systemAudioUnavailable(view);
    // Never repaint a box while its change is in flight.
    if (!remoteBusy) {
      en.checked = !!g.enabled;
      au.checked = !!g.audio && !noSystemAudio;
    }
    en.disabled = remoteBusy;
    // Computer audio means nothing until remote recording is allowed.
    au.disabled = remoteBusy || !g.enabled || !!noSystemAudio;
    const why = $('rec-remote-audio-unavailable');
    if (noSystemAudio) {
      why.textContent = "Computer audio can't be included: " + noSystemAudio + '.';
      show(why);
    } else {
      hide(why);
    }
  }

  async function setRemote(key, on) {
    remoteBusy = true;
    hide($('rec-remote-error'));
    try {
      await invoke('cmd_config_set', { key, value: on ? 'true' : 'false' });
    } catch (e) {
      const el = $('rec-remote-error');
      el.textContent = errorText(e);
      show(el);
    } finally {
      remoteBusy = false;
      await refresh({ force: true });
    }
  }

  function smallButton(label, onClick) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'sm';
    b.textContent = label;
    b.addEventListener('click', onClick);
    return b;
  }

  function makeRow(name) {
    const tr = document.createElement('tr');
    tr.dataset.name = name;
    const cells = {};
    for (const k of ['name', 'when', 'len', 'size', 'by']) {
      const td = document.createElement('td');
      tr.appendChild(td);
      cells[k] = td;
    }
    cells.name.className = 'mono small';
    const act = document.createElement('td');
    const wrap = document.createElement('div');
    wrap.className = 'actions';
    wrap.style.margin = '0';
    const del = smallButton('Delete', () => void deleteRecording(name));
    del.classList.add('danger');
    // FR-85 P5c — only where this device's service has the export engine.
    const edit = smallButton('Edit', () => void editRecording(name));
    edit.hidden = !canEdit;
    wrap.append(
      smallButton('Play', () => void openRecording(name, false)),
      edit,
      smallButton('Show', () => void openRecording(name, true)),
      del,
    );
    act.appendChild(wrap);
    tr.appendChild(act);
    return { tr, cells, del, edit };
  }

  /* ── FR-85 P5c — the Edit view (`editor.js`) ────────────────────── */

  let canEdit = false;

  function askEngine() {
    const editor = window.RoomlerEditor;
    if (!editor) return;
    void editor.engineAvailable().then((ok) => {
      canEdit = ok;
      for (const row of rows.values()) row.edit.hidden = !ok;
    });
  }

  async function editRecording(name) {
    hide($('rec-list-error'));
    try {
      await window.RoomlerEditor.open(name);
    } catch (e) {
      const el = $('rec-list-error');
      el.textContent = errorText(e);
      show(el);
    }
  }

  function fillRow(row, it) {
    row.cells.name.textContent = it.name;
    row.cells.when.textContent = fmtWhen(it.started_at);
    row.cells.len.textContent = it.duration_ms ? fmtDuration(it.duration_ms) : '—';
    row.cells.size.textContent = fmtBytes(it.bytes);
    row.cells.by.textContent =
      it.origin === 'remote' ? 'Remote' + (it.controller ? ' · ' + it.controller : '') : 'This device';
    row.tr.title =
      it.stop_reason && it.stop_reason !== 'requested' ? 'Ended: ' + describeEnding(it.stop_reason) : '';
    row.del.textContent = pendingDelete === it.name ? 'Confirm delete' : 'Delete';
  }

  function renderList(view) {
    const items = (view.listing && view.listing.items) || [];
    const body = $('rec-body');
    const names = new Set(items.map((i) => i.name));
    for (const [name, row] of rows) {
      if (!names.has(name)) {
        row.tr.remove();
        rows.delete(name);
        if (pendingDelete === name) pendingDelete = null;
      }
    }
    let prev = null;
    for (const it of items) {
      let row = rows.get(it.name);
      if (!row) {
        row = makeRow(it.name);
        rows.set(it.name, row);
      }
      fillRow(row, it);
      // Keep the daemon's order (newest first) without touching a row that
      // is already where it belongs.
      const want = prev ? prev.nextSibling : body.firstChild;
      if (want !== row.tr) body.insertBefore(row.tr, want);
      prev = row.tr;
    }
    $('rec-table').hidden = items.length === 0;
    $('rec-empty').hidden = items.length !== 0;
  }

  function render(view) {
    const banner = $('rec-banner');
    if (!view || !view.available) {
      const why = view && view.reason ? view.reason : 'the device service did not answer';
      banner.textContent =
        'Live data unavailable — ' + why + (lastGood ? '. Showing the last good data.' : '.');
      show(banner);
      if (!lastGood) setControlsEnabled(false);
      return;
    }
    if (view.unsupported) {
      banner.textContent =
        'This device service has no screen recorder yet — update it to record.';
      show(banner);
      setControlsEnabled(false);
      lastGood = null;
      return;
    }
    hide(banner);
    lastGood = view;
    renderControl(view);
    renderFolder(view);
    renderRemote(view);
    renderList(view);
  }

  /* ── refresh ────────────────────────────────────────────────────── */

  async function refresh(opts) {
    const force = !!(opts && opts.force);
    if (!force && (!visible() || inFlight > 0)) return;
    inFlight += 1;
    lastRefreshAt = Date.now();
    try {
      render(await invoke('cmd_recordings_view'));
    } catch (e) {
      render({ available: false, reason: errorText(e) });
    } finally {
      inFlight -= 1;
    }
  }

  function tick() {
    if (!visible() || inFlight > 0) return;
    const period = isActive(lastGood) ? 1000 : 5000;
    if (Date.now() - lastRefreshAt >= period) void refresh();
  }

  /* ── actions ────────────────────────────────────────────────────── */

  async function withBusy(errorId, label, fn) {
    if (busy) return;
    busy = true;
    hide($(errorId));
    const btn = label && $(label.id);
    const before = btn ? btn.textContent : null;
    if (btn) btn.textContent = label.text;
    if (lastGood) renderControl(lastGood);
    try {
      await fn();
    } catch (e) {
      const el = $(errorId);
      el.textContent = errorText(e);
      show(el);
    } finally {
      if (btn) btn.textContent = before;
      busy = false;
      await refresh({ force: true });
    }
  }

  function start() {
    return withBusy('rec-error', { id: 'rec-start', text: 'Starting…' }, () =>
      invoke('cmd_record_start', {
        fps: Number($('rec-fps').value) || 30,
        encoder: $('rec-encoder').value || 'auto',
        // FR-85 P1c — both OFF unless ticked.
        systemAudio: !!$('rec-system-audio').checked,
        microphone: !!$('rec-microphone').checked,
      }),
    );
  }

  function stop() {
    // The answer comes once the file is final — a long recording's remux
    // copies every byte once, so say what the wait is.
    return withBusy('rec-error', { id: 'rec-stop', text: 'Finishing the file…' }, () =>
      invoke('cmd_record_stop'),
    );
  }

  function changeFolder() {
    return withBusy('rec-folder-error', null, async () => {
      const current = lastGood && lastGood.listing ? lastGood.listing.dir : null;
      const picked = await invoke('cmd_pick_record_dir', { current });
      if (picked) await invoke('cmd_config_set', { key: 'record_dir', value: picked });
    });
  }

  function useDefaultFolder() {
    return withBusy('rec-folder-error', null, () =>
      invoke('cmd_config_set', { key: 'record_dir', value: null }),
    );
  }

  async function openRecording(name, reveal) {
    hide($('rec-list-error'));
    try {
      await invoke('cmd_recording_open', { name, reveal });
    } catch (e) {
      const el = $('rec-list-error');
      el.textContent = errorText(e);
      show(el);
    }
  }

  async function openFolder() {
    hide($('rec-folder-error'));
    try {
      await invoke('cmd_recording_open', { name: null, reveal: false });
    } catch (e) {
      const el = $('rec-folder-error');
      el.textContent = errorText(e);
      show(el);
    }
  }

  // Two clicks, no modal: the first arms the button for 4 s.
  async function deleteRecording(name) {
    if (pendingDelete !== name) {
      pendingDelete = name;
      if (lastGood) renderList(lastGood);
      setTimeout(() => {
        if (pendingDelete === name) {
          pendingDelete = null;
          if (lastGood) renderList(lastGood);
        }
      }, 4000);
      return;
    }
    pendingDelete = null;
    hide($('rec-list-error'));
    try {
      await invoke('cmd_recording_delete', { name });
    } catch (e) {
      const el = $('rec-list-error');
      el.textContent = errorText(e);
      show(el);
    }
    await refresh({ force: true });
  }

  /* ── boot ───────────────────────────────────────────────────────── */

  function boot() {
    $('rec-start').addEventListener('click', () => void start());
    $('rec-stop').addEventListener('click', () => void stop());
    $('rec-folder-change').addEventListener('click', () => void changeFolder());
    $('rec-folder-default').addEventListener('click', () => void useDefaultFolder());
    $('rec-folder-open').addEventListener('click', () => void openFolder());
    $('rec-remote-enabled').addEventListener('change', (ev) => {
      void setRemote('record_remote_enabled', ev.target.checked);
    });
    $('rec-remote-audio').addEventListener('change', (ev) => {
      void setRemote('record_remote_audio', ev.target.checked);
    });
    document.addEventListener('roomler:view', (ev) => {
      if (ev.detail === 'recordings') void refresh({ force: true });
    });
    // An export lands in the folder: the list shows it on the way back.
    document.addEventListener('roomler:editor-closed', () => void refresh({ force: true }));
    askEngine();
    setInterval(tick, 1000);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();

  // The tray's Start/Stop reports a refusal here — it has nowhere else to
  // put a sentence (tray.rs `toggle_recording`).
  function showError(message) {
    const el = $('rec-error');
    el.textContent = String(message || '');
    show(el);
    void refresh({ force: true });
  }

  window.RoomlerRecordings = { fmtDuration, describeEnding, describeLast, render, refresh, showError };
})();
