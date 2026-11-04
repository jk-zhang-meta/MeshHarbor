// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
/*
 * The Edit view (FR-85 P5c): cut pieces out of a recording, speed pieces
 * up, lay music under it, and export a new file beside it.
 *
 * Editing is non-destructive. The page keeps an EDIT LIST, saved beside the
 * recording as `<name>.edit.json` after every change, and the recording is
 * never written. The export is `roomlerd media`, which the companion runs as
 * the person; this page asks, and polls `cmd_export_status`.
 *
 * The pieces always cover the recording from 0 to its end, in order: a split
 * makes two, and each is kept, cut or sped up on its own. The file is
 * roomlerd's (`recording/edit.rs`), which validates it again and refuses by
 * name. The preview approximates the export with the player: a
 * cut is skipped, a speed-up plays at its rate, muted as the export mutes it.
 *
 * Everything is built with createElement + textContent (no innerHTML).
 */
(function () {
  'use strict';
  const { $, invoke, show, hide, setText, fmtBytes } = window.Roomler;

  /* ── pure helpers (exported for the unit tests) ─────────────────── */

  // What the Speed button offers; the file allows 1.25–16 in quarter steps.
  const SPEEDS = [1.5, 2, 4, 8, 16];
  // A split never leaves a piece shorter than this: a sliver nobody can click.
  const MIN_PIECE_MS = 200;

  function fmtDuration(ms) {
    const s = Math.floor(Math.max(0, Number(ms) || 0) / 1000);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const ss = String(s % 60).padStart(2, '0');
    return h > 0 ? h + ':' + String(m).padStart(2, '0') + ':' + ss : m + ':' + ss;
  }

  function whole(durationMs) {
    return [{ start_ms: 0, end_ms: Math.max(0, Math.round(durationMs)), action: 'keep' }];
  }

  // The piece under `ms` (the last one past the end).
  function indexAt(segs, ms) {
    for (let i = 0; i < segs.length; i++) if (ms < segs[i].end_ms) return i;
    return segs.length - 1;
  }

  // Split the piece under `ms` in two, or null when that would leave a sliver.
  function splitAt(segs, ms) {
    const at = Math.round(ms);
    const i = indexAt(segs, at);
    const s = segs[i];
    if (!s || at - s.start_ms < MIN_PIECE_MS || s.end_ms - at < MIN_PIECE_MS) return null;
    return segs
      .slice(0, i)
      .concat([Object.assign({}, s, { end_ms: at }), Object.assign({}, s, { start_ms: at })], segs.slice(i + 1));
  }

  // Piece `i` kept, cut, or sped up by `speed`. Its neighbours are left
  // alone even when they now do the same: a split is the person's, made to
  // be used, and merging it away on the next click would take it back.
  function setAction(segs, i, action, speed) {
    return segs.map((s, k) => {
      if (k !== i) return Object.assign({}, s);
      const t = { start_ms: s.start_ms, end_ms: s.end_ms, action };
      if (action === 'speed') t.speed = speed;
      return t;
    });
  }

  // The export's length: kept pieces whole, sped-up ones divided by their
  // speed, cut ones gone.
  function outputMs(segs) {
    let ms = 0;
    for (const s of segs) {
      const len = s.end_ms - s.start_ms;
      if (s.action === 'keep') ms += len;
      else if (s.action === 'speed') ms += len / s.speed;
    }
    return Math.round(ms);
  }

  function nothingKept(segs) {
    return segs.every((s) => s.action === 'cut');
  }

  // The file roomlerd reads. Defaults stay out of it: an untouched volume is
  // "as recorded", not a number.
  function toEditList(source, segs, sound) {
    const list = {
      version: 1,
      source,
      segments: segs.map((s) =>
        s.action === 'speed'
          ? { start_ms: s.start_ms, end_ms: s.end_ms, action: 'speed', speed: s.speed }
          : { start_ms: s.start_ms, end_ms: s.end_ms, action: s.action },
      ),
    };
    if (sound.originalVolume !== 1) list.original_volume = sound.originalVolume;
    if (sound.music) {
      const m = sound.music;
      list.music = {
        path: m.path,
        volume: m.volume,
        start_ms: m.start_ms,
        fade_in_ms: m.fade_in_ms,
        fade_out_ms: m.fade_out_ms,
        loop: m.loop,
      };
    }
    return list;
  }

  function validSpeed(v) {
    const q = Number(v) * 4;
    return Number.isFinite(q) && Math.abs(q - Math.round(q)) < 1e-9 && q >= 5 && q <= 64;
  }

  function volume(v, fallback) {
    const n = Number(v);
    return Number.isFinite(n) && n >= 0 && n <= 1 ? n : fallback;
  }

  function ms(v) {
    const n = Math.round(Number(v));
    return Number.isFinite(n) && n > 0 ? n : 0;
  }

  // A saved list back into pieces, fitted to this recording. A list that
  // does not fit (another length, a gap, a bad speed) starts over from the
  // whole recording, and `fitted` says so; what follows the last piece is
  // kept, as roomlerd keeps it.
  function fromEditList(list, durationMs) {
    const sound = { originalVolume: 1, music: null };
    const fresh = { segs: whole(durationMs), sound, fitted: false };
    if (!list || typeof list !== 'object' || list.version !== 1 || !Array.isArray(list.segments)) {
      return fresh;
    }
    sound.originalVolume = volume(list.original_volume, 1);
    const m = list.music;
    if (m && typeof m === 'object' && typeof m.path === 'string' && m.path.trim()) {
      sound.music = {
        path: m.path,
        volume: volume(m.volume, 0.5),
        start_ms: ms(m.start_ms),
        fade_in_ms: ms(m.fade_in_ms),
        fade_out_ms: ms(m.fade_out_ms),
        loop: m.loop !== false,
      };
    }
    const end = Math.round(durationMs);
    const segs = [];
    let at = 0;
    for (const s of list.segments) {
      if (!s || s.start_ms !== at || !(s.end_ms > s.start_ms)) return Object.assign(fresh, { sound });
      if (!['keep', 'cut', 'speed'].includes(s.action)) return Object.assign(fresh, { sound });
      if (s.action === 'speed' && !validSpeed(s.speed)) return Object.assign(fresh, { sound });
      at = s.end_ms;
      if (s.start_ms >= end) continue;
      const t = { start_ms: s.start_ms, end_ms: Math.min(s.end_ms, end), action: s.action };
      if (s.action === 'speed') t.speed = Number(s.speed);
      segs.push(t);
    }
    if (segs.length === 0) return Object.assign(fresh, { sound });
    // What follows the last piece is kept: a kept last piece simply goes on,
    // and only after a cut or a speed-up does a piece of its own appear (no
    // split the person never made).
    if (at < end) {
      const last = segs[segs.length - 1];
      if (last.action === 'keep') last.end_ms = end;
      else segs.push({ start_ms: at, end_ms: end, action: 'keep' });
    }
    return { segs, sound, fitted: true };
  }

  // What the player does at `ms`: skip a cut to the next piece that plays
  // (`end` when none does), play a speed-up at its rate and muted.
  function previewAt(segs, at, originalVolume) {
    const i = indexAt(segs, at);
    const s = segs[i];
    if (!s) return { end: true };
    if (s.action === 'cut') {
      let k = i;
      while (k < segs.length && segs[k].action === 'cut') k++;
      return k < segs.length ? { skipTo: segs[k].start_ms } : { end: true };
    }
    return {
      rate: s.action === 'speed' ? s.speed : 1,
      muted: s.action === 'speed' || originalVolume === 0,
    };
  }

  // One phrase per closed refusal code of `roomlerd media` (and the
  // companion's own `engine_failed`). A code this page has never heard of
  // (a newer service) reads as itself.
  const REFUSALS = {
    bad_edit_list: 'the edits cannot be followed',
    source_unreadable: 'the recording cannot be read',
    decoder_unavailable: 'this recording was made with the GPU encoder, and this device has no decoder for it',
    encoder_unavailable: 'no video encoder could be opened',
    decode_failed: 'the recording could not be decoded',
    write_failed: 'the new file could not be written',
    music_unreadable: 'the music file cannot be read',
    audio_unavailable: 'this device cannot put sound in a video',
    cancelled: 'the export was cancelled',
    engine_failed: 'the export stopped unexpectedly',
  };

  function describeRefusal(r) {
    if (!r) return '';
    const head = REFUSALS[r.code] || String(r.code || 'refused');
    return head.charAt(0).toUpperCase() + head.slice(1) + (r.detail ? ' (' + r.detail + ')' : '') + '.';
  }

  // What the new file's sound is, in words (`done.audio`).
  const SOUND = {
    none: 'no sound',
    original: "the recording's sound",
    music: 'the music',
    original_and_music: "the recording's sound and the music",
    not_carried: 'no sound: this device cannot encode audio',
  };

  function baseName(path) {
    return String(path || '').split(/[\\/]/).pop();
  }

  function describeDone(done) {
    const parts = [fmtDuration(done.duration_ms), fmtBytes(done.bytes)];
    const sound = SOUND[done.audio] || String(done.audio || 'no sound');
    return 'Saved as ' + baseName(done.path) + ' — ' + parts.join(', ') + ', with ' + sound + '.';
  }

  function errorText(e) {
    return String(e && e.message ? e.message : e);
  }

  /* ── state ──────────────────────────────────────────────────────── */

  let cur = null; // { name, durationMs, hasAudio, segs, sound, selected }
  let saveTimer = null;
  let saving = null; // the save in flight, so an export waits for it
  let pollTimer = null;
  let exporting = false;
  let available = null; // the engine: a promise of a boolean, asked once

  function engineAvailable() {
    if (!available) {
      available = invoke('cmd_media_available').then(
        (v) => !!v,
        () => false,
      );
    }
    return available;
  }

  /* ── render ─────────────────────────────────────────────────────── */

  function pct(v) {
    return cur.durationMs > 0 ? (100 * v) / cur.durationMs : 0;
  }

  function label(s) {
    return s.action === 'cut' ? 'cut' : s.action === 'speed' ? s.speed + '×' : 'kept';
  }

  function renderTimeline() {
    const tl = $('ed-timeline');
    for (const n of Array.from(tl.querySelectorAll('.ed-seg'))) n.remove();
    const head = $('ed-playhead');
    cur.segs.forEach((s, i) => {
      const d = document.createElement('button');
      d.type = 'button';
      d.className = 'ed-seg ed-' + s.action + (i === cur.selected ? ' ed-selected' : '');
      d.style.left = pct(s.start_ms) + '%';
      d.style.width = pct(s.end_ms - s.start_ms) + '%';
      d.dataset.index = String(i);
      d.textContent = s.action === 'keep' ? '' : label(s);
      d.title = fmtDuration(s.start_ms) + '–' + fmtDuration(s.end_ms) + ': ' + label(s);
      d.disabled = exporting;
      tl.insertBefore(d, head);
    });
  }

  function renderSelection() {
    const s = cur.segs[cur.selected];
    const note = s
      ? 'Selected: ' + fmtDuration(s.start_ms) + '–' + fmtDuration(s.end_ms) + ', ' + label(s) + '.'
      : '';
    setText('ed-selection', note);
    for (const id of ['ed-split', 'ed-keep', 'ed-cut', 'ed-speed', 'ed-speed-apply']) {
      $(id).disabled = exporting;
    }
    if (s) {
      $('ed-keep').disabled = exporting || s.action === 'keep';
      $('ed-cut').disabled = exporting || s.action === 'cut';
    }
  }

  function renderSound() {
    const snd = cur.sound;
    const vol = Math.round(snd.originalVolume * 100);
    $('ed-original-volume').value = String(vol);
    setText('ed-original-volume-value', vol + ' %');
    $('ed-original-volume').disabled = exporting || !cur.hasAudio;
    $('ed-original-note').hidden = cur.hasAudio;
    const m = snd.music;
    $('ed-music-pick').textContent = m ? 'Change music…' : 'Add music…';
    $('ed-music-pick').disabled = exporting;
    setText('ed-music-name', m ? baseName(m.path) : '');
    $('ed-music-remove').hidden = !m;
    $('ed-music-remove').disabled = exporting;
    $('ed-music-options').hidden = !m;
    if (m) {
      $('ed-music-volume').value = String(Math.round(m.volume * 100));
      $('ed-music-start').value = String(m.start_ms / 1000);
      $('ed-music-fade-in').value = String(m.fade_in_ms / 1000);
      $('ed-music-fade-out').value = String(m.fade_out_ms / 1000);
      $('ed-music-loop').checked = !!m.loop;
      for (const id of ['ed-music-volume', 'ed-music-start', 'ed-music-fade-in', 'ed-music-fade-out', 'ed-music-loop']) {
        $(id).disabled = exporting;
      }
    }
  }

  function renderSummary() {
    const out = outputMs(cur.segs);
    setText('ed-summary', 'The export: ' + fmtDuration(out) + ' of ' + fmtDuration(cur.durationMs));
    const none = nothingKept(cur.segs);
    const why = $('ed-export-why');
    if (none) {
      why.textContent = 'Everything is cut: there is nothing to export.';
      show(why);
    } else {
      hide(why);
    }
    $('ed-export').disabled = exporting || none;
    $('ed-encoder').disabled = exporting;
    $('ed-export').hidden = exporting;
    $('ed-export-cancel').hidden = !exporting;
  }

  function render() {
    if (!cur) return;
    renderTimeline();
    renderSelection();
    renderSound();
    renderSummary();
  }

  /* ── the edit list: every change saved ──────────────────────────── */

  function changed() {
    render();
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => void save(), 400);
  }

  async function save() {
    clearTimeout(saveTimer);
    saveTimer = null;
    if (!cur) return;
    const name = cur.name;
    const list = toEditList(name, cur.segs, cur.sound);
    const run = (async () => {
      try {
        await invoke('cmd_edit_save', { name, list });
        setText('ed-saved', 'Your edits are saved beside the recording.');
        show($('ed-saved'));
        hide($('ed-save-error'));
      } catch (e) {
        const el = $('ed-save-error');
        el.textContent = 'The edits could not be saved: ' + errorText(e);
        show(el);
      }
    })();
    saving = run;
    await run;
    if (saving === run) saving = null;
  }

  /* ── editing ────────────────────────────────────────────────────── */

  function playheadMs() {
    const v = $('ed-video');
    const t = Number(v && v.currentTime) * 1000;
    return Number.isFinite(t) ? Math.min(Math.max(0, t), cur.durationMs) : 0;
  }

  function select(i) {
    if (!cur || i < 0 || i >= cur.segs.length) return;
    cur.selected = i;
    render();
  }

  function split() {
    const at = playheadMs();
    const next = splitAt(cur.segs, at);
    const note = $('ed-note');
    if (!next) {
      note.textContent = 'Move the playhead further into a piece to split it there.';
      show(note);
      return;
    }
    hide(note);
    cur.segs = next;
    cur.selected = indexAt(next, at);
    changed();
  }

  function apply(action) {
    const s = cur.segs[cur.selected];
    if (!s) return;
    const mid = (s.start_ms + s.end_ms) / 2;
    const speed = Number($('ed-speed').value) || 2;
    cur.segs = setAction(cur.segs, cur.selected, action, speed);
    cur.selected = indexAt(cur.segs, mid);
    changed();
  }

  function seek(at) {
    const v = $('ed-video');
    if (v) {
      try {
        v.currentTime = at / 1000;
      } catch (_) {
        /* no media loaded */
      }
    }
    drawPlayhead(at);
  }

  function drawPlayhead(at) {
    $('ed-playhead').style.left = pct(at) + '%';
    setText('ed-time', fmtDuration(at) + ' / ' + fmtDuration(cur.durationMs));
  }

  function timelineClick(ev) {
    if (exporting) return;
    const seg = ev.target.closest && ev.target.closest('.ed-seg');
    const tl = $('ed-timeline');
    const box = tl.getBoundingClientRect();
    let at = null;
    if (box.width > 0) at = ((ev.clientX - box.left) / box.width) * cur.durationMs;
    if (seg) {
      const i = Number(seg.dataset.index);
      if (at == null) at = cur.segs[i] ? cur.segs[i].start_ms : 0;
      select(i);
    } else if (at != null) {
      select(indexAt(cur.segs, at));
    }
    if (at != null) seek(Math.min(Math.max(0, at), cur.durationMs));
  }

  /* ── sound ──────────────────────────────────────────────────────── */

  async function pickMusic() {
    hide($('ed-music-error'));
    try {
      const path = await invoke('cmd_pick_music');
      if (!path) return;
      const before = cur.sound.music;
      cur.sound.music = before
        ? Object.assign({}, before, { path })
        : { path, volume: 0.5, start_ms: 0, fade_in_ms: 0, fade_out_ms: 0, loop: true };
      changed();
    } catch (e) {
      const el = $('ed-music-error');
      el.textContent = errorText(e);
      show(el);
    }
  }

  function seconds(id) {
    return ms(Number($(id).value) * 1000);
  }

  function musicInput() {
    const m = cur.sound.music;
    if (!m) return;
    m.volume = volume(Number($('ed-music-volume').value) / 100, m.volume);
    m.start_ms = seconds('ed-music-start');
    m.fade_in_ms = seconds('ed-music-fade-in');
    m.fade_out_ms = seconds('ed-music-fade-out');
    m.loop = !!$('ed-music-loop').checked;
    changed();
  }

  /* ── the preview ────────────────────────────────────────────────── */

  const frame = window.requestAnimationFrame
    ? (f) => window.requestAnimationFrame(f)
    : (f) => setTimeout(f, 16);

  function follow() {
    const v = $('ed-video');
    if (!cur || !v) return;
    const at = playheadMs();
    const p = previewAt(cur.segs, at, cur.sound.originalVolume);
    if (p.end) {
      v.pause();
    } else if (p.skipTo != null) {
      seek(p.skipTo);
    } else {
      if (v.playbackRate !== p.rate) v.playbackRate = p.rate;
      v.muted = p.muted;
      v.volume = cur.sound.originalVolume;
    }
    drawPlayhead(playheadMs());
    if (!v.paused && !v.ended) frame(follow);
  }

  function togglePlay() {
    const v = $('ed-video');
    if (!v) return;
    if (v.paused) {
      const played = v.play();
      if (played && played.catch) played.catch(() => {});
      frame(follow);
    } else {
      v.pause();
    }
  }

  async function loadPreview(name) {
    const v = $('ed-video');
    const note = $('ed-preview-note');
    hide(note);
    const core = window.__TAURI__ && window.__TAURI__.core;
    if (!core || !core.convertFileSrc) {
      v.removeAttribute('src');
      return;
    }
    try {
      const path = await invoke('cmd_preview_src', { name });
      if (!cur || cur.name !== name) return;
      v.src = core.convertFileSrc(path);
    } catch (e) {
      note.textContent = 'No preview: ' + errorText(e) + '. The timeline and the export still work.';
      show(note);
    }
  }

  /* ── export ─────────────────────────────────────────────────────── */

  function renderExport(st) {
    const bar = $('ed-progress');
    const status = $('ed-export-status');
    const result = $('ed-result');
    const error = $('ed-export-error');
    exporting = !!st.running;
    if (st.running) {
      bar.max = Math.max(1, st.total || 1);
      bar.value = Math.min(st.frames || 0, bar.max);
      show(bar);
      const p = st.total ? Math.floor((100 * (st.frames || 0)) / st.total) : 0;
      status.textContent = 'Exporting… ' + p + ' %';
      show(status);
      hide(result);
      hide(error);
    } else {
      hide(bar);
      hide(status);
      if (st.done) {
        setText('ed-result-text', describeDone(st.done));
        result.dataset.file = baseName(st.done.path);
        show(result);
        hide(error);
      } else if (st.refused) {
        error.textContent = describeRefusal(st.refused);
        show(error);
        hide(result);
      }
    }
    render();
  }

  async function poll() {
    clearTimeout(pollTimer);
    pollTimer = null;
    let st;
    try {
      st = await invoke('cmd_export_status');
    } catch (e) {
      st = { running: false, refused: { code: 'engine_failed', detail: errorText(e) } };
    }
    if (!cur || (st.name && st.name !== cur.name)) {
      exporting = !!st.running;
      if (cur) render();
      return;
    }
    renderExport(st);
    if (st.running) pollTimer = setTimeout(() => void poll(), 400);
  }

  async function startExport() {
    if (!cur || exporting || nothingKept(cur.segs)) return;
    hide($('ed-export-error'));
    hide($('ed-result'));
    // The engine reads the list from disk: the last change must be on it.
    if (saveTimer) await save();
    if (saving) await saving;
    exporting = true;
    render();
    try {
      const st = await invoke('cmd_export_start', { name: cur.name, encoder: $('ed-encoder').value || 'auto' });
      renderExport(st);
      pollTimer = setTimeout(() => void poll(), 400);
    } catch (e) {
      exporting = false;
      const el = $('ed-export-error');
      el.textContent = errorText(e);
      show(el);
      render();
    }
  }

  async function cancelExport() {
    try {
      await invoke('cmd_export_cancel');
    } catch (e) {
      const el = $('ed-export-error');
      el.textContent = errorText(e);
      show(el);
    }
  }

  async function openResult(reveal) {
    const name = $('ed-result').dataset.file;
    if (!name) return;
    try {
      await invoke('cmd_recording_open', { name, reveal });
    } catch (e) {
      const el = $('ed-export-error');
      el.textContent = errorText(e);
      show(el);
    }
  }

  /* ── open / close ───────────────────────────────────────────────── */

  async function open(name) {
    if (saveTimer) await save();
    cur = null;
    clearTimeout(pollTimer);
    hide($('rec-main'));
    show($('rec-editor'));
    setText('ed-title', 'Edit ' + name);
    for (const id of ['ed-banner', 'ed-body', 'ed-sound', 'ed-export-card', 'ed-note', 'ed-saved', 'ed-save-error', 'ed-result', 'ed-export-error', 'ed-music-error']) {
      hide($(id));
    }
    setText('ed-summary', '');
    const banner = $('ed-banner');
    let probe;
    try {
      probe = await invoke('cmd_media_probe', { name });
    } catch (e) {
      banner.textContent = 'This recording cannot be opened for editing: ' + errorText(e) + '.';
      show(banner);
      return;
    }
    if (!probe || probe.ev === 'refused') {
      banner.textContent = describeRefusal(probe || { code: 'source_unreadable' });
      show(banner);
      return;
    }
    if (!probe.editable) {
      banner.textContent = 'This recording cannot be edited here: ' + (probe.reason || 'no reason given') + '.';
      show(banner);
      return;
    }
    let saved = null;
    let loadError = null;
    try {
      saved = await invoke('cmd_edit_load', { name });
    } catch (e) {
      loadError = errorText(e);
    }
    const durationMs = Number(probe.duration_ms) || 0;
    const fitted = fromEditList(saved, durationMs);
    cur = {
      name,
      durationMs,
      hasAudio: !!probe.audio,
      segs: fitted.segs,
      sound: fitted.sound,
      selected: 0,
    };
    if (loadError || (saved && !fitted.fitted)) {
      banner.textContent =
        'The saved edits did not fit this recording' +
        (loadError ? ' (' + loadError + ')' : '') +
        ': starting from the whole recording.';
      show(banner);
    }
    show($('ed-body'));
    show($('ed-sound'));
    show($('ed-export-card'));
    drawPlayhead(0);
    render();
    void loadPreview(name);
    // An export already running (this recording's, or another's) is shown.
    void poll();
  }

  async function close() {
    if (saveTimer) await save();
    const v = $('ed-video');
    if (v) {
      v.pause && v.pause();
      v.removeAttribute('src');
    }
    cur = null;
    hide($('rec-editor'));
    show($('rec-main'));
    document.dispatchEvent(new CustomEvent('roomler:editor-closed'));
  }

  /* ── boot ───────────────────────────────────────────────────────── */

  function boot() {
    $('ed-back').addEventListener('click', () => void close());
    $('ed-timeline').addEventListener('click', timelineClick);
    $('ed-split').addEventListener('click', split);
    $('ed-keep').addEventListener('click', () => apply('keep'));
    $('ed-cut').addEventListener('click', () => apply('cut'));
    $('ed-speed-apply').addEventListener('click', () => apply('speed'));
    $('ed-play').addEventListener('click', togglePlay);
    $('ed-original-volume').addEventListener('input', () => {
      cur.sound.originalVolume = volume(Number($('ed-original-volume').value) / 100, 1);
      changed();
    });
    $('ed-music-pick').addEventListener('click', () => void pickMusic());
    $('ed-music-remove').addEventListener('click', () => {
      cur.sound.music = null;
      changed();
    });
    for (const id of ['ed-music-volume', 'ed-music-start', 'ed-music-fade-in', 'ed-music-fade-out', 'ed-music-loop']) {
      $(id).addEventListener('change', musicInput);
    }
    $('ed-export').addEventListener('click', () => void startExport());
    $('ed-export-cancel').addEventListener('click', () => void cancelExport());
    $('ed-result-play').addEventListener('click', () => void openResult(false));
    $('ed-result-show').addEventListener('click', () => void openResult(true));
    const v = $('ed-video');
    v.addEventListener('play', () => {
      setText('ed-play', 'Pause');
      frame(follow);
    });
    v.addEventListener('pause', () => setText('ed-play', 'Play'));
    v.addEventListener('seeked', () => cur && drawPlayhead(playheadMs()));
    v.addEventListener('error', () => {
      if (!v.getAttribute('src')) return;
      const note = $('ed-preview-note');
      note.textContent = 'This system cannot play the recording here. The timeline and the export still work.';
      show(note);
    });
    // A hidden section keeps playing its sound: leaving the view, or closing
    // the window to the tray, pauses the preview.
    const quiet = () => {
      if (!v.paused) v.pause();
    };
    document.addEventListener('roomler:view', (ev) => {
      if (ev.detail !== 'recordings') quiet();
    });
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) quiet();
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();

  window.RoomlerEditor = {
    // pure helpers
    SPEEDS,
    MIN_PIECE_MS,
    whole,
    indexAt,
    splitAt,
    setAction,
    outputMs,
    toEditList,
    fromEditList,
    previewAt,
    describeRefusal,
    describeDone,
    // the view
    engineAvailable,
    open,
    close,
    select,
    seek,
    state: () => cur,
  };
})();
