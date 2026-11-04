// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-85 P5c — meshharbor-desktop's Edit view, driven in jsdom against a mocked
 * Tauri `invoke`.
 *
 * Like `recordings.spec.ts`, it loads the REAL `index.html` section and the
 * REAL `editor.js` and evaluates them the way the webview does. What it pins
 * is what the view promises: pieces that always cover the recording, split
 * and cut and sped up from the timeline; every change saved as the edit list
 * roomlerd reads (the SAME file `agents/meshharbord/src/recording/edit.rs`
 * parses in its own test, so the two ends cannot drift apart); an export
 * that waits for the last save, reports its progress, and says how it ended
 * in words.
 */
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const HERE = dirname(fileURLToPath(import.meta.url))
const DESKTOP = join(HERE, '..', '..', '..', '..', 'agents', 'meshharbor-desktop')
const FRONT = join(DESKTOP, 'src', 'front')
const HTML = readFileSync(join(FRONT, 'index.html'), 'utf8')
const EDITOR = readFileSync(join(FRONT, 'editor.js'), 'utf8')
const RECORDINGS = readFileSync(join(FRONT, 'recordings.js'), 'utf8')
const FIXTURE = JSON.parse(readFileSync(join(DESKTOP, 'tests', 'fixtures', 'edit-list.json'), 'utf8'))

type Seg = { start_ms: number; end_ms: number; action: string; speed?: number }
type Sound = { originalVolume: number; music: Record<string, unknown> | null }
type Invoke = (name: string, payload?: Record<string, unknown>) => Promise<unknown>
type Editor = {
  MIN_PIECE_MS: number
  whole: (ms: number) => Seg[]
  splitAt: (s: Seg[], ms: number) => Seg[] | null
  setAction: (s: Seg[], i: number, action: string, speed?: number) => Seg[]
  outputMs: (s: Seg[]) => number
  toEditList: (source: string, s: Seg[], sound: Sound) => Record<string, unknown>
  fromEditList: (list: unknown, ms: number) => { segs: Seg[]; sound: Sound; fitted: boolean }
  previewAt: (s: Seg[], ms: number, vol: number) => Record<string, unknown>
  describeRefusal: (r: { code: string; detail?: string }) => string
  engineAvailable: () => Promise<boolean>
  open: (name: string) => Promise<void>
  close: () => Promise<void>
  select: (i: number) => void
  seek: (ms: number) => void
  state: () => { segs: Seg[]; sound: Sound; selected: number } | null
}

const NAME = 'Roomler Recording 2026-09-26 10-00-00.mp4'
const $ = (id: string) => document.getElementById(id) as HTMLElement
const settle = () => vi.advanceTimersByTimeAsync(0)

function fmtBytes(n: number | null | undefined): string {
  if (n == null) return '—'
  let v = Number(n)
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let u = 0
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024
    u += 1
  }
  return (u === 0 ? String(v) : v.toFixed(1)) + ' ' + units[u]
}

let playhead = 0

function mount(invoke: Invoke, scripts: string[] = [EDITOR]): Editor {
  const parsed = new DOMParser().parseFromString(HTML, 'text/html')
  const section = document.importNode(parsed.getElementById('view-recordings')!, true)
  section.hidden = false
  document.body.innerHTML = ''
  document.body.appendChild(section)
  // jsdom has no media pipeline: a player whose clock the test sets.
  const video = $('ed-video') as HTMLVideoElement
  playhead = 0
  Object.defineProperty(video, 'currentTime', {
    configurable: true,
    get: () => playhead,
    set: (v: number) => {
      playhead = v
    },
  })
  Object.defineProperty(video, 'paused', { configurable: true, get: () => true })
  video.pause = vi.fn()
  video.play = vi.fn(() => Promise.resolve())
  const w = window as unknown as Record<string, unknown>
  w.Roomler = {
    $: (id: string) => document.getElementById(id),
    invoke,
    show: (el: HTMLElement | null) => el && (el.hidden = false),
    hide: (el: HTMLElement | null) => el && (el.hidden = true),
    setText: (id: string, t: string) => {
      const el = document.getElementById(id)
      if (el) el.textContent = t
    },
    fmtBytes,
  }
  for (const s of scripts) window.eval(s)
  return w.RoomlerEditor as Editor
}

/** A service with one 10 s recording, recording what the page asked. */
function service(over: Record<string, (p?: Record<string, unknown>) => unknown> = {}) {
  const calls: Array<{ name: string; payload?: Record<string, unknown> }> = []
  const handlers: Record<string, (p?: Record<string, unknown>) => unknown> = {
    cmd_media_available: () => true,
    cmd_media_probe: () => ({
      ev: 'probe',
      duration_ms: 10_000,
      width: 1920,
      height: 1080,
      frames: 300,
      profile: 66,
      audio: true,
      editable: true,
      reason: null,
    }),
    cmd_edit_load: () => null,
    cmd_edit_save: () => null,
    cmd_export_status: () => ({ running: false, frames: 0, total: 0, done: null, refused: null, name: null }),
    ...over,
  }
  const invoke: Invoke = async (name, payload) => {
    calls.push({ name, payload })
    const h = handlers[name]
    if (!h) throw new Error('unexpected ' + name)
    return h(payload)
  }
  return { invoke, calls, handlers }
}

const saves = (calls: Array<{ name: string; payload?: Record<string, unknown> }>) =>
  calls.filter((c) => c.name === 'cmd_edit_save').map((c) => c.payload!.list as Record<string, unknown>)

beforeEach(() => {
  vi.useFakeTimers()
})

afterEach(() => {
  vi.useRealTimers()
  document.body.innerHTML = ''
  delete (window as unknown as Record<string, unknown>).RoomlerEditor
  delete (window as unknown as Record<string, unknown>).RoomlerRecordings
})

describe('the pieces (pure)', () => {
  const ed = () => mount(service().invoke)

  it('always cover the recording, and keep every split the person made', () => {
    const e = ed()
    let s = e.whole(10_000)
    s = e.splitAt(s, 2000)!
    s = e.splitAt(s, 4000)!
    s = e.splitAt(s, 8000)!
    const bounds = (x: Seg[]) => x.map((p) => [p.start_ms, p.end_ms])
    const four = [
      [0, 2000],
      [2000, 4000],
      [4000, 8000],
      [8000, 10_000],
    ]
    expect(bounds(s)).toEqual(four)
    // Cutting the second leaves the split at 8 s, which the person made to
    // speed 4–8 s up next: merging the two kept pieces after it would take
    // that split back (red when setAction merges neighbours).
    s = e.setAction(s, 1, 'cut')
    expect(bounds(s)).toEqual(four)
    s = e.setAction(s, 2, 'speed', 4)
    expect(s.map((p) => p.action)).toEqual(['keep', 'cut', 'speed', 'keep'])
    // Keeping it again restores the action, and still every split.
    s = e.setAction(s, 1, 'keep')
    expect(bounds(s)).toEqual(four)
  })

  it('never splits a sliver off a piece', () => {
    const e = ed()
    const s = e.whole(10_000)
    expect(e.splitAt(s, e.MIN_PIECE_MS - 1)).toBeNull()
    expect(e.splitAt(s, 10_000 - e.MIN_PIECE_MS + 1)).toBeNull()
    expect(e.splitAt(s, e.MIN_PIECE_MS)).toHaveLength(2)
  })

  it("measures the export as roomlerd's time map does", () => {
    const e = ed()
    // The plan's oracle: keep 2 s · cut 2 s · 4 s at 4× · keep 2 s = 5 s.
    const s: Seg[] = [
      { start_ms: 0, end_ms: 2000, action: 'keep' },
      { start_ms: 2000, end_ms: 4000, action: 'cut' },
      { start_ms: 4000, end_ms: 8000, action: 'speed', speed: 4 },
      { start_ms: 8000, end_ms: 10_000, action: 'keep' },
    ]
    expect(e.outputMs(s)).toBe(5000)
  })

  it('writes exactly the list roomlerd reads (the shared fixture)', () => {
    const e = ed()
    const list = e.toEditList(NAME, e.fromEditList(FIXTURE, 10_000).segs, {
      originalVolume: 0.8,
      music: {
        path: 'C:\\Users\\me\\Music\\song.mp3',
        volume: 0.35,
        start_ms: 1000,
        fade_in_ms: 2000,
        fade_out_ms: 1500,
        loop: false,
      },
    })
    expect(list).toEqual(FIXTURE)
  })

  it('leaves the defaults out of the file: untouched means "as recorded"', () => {
    const e = ed()
    const list = e.toEditList(NAME, e.whole(1000), { originalVolume: 1, music: null })
    expect(list).toEqual({
      version: 1,
      source: NAME,
      segments: [{ start_ms: 0, end_ms: 1000, action: 'keep' }],
    })
  })

  it('reads a saved list back fitted to the recording, or starts over and says so', () => {
    const e = ed()
    const back = e.fromEditList(FIXTURE, 10_000)
    expect(back.fitted).toBe(true)
    expect(back.segs).toEqual(FIXTURE.segments)
    expect(back.sound.originalVolume).toBe(0.8)
    expect(back.sound.music).toMatchObject({ volume: 0.35, loop: false })

    // A shorter recording: clipped to it.
    const short = e.fromEditList(FIXTURE, 5000)
    expect(short.segs.at(-1)).toEqual({ start_ms: 4000, end_ms: 5000, action: 'speed', speed: 4 })
    // A longer one: what follows the last piece is kept, as roomlerd keeps
    // it. A kept last piece goes on; after a speed-up the rest is a piece of
    // its own.
    const long = e.fromEditList(FIXTURE, 12_000)
    expect(long.segs.at(-1)).toEqual({ start_ms: 8000, end_ms: 12_000, action: 'keep' })
    const endsFast = e.fromEditList({ ...FIXTURE, segments: FIXTURE.segments.slice(0, 3) }, 10_000)
    expect(endsFast.segs.slice(-2)).toEqual([
      { start_ms: 4000, end_ms: 8000, action: 'speed', speed: 4 },
      { start_ms: 8000, end_ms: 10_000, action: 'keep' },
    ])

    // A gap, a bad speed, another version: the whole recording, not fitted.
    const gap = { ...FIXTURE, segments: [{ start_ms: 0, end_ms: 1000, action: 'keep' }, { start_ms: 2000, end_ms: 3000, action: 'cut' }] }
    const speed = { ...FIXTURE, segments: [{ start_ms: 0, end_ms: 1000, action: 'speed', speed: 17 }] }
    for (const bad of [gap, speed, { ...FIXTURE, version: 2 }, null, 'nonsense']) {
      const r = e.fromEditList(bad, 10_000)
      expect(r.fitted).toBe(false)
      expect(r.segs).toEqual([{ start_ms: 0, end_ms: 10_000, action: 'keep' }])
    }
  })

  it('previews a cut as skipped and a speed-up as fast and muted', () => {
    const e = ed()
    const s = FIXTURE.segments as Seg[]
    expect(e.previewAt(s, 500, 1)).toEqual({ rate: 1, muted: false })
    expect(e.previewAt(s, 2500, 1)).toEqual({ skipTo: 4000 })
    expect(e.previewAt(s, 5000, 1)).toEqual({ rate: 4, muted: true })
    expect(e.previewAt(s, 9000, 0)).toEqual({ rate: 1, muted: true })
    const endsCut: Seg[] = [
      { start_ms: 0, end_ms: 1000, action: 'keep' },
      { start_ms: 1000, end_ms: 2000, action: 'cut' },
    ]
    expect(e.previewAt(endsCut, 1500, 1)).toEqual({ end: true })
  })
})

describe('the view', () => {
  it('opens a recording on its whole length, hiding the list', async () => {
    const svc = service()
    const e = mount(svc.invoke)
    await e.open(NAME)
    expect($('rec-main').hidden).toBe(true)
    expect($('rec-editor').hidden).toBe(false)
    expect($('ed-body').hidden).toBe(false)
    expect(document.querySelectorAll('.ed-seg')).toHaveLength(1)
    expect($('ed-summary').textContent).toBe('The export: 0:10 of 0:10')
  })

  it('splits at the playhead, cuts the selected piece, and saves the edit list', async () => {
    const svc = service()
    const e = mount(svc.invoke)
    await e.open(NAME)
    e.seek(4000)
    ;($('ed-split') as HTMLButtonElement).click()
    // The piece after the playhead is the one selected.
    expect(e.state()!.selected).toBe(1)
    ;($('ed-cut') as HTMLButtonElement).click()
    expect(document.querySelectorAll('.ed-seg.ed-cut')).toHaveLength(1)
    expect($('ed-summary').textContent).toBe('The export: 0:04 of 0:10')
    expect(saves(svc.calls)).toHaveLength(0) // saved after a pause, not per click
    await vi.advanceTimersByTimeAsync(400)
    expect(saves(svc.calls).at(-1)).toEqual({
      version: 1,
      source: NAME,
      segments: [
        { start_ms: 0, end_ms: 4000, action: 'keep' },
        { start_ms: 4000, end_ms: 10_000, action: 'cut' },
      ],
    })
    expect($('ed-saved').hidden).toBe(false)
  })

  it('speeds a piece up by the chosen factor, selected from the timeline', async () => {
    const svc = service()
    const e = mount(svc.invoke)
    await e.open(NAME)
    e.seek(5000)
    ;($('ed-split') as HTMLButtonElement).click()
    ;(document.querySelector('.ed-seg[data-index="0"]') as HTMLButtonElement).click()
    expect(e.state()!.selected).toBe(0)
    ;($('ed-speed') as HTMLSelectElement).value = '8'
    ;($('ed-speed-apply') as HTMLButtonElement).click()
    expect(e.state()!.segs[0]).toEqual({ start_ms: 0, end_ms: 5000, action: 'speed', speed: 8 })
    expect(document.querySelector('.ed-seg.ed-speed')!.textContent).toBe('8×')
  })

  it('adds music and saves its settings', async () => {
    const svc = service({ cmd_pick_music: () => 'C:\\Users\\me\\Music\\song.mp3' })
    const e = mount(svc.invoke)
    await e.open(NAME)
    ;($('ed-music-pick') as HTMLButtonElement).click()
    await settle()
    expect($('ed-music-options').hidden).toBe(false)
    expect($('ed-music-name').textContent).toBe('song.mp3')
    ;($('ed-music-volume') as HTMLInputElement).value = '35'
    ;($('ed-music-fade-in') as HTMLInputElement).value = '2'
    ;($('ed-music-loop') as HTMLInputElement).checked = false
    $('ed-music-loop').dispatchEvent(new Event('change'))
    await vi.advanceTimersByTimeAsync(400)
    expect(saves(svc.calls).at(-1)!.music).toEqual({
      path: 'C:\\Users\\me\\Music\\song.mp3',
      volume: 0.35,
      start_ms: 0,
      fade_in_ms: 2000,
      fade_out_ms: 0,
      loop: false,
    })
    ;($('ed-music-remove') as HTMLButtonElement).click()
    await vi.advanceTimersByTimeAsync(400)
    expect(saves(svc.calls).at(-1)!.music).toBeUndefined()
  })

  it('restores the saved edits', async () => {
    const svc = service({ cmd_edit_load: () => ({ ...FIXTURE, source: NAME }) })
    const e = mount(svc.invoke)
    await e.open(NAME)
    expect(e.state()!.segs).toEqual(FIXTURE.segments)
    expect($('ed-summary').textContent).toBe('The export: 0:05 of 0:10')
    expect($('ed-banner').hidden).toBe(true)
  })

  it('says so when the saved edits do not fit, and starts from the whole recording', async () => {
    const svc = service({ cmd_edit_load: () => ({ version: 7, source: NAME, segments: [] }) })
    const e = mount(svc.invoke)
    await e.open(NAME)
    expect(e.state()!.segs).toHaveLength(1)
    expect($('ed-banner').hidden).toBe(false)
    expect($('ed-banner').textContent).toContain('did not fit')
  })

  it('refuses a recording this build cannot edit, and says why', async () => {
    const svc = service({
      cmd_media_probe: () => ({ ev: 'probe', duration_ms: 10_000, editable: false, reason: 'profile 100 needs a newer decoder' }),
    })
    const e = mount(svc.invoke)
    await e.open(NAME)
    expect($('ed-body').hidden).toBe(true)
    expect($('ed-banner').textContent).toContain('profile 100 needs a newer decoder')
    expect(svc.calls.some((c) => c.name === 'cmd_edit_load')).toBe(false)
  })

  it('will not export a recording that is cut entirely, and says why', async () => {
    const svc = service()
    const e = mount(svc.invoke)
    await e.open(NAME)
    ;($('ed-cut') as HTMLButtonElement).click()
    expect(($('ed-export') as HTMLButtonElement).disabled).toBe(true)
    expect($('ed-export-why').hidden).toBe(false)
  })

  /**
   * The companion's export job, as the page sees it: idle until Start, then
   * whatever the test says the engine reported.
   */
  function exporter() {
    const idle = { running: false, frames: 0, total: 0, done: null, refused: null, name: null }
    const job: { status: Record<string, unknown>; order: string[] } = { status: idle, order: [] }
    const handlers = {
      cmd_edit_save: () => {
        job.order.push('save')
        return null
      },
      cmd_export_start: () => {
        job.order.push('start')
        job.status = { running: true, frames: 0, total: 150, done: null, refused: null, name: NAME }
        return job.status
      },
      cmd_export_status: () => job.status,
      cmd_export_cancel: () => {
        job.order.push('cancel')
        return null
      },
      cmd_recording_open: () => null,
    }
    return { job, handlers }
  }

  it('exports only once the last change is saved, shows progress, and names the new file', async () => {
    const { job, handlers } = exporter()
    const svc = service(handlers)
    const e = mount(svc.invoke)
    await e.open(NAME)
    await settle()
    expect(($('ed-export') as HTMLButtonElement).disabled).toBe(false) // nothing running yet
    e.seek(5000)
    ;($('ed-split') as HTMLButtonElement).click()
    ;($('ed-cut') as HTMLButtonElement).click()
    // Export at once, before the save's pause has run out: the engine reads
    // the list from disk, so the save must land first (red when it does not).
    ;($('ed-export') as HTMLButtonElement).click()
    await settle()
    expect(job.order).toEqual(['save', 'start'])
    expect(saves(svc.calls).at(-1)!.segments).toEqual([
      { start_ms: 0, end_ms: 5000, action: 'keep' },
      { start_ms: 5000, end_ms: 10_000, action: 'cut' },
    ])
    expect(svc.calls.find((c) => c.name === 'cmd_export_start')!.payload).toEqual({ name: NAME, encoder: 'auto' })

    job.status = { ...job.status, frames: 30 }
    await vi.advanceTimersByTimeAsync(400)
    expect($('ed-progress').hidden).toBe(false)
    expect($('ed-export-status').textContent).toBe('Exporting… 20 %')
    expect(($('ed-split') as HTMLButtonElement).disabled).toBe(true) // no edits mid-export
    expect($('ed-export-cancel').hidden).toBe(false)

    job.status = {
      running: false,
      frames: 150,
      total: 150,
      refused: null,
      name: NAME,
      done: {
        path: 'C:\\Users\\me\\Videos\\Roomler\\Roomler Recording 2026-09-26 10-00-00 (edited).mp4',
        duration_ms: 5000,
        bytes: 1024 * 1024,
        audio: 'original_and_music',
      },
    }
    await vi.advanceTimersByTimeAsync(400)
    expect($('ed-progress').hidden).toBe(true)
    expect($('ed-result-text').textContent).toBe(
      "Saved as Roomler Recording 2026-09-26 10-00-00 (edited).mp4 — 0:05, 1.0 MiB, with the recording's sound and the music.",
    )
    expect(($('ed-split') as HTMLButtonElement).disabled).toBe(false) // editable again
    ;($('ed-result-show') as HTMLButtonElement).click()
    await settle()
    // The page opens the new file by its BARE name; the companion joins it
    // with the daemon's folder, never with a path the page supplies.
    expect(svc.calls.find((c) => c.name === 'cmd_recording_open')!.payload).toEqual({
      name: 'Roomler Recording 2026-09-26 10-00-00 (edited).mp4',
      reveal: true,
    })
  })

  it('says how a refused export ended, in words', async () => {
    const { job, handlers } = exporter()
    const svc = service(handlers)
    const e = mount(svc.invoke)
    await e.open(NAME)
    await settle()
    expect($('ed-export-error').hidden).toBe(true)
    ;($('ed-export') as HTMLButtonElement).click()
    await settle()
    expect(job.order).toContain('start')
    job.status = {
      running: false,
      name: NAME,
      refused: { code: 'music_unreadable', detail: 'song.mp3: the music decoder failed on this file' },
    }
    await vi.advanceTimersByTimeAsync(400)
    expect($('ed-export-error').textContent).toBe(
      'The music file cannot be read (song.mp3: the music decoder failed on this file).',
    )
    // A code this page has never heard of reads as itself.
    expect(e.describeRefusal({ code: 'something_new' })).toBe('Something_new.')
  })

  it('cancels through the service', async () => {
    const { job, handlers } = exporter()
    const svc = service(handlers)
    const e = mount(svc.invoke)
    await e.open(NAME)
    await settle()
    expect($('ed-export-cancel').hidden).toBe(true)
    ;($('ed-export') as HTMLButtonElement).click()
    await settle()
    expect($('ed-export-cancel').hidden).toBe(false)
    ;($('ed-export-cancel') as HTMLButtonElement).click()
    await settle()
    expect(job.order).toEqual(['start', 'cancel'])
  })

  it('shows an export already running for this recording when it opens', async () => {
    const { job, handlers } = exporter()
    job.status = { running: true, frames: 75, total: 150, done: null, refused: null, name: NAME }
    const e = mount(service(handlers).invoke)
    await e.open(NAME)
    await settle()
    expect($('ed-export-status').textContent).toBe('Exporting… 50 %')
    expect($('ed-export').hidden).toBe(true)
  })

  it('goes back to the list, saving what is pending', async () => {
    const svc = service()
    const e = mount(svc.invoke)
    await e.open(NAME)
    ;($('ed-cut') as HTMLButtonElement).click()
    const closed = vi.fn()
    document.addEventListener('roomler:editor-closed', closed)
    ;($('ed-back') as HTMLButtonElement).click()
    await settle()
    expect(saves(svc.calls)).toHaveLength(1)
    expect($('rec-editor').hidden).toBe(true)
    expect($('rec-main').hidden).toBe(false)
    expect(closed).toHaveBeenCalled()
  })
})

describe('the Edit button in the list', () => {
  function recordingsView() {
    return {
      available: true,
      unsupported: false,
      record_dir: null,
      state: { available: true, active: false, duration_ms: 0, bytes: 0 },
      listing: {
        dir: 'C:\\Users\\me\\Videos\\Roomler',
        items: [{ name: NAME, bytes: 1024, duration_ms: 10_000, started_at: '2026-09-26T08:00:00Z', origin: 'local' }],
      },
    }
  }

  const edit = () =>
    Array.from(document.querySelectorAll('#rec-body button')).find(
      (b) => b.textContent === 'Edit',
    ) as HTMLButtonElement

  it('shows only where the service has the export engine', async () => {
    for (const engine of [true, false]) {
      const svc = service({ cmd_media_available: () => engine, cmd_recordings_view: () => recordingsView() })
      mount(svc.invoke, [EDITOR, RECORDINGS])
      await settle()
      const rec = (window as unknown as Record<string, { render: (v: unknown) => void }>).RoomlerRecordings
      rec.render(recordingsView())
      await settle()
      expect(edit().hidden).toBe(!engine)
    }
  })

  it('opens the editor on that recording', async () => {
    const svc = service({ cmd_recordings_view: () => recordingsView() })
    mount(svc.invoke, [EDITOR, RECORDINGS])
    await settle()
    const rec = (window as unknown as Record<string, { render: (v: unknown) => void }>).RoomlerRecordings
    rec.render(recordingsView())
    edit().click()
    await settle()
    expect(svc.calls.find((c) => c.name === 'cmd_media_probe')!.payload).toEqual({ name: NAME })
    expect($('rec-editor').hidden).toBe(false)
  })
})
