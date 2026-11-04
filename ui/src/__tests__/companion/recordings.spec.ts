// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-85 P2b — meshharbor-desktop's Recordings view, driven in jsdom against a
 * mocked Tauri `invoke`.
 *
 * The companion ships plain scripts with no bundler, so there is nothing to
 * import: the test loads the REAL `index.html` section and the REAL
 * `recordings.js` from the companion's tree and evaluates them, the way the
 * webview does. What it pins is what the view promises: Start greyed out
 * with the reason where recording is impossible, a two-click delete, the
 * folder picker saving through `cmd_config_set`, keyed rows that never move
 * under the cursor, and a failed refresh that keeps the last good data.
 */
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// node:path, not `new URL(…)`: under jsdom the global URL is jsdom's, which
// node's fileURLToPath rejects.
const HERE = dirname(fileURLToPath(import.meta.url))
const FRONT = join(HERE, '..', '..', '..', '..', 'agents', 'meshharbor-desktop', 'src', 'front')
const HTML = readFileSync(join(FRONT, 'index.html'), 'utf8')
const SCRIPT = readFileSync(join(FRONT, 'recordings.js'), 'utf8')

type Invoke = (name: string, payload?: Record<string, unknown>) => Promise<unknown>
type Api = {
  fmtDuration: (ms: number) => string
  describeLast: (last: Record<string, unknown>) => string
  render: (view: unknown) => void
  refresh: (opts?: { force?: boolean }) => Promise<void>
}

// app.js's formatter, so sizes read the way they do in the app.
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

function mount(invoke: Invoke): Api {
  // Only the Recordings section: every other view belongs to another script.
  const parsed = new DOMParser().parseFromString(HTML, 'text/html')
  const section = document.importNode(parsed.getElementById('view-recordings')!, true)
  section.hidden = false
  document.body.innerHTML = ''
  document.body.appendChild(section)
  const w = window as unknown as Record<string, unknown>
  w.MeshHarbor = {
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
  window.eval(SCRIPT)
  return w.MeshHarborRecordings as Api
}

const $ = (id: string) => document.getElementById(id) as HTMLElement
const settle = () => vi.advanceTimersByTimeAsync(0)

function view(over: Record<string, unknown> = {}) {
  return {
    available: true,
    reason: null,
    unsupported: false,
    record_dir: null,
    state: { available: true, active: false, duration_ms: 0, bytes: 0, frames: 0 },
    listing: {
      dir: 'C:\\Users\\me\\Videos\\MeshHarbor',
      items: [
        {
          name: 'MeshHarbor Recording 2026-09-25 14-30-12.mp4',
          bytes: 5 * 1024 * 1024,
          duration_ms: 65_000,
          started_at: '2026-09-25T12:30:12Z',
          origin: 'local',
          stop_reason: 'requested',
          width: 1920,
          height: 1080,
        },
        {
          name: 'MeshHarbor Recording 2026-09-24 09-00-00.mp4',
          bytes: 1024,
          duration_ms: 2_000,
          started_at: '2026-09-24T07:00:00Z',
          origin: 'remote',
          controller: 'GJ',
          stop_reason: 'disk_low',
          width: 1280,
          height: 720,
        },
      ],
    },
    ...over,
  }
}

describe('companion Recordings view (FR-85 P2b)', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })
  afterEach(() => {
    vi.clearAllTimers()
    vi.useRealTimers()
  })

  it('formats lengths and endings plainly', () => {
    const api = mount(vi.fn())
    expect(api.fmtDuration(0)).toBe('0:00')
    expect(api.fmtDuration(65_999)).toBe('1:05')
    expect(api.fmtDuration(3_662_000)).toBe('1:01:02')
    expect(
      api.describeLast({ reason: 'requested', path: 'x.mp4', duration_ms: 90_000, bytes: 1024 }),
    ).toBe('Last recording: 1:30, 1.0 KiB.')
    expect(
      api.describeLast({ reason: 'encoder_unavailable', path: null, detail: 'no GPU' }),
    ).toBe('The last recording did not start — no video encoder could be opened (no GPU).')
    // A code this page has never heard of reads as itself.
    expect(api.describeLast({ reason: 'from_the_future', path: null })).toContain('from_the_future')
    // #1760 — the recorder's refusal on a Mac, in plain words, with its own.
    expect(
      api.describeLast({
        reason: 'system_audio_unavailable',
        path: null,
        detail: "macOS can't capture what the computer plays yet",
      }),
    ).toBe(
      "The last recording did not start — computer audio could not be captured on this device (macOS can't capture what the computer plays yet).",
    )
  })

  it('greys computer audio out, unticked, with the reason, where the service cannot record it (#1760)', async () => {
    const reason = "macOS can't capture what the computer plays yet"
    const cannot = () =>
      view({
        state: {
          available: true,
          active: false,
          duration_ms: 0,
          bytes: 0,
          frames: 0,
          system_audio_unavailable_reason: reason,
        },
      })
    const invoke = vi.fn(async (name: string) => (name === 'cmd_recordings_view' ? cannot() : {}))
    const api = mount(invoke)
    // Ticked before the service answered: the answer unticks it.
    const sys = $('rec-system-audio') as HTMLInputElement
    sys.checked = true
    api.render(cannot())
    expect(sys.disabled).toBe(true)
    expect(sys.checked).toBe(false)
    expect($('rec-system-audio-unavailable').hidden).toBe(false)
    expect($('rec-system-audio-unavailable').textContent).toBe(
      'Computer audio is not available here: ' + reason + '.',
    )
    // The microphone and Start are still offered, and a start asks for no
    // computer audio.
    expect(($('rec-microphone') as HTMLInputElement).disabled).toBe(false)
    expect(($('rec-start') as HTMLButtonElement).disabled).toBe(false)
    $('rec-start').click()
    await settle()
    expect(invoke).toHaveBeenCalledWith(
      'cmd_record_start',
      expect.objectContaining({ systemAudio: false }),
    )
    // A service that can, or one older than the field: the box is offered.
    api.render(view())
    expect(sys.disabled).toBe(false)
    expect($('rec-system-audio-unavailable').hidden).toBe(true)
  })

  it('renders the idle state, the folder and the recordings, newest first', () => {
    const api = mount(vi.fn())
    api.render(view())
    expect($('rec-start').hidden).toBe(false)
    expect(($('rec-start') as HTMLButtonElement).disabled).toBe(false)
    expect($('rec-stop').hidden).toBe(true)
    expect($('rec-live').hidden).toBe(true)
    expect($('rec-folder').textContent).toBe('C:\\Users\\me\\Videos\\MeshHarbor')
    expect($('rec-folder-note').textContent).toBe('The default folder.')
    expect($('rec-folder-default').hidden).toBe(true)
    const rows = [...$('rec-body').querySelectorAll('tr')]
    expect(rows.map((r) => r.dataset.name)).toEqual([
      'MeshHarbor Recording 2026-09-25 14-30-12.mp4',
      'MeshHarbor Recording 2026-09-24 09-00-00.mp4',
    ])
    expect(rows[0].textContent).toContain('1:05')
    expect(rows[0].textContent).toContain('5.0 MiB')
    expect(rows[1].textContent).toContain('Remote · GJ')
    // An ending other than a plain stop is said on hover.
    expect(rows[1].title).toBe('Ended: the disk was nearly full')
  })

  it('greys Start out, with the reason, where the service cannot record', () => {
    const api = mount(vi.fn())
    api.render(
      view({
        state: {
          available: false,
          unavailable_reason: 'this device service runs as SYSTEM/root',
          active: false,
        },
      }),
    )
    expect(($('rec-start') as HTMLButtonElement).disabled).toBe(true)
    expect($('rec-unavailable').hidden).toBe(false)
    expect($('rec-unavailable').textContent).toContain('SYSTEM/root')
    // The saved recordings are still listed and playable.
    expect($('rec-body').querySelectorAll('tr').length).toBe(2)
  })

  it('shows a running recording and locks its options', () => {
    const api = mount(vi.fn())
    api.render(
      view({
        state: {
          available: true,
          active: true,
          duration_ms: 65_400,
          bytes: 3 * 1024 * 1024,
          encoder: 'h264_nvenc',
          width: 1920,
          height: 1080,
          fps: 30,
        },
      }),
    )
    expect($('rec-live').hidden).toBe(false)
    expect($('rec-live-time').textContent).toBe('1:05')
    expect($('rec-start').hidden).toBe(true)
    expect($('rec-stop').hidden).toBe(false)
    expect(($('rec-fps') as HTMLSelectElement).disabled).toBe(true)
    expect($('rec-status').textContent).toBe(
      'Recording — 1:05, 3.0 MiB, h264_nvenc, 1920×1080 @ 30 fps',
    )
  })

  it('starts with the chosen options', async () => {
    const invoke = vi.fn(async (name: string) => (name === 'cmd_recordings_view' ? view() : {}))
    const api = mount(invoke)
    api.render(view())
    ;($('rec-fps') as HTMLSelectElement).value = '60'
    ;($('rec-encoder') as HTMLSelectElement).value = 'software'
    $('rec-start').click()
    await settle()
    // FR-85 P1c — audio is OFF unless ticked.
    expect(invoke).toHaveBeenCalledWith('cmd_record_start', {
      fps: 60,
      encoder: 'software',
      systemAudio: false,
      microphone: false,
    })
  })

  it('asks for the audio the person ticked, and shows it while recording', async () => {
    const invoke = vi.fn(async (name: string) => (name === 'cmd_recordings_view' ? view() : {}))
    const api = mount(invoke)
    api.render(view())
    ;($('rec-system-audio') as HTMLInputElement).checked = true
    ;($('rec-microphone') as HTMLInputElement).checked = true
    $('rec-start').click()
    await settle()
    expect(invoke).toHaveBeenCalledWith(
      'cmd_record_start',
      expect.objectContaining({ systemAudio: true, microphone: true }),
    )
    api.render(
      view({
        state: {
          available: true,
          active: true,
          duration_ms: 1000,
          bytes: 1,
          system_audio: true,
          microphone: true,
        },
      }),
    )
    expect($('rec-status').textContent).toContain('computer audio + microphone')
    expect(($('rec-microphone') as HTMLInputElement).disabled).toBe(true)
  })

  it('says why a start was refused', async () => {
    const invoke = vi.fn(async (name: string) => {
      if (name === 'cmd_record_start') throw 'only the person at this device’s console can start a recording'
      return view()
    })
    const api = mount(invoke)
    api.render(view())
    $('rec-start').click()
    await settle()
    expect($('rec-error').hidden).toBe(false)
    expect($('rec-error').textContent).toContain('console')
  })

  it('deletes only on the second click', async () => {
    const invoke = vi.fn(async (name: string) => (name === 'cmd_recordings_view' ? view() : undefined))
    const api = mount(invoke)
    api.render(view())
    const first = () => $('rec-body').querySelector('tr')!
    const del = () => first().querySelector('button.danger') as HTMLButtonElement
    del().click()
    await settle()
    expect(invoke).not.toHaveBeenCalledWith('cmd_recording_delete', expect.anything())
    expect(del().textContent).toBe('Confirm delete')
    del().click()
    await settle()
    expect(invoke).toHaveBeenCalledWith('cmd_recording_delete', {
      name: 'MeshHarbor Recording 2026-09-25 14-30-12.mp4',
    })
  })

  it('disarms a delete that was not confirmed within 4 s', async () => {
    const api = mount(vi.fn())
    api.render(view())
    const del = () => $('rec-body').querySelector('tr button.danger') as HTMLButtonElement
    del().click()
    await settle()
    expect(del().textContent).toBe('Confirm delete')
    await vi.advanceTimersByTimeAsync(4000)
    expect(del().textContent).toBe('Delete')
  })

  it('saves a picked folder through the config surface, and a cancel saves nothing', async () => {
    let picked: string | null = 'D:\\Screen recordings'
    const invoke = vi.fn(async (name: string) => {
      if (name === 'cmd_pick_record_dir') return picked
      if (name === 'cmd_recordings_view') return view()
      return {}
    })
    const api = mount(invoke)
    api.render(view())
    $('rec-folder-change').click()
    await settle()
    expect(invoke).toHaveBeenCalledWith('cmd_pick_record_dir', {
      current: 'C:\\Users\\me\\Videos\\MeshHarbor',
    })
    expect(invoke).toHaveBeenCalledWith('cmd_config_set', {
      key: 'record_dir',
      value: 'D:\\Screen recordings',
    })
    invoke.mockClear()
    picked = null
    $('rec-folder-change').click()
    await settle()
    expect(invoke).not.toHaveBeenCalledWith('cmd_config_set', expect.anything())
  })

  it('offers the default folder back only when one was chosen', async () => {
    const invoke = vi.fn(async () => view({ record_dir: 'D:\\Rec' }))
    const api = mount(invoke)
    api.render(view({ record_dir: 'D:\\Rec' }))
    expect($('rec-folder-default').hidden).toBe(false)
    expect($('rec-folder-note').textContent).toBe('A folder you chose.')
    $('rec-folder-default').click()
    await settle()
    expect(invoke).toHaveBeenCalledWith('cmd_config_set', { key: 'record_dir', value: null })
  })

  it('names a folder fallback', () => {
    const api = mount(vi.fn())
    const v = view()
    ;(v.listing as Record<string, unknown>).folder_reason =
      'C:\\Users\\me\\Videos\\MeshHarbor is under OneDrive'
    api.render(v)
    expect($('rec-folder-reason').hidden).toBe(false)
    expect($('rec-folder-reason').textContent).toBe(
      'Not the usual folder: C:\\Users\\me\\Videos\\MeshHarbor is under OneDrive.',
    )
  })

  it('keeps rows in place across refreshes — a button never moves under the cursor', () => {
    const api = mount(vi.fn())
    api.render(view())
    const before = [...$('rec-body').querySelectorAll('tr')]
    api.render(view())
    const after = [...$('rec-body').querySelectorAll('tr')]
    expect(after).toHaveLength(2)
    expect(after[0]).toBe(before[0])
    expect(after[1]).toBe(before[1])
  })

  it('keeps the last good data when a refresh fails, and says so', async () => {
    let fail = false
    const invoke = vi.fn(async () => {
      if (fail) throw 'connect: device service not running'
      return view()
    })
    const api = mount(invoke)
    await api.refresh({ force: true })
    expect($('rec-banner').hidden).toBe(true)
    fail = true
    await api.refresh({ force: true })
    expect($('rec-banner').hidden).toBe(false)
    expect($('rec-banner').textContent).toContain('device service not running')
    expect($('rec-banner').textContent).toContain('last good data')
    expect($('rec-body').querySelectorAll('tr').length).toBe(2)
  })

  it('says so when the service has no recorder at all', () => {
    const api = mount(vi.fn())
    api.render({ available: true, unsupported: true })
    expect($('rec-banner').hidden).toBe(false)
    expect($('rec-banner').textContent).toContain('no screen recorder')
    expect(($('rec-start') as HTMLButtonElement).disabled).toBe(true)
  })
})

describe('companion Recordings view — remote recording (FR-85 P3b)', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })
  afterEach(() => {
    vi.clearAllTimers()
    vi.useRealTimers()
  })

  const box = (id: string) => $(id) as HTMLInputElement

  it('offers no toggle against a service that predates the gates', () => {
    const api = mount(vi.fn())
    api.render(view())
    expect($('rec-remote').hidden).toBe(true)
  })

  it('shows the gates, and computer audio only once remote recording is allowed', () => {
    const api = mount(vi.fn())
    api.render(view({ remote: { enabled: false, audio: false } }))
    expect($('rec-remote').hidden).toBe(false)
    expect(box('rec-remote-enabled').checked).toBe(false)
    expect(box('rec-remote-audio').disabled).toBe(true)

    api.render(view({ remote: { enabled: true, audio: true } }))
    expect(box('rec-remote-enabled').checked).toBe(true)
    expect(box('rec-remote-audio').checked).toBe(true)
    expect(box('rec-remote-audio').disabled).toBe(false)
  })

  it("greys the owner's computer-audio toggle out, with the reason, where the service cannot record it (#1760)", () => {
    const api = mount(vi.fn())
    const reason = "macOS can't capture what the computer plays yet"
    api.render(
      view({
        state: { available: true, active: false, system_audio_unavailable_reason: reason },
        remote: { enabled: true, audio: true },
      }),
    )
    // Remote recording itself is still the owner's to allow.
    expect(box('rec-remote-enabled').checked).toBe(true)
    expect(box('rec-remote-enabled').disabled).toBe(false)
    // The key may say true; the effective gate is off (the device never
    // advertises `remote-audio` there), and the box says so.
    expect(box('rec-remote-audio').disabled).toBe(true)
    expect(box('rec-remote-audio').checked).toBe(false)
    expect($('rec-remote-audio-unavailable').hidden).toBe(false)
    expect($('rec-remote-audio-unavailable').textContent).toBe(
      "Computer audio can't be included: " + reason + '.',
    )
    // Where it can: as before.
    api.render(view({ remote: { enabled: true, audio: true } }))
    expect(box('rec-remote-audio').disabled).toBe(false)
    expect(box('rec-remote-audio').checked).toBe(true)
    expect($('rec-remote-audio-unavailable').hidden).toBe(true)
  })

  it('saves each toggle through the config surface, as the daemon must accept it', async () => {
    const invoke = vi.fn(async (name: string) =>
      name === 'cmd_recordings_view' ? view({ remote: { enabled: true, audio: false } }) : {},
    )
    const api = mount(invoke)
    api.render(view({ remote: { enabled: false, audio: false } }))
    box('rec-remote-enabled').click()
    await settle()
    expect(invoke).toHaveBeenCalledWith('cmd_config_set', {
      key: 'record_remote_enabled',
      value: 'true',
    })
    box('rec-remote-audio').click()
    await settle()
    expect(invoke).toHaveBeenCalledWith('cmd_config_set', {
      key: 'record_remote_audio',
      value: 'true',
    })
  })

  it('says a refused toggle, and keeps what the service reports', async () => {
    const invoke = vi.fn(async (name: string) => {
      if (name === 'cmd_config_set') throw 'only the person at this computer can change that'
      return view({ remote: { enabled: false, audio: false } })
    })
    const api = mount(invoke)
    api.render(view({ remote: { enabled: false, audio: false } }))
    box('rec-remote-enabled').click()
    await settle()
    expect($('rec-remote-error').hidden).toBe(false)
    expect($('rec-remote-error').textContent).toContain('person at this computer')
    expect(box('rec-remote-enabled').checked).toBe(false)
  })

  it('names who a remote recording is for', () => {
    const api = mount(vi.fn())
    api.render(
      view({
        state: {
          available: true,
          active: true,
          duration_ms: 5_000,
          bytes: 1024,
          frames: 150,
          remote_controller: 'Alice',
        },
      }),
    )
    expect($('rec-status').textContent).toContain('Recording for Alice (remote)')
  })
})
