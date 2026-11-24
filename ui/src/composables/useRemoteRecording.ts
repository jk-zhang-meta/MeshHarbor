// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-85 P3c — the viewer's side of remote recording, over the session's
 * `record` DataChannel (`docs/recording.md` §10).
 *
 * The recording is made and kept ON THE DEVICE. This asks for it, follows it,
 * lists this controller's recordings there and downloads them — resumably:
 * a relay flap mid-transfer asks again from the bytes already held, on the
 * next channel, and the device's `sha256` covers the whole file either way.
 *
 * Channel-agnostic on purpose: `attach` takes any `RTCDataChannel`-shaped
 * object and the save sink is injectable, so the unit tests drive the real
 * protocol code with no browser save dialog and no PeerConnection.
 */
import { ref } from 'vue'
import i18n from '@/plugins/i18n'

export type RecordState =
  | 'idle'
  | 'pending_consent'
  | 'recording'
  /** P3b-3 — the session dropped mid-recording. The device goes on recording
   *  for up to a minute for this controller's next session, which picks it
   *  up when its `record` channel asks for the status. */
  | 'reconnecting'
  | 'stopped'
  | 'refused'
  | 'failed'

/** One of this controller's recordings on the device (`rc:record.list`). */
export interface RemoteRecordingItem {
  name: string
  bytes: number
  duration_ms: number
  started_at: string
  stop_reason?: string
  width: number
  height: number
}

export interface RecordDownload {
  name: string
  /** From `rc:record.file`; `null` until the device answers. */
  size: number | null
  /** Bytes held, a resumed prefix included. */
  received: number
  status: 'active' | 'paused' | 'done' | 'error' | 'cancelled'
  /** A code from the closed set, when it stopped short. */
  error?: string
  /** The device's SHA-256 of the whole file. */
  sha256?: string
  /** `true`/`false` when this side could hash the file (the in-memory path);
   *  `null` when it went straight to disk (compare `sha256` yourself). */
  verified?: boolean | null
}

/** Where a download's bytes go: a file the person chose, or memory. */
export interface RecordSink {
  mode: 'stream' | 'blob'
  write(chunk: ArrayBuffer): Promise<void>
  close(): Promise<void>
  abort(): Promise<void>
  /** The whole file, on the in-memory path once closed. */
  blob(): Blob | null
}

/** The part of an `RTCDataChannel` this uses. */
export interface RecordChannel {
  readyState: string
  binaryType: string
  send(data: string): void
  onmessage: ((ev: { data: unknown }) => void) | null
  onopen: (() => void) | null
  onclose: (() => void) | null
}

/** In memory, the in-memory path refuses past this (the files channel's cap). */
export const BLOB_CAP = 2 * 1024 * 1024 * 1024

/**
 * One sentence per code: the device's refusals and stop reasons
 * (`recording/remote.rs`, `sidecar.rs`) and the server's strip reasons
 * (`record_grant`). A code this build has never heard of reads as itself.
 */
export const RECORD_REASONS: Record<string, string> = {
  // the server
  device_cannot_record: "this device can't record its screen",
  controller_not_allowed: "you don't have permission to record remote screens",
  device_not_opted_in: "this device's owner hasn't allowed remote recording",
  // the device, refusing a start
  not_granted: "this session isn't allowed to record",
  disabled_on_device: "this device's owner hasn't allowed remote recording",
  unavailable: "this device can't record right now",
  login_screen: 'the device is at its sign-in screen; it can record once someone signs in',
  audio_not_allowed: "this device's owner hasn't allowed computer audio in a remote recording",
  // #1760 — a fact about the device (a Mac, until ScreenCaptureKit; a build
  // without audio), named ahead of the owner's gate because no setting fixes
  // it. Also what greys the box out before any start (`audioUnavailable`).
  audio_unsupported:
    "this device can't record what the computer plays (Windows and Linux devices only, for now)",
  busy: 'a recording is already running on this device',
  already_starting: 'a recording is already starting',
  consent_denied: 'the person at the device said no',
  consent_timeout: 'nobody at the device answered',
  no_prompt_surface: 'nobody at the device could be asked',
  rate_limited: 'the device said no a moment ago; try again in a minute',
  no_indicator_surface: "nothing on the device can show that it's being recorded",
  start_failed: 'the recorder could not start',
  // how a recording ended
  requested: 'you stopped it',
  host_stopped: 'the person at the device stopped it',
  gate_revoked: "the device's owner switched remote recording off",
  session_ended: 'the session ended',
  session_changed: "who is signed in at the device changed, or it went to its sign-in screen",
  display_changed: 'the display changed size',
  disk_low: "the device's disk was nearly full",
  max_duration: 'it reached the maximum length',
  encoder_failed: 'the video encoder failed',
  capture_failed: 'screen capture failed',
  interrupted: 'it was cut off, and recovered afterwards',
  // a download
  bad_name: 'that is not a recording name',
  not_found: 'no such recording of yours on this device',
  bad_offset: 'the transfer could not resume at that point',
  transfer_in_progress: 'another download is already running',
  read_failed: 'the device could not read the file',
  send_failed: 'the connection dropped',
  cancelled: 'cancelled',
  size_mismatch: 'the file did not arrive whole',
  hash_mismatch: 'the file arrived damaged (its checksum differs from the device’s)',
  too_large: 'the file is too large for this browser (use Chrome or Edge to save it)',
}

export function describeRecordReason(code: string | null | undefined): string {
  if (!code) return ''
  // FR-131 P3 — in the reader's language; the table above is the English.
  return code in RECORD_REASONS ? i18n.global.t(`remote.viewer.rec.reason.${code}`) : code
}

/**
 * FR-85 P3c-2 — whether the toolbar shows a disabled Record control for the
 * server's strip reason. Not for `device_cannot_record`: a device with no
 * recorder (every agent before recording, a build without it, one switched
 * off) has nothing to allow or refuse, and a control there would explain a
 * permission nobody could grant, on every session. Every other reason is
 * shown, so a controller learns what would let them record.
 */
export function showsRecordRefusal(code: string | null | undefined): boolean {
  return !!code && code !== 'device_cannot_record'
}

/** A file the person picks (Chromium), or memory with a size cap. */
export async function defaultOpenSink(name: string, size: number | null): Promise<RecordSink> {
  type Writable = {
    write(d: ArrayBuffer | Blob): Promise<void>
    close(): Promise<void>
    abort(reason?: string): Promise<void>
  }
  type Picker = (o?: { suggestedName?: string }) => Promise<{ createWritable(): Promise<Writable> }>
  const picker = (window as unknown as { showSaveFilePicker?: Picker }).showSaveFilePicker
  if (typeof picker === 'function') {
    const handle = await picker({ suggestedName: name })
    const w = await handle.createWritable()
    return {
      mode: 'stream',
      write: (c) => w.write(c),
      close: () => w.close(),
      abort: () => w.abort('cancelled').catch(() => {}),
      blob: () => null,
    }
  }
  if (size !== null && size > BLOB_CAP) throw new Error('too_large')
  const parts: ArrayBuffer[] = []
  let whole: Blob | null = null
  return {
    mode: 'blob',
    write: async (c) => {
      parts.push(c)
    },
    close: async () => {
      whole = new Blob(parts, { type: 'video/mp4' })
      parts.length = 0
    },
    abort: async () => {
      parts.length = 0
    },
    blob: () => whole,
  }
}

async function sha256Hex(blob: Blob): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', await blob.arrayBuffer())
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

/** Save a finished in-memory download the way the files channel does. */
function saveBlob(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 30_000)
}

export function useRemoteRecording(
  opts: {
    openSink?: (name: string, size: number | null) => Promise<RecordSink>
    save?: (blob: Blob, name: string) => void
  } = {},
) {
  const openSink = opts.openSink ?? defaultOpenSink
  const save = opts.save ?? saveBlob

  const state = ref<RecordState>('idle')
  const reason = ref<string | null>(null)
  const detail = ref<string | null>(null)
  const name = ref<string | null>(null)
  const bytes = ref(0)
  const durationMs = ref(0)
  const audio = ref(false)
  /** #1760 — why a recording here could not include what the computer plays
   *  (`audio_unsupported` | `audio_not_allowed`), from the device's every
   *  `rc:record.state`; `null` where it could, and from a device older than
   *  the field (which then refuses by name, as before). The view greys the
   *  box out with the sentence, and `start` never asks for what the device
   *  said it cannot give. */
  const audioUnavailable = ref<string | null>(null)
  const items = ref<RemoteRecordingItem[]>([])
  const download = ref<RecordDownload | null>(null)

  let channel: RecordChannel | null = null
  let seq = 0
  const newId = (p: string) => `${p}-${Date.now().toString(36)}-${(seq++).toString(36)}`
  let currentId = ''

  // The download in progress: its sink, the request id, and the write chain
  // that keeps chunks in order however long each write takes.
  let dl: { id: string; sink: RecordSink; chain: Promise<void> } | null = null

  function send(v: Record<string, unknown>): boolean {
    if (!channel || channel.readyState !== 'open') return false
    try {
      channel.send(JSON.stringify(v))
      return true
    } catch {
      return false
    }
  }

  function applyState(m: Record<string, unknown>) {
    let s = String(m.state ?? 'idle') as RecordState
    // P3b-3 — the device picked the recording up for this session: its id is
    // the one Stop must name, even if this page never started it (a reload).
    if (s === 'recording' && typeof m.id === 'string' && m.id) currentId = m.id
    // Back after a drop, and nothing is recording any more: it ended while
    // this session was away (the grace ran out, or the device stopped it).
    let away = false
    if (s === 'idle' && state.value === 'reconnecting') {
      s = 'stopped'
      away = true
    }
    state.value = s
    reason.value = away ? 'session_ended' : typeof m.reason === 'string' ? m.reason : null
    detail.value = typeof m.detail === 'string' ? m.detail : null
    if (typeof m.name === 'string') name.value = m.name
    bytes.value = Number(m.bytes ?? 0)
    durationMs.value = Number(m.duration_ms ?? 0)
    audio.value = m.audio === true
    // #1760 — absent means available (the device omits it then), and an
    // older device never sends it: both read as the box offered.
    audioUnavailable.value = typeof m.audio_unavailable === 'string' ? m.audio_unavailable : null
    // A finished recording is one more to list.
    if (s === 'stopped') list()
  }

  function onString(text: string) {
    let m: Record<string, unknown>
    try {
      m = JSON.parse(text)
    } catch {
      return
    }
    switch (m.t) {
      case 'rc:record.state':
        applyState(m)
        break
      case 'rc:record.list':
        items.value = Array.isArray(m.items) ? (m.items as RemoteRecordingItem[]) : []
        break
      case 'rc:record.file':
        if (dl && m.id === dl.id && download.value) {
          download.value.size = Number(m.size ?? 0)
          // The device resumes where we ASKED; anything else is a bug the
          // size check below would only catch at the end.
          if (Number(m.offset ?? 0) !== download.value.received) {
            fail('bad_offset')
          }
        }
        break
      case 'rc:record.done':
        if (dl && m.id === dl.id) void finish(m)
        break
      case 'rc:record.error':
        if (dl && m.id === dl.id) {
          const code = String(m.reason ?? 'read_failed')
          // A transfer the SESSION cut is resumable; everything else is final.
          if (code === 'session_ended' || code === 'send_failed') pause(code)
          else fail(code)
        }
        break
    }
  }

  function onBinary(buf: ArrayBuffer) {
    if (!dl || !download.value || download.value.status !== 'active') return
    const d = download.value
    const current = dl
    d.received += buf.byteLength
    current.chain = current.chain.then(() => current.sink.write(buf))
  }

  async function finish(m: Record<string, unknown>) {
    const current = dl
    const d = download.value
    if (!current || !d) return
    try {
      await current.chain
      const size = Number(m.size ?? d.size ?? 0)
      d.sha256 = typeof m.sha256 === 'string' ? m.sha256 : undefined
      if (d.received !== size) {
        await current.sink.abort()
        d.status = 'error'
        d.error = 'size_mismatch'
        dl = null
        return
      }
      await current.sink.close()
      if (current.sink.mode === 'blob') {
        const blob = current.sink.blob()
        d.verified = blob && d.sha256 ? (await sha256Hex(blob)) === d.sha256 : false
        if (d.verified && blob) save(blob, d.name)
        else d.error = 'hash_mismatch'
      } else {
        d.verified = null
      }
      d.status = d.verified === false ? 'error' : 'done'
    } catch (e) {
      d.status = 'error'
      d.error = e instanceof Error ? e.message : String(e)
    }
    dl = null
  }

  function pause(code: string) {
    if (download.value && download.value.status === 'active') {
      download.value.status = 'paused'
      download.value.error = code
    }
  }

  function fail(code: string) {
    const current = dl
    if (download.value) {
      download.value.status = code === 'cancelled' ? 'cancelled' : 'error'
      download.value.error = code
    }
    dl = null
    if (current) void current.chain.then(() => current.sink.abort())
  }

  /** Serve a session's `record` channel. A download the previous channel
   *  cut resumes here from the bytes already held. */
  function attach(ch: RecordChannel) {
    channel = ch
    ch.binaryType = 'arraybuffer'
    ch.onmessage = (ev) => {
      if (typeof ev.data === 'string') onString(ev.data)
      else if (ev.data instanceof ArrayBuffer) onBinary(ev.data)
    }
    ch.onopen = () => {
      send({ t: 'rc:record.status' })
      list()
      if (dl && download.value?.status === 'paused') resume()
    }
    ch.onclose = () => {
      if (channel === ch) channel = null
      pause('session_ended')
      // P3b-3 — the device does not stop a recording its session left: it
      // waits up to a minute for this controller's next session, whose
      // channel asks for the status as it opens and picks it up.
      if (state.value === 'recording') {
        state.value = 'reconnecting'
        reason.value = null
      } else if (state.value === 'pending_consent') {
        // A question the host was asked dies with the session.
        state.value = 'stopped'
        reason.value = 'session_ended'
      }
    }
    if (ch.readyState === 'open') ch.onopen()
  }

  function detach() {
    if (channel) {
      channel.onmessage = null
      channel.onopen = null
      channel.onclose = null
    }
    channel = null
    pause('session_ended')
  }

  function start(withAudio = false) {
    currentId = newId('rec')
    reason.value = null
    detail.value = null
    // #1760 — never ask for what the device said it cannot give: the box is
    // greyed out and unticked, and a stale tick must not become a start that
    // can only fail.
    const audio = withAudio && !audioUnavailable.value
    if (!send({ t: 'rc:record.start', id: currentId, audio })) {
      state.value = 'failed'
      reason.value = 'session_ended'
    }
  }

  function stop() {
    send({ t: 'rc:record.stop', id: currentId })
  }

  /** P3b-3 — a DELIBERATE Disconnect ends the recording first. The device
   *  cannot tell a hang-up from the reconnect ladder's retry (both are
   *  `controller_hangup`), and a retry is exactly what the re-attach grace
   *  keeps a recording running for: left alone, the device would record a
   *  minute more for a controller who has gone. Resolves once the device
   *  says it stopped, or after `timeoutMs` (the Disconnect goes ahead either
   *  way). A recording whose channel is already gone (`reconnecting`) cannot
   *  be asked; the device's grace ends it. */
  function stopBeforeLeaving(timeoutMs = 3000): Promise<void> {
    if (state.value !== 'recording') return Promise.resolve()
    stop()
    return new Promise<void>((resolve) => {
      const started = Date.now()
      const look = () => {
        if (state.value !== 'recording' || Date.now() - started >= timeoutMs) resolve()
        else setTimeout(look, 50)
      }
      look()
    })
  }

  function list() {
    send({ t: 'rc:record.list', id: newId('list') })
  }

  function resume() {
    if (!dl || !download.value) return
    dl.id = newId('dl')
    download.value.status = 'active'
    download.value.error = undefined
    send({
      t: 'rc:record.get',
      id: dl.id,
      name: download.value.name,
      offset: download.value.received,
    })
  }

  /** Download one of this controller's recordings. Call straight from the
   *  click: the save dialog must open within the user gesture. */
  async function downloadRecording(fileName: string, size: number | null = null) {
    if (dl) throw new Error('transfer_in_progress')
    const sink = await openSink(fileName, size)
    download.value = { name: fileName, size, received: 0, status: 'active' }
    dl = { id: newId('dl'), sink, chain: Promise.resolve() }
    if (!send({ t: 'rc:record.get', id: dl.id, name: fileName, offset: 0 })) {
      pause('session_ended')
    }
  }

  function cancelDownload() {
    if (!dl) return
    send({ t: 'rc:record.cancel', id: dl.id })
    fail('cancelled')
  }

  return {
    state,
    reason,
    detail,
    name,
    bytes,
    durationMs,
    audio,
    audioUnavailable,
    items,
    download,
    attach,
    detach,
    start,
    stop,
    stopBeforeLeaving,
    list,
    downloadRecording,
    cancelDownload,
  }
}
