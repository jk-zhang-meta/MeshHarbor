// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-85 P3c — the viewer's side of the `record` DataChannel, driven through a
 * fake channel and a fake save sink: the protocol code itself, with no
 * PeerConnection and no browser save dialog.
 */
import { describe, expect, it, vi } from 'vitest'
import {
  describeRecordReason,
  showsRecordRefusal,
  useRemoteRecording,
  type RecordChannel,
  type RecordSink,
} from '@/composables/useRemoteRecording'

/** A `record` channel whose sent messages the test reads, and whose inbound
 *  messages the test plays. */
function fakeChannel(open = true) {
  const sent: Record<string, unknown>[] = []
  const ch: RecordChannel & { deliver(v: unknown): void; close(): void; reopen(): void } = {
    readyState: open ? 'open' : 'connecting',
    binaryType: 'blob',
    onmessage: null,
    onopen: null,
    onclose: null,
    send(data: string) {
      sent.push(JSON.parse(data))
    },
    deliver(v: unknown) {
      this.onmessage?.({ data: typeof v === 'string' || v instanceof ArrayBuffer ? v : JSON.stringify(v) })
    },
    close() {
      this.readyState = 'closed'
      this.onclose?.()
    },
    reopen() {
      this.readyState = 'open'
      this.onopen?.()
    },
  }
  return { ch, sent }
}

/** A sink that keeps what it was given. */
function fakeSink(mode: 'stream' | 'blob' = 'stream') {
  const chunks: Uint8Array[] = []
  let closed = false
  let aborted = false
  const sink: RecordSink = {
    mode,
    write: async (c) => {
      chunks.push(new Uint8Array(c))
    },
    close: async () => {
      closed = true
    },
    abort: async () => {
      aborted = true
    },
    blob: () => (closed ? new Blob(chunks as BlobPart[]) : null),
  }
  return {
    sink,
    bytes: () => {
      const all = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0))
      let at = 0
      for (const c of chunks) {
        all.set(c, at)
        at += c.length
      }
      return all
    },
    closed: () => closed,
    aborted: () => aborted,
  }
}

const buf = (bytes: number[]) => new Uint8Array(bytes).buffer
const settle = () => new Promise((r) => setTimeout(r, 0))

async function sha256Hex(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', bytes)
  return Array.from(new Uint8Array(d))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

describe('useRemoteRecording (FR-85 P3c)', () => {
  it('asks where things stand and lists this controller’s recordings as the channel opens', () => {
    const r = useRemoteRecording()
    const { ch, sent } = fakeChannel()
    r.attach(ch)
    expect(ch.binaryType).toBe('arraybuffer')
    expect(sent.map((m) => m.t)).toEqual(['rc:record.status', 'rc:record.list'])
  })

  it('follows a recording from the prompt to its end, and says a refusal in words', () => {
    const r = useRemoteRecording()
    const { ch, sent } = fakeChannel()
    r.attach(ch)
    r.start(true)
    const start = sent.find((m) => m.t === 'rc:record.start')!
    expect(start.audio).toBe(true)
    expect(start).not.toHaveProperty('microphone')

    ch.deliver({ t: 'rc:record.state', id: start.id, state: 'pending_consent' })
    expect(r.state.value).toBe('pending_consent')
    ch.deliver({
      t: 'rc:record.state',
      id: start.id,
      state: 'recording',
      name: 'MeshHarbor Recording 2026-09-25 14-30-12.mp4',
      bytes: 1024,
      duration_ms: 1500,
      audio: true,
    })
    expect([r.state.value, r.name.value, r.durationMs.value, r.audio.value]).toEqual([
      'recording',
      'MeshHarbor Recording 2026-09-25 14-30-12.mp4',
      1500,
      true,
    ])
    r.stop()
    expect(sent.at(-1)).toEqual({ t: 'rc:record.stop', id: start.id })
    ch.deliver({ t: 'rc:record.state', id: start.id, state: 'stopped', reason: 'host_stopped', bytes: 4096 })
    expect(r.state.value).toBe('stopped')
    expect(describeRecordReason(r.reason.value)).toBe('the person at the device stopped it')
    // A finished recording is one more to list.
    expect(sent.at(-1)?.t).toBe('rc:record.list')

    ch.deliver({ t: 'rc:record.state', id: 'x', state: 'refused', reason: 'no_indicator_surface' })
    expect(describeRecordReason(r.reason.value)).toBe(
      "nothing on the device can show that it's being recorded",
    )
    expect(describeRecordReason('a_code_from_a_newer_device')).toBe('a_code_from_a_newer_device')

    // FR-85 decision 6: a login screen is its own refusal, and says what
    // would let it record — never the bare "can't record right now".
    ch.deliver({ t: 'rc:record.state', id: 'x', state: 'refused', reason: 'login_screen' })
    expect(r.state.value).toBe('refused')
    expect(describeRecordReason(r.reason.value)).toBe(
      'the device is at its sign-in screen; it can record once someone signs in',
    )
    expect(describeRecordReason('login_screen')).not.toBe(describeRecordReason('unavailable'))
  })

  it('greys "Include what the computer plays" out when the device says it cannot, and asks for none (#1760)', () => {
    const r = useRemoteRecording()
    const { ch, sent } = fakeChannel()
    r.attach(ch)
    // The device's answer to rc:record.status, before any start: a Mac.
    ch.deliver({ t: 'rc:record.state', id: '', state: 'idle', audio_unavailable: 'audio_unsupported' })
    expect(r.audioUnavailable.value).toBe('audio_unsupported')
    expect(describeRecordReason(r.audioUnavailable.value)).toBe(
      "this device can't record what the computer plays (Windows and Linux devices only, for now)",
    )
    // A box that cannot be ticked never asks: even a stale tick sends no audio.
    r.start(true)
    expect(sent.filter((m) => m.t === 'rc:record.start').at(-1)!.audio).toBe(false)
    // The owner's gate reads the same way, with its own sentence.
    ch.deliver({ t: 'rc:record.state', id: '', state: 'idle', audio_unavailable: 'audio_not_allowed' })
    expect(describeRecordReason(r.audioUnavailable.value)).toBe(
      "this device's owner hasn't allowed computer audio in a remote recording",
    )
    // The owner allowed it — or the device predates the field: the box is
    // offered, and a start asks for what was ticked.
    ch.deliver({ t: 'rc:record.state', id: '', state: 'idle' })
    expect(r.audioUnavailable.value).toBeNull()
    r.start(true)
    expect(sent.filter((m) => m.t === 'rc:record.start').at(-1)!.audio).toBe(true)
    // A refusal keeps the device's own words, for the line under the sentence.
    ch.deliver({
      t: 'rc:record.state',
      id: 'x',
      state: 'refused',
      reason: 'audio_unsupported',
      detail: "macOS can't capture what the computer plays yet",
      audio_unavailable: 'audio_unsupported',
    })
    expect([r.state.value, r.reason.value, r.detail.value, r.audioUnavailable.value]).toEqual([
      'refused',
      'audio_unsupported',
      "macOS can't capture what the computer plays yet",
      'audio_unsupported',
    ])
  })

  it('a device with no recorder gets no Record control; every other strip reason is shown (P3c-2)', () => {
    // Nothing there to allow or refuse: no disabled control on every session
    // to every device that predates recording.
    expect(showsRecordRefusal('device_cannot_record')).toBe(false)
    // What a controller can act on, or ask for, is still said.
    expect(showsRecordRefusal('device_not_opted_in')).toBe(true)
    expect(showsRecordRefusal('controller_not_allowed')).toBe(true)
    // A reason from a newer server is shown, never swallowed.
    expect(showsRecordRefusal('a_code_from_a_newer_server')).toBe(true)
    // No refusal, no control.
    expect(showsRecordRefusal(null)).toBe(false)
    expect(showsRecordRefusal(undefined)).toBe(false)
    expect(showsRecordRefusal('')).toBe(false)
    expect(describeRecordReason('device_cannot_record')).toBe("this device can't record its screen")
  })

  it('a channel that closes mid-recording reads as reconnecting, not ended (P3b-3)', () => {
    const r = useRemoteRecording()
    const { ch } = fakeChannel()
    r.attach(ch)
    ch.deliver({ t: 'rc:record.state', id: 'a', state: 'recording' })
    ch.close()
    // The device goes on recording for this controller's next session.
    expect([r.state.value, r.reason.value]).toEqual(['reconnecting', null])
    // A question still standing when the session went dies with it.
    const p = useRemoteRecording()
    const q = fakeChannel()
    p.attach(q.ch)
    q.ch.deliver({ t: 'rc:record.state', id: 'b', state: 'pending_consent' })
    q.ch.close()
    expect([p.state.value, p.reason.value]).toEqual(['stopped', 'session_ended'])
  })

  it("the next session's channel picks the recording up, and Stop names it (P3b-3)", () => {
    const r = useRemoteRecording()
    const first = fakeChannel()
    r.attach(first.ch)
    r.start(false)
    const started = first.sent.find((m) => m.t === 'rc:record.start')!
    first.ch.deliver({ t: 'rc:record.state', id: started.id, state: 'recording' })
    first.ch.close()
    expect(r.state.value).toBe('reconnecting')

    // The new session's channel asks for the status as it opens; the device
    // answers with the SAME recording.
    const next = fakeChannel(false)
    r.attach(next.ch)
    next.ch.reopen()
    expect(next.sent[0]).toEqual({ t: 'rc:record.status' })
    next.ch.deliver({ t: 'rc:record.state', id: started.id, state: 'recording', name: 'r.mp4' })
    expect(r.state.value).toBe('recording')
    r.stop()
    expect(next.sent.at(-1)).toEqual({ t: 'rc:record.stop', id: started.id })

    // A page that never started it (a reload) still stops it by its id.
    const fresh = useRemoteRecording()
    const again = fakeChannel()
    fresh.attach(again.ch)
    again.ch.deliver({ t: 'rc:record.state', id: 'device-side-id', state: 'recording' })
    fresh.stop()
    expect(again.sent.at(-1)).toEqual({ t: 'rc:record.stop', id: 'device-side-id' })
  })

  it('a deliberate Disconnect stops the recording first, and waits for the answer (P3b-3)', async () => {
    const r = useRemoteRecording()
    const { ch, sent } = fakeChannel()
    r.attach(ch)
    ch.deliver({ t: 'rc:record.state', id: 'a', state: 'recording' })
    let left = false
    const leaving = r.stopBeforeLeaving(2000).then(() => {
      left = true
    })
    expect(sent.at(-1)).toEqual({ t: 'rc:record.stop', id: 'a' })
    await new Promise((res) => setTimeout(res, 120))
    expect(left, 'it left before the device said the recording stopped').toBe(false)
    ch.deliver({ t: 'rc:record.state', id: 'a', state: 'stopped', reason: 'requested' })
    await leaving
    expect(left).toBe(true)

    // No answer: the Disconnect goes ahead anyway, after the wait.
    const q = useRemoteRecording()
    const silent = fakeChannel()
    q.attach(silent.ch)
    silent.ch.deliver({ t: 'rc:record.state', id: 'b', state: 'recording' })
    const t0 = Date.now()
    await q.stopBeforeLeaving(150)
    expect(Date.now() - t0).toBeGreaterThanOrEqual(140)

    // Nothing recording (or its channel already gone): nothing to stop.
    const idle = useRemoteRecording()
    const nothing = fakeChannel()
    idle.attach(nothing.ch)
    await idle.stopBeforeLeaving(5000)
    expect(nothing.sent.some((m) => m.t === 'rc:record.stop')).toBe(false)
    const gone = useRemoteRecording()
    const dropped = fakeChannel()
    gone.attach(dropped.ch)
    dropped.ch.deliver({ t: 'rc:record.state', id: 'c', state: 'recording' })
    dropped.ch.close()
    await gone.stopBeforeLeaving(5000)
    expect(dropped.sent.some((m) => m.t === 'rc:record.stop')).toBe(false)
  })

  it('back after a drop with nothing recording: it ended while this session was away (P3b-3)', () => {
    const r = useRemoteRecording()
    const first = fakeChannel()
    r.attach(first.ch)
    first.ch.deliver({ t: 'rc:record.state', id: 'a', state: 'recording' })
    first.ch.close()
    const next = fakeChannel()
    r.attach(next.ch)
    next.ch.deliver({ t: 'rc:record.state', id: '', state: 'idle' })
    expect([r.state.value, r.reason.value]).toEqual(['stopped', 'session_ended'])
    // Its file is one more to list.
    expect(next.sent.some((m) => m.t === 'rc:record.list')).toBe(true)
  })

  it('downloads a recording to disk: header, chunks in order, the device’s hash shown', async () => {
    const s = fakeSink('stream')
    const r = useRemoteRecording({ openSink: async () => s.sink })
    const { ch, sent } = fakeChannel()
    r.attach(ch)
    await r.downloadRecording('a.mp4', 6)
    const get = sent.find((m) => m.t === 'rc:record.get')!
    expect(get).toMatchObject({ name: 'a.mp4', offset: 0 })
    ch.deliver({ t: 'rc:record.file', id: get.id, name: 'a.mp4', offset: 0, size: 6 })
    ch.deliver(buf([1, 2, 3]))
    ch.deliver(buf([4, 5, 6]))
    ch.deliver({ t: 'rc:record.done', id: get.id, name: 'a.mp4', bytes: 6, size: 6, sha256: 'dev' })
    await settle()
    expect(Array.from(s.bytes())).toEqual([1, 2, 3, 4, 5, 6])
    expect(s.closed()).toBe(true)
    expect(r.download.value).toMatchObject({ status: 'done', received: 6, sha256: 'dev', verified: null })
  })

  it('resumes a transfer the session cut, from the bytes already held', async () => {
    const s = fakeSink('stream')
    const r = useRemoteRecording({ openSink: async () => s.sink })
    const first = fakeChannel()
    r.attach(first.ch)
    await r.downloadRecording('b.mp4')
    const get1 = first.sent.find((m) => m.t === 'rc:record.get')!
    first.ch.deliver({ t: 'rc:record.file', id: get1.id, offset: 0, size: 5 })
    first.ch.deliver(buf([10, 20]))
    first.ch.close()
    expect(r.download.value).toMatchObject({ status: 'paused', received: 2 })

    // The reconnect ladder's next session: a new channel, the same download.
    const second = fakeChannel(false)
    r.attach(second.ch)
    second.ch.reopen()
    const get2 = second.sent.find((m) => m.t === 'rc:record.get')!
    expect(get2).toMatchObject({ name: 'b.mp4', offset: 2 })
    second.ch.deliver({ t: 'rc:record.file', id: get2.id, offset: 2, size: 5 })
    second.ch.deliver(buf([30, 40, 50]))
    second.ch.deliver({ t: 'rc:record.done', id: get2.id, bytes: 3, size: 5, sha256: 'x' })
    await settle()
    expect(Array.from(s.bytes())).toEqual([10, 20, 30, 40, 50])
    expect(r.download.value?.status).toBe('done')
  })

  it('in memory, keeps the file only when its hash matches the device’s', async () => {
    const content = new Uint8Array([7, 8, 9])
    const good = await sha256Hex(content)
    const saved = vi.fn()

    const s = fakeSink('blob')
    const r = useRemoteRecording({ openSink: async () => s.sink, save: saved })
    const { ch, sent } = fakeChannel()
    r.attach(ch)
    await r.downloadRecording('c.mp4', 3)
    let get = sent.find((m) => m.t === 'rc:record.get')!
    ch.deliver({ t: 'rc:record.file', id: get.id, offset: 0, size: 3 })
    ch.deliver(content.buffer.slice(0))
    ch.deliver({ t: 'rc:record.done', id: get.id, bytes: 3, size: 3, sha256: good })
    // ⚠️ Wait for the OUTCOME, not a number of ticks: the check reads the
    // Blob and runs WebCrypto's digest, several async hops that two
    // `setTimeout(0)` did not always cover on a loaded CI runner.
    await vi.waitFor(() =>
      expect(r.download.value).toMatchObject({ status: 'done', verified: true }),
    )
    expect(saved).toHaveBeenCalledTimes(1)

    // The same bytes against a different hash: nothing is saved.
    const s2 = fakeSink('blob')
    const r2 = useRemoteRecording({ openSink: async () => s2.sink, save: saved })
    const two = fakeChannel()
    r2.attach(two.ch)
    await r2.downloadRecording('c.mp4', 3)
    get = two.sent.find((m) => m.t === 'rc:record.get')!
    two.ch.deliver({ t: 'rc:record.file', id: get.id, offset: 0, size: 3 })
    two.ch.deliver(content.buffer.slice(0))
    two.ch.deliver({ t: 'rc:record.done', id: get.id, bytes: 3, size: 3, sha256: '00'.repeat(32) })
    await vi.waitFor(() =>
      expect(r2.download.value).toMatchObject({
        status: 'error',
        error: 'hash_mismatch',
        verified: false,
      }),
    )
    expect(saved).toHaveBeenCalledTimes(1)
  })

  it('a short file is an error, never a quiet success', async () => {
    const s = fakeSink('stream')
    const r = useRemoteRecording({ openSink: async () => s.sink })
    const { ch, sent } = fakeChannel()
    r.attach(ch)
    await r.downloadRecording('d.mp4')
    const get = sent.find((m) => m.t === 'rc:record.get')!
    ch.deliver({ t: 'rc:record.file', id: get.id, offset: 0, size: 4 })
    ch.deliver(buf([1, 2]))
    ch.deliver({ t: 'rc:record.done', id: get.id, bytes: 2, size: 4, sha256: 'x' })
    await settle()
    expect(r.download.value).toMatchObject({ status: 'error', error: 'size_mismatch' })
    expect(s.aborted()).toBe(true)
  })

  it('a refusal ends the transfer by name; a cancel tells the device', async () => {
    const s = fakeSink('stream')
    const r = useRemoteRecording({ openSink: async () => s.sink })
    const { ch, sent } = fakeChannel()
    r.attach(ch)
    await r.downloadRecording('e.mp4')
    let get = sent.find((m) => m.t === 'rc:record.get')!
    ch.deliver({ t: 'rc:record.error', id: get.id, reason: 'not_found' })
    await settle()
    expect(r.download.value).toMatchObject({ status: 'error', error: 'not_found' })
    expect(describeRecordReason('not_found')).toBe('no such recording of yours on this device')

    await r.downloadRecording('f.mp4')
    get = sent.filter((m) => m.t === 'rc:record.get').at(-1)!
    r.cancelDownload()
    expect(sent.at(-1)).toEqual({ t: 'rc:record.cancel', id: get.id })
    expect(r.download.value).toMatchObject({ status: 'cancelled' })
  })

  it('one transfer at a time', async () => {
    const r = useRemoteRecording({ openSink: async () => fakeSink().sink })
    const { ch } = fakeChannel()
    r.attach(ch)
    await r.downloadRecording('g.mp4')
    await expect(r.downloadRecording('h.mp4')).rejects.toThrow('transfer_in_progress')
  })
})
