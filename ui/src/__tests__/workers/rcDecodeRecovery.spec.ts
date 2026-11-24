// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-131 P2 (upstream FR-135 R1) — the recovery decision, the worker wiring,
 * and the gap's gate.
 *
 * The second half is black-box, in the manner of `rcDecodeWorkersColorSpace`:
 * each real DC worker is driven through the messages the composable sends it,
 * with WebCodecs replaced by a recording fake.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { MAX_PARTIAL_FRAMES } from '@/workers/rc-chunk-framing'
import {
  createDecodeRecovery,
  DECODE_RECOVER_MAX_ATTEMPTS,
  DECODE_RECOVER_WINDOW_MS,
} from '@/workers/rc-decode-recovery'

describe('FR-135 R1 — the recovery decision', () => {
  function enabled() {
    const r = createDecodeRecovery()
    r.setEnabled(true)
    return r
  }

  it('leaves a failure before the first frame to the ban-and-renegotiate path', () => {
    const r = enabled()
    expect(r.onFailure(0, 1_000)).toBe(false)
    expect(r.attempts).toBe(0)
    expect(r.onOutput(2_000)).toBeNull()
  })

  it('is off until the session says otherwise, and the switch turns it off', () => {
    const r = createDecodeRecovery()
    expect(r.onFailure(10, 1_000)).toBe(false)
    r.setEnabled(true)
    expect(r.onFailure(10, 1_000)).toBe(true)
    r.setEnabled(false)
    expect(r.onFailure(10, 1_500)).toBe(false)
  })

  it('lets a chunk gap close the gate only on an ordered channel with the switch on', () => {
    const r = createDecodeRecovery()
    expect(r.gapClosesGate()).toBe(false)
    r.setEnabled(true)
    expect(r.gapClosesGate()).toBe(true)
    r.setUnorderedChannel(true)
    expect(r.gapClosesGate()).toBe(false)
    r.setUnorderedChannel(false)
    expect(r.gapClosesGate()).toBe(true)
    r.setEnabled(false)
    expect(r.gapClosesGate()).toBe(false)
  })

  it('times an outage from the failure to the first frame, once', () => {
    const r = enabled()
    expect(r.onOutput(500)).toBeNull()
    expect(r.onFailure(10, 1_000)).toBe(true)
    expect(r.attempts).toBe(1)
    expect(r.onOutput(1_240)).toEqual({ ms: 240, attempts: 1 })
    expect(r.attempts).toBe(0)
    expect(r.onOutput(1_250)).toBeNull()
  })

  it('counts a new decoder that fails before a frame as the same outage', () => {
    const r = enabled()
    expect(r.onFailure(10, 1_000)).toBe(true)
    expect(r.onFailure(10, 1_300)).toBe(true)
    expect(r.onOutput(1_700)).toEqual({ ms: 700, attempts: 2 })
  })

  it('gives up past the budget, and the attempts stay spent inside the window', () => {
    const r = enabled()
    for (let i = 0; i < DECODE_RECOVER_MAX_ATTEMPTS; i++) {
      expect(r.onFailure(10, 1_000 + i)).toBe(true)
      // A frame between failures does not refill it: a stream that decodes a
      // key frame and dies on the next delta must not loop for ever.
      expect(r.onOutput(1_000 + i)).not.toBeNull()
    }
    expect(r.onFailure(10, 2_000)).toBe(false)
    expect(r.onFailure(10, 3_000)).toBe(false)
  })

  it('recovers again once the old attempts leave the window', () => {
    const r = enabled()
    for (let i = 0; i < DECODE_RECOVER_MAX_ATTEMPTS; i++) r.onFailure(10, 1_000)
    expect(r.onFailure(10, 1_000 + DECODE_RECOVER_WINDOW_MS - 1)).toBe(false)
    expect(r.onFailure(10, 1_000 + DECODE_RECOVER_WINDOW_MS)).toBe(true)
  })

  it('keeps recovering a fault that recurs more slowly than the budget', () => {
    const r = enabled()
    const every = DECODE_RECOVER_WINDOW_MS / DECODE_RECOVER_MAX_ATTEMPTS + 1
    for (let i = 0; i < 20; i++) {
      expect(r.onFailure(10, i * every)).toBe(true)
      r.onOutput(i * every + 100)
    }
  })
})

type DecoderInit = { output: (frame: unknown) => void; error: (err: unknown) => void }

class FakeDecoder {
  static instances: FakeDecoder[] = []
  static isConfigSupported = vi.fn(async (config: VideoDecoderConfig) => ({ supported: true, config }))
  static throwOnDecode: unknown = null
  readonly configs: VideoDecoderConfig[] = []
  readonly chunks: { type: string; timestamp: number }[] = []
  state: 'unconfigured' | 'configured' | 'closed' = 'unconfigured'
  decodeQueueSize = 0
  constructor(readonly init: DecoderInit) {
    FakeDecoder.instances.push(this)
  }
  configure(config: VideoDecoderConfig): void {
    this.configs.push(config)
    this.state = 'configured'
  }
  decode(chunk: { type: string; timestamp: number }): void {
    if (this.state === 'closed') throw new DOMException('closed', 'InvalidStateError')
    if (FakeDecoder.throwOnDecode) throw FakeDecoder.throwOnDecode
    this.chunks.push(chunk)
  }
  close(): void {
    if (this.state === 'closed') throw new DOMException('closed', 'InvalidStateError')
    this.state = 'closed'
  }
  /** The browser's error path: the codec closes, then the callback runs. */
  fail(err: unknown): void {
    this.state = 'closed'
    this.init.error(err)
  }
}

class FakeChunk {
  type: string
  timestamp: number
  constructor(init: { type: string; timestamp: number }) {
    this.type = init.type
    this.timestamp = init.timestamp
  }
}

function fakeFrame(timestamp: number) {
  return {
    timestamp,
    displayWidth: 1920,
    displayHeight: 1080,
    codedWidth: 1920,
    codedHeight: 1080,
    visibleRect: { x: 0, y: 0, width: 1920, height: 1080 },
    colorSpace: { toJSON: () => ({}) },
    close: () => {},
  }
}

function fakeCanvas() {
  return { width: 0, height: 0, getContext: () => ({ drawImage: () => {} }) }
}

/** One frame as the agent frames it: u32 size, u8 flags (bit 0: key), u64
 *  timestamp, payload. */
function frameBytes(key: boolean, timestampUs: number): Uint8Array {
  const payload = [0, 0, 0, 1, 0x65]
  const buf = new ArrayBuffer(13 + payload.length)
  const view = new DataView(buf)
  view.setUint32(0, payload.length, true)
  view.setUint8(4, key ? 1 : 0)
  view.setUint32(5, timestampUs, true)
  view.setUint32(9, 0, true)
  new Uint8Array(buf, 13).set(payload)
  return new Uint8Array(buf)
}

function bare(key: boolean, timestampUs: number): ArrayBuffer {
  return frameBytes(key, timestampUs).buffer as ArrayBuffer
}

/** The FR-17 prefix: u32 seq, u16 chunk index, u16 chunk count. */
function framedChunk(seq: number, idx: number, count: number, payload: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(8 + payload.length)
  const view = new DataView(buf)
  view.setUint32(0, seq, true)
  view.setUint16(4, idx, true)
  view.setUint16(6, count, true)
  new Uint8Array(buf, 8).set(payload)
  return buf
}

/**
 * Frames `first`… lose their second chunk until the receiver must evict one to
 * hold the next: that eviction is the gap. Upstream drives this with a frame
 * overtaken by a newer complete one, which raises `gap` only after its FR-17
 * fix (8f5ea492e), not ported here; the eviction path raises it on both.
 * Returns the seq of the delta that revealed the gap (it completes at once).
 */
function loseFrames(send: (m: Record<string, unknown>) => void, first: number): number {
  let seq = first
  for (let i = 0; i < MAX_PARTIAL_FRAMES; i++, seq++) {
    send({ type: 'chunk', bytes: framedChunk(seq, 0, 2, frameBytes(false, seq)) })
  }
  send({ type: 'chunk', bytes: framedChunk(seq, 0, 1, frameBytes(false, seq)) })
  return seq
}

type Scope = {
  postMessage: (msg: unknown) => void
  onmessage: ((ev: { data: unknown }) => void) | null
}
const scope = self as unknown as Scope
let originalPost: Scope['postMessage']
let posted: Record<string, unknown>[] = []
let clock = 0
const ofType = (t: string) => posted.filter((m) => m.type === t)

beforeEach(() => {
  vi.resetModules()
  FakeDecoder.instances = []
  FakeDecoder.throwOnDecode = null
  vi.stubGlobal('VideoDecoder', FakeDecoder)
  vi.stubGlobal('EncodedVideoChunk', FakeChunk)
  // A clock the test moves, so a recovery's duration can be asserted.
  clock = 100_000
  vi.spyOn(performance, 'now').mockImplementation(() => clock)
  posted = []
  originalPost = scope.postMessage
  scope.postMessage = (msg) => {
    posted.push(msg as Record<string, unknown>)
  }
})

afterEach(() => {
  scope.postMessage = originalPost
  scope.onmessage = null
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

const DC_WORKERS = [
  { name: 'rc-vp9-444-worker', load: () => import('@/workers/rc-vp9-444-worker') },
  { name: 'rc-hevc-worker', load: () => import('@/workers/rc-hevc-worker') },
] as const

describe.each(DC_WORKERS)('FR-135 R1 — $name', ({ load }) => {
  async function start(init: Record<string, unknown> = { decodeRecover: true }) {
    await load()
    const onmessage = scope.onmessage!
    onmessage({ data: { type: 'init-canvas', canvas: fakeCanvas(), ...init } })
    return (msg: Record<string, unknown>) => onmessage({ data: msg })
  }

  /** A session past its first frame, on decoder 0. */
  async function painting(init?: Record<string, unknown>) {
    const send = await start(init)
    send({ type: 'chunk', bytes: bare(true, 1) })
    FakeDecoder.instances[0]!.init.output(fakeFrame(1))
    return send
  }

  it('replaces a decoder that fails after the first frame, and does not report it fatal', async () => {
    const send = await painting()
    posted = []
    FakeDecoder.instances[0]!.fail(new Error('Decoding error.'))

    expect(ofType('decoder-error')).toEqual([])
    expect(ofType('decode-recovering')).toEqual([{ type: 'decode-recovering', error: 'Decoding error.', attempt: 1 }])
    expect(FakeDecoder.instances).toHaveLength(2)
    expect(FakeDecoder.instances[1]!.state).toBe('configured')
    expect(ofType('request-keyframe')).toHaveLength(1)

    // The new decoder's first input is a key frame: deltas wait at the gate.
    send({ type: 'chunk', bytes: bare(false, 2) })
    expect(FakeDecoder.instances[1]!.chunks).toEqual([])
    expect(ofType('awaiting-keyframe')).toHaveLength(1)
    send({ type: 'chunk', bytes: bare(true, 3) })
    expect(FakeDecoder.instances[1]!.chunks.map((c) => c.type)).toEqual(['key'])
  })

  it('reports how long the picture was gone, on the first frame after it', async () => {
    const send = await painting()
    posted = []
    FakeDecoder.instances[0]!.fail(new Error('Decoding error.'))
    clock += 180
    send({ type: 'chunk', bytes: bare(true, 3) })
    expect(ofType('decode-recovered')).toEqual([])
    clock += 60
    FakeDecoder.instances[1]!.init.output(fakeFrame(3))
    expect(ofType('decode-recovered')).toEqual([{ type: 'decode-recovered', ms: 240, attempts: 1 }])
    // Once: the next frame is an ordinary one.
    FakeDecoder.instances[1]!.init.output(fakeFrame(4))
    expect(ofType('decode-recovered')).toHaveLength(1)
  })

  it('recovers when decode() throws too, closing the decoder it still holds', async () => {
    const send = await painting()
    FakeDecoder.throwOnDecode = new DOMException('A key frame is required', 'DataError')
    posted = []
    send({ type: 'chunk', bytes: bare(false, 2) })
    FakeDecoder.throwOnDecode = null

    expect(ofType('decode-error')).toEqual([])
    expect(ofType('decode-recovering')).toHaveLength(1)
    expect(FakeDecoder.instances[0]!.state).toBe('closed')
    expect(FakeDecoder.instances).toHaveLength(2)
    expect(ofType('request-keyframe')).toHaveLength(1)
  })

  it('hands the session to the watchdog path past the budget', async () => {
    const send = await painting()
    posted = []
    for (let i = 0; i < DECODE_RECOVER_MAX_ATTEMPTS; i++) {
      const decoder = FakeDecoder.instances.at(-1)!
      decoder.fail(new Error('Decoding error.'))
      clock += 300
      expect(FakeDecoder.instances.at(-1)).not.toBe(decoder)
      expect(ofType('decoder-error')).toEqual([])
      send({ type: 'chunk', bytes: bare(true, 10 + i) })
      FakeDecoder.instances.at(-1)!.init.output(fakeFrame(10 + i))
    }
    const built = FakeDecoder.instances.length
    FakeDecoder.instances.at(-1)!.fail(new Error('Decoding error.'))
    expect(ofType('decoder-error')).toEqual([{ type: 'decoder-error', error: 'Decoding error.' }])
    expect(FakeDecoder.instances).toHaveLength(built)
  })

  it('reports as before with the switch off, and with no flag', async () => {
    await painting({ decodeRecover: false })
    posted = []
    FakeDecoder.instances[0]!.fail(new Error('Decoding error.'))
    expect(ofType('decoder-error')).toEqual([{ type: 'decoder-error', error: 'Decoding error.' }])
    expect(ofType('decode-recovering')).toEqual([])
    expect(FakeDecoder.instances).toHaveLength(1)
  })

  it('leaves a failure before the first frame to the composable, which bans the transport', async () => {
    const send = await start()
    send({ type: 'chunk', bytes: bare(true, 1) })
    FakeDecoder.instances[0]!.fail(new DOMException('Unsupported configuration', 'NotSupportedError'))
    expect(ofType('decoder-error')).toHaveLength(1)
    expect(FakeDecoder.instances).toHaveLength(1)
  })

  it('keeps the flag across the idempotent visible-canvas re-init', async () => {
    const send = await painting()
    send({ type: 'init-canvas', canvas: fakeCanvas() })
    posted = []
    FakeDecoder.instances[0]!.fail(new Error('Decoding error.'))
    expect(ofType('decoder-error')).toEqual([])
    expect(FakeDecoder.instances).toHaveLength(2)
  })

  it('re-arms the gate on a chunk gap: no delta reaches the decoder until the key frame', async () => {
    const send = await start({ decodeRecover: true, chunkFraming: true })
    const decoder = FakeDecoder.instances[0]!
    send({ type: 'chunk', bytes: framedChunk(1, 0, 1, frameBytes(true, 1)) })
    send({ type: 'chunk', bytes: framedChunk(2, 0, 1, frameBytes(false, 2)) })
    expect(decoder.chunks.map((c) => c.type)).toEqual(['key', 'delta'])
    // Both came out, so no backlog: the shed also re-arms the gate, and this
    // test must pass on the gap's doing alone.
    decoder.init.output(fakeFrame(1))
    decoder.init.output(fakeFrame(2))
    clock += 1_000 // past the resync debounce
    posted = []

    // Frames 3–5 lose a chunk; the receiver evicts one to hold frame 6, so
    // they can never complete. Frame 6 is a delta against what was lost: the
    // gate drops it, and the next delta too.
    const revealed = loseFrames(send, 3)
    expect(ofType('frame-rejected')).toHaveLength(1)
    expect(ofType('frame-rejected')[0]).toMatchObject({ reason: 'chunk-gap' })
    expect(ofType('request-keyframe')).toHaveLength(1)
    send({ type: 'chunk', bytes: framedChunk(revealed + 1, 0, 1, frameBytes(false, revealed + 1)) })
    expect(decoder.chunks.map((c) => c.type)).toEqual(['key', 'delta'])

    // The key frame opens it, on the same decoder: a gap is no decoder failure.
    send({ type: 'chunk', bytes: framedChunk(revealed + 2, 0, 1, frameBytes(true, revealed + 2)) })
    expect(decoder.chunks.map((c) => c.type)).toEqual(['key', 'delta', 'key'])
    expect(FakeDecoder.instances).toHaveLength(1)
    expect(ofType('keyframe-acquired')).toHaveLength(1)
  })

  it.each([
    ['with the switch off', { decodeRecover: false, chunkFraming: true }],
    ['on an unordered channel, where a gap is routine', { decodeRecover: true, chunkFraming: true, unorderedVideo: true }],
  ])('keeps decoding the deltas behind a chunk gap %s', async (_name, init) => {
    const send = await start(init)
    const decoder = FakeDecoder.instances[0]!
    send({ type: 'chunk', bytes: framedChunk(1, 0, 1, frameBytes(true, 1)) })
    send({ type: 'chunk', bytes: framedChunk(2, 0, 1, frameBytes(false, 2)) })
    decoder.init.output(fakeFrame(1))
    decoder.init.output(fakeFrame(2))
    clock += 1_000 // past the resync debounce
    posted = []

    const revealed = loseFrames(send, 3)
    send({ type: 'chunk', bytes: framedChunk(revealed + 1, 0, 1, frameBytes(false, revealed + 1)) })
    // The gap is still counted and still asks for a key frame, as it always has.
    expect(ofType('frame-rejected')).toHaveLength(1)
    expect(ofType('request-keyframe')).toHaveLength(1)
    // Frames 3–5 died with their chunks, and the two behind them reach the decoder.
    expect(decoder.chunks.map((c) => c.type)).toEqual(['key', 'delta', 'delta', 'delta'])
  })

  it('keeps the channel flag across the idempotent visible-canvas re-init', async () => {
    const send = await start({ decodeRecover: true, chunkFraming: true, unorderedVideo: true })
    send({ type: 'init-canvas', canvas: fakeCanvas() })
    const decoder = FakeDecoder.instances[0]!
    send({ type: 'chunk', bytes: framedChunk(1, 0, 1, frameBytes(true, 1)) })
    decoder.init.output(fakeFrame(1))
    clock += 1_000
    loseFrames(send, 2)
    expect(ofType('frame-rejected')).toHaveLength(1)
    expect(decoder.chunks.map((c) => c.type)).toEqual(['key', 'delta'])
  })
})
