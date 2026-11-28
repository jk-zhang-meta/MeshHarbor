// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/// <reference lib="webworker" />

/**
 * Tier B7 — WebCodecs render path.
 *
 * Web Worker that receives encoded video frames from an
 * `RTCRtpScriptTransform` on the main thread, decodes them via
 * `VideoDecoder`, and paints the results onto an `OffscreenCanvas`.
 * Bypasses Chrome's built-in jitter buffer on the `<video>` element
 * (the ~80 ms soft floor that keeps the browser viewer perceptually
 * laggier than RustDesk's native path).
 *
 * The worker is Chrome-only in practice: Firefox exposes insertable
 * streams via a different API and Safari lands it piecemeal. The
 * composable feature-detects `RTCRtpScriptTransform` + `VideoDecoder`
 * and falls back to classic `<video>` rendering when either is
 * missing.
 *
 * Flow: main thread posts `init-canvas` with a transferred
 * OffscreenCanvas; then assigns `receiver.transform = new
 * RTCRtpScriptTransform(worker, { codec })`. That fires
 * `self.onrtctransform` here, which opens a VideoDecoder, pipes the
 * transformer's readable into it, and paints decoded frames to the
 * canvas. We intentionally do NOT write frames to the transformer's
 * writable — that swallows the stream's default path so the `<video>`
 * element would render black (fine; we're rendering the canvas
 * instead).
 */

import { epochNowMs } from './rc-hop-stats'
import { createBenchSampler } from './rc-bench-sampler'
import { PAINT_GAP_CLOSED, PAINT_GAP_MARK, PAINT_GAP_MARKED, createPaintGapMark } from './rc-paint-gap'

/** `bench` — FR-16 L4 bench mode, set only when the knob is on AND the
 *  agent advertised `bench`: sample the probe marker while a probe is armed. */
type InitCanvasMessage = { type: 'init-canvas'; canvas: OffscreenCanvas; bench?: boolean }
/** FR-16 L4 — the main thread just sent bench probe `seq`. */
type BenchArmMessage = { type: 'bench-arm'; seq: number }
/** FR-130 — the page started to hold its session (`rc-paint-gap.ts`). */
type PaintGapMarkMessage = { type: typeof PAINT_GAP_MARK }
type CloseMessage = { type: 'close' }
type IncomingMessage = InitCanvasMessage | BenchArmMessage | PaintGapMarkMessage | CloseMessage

interface RTCTransformerLike {
  readable: ReadableStream<unknown>
  writable: WritableStream<unknown>
  options?: { codec?: string }
}

interface RTCTransformEventLike {
  transformer: RTCTransformerLike
}

interface EncodedFrameLike {
  type?: string
  timestamp: number
  data: ArrayBuffer
}

const workerScope = self as unknown as {
  onmessage: ((ev: MessageEvent<IncomingMessage>) => void) | null
  onrtctransform: ((ev: RTCTransformEventLike) => void) | null
  postMessage: (msg: unknown) => void
}

/** FR-16 L4 — reads the bench probe off painted frames, only while armed. */
const bench = createBenchSampler({ post: (m) => workerScope.postMessage(m), now: epochNowMs })
/** FR-130 — the gap in the painted frames across a held session's cut. Says
 *  nothing unless the page marks a cut. */
const paintGap = createPaintGapMark()

let canvas: OffscreenCanvas | null = null
let ctx: OffscreenCanvasRenderingContext2D | null = null
let decoder: VideoDecoder | null = null
let configured = false
let sawKeyframe = false
let framesDecoded = 0
let framesReceived = 0
let framesFedToDecoder = 0
let lastPostedW = 0
let lastPostedH = 0
let lastKeyframeReqMs = 0
const MAX_DECODE_QUEUE = 4
const KEYFRAME_REQ_DEBOUNCE_MS = 1000

function requestKeyframeResync(): void {
  const now = performance.now()
  if (now - lastKeyframeReqMs < KEYFRAME_REQ_DEBOUNCE_MS) return
  lastKeyframeReqMs = now
  workerScope.postMessage({ type: 'request-keyframe' })
}

workerScope.onmessage = (e) => {
  const msg = e.data
  if (!msg) return
  if (msg.type === 'init-canvas') {
    canvas = msg.canvas
    ctx = canvas.getContext('2d')
    if (typeof msg.bench === 'boolean') bench.setEnabled(msg.bench)
  } else if (msg.type === 'bench-arm') {
    bench.arm(msg.seq)
  } else if (msg.type === PAINT_GAP_MARK) {
    // FR-130 — the page holds its session from here: when this worker last
    // painted, and the gap at the first frame it paints next.
    workerScope.postMessage({ type: PAINT_GAP_MARKED, sinceMs: paintGap.mark(performance.now()) })
  } else if (msg.type === 'close') {
    try {
      decoder?.close()
    } catch {
      /* idempotent teardown */
    }
    decoder = null
    canvas = null
    ctx = null
    configured = false
    sawKeyframe = false
    framesDecoded = 0
    lastPostedW = 0
    lastPostedH = 0
    paintGap.reset()
  }
}

workerScope.onrtctransform = async (event) => {
  const transformer = event.transformer
  const codec = transformer.options?.codec ?? 'h264'
  const codecString = codecMimeForShort(codec)

  let watchdogCleared = false
  decoder = new VideoDecoder({
    output: (frame) => {
      framesDecoded++
      if (!watchdogCleared) {
        watchdogCleared = true
        clearTimeout(watchdog)
      }
      // Snapshot before paint closes the frame (a closed one reports 0).
      const w = frame.displayWidth
      const h = frame.displayHeight
      // FR-16 L4 — a clone for the probe read; null unless a probe is armed.
      const benchClone = bench.take(frame)
      const drew = paintFrame(frame)
      // FR-130 — the first frame painted after a held session's cut.
      const gapClosed = drew ? paintGap.painted(performance.now()) : null
      if (gapClosed) workerScope.postMessage({ type: PAINT_GAP_CLOSED, gapMs: gapClosed.gapMs })
      if (benchClone) bench.settle(benchClone, epochNowMs())
      // Publish on frame 1 AND on every live dimension change so adaptive
      // cursor/input coordinate mapping stays accurate after resize.
      if (w > 0 && h > 0 && (w !== lastPostedW || h !== lastPostedH)) {
        lastPostedW = w
        lastPostedH = h
        workerScope.postMessage({
          type: 'first-frame',
          width: w,
          height: h,
          visible: drew,
        })
      }
    },
    error: (err) => {
      sawKeyframe = false
      workerScope.postMessage({
        type: 'decoder-error',
        error: extractErrorMessage(err),
      })
    },
  })

  // Try the "latency-first" config first, then fall back to a plain
  // config. Some Chrome builds reject `optimizeForLatency: true` for
  // HEVC specifically (the flag landed after the HEVC decoder did);
  // the plain config usually works when the codec itself is
  // supported. If NEITHER works, the worker still stands up but
  // every decode() call will error — surface `decoder-error` from
  // main-thread console.
  const configs: VideoDecoderConfig[] = [
    { codec: codecString, optimizeForLatency: true } as VideoDecoderConfig,
    { codec: codecString } as VideoDecoderConfig,
  ]
  let picked: VideoDecoderConfig | null = null
  for (const cfg of configs) {
    try {
      const support = await VideoDecoder.isConfigSupported(cfg)
      if (support.supported) {
        picked = cfg
        break
      }
    } catch {
      // isConfigSupported can reject on older Chromes; try configure() below anyway.
    }
  }
  const toUse = picked ?? configs[0]!
  try {
    decoder.configure(toUse)
    configured = true
  } catch (err) {
    workerScope.postMessage({
      type: 'decoder-configure-error',
      codec: codecString,
      error: extractErrorMessage(err),
    })
  }

  workerScope.postMessage({
    type: 'transform-active',
    codec,
    codecString,
    configured,
    pickedConfig: picked ? 'with-optimize-for-latency' : 'fallback',
  })

  // Watchdog: if 3 seconds pass after onrtctransform fires and no frame has
  // actually DECODED (not merely arrived encoded), surface a loud warning.
  let watchdogFired = false
  const watchdog = setTimeout(() => {
    if (framesDecoded === 0 && !watchdogFired) {
      watchdogFired = true
      workerScope.postMessage({
        type: 'watchdog',
        message: framesReceived === 0
          ? 'no encoded frames in 3s after transform-active — Chrome may be holding frames on the default path'
          : 'encoded frames arrived but 0 decoded in 3s — decoder stalled or awaiting keyframe',
      })
    }
  }, 3000)

  // Canonical RTCRtpScriptTransform pattern. We pipe frames through
  // a TransformStream to `transformer.writable` (the default decoder
  // path) because Chrome's receive-side transform uses the writable
  // as the demand source — an unconsumed writable eventually
  // back-pressures the readable. The transform callback decodes each
  // frame in parallel via our VideoDecoder → canvas, and enqueues
  // the original frame unchanged so the default pipeline stays fed.
  const inFlight = transformer.readable
    .pipeThrough(
      new TransformStream<unknown, unknown>({
        transform: (value, controller) => {
          // Log EVERY callback entry on the first 3 hits to prove
          // the transform actually runs. Many black-screen failure
          // modes show up as "transform never called once".
          framesReceived++
          if (framesReceived <= 3) {
            const sig = (() => {
              try {
                const f = value as unknown as EncodedFrameLike
                if (f?.data && f.data instanceof ArrayBuffer) {
                  const bytes = new Uint8Array(f.data)
                  return {
                    byteLength: f.data.byteLength,
                    frameType: f.type ?? 'unknown',
                    firstBytes: Array.from(bytes.slice(0, 8))
                      .map((b) => b.toString(16).padStart(2, '0'))
                      .join(' '),
                  }
                }
                return { byteLength: 0, frameType: typeof value }
              } catch {
                return { byteLength: -1, frameType: 'inspect-threw' }
              }
            })()
            workerScope.postMessage({
              type: framesReceived === 1 ? 'first-encoded-frame' : 'early-encoded-frame',
              idx: framesReceived,
              ...sig,
            })
          }
          if (framesReceived % 30 === 0) {
            workerScope.postMessage({
              type: 'reader-heartbeat',
              received: framesReceived,
              fedToDecoder: framesFedToDecoder,
              decoded: framesDecoded,
            })
          }
          // Defensive: if the value isn't what we expect, still
          // forward it so the pipeline doesn't stall on our filter.
          const encFrame = value as unknown as EncodedFrameLike
          if (
            !decoder
            || !encFrame
            || !encFrame.data
            || !(encFrame.data instanceof ArrayBuffer)
          ) {
            controller.enqueue(value)
            return
          }
          if (!configured) {
            try {
              decoder.configure({
                codec: codecString,
                optimizeForLatency: true,
              } as VideoDecoderConfig)
              configured = true
            } catch {
              controller.enqueue(value)
              return
            }
          }
          const isKey = encFrame.type === 'key'
          if (!isKey && !sawKeyframe) {
            // Leading-delta gate: VideoDecoder requires a keyframe first after
            // configure() or backlog shed; request one and keep default path fed.
            requestKeyframeResync()
            controller.enqueue(value)
            return
          }
          if (!isKey && decoder.decodeQueueSize >= MAX_DECODE_QUEUE) {
            // Bounded queue backpressure: shed delta frames and re-arm keyframe
            // gate instead of growing unbounded decode latency.
            sawKeyframe = false
            requestKeyframeResync()
            controller.enqueue(value)
            return
          }
          try {
            const chunk = new EncodedVideoChunk({
              type: isKey ? 'key' : 'delta',
              timestamp: encFrame.timestamp,
              data: encFrame.data,
            })
            decoder.decode(chunk)
            if (isKey) sawKeyframe = true
            framesFedToDecoder++
          } catch (err) {
            sawKeyframe = false
            workerScope.postMessage({
              type: 'decode-error',
              error: extractErrorMessage(err),
            })
          }
          controller.enqueue(value)
        },
      }),
    )
    .pipeTo(transformer.writable)
  inFlight.catch((err) => {
    workerScope.postMessage({
      type: 'pipe-error',
      error: extractErrorMessage(err),
    })
  })
}

/** Paint `frame` and close it; `true` when it reached the canvas. */
function paintFrame(frame: VideoFrame): boolean {
  if (!canvas || !ctx) {
    frame.close()
    return false
  }
  try {
    if (canvas.width !== frame.displayWidth) canvas.width = frame.displayWidth
    if (canvas.height !== frame.displayHeight) canvas.height = frame.displayHeight
    ctx.drawImage(frame, 0, 0)
    return true
  } catch {
    /* canvas vanished mid-teardown */
    return false
  } finally {
    frame.close()
  }
}

function extractErrorMessage(err: unknown): string {
  if (err instanceof Error) return err.message
  try {
    return String(err)
  } catch {
    return 'unknown'
  }
}

/**
 * Map a short codec name (from our protocol) to the codec string
 * `VideoDecoder.configure()` expects. These are permissive defaults;
 * Chrome tolerates variants when decoding Annex-B RTP NALUs from
 * webrtc-rs's depayloader. Exported for vitest.
 */
export function codecMimeForShort(short: string): string {
  switch (short.toLowerCase()) {
    case 'h264':
      return 'avc1.42E01F'
    case 'h265':
    case 'hevc':
      // rc.94 — Level 5.1 (`L153`), not L3.1 (`L93`). L3.1 maxes at
      // ~1280×720; desktops at 1920×1200 / 1440p / 4K exceed it and the
      // HW HEVC decoder renders black. L5.1 (up to 4K@64) is a declared
      // MAX, so smaller streams still decode. Matches rc-hevc-worker's
      // DEFAULT_HEVC_CODEC + the isHevcDecodeSupported probe.
      return 'hev1.1.6.L153.B0'
    case 'av1':
      return 'av01.0.08M.08'
    case 'vp9':
      return 'vp09.00.10.08'
    case 'vp8':
      return 'vp8'
    default:
      return 'avc1.42E01F'
  }
}
