// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/// <reference lib="webworker" />

/**
 * Phase Y.2 — VP9 4:4:4 decoder worker for the DataChannel-bypass
 * video transport. See `docs/encoders.md`.
 *
 * Receives length-prefixed encoded VP9 frames from the main thread
 * (which forwards them off `RTCDataChannel.onmessage`), reassembles
 * them, feeds `VideoDecoder({codec:'vp09.01.10.08'})` (profile 1,
 * 8-bit 4:4:4), and paints the resulting `VideoFrame`s to an
 * `OffscreenCanvas`. No `RTCRtpScriptTransform` involvement — this
 * worker is independent of the broken-in-Chrome 131 RTP transform
 * path.
 *
 * Wire format (matches `agents/meshharbord/src/encode/libvpx.rs`):
 *
 *   struct Frame {
 *     u32  size_le;          // payload length, little-endian
 *     u8   flags;            // bit 0: keyframe
 *     u64  timestamp_us;     // monotonic capture timestamp
 *     [u8] payload;          // raw VP9 frame
 *   }
 *
 * Header is 13 bytes. SCTP is reliable+ordered so a single frame
 * may arrive across multiple `onmessage` chunks; the assembler in
 * this worker concatenates by tracking how many bytes of the
 * declared payload size remain.
 */

import {
  HopStats,
  QueueDrift,
  ctxOptionsFor,
  epochNowMs,
  epochNowUs,
  frameAgeMs,
  normalizeCtxMode,
  normalizeIntKnob,
  round1,
  DEFAULT_MAX_DECODE_QUEUE,
  type CtxMode,
} from './rc-hop-stats'
import {
  FsrRenderer,
  computeRenderTarget,
  normalizeSharpenMode,
  normalizeSharpness,
  DEFAULT_RCAS_SHARPNESS,
  type RenderPass,
  type SharpenMode,
} from './rc-fsr-render'
import {
  createChunkFraming,
  stripChunkPrefix,
} from './rc-chunk-framing'
import { createBenchSampler } from './rc-bench-sampler'

type InitCanvasMessage = {
  type: 'init-canvas'
  canvas: OffscreenCanvas
  /** FR-16 L4 — bench mode: sample the probe marker while a probe is armed.
   *  Set only when the knob is on AND the agent advertised `bench`; sticks
   *  across the idempotent visible-canvas re-init, like `ctxMode`. */
  bench?: boolean
  /** FR-17 — true when the controller negotiated per-chunk framing for
   *  this session (the agent advertised `chunk-framing` in
   *  `AgentCaps.video`). Absent/false keeps the pre-FR-17 bare byte
   *  stream, which is what every agent below 0.4.14 still sends. */
  chunkFraming?: boolean
  /** Optional codec override. Production uses VP9 profile 1
   *  (vp09.01.10.08, 4:4:4 8-bit) — the default below — but the
   *  e2e harness lacks a 4:4:4 *encoder* in current Chromium
   *  WebCodecs, so it overrides with VP9 profile 0 (vp09.00.10.08,
   *  4:2:0) just to exercise the wire+DC+decoder mechanics. */
  codec?: string
  /** 2026-07-24 decode-stall A/B — optional `VideoDecoder.hardwareAcceleration`
   *  override from the composable (localStorage `roomler-rc-decode-pref`).
   *  Unset → `'no-preference'`, today's behaviour. */
  decodePref?: 'prefer-software' | 'prefer-hardware' | 'no-preference'
  /** P1 — 2D-context A/B mode (localStorage `roomler-rc-ctx-mode`).
   *  Remembered across the idempotent visible-canvas re-init (which omits
   *  it), so the swapped-in canvas keeps the same context options. */
  ctxMode?: string
  /** P1 — restore the legacy per-decoded-frame `frame-decoded` postMessage
   *  (localStorage `roomler-rc-per-frame-msg`). Default OFF: it was ~60
   *  structured-clone messages + 60 Vue reactive increments per second of
   *  pure main-thread overhead; the 1 s `stats` message carries
   *  `framesDecodedTotal` instead. */
  perFrameMsg?: boolean
  /** P6 — backlog-drop threshold override (localStorage
   *  `roomler-rc-max-queue`). Sticks across the idempotent visible-canvas
   *  re-init (which omits it), like `ctxMode`. */
  maxQueue?: number
  /** P7 — FSR sharpening mode (localStorage `roomler-rc-sharpen`).
   *  Sticks across the idempotent visible-canvas re-init, like `ctxMode`. */
  sharpen?: string
  /** P7 — RCAS sharpness stops (localStorage `roomler-rc-fsr-sharpness`). */
  sharpness?: number
}
type ChunkMessage = {
  type: 'chunk'
  bytes: ArrayBuffer
  /** P1 — main-thread epoch timestamp (timeOrigin + now) stamped at the DC
   *  `onmessage` → measures the main→worker forwarding hop. */
  sentAt?: number
}
/** P7 — the canvas element's CSS box + devicePixelRatio (composable
 *  ResizeObserver). Drives the FSR sizing policy; until the first report
 *  the worker stays on the 1:1 blit path. */
type ViewportMessage = { type: 'viewport'; cssW: number; cssH: number; dpr: number }
/** P7 — live sharpen-mode/sharpness change from the settings UI. */
type RenderModeMessage = { type: 'render-mode'; sharpen?: string; sharpness?: number }
/** FR-1 P7 — agent-clock offset from the main thread's rc:clock probe. */
type ClockOffsetMessage = { type: 'clock-offset'; offsetUs: number | null }
/** FR-16 L4 — the main thread just sent bench probe `seq`. */
type BenchArmMessage = { type: 'bench-arm'; seq: number }
type CloseMessage = { type: 'close' }
type IncomingMessage =
  | InitCanvasMessage
  | ChunkMessage
  | ViewportMessage
  | RenderModeMessage
  | ClockOffsetMessage
  | BenchArmMessage
  | CloseMessage

const HEADER_BYTES = 13
const FLAG_KEYFRAME = 0x01
/** Default codec — VP9 profile 1 (4:4:4 8-bit). Browsers' WebCodecs
 *  decoders use libvpx and accept this without quibble. Tests can
 *  override via the `codec` field on `init-canvas`. */
const DEFAULT_VP9_CODEC = 'vp09.01.10.08'
let activeCodec: string = DEFAULT_VP9_CODEC

const workerScope = self as unknown as {
  onmessage: ((ev: MessageEvent<IncomingMessage>) => void) | null
  postMessage: (msg: unknown) => void
}

/** FR-16 L4 — reads the bench probe off painted frames, only while armed. */
const bench = createBenchSampler({ post: (m) => workerScope.postMessage(m), now: epochNowMs })

let canvas: OffscreenCanvas | null = null
let ctx: OffscreenCanvasRenderingContext2D | null = null
let decoder: VideoDecoder | null = null
let configured = false
let framesDecoded = 0
let framesReceived = 0
// rc.103 — leading-delta gate, mirrored from rc-hevc-worker. The
// VideoDecoder rejects a delta as its FIRST input ("A key frame is
// required after configure() or flush()"). The libvpx pump that feeds
// this worker is synchronous (the first emitted packet is already the
// IDR) so the gate normally passes immediately — but the FFmpeg vp9_qsv
// path is async (pipeline depth) and can drain a buffered delta ahead of
// the DC-open IDR, exactly like the HEVC failure on WINHOST-G. Drop
// leading deltas until the first keyframe so neither feeder can wedge the
// decode path into a permanent <video> fallback.
let sawKeyframe = false
let framesSkippedAwaitingKey = 0

// rc.130 — decode-backlog shed (see the HEVC worker for the rationale). Drop
// deltas + ask the agent for a resync IDR when the decoder's input queue
// grows, so a sustained decode deficit can't make latency grow without bound.
// rc.188 — raised 2→4: the agent now caps send-fps to this viewer's reported
// sustainable rate (`rc:decodestat`), so in steady state the queue sits at ~0.
// The higher ceiling only matters transiently — it lets an onset burst (the
// first ~1 s of a window-drag, before the agent's cap engages) ride through
// WITHOUT the destructive drop+IDR-storm that used to freeze the screen. The
// composable's `struggling` rule trips at a lower queue depth, so the cap
// reacts before we ever reach this drop threshold.
// P6 — init-canvas-configurable (localStorage `roomler-rc-max-queue`) for the
// flow-control field-tuning round; default unchanged.
let maxDecodeQueue = DEFAULT_MAX_DECODE_QUEUE
let framesDroppedBacklog = 0
let lastKeyframeReqMs = 0

/** Debounced keyframe-resync request after a backlog drop. */
function requestKeyframeResync(): void {
  const now = typeof performance !== 'undefined' ? performance.now() : Date.now()
  if (now - lastKeyframeReqMs < 250) return
  lastKeyframeReqMs = now
  workerScope.postMessage({ type: 'request-keyframe' })
}

// 2026-07-24 decode-stall telemetry — field: DEVBOX viewing WINHOST-A hits 3-5 s
// mid-session stalls where bytes keep ARRIVING (Mbps > 0) but the decoder
// produces NO output, then a catch-up burst (queued frames flushing) — on
// both HEVC and VP9, with the agent proven healthy. That shape points at the
// decoder/GPU-process layer, not transport and not the resync gate. Track the
// output-callback cadence: if chunks keep landing while output has been
// silent > STALL_GAP_MS with work queued, report a one-shot `decode-stall`
// (and `decode-stall-recovered` with the true gap once output resumes) so the
// console pins the layer during field repros.
const STALL_GAP_MS = 1500
let decodePref: 'prefer-software' | 'prefer-hardware' | 'no-preference' = 'no-preference'
let lastOutputMs = 0
let stallSince = 0 // 0 = no active stall; else the lastOutputMs the stall started from

function noteChunkForStallCheck(): void {
  if (!configured || framesDecoded === 0 || stallSince !== 0 || lastOutputMs === 0) return
  const now = performance.now()
  // 2026-07-24 round 3 — fire even with an EMPTY queue: during a gate wedge
  // the deltas are dropped before decode() so the queue sits at 0, and the
  // original queue>0 requirement made the detector silent for exactly the
  // freeze it was built to catch (field: round-1 freezes with zero console
  // output). `gated` says whether the keyframe gate was armed at the time.
  if (now - lastOutputMs > STALL_GAP_MS) {
    stallSince = lastOutputMs
    workerScope.postMessage({
      type: 'decode-stall',
      gapMs: Math.round(now - lastOutputMs),
      queue: decoder?.decodeQueueSize ?? 0,
      gated: !sawKeyframe,
    })
  }
}

function noteOutputForStallCheck(): void {
  const now = performance.now()
  // P1 — max inter-output gap per stats window (sub-stall stutter that the
  // 1500 ms stall detector never sees).
  if (lastOutputMs > 0) {
    const gap = now - lastOutputMs
    if (gap > outGapMaxMs) outGapMaxMs = gap
  }
  if (stallSince !== 0) {
    workerScope.postMessage({
      type: 'decode-stall-recovered',
      gapMs: Math.round(now - stallSince),
    })
    stallSince = 0
  }
  lastOutputMs = now
}

/** Rolling-window stats for the HUD. Computed in the worker so the
 *  main thread doesn't need to touch the DC traffic. Bitrate is
 *  delivered-bytes/sec at the SCTP-receive boundary (post-network,
 *  pre-decode). Latest VideoFrame dims are captured in the decoder's
 *  output callback. */
let statsBytesInWindow = 0
let statsBytesTotal = 0
let statsFramesInWindow = 0
let statsLastWidth = 0
let statsLastHeight = 0
// rc.187 — last frame dims we reported to the composable. Re-posted whenever
// the decoded size changes (the agent's viewer-adaptive resolution downscales
// mid-session), so the cursor mapping's `mediaIntrinsic` never goes stale.
let lastPostedW = 0
let lastPostedH = 0
let statsLastEmitMs: number = (typeof performance !== 'undefined' ? performance.now() : Date.now())
const STATS_EMIT_INTERVAL_MS = 1000

// P1 — per-hop instrumentation (see rc-hop-stats.ts). Folded into the 1 s
// stats message; zero extra message cadence.
let ctxMode: CtxMode = 'opaque-desync'
let perFrameMsg = false
const paintStats = new HopStats()
const fwdStats = new HopStats()
const decodeStats = new HopStats()
// FR-1 P7 — end-to-end age. The offset arrives from the main thread's
// rc:clock probe; until the first echo it stays null and the stats
// message reports `age: null` (HUD shows nothing rather than garbage).
const ageStats = new HopStats()
// FR-59 P3 — how much the transit queue grew this window. Needs NO clock
// probe (it is a difference of intervals), so unlike `ageStats` it keeps
// reporting on exactly the links where the probe is biased or absent.
const queueDrift = new QueueDrift()
let clockOffsetUs: number | null = null
let outGapMaxMs = 0
// Decode-submission timestamps keyed by chunk timestamp, matched in the
// output callback → submit→output latency. Entries are deleted on match;
// cleared wholesale if drops/gating ever let it grow past 240.
const pendingDecodeAt = new Map<number, number>()
// FR-70 M0 — the age SPLIT (mirrors rc-hevc-worker): the age at ARRIVAL of
// the frame's last chunk (agent clock via the probe) and the local
// arrival→paint time. The agent subtracts the rest.
const arrivalStats = new HopStats()
const viewerStats = new HopStats()
const pendingArrivalUs = new Map<number, number>()

// P7 — FSR sharpening state (mirrors rc-hevc-worker; see rc-fsr-render.ts).
const MAX_FSR_REBUILDS = 3
let sharpenMode: SharpenMode = 'auto'
let sharpness = DEFAULT_RCAS_SHARPNESS
let viewport: { cssW: number; cssH: number; dpr: number } | null = null
let fsr: FsrRenderer | null = null
let fsrUnavailable = false
let fsrRebuilds = 0
let lastRenderPass: RenderPass = 'blit'

function reportFsrFallback(reason: string): void {
  fsrUnavailable = true
  fsr?.dispose()
  fsr = null
  workerScope.postMessage({ type: 'render-fallback', reason })
}

function maybeEmitStats(): void {
  const now = (typeof performance !== 'undefined' ? performance.now() : Date.now())
  const elapsed = now - statsLastEmitMs
  if (elapsed < STATS_EMIT_INTERVAL_MS) return
  const elapsedSec = elapsed / 1000
  const bitrateBps = Math.round((statsBytesInWindow * 8) / elapsedSec)
  const fps = Math.round(statsFramesInWindow / elapsedSec)
  workerScope.postMessage({
    type: 'stats',
    bitrateBps,
    fps,
    width: statsLastWidth,
    height: statsLastHeight,
    framesDecodedTotal: framesDecoded,
    bytesReceivedTotal: statsBytesTotal,
    decodeQueueSize: decoder?.decodeQueueSize ?? 0,
    framesDroppedBacklog,
    // FR-17 - the framing counters, surfaced rather than left
    // internal: a rising `chunkStragglers` with steady fps is the
    // unordered transport WORKING (late chunks discarded without
    // harming the frames after them), while a rising `chunkGaps`
    // is real loss costing an IDR each. Told apart only if both
    // are readable - FR-18 shipped a counter nothing read and its
    // acceptance criterion became unmeasurable.
    chunkGaps: framingState.gaps,
    chunkStragglers: framingState.stragglers,
    paint: paintStats.snapshotAndReset(),
    // FR-1 P7 — end-to-end frame age; null until the clock probe lands.
    age: clockOffsetUs !== null ? ageStats.snapshotAndReset() : null,
    // FR-70 M0 — the split (see the hevc worker).
    arrival: clockOffsetUs !== null ? arrivalStats.snapshotAndReset() : null,
    viewer: viewerStats.snapshotAndReset(),
    // FR-59 P3 — window queue growth in ms (null = fewer than two frames
    // arrived, which is no-signal rather than a stable queue).
    queueMs: queueDrift.snapshotAndReset(),
    fwd: fwdStats.snapshotAndReset(),
    decode: decodeStats.snapshotAndReset(),
    outGapMaxMs: round1(outGapMaxMs),
    ctxMode,
    // P7 — the active render path + actual backing size, for the stats
    // pill ("· FSR") and the diag HUD (`fsr@2048x1280`).
    render: lastRenderPass === 'easu-rcas' ? 'fsr' : lastRenderPass === 'rcas' ? 'rcas' : '2d',
    renderW: canvas?.width ?? 0,
    renderH: canvas?.height ?? 0,
  })
  outGapMaxMs = 0
  statsBytesInWindow = 0
  statsFramesInWindow = 0
  statsLastEmitMs = now
}

/** Frame assembler state — rolling buffer plus the size we're trying
 *  to fill on the current frame. Fragments concatenate until
 *  `pendingPayloadSize` is satisfied; then we emit the chunk. */
const assembler = {
  // Pending header bytes (until we have all 13)
  headerBuf: new Uint8Array(HEADER_BYTES),
  headerHave: 0,
  // Once header is parsed, we know the payload size and start
  // accumulating into payloadBuf.
  payloadBuf: null as Uint8Array | null,
  payloadHave: 0,
  pendingPayloadSize: 0,
  pendingFlags: 0,
  pendingTimestampUs: 0n,
}

/** FR-17 — reset the byte assembler after a chunk gap. Its header/size
 *  state describes a frame that can no longer be completed, so leaving it
 *  in place would make the next good chunk 0 look like payload. */
function resetAssembler(): void {
  assembler.headerHave = 0
  assembler.payloadBuf = null
  assembler.payloadHave = 0
}

/** FR-17 — per-session, set by `init-canvas`. Default false so an agent
 *  that never advertised `chunk-framing` (or a viewer that didn't ask)
 *  keeps the pre-FR-17 bare byte stream exactly. */
let chunkFraming = false
const framingState = createChunkFraming()

workerScope.onmessage = (e) => {
  const msg = e.data
  if (!msg) return
  if (msg.type === 'init-canvas') {
    if (typeof msg.chunkFraming === 'boolean') chunkFraming = msg.chunkFraming
    canvas = msg.canvas
    // P1 — ctx mode sticks across the idempotent visible-canvas re-init
    // (the watcher's second init-canvas omits it).
    if (msg.ctxMode !== undefined) ctxMode = normalizeCtxMode(msg.ctxMode)
    if (typeof msg.perFrameMsg === 'boolean') perFrameMsg = msg.perFrameMsg
    if (msg.maxQueue !== undefined) {
      maxDecodeQueue = normalizeIntKnob(msg.maxQueue, DEFAULT_MAX_DECODE_QUEUE, 1, 60)
    }
    // P7 — FSR knobs stick across the idempotent visible re-init like ctxMode.
    if (msg.sharpen !== undefined) sharpenMode = normalizeSharpenMode(msg.sharpen)
    if (msg.sharpness !== undefined) sharpness = normalizeSharpness(msg.sharpness)
    if (typeof msg.bench === 'boolean') bench.setEnabled(msg.bench)
    ctx = canvas.getContext('2d', ctxOptionsFor(ctxMode))
    if (typeof msg.codec === 'string' && msg.codec.length > 0) {
      activeCodec = msg.codec
    }
    if (
      msg.decodePref === 'prefer-software'
      || msg.decodePref === 'prefer-hardware'
      || msg.decodePref === 'no-preference'
    ) {
      decodePref = msg.decodePref
    }
    initDecoder()
  } else if (msg.type === 'viewport') {
    // P7 — cache the element box; the sizing policy runs per paint.
    viewport = { cssW: msg.cssW, cssH: msg.cssH, dpr: msg.dpr }
  } else if (msg.type === 'clock-offset') {
    clockOffsetUs = typeof msg.offsetUs === 'number' ? msg.offsetUs : null
  } else if (msg.type === 'bench-arm') {
    bench.arm(msg.seq)
  } else if (msg.type === 'render-mode') {
    if (msg.sharpen !== undefined) sharpenMode = normalizeSharpenMode(msg.sharpen)
    if (msg.sharpness !== undefined) sharpness = normalizeSharpness(msg.sharpness)
  } else if (msg.type === 'chunk') {
    framesReceived++
    if (typeof msg.sentAt === 'number') fwdStats.add(epochNowMs() - msg.sentAt)
    const u8 = new Uint8Array(msg.bytes)
    statsBytesInWindow += u8.byteLength
    statsBytesTotal += u8.byteLength
    noteChunkForStallCheck()
    // FR-17 — when the session negotiated framing, every message carries
    // an 8-byte prefix and a gap in it means the frame under assembly can
    // never complete. Feeding its surviving chunks to `consumeBytes`
    // would splice two frames into one bitstream, which the decoder
    // reports as corruption rather than loss, so the assembler is reset
    // and a fresh IDR requested instead.
    if (chunkFraming) {
      const { payload, gap } = stripChunkPrefix(framingState, u8)
      if (gap) {
        resetAssembler()
        workerScope.postMessage({
          type: 'frame-rejected',
          reason: 'chunk-gap',
          gaps: framingState.gaps,
        })
        requestKeyframeResync()
      }
      if (payload) consumeBytes(payload)
    } else {
      consumeBytes(u8)
    }
    maybeEmitStats()
  } else if (msg.type === 'close') {
    teardown()
  }
}

function initDecoder() {
  if (decoder) return
  decoder = new VideoDecoder({
    output: (frame) => {
      framesDecoded++
      statsFramesInWindow++
      noteOutputForStallCheck()
      // P1 — submit→output latency (queue + decoder time).
      const submittedAt = pendingDecodeAt.get(frame.timestamp)
      if (submittedAt !== undefined) {
        decodeStats.add(performance.now() - submittedAt)
        pendingDecodeAt.delete(frame.timestamp)
      }
      // Snapshot dims BEFORE paintFrame — it calls frame.close() in a
      // finally block, after which displayWidth/displayHeight return 0.
      const w = frame.displayWidth
      const h = frame.displayHeight
      statsLastWidth = w
      statsLastHeight = h
      // FR-1 P7 — capture the wire timestamp BEFORE paintFrame closes the
      // frame (a closed VideoFrame reports 0).
      const wireTsUs = frame.timestamp
      // FR-16 L4 — a clone for the probe read, taken before paint closes
      // `frame`; null unless a bench probe is outstanding.
      const benchClone = bench.take(frame)
      const paintT0 = performance.now()
      paintFrame(frame, w, h)
      paintStats.add(performance.now() - paintT0)
      if (benchClone) bench.settle(benchClone, epochNowMs())
      // Age at paint on the agent's clock (mapped via the rc:clock probe).
      const arrivalUs = epochNowUs()
      if (clockOffsetUs !== null) {
        ageStats.add(frameAgeMs(wireTsUs, clockOffsetUs, arrivalUs))
      }
      // FR-70 M0 — the same age at ARRIVAL, and the local arrival→paint time.
      const arrivedUs = pendingArrivalUs.get(wireTsUs)
      if (arrivedUs !== undefined) {
        pendingArrivalUs.delete(wireTsUs)
        if (clockOffsetUs !== null) {
          arrivalStats.add(frameAgeMs(wireTsUs, clockOffsetUs, arrivedUs))
        }
        viewerStats.add((arrivalUs - arrivedUs) / 1000)
      }
      // FR-59 P3 — unconditional: the drift needs no probe lock.
      queueDrift.add(wireTsUs, arrivalUs)
      // rc.187 — report dims on frame 1 AND on every size change (live
      // downscale), so the composable updates the cursor-mapping intrinsic.
      if (w !== lastPostedW || h !== lastPostedH) {
        lastPostedW = w
        lastPostedH = h
        workerScope.postMessage({ type: 'first-frame', width: w, height: h })
      }
      if (perFrameMsg && framesDecoded > 1) {
        // P1 — legacy per-frame counter message, OFF by default (a pure
        // main-thread tax at 60 fps); the 1 s stats message carries
        // framesDecodedTotal. localStorage roomler-rc-per-frame-msg
        // restores it for A/B.
        workerScope.postMessage({ type: 'frame-decoded', count: framesDecoded })
      }
      // Emit on every output too so dims update promptly during
      // resolution changes (rc:resolution / DPI flip / monitor swap).
      maybeEmitStats()
    },
    error: (err) => {
      workerScope.postMessage({
        type: 'decoder-error',
        error: extractErrorMessage(err),
      })
    },
  })
  // Configure now; the default `vp09.01.10.08` is unconditionally
  // supported by WebCodecs in Chromium-based browsers (libvpx ships
  // in-tree). If a future Chrome deprecates profile 1 we'll see the
  // rejection in the error callback. Tests may override via
  // `init-canvas.codec`.
  try {
    decoder.configure({
      codec: activeCodec,
      optimizeForLatency: true,
      // Hardware-decode preference. Profile-1 (4:4:4) HW decode is
      // rare — Intel Tiger Lake+, some AMD; NVDEC and Intel UHD 630
      // don't expose it. `'prefer-hardware'` was tried (added in
      // aac736b) on the theory Chromium would silently fall back to
      // SW decode on GPUs without 4:4:4 support — but on Chrome 148
      // it does NOT: `configure()` accepts the hint, then the first
      // real frame hard-rejects with "Unsupported configuration",
      // the decoder closes, and the canvas goes black (field repro
      // 2026-05-21, RTX 5090 + UHD 630). `'no-preference'` lets
      // Chromium pick HW decode where it genuinely exists and SW
      // otherwise — the actual silent-fallback behaviour we want.
      // 2026-07-24 — `decodePref` (localStorage A/B) can override to
      // prefer-software/-hardware for the decode-stall field diagnosis;
      // defaults to 'no-preference' (unchanged behaviour).
      hardwareAcceleration: decodePref,
    } as VideoDecoderConfig)
    configured = true
    workerScope.postMessage({
      type: 'decoder-configured',
      codec: activeCodec,
      pref: decodePref,
    })
  } catch (err) {
    workerScope.postMessage({
      type: 'decoder-configure-error',
      codec: activeCodec,
      error: extractErrorMessage(err),
    })
  }
}

function consumeBytes(bytes: Uint8Array): void {
  let cursor = 0
  while (cursor < bytes.length) {
    if (assembler.payloadBuf === null) {
      // Still collecting the 13-byte header.
      const need = HEADER_BYTES - assembler.headerHave
      const take = Math.min(need, bytes.length - cursor)
      assembler.headerBuf.set(
        bytes.subarray(cursor, cursor + take),
        assembler.headerHave,
      )
      assembler.headerHave += take
      cursor += take
      if (assembler.headerHave === HEADER_BYTES) {
        // Header complete — parse it.
        const view = new DataView(
          assembler.headerBuf.buffer,
          assembler.headerBuf.byteOffset,
          HEADER_BYTES,
        )
        const size = view.getUint32(0, true /* little-endian */)
        const flags = view.getUint8(4)
        const ts_lo = view.getUint32(5, true)
        const ts_hi = view.getUint32(9, true)
        const ts_us = (BigInt(ts_hi) << 32n) | BigInt(ts_lo)
        if (size === 0 || size > 16 * 1024 * 1024) {
          // Out-of-spec; drop and resync. 16 MB cap is generous —
          // a 4K I444 keyframe at very high bitrate is ~6 MB.
          workerScope.postMessage({
            type: 'frame-rejected',
            reason: 'implausible-size',
            size,
          })
          assembler.headerHave = 0
          continue
        }
        assembler.payloadBuf = new Uint8Array(size)
        assembler.payloadHave = 0
        assembler.pendingPayloadSize = size
        assembler.pendingFlags = flags
        assembler.pendingTimestampUs = ts_us
      }
    } else {
      // Filling payload.
      const need = assembler.pendingPayloadSize - assembler.payloadHave
      const take = Math.min(need, bytes.length - cursor)
      assembler.payloadBuf.set(
        bytes.subarray(cursor, cursor + take),
        assembler.payloadHave,
      )
      assembler.payloadHave += take
      cursor += take
      if (assembler.payloadHave === assembler.pendingPayloadSize) {
        emitFrame()
        // Reset for the next frame.
        assembler.headerHave = 0
        assembler.payloadBuf = null
        assembler.payloadHave = 0
      }
    }
  }
}

function emitFrame(): void {
  if (!decoder || !configured) return
  const payload = assembler.payloadBuf
  if (!payload) return
  const isKey = (assembler.pendingFlags & FLAG_KEYFRAME) !== 0
  // rc.103 — gate on the first keyframe (see `sawKeyframe` note above).
  if (!shouldDecodeFrame(sawKeyframe, isKey)) {
    framesSkippedAwaitingKey++
    // 2026-07-24 freeze fix — keep re-requesting the resync IDR while gated
    // (mirrors the HEVC worker; see its comment for the full field story).
    // The backlog branch fires the request once then re-arms the gate; a lost
    // request or a far-away GOP boundary left the decoder wedged on a stale
    // frame. Debounced + agent-clamped to ~4 req/s.
    requestKeyframeResync()
    if (framesSkippedAwaitingKey === 1 || framesSkippedAwaitingKey % 60 === 0) {
      workerScope.postMessage({
        type: 'awaiting-keyframe',
        dropped: framesSkippedAwaitingKey,
      })
    }
    return
  }
  if (isKey && !sawKeyframe) {
    sawKeyframe = true
    workerScope.postMessage({
      type: 'keyframe-acquired',
      droppedBefore: framesSkippedAwaitingKey,
    })
  }
  // rc.130 — backlog shed. Drop this delta + re-arm the keyframe gate (so we
  // keep dropping deltas, which would otherwise decode-error against the
  // missing reference) until the resync IDR lands.
  if (!isKey && decoder.decodeQueueSize > maxDecodeQueue) {
    framesDroppedBacklog++
    sawKeyframe = false
    requestKeyframeResync()
    if (framesDroppedBacklog === 1 || framesDroppedBacklog % 60 === 0) {
      workerScope.postMessage({
        type: 'backlog-drop',
        dropped: framesDroppedBacklog,
        queue: decoder.decodeQueueSize,
      })
    }
    return
  }
  // EncodedVideoChunk.timestamp is a microsecond integer per spec.
  // We pass the agent-side capture timestamp through unmodified —
  // VideoDecoder uses it for ordering / frame.timestamp passthrough.
  const ts = Number(assembler.pendingTimestampUs)
  try {
    const chunk = new EncodedVideoChunk({
      type: isKey ? 'key' : 'delta',
      timestamp: ts,
      data: payload,
    })
    // P1 — record the submission time for the submit→output hop. Bounded:
    // matched entries delete themselves; a decoder that never outputs
    // (gate/drop churn) can't grow the map past 240.
    if (pendingDecodeAt.size > 240) pendingDecodeAt.clear()
    pendingDecodeAt.set(ts, performance.now())
    // FR-70 M0 — and the frame's arrival (its last chunk is in hand here).
    if (pendingArrivalUs.size > 240) pendingArrivalUs.clear()
    pendingArrivalUs.set(ts, epochNowUs())
    decoder.decode(chunk)
  } catch (err) {
    workerScope.postMessage({
      type: 'decode-error',
      error: extractErrorMessage(err),
    })
  }
}

function paintFrame(frame: VideoFrame, w: number, h: number): void {
  if (!canvas || !ctx) {
    frame.close()
    return
  }
  try {
    // P7 — FSR sharpening upscale (mirrors rc-hevc-worker; see
    // rc-fsr-render.ts). `blit` is the pre-P7 path, byte-identical; any GL
    // failure falls back to it the SAME frame.
    const target = computeRenderTarget(
      w,
      h,
      viewport?.cssW ?? 0,
      viewport?.cssH ?? 0,
      viewport?.dpr ?? 1,
      fsrUnavailable ? 'off' : sharpenMode,
    )
    let painted = false
    if (target.pass !== 'blit') {
      if (!fsr && !fsrUnavailable) {
        fsr = FsrRenderer.create()
        if (!fsr) reportFsrFallback('webgl2-unavailable')
      }
      if (fsr) {
        const src = fsr.render(frame, w, h, target.w, target.h, target.pass, sharpness)
        if (src) {
          if (canvas.width !== target.w) canvas.width = target.w
          if (canvas.height !== target.h) canvas.height = target.h
          ctx.drawImage(src, 0, 0, target.w, target.h)
          lastRenderPass = target.pass
          painted = true
        } else {
          fsr.dispose()
          fsr = null
          fsrRebuilds++
          if (fsrRebuilds > MAX_FSR_REBUILDS) reportFsrFallback('gl-context-lost')
        }
      }
    }
    if (!painted) {
      if (canvas.width !== w) canvas.width = w
      if (canvas.height !== h) canvas.height = h
      ctx.drawImage(frame, 0, 0)
      lastRenderPass = 'blit'
    }
  } catch {
    /* canvas lost mid-teardown */
  } finally {
    frame.close()
  }
}

function teardown(): void {
  try {
    decoder?.close()
  } catch {
    /* idempotent */
  }
  decoder = null
  configured = false
  canvas = null
  ctx = null
  framesDecoded = 0
  framesReceived = 0
  lastPostedW = 0
  lastPostedH = 0
  // rc.103 — re-arm the leading-delta gate for the next decoder.
  sawKeyframe = false
  framesSkippedAwaitingKey = 0
  framesDroppedBacklog = 0
  // P1 — drop the hop-instrumentation state with the session.
  pendingDecodeAt.clear()
  pendingArrivalUs.clear()
  paintStats.snapshotAndReset()
  fwdStats.snapshotAndReset()
  decodeStats.snapshotAndReset()
  ageStats.snapshotAndReset()
  arrivalStats.snapshotAndReset()
  viewerStats.snapshotAndReset()
  queueDrift.snapshotAndReset()
  queueDrift.reset()
  clockOffsetUs = null
  outGapMaxMs = 0
  // P7 — release the GL renderer; a fresh session re-creates lazily.
  fsr?.dispose()
  fsr = null
  fsrUnavailable = false
  fsrRebuilds = 0
  lastRenderPass = 'blit'
  viewport = null
  assembler.headerHave = 0
  assembler.payloadBuf = null
  assembler.payloadHave = 0
}

function extractErrorMessage(err: unknown): string {
  if (err instanceof Error) return err.message
  try {
    return String(err)
  } catch {
    return 'unknown'
  }
}

/** Exported for vitest — pure function that parses the 13-byte
 *  frame header. Lets the wire format stay regression-tested
 *  without standing up a full WebCodecs harness. */
export function parseFrameHeader(buf: Uint8Array): {
  payloadSize: number
  flags: number
  timestampUs: bigint
} | null {
  if (buf.length < HEADER_BYTES) return null
  const view = new DataView(buf.buffer, buf.byteOffset, HEADER_BYTES)
  const size = view.getUint32(0, true)
  const flags = view.getUint8(4)
  const ts_lo = view.getUint32(5, true)
  const ts_hi = view.getUint32(9, true)
  const ts_us = (BigInt(ts_hi) << 32n) | BigInt(ts_lo)
  return { payloadSize: size, flags, timestampUs: ts_us }
}

export function isKeyframe(flags: number): boolean {
  return (flags & FLAG_KEYFRAME) !== 0
}

/** rc.103 — leading-delta gate decision, pure for vitest. A delta is only
 *  decodable once a keyframe has been seen; a keyframe is always decodable.
 *  Mirrors rc-hevc-worker so the wire-level invariant is shared. */
export function shouldDecodeFrame(hasSeenKeyframe: boolean, isKey: boolean): boolean {
  return hasSeenKeyframe || isKey
}
