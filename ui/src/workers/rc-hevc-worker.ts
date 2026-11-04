// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/// <reference lib="webworker" />

/**
 * rc.78 — HEVC decoder worker for the Option B HEVC-over-DataChannel
 * transport. Sibling to `rc-vp9-444-worker.ts`; same wire format, same
 * 13-byte length-prefix header, same `OffscreenCanvas` paint path.
 * Only difference: codec string is `hev1.1.6.L153.B0` (HEVC Main
 * profile, Level 5.1, no decoder description). The pre-flight WebCodecs
 * spike (2026-05-26) confirmed Chrome + Edge accept Annex-B no-
 * description HEVC at L3.1; rc.94 bumped the level to 5.1 because the
 * field SystemContext host captures 1920×1200, which exceeds L3.1's
 * ~1280×720 ceiling and rendered black (see DEFAULT_HEVC_CODEC note).
 *
 * Source agent: `agents/meshharbord/src/encode/ffmpeg/encoder.rs`
 * via `peer.rs::media_pump_hevc_dc`. Cascade: hevc_nvenc → hevc_qsv
 * → hevc_amf. Gate 0 smoke (2026-05-29) validated both NVENC on RTX
 * 5090 Blackwell AND QSV on Iris Xe Tiger Lake — the two MF-broken
 * platforms the entire Option B plan was built to bypass.
 *
 * Wire format (matches `frame_video_bytes` in agent peer.rs:1502):
 *
 *   struct Frame {
 *     u32  size_le;          // payload length, little-endian
 *     u8   flags;            // bit 0: keyframe
 *     u64  timestamp_us;     // monotonic capture timestamp
 *     [u8] payload;          // HEVC Annex-B (4-byte start codes,
 *                            // AUD → VPS → SPS → PPS → IDR on keyframes)
 *   }
 *
 * Header is 13 bytes. SCTP is reliable+ordered so a single frame may
 * arrive across multiple `onmessage` chunks; the assembler in this
 * worker concatenates by tracking how many bytes of the declared
 * payload size remain.
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
  /** FR-17 — true when the controller negotiated per-chunk framing for
   *  this session (the agent advertised `chunk-framing` in
   *  `AgentCaps.video`). Absent/false keeps the pre-FR-17 bare byte
   *  stream, which is what every agent below 0.4.14 still sends. */
  chunkFraming?: boolean
  /** Optional codec override. Default is HEVC Main profile, L3.1
   *  (1080p) which covers Gate 0's test resolutions. Bump to
   *  `hev1.1.6.L120.90` (L4.0) for 4K or `hev1.1.6.L150.90` (L5.0)
   *  for 4K60. Tests may override. */
  codec?: string
  /** 2026-07-24 decode-stall A/B — optional `VideoDecoder.hardwareAcceleration`
   *  override from the composable (localStorage `meshharbor-rc-decode-pref`).
   *  Unset → `'no-preference'`, today's behaviour. */
  decodePref?: 'prefer-software' | 'prefer-hardware' | 'no-preference'
  /** P1 — 2D-context A/B mode (localStorage `meshharbor-rc-ctx-mode`).
   *  Remembered across the idempotent visible-canvas re-init. */
  ctxMode?: string
  /** P1 — restore the legacy per-decoded-frame `frame-decoded` postMessage
   *  (localStorage `meshharbor-rc-per-frame-msg`). Default OFF — see the
   *  vp9-444 worker's comment. */
  perFrameMsg?: boolean
  /** P6 — backlog-drop threshold override (localStorage
   *  `meshharbor-rc-max-queue`). Sticks across the idempotent visible-canvas
   *  re-init (which omits it), like `ctxMode`. */
  maxQueue?: number
  /** P7 — FSR sharpening mode (localStorage `meshharbor-rc-sharpen`).
   *  Sticks across the idempotent visible-canvas re-init, like `ctxMode`. */
  sharpen?: string
  /** P7 — RCAS sharpness stops (localStorage `meshharbor-rc-fsr-sharpness`). */
  sharpness?: number
  /** FR-16 L4 — bench mode: sample the probe marker while a probe is armed.
   *  Set only when the knob is on AND the agent advertised `bench`; sticks
   *  across the idempotent visible-canvas re-init, like `ctxMode`. */
  bench?: boolean
}
type ChunkMessage = {
  type: 'chunk'
  bytes: ArrayBuffer
  /** P1 — main-thread epoch timestamp for the main→worker forwarding hop. */
  sentAt?: number
}
/** P7 — the canvas element's CSS box + devicePixelRatio, reported by the
 *  composable's ResizeObserver. Drives the FSR backing-store sizing policy;
 *  until the first report the worker stays on the 1:1 blit path. */
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
/** Default codec — HEVC Main, Level **5.1**, no decoder description.
 *  rc.94 — bumped from L3.1 (`L93`). L3.1 maxes at 983,040 luma
 *  samples (~1280×720); the field SystemContext host (WINHOST-E)
 *  captures 1920×1200 = 2,304,000 samples, which exceeds even L4.1
 *  (2,228,224) — so Chromium's HW HEVC decoder rejected the stream
 *  and rendered a BLACK screen. The pre-flight spike only validated a
 *  low-res sample at L3.1, so it never caught this. L5.1 (`L153`,
 *  8,912,896 samples, up to 4K@64) covers every realistic desktop
 *  resolution and is HW-decodable on Iris Xe / RTX 5090 (the Gate 0
 *  hosts). The codec-string level is a declared MAX; a smaller stream
 *  decodes fine under it. Tests can override via the `codec` field on
 *  `init-canvas`. */
const DEFAULT_HEVC_CODEC = 'hev1.1.6.L153.B0'
let activeCodec: string = DEFAULT_HEVC_CODEC

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
// rc.103 — leading-delta gate. The HW HEVC decoder rejects a delta as
// its FIRST input after configure()/flush() ("A key frame is required").
// The agent's FFmpeg QSV/NVENC encoder is ASYNC (pipeline depth): at the
// instant the DC reaches Open, the packet draining is a buffered delta
// from earlier in the encoder queue — it ships ahead of the freshly-forced
// IDR (rc.97 force-kf-on-open), so the browser's first ASSEMBLED frame is
// sometimes a delta. Field WINHOST-G (hevc_qsv) hit exactly this:
// "hevc DC opened" → "decode-error: A key frame is required" → permanent
// <video> fallback. The libvpx VP9-444 path never hit it because libvpx is
// synchronous (request_keyframe → the very next packet IS the IDR). Drop
// leading deltas until the first keyframe; the IDR is only a handful of
// frames behind them in the async queue, so the wait is a few ms.
let sawKeyframe = false
let framesSkippedAwaitingKey = 0

// rc.130 — decode-backlog shed. With `optimizeForLatency` the decoder keeps
// its input queue at 0–1 when it's keeping up; a sustained queue above this
// means it has fallen behind (slow client / 4K on a weak iGPU / throttled
// background tab) and the stream latency is growing monotonically. When that
// happens we drop incoming DELTAS and ask the agent for a fresh keyframe to
// resync — never dropping a key frame (it's the resync point). Without this
// the queue never drains and "typing appears seconds later" is permanent.
// rc.188 — raised 2→4: the agent now caps send-fps to this viewer's reported
// sustainable rate (`rc:decodestat`), so in steady state the queue sits at ~0.
// The higher ceiling only matters transiently — it lets an onset burst (the
// first ~1 s of a window-drag, before the agent's cap engages) ride through
// WITHOUT the destructive drop+IDR-storm that used to freeze the screen. The
// composable's `struggling` rule trips at a lower queue depth, so the cap
// reacts before we ever reach this drop threshold.
// P6 — init-canvas-configurable (localStorage `meshharbor-rc-max-queue`) for the
// flow-control field-tuning round; default unchanged.
let maxDecodeQueue = DEFAULT_MAX_DECODE_QUEUE
let framesDroppedBacklog = 0
let lastKeyframeReqMs = 0

/** Ask the agent (via the composable → `control` DC) to force an IDR so the
 *  decoder can resync after a backlog drop. Debounced so a sustained deficit
 *  can't spam keyframe requests (the largest frames) onto a congested link. */
function requestKeyframeResync(): void {
  const now = typeof performance !== 'undefined' ? performance.now() : Date.now()
  if (now - lastKeyframeReqMs < 250) return
  lastKeyframeReqMs = now
  workerScope.postMessage({ type: 'request-keyframe' })
}

// 2026-07-24 decode-stall telemetry + A/B (mirrors rc-vp9-444-worker — see
// its comment for the field story): report a one-shot `decode-stall` when
// chunks keep arriving while the decoder has produced no output for
// STALL_GAP_MS with work queued, and `decode-stall-recovered` (true gap) once
// output resumes. `decodePref` is the composable's localStorage A/B override
// for `hardwareAcceleration` (NOTE: HEVC has no SW decoder in Chromium —
// prefer-software here fails configure() and the composable's existing
// fallback path takes over; the A/B is meaningful on the VP9/AV1 workers).
const STALL_GAP_MS = 1500
let decodePref: 'prefer-software' | 'prefer-hardware' | 'no-preference' = 'no-preference'
let lastOutputMs = 0
let stallSince = 0 // 0 = no active stall

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

/** Rolling-window stats for the HUD, matching the VP9-444 worker so
 *  the composable can consume both with the same message shape. */
let statsBytesInWindow = 0
let statsBytesTotal = 0
let statsFramesInWindow = 0
let statsLastWidth = 0
let statsLastHeight = 0
// rc.187 — last frame dims reported to the composable; re-posted on every size
// change (live viewer-adaptive downscale) so the cursor-mapping intrinsic
// tracks the actual resolution instead of freezing on the first frame's size.
let lastPostedW = 0
let lastPostedH = 0
let statsLastEmitMs: number = (typeof performance !== 'undefined' ? performance.now() : Date.now())
const STATS_EMIT_INTERVAL_MS = 1000

// P1 — per-hop instrumentation (see rc-hop-stats.ts + the vp9-444 worker's
// mirror). Folded into the 1 s stats message; zero extra message cadence.
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
const pendingDecodeAt = new Map<number, number>()
// FR-70 M0 — the age SPLIT. `ageStats` fuses sender, transit and viewer
// latency into one number, which is how a 4903 ms relay stall on 2026-09-04
// arrived looking like a pump problem. `arrivalStats` is the age of the
// frame when its LAST CHUNK reached this worker (agent clock via the probe,
// like `ageStats`), and `viewerStats` is the purely local time from that
// arrival to the paint (decode queue + decode + paint) — no probe needed.
// The agent subtracts: viewer = age − arrival, transit = arrival − its own
// send-queue wait. Keyed by the wire timestamp, like `pendingDecodeAt`.
const arrivalStats = new HopStats()
const viewerStats = new HopStats()
const pendingArrivalUs = new Map<number, number>()

// P7 — FSR sharpening state (see rc-fsr-render.ts). The renderer is created
// lazily on the first frame that needs it; a GL failure disposes it and the
// next frame re-creates (bounded by MAX_FSR_REBUILDS, then the session goes
// permanently 2D with a one-shot `render-fallback` breadcrumb). The visible
// canvas stays 2D throughout, so every failure lands on the byte-identical
// legacy path the same frame.
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
    fwd: fwdStats.snapshotAndReset(),
    decode: decodeStats.snapshotAndReset(),
    // FR-1 P7 — end-to-end frame age; null until the clock probe lands.
    age: clockOffsetUs !== null ? ageStats.snapshotAndReset() : null,
    // FR-70 M0 — the split: age at ARRIVAL (same clock mapping as `age`)
    // and the local arrival→paint time.
    arrival: clockOffsetUs !== null ? arrivalStats.snapshotAndReset() : null,
    viewer: viewerStats.snapshotAndReset(),
    // FR-59 P3 — window queue growth in ms (null = fewer than two frames
    // arrived, which is no-signal rather than a stable queue).
    queueMs: queueDrift.snapshotAndReset(),
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

const assembler = {
  headerBuf: new Uint8Array(HEADER_BYTES),
  headerHave: 0,
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
    // P1 — ctx mode sticks across the idempotent visible-canvas re-init.
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
      // rc.100/rc.102 — Chrome's NVDEC HEVC decode mis-reports the picture
      // geometry for our hevc_nvenc stream (field DEVBOX, RTX 5090):
      // the agent encodes a FULL 2560×1600 desktop (proven by the FFmpeg DC
      // pump heartbeat: w=2560 h=1600 enc=hevc_nvenc, ~3 MB/window), but the
      // decoded VideoFrame carries a SPURIOUS conformance window —
      // codedWidth/Height = 2560×1600 yet visibleRect/displayWidth = 1280×720
      // at offset (0,0). `drawImage` honours visibleRect, so we were painting
      // only the top-left region. The coded pixels ARE the whole desktop, so
      // re-wrap the frame with visibleRect = the full coded rect and render
      // THAT. (rc.100 first moved to codedWidth for the reported intrinsic;
      // rc.102 also overrides the crop drawImage honours.)
      //
      // A SMALL top-left crop is NOT that bug, though — it is a legitimate
      // encoder alignment crop, and the rewrap must NOT override it. Field
      // WINHOST-F (hevc_qsv, 1920×1080 — the first non-mod-16-height
      // sender): QSV pads HEVC to its row alignment, coding 1920×1088 with a
      // conformance window hiding 8 rows of pooled-surface junk that changes
      // per frame. Rendering the coded rect painted the junk — a purple/blue
      // band flickering on every arriving frame during window drags. Every
      // earlier QSV host had a mod-16 panel (1200/1600/2160 → no crop), which
      // is why qsv looked "unaffected". `classifyCrop` separates the cases.
      const fallbackW = frame.codedWidth || frame.displayWidth
      const fallbackH = frame.codedHeight || frame.displayHeight
      const vr = frame.visibleRect
      const crop = classifyCrop(frame.codedWidth, frame.codedHeight, vr)
      let render: VideoFrame = frame
      let rewrapped = false
      let renderW = fallbackW
      let renderH = fallbackH
      if (crop === 'spurious') {
        try {
          render = new VideoFrame(frame, {
            visibleRect: { x: 0, y: 0, width: frame.codedWidth, height: frame.codedHeight },
          })
          rewrapped = true
        } catch {
          render = frame // re-wrap rejected → fall back to the cropped frame
        }
      } else if (crop === 'alignment' && vr) {
        // Trust the conformance window: drawImage honours visibleRect
        // natively, so no rewrap — paint (and report) the visible dims.
        renderW = vr.width
        renderH = vr.height
      }
      // Capture the one-shot diagnostic BEFORE paintFrame() calls close()
      // (a closed VideoFrame reports 0/null — rc.100 logged {0,0} this way).
      let firstFrameMsg: Record<string, unknown> | null = null
      // rc.187 — post dims on frame 1 AND whenever the decoded size changes
      // (the agent's viewer-adaptive resolution downscales mid-session), so the
      // composable's cursor mapping never divides by a stale intrinsic.
      if (renderW !== lastPostedW || renderH !== lastPostedH) {
        lastPostedW = renderW
        lastPostedH = renderH
        firstFrameMsg = {
          type: 'first-frame',
          width: renderW,
          height: renderH,
          coded: { w: frame.codedWidth, h: frame.codedHeight },
          display: { w: frame.displayWidth, h: frame.displayHeight },
          visible: vr ? { x: vr.x, y: vr.y, w: vr.width, h: vr.height } : null,
          crop,
          rewrapped,
        }
      }
      statsLastWidth = renderW
      statsLastHeight = renderH
      // FR-1 P7 — capture the wire timestamp BEFORE paint can close the
      // frame; a closed VideoFrame reports 0 (the rc.100 lesson).
      const wireTsUs = frame.timestamp
      // FR-16 L4 — a clone for the probe read, taken before paint closes
      // `render`; null unless a bench probe is outstanding.
      const benchClone = bench.take(render)
      const paintT0 = performance.now()
      paintFrame(render, renderW, renderH)
      paintStats.add(performance.now() - paintT0)
      if (benchClone) bench.settle(benchClone, epochNowMs())
      // Age at paint on the agent's clock (mapped via the rc:clock probe):
      // framing → send queue → network → decode → paint, end to end.
      const arrivalUs = epochNowUs()
      if (clockOffsetUs !== null) {
        ageStats.add(frameAgeMs(wireTsUs, clockOffsetUs, arrivalUs))
      }
      // FR-70 M0 — the same age at the moment the frame ARRIVED, and the
      // local arrival→paint time; see `arrivalStats`.
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
      if (rewrapped) frame.close() // paintFrame closed `render`; close the original too
      if (firstFrameMsg) {
        workerScope.postMessage(firstFrameMsg)
      } else if (perFrameMsg) {
        // P1 — legacy per-frame counter message, OFF by default (see the
        // vp9-444 worker); the 1 s stats message carries framesDecodedTotal.
        workerScope.postMessage({ type: 'frame-decoded', count: framesDecoded })
      }
      maybeEmitStats()
    },
    error: (err) => {
      workerScope.postMessage({
        type: 'decoder-error',
        error: extractErrorMessage(err),
      })
    },
  })
  // Configure. HEVC WebCodecs support is HW-only in Chromium today —
  // there's no in-tree SW HEVC decoder. If the platform's OS HEVC
  // decoder isn't available (Linux Chromium typically, corporate
  // policy disabled, very old hardware), `isConfigSupported` returns
  // false and the composable falls back to VP9-444-DC before this
  // worker is even instantiated. By the time we get here, the
  // platform claimed support — but mid-session HW driver hiccup can
  // still rip the rug; the `error` callback above surfaces it to the
  // main thread for re-negotiation.
  //
  // hardwareAcceleration='no-preference' lets Chromium pick: HW
  // where it exists (Win11 + RTX 5090 / Iris Xe is what Gate 0
  // validated), no fallback otherwise (HEVC HAS no SW fallback in
  // WebCodecs, unlike VP9). Same setting as the VP9-444 worker for
  // consistency.
  try {
    decoder.configure({
      codec: activeCodec,
      optimizeForLatency: true,
      // 2026-07-24 — `decodePref` (localStorage A/B) can override for the
      // decode-stall field diagnosis; defaults to 'no-preference'.
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
      const need = HEADER_BYTES - assembler.headerHave
      const take = Math.min(need, bytes.length - cursor)
      assembler.headerBuf.set(
        bytes.subarray(cursor, cursor + take),
        assembler.headerHave,
      )
      assembler.headerHave += take
      cursor += take
      if (assembler.headerHave === HEADER_BYTES) {
        const view = new DataView(
          assembler.headerBuf.buffer,
          assembler.headerBuf.byteOffset,
          HEADER_BYTES,
        )
        const size = view.getUint32(0, true)
        const flags = view.getUint8(4)
        const ts_lo = view.getUint32(5, true)
        const ts_hi = view.getUint32(9, true)
        const ts_us = (BigInt(ts_hi) << 32n) | BigInt(ts_lo)
        if (size === 0 || size > 16 * 1024 * 1024) {
          // Out-of-spec; drop and resync. 16 MB cap covers 4K HEVC
          // IDRs (typically 0.5-2 MB at our bitrates) with headroom.
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
  // Feeding a leading delta to the HW decoder throws "A key frame is
  // required" and the composable then tears the whole HEVC path down to
  // <video>. Drop deltas until the IDR (right behind them) arrives.
  if (!shouldDecodeFrame(sawKeyframe, isKey)) {
    framesSkippedAwaitingKey++
    // 2026-07-24 freeze fix — keep re-requesting the resync IDR while gated.
    // The backlog branch below fires the request exactly ONCE (it re-arms the
    // gate, so it can never fire again for this wedge); if that single
    // control-DC message was lost — or the natural GOP IDR is far away
    // because the viewer-rate cap shed the encode rate (240-frame GOP at
    // 12 fps = 20 s) or the screen went static (frame-counted GOP never
    // advances) — the decoder sat wedged on a stale frame indefinitely
    // (field: "old screen for 30+ s", DEVBOX viewing WINHOST-A). The 250 ms
    // debounce + the agent's MIN_KF_GAP clamp bound this to ~4 req/s.
    requestKeyframeResync()
    // One-shot + periodic diagnostic so the field log shows the gate
    // engaged (and how many deltas it ate) without flooding.
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
  // rc.130 — backlog shed. If the decoder has fallen behind, drop this delta
  // and re-arm the keyframe gate so we keep dropping deltas (which would
  // otherwise decode-error against the missing reference and tear the path
  // down to <video>) until the resync IDR lands.
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
  const ts = Number(assembler.pendingTimestampUs)
  try {
    const chunk = new EncodedVideoChunk({
      type: isKey ? 'key' : 'delta',
      timestamp: ts,
      data: payload,
    })
    // P1 — record the submission time for the submit→output hop (bounded;
    // see the vp9-444 worker's mirror).
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
    // P7 — FSR sharpening upscale (see rc-fsr-render.ts). The sizing policy
    // is pure and ns-cheap, so it runs per paint: a mid-stream resolution
    // flip (the agent rebuilds on rung changes) or a window resize just
    // yields a different target next frame. `blit` is the pre-P7 path,
    // byte-identical; any GL failure falls back to it the SAME frame.
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
          // Lost/failed GL — dispose so the next frame lazily re-creates a
          // fresh context; after MAX_FSR_REBUILDS the session goes 2D.
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
      // rc.100 — pass the explicit dest rect. The bare `drawImage(frame, 0, 0)`
      // uses the frame's `displayWidth/Height` as its natural size, which is
      // exactly the shrunken value we're routing around on the NVDEC-bug path;
      // an explicit dest of the render size (coded for the rewrapped spurious
      // case, visible for a trusted alignment crop) keeps the output 1:1.
      ctx.drawImage(frame, 0, 0, w, h)
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
  // rc.103 — re-arm the leading-delta gate so a fresh decoder (re-connect
  // / re-negotiation) again waits for an IDR before its first decode().
  sawKeyframe = false
  framesSkippedAwaitingKey = 0
  framesDroppedBacklog = 0
  // P1 — drop the hop-instrumentation state with the session.
  pendingDecodeAt.clear()
  paintStats.snapshotAndReset()
  fwdStats.snapshotAndReset()
  decodeStats.snapshotAndReset()
  ageStats.snapshotAndReset()
  queueDrift.snapshotAndReset()
  queueDrift.reset()
  clockOffsetUs = null
  outGapMaxMs = 0
  // P7 — release the GL renderer; a fresh session re-creates lazily and
  // gets a fresh unavailability verdict (a new tab/GPU state may differ).
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
 *  frame header. Same wire format as the VP9-444 path. */
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

/** rc.103 — leading-delta gate decision, pure for vitest. Returns whether
 *  a frame should be fed to `decoder.decode()`: a delta is only decodable
 *  once a keyframe has already been seen; a keyframe is always decodable.
 *  This is the guard that stops the HW HEVC decoder throwing "A key frame
 *  is required after configure() or flush()" on a leading delta — the
 *  field WINHOST-G hevc_qsv failure (async-encoder DC-open race). */
export function shouldDecodeFrame(hasSeenKeyframe: boolean, isKey: boolean): boolean {
  return hasSeenKeyframe || isKey
}

/** Crop classification for a decoded HEVC frame — pure for vitest.
 *
 *  - `exact`: no conformance window (visibleRect == coded size), or the
 *    frame carries no usable geometry — render as-is.
 *  - `alignment`: a REAL encoder alignment crop — origin (0,0) and less
 *    than one CTU (64 px) smaller than the coded size on BOTH axes. HEVC
 *    encoders pad the picture to their block alignment and crop the excess:
 *    Intel QSV codes a 1920×1080 desktop as 1920×1088 with an 8-row bottom
 *    crop whose padding rows are pooled-surface junk. TRUST it — `drawImage`
 *    honours the visibleRect natively. (Field WINHOST-F: painting the
 *    coded rect instead showed the junk as a purple/blue band flickering on
 *    every frame while dragging windows.)
 *  - `spurious`: anything else — a drastically smaller visible rect or an
 *    offset origin is the Chrome NVDEC misreported-geometry bug (field
 *    DEVBOX: coded 2560×1600, visible 1280×720). The coded pixels
 *    are the whole desktop → re-wrap and render the full coded rect.
 *
 *  An alignment pad can never reach 64: aligning to any of 8/16/32/64 pads
 *  by at most alignment−1 px, so a ≥64 deficit means the visible picture is
 *  genuinely smaller than the coded surface — NVDEC-bug territory. */
export function classifyCrop(
  codedW: number,
  codedH: number,
  vr: { x: number; y: number; width: number; height: number } | null | undefined,
): 'exact' | 'alignment' | 'spurious' {
  if (!vr || codedW <= 0 || codedH <= 0) return 'exact'
  if (vr.width === codedW && vr.height === codedH) return 'exact'
  const dw = codedW - vr.width
  const dh = codedH - vr.height
  if (vr.x === 0 && vr.y === 0 && dw >= 0 && dh >= 0 && dw < 64 && dh < 64) {
    return 'alignment'
  }
  return 'spurious'
}
