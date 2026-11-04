// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-16 L4 — input to photon in the real viewer: the main thread's half.
 *
 * In bench mode the viewer sends `{"t":"probe","seq":N}` on the input
 * channel. A bench agent (the synthetic source, `MESHHARBORD_BENCH=1`) paints
 * the last probe it saw into a marker in the bottom-right of every frame
 * that follows. Whatever paints frames reads that marker back: a decode
 * worker (`rc-bench-sampler.ts`) or, on the plain `<video>` path, the
 * sampler here. The first painted frame carrying `N` ends the round trip,
 * and `paint − send` is input to photon minus the display's own latency,
 * on one clock (`epochNowMs`), with no clock offset anywhere.
 *
 * Gated at every entry point. The knob `meshharbor-rc-bench` is honoured only
 * when the agent advertised `bench` in `AgentCaps.video`; the agent paints
 * only in a test-only build with bench mode on; the workers sample only
 * when their init says so; and probes ride `sendInput`'s channel, so a
 * session without INPUT sends none.
 *
 * ⚠️ Probes go out at a JITTERED interval. 250 ms is exactly 15 frames at
 * 60 fps: without jitter every probe lands on the same phase of the capture
 * clock, and a run reports one arbitrary point of the wait for the next
 * capture instead of its distribution. That follows from the arithmetic;
 * the agent's in-process harness (`agents/meshharbord/tests/l4_latency.rs`)
 * jitters for the same reason.
 */
import * as benchMarker from '../workers/rc-bench-marker'
import { RC_CONNECT_UPLOAD_PATH } from './rcConnectTimingUpload'

export const BENCH_STORAGE_KEY = 'meshharbor-rc-bench'
/** The capability an agent advertises in `AgentCaps.video` when a frame
 *  will answer a probe. */
export const BENCH_CAP = 'bench'
export const BENCH_PROBE_EVERY_MS = 250
/** At least one frame interval at 30 fps, so probes land on every phase. */
export const BENCH_PROBE_JITTER_MS = 34
/** A probe not answered by then is counted lost: the input channel is
 *  unreliable by design, and a lost probe must not hold a slot forever. */
export const BENCH_PROBE_TTL_MS = 2_000
/** Round trips per uploaded record (about ten seconds of probing). */
export const BENCH_UPLOAD_EVERY = 40
/** At most this many records a minute; one per ~10 s is the steady state. */
export const BENCH_UPLOAD_MAX_PER_MIN = 6
export const RC_L4_LOG_TARGET = 'rc.l4'
/** Bump when `fields` changes shape. */
export const RC_L4_RECORD_VERSION = 1

/** Where a frame was painted, so a record says which path it measured. */
export type BenchPath = 'video' | 'webcodecs' | 'hevc' | 'vp9-444'

/** How a session times input to photon.
 *  - `probe`: the agent paints the probe itself. Only a synthetic-source
 *    build with bench mode on can, and it advertises `bench`.
 *  - `target`: `meshharbord probe-target` paints it, a window on the host whose
 *    marker changes when a real pointer move reaches one of its cells. Any
 *    build, Windows hosts. The probe is a pointer move, so the round trip
 *    also counts injection and the host's compositor. */
export type BenchMode = 'probe' | 'target'

/** `meshharbor-rc-bench`: `1` → `probe`, `target` → `target`, anything else off.
 *  Read once per session, like every other `meshharbor-rc-*` knob. */
export function storedBenchMode(): BenchMode | null {
  try {
    const v = globalThis.localStorage?.getItem(BENCH_STORAGE_KEY)
    return v === '1' ? 'probe' : v === 'target' ? 'target' : null
  } catch {
    return null
  }
}

/** `meshharbor-rc-bench=1` in localStorage: probe mode asked for. */
export function storedBench(): boolean {
  return storedBenchMode() === 'probe'
}

/** The mode a session runs. `probe` only when the agent advertised `bench`:
 *  a probe sent to anything else is noise on the input channel and a number
 *  nobody can read. `target` whenever asked: the window answers it, not the
 *  agent, and the operator who set the knob started the window. */
export function benchSessionMode(
  mode: BenchMode | null,
  videoCaps: readonly string[] | null | undefined,
): BenchMode | null {
  if (mode === 'probe') return (videoCaps ?? []).includes(BENCH_CAP) ? 'probe' : null
  return mode
}

/** Probe mode is on for a session: asked for AND advertised. */
export function benchSessionActive(knob: boolean, videoCaps: readonly string[] | null | undefined): boolean {
  return benchSessionMode(knob ? 'probe' : null, videoCaps) === 'probe'
}

/** `meshharbord probe-target`'s layout (`agents/meshharbord/src/probe_target.rs`),
 *  in the host monitor's physical pixels: 144 wide, a 32 px pad of 16 cells
 *  × 9 px above the 48 px marker area, flush in the bottom-right corner. */
export const PROBE_TARGET = { width: 144, height: 80, padH: 32, cells: 16, cellW: 9 } as const

/** A cell's centre in a `monW × monH` monitor's own pixels, or null outside
 *  1..16 or on a monitor too small for the window. Mirrors
 *  `probe_target::cell_centre`; both suites pin the same vectors. */
export function probeTargetCellCentre(monW: number, monH: number, cell: number): { x: number; y: number } | null {
  const t = PROBE_TARGET
  if (!Number.isInteger(cell) || cell < 1 || cell > t.cells || monW < t.width || monH < t.height) return null
  return {
    x: monW - t.width + (cell - 1) * t.cellW + Math.floor(t.cellW / 2),
    y: monH - t.height + t.padH / 2,
  }
}

/** The same point as the normalised coordinates a `mouse_move` carries. The
 *  agent maps `round(x · (w − 1))` (`map_normalised_to_virtual`), so dividing
 *  by `w − 1` lands on the pixel exactly. */
export function probeTargetPointer(monW: number, monH: number, cell: number): { x: number; y: number } | null {
  const c = probeTargetCellCentre(monW, monH, cell)
  if (!c) return null
  return { x: c.x / (monW - 1), y: c.y / (monH - 1) }
}

export interface BenchStats {
  n: number
  lost: number
  p50: number | null
  p95: number | null
  min: number | null
  max: number | null
}

export function quantile(sorted: readonly number[], p: number): number | null {
  if (sorted.length === 0) return null
  return sorted[Math.round((sorted.length - 1) * p)] ?? null
}

export function benchStats(rtts: readonly number[], lost: number): BenchStats {
  const s = [...rtts].sort((a, b) => a - b)
  return {
    n: s.length,
    lost,
    p50: quantile(s, 0.5),
    p95: quantile(s, 0.95),
    min: s[0] ?? null,
    max: s[s.length - 1] ?? null,
  }
}

export interface BenchProberDeps {
  /** Send one probe; false when the channel could not take it. */
  send: (probe: { t: 'probe'; seq: number }) => boolean
  /** Tell every sampler that probe `seq` is outstanding. */
  arm: (seq: number) => void
  /** A batch of round trips is ready (every BENCH_UPLOAD_EVERY, and on stop). */
  flush?: (batch: BenchBatch) => void
  now?: () => number
  random?: () => number
  setTimer?: (fn: () => void, ms: number) => unknown
  clearTimer?: (handle: unknown) => void
  /** Probe numbers run 1..maxSeq. 4095 for the agent's 12-bit probe; 16 for
   *  `probe-target`, whose cells are the numbers. */
  maxSeq?: number
}

export interface BenchBatch {
  rtts: number[]
  lost: number
  paths: BenchPath[]
}

export interface BenchProber {
  start(): void
  /** Stop probing and flush what was measured. */
  stop(): void
  /** A frame carrying `seq` was painted at `paintedAt` (epoch ms). Returns
   *  the round trip, or null for a probe this prober did not send, sent
   *  already answered, or expired. */
  onPainted(seq: number, paintedAt: number, path: BenchPath): number | null
  stats(): BenchStats
  running(): boolean
}

export function createBenchProber(deps: BenchProberDeps): BenchProber {
  const now = deps.now ?? (() => performance.timeOrigin + performance.now())
  const random = deps.random ?? Math.random
  const setTimer = deps.setTimer ?? ((fn: () => void, ms: number) => setTimeout(fn, ms))
  const clearTimer = deps.clearTimer ?? ((h: unknown) => clearTimeout(h as ReturnType<typeof setTimeout>))
  const maxSeq = Math.max(1, Math.min(deps.maxSeq ?? 0x0fff, 0x0fff))
  const sent = new Map<number, number>()
  let seq = 0
  let timer: unknown = null
  let lost = 0
  let batch: number[] = []
  let batchLost = 0
  let batchPaths = new Set<BenchPath>()
  const all: number[] = []

  function expire(nowMs: number) {
    for (const [s, at] of sent) {
      if (nowMs - at > BENCH_PROBE_TTL_MS) {
        sent.delete(s)
        lost++
        batchLost++
      }
    }
  }

  function flush() {
    if (batch.length === 0 && batchLost === 0) return
    deps.flush?.({ rtts: batch, lost: batchLost, paths: [...batchPaths] })
    batch = []
    batchLost = 0
    batchPaths = new Set()
  }

  function tick() {
    timer = null
    const nowMs = now()
    expire(nowMs)
    // 1..maxSeq: the agent keeps 12 bits, an all-zero word paints a black
    // grid, and probe-target's cells are numbered from 1, so 0 is never used.
    // With 16 numbers and a 2 s expiry at ~4 probes a second, a number is
    // never reused while its last probe could still be in flight.
    seq = (seq % maxSeq) + 1
    if (deps.send({ t: 'probe', seq })) {
      sent.set(seq, nowMs)
      deps.arm(seq)
    }
    schedule()
  }

  function schedule() {
    timer = setTimer(tick, BENCH_PROBE_EVERY_MS + Math.floor(random() * BENCH_PROBE_JITTER_MS))
  }

  return {
    start() {
      if (timer === null) schedule()
    },
    stop() {
      if (timer !== null) clearTimer(timer)
      timer = null
      // What is still in flight never had its full TTL: dropped, not lost.
      expire(now())
      sent.clear()
      flush()
    },
    onPainted(s, paintedAt, path) {
      const at = sent.get(s)
      if (at === undefined) return null
      sent.delete(s)
      const rtt = paintedAt - at
      if (!Number.isFinite(rtt) || rtt < 0) return null
      all.push(rtt)
      batch.push(rtt)
      batchPaths.add(path)
      if (batch.length >= BENCH_UPLOAD_EVERY) flush()
      return rtt
    },
    stats() {
      return benchStats(all, lost)
    },
    running() {
      return timer !== null
    },
  }
}

/** The `<video>` path's sampler. While a probe is outstanding it reads the
 *  bottom-right marker of each presented frame through a small canvas,
 *  stamped with `requestVideoFrameCallback`'s `presentationTime` (when the
 *  frame was submitted for composition, the `<video>` analogue of a worker's
 *  paint call). */
export interface VideoBenchSampler {
  arm(seq: number): void
  stop(): void
}

export interface VideoBenchSamplerDeps {
  findVideo: () => HTMLVideoElement | null
  onProbe: (seq: number, paintedAt: number) => void
  /** Reads the probe from the presented frame; injected for tests. */
  read?: (video: HTMLVideoElement) => number | null
  now?: () => number
}

type RvfcVideo = HTMLVideoElement & {
  requestVideoFrameCallback?: (cb: (now: number, md: { presentationTime?: number }) => void) => number
  cancelVideoFrameCallback?: (handle: number) => void
}

export function createVideoBenchSampler(deps: VideoBenchSamplerDeps): VideoBenchSampler {
  const now = deps.now ?? (() => performance.now())
  const read = deps.read ?? readVideoProbe
  const armed = new Map<number, number>()
  let handle: number | null = null
  let video: RvfcVideo | null = null

  function prune(nowMs: number) {
    for (const [s, at] of armed) if (nowMs - at > BENCH_PROBE_TTL_MS) armed.delete(s)
  }

  function onFrame(_now: number, md: { presentationTime?: number }) {
    handle = null
    const v = video
    if (!v) return
    prune(now())
    if (armed.size === 0) return
    const presented = typeof md.presentationTime === 'number' ? md.presentationTime : performance.now()
    let s: number | null = null
    try {
      s = read(v)
    } catch {
      s = null
    }
    if (s !== null && armed.delete(s)) deps.onProbe(s, performance.timeOrigin + presented)
    if (armed.size > 0) request()
  }

  function request() {
    const v = video
    if (!v || handle !== null || typeof v.requestVideoFrameCallback !== 'function') return
    handle = v.requestVideoFrameCallback(onFrame)
  }

  return {
    arm(s) {
      video = deps.findVideo() as RvfcVideo | null
      if (!video) return
      // On a data-channel path a `<video>` may exist and never present a
      // frame, so expiry cannot wait for a frame callback.
      const nowMs = now()
      prune(nowMs)
      armed.set(s & 0x0fff, nowMs)
      request()
    },
    stop() {
      if (handle !== null && video?.cancelVideoFrameCallback) video.cancelVideoFrameCallback(handle)
      handle = null
      armed.clear()
      video = null
    },
  }
}

let probeCanvas: HTMLCanvasElement | null = null

/** Draw the presented frame's bottom-right region into a small canvas and
 *  read the probe marker from it. */
export function readVideoProbe(video: HTMLVideoElement): number | null {
  const region = benchMarker.probeRegion(video.videoWidth, video.videoHeight)
  if (!region) return null
  probeCanvas ??= document.createElement('canvas')
  const c = probeCanvas
  if (c.width !== region.width) c.width = region.width
  if (c.height !== region.height) c.height = region.height
  const ctx = c.getContext('2d', { willReadFrequently: true })
  if (!ctx) return null
  ctx.drawImage(video, region.x, region.y, region.width, region.height, 0, 0, region.width, region.height)
  const px = ctx.getImageData(0, 0, region.width, region.height).data
  const luma = benchMarker.lumaFromRgba(px, region.width, region.height, region.width * 4, 'rgba')
  return benchMarker.decodeLumaAt('bottom-right', luma, region.width, region.height, region.width)
}

// ── the `rc.l4` record ──────────────────────────────────────────────────────

export interface RcL4UploadContext {
  tenantId: string | null
  agentOrgId?: string | null
  agentId: string | null
  sessionId: string | null
}

export interface RcL4RecordFields {
  v: typeof RC_L4_RECORD_VERSION
  paths: BenchPath[]
  n: number
  lost: number
  p50_ms: number | null
  p95_ms: number | null
  min_ms: number | null
  max_ms: number | null
  /** Every round trip in the batch, 0.1 ms resolution, in arrival order. */
  rtt_ms: number[]
  agent_id: string | null
  agent_org_id?: string
}

export interface RcL4UploadBody {
  tenant_id: string
  source: 'browser'
  session_id?: string
  lines: [
    {
      ts: { $date: { $numberLong: string } }
      level: 'INFO'
      target: typeof RC_L4_LOG_TARGET
      msg: string
      fields: RcL4RecordFields
    },
  ]
}

const OBJECT_ID_HEX = /^[0-9a-f]{24}$/
const hexOrNull = (v: string | null | undefined) => (v && OBJECT_ID_HEX.test(v) ? v : null)
const tenth = (v: number | null) => (v === null ? null : Math.round(v * 10) / 10)

export function formatBenchLine(s: BenchStats, paths: readonly BenchPath[]): string {
  const ms = (v: number | null) => (v === null ? '—' : `${v.toFixed(1)}ms`)
  return `L4 n=${s.n} lost=${s.lost} p50=${ms(s.p50)} p95=${ms(s.p95)} max=${ms(s.max)} path=${paths.join('+') || '—'}`
}

/** One batch → one `rc.l4` line. Pure; null without a tenant to file it
 *  under. Timing metadata only: numbers, ids and the paint path. */
export function buildL4Upload(
  batch: BenchBatch,
  ctx: RcL4UploadContext,
  nowMs: number = Date.now(),
): RcL4UploadBody | null {
  const tenantId = hexOrNull(ctx.tenantId)
  if (!tenantId) return null
  const s = benchStats(batch.rtts, batch.lost)
  const fields: RcL4RecordFields = {
    v: RC_L4_RECORD_VERSION,
    paths: batch.paths,
    n: s.n,
    lost: s.lost,
    p50_ms: tenth(s.p50),
    p95_ms: tenth(s.p95),
    min_ms: tenth(s.min),
    max_ms: tenth(s.max),
    rtt_ms: batch.rtts.map((v) => Math.round(v * 10) / 10),
    agent_id: hexOrNull(ctx.agentId),
  }
  const agentOrg = hexOrNull(ctx.agentOrgId)
  if (agentOrg && agentOrg !== tenantId) fields.agent_org_id = agentOrg
  const sessionId = hexOrNull(ctx.sessionId)
  return {
    tenant_id: tenantId,
    source: 'browser',
    ...(sessionId ? { session_id: sessionId } : {}),
    lines: [
      {
        ts: { $date: { $numberLong: String(Math.round(nowMs)) } },
        level: 'INFO',
        target: RC_L4_LOG_TARGET,
        msg: formatBenchLine(s, batch.paths),
        fields,
      },
    ],
  }
}

export interface RcL4Uploader {
  send(batch: BenchBatch, ctx: RcL4UploadContext): void
  sentCount(): number
}

/** Fire-and-forget, rate-capped, never throws: the FR-22 uploader's rules,
 *  for the same reasons (`rcConnectTimingUpload.ts`). A diagnostic must
 *  never become the incident. */
export function createL4Uploader(
  deps: {
    fetch?: (input: string, init: RequestInit) => Promise<unknown>
    now?: () => number
    maxPerMinute?: number
  } = {},
): RcL4Uploader {
  const now = deps.now ?? (() => Date.now())
  const cap = deps.maxPerMinute ?? BENCH_UPLOAD_MAX_PER_MIN
  const recent: number[] = []
  let sent = 0
  return {
    send(batch, ctx) {
      try {
        const nowMs = now()
        const body = buildL4Upload(batch, ctx, nowMs)
        if (!body) return
        while (recent.length > 0 && nowMs - recent[0]! >= 60_000) recent.shift()
        if (recent.length >= cap) return
        recent.push(nowMs)
        const init: RequestInit = {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
          keepalive: true,
          credentials: 'same-origin',
        }
        const p = deps.fetch
          ? deps.fetch(RC_CONNECT_UPLOAD_PATH, init)
          : typeof globalThis.fetch === 'function'
            ? globalThis.fetch(RC_CONNECT_UPLOAD_PATH, init)
            : null
        if (!p) return
        sent += 1
        void Promise.resolve(p).then(
          () => undefined,
          () => undefined,
        )
      } catch {
        /* never let a diagnostic reach the session */
      }
    },
    sentCount() {
      return sent
    },
  }
}
