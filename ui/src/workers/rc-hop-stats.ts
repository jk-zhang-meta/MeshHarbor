// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * P1 (Parsec-class plan) — shared pure helpers for the decode workers'
 * per-hop instrumentation. The DEVBOX field ceiling (~25-35 fps on an RTX
 * 5090 viewer) could be decode-bound, paint-bound, or main-thread-bound —
 * indistinguishable without per-hop numbers. Each worker accumulates
 * per-window hop timings with `HopStats` and folds the snapshots into its
 * existing 1 s `stats` message (no new message cadence), so the diagnosis
 * costs nothing at steady state.
 *
 * Hops measured:
 *  - `fwd`    — main-thread DC `onmessage` → worker `chunk` arrival
 *               (epoch-absolute clocks via `epochNowMs`, valid across
 *               contexts because both sides use timeOrigin + now()).
 *  - `decode` — `decoder.decode(chunk)` submission → `output` callback
 *               (queue + decoder latency; indicts the decoder itself).
 *  - `paint`  — the `paintFrame` body (canvas blit cost).
 *
 * Also home to the 2D-context A/B options: `alpha:false` enables the
 * opaque compositor fast path; `desynchronized:true` requests the
 * low-latency canvas swap chain (may be a no-op for placeholder-composited
 * OffscreenCanvas — which is exactly why it ships as an A/B, not an
 * assumed win). localStorage `meshharbor-rc-ctx-mode` drives it.
 */

/** One window's aggregate for a hop. `minMs` (FR-15) is what makes the
 *  age window usable as a PATH-FLOOR sample: even a queued window usually
 *  contains one frame that rode a momentarily drained pipe, and the
 *  difference between that and the average is the queue the agent should
 *  react to. 0 for an empty window (n = 0). */
export type HopWindow = { avgMs: number; maxMs: number; minMs: number; n: number }

/** Round to 0.1 ms — enough resolution for hop diagnosis, keeps the
 *  stats payload compact. */
export function round1(v: number): number {
  return Math.round(v * 10) / 10
}

/** Rolling per-window accumulator: `add()` samples, `snapshotAndReset()`
 *  once per stats window. Non-finite / negative samples are ignored (a
 *  clock hiccup must not poison the window). */
export class HopStats {
  private sum = 0
  private max = 0
  private min = Number.POSITIVE_INFINITY
  private n = 0

  add(ms: number): void {
    if (!Number.isFinite(ms) || ms < 0) return
    this.sum += ms
    if (ms > this.max) this.max = ms
    if (ms < this.min) this.min = ms
    this.n++
  }

  snapshotAndReset(): HopWindow {
    const w: HopWindow = {
      avgMs: this.n > 0 ? round1(this.sum / this.n) : 0,
      maxMs: round1(this.max),
      minMs: this.n > 0 ? round1(this.min) : 0,
      n: this.n,
    }
    this.sum = 0
    this.max = 0
    this.min = Number.POSITIVE_INFINITY
    this.n = 0
    return w
  }
}

/** FR-59 P3 — the largest per-frame drift the accumulator will believe, µs.
 *  A pair astride an encoder rebuild, a resync or an idle gap can produce
 *  an arbitrary delta in either direction; clamping keeps one such glitch
 *  from deciding the whole window. */
const DRIFT_CLAMP_US = 1_000_000
/** Frame intervals longer than this are not a cadence — the stream paused,
 *  or the timestamps were reset — so the pair is dropped rather than
 *  clamped. */
const DRIFT_MAX_INTERVAL_US = 5_000_000

/** FR-59 P3 — how much the transit queue GREW over a window, in ms.
 *
 *  The measurement is `Σ(Δarrival − Δwire)`: how much longer the frames
 *  took to *arrive* than they took to be *produced*. If the agent frames
 *  every 33 ms and they land every 50 ms, the queue between them is
 *  growing 17 ms per frame, and the sum over a window is how far the
 *  viewer fell behind during it.
 *
 *  Why this and not the paint age (FR-15): both terms are DIFFERENCES of
 *  timestamps from a single clock, so the unknown agent↔browser offset
 *  cancels exactly. No `rc:clock` probe, no plausibility bound, nothing to
 *  reject. That matters because on a jittery mobile link the probe is
 *  biased by the very congestion it measures — field 2026-09-01 had the
 *  age absent in 8 of 14 windows and 60 samples rejected as impossible,
 *  in a session running 2.3–7.1 s behind.
 *
 *  It reports the DERIVATIVE, not the level: a positive number means the
 *  queue is growing right now, which is what a latency-first controller
 *  wants to act on — before the queue is seconds deep, and regardless of
 *  how deep it already is. */
export class QueueDrift {
  private lastWireUs: number | null = null
  private lastArrivalUs = 0
  private driftUs = 0
  private n = 0

  /** One frame. `wireTsUs` is the agent-clock framing timestamp carried in
   *  the frame header; `arrivalUs` is any consistent local clock — the
   *  point in the pipeline does not matter, only that it is the same point
   *  every frame, because a constant offset cancels in the delta. */
  add(wireTsUs: number, arrivalUs: number): void {
    if (!Number.isFinite(wireTsUs) || !Number.isFinite(arrivalUs)) return
    const prevWire = this.lastWireUs
    const prevArrival = this.lastArrivalUs
    this.lastWireUs = wireTsUs
    this.lastArrivalUs = arrivalUs
    if (prevWire === null) return
    const dWire = wireTsUs - prevWire
    const dArrival = arrivalUs - prevArrival
    // A non-advancing or absurd wire interval is a reset, not a cadence.
    if (dWire <= 0 || dWire > DRIFT_MAX_INTERVAL_US) return
    if (dArrival < 0 || dArrival > DRIFT_MAX_INTERVAL_US) return
    const drift = dArrival - dWire
    this.driftUs += Math.max(-DRIFT_CLAMP_US, Math.min(DRIFT_CLAMP_US, drift))
    this.n++
  }

  /** Window total in ms, or `null` when fewer than two frames arrived —
   *  which is "no signal", NOT a 0 ms drift. The agent must be able to
   *  tell those apart: one says the queue is stable, the other says
   *  nothing at all. */
  snapshotAndReset(): number | null {
    const ms = this.n > 0 ? Math.round(this.driftUs / 1000) : null
    this.driftUs = 0
    this.n = 0
    return ms
  }

  /** Drop the cadence history without emitting — for a decoder reset,
   *  where the next pair would straddle the discontinuity. */
  reset(): void {
    this.lastWireUs = null
    this.lastArrivalUs = 0
  }
}

/** Epoch-absolute milliseconds, comparable across window/worker contexts
 *  (each context's `performance.now()` is relative to its own
 *  `timeOrigin`; adding them re-bases onto the shared epoch). */
export function epochNowMs(): number {
  return performance.timeOrigin + performance.now()
}

// ── FR-1 P7 — end-to-end age clock sync ─────────────────────────────────────
// The agent stamps every DC video frame with µs on its process-wide epoch
// (see peer.rs `agent_epoch_us`) and echoes the same clock over the control
// DC (`rc:clock` → `rc:clock.echo`). The browser probes it every couple of
// seconds, keeps the lowest-RTT sample (NTP-style — asymmetry error is
// bounded by RTT/2 of the BEST probe, not the average), and can then read
// any frame's wire timestamp as a true capture-side age on its own clock.

/** Epoch-absolute microseconds (same convention as `epochNowMs`, scaled).
 *  Precision note: epoch-µs ≈ 1.7e15 sits well inside Number's 2^53 exact
 *  range; sub-µs float dust is irrelevant at HUD resolution. */
export function epochNowUs(): number {
  return epochNowMs() * 1000
}

/** One clock probe: `offsetUs` maps browser epoch-µs onto the agent clock
 *  (`agentNow ≈ epochNowUs() + offsetUs`); `rttMs` is the probe's own
 *  round trip, doubling as the HUD's control-path RTT readout. */
export type ClockSample = { offsetUs: number; rttMs: number }

/** Build a sample from one probe round trip. `t0`/`t1` are the browser's
 *  epoch-µs at send/receive, `agentUs` the agent's clock from the echo.
 *  Returns null for garbage (non-finite, negative RTT) — a bad echo must
 *  never poison the offset. */
export function clockSample(
  t0EpochUs: number,
  t1EpochUs: number,
  agentUs: number,
): ClockSample | null {
  if (
    !Number.isFinite(t0EpochUs)
    || !Number.isFinite(t1EpochUs)
    || !Number.isFinite(agentUs)
  ) {
    return null
  }
  const rttUs = t1EpochUs - t0EpochUs
  if (rttUs < 0) return null
  return {
    offsetUs: agentUs - (t0EpochUs + t1EpochUs) / 2,
    rttMs: rttUs / 1000,
  }
}

/** The sample to trust: minimum-RTT of the retained window. */
export function bestClockSample(samples: ClockSample[]): ClockSample | null {
  let best: ClockSample | null = null
  for (const s of samples) {
    if (best === null || s.rttMs < best.rttMs) best = s
  }
  return best
}

/** Age of a frame at `epochUs` on the browser clock, given the frame's
 *  agent-clock wire timestamp and the probe offset. Covers everything from
 *  the agent's framing point (encode output + send queue + network + decode
 *  + paint queue); agent-side capture+encode (~10–15 ms) sits BEFORE the
 *  stamp and is not included. */
export function frameAgeMs(
  wireTsUs: number,
  offsetUs: number,
  epochUs: number,
): number {
  return (epochUs + offsetUs - wireTsUs) / 1000
}

/** 2D-context A/B mode. `legacy` = today's optionless `getContext('2d')`. */
export type CtxMode = 'legacy' | 'opaque' | 'opaque-desync'

export function normalizeCtxMode(v: unknown): CtxMode {
  return v === 'legacy' || v === 'opaque' || v === 'opaque-desync'
    ? v
    : 'opaque-desync'
}

/** Context settings for a mode. `undefined` = call getContext with no
 *  options (bit-identical to the pre-P1 behaviour). */
export function ctxOptionsFor(
  mode: CtxMode,
): CanvasRenderingContext2DSettings | undefined {
  if (mode === 'opaque') return { alpha: false }
  if (mode === 'opaque-desync') return { alpha: false, desynchronized: true }
  return undefined
}

// ── P6 (Parsec-class plan) — flow-control knobs ─────────────────────────────
// The rc.188 viewer-rate loop had two hardwired constants sized for a janky
// (pre-P1) viewer: the workers' backlog-drop threshold (queue > 4) and the
// composable's INSTANTANEOUS per-window struggling rule (any backlog drop OR
// queue > 2 inside a single 1 s window). P1's field read showed a healthy
// viewer parks at queue 0 — so one bad window (e.g. a large IDR landing while
// the tab briefly lost the GPU) tripped the struggling bit, the agent clamped
// its send-fps, and the lazy recovery took ~20 s to climb back. Both knobs are
// now configurable (init-canvas / localStorage), and the struggling bit needs
// a SUSTAINED run of bad windows before it fires.

/** Worker decode-queue depth above which non-key frames are dropped and an
 *  IDR resync is requested. */
export const DEFAULT_MAX_DECODE_QUEUE = 4
/** Queue depth that makes a 1 s stats window count as "bad" for the
 *  struggling rule (strictly-greater compare). */
export const DEFAULT_STRUGGLE_QUEUE = 2
/** Consecutive bad windows before the struggling bit is reported to the
 *  agent. 1 = the legacy instantaneous rule. */
export const DEFAULT_STRUGGLE_WINDOWS = 2

/** Parse an integer knob (localStorage string or init-canvas number) with a
 *  clamp. Anything non-numeric (null, '', 'banana') → the default; fractions
 *  truncate toward zero BEFORE clamping. */
export function normalizeIntKnob(
  raw: unknown,
  def: number,
  min: number,
  max: number,
): number {
  const n =
    typeof raw === 'number'
      ? raw
      : typeof raw === 'string'
        ? Number.parseInt(raw, 10)
        : Number.NaN
  if (!Number.isFinite(n)) return def
  return Math.min(max, Math.max(min, Math.trunc(n)))
}

/** Sustained-window struggle fold. Call `observe(bad)` once per 1 s stats
 *  window; it returns true only after `windows` CONSECUTIVE bad windows (and
 *  keeps returning true while the bad run continues). A single clean window
 *  resets the streak — recovery is immediate, assertion is lazy. */
export class StruggleWindow {
  private streak = 0
  private readonly windows: number

  constructor(windows: number) {
    this.windows = Math.max(1, Math.trunc(Number.isFinite(windows) ? windows : 1))
  }

  observe(bad: boolean): boolean {
    this.streak = bad ? this.streak + 1 : 0
    return this.streak >= this.windows
  }

  reset(): void {
    this.streak = 0
  }
}
