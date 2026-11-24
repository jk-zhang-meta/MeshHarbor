// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// Adaptive pixel-ratio degradation controller (FR-136 S11 / AC13):
// - Samples interactive frame deltas while the camera is actively moving.
// - Once a rolling window of 120 interactive frames has p95 > 24 ms, steps
//   pixelRatio down monotonically (2 -> 1.5 -> 1) and never raises it again
//   within the same session (inspired by GitHub's tiered globe degradation).
// - Zero timers, zero idle frames; safe to unit-test without WebGL or DOM.

export const ADAPTIVE_DPR_WINDOW = 120
export const ADAPTIVE_DPR_P95_THRESHOLD_MS = 24
export const ADAPTIVE_DPR_TIERS = [2, 1.5, 1] as const

export interface AdaptiveDprController {
  /** Current effective pixel ratio (clamped to `[1, cap]`). */
  current(): number
  /** Update the upper bound (e.g. prop change); never raises past degraded floor. */
  setCap(cap: number): number
  /** Mark the start of an active user/camera interaction burst. */
  beginInteraction(): void
  /** Mark the end of an interaction burst so idle gaps are never timed. */
  endInteraction(): void
  /**
   * Record one WebGL render frame timestamp (`performance.now()` in ms).
   * Returns the new pixel ratio if a downgrade occurred, or `null` otherwise.
   */
  recordFrame(nowMs: number): number | null
  /** Reset rolling frame window (used after a downgrade). */
  resetWindow(): void
}

function clampCap(cap: number): number {
  if (!Number.isFinite(cap)) return 2
  return Math.max(1, Math.min(2, cap))
}

function nextLowerTier(current: number): number | null {
  for (const tier of ADAPTIVE_DPR_TIERS) {
    if (tier < current - 1e-6) return tier
  }
  return null
}

function computeP95(samples: readonly number[]): number {
  if (samples.length === 0) return 0
  const sorted = [...samples].sort((a, b) => a - b)
  const idx = Math.min(sorted.length - 1, Math.floor(0.95 * sorted.length))
  return sorted[idx]!
}

export function createAdaptiveDprController(
  initialCap = 2,
  options: { windowSize?: number; p95ThresholdMs?: number } = {},
): AdaptiveDprController {
  const windowSize = Math.max(8, Math.round(options.windowSize ?? ADAPTIVE_DPR_WINDOW))
  const thresholdMs = options.p95ThresholdMs ?? ADAPTIVE_DPR_P95_THRESHOLD_MS

  let cap = clampCap(initialCap)
  let degradedCeiling = cap
  let interacting = false
  let lastFrameMs: number | null = null
  const deltas: number[] = []

  function current(): number {
    return Math.min(cap, degradedCeiling)
  }

  function resetWindow(): void {
    deltas.length = 0
    lastFrameMs = null
  }

  return {
    current,
    setCap(nextCap: number): number {
      cap = clampCap(nextCap)
      // Never step back up past a prior session downgrade.
      degradedCeiling = Math.min(degradedCeiling, cap)
      resetWindow()
      return current()
    },
    beginInteraction(): void {
      interacting = true
      lastFrameMs = null
    },
    endInteraction(): void {
      interacting = false
      lastFrameMs = null
    },
    recordFrame(nowMs: number): number | null {
      if (!interacting || !Number.isFinite(nowMs)) return null
      if (lastFrameMs != null) {
        const dt = nowMs - lastFrameMs
        // Ignore non-positive or tab-backgrounded (>500ms) pauses.
        if (dt > 0 && dt < 500) {
          deltas.push(dt)
          if (deltas.length > windowSize) {
            deltas.shift()
          }
        }
      }
      lastFrameMs = nowMs

      if (deltas.length < windowSize) return null
      if (computeP95(deltas) <= thresholdMs) return null

      const next = nextLowerTier(current())
      if (next == null) {
        resetWindow()
        return null
      }
      degradedCeiling = next
      resetWindow()
      return current()
    },
    resetWindow,
  }
}
