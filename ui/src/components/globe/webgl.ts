// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// Runtime capability probes for the 3D globe (WebGL2 + reduced motion).
// Kept pure and defensive so SSR, jsdom unit tests, and low-end GPUs all
// degrade cleanly without throwing.

/** True when this browser can open a usable WebGL2 rendering context. */
export function isWebGL2Supported(): boolean {
  if (typeof document === 'undefined' || typeof WebGL2RenderingContext === 'undefined') {
    return false
  }
  try {
    const canvas = document.createElement('canvas')
    const gl = canvas.getContext('webgl2', { failIfMajorPerformanceCaveat: false })
    if (!gl) return false
    const ext = gl.getExtension('WEBGL_lose_context')
    ext?.loseContext()
    return true
  } catch {
    return false
  }
}

/** True when the OS/browser asks to avoid continuous motion. */
export function prefersReducedMotion(): boolean {
  if (typeof globalThis.matchMedia !== 'function') return false
  try {
    return globalThis.matchMedia('(prefers-reduced-motion: reduce)').matches
  } catch {
    return false
  }
}
