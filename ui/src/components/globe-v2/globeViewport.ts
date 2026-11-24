// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// Pure viewport geometry helpers for MapLibre GL JS v6 globe projection:
// - Fix #1: Exact fit-to-container zoom so globe diameter is ~85-90% of min(width, height).
// - Fix #3: Edge-aware label placement so 0 label pixels clip outside [4, W-4] x [4, H-4].
// - Fix #5: Exact projected screen circle (cx, cy, radius) for the 360° Fresnel rim glow.
// - S7: 64-gon accuracy circle geometry & pixel radius check for `coords` precision.

export const DEFAULT_GLOBE_CENTER: readonly [number, number] = [108, 30]
export const DEFAULT_GLOBE_FOV_DEG = 36.87
export const DEFAULT_TARGET_DIAMETER_RATIO = 0.875
export const MIN_GLOBE_ZOOM = 0.6
export const MAX_GLOBE_ZOOM = 14

const MAX_VALID_LATITUDE = 85.051129
const EARTH_RADIUS_KM = 6371

/** Mirrors MapLibre `planetScaleAtLatitude`. */
export function planetScaleAtLatitude(latitudeDegrees: number): number {
  const clamped = Math.min(Math.abs(latitudeDegrees), MAX_VALID_LATITUDE)
  return Math.cos((clamped * Math.PI) / 180)
}

/** Focal distance in CSS px from camera to viewport center (`height / (2 * tan(fov/2))`). */
export function cameraFocalDistancePx(height: number, fovDeg = DEFAULT_GLOBE_FOV_DEG): number {
  const halfFovRad = ((fovDeg * 0.5) * Math.PI) / 180
  return Math.max(1, height) / (2 * Math.tan(halfFovRad))
}

/**
 * Exact apparent silhouette radius of the MapLibre v6 globe in CSS pixels at pitch 0.
 * Matches MapLibre's perspective projection of a sphere of world-radius
 * `R = 512 * 2^z / (2*pi * cos(lat))` at distance `D = f + R` from the camera.
 */
export function globeScreenRadiusPx(
  _width: number,
  height: number,
  zoom: number,
  latitudeDegrees = DEFAULT_GLOBE_CENTER[1],
  fovDeg = DEFAULT_GLOBE_FOV_DEG,
): number {
  const f = cameraFocalDistancePx(height, fovDeg)
  const worldSize = 512 * Math.pow(2, zoom)
  const rWorld = worldSize / (2 * Math.PI * planetScaleAtLatitude(latitudeDegrees))
  return (f * rWorld) / Math.sqrt(f * f + 2 * f * rWorld)
}

/**
 * Exact zoom level so the MapLibre globe's rendered diameter equals
 * `targetDiameterRatio * min(width, height)` (default 0.875 -> 87.5%, inside 85-90%).
 */
export function computeFitGlobeZoom(
  width: number,
  height: number,
  latitudeDegrees = DEFAULT_GLOBE_CENTER[1],
  targetDiameterRatio = DEFAULT_TARGET_DIAMETER_RATIO,
  fovDeg = DEFAULT_GLOBE_FOV_DEG,
): number {
  const w = Math.max(120, width)
  const h = Math.max(120, height)
  const minDim = Math.min(w, h)
  const desiredR = (minDim * targetDiameterRatio) / 2
  const f = cameraFocalDistancePx(h, fovDeg)
  // Solve r = f * R / sqrt(f^2 + 2*f*R)  =>  f*R^2 - 2*r^2*R - r^2*f = 0
  const rWorld = (desiredR * desiredR + desiredR * Math.sqrt(desiredR * desiredR + f * f)) / f
  const worldSize = rWorld * 2 * Math.PI * planetScaleAtLatitude(latitudeDegrees)
  const z = Math.log2(worldSize / 512)
  return Math.max(MIN_GLOBE_ZOOM, Math.min(4.5, Math.round(z * 1000) / 1000))
}

export interface GlobeScreenCircle {
  cx: number
  cy: number
  radius: number
  /** Smooth 0..1 opacity fade for the 360° Fresnel rim glow (1 at z<=3.2, 0 at z>=4.8). */
  rimOpacity: number
}

export function computeGlobeScreenCircle(
  width: number,
  height: number,
  zoom: number,
  latitudeDegrees: number,
  padding: { top?: number; right?: number; bottom?: number; left?: number } = {},
  fovDeg = DEFAULT_GLOBE_FOV_DEG,
): GlobeScreenCircle {
  const left = padding.left ?? 0
  const right = padding.right ?? 0
  const top = padding.top ?? 0
  const bottom = padding.bottom ?? 0
  const cx = width / 2 + (left - right) / 2
  const cy = height / 2 + (top - bottom) / 2
  const radius = globeScreenRadiusPx(width, height, zoom, latitudeDegrees, fovDeg)
  let rimOpacity = 1
  if (zoom >= 4.8) {
    rimOpacity = 0
  } else if (zoom > 3.2) {
    const t = (zoom - 3.2) / (4.8 - 3.2)
    rimOpacity = Math.max(0, Math.min(1, 1 - t * t * (3 - 2 * t)))
  }
  return { cx, cy, radius, rimOpacity }
}

/**
 * Estimate rendered CSS pixel width of a 11px bold map label (CJK + Latin).
 * Slightly conservative so labels never touch or cross the viewport edge.
 */
export function estimateLabelWidthPx(text: string): number {
  if (!text) return 0
  let w = 0
  for (const ch of text) {
    const cp = ch.codePointAt(0) ?? 0
    if (cp >= 0x2e80) {
      w += 11.8
    } else if (ch === ' ' || ch === '·' || ch === '.') {
      w += 4.5
    } else if (ch >= 'A' && ch <= 'Z') {
      w += 7.6
    } else {
      w += 6.8
    }
  }
  return Math.ceil(w + 6)
}

export type MarkerEdgePlacement = 'extend-both' | 'extend-right' | 'extend-left' | 'hide'

/**
 * Choose which edge-safe symbol layer places a marker's text label (Fix #3):
 * - `'extend-both'`: label fits inside `[margin, W - margin]` whether extending left or right
 *   (and centered above/below), so full 8-way variable anchor is safe.
 * - `'extend-right'`: marker is near the LEFT edge -> use MapLibre `anchor: 'left'` so text
 *   extends rightward into the canvas (never clips left edge!).
 * - `'extend-left'`: marker is near the RIGHT edge -> use MapLibre `anchor: 'right'` so text
 *   extends leftward into the canvas (never clips right edge!).
 * - `'hide'`: marker is outside `[margin, W - margin]` or label cannot fit on either side ->
 *   suppress text cleanly so 0 pixels clip!
 */
export function assignMarkerEdgePlacement(
  screenX: number,
  screenY: number,
  stageWidth: number,
  stageHeight: number,
  labelText: string,
  marginPx = 6,
  radialOffsetPx = 15,
): MarkerEdgePlacement {
  if (!labelText) return 'hide'
  if (
    !Number.isFinite(screenX) ||
    !Number.isFinite(screenY) ||
    screenX < marginPx ||
    screenX > stageWidth - marginPx ||
    screenY < marginPx + 8 ||
    screenY > stageHeight - marginPx - 8
  ) {
    return 'hide'
  }

  const estW = estimateLabelWidthPx(labelText)
  const fitsRight = screenX + radialOffsetPx + estW <= stageWidth - marginPx
  const fitsLeft = screenX - radialOffsetPx - estW >= marginPx

  if (fitsRight && fitsLeft) {
    // Also verify centered top/bottom fits within horizontal bounds
    if (screenX - estW / 2 >= marginPx && screenX + estW / 2 <= stageWidth - marginPx) {
      return 'extend-both'
    }
    return screenX < stageWidth / 2 ? 'extend-right' : 'extend-left'
  }
  if (fitsRight) return 'extend-right'
  if (fitsLeft) return 'extend-left'
  return 'hide'
}

/** Approximate screen pixel radius for a geographic accuracy circle of `radiusKm` at `zoom` & `lat`. */
export function accuracyCircleRadiusPx(
  radiusKm: number,
  zoom: number,
  latitudeDegrees: number,
): number {
  if (!Number.isFinite(radiusKm) || radiusKm <= 0) return 0
  const angularRad = radiusKm / EARTH_RADIUS_KM
  const worldSize = 512 * Math.pow(2, zoom)
  const globeR = worldSize / (2 * Math.PI * planetScaleAtLatitude(latitudeDegrees))
  return angularRad * globeR
}

/**
 * Build a closed 64-gon spherical circle ring around `[lon, lat]` of radius `radiusKm` (S7).
 * Unwrapped cleanly in longitude so MapLibre renders without antimeridian wrap artifacts.
 */
export function buildAccuracyCircleRing(
  lonDeg: number,
  latDeg: number,
  radiusKm: number,
  sides = 64,
): Array<[number, number]> {
  const deg = Math.PI / 180
  const rad = 180 / Math.PI
  const lat1 = latDeg * deg
  const lon1 = lonDeg * deg
  const d = Math.max(0.0001, radiusKm / EARTH_RADIUS_KM)

  const sinLat1 = Math.sin(lat1)
  const cosLat1 = Math.cos(lat1)
  const sinD = Math.sin(d)
  const cosD = Math.cos(d)

  const ring: Array<[number, number]> = []
  for (let i = 0; i <= sides; i++) {
    const brng = (i / sides) * Math.PI * 2
    const lat2 = Math.asin(
      Math.max(-1, Math.min(1, sinLat1 * cosD + cosLat1 * sinD * Math.cos(brng))),
    )
    const lon2 =
      lon1 + Math.atan2(Math.sin(brng) * sinD * cosLat1, cosD - sinLat1 * Math.sin(lat2))
    let lonOut = lon2 * rad
    if (ring.length > 0) {
      const prevLon = ring[ring.length - 1]![0]
      while (lonOut - prevLon > 180) lonOut -= 360
      while (lonOut - prevLon < -180) lonOut += 360
    }
    ring.push([lonOut, lat2 * rad])
  }
  return ring
}
