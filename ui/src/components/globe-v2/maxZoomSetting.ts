// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// Shared per-viewer Max Zoom preference helper for both Device Network and Backbone views.
// - Range: 6..14, default: 11.
// - Persisted in localStorage (`meshharbor-globe-max-zoom`) with full try/catch safety.
// - Computes live horizontal ground span at the current center latitude and viewport width.

import type { GlobeLang } from './tokens'

export const MAX_ZOOM_STORAGE_KEY = 'meshharbor-globe-max-zoom'
export const MIN_ALLOWED_MAX_ZOOM = 6
export const MAX_ALLOWED_MAX_ZOOM = 14
export const DEFAULT_MAX_ZOOM = 11

const EARTH_EQUATOR_CIRCUMFERENCE_M = 40_075_016.68557849
const MAX_MERCATOR_LAT = 85.051129

/** Clamp a numeric max-zoom value cleanly into `[6, 14]` (integer), defaulting to `11` on NaN. */
export function clampMaxZoom(value: number): number {
  if (!Number.isFinite(value)) return DEFAULT_MAX_ZOOM
  const rounded = Math.round(value)
  if (rounded < MIN_ALLOWED_MAX_ZOOM) return MIN_ALLOWED_MAX_ZOOM
  if (rounded > MAX_ALLOWED_MAX_ZOOM) return MAX_ALLOWED_MAX_ZOOM
  return rounded
}

/**
 * Parse a persisted storage value: missing, empty, NaN, or out-of-range values
 * cleanly fall back to `DEFAULT_MAX_ZOOM` (11).
 */
export function parseStoredMaxZoom(raw: string | null | undefined): number {
  if (raw == null) return DEFAULT_MAX_ZOOM
  const trimmed = String(raw).trim()
  if (!trimmed) return DEFAULT_MAX_ZOOM
  const n = Number(trimmed)
  if (!Number.isFinite(n)) return DEFAULT_MAX_ZOOM
  const rounded = Math.round(n)
  if (rounded < MIN_ALLOWED_MAX_ZOOM || rounded > MAX_ALLOWED_MAX_ZOOM) {
    return DEFAULT_MAX_ZOOM
  }
  return rounded
}

/** Read per-viewer max zoom from localStorage safely (never throws in restricted/private contexts). */
export function readStoredMaxZoom(
  storage: Pick<Storage, 'getItem'> | null | undefined = typeof localStorage !== 'undefined'
    ? localStorage
    : null,
): number {
  if (!storage) return DEFAULT_MAX_ZOOM
  try {
    return parseStoredMaxZoom(storage.getItem(MAX_ZOOM_STORAGE_KEY))
  } catch {
    return DEFAULT_MAX_ZOOM
  }
}

/** Persist per-viewer max zoom to localStorage safely; returns the clamped integer written. */
export function writeStoredMaxZoom(
  value: number,
  storage: Pick<Storage, 'setItem'> | null | undefined = typeof localStorage !== 'undefined'
    ? localStorage
    : null,
): number {
  const clamped = clampMaxZoom(value)
  if (!storage) return clamped
  try {
    storage.setItem(MAX_ZOOM_STORAGE_KEY, String(clamped))
  } catch {
    /* ignore quota / privacy mode storage errors */
  }
  return clamped
}

/**
 * Ground meters per CSS pixel at `latitudeDeg` and MapLibre 512px-tile `zoom`.
 */
export function metersPerPixelAtZoom(latitudeDeg: number, zoom: number): number {
  const clampedLat = Math.min(Math.abs(Number.isFinite(latitudeDeg) ? latitudeDeg : 0), MAX_MERCATOR_LAT)
  const cosLat = Math.cos((clampedLat * Math.PI) / 180)
  return (EARTH_EQUATOR_CIRCUMFERENCE_M * cosLat) / (512 * Math.pow(2, zoom))
}

/** Approximate horizontal ground span across `containerWidthPx` in kilometers. */
export function horizontalSpanKm(
  latitudeDeg: number,
  zoom: number,
  containerWidthPx: number,
): number {
  const w = Math.max(240, Number.isFinite(containerWidthPx) ? containerWidthPx : 960)
  return (metersPerPixelAtZoom(latitudeDeg, zoom) * w) / 1000
}

function formatDistance(spanKm: number, lang: GlobeLang): string {
  if (spanKm < 1) {
    const meters = Math.max(50, Math.round((spanKm * 1000) / 50) * 50)
    return `${meters} m`
  }
  if (spanKm < 10) {
    const km = Math.max(1, Math.round(spanKm))
    return `${km} km`
  }
  if (spanKm < 100) {
    const km = Math.round(spanKm)
    return `${km} km`
  }
  const km = Math.round(spanKm / 10) * 10
  return lang === 'zh-CN' ? `${km} km` : `${km} km`
}

function zoomTierLabel(zoom: number, lang: GlobeLang): string {
  if (zoom <= 7) {
    return lang === 'zh-CN' ? '省级/区域' : 'region & provinces'
  }
  if (zoom <= 9) {
    return lang === 'zh-CN' ? '城市及周边' : 'city & surroundings'
  }
  if (zoom <= 11) {
    return lang === 'zh-CN' ? '可见多个区' : 'several districts'
  }
  return lang === 'zh-CN' ? '城区/街道细节' : 'urban detail'
}

/**
 * Live bilingual span hint shown beside the max-zoom slider, e.g.:
 * - zh-CN: `"约 35 km · 可见多个区"`, `"约 140 km · 城市及周边"`, `"约 4 km · 城区/街道细节"`
 * - en:    `"about 35 km · several districts"`, `"about 140 km · city & surroundings"`
 */
export function formatMaxZoomSpanHint(
  zoom: number,
  latitudeDeg: number,
  containerWidthPx: number,
  lang: GlobeLang,
): string {
  const z = clampMaxZoom(zoom)
  const km = horizontalSpanKm(latitudeDeg, z, containerWidthPx)
  const dist = formatDistance(km, lang)
  const tier = zoomTierLabel(z, lang)
  return lang === 'zh-CN' ? `约 ${dist} · ${tier}` : `about ${dist} · ${tier}`
}
