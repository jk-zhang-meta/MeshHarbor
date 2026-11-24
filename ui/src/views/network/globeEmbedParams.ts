// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import type { GlobeLang, GlobeThemeMode } from '@/components/globe-v2/tokens'

export type EmbedThemeParam = 'light' | 'dark' | 'system'

/** Read the first string value from a Vue Router query entry (string | string[] | null | undefined). */
export function firstQueryValue(raw: unknown): string | null {
  if (typeof raw === 'string') return raw
  if (Array.isArray(raw)) {
    for (const item of raw) {
      if (typeof item === 'string') return item
    }
  }
  return null
}

/** True when `?embed=1` is present in the route query. */
export function parseEmbedFlag(raw: unknown): boolean {
  return firstQueryValue(raw) === '1'
}

/**
 * Parse `?lang=...` into a supported globe/UI locale.
 * Accepts `zh*` (`zh`, `zh-CN`, `zh-Hans`, `zh_CN`, …) → `'zh-CN'` and `en*` → `'en'`.
 * Returns `null` when absent or unrecognized so the active locale stays unchanged.
 */
export function parseLangParam(raw: unknown): GlobeLang | null {
  const val = firstQueryValue(raw)
  if (!val) return null
  const norm = val.trim().replace(/_/g, '-').toLowerCase()
  if (norm === 'zh' || norm.startsWith('zh-')) return 'zh-CN'
  if (norm === 'en' || norm.startsWith('en-')) return 'en'
  return null
}

/**
 * Parse `?theme=light|dark|system`.
 * Returns `null` when absent or unrecognized so the active Vuetify theme stays unchanged.
 */
export function parseThemeParam(raw: unknown): EmbedThemeParam | null {
  const val = firstQueryValue(raw)
  if (!val) return null
  const norm = val.trim().toLowerCase()
  if (norm === 'light' || norm === 'dark' || norm === 'system') return norm
  return null
}

/** Resolve an optional theme query param into a concrete `'light' | 'dark'` mode. */
export function resolveThemeMode(
  param: EmbedThemeParam | null,
  systemPrefersDark: boolean,
  currentDark: boolean,
): GlobeThemeMode {
  if (param === 'light') return 'light'
  if (param === 'dark') return 'dark'
  if (param === 'system') return systemPrefersDark ? 'dark' : 'light'
  return currentDark ? 'dark' : 'light'
}

/**
 * True when the active route opts into chrome-less embed mode (`meta.allowEmbed` + `?embed=1`).
 * Used by `AppLayout.vue` to hide the app bar, navigation drawer, and shell chrome.
 */
export function isEmbedChromeHidden(route: {
  meta?: { allowEmbed?: boolean }
  query?: Record<string, unknown>
}): boolean {
  return Boolean(route.meta?.allowEmbed) && parseEmbedFlag(route.query?.embed)
}
