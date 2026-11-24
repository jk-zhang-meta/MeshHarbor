// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// Visual design tokens (S2), WCAG contrast helpers, neutral naming overrides (S6/AC7),
// and font stacks for the MapLibre GL JS v6 globe rebuild.

export type GlobeThemeMode = 'dark' | 'light'
export type GlobeLang = 'en' | 'zh-CN'

export interface GlobeTokens {
  mode: GlobeThemeMode
  space: string
  ocean: string
  land: string
  coast: string
  border: string
  borderOpacity: readonly [number, number, number]
  horizon: string
  labelPrimary: string
  labelSecondary: string
  labelMuted: string
  labelHalo: string
  online: string
  direct: string
  stale: string
  relay: string
  derp: string
  tunnel: string
  offline: string
  blocked: string
  stalled: string
  centre: string
  focusRing: string
  leg: string
  hubFill: string
  hubText: string
  zones: readonly [string, string, string, string, string, string]
}

export const DARK_TOKENS: GlobeTokens = {
  mode: 'dark',
  space: '#060B13',
  ocean: '#08131E',
  land: '#172A3C',
  coast: '#335975',
  border: '#8FA3BF',
  borderOpacity: [0.58, 0.30, 0.16],
  horizon: '#2A7AB0',
  labelPrimary: '#E6EDF6',
  labelSecondary: '#A9B6C8',
  labelMuted: '#7889A0',
  labelHalo: 'rgba(8, 19, 30, 0.92)',
  online: '#56B4E9',
  direct: '#56B4E9',
  stale: '#E69F00',
  relay: '#E69F00',
  derp: '#D98CB8',
  tunnel: '#2BB58A',
  offline: '#8C96A5',
  blocked: '#8C96A5',
  stalled: '#F0703A',
  centre: '#F5F7FA',
  focusRing: '#FFFFFF',
  leg: 'rgba(169, 182, 200, 0.6)',
  hubFill: '#08131E',
  hubText: '#E6EDF6',
  zones: ['#56B4E9', '#E69F00', '#2BB58A', '#D98CB8', '#F0E442', '#A9B6C8'],
}

export const LIGHT_TOKENS: GlobeTokens = {
  mode: 'light',
  space: '#F5F7FA',
  ocean: '#DCE6F0',
  land: '#FAFBFC',
  coast: '#B9C6D4',
  border: '#4A5B70',
  borderOpacity: [0.6, 0.32, 0.18],
  horizon: '#BFD8F0',
  labelPrimary: '#1F2937',
  labelSecondary: '#4B5563',
  labelMuted: '#6B7280',
  labelHalo: 'rgba(250, 251, 252, 0.9)',
  online: '#0072B2',
  direct: '#0072B2',
  stale: '#A66300',
  relay: '#A66300',
  derp: '#A3527F',
  tunnel: '#00785A',
  offline: '#6B7280',
  blocked: '#6B7280',
  stalled: '#C24A00',
  centre: '#111827',
  focusRing: '#111827',
  leg: 'rgba(75, 85, 99, 0.6)',
  hubFill: '#FFFFFF',
  hubText: '#1F2937',
  zones: ['#0072B2', '#A66300', '#00785A', '#A3527F', '#8A7A00', '#4B5563'],
}

export function getGlobeTokens(mode: GlobeThemeMode): GlobeTokens {
  return mode === 'dark' ? DARK_TOKENS : LIGHT_TOKENS
}

/** Local CJK font stack — zero hosted glyph PBFs (S1/S2). */
export const CJK_FONT_STACK =
  '"PingFang SC","Hiragino Sans GB","Microsoft YaHei","Noto Sans CJK SC","Source Han Sans SC",sans-serif'

export const UI_FONT_STACK =
  `system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans",${CJK_FONT_STACK}`

/** MapLibre text-font array when style `glyphs` is omitted (v5.11+/v6 local text). */
export const MAPLIBRE_LOCAL_TEXT_FONT = [
  'Noto Sans CJK SC',
  'PingFang SC',
  'Microsoft YaHei',
  'Noto Sans',
  'sans-serif',
]

/** Neutral country/region naming overrides (S6 / AC7). */
export const REGION_NAME_OVERRIDES: Readonly<
  Record<string, { zh: string; en: string }>
> = {
  TW: { zh: '台湾', en: 'Taiwan' },
  TWN: { zh: '台湾', en: 'Taiwan' },
  HK: { zh: '香港', en: 'Hong Kong' },
  HKG: { zh: '香港', en: 'Hong Kong' },
  MO: { zh: '澳门', en: 'Macau' },
  MAC: { zh: '澳门', en: 'Macau' },
}

export function formatNeutralRegionName(
  code: string | null | undefined,
  fallback: string,
  lang: GlobeLang,
): string {
  const key = (code ?? '').trim().toUpperCase()
  const hit = REGION_NAME_OVERRIDES[key]
  if (hit) return lang === 'zh-CN' ? hit.zh : hit.en
  return fallback
}

export const BOUNDARY_ATTRIBUTION: Readonly<Record<GlobeLang, string>> = {
  'zh-CN':
    '边界：Natural Earth（公有领域）；geoBoundaries（CC BY 4.0），含 © OpenStreetMap 贡献者（ODbL）数据',
  en: 'Boundaries: Natural Earth (public domain); geoBoundaries (CC BY 4.0), incl. © OpenStreetMap contributors (ODbL)',
}

/** Parse `#RGB` or `#RRGGBB` into `[r, g, b]` 0..255. */
export function parseHexRgb(hex: string): [number, number, number] {
  const clean = hex.trim().replace(/^#/, '')
  if (clean.length === 3) {
    return [
      parseInt(clean[0]! + clean[0]!, 16),
      parseInt(clean[1]! + clean[1]!, 16),
      parseInt(clean[2]! + clean[2]!, 16),
    ]
  }
  if (clean.length !== 6) {
    throw new Error(`Invalid hex color: ${hex}`)
  }
  return [
    parseInt(clean.slice(0, 2), 16),
    parseInt(clean.slice(2, 4), 16),
    parseInt(clean.slice(4, 6), 16),
  ]
}

/** WCAG 2.1 relative luminance in `[0, 1]`. */
export function relativeLuminance(hex: string): number {
  const [r8, g8, b8] = parseHexRgb(hex)
  const chan = (c8: number): number => {
    const s = c8 / 255
    return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4)
  }
  return 0.2126 * chan(r8) + 0.7152 * chan(g8) + 0.0722 * chan(b8)
}

/** WCAG 2.1 contrast ratio in `[1, 21]`. */
export function contrastRatio(hexA: string, hexB: string): number {
  const l1 = relativeLuminance(hexA)
  const l2 = relativeLuminance(hexB)
  const hi = Math.max(l1, l2)
  const lo = Math.min(l1, l2)
  return (hi + 0.05) / (lo + 0.05)
}

export function hexToRgbaArray(hex: string, alpha = 1): [number, number, number, number] {
  const [r, g, b] = parseHexRgb(hex)
  return [r / 255, g / 255, b / 255, alpha]
}
