// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { computed } from 'vue'
import { useTheme } from 'vuetify'
import logoLight from '@/assets/brand/meshharbor-logo-light.svg'
import logoDark from '@/assets/brand/meshharbor-logo-dark.svg'
import markLight from '@/assets/brand/meshharbor-mark-light.svg'
import markDark from '@/assets/brand/meshharbor-mark-dark.svg'

/** The light lockup, for a surface that is always light (the landing page
 *  forces the light theme, so it does not follow the app's). */
export const BRAND_LOGO_LIGHT = logoLight

/**
 * The Roomler logo for the app's current theme: `logo` is the symbol plus the
 * wordmark, for a header with room for it; `mark` is the symbol alone, drawn
 * for 24–48 px (`roomler-mark-32`), where only the symbol fits. The light
 * files have a dark R and wordmark, the dark ones a white R and a brighter
 * mesh. Vite hashes all four, so a changed logo ships under a new URL.
 */
export function useBrand() {
  const theme = useTheme()
  const dark = computed(() => theme.global.current.value.dark)
  return {
    logo: computed(() => (dark.value ? logoDark : logoLight)),
    mark: computed(() => (dark.value ? markDark : markLight)),
  }
}
