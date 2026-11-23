// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import 'vuetify/styles'
import '@mdi/font/css/materialdesignicons.css'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import type { ThemeDefinition } from 'vuetify'
import { createVueI18nAdapter } from 'vuetify/locale/adapters/vue-i18n'
import { useI18n } from 'vue-i18n'
import i18n from './i18n'

// The flat theme (2026-11-23): a cool paper ground, harbor-ink text, the brand's
// teal as the one strong colour, and buoy orange only where something asks for
// attention. Surfaces are told apart by a hairline border, never a shadow; the
// border and text tokens live in `styles/theme.css` beside the type scale.
export const lightTheme: ThemeDefinition = {
  dark: false,
  colors: {
    primary: '#0A8F86',
    secondary: '#10212B',
    accent: '#E07A2E',
    background: '#F5F7F9',
    surface: '#FFFFFF',
    'surface-bright': '#FFFFFF',
    'surface-light': '#F0F3F5',
    // Vuetify paints tooltips and snackbars with surface-variant: dark on light.
    'surface-variant': '#1D2B33',
    'on-surface-variant': '#EEF3F5',
    success: '#1F9D57',
    warning: '#B97E08',
    error: '#D14343',
    info: '#2F7BD8',
  },
  variables: {
    'border-color': '#10212B',
    'border-opacity': 0.1,
    'high-emphasis-opacity': 0.9,
    'medium-emphasis-opacity': 0.62,
    'disabled-opacity': 0.4,
    'hover-opacity': 0.04,
    'focus-opacity': 0.1,
    'activated-opacity': 0.1,
  },
}

export const darkTheme: ThemeDefinition = {
  dark: true,
  colors: {
    primary: '#3CC7B9',
    secondary: '#E6EEF2',
    accent: '#F0965A',
    background: '#0E151A',
    surface: '#141D23',
    'surface-bright': '#1B262D',
    'surface-light': '#1A252C',
    'surface-variant': '#E6EEF2',
    'on-surface-variant': '#0E151A',
    success: '#3CCB7F',
    warning: '#E0A93B',
    error: '#F06A6A',
    info: '#5C9EF0',
  },
  variables: {
    'border-color': '#E6EEF2',
    'border-opacity': 0.1,
    'high-emphasis-opacity': 0.92,
    'medium-emphasis-opacity': 0.64,
    'disabled-opacity': 0.4,
    'hover-opacity': 0.05,
    'focus-opacity': 0.12,
    'activated-opacity': 0.12,
  },
}

/** The saved choice, else the system's own light or dark setting. */
export function getDefaultTheme(): string {
  try {
    const saved = localStorage.getItem('meshharbor-theme')
    if (saved === 'light' || saved === 'dark') return saved
  } catch {
    /* storage can be absent (private mode): follow the system */
  }
  return globalThis.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

const vuetify = createVuetify({
  components,
  directives,
  locale: {
    adapter: createVueI18nAdapter({ i18n, useI18n }),
  },
  theme: {
    defaultTheme: getDefaultTheme(),
    themes: {
      light: lightTheme,
      dark: darkTheme,
    },
  },
  // Flat by default: a card is a bordered sheet, a button carries no shadow, an
  // alert is a tint rather than a block of colour. An explicit prop still wins.
  defaults: {
    VBtn: { variant: 'flat', rounded: 'lg' },
    VCard: { flat: true, border: true, rounded: 'lg' },
    VAlert: { variant: 'tonal', rounded: 'lg' },
    VChip: { rounded: 'md' },
    VTextField: { variant: 'outlined', density: 'comfortable', rounded: 'lg', color: 'primary' },
    VTextarea: { variant: 'outlined', rounded: 'lg', color: 'primary' },
    VSelect: { variant: 'outlined', density: 'comfortable', rounded: 'lg', color: 'primary' },
    VAutocomplete: { variant: 'outlined', density: 'comfortable', rounded: 'lg', color: 'primary' },
    VCombobox: { variant: 'outlined', density: 'comfortable', rounded: 'lg', color: 'primary' },
    VAppBar: { flat: true },
    VToolbar: { flat: true },
    VTable: { hover: true },
    VDataTable: { hover: true },
    VDataTableServer: { hover: true },
    VSnackbar: { rounded: 'lg' },
    VSwitch: { color: 'primary', inset: true, density: 'compact' },
    VCheckbox: { color: 'primary' },
    VRadio: { color: 'primary' },
    VProgressLinear: { rounded: true },
    VTooltip: { openDelay: 250 },
  },
})

export default vuetify
