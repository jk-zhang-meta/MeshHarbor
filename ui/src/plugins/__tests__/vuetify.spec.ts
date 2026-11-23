// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, it, expect, beforeEach, vi } from 'vitest'

// Mock localStorage before importing
const store: Record<string, string> = {}
const localStorageMock = {
  getItem: vi.fn((key: string) => store[key] ?? null),
  setItem: vi.fn((key: string, val: string) => { store[key] = val }),
  removeItem: vi.fn((key: string) => { delete store[key] }),
  clear: vi.fn(() => { Object.keys(store).forEach(k => delete store[k]) }),
}
Object.defineProperty(globalThis, 'localStorage', { value: localStorageMock })

// Mock i18n module to avoid import side effects
vi.mock('../i18n', () => ({ default: {} }))
vi.mock('vuetify/locale/adapters/vue-i18n', () => ({
  createVueI18nAdapter: () => ({}),
}))
vi.mock('vue-i18n', () => ({
  useI18n: () => ({}),
}))

describe('Vuetify theme configuration', () => {
  beforeEach(() => {
    localStorageMock.clear()
    vi.resetModules()
  })

  it('lightTheme is the flat palette: harbor teal on a cool paper ground', async () => {
    const { lightTheme } = await import('../vuetify')
    expect(lightTheme.dark).toBe(false)
    expect(lightTheme.colors!.primary).toBe('#0A8F86')
    expect(lightTheme.colors!.secondary).toBe('#10212B')
    expect(lightTheme.colors!.accent).toBe('#E07A2E')
    expect(lightTheme.colors!.background).toBe('#F5F7F9')
    expect(lightTheme.colors!.surface).toBe('#FFFFFF')
    expect(lightTheme.colors!.info).toBe('#2F7BD8')
    expect(lightTheme.colors!.warning).toBe('#B97E08')
    expect(lightTheme.colors!.error).toBe('#D14343')
    expect(lightTheme.colors!.success).toBe('#1F9D57')
  })

  it('darkTheme is the flat palette on deep harbor blue, not grey', async () => {
    const { darkTheme } = await import('../vuetify')
    expect(darkTheme.dark).toBe(true)
    expect(darkTheme.colors!.primary).toBe('#3CC7B9')
    expect(darkTheme.colors!.background).toBe('#0E151A')
    expect(darkTheme.colors!.surface).toBe('#141D23')
    expect(darkTheme.colors!.info).toBe('#5C9EF0')
    expect(darkTheme.colors!.warning).toBe('#E0A93B')
    expect(darkTheme.colors!.error).toBe('#F06A6A')
    expect(darkTheme.colors!.success).toBe('#3CCB7F')
  })

  it('getDefaultTheme follows a dark system setting when nothing is saved', async () => {
    const mm = vi.fn((q: string) => ({
      matches: q === '(prefers-color-scheme: dark)',
      addEventListener: () => {},
      removeEventListener: () => {},
    }))
    Object.defineProperty(globalThis, 'matchMedia', { value: mm, configurable: true })
    try {
      const { getDefaultTheme } = await import('../vuetify')
      expect(getDefaultTheme()).toBe('dark')
      store['meshharbor-theme'] = 'light'
      expect(getDefaultTheme()).toBe('light')
    } finally {
      delete (globalThis as { matchMedia?: unknown }).matchMedia
    }
  })

  it('getDefaultTheme returns light when no localStorage', async () => {
    const { getDefaultTheme } = await import('../vuetify')
    expect(getDefaultTheme()).toBe('light')
  })

  it('getDefaultTheme returns dark when stored', async () => {
    store['meshharbor-theme'] = 'dark'
    const { getDefaultTheme } = await import('../vuetify')
    expect(getDefaultTheme()).toBe('dark')
  })
})
