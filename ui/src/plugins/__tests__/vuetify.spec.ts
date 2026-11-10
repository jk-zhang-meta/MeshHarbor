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

  it('lightTheme has correct colors', async () => {
    const { lightTheme } = await import('../vuetify')
    expect(lightTheme.dark).toBe(false)
    expect(lightTheme.colors!.primary).toBe('#009688')
    expect(lightTheme.colors!.secondary).toBe('#ef5350')
    expect(lightTheme.colors!.accent).toBe('#424242')
    expect(lightTheme.colors!.background).toBe('#EEEEEE')
    expect(lightTheme.colors!.info).toBe('#4DB6AC')
    expect(lightTheme.colors!.warning).toBe('#FFC107')
    expect(lightTheme.colors!.error).toBe('#DD2C00')
    expect(lightTheme.colors!.success).toBe('#69F0AE')
  })

  it('darkTheme has correct colors', async () => {
    const { darkTheme } = await import('../vuetify')
    expect(darkTheme.dark).toBe(true)
    expect(darkTheme.colors!.primary).toBe('#B2DFDB')
    expect(darkTheme.colors!.secondary).toBe('#ef5350')
    expect(darkTheme.colors!.accent).toBe('#424242')
    expect(darkTheme.colors!.background).toBe('#555555')
    expect(darkTheme.colors!.surface).toBe('#333333')
    expect(darkTheme.colors!.info).toBe('#4DB6AC')
    expect(darkTheme.colors!.warning).toBe('#FFC107')
    expect(darkTheme.colors!.error).toBe('#DD2C00')
    expect(darkTheme.colors!.success).toBe('#69F0AE')
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
