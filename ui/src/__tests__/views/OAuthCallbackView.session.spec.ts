// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// The OAuth callback must leave the REAL auth store signed in. The session
// arrives as a Set-Cookie on the redirect that lands here, so the store never
// saw a `login()`: it was created when this page loaded and, after a logout,
// created signed OUT. Writing only the local hint left `isAuthenticated` false
// and `user` null (`fetchMe()` returns early while the store's flag is false),
// so the app bar's user menu (`v-if="auth.isAuthenticated"`) stayed hidden
// until a reload re-seeded the flag from the hint. The sibling spec replaces
// the store with a stub, which is why it could not see this.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { createMemoryHistory, createRouter } from 'vue-router'

vi.mock('@/plugins/router', () => ({ default: { push: vi.fn() } }))
vi.mock('@/composables/usePush', () => ({
  subscribePush: vi.fn(() => Promise.resolve()),
  unsubscribePush: vi.fn(() => Promise.resolve()),
}))
vi.mock('@/api/client', () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() },
}))
vi.mock('@/stores/ws', () => ({ useWsStore: () => ({ connect: vi.fn() }) }))

import OAuthCallbackView from '@/views/auth/OAuthCallbackView.vue'
import { useAuthStore } from '@/stores/auth'
import { api } from '@/api/client'

/** The non-credential hint the store renders from before `/auth/me`. */
const SIGNED_IN = 'meshharbor-signed-in'
const USER = { id: 'u1', email: 'a@example.test', username: 'a', display_name: 'A B' }

const vuetify = createVuetify({ components, directives })

async function land(sessionOk = true) {
  vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({ ok: sessionOk })))
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/oauth/callback', component: OAuthCallbackView },
      { path: '/', name: 'dashboard', component: { template: '<div />' } },
      { path: '/login', name: 'login', component: { template: '<div />' } },
    ],
  })
  await router.push('/oauth/callback')
  await router.isReady()
  const w = mount(OAuthCallbackView, { global: { plugins: [vuetify, router] } })
  await flushPromises()
  return { w, router }
}

beforeEach(() => {
  setActivePinia(createPinia())
  localStorage.clear()
  vi.clearAllMocks()
  vi.mocked(api.get).mockResolvedValue(USER)
  // jsdom has none; the page's spinner (VProgressCircular) needs one.
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  )
})

afterEach(() => {
  vi.unstubAllGlobals()
  window.history.replaceState({}, '', '/')
})

describe('OAuthCallbackView — the real auth store', () => {
  it('a store created signed OUT ends signed in, with its user, before the dashboard', async () => {
    // As after a logout: the hint is gone when the page (and the store) loads.
    const auth = useAuthStore()
    expect(auth.isAuthenticated).toBe(false)

    const { w, router } = await land()

    expect(w.text()).not.toContain('Failed to complete OAuth login')
    // The app bar's menu renders on exactly this.
    expect(auth.isAuthenticated).toBe(true)
    // …and its initials come from the user `/auth/me` returned.
    expect(api.get).toHaveBeenCalledWith('/auth/me')
    expect(auth.user?.id).toBe('u1')
    expect(localStorage.getItem(SIGNED_IN)).toBe('1')
    expect(router.currentRoute.value.name).toBe('dashboard')
  })

  it('a session the server refuses leaves the store signed out, not only the hint', async () => {
    // A stale hint from an earlier session: the store was created signed IN.
    localStorage.setItem(SIGNED_IN, '1')
    const auth = useAuthStore()
    expect(auth.isAuthenticated).toBe(true)

    const { w } = await land(false)

    expect(w.text()).toContain('Failed to complete OAuth login')
    expect(auth.isAuthenticated).toBe(false)
    expect(auth.user).toBeNull()
    expect(localStorage.getItem(SIGNED_IN)).toBeNull()
    expect(api.get).not.toHaveBeenCalled()
  })
})
