// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { createMemoryHistory, createRouter } from 'vue-router'
import { createPinia } from 'pinia'
import { createI18n } from 'vue-i18n'
import en from '@/locales/en.json'

vi.mock('@/api/client', () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() },
}))
vi.mock('@/plugins/router', () => ({ default: { push: vi.fn() } }))
vi.mock('@/composables/usePush', () => ({
  subscribePush: vi.fn(() => Promise.resolve()),
  unsubscribePush: vi.fn(() => Promise.resolve()),
}))
vi.mock('@/stores/ws', () => ({ useWsStore: () => ({ connect: vi.fn() }) }))

import LoginView from '@/views/auth/LoginView.vue'

const vuetify = createVuetify({ components, directives })

async function mountAt(path: string) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/login', name: 'login', component: LoginView },
      { path: '/register', name: 'register', component: { template: '<div />' } },
      { path: '/', name: 'dashboard', component: { template: '<div />' } },
    ],
  })
  await router.push(path)
  await router.isReady()
  const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })
  const w = mount(LoginView, { global: { plugins: [vuetify, router, createPinia(), i18n] } })
  await flushPromises()
  return w
}

beforeEach(() => {
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
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('LoginView — sign-in controls', () => {
  it('keeps the provider controls BUTTONS (e2e/oauth.spec.ts finds them by that role)', async () => {
    const w = await mountAt('/login')
    const labels = w.findAll('button').map((b) => b.text().trim())
    expect(labels).toContain('Google')
    for (const removed of ['Facebook', 'GitHub', 'LinkedIn', 'Microsoft']) {
      expect(labels).not.toContain(removed)
    }
    expect(w.find('a[href^="/api/oauth/"]').exists()).toBe(false)
  })

  it('links to /register', async () => {
    const plain = await mountAt('/login')
    expect(plain.find('a[href^="/register"]').attributes('href')).toBe('/register')
  })
})

// FR-116 P7 — iOS capitalises the first letter of a text field by default,
// and the server matches the username exactly: "goran" typed on an iPhone
// arrived as "Goran" and was refused. The attributes must reach the <input>.
describe('LoginView — on a phone keyboard (FR-116)', () => {
  it('uses an email account identity without autocorrection or capitalisation', async () => {
    const w = await mountAt('/login')
    const user = w.find('input[autocomplete="username"]')
    expect(user.exists()).toBe(true)
    expect(user.attributes('type')).toBe('email')
    expect(w.text()).not.toContain('Username')
    expect(user.attributes('autocapitalize')).toBe('none')
    expect(user.attributes('autocorrect')).toBe('off')
    expect(user.attributes('spellcheck')).toBe('false')
  })

  it('names the password for the password manager', async () => {
    const w = await mountAt('/login')
    expect(w.find('input[autocomplete="current-password"]').exists()).toBe(true)
  })
})
