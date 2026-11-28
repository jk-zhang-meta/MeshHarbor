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
// The auth store imports the app router and push; neither matters here.
vi.mock('@/plugins/router', () => ({ default: { push: vi.fn() } }))
vi.mock('@/composables/usePush', () => ({
  subscribePush: vi.fn(() => Promise.resolve()),
  unsubscribePush: vi.fn(() => Promise.resolve()),
}))
vi.mock('@/stores/ws', () => ({ useWsStore: () => ({ connect: vi.fn() }) }))

import RegisterView from '@/views/auth/RegisterView.vue'
import { api } from '@/api/client'

const vuetify = createVuetify({ components, directives })
const mockApi = vi.mocked(api)
type W = Window & { purestat?: unknown }

async function mountAt(path: string) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/register', name: 'register', component: RegisterView },
      { path: '/', name: 'dashboard', component: { template: '<div />' } },
      { path: '/login', name: 'login', component: { template: '<div />' } },
    ],
  })
  await router.push(path)
  await router.isReady()
  const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })
  const w = mount(RegisterView, {
    global: { plugins: [vuetify, router, createPinia(), i18n] },
    attachTo: document.body,
  })
  await flushPromises()
  return { w, router }
}

async function fillAndSubmit(w: Awaited<ReturnType<typeof mountAt>>['w']) {
  const inputs = w.findAll('input')
  await inputs[0]!.setValue('new@example.com')
  await inputs[1]!.setValue('New User')
  await w.find('input[type="password"]').setValue('secret123')
  await w.find('form').trigger('submit')
  await flushPromises()
}

function registerBody(): Record<string, unknown> {
  const call = mockApi.post.mock.calls.find(([url]) => url === '/auth/register')
  expect(call, 'no register request was sent').toBeDefined()
  return call![1] as Record<string, unknown>
}

let setItem: ReturnType<typeof vi.spyOn>
let cookieSet: ReturnType<typeof vi.spyOn>
const purestat = vi.fn()

beforeEach(() => {
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  )
  mockApi.post.mockReset()
  mockApi.post.mockResolvedValue({ message: 'Registration successful. Please check your email to activate your account.' })
  purestat.mockReset()
  ;(window as W).purestat = purestat
  setItem = vi.spyOn(Storage.prototype, 'setItem')
  cookieSet = vi.spyOn(Document.prototype, 'cookie', 'set')
})

afterEach(() => {
  delete (window as W).purestat
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  document.body.innerHTML = ''
})

describe('RegisterView — registration controls', () => {
  it('uses email as the account identity without requesting an independent username', async () => {
    const { w } = await mountAt('/register')
    expect(w.find('input[type="email"]').exists()).toBe(true)
    expect(w.text()).not.toContain('Username')
    await fillAndSubmit(w)
    expect(registerBody()).toEqual({
      email: 'new@example.com',
      password: 'secret123',
      display_name: 'New User',
    })
    expect(registerBody()).not.toHaveProperty('username')
    expect(registerBody()).not.toHaveProperty('attribution')
  })

  it('keeps the provider controls BUTTONS, as on the sign-in page (e2e finds them by that role)', async () => {
    const { w } = await mountAt('/register')
    const labels = w.findAll('button').map((b) => b.text().trim())
    expect(labels).toContain('Google')
    for (const removed of ['Facebook', 'GitHub', 'LinkedIn', 'Microsoft']) {
      expect(labels).not.toContain(removed)
    }
    expect(w.find('a[href^="/api/oauth/"]').exists()).toBe(false)
  })

  it('links to /login and writes nothing to the device', async () => {
    const { w } = await mountAt('/register')
    expect(w.find('a[href^="/login"]').attributes('href')).toBe('/login')
    await fillAndSubmit(w)
    expect(setItem).not.toHaveBeenCalled()
    expect(cookieSet).not.toHaveBeenCalled()
  })
})

describe('RegisterView — the signup goal (FR-88)', () => {
  it('fires once, on the server’s yes', async () => {
    const { w } = await mountAt('/register')
    await fillAndSubmit(w)
    expect(purestat).toHaveBeenCalledTimes(1)
    expect(purestat).toHaveBeenCalledWith('signup')
  })

  it('does not fire when the server refuses', async () => {
    mockApi.post.mockRejectedValueOnce(new Error('Email already registered'))
    const { w } = await mountAt('/register')
    await fillAndSubmit(w)
    expect(purestat).not.toHaveBeenCalled()
  })

  it('is a no-op without purestat: the sign-up still completes and navigates', async () => {
    delete (window as W).purestat
    const { w, router } = await mountAt('/register')
    await fillAndSubmit(w)
    expect(mockApi.post).toHaveBeenCalledWith('/auth/register', expect.any(Object))
    await vi.waitFor(() => expect(router.currentRoute.value.name).toBe('dashboard'))
  })
})

// FR-116 P7 — the same keyboard rules as the sign-in page: an account made
// on a phone must not be "Goran" when its owner typed "goran".
describe('RegisterView — on a phone keyboard (FR-116)', () => {
  it('asks the keyboard not to capitalise the email and names the new password without a second identity', async () => {
    const { w } = await mountAt('/register')
    const user = w.find('input[autocomplete="email"]')
    expect(user.attributes('autocapitalize')).toBe('none')
    expect(user.attributes('autocorrect')).toBe('off')
    expect(w.find('input[autocomplete="username"]').exists()).toBe(false)
    expect(w.find('input[autocomplete="email"]').attributes('autocapitalize')).toBe('none')
    expect(w.find('input[autocomplete="new-password"]').exists()).toBe(true)
  })
})
