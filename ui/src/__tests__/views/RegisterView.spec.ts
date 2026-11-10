// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-88 (#1790) — the register view: the campaign keys on its URL go out
// ONCE, as `attribution` on the register request or on the OAuth start URL;
// the optional "How did you hear about MeshHarbor?" never blocks sign-up; the
// `signup` goal fires on the server's yes; and nothing is written to the
// device on the way (carry, don't store).
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
// Leaving for the provider is the one thing jsdom cannot do; everything else
// in the module is the real one.
vi.mock('@/utils/attribution', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/utils/attribution')>()),
  startOAuth: vi.fn(),
}))

import RegisterView from '@/views/auth/RegisterView.vue'
import { api } from '@/api/client'
import { oauthStartUrl, startOAuth } from '@/utils/attribution'

const vuetify = createVuetify({ components, directives })
const mockApi = vi.mocked(api)
const mockStartOAuth = vi.mocked(startOAuth)
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
  await inputs[1]!.setValue('newuser')
  await inputs[2]!.setValue('New User')
  await w.find('input[type="password"]').setValue('secret123')
  await w.find('form').trigger('submit')
  await flushPromises()
}

function registerBody(): Record<string, unknown> {
  const call = mockApi.post.mock.calls.find(([url]) => url === '/auth/register')
  expect(call, 'no register request was sent').toBeDefined()
  return call![1] as Record<string, unknown>
}

/** Click a provider button; the URL the browser would be sent to. */
async function clickProvider(w: Awaited<ReturnType<typeof mountAt>>['w'], label: string): Promise<URL> {
  const btn = w.findAll('button').find((b) => b.text().trim() === label)
  expect(btn, `no ${label} button`).toBeDefined()
  mockStartOAuth.mockClear()
  await btn!.trigger('click')
  expect(mockStartOAuth).toHaveBeenCalledTimes(1)
  const [provider, attribution] = mockStartOAuth.mock.calls[0]!
  return new URL(oauthStartUrl(provider, attribution), 'https://meshharbor.itachi.fans')
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

describe('RegisterView — attribution (FR-88)', () => {
  it('sends the landing’s campaign, as the static pages carried it, with the account', async () => {
    const { w } = await mountAt(
      '/register?utm_source=youtube&utm_medium=video&utm_campaign=fr88-test&referrer_host=www.youtube.com&landing_path=%2Fblog%2Fx%2F',
    )
    await fillAndSubmit(w)
    expect(registerBody()).toEqual({
      email: 'new@example.com',
      username: 'newuser',
      password: 'secret123',
      display_name: 'New User',
      attribution: {
        source: 'youtube',
        medium: 'video',
        campaign: 'fr88-test',
        referrer_host: 'www.youtube.com',
        landing_path: '/blog/x/',
      },
    })
  })

  it('works out the landing itself when the visitor arrived here directly', async () => {
    Object.defineProperty(document, 'referrer', { value: 'https://www.tiktok.com/', configurable: true })
    try {
      const { w } = await mountAt('/register?ref=tiktok-bio')
      await fillAndSubmit(w)
      expect(registerBody().attribution).toEqual({ source: 'tiktok-bio', referrer_host: 'www.tiktok.com', landing_path: '/register' })
    } finally {
      delete (document as { referrer?: string }).referrer
    }
  })

  it('sends no attribution key at all without a campaign or an answer', async () => {
    const { w } = await mountAt('/register')
    await fillAndSubmit(w)
    expect(registerBody()).not.toHaveProperty('attribution')
  })

  it('asks "How did you hear about MeshHarbor?" as an OPTIONAL question: unanswered, sign-up goes through', async () => {
    const { w } = await mountAt('/register')
    expect(w.text()).toContain('How did you hear about MeshHarbor?')
    await fillAndSubmit(w) // the select left empty
    expect(mockApi.post).toHaveBeenCalledWith('/auth/register', expect.any(Object))
    expect(w.text()).not.toMatch(/required/i)
  })

  it('sends the answer as `self_reported`, with or without a campaign', async () => {
    const { w } = await mountAt('/register')
    w.findComponent({ name: 'VSelect' }).vm.$emit('update:modelValue', 'friend')
    await flushPromises()
    await fillAndSubmit(w)
    expect(registerBody().attribution).toEqual({ self_reported: 'friend' })
  })

  it('sends the same attribution from every provider button, and nothing without one', async () => {
    const tagged = await mountAt('/register?utm_source=youtube&utm_campaign=c1&landing_path=%2F')
    tagged.w.findComponent({ name: 'VSelect' }).vm.$emit('update:modelValue', 'youtube')
    await flushPromises()
    for (const [label, p] of [['Google', 'google'], ['Facebook', 'facebook'], ['GitHub', 'github'], ['LinkedIn', 'linkedin'], ['Microsoft', 'microsoft']]) {
      const u = await clickProvider(tagged.w, label!)
      expect(u.pathname).toBe(`/api/oauth/${p}`)
      expect(Object.fromEntries(u.searchParams)).toEqual({
        utm_source: 'youtube',
        utm_campaign: 'c1',
        landing_path: '/',
        self_reported: 'youtube',
      })
    }
    tagged.w.unmount()

    const plain = await mountAt('/register')
    expect((await clickProvider(plain.w, 'Google')).href).toBe('https://meshharbor.itachi.fans/api/oauth/google')
  })

  it('keeps the provider controls BUTTONS, as on the sign-in page (e2e finds them by that role)', async () => {
    const { w } = await mountAt('/register?utm_source=youtube')
    const labels = w.findAll('button').map((b) => b.text().trim())
    expect(labels).toEqual(expect.arrayContaining(['Google', 'Facebook', 'GitHub', 'LinkedIn', 'Microsoft']))
    expect(w.find('a[href^="/api/oauth/"]').exists()).toBe(false)
  })

  it('carries the keys onto the sign-in link, whose provider buttons create accounts too', async () => {
    Object.defineProperty(document, 'referrer', { value: 'https://www.youtube.com/', configurable: true })
    try {
      const tagged = await mountAt('/register?utm_source=youtube&utm_campaign=c1&invite=abc')
      const u = new URL(tagged.w.find('a[href^="/login"]').attributes('href')!, 'https://meshharbor.itachi.fans')
      expect(Object.fromEntries(u.searchParams)).toEqual({
        utm_source: 'youtube',
        utm_campaign: 'c1',
        referrer_host: 'www.youtube.com',
        landing_path: '/register',
      })
      tagged.w.unmount()
    } finally {
      delete (document as { referrer?: string }).referrer
    }
    const plain = await mountAt('/register')
    expect(plain.w.find('a[href^="/login"]').attributes('href')).toBe('/login')
  })

  it('writes nothing to the device: no localStorage, no sessionStorage, no cookie', async () => {
    const { w } = await mountAt('/register?utm_source=youtube&utm_campaign=c1')
    w.findComponent({ name: 'VSelect' }).vm.$emit('update:modelValue', 'reddit')
    await flushPromises()
    await clickProvider(w, 'Google')
    await fillAndSubmit(w)
    expect(setItem).not.toHaveBeenCalled()
    expect(cookieSet).not.toHaveBeenCalled()
  })
})

describe('RegisterView — the signup goal (FR-88)', () => {
  it('fires once, on the server’s yes', async () => {
    const { w } = await mountAt('/register?utm_source=youtube')
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
  it('asks the keyboard not to capitalise the username or the email, and names the new password', async () => {
    const { w } = await mountAt('/register')
    const user = w.find('input[autocomplete="username"]')
    expect(user.attributes('autocapitalize')).toBe('none')
    expect(user.attributes('autocorrect')).toBe('off')
    expect(w.find('input[autocomplete="email"]').attributes('autocapitalize')).toBe('none')
    expect(w.find('input[autocomplete="new-password"]').exists()).toBe(true)
  })
})
