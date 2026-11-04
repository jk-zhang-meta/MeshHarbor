// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-88 (#1790) — the sign-in page's part in attribution. A provider "sign-in"
// creates the account when there is none, and it then counts as a `signup`,
// so its buttons must carry the campaign exactly as the register view's do.
// The server attaches it only to an account it creates. The link to the
// register page carries the same keys, and nothing is written to the device.
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
vi.mock('@/utils/attribution', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/utils/attribution')>()),
  startOAuth: vi.fn(),
}))

import LoginView from '@/views/auth/LoginView.vue'
import { oauthStartUrl, startOAuth } from '@/utils/attribution'

const vuetify = createVuetify({ components, directives })
const mockStartOAuth = vi.mocked(startOAuth)

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

/** Click a provider button; the URL the browser would be sent to. */
async function clickProvider(w: Awaited<ReturnType<typeof mountAt>>, label: string): Promise<URL> {
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

beforeEach(() => {
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  )
  Object.defineProperty(document, 'referrer', { value: 'https://www.youtube.com/', configurable: true })
  setItem = vi.spyOn(Storage.prototype, 'setItem')
  cookieSet = vi.spyOn(Document.prototype, 'cookie', 'set')
})

afterEach(() => {
  delete (document as { referrer?: string }).referrer
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  mockStartOAuth.mockReset()
})

describe('LoginView — attribution (FR-88)', () => {
  it('carries a campaign carried here onto every provider button', async () => {
    // Reached from the homepage's "Log in" link: attribution.js put these on it.
    const w = await mountAt('/login?utm_source=youtube&utm_campaign=c1&referrer_host=www.youtube.com&landing_path=%2F')
    for (const [label, p] of [['Google', 'google'], ['Facebook', 'facebook'], ['GitHub', 'github'], ['LinkedIn', 'linkedin'], ['Microsoft', 'microsoft']]) {
      const u = await clickProvider(w, label!)
      expect(u.pathname).toBe(`/api/oauth/${p}`)
      expect(Object.fromEntries(u.searchParams)).toEqual({
        utm_source: 'youtube',
        utm_campaign: 'c1',
        referrer_host: 'www.youtube.com',
        landing_path: '/',
      })
    }
  })

  it('works out where the journey began when the visitor landed here directly', async () => {
    const u = await clickProvider(await mountAt('/login?ref=tiktok-bio'), 'Google')
    expect(Object.fromEntries(u.searchParams)).toEqual({ utm_source: 'tiktok-bio', referrer_host: 'www.youtube.com', landing_path: '/login' })
  })

  it('starts a plain sign-in, exactly as before, without a campaign', async () => {
    const u = await clickProvider(await mountAt('/login'), 'Google')
    expect(u.href).toBe('https://meshharbor.itachi.fans/api/oauth/google')
    expect(mockStartOAuth).toHaveBeenCalledWith('google', undefined)
  })

  it('keeps the provider controls BUTTONS (e2e/oauth.spec.ts finds them by that role)', async () => {
    const w = await mountAt('/login?utm_source=youtube')
    expect(w.findAll('button').map((b) => b.text().trim())).toEqual(
      expect.arrayContaining(['Google', 'Facebook', 'GitHub', 'LinkedIn', 'Microsoft']),
    )
    expect(w.find('a[href^="/api/oauth/"]').exists()).toBe(false)
  })

  it('carries the keys onto the register link, and leaves it bare without a campaign', async () => {
    const tagged = await mountAt('/login?utm_source=youtube&utm_medium=video')
    const u = new URL(tagged.find('a[href^="/register"]').attributes('href')!, 'https://meshharbor.itachi.fans')
    expect(Object.fromEntries(u.searchParams)).toEqual({
      utm_source: 'youtube',
      utm_medium: 'video',
      referrer_host: 'www.youtube.com',
      landing_path: '/login',
    })
    tagged.unmount()
    const plain = await mountAt('/login')
    expect(plain.find('a[href^="/register"]').attributes('href')).toBe('/register')
  })

  it('writes nothing to the device', async () => {
    await clickProvider(await mountAt('/login?utm_source=youtube&utm_campaign=c1'), 'Google')
    expect(setItem).not.toHaveBeenCalled()
    expect(cookieSet).not.toHaveBeenCalled()
  })
})

// FR-116 P7 — iOS capitalises the first letter of a text field by default,
// and the server matches the username exactly: "goran" typed on an iPhone
// arrived as "Goran" and was refused. The attributes must reach the <input>.
describe('LoginView — on a phone keyboard (FR-116)', () => {
  it('asks the keyboard not to capitalise or correct the username', async () => {
    const w = await mountAt('/login')
    const user = w.find('input[autocomplete="username"]')
    expect(user.exists()).toBe(true)
    expect(user.attributes('autocapitalize')).toBe('none')
    expect(user.attributes('autocorrect')).toBe('off')
    expect(user.attributes('spellcheck')).toBe('false')
  })

  it('names the password for the password manager', async () => {
    const w = await mountAt('/login')
    expect(w.find('input[autocomplete="current-password"]').exists()).toBe(true)
  })
})
