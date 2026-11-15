// SPDX-License-Identifier: AGPL-3.0-only
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { createMemoryHistory, createRouter } from 'vue-router'
import { createPinia } from 'pinia'
import { createI18n } from 'vue-i18n'
import en from '@/locales/en.json'

const wsDisconnect = vi.fn()

vi.mock('@/api/client', () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() },
  ApiError: class ApiError extends Error {
    status: number
    constructor(message: string, status: number) {
      super(message)
      this.status = status
    }
  },
}))
vi.mock('@/plugins/router', () => ({ default: { push: vi.fn() } }))
vi.mock('@/composables/usePush', () => ({
  subscribePush: vi.fn(() => Promise.resolve()),
  unsubscribePush: vi.fn(() => Promise.resolve()),
}))
vi.mock('@/stores/ws', () => ({
  useWsStore: () => ({ connect: vi.fn(), disconnect: wsDisconnect }),
}))

import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import VerifyEmailChangeView from '@/views/auth/VerifyEmailChangeView.vue'
import DeviceLoginView from '@/views/account/DeviceLoginView.vue'

const vuetify = createVuetify({ components, directives })
const mockPost = vi.mocked(api.post)

beforeEach(() => {
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  )
  localStorage.clear()
  sessionStorage.clear()
  mockPost.mockReset()
  wsDisconnect.mockReset()
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('VerifyEmailChangeView', () => {
  it('scrubs #token fragment immediately and never auto-submits until explicit click', async () => {
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [
        {
          path: '/verify-email-change',
          name: 'verify-email-change',
          component: VerifyEmailChangeView,
        },
        { path: '/login', name: 'login', component: { template: '<div />' } },
      ],
    })
    await router.push('/verify-email-change?request_id=507f1f77bcf86cd799439055#token=secret-proof-token')
    await router.isReady()
    const pinia = createPinia()
    const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })
    const wrapper = mount(VerifyEmailChangeView, {
      global: { plugins: [vuetify, router, pinia, i18n] },
    })
    await flushPromises()

    expect(router.currentRoute.value.hash).toBe('')
    expect(mockPost).not.toHaveBeenCalled()

    mockPost.mockResolvedValueOnce({ email: 'new@example.test', email_verified: true })
    await wrapper.find('button').trigger('click')
    await flushPromises()

    expect(mockPost).toHaveBeenCalledTimes(1)
    expect(mockPost).toHaveBeenCalledWith('/auth/email-change/confirm', {
      request_id: '507f1f77bcf86cd799439055',
      token: 'secret-proof-token',
    })
    expect(wsDisconnect).toHaveBeenCalled()
    expect(wrapper.text()).toContain('new@example.test')
    wrapper.unmount()
  })
})

describe('DeviceLoginView — explicit user_session consent & verified email gate', () => {
  it('blocks user_session approval when account email is unverified, and enables it when verified', async () => {
    mockPost.mockResolvedValueOnce({
      purpose: 'user_session',
      requested_scopes: ['user_session'],
      personal_device: false,
      device: { name: 'Workstation', os: 'linux' },
      client: '127.0.0.1',
      requested_at_ms: Date.now(),
      expires_at_ms: Date.now() + 300_000,
    })

    const router = createRouter({
      history: createMemoryHistory(),
      routes: [
        { path: '/device-login', name: 'device-login', component: DeviceLoginView },
        { path: '/profile/edit', name: 'profile-edit', component: { template: '<div />' } },
      ],
    })
    await router.push('/device-login?code=BCDFG-HJKLM')
    await router.isReady()
    const pinia = createPinia()
    const auth = useAuthStore(pinia)
    auth.completeNativeHandoff({
      id: '6ad98b618c7a3357a7f9ef69',
      email: 'owner@meshharbor.invalid',
      email_verified: false,
      username: 'owner',
      display_name: 'Owner',
        })
    const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })
    const wrapper = mount(DeviceLoginView, {
      global: { plugins: [vuetify, router, pinia, i18n] },
    })
    await flushPromises()

    expect(wrapper.find('[data-testid="device-login-user-session"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="device-login-email-required"]').exists()).toBe(true)
    const approveBtn = wrapper.find('[data-testid="device-login-approve"]')
    expect(approveBtn.attributes('disabled')).toBeDefined()

    auth.completeNativeHandoff({
      id: '6ad98b618c7a3357a7f9ef69',
      email: 'person@example.test',
      email_verified: true,
      username: 'owner',
      display_name: 'Owner',
        })
    await flushPromises()
    expect(wrapper.find('[data-testid="device-login-email-required"]').exists()).toBe(false)
    expect(approveBtn.attributes('disabled')).toBeUndefined()

    mockPost.mockResolvedValueOnce({ status: 'approved' })
    await approveBtn.trigger('click')
    await flushPromises()
    expect(mockPost).toHaveBeenLastCalledWith('/native/device-login/decision', {
      user_code: 'BCDFG-HJKLM',
      approve: true,
    })
    wrapper.unmount()
  })
})
