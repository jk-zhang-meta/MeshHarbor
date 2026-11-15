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

const wsConnect = vi.fn()
const wsDisconnect = vi.fn()

vi.mock('@/api/client', () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() },
}))
vi.mock('@/plugins/router', () => ({ default: { push: vi.fn() } }))
vi.mock('@/composables/usePush', () => ({
  subscribePush: vi.fn(() => Promise.resolve()),
  unsubscribePush: vi.fn(() => Promise.resolve()),
}))
vi.mock('@/stores/ws', () => ({
  useWsStore: () => ({ connect: wsConnect, disconnect: wsDisconnect }),
}))

import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import NativeSessionCompleteView from '@/views/auth/NativeSessionCompleteView.vue'

const vuetify = createVuetify({ components, directives })
const mockPost = vi.mocked(api.post)

const VALID_USER = {
  id: '6ad98b618c7a3357a7f9ef69',
  email: 'person@example.test',
  email_verified: true,
  username: 'user_internal',
  display_name: 'Person',
}

async function mountComplete(fullPath: string) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      {
        path: '/native-session-complete',
        name: 'native-session-complete',
        component: NativeSessionCompleteView,
      },
      { path: '/login', name: 'login', component: { template: '<div />' } },
      { path: '/', name: 'dashboard', component: { template: '<div />' } },
      { path: '/my-devices', name: 'my-devices', component: { template: '<div />' } },
      { path: '/device-shares', name: 'device-shares', component: { template: '<div />' } },
      {
        path: '/tenant/:tenantId/agent/:agentId/remote',
        name: 'agent-remote',
        component: { template: '<div />' },
      },
      {
        path: '/device-shares/:shareId/remote',
        name: 'shared-remote',
        component: { template: '<div />' },
      },
    ],
  })
  await router.push(fullPath)
  await router.isReady()
  const pinia = createPinia()
  const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })
  const wrapper = mount(NativeSessionCompleteView, {
    global: { plugins: [vuetify, router, pinia, i18n] },
  })
  await flushPromises()
  return { wrapper, router, auth: useAuthStore(pinia) }
}

beforeEach(() => {
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  localStorage.clear()
  sessionStorage.clear()
  wsConnect.mockReset()
  wsDisconnect.mockReset()
  mockPost.mockReset()
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('NativeSessionCompleteView', () => {
  it('routes every fixed handoff target after validating receipt and verified user', async () => {
    const cases = [
      {
        target: {
          purpose: 'remote',
          tenant_id: '6af73601241993a1ecbaa1f9',
          agent_id: '507f1f77bcf86cd799439011',
        },
        expected: '/tenant/6af73601241993a1ecbaa1f9/agent/507f1f77bcf86cd799439011/remote?desktop=1',
      },
      {
        target: {
          purpose: 'device_share_remote',
          share_id: '507f1f77bcf86cd799439012',
        },
        expected: '/device-shares/507f1f77bcf86cd799439012/remote?desktop=1',
      },
      { target: { purpose: 'my_devices' }, expected: '/my-devices?desktop=1' },
      {
        target: { purpose: 'device_shares_sent' },
        expected: '/device-shares?desktop=1&direction=sent',
      },
      {
        target: { purpose: 'device_shares_received' },
        expected: '/device-shares?desktop=1&direction=received',
      },
      { target: { purpose: 'dashboard' }, expected: '/?desktop=1' },
    ] as const

    for (const c of cases) {
      mockPost.mockResolvedValueOnce({ user: VALID_USER, target: c.target })
      const { router, auth, wrapper } = await mountComplete(
        '/native-session-complete?handoff_id=507f1f77bcf86cd799439099',
      )
      expect(mockPost).toHaveBeenLastCalledWith('/native/handoff/complete', {
        handoff_id: '507f1f77bcf86cd799439099',
      })
      expect(auth.isAuthenticated).toBe(true)
      expect(auth.user?.id).toBe(VALID_USER.id)
      expect(wsConnect).toHaveBeenCalled()
      expect(router.currentRoute.value.fullPath).toBe(c.expected)
      wrapper.unmount()
    }
  })

  it('refuses invalid handoff_id without calling the API or adopting any session', async () => {
    const { wrapper, auth } = await mountComplete('/native-session-complete?handoff_id=not-an-oid')
    expect(mockPost).not.toHaveBeenCalled()
    expect(auth.isAuthenticated).toBe(false)
    expect(wsConnect).not.toHaveBeenCalled()
    expect(wsDisconnect).toHaveBeenCalledTimes(1)
    expect(wrapper.text()).toContain('incomplete or invalid')
  })

  it('refuses unverified user or unexpected target shapes and clears local session hint', async () => {
    mockPost.mockResolvedValueOnce({
      user: { ...VALID_USER, email_verified: false },
      target: { purpose: 'dashboard' },
    })
    const first = await mountComplete('/native-session-complete?handoff_id=507f1f77bcf86cd799439099')
    expect(first.auth.isAuthenticated).toBe(false)
    expect(wsConnect).not.toHaveBeenCalled()
    expect(first.wrapper.find('[role="alert"]').exists()).toBe(true)
    first.wrapper.unmount()

    mockPost.mockResolvedValueOnce({
      user: VALID_USER,
      target: { purpose: 'remote', tenant_id: '../../evil', agent_id: '507f1f77bcf86cd799439011' },
    })
    const second = await mountComplete('/native-session-complete?handoff_id=507f1f77bcf86cd799439099')
    expect(second.auth.isAuthenticated).toBe(false)
    expect(wsConnect).not.toHaveBeenCalled()
    expect(second.wrapper.find('[role="alert"]').exists()).toBe(true)
    second.wrapper.unmount()
  })
})
