// SPDX-License-Identifier: AGPL-3.0-only
import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { createPinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { useAuthStore } from '@/stores/auth'
import NativeSshApprovalView from '@/views/account/NativeSshApprovalView.vue'

let wrapper: VueWrapper | undefined
afterEach(() => {
  wrapper?.unmount()
  wrapper = undefined
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  localStorage.clear()
  sessionStorage.clear()
})

describe('explicit native shared SSH browser approval', () => {
  it('previews the actual scope without approving and posts its server revision only on approval', async () => {
    const authorization = '111111111111111111111111'
    const userCode = 'AbCdEfGhIj_9'
    const recipient = {
      id: '222222222222222222222222',
      username: 'fixture-recipient',
      display_name: 'Fixture Recipient',
      email: 'fixture-recipient@example.test',
    }
    const preview = {
      authorization_id: authorization,
      recipient,
      device: { id: '333333333333333333333333', name: 'Fixture SSH Host', os: 'linux' },
      ssh_account: 'fixture_os_account',
      request_expires_at_ms: Date.parse('2099-01-02T03:04:05.000Z'),
      session_secs: 900,
      // Opaque fixture standing in for a SERVER-issued binding of the full
      // displayed scope and relevant share/account/policy revisions. The UI
      // must echo it; it must not calculate its own approval authority.
      scope_revision: 'fixture-server-issued-complete-scope-revision',
    }
    const base = `/api/native/share-ssh/authorizations/${authorization}`
    const calls: { path: string; method: string; body: unknown; headers: Headers }[] = []
    const fetchBoundary = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input)
      const path = new URL(url, window.location.href).pathname
      const method = init?.method ?? 'GET'
      const body = typeof init?.body === 'string' ? JSON.parse(init.body) : null
      calls.push({ path, method, body, headers: new Headers(init?.headers) })
      let data: unknown
      if (path === `${base}/preview` && method === 'POST') data = preview
      else if (path === `${base}/decision` && method === 'POST') data = { status: 'approved' }
      else if (path === '/api/auth/me' && method === 'GET') data = recipient
      else throw new Error(`Unexpected approval network request: ${method} ${path}`)
      return new Response(JSON.stringify(data), {
        status: 200,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
      })
    })
    vi.stubGlobal('fetch', fetchBoundary)
    // A jsdom platform shim, not a replacement for component/store behavior.
    vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
    localStorage.clear()
    sessionStorage.clear()
    localStorage.setItem('meshharbor-signed-in', '1')
    const pinia = createPinia()
    useAuthStore(pinia).user = recipient
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: '/native/share-ssh/approve', component: NativeSshApprovalView }],
    })
    await router.push('/native/share-ssh/approve')
    await router.isReady()
    const locationBefore = window.location.href
    const storageWrites = vi.spyOn(Storage.prototype, 'setItem')
    wrapper = mount(NativeSshApprovalView, {
      global: { plugins: [pinia, router, createVuetify({ components, directives })] },
    })
    await flushPromises()
    const decisions = () => calls.filter(c => c.path === `${base}/decision`)
    expect(decisions()).toHaveLength(0)
    expect(calls.filter(c => c.path === `${base}/preview`)).toHaveLength(0)

    await wrapper.get('[data-testid="native-ssh-authorization-id"] input').setValue(authorization)
    await wrapper.get('[data-testid="native-ssh-user-code"] input').setValue(userCode)
    await wrapper.get('[data-testid="native-ssh-preview"]').trigger('click')
    await flushPromises()
    expect(calls.filter(c => c.path === `${base}/preview`)).toEqual([
      expect.objectContaining({ method: 'POST', body: { user_code: userCode } }),
    ])
    expect(decisions()).toHaveLength(0)
    const shownRecipient = wrapper.get('[data-testid="native-ssh-recipient"]').text()
    expect(shownRecipient).toContain(recipient.username)
    expect(shownRecipient).toContain(recipient.id)
    const shownDevice = wrapper.get('[data-testid="native-ssh-device"]').text()
    expect(shownDevice).toContain(preview.device.name)
    expect(shownDevice).toContain(preview.device.id)
    expect(wrapper.get('[data-testid="native-ssh-os-account"]').text()).toContain(preview.ssh_account)
    const expiry = wrapper.get('[data-testid="native-ssh-request-expiry"]')
    expect(expiry.attributes('datetime')).toBe(new Date(preview.request_expires_at_ms).toISOString())
    expect(expiry.text()).toContain('2099')
    expect(wrapper.get('[data-testid="native-ssh-session-duration"]').text()).toContain('900')

    await wrapper.get('[data-testid="native-ssh-approve"]').trigger('click')
    await flushPromises()
    expect(decisions()).toEqual([
      expect.objectContaining({
        method: 'POST',
        body: { user_code: userCode, approve: true, expected_scope_revision: preview.scope_revision },
      }),
    ])
    expect(wrapper.find('[data-testid="native-ssh-approved"]').exists()).toBe(true)
    expect(calls.every(c => !c.headers.has('Authorization'))).toBe(true)
    expect(storageWrites).not.toHaveBeenCalled()
    expect(router.currentRoute.value.fullPath).toBe('/native/share-ssh/approve')
    expect(window.location.href).toBe(locationBefore)
    // Exact bodies, unchanged URL and no storage writes exclude password,
    // grant, device_code or verifier handoff. No actual cookies or credentials
    // are supplied. The absent backend preview/revision contract means this
    // component test is not an end-to-end authorization result.
  })
})
