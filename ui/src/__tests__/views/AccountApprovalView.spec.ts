// SPDX-License-Identifier: AGPL-3.0-only
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mount, flushPromises, type VueWrapper } from '@vue/test-utils'
import { createPinia } from 'pinia'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { api } from '@/api/client'
import AccountApprovalView from '@/views/account/AccountApprovalView.vue'
import { useAccountApprovalStore } from '@/stores/accountApproval'
vi.mock('@/api/client', () => ({ api: { get: vi.fn(), post: vi.fn() } }))
vi.mock('@/stores/auth', () => ({ useAuthStore: () => ({ user: { id: 'owner-id' } }) }))
const vuetify = createVuetify({ components, directives })
const account = { user_id: 'alice-id', username: 'alice', email: 'alice@example.test', state: 'approved', revision: 3, email_verified: true }
let wrapper: VueWrapper | undefined
function open() {
  const pinia = createPinia()
  wrapper = mount(AccountApprovalView, { global: { plugins: [pinia, vuetify], stubs: { VDialog: { props: ['modelValue'], template: '<div v-if="modelValue"><slot /></div>' } } } })
  return { wrapper, store: useAccountApprovalStore(pinia) }
}
beforeEach(() => {
  vi.clearAllMocks()
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
})
afterEach(() => { wrapper?.unmount(); wrapper = undefined; vi.unstubAllGlobals() })
describe('central owner approval console', () => {
  it('shows server-authorized global review controls without a tenant', async () => {
    vi.mocked(api.get).mockImplementation(async (path) => path === '/auth/approval/access'
      ? { enabled: true, is_owner: true } : { items: [account], total: 1, page: 1 })
    const { wrapper } = open()
    await flushPromises()
    expect(wrapper.text()).toContain('Account approvals')
    expect(wrapper.text()).toContain('alice@example.test')
    expect(wrapper.text()).toContain('Pending review')
    expect(wrapper.find('[data-testid="suspend-account"]').exists()).toBe(true)
  })
  it('refuses nonowners and never requests the account queue', async () => {
    vi.mocked(api.get).mockResolvedValue({ enabled: true, is_owner: false })
    const { wrapper } = open()
    await flushPromises()
    expect(wrapper.get('[data-testid="approval-access-denied"]').text()).toContain('Only the central approval owner')
    expect(wrapper.find('[data-testid="suspend-account"]').exists()).toBe(false)
    expect(api.get).toHaveBeenCalledTimes(1)
  })
  it('requires a visible confirmation before sending a suspension with the current revision', async () => {
    vi.mocked(api.get).mockImplementation(async (path) => path === '/auth/approval/access'
      ? { enabled: true, is_owner: true } : { items: [account], total: 1, page: 1 })
    vi.mocked(api.post).mockResolvedValue({ ...account, state: 'suspended', revision: 4 })
    const { wrapper } = open()
    await flushPromises()
    await wrapper.get('[data-testid="suspend-account"]').trigger('click')
    expect(wrapper.text()).toContain('This revokes account admission')
    expect(api.post).not.toHaveBeenCalled()
    await wrapper.get('[data-testid="confirm-account-review"]').trigger('click')
    await flushPromises()
    expect(api.post).toHaveBeenCalledWith('/auth/approval/alice-id', { state: 'suspended', expected_revision: 3 })
  })
  it('on a conflicting review closes confirmation and requires a fresh review', async () => {
    vi.mocked(api.get).mockImplementation(async (path) => path === '/auth/approval/access'
      ? { enabled: true, is_owner: true } : { items: [account], total: 1, page: 1 })
    vi.mocked(api.post).mockRejectedValue(Object.assign(new Error('stale revision'), { status: 409 }))
    const { wrapper } = open()
    await flushPromises()
    await wrapper.get('[data-testid="suspend-account"]').trigger('click')
    await wrapper.get('[data-testid="confirm-account-review"]').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('review its current state before trying again')
    expect(wrapper.find('[data-testid="confirm-account-review"]').exists()).toBe(false)
    expect(api.post).toHaveBeenCalledTimes(1)
  })
})
