// SPDX-License-Identifier: AGPL-3.0-only
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mount, flushPromises, type VueWrapper } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { createRouter, createMemoryHistory } from 'vue-router'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import PersonalDevicesView from '@/views/account/PersonalDevicesView.vue'
vi.mock('@/api/client', () => ({ api: { get: vi.fn() } }))
vi.mock('@/stores/auth', async () => { const { reactive } = await import('vue'); const state = reactive<{ user: { id: string } | null }>({ user: { id: 'account-a' } }); return { useAuthStore: () => state } })
const auth = useAuthStore() as unknown as { user: { id: string } | null }
const vuetify = createVuetify({ components, directives })
const tenant = '111111111111111111111111', id = '222222222222222222222222'
const empty = { active_devices: 0, active_grants: 0, total_records: 0, expired_records: 0, revoked_records: 0 }
const counts = () => ({ own_devices: 1, received: { active_devices: 1, active_grants: 2, total_records: 4, expired_records: 1, revoked_records: 1 }, sent: { ...empty } })
const page = () => ({ items: [{ id, tenant_id: tenant, name: 'My registered box', machine_name: 'registry-name-not-hostname', os: 'linux', status: 'online' }], page: 1, total: 1 })
let wrapper: VueWrapper | undefined
async function open(query = '') {
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/', component: { template: '<div />' } }, { path: '/tenant/:tenantId/agent/:agentId/remote', name: 'agent-remote', component: { template: '<div />' } }] })
  await router.push('/' + query); await router.isReady()
  wrapper = mount(PersonalDevicesView, { global: { plugins: [vuetify, router], stubs: { DeviceSharesView: { template: '<div data-testid="sharing-records-child" />' } } } })
  await flushPromises(); return wrapper
}
beforeEach(() => { vi.clearAllMocks(); auth.user = { id: 'account-a' }; vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} }); vi.mocked(api.get).mockImplementation(async path => String(path).endsWith('/summary') ? counts() : page()) })
afterEach(() => { wrapper?.unmount(); wrapper = undefined; vi.restoreAllMocks(); vi.unstubAllGlobals() })
describe('personal devices and authoritative sharing record counts', () => {
  it('shows actual personal totals and separates distinct devices, grants and retained records', async () => {
    const w = await open()
    expect(api.get).toHaveBeenCalledWith('/account/devices?page=1&per_page=25')
    expect(w.get('[data-testid="owned-device-count"]').text()).toBe('1')
    expect(w.get('[data-testid="received-device-count"]').text()).toBe('1')
    expect(w.get('[data-testid="received-record-count"]').text()).toContain('2 current grants · 4 retained records')
    expect(w.text()).toContain('registry-name-not-hostname'); expect(w.find('[data-testid="sharing-records-child"]').exists()).toBe(true)
    expect(w.text()).toContain('not proof that a device is online')
  })
  it('does not invent zero counts when the server is missing the new API', async () => {
    vi.mocked(api.get).mockRejectedValue(new Error('404 missing endpoint'))
    const w = await open(); expect(w.get('[data-testid="owned-device-count"]').text()).toBe('—'); expect(w.find('[data-testid="personal-devices-error"]').exists()).toBe(true)
  })
  it('clears old account data and discards late responses after an identity change', async () => {
    let resolvePage!: (value: ReturnType<typeof page>) => void, resolveCounts!: (value: ReturnType<typeof counts>) => void
    vi.mocked(api.get).mockImplementation(path => new Promise(resolve => { if (String(path).endsWith('/summary')) resolveCounts = resolve; else resolvePage = resolve }))
    const w = await open(); auth.user = null; await flushPromises(); resolvePage(page()); resolveCounts(counts()); await flushPromises()
    expect(w.text()).not.toContain('My registered box'); expect(w.get('[data-testid="owned-device-count"]').text()).toBe('—')
  })
  it('retains last same-account data with an explicit stale warning when refresh fails', async () => {
    const w = await open(); vi.mocked(api.get).mockRejectedValue(new Error('offline')); await w.get('[data-testid="personal-refresh"]').trigger('click'); await flushPromises()
    expect(w.get('[data-testid="owned-device-count"]').text()).toBe('1'); expect(w.get('[data-testid="personal-devices-error"]').text()).toContain('may be stale')
  })
  it('rejects inconsistent sharing counts instead of presenting them as real inventory', async () => {
    vi.mocked(api.get).mockImplementation(async path => String(path).endsWith('/summary') ? { ...counts(), received: { ...empty, active_devices: 9 } } : page())
    const w = await open(); expect(w.get('[data-testid="received-device-count"]').text()).toBe('—'); expect(w.find('[data-testid="personal-devices-error"]').exists()).toBe(true)
  })
  it('uses an external viewer link only for the embedded desktop account context', async () => {
    const w = await open('?desktop=1'); const link = w.findAll('a').find(a => a.text() === 'Open desktop')!
    expect(link.attributes('target')).toBe('_blank'); expect(link.attributes('rel')).toContain('noopener'); expect(link.attributes('href')).toContain(`/tenant/${tenant}/agent/${id}/remote`)
  })
})
