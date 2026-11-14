// SPDX-License-Identifier: AGPL-3.0-only
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { api } from '@/api/client'
import DeviceFeatureSummary from '@/components/admin/DeviceFeatureSummary.vue'
import DeviceLoginView from '@/views/account/DeviceLoginView.vue'
import { deviceFeatureKeys, enabledDeviceFeatures, type DeviceAccessFeatures } from '@/utils/deviceFeatures'

vi.mock('@/api/client', () => ({ api: { post: vi.fn() }, ApiError: class extends Error { status = 500 } }))
vi.mock('vue-router', () => ({ useRoute: () => ({ query: { code: 'BCDFG-HJKLM' } }) }))
vi.mock('@/stores/tenant', () => ({ useTenantStore: () => ({ tenants: [{ id: 'org1', name: 'My devices' }], current: { id: 'org1' }, fetchTenants: vi.fn() }) }))

const off = Object.fromEntries(deviceFeatureKeys.map(key => [key, false])) as DeviceAccessFeatures
const vuetify = createVuetify({ components, directives })
let wrapper: VueWrapper | undefined
beforeEach(() => {
  vi.clearAllMocks()
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
})
afterEach(() => { wrapper?.unmount(); wrapper = undefined; vi.unstubAllGlobals() })

describe('host-selected feature presentation', () => {
  it('does not invent all-on rights for legacy or malformed selections', () => {
    for (const value of [null, undefined, [], {}, { ...off, ssh: 'true' }]) expect(enabledDeviceFeatures(value)).toBeNull()
  })
  it('distinguishes a deliberate empty selection from a legacy record', () => {
    expect(enabledDeviceFeatures(off)).toEqual([])
    wrapper = mount(DeviceFeatureSummary, { props: { features: off } })
    expect(wrapper.text()).toContain('No features allowed')
  })
  it('shows the exact subset without turning SSH into a desktop grant', () => {
    const selection = { ...off, ssh: true }
    expect(enabledDeviceFeatures(selection)).toEqual(['ssh'])
    wrapper = mount(DeviceFeatureSummary, { props: { features: selection } })
    expect(wrapper.text()).toContain('SSH shell')
    expect(wrapper.text()).not.toContain('View desktop')
    expect(wrapper.text()).not.toContain('Remote commands')
  })
  it('discloses the scope of network services instead of promising port isolation', () => {
    wrapper = mount(DeviceFeatureSummary, { props: { features: { ...off, network: true } } })
    expect(wrapper.text()).toContain('Network access includes system services')
  })
  it('does not misrepresent a saved all-off selection as completed live revocation', async () => {
    wrapper = mount(DeviceFeatureSummary, { props: { features: off, revocationPending: true } })
    expect(wrapper.get('[data-testid="device-feature-revocation-pending"]').text()).toContain('NOT confirmed')
    await wrapper.setProps({ revocationPending: false })
    expect(wrapper.find('[data-testid="device-feature-revocation-pending"]').exists()).toBe(false)
  })
})

async function login(personal?: boolean) {
  vi.mocked(api.post).mockResolvedValueOnce({
    device: { name: 'My laptop', os: 'linux' }, client: '127.0.0.x',
    expires_at_ms: Date.now() + 600_000, requested_at_ms: Date.now(),
    ...(personal === undefined ? {} : { personal_device: personal }),
  })
  wrapper = mount(DeviceLoginView, { global: { plugins: [vuetify] } })
  await flushPromises()
  return wrapper
}

describe('personal device approval disclosure', () => {
  it('discloses account scope and root/SYSTEM before approving a personal profile', async () => {
    const w = await login(true)
    const warning = w.get('[data-testid="device-login-personal-access"]').text()
    expect(warning).toContain('not for every organization member')
    expect(warning).toContain('root or SYSTEM')
    expect(warning).toContain('explicit local refusals')
    vi.mocked(api.post).mockResolvedValueOnce({ status: 'approved' })
    await w.get('[data-testid="device-login-approve"]').trigger('click')
    await flushPromises()
    expect(api.post).toHaveBeenLastCalledWith('/native/device-login/decision', {
      user_code: 'BCDFG-HJKLM', approve: true, tenant_id: 'org1',
    })
    expect(w.find('[data-testid="device-login-approved"]').exists()).toBe(true)
  })
  it('does not promise new defaults when an older server omits the capability', async () => {
    const w = await login()
    expect(w.find('[data-testid="device-login-preview"]').exists()).toBe(true)
    expect(w.find('[data-testid="device-login-personal-access"]').exists()).toBe(false)
  })
})
