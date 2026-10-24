// SPDX-License-Identifier: AGPL-3.0-only
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mount, flushPromises, type VueWrapper } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { createRouter, createMemoryHistory } from 'vue-router'
import { api } from '@/api/client'
import DeviceSharesView from '@/views/account/DeviceSharesView.vue'
import { useAuthStore } from '@/stores/auth'
vi.mock('@/api/client', () => ({ api: { get: vi.fn(), post: vi.fn() } }))
vi.mock('@/stores/auth', async () => {
  const { reactive } = await import('vue')
  const state = reactive<{ user: { id: string } | null }>({ user: { id: '444444444444444444444444' } })
  return { useAuthStore: () => state }
})
const auth = useAuthStore() as unknown as { user: { id: string } | null }
const vuetify = createVuetify({ components, directives })
const grant = '111111111111111111111111', device = '222222222222222222222222', recipient = '555555555555555555555555'
const no = { ssh: false, desktop_view: false, desktop_control: false, files_read: false, files_write: false }
const shared = () => ({ id: grant, device_id: device, owner_user_id: '333333333333333333333333', recipient_user_id: auth.user!.id, permissions: { ...no, ssh: true }, tcp_ports: [], expires_at_ms: Date.now() + 60_000, revoked_at_ms: null, revision: 0 })
const metadata = { id: device, name: 'Fixture shared SSH device', host_pubkey: 'ssh-ed25519 AAAAFIXTUREPUBLICKEY' }
let wrapper: VueWrapper | undefined
async function open() {
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/', component: DeviceSharesView }, { path: '/device-shares/:shareId/remote', name: 'shared-remote', component: { template: '<div />' } }] })
  await router.push('/'); await router.isReady()
  wrapper = mount(DeviceSharesView, { global: { plugins: [vuetify, router], stubs: { VDialog: { props: ['modelValue'], template: '<div v-if="modelValue"><slot /></div>' } } } })
  await flushPromises(); return wrapper
}
async function form() {
  const w = wrapper!
  await w.get('.v-expansion-panel-title').trigger('click'); await flushPromises()
  await w.findAllComponents({ name: 'VTextField' }).find(c => c.props('label') === 'Device ID (one device you own)')!.get('input').setValue(device)
  await w.findAllComponents({ name: 'VTextField' }).find(c => c.props('label') === 'Approved recipient user ID')!.get('input').setValue(recipient)
}
async function checkbox(id: string, value: boolean) { const labels: Record<string, string> = { 'share-desktop-permission': 'View desktop', 'share-ssh-permission': 'SSH shell / exec (native client)', 'share-files-permission': 'Bidirectional file transfer (read AND write)' }; const control = wrapper!.findAllComponents({ name: 'VCheckbox' }).find(c => c.props('label') === labels[id]); expect(control, `explicit checkbox ${labels[id]}`).toBeDefined(); await control!.get('input').setValue(value) }
beforeEach(() => {
  vi.clearAllMocks(); auth.user = { id: '444444444444444444444444' }
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  vi.mocked(api.get).mockImplementation(async path => String(path).endsWith('/ssh') ? metadata : { items: [shared()], total: 1 })
  vi.mocked(api.post).mockResolvedValue({})
})
afterEach(() => { wrapper?.unmount(); wrapper = undefined; vi.unstubAllGlobals() })
describe('single-device SSH share authorization and truthful native instructions', () => {
  it('creates an SSH-only grant without silently enabling desktop, files or TCP ports', async () => {
    await open(); await form(); await checkbox('share-desktop-permission', false); await checkbox('share-ssh-permission', true)
    await wrapper!.get('form').trigger('submit'); await flushPromises()
    expect(api.post).toHaveBeenCalledWith('/device-shares', { device_id: device, recipient_user_id: recipient, permissions: { ...no, ssh: true }, tcp_ports: [], expires_in_secs: 86400 })
  })
  it('still refuses an entirely empty service selection', async () => {
    await open(); await form(); await checkbox('share-desktop-permission', false)
    await wrapper!.get('form').trigger('submit'); await flushPromises()
    expect(api.post).not.toHaveBeenCalled(); expect(wrapper!.text()).toContain('a supported capability')
  })
  it('preserves explicit desktop and bidirectional file permissions when SSH is also selected', async () => {
    await open(); await form(); await checkbox('share-ssh-permission', true); await checkbox('share-files-permission', true)
    await wrapper!.get('form').trigger('submit'); await flushPromises()
    expect(api.post).toHaveBeenCalledWith('/device-shares', expect.objectContaining({ permissions: { ...no, ssh: true, desktop_view: true, files_read: true, files_write: true }, tcp_ports: [] }))
  })
  it('gives an SSH-only recipient a separate metadata-checked native instruction entry, not desktop/terminal access', async () => {
    await open(); await wrapper!.get('[data-testid="shared-ssh-open"]').trigger('click'); await flushPromises()
    expect(api.get).toHaveBeenCalledWith(`/device-shares/${grant}/ssh`)
    expect(wrapper!.get('[data-testid="shared-ssh-device"]').text()).toContain(metadata.name)
    expect(wrapper!.get('[data-testid="shared-ssh-host-key"]').text()).toBe(metadata.host_pubkey)
    const text = wrapper!.get('[data-testid="shared-ssh-instructions"]').text()
    expect(text).toContain('not an SSH session or a browser terminal'); expect(text).toContain('hidden terminal prompt'); expect(text).not.toContain('Native login / automatic handoff is not implemented here')
    expect(wrapper!.get('[data-testid="shared-ssh-command"]').text()).toContain(`--share ${grant} --login --username YOUR_ACCOUNT_USERNAME`)
    expect(api.post).not.toHaveBeenCalled()
  })
  it('disables SSH entry for expired/revoked grants and omits it without explicit SSH permission', async () => {
    const a = { ...shared(), expires_at_ms: Date.now() - 1 }, b = { ...shared(), id: '666666666666666666666666', revoked_at_ms: 1 }, c = { ...shared(), id: '777777777777777777777777', permissions: { ...no, desktop_view: true } }
    vi.mocked(api.get).mockResolvedValue({ items: [a, b, c], total: 3 }); await open()
    const buttons = wrapper!.findAll('[data-testid="shared-ssh-open"]'); expect(buttons).toHaveLength(2); expect(buttons.every(b => b.attributes('disabled') !== undefined)).toBe(true)
    expect(api.get).toHaveBeenCalledTimes(1)
  })
  it('shows current server denial and exposes no launch details after revocation', async () => {
    vi.mocked(api.get).mockImplementation(async path => { if (String(path).endsWith('/ssh')) throw new Error('Share no longer permits SSH'); return { items: [shared()], total: 1 } })
    await open(); await wrapper!.get('[data-testid="shared-ssh-open"]').trigger('click'); await flushPromises()
    expect(wrapper!.get('[data-testid="shared-ssh-error"]').text()).toContain('Share no longer permits SSH')
    expect(wrapper!.find('[data-testid="shared-ssh-command"]').exists()).toBe(false)
  })
  it('does not promote metadata for a different device to a usable handoff', async () => {
    vi.mocked(api.get).mockImplementation(async path => String(path).endsWith('/ssh') ? { ...metadata, id: '888888888888888888888888' } : { items: [shared()], total: 1 })
    await open(); await wrapper!.get('[data-testid="shared-ssh-open"]').trigger('click'); await flushPromises()
    expect(wrapper!.get('[data-testid="shared-ssh-error"]').text()).toContain('shared device identity changed')
    expect(wrapper!.find('[data-testid="shared-ssh-command"]').exists()).toBe(false)
  })
  it('retains expired and revoked sharing history with an explicit state and grant revision', async () => {
    const expired = { ...shared(), expires_at_ms: Date.now() - 1000 }, revoked = { ...shared(), id: '666666666666666666666666', created_at_ms: Date.now() - 100000, revoked_at_ms: Date.now() - 2000, revision: 1 }
    vi.mocked(api.get).mockResolvedValue({ items: [expired, revoked], total: 2 }); await open()
    expect(wrapper!.get(`[data-testid="share-state-${grant}"]`).text()).toContain('Expired')
    expect(wrapper!.get('[data-testid="share-state-666666666666666666666666"]').text()).toContain('Revoked')
    expect(wrapper!.text()).toContain('2 retained sharing records'); expect(wrapper!.text()).toContain('Not reported by this server')
  })
  it('drops pending SSH metadata when the account changes and leaves no old dialog', async () => {
    let resolve!: (value: typeof metadata) => void
    vi.mocked(api.get).mockImplementation(async path => String(path).endsWith('/ssh') ? await new Promise<typeof metadata>(r => { resolve = r }) : { items: [shared()], total: 1 })
    await open(); await wrapper!.get('[data-testid="shared-ssh-open"]').trigger('click'); await flushPromises()
    auth.user = { id: '999999999999999999999999' }; await flushPromises(); resolve(metadata); await flushPromises()
    expect(wrapper!.find('[data-testid="shared-ssh-instructions"]').exists()).toBe(false)
    expect(wrapper!.text()).not.toContain(metadata.name)
  })
})
