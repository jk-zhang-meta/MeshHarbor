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
const grant = '111111111111111111111111', device = '222222222222222222222222', recipient = 'share_recipient'
const ownedPage = { items: [{ id: device, name: 'Fixture box', status: 'online' }], page: 1, total: 1 }
const no = { ssh: false, desktop_view: false, desktop_control: false, files_read: false, files_write: false }
const shared = () => ({ id: grant, device_id: device, owner_user_id: '333333333333333333333333', recipient_user_id: auth.user!.id, permissions: { ...no, ssh: true }, tcp_ports: [], expires_at_ms: Date.now() + 60_000, revoked_at_ms: null, revision: 0 })
const deviceAccounts = { accounts: [{ name: 'alice', uid: 1000, admin: false }, { name: 'ops', uid: 1001, admin: true }] }
const metadata = { id: device, name: 'Fixture shared SSH device', host_pubkey: 'ssh-ed25519 AAAAFIXTUREPUBLICKEY' }
let wrapper: VueWrapper | undefined
async function open(at = '/') {
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/', component: DeviceSharesView }, { path: '/device-shares/:shareId/remote', name: 'shared-remote', component: { template: '<div />' } }] })
  await router.push(at); await router.isReady()
  wrapper = mount(DeviceSharesView, { global: { plugins: [vuetify, router], stubs: { VDialog: { props: ['modelValue'], template: '<div v-if="modelValue"><slot /></div>' } } } })
  await flushPromises(); return wrapper
}
async function form() {
  const w = wrapper!
  await w.get('.v-expansion-panel-title').trigger('click'); await flushPromises()
  await w.findAllComponents({ name: 'VSelect' }).find(c => c.props('label') === 'Device (one you own)')!.setValue(device)
  await w.findAllComponents({ name: 'VTextField' }).find(c => c.props('label') === 'Recipient username or email')!.get('input').setValue(recipient)
}
async function account(name: string) { await wrapper!.get('[data-testid="share-ssh-account"] input').setValue(name) }
async function checkbox(id: string, value: boolean) { const labels: Record<string, string> = { 'share-desktop-permission': 'View desktop', 'share-ssh-permission': 'SSH shell / exec (native client)', 'share-files-permission': 'Bidirectional file transfer (read AND write)' }; const control = wrapper!.findAllComponents({ name: 'VCheckbox' }).find(c => c.props('label') === labels[id]); expect(control, `explicit checkbox ${labels[id]}`).toBeDefined(); await control!.get('input').setValue(value) }
beforeEach(() => {
  vi.clearAllMocks(); auth.user = { id: '444444444444444444444444' }
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  vi.mocked(api.get).mockImplementation(async path => String(path).endsWith('/ssh') ? metadata : String(path).endsWith('/local-accounts') ? deviceAccounts : String(path).startsWith('/account/devices') ? ownedPage : { items: [shared()], total: 1 })
  vi.mocked(api.post).mockResolvedValue({})
})
afterEach(() => { wrapper?.unmount(); wrapper = undefined; vi.unstubAllGlobals() })
describe('single-device SSH share authorization and truthful native instructions', () => {
  it('creates an SSH-only grant without silently enabling desktop, files or TCP ports', async () => {
    await open(); await form(); await checkbox('share-desktop-permission', false); await checkbox('share-ssh-permission', true); await account(' alice ')
    await wrapper!.get('form').trigger('submit'); await flushPromises()
    expect(api.post).toHaveBeenCalledWith('/device-shares', { device_id: device, recipient, permissions: { ...no, ssh: true }, tcp_ports: [], expires_in_secs: 86400, ssh_account: 'alice' })
  })
  it('asks for the device account only with SSH, and refuses a missing or malformed one without calling the server', async () => {
    await open(); await form()
    expect(wrapper!.find('[data-testid="share-ssh-account"]').exists()).toBe(false)
    await checkbox('share-ssh-permission', true)
    for (const bad of ['', 'Alice', '../etc', 'a b']) {
      await account(bad); await wrapper!.get('form').trigger('submit'); await flushPromises()
      expect(api.post).not.toHaveBeenCalled()
      expect(wrapper!.text()).toContain('Enter the device account for SSH')
    }
    await account('root'); await wrapper!.get('form').trigger('submit'); await flushPromises()
    expect(api.post).not.toHaveBeenCalled(); expect(wrapper!.text()).toContain('root cannot be shared directly')
  })
  it('asks the device for its accounts and lets one be picked instead of typed', async () => {
    await open(); await form(); await checkbox('share-desktop-permission', false); await checkbox('share-ssh-permission', true); await flushPromises()
    expect(api.get).toHaveBeenCalledWith(`/account/devices/${device}/local-accounts`)
    expect(wrapper!.get('[data-testid="share-ssh-account-ops"]').text()).toContain('administrator')
    await wrapper!.get('[data-testid="share-ssh-account-alice"]').trigger('click')
    await wrapper!.get('form').trigger('submit'); await flushPromises()
    expect(api.post).toHaveBeenCalledWith('/device-shares', expect.objectContaining({ ssh_account: 'alice' }))
  })
  it('has the device create an administrator account and shares SSH as it', async () => {
    vi.mocked(api.post).mockImplementation(async path => String(path).endsWith('/local-accounts') ? { accounts: [...deviceAccounts.accounts, { name: 'share1', uid: 1002, admin: true }] } : {})
    await open(); await form(); await checkbox('share-desktop-permission', false); await checkbox('share-ssh-permission', true); await flushPromises()
    await wrapper!.get('[data-testid="share-new-account"] input').setValue('root')
    await wrapper!.get('[data-testid="share-new-account-create"]').trigger('click'); await flushPromises()
    expect(api.post).not.toHaveBeenCalled()
    await wrapper!.get('[data-testid="share-new-account"] input').setValue('share1')
    await wrapper!.get('[data-testid="share-new-account-admin"] input').setValue(true)
    await wrapper!.get('[data-testid="share-new-account-create"]').trigger('click'); await flushPromises()
    expect(api.post).toHaveBeenCalledWith(`/account/devices/${device}/local-accounts`, { name: 'share1', admin: true })
    expect(wrapper!.get('[data-testid="share-ssh-account-created"]').text()).toContain('share1')
    await wrapper!.get('form').trigger('submit'); await flushPromises()
    expect(api.post).toHaveBeenLastCalledWith('/device-shares', expect.objectContaining({ ssh_account: 'share1', permissions: { ...no, ssh: true } }))
  })
  it('still allows typing an account when the device cannot list them', async () => {
    vi.mocked(api.get).mockImplementation(async path => { if (String(path).endsWith('/local-accounts')) throw new Error('The device is not connected to this server'); return String(path).startsWith('/account/devices') ? ownedPage : { items: [shared()], total: 1 } })
    await open(); await form(); await checkbox('share-ssh-permission', true); await flushPromises()
    expect(wrapper!.get('[data-testid="share-ssh-accounts-error"]').text()).toContain('not connected')
    await account('alice'); await wrapper!.get('form').trigger('submit'); await flushPromises()
    expect(api.post).toHaveBeenCalledWith('/device-shares', expect.objectContaining({ ssh_account: 'alice' }))
  })
  it('sends no device account on a share without SSH', async () => {
    await open(); await form(); await wrapper!.get('form').trigger('submit'); await flushPromises()
    expect(vi.mocked(api.post).mock.calls[0]![1]).not.toHaveProperty('ssh_account')
  })
  it('offers the devices this account owns and names the recipient, never asking for raw ids', async () => {
    await open(); await wrapper!.get('.v-expansion-panel-title').trigger('click'); await flushPromises()
    expect(api.get).toHaveBeenCalledWith('/account/devices?page=1&per_page=25')
    const select = wrapper!.findAllComponents({ name: 'VSelect' }).find(c => c.props('label') === 'Device (one you own)')!
    expect(select.props('items')).toEqual([{ title: 'Fixture box (online)', value: device }])
    expect(wrapper!.findAllComponents({ name: 'VTextField' }).some(c => /user ID/i.test(String(c.props('label'))))).toBe(false)
  })
  it('refuses a blank recipient without calling the server', async () => {
    await open(); await form()
    await wrapper!.findAllComponents({ name: 'VTextField' }).find(c => c.props('label') === 'Recipient username or email')!.get('input').setValue('   ')
    await wrapper!.get('form').trigger('submit'); await flushPromises()
    expect(api.post).not.toHaveBeenCalled(); expect(wrapper!.text()).toContain('name the recipient')
  })
  it('opens the form with the device a "Share" link carried', async () => {
    await open(`/?direction=sent&share_device=${device}`)
    const select = wrapper!.findAllComponents({ name: 'VSelect' }).find(c => c.props('label') === 'Device (one you own)')!
    expect(select.props('modelValue')).toBe(device)
  })
  it('lists device and account names, keeping the device id visible beside the name', async () => {
    vi.mocked(api.get).mockImplementation(async path => String(path).startsWith('/account/devices') ? ownedPage : { items: [{ ...shared(), device_name: 'Office box', owner_username: 'alice', recipient_username: 'bob' }], total: 1 })
    await open()
    expect(wrapper!.text()).toContain('Office box'); expect(wrapper!.text()).toContain('alice → bob'); expect(wrapper!.text()).toContain(device)
  })
  it('still refuses an entirely empty service selection', async () => {
    await open(); await form(); await checkbox('share-desktop-permission', false)
    await wrapper!.get('form').trigger('submit'); await flushPromises()
    expect(api.post).not.toHaveBeenCalled(); expect(wrapper!.text()).toContain('a supported capability')
  })
  it('preserves explicit desktop and bidirectional file permissions when SSH is also selected', async () => {
    await open(); await form(); await checkbox('share-ssh-permission', true); await account('alice'); await checkbox('share-files-permission', true)
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
    // No SSH metadata is fetched for a grant that cannot use it (the list and the owned-device
    // directory are the only reads).
    expect(vi.mocked(api.get).mock.calls.filter(([p]) => String(p).endsWith('/ssh'))).toHaveLength(0)
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
