import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mount, flushPromises, type VueWrapper } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import DeviceEditDialog from '@/components/admin/DeviceEditDialog.vue'
import { useAgentStore, type Agent } from '@/stores/agents'
import { api } from '@/api/client'
vi.mock('@/api/client', () => ({ api: { get: vi.fn(), put: vi.fn() } }))
let wrapper: VueWrapper | undefined
const vuetify = createVuetify({ components, directives })
const pending = { revision: '2', acked_revision: null, event_seq: '3', state: 'pending' as const }
beforeEach(() => {
  vi.resetAllMocks()
  vi.useFakeTimers()
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
})
afterEach(() => { wrapper?.unmount(); wrapper = undefined; vi.useRealTimers(); vi.unstubAllGlobals() })
async function openAndSave() {
  const pinia = createPinia()
  setActivePinia(pinia)
  const agents = useAgentStore()
  agents.agents = [{ id: 'a', tenant_id: 't', name: 'old' } as Agent]
  vi.mocked(api.put).mockResolvedValue({ name_sync: pending, agent: { id: 'a', tenant_id: 't', name: 'new', name_sync: pending } })
  wrapper = mount(DeviceEditDialog, { props: { modelValue: true, tenantId: 't', device: { kind: 'agent', id: 'a', name: 'old' } }, global: { plugins: [pinia, vuetify], stubs: { VDialog: { template: '<div><slot /></div>' } } } })
  await wrapper.findAll('input')[0]!.setValue('new')
  const save = wrapper.findAll('button').find(b => b.text() === 'Save')!
  await save.trigger('click')
  await flushPromises()
  return agents
}
describe('rename dialog acknowledgement lifecycle', () => {
  it('keeps pending visible after save, then reflects live device acknowledgement', async () => {
    const agents = await openAndSave()
    expect(wrapper!.text()).toContain('Name sync pending')
    expect(wrapper!.emitted('update:modelValue')).toBeUndefined()
    expect(wrapper!.findAll('button').find(b => b.text() === 'Save')!.attributes('disabled')).toBeDefined()
    agents.applyNameSync({ tenant_id: 't', agent_id: 'a', name: 'new', name_sync: { ...pending, acked_revision: '2', event_seq: '4', state: 'synced' } })
    await flushPromises()
    expect(wrapper!.text()).toContain('Name synced')
  })
  it('uses bounded polling to recover a lost event and stops after closing', async () => {
    await openAndSave()
    vi.mocked(api.get).mockResolvedValue({ id: 'a', tenant_id: 't', name: 'new', name_sync: { ...pending, event_seq: '4', state: 'failed' } })
    await vi.advanceTimersByTimeAsync(2000)
    await flushPromises()
    expect(wrapper!.text()).toContain('Name sync failed')
    const calls = vi.mocked(api.get).mock.calls.length
    await wrapper!.setProps({ modelValue: false })
    await vi.advanceTimersByTimeAsync(10000)
    expect(api.get).toHaveBeenCalledTimes(calls)
  })
  it('can retry a failed canonical name without changing it to a different name', async () => {
    const agents = await openAndSave()
    agents.applyNameSync({ tenant_id: 't', agent_id: 'a', name: 'new', name_sync: { ...pending, event_seq: '4', state: 'failed' } })
    await flushPromises()
    const next = { ...pending, revision: '3', event_seq: '5' }
    vi.mocked(api.put).mockResolvedValue({ agent: { id: 'a', tenant_id: 't', name: 'new', name_sync: next }, name_sync: next })
    await wrapper!.findAll('button').find(b => b.text() === 'Retry name sync')!.trigger('click')
    await flushPromises()
    expect(api.put).toHaveBeenLastCalledWith('/tenant/t/agent/a', { name: 'new' })
    expect(wrapper!.text()).toContain('Name sync pending')
  })
})
