import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import DeviceNameSyncStatus from '@/components/admin/DeviceNameSyncStatus.vue'

describe('device acknowledgement presentation', () => {
  it('announces pending separately from persisted acknowledgement and local failure', async () => {
    const w = mount(DeviceNameSyncStatus, { props: { sync: { revision: '2', acked_revision: null, event_seq: '3', state: 'pending' } }, global: { stubs: { VChip: { template: '<span><slot /></span>' } } } })
    expect(w.text()).toContain('Name sync pending')
    expect(w.attributes('aria-live')).toBe('polite')
    await w.setProps({ sync: { revision: '2', acked_revision: '2', event_seq: '4', state: 'synced' } })
    expect(w.text()).toContain('Name synced')
    await w.setProps({ sync: { revision: '3', acked_revision: '2', event_seq: '5', state: 'failed' } })
    expect(w.text()).toContain('Name sync failed')
    w.unmount()
  })
  it('does not present an old client or secondary organization alias as globally synchronized', () => {
    for (const [sync, expected] of [
      [undefined, 'Local name unverified'],
      [{ revision: '1', acked_revision: null, state: 'unsupported' }, 'Device update needed'],
      [{ revision: '1', acked_revision: null, state: 'synced', scope: 'organization_alias' }, 'Name sync pending'],
      [{ revision: '1', acked_revision: '1', state: 'synced', scope: 'organization_alias' }, 'Organization alias saved'],
    ] as const) {
      const w = mount(DeviceNameSyncStatus, { props: { sync }, global: { stubs: { VChip: { template: '<span><slot /></span>' } } } })
      expect(w.text()).toContain(expected)
      w.unmount()
    }
  })
})
