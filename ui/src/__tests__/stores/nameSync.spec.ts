import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { useAgentStore, type Agent } from '@/stores/agents'
import { useDeviceStore, type DeviceRow } from '@/stores/devices'
import { api } from '@/api/client'
vi.mock('@/api/client', () => ({ api: { get: vi.fn(), put: vi.fn() } }))
const pending = { revision: '2', acked_revision: null, event_seq: '3', state: 'pending' as const }
const applied = { ...pending, acked_revision: '2', event_seq: '4', state: 'synced' as const }
const row = () => ({ id: 'a', tenant_id: 't', name: 'latest', name_sync: applied }) as Agent

describe('name synchronization across HTTP and realtime updates', () => {
  beforeEach(() => { setActivePinia(createPinia()); vi.resetAllMocks() })
  it('never downgrades an acknowledgement when a slow GET finishes after its websocket update', async () => {
    const s = useAgentStore()
    s.agents = [row()]
    vi.mocked(api.get).mockResolvedValue({ ...row(), name: 'previous', name_sync: pending })
    const result = await s.fetchAgent('t', 'a')
    expect(result.name).toBe('latest')
    expect(result.name_sync).toEqual(applied)
  })
  it('accepts only the matching tenant and ignores reordered websocket events', () => {
    const s = useAgentStore()
    s.agents = [row()]
    s.applyNameSync({ tenant_id: 'another', agent_id: 'a', name: 'wrong tenant', name_sync: { ...applied, event_seq: '5' } })
    s.applyNameSync({ tenant_id: 't', agent_id: 'a', name: 'old', name_sync: pending })
    expect(s.agents[0]!.name).toBe('latest')
    s.applyNameSync({ tenant_id: 't', agent_id: 'a', name: 'newest', name_sync: { ...pending, revision: '3', event_seq: '5' } })
    expect(s.agents[0]!.name).toBe('newest')
  })
  it('does not let a delayed grid refresh overwrite confirmed realtime names', async () => {
    const s = useDeviceStore()
    s.items = [{ ...row(), kind: 'agent' } as unknown as DeviceRow]
    vi.mocked(api.get).mockResolvedValue({ items: [{ ...s.items[0], name: 'old', name_sync: pending }], total: 1, page: 1, per_page: 25, total_pages: 1 })
    await s.fetchDevices('t')
    expect(s.items[0]!.name).toBe('latest')
    expect(s.items[0]!.name_sync).toEqual(applied)
  })
  it('returns persistence evidence from save without inventing an acknowledged client', async () => {
    const s = useAgentStore()
    s.agents = [row()]
    const next = { ...pending, revision: '3', event_seq: '5' }
    vi.mocked(api.put).mockResolvedValue({ agent: { ...row(), name: 'next', name_sync: next }, name_sync: next })
    const result = await s.updateDevice('t', 'a', { name: 'next' })
    expect(result.nameSync?.state).toBe('pending')
    expect(s.agents[0]!.name_sync).toEqual(next)
  })
})
