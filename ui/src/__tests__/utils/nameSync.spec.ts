import { describe, expect, it } from 'vitest'
import { mergeNameSync, nameSyncPresentation, shouldAcceptNameSync } from '@/utils/nameSync'
import type { NameSync } from '@/utils/nameSync'

describe('device name synchronization evidence', () => {
  it('never treats a saved server name or missing legacy evidence as device acknowledgement', () => {
    expect(nameSyncPresentation(undefined).key).toBe('unverified')
    expect(nameSyncPresentation({ revision: '2', acked_revision: '1', state: 'synced' }).key).toBe('pending')
    expect(nameSyncPresentation({ revision: '2', acked_revision: '2', state: 'synced' }).key).toBe('synced')
  })
  it('keeps offline, failed, unsupported and organization-alias outcomes explicit', () => {
    for (const state of ['pending', 'failed', 'unsupported', 'unverified'] as const)
      expect(nameSyncPresentation({ revision: '2', acked_revision: '0', state }).key).toBe(state)
    expect(nameSyncPresentation({ revision: '2', acked_revision: '2', state: 'synced', scope: 'organization_alias' }).key).toBe('organizationAlias')
  })
  it('rejects reordered updates without losing precision for 64-bit revisions', () => {
    expect(shouldAcceptNameSync({ revision: '9007199254740993', acked_revision: '0', state: 'pending' }, { revision: '9007199254740992', acked_revision: '9007199254740992', state: 'synced' })).toBe(false)
    expect(shouldAcceptNameSync({ revision: '2', acked_revision: '2', state: 'synced' }, { revision: '2', acked_revision: '1', state: 'pending' })).toBe(false)
    expect(shouldAcceptNameSync(undefined, { revision: '1', acked_revision: '0', state: 'pending' })).toBe(true)
  })
  it('orders acknowledgement outcomes by durable event sequence, not HTTP arrival time', () => {
    const current: { name: string; name_sync: NameSync } = { name: 'latest', name_sync: { revision: '3', acked_revision: '3', event_seq: '9', state: 'synced' } }
    const old = { name: 'old', name_sync: { revision: '3', acked_revision: null, event_seq: '8', state: 'failed' as const } }
    expect(mergeNameSync(current, old)).toEqual(current)
    expect(mergeNameSync(current, { name: 'legacy' })).toEqual(current)
    expect(shouldAcceptNameSync(current.name_sync, { ...current.name_sync, event_seq: '10' })).toBe(true)
  })
})
