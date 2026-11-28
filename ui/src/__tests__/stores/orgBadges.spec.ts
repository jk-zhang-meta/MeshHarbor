// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'

vi.mock('@/api/client', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
}))

import { api } from '@/api/client'
import { useOrgBadgesStore } from '@/stores/orgBadges'

describe('useOrgBadgesStore (P4 cross-org badges)', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('accumulates live deltas per org and sums them into badgeCount', () => {
    const s = useOrgBadgesStore()
    s.noteForeignNotification('org-b', 'invite')
    s.noteForeignNotification('org-b', 'device_moved')
    s.noteForeignNotification('org-c', 'consent_request')

    expect(s.badgeCount('org-b')).toBe(2)
    expect(s.badgeCount('org-c')).toBe(1)
    expect(s.summaries['org-c']?.consents).toBe(1)
    expect(s.badgeCount('org-unknown')).toBe(0)
  })

  it('counts only offline/stale device transitions as attention events', () => {
    const s = useOrgBadgesStore()
    s.noteDevicePresence('org-b', [
      { presence: 'online' },
      { presence: 'offline' },
      { presence: 'stale' },
    ])
    expect(s.hasDeviceEvents('org-b')).toBe(true)
    expect(s.deviceEvents['org-b']).toBe(2)

    s.noteDevicePresence('org-b', [{ presence: 'online' }])
    expect(s.deviceEvents['org-b']).toBe(2)
  })

  it('clearForTenant acknowledges device events and schedules a summary re-sync', async () => {
    const s = useOrgBadgesStore()
    vi.mocked(api.get).mockResolvedValue({ tenants: [] })
    s.noteDevicePresence('org-b', [{ presence: 'offline' }])

    s.clearForTenant('org-b')
    expect(s.hasDeviceEvents('org-b')).toBe(false)

    expect(api.get).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(2100)
    expect(api.get).toHaveBeenCalledWith('/user/unread-summary')
  })

  it('fetchSummaryNow replaces summaries with server truth', async () => {
    const s = useOrgBadgesStore()
    s.noteForeignNotification('org-stale')
    vi.mocked(api.get).mockResolvedValue({
      tenants: [
        {
          tenant_id: 'org-b',
          name: 'B',
          notifications: 3,
          consents: 1,
        },
      ],
    })

    await s.fetchSummaryNow()

    expect(s.badgeCount('org-b')).toBe(3)
    expect(s.badgeCount('org-stale')).toBe(0)
  })

  it('anyForeignActivity ignores the active org', () => {
    const s = useOrgBadgesStore()
    s.noteForeignNotification('org-a')
    expect(s.anyForeignActivity('org-a')).toBe(false)
    expect(s.anyForeignActivity('org-z')).toBe(true)

    const s2 = useOrgBadgesStore()
    s2.deviceEvents['org-d'] = 1
    expect(s2.anyForeignActivity('org-a')).toBe(true)
  })
})
