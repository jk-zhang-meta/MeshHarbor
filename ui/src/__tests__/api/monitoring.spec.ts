// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, expect, it, vi, beforeEach } from 'vitest'
import {
  disconnectLiveSession,
  fetchLiveMonitoring,
  fetchMonitoringHistory,
  formatMonitoringBytes,
  formatMonitoringDuration,
  setMonitorTakeover,
} from '@/api/monitoring'
import { api } from '@/api/client'
import { canViewMonitoring, canViewRemoteAudit, DEFAULT_ADMIN, DEFAULT_MEMBER } from '@/utils/permissions'

vi.mock('@/api/client', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
  },
}))

describe('monitoring API client and helpers', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('formats durations cleanly across seconds, minutes, hours, and days', () => {
    expect(formatMonitoringDuration(undefined)).toBe('—')
    expect(formatMonitoringDuration(0)).toBe('0s')
    expect(formatMonitoringDuration(45)).toBe('45s')
    expect(formatMonitoringDuration(125)).toBe('2m 5s')
    expect(formatMonitoringDuration(3661)).toBe('1h 1m 1s')
    expect(formatMonitoringDuration(90061)).toBe('1d 1h 1m')
  })

  it('formats byte counters cleanly', () => {
    expect(formatMonitoringBytes(0)).toBe('0 B')
    expect(formatMonitoringBytes(512)).toBe('512 B')
    expect(formatMonitoringBytes(2048)).toBe('2.0 KB')
    expect(formatMonitoringBytes(5 * 1024 * 1024)).toBe('5.0 MB')
  })

  it('builds live and history query strings without leaking empty params', async () => {
    vi.mocked(api.get).mockResolvedValueOnce({ items: [] })
    await fetchLiveMonitoring('tid1', { kind: 'ssh', q: 'alice' })
    expect(api.get).toHaveBeenCalledWith('/tenant/tid1/monitoring/live?kind=ssh&q=alice')

    vi.mocked(api.get).mockResolvedValueOnce({ items: [] })
    await fetchMonitoringHistory('tid1', {
      kind: 'all',
      status: 'denied',
      date_from: '2026-11-01',
      min_duration_secs: 60,
      page: 2,
      per_page: 50,
    })
    expect(api.get).toHaveBeenCalledWith(
      '/tenant/tid1/monitoring/history?date_from=2026-11-01&min_duration_secs=60&status=denied&page=2&per_page=50',
    )
  })

  it('posts active disconnect and takeover requests to the tenant monitoring endpoints', async () => {
    vi.mocked(api.post).mockResolvedValueOnce({ disconnected: true })
    await disconnectLiveSession('tid1', { kind: 'ssh', id: 'grant-1', agent_id: 'a1' })
    expect(api.post).toHaveBeenCalledWith('/tenant/tid1/monitoring/disconnect', {
      kind: 'ssh',
      id: 'grant-1',
      agent_id: 'a1',
    })

    vi.mocked(api.post).mockResolvedValueOnce({ ok: true })
    await setMonitorTakeover('tid1', 'sess-9', true)
    expect(api.post).toHaveBeenCalledWith('/tenant/tid1/monitoring/takeover', {
      session_id: 'sess-9',
      active: true,
    })
  })

  it('gates monitoring nav cleanly on VIEW_REMOTE_AUDIT or VIEW_SSH_AUDIT', () => {
    expect(canViewRemoteAudit(DEFAULT_MEMBER, false)).toBe(false)
    expect(canViewMonitoring(DEFAULT_MEMBER, false)).toBe(false)
    expect(canViewRemoteAudit(DEFAULT_ADMIN, false)).toBe(true)
    expect(canViewMonitoring(DEFAULT_ADMIN, false)).toBe(true)
    expect(canViewMonitoring(null, true)).toBe(true)
    expect(canViewMonitoring(null, false)).toBe(false)
  })
})
