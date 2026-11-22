// SPDX-License-Identifier: AGPL-3.0-only
import { describe, it, expect } from 'vitest'
import { sharedRemotePermissions, shareLive, shareLifetime, sharePermanent, PERMANENT_EXPIRES_AT_MS, type DeviceSharePermissions, type DeviceShare } from '@/utils/deviceShare'
const none: DeviceSharePermissions = { ssh: false, desktop_view: false, desktop_control: false, files_read: false, files_write: false }
describe('device_share remote capabilities', () => {
  it('keeps read-only files unavailable, never promotes them to bidirectional FILES', () => { expect(sharedRemotePermissions({ ...none, files_read: true })).toBe('') })
  it('asks only explicitly granted desktop/control and bidirectional files', () => { expect(sharedRemotePermissions({ ...none, desktop_view: true, desktop_control: true, files_read: true, files_write: true })).toBe('VIEW | INPUT | FILES') })
  it('does not infer remote desktop from SSH, ports or invalid input-only permission', () => { expect(sharedRemotePermissions({ ...none, ssh: true, desktop_control: true })).toBe('') })
  it('treats exact expiry and revocation as non-live', () => { const share = { expires_at_ms: 10, revoked_at_ms: null } as DeviceShare; expect(shareLive(share, 9)).toBe(true); expect(shareLive(share, 10)).toBe(false); expect(shareLive({ ...share, revoked_at_ms: 5 }, 9)).toBe(false) })
})
describe('device_share lifetime units', () => {
  const now = new Date(2026, 0, 31, 10, 30, 0)
  const secs = (r: ReturnType<typeof shareLifetime>) => (r && 'expires_in_secs' in r ? r.expires_in_secs : null)
  const end = (r: ReturnType<typeof shareLifetime>) => new Date(now.getTime() + (secs(r) ?? 0) * 1000)
  it('converts minutes, hours, days and weeks exactly', () => {
    expect(secs(shareLifetime(1, 'minutes', now))).toBe(60)
    expect(secs(shareLifetime(36, 'hours', now))).toBe(36 * 3600)
    expect(secs(shareLifetime(2, 'days', now))).toBe(2 * 86400)
    expect(secs(shareLifetime(3, 'weeks', now))).toBe(3 * 604800)
  })
  it('counts months and years on the calendar, clamped to the month end', () => {
    const feb = end(shareLifetime(1, 'months', now))
    expect([feb.getFullYear(), feb.getMonth(), feb.getDate(), feb.getHours(), feb.getMinutes()]).toEqual([2026, 1, 28, 10, 30])
    const year = end(shareLifetime(2, 'years', now))
    expect([year.getFullYear(), year.getMonth(), year.getDate()]).toEqual([2028, 0, 31])
    const leap = end(shareLifetime(1, 'years', new Date(2028, 1, 29, 9, 0, 0)))
    expect(leap.getTime()).toBeGreaterThan(0)
  })
  it('asks for a permanent share explicitly, and refuses what the server would', () => {
    expect(shareLifetime(0, 'permanent', now)).toEqual({ permanent: true })
    for (const bad of [0, -1, 1.5, Number.NaN]) expect(shareLifetime(bad, 'days', now)).toBeNull()
    expect(shareLifetime(9000, 'years', now)).toBeNull()
    expect(secs(shareLifetime(100, 'years', now))).toBeGreaterThan(100 * 365 * 86400)
  })
  it('shows the permanent expiry as permanent', () => {
    expect(sharePermanent(PERMANENT_EXPIRES_AT_MS)).toBe(true)
    expect(sharePermanent(Date.now() + 10 * 365 * 86400 * 1000)).toBe(false)
  })
})
