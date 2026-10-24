// SPDX-License-Identifier: AGPL-3.0-only
import { describe, it, expect } from 'vitest'
import { sharedRemotePermissions, shareLive, type DeviceSharePermissions, type DeviceShare } from '@/utils/deviceShare'
const none: DeviceSharePermissions = { ssh: false, desktop_view: false, desktop_control: false, files_read: false, files_write: false }
describe('device_share remote capabilities', () => {
  it('keeps read-only files unavailable, never promotes them to bidirectional FILES', () => { expect(sharedRemotePermissions({ ...none, files_read: true })).toBe('') })
  it('asks only explicitly granted desktop/control and bidirectional files', () => { expect(sharedRemotePermissions({ ...none, desktop_view: true, desktop_control: true, files_read: true, files_write: true })).toBe('VIEW | INPUT | FILES') })
  it('does not infer remote desktop from SSH, ports or invalid input-only permission', () => { expect(sharedRemotePermissions({ ...none, ssh: true, desktop_control: true })).toBe('') })
  it('treats exact expiry and revocation as non-live', () => { const share = { expires_at_ms: 10, revoked_at_ms: null } as DeviceShare; expect(shareLive(share, 9)).toBe(true); expect(shareLive(share, 10)).toBe(false); expect(shareLive({ ...share, revoked_at_ms: 5 }, 9)).toBe(false) })
})
