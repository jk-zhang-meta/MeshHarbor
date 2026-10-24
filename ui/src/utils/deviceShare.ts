// SPDX-License-Identifier: AGPL-3.0-only
export interface DeviceSharePermissions {
  ssh: boolean; desktop_view: boolean; desktop_control: boolean; files_read: boolean; files_write: boolean
}
export interface DeviceShare {
  id: string; device_id: string; owner_user_id: string; recipient_user_id: string
  permissions: DeviceSharePermissions; tcp_ports: number[]; created_at_ms?: number; expires_at_ms: number; revoked_at_ms: number | null; revision: number
}
/** Existing native FILES is bidirectional; read-only never silently receives FILES. */
export function sharedRemotePermissions(p: DeviceSharePermissions): string {
  const out: string[] = []
  if (p.desktop_view) out.push('VIEW')
  if (p.desktop_view && p.desktop_control) out.push('INPUT')
  if (p.files_read && p.files_write) out.push('FILES')
  return out.join(' | ')
}
export function shareLive(share: DeviceShare, now = Date.now()): boolean {
  return share.revoked_at_ms === null && share.expires_at_ms > now
}

/** Ledger status only; never a claim that service policy currently permits access. */
export function shareRecordState(share: DeviceShare, now = Date.now()): 'Revoked' | 'Expired' | 'Unrevoked / unexpired' {
  if (share.revoked_at_ms !== null) return 'Revoked'
  return share.expires_at_ms <= now ? 'Expired' : 'Unrevoked / unexpired'
}
