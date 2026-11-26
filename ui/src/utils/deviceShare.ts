// SPDX-License-Identifier: AGPL-3.0-only
export interface DeviceSharePermissions {
  ssh: boolean; desktop_view: boolean; desktop_control: boolean; files_read: boolean; files_write: boolean
}
export interface DeviceShare {
  id: string; device_id: string; owner_user_id: string; recipient_user_id: string
  permissions: DeviceSharePermissions; tcp_ports: number[]; created_at_ms?: number; expires_at_ms: number; revoked_at_ms: number | null; revision: number
  /** The device account an SSH share runs as. */
  ssh_account?: string
  /** Display names resolved by the server when it reads the record; ids stay the identity. */
  device_name?: string; owner_username?: string; recipient_username?: string
  /** FR-139 — GPU server identity & live summary carried by default on shares. */
  gpu_server?: boolean
  gpu_inventory?: import('@/api/gpu').GpuInventory | null
  gpu_summary?: import('@/api/gpu').GpuShareSummary | null
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

/** The expiry the server gives a permanent share (9999-12-31T23:59:59Z), and the latest any share may have. */
export const PERMANENT_EXPIRES_AT_MS = 253_402_300_799_000
export function sharePermanent(expiresAtMs: number): boolean {
  return expiresAtMs >= PERMANENT_EXPIRES_AT_MS
}
export const SHARE_UNITS = ['minutes', 'hours', 'days', 'weeks', 'months', 'years', 'permanent'] as const
export type ShareUnit = typeof SHARE_UNITS[number]
const FIXED_SECS: Partial<Record<ShareUnit, number>> = { minutes: 60, hours: 3600, days: 86400, weeks: 604800 }
/**
 * The create request's lifetime: `{ permanent: true }`, or `{ expires_in_secs }` for `amount` units
 * from `now`. Months and years are calendar ones (the same day and time that many months on,
 * clamped to the month's last day), so "1 month" from 31 January ends on the last day of February.
 * `null`: not a whole positive amount, or an end after the permanent expiry.
 */
export function shareLifetime(amount: number, unit: ShareUnit, now: Date = new Date()): { permanent: true } | { expires_in_secs: number } | null {
  if (unit === 'permanent') return { permanent: true }
  if (!Number.isInteger(amount) || amount < 1) return null
  let end: number
  const fixed = FIXED_SECS[unit]
  if (fixed !== undefined) {
    end = now.getTime() + amount * fixed * 1000
  } else {
    const months = unit === 'years' ? amount * 12 : amount
    const d = new Date(now.getTime()), day = d.getDate()
    d.setDate(1)
    d.setMonth(d.getMonth() + months)
    const last = new Date(d.getFullYear(), d.getMonth() + 1, 0).getDate()
    d.setDate(Math.min(day, last))
    end = d.getTime()
  }
  if (!Number.isFinite(end) || end > PERMANENT_EXPIRES_AT_MS) return null
  return { expires_in_secs: Math.round((end - now.getTime()) / 1000) }
}
