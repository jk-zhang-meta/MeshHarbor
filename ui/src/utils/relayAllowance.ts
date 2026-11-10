// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-115 P4a — how the org's analytics page states its relay allowance. In
 * decimal units, because the plans are sold in decimal gigabytes ("10 GB"),
 * and never in money (FR-20).
 */
import type { RelayAllowance } from '@/stores/stats'

/** `bytes` in decimal units: `3.2 GB`, `640 MB`, `12 KB`, `0 B`. */
export function decimalBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B'
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`
  if (bytes >= 1e6) return `${Math.round(bytes / 1e6)} MB`
  if (bytes >= 1e3) return `${Math.round(bytes / 1e3)} KB`
  return `${Math.round(bytes)} B`
}

/** `1 Mbit/s`, `4 Mbit/s`, `512 kbit/s`. */
export function rateText(kbps: number): string {
  return kbps >= 1000 && kbps % 1000 === 0 ? `${kbps / 1000} Mbit/s` : `${kbps} kbit/s`
}

export interface RelayAllowanceView {
  /** `3.2 GB of 10 GB`, or `3.2 GB (unlimited)` */
  usage: string
  /** 0–100, or null when there is no allowance to measure against */
  percent: number | null
  /** the warning shown while the throttle holds the org back */
  throttledNote: string | null
  /** what happens past the allowance, while the throttle is on */
  policyNote: string | null
}

/** The first of the month the allowance resets on: `1 November`. */
function resetDay(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return 'the first of next month'
  return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', timeZone: 'UTC' })
}

export function relayAllowanceView(q: RelayAllowance): RelayAllowanceView {
  const used = decimalBytes(q.used_bytes)
  if (q.allowance_bytes === null) {
    return { usage: `${used} (unlimited)`, percent: null, throttledNote: null, policyNote: null }
  }
  const percent = Math.min(
    100,
    q.allowance_bytes > 0 ? Math.round((q.used_bytes / q.allowance_bytes) * 100) : 100,
  )
  const rate = q.rate_kbps !== null ? rateText(q.rate_kbps) : null
  const day = resetDay(q.resets_at)
  return {
    usage: `${used} of ${decimalBytes(q.allowance_bytes)}`,
    percent,
    throttledNote:
      q.throttled && rate
        ? `This org is past its mesh relay allowance for the month. Mesh traffic relayed through MeshHarbor's servers is slowed to ${rate} until ${day}. Direct connections are not affected.`
        : null,
    policyNote:
      q.enforced && !q.throttled && rate
        ? `Past the allowance, mesh relay slows to ${rate} until the month ends. It is never cut off.`
        : null,
  }
}
