// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-103 — when a device's agent token needs someone's attention.
 *
 * A device renews its own token with 180 days to spare (agent 0.4.135 and
 * later), so the list stays quiet for every healthy device. A token within
 * {@link WARN_DAYS} of expiry is one that is NOT renewing: an agent too old to
 * renew, or a renewal the server refused. An expired one can still renew for
 * {@link GRACE_DAYS} days once its agent can; after that only a re-enrollment
 * brings it back.
 */
import i18n from '@/plugins/i18n'

/** Read at call time, so a caller re-renders in the current language. */
function t(key: string, named?: Record<string, unknown>): string {
  return named ? i18n.global.t(key, named) : i18n.global.t(key)
}

export const WARN_DAYS = 60
/** The server's renewal grace past `exp` (`RENEWAL_GRACE_SECS`). */
export const GRACE_DAYS = 90

const DAY_MS = 86_400_000

export interface CredentialChip {
  text: string
  color: 'warning' | 'error'
  tooltip: string
}

/** The chip for a token expiring at `expiresAt` (RFC 3339), or `null` when
 *  there is nothing to act on: not reported, unreadable, or comfortably far. */
export function credentialChip(
  expiresAt: string | null | undefined,
  now: number = Date.now(),
): CredentialChip | null {
  if (!expiresAt) return null
  const at = Date.parse(expiresAt)
  if (Number.isNaN(at)) return null
  const left = at - now
  const on = new Date(at).toISOString().slice(0, 10)
  if (left > WARN_DAYS * DAY_MS) return null
  if (left > 0) {
    const days = Math.floor(left / DAY_MS)
    return {
      text: days === 0 ? t('mh.cred.today') : t('mh.cred.inDays', { days }),
      color: 'warning',
      tooltip: t('mh.cred.soonTip', { on }),
    }
  }
  const late = Math.floor(-left / DAY_MS)
  const renewable = late < GRACE_DAYS
  return {
    text: t('mh.cred.expired'),
    color: 'error',
    tooltip: renewable
      ? t('mh.cred.renewableTip', { on, days: GRACE_DAYS - late })
      : t('mh.cred.lostTip', { on, grace: GRACE_DAYS }),
  }
}
