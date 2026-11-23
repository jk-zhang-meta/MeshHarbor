// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-129 — a device that asks for a code (docs/fr/FR-129-a-device-that-asks-for-a-code.md).
 *
 * A device with two-factor on asks for a 6-digit code from an authenticator app (or one of its
 * one-time recovery codes) on every connection, and checks it ITSELF: the server relays the code
 * and holds no secret. Everything the browser needs to know about that lives here, so the admin
 * dialog, the remote-desktop viewer and the web console read one set of rules:
 *
 * - whether a device understands it (`two-factor` in `capabilities.rpc`, by EQUALITY) and
 *   whether it is on (`capabilities.two_factor`, absent = off);
 * - the device's refusal words, matched by equality (an `rc:terminate` reason) or as the
 *   `<word>: ` prefix of an exec result's `error`;
 * - how a typed code goes on the wire, and the words a person reads for each refusal.
 *
 * Nothing here logs: a secret, an `otpauth://` URI, a code or a recovery code never reaches the
 * console.
 */

import i18n from '@/plugins/i18n'

/** Read at call time, so a caller re-renders in the current language. */
function t(key: string, named?: Record<string, unknown>): string {
  return named ? i18n.global.t(key, named) : i18n.global.t(key)
}

/** The verb a device lists in `capabilities.rpc` when it understands two-factor. */
export const TWO_FACTOR_RPC = 'two-factor'

/** The device can switch two-factor on and reads `two_factor_code`. Equality, never a prefix:
 *  an rpc verb that merely starts with this word is another feature. */
export function supportsTwoFactor(caps?: { rpc?: string[] } | null): boolean {
  return (caps?.rpc ?? []).includes(TWO_FACTOR_RPC)
}

/** Two-factor is on for the device, as it last reported. Absent = off. */
export function twoFactorOn(caps?: { two_factor?: boolean } | null): boolean {
  return caps?.two_factor === true
}

/** The device's code refusals. `two_factor_unavailable` reaches a remote-desktop viewer as
 *  `two_factor_locked`; the exec and setup answers carry it as itself. */
export const TWO_FACTOR_REFUSALS = [
  'two_factor_required',
  'two_factor_invalid',
  'two_factor_locked',
  'two_factor_unavailable',
] as const
export type TwoFactorRefusal = (typeof TWO_FACTOR_REFUSALS)[number]

/** A refusal word, or `null` for anything else. Equality only. */
export function asTwoFactorRefusal(reason: unknown): TwoFactorRefusal | null {
  return typeof reason === 'string' && (TWO_FACTOR_REFUSALS as readonly string[]).includes(reason)
    ? (reason as TwoFactorRefusal)
    : null
}

/** An exec result's `error` carries a device refusal as `<word>: <words>`. */
export function twoFactorRefusalOfExecError(error: string | null | undefined): TwoFactorRefusal | null {
  if (!error) return null
  for (const r of TWO_FACTOR_REFUSALS) {
    if (error === r || error.startsWith(`${r}:`)) return r
  }
  return null
}

/** Whether the person should be asked for a (new) code: none came, or it was wrong, expired or
 *  used. A locked or unreadable device refuses every code, so asking again would not help. */
export function asksForCode(r: TwoFactorRefusal | null): boolean {
  return r === 'two_factor_required' || r === 'two_factor_invalid'
}

/** The setup key with whitespace removed: what the copy button copies. */
export function ungroupKey(secret: string): string {
  return secret.replace(/\s+/g, '')
}

/** The setup key in groups of four, as both apps' manual-entry screens are easiest to type. */
export function groupKey(secret: string): string {
  return (ungroupKey(secret).match(/.{1,4}/g) ?? []).join(' ')
}

/** What a person typed, the way the device reads it: no spaces or dashes, lower case. */
export function normalizeCode(raw: string): string {
  return raw.replace(/[\s-]/g, '').toLowerCase()
}

/**
 * The code as it goes on the wire, or `null` when it is not one: six digits, or (when allowed) a
 * recovery code, sent as `abcd-efgh`. The device normalises again; this only keeps an obviously
 * malformed code from costing one of the five tries before a lock.
 */
export function codeForWire(raw: string, allowRecovery = true): string | null {
  const c = normalizeCode(raw)
  if (/^\d{6}$/.test(c)) return c
  if (allowRecovery && /^[a-z0-9]{8}$/.test(c)) return `${c.slice(0, 4)}-${c.slice(4)}`
  return null
}

/** "45 s", "15 min". */
export function formatWait(secs: number): string {
  const s = Math.max(1, Math.ceil(secs))
  return s >= 60 ? t('mh.tfa.time.min', { n: Math.ceil(s / 60) }) : t('mh.tfa.time.sec', { n: s })
}

/**
 * The words for a refusal — a code refusal or a setup step's. `message` is the device's own
 * English sentence, shown for a word this page does not know.
 */
export function twoFactorRefusalText(
  reason: string | null | undefined,
  opts: { retryAfterSecs?: number | null; message?: string | null } = {},
): string {
  switch (reason) {
    case 'two_factor_required':
      return t('mh.tfa.reason.required')
    case 'two_factor_invalid':
      return t('mh.tfa.reason.invalid')
    case 'two_factor_locked':
      return typeof opts.retryAfterSecs === 'number' && opts.retryAfterSecs > 0
        ? t('mh.tfa.reason.lockedFor', { time: formatWait(opts.retryAfterSecs) })
        : t('mh.tfa.reason.locked')
    case 'two_factor_unavailable':
      return t('mh.tfa.reason.unavailable')
    case 'already_on':
      return t('mh.tfa.reason.alreadyOn')
    case 'already_off':
      return t('mh.tfa.reason.alreadyOff')
    case 'no_pending':
      return t('mh.tfa.reason.noPending')
    case 'not_primary':
      return t('mh.tfa.reason.notPrimary')
    case 'storage':
      return t('mh.tfa.reason.storage')
    default:
      return opts.message || t('mh.tfa.reason.other')
  }
}

/** The recovery codes as a text file to keep. */
export function recoveryCodesFile(deviceName: string, codes: readonly string[], when: Date): string {
  return [
    t('mh.tfa.file.title'),
    t('mh.tfa.file.device', { name: deviceName }),
    t('mh.tfa.file.created', { when: when.toISOString() }),
    t('mh.tfa.file.note'),
    '',
    ...codes,
    '',
  ].join('\n')
}
