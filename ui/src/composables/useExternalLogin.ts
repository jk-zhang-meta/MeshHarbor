// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-52 P4e — an outsider's login to a device, over the user socket.
 *
 * OPAQUE (RFC 9807) with `@serenity-kit/opaque`, which is the device's own
 * opaque-ke compiled to WebAssembly. Three messages cross the server, which
 * relays them blind: it never sees the password, nothing it could attack
 * offline, nothing it could replay. What a successful login leaves behind is
 * held HERE, in memory, for one session:
 *
 * - the `attemptId` the server and the device both know it by;
 * - the `appKey` derived from the session key the two ends share and nobody
 *   else ever saw — what seals this page's offer and checks the device's answer.
 *
 * ⚠️ A wrong password is decided in this browser, at KE2, and the device never
 * hears a failure — but the attempt still cost it a guess (spec §4b). So the
 * page must not retry a login on its own: every retry is a guess.
 */
import { useWsStore } from '@/stores/ws'
import i18n from '@/plugins/i18n'
import { KEY_STRETCHING, deriveAppKey, fromBase64Url } from '@/utils/extauth'
import type { ExternalSessionAuth } from './useRemoteControl'

/**
 * The login `/connect` just completed, waiting for the viewer to take it.
 * A module variable — NOT a store, not sessionStorage: a store's state is
 * readable from devtools and persisted plugins, and a key that survives a
 * reload would outlive the one session it is good for. Single-use: taking it
 * clears it, so a reload of the viewer goes back through the password.
 */
let handedOff: ExternalSessionAuth | null = null

export function handOffExternalSession(auth: ExternalSessionAuth): void {
  handedOff?.appKey.fill(0)
  handedOff = auth
}

export function takeExternalSession(): ExternalSessionAuth | null {
  const auth = handedOff
  handedOff = null
  return auth
}

/** The refusals the server relays (`ExtauthRefusal` on the wire). */
export type ExtauthRefusal =
  | 'unavailable'
  | 'throttled'
  | 'rate_limited'
  | 'busy'
  | 'malformed'
  | 'rejected'
  | 'unknown_attempt'
  // FR-115 P3b — the session's org (or the account) has every slot in use.
  | 'session_limit'
  | 'other'

export type ExternalLoginResult =
  | { ok: true; attemptId: string; appKey: Uint8Array }
  | {
      ok: false
      /** A wire refusal, or one of this page's own: the password did not
       *  open the device's answer, or the device/server never answered. */
      reason: ExtauthRefusal | 'wrong_password' | 'no_answer'
      /** With `throttled`: how long the device asked the outsider to wait. */
      retryAfterSecs?: number
    }

/** Longer than the server's own wait on the device (10 s) plus a relay hop. */
const ANSWER_BOUND_MS = 20_000

const KNOWN: ReadonlySet<string> = new Set([
  'unavailable',
  'throttled',
  'rate_limited',
  'busy',
  'malformed',
  'rejected',
  'unknown_attempt',
  'session_limit',
  'other',
])

/** A refusal this page does not know is still a refusal — never a login. */
function refusal(raw: unknown): ExtauthRefusal {
  return typeof raw === 'string' && KNOWN.has(raw) ? (raw as ExtauthRefusal) : 'other'
}

/**
 * What the outsider is told. Deliberately as coarse as the wire: `unavailable`
 * covers a mistyped code, a device that is off, an org that switched the
 * feature off and a device that never opted in, and this text must not guess
 * between them — telling them apart would turn a connect code, which is read
 * out loud, into a probe of the device's setup.
 */
export function friendlyExtauthRefusal(reason: unknown, retryAfterSecs?: unknown): string {
  switch (reason) {
    // FR-131 P3 — in the reader's language (`remote.viewer.ext.*`).
    case 'wrong_password':
      return i18n.global.t('remote.viewer.ext.wrong_password')
    case 'throttled':
      return typeof retryAfterSecs === 'number'
        ? i18n.global.t('remote.viewer.ext.throttledFor', { s: Math.ceil(retryAfterSecs) })
        : i18n.global.t('remote.viewer.ext.throttled')
    case 'rate_limited':
      return i18n.global.t('remote.viewer.ext.rate_limited')
    case 'busy':
      return i18n.global.t('remote.viewer.ext.busy')
    case 'unknown_attempt':
      return i18n.global.t('remote.viewer.ext.unknown_attempt')
    case 'no_answer':
      return i18n.global.t('remote.viewer.ext.no_answer')
    case 'malformed':
      return i18n.global.t('remote.viewer.ext.malformed')
    case 'unavailable':
      return i18n.global.t('remote.viewer.ext.unavailable')
    case 'session_limit':
      // The server's own words name who holds the slot; this is the fallback.
      return i18n.global.t('remote.viewer.ext.session_limit')
    default:
      return i18n.global.t('remote.viewer.ext.other')
  }
}

type Frame = Record<string, unknown> & { t: string }

/**
 * The next frame of one of `types` that `accept` takes, or `null` after
 * `ANSWER_BOUND_MS`. Subscribes BEFORE `send` runs, so an answer that beats
 * the send's return still lands.
 */
function exchange(
  types: string[],
  send: () => void,
  accept: (f: Frame) => boolean,
): Promise<Frame | null> {
  const ws = useWsStore()
  return new Promise((resolve) => {
    const unsubs: Array<() => void> = []
    const done = (f: Frame | null) => {
      clearTimeout(timer)
      for (const u of unsubs) u()
      resolve(f)
    }
    const timer = setTimeout(() => done(null), ANSWER_BOUND_MS)
    for (const t of types) {
      unsubs.push(
        ws.onRcMessage(t, (msg: Frame) => {
          if (accept(msg)) done(msg)
        }),
      )
    }
    send()
  })
}

/**
 * Log in to the device behind `connectCode` as `principal` (this account's own
 * user id — the device binds the key to it). The password is used and dropped;
 * it is never stored, logged, or sent anywhere.
 */
export async function externalLogin(
  connectCode: string,
  password: string,
  principal: string,
): Promise<ExternalLoginResult> {
  // Loaded HERE, not at module scope: the library carries ~430 KB of inlined
  // WebAssembly, and the viewer imports this module for the handoff and the
  // refusal text — a static import would ship the blob to every
  // remote-control page whether or not anyone logs in from outside.
  const opaque = await import('@serenity-kit/opaque')
  await opaque.ready
  const ws = useWsStore()
  const { clientLoginState, startLoginRequest } = opaque.client.startLogin({ password })

  // Only one login is in flight per page, so the first challenge or result is
  // this start's. A start refused by the SERVER carries no attempt id at all.
  const first = await exchange(
    ['rc:extauth.challenge', 'rc:extauth.result'],
    () => ws.sendRaw({ t: 'rc:extauth.start', connect_code: connectCode, ke1: startLoginRequest }),
    () => true,
  )
  if (!first) return { ok: false, reason: 'no_answer' }
  if (first.t === 'rc:extauth.result') {
    return {
      ok: false,
      reason: refusal(first.refused),
      retryAfterSecs: typeof first.retry_after_secs === 'number' ? first.retry_after_secs : undefined,
    }
  }
  const attemptId = String(first.attempt_id ?? '')
  const ke2 = String(first.ke2 ?? '')

  // The password is checked HERE: a wrong one does not open the device's KE2,
  // and nothing more is sent — the device sees an abandoned login (§4b).
  const finished = opaque.client.finishLogin({
    clientLoginState,
    loginResponse: ke2,
    password,
    keyStretching: KEY_STRETCHING,
  })
  if (!finished) return { ok: false, reason: 'wrong_password' }

  const result = await exchange(
    ['rc:extauth.result'],
    () =>
      ws.sendRaw({
        t: 'rc:extauth.finish',
        connect_code: connectCode,
        attempt_id: attemptId,
        ke3: finished.finishLoginRequest,
      }),
    (f) => f.attempt_id === attemptId || f.attempt_id === undefined || f.attempt_id === null,
  )
  if (!result) return { ok: false, reason: 'no_answer' }
  // Anything present in `refused` is a refusal, whatever its spelling.
  if (result.refused !== undefined && result.refused !== null) {
    return { ok: false, reason: refusal(result.refused) }
  }
  const sessionKey = fromBase64Url(finished.sessionKey)
  if (!sessionKey) return { ok: false, reason: 'other' }
  return { ok: true, attemptId, appKey: await deriveAppKey(sessionKey, attemptId, principal) }
}
