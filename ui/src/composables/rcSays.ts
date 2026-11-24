// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-131 P3 — the sentences `useRemoteControl` puts in `error`, `notice` and
 * `appsError` from inside the composable, in the reader's language.
 *
 * The composable's pure helpers (`friendlyRcError`, `friendlyEndReason`,
 * `mediaWaitingCopy` and the rest) translate themselves. What is left is a
 * handful of constants and literals set inside the session machinery, which
 * is shared with other work in flight; rather than edit that machinery, the
 * viewer names each one here, by the constant itself or by its exact words,
 * and shows the translation. Anything else — the server's or the device's
 * own prose — is shown as it came.
 *
 * ⚠️ A literal here must stay byte-identical to the composable's;
 * `rcSays.spec.ts` reads the composable's source and fails when one drifts,
 * so a reworded message cannot silently fall back to English.
 */
import {
  APPS_UNAVAILABLE_NO_REASON,
  EXTERNAL_ANSWER_UNSEALED,
  EXTERNAL_LOGIN_GONE,
  EXTERNAL_SESSION_ENDED,
  PEER_AUTH_BAD_SIGNATURE,
  ZONE_NEEDS_LOCAL_ACCESS,
  ZONE_REQUIRES_MESH_CONTROLLER,
} from './useRemoteControl'

type Translate = (key: string, named?: Record<string, unknown>) => string

/** The composable's constants, by identity. */
const CONSTANTS: ReadonlyMap<string, string> = new Map([
  [EXTERNAL_LOGIN_GONE, 'remote.viewer.says.externalLoginGone'],
  [EXTERNAL_ANSWER_UNSEALED, 'remote.viewer.says.externalAnswerUnsealed'],
  [EXTERNAL_SESSION_ENDED, 'remote.viewer.says.externalSessionEnded'],
  [PEER_AUTH_BAD_SIGNATURE, 'remote.viewer.says.peerAuthBadSignature'],
  [ZONE_REQUIRES_MESH_CONTROLLER, 'remote.viewer.says.zoneRequiresMesh'],
  [ZONE_NEEDS_LOCAL_ACCESS, 'remote.viewer.says.zoneNeedsLocalAccess'],
  [APPS_UNAVAILABLE_NO_REASON, 'remote.viewer.says.appsNoReason'],
])

/** Literals set inside the composable, word for word. Exported for the drift
 *  test. */
export const RC_LITERALS: Readonly<Record<string, string>> = {
  'connection timed out': 'remote.viewer.says.timedOut',
  'peer connection failed': 'remote.viewer.says.peerFailed',
  'session setup raced teardown': 'remote.viewer.says.raced',
  'signalling error': 'remote.viewer.says.signalling',
  "Rerouting to your device's server...": 'remote.viewer.says.rerouting',
  'Still reaching your device through the cluster. Retrying automatically...': 'remote.viewer.says.stillReaching',
  'apps list failed': 'remote.viewer.says.appsFailed',
}

/** Literals with a number in them: the composable's template, as a pattern,
 *  and the key that says it. Exported for the drift test, which checks each
 *  `source` against the composable. */
export const RC_PATTERNS: readonly { source: string; re: RegExp; key: string; names: string[] }[] = [
  {
    source: 'No video from this device after ${deadAirStreak.value} attempts — retrying every ${Math.round(delay / 1000)}s. Its network may be blocking the connection.',
    re: /^No video from this device after (\d+) attempts — retrying every (\d+)s\. Its network may be blocking the connection\.$/,
    key: 'remote.viewer.says.deadAir',
    names: ['n', 's'],
  },
  {
    source: "This device's processor cannot keep up with VP9 (${swFps} fps measured) - switching to H.264...",
    re: /^This device's processor cannot keep up with VP9 \(([\d.]+) fps measured\) - switching to H\.264\.\.\.$/,
    key: 'remote.viewer.says.vp9Slow',
    names: ['fps'],
  },
]

/** `text` in the reader's language when the viewer knows it; as it came
 *  otherwise (the server's or the device's own words). */
export function rcSays(text: string | null | undefined, t: Translate): string {
  if (!text) return ''
  const key = CONSTANTS.get(text) ?? RC_LITERALS[text]
  if (key) return t(key)
  for (const p of RC_PATTERNS) {
    const m = p.re.exec(text)
    if (m) return t(p.key, Object.fromEntries(p.names.map((n, i) => [n, m[i + 1]])))
  }
  return text
}
