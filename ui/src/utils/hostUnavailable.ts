// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-97 P0c — what a device says it cannot serve, and why.
 *
 * A word in the hello is a promise (FR-97 §3.1). Where a host cannot keep one,
 * the agent takes the word out of its lists and names the feature in
 * `AgentCaps.unavailable` (feature → `{code, reason}`), and the viewer shows
 * that reason on the control instead of a control that fails silently.
 *
 * - Whether a control WORKS still follows the lists, exactly as before: an
 *   empty `audio` list already disables the audio toggle. This map adds the why.
 * - `not-applicable` is the one code that HIDES a control: the feature means
 *   nothing on that OS (Ctrl+Alt+Del on a Mac). That is how the viewer adapts
 *   to the OS without ever reading `agent.os`.
 * - An agent before P0c sends no map, and an absent key never means
 *   "unavailable".
 *
 * Pure functions only, so the parsing and the rules are unit-tested without a
 * session.
 */
import i18n from '@/plugins/i18n'
import { asSentence } from '@/utils/sentence'

/** The features an agent can mark, by their wire names (`Unavailable::KEYS`). */
export type HostFeature = 'audio' | 'clipboard' | 'clipboard-image-events' | 'sas' | 'display-match'

/** One entry of `AgentCaps.unavailable`. */
export interface HostUnavailable {
  code: string
  reason: string
}

/** The code that hides a control instead of greying it. */
export const NOT_APPLICABLE = 'not-applicable'

/** Longer than any reason an agent sends today; a tooltip, not a page. */
const MAX_REASON = 300

/**
 * `AgentCaps.unavailable` as a plain map. An entry is kept only when its
 * `code` is a non-empty string; anything else, or no map at all (an older
 * agent or server), reads as nothing said. A feature this build does not know
 * is kept, so a newer agent's word is not lost on the way to a newer control.
 */
export function parseUnavailable(raw: unknown): Record<string, HostUnavailable> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {}
  const out: Record<string, HostUnavailable> = {}
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (!v || typeof v !== 'object' || Array.isArray(v)) continue
    const { code, reason } = v as { code?: unknown; reason?: unknown }
    if (typeof code !== 'string' || code.length === 0) continue
    out[k] = {
      code,
      reason: typeof reason === 'string' ? reason.slice(0, MAX_REASON) : '',
    }
  }
  return out
}

/** What the device said about `feature`, or null when it said nothing. */
export function hostUnavailable(
  caps: { unavailable?: unknown } | null | undefined,
  feature: HostFeature,
): HostUnavailable | null {
  return parseUnavailable(caps?.unavailable)[feature] ?? null
}

/**
 * The device's reason for `feature` as a sentence, or null when it said
 * nothing. An entry with no reason still says something: the code.
 */
export function hostReason(
  caps: { unavailable?: unknown } | null | undefined,
  feature: HostFeature,
): string | null {
  const u = hostUnavailable(caps, feature)
  if (!u) return null
  return asSentence(u.reason) || i18n.global.t('remote.viewer.host.unavailable', { code: u.code })
}

/**
 * FR-97 P3e-2 — whether the device says anything here at all. Every agent
 * from P0c on (0.4.142) carries the map, with `sas` at least; before it an
 * absent key says nothing either way, so a control that gated on something
 * else keeps that gate for such an agent.
 */
export function hostSpeaks(caps: { unavailable?: unknown } | null | undefined): boolean {
  return Object.keys(parseUnavailable(caps?.unavailable)).length > 0
}

/** False only when the device says the feature means nothing on its OS. */
export function hostOffers(
  caps: { unavailable?: unknown } | null | undefined,
  feature: HostFeature,
): boolean {
  return hostUnavailable(caps, feature)?.code !== NOT_APPLICABLE
}
