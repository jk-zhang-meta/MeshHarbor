// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * A device's access policy as the Devices page shows and edits it — the
 * choices, their help text, and the one-line summary a collapsed card or row
 * shows in place of the six controls.
 *
 * ONE definition for the desktop grid and the phone card. The two used to
 * carry their own copies of every control, and copies drift: the phone card
 * ended up showing a different name and a shorter menu than the grid.
 */
import type { AccessPolicy, ConsentMode, LockOnEnd } from '@/stores/agents'
import i18n from '@/plugins/i18n'

/** Read at call time, so a template that calls these re-renders when the
 *  interface language changes. */
function t(key: string, named?: Record<string, unknown>): string {
  return named ? i18n.global.t(key, named) : i18n.global.t(key)
}

const CONSENT_MODES: ConsentMode[] = ['prompt', 'auto', 'email', 'push', 'prompt_then_email']

// Per-device consent mode. Email/Push route the request to the device OWNER
// (approve-link) for unattended hosts. `prompt_then_email` runs BOTH legs in
// parallel — first answer wins — with the on-host modal bounded to the attended
// window while the emailed link keeps the full async one; a host that goes
// unanswered hands over to the owner rather than ending the session.
export function consentModeItems(): { title: string; value: ConsentMode }[] {
  return CONSENT_MODES.map((value) => ({ title: t(`mh.policy.consent.${value}`), value }))
}

export function consentModeTitle(mode: ConsentMode): string {
  return CONSENT_MODES.includes(mode) ? t(`mh.policy.consent.${mode}`) : mode
}

// P6 — per-device multi-user input arbitration mode. `free` (default) =
// every INPUT-granted viewer injects (agent-fenced); `exclusive` = one
// floor holder with request/grant. Applies to NEW sessions.
export function inputModeItems(): { title: string; value: 'free' | 'exclusive' }[] {
  return (['free', 'exclusive'] as const).map((value) => ({ title: t(`mh.policy.input.${value}`), value }))
}

// FR-101 P4b-2b — this device's own idle limit, in minutes
// (`AccessPolicy.auto_terminate_idle_minutes`). `0` in the select is "none of
// its own" (stored as null), so the organization's limit alone applies.
const IDLE_MINUTE_PRESETS = [5, 15, 30, 60, 120]

/** The presets, plus a stored value that is none of them (set through the
 *  API), so the select never shows blank for a limit that is in force. */
export function idleMinuteItems(current: number | null | undefined): { title: string; value: number }[] {
  const minutes = [...IDLE_MINUTE_PRESETS]
  if (typeof current === 'number' && current > 0 && !minutes.includes(current)) {
    minutes.push(current)
    minutes.sort((a, b) => a - b)
  }
  return [
    { title: t('mh.policy.idle.orgOnly'), value: 0 },
    ...minutes.map((m) => ({ title: t('mh.policy.idle.minutes', { m }), value: m })),
  ]
}

export function idleLimitHint(): string {
  return t('mh.policy.idle.hint')
}

// FR-99 P3b — what this device's sessions ask of it when the last one ends
// (`AccessPolicy.lock_on_end`). `never` in the select asks nothing (stored as
// null), so the device owner's own setting alone applies.
export function lockOnEndItems(): { title: string; value: LockOnEnd }[] {
  return (['never', 'auto', 'always'] as const).map((value) => ({ title: t(`mh.policy.lock.${value}`), value }))
}

export function lockOnEndHint(): string {
  return t('mh.policy.lock.hint')
}

/** #1882 — what the "Remote desktop over the mesh" switch does, for its
 *  tooltip. */
export function rcOverlayHint(): string {
  return t('mh.policy.rcOverlay.hint')
}

/** The label says what is TRUE right now, not what the checkbox is called —
 *  "you own this device, so consent is currently skipped" is the fact an
 *  operator needs; "Ask me too" alone would leave them guessing what the
 *  unchecked state means. */
export function ownerPromptLabel(policy: AccessPolicy): string {
  const mode = policy.consent_mode ?? 'prompt'
  return policy.prompt_owner
    ? t('mh.policy.owner.applies', { mode: consentModeTitle(mode) })
    : t('mh.policy.owner.skipped')
}

/**
 * What a collapsed policy says, in a few words: the consent mode always (it is
 * the one setting every device has an answer for), then only the settings
 * that DIFFER from their defaults — a summary that repeats every default on
 * every row is noise, and the point is to show what someone changed.
 *
 * `ownedByMe` adds the owner's own exemption, because for the owner it is the
 * fact that decides whether the consent mode applies at all (FR-27) — except
 * under auto-grant, where nobody is asked anyway and saying so is noise.
 */
export function policySummary(policy: AccessPolicy | null | undefined, ownedByMe: boolean): string[] {
  if (!policy) return []
  const mode = policy.consent_mode ?? 'prompt'
  const out = [CONSENT_MODES.includes(mode) ? t(`mh.policy.short.${mode}`) : mode]
  if (ownedByMe && !policy.prompt_owner && mode !== 'auto') out.push(t('mh.policy.short.skippedForYou'))
  if ((policy.input_mode ?? 'free') === 'exclusive') out.push(t('mh.policy.short.oneController'))
  const idle = policy.auto_terminate_idle_minutes
  if (typeof idle === 'number' && idle > 0) out.push(t('mh.policy.short.idle', { m: idle }))
  if (policy.lock_on_end === 'auto') out.push(t('mh.policy.short.lockIfLocked'))
  if (policy.lock_on_end === 'always') out.push(t('mh.policy.short.lockAtEnd'))
  if (policy.rc_overlay) out.push(t('mh.policy.short.overMesh'))
  return out
}
