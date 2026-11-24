// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-108 — display match, the viewer's half of the device's answer.
 *
 * The viewer asks (`rc:display-match`, on connect and on toggle) and the
 * DEVICE decides: its owner's `display_match`, and under `auto` whether
 * someone is using the screen. Every request gets one
 * `rc:display-match.state` back, which this module reads and words. An agent
 * from before FR-108 answers nothing, and the state stays `null`: the toggle
 * then reads as it always did.
 *
 * Pure on purpose — no Vue, no channel — so all of it is unit-tested.
 */
import i18n from '@/plugins/i18n'

/** The device's answer to the latest request. */
export interface DisplayMatchState {
  /** The host's display runs at `mode` for this session. */
  on: boolean
  mode: { w: number; h: number } | null
  /** Why not, in the device's word (`attended`, `locked`, …), or null. */
  refused: string | null
}

/** Read an `rc:display-match.state` frame; `null` when it is not one. */
export function parseDisplayMatchState(obj: Record<string, unknown>): DisplayMatchState | null {
  if (obj.t !== 'rc:display-match.state' || typeof obj.on !== 'boolean') return null
  const m = obj.mode as Record<string, unknown> | null | undefined
  const mode =
    obj.on && m && typeof m === 'object' && Number.isFinite(m.w) && Number.isFinite(m.h)
      ? { w: Number(m.w), h: Number(m.h) }
      : null
  const refused = typeof obj.refused === 'string' && obj.refused.length > 0 ? obj.refused : null
  return { on: obj.on && !refused, mode, refused }
}

/** Why the device did not switch, in words. A word this viewer does not know
 *  (from a newer agent) is shown as it came: never read as a success. */
export function describeDisplayMatchRefusal(word: string): string {
  switch (word) {
    case 'attended':
      return i18n.global.t('remote.viewer.match.refused.attended')
    case 'locked':
      return i18n.global.t('remote.viewer.match.refused.locked')
    case 'disabled_on_device':
      return i18n.global.t('remote.viewer.match.refused.disabled_on_device')
    case 'no_fitting_mode':
      return i18n.global.t('remote.viewer.match.refused.no_fitting_mode')
    case 'switch_failed':
      return i18n.global.t('remote.viewer.match.refused.switch_failed')
    case 'unsupported':
      return i18n.global.t('remote.viewer.match.refused.unsupported')
    default:
      return word
  }
}

/** One line for the toggle, from the device's answer; `null` when there is
 *  none (an older agent, or no request yet this session). */
export function displayMatchSummary(state: DisplayMatchState | null): string | null {
  if (!state) return null
  if (state.on && state.mode) return i18n.global.t('remote.viewer.match.runsAt', { w: state.mode.w, h: state.mode.h })
  if (state.refused) return i18n.global.t('remote.viewer.match.notNow', { why: describeDisplayMatchRefusal(state.refused) })
  return i18n.global.t('remote.viewer.match.offThisSession')
}
