// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-67 P7 — whether a device acts on an update ordered from THIS
 * organization, from what its hello said (`capabilities.update_mode`).
 *
 * A device can be told to update and not do it. A secondary enrollment
 * ignores the order, because only the machine's primary drives its
 * self-updater. A device with `auto_update = false` drops it. Before P7 the
 * dashboard counted both as "pushed". The server now refuses those pushes up
 * front (`refused_code` on a bulk row, a 409 on one device). This module lets
 * the dashboard say so before the click, too.
 *
 * Mirrors `AgentCaps::update_refusal` (crates/remote_control). An unknown
 * word, or no word at all (an older agent), means "unknown": shown as before.
 */

import i18n from '@/plugins/i18n'

/** Read at call time, so a caller re-renders in the current language. */
function t(key: string, named?: Record<string, unknown>): string {
  return named ? i18n.global.t(key, named) : i18n.global.t(key)
}

export type UpdateRefusalCode = 'primary_org' | 'auto_update_off'

export function updateRefusal(caps?: { update_mode?: string } | null): UpdateRefusalCode | null {
  switch (caps?.update_mode) {
    case 'primary_org':
      return 'primary_org'
    case 'off':
      return 'auto_update_off'
    default:
      return null
  }
}

/** A short reason, for a list or a disabled menu item. Also covers FR-2's
 *  `pin_downgrade` code, which a bulk row can carry too. */
export function refusalShort(code?: string | null): string {
  switch (code) {
    case 'primary_org':
      return t('mh.refusal.primary_org')
    case 'auto_update_off':
      return t('mh.refusal.auto_update_off')
    case 'pin_downgrade':
      return t('mh.refusal.pin_downgrade')
    default:
      return t('mh.refusal.other')
  }
}
