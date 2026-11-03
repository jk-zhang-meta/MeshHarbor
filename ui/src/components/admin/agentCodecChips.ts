// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import type { Agent } from '@/stores/agents'
import { cellsFromCaps, type CellCodec } from '@/composables/videoCells'
import i18n from '@/plugins/i18n'

/** Read at call time, so a caller re-renders in the current language. */
function t(key: string, named?: Record<string, unknown>): string {
  return named ? i18n.global.t(key, named) : i18n.global.t(key)
}

export interface CodecChip {
  label: string
  color: string
  tooltip: string
}

/**
 * Render the agent's advertised codec capabilities as a list of chips
 * (e.g. "H.264 HW", "H.265 HW", "AV1 SW"). Combines `codecs` (the
 * codec names) with `hw_encoders` (the backend labels) so the chip
 * shows both what's supported and how. Pure function — exported as
 * a standalone module so vitest can cover it without mounting Vue.
 */
export function codecChips(a: Agent): CodecChip[] {
  const caps = a.capabilities
  if (!caps) return []
  // FR-77 — an agent that sends `video_cells` is read through the ONE
  // derivation the picker uses, so the chips and the picker cannot disagree:
  // a codec is HW when any of its cells is a verified hardware backend, and a
  // 4:4:4 cell is shown, since that is what the operator hunting for crisp
  // text needs to know. Older agents fall through to the legacy labels below.
  if (Array.isArray(caps.video_cells) && caps.video_cells.length > 0) {
    const cells = cellsFromCaps(caps)
    const order: CellCodec[] = ['h264', 'hevc', 'av1', 'vp9']
    return order
      .filter((codec) => cells.some((c) => c.codec === codec))
      .map((codec) => {
        const mine = cells.filter((c) => c.codec === codec)
        const isHw = mine.some((c) => c.hw)
        const has444 = mine.some((c) => c.chroma.includes('yuv444'))
        const display = codec === 'hevc' ? 'H.265' : codec === 'h264' ? 'H.264' : codec.toUpperCase()
        const backends = [...new Set(mine.map((c) => c.backend).filter(Boolean))].join(', ')
        return {
          label: `${display} ${isHw ? 'HW' : 'SW'}${has444 ? ' 4:4:4' : ''}`,
          color: isHw ? 'primary' : 'default',
          tooltip:
            t(isHw ? 'mh.codec.hw' : 'mh.codec.sw', { codec: display }) +
            (backends ? ` (${backends})` : '') +
            (has444 ? t('mh.codec.yuv444') : ''),
        }
      })
  }
  // Group hw_encoders by codec stem ("h264", "h265", "av1") so we can
  // tell HW from SW. "openh264-sw" → h264 SW; "mf-h264-hw" → h264 HW;
  // "mf-h265-hw" → h265 HW; etc.
  const hwForCodec = new Map<string, boolean>()
  for (const enc of caps.hw_encoders ?? []) {
    const lower = enc.toLowerCase()
    const isHw = lower.includes('-hw')
    for (const codec of ['h264', 'h265', 'av1', 'vp9', 'vp8'] as const) {
      if (lower.includes(codec)) {
        hwForCodec.set(codec, hwForCodec.get(codec) || isHw)
      }
    }
  }
  return (caps.codecs ?? []).map((codec) => {
    const lower = codec.toLowerCase()
    const isHw = hwForCodec.get(lower) ?? false
    const display = lower
      .replace(/^h(\d{3})$/, (_m, n) => `H.${n}`)
      .toUpperCase()
    return {
      label: `${display} ${isHw ? 'HW' : 'SW'}`,
      color: isHw ? 'primary' : 'default',
      tooltip: t(isHw ? 'mh.codec.hwAvailable' : 'mh.codec.swAvailable', { codec: display }),
    }
  })
}

export interface PermissionWarning {
  label: string
  tooltip: string
}

/**
 * Host permissions the agent is MISSING, as operator-facing warnings.
 *
 * macOS gates screen capture and input injection, and it never errors when a
 * grant is absent: capture returns wallpaper-only frames and injected events
 * are silently dropped. Without this the product's only symptom is a black
 * screen or a dead mouse with a clean log — so the device list says it.
 *
 * ⚠️ `undefined` and `[]` mean OPPOSITE things and must not be collapsed:
 * `undefined` is a pre-rc.454 agent that cannot report (no information — warn
 * about nothing), `[]` is an agent reporting it holds NEITHER permission (warn
 * about both). A falsy check would silence exactly the case that matters.
 */
export function permissionWarnings(a: Agent): PermissionWarning[] {
  const perms = a.capabilities?.permissions
  if (perms === undefined) return []
  // Not a capture target at all — macOS's root LaunchDaemon, which has no GUI
  // session. It is missing nothing; there is no toggle that would change this,
  // and saying "No screen access" about a mesh-only node is a wild goose chase.
  if (perms.includes('no-gui-session')) return []
  const out: PermissionWarning[] = []
  if (!perms.includes('screen-capture')) {
    out.push({
      label: t('mh.perm.noScreen'),
      tooltip: t('mh.perm.noScreenTip'),
    })
  }
  if (!perms.includes('input')) {
    out.push({
      label: t('mh.perm.noInput'),
      tooltip: t('mh.perm.noInputTip'),
    })
  }
  return out
}
