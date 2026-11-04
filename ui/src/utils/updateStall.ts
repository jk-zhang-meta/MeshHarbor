// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-106 — when a device has stopped taking updates.
 *
 * A healthy online device installs a release within about 6.5 h. A root
 * daemon checks every 4 h. A per-user one is updated by the root helper,
 * whose timer runs every 6 h plus up to 30 min, and which a push reaches at
 * once. So a device that is online and has not installed a release out for
 * {@link STALL_HOURS} is not taking updates. FR-96's case: a per-user Linux
 * install made before 0.4.138 cannot install them at all, and only one install
 * by a person heals it.
 *
 * The age is the OLDEST missed release's, not the newest's: releases can come
 * 12 h apart, and measured from the newest a device stalled for weeks would
 * lose its chip at every release and regain it a day later.
 *
 * Nothing unknown ever produces a chip. A version that does not parse, or an
 * empty or failed release list, shows nothing: the absence of a signal must
 * never invent a problem on a healthy device.
 */
import i18n from '@/plugins/i18n'

/** Read at call time, so a caller re-renders in the current language. */
function t(key: string, named?: Record<string, unknown>): string {
  return named ? i18n.global.t(key, named) : i18n.global.t(key)
}

export const STALL_HOURS = 24

const HOUR_MS = 3_600_000
const DAY_MS = 86_400_000

/** What the chip needs from one entry of `GET /api/agent/latest-release`. */
export interface AgentReleaseBrief {
  tag_name: string
  published_at?: string | null
  draft?: boolean
  prerelease?: boolean
}

export interface UpdateStallChip {
  text: string
  color: 'warning'
  tooltip: string
}

/** A version's place in the release order: `0.4.N` (or the tag `agent-v0.4.N`)
 *  is N; `0.3.0-rc.N` comes before every 0.4.x; anything else is `null`. */
export function versionOrdinal(version: string | null | undefined): number | null {
  if (!version) return null
  const v = version.trim().replace(/^agent-v/, '').replace(/^v/, '')
  const four = /^0\.4\.(\d+)$/.exec(v)
  if (four) return Number(four[1])
  const rc = /^0\.3\.0-rc\.(\d+)$/.exec(v)
  if (rc) return Number(rc[1]) - 1_000_000
  return null
}


/** The chip for a device, or `null` when there is nothing to act on. */
export function updateStallChip(
  version: string | null | undefined,
  online: boolean,
  os: string | null | undefined,
  releases: readonly AgentReleaseBrief[] | null | undefined,
  now: number = Date.now(),
): UpdateStallChip | null {
  if (!online) return null
  const mine = versionOrdinal(version)
  if (mine === null || !releases || releases.length === 0) return null

  const listed = releases
    .filter((r) => !r.draft && !r.prerelease)
    .map((r) => ({
      version: r.tag_name.replace(/^agent-v/, ''),
      n: versionOrdinal(r.tag_name),
      at: r.published_at ? Date.parse(r.published_at) : Number.NaN,
    }))
    .filter((r): r is { version: string; n: number; at: number } => r.n !== null)
  const missed = listed.filter((r) => r.n > mine && !Number.isNaN(r.at))
  if (missed.length === 0) return null

  const first = missed.reduce((a, b) => (b.n < a.n ? b : a))
  const age = now - first.at
  if (age < STALL_HOURS * HOUR_MS) return null

  // The list holds only the newest releases: older than all of them, the
  // device is at least that many behind.
  const capped = listed.every((r) => r.n > mine)
  const behind = capped
    ? t('mh.stall.behindPlus', { n: missed.length })
    : missed.length === 1
      ? t('mh.stall.behindOne')
      : t('mh.stall.behindN', { n: missed.length })
  const ago =
    age >= DAY_MS
      ? t('mh.stall.days', { n: Math.floor(age / DAY_MS) })
      : t('mh.stall.hours', { n: Math.floor(age / HOUR_MS) })
  return {
    text: t('mh.stall.chip'),
    color: 'warning',
    tooltip:
      t('mh.stall.tooltip', { version, behind, first: first.version, ago }) +
      ' ' +
      (os === 'linux' ? t('mh.stall.remedyLinux') : t('mh.stall.remedyOther')),
  }
}
