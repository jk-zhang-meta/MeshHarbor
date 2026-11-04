// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { computed, ref, watch } from 'vue'
import { api } from '@/api/client'

/**
 * FR-12 (#788) — per-user tutorial state, entirely client-side.
 *
 * Two independent things live here, both keyed by user id so a shared
 * machine doesn't leak one person's state to the next:
 *
 *  - **seen**: has the welcome tour ever been auto-opened for this user
 *    (`meshharbor-tour-seen:<userId>`). Set on the FIRST auto-open and never
 *    cleared by normal use, so the tour can never ambush someone twice.
 *  - **progress**: which chapters they ticked off
 *    (`meshharbor:tour-progress:<userId>`) — same storage conventions as
 *    `useGridColumns`.
 *
 * Every access is try/catch'd: localStorage throws in private windows and
 * under some enterprise policies, and a tutorial must never be the thing
 * that breaks the app shell.
 */

export const TOUR_SEEN_PREFIX = 'meshharbor-tour-seen:'
export const TOUR_PROGRESS_PREFIX = 'meshharbor:tour-progress:'

export function tourSeenKey(userId: string): string {
  return `${TOUR_SEEN_PREFIX}${userId || 'anon'}`
}

export function tourProgressKey(userId: string): string {
  return `${TOUR_PROGRESS_PREFIX}${userId || 'anon'}`
}

/** Has the tour already been shown to this user? Unreadable storage reads
 *  as "seen" — failing that way means we never auto-navigate someone we
 *  can't remember having done it to. */
export function hasSeenTour(userId: string): boolean {
  try {
    return globalThis.localStorage?.getItem(tourSeenKey(userId)) != null
  } catch {
    return true
  }
}

export function markTourSeen(userId: string): void {
  try {
    globalThis.localStorage?.setItem(tourSeenKey(userId), new Date().toISOString())
  } catch {
    /* private window / policy — the tour just may open again next session */
  }
}

export function readTourProgress(userId: string): string[] {
  try {
    const raw = globalThis.localStorage?.getItem(tourProgressKey(userId))
    const parsed = raw ? JSON.parse(raw) : null
    return Array.isArray(parsed) ? parsed.filter((c: unknown) => typeof c === 'string') : []
  } catch {
    return []
  }
}

export function writeTourProgress(userId: string, done: string[]): void {
  try {
    globalThis.localStorage?.setItem(tourProgressKey(userId), JSON.stringify(done))
  } catch {
    /* non-fatal — progress ticks are a convenience, not state we own */
  }
}

/**
 * Should the tour auto-open for this user right now?
 *
 * Deliberately narrow: an established org never surprises its members. The
 * "fresh" heuristic is the org having no devices AND at most one room —
 * i.e. nothing has been set up yet. `devices`/`rooms` are counts the
 * caller already has; pass `null` for a count that hasn't loaded, which
 * suppresses the auto-open (we only navigate on positive evidence).
 */
export function shouldAutoOpenTour(opts: {
  userId: string | undefined
  devices: number | null
  rooms: number | null
}): boolean {
  if (!opts.userId) return false
  if (opts.devices == null || opts.rooms == null) return false
  if (hasSeenTour(opts.userId)) return false
  return opts.devices === 0 && opts.rooms <= 1
}

/**
 * FR-12 P3 — the server-side mirror.
 *
 * The tutorial is a convenience and must never be the thing that breaks the
 * app shell, so every call here is fire-and-forget: a failed PUT loses a
 * checkbox tick, nothing more, and localStorage remains the source the UI
 * actually reads.
 */
export interface ServerTutorialState {
  done?: string[]
  /** ISO timestamp, or absent. Presence is the whole signal. */
  seen_at?: string | null
}

/**
 * Seed this browser from the account's stored state.
 *
 * `done` is UNIONED rather than overwritten: a device that ticked a chapter
 * while the PUT failed should not lose it the moment another device syncs.
 * The union is only ever applied on load — writes replace, so un-ticking
 * still works (it just needs the write to land).
 *
 * `seen_at` only ever sets the local flag, never clears it: its whole job is
 * to stop the tour ambushing someone a second time, and a missing server
 * value means "no opinion", not "never seen".
 */
export function seedTutorialFromServer(userId: string, remote: ServerTutorialState | undefined) {
  if (!remote) return
  if (Array.isArray(remote.done) && remote.done.length) {
    const merged = [...new Set([...readTourProgress(userId), ...remote.done])]
    writeTourProgress(userId, merged)
  }
  if (remote.seen_at) markTourSeen(userId)
}

/** Push a change up. Never throws, never awaited by the caller's UI path. */
export function pushTutorialState(patch: { done?: string[]; seen?: boolean }): void {
  void api.put('/user/tutorial', patch).catch(() => {
    /* offline, logged out, route absent on an older server — all survivable */
  })
}

/** Reactive per-user chapter checklist for the Tutorial view. */
export function useTutorialProgress(userId: () => string | undefined) {
  const done = ref<string[]>(readTourProgress(userId() ?? ''))

  // A tenant/user switch reloads from that identity's own bucket.
  watch(
    () => userId(),
    (u) => {
      done.value = readTourProgress(u ?? '')
    },
  )

  function isDone(chapterId: string): boolean {
    return done.value.includes(chapterId)
  }

  function toggle(chapterId: string, value?: boolean): void {
    const next = value ?? !isDone(chapterId)
    done.value = next
      ? [...new Set([...done.value, chapterId])]
      : done.value.filter((c) => c !== chapterId)
    writeTourProgress(userId() ?? '', done.value)
    pushTutorialState({ done: done.value })
  }

  function reset(): void {
    done.value = []
    writeTourProgress(userId() ?? '', [])
    pushTutorialState({ done: [] })
  }

  const doneCount = computed(() => done.value.length)

  return { done, doneCount, isDone, toggle, reset }
}
