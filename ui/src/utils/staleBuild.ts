// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { appPath } from '@/utils/deployment'
/**
 * A tab that outlived a promote. Every image ships a new set of
 * content-hashed chunks and none of the old ones, so a tab still running the
 * previous build asks for a route's chunk that no longer exists: the import
 * 404s, the navigation is dropped, and the click does nothing at all.
 *
 * The cure is the page the server serves now, so: load it once. Vite reports
 * a failed dynamic import as `vite:preloadError` (its documented hook for
 * exactly this), and the router reports which navigation it cost, so the
 * reload lands where the person was going rather than where they were.
 *
 * Once, never a loop: a reload is recorded in sessionStorage, and a second
 * failure inside `RELOAD_WINDOW_MS` leaves the error alone, because a chunk
 * missing from the build being served is not cured by asking again. Where
 * storage cannot be written there is no record to stop a loop with, so
 * nothing reloads at all: the old behaviour, never a worse one.
 */
import type { Router } from 'vue-router'

export const RELOAD_KEY = 'roomler.staleBuildReloadAt'
export const RELOAD_WINDOW_MS = 10_000

/** The messages a failed dynamic import carries in Chrome, Firefox and Safari. */
const CHUNK_ERROR =
  /Failed to fetch dynamically imported module|error loading dynamically imported module|Importing a module script failed|Unable to preload CSS/i

export function isChunkLoadError(err: unknown): boolean {
  const message = err instanceof Error ? err.message : String(err ?? '')
  return CHUNK_ERROR.test(message)
}

/**
 * Records the reload and returns true when one may happen now; false inside
 * the window of the last one, or when storage cannot hold the record.
 */
export function claimReload(storage: Pick<Storage, 'getItem' | 'setItem'> | undefined, now: number): boolean {
  if (!storage) return false
  try {
    const last = Number(storage.getItem(RELOAD_KEY) ?? 0)
    if (Number.isFinite(last) && now - last < RELOAD_WINDOW_MS) return false
    storage.setItem(RELOAD_KEY, String(now))
    return true
  } catch {
    return false
  }
}

interface Host {
  addEventListener: Window['addEventListener']
  sessionStorage?: Storage
  location: Pick<Location, 'reload' | 'assign'>
  navigator?: Pick<Navigator, 'onLine'>
  setTimeout: (fn: () => void, ms: number) => unknown
}

export function installStaleBuildRecovery(host: Host, router: Pick<Router, 'onError'>): void {
  // The navigation a failed chunk cost, if the router claims it. Vite's event
  // fires first, inside the import, and the router's rejection lands a
  // microtask later, so the recovery waits one macrotask to learn the target.
  // Either signal alone starts it; both together start it once.
  let target: string | null = null
  let pending = false

  const recover = () => {
    pending = false
    const to = target
    target = null
    // Offline, the reload would trade the app for the browser's error page,
    // and the chunk is not gone, only out of reach.
    if (host.navigator?.onLine === false) return
    let storage: Storage | undefined
    try {
      storage = host.sessionStorage
    } catch {
      storage = undefined
    }
    if (!claimReload(storage, Date.now())) return
    if (to) host.location.assign(appPath(to))
    else host.location.reload()
  }
  const schedule = () => {
    if (pending) return
    pending = true
    host.setTimeout(recover, 0)
  }

  router.onError((err, to) => {
    if (!isChunkLoadError(err)) return
    if (to) target = to.fullPath
    schedule()
  })

  // Never `preventDefault()`ed: Vite would then swallow the error, and the
  // router, which names the target, would never hear of it.
  host.addEventListener('vite:preloadError', schedule)
}
