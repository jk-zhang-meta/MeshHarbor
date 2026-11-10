// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// A tab that outlived a promote asks for chunks the new image no longer has.
// It loads the page the server serves now, once, and lands where the person
// was going; it never loops, and never reloads offline.
import { describe, expect, it, vi } from 'vitest'
import {
  RELOAD_KEY,
  RELOAD_WINDOW_MS,
  claimReload,
  installStaleBuildRecovery,
  isChunkLoadError,
} from '@/utils/staleBuild'

function memoryStorage(seed: Record<string, string> = {}) {
  const m = new Map(Object.entries(seed))
  return {
    getItem: (k: string) => m.get(k) ?? null,
    setItem: (k: string, v: string) => void m.set(k, v),
    removeItem: (k: string) => void m.delete(k),
    clear: () => m.clear(),
    key: () => null,
    get length() {
      return m.size
    },
  } as Storage
}

function harness(opts: { storage?: Storage | 'throws'; onLine?: boolean } = {}) {
  const listeners: Record<string, () => void> = {}
  const timers: Array<() => void> = []
  let onError: ((err: unknown, to?: { fullPath: string }) => void) | null = null
  const location = { reload: vi.fn(), assign: vi.fn() }
  const host = {
    addEventListener: ((type: string, fn: () => void) => {
      listeners[type] = fn
    }) as unknown as Window['addEventListener'],
    get sessionStorage(): Storage | undefined {
      if (opts.storage === 'throws') throw new Error('SecurityError')
      return opts.storage
    },
    location,
    navigator: { onLine: opts.onLine ?? true },
    setTimeout: (fn: () => void) => void timers.push(fn),
  }
  const router = {
    onError: (fn: typeof onError) => {
      onError = fn
      return () => {}
    },
  }
  installStaleBuildRecovery(host, router as never)
  return {
    location,
    preloadError: () => listeners['vite:preloadError']?.(),
    routerError: (err: unknown, fullPath?: string) => onError?.(err, fullPath ? { fullPath } : undefined),
    flush: () => timers.splice(0).forEach((t) => t()),
  }
}

const chunkError = new TypeError('Failed to fetch dynamically imported module: https://meshharbor.itachi.fans/assets/AgentsSection-Ab12.js')

describe('isChunkLoadError', () => {
  it('knows the failed-import message of each browser', () => {
    expect(isChunkLoadError(chunkError)).toBe(true)
    expect(isChunkLoadError(new TypeError('error loading dynamically imported module'))).toBe(true)
    expect(isChunkLoadError(new TypeError('Importing a module script failed.'))).toBe(true)
    expect(isChunkLoadError(new Error('Unable to preload CSS for /assets/x.css'))).toBe(true)
  })

  it('leaves every other error alone', () => {
    expect(isChunkLoadError(new Error('Request failed with status 500'))).toBe(false)
    expect(isChunkLoadError(undefined)).toBe(false)
  })
})

describe('claimReload', () => {
  it('claims once, then not again inside the window, then again after it', () => {
    const s = memoryStorage()
    expect(claimReload(s, 1_000_000)).toBe(true)
    expect(s.getItem(RELOAD_KEY)).toBe('1000000')
    expect(claimReload(s, 1_000_000 + RELOAD_WINDOW_MS - 1)).toBe(false)
    expect(claimReload(s, 1_000_000 + RELOAD_WINDOW_MS)).toBe(true)
  })

  it('claims nothing where storage cannot hold the record, so nothing can loop', () => {
    expect(claimReload(undefined, 1)).toBe(false)
    const broken = { getItem: () => null, setItem: () => { throw new Error('QuotaExceededError') } }
    expect(claimReload(broken, 1)).toBe(false)
  })
})

describe('installStaleBuildRecovery', () => {
  it("lands where the person was going when the router names the navigation", () => {
    const h = harness({ storage: memoryStorage() })
    h.preloadError()
    h.routerError(chunkError, '/tenant/t1/devices')
    h.flush()
    expect(h.location.assign).toHaveBeenCalledExactlyOnceWith('/tenant/t1/devices')
    expect(h.location.reload).not.toHaveBeenCalled()
  })

  it('reloads the page for a failed import no navigation owns', () => {
    const h = harness({ storage: memoryStorage() })
    h.preloadError()
    h.flush()
    expect(h.location.reload).toHaveBeenCalledOnce()
    expect(h.location.assign).not.toHaveBeenCalled()
  })

  it("recovers on the router's word alone", () => {
    const h = harness({ storage: memoryStorage() })
    h.routerError(chunkError, '/observability')
    h.flush()
    expect(h.location.assign).toHaveBeenCalledExactlyOnceWith('/observability')
  })

  it('ignores a navigation that failed for any other reason', () => {
    const h = harness({ storage: memoryStorage() })
    h.routerError(new Error('Navigation cancelled'), '/observability')
    h.flush()
    expect(h.location.assign).not.toHaveBeenCalled()
    expect(h.location.reload).not.toHaveBeenCalled()
  })

  it('does not ask again when the page it loaded fails the same way', () => {
    const storage = memoryStorage({ [RELOAD_KEY]: String(Date.now()) })
    const h = harness({ storage })
    h.preloadError()
    h.flush()
    expect(h.location.reload).not.toHaveBeenCalled()
  })

  it('does nothing offline, or where storage is refused', () => {
    const offline = harness({ storage: memoryStorage(), onLine: false })
    offline.preloadError()
    offline.flush()
    expect(offline.location.reload).not.toHaveBeenCalled()

    const refused = harness({ storage: 'throws' })
    refused.preloadError()
    refused.flush()
    expect(refused.location.reload).not.toHaveBeenCalled()
  })
})
