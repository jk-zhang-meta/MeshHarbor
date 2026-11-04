// SPDX-License-Identifier: AGPL-3.0-only
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { LOCAL_RELAY_PROBE_PORTS, probeLocalRelay } from '@/composables/useRemoteControl'

const descriptor = { turn_port: 47990, overlay_ip: '100.64.0.5', username: 'fixture', credential: 'fixture' }

function pendingUntilAbort(signal: AbortSignal): Promise<Response> {
  return new Promise((_resolve, reject) => {
    signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true })
  })
}

describe('local relay discovery startup budget', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(async () => {
    await vi.runAllTimersAsync()
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it('finishes all unreachable ports within one 800 ms discovery deadline', async () => {
    vi.stubGlobal('fetch', vi.fn((_url, init) => pendingUntilAbort(init.signal)))
    const settled = vi.fn()
    const request = probeLocalRelay().then(settled)
    try {
      await vi.advanceTimersByTimeAsync(800)
      expect(settled).toHaveBeenCalledWith(null)
      expect(vi.getTimerCount()).toBe(0)
    } finally {
      await vi.runAllTimersAsync()
      await request
    }
  })

  it('uses a responsive fallback-band agent without waiting for silent primary ports', async () => {
    const signals: AbortSignal[] = []
    vi.stubGlobal('fetch', vi.fn((url, init) => {
      signals.push(init.signal)
      if (new URL(url).port === String(LOCAL_RELAY_PROBE_PORTS.at(-1))) {
        return new Promise<Response>((resolve) => setTimeout(() => resolve(Response.json(descriptor)), 25))
      }
      return pendingUntilAbort(init.signal)
    }))
    const settled = vi.fn()
    const request = probeLocalRelay().then(settled)
    try {
      await vi.advanceTimersByTimeAsync(25)
      expect(settled).toHaveBeenCalledWith(descriptor)
      expect(signals.every((signal) => signal.aborted)).toBe(true)
      expect(vi.getTimerCount()).toBe(0)
    } finally {
      await vi.runAllTimersAsync()
      await request
    }
  })

  it('keeps an immediately available agent fast and cancels losing requests', async () => {
    const signals: AbortSignal[] = []
    vi.stubGlobal('fetch', vi.fn((url, init) => {
      signals.push(init.signal)
      return new URL(url).port === String(LOCAL_RELAY_PROBE_PORTS[0])
        ? Promise.resolve(Response.json(descriptor))
        : pendingUntilAbort(init.signal)
    }))
    expect(await probeLocalRelay()).toEqual(descriptor)
    expect(signals.every((signal) => signal.aborted)).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('falls back to normal TURN when endpoints refuse or return unusable responses', async () => {
    let call = 0
    vi.stubGlobal('fetch', vi.fn(() => {
      switch (call++ % 4) {
        case 0: return Promise.reject(new TypeError('connection refused'))
        case 1: return Promise.resolve(new Response('', { status: 503 }))
        case 2: return Promise.resolve(new Response('not json'))
        default: return Promise.resolve(Response.json({ ...descriptor, turn_port: 0 }))
      }
    }))
    expect(await probeLocalRelay()).toBeNull()
    expect(vi.getTimerCount()).toBe(0)
  })
})
