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

  it('starts probeLocalRelay in parallel with /ws and TURN fetch and sends rc:session.request no later than ws_ready + turn_ready', async () => {
    const { createPinia, setActivePinia } = await import('pinia')
    const { ref } = await import('vue')
    const { useWsStore } = await import('@/stores/ws')
    const { api } = await import('@/api/client')
    const { useRemoteControl, localRelayIceServer } = await import('@/composables/useRemoteControl')

    setActivePinia(createPinia())
    const ws = useWsStore()
    ws.status = 'connecting'

    const origOnRc = ws.onRcMessage
    ws.onRcMessage = (() => () => {}) as typeof origOnRc

    const sentAtMs: Array<{ t: string; at: number; msg: Record<string, unknown> }> = []
    let clockMs = 0
    ws.sendRaw = (msg: unknown) => {
      const m = msg as Record<string, unknown>
      sentAtMs.push({ t: String(m.t), at: clockMs, msg: m })
    }

    const WS_READY_MS = 40
    const TURN_READY_MS = 60
    setTimeout(() => {
      clockMs = WS_READY_MS
      ws.status = 'connected'
    }, WS_READY_MS)

    let turnStartedAt: number | null = null
    const origApiGet = api.get
    api.get = (async () => {
      turnStartedAt = clockMs
      await new Promise((r) => setTimeout(r, TURN_READY_MS))
      clockMs = Math.max(clockMs, TURN_READY_MS)
      return { ice_servers: [{ urls: ['stun:stun.example.org:3478'] }] }
    }) as typeof origApiGet

    let probeStartedAt: number | null = null
    vi.stubGlobal('fetch', vi.fn((url, init) => {
      if (probeStartedAt === null) probeStartedAt = clockMs
      if (new URL(url).port === String(LOCAL_RELAY_PROBE_PORTS[0])) {
        return new Promise<Response>((resolve) =>
          setTimeout(() => {
            clockMs = Math.max(clockMs, 250)
            resolve(Response.json(descriptor))
          }, 250),
        )
      }
      return pendingUntilAbort(init.signal)
    }))

    class FakePc {
      static instances: FakePc[] = []
      config: RTCConfiguration
      updatedConfigs: RTCConfiguration[] = []
      constructor(config: RTCConfiguration) {
        this.config = config
        FakePc.instances.push(this)
      }
      setConfiguration(config: RTCConfiguration) {
        this.config = config
        this.updatedConfigs.push(config)
      }
      addTransceiver() {}
      createDataChannel() {
        return {
          readyState: 'open',
          binaryType: 'arraybuffer',
          bufferedAmount: 0,
          send() {},
          close() {},
        } as unknown as RTCDataChannel
      }
      close() {}
    }
    const origPc = globalThis.RTCPeerConnection
    globalThis.RTCPeerConnection = FakePc as unknown as typeof RTCPeerConnection

    let rc: ReturnType<typeof useRemoteControl> | null = null
    try {
      const agentRef = ref({
        id: '69c92d8f011ff058c228e0d0',
        os: 'macos' as const,
        capabilities: {
          codecs: ['h264'] as ('h264' | 'h265' | 'av1')[],
          hw_encoders: [],
          has_input_permission: true,
          supports_clipboard: true,
          supports_file_transfer: true,
          max_simultaneous_sessions: 4,
        },
      })
      rc = useRemoteControl(agentRef)
      const connectPromise = rc.connect('69c92d8f011ff058c228e0d0')

      // Advance to max(WS_READY_MS, TURN_READY_MS) = 60 ms.
      // Both TURN fetch and probeLocalRelay must have started at t=0 in parallel with /ws wait,
      // and rc:session.request must already be sent no later than WS_READY_MS + TURN_READY_MS
      // without waiting 250..800 ms for probeLocalRelay.
      await vi.advanceTimersByTimeAsync(TURN_READY_MS)

      expect(turnStartedAt).toBe(0)
      expect(probeStartedAt).toBe(0)

      const reqEntry = sentAtMs.find((e) => e.t === 'rc:session.request')
      expect(reqEntry).toBeDefined()
      expect(reqEntry!.at).toBeLessThanOrEqual(WS_READY_MS + TURN_READY_MS)
      await connectPromise

      // When the late local-relay probe finishes at 250 ms, its TURN server is added via setConfiguration for trickle ICE.
      await vi.advanceTimersByTimeAsync(250 - TURN_READY_MS)
      expect(FakePc.instances.length).toBe(1)
      expect(FakePc.instances[0]!.updatedConfigs.length).toBe(1)
      expect(FakePc.instances[0]!.updatedConfigs[0]!.iceServers?.[0]).toEqual(
        localRelayIceServer(descriptor),
      )
    } finally {
      rc?.disconnect()
      ws.onRcMessage = origOnRc
      api.get = origApiGet
      globalThis.RTCPeerConnection = origPc
    }
  })

  it('includes local_relay in rc:session.request and initial PC iceServers when probeLocalRelay settles before ws_ready + turn_ready', async () => {
    const { createPinia, setActivePinia } = await import('pinia')
    const { ref } = await import('vue')
    const { useWsStore } = await import('@/stores/ws')
    const { api } = await import('@/api/client')
    const { useRemoteControl, localRelayIceServer } = await import('@/composables/useRemoteControl')

    setActivePinia(createPinia())
    const ws = useWsStore()
    ws.status = 'connecting'

    const origOnRc = ws.onRcMessage
    ws.onRcMessage = (() => () => {}) as typeof origOnRc

    const sentWs: Record<string, unknown>[] = []
    ws.sendRaw = (msg: unknown) => {
      sentWs.push(msg as Record<string, unknown>)
    }

    setTimeout(() => {
      ws.status = 'connected'
    }, 40)

    const origApiGet = api.get
    api.get = (async () => {
      await new Promise((r) => setTimeout(r, 60))
      return { ice_servers: [{ urls: ['stun:stun.example.org:3478'] }] }
    }) as typeof origApiGet

    vi.stubGlobal('fetch', vi.fn((url, init) => {
      if (new URL(url).port === String(LOCAL_RELAY_PROBE_PORTS[0])) {
        return new Promise<Response>((resolve) =>
          setTimeout(() => resolve(Response.json(descriptor)), 15),
        )
      }
      return pendingUntilAbort(init.signal)
    }))

    class FakePc {
      static instances: FakePc[] = []
      config: RTCConfiguration
      constructor(config: RTCConfiguration) {
        this.config = config
        FakePc.instances.push(this)
      }
      addTransceiver() {}
      createDataChannel() {
        return {
          readyState: 'open',
          binaryType: 'arraybuffer',
          bufferedAmount: 0,
          send() {},
          close() {},
        } as unknown as RTCDataChannel
      }
      close() {}
    }
    const origPc = globalThis.RTCPeerConnection
    globalThis.RTCPeerConnection = FakePc as unknown as typeof RTCPeerConnection

    let rc: ReturnType<typeof useRemoteControl> | null = null
    try {
      const agentRef = ref({
        id: '69c92d8f011ff058c228e0d0',
        os: 'macos' as const,
        capabilities: {
          codecs: ['h264'] as ('h264' | 'h265' | 'av1')[],
          hw_encoders: [],
          has_input_permission: true,
          supports_clipboard: true,
          supports_file_transfer: true,
          max_simultaneous_sessions: 4,
        },
      })
      rc = useRemoteControl(agentRef)
      const connectPromise = rc.connect('69c92d8f011ff058c228e0d0')
      await vi.advanceTimersByTimeAsync(60)
      await connectPromise

      const req = sentWs.find((m) => m.t === 'rc:session.request')
      expect(req).toBeDefined()
      expect(req!.local_relay).toEqual(descriptor)
      expect(FakePc.instances[0]!.config.iceServers?.[0]).toEqual(localRelayIceServer(descriptor))
    } finally {
      rc?.disconnect()
      ws.onRcMessage = origOnRc
      api.get = origApiGet
      globalThis.RTCPeerConnection = origPc
    }
  })
})
