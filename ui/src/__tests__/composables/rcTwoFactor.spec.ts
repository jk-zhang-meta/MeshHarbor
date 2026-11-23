// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-129 — a remote-desktop session into a device that asks for a code. The
// code rides ONE `rc:session.request`; the device's refusal ends the session
// for good (the person types a fresh code), and nothing replays a spent one.
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  friendlyEndReason,
  isRetryableTerminateReason,
  terminateAction,
} from '@/composables/useRemoteControl'
import { isEligibleRdpFallbackErrorCode } from '@/utils/rdpFallback'

const REASONS = ['two_factor_required', 'two_factor_invalid', 'two_factor_locked'] as const

describe('FR-129 two-factor endings', () => {
  it('are never retried by the reconnect ladder', () => {
    for (const r of REASONS) {
      expect(isRetryableTerminateReason(r)).toBe(false)
      for (const phase of ['requesting', 'awaiting_consent', 'negotiating', 'connected'] as const) {
        expect(
          terminateAction({ phase, retryable: isRetryableTerminateReason(r), canReplay: true }),
        ).toBe('close')
      }
    }
    // The control: an involuntary end still is.
    expect(isRetryableTerminateReason('agent_disconnect')).toBe(true)
  })

  it('never offer an RDP detour around the device check', () => {
    for (const r of REASONS) expect(isEligibleRdpFallbackErrorCode(r)).toBe(false)
  })

  it('say what happened, in words', () => {
    expect(friendlyEndReason('two_factor_required')).toMatch(/asks for a two-factor code/)
    expect(friendlyEndReason('two_factor_invalid')).toMatch(/wrong, expired or already used/)
    expect(friendlyEndReason('two_factor_locked')).toMatch(/Too many wrong two-factor codes/)
  })
})

describe('FR-129 the code on the session request', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('sends the code once, ends on the refusal without reconnecting, and never replays it', async () => {
    const { createPinia, setActivePinia } = await import('pinia')
    const { ref } = await import('vue')
    const { useWsStore } = await import('@/stores/ws')
    const { api } = await import('@/api/client')
    const { useRemoteControl } = await import('@/composables/useRemoteControl')

    setActivePinia(createPinia())
    const ws = useWsStore()
    ws.status = 'connected'

    const rcListeners = new Map<string, Set<(msg: Record<string, unknown>) => void>>()
    const origOnRc = ws.onRcMessage
    ws.onRcMessage = ((t: string, h: (msg: Record<string, unknown>) => void) => {
      let s = rcListeners.get(t)
      if (!s) {
        s = new Set()
        rcListeners.set(t, s)
      }
      s.add(h)
      return () => s?.delete(h)
    }) as typeof origOnRc
    const deliverRc = (t: string, msg: Record<string, unknown>) => {
      for (const h of Array.from(rcListeners.get(t) ?? [])) h({ t, ...msg })
    }

    const sentWs: Record<string, unknown>[] = []
    const origSendRaw = ws.sendRaw
    ws.sendRaw = (msg: unknown) => {
      sentWs.push(msg as Record<string, unknown>)
    }

    const origApiGet = api.get
    api.get = (async () => ({ ice_servers: [] })) as typeof origApiGet
    // No local agent to find.
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 503 })))

    class FakePc {
      addTransceiver() {}
      setConfiguration() {}
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

    const AGENT_ID = '69c92d8f011ff058c228e0d0'
    let rc: ReturnType<typeof useRemoteControl> | null = null
    try {
      const agentRef = ref({
        id: AGENT_ID,
        os: 'linux' as const,
        capabilities: {
          codecs: ['h264'] as ('h264' | 'h265' | 'av1')[],
          hw_encoders: [],
          has_input_permission: true,
          supports_clipboard: true,
          supports_file_transfer: true,
          max_simultaneous_sessions: 4,
          rpc: ['two-factor'],
          two_factor: true,
        },
      })
      rc = useRemoteControl(agentRef)
      const requests = () => sentWs.filter((m) => m.t === 'rc:session.request')

      rc.twoFactorCode.value = '123456'
      await rc.connect(AGENT_ID)
      expect(requests()).toHaveLength(1)
      expect(requests()[0]!.two_factor_code).toBe('123456')
      // One-shot: gone the moment it went out.
      expect(rc.twoFactorCode.value).toBe('')

      deliverRc('rc:terminate', { reason: 'two_factor_invalid' })
      expect(rc.phase.value).toBe('closed')
      expect(rc.errorCode.value).toBe('two_factor_invalid')
      expect(rc.error.value).toMatch(/wrong, expired or already used/)
      await new Promise((r) => setTimeout(r, 400))
      expect(rc.reconnectAttempt.value).toBe(0)
      expect(requests()).toHaveLength(1)

      // The next Connect without a fresh code carries none: the device asks.
      await rc.connect(AGENT_ID)
      expect(requests()).toHaveLength(2)
      expect(requests()[1]).not.toHaveProperty('two_factor_code')
    } finally {
      rc?.disconnect()
      ws.onRcMessage = origOnRc
      ws.sendRaw = origSendRaw
      api.get = origApiGet
      globalThis.RTCPeerConnection = origPc
    }
  })
})
