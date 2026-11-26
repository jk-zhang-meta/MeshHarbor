// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-141 — Remote Desktop graceful restart/update continuity:
// 1. `parseControlInbound` parses `rc:ended` restart metadata (`eta_ms`, `to_version`)
//    without breaking legacy payloads that omit them.
// 2. Receiving `rc:ended { reason: "agent_disconnect", limit: "restart" }` enters soft
//    restart recovery (`restartingDevice`), auto-reconnects with `continues_from`,
//    and clears recovery state upon reconnect or manual disconnect.
// 3. Target agent presence flipping `false -> true` while reconnecting wakes the
//    reconnect ladder immediately instead of waiting out the backoff timer.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { nextTick, ref } from 'vue'
import { createPinia, setActivePinia } from 'pinia'

vi.mock('@/api/client', () => ({ api: { get: vi.fn(async () => ({ ice_servers: [] })) } }))

import {
  RC_CONTINUE_WINDOW_MS,
  parseControlInbound,
  useRemoteControl,
} from '@/composables/useRemoteControl'
import { useWsStore } from '@/stores/ws'
import type { Agent } from '@/stores/agents'

const AGENT_ID = '69f0000000000000000000c3'
const TENANT_ID = '69f0000000000000000000a1'
const S1 = '69f0000000000000000000d1'
const S2 = '69f0000000000000000000d2'

class FakeChannel {
  readyState: 'connecting' | 'open' | 'closed' = 'connecting'
  binaryType = 'blob'
  onopen: (() => void) | null = null
  onclose: (() => void) | null = null
  onmessage: ((ev: { data: unknown }) => void) | null = null
  sent: unknown[] = []
  constructor(readonly label: string) {}
  send(d: unknown) {
    this.sent.push(d)
  }
  open() {
    this.readyState = 'open'
    this.onopen?.()
  }
  close() {
    if (this.readyState === 'closed') return
    this.readyState = 'closed'
    this.onclose?.()
  }
  addEventListener() {}
  removeEventListener() {}
}

class FakePc {
  static all: FakePc[] = []
  connectionState = 'new'
  closed = false
  bytes = 0
  channels: FakeChannel[] = []
  onconnectionstatechange: (() => void) | null = null
  ontrack: unknown = null
  onicecandidate: ((ev: { candidate: unknown }) => void) | null = null
  constructor(public config: unknown) {
    FakePc.all.push(this)
  }
  createDataChannel(label: string) {
    const c = new FakeChannel(label)
    this.channels.push(c)
    return c
  }
  addTransceiver() {
    return {}
  }
  getConfiguration() {
    return this.config
  }
  setConfiguration(c: unknown) {
    this.config = c
  }
  async getStats() {
    this.bytes += 10_000
    return new Map([['in', { type: 'inbound-rtp', kind: 'video', bytesReceived: this.bytes, timestamp: Date.now() }]])
  }
  async createOffer() {
    return { type: 'offer', sdp: 'v=0\r\n' }
  }
  async setLocalDescription() {}
  async setRemoteDescription() {}
  async addIceCandidate() {}
  close() {
    this.closed = true
    this.connectionState = 'closed'
  }
  setState(s: string) {
    this.connectionState = s
    this.onconnectionstatechange?.()
  }
  addEventListener() {}
  removeEventListener() {}
  getReceivers() {
    return []
  }
  getTransceivers() {
    return []
  }
  getSenders() {
    return []
  }
}

type Msg = Record<string, unknown>

function makeRig(opts?: { shareGrantId?: string }) {
  setActivePinia(createPinia())
  const ws = useWsStore()
  const sent: Msg[] = []
  const handlers = new Map<string, Set<(m: Msg) => void>>()
  ws.sendRaw = (m: unknown) => {
    if (ws.status === 'connected') sent.push(m as Msg)
  }
  ws.onRcMessage = (t: string, h: (m: Msg) => void) => {
    let s = handlers.get(t)
    if (!s) {
      s = new Set()
      handlers.set(t, s)
    }
    s.add(h)
    return () => {
      handlers.get(t)?.delete(h)
    }
  }
  ws.forceRedial = vi.fn()
  ws.setTenantAffinity = vi.fn()
  ws.getDialedTid = () => TENANT_ID
  ws.status = 'connected'
  globalThis.fetch = vi.fn(async () => ({})) as unknown as typeof fetch

  const agentRef = ref<Agent | null>({
    id: AGENT_ID,
    name: 'workstation-1',
    is_online: true,
    os: 'linux',
  } as unknown as Agent)

  const rc = useRemoteControl(agentRef, {
    userId: () => 'user-1',
    shareGrantId: opts?.shareGrantId ? () => opts.shareGrantId! : undefined,
  })
  return {
    rc,
    ws,
    agentRef,
    sent,
    deliver(m: Msg) {
      for (const h of [...(handlers.get(String(m.t)) ?? [])]) h(m)
    },
    pc: () => FakePc.all[FakePc.all.length - 1]!,
    control: () => FakePc.all[FakePc.all.length - 1]!.channels.find((c) => c.label === 'control')!,
    sentOf: (t: string) => sent.filter((m) => m.t === t),
  }
}

async function openSession(rig: ReturnType<typeof makeRig>, sid: string) {
  await rig.rc.connect(AGENT_ID, 'VIEW | INPUT')
  rig.deliver({ t: 'rc:session.created', session_id: sid, agent_id: AGENT_ID, permissions: 'VIEW | INPUT' })
  rig.deliver({ t: 'rc:ready', session_id: sid })
  await vi.advanceTimersByTimeAsync(10)
  rig.deliver({ t: 'rc:sdp.answer', session_id: sid, sdp: 'v=0\r\n' })
  await vi.advanceTimersByTimeAsync(10)
  rig.pc().setState('connected')
  rig.control().open()
  await vi.advanceTimersByTimeAsync(10)
}

beforeEach(() => {
  FakePc.all = []
  vi.stubGlobal('RTCPeerConnection', FakePc)
  vi.useFakeTimers()
  vi.setSystemTime(1_800_000_000_000)
})

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe('FR-141 remote desktop restart continuity', () => {
  it('parseControlInbound extracts optional restart metadata while preserving legacy shape', () => {
    expect(
      parseControlInbound(JSON.stringify({ t: 'rc:ended', reason: 'host_disconnect' })),
    ).toEqual({ kind: 'ended', reason: 'host_disconnect', limit: null })

    expect(
      parseControlInbound(
        JSON.stringify({
          t: 'rc:ended',
          reason: 'agent_disconnect',
          limit: 'restart',
          eta_ms: 5000,
          to_version: '0.4.219',
        }),
      ),
    ).toEqual({
      kind: 'ended',
      reason: 'agent_disconnect',
      limit: 'restart',
      etaMs: 5000,
      toVersion: '0.4.219',
    })
  })

  it('sets restartingDevice, wakes immediately when presence flips online, and sends continues_from', async () => {
    const rig = makeRig()
    await openSession(rig, S1)
    expect(rig.rc.phase.value).toBe('connected')
    expect(rig.rc.restartingDevice.value).toBeNull()

    // Device announces graceful update restart on the control DataChannel.
    rig.control().onmessage?.({
      data: JSON.stringify({
        t: 'rc:ended',
        reason: 'agent_disconnect',
        limit: 'restart',
        eta_ms: 5000,
        to_version: '0.4.219',
      }),
    })
    expect(rig.rc.phase.value).toBe('reconnecting')
    expect(rig.rc.restartingDevice.value).toMatchObject({
      etaMs: 5000,
      toVersion: '0.4.219',
    })

    // Simulate device going offline briefly then flipping back online via presence push.
    rig.agentRef.value = { ...(rig.agentRef.value as Agent), is_online: false }
    await nextTick()
    rig.agentRef.value = { ...(rig.agentRef.value as Agent), is_online: true }
    await nextTick()
    await vi.advanceTimersByTimeAsync(10)

    const reqs = rig.sentOf('rc:session.request')
    expect(reqs.length).toBeGreaterThanOrEqual(2)
    const retryReq = reqs[reqs.length - 1]!
    expect(retryReq.continues_from).toBe(S1)

    // Complete reconnect and verify recovery banner clears once live.
    rig.deliver({ t: 'rc:session.created', session_id: S2, agent_id: AGENT_ID, permissions: 'VIEW | INPUT' })
    rig.deliver({ t: 'rc:ready', session_id: S2 })
    await vi.advanceTimersByTimeAsync(10)
    rig.deliver({ t: 'rc:sdp.answer', session_id: S2, sdp: 'v=0\r\n' })
    await vi.advanceTimersByTimeAsync(10)
    rig.pc().setState('connected')
    expect(rig.rc.phase.value).toBe('connected')
    expect(rig.rc.restartingDevice.value).toBeNull()
  })

  it('omits continues_from past the 120 s window and clears state on user disconnect', async () => {
    const rig = makeRig()
    await openSession(rig, S1)

    rig.control().onmessage?.({
      data: JSON.stringify({
        t: 'rc:ended',
        reason: 'agent_disconnect',
        limit: 'restart',
        eta_ms: 5000,
      }),
    })
    expect(rig.rc.restartingDevice.value).not.toBeNull()

    // User cancels recovery manually.
    rig.rc.disconnect()
    expect(rig.rc.restartingDevice.value).toBeNull()
    expect(rig.rc.phase.value).toBe('closed')

    // Even after time passes beyond RC_CONTINUE_WINDOW_MS, a fresh connect never carries stale continues_from.
    vi.advanceTimersByTime(RC_CONTINUE_WINDOW_MS + 1_000)
    await rig.rc.connect(AGENT_ID, 'VIEW | INPUT')
    const lastReq = rig.sentOf('rc:session.request').at(-1)!
    expect(lastReq.continues_from).toBeUndefined()
  })

  it('never emits continues_from or restart recovery for shared sessions', async () => {
    const rig = makeRig({ shareGrantId: '69f0000000000000000000e1' })
    await openSession(rig, S1)

    rig.control().onmessage?.({
      data: JSON.stringify({
        t: 'rc:ended',
        reason: 'agent_disconnect',
        limit: 'restart',
        eta_ms: 5000,
      }),
    })
    expect(rig.rc.restartingDevice.value).toBeNull()
    await vi.advanceTimersByTimeAsync(500)
    const retryReq = rig.sentOf('rc:session.request').at(-1)!
    expect(retryReq.continues_from).toBeUndefined()
  })
})
