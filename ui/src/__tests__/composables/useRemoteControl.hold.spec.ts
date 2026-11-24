// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-130 P1c (#3604) — the viewer's hold, end to end through the real
// composable: a session whose `rc:session.created` carried `resume_secs` rides
// out the loss of its control socket (its own, or the device's, which the
// server says with `rc:session.detached`), claims the session back with
// `rc:session.rejoin`, and falls back to today's ladder at its deadline or on a
// transport signal, naming what its redial replaces. Without `resume_secs` the
// page is today's, on the wire and off it. Spec §4.5.
//
// The peer is a fake `RTCPeerConnection` and the socket the WS store with its
// I/O stubbed; everything between them is the composable as it ships.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ref } from 'vue'
import { createPinia, setActivePinia } from 'pinia'

vi.mock('@/api/client', () => ({ api: { get: vi.fn(async () => ({ ice_servers: [] })) } }))

import {
  RC_PC_DISCONNECTED_GRACE_MS,
  classifyDegraded,
  friendlyEndReason,
  parseControlInbound,
  useRemoteControl,
} from '@/composables/useRemoteControl'
import { useWsStore } from '@/stores/ws'

const AGENT = '69f0000000000000000000c3'
const TENANT = '69f0000000000000000000a1'
const S1 = '69f0000000000000000000d1'
const S2 = '69f0000000000000000000d2'
const PERMS = 'VIEW | INPUT | CLIPBOARD | FILES | RECORD'
/** The spec's numbers (§4.5), pinned here rather than read from the code:
 *  the page gives a held session up `resume_by` plus 5 s, and asks again once
 *  a second while the device has not claimed it. */
const RC_HOLD_GRACE_MS = 5_000
const RC_REJOIN_RETRY_MS = 1_000

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
  /** RTP bytes that grow on every read: media is flowing, so the media
   *  watchdog never re-creates the session on its own. */
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

type Msg = Record<string, any>

/** One page: its own store, so a second rig in a test never shares a socket
 *  with the first. */
function makeRig() {
  setActivePinia(createPinia())
  const ws = useWsStore()
  const sent: Msg[] = []
  const dropped: Msg[] = []
  const handlers = new Map<string, Set<(m: any) => void>>()
  // The real `sendRaw` drops what it is given while the socket is not open.
  ws.sendRaw = (m: unknown) => {
    if (ws.status === 'connected') sent.push(m as Msg)
    else dropped.push(m as Msg)
  }
  ws.onRcMessage = (t: string, h: (m: any) => void) => {
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
  ws.getDialedTid = () => TENANT
  ws.status = 'connected'
  const posts: Msg[] = []
  globalThis.fetch = vi.fn(async (_url: unknown, init?: RequestInit) => {
    posts.push(JSON.parse(String(init?.body)))
    return {}
  }) as unknown as typeof fetch
  const rc = useRemoteControl(ref(null), { userId: () => null })
  return {
    rc,
    ws,
    sent,
    dropped,
    posts,
    deliver(m: Msg) {
      for (const h of [...(handlers.get(m.t) ?? [])]) h(m)
    },
    pc: () => FakePc.all[FakePc.all.length - 1]!,
    control: () => FakePc.all[FakePc.all.length - 1]!.channels.find((c) => c.label === 'control')!,
    sentOf: (t: string) => sent.filter((m) => m.t === t),
    records: (target: string): Msg[] =>
      posts.flatMap((b) => (b.lines as Msg[]).filter((l) => l.target === target).map((l) => ({ ...l, session_id: b.session_id }))),
    /** The page's socket goes down, or comes back as the store brings it back. */
    socket(up: boolean) {
      ws.status = up ? 'connected' : 'disconnected'
      if (up) window.dispatchEvent(new CustomEvent('ws:reconnected'))
    },
  }
}
type Rig = ReturnType<typeof makeRig>

async function flush(ms = 0) {
  await vi.advanceTimersByTimeAsync(ms)
}

/** A live session: requested, created with `created`'s extra fields, offered,
 *  answered and connected, its control channel open. */
async function live(r: Rig, created: Msg = {}, sid = S1) {
  await r.rc.connect(AGENT, PERMS, false, TENANT)
  r.deliver({ t: 'rc:session.created', session_id: sid, agent_id: AGENT, ...created })
  r.deliver({ t: 'rc:ready', session_id: sid })
  await flush()
  r.deliver({ t: 'rc:sdp.answer', session_id: sid, sdp: 'v=0\r\n' })
  await flush()
  r.pc().setState('connected')
  r.control().open()
  await flush(1_000)
  expect(r.rc.phase.value).toBe('connected')
}

/** Frames on the `<video>` path, as the view's frame callback reports them:
 *  one every `every` ms for `ms` ms (`ms` a multiple of `every`). */
async function paint(r: Rig, ms: number, every = 20) {
  for (let t = 0; t < ms; t += every) {
    r.rc.notePaint(performance.now())
    await flush(every)
  }
}

/** The next redial's request, once the ladder has fired it. */
async function nextRequest(r: Rig): Promise<Msg> {
  const before = r.sentOf('rc:session.request').length
  for (let i = 0; i < 40 && r.sentOf('rc:session.request').length === before; i += 1) await flush(250)
  const all = r.sentOf('rc:session.request')
  expect(all.length).toBeGreaterThan(before)
  return all[all.length - 1]!
}

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(1_800_000_000_000)
  // No loopback probe: the page would fetch 127.0.0.1 for a relay.
  localStorage.setItem('meshharbor-rc-local-relay', '0')
  ;(globalThis as unknown as { RTCPeerConnection: unknown }).RTCPeerConnection = FakePc
  FakePc.all = []
})
afterEach(() => {
  vi.useRealTimers()
  localStorage.clear()
})

describe('FR-130 P1c — hold', () => {
  it('holds through its own socket loss: connected, the same peer and channels, the chip reading server link down', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    const pc = r.pc()
    r.socket(false)
    await flush(10_000)
    expect(r.rc.phase.value).toBe('connected')
    expect(r.rc.sessionHeld.value).toBe(true)
    expect(pc.closed).toBe(false)
    expect(r.control().readyState).toBe('open')
    expect(FakePc.all).toHaveLength(1)
    expect(r.rc.degraded.value).toBe('signalling_offline')
  })

  it('holds through rc:session.detached while its own socket is up, and still says server link down', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    r.deliver({ t: 'rc:session.detached', session_id: S1, resume_by: Date.now() + 60_000 })
    await flush(2_000)
    expect(r.rc.phase.value).toBe('connected')
    expect(r.rc.degraded.value).toBe('signalling_offline')
    expect(r.rc.sessionHeld.value).toBe(true)
    expect(r.pc().closed).toBe(false)
  })

  it('sends no ICE while it holds: the server cannot route it, and an error back would end the session', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    r.deliver({ t: 'rc:session.detached', session_id: S1, resume_by: Date.now() + 60_000 })
    r.pc().onicecandidate?.({ candidate: { toJSON: () => ({ candidate: 'candidate:1' }) } })
    expect(r.sentOf('rc:ice')).toEqual([])
  })
})

describe('FR-130 P1c — rejoin', () => {
  it('rejoins the moment its socket is back; rc:session.resumed clears the chip, and no new attempt starts', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    r.socket(false)
    await flush(3_000)
    expect(r.sentOf('rc:session.rejoin')).toEqual([])
    r.socket(true)
    expect(r.sentOf('rc:session.rejoin')).toEqual([{ t: 'rc:session.rejoin', session_id: S1 }])
    r.deliver({ t: 'rc:session.resumed', session_id: S1 })
    expect(r.rc.sessionHeld.value).toBe(false)
    await flush(1_000)
    expect(r.rc.degraded.value).toBeNull()
    expect(r.rc.phase.value).toBe('connected')
    expect(r.sentOf('rc:session.request')).toHaveLength(1)
    expect(FakePc.all).toHaveLength(1)
  })

  it('a rejoin answered rc:session.detached asks again once a second, until it is answered', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    r.socket(false)
    await flush(2_000)
    r.socket(true)
    expect(r.sentOf('rc:session.rejoin')).toHaveLength(1)
    for (let i = 2; i <= 4; i += 1) {
      r.deliver({ t: 'rc:session.detached', session_id: S1, resume_by: Date.now() + 50_000 })
      await flush(RC_REJOIN_RETRY_MS - 1)
      expect(r.sentOf('rc:session.rejoin')).toHaveLength(i - 1)
      await flush(1)
      expect(r.sentOf('rc:session.rejoin')).toHaveLength(i)
    }
    r.deliver({ t: 'rc:session.resumed', session_id: S1 })
    await flush(10_000)
    expect(r.sentOf('rc:session.rejoin')).toHaveLength(4)
    expect(r.rc.sessionHeld.value).toBe(false)
  })

  it('a rejoin answered rc:terminate with a retryable reason starts today\'s ladder, and the redial names the session it replaces', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    const held = r.pc()
    r.socket(false)
    await flush(2_000)
    r.socket(true)
    r.deliver({ t: 'rc:terminate', session_id: S1, reason: 'agent_disconnect' })
    expect(r.rc.phase.value).toBe('reconnecting')
    expect(held.closed).toBe(true)
    const req = await nextRequest(r)
    expect(req.replaces).toBe(S1)
    expect(req.agent_id).toBe(AGENT)
  })

  it('a rejoin answered rc:terminate with a deliberate reason closes, says why, and redials nothing', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    r.socket(false)
    await flush(2_000)
    r.socket(true)
    r.deliver({ t: 'rc:terminate', session_id: S1, reason: 'admin_terminated' })
    expect(r.rc.phase.value).toBe('closed')
    expect(r.rc.error.value).toBe(friendlyEndReason('admin_terminated'))
    expect(r.rc.error.value).not.toBeNull()
    await flush(30_000)
    expect(r.sentOf('rc:session.request')).toHaveLength(1)
  })

  it('an rc:error while it holds is the server refusing the rejoin: it redials, naming what it replaces', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    r.socket(false)
    await flush(1_000)
    r.socket(true)
    r.deliver({ t: 'rc:error', code: 'session_not_found', message: 'no such session' })
    expect(r.rc.phase.value).toBe('reconnecting')
    expect(r.rc.error.value).toBeNull()
    const req = await nextRequest(r)
    expect(req.replaces).toBe(S1)
  })
})

describe('FR-130 P1c — fall back', () => {
  it('with no resume_by at all: its socket\'s loss + resume_secs + 5 s, then the peer is closed and the ladder starts', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    const held = r.pc()
    r.socket(false)
    await flush(60_000 + RC_HOLD_GRACE_MS - 100)
    expect(r.rc.phase.value).toBe('connected')
    expect(held.closed).toBe(false)
    await flush(200)
    expect(r.rc.phase.value).toBe('reconnecting')
    expect(held.closed).toBe(true)
    r.socket(true)
    const req = await nextRequest(r)
    expect(req.replaces).toBe(S1)
  })

  it('the deadline from resume_by is skew-safe: a browser an hour BEHIND the server holds resume_secs + 5 s, not an hour', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    const serverNow = Date.now() + 3_600_000
    r.deliver({ t: 'rc:session.detached', session_id: S1, resume_by: serverNow + 60_000 })
    await flush(60_000 + RC_HOLD_GRACE_MS - 100)
    expect(r.rc.phase.value).toBe('connected')
    await flush(200)
    expect(r.rc.phase.value).toBe('reconnecting')
  })

  it('…and a browser an hour AHEAD reads the deadline as past: it gives the session up after the grace alone', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    const serverNow = Date.now() - 3_600_000
    r.deliver({ t: 'rc:session.detached', session_id: S1, resume_by: serverNow + 60_000 })
    await flush(RC_HOLD_GRACE_MS - 100)
    expect(r.rc.phase.value).toBe('connected')
    await flush(200)
    expect(r.rc.phase.value).toBe('reconnecting')
  })

  it('a transport signal during the hold keeps today\'s meaning: the peer failed, so it redials, naming what it replaces', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    r.socket(false)
    await flush(1_000)
    r.pc().setState('failed')
    expect(r.rc.phase.value).toBe('reconnecting')
    // The best-effort hangup went into a dead socket, as it does today.
    expect(r.dropped.filter((m) => m.t === 'rc:terminate')).toEqual([
      { t: 'rc:terminate', session_id: S1, reason: 'controller_hangup' },
    ])
    r.socket(true)
    const req = await nextRequest(r)
    expect(req.replaces).toBe(S1)
    expect(r.rc.sessionHeld.value).toBe(false)
  })

  it('a peer sitting disconnected past its grace during the hold redials as today (the derp case)', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    r.socket(false)
    r.pc().setState('disconnected')
    await flush(RC_PC_DISCONNECTED_GRACE_MS + 10)
    expect(r.rc.phase.value).toBe('reconnecting')
    r.socket(true)
    const req = await nextRequest(r)
    expect(req.replaces).toBe(S1)
  })

  it('the replaced id is kept until a request is answered, then dropped', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    r.pc().setState('failed')
    const first = await nextRequest(r)
    expect(first.replaces).toBe(S1)
    // Unanswered: the next attempt names it again.
    const second = await nextRequest(r)
    expect(second.replaces).toBe(S1)
    // Answered with a session this page never held: nothing to replace next.
    r.deliver({ t: 'rc:session.created', session_id: S2, agent_id: AGENT })
    r.deliver({ t: 'rc:terminate', session_id: S2, reason: 'agent_disconnect' })
    const third = await nextRequest(r)
    expect(third.replaces).toBeUndefined()
  })

})

describe('FR-130 D5 — no hangup before the redial of a session the server says is detached', () => {
  // D5 = A (the operator, 2026-11-11). The device is away, so the session
  // ended on its side, and the redial's `replaces` records that
  // (`agent_disconnect`, inferred). A hangup sent first, over this page's own
  // socket, wrote `controller_hangup` for a session nobody hung up (#3604,
  // AC4 cell (d)).
  const hangups = (r: Rig) => [...r.sent, ...r.dropped].filter((m) => m.t === 'rc:terminate')
  const HANGUP = { t: 'rc:terminate', session_id: S1, reason: 'controller_hangup' }

  it('the device closes its kept peer at its deadline: no rc:terminate, and the redial names what it replaces', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    r.deliver({ t: 'rc:session.detached', session_id: S1, resume_by: Date.now() + 60_000 })
    await flush(2_000)
    r.control().close()
    expect(r.rc.phase.value).toBe('reconnecting')
    const req = await nextRequest(r)
    expect(req.replaces).toBe(S1)
    expect(hangups(r)).toEqual([])
  })

  it('…nor when the peer fails during the gap', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    r.deliver({ t: 'rc:session.detached', session_id: S1, resume_by: Date.now() + 60_000 })
    await flush(2_000)
    r.pc().setState('failed')
    expect(r.rc.phase.value).toBe('reconnecting')
    const req = await nextRequest(r)
    expect(req.replaces).toBe(S1)
    expect(hangups(r)).toEqual([])
  })

  it('…nor at the page\'s own deadline, resume_by + 5 s', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    r.deliver({ t: 'rc:session.detached', session_id: S1, resume_by: Date.now() + 60_000 })
    await flush(60_000 + RC_HOLD_GRACE_MS + 100)
    expect(r.rc.phase.value).toBe('reconnecting')
    const req = await nextRequest(r)
    expect(req.replaces).toBe(S1)
    expect(hangups(r)).toEqual([])
  })

  it('a rejoin answered rc:session.detached counts the same: the page\'s own socket was back first', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    r.socket(false)
    await flush(2_000)
    r.socket(true)
    r.deliver({ t: 'rc:session.detached', session_id: S1, resume_by: Date.now() + 50_000 })
    await flush(500)
    r.control().close()
    const req = await nextRequest(r)
    expect(req.replaces).toBe(S1)
    expect(hangups(r)).toEqual([])
  })

  it('the person\'s own Disconnect during the gap still says controller_hangup', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    r.deliver({ t: 'rc:session.detached', session_id: S1, resume_by: Date.now() + 60_000 })
    await flush(1_000)
    r.rc.disconnect()
    expect(hangups(r)).toEqual([HANGUP])
  })

  it('once the device has claimed it back (rc:session.resumed), a transport signal sends the hangup as today', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    r.deliver({ t: 'rc:session.detached', session_id: S1, resume_by: Date.now() + 60_000 })
    await flush(1_000)
    r.deliver({ t: 'rc:session.resumed', session_id: S1 })
    r.pc().setState('failed')
    expect(hangups(r)).toEqual([HANGUP])
  })

  it('a session the server never said is detached keeps today\'s hangup: its device is connected, and the hangup frees its place now', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    r.pc().setState('failed')
    expect(hangups(r)).toEqual([HANGUP])
    const req = await nextRequest(r)
    expect(req.replaces).toBe(S1)
  })
})

describe('FR-130 P1c — rc:ended on the control channel', () => {
  it('the person at the device ended it during the gap: closed as host_disconnect is, no ladder, the replay arguments dropped', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    r.socket(false)
    await flush(1_000)
    r.control().onmessage?.({ data: JSON.stringify({ t: 'rc:ended', reason: 'host_disconnect' }) })
    expect(r.rc.phase.value).toBe('closed')
    expect(r.rc.endedBy.value).toBe('host')
    expect(r.pc().closed).toBe(true)
    r.socket(true)
    await flush(30_000)
    expect(r.sentOf('rc:session.request')).toHaveLength(1)
    expect(r.sentOf('rc:session.rejoin')).toEqual([])
  })

  it('a retryable end said by the device (a refused claim) starts today\'s ladder, naming what it replaces', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    r.socket(false)
    r.control().onmessage?.({ data: JSON.stringify({ t: 'rc:ended', reason: 'agent_disconnect' }) })
    expect(r.rc.phase.value).toBe('reconnecting')
    expect(r.rc.endedBy.value).toBeNull()
    expect(r.rc.error.value).toBeNull()
    r.socket(true)
    const req = await nextRequest(r)
    expect(req.replaces).toBe(S1)
  })

  it('a final end said by the device (a kick) closes with its sentence, no ladder, the replay arguments dropped', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    r.control().onmessage?.({ data: JSON.stringify({ t: 'rc:ended', reason: 'admin_terminated' }) })
    expect(r.rc.phase.value).toBe('closed')
    expect(r.rc.endedBy.value).toBeNull()
    expect(r.rc.error.value).toBe(friendlyEndReason('admin_terminated'))
    await flush(30_000)
    expect(r.sentOf('rc:session.request')).toHaveLength(1)
  })

  it('the organization\'s maximum length, said by the device, is final and says so', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    r.control().onmessage?.({ data: JSON.stringify({ t: 'rc:ended', reason: 'idle_timeout', limit: 'max_duration' }) })
    expect(r.rc.phase.value).toBe('closed')
    expect(r.rc.error.value).toBe(friendlyEndReason('idle_timeout', 'max_duration'))
    await flush(30_000)
    expect(r.sentOf('rc:session.request')).toHaveLength(1)
  })

  it('rc:ended then rc:terminate for the same session is one end: the first wins, the second does nothing', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    r.control().onmessage?.({ data: JSON.stringify({ t: 'rc:ended', reason: 'host_disconnect' }) })
    r.deliver({ t: 'rc:terminate', session_id: S1, reason: 'admin_terminated' })
    expect(r.rc.phase.value).toBe('closed')
    expect(r.rc.endedBy.value).toBe('host')
    expect(r.rc.error.value).toBeNull()
  })

  it('rc:terminate then rc:ended for the same session is one end too: a late retryable rc:ended starts no ladder', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    const control = r.control()
    r.deliver({ t: 'rc:terminate', session_id: S1, reason: 'admin_terminated' })
    control.onmessage?.({ data: JSON.stringify({ t: 'rc:ended', reason: 'agent_disconnect' }) })
    expect(r.rc.phase.value).toBe('closed')
    expect(r.rc.error.value).toBe(friendlyEndReason('admin_terminated'))
    await flush(30_000)
    expect(r.sentOf('rc:session.request')).toHaveLength(1)
  })

  it('a late rc:ended from a peer the page has replaced ends nothing', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    const oldControl = r.control()
    r.pc().setState('failed')
    await nextRequest(r)
    r.deliver({ t: 'rc:session.created', session_id: S2, agent_id: AGENT })
    r.deliver({ t: 'rc:ready', session_id: S2 })
    await flush()
    r.deliver({ t: 'rc:sdp.answer', session_id: S2, sdp: 'v=0\r\n' })
    await flush()
    r.pc().setState('connected')
    expect(r.rc.phase.value).toBe('connected')
    oldControl.onmessage?.({ data: JSON.stringify({ t: 'rc:ended', reason: 'host_disconnect' }) })
    expect(r.rc.phase.value).toBe('connected')
    expect(r.rc.endedBy.value).toBeNull()
  })

  it('the device\'s idle limit says so, and is no more retried than the server\'s idle end', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    r.deliver({ t: 'rc:session.detached', session_id: S1, resume_by: Date.now() + 60_000 })
    r.control().onmessage?.({ data: JSON.stringify({ t: 'rc:ended', reason: 'idle_timeout', limit: 'idle' }) })
    expect(r.rc.phase.value).toBe('closed')
    expect(r.rc.endedBy.value).toBeNull()
    expect(r.rc.error.value).toBe(friendlyEndReason('idle_timeout', 'idle'))
    await flush(30_000)
    expect(r.sentOf('rc:session.request')).toHaveLength(1)
  })
})

describe('FR-130 P1c — rc.resume, a record of its own', () => {
  it('resumed: v, outcome, gap_ms across the cut, ws_down_ms, filed under the held session; no rc.connect for a resume', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    await paint(r, 200)
    const connectBefore = r.records('rc.connect').length
    r.socket(false)
    await paint(r, 3_000)
    r.socket(true)
    await paint(r, 400)
    r.deliver({ t: 'rc:session.resumed', session_id: S1 })
    const rec = r.records('rc.resume')
    expect(rec).toHaveLength(1)
    expect(rec[0]!.session_id).toBe(S1)
    expect(rec[0]!.level).toBe('INFO')
    expect(rec[0]!.fields).toMatchObject({
      v: 1,
      outcome: 'resumed',
      gap_open: false,
      ws_down_ms: 3_000,
      held_ms: 3_400,
      agent_id: AGENT,
      hidden: false,
    })
    // Frames every 20 ms straight through the cut: the gap is one of them.
    expect(rec[0]!.fields.gap_ms).toBe(20)
    expect(r.records('rc.connect')).toHaveLength(connectBefore)
  })

  it('a frozen picture across the cut is what gap_ms reads', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    await paint(r, 100)
    r.deliver({ t: 'rc:session.detached', session_id: S1, resume_by: Date.now() + 60_000 })
    await flush(2_436)
    await paint(r, 100)
    r.deliver({ t: 'rc:session.resumed', session_id: S1 })
    const f = r.records('rc.resume')[0]!.fields
    expect(f.gap_open).toBe(false)
    expect(f.gap_ms).toBeGreaterThanOrEqual(2_436)
    expect(f.gap_ms).toBeLessThan(2_436 + 40)
  })

  it('ended, with the server\'s reason', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    r.socket(false)
    await flush(500)
    r.socket(true)
    r.deliver({ t: 'rc:terminate', session_id: S1, reason: 'agent_disconnect' })
    const ended = r.records('rc.resume')
    expect(ended.map((x) => [x.fields.outcome, x.fields.reason])).toEqual([['ended', 'agent_disconnect']])
    expect(ended[0]!.level).toBe('WARN')
  })

  it('expired at the deadline, its socket down the whole time', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    r.socket(false)
    await flush(65_100)
    const expired = r.records('rc.resume')
    expect(expired.map((x) => x.fields.outcome)).toEqual(['expired'])
    expect(expired[0]!.fields.ws_down_ms).toBe(65_000)
    expect(expired[0]!.fields.held_ms).toBe(65_000)
  })

  it('a peer that fails during the hold ends it as transport', async () => {
    const r = makeRig()
    await live(r, { resume_secs: 60 })
    r.socket(false)
    await flush(700)
    r.pc().setState('failed')
    expect(r.records('rc.resume').map((x) => [x.fields.outcome, x.fields.reason])).toEqual([['ended', 'transport']])
  })
})

describe('FR-130 P1c — without resume_secs, the page is today\'s', () => {
  it('no rejoin, rc:session.detached ignored, no rc.resume, and the redial\'s request is the same as master\'s', async () => {
    const r = makeRig()
    await live(r, {})
    const first = r.sentOf('rc:session.request')[0]!
    r.deliver({ t: 'rc:session.detached', session_id: S1, resume_by: Date.now() + 60_000 })
    await flush(2_000)
    expect(r.rc.degraded.value).toBeNull()
    r.socket(false)
    await flush(5_000)
    expect(r.rc.degraded.value).toBe('signalling_offline')
    r.socket(true)
    await flush(70_000)
    expect(r.sentOf('rc:session.rejoin')).toEqual([])
    expect(r.rc.phase.value).toBe('connected')
    r.pc().setState('failed')
    const redial = await nextRequest(r)
    expect(Object.keys(redial).sort()).toEqual(Object.keys(first).sort())
    expect(redial).toEqual(first)
    expect('replaces' in redial).toBe(false)
    expect(r.records('rc.resume')).toEqual([])
  })

  it('a resume_secs of 0 or of no number is no window', async () => {
    for (const resume_secs of [0, '60', -1]) {
      const r = makeRig()
      await live(r, { resume_secs })
      r.socket(false)
      await flush(1_000)
      r.socket(true)
      expect(r.sentOf('rc:session.rejoin')).toEqual([])
      r.rc.disconnect()
    }
  })
})

describe('FR-130 P1c — the pure pieces the page reads', () => {
  it('classifyDegraded: a held session reads server link down while its socket is up; the priorities stand', () => {
    expect(classifyDegraded({ pcState: 'connected', wsConnected: true, stallTicks: 0, held: true })).toBe('signalling_offline')
    expect(classifyDegraded({ pcState: 'connected', wsConnected: true, stallTicks: 0, held: false })).toBeNull()
    expect(classifyDegraded({ pcState: 'connected', wsConnected: true, stallTicks: 0 })).toBeNull()
    expect(classifyDegraded({ pcState: 'disconnected', wsConnected: true, stallTicks: 0, held: true })).toBe('transport_unstable')
    expect(classifyDegraded({ pcState: 'connected', wsConnected: true, stallTicks: 6, held: true })).toBe('media_stalled')
  })

  it('parseControlInbound reads rc:ended, its reason and its limit', () => {
    expect(parseControlInbound(JSON.stringify({ t: 'rc:ended', reason: 'host_disconnect' }))).toEqual({
      kind: 'ended',
      reason: 'host_disconnect',
      limit: null,
    })
    expect(parseControlInbound(JSON.stringify({ t: 'rc:ended', reason: 'idle_timeout', limit: 'idle' }))).toEqual({
      kind: 'ended',
      reason: 'idle_timeout',
      limit: 'idle',
    })
    expect(parseControlInbound(JSON.stringify({ t: 'rc:ended' }))).toBeNull()
  })

  it('an admin\'s end gets a sentence (spec §2.5)', () => {
    expect(friendlyEndReason('admin_terminated')).toMatch(/administrator/i)
  })
})
