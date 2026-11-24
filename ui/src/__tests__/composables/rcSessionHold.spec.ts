// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-130 P1c (#3604) — the viewer's hold, as a machine with its clocks and
// timers handed in: a session the server called resumable (`resume_secs` on
// `rc:session.created`) rides out the loss of its control socket, claims the
// session back with `rc:session.rejoin`, and gives it up at its own deadline.
// Spec §4.5; the composable wiring is locked in `useRemoteControl.hold.spec.ts`.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  RC_HOLD_GRACE_MS,
  RC_REJOIN_RETRY_MS,
  RC_RESUME_SECS_MAX,
  createHoldPaintGap,
  createSessionHold,
  holdRemainingMs,
  holdWindowFor,
  parseResumeSecs,
  type RcHoldSummary,
  type SessionHold,
} from '@/composables/rcSessionHold'

const S1 = '69f0000000000000000000d1'
const S2 = '69f0000000000000000000d2'

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(1_800_000_000_000)
})
afterEach(() => {
  vi.useRealTimers()
})

/** A hold over the fake clock. `skewMs` is how far this browser's wall clock
 *  reads from the server's (+ ahead, - behind); the monotonic clock is the
 *  fake timers' own. */
function rig(opts: { skewMs?: number; up?: boolean } = {}) {
  let up = opts.up ?? true
  const rejoins: Array<{ id: string; at: number }> = []
  const starts: string[] = []
  const expired: RcHoldSummary[] = []
  const t0 = performance.now()
  const hold: SessionHold = createSessionHold({
    now: () => performance.now(),
    wallNow: () => Date.now() + (opts.skewMs ?? 0),
    setTimer: (fn, ms) => setTimeout(fn, ms),
    clearTimer: (h) => clearTimeout(h as ReturnType<typeof setTimeout>),
    socketUp: () => up,
    sendRejoin: (id) => rejoins.push({ id, at: performance.now() - t0 }),
    onStart: (id) => starts.push(id),
    onExpired: (s) => expired.push(s),
  })
  return {
    hold,
    rejoins,
    starts,
    expired,
    setUp(v: boolean) {
      up = v
      if (v) hold.socketUp()
      else hold.socketDown()
    },
    /** The server's wall clock now: `resume_by` is on it. */
    serverNow: () => Date.now(),
  }
}

describe('parseResumeSecs / holdWindowFor — which sessions may be held', () => {
  it('a positive whole number of seconds is a window; anything else is no hold at all', () => {
    expect(parseResumeSecs(60)).toBe(60)
    expect(parseResumeSecs(1)).toBe(1)
    for (const v of [0, -5, 59.5, '60', null, undefined, Number.NaN, Infinity, {}]) {
      expect(parseResumeSecs(v)).toBeNull()
    }
  })

  it('never longer than the agent keeps a peer (120 s), whatever a server says', () => {
    expect(RC_RESUME_SECS_MAX).toBe(120)
    expect(parseResumeSecs(3600)).toBe(120)
    expect(parseResumeSecs(120)).toBe(120)
  })

  it('an external session (FR-52) never holds, whatever the create carried (D3)', () => {
    expect(holdWindowFor(60, true)).toBeNull()
    expect(holdWindowFor(60, false)).toBe(60)
    expect(holdWindowFor(undefined, false)).toBeNull()
  })
})

describe('holdRemainingMs — resume_by is on the SERVER clock (#3511)', () => {
  it('read once, at receipt, against this browser: the clocks agree', () => {
    expect(holdRemainingMs(1_000_030_000, 1_000_000_000, 60)).toBe(30_000)
  })

  it('a browser an hour behind the server holds no longer than the window itself', () => {
    const server = 1_000_000_000
    const browser = server - 3_600_000
    expect(holdRemainingMs(server + 60_000, browser, 60)).toBe(60_000)
  })

  it('a browser an hour ahead reads a deadline already past: nothing left, never negative', () => {
    const server = 1_000_000_000
    const browser = server + 3_600_000
    expect(holdRemainingMs(server + 60_000, browser, 60)).toBe(0)
  })

  it('a resume_by that is no number reads as the whole window', () => {
    expect(holdRemainingMs(Number.NaN, 1, 60)).toBe(60_000)
  })
})

describe('createSessionHold — off is today', () => {
  it('a session the server did not call resumable never holds, never rejoins', () => {
    const r = rig()
    r.hold.arm(S1, null)
    expect(r.hold.resumable(S1)).toBe(false)
    r.setUp(false)
    expect(r.hold.detached(S1, r.serverNow() + 60_000)).toBe(false)
    vi.advanceTimersByTime(5_000)
    r.setUp(true)
    vi.advanceTimersByTime(200_000)
    expect(r.hold.holding()).toBe(false)
    expect(r.starts).toEqual([])
    expect(r.rejoins).toEqual([])
    expect(r.expired).toEqual([])
  })
})

describe('createSessionHold — hold through the page\'s own socket loss', () => {
  it('starts at the loss, keeps going while the socket is down, and rejoins the moment it is back', () => {
    const r = rig()
    r.hold.arm(S1, 60)
    expect(r.hold.resumable(S1)).toBe(true)
    expect(r.hold.resumable(S2)).toBe(false)
    r.setUp(false)
    expect(r.hold.holding()).toBe(true)
    expect(r.hold.heldSession()).toBe(S1)
    expect(r.starts).toEqual([S1])
    vi.advanceTimersByTime(3_000)
    // Nothing is asked while the socket is down.
    expect(r.rejoins).toEqual([])
    r.setUp(true)
    expect(r.rejoins).toEqual([{ id: S1, at: 3_000 }])
  })

  it('rc:session.resumed ends the hold: how long it held and how long the socket was down', () => {
    const r = rig()
    r.hold.arm(S1, 60)
    r.setUp(false)
    vi.advanceTimersByTime(3_000)
    r.setUp(true)
    vi.advanceTimersByTime(400)
    expect(r.hold.resumed(S2)).toBeNull()
    const s = r.hold.resumed(S1)
    expect(s).toEqual({ sessionId: S1, outcome: 'resumed', reason: null, heldMs: 3_400, wsDownMs: 3_000 })
    expect(r.hold.holding()).toBe(false)
    // Still resumable: the next loss holds again.
    expect(r.hold.resumable(S1)).toBe(true)
    vi.advanceTimersByTime(200_000)
    expect(r.expired).toEqual([])
  })

  it('no resume_by at all (a dying pod may never send one): the socket\'s loss + resume_secs + 5 s', () => {
    const r = rig()
    r.hold.arm(S1, 60)
    r.setUp(false)
    expect(r.hold.deadlineIn()).toBe(60_000 + RC_HOLD_GRACE_MS)
    vi.advanceTimersByTime(60_000 + RC_HOLD_GRACE_MS - 1)
    expect(r.expired).toEqual([])
    vi.advanceTimersByTime(1)
    expect(r.expired).toEqual([{ sessionId: S1, outcome: 'expired', reason: null, heldMs: 65_000, wsDownMs: 65_000 }])
    expect(r.hold.holding()).toBe(false)
  })

  it('a socket that bounces inside one hold counts both outages, and rejoins each time it is back', () => {
    const r = rig()
    r.hold.arm(S1, 60)
    r.setUp(false)
    vi.advanceTimersByTime(1_000)
    r.setUp(true)
    vi.advanceTimersByTime(500)
    r.setUp(false)
    vi.advanceTimersByTime(2_000)
    r.setUp(true)
    expect(r.rejoins.map((x) => x.at)).toEqual([1_000, 3_500])
    expect(r.hold.end('transport')).toEqual({
      sessionId: S1,
      outcome: 'ended',
      reason: 'transport',
      heldMs: 3_500,
      wsDownMs: 3_000,
    })
  })

  it('a window above the agent\'s cap is held for the cap', () => {
    const r = rig()
    r.hold.arm(S1, parseResumeSecs(3600))
    r.setUp(false)
    expect(r.hold.deadlineIn()).toBe(120_000 + RC_HOLD_GRACE_MS)
  })
})

describe('createSessionHold — rc:session.detached', () => {
  it('holds a session whose device lost its socket while this page\'s socket stayed up, and asks once a second', () => {
    const r = rig()
    r.hold.arm(S1, 60)
    expect(r.hold.detached(S1, r.serverNow() + 60_000)).toBe(true)
    expect(r.hold.holding()).toBe(true)
    expect(r.starts).toEqual([S1])
    vi.advanceTimersByTime(RC_REJOIN_RETRY_MS - 1)
    expect(r.rejoins).toEqual([])
    vi.advanceTimersByTime(1)
    expect(r.rejoins).toEqual([{ id: S1, at: 1_000 }])
    // Answered `rc:session.detached` again: the device has not claimed yet.
    r.hold.detached(S1, r.serverNow() + 59_000)
    vi.advanceTimersByTime(RC_REJOIN_RETRY_MS)
    r.hold.detached(S1, r.serverNow() + 58_000)
    vi.advanceTimersByTime(RC_REJOIN_RETRY_MS)
    expect(r.rejoins.map((x) => x.at)).toEqual([1_000, 2_000, 3_000])
  })

  it('without an answer it does not ask again: no rejoin storm against a server that drops them', () => {
    const r = rig()
    r.hold.arm(S1, 60)
    r.hold.detached(S1, r.serverNow() + 60_000)
    vi.advanceTimersByTime(30_000)
    expect(r.rejoins).toHaveLength(1)
  })

  it('a detached for another session is not this hold\'s', () => {
    const r = rig()
    r.hold.arm(S1, 60)
    expect(r.hold.detached(S2, r.serverNow() + 60_000)).toBe(false)
    expect(r.hold.holding()).toBe(false)
  })

  it('while the socket is down nothing is asked; its return asks at once', () => {
    const r = rig()
    r.hold.arm(S1, 60)
    r.setUp(false)
    r.hold.detached(S1, r.serverNow() + 60_000)
    vi.advanceTimersByTime(5_000)
    expect(r.rejoins).toEqual([])
    r.setUp(true)
    expect(r.rejoins).toEqual([{ id: S1, at: 5_000 }])
  })

  it('the deadline is resume_by + 5 s, counted from receipt', () => {
    const r = rig()
    r.hold.arm(S1, 60)
    r.hold.detached(S1, r.serverNow() + 30_000)
    expect(r.hold.deadlineIn()).toBe(30_000 + RC_HOLD_GRACE_MS)
    vi.advanceTimersByTime(35_000 - 1)
    expect(r.expired).toEqual([])
    vi.advanceTimersByTime(1)
    expect(r.expired.map((s) => s.outcome)).toEqual(['expired'])
  })

  it('a browser clock an hour BEHIND the server: bounded by resume_secs, never an hour', () => {
    const r = rig({ skewMs: -3_600_000 })
    r.hold.arm(S1, 60)
    r.hold.detached(S1, r.serverNow() + 60_000)
    expect(r.hold.deadlineIn()).toBe(60_000 + RC_HOLD_GRACE_MS)
    vi.advanceTimersByTime(65_000)
    expect(r.expired).toHaveLength(1)
  })

  it('a browser clock an hour AHEAD: the deadline reads as past, so the grace alone, then the ladder', () => {
    const r = rig({ skewMs: 3_600_000 })
    r.hold.arm(S1, 60)
    r.hold.detached(S1, r.serverNow() + 60_000)
    expect(r.hold.deadlineIn()).toBe(RC_HOLD_GRACE_MS)
    vi.advanceTimersByTime(RC_HOLD_GRACE_MS)
    expect(r.expired).toHaveLength(1)
  })

  it('a repeated detached never moves the deadline later (a skewed recount would)', () => {
    const r = rig({ skewMs: -3_600_000 })
    r.hold.arm(S1, 60)
    const resumeBy = r.serverNow() + 60_000
    r.hold.detached(S1, resumeBy)
    for (let i = 0; i < 64; i += 1) {
      vi.advanceTimersByTime(1_000)
      r.hold.detached(S1, resumeBy)
    }
    vi.advanceTimersByTime(1_000)
    expect(r.expired).toHaveLength(1)
    expect(r.expired[0]!.heldMs).toBe(65_000)
  })

  it('the first resume_by the hold hears replaces the socket-loss fallback', () => {
    const r = rig()
    r.hold.arm(S1, 60)
    r.setUp(false) // fallback: 65 s from here
    vi.advanceTimersByTime(30_000)
    r.setUp(true)
    // The device detached later than this page's socket dropped.
    r.hold.detached(S1, r.serverNow() + 60_000)
    expect(r.hold.deadlineIn()).toBe(65_000)
    vi.advanceTimersByTime(64_999)
    expect(r.expired).toEqual([])
    vi.advanceTimersByTime(1)
    expect(r.expired[0]!.heldMs).toBe(95_000)
  })

  it('a resume_by that is no number keeps the fallback', () => {
    const r = rig()
    r.hold.arm(S1, 60)
    r.hold.detached(S1, 'soon')
    expect(r.hold.deadlineIn()).toBe(65_000)
  })
})

describe('createSessionHold — deviceDetached: the server said the device holds the session no longer (D5 = A)', () => {
  it('false until rc:session.detached names this hold\'s session; a loss of this page\'s own socket is not it', () => {
    const r = rig()
    r.hold.arm(S1, 60)
    expect(r.hold.deviceDetached(S1)).toBe(false)
    r.setUp(false)
    expect(r.hold.holding()).toBe(true)
    expect(r.hold.deviceDetached(S1)).toBe(false)
    r.setUp(true)
    r.hold.detached(S1, r.serverNow() + 60_000)
    expect(r.hold.deviceDetached(S1)).toBe(true)
    expect(r.hold.deviceDetached(S2)).toBe(false)
    expect(r.hold.deviceDetached(null)).toBe(false)
  })

  it('outlives the hold\'s own end: the deadline\'s redial reads it after expired, and a transport end too', () => {
    const r = rig()
    r.hold.arm(S1, 60)
    r.hold.detached(S1, r.serverNow() + 60_000)
    vi.advanceTimersByTime(65_000)
    expect(r.expired).toHaveLength(1)
    expect(r.hold.deviceDetached(S1)).toBe(true)
    const t = rig()
    t.hold.arm(S1, 60)
    t.hold.detached(S1, t.serverNow() + 60_000)
    t.hold.end('transport')
    expect(t.hold.deviceDetached(S1)).toBe(true)
  })

  it('rc:session.resumed clears it (the device has the session again), and so do arm() and disarm()', () => {
    const r = rig()
    r.hold.arm(S1, 60)
    r.hold.detached(S1, r.serverNow() + 60_000)
    r.hold.resumed(S1)
    expect(r.hold.deviceDetached(S1)).toBe(false)
    r.hold.detached(S1, r.serverNow() + 60_000)
    r.hold.arm(S2, 60)
    expect(r.hold.deviceDetached(S1)).toBe(false)
    r.hold.detached(S2, r.serverNow() + 60_000)
    r.hold.disarm()
    expect(r.hold.deviceDetached(S2)).toBe(false)
  })

  it('a detached for another session, or for a session never armed, sets nothing', () => {
    const r = rig()
    r.hold.arm(S1, 60)
    r.hold.detached(S2, r.serverNow() + 60_000)
    expect(r.hold.deviceDetached(S2)).toBe(false)
    const off = rig()
    off.hold.arm(S1, null)
    off.hold.detached(S1, off.serverNow() + 60_000)
    expect(off.hold.deviceDetached(S1)).toBe(false)
  })
})

describe('createSessionHold — every end clears its timers', () => {
  it('end() is an end with its reason, and nothing fires after it', () => {
    const r = rig()
    r.hold.arm(S1, 60)
    r.hold.detached(S1, r.serverNow() + 60_000)
    vi.advanceTimersByTime(700)
    expect(r.hold.end('agent_disconnect')).toEqual({
      sessionId: S1,
      outcome: 'ended',
      reason: 'agent_disconnect',
      heldMs: 700,
      wsDownMs: 0,
    })
    vi.advanceTimersByTime(200_000)
    expect(r.rejoins).toEqual([])
    expect(r.expired).toEqual([])
    expect(r.hold.end('again')).toBeNull()
  })

  it('disarm() drops a hold silently, and the session is no longer resumable', () => {
    const r = rig()
    r.hold.arm(S1, 60)
    r.setUp(false)
    r.hold.disarm()
    expect(r.hold.holding()).toBe(false)
    expect(r.hold.resumable(S1)).toBe(false)
    r.setUp(true)
    vi.advanceTimersByTime(200_000)
    expect(r.rejoins).toEqual([])
    expect(r.expired).toEqual([])
  })
})

describe('createHoldPaintGap — gap_ms, from the last frame painted before the cut to the first after it', () => {
  it('exact once a frame was painted after the cut', () => {
    const g = createHoldPaintGap(1_000)
    g.marked(40)
    g.closed(56)
    expect(g.read(9_000)).toEqual({ gapMs: 56, open: false })
    // Only the first frame after the cut counts.
    g.closed(4_000)
    expect(g.read(9_000)).toEqual({ gapMs: 56, open: false })
  })

  it('no frame after the cut yet: a lower bound, marked open', () => {
    const g = createHoldPaintGap(1_000)
    g.marked(40)
    expect(g.read(2_000)).toEqual({ gapMs: 1_040, open: true })
  })

  it('nothing ever painted before the cut: there is no gap to name', () => {
    const g = createHoldPaintGap(1_000)
    g.marked(null)
    expect(g.read(2_000)).toEqual({ gapMs: null, open: true })
    g.closed(null)
    expect(g.read(2_000)).toEqual({ gapMs: null, open: false })
  })

  it('a paint path that never answered the mark names nothing; garbage is ignored', () => {
    const g = createHoldPaintGap(1_000)
    expect(g.read(2_000)).toEqual({ gapMs: null, open: true })
    g.marked('x')
    g.marked(-1)
    g.closed(Number.NaN)
    expect(g.read(2_000)).toEqual({ gapMs: null, open: true })
  })
})
