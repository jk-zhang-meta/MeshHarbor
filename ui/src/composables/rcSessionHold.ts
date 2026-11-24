// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-130 P1c (#3604) — the viewer's hold: a remote-control session the server
 * called resumable rides out the loss of its control socket, and claims the
 * session back when a socket is up again. Spec §4.5.
 *
 * A server roll used to end every live session: the agent closed its peers at
 * its control socket's loss, and the page then opened a new session, at a cost
 * of 6–24 s, a new row and, on a device that asks, a new consent prompt. With
 * FR-130 the agent keeps its peer through the gap, and so does the page: the
 * pixels and the input never crossed the server, only the signalling did.
 *
 * | Event | What the hold does |
 * |---|---|
 * | `rc:session.created` with `resume_secs` | {@link SessionHold.arm}: the session may be held, for that many seconds at most |
 * | the page's own socket drops, the session live | the hold starts; its deadline is the drop + `resume_secs` + {@link RC_HOLD_GRACE_MS} |
 * | `rc:session.detached {resume_by}` | the hold starts, if it has not; its deadline becomes `resume_by` + {@link RC_HOLD_GRACE_MS}, read skew-safe ({@link holdRemainingMs}); a rejoin goes out {@link RC_REJOIN_RETRY_MS} later |
 * | the page's socket is back | `rc:session.rejoin {session_id}` at once |
 * | `rc:session.resumed` | the hold ends, `resumed` |
 * | `rc:terminate`, `rc:ended`, a transport signal, a hangup | the hold ends, `ended`, and the composable does what it does today |
 * | the deadline | the hold ends, `expired`: the composable closes the peer and starts today's ladder |
 * | an automatic redial of a session `rc:session.detached` named, until `rc:session.resumed` | {@link SessionHold.deviceDetached}: the composable sends no hangup first (D5 = A); a person's Disconnect still does |
 *
 * The machine owns no socket, no peer and no clock: the composable hands them
 * in ({@link SessionHoldDeps}), so every row above is a unit test
 * (`rcSessionHold.spec.ts`).
 *
 * ⚠️ Off is today. A session whose create carried no `resume_secs` (every
 * session until the server announces windows, FR-130 P3), or an external one
 * (FR-52, D3), is never armed, and an unarmed hold does nothing at all: no
 * rejoin, no deadline, no record.
 */

/** How long past its deadline the page holds before it gives the session up:
 *  the spec's "`resume_by` plus 5 s". The device's own deadline is the window;
 *  the grace lets its claim, and the server's answer to the page, land first. */
export const RC_HOLD_GRACE_MS = 5_000

/** A rejoin answered `rc:session.detached` (the device has not claimed the
 *  session yet) asks again this long after that answer: "once a second". */
export const RC_REJOIN_RETRY_MS = 1_000

/** The most a page ever holds, whatever a server announces: the agent caps
 *  its own window at 120 s (P2a), so a longer hold would wait on a peer the
 *  device has already closed. */
export const RC_RESUME_SECS_MAX = 120

/**
 * `resume_secs` from `rc:session.created`: a positive whole number of seconds,
 * capped at {@link RC_RESUME_SECS_MAX}; anything else is no window, and the
 * session is never held. Absent is what every server sends until FR-130 P3.
 */
export function parseResumeSecs(v: unknown): number | null {
  if (typeof v !== 'number' || !Number.isInteger(v) || v <= 0) return null
  return Math.min(v, RC_RESUME_SECS_MAX)
}

/** The window a session is held for: none for an external session (FR-52, D3:
 *  an outsider's authority is a login bound to both DTLS fingerprints, which a
 *  new pod cannot re-prove), else {@link parseResumeSecs}. */
export function holdWindowFor(resumeSecs: unknown, external: boolean): number | null {
  return external ? null : parseResumeSecs(resumeSecs)
}

/**
 * How long this page may still hold a detached session, counted from the
 * receipt of `rc:session.detached`.
 *
 * `resume_by` is unix ms on the SERVER's clock, and a server's time is not this
 * browser's (#3511). So it is read once, at receipt, against this browser's
 * wall clock, and what is left is bounded to `[0, resume_secs]`: a browser
 * clock behind the server's holds no longer than the window itself, one ahead
 * reads the deadline as past and gives up after the grace. From then on only
 * the monotonic clock counts, so a wall-clock step during the hold moves
 * nothing. A `resume_by` that is no number reads as the whole window.
 */
export function holdRemainingMs(resumeByMs: number, wallNowMs: number, resumeSecs: number): number {
  const windowMs = resumeSecs * 1000
  const left = resumeByMs - wallNowMs
  if (!Number.isFinite(left)) return windowMs
  return Math.min(Math.max(left, 0), windowMs)
}

export type RcHoldOutcome = 'resumed' | 'ended' | 'expired'

/** One hold, as it ended: what `rc.resume` records (`rcResumeRecord.ts`). */
export interface RcHoldSummary {
  sessionId: string
  outcome: RcHoldOutcome
  /** Why an `ended` hold ended: the server's or the device's reason token,
   *  `transport` for a transport signal, `controller_hangup` for the person's
   *  own hangup. `null` for `resumed` and `expired`. */
  reason: string | null
  /** From the cut to the outcome. */
  heldMs: number
  /** How long the page's own socket was down inside the hold. */
  wsDownMs: number
}

export interface SessionHoldDeps {
  /** A monotonic clock, in ms: `performance.now()`. */
  now(): number
  /** This browser's wall clock, in unix ms: read only against `resume_by`. */
  wallNow(): number
  setTimer(fn: () => void, ms: number): unknown
  clearTimer(handle: unknown): void
  /** The page's socket is open now. */
  socketUp(): boolean
  /** Send `rc:session.rejoin {session_id}`. */
  sendRejoin(sessionId: string): void
  /** A hold started: the cut. */
  onStart(sessionId: string): void
  /** The deadline passed with no answer. The hold has ended `expired`; the
   *  composable closes the peer and starts today's ladder. */
  onExpired(summary: RcHoldSummary): void
}

export interface SessionHold {
  /** The session `rc:session.created` named, held for `resumeSecs` at most;
   *  `null` disarms (the session is never held). */
  arm(sessionId: string, resumeSecs: number | null): void
  /** Forget the session, a hold in progress included, silently: its teardown. */
  disarm(): void
  /** Did the server call this session resumable? */
  resumable(sessionId: string | null): boolean
  holding(): boolean
  heldSession(): string | null
  /** Ms left before the hold gives up, `null` when none runs. */
  deadlineIn(): number | null
  /** The page's socket dropped. The composable calls it only while the
   *  session is live, and once more when a session goes live with it down. */
  socketDown(): void
  /** The page's socket is back. */
  socketUp(): void
  /** `rc:session.detached` arrived; `false` when it is not this hold's. */
  detached(sessionId: string, resumeBy: unknown): boolean
  /** `rc:session.resumed` arrived: the hold's summary when it ended one. */
  resumed(sessionId: string): RcHoldSummary | null
  /** The hold ends `ended`, with `reason`; `null` when none ran. */
  end(reason: string): RcHoldSummary | null
  /**
   * FR-130 D5 = A (#3604) — has the server told this page that its device
   * holds `sessionId` no longer (`rc:session.detached`), with no
   * `rc:session.resumed` since? The hold's end does not clear it (the
   * deadline's own redial reads it after `expired`); the next {@link arm},
   * {@link disarm} or `rc:session.resumed` does. While it is true an automatic
   * redial sends no hangup: the session ended on its device's side, and the
   * redial's `replaces` records that (`agent_disconnect`, inferred).
   */
  deviceDetached(sessionId: string | null): boolean
}

interface Running {
  sessionId: string
  startedAt: number
  deadlineAt: number
  /** Whether the deadline now comes from a `resume_by`: the first one replaces
   *  the socket-loss fallback, and each later one may only bring it closer. */
  fromResumeBy: boolean
  downSince: number | null
  downMs: number
  deadlineTimer: unknown
  rejoinTimer: unknown
}

export function createSessionHold(deps: SessionHoldDeps): SessionHold {
  let armedId: string | null = null
  let windowSecs = 0
  let run: Running | null = null
  /** The session `rc:session.detached` last named for this hold, until it is
   *  resumed or the hold is armed again ({@link SessionHold.deviceDetached}). */
  let detachedId: string | null = null

  function setDeadline(at: number) {
    if (!run) return
    run.deadlineAt = at
    if (run.deadlineTimer !== null) deps.clearTimer(run.deadlineTimer)
    run.deadlineTimer = deps.setTimer(onDeadline, Math.max(0, at - deps.now()))
  }

  function clearRejoin() {
    if (run && run.rejoinTimer !== null) {
      deps.clearTimer(run.rejoinTimer)
      run.rejoinTimer = null
    }
  }

  function onDeadline() {
    if (!run) return
    run.deadlineTimer = null
    const summary = finish('expired', null)
    if (summary) deps.onExpired(summary)
  }

  function start(downNow: boolean) {
    if (!armedId) return
    const now = deps.now()
    run = {
      sessionId: armedId,
      startedAt: now,
      deadlineAt: now,
      fromResumeBy: false,
      downSince: downNow ? now : null,
      downMs: 0,
      deadlineTimer: null,
      rejoinTimer: null,
    }
    // A dying pod may never send `rc:session.detached`: until one arrives the
    // hold counts from its own start.
    setDeadline(now + windowSecs * 1000 + RC_HOLD_GRACE_MS)
    deps.onStart(armedId)
  }

  function finish(outcome: RcHoldOutcome, reason: string | null): RcHoldSummary | null {
    if (!run) return null
    const now = deps.now()
    if (run.deadlineTimer !== null) deps.clearTimer(run.deadlineTimer)
    clearRejoin()
    const downMs = run.downMs + (run.downSince !== null ? now - run.downSince : 0)
    const summary: RcHoldSummary = {
      sessionId: run.sessionId,
      outcome,
      reason,
      heldMs: Math.round(now - run.startedAt),
      wsDownMs: Math.round(downMs),
    }
    run = null
    return summary
  }

  return {
    arm(sessionId, resumeSecs) {
      finish('ended', 'teardown')
      armedId = resumeSecs ? sessionId : null
      windowSecs = resumeSecs ?? 0
      detachedId = null
    },
    disarm() {
      finish('ended', 'teardown')
      armedId = null
      windowSecs = 0
      detachedId = null
    },
    resumable(sessionId) {
      return sessionId !== null && armedId !== null && sessionId === armedId
    },
    holding() {
      return run !== null
    },
    heldSession() {
      return run?.sessionId ?? null
    },
    deadlineIn() {
      return run ? Math.max(0, run.deadlineAt - deps.now()) : null
    },
    socketDown() {
      if (!armedId) return
      if (!run) {
        start(true)
        return
      }
      if (run.downSince === null) run.downSince = deps.now()
      // Nothing can be asked while the socket is down; its return asks.
      clearRejoin()
    },
    socketUp() {
      if (!run) return
      if (run.downSince !== null) {
        run.downMs += deps.now() - run.downSince
        run.downSince = null
      }
      clearRejoin()
      deps.sendRejoin(run.sessionId)
    },
    detached(sessionId, resumeBy) {
      if (!armedId || sessionId !== armedId) return false
      if (!run) start(!deps.socketUp())
      if (!run) return false
      detachedId = sessionId
      if (typeof resumeBy === 'number' && Number.isFinite(resumeBy)) {
        const at = deps.now() + holdRemainingMs(resumeBy, deps.wallNow(), windowSecs) + RC_HOLD_GRACE_MS
        // A repeated `rc:session.detached` never moves the deadline later: a
        // recount against a skewed clock would, every second.
        setDeadline(run.fromResumeBy ? Math.min(run.deadlineAt, at) : at)
        run.fromResumeBy = true
      }
      // The device has not claimed the session yet: ask again in a second.
      // While the socket is down its return asks instead.
      if (deps.socketUp()) {
        clearRejoin()
        const held = run
        held.rejoinTimer = deps.setTimer(() => {
          held.rejoinTimer = null
          if (run === held && deps.socketUp()) deps.sendRejoin(held.sessionId)
        }, RC_REJOIN_RETRY_MS)
      }
      return true
    },
    resumed(sessionId) {
      // The device has the session again, whether or not a hold still runs.
      if (detachedId === sessionId) detachedId = null
      if (!run || run.sessionId !== sessionId) return null
      return finish('resumed', null)
    },
    end(reason) {
      return finish('ended', reason)
    },
    deviceDetached(sessionId) {
      return sessionId !== null && detachedId === sessionId
    },
  }
}

/** The page's reading of `gap_ms` for one hold, from the paint path's answers
 *  to its mark (`workers/rc-paint-gap.ts`). */
export interface RcHoldPaintGap {
  /** How long before the cut the last frame was painted; `null` before any. */
  marked(sinceMs: unknown): void
  /** The first frame painted after the cut came `gapMs` after the last one
   *  before it; `null` when none came before. Only the first one counts. */
  closed(gapMs: unknown): void
  /** The gap as it reads at `nowMs` (the page's monotonic clock): exact once a
   *  frame was painted after the cut; before that a lower bound, `open`. */
  read(nowMs: number): { gapMs: number | null; open: boolean }
}

function msOrNull(v: unknown): number | null | undefined {
  if (v === null) return null
  return typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : undefined
}

export function createHoldPaintGap(cutAtMs: number): RcHoldPaintGap {
  /** `undefined`: the paint path has not answered (or answered garbage). */
  let sinceAtCut: number | null | undefined = undefined
  let gap: number | null | undefined = undefined
  return {
    marked(sinceMs) {
      const v = msOrNull(sinceMs)
      if (v !== undefined && sinceAtCut === undefined) sinceAtCut = v
    },
    closed(gapMs) {
      const v = msOrNull(gapMs)
      if (v !== undefined && gap === undefined) gap = v
    },
    read(nowMs) {
      if (gap !== undefined) return { gapMs: gap, open: false }
      if (typeof sinceAtCut === 'number') return { gapMs: sinceAtCut + Math.max(0, nowMs - cutAtMs), open: true }
      return { gapMs: null, open: true }
    },
  }
}
