// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { appRoutePath } from '@/utils/deployment'
import { defaultStunServers } from '@/utils/stun'
import { ref, watch, onBeforeUnmount, computed, type Ref, type ComputedRef } from 'vue'
import { useWsStore } from '@/stores/ws'
import { api } from '@/api/client'
import type { Agent } from '@/stores/agents'
import { sdpFingerprint, transportMac, verifyTransportMac } from '@/utils/extauth'
import {
  applyPeerAuthVerdict,
  browserStorage,
  controllerKeyFor,
  indexedDbKeyBackend,
  judgePeerAuth,
  offerAsk,
  withinMs,
  newPeerAuthNonce,
  peerAuthAskDisabled,
  peerAuthCanVerify,
  peerAuthFingerprint,
  shouldAskPeerAuth,
  singleFingerprint,
  storagePins,
  trustChangedKey,
  type PeerAuthJudgement,
  type PeerAuthPins,
} from '@/utils/peerAuth'
import { friendlyExtauthRefusal } from './useExternalLogin'
import {
  cellCodecOfTransport,
  cellsFromCaps,
  rememberCellFailure,
  rememberedCellFailures,
  resolveChroma,
} from '@/composables/videoCells'
import {
  bestClockSample,
  clockSample,
  epochNowUs,
  normalizeCtxMode,
  normalizeIntKnob,
  StruggleWindow,
  DEFAULT_MAX_DECODE_QUEUE,
  DEFAULT_STRUGGLE_QUEUE,
  DEFAULT_STRUGGLE_WINDOWS,
  type ClockSample,
  type CtxMode,
  type HopWindow,
} from '@/workers/rc-hop-stats'
import {
  normalizeSharpenMode,
  normalizeSharpness,
  DEFAULT_RCAS_SHARPNESS,
  type SharpenMode,
} from '@/workers/rc-fsr-render'

/**
 * Remote-control session state machine driven from the controller browser.
 *
 * Lifecycle: idle Ã¢ÂÂ requesting Ã¢ÂÂ awaiting_consent Ã¢ÂÂ negotiating Ã¢ÂÂ connected
 *                                                                Ã¢ÂÂ error
 *                                                                Ã¢ÂÂ closed
 *
 * The composable owns one RTCPeerConnection per session. It uses the shared
 * WS connection (useWsStore) as the signalling transport and speaks the
 * `rc:*` protocol. See docs/remote-control.md ÃÂ§7.
 */

export type RcPhase =
  | 'idle'
  | 'requesting'
  | 'awaiting_consent'
  | 'negotiating'
  | 'connected'
  | 'reconnecting'
  | 'closed'
  | 'error'

import {
  beginAttempt,
  describeConnectTiming,
  STALL_SNACK_MIN_GAP_MS,
  formatConnectTiming,
  type RcConnectMark,
  type RcConnectRecorder,
} from './rcConnectTiming'
import { createConnectTimingUploader, type RcConnectOutcome } from './rcConnectTimingUpload'
import {
  PROBE_TARGET,
  benchSessionMode,
  benchStats,
  createBenchProber,
  createL4Uploader,
  createVideoBenchSampler,
  formatBenchLine,
  probeTargetPointer,
  storedBenchMode,
  type BenchMode,
  type BenchPath,
  type BenchProber,
  type VideoBenchSampler,
} from './rcBench'
import { useSnackbar } from './useSnackbar'
import { useRemoteRecording, type RecordChannel } from './useRemoteRecording'
import {
  grantHoldsPrivacy,
  openPrivacyChannel,
  usePrivacyMode,
  withPrivacyAsked,
  type PrivacyChannel,
} from './usePrivacyMode'
import { keepBusySetMessage, parseKeepBusyState, type KeepBusyRequest, type KeepBusyState } from './keepBusy'
import { parseDisplayMatchState, type DisplayMatchState } from './displayMatch'
import {
  FRAME_RATE_STORAGE_KEY,
  agentOffersHighRefresh,
  fpsWireMessage,
  frameRateAnswerOf,
  frameRateOptions,
  hostRefreshHzOf,
  toFrameRate,
  type FrameRate,
} from './frameRate'
import {
  createRelAccumulator,
  relativeAutoSwitchedOff,
  relativeButtonMessage,
  shouldAutoEnterRelative,
} from './relativeMouse'
import {
  createPointerPressTracker,
  phoneSized,
  readTouchMode,
  releaseForCancelledPointer,
  stageTouchAction,
  TOUCH_MODE_STORAGE_KEY,
  type TouchMode,
} from './touchInput'
import {
  createDirectGestures,
  createTrackpadGestures,
  createWheelSteps,
  WHEEL_CARRY_IDLE_MS,
  type GestureAction,
  type TouchSample,
  type TrackpadAction,
} from './touchGestures'
import { modsOf, type ControlsSink, type MouseBtn } from './touchControls'
import { parseFeaturesRefused } from './useSessionFeatures'
import { ctrlAltDelFrames } from './ctrlAltDel'

/**
 * Backoff ladder for the auto-reconnect path. The first three steps
 * (250 ms / 500 ms / 1 s) are tuned for desktop-transition recovery Ã¢ÂÂ
 * a Win+L lock or a M3 SYSTEM-context capture handoff usually
 * resolves in well under a second, and a 2 s first-retry would leave
 * a visible black-frame window every time the user touches the lock
 * screen. The last three (2 s / 4 s / 8 s) cover real network drops.
 * 6 attempts caps the worst case at ~16 s before we give up and
 * surface an error to the operator.
 */
export const RC_RECONNECT_LADDER_MS = [250, 500, 1000, 2000, 4000, 8000] as const

/**
 * Steady-state retry delay used AFTER `RC_RECONNECT_LADDER_MS` is
 * exhausted. rc.23 Ã¢ÂÂ the DC stays "open" from the operator's POV by
 * never surfacing a terminal "budget exhausted" state; the reconnect
 * loop keeps trying every `RC_RECONNECT_STEADY_MS` until the operator
 * cancels via the existing Cancel button or the upload completes via
 * resume. Field repro on the field-test host 2026-05-11/12: large file uploads
 * fail with the legacy 6-attempt cap because ESET intercepts cause
 * repeated DC drops; an operator who walks away from their machine
 * came back to a failed upload with no diagnostic context. With the
 * cap removed, they can leave it retrying and inspect the log
 * panel (also new in rc.23) at their leisure.
 */
export const RC_RECONNECT_STEADY_MS = 8000

/**
 * Extra delay for consecutive **dead-air** cycles — sessions that reached
 * `connected` but never delivered a single frame before the media watchdog
 * tore them down.
 *
 * `RC_RECONNECT_LADDER_MS` alone cannot slow this down, because reaching
 * `connected` used to reset the attempt counter: the peer connects, the
 * watchdog kills it 10 s later (`RC_WATCHDOG_TICK_MS` × `RC_STALL_FAIL_TICKS`)
 * having seen no media, and the next retry starts back at 250 ms. The ladder
 * counts CONNECTION failures, and this failure happens after a successful
 * connection — so the backoff never grew and the retry ran at fixed rate
 * forever.
 *
 * Field 2026-08-07: a controller left pointed at winhost-a, whose Check Point
 * profile leaves it with no usable ICE candidate, produced **388 sessions in
 * 24 h** — each connecting, running ~10.9 s of dead air, and dying. The other
 * hosts in the same office logged 3 and 4.
 *
 * The first two cycles stay fast: a lock-screen/SYSTEM-context handoff or a
 * codec renegotiation genuinely can produce one frameless session. From the
 * third, the pair almost certainly has no media path at all, and retrying
 * every ~19 s buys nothing — so back off to minutes and tell the operator.
 */
export const RC_DEAD_AIR_LADDER_MS = [0, 0, 0, 30_000, 60_000, 120_000, 300_000] as const

/**
 * Consecutive dead-air cycles → minimum delay before the next attempt.
 * `streak` is the number of frameless sessions seen in a row (1 = the first).
 * Exported for unit testing.
 */
export function deadAirDelayMs(streak: number): number {
  if (streak <= 0) return 0
  return RC_DEAD_AIR_LADDER_MS[Math.min(streak, RC_DEAD_AIR_LADDER_MS.length - 1)]
}

/**
 * S3 viewer resilience Ã¢ÂÂ detection constants. All exported so the
 * decision tables below are unit-lockable.
 *
 * - `RC_PC_DISCONNECTED_GRACE_MS`: how long the peer connection may sit
 *   in `'disconnected'` before we treat it as a failure and re-create
 *   the session. ICE flaps recover in ~1-2 s; a VPN flip on the host
 *   never does Ã¢ÂÂ 4 s separates the two without a visible false-positive
 *   window.
 * - `RC_SIGNALING_TIMEOUT_MS`: max time in `'negotiating'` before the
 *   attempt is abandoned and the ladder advances. ICE legitimately
 *   varies by network here (a corp-VPN host reaching a DERP relay is
 *   nothing like a LAN pair), so this stays generous.
 * - `RC_REQUEST_TIMEOUT_MS` (FR-22): the same bound applied to
 *   `'requesting'`, which is a different question - *did the server
 *   answer at all?* That is one hop, measured sub-second across ten
 *   consecutive sessions, so guarding it with the ICE-sized number meant
 *   a lost request cost 15 s before the 250 ms ladder retried and
 *   succeeded on the normal ~3 s path: about 18 s total, which is
 *   exactly the "sometimes 10-15 seconds" the operator reported. The bad
 *   case is now ~7 s; the good case is untouched.
 *   `awaiting_consent` is exempt from both - the SERVER owns that
 *   timeout (consent_timeout), and a human on a Prompt-mode org device
 *   may legitimately take longer than any client-side number.
 * - Watchdog: ticks every `RC_WATCHDOG_TICK_MS` while connected. After
 *   `RC_STALL_PROBE_TICKS` ticks with zero media progress it sends ONE
 *   `rc:keyframe` probe Ã¢ÂÂ a static remote desktop legitimately produces
 *   no frames, so flat counters alone must NOT trigger a reconnect; a
 *   live agent answers the probe with an IDR within a tick. Only if the
 *   counters stay flat through `RC_STALL_FAIL_TICKS` (probe unanswered)
 *   is the pipe declared dead.
 */
export const RC_PC_DISCONNECTED_GRACE_MS = 4000
export const RC_SIGNALING_TIMEOUT_MS = 15000
export const RC_REQUEST_TIMEOUT_MS = 4000

/**
 * #1631 - how long a request that went out and was then abandoned (the view
 * unmounted or the operator hung up while it was unanswered) keeps a
 * terminator armed for its late `rc:session.created`
 * (`createAbandonedRequestRegistry`). Twice the request timeout: a create
 * later than that would have been abandoned by the ladder anyway, and the
 * next request to the same agent reaps it on the hub.
 */
export const RC_LATE_CREATE_WINDOW_MS = 2 * RC_REQUEST_TIMEOUT_MS

/**
 * FR-22 - how long an attempt may sit in `phase` before the ladder
 * abandons it. `null` means "do not arm": `awaiting_consent` is
 * human-paced and server-owned, and the terminal phases have nothing
 * left to wait for.
 *
 * Exported and total over `RcPhase` so the table is unit-lockable and a
 * new phase must declare its own bound rather than silently inheriting
 * the ICE-sized one.
 */
export function signalingTimeoutFor(phase: RcPhase): number | null {
  switch (phase) {
    case 'requesting':
      return RC_REQUEST_TIMEOUT_MS
    case 'negotiating':
      return RC_SIGNALING_TIMEOUT_MS
    default:
      return null
  }
}

/**
 * PR-1 pre-flight: how long connect() waits for the signalling socket
 * to reach 'connected' after a re-key redial (or a plain cold socket)
 * before proceeding anyway and letting the ladder pace retries.
 */
export const RC_PREFLIGHT_WS_WAIT_MS = 5000
export const RC_WATCHDOG_TICK_MS = 1000
export const RC_STALL_PROBE_TICKS = 6
export const RC_STALL_FAIL_TICKS = 10

/**
 * Sub-`connected` health surfaced while `phase === 'connected'`:
 * the session is still up but something is wrong. Priority order
 * (highest wins): transport_unstable (pc left 'connected'),
 * media_stalled (probe outstanding, no frames), signalling_offline
 * (WS down Ã¢ÂÂ media may still flow P2P, but no renegotiation is
 * possible).
 */
export type RcDegradedReason =
  | 'transport_unstable'
  | 'media_stalled'
  | 'signalling_offline'

/**
 * `rc:terminate` reasons that auto-re-create the session instead of
 * closing the viewer. `agent_disconnect` is the reported VPN/agent-WS
 * displacement symptom; `error` covers transient agent-side failures.
 * Everything deliberate (hangups, denials, admin, idle) stays
 * terminal. Consent-loop note: a retry against a Prompt-mode org
 * device re-prompts its owner ONCE Ã¢ÂÂ an unanswered prompt ends in
 * `consent_timeout`, which is terminal, so the loop self-limits.
 *
 * #2251 - one `error` is final: `limit: 'no_common_codec'`, the device finding
 * no codec in common with this browser's offer. Asking again would send the
 * same offer into the same refusal, so it is said, never retried.
 */
export function isRetryableTerminateReason(reason: unknown, limit?: unknown): boolean {
  if (limit === 'no_common_codec') return false
  return reason === 'agent_disconnect' || reason === 'error'
}

/**
 * FR-27 P10 - the `rc:terminate` reason that means the PERSON AT THE DEVICE
 * ended the session (the banner's or the badge's Disconnect). Terminal like
 * every deliberate ending, and the one the viewer says out loud and offers
 * an explicit Reconnect for: re-asking a host that just sent you away is not
 * a retry, it is a new request, and it goes through consent like any other.
 * Only the device may claim it (the hub records a controller's claim as
 * `controller_hangup`), and pre-P10 agents never sent it, so a `true` here
 * is always the host's own word.
 */
export function endedByHost(reason: unknown): boolean {
  return reason === 'host_disconnect'
}

/**
 * `rc:error` codes that advance the reconnect ladder instead of
 * killing it. Only honoured while a reconnect cycle is active Ã¢ÂÂ a
 * user-initiated first connect hitting `agent_offline` should fail
 * fast and honestly. `agent_busy`: the old session's slot hasn't
 * freed yet (max_simultaneous_sessions=1). `agent_offline`: agent WS
 * mid-flap. `session_not_found`: stale state from the session we
 * already abandoned.
 */
export type ReadyRecoveryAction = 'proceed' | 'ignore' | 'reschedule' | 'fail'

/**
 * Decision for an inbound `rc:ready`. The old handler silently returned on
 * `!pc` or a gate mismatch, which parked the UI in `awaiting_consent`
 * FOREVER when the server's reply won a race against a client teardown
 * (2026-08-05 winhost-a incident: consent granted server-side, Ready
 * processed by nobody, session stuck in Negotiating, operator stuck at
 * "awaiting consent"). Gate mismatch = stale session, ignore; a missing
 * PeerConnection with retry args = reschedule through the ladder; without
 * args there is nothing to retry with = honest failure. Pure for tests.
 */
export function readyRecoveryAction(
  gateOk: boolean,
  hasPc: boolean,
  hasRetryArgs: boolean,
): ReadyRecoveryAction {
  if (!gateOk) return 'ignore'
  if (hasPc) return 'proceed'
  return hasRetryArgs ? 'reschedule' : 'fail'
}

/** What an inbound `rc:terminate` does, once it is known to be this session's. */
export type TerminateAction = 'keep-error' | 'reconnect' | 'close'

/**
 * Decision for an inbound `rc:terminate` that passed the session gate (a
 * `reconnecting` page has already ignored it). Pure for tests.
 *
 * - `keep-error`: this page already failed the session. Only `failWith` sets
 *   `error`, and it has torn everything down, so the terminate (typically the
 *   server's echo of the one the failing path sent) has nothing left to end.
 *   Turning the error into a plain `closed` would hide the error view, which is
 *   where the person reads why and where FR-100's "Trust the new key and
 *   connect" lives; field-caught on prod 2026-10-19, the button never showed.
 * - `reconnect`: an involuntary end, with the original request to replay.
 * - `close`: everything else; deliberate endings stay terminal.
 */
export function terminateAction(args: {
  phase: RcPhase
  retryable: boolean
  canReplay: boolean
}): TerminateAction {
  if (args.phase === 'error') return 'keep-error'
  if (args.retryable && args.canReplay && args.phase !== 'idle' && args.phase !== 'closed') {
    return 'reconnect'
  }
  return 'close'
}

export function isRetryableRcErrorCode(code: unknown): boolean {
  return code === 'agent_busy' || code === 'agent_offline' || code === 'session_not_found'
}

/**
 * #2251 - is this `rc:error` fallout of a session the server already ended?
 * After a scoped `rc:terminate` the phase is `closed` and the view shows that
 * end's own sentence. Frames that were in flight as it ended (the ICE
 * candidates a viewer trickles after an offer the device refused) come back as
 * errors scoped to that same session, `session_not_found`. They are not news:
 * failing on one replaced "This browser can't decode the video this device
 * sends" with "session ... not found" and turned a refusal into "The session
 * could not continue".
 */
export function isFalloutOfEndedSession(
  phase: string,
  errorSessionId: unknown,
  sessionId: string | null,
): boolean {
  return phase === 'closed' && typeof errorSessionId === 'string' && errorSessionId === sessionId
}

/**
 * Session-gate for inbound rc:* handlers: a message carrying a
 * session_id is only accepted when it matches the CURRENT session.
 * Messages without one (pre-session errors) always pass. Before this
 * gate, a stale `rc:terminate` from an abandoned session could kill
 * the fresh session that replaced it.
 */
export function sessionGateAllows(
  msgSessionId: unknown,
  currentSessionId: string | null,
): boolean {
  if (typeof msgSessionId !== 'string' || msgSessionId.length === 0) return true
  return currentSessionId !== null && msgSessionId === currentSessionId
}

/** #1631 - what the `rc:session.created` handler does with a create. */
export type SessionCreatedAction = 'adopt' | 'ignore' | 'terminate'

/**
 * #1631 - decide what an inbound `rc:session.created` means to THIS
 * composable.
 *
 * Outside `requesting` nothing is expected. A create naming the session we
 * already track is the #1045 coalesce echo (the server re-affirming our live
 * session after a duplicate request on this socket) and is ignored; any
 * other is a ghost the server would otherwise hold pinned to the agent until
 * the consent timeout, so it is released (`terminate`).
 *
 * Inside `requesting` the create is ours ONLY if it names the agent we asked
 * for. The server always sends `agent_id`
 * (`crates/remote_control/src/signaling.rs` `ServerMsg::SessionCreated`), and
 * a create for a different agent while we wait is exactly the device-switch
 * race: A's late create landing while B's request is in flight. The old
 * inline logic adopted it, and B's viewer then drove A. A create without an
 * `agent_id`, or one arriving while the requested agent is not known, is
 * adopted as before: the guard refuses only what it can prove foreign, so a
 * server that omitted the field could never brick Connect.
 */
/**
 * FR-85 P3c — does the session's EFFECTIVE grant (`rc:session.created`'s
 * `permissions`) hold RECORD? Never assumed: an older server that sends no
 * grant cannot have checked who may record, so absent means no. Each bit is
 * matched by equality, never as a prefix.
 */
export function grantHoldsRecord(permissions: unknown): boolean {
  return (
    typeof permissions === 'string' &&
    permissions.split('|').some((p) => p.trim() === 'RECORD')
  )
}

/**
 * FR-85 P3c — open the session's `record` channel from its grant: once per
 * PeerConnection, and only on a grant that holds RECORD (the device answers a
 * channel without it `not_granted`). Reliable and ordered, because a
 * download's chunks carry no offsets. Returns the channel it opened, or null.
 *
 * ⚠️ Called from `rc:session.created`, never beside `files` in `connect()`.
 * Those channels are made BEFORE the session request goes out, when no grant
 * has been seen, so a gate there is always closed and the channel never
 * exists: the Record button showed and did nothing (P3c's first cut, caught
 * before merge). The offer is built on `rc:ready`, which follows the create,
 * so a channel opened here is in it.
 */
export function openRecordChannel(
  pc: Pick<RTCPeerConnection, 'createDataChannel'> | null,
  channels: Record<string, RTCDataChannel>,
  permissions: unknown,
): RTCDataChannel | null {
  if (!pc || channels.record || !grantHoldsRecord(permissions)) return null
  channels.record = pc.createDataChannel('record', { ordered: true })
  return channels.record
}

export function sessionCreatedAction(
  phase: RcPhase,
  msg: { session_id?: unknown; agent_id?: unknown },
  trackedSessionId: string | null,
  requestedAgentId: string | null,
  isExternal: boolean,
): SessionCreatedAction {
  if (phase !== 'requesting') {
    if (typeof msg.session_id === 'string' && msg.session_id === trackedSessionId) {
      return 'ignore'
    }
    return 'terminate'
  }
  // FR-52 — an external session's agent_id is always the all-zero placeholder
  // (an outsider never learns the device's real id), so it can never equal
  // `requestedAgentId` ("ext:<code>"), and the foreign-agent guard below would
  // terminate every legitimate external session the instant it's created. The
  // device-switch race that guard exists for (#1631) has no external
  // equivalent: connect() only ever has one external request in flight per
  // composable, and a late create from an abandoned EARLIER attempt is the
  // abandoned-requests registry's job, not this live-phase check's.
  if (isExternal) return 'adopt'
  if (
    typeof msg.agent_id === 'string'
    && msg.agent_id !== ''
    && requestedAgentId !== null
    && msg.agent_id !== requestedAgentId
  ) {
    return 'terminate'
  }
  return 'adopt'
}

/** The slice of the WS store the late-create terminator needs. */
export interface AbandonedRequestIo {
  onRcMessage(t: string, handler: (msg: any) => void): () => void
  sendRaw(msg: unknown): void
}

export interface AbandonedRequestRegistry {
  /** Watch for the late create of a request to `agentId` that no composable
   *  will answer for any more, and release it when it lands. Re-arming
   *  replaces the previous entry and restarts its window. */
  arm(agentId: string): void
  /** Stop watching: the caller is about to request `agentId` again and wants
   *  the session the hub coalesces onto, not a terminate under its feet. */
  disarm(agentId: string): void
  /** Entries currently armed (tests). */
  readonly size: number
}

type AbandonedRequestEntry = { unsub: () => void; timer: ReturnType<typeof setTimeout> }

/**
 * #1631 - a bounded terminator for `rc:session.created`s that answer a
 * request whose composable is gone.
 *
 * `disconnect()` removes this composable's handlers, so a create landing
 * after the view unmounted mid-request (the operator picked another device in
 * the nav, or hung up before the server answered) had nobody to release it:
 * the hub kept the session pinned to the agent until the consent timeout, and
 * the next Connect on that agent bounced off `agent_busy`.
 *
 * The entries live at MODULE scope (`ABANDONED_REQUESTS`), shared by every
 * composable instance, because the instance that armed one is gone by the
 * time the create arrives. `connect()` disarms its agent right before it
 * sends, so A -> B -> A keeps the session the hub coalesces onto instead of
 * terminating it under the new viewer (coalescing is same-socket +
 * same-agent: `crates/modules/fleet/src/hub.rs`, `request_session`). Terminate
 * is idempotent on the hub, so this and a still-mounted sibling composable
 * both releasing one ghost is harmless. An entry disarms itself after
 * `windowMs`.
 */
export function createAbandonedRequestRegistry(
  io: AbandonedRequestIo,
  windowMs: number = RC_LATE_CREATE_WINDOW_MS,
  entries: Map<string, AbandonedRequestEntry> = new Map(),
): AbandonedRequestRegistry {
  function disarm(agentId: string) {
    const entry = entries.get(agentId)
    if (!entry) return
    entries.delete(agentId)
    clearTimeout(entry.timer)
    entry.unsub()
  }
  function arm(agentId: string) {
    disarm(agentId)
    const unsub = io.onRcMessage('rc:session.created', (msg) => {
      if (!msg || msg.agent_id !== agentId) return
      if (typeof msg.session_id === 'string' && msg.session_id) {
        console.warn(
          '[rc] late rc:session.created for an abandoned request to',
          agentId,
          '- releasing the session',
        )
        io.sendRaw({
          t: 'rc:terminate',
          session_id: msg.session_id,
          reason: 'controller_hangup',
        })
      }
      disarm(agentId)
    })
    const timer = setTimeout(() => disarm(agentId), windowMs)
    entries.set(agentId, { unsub, timer })
  }
  return {
    arm,
    disarm,
    get size() {
      return entries.size
    },
  }
}

/** #1631 - module-level registry state; see `createAbandonedRequestRegistry`. */
const ABANDONED_REQUESTS = new Map<string, AbandonedRequestEntry>()

/** Stall decision table Ã¢ÂÂ see the constants docblock above. */
export function nextStallAction(stallTicks: number): 'none' | 'probe' | 'reconnect' {
  if (stallTicks >= RC_STALL_FAIL_TICKS) return 'reconnect'
  if (stallTicks === RC_STALL_PROBE_TICKS) return 'probe'
  return 'none'
}

/**
 * FR-93 — one media-watchdog tick's stall count. Pure so the rule is testable.
 *
 * Progress resets it, and so does the agent having SAID this session will
 * produce no pixels (`rc:media-unavailable`, FR-80). Silence is then the
 * expected state, not a stall. Counted anyway, the watchdog probed with a
 * keyframe nobody could answer, re-created the session (which took the
 * reason off the screen), and after three rounds backed off with "its
 * network may be blocking the connection", which was false. Measured on the
 * FR-93 lab: every attempt received the reason, and every attempt was torn
 * down 10 s later.
 */
export function nextStallTicks(prev: number, advanced: boolean, agentSaidNoPixels: boolean): number {
  return advanced || agentSaidNoPixels ? 0 : prev + 1
}

/**
 * FR-93 — is a session that is ending "dead air" (it reached `connected`
 * and never delivered a frame)? Not when the agent said why there are no
 * frames: that message came over the control channel, which is itself proof
 * that the path to this browser works. Dead air raises the reconnect floor
 * and tells the operator the device's network may be blocking them.
 */
export function isDeadAir(s: {
  mediaEverFlowed: boolean
  connected: boolean
  agentSaidNoPixels: boolean
}): boolean {
  return !s.mediaEverFlowed && s.connected && !s.agentSaidNoPixels
}

/**
 * PR-1 rehome: how many consecutive `agent_on_other_pod` errors trigger
 * a socket re-key + redial before we stop cycling the socket. Past the
 * cap the dial inputs are evidently not the problem (a parked agent
 * still converging server-side, or a stale directory record) and the
 * retry rides the normal infinite ladder instead (rc.23: no terminal).
 */
export const RC_REHOME_MAX_REDIALS = 6

export type RehomeAction = 'redial_retry' | 'ladder_only'

/**
 * Decision for one `agent_on_other_pod` occurrence. `consecutive` is
 * 1-based (incremented before the call) and resets on any successful
 * connect or user-initiated action. Pure for unit tests.
 */
export function rehomeRetryDecision(consecutive: number): RehomeAction {
  return consecutive <= RC_REHOME_MAX_REDIALS ? 'redial_retry' : 'ladder_only'
}

/**
 * The tenant whose pod the rc session must originate from: the AGENT's
 * org. An explicit id (threaded from the view; authoritative for
 * cross-org device modals) wins over the page URL. Pure for tests.
 */
export function expectedOrgTid(
  explicitOrgId: string | null | undefined,
  pathname: string,
): string | null {
  if (explicitOrgId && /^[0-9a-f]{24}$/.test(explicitOrgId)) return explicitOrgId
  return appRoutePath(pathname).match(/^\/tenant\/([0-9a-f]{24})\b/)?.[1] ?? null
}

/**
 * FR-115 P4b — the TURN pre-fetch path. Naming the device and its org lets
 * the server charge the relay to the org that pays (it checks that the
 * caller is a member and the device is live there, and issues uncharged
 * credentials otherwise). Without both ids, the plain path, as before.
 */
export function turnCredsPath(agentId: string, orgTid: string | null): string {
  const hex = /^[0-9a-f]{24}$/
  if (!orgTid || !hex.test(orgTid) || !hex.test(agentId)) return '/turn/credentials'
  return `/turn/credentials?tenant_id=${orgTid}&agent_id=${agentId}`
}

/**
 * FR-52 P4e — what an EXTERNAL session rests on: the device, named by its
 * connect code (an outsider never learns its internal id), and the login the
 * device verified. Held in memory for one session and zeroed when it ends.
 */
export interface ExternalSessionAuth {
  connectCode: string
  attemptId: string
  appKey: Uint8Array
  /**
   * FR-115 P3b (O6) — the org (hex) the outsider runs this session for: its
   * concurrent-session slots are the ones the session takes. Absent: the
   * server takes their only org, or counts the account with Free's quota.
   */
  chargeOrg?: string | null
}

/** An external viewer asked to offer or answer with no login in hand. */
export const EXTERNAL_LOGIN_GONE =
  'This session needs a fresh login. Connect again with the device password.'
/** The device's answer did not carry the login's seal over its certificate. */
export const EXTERNAL_ANSWER_UNSEALED =
  'The device could not be verified, so the session was not started. Nothing was shown or sent.'
/** Every automatic retry ends here for an external session (spec decision 10). */
export const EXTERNAL_SESSION_ENDED =
  'The session ended. A session from outside the organization cannot resume on its own: connect again with the device password.'

/**
 * FR-100 P2a — the device answered with another identity key than the one
 * this browser pinned for it. The two fingerprints are shown so a person can
 * compare them with the device's own.
 */
export function peerAuthKeyChangedMessage(was: string | null, now: string | null): string {
  const keys = was && now ? ` (this browser knows ${was}; the answer came from ${now})` : ''
  return (
    `This device answered with a different identity key than the one this browser knows for it${keys}, ` +
    'so the session was not started. Nothing was shown or sent. If the device was reinstalled, ' +
    'you can trust its new key and connect again. Otherwise, someone between you and the device ' +
    'may be impersonating it.'
  )
}
/** FR-100 P2a — the device's signature does not verify over this session. */
export const PEER_AUTH_BAD_SIGNATURE =
  "The device's answer carried a signature that does not verify for this session, so the session was not started. Nothing was shown or sent."

/**
 * User-facing text for `rc:error` codes. Server prose can carry
 * internals (pod IPs, agent hexes) and must never render for codes we
 * know; unknown codes fall back to the server message so genuinely
 * novel failures stay diagnosable.
 */
export function friendlyRcError(code: unknown, serverMessage: unknown): string {
  switch (code) {
    case 'agent_on_other_pod':
      return 'Your device is connected to a different server right now. Automatic retries could not reach it yet; try again in a moment.'
    case 'agent_offline':
      return 'This device is offline. Check that it is powered on and connected.'
    case 'agent_busy':
      return 'This device has reached its concurrent session limit. Try again in a moment.'
    // FR-115 P3 — the org's plan cap on sessions at once. The server's
    // sentence names who holds the slot and on which device (our own
    // words, built from names, never internals), so it is shown as is.
    // Not retryable: waiting does not free a slot someone is using.
    case 'org_session_limit':
      return (
        (typeof serverMessage === 'string' && serverMessage)
        || "Your organization's plan runs one remote session at a time, and one is open now. End it, or upgrade the plan for one remote session per user."
      )
    case 'forbidden':
      return 'You do not have permission to control this device.'
    case 'invalid_token':
      return 'Your session has expired. Refresh the page and sign in again.'
    default:
      return (
        (typeof serverMessage === 'string' && serverMessage)
        || (typeof code === 'string' && code)
        || 'signalling error'
      )
  }
}

/**
 * FR-27 - user-facing text for a session that ended before it started.
 *
 * These used to render as the raw enum name (`user_denied`,
 * `consent_timeout`), which is unhelpful on its own and was, until FR-27,
 * frequently WRONG: the agent's own prompt timeout came back as a bare
 * `granted: false`, so "nobody was at the machine" reached the controller as
 * "the user denied your request". The agent now says which it was, and the
 * three outcomes need three different next steps from whoever reads this.
 *
 * Returns `null` for a nominal end (hangups, idle timeouts) so the caller can
 * stay silent - an alert on a normal disconnect is noise.
 */
export function friendlyEndReason(reason: unknown, limit?: unknown): string | null {
  // FR-101 P4b — a limit the organization set ended it (`rc:terminate`'s
  // `limit`). Said as such: "idle" would be the wrong story for someone who
  // was working the whole time.
  if (reason === 'idle_timeout' && limit === 'max_duration') {
    return "The session reached your organization's maximum length. Connect again to start a new one."
  }
  // P4b-2 — the device ended it after its idle limit: no input and no
  // change on the screen for that long. Whoever reads this was most likely
  // away, so it says what happened rather than staying silent.
  if (reason === 'idle_timeout' && limit === 'idle') {
    return 'The session ended after a period with no activity. Connect again to start a new one.'
  }
  // #2251 - the device sends its picture on the WebRTC track in a codec this
  // browser did not offer, so no retry can work. Said once, with what would
  // help, where the viewer used to retry without a word.
  if (reason === 'error' && limit === 'no_common_codec') {
    return "This browser can't decode the video this device sends. Try Chrome, Edge or Safari, or turn on the OpenH264 plugin in Firefox's add-ons."
  }
  switch (reason) {
    case 'user_denied':
      return 'Someone at that device declined the request.'
    case 'consent_timeout':
      return 'Nobody answered the prompt on that device in time. Nothing was declined - try again, or ask the person there to approve it.'
    case 'no_prompt_surface':
      return 'That device could not show a prompt to anyone - nobody is signed in at its screen, or the Roomler desktop app is not running there. Start it on the device, or set this device to email/push consent.'
    case 'error':
      return 'The session could not be established.'
    default:
      return null
  }
}

/**
 * FR-101 P4b-2b — whole seconds left on the device's idle countdown, rounded
 * up so the banner never reads 0 while the session still stands; never below
 * zero. `null` when no warning stands. Pure so the rounding is testable.
 */
export function idleSecondsLeft(endsAt: number | null, nowMs: number): number | null {
  if (endsAt === null) return null
  return Math.max(0, Math.ceil((endsAt - nowMs) / 1000))
}

/** Degraded classification Ã¢ÂÂ pure so the priority order is testable. */
export function classifyDegraded(inp: {
  pcState: string | null
  wsConnected: boolean
  stallTicks: number
}): RcDegradedReason | null {
  if (inp.pcState === 'disconnected') return 'transport_unstable'
  if (inp.stallTicks >= RC_STALL_PROBE_TICKS) return 'media_stalled'
  if (!inp.wsConnected) return 'signalling_offline'
  return null
}

/**
 * Parse an inbound `control` data-channel message into a typed
 * value. Returns `null` for any non-JSON, non-string, or unknown
 * envelope shape so the caller can no-op silently. Recognised
 * variants:
 *   - `rc:host_locked` Ã¢ÂÂ boolean lock-state flip (agents 0.2.3+)
 *   - `rc:desktop_changed` Ã¢ÂÂ input desktop name (agents 0.3.0+
 *     SYSTEM-context worker; emitted on `try_change_desktop`
 *     Switched). Powers the secondary "On Winlogon" chip.
 * Future agent Ã¢ÂÂ browser control messages (rc:cursor-shape,
 * rc:dpi-change, ...) layer on the same parse-by-`t` switch.
 * Unknown `t` values fall through to `null` so older browsers
 * stay forward-compatible with newer agents.
 *
 * Exported for unit testing. Production code should consume the
 * already-applied `hostLocked` / `currentDesktop` refs from the
 * composable.
 */
export type RcLogsFetchReply = {
  ok: boolean
  /** Absolute path of the file the lines came from (when ok). */
  path?: string
  /** One string per line, in file order (oldest first). */
  lines?: string[]
  /** True when the file had more lines than were returned. */
  truncated?: boolean
  /** Error message when ok = false. */
  error?: string
}

/** rc.87 Ã¢ÂÂ the agent's real encoder info, sent over the control DC
 *  when a DC video pump opens its encoder. Lets the stats badge show
 *  the truth (e.g. "VP9 4:2:0 HW vp9_qsv") instead of the hardcoded
 *  "VP9 4:4:4 SW". `codec` is the negotiation vocabulary ("h265"/
 *  "vp9"); `chroma` is "yuv420"/"yuv444". `transport` (relay-escape) is
 *  "relay"/"direct" Ã¢ÂÂ WHICH ICE path this session took; the agent
 *  re-sends the message when the path changes mid-session. '' from
 *  agents older than the field. */
/** FR-80 — the codec a WebCodecs configuration string names, for the status
 *  pill's label before `rc:video-info` arrives. Pure + exported so the tests
 *  lock it.
 *
 *  Before this the pill hardcoded `VP9` whenever the DataChannel worker was
 *  active — and that worker serves VP9, AV1 and H.264 alike (its log prefix is
 *  a legacy name, not a codec). So an H.264 session that never received a
 *  frame reported "VP9 4:4:4", and the operator chasing a black screen was
 *  sent to the codec picker instead of the host's capture failure (field,
 *  2026-09-08). The decoder's own configuration is the one codec fact the
 *  viewer owns before the agent speaks; everything else it must be told. */
export function codecLabelFromDecoderConfig(codec: string | null | undefined): string {
  if (!codec) return ''
  const c = codec.toLowerCase()
  if (c.startsWith('avc1') || c.startsWith('avc3')) return 'H.264'
  if (c.startsWith('hev1') || c.startsWith('hvc1')) return 'H.265'
  if (c.startsWith('av01')) return 'AV1'
  if (c.startsWith('vp09') || c === 'vp9') return 'VP9'
  if (c.startsWith('vp8')) return 'VP8'
  return ''
}

/** FR-80 — the agent's answer to "why is there no picture?".
 *
 *  Sent once per session, as soon as the host knows its capture backend will
 *  produce nothing — which is BEFORE any frame, and therefore before
 *  `rc:video-info`, the message a pump with no frames never reaches. That gap
 *  is the whole reason this type exists: on 2026-09-08 a macOS Screen
 *  Recording grant invalidated by a signing-identity change produced a black
 *  canvas, a stall, and no explanation anywhere the operator could see.
 *
 *  `code` is a closed vocabulary today (`permission`, `no_display`,
 *  `not_built`, `backend_error`) but is typed as a string on purpose: a newer
 *  agent may name a cause this bundle has never heard of, and its `hint` is
 *  still worth showing. */
export interface RcMediaUnavailable {
  code: string
  /** The backend's own error text, capped agent-side. May be empty. */
  detail: string
  /** The operator-facing sentence, composed by the agent because only it
   *  knows which OS it is on. May be empty from an older agent. */
  hint: string
}

/** FR-97 P3c-1 — `rc:audio-unavailable`: this session's audio track will carry
 *  no sound, and why. The audio twin of `rc:media-unavailable`, with the same
 *  shape. Before it, a host that could not capture its sound sent silence and
 *  said nothing, and a Linux host sent its microphone instead.
 *
 *  `code` is `no_monitor`, `source_not_found`, `no_output`, `backend_error` or
 *  `not_supported` today, typed as a string so a newer agent's code still
 *  shows its `hint`. */
export type RcAudioUnavailable = RcMediaUnavailable

/** FR-93 P1 — `rc:input-reach`: this session's mouse and keyboard will NOT
 *  reach the whole desktop. Sent once, and only then; a session that reaches
 *  everything sends nothing. An injector that reaches nothing does not fail
 *  (XTest into Xwayland succeeds and moves nobody's pointer), so before this
 *  a session on a GNOME Wayland host looked interactive and did nothing.
 *
 *  `reach` is `none` or `xwayland_only` today, typed as a string on purpose:
 *  a newer agent's value still carries a `reason` worth showing. */
export interface RcInputReach {
  reach: string
  /** The agent's own words: what it found, and the key that would fix it. */
  reason: string
}

/** FR-93 P2d-2 — `rc:media-waiting`: this session's capture is waiting for the
 *  person at the screen to answer a dialog (the desktop portal's "share your
 *  screen"). Sent once per open that waits, about 2 s in, because a restore
 *  token answers sooner with no dialog at all. Until `deadlineMs` the media
 *  watchdog does not count the silence as a stall. Before this the viewer
 *  re-created the session every 10 s, so the session the person finally
 *  answered for was rarely the one on screen.
 *
 *  `for` is `person_at_screen` (a dialog), from P5b `screen_unlock` (GNOME's
 *  lock screen, #2145), from P3e `display_wake` (a display switched off, DRM),
 *  from P5f `session_away` (a user switch), or from P5h `host_sleep` (the
 *  computer going to sleep); `mediaWaitingCopy` words each.
 *  It is typed as a string on purpose: a newer agent may wait for something
 *  else, and its `hint` still reads. */
export interface RcMediaWaiting {
  for: string
  /** When the dialog gives up, on THIS browser's clock: the agent sends how
   *  long is left (`waits_ms`), not a time of day, so the two clocks never
   *  have to agree. */
  deadlineMs: number
  /** The operator-facing sentence, composed by the agent. May be empty. */
  hint: string
}

/** FR-93 P2d-2 — slack past the dialog's deadline before the watchdog counts
 *  stalls again. The agent's waiter outlives the request by 5 s, and the
 *  reason it then sends (`rc:media-unavailable`) has to reach us. */
export const RC_MEDIA_WAITING_GRACE_MS = 10_000

/** FR-93 P2d-2 — is the agent still saying it waits for the person at the
 *  screen? Pure so the watchdog's rule is testable. */
export function agentIsWaiting(waiting: RcMediaWaiting | null, nowMs: number): boolean {
  return waiting !== null && nowMs < waiting.deadlineMs + RC_MEDIA_WAITING_GRACE_MS
}

/** FR-93 P5j — the wait a redial keeps on screen. A computer that said it was
 *  going to sleep keeps saying so while this viewer redials it: the dead link
 *  is the sleep's consequence, not news. Before this, the redial's teardown
 *  cleared the notice, and a request to a sleeping computer sits in
 *  awaiting_consent: the stage read "Waiting for the agent to allow the
 *  connection…" until the computer was back (0.4.142 in the lab: 48 s that
 *  named no reason, the last 19 of them after the wake). Its deadline is
 *  spent, so it holds nothing back: a
 *  new session that stays silent is re-created on the usual clock. Any other
 *  wait belonged to the session that ended. The next session's own report
 *  replaces it, and its first frame ends it. */
export function waitKeptAcrossReconnect(
  waiting: RcMediaWaiting | null,
  nowMs: number,
): RcMediaWaiting | null {
  if (waiting?.for !== 'host_sleep') return null
  return {
    ...waiting,
    deadlineMs: Math.min(waiting.deadlineMs, nowMs - RC_MEDIA_WAITING_GRACE_MS),
  }
}

/** FR-93 P5j — is this the sleep notice a redial kept? A session that connects
 *  ends it: the computer evidently woke, and the session reports its own wait
 *  or its frames. A notice of the live session (its deadline not spent: an ICE
 *  flap the same session recovers from) is not one. */
export function isKeptSleepNotice(waiting: RcMediaWaiting | null, nowMs: number): boolean {
  return waiting?.for === 'host_sleep' && !agentIsWaiting(waiting, nowMs)
}

/** FR-93 P5f — how long after a notice arrives a frame the watchdog counts may
 *  still have come in before it: one stats poll (`STATS_POLL_MS`) and its
 *  latency, on the RTP path. */
export const RC_MEDIA_WAITING_SETTLE_MS = 1_000

/** FR-93 P5f — does a watchdog tick that saw media advance end the agent's
 *  wait? Only when the interval it counted (since `intervalFromMs`) began a
 *  settle time after the notice arrived. The agent's last frames travel on the
 *  video channel and its notice on the control one, so a frame sent just
 *  before the notice can be counted just after it. Measured on the FR-93 lab:
 *  that frame cleared the notice, and the watchdog re-created the session
 *  10 s later. Pure so the rule is testable. */
export function advanceEndsWait(
  advanced: boolean,
  intervalFromMs: number,
  waitingSinceMs: number,
): boolean {
  return advanced && intervalFromMs >= waitingSinceMs + RC_MEDIA_WAITING_SETTLE_MS
}

/** FR-93 P5b — the waiting overlay's words, by what the agent waits for. */
export interface RcMediaWaitingCopy {
  /** The overlay's headline. */
  title: string
  /** The status chip's words after "connected · ". */
  status: string
  /** Whether the deadline reads as a request that ends ("If nobody answers…"). */
  showsDeadline: boolean
}

/** FR-93 P5b — `screen_unlock` is GNOME's lock screen (#2145): a per-user
 *  install sees nothing past it, the picture comes back by itself after the
 *  unlock, and no request ends, so there is no "if nobody answers". Anything
 *  else, a `for` from a newer agent included, reads as the person at the
 *  screen being asked (P2d-2); the agent's hint says the rest. */
export function mediaWaitingCopy(waitingFor: string): RcMediaWaitingCopy {
  if (waitingFor === 'screen_unlock') {
    return {
      title: "Waiting for this computer's screen to be unlocked.",
      status: 'waiting for the screen to be unlocked',
      showsDeadline: false,
    }
  }
  // FR-93 P3e — the display went to sleep. Input wakes it, this viewer's
  // too when it controls the computer, and nothing ends on its own.
  if (waitingFor === 'display_wake') {
    return {
      title: "This computer's display is asleep.",
      status: 'waiting for the display to wake',
      showsDeadline: false,
    }
  }
  // FR-93 P5f — a user switch put this user's session in the background; it
  // comes back when that session is on screen again, and nothing ends.
  if (waitingFor === 'session_away') {
    return {
      title: 'This computer is showing another session.',
      status: "waiting for this user's session to be on screen",
      showsDeadline: false,
    }
  }
  // FR-93 P5h — the computer is going to sleep. Nothing here wakes it; the
  // viewer reconnects by itself once it does, and nothing ends on its own.
  if (waitingFor === 'host_sleep') {
    return {
      title: 'This computer is going to sleep.',
      status: 'the computer is asleep',
      showsDeadline: false,
    }
  }
  return {
    title: 'Waiting for the person at the screen to share it.',
    status: 'waiting for the person at the screen',
    showsDeadline: true,
  }
}

export interface RcVideoInfo {
  codec: string
  encoder: string
  hardware: boolean
  chroma: string
  transport: string
  /** rc.199 Ã¢ÂÂ native (pre-downscale) capture dims. The viewer compares them
   *  against the decoded frame size to tell whether the stream is capped and,
   *  by `transport`, why ("ÃÂ· relay-limited"). `0` when the agent didn't report
   *  them (older agents) Ã¢ÂÂ the badge then omits the annotation. */
  native_w: number
  native_h: number
  /** P5 — how many viewers share this encoded stream (agent-side
   *  shared-floor pipeline). `1` (or absent on pre-P5 agents) = solo;
   *  `>1` = the stream's rate/dials are floor-merged across viewers and
   *  the stats badge shows "shared ×N" to explain a capped stream. */
  viewers: number
  /** FR-33 P3 — WHY the transport is `relay`, when the agent can name it.
   *  `'lan-captured'` = a VPN on the agent's host captures its LAN prefix and
   *  this viewer sits inside that prefix, so the LAN pair could never form;
   *  the pill reads `relay · VPN captures the host's LAN`. Absent from older
   *  agents and whenever the relay has another cause (e.g. a symmetric NAT
   *  toward an off-LAN viewer) — then the pill stays plain `relay`. */
  transport_reason?: string
  /** FR-70 P1 — WHY the stream is encoded below the operator's resolution
   *  choice, when it is: the agent's rung reason (`'slow-link-cap'`,
   *  `'priority-cap'`, `'soft-cap'`, `'refined-cap'`). Present ONLY while
   *  the agent's effective target differs from the user's, and re-sent
   *  whenever the cap engages, moves or lifts. Absent from older agents —
   *  the pill then falls back to the transport-only `relay-limited` guess,
   *  whose advice (Priority → Sharper) is wrong for the slow-link profile:
   *  that cap is resolved once at pump start from the pair's REMEMBERED rate
   *  and lifts only on a later session. */
  cap_reason?: string
  /** FR-70 P1 — a short human detail for `cap_reason`, e.g.
   *  `'remembered 200 kbps'` for the slow-link profile. */
  cap_detail?: string
  /** FR-93 P2 — the Linux arm serving this session: `'drm'`, `'mutter'`,
   *  `'portal'` or `'x11'`. Absent from Windows, macOS and older agents. */
  capture_arm?: string
  /** FR-93 P2 — did a person at the screen have to allow this capture?
   *  `true` only for the portal. Present exactly when `capture_arm` is. */
  attended?: boolean
  /** FR-119 P1 — the frame rate the stream runs at. Present only from an agent
   *  advertising `fps-high` (`composables/frameRate.ts`). */
  fps?: number
  /** FR-119 P1 — the viewer's `rc:fps` ask and why the agent did not grant it
   *  (`'unproven'`, `'constrained'`). Present together, only when refused. */
  fps_asked?: number
  fps_reason?: string
  /** FR-119 P2b — the stream runs at a rate granted as a trial. */
  fps_trial?: boolean
  /** FR-119 P2b-3 — the host screen's refresh rate, when the agent read it. */
  refresh_hz?: number
}

/** FR-93 P2 (FR-45 AC8 option b) — the capture pill: which Linux arm serves
 *  this session, and whether anyone at the screen was asked. DRM and mutter
 *  capture without asking, so the operator should be able to see that they
 *  did. `''` when the agent did not say (Windows, macOS, older agents).
 *  Unknown arms from a newer agent are shown as they are named: the rule for
 *  every additive wire string. */
export function captureArmLabel(vi: RcVideoInfo | null | undefined): string {
  const arm = vi?.capture_arm
  if (!arm) return ''
  const name = arm === 'drm'
    ? 'DRM scanout'
    : arm === 'mutter'
      ? 'GNOME screencast'
      : arm === 'portal'
        ? 'desktop portal'
        : arm === 'x11'
          ? 'X11'
          : arm
  if (arm === 'x11') return name
  return `${name} · ${vi?.attended ? 'allowed at the screen' : 'asks nobody'}`
}

/** FR-70 P1 — the resolution pill's annotation for a stream encoded below
 *  the agent's native panel: names the cap in force from the agent's own
 *  report, so an overridden `Native` pick is never silent. `''` when the
 *  stream is not below native, or when nothing about it is known.
 *
 *  Pure so it unit-tests: `vi` = the last `rc:video-info`, `w`/`h` = the
 *  decoded frame size. A pre-P1 agent reports no `cap_reason`; then, and
 *  only on a relay, the old transport-derived guess stands. */
export function resolutionCapAnnotation(
  vi: RcVideoInfo | null | undefined,
  w: number,
  h: number,
): string {
  const nw = vi?.native_w ?? 0
  const nh = vi?.native_h ?? 0
  if (!vi || nw <= 0 || nh <= 0 || !(w < nw || h < nh)) return ''
  const native = `native ${nw}×${nh}`
  switch (vi.cap_reason) {
    case 'slow-link-cap':
      return ` · slow link${vi.cap_detail ? ` (${vi.cap_detail})` : ''} · ${native}`
    case 'priority-cap':
      return ` · Priority cap · ${native}`
    case 'soft-cap':
      return ` · encode-bound · ${native}`
    case 'refined-cap':
      return ` · refined cap · ${native}`
    case undefined:
      // Pre-P1 agent: the rc.199 guess, relay-only.
      return vi.transport === 'relay' ? ` · relay-limited (${native})` : ''
    default:
      return ` · ${vi.cap_reason} · ${native}`
  }
}

/** FR-70 P1 — the Resolution setting's explanation when the operator's
 *  choice is overridden by the agent: what is capping, why, and what lifts
 *  it. `''` when nothing is overridden (or the agent is older than P1). */
export function resolutionOverrideHint(vi: RcVideoInfo | null | undefined, w: number, h: number): string {
  if (!vi?.cap_reason || !w || !h) return ''
  const box = `${w}×${h}`
  switch (vi.cap_reason) {
    case 'slow-link-cap':
      return `This session is capped at ${box}: the path was ${vi.cap_detail ?? 'remembered as slow'} when it opened (slow-link profile). It re-evaluates on the next session once the link has carried more.`
    case 'priority-cap':
      return `This session is capped at ${box} by the Priority dial — Sharper lifts it.`
    case 'soft-cap':
      return `This session is capped at ${box}: the host's encoder cannot keep up at native (encode-bound).`
    case 'refined-cap':
      return `This session is capped at ${box} by the crisp-at-rest refinement bound.`
    default:
      return `This session is capped at ${box} by the agent (${vi.cap_reason}).`
  }
}

/** FR-74 P4 — the viewer's own pixel chain: how many SCREEN pixels one
 *  decoded frame pixel lands on, computed the way the FSR sizing policy
 *  computes its fit factor (`computeRenderTarget`: the `object-fit: contain`
 *  factor in adaptive mode, the element's own CSS box in original/custom,
 *  × `devicePixelRatio`). `1` is pixel-exact; anything else is a resample
 *  the browser (or FSR) does AFTER the codec, which no encoder setting can
 *  undo — the pill exists so an upscale is never again hunted as encoder
 *  blur, and so "1:1 Match host display" can be VERIFIED rather than
 *  trusted. `Original` is 1:1 in CSS pixels, which on a scaled display is
 *  NOT 1:1 on screen (1.5× at 150 % scaling) — the hint says so. */
export interface RcDisplayScale {
  /** Screen pixels per frame pixel (1 = pixel-exact); `null` until the
   *  frame and the stage are both known. */
  scale: number | null
  /** The pill text: `1:1 pixels`, `shown at 1.05×`, or `''` when unknown. */
  label: string
  /** The tooltip / Display-tab explanation, with the way to 1:1. */
  hint: string
}

export function displayScale(args: {
  frameW: number
  frameH: number
  /** The stage's CSS box (what `object-fit: contain` fits into). */
  stageW: number
  stageH: number
  dpr: number
  mode: RcScaleMode
  customPct: number
  /** Whether the FSR pass is active (the hint then names it). */
  sharpened?: boolean
}): RcDisplayScale {
  const { frameW, frameH, stageW, stageH, mode, customPct } = args
  const known = (n: number) => Number.isFinite(n) && n > 0
  if (!known(frameW) || !known(frameH) || !known(stageW) || !known(stageH)) {
    return { scale: null, label: '', hint: 'Display scale surfaces after the first decoded frame' }
  }
  const dpr = known(args.dpr) ? args.dpr : 1
  // The CSS box the frame is painted into, per scale mode (mirrors
  // `videoScaleStyle` + the adaptive contain-fit in the view).
  const cssFactor =
    mode === 'original'
      ? 1
      : mode === 'custom'
        ? Math.max(5, Math.min(1000, customPct)) / 100
        : Math.min(stageW / frameW, stageH / frameH)
  const scale = cssFactor * dpr
  const exact = Math.abs(scale - 1) <= 0.001
  const label = exact ? '1:1 pixels' : `shown at ${scale.toFixed(2)}×`
  const stageDevW = Math.round(stageW * dpr)
  const stageDevH = Math.round(stageH * dpr)
  const fits = frameW <= stageDevW && frameH <= stageDevH
  // The zoom that makes CSS × dpr land on exactly one screen pixel per
  // frame pixel; one decimal, because 150 % scaling needs 66.7 %.
  const onePct = Math.round((100 / dpr) * 10) / 10
  const zoomNote = dpr !== 1 ? ` (your display scaling is ${dpr}×, so Original is ${dpr.toFixed(2)}× on screen)` : ''
  const recipe =
    `For 1:1 use Display → Custom zoom ${onePct} %${fits ? '' : ' (the frame is larger than your window and will scroll)'}` +
    `, or Match remote display so the host renders at your window's ${stageDevW}×${stageDevH}${zoomNote}.`
  if (exact) {
    return { scale, label, hint: 'Pixel-exact: each remote pixel lands on exactly one screen pixel.' }
  }
  if (scale > 1) {
    const fsr = args.sharpened ? ' — FSR sharpens the result' : ''
    return {
      scale,
      label,
      hint: `Each remote pixel is spread over ${scale.toFixed(2)} screen pixels, so text is resampled after decoding${fsr}. ${recipe}`,
    }
  }
  return {
    scale,
    label,
    hint: `The ${frameW}×${frameH} frame is squeezed to ${scale.toFixed(2)} screen pixels per remote pixel, so fine detail is lost after decoding. ${recipe}`,
  }
}

/** P6 — one participant on the agent's InputArbiter rail. */
export interface RcParticipant {
  session: string
  name: string
  /** Whether this session holds the INPUT permission. */
  input: boolean
}

/** P6 — the arbiter state broadcast (`rc:control.state` on the control DC):
 *  arbitration mode, the exclusive-mode floor holder (session hex or null),
 *  and every session on the device. Old agents never send it — the ref
 *  stays null and the multi-user UI self-hides. */
export interface RcControlState {
  mode: 'free' | 'exclusive'
  holder: string | null
  participants: RcParticipant[]
  /** FR-27 — who is waiting for the exclusive-mode floor, when a request was
   *  refused because the holder was active. `null` when nothing is pending,
   *  and always `null` in free mode.
   *
   *  Before this the refusal was dropped silently: the holder never learned
   *  anyone had asked, and the requester saw nothing, so "Request control"
   *  only appeared to work if you happened to click during the holder's idle
   *  window. Absent from pre-FR-27 agents, which is indistinguishable from
   *  "nothing pending" — the correct degradation. */
  pendingRequest: { session: string; name: string } | null
}

/** P6 — a ghost cursor: another session's pointer, rebroadcast by the
 *  agent as `cursor:peer` on the cursor DC (normalized 0..1 per monitor). */
export interface PeerCursor {
  name: string
  x: number
  y: number
  mon: number
  /** Last-update wall time (ms) — the view fades ghosts that stop moving. */
  ts: number
}

/** rc.NEXT Ã¢ÂÂ remote app selection & launch (virtual-desktop hosts). The
 *  agent enumerates windows on its desktop; the browser can focus one or
 *  launch a new allowlisted app. Rides the control DC (same request/reply
 *  pattern as rc:logs-fetch). See `agents/roomlerd/src/apps/`. */
export interface RcWindowEntry {
  window_id: string
  title: string
  /** matches a `launchable.key` when the window is a known launched app */
  app_key?: string
  /** tmux session (bash flagship); absent for GUI windows */
  session?: string
  focused: boolean
}
export interface RcLaunchable {
  key: string
  label: string
}
/** What a listing actually covered (FR-56 P2).
 *
 *  `supported` is a bool and cannot express "X11 windows only", which on a
 *  Wayland host is the truth: the agent sees Xwayland clients and is blind to
 *  native Wayland ones. Without this the panel shows a SHORTER list that looks
 *  exactly like a quiet desktop. `unlisted` is the half that matters — it names
 *  the source that exists but could not be enumerated, and why. */
export interface RcAppsMissingTool {
  tool: string
  blocks: string
  install: string
}
export interface RcAppsCoverage {
  sources: string[]
  unlisted?: string
  /** FR-56 P5 — helper binaries the agent host does not have.
   *
   *  `supported: true` was measured to be a lie on a host with no `tmux`: the
   *  panel offered the button and only failed once somebody clicked it. This
   *  names what is missing BEFORE the click.
   *
   *  ⚠️ Absent stays absent — an older agent sends no such field, and
   *  inventing an empty array here would claim we checked and found nothing,
   *  which is exactly the lie this field exists to remove. */
  missing_tools?: RcAppsMissingTool[]
}
/** FR-56 AC10 — why remote apps are unavailable on this host, from the agent.
 *  `code` is a closed set on the agent side (`disabled`, `no_session`,
 *  `no_x_display`, `cannot_run_as`, `tool_missing`, `platform`); the sentence
 *  is composed there, because only the agent knows which arm it took. Rides
 *  every `supported: false` list reply and every focus/launch refusal that had
 *  no backend. Absent from agents older than AC10. */
export interface RcAppsUnavailable {
  code: string
  reason: string
}
export interface RcAppsListReply {
  ok: boolean
  supported: boolean
  windows: RcWindowEntry[]
  launchable: RcLaunchable[]
  /** Absent from agents older than FR-56 P2 — treat as "no caveat known", not
   *  as "the listing is complete". */
  coverage?: RcAppsCoverage
  error?: string
  /** Set beside `supported: false` by agents that carry FR-56 AC10. */
  unavailable?: RcAppsUnavailable
}
/** focus + launch share this shape. `window_id` is the new window on a
 *  successful launch (best-effort Ã¢ÂÂ may be absent). */
export interface RcAppsActionReply {
  ok: boolean
  window_id?: string
  error?: string
  /** FR-56 AC10 — set when the refusal was "no backend", with the reason. */
  unavailable?: RcAppsUnavailable
}

/** FR-56 AC10 — what the dialog says when an agent answers `supported: false`
 *  without a reason (every agent before AC10). Exported so the wording is one
 *  string and the arm that uses it can be tested. */
export const APPS_UNAVAILABLE_NO_REASON =
  'Remote apps are not available on this host. This agent did not say why (agents ' +
  'older than FR-56 AC10 carry no reason) — run `roomlerd apps-probe` on the host.'

/** What the person at the viewer can do at the host's lock screen, from
 *  `rc:host_locked`'s `input`. `passes` (FR-97 P3b, Linux): it takes input
 *  like any other screen. `unknown` (FR-97 P2d-1, a Mac): not measured, so the
 *  chip claims neither way. Anything else, or no `input` at all (Windows,
 *  older agents), is Windows' meaning: input is suppressed. */
export type HostLockedInput = 'passes' | 'unknown' | 'suppressed'

/** The "Host locked" chip's title for each {@link HostLockedInput}. */
export function hostLockedChipTitle(input: HostLockedInput): string {
  switch (input) {
    case 'passes':
      return 'The remote host is on its lock screen. Your input reaches it, so you can type the password to unlock.'
    case 'unknown':
      return 'The remote host is on its lock screen.'
    case 'suppressed':
      return 'The remote host is on the lock screen — input is suppressed.'
  }
}

export type RcControlInbound =
  /** `input` (FR-97 P3b, P2d-1): what the lock screen does with input — see
   *  {@link HostLockedInput}. Windows never sends it. */
  | { kind: 'host_locked'; locked: boolean; input: HostLockedInput }
  /** FR-92 — the device's keep-busy state (to every viewer, on change). */
  | { kind: 'keep_busy'; state: KeepBusyState }
  /** FR-108 — the device's answer to this viewer's display-match request. */
  | { kind: 'display_match'; state: DisplayMatchState }
  | { kind: 'clock_echo'; t0: number; agentUs: number }
  | { kind: 'desktop_changed'; name: string }
  | { kind: 'video_info'; info: RcVideoInfo }
  | { kind: 'media_unavailable'; reason: RcMediaUnavailable }
  /** FR-97 P3c-1 — the session's audio track carries no sound, and why. */
  | { kind: 'audio_unavailable'; reason: RcAudioUnavailable }
  | { kind: 'media_waiting'; for: string; waitsMs: number; hint: string }
  | { kind: 'input_reach'; reach: RcInputReach }
  /** FR-101 P4b-2b — the device's idle limit: the session ends in `endsInMs`
   *  unless someone acts; `null` withdraws the warning. */
  | { kind: 'idle'; endsInMs: number | null }
  | { kind: 'control_state'; state: RcControlState }
  | { kind: 'logs_fetch_reply'; reply: RcLogsFetchReply }
  | { kind: 'logs_fetch_start'; id: string | null; path?: string; totalLines?: number; truncated?: boolean }
  | { kind: 'logs_fetch_chunk'; id: string | null; lines: string[] }
  | { kind: 'logs_fetch_end'; id: string | null }
  | { kind: 'apps_list_reply'; id: string | null; reply: RcAppsListReply }
  | { kind: 'apps_focus_reply'; id: string | null; reply: RcAppsActionReply }
  | { kind: 'apps_launch_reply'; id: string | null; reply: RcAppsActionReply }
  | {
      kind: 'layout'
      activeHkl: string
      activeTag: string
      installed: { hkl: string; tag: string }[]
    }
  | null

export function parseControlInbound(data: unknown): RcControlInbound {
  if (typeof data !== 'string') return null
  let parsed: unknown
  try {
    parsed = JSON.parse(data)
  } catch {
    return null
  }
  if (parsed === null || typeof parsed !== 'object') return null
  const obj = parsed as Record<string, unknown>
  if (obj.t === 'rc:host_locked' && typeof obj.locked === 'boolean') {
    const input: HostLockedInput =
      obj.input === 'passes' || obj.input === 'unknown' ? obj.input : 'suppressed'
    return { kind: 'host_locked', locked: obj.locked, input }
  }
  if (
    obj.t === 'rc:clock.echo'
    && typeof obj.t0 === 'number'
    && typeof obj.agent_us === 'number'
  ) {
    return { kind: 'clock_echo', t0: obj.t0, agentUs: obj.agent_us }
  }
  if (
    obj.t === 'rc:desktop_changed' &&
    typeof obj.name === 'string' &&
    obj.name.length > 0
  ) {
    return { kind: 'desktop_changed', name: obj.name }
  }
  if (
    obj.t === 'rc:video-info' &&
    typeof obj.codec === 'string' &&
    typeof obj.encoder === 'string'
  ) {
    return {
      kind: 'video_info',
      info: {
        codec: obj.codec,
        encoder: obj.encoder,
        hardware: obj.hardware === true,
        chroma: typeof obj.chroma === 'string' ? obj.chroma : '',
        transport: typeof obj.transport === 'string' ? obj.transport : '',
        native_w: typeof obj.native_w === 'number' ? obj.native_w : 0,
        native_h: typeof obj.native_h === 'number' ? obj.native_h : 0,
        viewers: typeof obj.viewers === 'number' && obj.viewers > 0 ? obj.viewers : 1,
        // FR-33 P3 — optional; only ever present when the agent can name it.
        ...(typeof obj.transport_reason === 'string'
          ? { transport_reason: obj.transport_reason }
          : {}),
        // FR-70 P1 — optional; present only while the agent overrides the
        // operator's resolution choice. The detail never rides alone.
        ...(typeof obj.cap_reason === 'string' && obj.cap_reason.length > 0
          ? {
              cap_reason: obj.cap_reason,
              ...(typeof obj.cap_detail === 'string' && obj.cap_detail.length > 0
                ? { cap_detail: obj.cap_detail }
                : {}),
            }
          : {}),
        // FR-93 P2 — optional; only a Linux agent names its arm.
        ...(typeof obj.capture_arm === 'string' && obj.capture_arm.length > 0
          ? { capture_arm: obj.capture_arm, attended: obj.attended === true }
          : {}),
        // FR-119 P1 — optional; only an agent advertising `fps-high` says
        // what the stream runs at, and, when it refused an ask, what and why.
        ...(typeof obj.fps === 'number' && Number.isFinite(obj.fps)
          ? {
              fps: obj.fps,
              ...(typeof obj.fps_asked === 'number' && typeof obj.fps_reason === 'string'
                ? { fps_asked: obj.fps_asked, fps_reason: obj.fps_reason }
                : {}),
              // FR-119 P2b — a trial, and the host screen's refresh rate.
              ...(obj.fps_trial === true ? { fps_trial: true } : {}),
              ...(typeof obj.refresh_hz === 'number' && Number.isFinite(obj.refresh_hz)
                ? { refresh_hz: obj.refresh_hz }
                : {}),
            }
          : {}),
      },
    }
  }
  // FR-80 — the agent says this session will produce no pixels, and why.
  // `code` is a closed vocabulary but an unknown one is kept, not dropped:
  // a newer agent's code still carries a usable `hint`, and inventing
  // "unknown" here would repeat the mistake this message exists to fix.
  if (obj.t === 'rc:media-unavailable' && typeof obj.code === 'string') {
    return {
      kind: 'media_unavailable',
      reason: {
        code: obj.code,
        detail: typeof obj.detail === 'string' ? obj.detail : '',
        hint: typeof obj.hint === 'string' ? obj.hint : '',
      },
    }
  }
  // FR-97 P3c-1 — the same rule for the session's sound: an unknown code is
  // kept, because its hint is still worth showing.
  if (obj.t === 'rc:audio-unavailable' && typeof obj.code === 'string') {
    return {
      kind: 'audio_unavailable',
      reason: {
        code: obj.code,
        detail: typeof obj.detail === 'string' ? obj.detail : '',
        hint: typeof obj.hint === 'string' ? obj.hint : '',
      },
    }
  }
  // FR-93 P2d-2 — the agent is waiting for the person at the screen. The
  // duration is turned into a deadline by the caller, at receipt, on this
  // browser's clock. An unknown `for` is kept, like an unknown FR-80 code.
  if (
    obj.t === 'rc:media-waiting'
    && typeof obj.for === 'string'
    && typeof obj.waits_ms === 'number'
    && Number.isFinite(obj.waits_ms)
    && obj.waits_ms >= 0
  ) {
    return {
      kind: 'media_waiting',
      for: obj.for,
      waitsMs: obj.waits_ms,
      hint: typeof obj.hint === 'string' ? obj.hint : '',
    }
  }
  // FR-101 P4b-2b — the device's idle limit is about to end the session:
  // `ends_in_ms` is a duration, turned into a deadline by the caller at
  // receipt on this browser's clock (as `rc:media-waiting` is). `null`
  // withdraws the warning: there was activity. Anything else is no message.
  if (obj.t === 'rc:idle') {
    const ms = obj.ends_in_ms
    if (ms === null) return { kind: 'idle', endsInMs: null }
    if (typeof ms === 'number' && Number.isFinite(ms) && ms >= 0) {
      return { kind: 'idle', endsInMs: ms }
    }
    return null
  }
  // FR-93 P1 — the session's input will not reach the whole desktop. An
  // unknown `reach` is kept, like an unknown FR-80 code: its reason still reads.
  if (obj.t === 'rc:input-reach' && typeof obj.reach === 'string') {
    return {
      kind: 'input_reach',
      reach: {
        reach: obj.reach,
        reason: typeof obj.reason === 'string' ? obj.reason : '',
      },
    }
  }
  if (obj.t === 'rc:control.state') {
    const rawParts = Array.isArray(obj.participants) ? obj.participants : []
    const participants: RcParticipant[] = rawParts.flatMap((p) => {
      const r = p as Record<string, unknown>
      if (typeof r.session !== 'string') return []
      return [
        {
          session: r.session,
          name: typeof r.name === 'string' ? r.name : '',
          input: r.input === true,
        },
      ]
    })
    const rawPending = obj.pending_request as Record<string, unknown> | null | undefined
    const pendingRequest =
      rawPending && typeof rawPending.session === 'string'
        ? {
            session: rawPending.session,
            name: typeof rawPending.name === 'string' ? rawPending.name : '',
          }
        : null
    return {
      kind: 'control_state',
      state: {
        mode: obj.mode === 'exclusive' ? 'exclusive' : 'free',
        holder: typeof obj.holder === 'string' ? obj.holder : null,
        participants,
        pendingRequest,
      },
    }
  }
  if (obj.t === 'rc:logs-fetch.reply') {
    const reply: RcLogsFetchReply = {
      ok: obj.ok === true,
    }
    if (typeof obj.path === 'string') reply.path = obj.path
    if (Array.isArray(obj.lines)) {
      reply.lines = obj.lines.filter((s): s is string => typeof s === 'string')
    }
    if (typeof obj.truncated === 'boolean') reply.truncated = obj.truncated
    if (typeof obj.error === 'string') reply.error = obj.error
    return { kind: 'logs_fetch_reply', reply }
  }
  // rc.24 streamed log-fetch reply: start / chunk / end. Browser
  // accumulates chunks keyed by `id` (or a null sentinel when the
  // agent didn't echo the request id back).
  if (obj.t === 'rc:logs-fetch.reply.start') {
    const id = typeof obj.id === 'string' ? obj.id : null
    const start: Extract<RcControlInbound, { kind: 'logs_fetch_start' }> = {
      kind: 'logs_fetch_start',
      id,
    }
    if (typeof obj.path === 'string') start.path = obj.path
    if (typeof obj.total_lines === 'number') start.totalLines = obj.total_lines
    if (typeof obj.truncated === 'boolean') start.truncated = obj.truncated
    return start
  }
  if (obj.t === 'rc:logs-fetch.reply.chunk') {
    const id = typeof obj.id === 'string' ? obj.id : null
    const lines = Array.isArray(obj.lines)
      ? obj.lines.filter((s): s is string => typeof s === 'string')
      : []
    return { kind: 'logs_fetch_chunk', id, lines }
  }
  if (obj.t === 'rc:logs-fetch.reply.end') {
    const id = typeof obj.id === 'string' ? obj.id : null
    return { kind: 'logs_fetch_end', id }
  }
  if (obj.t === 'rc:apps.list.reply') {
    return { kind: 'apps_list_reply', id: strOrNull(obj.id), reply: parseAppsListReply(obj) }
  }
  if (obj.t === 'rc:apps.focus.reply') {
    return { kind: 'apps_focus_reply', id: strOrNull(obj.id), reply: parseAppsActionReply(obj) }
  }
  if (obj.t === 'rc:apps.launch.reply') {
    return { kind: 'apps_launch_reply', id: strOrNull(obj.id), reply: parseAppsActionReply(obj) }
  }
  // FR-92 — keep busy. The device owns the state; this only renders it.
  if (obj.t === 'rc:keep-busy.state') {
    const state = parseKeepBusyState(obj)
    return state ? { kind: 'keep_busy', state } : null
  }
  // FR-108 — display match: the device decided, and says how.
  if (obj.t === 'rc:display-match.state') {
    const state = parseDisplayMatchState(obj)
    return state ? { kind: 'display_match', state } : null
  }
  // rc.227 Ã¢ÂÂ keyboard-layout snapshot from the agent (Windows hosts).
  // Defensive filtering: malformed installed entries are dropped, a
  // missing list degrades to [] (chip still renders from the active
  // fields; the picker just has no options).
  if (obj.t === 'rc:layout' && typeof obj.active_hkl === 'string' && typeof obj.active === 'string') {
    const installed = Array.isArray(obj.installed)
      ? obj.installed
          .filter((e): e is Record<string, unknown> => typeof e === 'object' && e !== null)
          .filter((e) => typeof e.hkl === 'string' && typeof e.tag === 'string')
          .map((e) => ({ hkl: e.hkl as string, tag: e.tag as string }))
      : []
    return {
      kind: 'layout',
      activeHkl: obj.active_hkl,
      activeTag: obj.active,
      installed,
    }
  }
  return null
}

/** Pure builder for the `rc:layout.set` control-DC envelope Ã¢ÂÂ the
 *  viewer's manual layout switch. `hkl` must be the opaque hex string
 *  the agent itself reported in `rc:layout.installed[].hkl`; anything
 *  else returns null (never sent). Exported so tests lock the wire
 *  shape the agent's control-handler arm validates. */
export function layoutSetWireMessage(hkl: string): { t: 'rc:layout.set'; hkl: string } | null {
  if (!/^[0-9a-fA-F]{1,16}$/.test(hkl)) return null
  return { t: 'rc:layout.set', hkl }
}

function strOrNull(v: unknown): string | null {
  return typeof v === 'string' ? v : null
}

/** Parse an `rc:apps.list.reply` body defensively Ã¢ÂÂ unknown/missing
 *  fields degrade to safe empties (never throws) so version skew can't
 *  break the menu. Exported so the wire format is locked by tests. */
export function parseAppsListReply(obj: Record<string, unknown>): RcAppsListReply {
  const windows: RcWindowEntry[] = Array.isArray(obj.windows)
    ? obj.windows
        .filter((w): w is Record<string, unknown> => typeof w === 'object' && w !== null)
        .filter((w) => typeof w.window_id === 'string' && typeof w.title === 'string')
        .map((w) => {
          const e: RcWindowEntry = {
            window_id: w.window_id as string,
            title: w.title as string,
            focused: w.focused === true,
          }
          if (typeof w.app_key === 'string') e.app_key = w.app_key
          if (typeof w.session === 'string') e.session = w.session
          return e
        })
    : []
  const launchable: RcLaunchable[] = Array.isArray(obj.launchable)
    ? obj.launchable
        .filter((a): a is Record<string, unknown> => typeof a === 'object' && a !== null)
        .filter((a) => typeof a.key === 'string' && typeof a.label === 'string')
        .map((a) => ({ key: a.key as string, label: a.label as string }))
    : []
  const reply: RcAppsListReply = {
    ok: obj.ok === true,
    supported: obj.supported === true,
    windows,
    launchable,
  }
  // FR-56 P2. Parsed defensively like everything else here: an older agent
  // sends no `coverage`, and a malformed one must cost the caveat, never the
  // whole reply.
  const cov = obj.coverage
  if (typeof cov === 'object' && cov !== null) {
    const c = cov as Record<string, unknown>
    const sources = Array.isArray(c.sources)
      ? c.sources.filter((s): s is string => typeof s === 'string')
      : []
    const parsed: RcAppsCoverage = { sources }
    if (typeof c.unlisted === 'string' && c.unlisted !== '') parsed.unlisted = c.unlisted
    // FR-56 P5 — the helpers the host lacks, named BEFORE the click.
    // ⚠️ This parse was missing from P5's own PR (#1179): the agent sent the
    // field, the template rendered it, and this function dropped it in
    // between — so the warning was field-verified on the host with
    // `roomlerd apps-probe` and never once reached a screen (found by the
    // FR-56 AC10 audit). An entry needs all three strings or it is dropped:
    // the template prints all three, and a blank `install` beside a broken
    // button is not actionable. Absent stays absent (an older agent).
    if (Array.isArray(c.missing_tools)) {
      parsed.missing_tools = c.missing_tools
        .filter((t): t is Record<string, unknown> => typeof t === 'object' && t !== null)
        .filter(
          (t) =>
            typeof t.tool === 'string' &&
            t.tool !== '' &&
            typeof t.blocks === 'string' &&
            typeof t.install === 'string',
        )
        .map((t) => ({
          tool: t.tool as string,
          blocks: t.blocks as string,
          install: t.install as string,
        }))
    }
    reply.coverage = parsed
  }
  if (typeof obj.error === 'string') reply.error = obj.error
  const unavailable = parseAppsUnavailable(obj.unavailable)
  if (unavailable) reply.unavailable = unavailable
  return reply
}

/** FR-56 AC10 — the agent's `unavailable` object. Both halves are required:
 *  the code is what a viewer keys copy off, the reason is what this one shows.
 *  An object missing either is malformed and costs itself, never the reply —
 *  and `undefined` here means "no reason given", which the arm renders as such
 *  rather than inventing one. */
function parseAppsUnavailable(v: unknown): RcAppsUnavailable | undefined {
  if (typeof v !== 'object' || v === null) return undefined
  const u = v as Record<string, unknown>
  if (typeof u.code !== 'string' || u.code === '') return undefined
  if (typeof u.reason !== 'string' || u.reason === '') return undefined
  return { code: u.code, reason: u.reason }
}

/** Parse an `rc:apps.focus.reply` / `rc:apps.launch.reply` body. Exported for tests. */
export function parseAppsActionReply(obj: Record<string, unknown>): RcAppsActionReply {
  const reply: RcAppsActionReply = { ok: obj.ok === true }
  if (typeof obj.window_id === 'string') reply.window_id = obj.window_id
  if (typeof obj.error === 'string') reply.error = obj.error
  const unavailable = parseAppsUnavailable(obj.unavailable)
  if (unavailable) reply.unavailable = unavailable
  return reply
}

/** Build the `rc:apps.list` request. Exported so the wire format is
 *  locked by tests (mirrors `resolutionWireMessage`). Returns null on an
 *  empty id so the caller drops the send. */
export function appsListWireMessage(id: string): Record<string, unknown> | null {
  if (!id) return null
  return { t: 'rc:apps.list', id }
}
export function appsFocusWireMessage(
  id: string,
  windowId: string,
): Record<string, unknown> | null {
  if (!id || !windowId) return null
  return { t: 'rc:apps.focus', id, window_id: windowId }
}
export function appsLaunchWireMessage(
  id: string,
  appKey: string,
): Record<string, unknown> | null {
  if (!id || !appKey) return null
  return { t: 'rc:apps.launch', id, app_key: appKey }
}

/**
 * Pure helper: given the number of attempts already made (0-indexed
 * Ã¢ÂÂ i.e. `0` means the first retry hasn't fired yet), return the
 * delay before the next attempt. Always returns a positive delay Ã¢ÂÂ
 * after `RC_RECONNECT_LADDER_MS` is exhausted, falls back to
 * `RC_RECONNECT_STEADY_MS` (8 s) forever. The operator cancels by
 * settling the in-flight transfer (Cancel button), tearing down the
 * session (Disconnect), or closing the page. rc.23 Ã¢ÂÂ was previously
 * `null` after 6 attempts, which surfaced "budget exhausted" to the
 * field; field repro on the field-test host made it clear that operators on
 * corporate AV-protected hosts need indefinite retry.
 *
 * Exported for unit testing. Called by `scheduleReconnect()` inside
 * the composable; production code should not need this directly.
 */
export function nextReconnectDelayMs(attempt: number): number {
  if (attempt < 0) return RC_RECONNECT_LADDER_MS[0]
  if (attempt >= RC_RECONNECT_LADDER_MS.length) return RC_RECONNECT_STEADY_MS
  return RC_RECONNECT_LADDER_MS[attempt]
}

/** Pure helper: derive the host path to navigate to when the user
 *  double-clicks an entry in the files-browser drawer. Encodes two
 *  invariants that have each tripped a field bug:
 *
 *  1. **Roots view** (Drives on Windows / `/` on Unix) Ã¢ÂÂ `entry.name`
 *     is already an absolute path (e.g. `C:\` or `/`). The composable
 *     MUST drive into it directly; concatenating with the localised
 *     "Drives" label produces bogus paths like `Drives/C:\` (rc.15
 *     field repro 2026-05-07).
 *  2. **Inside a verbatim drive root** (`\\?\C:\`) Ã¢ÂÂ `Path::parent()`
 *     in the agent returns `None`, so a `currentParent === null`
 *     proxy mis-classifies the verbatim drive root as roots-view.
 *     The drawer must use an EXPLICIT `isRootsView` flag, set only
 *     when the navigateTo request was for empty/`/`/`~`. This helper
 *     takes that flag as input rather than re-deriving it
 *     (regression bug 2026-05-09: dbl-click `dev` after `C:\` shipped
 *     just `dev` to the agent Ã¢ÂÂ "canonicalising dev").
 *
 *  Path-separator heuristic: any drive-letter prefix or backslash in
 *  the current path Ã¢ÂÂ Windows; otherwise Unix. Trailing separator on
 *  the current path is detected so we don't double up.
 *
 *  Exported for unit-testing; the caller (RemoteControl.vue's
 *  `onEntryDblClick`) is a one-line wrapper that forwards `entry`,
 *  `currentDirPath`, and `isRootsView` directly.
 */
export function nextDirPath(
  entry: { name: string; is_dir: boolean },
  currentDirPath: string,
  isRootsView: boolean
): string | null {
  if (!entry.is_dir) return null
  if (isRootsView) {
    // Roots view: drive directly into the entry's name (already an
    // absolute path on Win / Unix).
    return entry.name
  }
  const trailingSep = /[\\/]$/.test(currentDirPath)
  // Win paths contain a drive-letter colon or a backslash. Anything
  // else is treated as Unix (forward-slash separator).
  const isWindows =
    /^[A-Za-z]:[\\\/]/.test(currentDirPath) || currentDirPath.includes('\\')
  const sep = trailingSep ? '' : isWindows ? '\\' : '/'
  return currentDirPath + sep + entry.name
}

/** Controller's quality preference. `auto` lets the agent follow TWCC; `low`
 *  clamps for bandwidth-constrained WAN; `high` asks for the best codec the
 *  agent can offer (HEVC/AV1 when negotiated in Phase 2). Persisted to
 *  `localStorage` so it survives a page reload. */
export type RcQuality = 'auto' | 'low' | 'high'

/** Live readout of the inbound video stream derived from
 *  `RTCPeerConnection.getStats()`. Updated every 500 ms while connected. */
export interface RcStats {
  /** Decoded inbound bitrate in bits per second. 0 until two polls land. */
  bitrate_bps: number
  /** Decoded framerate reported by the browser. */
  fps: number
  /** Codec short name ("H264", "H265", "AV1", "VP9", "VP8"). Empty string
   *  until the browser reports one. Phase 2 uses this for the UI badge. */
  codec: string
}

/** Remote cursor state: position in source pixels + a cache of shape
 *  bitmaps keyed by the handle id the agent sent. RemoteControl.vue
 *  uses this to draw the real OS cursor over the video (replacing the
 *  synthetic initials badge for single-controller sessions). Undefined
 *  while the agent hasn't advertised Ã¢ÂÂ the view falls back to the
 *  initials badge. */
export interface RcCursor {
  /** Current position in agent-source pixels. Null = hidden
   *  (fullscreen video, cursor moved off primary display). */
  pos: { x: number; y: number; id: number } | null
  /** ImageBitmap cache by shape id. Pure side-effect: decoding a
   *  shape on receive means the paint loop can hand it straight to
   *  canvas.drawImage without per-frame decode cost. */
  shapes: Map<
    number,
    {
      bitmap: ImageBitmap
      hotspotX: number
      hotspotY: number
      /** CSS `cursor` keyword when the agent identified this shape as a
       *  standard system cursor ("text", "default", "pointer", Ã¢ÂÂ¦), so
       *  the view renders the viewer's native OS cursor instead of the
       *  bitmap. Absent for app-custom cursors. */
      css?: string
    }
  >
}

/** Derive the CSS `cursor` keyword to apply to the video surface for
 *  the current remote cursor: the css of the shape referenced by the
 *  current position, or null when the cursor is hidden or the active
 *  shape is an app-custom bitmap (Ã¢ÂÂ the canvas overlay renders it). */
export function remoteCursorCssFor(state: RcCursor): string | null {
  const pos = state.pos
  if (!pos) return null
  return state.shapes.get(pos.id)?.css ?? null
}

interface IceServer {
  urls: string[]
  username?: string
  credential?: string
}

interface TurnCredsResponse {
  ice_servers: IceServer[]
}

const EMPTY_STATS: RcStats = { bitrate_bps: 0, fps: 0, codec: '' }
const QUALITY_STORAGE_KEY = 'rc:quality'
const STATS_POLL_MS = 500

function readStoredQuality(): RcQuality {
  try {
    const v = globalThis.localStorage?.getItem(QUALITY_STORAGE_KEY)
    if (v === 'low' || v === 'high' || v === 'auto') return v
  } catch {
    /* localStorage may be disabled or unavailable (SSR). */
  }
  return 'auto'
}

function persistQuality(q: RcQuality) {
  try {
    globalThis.localStorage?.setItem(QUALITY_STORAGE_KEY, q)
  } catch {
    /* best-effort Ã¢ÂÂ swallow quota / privacy-mode errors */
  }
}

/** Persist key for the optional codec override. When the user forces a
 *  specific codec (H.265 or AV1) for an A/B comparison, we save it so
 *  the choice survives a page reload. `null` means no override Ã¢ÂÂ the
 *  agent picks from the full browserÃÂagent intersection. */
const PREFERRED_CODEC_STORAGE_KEY = 'roomler-rc-preferred-codec'

/** Codec names that round-trip between `RTCRtpReceiver.getCapabilities`,
 *  the agent's advertised caps, and SDP fmtp munging. Keep in sync
 *  with `encode/caps.rs::pick_best_codec`. */
export type RcPreferredCodec = 'h264' | 'h265' | 'av1' | 'vp9' | 'vp8'

function readStoredPreferredCodec(): RcPreferredCodec | null {
  try {
    const raw = globalThis.localStorage?.getItem(PREFERRED_CODEC_STORAGE_KEY)
    if (raw === 'h264' || raw === 'h265' || raw === 'av1' || raw === 'vp9' || raw === 'vp8') {
      return raw
    }
  } catch {
    /* privacy mode Ã¢ÂÂ treat as no override */
  }
  return null
}

function persistPreferredCodec(c: RcPreferredCodec | null) {
  try {
    if (c == null) {
      globalThis.localStorage?.removeItem(PREFERRED_CODEC_STORAGE_KEY)
    } else {
      globalThis.localStorage?.setItem(PREFERRED_CODEC_STORAGE_KEY, c)
    }
  } catch {
    /* best-effort */
  }
}

/** How the remote video is rendered inside the viewer stage.
 *  - `adaptive`: fit-to-stage with aspect preserved (default;
 *    equivalent to `object-fit: contain`).
 *  - `original`: 1:1 intrinsic pixels; stage shows scrollbars if the
 *    remote is larger than the viewport.
 *  - `custom`: scaled to `scaleCustomPercent` of intrinsic size. */
export type RcScaleMode = 'adaptive' | 'original' | 'custom'

/** Which capture/encode resolution the REMOTE agent should use.
 *  - `original`: the agent's native monitor resolution.
 *  - `fit`: the agent downscales to match the local viewer's stage
 *    dimensions ÃÂ devicePixelRatio (re-emitted on viewport resize).
 *  - `custom`: an explicit width ÃÂ height picked from a preset list or
 *    typed in by the operator. */
export type RcResolutionMode = 'original' | 'fit' | 'custom'

export interface RcResolutionSetting {
  mode: RcResolutionMode
  /** Only meaningful for `fit` + `custom`. */
  width?: number
  height?: number
}

/** Per-agent localStorage prefix Ã¢ÂÂ resolution preferences should NOT
 *  bleed across machines (a "Fit to local at 1920ÃÂ1080" set for my
 *  laptop monitor is wrong for my 4K desktop).
 *
 *  rc.190.1 Ã¢ÂÂ prefix bumped `:` Ã¢ÂÂ `.v2:` as a ONE-TIME migration to the
 *  new Fit default. Field 2026-07-16: prefs stored during the earlier
 *  debugging rounds (e.g. 'original' left on WINHOST-H) silently overrode
 *  the new default and kept a 4K panel streaming at native through a
 *  ~60 ms/frame encode. Old-key values are intentionally orphaned; any
 *  pick made from now on persists under the new key as usual. */
const RESOLUTION_STORAGE_PREFIX = 'roomler-rc-resolution.v2:'

const SCALE_MODE_STORAGE_KEY = 'roomler-rc-scale-mode'
const SCALE_CUSTOM_PCT_STORAGE_KEY = 'roomler-rc-scale-pct'

function readStoredScaleMode(): RcScaleMode {
  try {
    const raw = globalThis.localStorage?.getItem(SCALE_MODE_STORAGE_KEY)
    if (raw === 'adaptive' || raw === 'original' || raw === 'custom') return raw
  } catch {
    /* privacy mode Ã¢ÂÂ default */
  }
  return 'adaptive'
}

function persistScaleMode(m: RcScaleMode) {
  try {
    globalThis.localStorage?.setItem(SCALE_MODE_STORAGE_KEY, m)
  } catch {
    /* best-effort */
  }
}

function readStoredScalePct(): number {
  try {
    const raw = globalThis.localStorage?.getItem(SCALE_CUSTOM_PCT_STORAGE_KEY)
    if (raw != null) {
      const n = Number(raw)
      if (Number.isFinite(n) && n >= 5 && n <= 1000) return n
    }
  } catch {
    /* privacy mode Ã¢ÂÂ default */
  }
  return 100
}

function persistScalePct(n: number) {
  try {
    globalThis.localStorage?.setItem(SCALE_CUSTOM_PCT_STORAGE_KEY, String(n))
  } catch {
    /* best-effort */
  }
}

/** FR-119 P1 — the viewer's frame-rate pick, per browser (a high-refresh screen
 *  is a property of where the viewer sits, not of the device it controls).
 *  60, today's rate, when nothing valid is stored. */
function readStoredFrameRate(): FrameRate {
  try {
    return toFrameRate(globalThis.localStorage?.getItem(FRAME_RATE_STORAGE_KEY)) ?? 60
  } catch {
    /* privacy mode: default */
  }
  return 60
}

function persistFrameRate(fps: FrameRate) {
  try {
    globalThis.localStorage?.setItem(FRAME_RATE_STORAGE_KEY, String(fps))
  } catch {
    /* best-effort */
  }
}

function readStoredResolution(agentId: string): RcResolutionSetting {
  try {
    const raw = globalThis.localStorage?.getItem(RESOLUTION_STORAGE_PREFIX + agentId)
    if (raw) {
      const parsed = JSON.parse(raw)
      if (
        parsed &&
        (parsed.mode === 'original' || parsed.mode === 'fit' || parsed.mode === 'custom')
      ) {
        return {
          mode: parsed.mode,
          width: typeof parsed.width === 'number' ? parsed.width : undefined,
          height: typeof parsed.height === 'number' ? parsed.height : undefined,
        }
      }
    }
  } catch {
    /* fall through to default */
  }
  // 2026-08-02 (operator default set) — default is ORIGINAL: stream the
  // host's native resolution for a 1:1 pixel mapping (pairs with the new
  // display-match-ON default; sharpest possible text). The rc.190 'fit'
  // rationale (a small viewer paying 4x for pixels it throws away) still
  // holds as advice for small screens — those users pick Fit once and
  // their stored value wins forever.
  return { mode: 'original' }
}

function persistResolution(agentId: string, s: RcResolutionSetting) {
  try {
    globalThis.localStorage?.setItem(
      RESOLUTION_STORAGE_PREFIX + agentId,
      JSON.stringify(s),
    )
  } catch {
    /* best-effort */
  }
}

/** Per-agent codec override (2026-07-28): an explicit Codec-picker choice on
 *  agent X sticks for X across sessions; "Auto" clears X's override so the
 *  global (per-browser) default applies again. Restored in `connect()` via
 *  the persist-FREE apply path Ã¢ÂÂ restoring through the `codecChoice` setter
 *  would rewrite the four GLOBAL keys and silently turn one agent's override
 *  into every agent's default. */
export const CODEC_STORAGE_PREFIX = 'roomler-rc-codec.v1:'

/** Every value the Codec picker can hold. The ONE list both the type and the
 *  storage allow-list derive from: `RcCodecChoice` is `typeof` this array, so a
 *  picker value that is not in it does not type-check anywhere. Before this the
 *  allow-list was a second, hand-maintained copy that missed `hevc-444`, so a
 *  per-agent HEVC 4:4:4 override was written and never read back. */
export const RC_CODEC_CHOICES = [
  'auto',
  'av1',
  'hevc',
  'hevc-444',
  'vp9',
  'vp9-444',
  'vp9-420',
  'h264',
  // FR-77 P3b — H.264 High 4:4:4 (NVENC encode, software decode).
  'h264-444',
  // FR-77 — the two-axis picker: codec "Auto" with an explicit chroma format.
  'auto-444',
  'auto-420',
] as const

export function readStoredCodecChoice(agentId: string): RcCodecChoice | null {
  try {
    const raw = globalThis.localStorage?.getItem(CODEC_STORAGE_PREFIX + agentId)
    if (
      raw &&
      raw !== 'auto' &&
      (RC_CODEC_CHOICES as readonly string[]).includes(raw)
    ) {
      return raw as RcCodecChoice
    }
  } catch {
    /* privacy mode Ã¢ÂÂ no override */
  }
  return null
}

export function persistCodecChoice(agentId: string, choice: RcCodecChoice | null) {
  try {
    if (choice == null || choice === 'auto') {
      globalThis.localStorage?.removeItem(CODEC_STORAGE_PREFIX + agentId)
    } else {
      globalThis.localStorage?.setItem(CODEC_STORAGE_PREFIX + agentId, choice)
    }
  } catch {
    /* best-effort */
  }
}

/** Pure decision core for the connect-time pick-vs-restore precedence
 *  (mirrors the rc.190 resolution guard) Ã¢ÂÂ unit-tested. Returns what
 *  `connect()` should do: persist the fresh user pick, apply the stored
 *  override, or leave the global default alone. */
export function codecConnectAction(
  userPickedThisSession: boolean,
  stored: RcCodecChoice | null,
): 'persist-pick' | 'apply-stored' | 'none' {
  if (userPickedThisSession) return 'persist-pick'
  if (stored) return 'apply-stored'
  return 'none'
}

/** Translate an `RcResolutionSetting` into the exact JSON shape the
 *  agent's control-DC handler expects. Returns `null` when the
 *  setting is invalid (fit/custom with no dims) Ã¢ÂÂ the caller drops
 *  the send rather than emitting a half-formed message. Exported
 *  for tests so the wire format is locked. */
export function resolutionWireMessage(
  s: RcResolutionSetting,
): Record<string, unknown> | null {
  if (s.mode === 'original') {
    return { t: 'rc:resolution', mode: 'original' }
  }
  // fit + custom both require positive integer dims. Missing or
  // zero/negative values return null so the caller drops the send
  // rather than emitting an invalid message.
  if (s.width == null || s.height == null) return null
  if (!Number.isFinite(s.width) || !Number.isFinite(s.height)) return null
  const w = Math.round(s.width)
  const h = Math.round(s.height)
  if (w < 1 || h < 1) return null
  return { t: 'rc:resolution', mode: s.mode, width: w, height: h }
}

/** rc.188 Ã¢ÂÂ viewerÃ¢ÂÂagent sustainable-rate feedback. Each stats window the
 *  active decode worker reports the fps it actually DECODED plus whether it
 *  dropped frames to a decode backlog; the agent's `ViewerRateController` folds
 *  this into a send-fps cap so it stops firehosing faster than THIS viewer can
 *  decode (which is what caused the freeze spiral: queue backs up Ã¢ÂÂ drop deltas
 *  Ã¢ÂÂ request a heavy IDR Ã¢ÂÂ even harder to decode Ã¢ÂÂ 1-2 s hang). Replaces the
 *  rc.187 auto-resolution ladder + the rc.184 keyframe-request-rate heuristic
 *  with one direct measured signal. Pure so the wire shape is unit-tested. */
export function decodeStatWireMessage(
  fps: number,
  struggling: boolean,
  age?: { avgMs: number; minMs: number } | null,
  probeRttMs?: number | null,
  link?: { rxBps: number; queueMs: number | null } | null,
  arrival?: { avgMs: number } | null,
): Record<string, unknown> {
  const f = Number.isFinite(fps) && fps > 0 ? Math.min(Math.round(fps), 240) : 0
  const msg: Record<string, unknown> = { t: 'rc:decodestat', fps: f, struggling: !!struggling }
  // FR-15 — the window's paint age (average) and its minimum, which the
  // agent uses as the path-floor sample. Sent only when the FR-1 P7 clock
  // probe has locked AND frames actually painted this window: an absent
  // pair means "no signal" to the agent's age loop, which is different
  // from (and must not be reported as) a 0 ms age. Both are clamped to
  // the u16 the agent packs them into.
  const clamp = (v: number) => Math.min(Math.max(Math.round(v), 0), 65535)
  if (age && Number.isFinite(age.avgMs) && Number.isFinite(age.minMs)) {
    msg.age_ms = clamp(age.avgMs)
    msg.age_min_ms = clamp(age.minMs)
    // FR-15 P2 — the probe's own round trip travels WITH the age, because
    // the agent cannot otherwise tell a real path floor from a clock-biased
    // one: half of this is the smallest age the path can physically produce.
    // Sent only alongside an age (it is meaningless on its own) and only
    // when a probe has actually landed.
    if (typeof probeRttMs === 'number' && Number.isFinite(probeRttMs) && probeRttMs >= 0) {
      msg.probe_rtt_ms = clamp(probeRttMs)
    }
    // FR-70 M0 — the window's age at ARRIVAL (same clock mapping as
    // `age_ms`, so it rides only alongside it). The agent splits the fused
    // age with it: viewer = age − arrival, transit = arrival − its own
    // send-queue wait. Clamped to ≥ 1 because 0 is the agent's "absent"
    // sentinel for this slot.
    if (arrival && Number.isFinite(arrival.avgMs)) {
      msg.arr_ms = Math.max(clamp(arrival.avgMs), 1)
    }
  }
  // FR-59 P3 — the link report: what actually arrived this window, and how
  // much the transit queue grew. Sent as a PAIR and only when both are
  // real: `rx_bps` on its own is a lower bound on capacity (a static
  // desktop sends a few KB/s), so the agent may only read it as a ceiling
  // while the queue is also growing — see `viewer_rate::LinkLoop`. Sent
  // independently of `age`, deliberately: neither value needs the clock
  // probe, which is the whole reason this exists.
  if (
    link &&
    Number.isFinite(link.rxBps) &&
    link.rxBps >= 0 &&
    typeof link.queueMs === 'number' &&
    Number.isFinite(link.queueMs)
  ) {
    msg.rx_bps = Math.min(Math.max(Math.round(link.rxBps), 0), 4_294_967_295)
    // The agent packs this into an i16; clamp here so a pathological
    // window cannot wrap into its own sign.
    msg.queue_ms = Math.min(Math.max(Math.round(link.queueMs), -32768), 32767)
  }
  return msg
}

/** Which render path the viewer uses for the inbound video track.
 *  - `video`: classic `<video>` element bound to a MediaStream. Goes
 *    through Chrome's built-in jitter buffer (~80 ms soft floor).
 *  - `webcodecs`: a Web Worker receives encoded RTP frames via
 *    `RTCRtpScriptTransform`, decodes them with `VideoDecoder`, and
 *    paints the results to an `OffscreenCanvas`. Bypasses the jitter
 *    buffer for measurable latency savings. Chrome-only in practice;
 *    falls back to `video` when `RTCRtpScriptTransform` or
 *    `VideoDecoder` are unavailable. Takes effect on the next
 *    `connect()` Ã¢ÂÂ live sessions keep whatever path they started
 *    with, since swapping receiver transforms mid-session tears
 *    down the decoder. */
export type RcRenderPath = 'video' | 'webcodecs'

const RENDER_PATH_STORAGE_KEY = 'roomler-rc-render-path'

function readStoredRenderPath(): RcRenderPath {
  try {
    const raw = globalThis.localStorage?.getItem(RENDER_PATH_STORAGE_KEY)
    if (raw === 'webcodecs' || raw === 'video') return raw
  } catch {
    /* privacy mode Ã¢ÂÂ default */
  }
  return 'video'
}

function persistRenderPath(p: RcRenderPath) {
  try {
    globalThis.localStorage?.setItem(RENDER_PATH_STORAGE_KEY, p)
  } catch {
    /* best-effort */
  }
}

// P1 (Parsec-class plan) Ã¢ÂÂ viewer-pipeline diagnosis knobs. All localStorage,
// all per-viewer, all live-flippable without a redeploy:
//  - roomler-rc-ctx-mode: 2D-context A/B ('legacy' | 'opaque' |
//    'opaque-desync'; default opaque-desync Ã¢ÂÂ alpha:false enables the opaque
//    compositor fast path, desynchronized requests the low-latency swap
//    chain).
//  - roomler-rc-per-frame-msg=1: restore the legacy per-decoded-frame
//    workerÃ¢ÂÂmain message + reactive increment (default OFF Ã¢ÂÂ it was ~60
//    messages + 60 Vue triggers per second of pure overhead).
//  - roomler-rc-diag-hud=1: render the per-hop diagnostics row in the HUD.
const CTX_MODE_STORAGE_KEY = 'roomler-rc-ctx-mode'
const PER_FRAME_MSG_STORAGE_KEY = 'roomler-rc-per-frame-msg'
const DIAG_HUD_STORAGE_KEY = 'roomler-rc-diag-hud'

export function storedCtxMode(): CtxMode {
  try {
    return normalizeCtxMode(globalThis.localStorage?.getItem(CTX_MODE_STORAGE_KEY))
  } catch {
    return 'opaque-desync'
  }
}

export function storedPerFrameMsg(): boolean {
  try {
    return globalThis.localStorage?.getItem(PER_FRAME_MSG_STORAGE_KEY) === '1'
  } catch {
    return false
  }
}

// P6 (Parsec-class plan) Ã¢ÂÂ flow-control knobs for the field-tuning round.
// All localStorage, all default to today's baked values; proven values get
// baked as the new defaults in a follow-up (one constant per field round):
//  - roomler-rc-max-queue: worker decode-queue depth above which deltas are
//    dropped + an IDR resync is requested (default 4, clamp 1..60).
//  - roomler-rc-struggle-queue: queue depth that makes a 1 s stats window
//    "bad" for the struggling rule (default 2, clamp 0..59).
//  - roomler-rc-struggle-windows: consecutive bad windows before the
//    struggling bit is sent to the agent (default 2; 1 = the legacy
//    instantaneous rule, clamp 1..10).
const MAX_QUEUE_STORAGE_KEY = 'roomler-rc-max-queue'
const STRUGGLE_QUEUE_STORAGE_KEY = 'roomler-rc-struggle-queue'
const STRUGGLE_WINDOWS_STORAGE_KEY = 'roomler-rc-struggle-windows'

export interface RcFlowParams {
  maxQueue: number
  struggleQueue: number
  struggleWindows: number
}

/** Read the P6 flow-control knobs (pure + exported so the defaults and
 *  clamps are locked by unit tests). Read once per composable Ã¢ÂÂ a knob
 *  change needs a page refresh, like every other `roomler-rc-*` knob. */
export function storedFlowParams(): RcFlowParams {
  let mq: string | null = null
  let sq: string | null = null
  let sw: string | null = null
  try {
    mq = globalThis.localStorage?.getItem(MAX_QUEUE_STORAGE_KEY) ?? null
    sq = globalThis.localStorage?.getItem(STRUGGLE_QUEUE_STORAGE_KEY) ?? null
    sw = globalThis.localStorage?.getItem(STRUGGLE_WINDOWS_STORAGE_KEY) ?? null
  } catch {
    /* privacy mode Ã¢ÂÂ defaults */
  }
  return {
    maxQueue: normalizeIntKnob(mq, DEFAULT_MAX_DECODE_QUEUE, 1, 60),
    struggleQueue: normalizeIntKnob(sq, DEFAULT_STRUGGLE_QUEUE, 0, 59),
    struggleWindows: normalizeIntKnob(sw, DEFAULT_STRUGGLE_WINDOWS, 1, 10),
  }
}

/** FR-98 C3 — `roomler-rc-input-gap`: the pointer-move coalescing gap in ms.
 *  Default 8 (≈125 Hz, FR-1 P6), clamped to 0..16; 0 sends every pointer
 *  event as it arrives. A knob for the field A/B: FR-98 keeps a cadence
 *  change only if L4 shows it moving input to photon. Read once per
 *  composable, like every other `roomler-rc-*` knob. Pure + exported for
 *  tests. */
export const INPUT_GAP_STORAGE_KEY = 'roomler-rc-input-gap'
export const DEFAULT_INPUT_GAP_MS = 8

export function storedInputGapMs(): number {
  try {
    return normalizeIntKnob(
      globalThis.localStorage?.getItem(INPUT_GAP_STORAGE_KEY),
      DEFAULT_INPUT_GAP_MS,
      0,
      16,
    )
  } catch {
    return DEFAULT_INPUT_GAP_MS
  }
}

export function diagHudEnabled(): boolean {
  try {
    return globalThis.localStorage?.getItem(DIAG_HUD_STORAGE_KEY) === '1'
  } catch {
    return false
  }
}

// FR-26 — which quality pills the toolbar readout shows, per user.
//
// The readout grew one pill at a time until it was six wide, and the only
// way to influence it was an undiscoverable `roomler-rc-diag-hud=1`
// localStorage flag. Now every pill has a checkbox in Viewer settings.
// Everything is ON by default except `paint`: the per-hop numbers answer a
// question ("is the fps ceiling paint-, decode- or main-thread-bound?")
// that only matters while you are chasing it.
const METRICS_STORAGE_KEY = 'roomler-rc-metrics'

export interface RcMetricToggles {
  codec: boolean
  bitrate: boolean
  fps: boolean
  resolution: boolean
  age: boolean
  /** FR-74 P4 — the display-scale pill (1:1 check). */
  scale: boolean
  paint: boolean
}

export const DEFAULT_RC_METRICS: RcMetricToggles = {
  codec: true,
  bitrate: true,
  fps: true,
  resolution: true,
  age: true,
  scale: true,
  paint: false,
}

/**
 * Read the per-pill preference. Anything unreadable, corrupt or partial
 * falls back **per key**, so a stored object written by an older build
 * (fewer pills) keeps working and newly added pills appear rather than
 * silently reading as `false`.
 *
 * ⚠️ `paint` additionally inherits the legacy `roomler-rc-diag-hud=1` flag
 * the first time, so anyone who set it by hand keeps their HUD.
 */
export function storedMetricToggles(): RcMetricToggles {
  let parsed: Partial<RcMetricToggles> = {}
  try {
    const raw = globalThis.localStorage?.getItem(METRICS_STORAGE_KEY)
    const obj = raw ? JSON.parse(raw) : null
    if (obj && typeof obj === 'object' && !Array.isArray(obj)) parsed = obj
  } catch {
    /* privacy mode / corrupt JSON — defaults */
  }
  const pick = (k: keyof RcMetricToggles): boolean =>
    typeof parsed[k] === 'boolean' ? (parsed[k] as boolean) : DEFAULT_RC_METRICS[k]
  return {
    codec: pick('codec'),
    bitrate: pick('bitrate'),
    fps: pick('fps'),
    resolution: pick('resolution'),
    age: pick('age'),
    scale: pick('scale'),
    paint: typeof parsed.paint === 'boolean' ? parsed.paint : diagHudEnabled(),
  }
}

export function persistMetricToggles(m: RcMetricToggles): void {
  try {
    globalThis.localStorage?.setItem(METRICS_STORAGE_KEY, JSON.stringify(m))
  } catch {
    /* non-fatal — the toggles just won't survive this session */
  }
}

// P7 (Parsec-class plan) — FSR sharpening knobs (see rc-fsr-render.ts).
//  - roomler-rc-sharpen: 'auto' | 'on' | 'off'. Default 'auto' — the EASU+
//    RCAS upscale engages only when the decoded stream is SMALLER than the
//    viewer's window needs (the Smoother/relay rungs). Doubles as the field
//    escape hatch: localStorage.setItem('roomler-rc-sharpen','off') + refresh.
//  - roomler-rc-fsr-sharpness: RCAS sharpness in AMD stops (default 0.25,
//    clamp 0..2; LOWER = sharper). Tuning-only — no UI.
const SHARPEN_STORAGE_KEY = 'roomler-rc-sharpen'
const FSR_SHARPNESS_STORAGE_KEY = 'roomler-rc-fsr-sharpness'

export function storedSharpenMode(): SharpenMode {
  try {
    return normalizeSharpenMode(globalThis.localStorage?.getItem(SHARPEN_STORAGE_KEY))
  } catch {
    // FR-26 - unreadable storage gets the same default a fresh profile does.
    return 'on'
  }
}

export function storedSharpness(): number {
  try {
    const raw = globalThis.localStorage?.getItem(FSR_SHARPNESS_STORAGE_KEY)
    return raw === null || raw === undefined ? DEFAULT_RCAS_SHARPNESS : normalizeSharpness(raw)
  } catch {
    return DEFAULT_RCAS_SHARPNESS
  }
}

function persistSharpenMode(m: SharpenMode) {
  try {
    globalThis.localStorage?.setItem(SHARPEN_STORAGE_KEY, m)
  } catch {
    /* best-effort */
  }
}

/** P7 — report the canvas element's CSS box + devicePixelRatio to a DC
 *  video worker (drives the FSR backing-store sizing policy). Posts once
 *  immediately, then on element resize (150 ms trailing debounce — a
 *  backing realloc is cheap, no encoder rebuild involved) and on window
 *  `resize` (catches browser-zoom / monitor-move DPR changes that don't
 *  change the element box). Returns a cleanup closure. */
export function startViewportReporter(el: HTMLCanvasElement, worker: Worker): () => void {
  let timer: ReturnType<typeof setTimeout> | null = null
  const post = () => {
    timer = null
    const rect = el.getBoundingClientRect()
    try {
      worker.postMessage({
        type: 'viewport',
        cssW: rect.width,
        cssH: rect.height,
        dpr: globalThis.devicePixelRatio ?? 1,
      })
    } catch {
      /* worker torn down mid-report */
    }
  }
  const schedule = () => {
    if (timer !== null) clearTimeout(timer)
    timer = setTimeout(post, 150)
  }
  post()
  let ro: ResizeObserver | null = null
  if (typeof ResizeObserver !== 'undefined') {
    ro = new ResizeObserver(schedule)
    ro.observe(el)
  }
  globalThis.addEventListener?.('resize', schedule)
  return () => {
    if (timer !== null) clearTimeout(timer)
    ro?.disconnect()
    globalThis.removeEventListener?.('resize', schedule)
  }
}

/** P2 — restore the LEGACY H.264 mapping (RTP track + `<video>`) for the
 *  explicit H.264 codec choice. Escape hatch for the `data-channel-h264`
 *  rollout; see `codecChoiceToSettings`. */
const H264_RTP_STORAGE_KEY = 'roomler-rc-h264-rtp'

export function storedH264Rtp(): boolean {
  try {
    return globalThis.localStorage?.getItem(H264_RTP_STORAGE_KEY) === '1'
  } catch {
    return false
  }
}

/** P1 Ã¢ÂÂ one stats-window of per-hop pipeline diagnostics (worker hops + the
 *  main thread's long-task pressure). Consumed by the diag HUD. */
export type RcDecodeDiag = {
  paint: HopWindow | null
  fwd: HopWindow | null
  decode: HopWindow | null
  /** FR-1 P7 — end-to-end frame age at paint (agent framing → canvas),
   *  on the agent's clock mapped via the rc:clock probe. Null until the
   *  probe lands (old agents never echo — the field just stays null). */
  age: HopWindow | null
  /** FR-70 M0 — the age at ARRIVAL (last chunk in the worker), same clock
   *  mapping as `age`; and the local arrival→paint time. `age − arrival`
   *  is what this browser adds; `arrival` minus the agent's send-queue
   *  wait is the transit. Absent from workers older than M0. */
  arrival?: HopWindow | null
  viewer?: HopWindow | null
  /** FR-1 P7 — control-DC round trip of the best retained clock probe. */
  probeRttMs: number | null
  outGapMaxMs: number
  queue: number
  droppedTotal: number
  ctxMode: string
  longTasksPerSec: number
  longTaskMsPerSec: number
}

/** Feature-detect WebCodecs + RTCRtpScriptTransform. Returns true only
 *  when both pieces are present Ã¢ÂÂ Firefox has VideoDecoder but exposes
 *  insertable streams via a different API, so the toggle stays off
 *  there until we add that path too. Exported for vitest. */
export function isWebCodecsSupported(): boolean {
  const g = globalThis as unknown as {
    RTCRtpScriptTransform?: unknown
    VideoDecoder?: unknown
  }
  return typeof g.RTCRtpScriptTransform === 'function'
    && typeof g.VideoDecoder === 'function'
}

/** Which video transport the viewer prefers for inbound frames.
 *  - `webrtc`: classic WebRTC video track. The default. Works on
 *    every browser; pixels go through Chrome's chroma-subsampled
 *    (4:2:0) decode path for every codec.
 *  - `data-channel-vp9-444`: VP9 profile 1 (8-bit 4:4:4) frames over
 *    an RTCDataChannel named `video-bytes`, decoded with WebCodecs
 *    `VideoDecoder` and painted to a canvas. Bypasses the WebRTC
 *    pipeline's 4:2:0 enforcement so screen-content text stays
 *    crisp. Requires `VideoDecoder.isConfigSupported({codec:
 *    'vp09.01.10.08'})` and an agent that advertises
 *    `data-channel-vp9-444` in its `AgentCaps.transports`. Falls
 *    back to `webrtc` silently when either side lacks support.
 *    Takes effect on the next `connect()`. */
export type RcVideoTransport =
  | 'auto'
  | 'webrtc'
  | 'data-channel-vp9-444'
  | 'data-channel-hevc'
  | 'data-channel-av1'
  | 'data-channel-h264'

/** rc.190.1 Ã¢ÂÂ key bumped as a ONE-TIME migration to the new Auto
 *  default (same rationale as the resolution-prefix bump: transports
 *  toggled during the earlier debugging rounds would silently block the
 *  HWÃÂHW auto-rank forever). Explicit picks made from now on persist. */
const VIDEO_TRANSPORT_STORAGE_KEY = 'roomler-rc-video-transport.v2'

/** rc.62 Ã¢ÂÂ localStorage key for the per-browser VP9 chroma preference.
 *  Recognised values: `'auto'` (let the agent decide via env var),
 *  `'yuv420'` (VP9 profile 0, ~30% lower bandwidth), `'yuv444'`
 *  (VP9 profile 1, sharpest text). Default `'auto'` keeps rc.61
 *  behaviour for browsers that don't see the dropdown yet. */
const VP9_CHROMA_STORAGE_KEY = 'roomler-rc-vp9-chroma'

export type Vp9ChromaPref = 'auto' | 'yuv420' | 'yuv444'

function readStoredVp9Chroma(): Vp9ChromaPref {
  try {
    const raw = globalThis.localStorage?.getItem(VP9_CHROMA_STORAGE_KEY)
    if (raw === 'yuv420' || raw === 'yuv444' || raw === 'auto') return raw
  } catch {
    /* privacy mode Ã¢ÂÂ default */
  }
  return 'auto'
}

function persistVp9Chroma(c: Vp9ChromaPref) {
  try {
    globalThis.localStorage?.setItem(VP9_CHROMA_STORAGE_KEY, c)
  } catch {
    /* best-effort */
  }
}

function readStoredVideoTransport(): RcVideoTransport {
  try {
    const raw = globalThis.localStorage?.getItem(VIDEO_TRANSPORT_STORAGE_KEY)
    if (
      raw === 'data-channel-vp9-444'
      || raw === 'data-channel-hevc'
      || raw === 'data-channel-av1'
      || raw === 'webrtc'
      || raw === 'auto'
    )
      return raw
  } catch {
    /* privacy mode Ã¢ÂÂ default */
  }
  // rc.190 Ã¢ÂÂ default is AUTO: rank the transports by what's HARDWARE on
  // BOTH ends (agent hw_encoders ÃÂ viewer MediaCapabilities) at connect
  // time. Users who explicitly picked a transport (any stored value,
  // incl. 'webrtc' written by a toggle) keep their choice.
  return 'auto'
}

function persistVideoTransport(t: RcVideoTransport) {
  try {
    globalThis.localStorage?.setItem(VIDEO_TRANSPORT_STORAGE_KEY, t)
  } catch {
    /* best-effort */
  }
}

/** Opt-in "receive host audio" preference. localStorage key for the
 *  per-browser flag. When on, the controller adds a `recvonly` audio
 *  transceiver at `connect()` time AND sets `audio_enabled: true` in
 *  the `rc:session.request` payload; the agent only attaches an Opus
 *  track when it *also* advertises `"opus"` in `AgentCaps.audio` and
 *  was built with the `audio` feature Ã¢ÂÂ otherwise it silently ignores
 *  the flag (graceful no-op). Default OFF so audio stays opt-in and no
 *  autoplay-with-sound prompt fires unless the user asked for it. */
const AUDIO_ENABLED_STORAGE_KEY = 'roomler-rc-audio-enabled'

/** Read the persisted audio-enabled flag. Pure + exported so the wire
 *  contract (default OFF, exact truthy value) is locked by a unit
 *  test alongside the request-payload builder. */
export function readStoredAudioEnabled(): boolean {
  try {
    return globalThis.localStorage?.getItem(AUDIO_ENABLED_STORAGE_KEY) === '1'
  } catch {
    /* privacy mode Ã¢ÂÂ default OFF */
    return false
  }
}

/** Persist the audio-enabled flag (`'1'` on, key removed off). */
export function persistAudioEnabled(on: boolean) {
  try {
    if (on) globalThis.localStorage?.setItem(AUDIO_ENABLED_STORAGE_KEY, '1')
    else globalThis.localStorage?.removeItem(AUDIO_ENABLED_STORAGE_KEY)
  } catch {
    /* best-effort */
  }
}

/** Pure builder for the audio-related fields of an `rc:session.request`.
 *  Returns `{ audio_enabled: true }` only when the user opted in; an
 *  empty object otherwise so pre-audio agents get the silent-by-default
 *  behaviour (`#[serde(default)]` on the agent side Ã¢ÂÂ `false`).
 *  Exported so the field name + presence semantics are locked by a
 *  unit test. */
export function audioRequestFields(audioEnabled: boolean): Record<string, unknown> {
  return audioEnabled ? { audio_enabled: true } : {}
}

/** Feature-detect VP9 profile 1 (8-bit 4:4:4) decode via WebCodecs.
 *  Returns `false` synchronously when the browser has no
 *  `VideoDecoder` at all; otherwise calls `isConfigSupported` and
 *  awaits the answer. Codec string is the WebCodecs canonical form
 *  for VP9 profile 1, bit depth 8 (`vp09.<profile>.<level>.<bit>`).
 *
 *  Exported for tests so the codec string is locked alongside the
 *  worker's `VideoDecoder.configure` call. */
export async function isVp9_444DecodeSupported(): Promise<boolean> {
  const g = globalThis as unknown as {
    VideoDecoder?: { isConfigSupported?: (cfg: { codec: string }) => Promise<{ supported?: boolean }> }
  }
  const isConfigSupported = g.VideoDecoder?.isConfigSupported
  if (typeof isConfigSupported !== 'function') return false
  try {
    const res = await isConfigSupported({ codec: 'vp09.01.10.08' })
    return res?.supported === true
  } catch {
    return false
  }
}

/** #2231 — the same probe for VP9 profile 0 (`vp09.00.10.08`, 4:2:0, 8-bit),
 *  the string the worker configures when the session runs at 4:2:0. Firefox's
 *  WebCodecs decodes profile 0 but not profile 1, so this is what lets it
 *  take the VP9 DataChannel instead of the RTP track. Exported for tests. */
export async function isVp9_420DecodeSupported(): Promise<boolean> {
  const g = globalThis as unknown as {
    VideoDecoder?: { isConfigSupported?: (cfg: { codec: string }) => Promise<{ supported?: boolean }> }
  }
  const isConfigSupported = g.VideoDecoder?.isConfigSupported
  if (typeof isConfigSupported !== 'function') return false
  try {
    const res = await isConfigSupported({ codec: 'vp09.00.10.08' })
    return res?.supported === true
  } catch {
    return false
  }
}

/** rc.78 Ã¢ÂÂ feature-detect HEVC decode via WebCodecs. rc.94 Ã¢ÂÂ probes
 *  `hev1.1.6.L153.B0` (Main profile, Level **5.1**), matching the
 *  worker's `DEFAULT_HEVC_CODEC`. MUST stay in sync with the worker:
 *  the probe has to declare the SAME level the worker will configure,
 *  or we'd green-light a level the decoder then rejects on real bytes.
 *  Bumped from L3.1 (`L93`) which maxed at ~1280ÃÂ720 and rendered the
 *  field host's 1920ÃÂ1200 capture as a black screen (see worker note).
 *  The composable probes once on construction + caches in
 *  `hevcSupported`; `connect()` re-probes on the off-chance the cache
 *  hasn't resolved yet.
 *
 *  Unlike VP9, HEVC has NO software fallback in WebCodecs Ã¢ÂÂ Chromium
 *  only enables HEVC decode when the OS provides a HW decoder.
 *  Returns false on:
 *  - any pre-WebCodecs browser (no `VideoDecoder` at all)
 *  - Linux Chromium without HW HEVC (typical default)
 *  - corporate Chrome with HEVC policy disabled
 *  - very old GPUs without HW HEVC
 *
 *  Exported for tests so the codec string is locked alongside the
 *  worker's `VideoDecoder.configure` call. */
export async function isHevcDecodeSupported(): Promise<boolean> {
  const g = globalThis as unknown as {
    VideoDecoder?: { isConfigSupported?: (cfg: { codec: string }) => Promise<{ supported?: boolean }> }
  }
  const isConfigSupported = g.VideoDecoder?.isConfigSupported
  if (typeof isConfigSupported !== 'function') return false
  try {
    const res = await isConfigSupported({ codec: 'hev1.1.6.L153.B0' })
    return res?.supported === true
  } catch {
    return false
  }
}

/** P7 — HEVC Rext (Range extensions) 8-bit 4:4:4 codec string, Level 5.1.
 *  The Annex-B no-description contract is identical to the Main-profile
 *  string the HEVC worker ships; only the profile fields differ
 *  (profile_idc 4 + the Rext compatibility flag). */
export const HEVC_REXT_CODEC_STRING = 'hev1.4.10.L153.B0'

/** P7 — Rext 4:4:4 decode probe. Chrome support is NARROW and there is no
 *  software HEVC fallback at all: Windows NVIDIA needs Chrome ≥137 +
 *  driver ≥572.16; Windows Intel Gen11+ has it since 117; most other
 *  combinations return false. The 4:4:4 picker entry AND the connect-time
 *  chroma_pref are both gated on this probe — a mismatch would black-screen
 *  (the exact VP9-profile-1 prefer-hardware lesson). */
export async function isHevcRextDecodeSupported(): Promise<boolean> {
  const g = globalThis as unknown as {
    VideoDecoder?: { isConfigSupported?: (cfg: { codec: string }) => Promise<{ supported?: boolean }> }
  }
  const isConfigSupported = g.VideoDecoder?.isConfigSupported
  if (typeof isConfigSupported !== 'function') return false
  try {
    const res = await isConfigSupported({ codec: HEVC_REXT_CODEC_STRING })
    return res?.supported === true
  } catch {
    return false
  }
}

/** rc.186 — HARDWARE-and-smooth HEVC decode probe.
 *
 *  `isHevcDecodeSupported()` (VideoDecoder.isConfigSupported) returns `true`
 *  even when the browser can only decode HEVC in SOFTWARE or via a HW path
 *  too slow for real-time Ã¢ÂÂ the comment above assumed "no SW fallback", but
 *  the field disproved it: a weak Intel iGPU (Iris Xe) reports HEVC support,
 *  picks HEVC-over-DC, then its decode queue backs up at 1080p+/40fps Ã¢ÂÂ
 *  periodic keyframe-request spiral Ã¢ÂÂ the 1-2 s hang. The SAME viewer is
 *  perfectly smooth on VP9 4:2:0 (universal fixed-function HW decode).
 *
 *  `MediaCapabilities.decodingInfo()` exposes the two signals that matter:
 *  `smooth` (can sustain the target framerate) + `powerEfficient` (uses
 *  fixed-function silicon, not the CPU / GPU shaders). We require BOTH at a
 *  representative 1920ÃÂ1200@60 before PREFERRING HEVC; otherwise the caller
 *  falls back to VP9 4:2:0. Biasing toward VP9 is cheap (it's HW-decoded
 *  everywhere) and avoids the software-HEVC hang. Decoding is still probed
 *  via `isHevcDecodeSupported()` for the worker Ã¢ÂÂ this only gates the
 *  transport *preference*. */
export async function isHevcHwDecodeSupported(): Promise<boolean> {
  const mc = (
    navigator as Navigator & {
      mediaCapabilities?: {
        decodingInfo?: (cfg: unknown) => Promise<{
          supported?: boolean
          smooth?: boolean
          powerEfficient?: boolean
        }>
      }
    }
  ).mediaCapabilities
  if (typeof mc?.decodingInfo !== 'function') return false
  try {
    const info = await mc.decodingInfo({
      type: 'file',
      video: {
        contentType: 'video/mp4; codecs="hev1.1.6.L153.B0"',
        width: 1920,
        height: 1200,
        bitrate: 8_000_000,
        framerate: 60,
      },
    })
    return info.supported === true && info.smooth === true && info.powerEfficient === true
  } catch {
    return false
  }
}

/** rc.191 Ã¢ÂÂ wire shape for the display-match request (the agent switches
 *  its display to the largest mode fitting the viewer's stage, making the
 *  pixel chain 1:1 Ã¢ÂÂ see the agent's `display_match` module). `null` dims
 *  = disable/restore. Pure + exported so the shape is test-locked. */
export function displayMatchWireMessage(
  dims: { width: number; height: number } | null,
): Record<string, unknown> {
  if (!dims || !Number.isFinite(dims.width) || !Number.isFinite(dims.height)) {
    return { t: 'rc:display-match', enable: false }
  }
  return {
    t: 'rc:display-match',
    width: Math.max(1, Math.round(dims.width)),
    height: Math.max(1, Math.round(dims.height)),
  }
}

/** #2638 - a request the control channel cannot carry yet, held until it
 *  opens. The newest wins, and a held `null` (turn it off) is a request too.
 *  The viewer re-sends its display-match preference when the session turns
 *  `connected`, which is the peer connection's state; the control channel
 *  opens after it, so a send that waited for nothing was dropped and the
 *  default-ON preference never reached a host. */
export class HeldRequest<T> {
  private held: { value: T } | null = null
  hold(value: T): void {
    this.held = { value }
  }
  clear(): void {
    this.held = null
  }
  /** The held request, once; `null` when nothing is held. */
  take(): { value: T } | null {
    const h = this.held
    this.held = null
    return h
  }
}

/** rc.190 Ã¢ÂÂ the AV1 codec string for the `data-channel-av1` transport.
 *  Main profile (0), seq_level_idx 13 = Level 5.1 (covers 4K@60 Ã¢ÂÂ the
 *  HEVC L3.1 lesson: the declared level is a MAX, a smaller stream
 *  decodes fine under it, but a level BELOW the stream's resolution
 *  hard-rejects), Main tier, 8-bit. Shared by the probe + the decode
 *  worker `configure()` so they can't drift. */
export const AV1_CODEC_STRING = 'av01.0.13M.08'

/** rc.190 Ã¢ÂÂ feature-detect AV1 decode via WebCodecs. Chromium ships an
 *  in-tree dav1d SOFTWARE decoder, so unlike HEVC this is ~always true
 *  on Chrome Ã¢ÂÂ it gates the explicit user pick, not the auto-rank
 *  (which requires `isAv1HwDecodeSupported`). */
export async function isAv1DecodeSupported(): Promise<boolean> {
  const g = globalThis as unknown as {
    VideoDecoder?: { isConfigSupported?: (cfg: { codec: string }) => Promise<{ supported?: boolean }> }
  }
  const isConfigSupported = g.VideoDecoder?.isConfigSupported
  if (typeof isConfigSupported !== 'function') return false
  try {
    const res = await isConfigSupported({ codec: AV1_CODEC_STRING })
    return res?.supported === true
  } catch {
    return false
  }
}

/** rc.190 Ã¢ÂÂ HARDWARE-and-smooth AV1 decode probe (MediaCapabilities
 *  `smooth` + `powerEfficient`, same contract as the HEVC HW probe).
 *  dav1d SW decode exists everywhere, so `powerEfficient` is what
 *  separates a Gen12-Iris-Xe/RTX/RDNA2 viewer (fixed-function AV1
 *  decode) from a weak CPU grinding 4K AV1 in software. */
export async function isAv1HwDecodeSupported(): Promise<boolean> {
  const mc = (
    navigator as Navigator & {
      mediaCapabilities?: {
        decodingInfo?: (cfg: unknown) => Promise<{
          supported?: boolean
          smooth?: boolean
          powerEfficient?: boolean
        }>
      }
    }
  ).mediaCapabilities
  if (typeof mc?.decodingInfo !== 'function') return false
  try {
    const info = await mc.decodingInfo({
      type: 'file',
      video: {
        contentType: `video/mp4; codecs="${AV1_CODEC_STRING}"`,
        width: 1920,
        height: 1200,
        bitrate: 8_000_000,
        framerate: 60,
      },
    })
    return info.supported === true && info.smooth === true && info.powerEfficient === true
  } catch {
    return false
  }
}

/** rc.190 Ã¢ÂÂ HARDWARE-and-smooth VP9 profile-0 decode probe, for the
 *  auto-rank + the viewer-decode HUD badge. Profile 0 (4:2:0 8-bit) is
 *  the universally-HW-decoded VP9; profile 1 (4:4:4) is software
 *  everywhere and intentionally NOT probed here. */
export async function isVp9HwDecodeSupported(): Promise<boolean> {
  const mc = (
    navigator as Navigator & {
      mediaCapabilities?: {
        decodingInfo?: (cfg: unknown) => Promise<{
          supported?: boolean
          smooth?: boolean
          powerEfficient?: boolean
        }>
      }
    }
  ).mediaCapabilities
  if (typeof mc?.decodingInfo !== 'function') return false
  try {
    const info = await mc.decodingInfo({
      type: 'file',
      video: {
        contentType: 'video/mp4; codecs="vp09.00.10.08"',
        width: 1920,
        height: 1200,
        bitrate: 8_000_000,
        framerate: 60,
      },
    })
    return info.supported === true && info.smooth === true && info.powerEfficient === true
  } catch {
    return false
  }
}

/** P2 (Parsec-class plan) Ã¢ÂÂ H.264-over-DC codec-string probe ladder.
 *  Declared-max levels (a smaller stream decodes under them Ã¢ÂÂ the rc.94
 *  HEVC L93Ã¢ÂÂL153 lesson): High@L5.2 (4K60), High@L5.1, High@L4.2. The
 *  agent ships Annex-B with in-band SPS/PPS; per the WebCodecs AVC
 *  registry an `avc1.*` config WITHOUT `description` means Annex-B Ã¢ÂÂ
 *  the same description-less contract the `hev1` path has shipped for
 *  months. */
export const H264_DC_CODEC_CANDIDATES = ['avc1.640034', 'avc1.640033', 'avc1.64002A'] as const

/** P2 Ã¢ÂÂ first Annex-B avc1 codec string this browser's VideoDecoder
 *  accepts, or null when none (Ã¢ÂÂ the caller stays on the RTP track). */
export async function isH264DcDecodeSupported(): Promise<string | null> {
  const g = globalThis as unknown as {
    VideoDecoder?: { isConfigSupported?: (cfg: { codec: string }) => Promise<{ supported?: boolean }> }
  }
  const isConfigSupported = g.VideoDecoder?.isConfigSupported
  if (typeof isConfigSupported !== 'function') return null
  for (const codec of H264_DC_CODEC_CANDIDATES) {
    try {
      const res = await isConfigSupported({ codec })
      if (res?.supported === true) return codec
    } catch {
      /* try the next level down */
    }
  }
  return null
}

/** FR-77 P3b — H.264 High 4:4:4 Predictive (profile_idc 244 = 0xF4) over the
 *  same Annex-B, description-less contract as the 4:2:0 DC path, at the same
 *  declared-max level ladder. Chrome decodes it in SOFTWARE only (no D3D11 /
 *  VT profile for High 4:4:4), which the auto-rank prices in. */
export const H264_HIGH444_CODEC_CANDIDATES = ['avc1.F40034', 'avc1.F40033', 'avc1.F4002A'] as const

/** FR-77 P3b — first High 4:4:4 avc1 codec string this browser's
 *  VideoDecoder accepts, or null (the caller keeps the session on 4:2:0). */
export async function isH264High444DecodeSupported(): Promise<string | null> {
  const g = globalThis as unknown as {
    VideoDecoder?: { isConfigSupported?: (cfg: { codec: string }) => Promise<{ supported?: boolean }> }
  }
  const isConfigSupported = g.VideoDecoder?.isConfigSupported
  if (typeof isConfigSupported !== 'function') return null
  for (const codec of H264_HIGH444_CODEC_CANDIDATES) {
    try {
      const res = await isConfigSupported({ codec })
      if (res?.supported === true) return codec
    } catch {
      /* try the next level down */
    }
  }
  return null
}

/** P2 Ã¢ÂÂ HARDWARE-and-smooth H.264 decode probe (MediaCapabilities
 *  `smooth` + `powerEfficient`, same contract as the HEVC/AV1 HW probes).
 *  H.264 HW decode is near-universal, but the gate keeps the auto-rank
 *  honest on exotic viewers. */
export async function isH264HwDecodeSupported(): Promise<boolean> {
  const mc = (
    navigator as Navigator & {
      mediaCapabilities?: {
        decodingInfo?: (cfg: unknown) => Promise<{
          supported?: boolean
          smooth?: boolean
          powerEfficient?: boolean
        }>
      }
    }
  ).mediaCapabilities
  if (typeof mc?.decodingInfo !== 'function') return false
  try {
    const info = await mc.decodingInfo({
      type: 'file',
      video: {
        contentType: 'video/mp4; codecs="avc1.64002A"',
        width: 1920,
        height: 1200,
        bitrate: 8_000_000,
        framerate: 60,
      },
    })
    return info.supported === true && info.smooth === true && info.powerEfficient === true
  } catch {
    return false
  }
}

/**
 * FR-22 — memoise a capability probe for the lifetime of the page.
 *
 * ⚠️ Measured, not assumed. Driving a real session through the browser
 * caught `probes_ready: +1878 ms` on a reconnect — **45 % of that
 * connect's entire 4216 ms time-to-first-frame** — while other connects
 * in the same page showed 7-8 ms for identical work. `connect()` fires
 * seven of these concurrently on EVERY attempt and nothing cached them,
 * so every reconnect paid it again.
 *
 * Sound to cache because the answers cannot change while the page lives:
 * they describe this browser's decoders and this machine's GPU. A driver
 * change needs at minimum a reload, which clears this.
 *
 * The PROMISE is memoised, not the value. `connect()` launches these in
 * a `Promise.all`, so a value-only cache would still let a second caller
 * start a second probe while the first was in flight — precisely the
 * case that is slow.
 *
 * ⚠️ A rejection is NOT cached: every probe resolves `false` on failure
 * rather than throwing, so a cached rejection would be a permanent false
 * negative. Re-probing next call is the safe direction.
 *
 * ⚠️ Applied at the CALL SITE, not to the exported probes. The exported
 * `isXxxSupported` stay pure so they remain individually testable
 * against a stubbed `VideoDecoder` / `mediaCapabilities` — memoising
 * those directly made one existing test fail by serving a previous
 * test's stub, which is the same staleness this would cause for anyone
 * re-probing after an environment change.
 */
export function memoProbe<T>(fn: () => Promise<T>): () => Promise<T> {
  let inflight: Promise<T> | null = null
  return () => {
    if (inflight) return inflight
    const p = fn().catch((e) => {
      inflight = null
      throw e
    })
    inflight = p
    return p
  }
}

/** The probe set `connect()` runs on every attempt, cached per page. */
const probeAv1Hw = memoProbe(isAv1HwDecodeSupported)
const probeHevcHw = memoProbe(isHevcHwDecodeSupported)
const probeHevcDec = memoProbe(isHevcDecodeSupported)
const probeVp9Hw = memoProbe(isVp9HwDecodeSupported)
const probeVp9_444 = memoProbe(isVp9_444DecodeSupported)
const probeVp9_420 = memoProbe(isVp9_420DecodeSupported)
const probeH264Hw = memoProbe(isH264HwDecodeSupported)
const probeH264Dc = memoProbe(isH264DcDecodeSupported)
const probeAv1Dec = memoProbe(isAv1DecodeSupported)
const probeHevcRext = memoProbe(isHevcRextDecodeSupported)
const probeH264High444 = memoProbe(isH264High444DecodeSupported)

/** rc.190 Ã¢ÂÂ inputs to the pure transport auto-rank. `agentTransports` /
 *  `agentHwEncoders` come from `Agent.capabilities` (the agent's caps
 *  probe truth); the `viewer*` bits are this browser's MediaCapabilities
 *  probes. P2 adds `viewerH264Hw` (HW decode AND an accepted Annex-B
 *  avc1 config Ã¢ÂÂ see `isH264DcDecodeSupported`). */
export interface AutoTransportInputs {
  agentTransports: string[]
  agentHwEncoders: string[]
  viewerAv1Hw: boolean
  viewerHevcHw: boolean
  /** Whether WebCodecs `VideoDecoder.isConfigSupported('hev1…')` passed —
   *  the contract the HEVC-DC worker actually configures against.
   *  `viewerHevcHw` alone is a MediaCapabilities probe of the `<video>`
   *  pipeline, and the two DIVERGE on Edge: platform HEVC (HEVC Video
   *  Extensions) makes MC report supported+smooth while WebCodecs still
   *  refuses `hev1`, so the rank picked a transport whose worker then
   *  failed `configure()` — a black session the watchdog re-picked
   *  forever (field: CORPLAP-3, 2026-08-25). Same shape as P2's
   *  `viewerH264Hw = MC && accepted avc1 config`. */
  viewerHevcDecodable: boolean
  viewerVp9Hw: boolean
  viewerVp9Decodable: boolean
  /** #2231 — WebCodecs decodes VP9 profile 0 (`vp09.00.10.08`, 4:2:0).
   *  `viewerVp9Decodable` is the profile-1 probe; Firefox decodes profile 0
   *  only, and without this the VP9 DataChannel was never offered to it.
   *  Optional: absent reads as "not known", which changes nothing. */
  viewerVp9_420Decodable?: boolean
  /** #2231 — this browser can decode the RTP track's universal fallback,
   *  H.264: its receiver caps list H.264, or list nothing at all (which the
   *  agent reads as H.264). Optional: absent reads as "yes", the old
   *  assumption, so the profile-0 rung below stays off. */
  viewerRtpH264?: boolean
  viewerH264Hw: boolean
  /** The viewer's Priority dial. Only `sharper` changes the outcome, and
   *  only on the libvpx SW rung — see the chroma note on `pickAutoTransport`.
   *  Optional so existing callers/tests keep their meaning (absent =
   *  `balanced` = the pre-existing 4:2:0 behaviour). */
  priority?: RcPriority
  /** FR-77 — the chroma dropdown. `yuv444` puts the 4:4:4 cells first (HEVC
   *  Rext on a HW×HW pair, then VP9 profile 1) and falls back to the normal
   *  rank when the pair has none; `yuv420` pins every rung to 4:2:0; `auto`
   *  (or absent) lets the Priority dial decide — `sharper` then takes the
   *  HEVC 4:4:4 cell when the pair has it. */
  chromaPref?: 'auto' | 'yuv420' | 'yuv444'
  /** FR-77 — the agent advertises an HEVC 4:4:4 cell (`video_cells`, or the
   *  legacy `hevc_chroma`). Never optimistic: a chroma mismatch is a black
   *  screen. */
  agentHevc444?: boolean
  /** FR-77 — WebCodecs accepts the HEVC Rext codec string here. */
  viewerHevcRext?: boolean
  /** FR-77 P3b — the agent opened H.264 4:4:4 (NVENC High 4:4:4). */
  agentH264_444?: boolean
  /** FR-77 P3b — this browser decodes H.264 High 4:4:4 (software). */
  viewerH264High444?: boolean
  /** FR-77 P3b — the agent opened a HARDWARE VP9 4:4:4 cell (vp9_qsv profile 1). */
  agentVp9Hw444?: boolean
}

/** rc.190 Ã¢ÂÂ pure HWÃÂHW transport rank for `videoTransport === 'auto'`.
 *
 *  Field lesson (2026-07-16, WINHOST-H/DEVBOX Ã¢ÂÂ WINHOST-A): VP9 is
 *  software-ENCODED on almost every host (only Intel Gen11+ iGPUs have
 *  VP9 encode silicon; NVIDIA/AMD never shipped it), and HEVC/AV1 can be
 *  software-DECODED on the viewer Ã¢ÂÂ a codec is only smooth when it's
 *  hardware on BOTH ends. Rank:
 *    1. AV1-DC   Ã¢ÂÂ agent HW av1 encoder  ÃÂ viewer HW AV1 decode
 *    2. HEVC-DC  Ã¢ÂÂ agent HW hevc encoder ÃÂ viewer HW HEVC decode
 *    3. VP9-DC 4:2:0 Ã¢ÂÂ agent HW vp9 encoder (vp9_qsv) ÃÂ viewer HW VP9
 *    4. H264-DC  Ã¢ÂÂ agent HW h264 encoder ÃÂ viewer HW H.264 decode (P2:
 *       HWÃÂHW beats the SW-encode tier below on CPU cost and its Ã¢ÂÂ¤1920
 *       cap; H.264's poorer compression only matters on constrained
 *       links, which the relay clamps already govern)
 *    5. VP9-DC 4:2:0 Ã¢ÂÂ agent libvpx SW encode (the agent's rc.190 SW cap
 *       keeps it Ã¢ÂÂ¤1920 long edge) ÃÂ viewer HW VP9 decode
 *    6. webrtc   Ã¢ÂÂ the REMB-adaptive H.264 track (universal fallback)
 *  Returns the transport (null = webrtc) + a chroma override ('yuv420'
 *  for the VP9 picks so the fallback never lands on software-decoded
 *  profile 1). Exported for vitest.
 *
 *  Chroma vs. the Priority dial: 4:2:0 is the right DEFAULT (it is the
 *  universally HW-decoded VP9 profile), but it subsamples exactly the
 *  colour edges that make TEXT legible, so a Mac streaming a terminal on
 *  Auto looked soft for a reason the picker never surfaced. `sharper`
 *  therefore buys full chroma at the cost of SW decode — which is the
 *  trade that dial already means everywhere else. Deliberately narrow:
 *  ONLY rung 5, because that rung's encoder is libvpx (profile 1 always
 *  available) and its own guard is `isVp9_444DecodeSupported()`, i.e. it
 *  has already proven this browser decodes profile 1. Rung 3 is
 *  `vp9_qsv`, whose 4:4:4 support is not established — forcing it there
 *  risks failing the encoder open, so it stays 4:2:0 whatever the dial
 *  says. HEVC stays untouched: its Rext 4:4:4 pick is double-gated on a
 *  browser probe AND agent caps precisely because a mismatch is a black
 *  screen, and the auto-rank must not guess at it. */
export function pickAutoTransport(inputs: AutoTransportInputs): {
  transport: Exclude<RcVideoTransport, 'auto' | 'webrtc'> | null
  chromaOverride: string | null
  reason: string
} {
  const t = inputs.agentTransports
  const enc = inputs.agentHwEncoders
  // Transport advertisement, with hw_encoders-derived fallback for agent
  // rows saved before `transports` serialization existed.
  const hasAv1Dc = t.includes('data-channel-av1') || enc.some((e) => e.startsWith('ffmpeg-av1_'))
  const hasHevcDc = t.includes('data-channel-hevc') || enc.some((e) => e.startsWith('ffmpeg-hevc_'))
  const hasVp9Dc = t.includes('data-channel-vp9-444') || enc.includes('libvpx-vp9-444-sw')
  const agentVp9Hw = enc.includes('ffmpeg-vp9_qsv')
  // P2 Ã¢ÂÂ transport-advertisement ONLY (no hw_encoders fallback like AV1/HEVC:
  // `ffmpeg-h264_*` entries and the transport shipped in the same release, so
  // there are no older agent rows with the encoder but not the transport).
  const hasH264Dc = t.includes('data-channel-h264')

  // FR-77 — chroma before codec. An explicit 4:4:4 (or Sharper with chroma on
  // Auto) reaches for the one 4:4:4 cell that is hardware on BOTH ends —
  // HEVC Rext — ahead of every 4:2:0 pair, because that is what the dropdown
  // (or the dial) asked for. An explicit 4:4:4 then settles for VP9 profile 1
  // (software encode, software decode) before giving up on full chroma;
  // Sharper-on-Auto does NOT, since the SW rung below already knows how to
  // trade for it. Both gates are the picker's: the agent must have OPENED the
  // cell and this browser must accept the Rext string.
  const want444 = inputs.chromaPref === 'yuv444'
    || (inputs.chromaPref !== 'yuv420' && inputs.priority === 'sharper')
  const force420 = inputs.chromaPref === 'yuv420'
  const hevc444Pair = hasHevcDc
    && inputs.viewerHevcHw
    && inputs.viewerHevcDecodable
    && inputs.viewerHevcRext === true
    && inputs.agentHevc444 === true
  if (want444 && hevc444Pair) {
    return {
      transport: 'data-channel-hevc',
      chromaOverride: 'yuv444',
      reason: 'HEVC 4:4:4: HW Rext encode on agent + HW Rext decode here',
    }
  }
  // FR-77 P3b — an EXPLICIT 4:4:4 keeps reaching for hardware-ENCODED full
  // chroma before the software-encoded libvpx cell: H.264 High 4:4:4 on
  // NVENC, then VP9 profile 1 on vp9_qsv. Both decode in software here, which
  // is why Sharper-on-Auto does not take them (it trades decode for chroma
  // only at the libvpx rung, where nothing is lost).
  if (inputs.chromaPref === 'yuv444' && hasH264Dc && inputs.agentH264_444 === true
    && inputs.viewerH264High444 === true) {
    return {
      transport: 'data-channel-h264',
      chromaOverride: 'yuv444',
      reason: 'H.264 4:4:4: HW High 4:4:4 encode on agent + software decode here',
    }
  }
  if (inputs.chromaPref === 'yuv444' && hasVp9Dc && inputs.agentVp9Hw444 === true
    && inputs.viewerVp9Decodable) {
    return {
      transport: 'data-channel-vp9-444',
      chromaOverride: 'yuv444',
      reason: 'VP9 4:4:4: HW profile-1 encode (vp9_qsv) on agent + software decode here',
    }
  }
  if (inputs.chromaPref === 'yuv444' && hasVp9Dc && inputs.viewerVp9Decodable) {
    return {
      transport: 'data-channel-vp9-444',
      chromaOverride: 'yuv444',
      reason: 'VP9 4:4:4: the only full-chroma cell this pair has (SW encode, SW decode)',
    }
  }

  if (hasAv1Dc && inputs.viewerAv1Hw) {
    return {
      transport: 'data-channel-av1',
      chromaOverride: null,
      reason: 'AV1: HW encode on agent + HW decode here',
    }
  }
  // Both halves required: MC says the DECODE is hardware-smooth, WebCodecs
  // says the worker's configure() will actually be accepted. See the
  // `viewerHevcDecodable` doc — MC alone lies on Edge.
  if (hasHevcDc && inputs.viewerHevcHw && inputs.viewerHevcDecodable) {
    return {
      transport: 'data-channel-hevc',
      chromaOverride: null,
      reason: 'HEVC: HW encode on agent + HW decode here',
    }
  }
  if (hasVp9Dc && agentVp9Hw && inputs.viewerVp9Hw) {
    return {
      transport: 'data-channel-vp9-444',
      chromaOverride: 'yuv420',
      reason: 'VP9 4:2:0: HW encode (vp9_qsv) + HW decode here',
    }
  }
  if (hasH264Dc && inputs.viewerH264Hw) {
    return {
      transport: 'data-channel-h264',
      chromaOverride: null,
      reason: 'H.264-DC: HW encode on agent + HW decode here (beats the SW-encode tier)',
    }
  }
  if (hasVp9Dc && inputs.viewerVp9Decodable) {
    // Sharper => full chroma. Safe here and ONLY here: libvpx always has
    // profile 1, and this rung's own guard IS the profile-1 decode probe.
    // FR-77 — an explicit 4:2:0 in the chroma dropdown overrides the dial.
    if (inputs.priority === 'sharper' && !force420) {
      return {
        transport: 'data-channel-vp9-444',
        chromaOverride: 'yuv444',
        reason: 'VP9 4:4:4: SW encode on agent - Sharper trades HW decode for full-chroma text',
      }
    }
    return {
      transport: 'data-channel-vp9-444',
      chromaOverride: 'yuv420',
      reason: 'VP9 4:2:0: SW encode on agent (capped Ã¢ÂÂ¤1920) Ã¢ÂÂ no HWÃÂHW codec pair available',
    }
  }
  // #2231 — a browser that decodes VP9 profile 0 but not profile 1 (Firefox's
  // WebCodecs) takes the VP9 DataChannel at 4:2:0 when the RTP track below
  // cannot work for it: no H.264 to decode (a Firefox without OpenH264), so an
  // agent that offers the track only as H.264 has no codec in common with it.
  // A browser that does decode H.264 keeps the track it has always used: this
  // rung rescues the broken case and moves no working one.
  if (hasVp9Dc && inputs.viewerVp9_420Decodable === true && inputs.viewerRtpH264 === false) {
    return {
      transport: 'data-channel-vp9-444',
      chromaOverride: 'yuv420',
      reason: 'VP9 4:2:0: SW encode on agent - this browser decodes VP9 profile 0 only',
    }
  }
  return { transport: null, chromaOverride: null, reason: 'webrtc H.264 fallback' }
}

/** rc.199 Ã¢ÂÂ the viewer "Priority" dial (`rc:priority` control message). A
 *  per-session lever that trades resolution sharpness against motion
 *  smoothness; the agent reads it to resolve the relay resolution cap
 *  (balanced = link-physics cap on a relay, sharper = native override / the
 *  "Sharpness" lever, smoother = fewer pixels everywhere). */
export type RcPriority = 'balanced' | 'sharper' | 'smoother'

const PRIORITY_STORAGE_KEY = 'roomler-rc-priority'

function readStoredPriority(): RcPriority {
  try {
    const raw = globalThis.localStorage?.getItem(PRIORITY_STORAGE_KEY)
    if (raw === 'balanced' || raw === 'sharper' || raw === 'smoother') return raw
  } catch {
    /* privacy mode Ã¢ÂÂ default */
  }
  // 2026-08-02 operator default: Sharper (text fidelity over motion).
  return 'sharper'
}

function persistPriority(p: RcPriority) {
  try {
    globalThis.localStorage?.setItem(PRIORITY_STORAGE_KEY, p)
  } catch {
    /* best-effort Ã¢ÂÂ swallow quota / privacy-mode errors */
  }
}

/** loopback-TURN corp-relay (Phase 2; default ON since 2026-08-02 — bedded
 *  in). When on, `connect()` probes the local agent's loopback TURN and, if
 *  present, relays through it. */
const LOCAL_RELAY_STORAGE_KEY = 'roomler-rc-local-relay'

function readStoredLocalRelay(): boolean {
  // 2026-08-02 operator default: ON (bedded in since rc.220 agent-side).
  // Explicit off is stored as '0' (persist always writes), so users who
  // turned it off keep their choice.
  try {
    return globalThis.localStorage?.getItem(LOCAL_RELAY_STORAGE_KEY) !== '0'
  } catch {
    return true
  }
}

function persistLocalRelay(on: boolean) {
  try {
    globalThis.localStorage?.setItem(LOCAL_RELAY_STORAGE_KEY, on ? '1' : '0')
  } catch {
    /* best-effort */
  }
}

/** Pure builder for the `rc:priority` control-DC envelope. Exported so the
 *  unit tests can lock the wire shape the agent's `priority::from_wire`
 *  parses. */
export function priorityWireMessage(mode: RcPriority): { t: 'rc:priority'; mode: RcPriority } {
  return { t: 'rc:priority', mode }
}

/** rc.199 Ã¢ÂÂ the single "Codec" picker that replaces the four transport
 *  toggle buttons + the codec-override + VP9-chroma dropdowns. Each choice
 *  maps to a full (transport, chroma, preferredCodec, renderPath) tuple so the
 *  picker fully determines the previously-scattered controls. */
export type RcCodecChoice = (typeof RC_CODEC_CHOICES)[number]

export interface CodecChoiceSettings {
  videoTransport: RcVideoTransport
  chroma: Vp9ChromaPref
  preferredCodec: RcPreferredCodec | null
  renderPath: RcRenderPath
}

/** Map a Codec-picker choice to the underlying settings. Pure + exported so
 *  the tests lock it. `renderPath` is auto-managed here (this is what lets us
 *  drop the old standalone WebCodecs toggle): everything uses the low-latency
 *  WebCodecs path. The DC transports decode via the workerÃ¢ÂÂcanvas regardless
 *  of `renderPath`, so setting it for them is harmless and keeps the mapping
 *  total. `setRenderPath` clamps `webcodecs`Ã¢ÂÂ`video` on browsers without
 *  WebCodecs.
 *
 *  P2 Ã¢ÂÂ the explicit H.264 choice now maps to `data-channel-h264` (the same
 *  reliable-DC + WebCodecs pipeline as the other three codecs; connect()
 *  falls back to the legacy RTP track when the agent doesn't advertise it or
 *  this browser rejects Annex-B avc1). `opts.h264Rtp` (localStorage
 *  `roomler-rc-h264-rtp=1`, threaded by the caller to keep this pure)
 *  restores the legacy RTP + `<video>` mapping outright. */
export function codecChoiceToSettings(
  choice: RcCodecChoice,
  opts?: { h264Rtp?: boolean },
): CodecChoiceSettings {
  switch (choice) {
    case 'av1':
      return { videoTransport: 'data-channel-av1', chroma: 'auto', preferredCodec: null, renderPath: 'webcodecs' }
    case 'hevc':
      return { videoTransport: 'data-channel-hevc', chroma: 'auto', preferredCodec: null, renderPath: 'webcodecs' }
    case 'hevc-444':
      // P7 — HEVC Rext 4:4:4 (hevc_nvenc + Chrome Rext decode; kills
      // ClearType chroma fringing on the HW pipeline). connect() gates on
      // BOTH ends and silently falls back to 4:2:0 HEVC when either lacks
      // Rext.
      return {
        videoTransport: 'data-channel-hevc',
        chroma: 'yuv444',
        preferredCodec: null,
        renderPath: 'webcodecs',
      }
    case 'vp9-444':
      return {
        videoTransport: 'data-channel-vp9-444',
        chroma: 'yuv444',
        preferredCodec: null,
        renderPath: 'webcodecs',
      }
    case 'vp9-420':
      return {
        videoTransport: 'data-channel-vp9-444',
        chroma: 'yuv420',
        preferredCodec: null,
        renderPath: 'webcodecs',
      }
    case 'vp9':
      // FR-77 — VP9 with chroma "Auto": connect() resolves the chroma from
      // the Priority dial (`resolveChroma`), so this is the one VP9 choice
      // that follows the dial instead of pinning a profile.
      return {
        videoTransport: 'data-channel-vp9-444',
        chroma: 'auto',
        preferredCodec: null,
        renderPath: 'webcodecs',
      }
    case 'auto-444':
      // FR-77 — codec "Auto" + chroma 4:4:4: the auto-rank tries the 4:4:4
      // cells first (HEVC Rext on a HW×HW pair, then VP9 profile 1) and
      // falls back to the normal rank when this pair has none.
      return { videoTransport: 'auto', chroma: 'yuv444', preferredCodec: null, renderPath: 'webcodecs' }
    case 'auto-420':
      // FR-77 — codec "Auto" + chroma 4:2:0: the normal rank, with the
      // libvpx rung pinned to profile 0 whatever the Priority dial says.
      return { videoTransport: 'auto', chroma: 'yuv420', preferredCodec: null, renderPath: 'webcodecs' }
    case 'h264-444':
      return {
        videoTransport: 'data-channel-h264',
        chroma: 'yuv444',
        preferredCodec: 'h264',
        renderPath: 'webcodecs',
      }
    case 'h264':
      if (opts?.h264Rtp) {
        return { videoTransport: 'webrtc', chroma: 'auto', preferredCodec: 'h264', renderPath: 'video' }
      }
      return {
        videoTransport: 'data-channel-h264',
        chroma: 'auto',
        preferredCodec: 'h264',
        renderPath: 'webcodecs',
      }
    case 'auto':
    default:
      return { videoTransport: 'auto', chroma: 'auto', preferredCodec: null, renderPath: 'webcodecs' }
  }
}

/** Reverse of `codecChoiceToSettings` (for the picker's displayed value): map
 *  the stored transport + chroma back to a choice. A `data-channel-vp9-444`
 *  transport reads as 4:4:4 only when the chroma is explicitly `yuv444`;
 *  otherwise (incl. the legacy `auto`) it reads as the 4:2:0 efficient choice.
 *  Pure + exported for the round-trip test. */
export function settingsToCodecChoice(
  transport: RcVideoTransport,
  chroma: Vp9ChromaPref,
): RcCodecChoice {
  switch (transport) {
    case 'data-channel-av1':
      return 'av1'
    case 'data-channel-hevc':
      // P7 — an explicit yuv444 chroma on the HEVC transport is the Rext
      // pick; everything else (incl. the legacy 'auto') reads as plain HEVC.
      return chroma === 'yuv444' ? 'hevc-444' : 'hevc'
    case 'data-channel-vp9-444':
      // FR-77 — an explicit chroma keeps its VP9 profile; `auto` is the
      // dial-following `vp9` choice (it used to read as 4:2:0, which hid that
      // the agent's default for an unstated chroma is profile 1).
      return chroma === 'yuv444' ? 'vp9-444' : chroma === 'yuv420' ? 'vp9-420' : 'vp9'
    case 'data-channel-h264':
      return chroma === 'yuv444' ? 'h264-444' : 'h264'
    case 'webrtc':
      return 'h264'
    case 'auto':
    default:
      // FR-77 — codec Auto remembers an explicit chroma.
      return chroma === 'yuv444' ? 'auto-444' : chroma === 'yuv420' ? 'auto-420' : 'auto'
  }
}

/** loopback-TURN corp-relay (Phase 2 Ã¢ÂÂ plan
 *  `~/.claude/plans/roomler-loopback-turn-corp-relay.md`). The corp host's
 *  local enrolled agent hosts a TURN server (`tunnel-core::transport::
 *  turn_host::LocalTurnHost`) + a loopback HTTP endpoint that returns this
 *  descriptor. The browser Ã¢ÂÂ loopback is never firewall-blocked, unlike its
 *  direct/coturn UDP Ã¢ÂÂ probes the endpoint, uses `turn:127.0.0.1:{turn_port}`
 *  as an ICE server, AND forwards the whole descriptor to the server so the Hub
 *  adds `turn:{overlay_ip}:{turn_port}` to the REMOTE agent's ICE servers. The
 *  media then relays through the local agent's overlay (WFP-permitted) instead
 *  of the capped far coturn. */
export interface LocalRelayDescriptor {
  turn_port: number
  overlay_ip: string
  username: string
  credential: string
}

/** Primary loopback port the agent serves its descriptor + clipboard
 *  bridge on. The browser probes `http://127.0.0.1:{port}/rc-local-turn`
 *  (+ `/rc-clipboard`); no response (no local agent, feature off,
 *  Private-Network-Access blocked, timeout) makes the probe a graceful
 *  no-op. */
export const LOCAL_RELAY_PROBE_PORT = 47989
/** Candidate discovery ports, two bands. A host can run MORE THAN ONE
 *  agent (Windows + WSL under mirrored networking, sharing the Windows
 *  loopback), so the browser probes a range not a single port. The
 *  FALLBACK band (`41989+`) covers hosts whose Hyper-V/WSL/HNS
 *  reservations swallow the whole primary band (`47989+` sits at the
 *  edge of that reservation zone; the fallback lives well below it).
 *  First match wins. MUST match the agent's `PROBE_PORT` +
 *  `PROBE_PORT_FALLBACK` + `PROBE_PORT_BAND` in `rc_local_turn.rs`. */
export const LOCAL_RELAY_PROBE_PORTS = [
  47989, 47990, 47991, 47992, 47993, 41989, 41990, 41991, 41992, 41993,
]

/** Validate an untrusted JSON blob from the loopback probe into a
 *  [`LocalRelayDescriptor`], or `null`. Pure + exported for tests. */
export function parseLocalRelayDescriptor(raw: unknown): LocalRelayDescriptor | null {
  if (raw === null || typeof raw !== 'object') return null
  const o = raw as Record<string, unknown>
  const { turn_port, overlay_ip, username, credential } = o
  if (
    typeof turn_port !== 'number' ||
    !Number.isInteger(turn_port) ||
    turn_port <= 0 ||
    turn_port > 65535 ||
    typeof overlay_ip !== 'string' ||
    overlay_ip.length === 0 ||
    typeof username !== 'string' ||
    typeof credential !== 'string'
  ) {
    return null
  }
  return { turn_port, overlay_ip, username, credential }
}

/** 2026-07-24 decode-stall A/B Ã¢ÂÂ experimental override for the DC decode
 *  workers' `VideoDecoder.hardwareAcceleration`. localStorage
 *  `roomler-rc-decode-pref`: `'software'` | `'hardware'` | unset
 *  (`no-preference`, today's behaviour). Field context: DEVBOX viewing WINHOST-A
 *  hits 3-5 s mid-session decoder stalls (Mbps > 0, decoded fps Ã¢ÂÂ 0, then a
 *  catch-up burst) on BOTH HEVC and VP9 with the agent proven healthy Ã¢ÂÂ
 *  suspect Chrome's GPU-process decode on the hybrid-GPU laptop. Setting
 *  `'software'` A/Bs that theory on VP9/AV1 (HEVC has no SW decoder in
 *  Chromium Ã¢ÂÂ prefer-software there fails configure() and the existing
 *  fallback path takes over). Pure + exported for tests. */
export function storedDecodePref(): 'prefer-software' | 'prefer-hardware' | 'no-preference' {
  try {
    const raw = globalThis.localStorage?.getItem('roomler-rc-decode-pref')
    if (raw === 'software') return 'prefer-software'
    if (raw === 'hardware') return 'prefer-hardware'
  } catch {
    /* privacy mode Ã¢ÂÂ default */
  }
  return 'no-preference'
}

/** The browser's ICE-server entry for the loopback TURN (dialled over loopback,
 *  never firewalled). Pure + exported for tests. */
export function localRelayIceServer(desc: LocalRelayDescriptor): IceServer {
  return {
    urls: [`turn:127.0.0.1:${desc.turn_port}`],
    username: desc.username,
    credential: desc.credential,
  }
}

/** rc.44 Ã¢ÂÂ clipboard chunking constants. The single-envelope
 *  `clipboard:write` shape sent a `text` field unbounded by length;
 *  on payloads >~50 KB this hit webrtc-rs's SCTP `max_message_size=
 *  65536` default and threw `failed to handle_inbound: ErrChunk`,
 *  killing the data channel + session (field repro 2026-05-19,
 *  sessions dying every 1-2 min). The chunked variants cap each
 *  envelope at [`CLIPBOARD_CHUNK_BYTES`] to stay comfortably under
 *  the SCTP ceiling. Total payload capped at [`CLIPBOARD_MAX_BYTES`]
 *  (1 MB) on both sides; the agent rejects oversized writes via
 *  `clipboard:error`. */
export const CLIPBOARD_CHUNK_BYTES = 14 * 1024
export const CLIPBOARD_MAX_BYTES = 1024 * 1024
/** Below this UTF-8 byte length the single-envelope `clipboard:write`
 *  shape is used for back-compat with rc.43-and-older agents that
 *  don't know the chunked variant. Above this, the browser switches
 *  to `clipboard:write-chunk`. */
export const CLIPBOARD_SINGLE_ENVELOPE_THRESHOLD_BYTES = 12 * 1024

/** UTF-8-byte-aware chunker for clipboard payloads. Splits `text`
 *  into substrings each of at most [`CLIPBOARD_CHUNK_BYTES`] when
 *  encoded as UTF-8, while preserving codepoint boundaries so a
 *  consumer that simply concatenates the chunks reproduces the
 *  original text. Mirrors the agent's `clipboard::split_into_chunks`
 *  in Rust. Exported for tests; the locked invariant is
 *  `chunks.join('') === text` regardless of input content. */
export function chunkClipboardText(text: string): string[] {
  const enc = new TextEncoder()
  const dec = new TextDecoder('utf-8', { fatal: true })
  const bytes = enc.encode(text)
  if (bytes.length === 0) return ['']
  if (bytes.length <= CLIPBOARD_CHUNK_BYTES) return [text]
  const out: string[] = []
  let cursor = 0
  while (cursor < bytes.length) {
    let end = Math.min(cursor + CLIPBOARD_CHUNK_BYTES, bytes.length)
    // UTF-8 continuation bytes match 10xxxxxx (0x80..0xBF). Walk
    // back past any partial multi-byte sequence so each slice is a
    // valid standalone UTF-8 string.
    while (end > cursor && end < bytes.length && (bytes[end] & 0xc0) === 0x80) {
      end -= 1
    }
    out.push(dec.decode(bytes.subarray(cursor, end)))
    cursor = end
  }
  return out
}

/** Send a clipboard write over the supplied DC. Below
 *  [`CLIPBOARD_SINGLE_ENVELOPE_THRESHOLD_BYTES`] uses the legacy
 *  single-envelope `clipboard:write` for back-compat with older
 *  agents; above, splits into `clipboard:write-chunk` envelopes
 *  carrying a shared transaction id. Caller owns try/catch Ã¢ÂÂ this
 *  function may throw if the DC closes mid-burst.
 *
 *  v2 Ã¢ÂÂ every envelope (single included) now carries an `id`; v2
 *  agents reply `clipboard:write-ack {id}` once the OS clipboard
 *  write completes, which the caller can await via
 *  `awaitClipboardAck` to gate a deferred Ctrl+V. Old agents ignore
 *  the unknown field (no `deny_unknown_fields` on their serde enum).
 *  The text goes on the wire RAW Ã¢ÂÂ never canonicalized Ã¢ÂÂ because v1
 *  agents write it to the OS clipboard verbatim (stripping CRLF here
 *  would regress Windows-host pastes through them; v2 agents
 *  normalize server-side). Returns the envelope count + the id. */
export function sendClipboardWriteOverDc(
  ch: RTCDataChannel,
  text: string,
): { envelopes: number; id: string } {
  const enc = new TextEncoder()
  const byteLen = enc.encode(text).length
  const id =
    'cb-' +
    Date.now().toString(36) +
    '-' +
    Math.random().toString(36).slice(2, 10)
  if (byteLen <= CLIPBOARD_SINGLE_ENVELOPE_THRESHOLD_BYTES) {
    ch.send(JSON.stringify({ t: 'clipboard:write', text, id }))
    return { envelopes: 1, id }
  }
  // Truncate at the 1 MB cap; warn so the user knows. The agent
  // rejects oversized writes anyway via `clipboard:error`, but
  // truncating browser-side avoids the network round-trip + saves
  // sending 1 MB+ over the DC just to be told no.
  let payload = text
  if (byteLen > CLIPBOARD_MAX_BYTES) {
    // Walk back from CLIPBOARD_MAX_BYTES to a codepoint boundary.
    const bytes = enc.encode(text)
    let end = CLIPBOARD_MAX_BYTES
    while (end > 0 && (bytes[end] & 0xc0) === 0x80) end -= 1
    payload = new TextDecoder('utf-8').decode(bytes.subarray(0, end))
    // eslint-disable-next-line no-console
    console.warn(
      `[rc] clipboard:write truncated from ${byteLen}B to ${end}B Ã¢ÂÂ agent rejects payloads above ${CLIPBOARD_MAX_BYTES}B`,
    )
  }
  const chunks = chunkClipboardText(payload)
  chunks.forEach((chunk, i) => {
    ch.send(
      JSON.stringify({
        t: 'clipboard:write-chunk',
        id,
        seq: i,
        text: chunk,
        last: i + 1 === chunks.length,
      }),
    )
  })
  return { envelopes: chunks.length, id }
}

// Ã¢ÂÂÃ¢ÂÂ Clipboard protocol v2: auto-sync helpers Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ

/** Hard cap on a PNG clipboard image on the wire, both directions.
 *  Mirrors the agent's `CLIPBOARD_IMAGE_MAX_BYTES`. */
export const CLIPBOARD_IMAGE_MAX_BYTES = 8 * 1024 * 1024
/** Binary frame size for browser Ã¢ÂÂ agent image sends. Matches the
 *  files-DC upload pump: webrtc-rs's inbound SCTP `max_message_size`
 *  is 65536 and 64 KiB frames sat exactly on the boundary, so 16 KiB.
 *  (The agent sends 64 KiB frames the other way Ã¢ÂÂ Chrome's inbound
 *  cap is 256 KiB.) */
export const CLIPBOARD_IMG_FRAME_BYTES = 16 * 1024
/** How long the deferred Ctrl+V waits for `clipboard:write-ack`
 *  before flushing anyway (agent wedged / reply lost). */
export const CLIPBOARD_ACK_TIMEOUT_MS = 1000
/** Focused-tab polling cadence for localÃ¢ÂÂremote text sync. Chrome has
 *  no `clipboardchange` event in stable, so change detection is
 *  focus/visibility triggers + this poll. Text-only Ã¢ÂÂ image reads are
 *  event-driven (focus/paste) to avoid hashing megabytes per tick. */
export const CLIPBOARD_SYNC_POLL_MS = 2000
/** Throttle between consecutive localÃ¢ÂÂremote sync attempts. */
const CLIPBOARD_SYNC_MIN_INTERVAL_MS = 300

/** Whether a session's EFFECTIVE grant (`rc:session.created.permissions`)
 *  lets clipboard content cross, in either direction. Exact tokens: a newer
 *  bit that merely contains the name is not CLIPBOARD. A grant the server did
 *  not report (pre-P3) is the request, which always asks for CLIPBOARD — the
 *  rule `inputGranted` follows for INPUT. */
export function grantAllowsClipboard(permissions: unknown): boolean {
  return (
    typeof permissions !== 'string' ||
    permissions.split('|').some((p) => p.trim() === 'CLIPBOARD')
  )
}

/** Close and forget the `clipboard` channel of a session whose grant does not
 *  allow it — FR-52's outsider gets `VIEW | INPUT` by default.
 *
 *  The channels are made in `connect()`, BEFORE the session request goes out,
 *  so this one exists before anyone knows the grant; but `rc:session.created`
 *  lands before the offer is even created, so it is dropped before it is ever
 *  negotiated. Every path that moves clipboard content needs it OPEN — the
 *  auto-sync that reads this machine's clipboard while the tab has focus, the
 *  subscription through which the device writes to it, the toolbar's
 *  send/get — so none of them can run. Before this, a session the device
 *  refused clipboard to still READ the controller's clipboard and sent every
 *  change to the device, which answered each with an error.
 *
 *  Returns whether a channel was dropped. */
export function dropClipboardChannel(channels: Record<string, RTCDataChannel>): boolean {
  const ch = channels.clipboard
  if (!ch) return false
  delete channels.clipboard
  try {
    ch.close()
  } catch {
    /* already closing */
  }
  return true
}

/** Canonicalize text for HASHING (CRLF / lone CR Ã¢ÂÂ LF). Never applied
 *  to outbound wire text Ã¢ÂÂ see [`sendClipboardWriteOverDc`]. Both
 *  sides of the echo gate hash this canonical form; the agent's
 *  `host_to_wire` produces the same bytes. */
export function normalizeClipboardText(text: string): string {
  if (!text.includes('\r')) return text
  return text.replace(/\r\n/g, '\n').replace(/\r/g, '\n')
}

/** FNV-1a 64 over raw bytes, as a 16-hex-digit string. Locks the same
 *  published vectors as the agent's `clipboard::fnv1a64` Ã¢ÂÂ echo
 *  suppression silently breaks if either side drifts. */
export function hashClipboardBytes(bytes: Uint8Array): string {
  let h = 0xcbf29ce484222325n
  const prime = 0x100000001b3n
  const mask = 0xffffffffffffffffn
  for (let i = 0; i < bytes.length; i++) {
    h ^= BigInt(bytes[i])
    h = (h * prime) & mask
  }
  return h.toString(16).padStart(16, '0')
}

/** Hash text content for the echo gate: canonicalize, then FNV-1a 64
 *  over the UTF-8 bytes. */
export function hashClipboardText(text: string): string {
  return hashClipboardBytes(new TextEncoder().encode(normalizeClipboardText(text)))
}

/** Echo-suppression gate for bidirectional auto-sync. Remembers the
 *  hash of the last content APPLIED locally (came from the remote)
 *  and the last content PUSHED to the remote; either one re-surfacing
 *  as a local "change" is an echo and must not be re-pushed Ã¢ÂÂ else
 *  remote-change Ã¢ÂÂ local-write Ã¢ÂÂ local-"change" Ã¢ÂÂ push-back loops
 *  forever. The agent holds the mirror-image gate (`SelfMarks`). */
export interface ClipboardEchoGate {
  recordApplied(hash: string): void
  recordPushed(hash: string): void
  /** True when the hash matches either remembered side. */
  knows(hash: string): boolean
  /** True when the content is new to the gate (and non-empty). */
  shouldPush(hash: string): boolean
  reset(): void
}

export function createClipboardEchoGate(): ClipboardEchoGate {
  // Small rings, not single slots: one clipboard state can surface as
  // SEVERAL hashes (v2.1 Ã¢ÂÂ an html payload is seen as its combined
  // html+text hash by rich reads and as its plain-text-alt hash by
  // readText polling; both must be remembered or the poll re-pushes
  // the alt forever). 4 is plenty: a state contributes Ã¢ÂÂ¤2 hashes and
  // anything older refers to overwritten clipboard content.
  const MAX = 4
  const applied: string[] = []
  const pushed: string[] = []
  const remember = (list: string[], hash: string) => {
    if (hash === '') return
    const i = list.indexOf(hash)
    if (i !== -1) list.splice(i, 1)
    list.push(hash)
    if (list.length > MAX) list.shift()
  }
  return {
    recordApplied(hash: string) {
      remember(applied, hash)
    },
    recordPushed(hash: string) {
      remember(pushed, hash)
    },
    knows(hash: string) {
      return hash !== '' && (applied.includes(hash) || pushed.includes(hash))
    },
    shouldPush(hash: string) {
      return hash !== '' && !applied.includes(hash) && !pushed.includes(hash)
    },
    reset() {
      applied.length = 0
      pushed.length = 0
    },
  }
}

/** Tracks which HID key codes and pointer buttons this viewer has told the
 *  host to PRESS but not yet RELEASE. When the window blurs mid-chord
 *  (alt-tab: AltLeft + Tab go down, focus leaves, the matching keyups never
 *  fire), the host was left with a physically held Alt — every following
 *  keystroke became an Alt-accelerator ("typing is dead" until some chord
 *  happened to release Alt; the field-reported alt+shift 'fix' worked only
 *  because it ends in a real AltLeft keyup). `releaseAll()` drains what the
 *  caller must send as up-events. Applies under Keyboard Lock too: with the
 *  lock active alt-tab is swallowed (no blur, tracker stays idle), and a
 *  blur that DOES fire under lock is an OS-level steal (secure desktop) —
 *  exactly a stuck-modifier scenario, so releasing is correct there as well.
 *  Pure and exported for vitest. */
export interface HeldInputTracker {
  key(code: number, down: boolean): void
  button(btn: string, down: boolean): void
  /** Held codes/buttons in press order; clears the tracker. */
  releaseAll(): { keys: number[]; buttons: string[] }
  /** FR-109 — held pointer buttons only, in press order; held keys stay.
   *  Leaving Pointer Lock lets go of the mouse, not of a chord. */
  releaseButtons(): string[]
  size(): number
}

export function createHeldInputTracker(): HeldInputTracker {
  const keys = new Set<number>()
  const buttons = new Set<string>()
  return {
    key(code: number, down: boolean) {
      if (down) keys.add(code)
      else keys.delete(code)
    },
    button(btn: string, down: boolean) {
      if (down) buttons.add(btn)
      else buttons.delete(btn)
    },
    releaseAll() {
      const out = { keys: [...keys], buttons: [...buttons] }
      keys.clear()
      buttons.clear()
      return out
    },
    releaseButtons() {
      const out = [...buttons]
      buttons.clear()
      return out
    },
    size() {
      return keys.size + buttons.size
    },
  }
}

/** Build the wire frames for one browser Ã¢ÂÂ agent image transfer:
 *  a `clipboard:img-begin` JSON header, Ã¢ÂÂ¤16 KiB binary PNG frames,
 *  and the `clipboard:img-end` trailer, all sharing one id. Exported
 *  for tests Ã¢ÂÂ the locked invariants are frame size Ã¢ÂÂ¤
 *  [`CLIPBOARD_IMG_FRAME_BYTES`], total bytes preserved, and the
 *  begin/end shapes the agent's `ClipboardIncoming` parses. */
export function buildClipboardImageFrames(
  png: Uint8Array<ArrayBuffer>,
  w: number,
  h: number,
): { id: string; begin: string; frames: Uint8Array<ArrayBuffer>[]; end: string } {
  const id =
    'cb-img-' +
    Date.now().toString(36) +
    '-' +
    Math.random().toString(36).slice(2, 10)
  const frames: Uint8Array<ArrayBuffer>[] = []
  for (let off = 0; off < png.length; off += CLIPBOARD_IMG_FRAME_BYTES) {
    frames.push(png.subarray(off, Math.min(off + CLIPBOARD_IMG_FRAME_BYTES, png.length)))
  }
  return {
    id,
    begin: JSON.stringify({
      t: 'clipboard:img-begin',
      id,
      w,
      h,
      bytes: png.length,
      format: 'png',
    }),
    frames,
    end: JSON.stringify({ t: 'clipboard:img-end', id }),
  }
}

/** v2.1 Ã¢ÂÂ cap on an html+text clipboard payload on the wire, both
 *  directions. Mirrors the agent's `CLIPBOARD_HTML_MAX_BYTES`. */
export const CLIPBOARD_HTML_MAX_BYTES = 4 * 1024 * 1024

/** v2.1 Ã¢ÂÂ combined echo-gate hash for html clipboard content: FNV over
 *  html bytes + 0x1F separator + canonical text bytes (mirrors the
 *  agent's `html_event_hash` construction; each side hashes its own
 *  reads, so only per-side self-consistency is load-bearing). */
export function hashClipboardHtml(html: string, text: string): string {
  const enc = new TextEncoder()
  const h = enc.encode(html)
  const t = enc.encode(normalizeClipboardText(text))
  const combined = new Uint8Array(h.length + 1 + t.length)
  combined.set(h, 0)
  combined[h.length] = 0x1f
  combined.set(t, h.length + 1)
  return hashClipboardBytes(combined)
}

/** v2.1 Ã¢ÂÂ build the wire frames for one browser Ã¢ÂÂ agent html transfer:
 *  `clipboard:html-begin` header, Ã¢ÂÂ¤16 KiB binary frames (html UTF-8
 *  bytes then the plain-text alt), `clipboard:html-end` trailer, one
 *  shared id. Returns null when the combined payload exceeds the cap.
 *  Exported for tests. */
export function buildClipboardHtmlFrames(
  html: string,
  text: string,
): { id: string; begin: string; frames: Uint8Array<ArrayBuffer>[]; end: string } | null {
  const enc = new TextEncoder()
  const htmlBytes = enc.encode(html)
  const textBytes = enc.encode(text)
  if (htmlBytes.length === 0 || htmlBytes.length + textBytes.length > CLIPBOARD_HTML_MAX_BYTES) {
    return null
  }
  const combined = new Uint8Array(htmlBytes.length + textBytes.length)
  combined.set(htmlBytes, 0)
  combined.set(textBytes, htmlBytes.length)
  const id =
    'cb-html-' +
    Date.now().toString(36) +
    '-' +
    Math.random().toString(36).slice(2, 10)
  const frames: Uint8Array<ArrayBuffer>[] = []
  for (let off = 0; off < combined.length; off += CLIPBOARD_IMG_FRAME_BYTES) {
    frames.push(combined.subarray(off, Math.min(off + CLIPBOARD_IMG_FRAME_BYTES, combined.length)))
  }
  return {
    id,
    begin: JSON.stringify({
      t: 'clipboard:html-begin',
      id,
      html_bytes: htmlBytes.length,
      text_bytes: textBytes.length,
    }),
    frames,
    end: JSON.stringify({ t: 'clipboard:html-end', id }),
  }
}

/** v2.2 Ã¢ÂÂ cap on a NATIVE clipboard payload (RTF + html + text) on
 *  the wire and through the bridge. Mirrors the agent's
 *  `CLIPBOARD_NATIVE_MAX_BYTES`. RTF hex-encodes embedded images at
 *  ~2ÃÂ their binary size, so real documents run to megabytes. */
export const CLIPBOARD_NATIVE_MAX_BYTES = 16 * 1024 * 1024

/** v2.2 Ã¢ÂÂ the loopback clipboard bridge on the VIEWER machine's own
 *  agent (same fixed port as the TURN probe; the `/rc-clipboard`
 *  routes are the bridge half). Only an enrolled local agent with the
 *  clipboard feature answers; everything else times out Ã¢ÂÂ graceful
 *  fallback to the browser-reachable lanes. */
export function clipboardBridgeUrl(port: number): string {
  return `http://127.0.0.1:${port}/rc-clipboard`
}

/** Uint8Array Ã¢ÂÂ base64 (chunked Ã¢ÂÂ a spread over megabytes of bytes
 *  blows the arg-count/stack limit). Inverse of [`base64ToBytes`].
 *  Exported for tests. */
export function bytesToBase64(bytes: Uint8Array): string {
  let bin = ''
  const CHUNK = 0x8000
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode(...bytes.subarray(i, Math.min(i + CHUNK, bytes.length)))
  }
  return btoa(bin)
}

/** v2.2 Ã¢ÂÂ validate an untrusted bridge GET body into the native
 *  payload shape. Pure + exported for tests. */
export function parseNativeClipPayload(
  raw: unknown,
): { rtf: Uint8Array<ArrayBuffer>; html: string; text: string } | null {
  if (raw === null || typeof raw !== 'object') return null
  const o = raw as Record<string, unknown>
  if (typeof o.rtf !== 'string' || o.rtf.length === 0) return null
  let rtf: Uint8Array<ArrayBuffer>
  try {
    rtf = base64ToBytes(o.rtf) as Uint8Array<ArrayBuffer>
  } catch {
    return null
  }
  const html = typeof o.html === 'string' ? o.html : ''
  const text = typeof o.text === 'string' ? o.text : ''
  if (rtf.length === 0 || rtf.length + html.length + text.length > CLIPBOARD_NATIVE_MAX_BYTES) {
    return null
  }
  return { rtf, html, text }
}

/** v2.2 Ã¢ÂÂ build the wire frames for one browser Ã¢ÂÂ agent NATIVE
 *  transfer: `clipboard:native-begin` header, Ã¢ÂÂ¤16 KiB binary frames
 *  (rtf ++ html UTF-8 ++ text UTF-8), `clipboard:native-end` trailer.
 *  Null when the combined payload exceeds the cap. Exported for
 *  tests. */
export function buildClipboardNativeFrames(
  rtf: Uint8Array<ArrayBuffer>,
  html: string,
  text: string,
): { id: string; begin: string; frames: Uint8Array<ArrayBuffer>[]; end: string } | null {
  const enc = new TextEncoder()
  const htmlBytes = enc.encode(html)
  const textBytes = enc.encode(text)
  const total = rtf.length + htmlBytes.length + textBytes.length
  if (rtf.length === 0 || total > CLIPBOARD_NATIVE_MAX_BYTES) return null
  const combined = new Uint8Array(total)
  combined.set(rtf, 0)
  combined.set(htmlBytes, rtf.length)
  combined.set(textBytes, rtf.length + htmlBytes.length)
  const id =
    'cb-native-' +
    Date.now().toString(36) +
    '-' +
    Math.random().toString(36).slice(2, 10)
  const frames: Uint8Array<ArrayBuffer>[] = []
  for (let off = 0; off < combined.length; off += CLIPBOARD_IMG_FRAME_BYTES) {
    frames.push(combined.subarray(off, Math.min(off + CLIPBOARD_IMG_FRAME_BYTES, combined.length)))
  }
  return {
    id,
    begin: JSON.stringify({
      t: 'clipboard:native-begin',
      id,
      rtf_bytes: rtf.length,
      html_bytes: htmlBytes.length,
      text_bytes: textBytes.length,
    }),
    frames,
    end: JSON.stringify({ t: 'clipboard:native-end', id }),
  }
}

/** Clipboard auto-sync opt-out. Default ON Ã¢ÂÂ only an explicit '0'
 *  disables (the feature is the whole point of clipboard v2; users
 *  who want the old button-driven flow flip the Settings toggle). */
const CLIPBOARD_AUTO_SYNC_STORAGE_KEY = 'roomler-rc-clipboard-auto'

function readStoredClipboardAutoSync(): boolean {
  try {
    return globalThis.localStorage?.getItem(CLIPBOARD_AUTO_SYNC_STORAGE_KEY) !== '0'
  } catch {
    return true
  }
}

function persistClipboardAutoSync(on: boolean) {
  try {
    globalThis.localStorage?.setItem(CLIPBOARD_AUTO_SYNC_STORAGE_KEY, on ? '1' : '0')
  } catch {
    /* best-effort */
  }
}

/** Chrome 148+ regressed `RTCRtpScriptTransform`: the transform attaches,
 *  `configure()` reports success, but encoded frames are never delivered
 *  to the transformer's readable AND the default `<video>` path stays
 *  starved too (Chrome holds frames on neither pipe). Field repro on
 *  Chrome 148 (Chromium 148): worker's 3 s watchdog fires + auto-fallback
 *  to `<video>` doesn't render either, viewer stays blank 1-2 min.
 *
 *  We pre-empt the broken activation: when this returns `true`,
 *  `installWebCodecsTransform()` returns false immediately and the
 *  default `<video>` element renders normally.
 *
 *  Exported for tests. Tracked upstream Ã¢ÂÂ once a Chromium fix lands
 *  and ships, bump the upper bound or remove the gate entirely. */
export function isChromeWithBrokenScriptTransform(): boolean {
  const nav = globalThis.navigator as
    | (Navigator & { userAgentData?: { brands?: { brand: string; version: string }[] } })
    | undefined
  if (!nav) return false
  const brands = nav.userAgentData?.brands
  if (brands && brands.length) {
    for (const b of brands) {
      if (b.brand === 'Chromium' || b.brand === 'Google Chrome') {
        const v = parseInt(b.version, 10)
        if (Number.isFinite(v) && v >= 148) return true
      }
    }
    return false
  }
  const ua = nav.userAgent ?? ''
  const m = /Chrome\/(\d+)/.exec(ua)
  if (m) {
    const v = parseInt(m[1], 10)
    if (Number.isFinite(v) && v >= 148) return true
  }
  return false
}

/** Wire-format constants for the `video-bytes` DataChannel. The label
 *  must match the agent's `on_data_channel` arm at peer.rs:494. The
 *  channel is reliable + ordered because (a) SCTP is doing the
 *  reassembly anyway and (b) dropping a P-frame would force the
 *  worker to wait for the next IDR Ã¢ÂÂ far worse than a few ms of
 *  retransmit latency. */
export const VP9_444_DC_LABEL = 'video-bytes'

/**
 * FR-17 stage B — how the `video-bytes` channel is opened.
 *
 * Historically `{ ordered: true }`, justified as "SCTP is doing the
 * reassembly anyway, and dropping a P-frame is far worse than a few ms
 * of retransmit latency". True on a LAN; falsified on a 90-210 ms relay,
 * where one lost chunk head-of-line-blocks everything behind it and the
 * backlog has no bound — measured `send_wait_max` 10,263 ms on an agent
 * whose encoder was idle at 8-12 ms/frame.
 *
 * `maxRetransmits: 0` rather than a bounded retransmit is deliberate and
 * is coupled to the RECEIVER. Stage A's assembler treats a chunk-index
 * jump as an unrecoverable gap: it drops the frame and asks for an IDR.
 * That is exactly right when a lost chunk never arrives, and WRONG the
 * moment retransmits are allowed — a chunk that arrives one RTT late
 * would be discarded as a gap, converting a recoverable frame into a
 * lost one plus a keyframe request. Testing 1-2 retransmits (stage C)
 * therefore requires a reorder buffer in the worker first; it is not a
 * number that can be turned up on its own.
 *
 * ⚠️ Unordered is only legal WITH framing. An unframed stream is a bare
 * byte sequence whose reassembly depends entirely on arrival order, so
 * delivering it out of order does not degrade the picture — it produces
 * garbage the decoder reports as corruption. This function is the single
 * place that pairing is enforced, so the two can never be set
 * independently by a caller who has not thought about it.
 */
export function videoDcOptions(
  chunkFraming: boolean,
  unordered: boolean,
): RTCDataChannelInit {
  if (!chunkFraming || !unordered) return { ordered: true }
  return { ordered: false, maxRetransmits: 0 }
}

/** Field opt-in for stage B, mirroring `storedDecodePref`'s A/B knob.
 *  Default OFF: this changes the delivery guarantee of the video path,
 *  and the FR's own acceptance bar is a measured relay-pair improvement,
 *  not a plausible argument. Pure + exported for tests. */
export function storedUnorderedVideo(): boolean {
  try {
    return globalThis.localStorage?.getItem('roomler-rc-unordered-video') === '1'
  } catch {
    /* privacy mode - default off */
    return false
  }
}

/** Short codec name to pass into `new RTCRtpScriptTransform(worker,
 *  { codec })`. Reads the first negotiated codec off
 *  `RTCRtpReceiver.getParameters().codecs` and maps it back to our
 *  protocol's short name. Defaults to 'h264' when nothing has
 *  negotiated yet or the mime type is unrecognised. Exported for tests. */
export function shortCodecFromReceiver(
  receiver: Pick<RTCRtpReceiver, 'getParameters'> | null | undefined,
): RcPreferredCodec {
  if (!receiver) return 'h264'
  let mime = ''
  try {
    const params = receiver.getParameters()
    const codecs = (params as { codecs?: Array<{ mimeType?: string }> }).codecs
    if (codecs && codecs.length > 0 && codecs[0]?.mimeType) {
      mime = codecs[0].mimeType.toLowerCase()
    }
  } catch {
    return 'h264'
  }
  if (mime.includes('h265') || mime.includes('hevc')) return 'h265'
  if (mime.includes('av1')) return 'av1'
  if (mime.includes('vp9')) return 'vp9'
  if (mime.includes('vp8')) return 'vp8'
  return 'h264'
}

/** Inspect the negotiated codec by reading the remote SDP answer.
 *  More reliable than `RTCRtpReceiver.getParameters()` at
 *  `pc.ontrack` time Ã¢ÂÂ Chrome populates that lazily and it's often
 *  empty on first read, which silently defaulted us to H.264 even
 *  when HEVC was negotiated. The SDP, in contrast, is fully settled
 *  by the time ontrack fires (it fires as a consequence of SRD).
 *
 *  Parses the first video m-line's first payload type, then finds
 *  the matching a=rtpmap entry. Returns `null` when nothing could
 *  be parsed Ã¢ÂÂ the caller falls back to the receiver-based detector.
 *  Exported for tests so the parse rule is locked. */
export function codecFromSdp(sdp: string | null | undefined): RcPreferredCodec | null {
  if (!sdp) return null
  const lines = sdp.split(/\r?\n/)
  let videoPt: string | null = null
  for (const line of lines) {
    if (line.startsWith('m=video')) {
      // m=video <port> <proto> <pt1> <pt2> ...
      const parts = line.split(' ')
      videoPt = parts[3] ?? null
      break
    }
  }
  if (!videoPt) return null
  const rtpmapPrefix = `a=rtpmap:${videoPt} `
  for (const line of lines) {
    if (!line.startsWith(rtpmapPrefix)) continue
    // a=rtpmap:<pt> <codec>/<rate>[/<params>]
    const rest = line.slice(rtpmapPrefix.length).trim()
    const codec = (rest.split('/')[0] ?? '').toLowerCase()
    switch (codec) {
      case 'h264':
        return 'h264'
      case 'h265':
      case 'hevc':
        return 'h265'
      case 'av1':
      case 'av1x':
        return 'av1'
      case 'vp9':
        return 'vp9'
      case 'vp8':
        return 'vp8'
      default:
        return null
    }
  }
  return null
}

/** Given the full set of browser-supported codecs and an optional
 *  override, return the list the agent should see in `browser_caps`.
 *  When `preferred` is set, only that codec (plus H.264 as a safety
 *  fallback if the browser has it) is forwarded Ã¢ÂÂ so the agent's
 *  `pick_best_codec` can only land on the preferred one, or fall back
 *  to H.264 if the agent itself lacks support. Exported for tests. */
export function filterCapsByPreference(
  caps: string[],
  preferred: RcPreferredCodec | null,
): string[] {
  if (preferred == null) return caps
  const out = caps.filter((c) => c === preferred)
  // Always keep H.264 as a parachute Ã¢ÂÂ if the user forces AV1 but the
  // agent on this host can't encode AV1, we want a working session
  // rather than a failed one.
  if (preferred !== 'h264' && caps.includes('h264')) {
    out.push('h264')
  }
  return out
}

/**
 * rc.19: optional argument carrying the current agent's reactive
 * record so the composable can read `capabilities.files` (file-DC
 * v3 cap list including `"resume"`) without a separate Pinia
 * dependency. `RemoteControl.vue` passes its `agent: Ref<Agent>`;
 * tests + older callers can omit it and `supportsResume` falls
 * back to false (legacy rc.18 fail-fast upload semantics).
 */
export function useRemoteControl(
  agent?: Ref<Pick<Agent, 'id' | 'os' | 'capabilities' | 'peer_auth_key'> | null>,
  opts?: {
    external?: boolean
    shareGrantId?: () => string | null
    /**
     * FR-100 P2a — the signed-in user's id, which the device's signature over
     * its answer names. Without it this page never asks for one.
     */
    userId?: () => string | null
  },
) {
  const ws = useWsStore()
  const phase = ref<RcPhase>('idle')

  // FR-52 P4e — this instance drives an EXTERNAL session (the /connect page).
  // FIXED for the instance's life, and deliberately separate from the login
  // it holds: with no login in hand an external viewer refuses to offer or to
  // accept an answer — it never falls back to an unsealed, ordinary session.
  // The browser-side twin of the device remembering an ended external session.
  const externalMode = opts?.external === true
  const sharedMode = !!opts?.shareGrantId
  let externalAuth: ExternalSessionAuth | null = null
  function forgetExternalAuth() {
    externalAuth?.appKey.fill(0)
    externalAuth = null
  }

  // FR-100 P2a — the device's signature over its answer. `peerAuthPlan` is
  // decided when the request goes out, for the agent THAT request names (a
  // device switch can race it); `peerAuthAsked` is what the offer then asked,
  // so the answer is judged against exactly that. Both live for one attempt.
  let peerAuthPlan: { agentId: string; userId: string } | null = null
  let peerAuthAsked: {
    agentId: string
    userId: string
    sessionId: string
    nonce: string
    offerFingerprint: string
  } | null = null
  /**
   * What this page concluded about the last answer it asked a device to sign:
   * the verdict, whose (user, device) pin it concerns, and both keys'
   * fingerprints. Kept across a failed attempt on purpose (the error view
   * offers "trust the new key" from it); cleared when the next offer goes out.
   */
  const peerAuth = ref<PeerAuthJudgement | null>(null)
  let peerAuthPinStore: PeerAuthPins | null = null
  const peerAuthPins = (): PeerAuthPins => (peerAuthPinStore ??= storagePins(browserStorage()))
  // FR-100 P2b — this browser's own key for the attempt's user, loading from
  // the moment the request goes out so the offer never waits on it. `null`
  // when this browser cannot keep one: the offer then asks without signing.
  let peerAuthKey: Promise<CryptoKeyPair | null> | null = null

  /**
   * FR-100 P2a — ask the device this request names to sign its answer? Only
   * when the page's agent IS that device (its row carries what it signs
   * with), the user is known (the signature names them), this page can verify
   * at all, and the shared rules hold (`shouldAskPeerAuth`).
   */
  function planPeerAuth(agentId: string): { agentId: string; userId: string } | null {
    const row = agent?.value?.id === agentId ? agent.value : null
    const userId = opts?.userId?.() ?? null
    if (!row || !userId || !peerAuthCanVerify()) return null
    const ask = shouldAskPeerAuth({
      external: externalMode,
      rpc: row.capabilities?.rpc,
      peerAuthKey: row.peer_auth_key,
      disabled: peerAuthAskDisabled(browserStorage()),
    })
    return ask ? { agentId, userId } : null
  }

  /**
   * FR-100 P2a — the person chose to trust the device's NEW key after a
   * `key-changed` refusal: pin it, so the next attempt proceeds. It trusts
   * that key and nothing else: the next answer must still carry a signature
   * that verifies under it, over its own session.
   */
  function trustPeerAuthKey(): boolean {
    if (!trustChangedKey(peerAuth.value, peerAuthPins())) return false
    peerAuth.value = null
    return true
  }

  /**
   * rc.19: resume opt-in gate. True only when the agent has
   * advertised `"resume"` in `capabilities.files`. Browsers that
   * see no resume cap (rc.18 agents, or rc.19 agents with browse
   * disabled) keep the legacy direct-pump-with-fail-fast path.
   */
  const supportsResume: ComputedRef<boolean> = computed(() => {
    const files = agent?.value?.capabilities?.files
    return Array.isArray(files) && files.includes('resume')
  })
  /** Clipboard protocol-v2 capability gates (see AgentCaps.clipboard).
   *  Empty on old agents Ã¢ÂÂ v1 button-driven text-only flow. */
  const clipboardCaps: ComputedRef<string[]> = computed(() => {
    const c = agent?.value?.capabilities?.clipboard
    return Array.isArray(c) ? c : []
  })

  /** FR-13 (#789): the host is a Mac — its primary modifier is Cmd. */
  const hostIsMac: ComputedRef<boolean> = computed(() => agent?.value?.os === 'macos')
  /** FR-13: translate the viewer's Ctrl to the mac host's Cmd (default ON
   *  for mac hosts; the toolbar toggle restores literal Ctrl for terminal
   *  work — SIGINT et al). No effect on non-mac hosts. */
  const ctrlAsCmd = ref(true)
  // Release-consistency state for translateModifierForHost — keyed on what
  // was actually sent, so a mid-hold toggle flip can't strand a held Cmd.
  const ctrlSubState = { ctrlHeldAsCmd: false }
  const supportsClipboardAck = computed(() => clipboardCaps.value.includes('ack'))
  const supportsClipboardEvents = computed(() => clipboardCaps.value.includes('events'))
  const supportsClipboardImages = computed(() => clipboardCaps.value.includes('images'))
  const supportsClipboardHtml = computed(() => clipboardCaps.value.includes('html'))
  /** v2.2 Ã¢ÂÂ the REMOTE agent can read/write RTF (embedded images).
   *  Needed for the full-fidelity path, but only usable when the
   *  VIEWER also has a local bridge (see `localClipboardBridge`). */
  const supportsClipboardNative = computed(() => clipboardCaps.value.includes('native'))
  /** v2.2 Ã¢ÂÂ whether THIS machine's local agent exposes the loopback
   *  clipboard bridge. Probed once per connect (loopback is never
   *  firewalled); null until probed, then true/false. When true, the
   *  viewer reads native RTF locally and ships it, and writes remote
   *  RTF back to the local clipboard Ã¢ÂÂ the WordÃ¢ÂÂWord fidelity path. */
  const localClipboardBridge = ref<boolean | null>(null)
  /** The discovery port the local Windows-native bridge answered on
   *  (a host with several agents binds distinct ports from the
   *  candidate range). Null until the probe finds one. */
  const localClipboardBridgePort = ref<number | null>(null)
  const error = ref<string | null>(null)
  const sessionId = ref<string | null>(null)
  /**
   * Auto-reconnect state. `lastConnectArgs` remembers the user's
   * original `connect(agentId, permissions)` call so a reconnect can
   * re-establish the same session against the same agent without
   * the operator hitting Connect again. `reconnectAttempt` is exposed
   * so the viewer can render "Reconnecting (3/6)..." in the toolbar
   * Ã¢ÂÂ silent retries are confusing when an operator is watching the
   * stream go dark. `reconnectTimer` is private; managed by
   * scheduleReconnect / cancelReconnect.
   */
  let lastConnectArgs: { agentId: string; permissions: string; orgId?: string } | null = null
  /** #1631 - the late-create terminator over the module-level entries, bound
   *  to this store's socket (see `createAbandonedRequestRegistry`). */
  const abandonedRequests = createAbandonedRequestRegistry(
    ws,
    RC_LATE_CREATE_WINDOW_MS,
    ABANDONED_REQUESTS,
  )
  /** #1631 - the generation of the `connect()` in flight. Every teardown
   *  bumps it, so a pre-flight that resumes after its composable was torn
   *  down (disconnect(), failWith(), a scoped rc:terminate, the ladder)
   *  finds `gen !== connectGen` and stops before it creates a peer or sends
   *  a request on behalf of a state that no longer exists. */
  let connectGen = 0
  /** #1631 - an `rc:session.request` went out and nothing has answered it
   *  yet: neither a create (adopted -> false) nor a failing rc:error
   *  (failWith -> false). Deliberately NOT cleared by teardown(): the
   *  ladder's teardown after a request timeout does not answer the request,
   *  and its late create is exactly what `abandonedRequests` exists to
   *  release. Consumed by disconnect(). */
  let requestSent = false
  const reconnectAttempt = ref(0)
  /**
   * FR-27 P10 - who ended the last session when it was not this viewer:
   * `'host'` after a `host_disconnect` (the person at the device clicked
   * Disconnect on their screen). The view renders it as a notice with an
   * explicit Reconnect; cleared by the next user-initiated connect().
   */
  const endedBy = ref<'host' | null>(null)
  /** FR-22 - ms from `rc:session.request` to the first painted frame on
   *  the attempt that succeeded. Null until one does. Exposed so the
   *  viewer HUD and the field can read a NUMBER instead of an anecdote:
   *  "sometimes 10-15 s" is not something a fix can be measured against. */
  const lastTtffMs = ref<number | null>(null)
  // FR-22 - the operator-facing half of the connect timing. The snackbar
  // store is a module singleton, so this is the same surface every other
  // part of the app already writes to.
  const { showSnackbar } = useSnackbar()
  /** Last time a STALL snackbar was shown, so a flapping path cannot
   *  bury its own message under repeats. */
  let lastStallSnackAtMs = -Infinity
  /** FR-22 - has ANY attempt in this connect cycle already painted a
   *  frame? Distinguishes "the session dropped and came back" from "the
   *  request was never answered", which the attempt counter alone cannot.
   *  Cleared by a fresh user-initiated connect, not by a retry. */
  let sessionEverPainted = false

  /** FR-22 - per-attempt connect timing. Null outside an attempt; a
   *  retry replaces it wholesale so the ladder's second attempt cannot
   *  overwrite the first one's marks and make a two-attempt connect read
   *  as one fast one. */
  let connectTiming: RcConnectRecorder | null = null
  /** FR-22 part 4 - the console line, persisted. One POST per finished
   *  attempt into `agent_logs` (source `browser`, target `rc.connect`) so
   *  a stall's phase outlives the tab. Best effort: it can never throw,
   *  retry, or surface anything to the operator. */
  const connectTimingUploader = createConnectTimingUploader()
  /** FR-22 part 4 - the `rc:error` code that ended the live attempt, if
   *  one did. In the marks a refusal and a silence stop at the same missing
   *  step; this is what tells them apart in the record. Cleared per attempt. */
  let attemptErrorCode: string | null = null

  /** Emit the current attempt's timing once, then release it. `reason`
   *  distinguishes the success line from the abandonment line, because
   *  an INCOMPLETE record is the diagnostically valuable one - the
   *  missing mark names the step that never completed.
   *
   *  `retried` (FR-22 part 4): the ladder advanced past a live attempt for
   *  a reason other than a phase bound - a transient `rc:error` it rides,
   *  an ICE failure, dead air before the first frame. Such an attempt used
   *  to be replaced by the next `beginAttempt()` with no line and no
   *  record; it is persisted like the others but, like `closed`, never
   *  reaches the snackbar, whose verdict vocabulary is about stalls. */
  function logConnectTiming(reason: 'first-frame' | 'abandoned' | 'closed' | 'retried') {
    const t = connectTiming
    if (!t) return
    // A successful attempt reports exactly once, at first paint. Later
    // teardown must not re-log it as if it were a second connect.
    if (reason !== 'first-frame' && t.done()) {
      connectTiming = null
      disarmVisibilityTiming()
      return
    }
    connectTiming = null
    disarmVisibilityTiming()
    const snap = t.snapshot()
    const line = formatConnectTiming(snap)
    if (reason === 'first-frame') {
      lastTtffMs.value = snap.marks.first_frame ?? null
      sessionEverPainted = true
      console.info('[rc] connect', line)
    } else {
      console.warn('[rc] connect', reason, line)
    }
    // FR-22 part 4 - persist what was just printed. Filed under the PAGE's
    // org (membership is what let the operator open this page; the route
    // refuses any other), with the device's org alongside when it differs
    // (FR-52 cross-org). `sessionId` is still set here on every path that
    // reaches this line - `scheduleReconnect` reports before it clears it,
    // and `disconnect`/`failWith` clear `lastConnectArgs` only afterwards -
    // and its ABSENCE is the record of a stall in `requesting`.
    const outcome: RcConnectOutcome = reason === 'first-frame' ? 'first_frame' : reason
    connectTimingUploader.send(snap, {
      tenantId: expectedOrgTid(null, location.pathname) ?? lastConnectArgs?.orgId ?? null,
      agentOrgId: lastConnectArgs?.orgId ?? null,
      agentId: lastConnectArgs?.agentId ?? null,
      sessionId: sessionId.value,
      outcome,
      errorCode: attemptErrorCode,
    })
    // FR-22 - tell the OPERATOR, not just the console. A devtools line
    // is invisible during exactly the sessions this exists to explain,
    // and "it was slow again" is not a report anyone can act on. The
    // verdict names which wait dominated in plain words, so a slow
    // connect becomes a fact someone can pass on without opening
    // devtools - which is what turns this from telemetry into the route
    // to the root cause.
    //
    // Cancellation is excluded on purpose: the operator pressed the
    // button, so telling them their own action interrupted a connect is
    // noise, not information. So is a ladder advance the operator was
    // already told about by the error path that caused it.
    if (reason === 'closed' || reason === 'retried') return
    const verdict = describeConnectTiming(snap)
    if (!verdict.notable) return
    // Throttle the STALL warnings only. A flapping path abandons an
    // attempt every few seconds, and one snackbar per abandonment is
    // spam that buries the message it is trying to deliver. The
    // resolution ("connected after N failed attempts") is never
    // throttled: suppressing the line that says it finally worked, while
    // having shown the one that said it was failing, would leave the
    // operator with a warning and no ending.
    const nowMs = typeof performance !== 'undefined' ? performance.now() : Date.now()
    if (reason === 'abandoned') {
      if (nowMs - lastStallSnackAtMs < STALL_SNACK_MIN_GAP_MS) return
      lastStallSnackAtMs = nowMs
    }
    showSnackbar(verdict.text, verdict.color, 8000)
  }

  /** Mark a connect milestone on the live attempt, if any. A no-op
   *  outside an attempt, so callers never have to guard. */
  function markConnect(name: RcConnectMark) {
    connectTiming?.mark(name)
  }
  /** FR-22 part 4 - a tab that goes hidden mid-attempt taints that
   *  attempt's paint timing (standing rule: no rAF, no valid `first_frame`).
   *  The recorder starts from the visibility at `beginAttempt` and this
   *  listener catches a change during the attempt. Armed with the recorder,
   *  released with it, and on unmount. */
  function onVisibilityTiming() {
    if (globalThis.document.visibilityState === 'hidden') connectTiming?.noteHidden()
  }
  let visibilityTimingArmed = false
  function armVisibilityTiming() {
    if (visibilityTimingArmed || typeof document === 'undefined') return
    visibilityTimingArmed = true
    document.addEventListener('visibilitychange', onVisibilityTiming)
  }
  function disarmVisibilityTiming() {
    if (!visibilityTimingArmed) return
    visibilityTimingArmed = false
    document.removeEventListener('visibilitychange', onVisibilityTiming)
  }
  /** Consecutive sessions that connected but never delivered a frame —
   *  drives `deadAirDelayMs`. Cleared the moment media actually moves. */
  const deadAirStreak = ref(0)
  /** Has media EVER advanced on the current session? The media watchdog
   *  owns this; it is what "the connection is genuinely working" means,
   *  as opposed to merely having reached `connected`. */
  let mediaEverFlowed = false
  // PR-1 rehome: consecutive `agent_on_other_pod` streak. Each one
  // re-keys + redials the WS (bounded by RC_REHOME_MAX_REDIALS, then
  // the infinite ladder carries on without socket cycling). Reset by
  // cancelReconnect (user action / successful connect).
  let rehomeStreak = 0
  // Non-terminal, user-facing progress notice (e.g. "rerouting...").
  // Shown by the view alongside the spinner; never blocks retries.
  const notice = ref<string | null>(null)
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null

  // Ã¢ÂÂÃ¢ÂÂ S3 viewer resilience state Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ
  /** Sub-connected health; null = fully healthy (or not connected). */
  const degraded = ref<RcDegradedReason | null>(null)
  /** Armed when pc hits 'disconnected'; fires scheduleReconnect if it
   *  hasn't recovered within RC_PC_DISCONNECTED_GRACE_MS. */
  let pcDisconnectedTimer: ReturnType<typeof setTimeout> | null = null
  /** Abandons a 'requesting'/'negotiating' attempt that hangs. */
  let signalingTimer: ReturnType<typeof setTimeout> | null = null
  /** 1 Hz media-progress watchdog (runs only while connected). */
  let watchdogTimer: ReturnType<typeof setInterval> | null = null
  let stallTicks = 0
  let lastMediaProgress = { rtpBytes: 0, vp9Frames: 0, hevcFrames: 0 }

  function clearPcDisconnectedTimer() {
    if (pcDisconnectedTimer !== null) {
      clearTimeout(pcDisconnectedTimer)
      pcDisconnectedTimer = null
    }
  }

  function clearSignalingTimeout() {
    if (signalingTimer !== null) {
      clearTimeout(signalingTimer)
      signalingTimer = null
    }
  }

  /** (Re-)arm the signalling stuck-detector for the CURRENT phase.
   *  FR-22 - the bound is per-phase (`signalingTimeoutFor`): 'requesting'
   *  waits on ONE server hop, 'negotiating' waits on ICE, and guarding
   *  the first with the second's number is what made a lost request cost
   *  15 s. NOT 'awaiting_consent' - the server owns that timeout.
   *  Call AFTER assigning `phase.value`, so the bound matches the wait. */
  function armSignalingTimeout() {
    clearSignalingTimeout()
    const stuckIn = phase.value
    const bound = signalingTimeoutFor(stuckIn)
    if (bound === null) return
    signalingTimer = setTimeout(() => {
      signalingTimer = null
      // Re-read the phase: it may have advanced since we armed, in which
      // case a later arm owns that wait and this timer is stale.
      if (phase.value !== stuckIn) return
      console.warn('[rc] signalling stuck in', stuckIn, 'for', bound, 'ms - retrying')
      // FR-22 - an abandoned attempt is the informative one: its MISSING
      // mark names the exact step that never completed, which is what
      // distinguishes a half-open agent WS from a cross-pod split.
      logConnectTiming('abandoned')
      if (lastConnectArgs) scheduleReconnect()
      else failWith('connection timed out')
    }, bound)
  }

  function stopMediaWatchdog() {
    if (watchdogTimer !== null) {
      clearInterval(watchdogTimer)
      watchdogTimer = null
    }
    stallTicks = 0
    lastMediaProgress = { rtpBytes: 0, vp9Frames: 0, hevcFrames: 0 }
    degraded.value = null
  }

  /**
   * Detect the silent-wedge failure mode: pc still reports
   * 'connected' but no media has advanced for seconds (agent-side
   * pipeline death, WS displacement with a zombie peer, one-way
   * network failure). Progress = ANY of: inbound RTP bytes (classic
   * <video> + WebCodecs paths), VP9-444 DC frames, HEVC DC frames.
   * Static desktops legitimately go flat Ã¢ÂÂ probe with rc:keyframe
   * first (see nextStallAction) and only reconnect when the probe
   * goes unanswered.
   */
  function startMediaWatchdog() {
    if (watchdogTimer !== null) return
    stallTicks = 0
    lastMediaProgress = { rtpBytes: statsPrevBytes, vp9Frames: 0, hevcFrames: 0 }
    // FR-93 P5f — when the interval this tick counts began (see advanceEndsWait).
    let tickFromMs = Date.now()
    watchdogTimer = setInterval(() => {
      const intervalFromMs = tickFromMs
      tickFromMs = Date.now()
      if (phase.value !== 'connected') return
      const cur = {
        rtpBytes: statsPrevBytes,
        vp9Frames: vp9_444FramesDecoded.value,
        hevcFrames: hevcFramesDecoded.value,
      }
      // No hasMedia special-case: a session that reached 'connected'
      // but never produced a track/frame is just as dead as one that
      // stalled mid-flight Ã¢ÂÂ both count ticks toward probe/reconnect.
      const advanced =
        cur.rtpBytes > lastMediaProgress.rtpBytes
        || cur.vp9Frames > lastMediaProgress.vp9Frames
        || cur.hevcFrames > lastMediaProgress.hevcFrames
      lastMediaProgress = cur
      // Media actually moving is the ONLY proof this pair has a working
      // path — reaching `connected` is not. Reset the ladders here rather
      // than on the connection state, so a session that connects and then
      // sits in dead air keeps climbing instead of restarting at 250 ms.
      if (advanced && !mediaEverFlowed) {
        mediaEverFlowed = true
        deadAirStreak.value = 0
        reconnectAttempt.value = 0
      }
      // FR-93 P2d-2 — the first frame ends any wait the agent announced. P5f —
      // the first frame after the notice: one counted with it may predate it.
      if (
        mediaWaiting.value !== null
        && advanceEndsWait(advanced, intervalFromMs, mediaWaitingSinceMs)
      ) mediaWaiting.value = null
      // FR-93 — an agent that said it cannot capture is believed: no probe,
      // no re-create, the reason stays on the screen. P2d-2 — and so is one
      // that said it waits for the person at the screen, until the dialog's
      // deadline: a re-created session would only hand the person's answer to
      // a session this viewer no longer shows.
      stallTicks = nextStallTicks(
        stallTicks,
        advanced,
        mediaUnavailable.value !== null || agentIsWaiting(mediaWaiting.value, Date.now()),
      )
      degraded.value = classifyDegraded({
        pcState: pc?.connectionState ?? null,
        wsConnected: ws.status === 'connected',
        stallTicks,
      })
      const action = nextStallAction(stallTicks)
      if (action === 'probe') {
        console.info('[rc] media stalled', stallTicks, 's Ã¢ÂÂ probing with rc:keyframe')
        requestKeyframe()
      } else if (action === 'reconnect') {
        console.warn('[rc] media stalled', stallTicks, 's, keyframe probe unanswered Ã¢ÂÂ re-creating session')
        scheduleReconnect()
      }
    }, RC_WATCHDOG_TICK_MS)
  }
  /**
   * Whether the agent has signalled (over the `control` data channel)
   * that the host's input desktop has transitioned to `winsta0\Winlogon`
   * (lock screen / UAC consent / secure attention sequence). The
   * lock-overlay frame on the video track already shows the visual
   * state; this flag is a separate machine-readable signal so the
   * viewer can render a toolbar badge that's visible even when the
   * video element is scrolled out of view.
   *
   * Stays false on agents older than 0.2.2 (which never emit the
   * message); the flag remains coherent because falling back to
   * always-false matches the pre-overlay behaviour for those agents.
   */
  const hostLocked = ref(false)
  /** FR-97 P3b — what the host says its lock screen does with input: a Linux
   *  lock screen TAKES it (captured and typed into like any other screen), so
   *  the chip must not say input is suppressed; a Mac's is `unknown` (P2d-1).
   *  `suppressed` from Windows and older agents. */
  const hostLockedInput = ref<HostLockedInput>('suppressed')
  /** FR-92 — the device's keep-busy state; `null` until an agent that has
   *  the feature says something (older agents never do). */
  const keepBusy = ref<KeepBusyState | null>(null)
  /** FR-108 — the device's answer to this session's latest display-match
   *  request; `null` until it answers (agents before FR-108 never do). */
  const displayMatchState = ref<DisplayMatchState | null>(null)
  /** rc.227 Ã¢ÂÂ the remote host's keyboard-layout state, pushed by
   *  Windows agents as `rc:layout` over the control DC (on change;
   *  first snapshot arrives with the first input event). Null on old
   *  agents / non-Windows hosts Ã¢ÂÂ the layout chip + picker self-hide.
   *  `installed` entries are `(opaque 8-hex HKL, BCP-47 tag)`. */
  const remoteLayout = ref<{
    activeHkl: string
    activeTag: string
    installed: { hkl: string; tag: string }[]
  } | null>(null)
  /** True while `navigator.keyboard.lock()` is active (locked
   *  fullscreen). Drives the aggressive preventDefault policy in
   *  `attachInput` (every forwarded key suppresses its local default
   *  so Alt+Tab / Win / Ctrl+W act on the remote) and relaxes the
   *  pointer-inside gates on the Ctrl+V/Ctrl+C interceptors + the
   *  SAS chord. */
  const keyboardLockActive = ref(false)

  /** Engage the Keyboard Lock API (call on entering fullscreen).
   *  Resolves `true` when the lock took. Never awaited inline by the
   *  fullscreenchange handler Ã¢ÂÂ a hung promise must degrade to legacy
   *  behavior, not block. */
  async function enableKeyboardLock(): Promise<boolean> {
    if (!isKeyboardLockSupported()) return false
    const kb = (globalThis.navigator as Navigator & {
      keyboard?: { lock?: (k?: string[]) => Promise<void>; unlock?: () => void }
    }).keyboard
    try {
      // No args = capture ALL capturable keys, incl. Alt+Tab, Win,
      // Ctrl+W, Escape. (Esc stays exitable via press-and-hold Ã¢ÂÂ
      // browser-level gesture, not cancellable by pages.)
      await kb!.lock!()
      keyboardLockActive.value = true
      return true
    } catch {
      // Permissions-policy iframe, non-secure context, platform quirk.
      keyboardLockActive.value = false
      return false
    }
  }

  /** Release the Keyboard Lock (fullscreen exit / disconnect /
   *  unmount). Idempotent. */
  function disableKeyboardLock() {
    try {
      const kb = (globalThis.navigator as Navigator & {
        keyboard?: { unlock?: () => void }
      }).keyboard
      kb?.unlock?.()
    } catch {
      /* noop */
    }
    keyboardLockActive.value = false
  }
  /** rc.87 Ã¢ÂÂ the agent's real encoder (codec/encoder/hardware/chroma),
   *  reported over the control DC by the FFmpeg DC pump. Null until
   *  the agent sends `rc:video-info` (legacy track + libvpx paths
   *  don't send it yet Ã¢ÂÂ badge falls back to a selection-derived
   *  label). The stats badge reads this for an honest readout. */
  const videoInfo = ref<RcVideoInfo | null>(null)
  /** FR-80 — set when the agent tells us it cannot capture; cleared on every
   *  new connect so a fixed host stops showing yesterday's reason. */
  const mediaUnavailable = ref<RcMediaUnavailable | null>(null)
  /** FR-97 P3c-1 — set when the agent says this session's audio track carries
   *  no sound; cleared on every new connect, like `mediaUnavailable`. */
  const audioUnavailable = ref<RcAudioUnavailable | null>(null)
  /** FR-93 P1 — set when the agent says this session's input will not reach
   *  the whole desktop; cleared on every new connect, like `mediaUnavailable`. */
  const inputReach = ref<RcInputReach | null>(null)
  /** FR-101 P4b-2b — when the device's idle limit will end this session, on
   *  this browser's clock (`rc:idle`), or `null` with no warning standing.
   *  Cleared by the device's own withdrawal, by any input sent from here, and
   *  on every new connect. */
  const idleEndsAt = ref<number | null>(null)
  /** FR-93 P2d-2 — set while the agent says its capture waits for the person
   *  at the screen. Cleared by the first frame, by `rc:media-unavailable` (the
   *  wait ended without an answer, and that message says why), and on every
   *  new connect. */
  const mediaWaiting = ref<RcMediaWaiting | null>(null)
  /** FR-93 P5f — when the latest notice arrived, on this browser's clock: only
   *  a frame after it ends the wait (`advanceEndsWait`). */
  let mediaWaitingSinceMs = 0
  /** FR-80 — the WebCodecs config string the active DataChannel decoder was
   *  built with (`avc1.640034`, `av01.0.13M.08`, …). The pill's honest label
   *  until `rc:video-info` names the agent's real encoder. */
  const dcDecoderCodec = ref<string | null>(null)
  /** P6 — the agent's InputArbiter state (participants, mode, floor
   *  holder). Null until the first `rc:control.state` broadcast; old
   *  agents never send it, so the multi-user UI self-hides. */
  const controlState = ref<RcControlState | null>(null)
  /** P6 — ghost cursors: other sessions' pointers keyed by session hex. */
  const peerCursors = ref<Record<string, PeerCursor>>({})
  /**
   * Current input desktop name reported by the SYSTEM-context
   * worker (agents 0.3.0+) via the `rc:desktop_changed` control-DC
   * message. `'Default'` is the normal interactive desktop;
   * `'Winlogon'` (or `'Screen-saver'`, etc.) means the operator
   * is on a secure desktop. Older agents never emit the message;
   * the ref stays at `'Default'` and the viewer renders no
   * secondary chip.
   */
  const currentDesktop = ref<string>('Default')
  /**
   * rc.23 Ã¢ÂÂ diagnostic surface for the `rc:logs-fetch` round-trip.
   * `agentLogs` holds the last reply (or null if no fetch has run);
   * `agentLogsLoading` flips true while a request is in flight.
   * Operator drives via `fetchAgentLogs(linesCount)` from the UI.
   */
  const agentLogs = ref<RcLogsFetchReply | null>(null)
  const agentLogsLoading = ref(false)
  // rc.NEXT Ã¢ÂÂ remote app selection & launch (virtual-desktop hosts).
  const remoteWindows = ref<RcWindowEntry[]>([])
  const launchableApps = ref<RcLaunchable[]>([])
  // FR-56 P2 - what the last listing could and could not enumerate. `null`
  // means the agent predates P2, which is NOT the same as "nothing unlisted".
  const appsCoverage = ref<RcAppsCoverage | null>(null)
  const appsLoading = ref(false)
  const appsError = ref<string | null>(null)
  /** Capability truth: null = unknown (never asked); set from the first
   *  list reply's `supported` field, or flipped false by a request
   *  timeout (an agent too old to speak rc:apps.*). */
  const appsSupported = ref<boolean | null>(null)
  /** idÃ¢ÂÂresolver map for interleaved list/focus/launch round-trips
   *  (mirrors `pendingDirRequests`). */
  const pendingAppsRequests = new Map<
    string,
    {
      resolve: (r: RcAppsListReply | RcAppsActionReply) => void
      reject: (e: Error) => void
      timer: ReturnType<typeof setTimeout>
    }
  >()
  function settleAppsRequest(id: string) {
    const p = pendingAppsRequests.get(id)
    if (!p) return null
    clearTimeout(p.timer)
    pendingAppsRequests.delete(id)
    return { resolve: p.resolve, reject: p.reject }
  }
  let nextAppsReqId = 1
  function makeAppsReqId(): string {
    return `apps-${Date.now().toString(36)}-${nextAppsReqId++}`
  }
  /**
   * Single-flight promise resolver Ã¢ÂÂ when set, the next
   * `rc:logs-fetch.reply` arriving over the control DC resolves it.
   * Set inside `fetchAgentLogs()`, cleared in the onmessage handler.
   * Subsequent rapid calls cancel the pending promise (reply may
   * still arrive and is dropped silently).
   */
  let pendingLogsResolver: ((reply: RcLogsFetchReply) => void) | null = null
  /**
   * rc.24 Ã¢ÂÂ accumulator for the streamed `rc:logs-fetch.reply.{start,chunk,end}`
   * envelope sequence. `null` outside of an active stream;
   * populated by the `start` handler and finalised by `end`. Only
   * one stream-in-flight at a time (single-flight, matched by
   * `pendingLogsResolver`); a second `start` mid-stream would
   * silently clobber the prior accumulator.
   */
  let streamingLogsAcc: RcLogsFetchReply | null = null
  const remoteStream = ref<MediaStream | null>(null)
  /** Set once we've received at least one video/audio track. False until
   *  the agent attaches media (the native agent currently does not). */
  const hasMedia = ref(false)
  /** Live inbound-RTP stats: bitrate, fps, codec. Zero until the first
   *  two polls land (we need two snapshots to derive bitrate). */
  const stats = ref<RcStats>({ ...EMPTY_STATS })
  // e2e hook (FR-61): the live stats ref — a path-agnostic "frames are
  // flowing" oracle (fps/bitrate update on the RTP path AND every DC pump,
  // where inbound-rtp getStats is silent).
  ;(window as unknown as Record<string, unknown>).__roomler_remote_stats = stats
  /** Remote cursor state. `pos` = null Ã¢ÂÂ hide the overlay + fall back
   *  to the initials badge. Shape bitmaps are cached so the canvas
   *  paint is just a `drawImage`. */
  const cursor = ref<RcCursor>({ pos: null, shapes: new Map() })
  /** Controller's quality preference, persisted in localStorage. Sent to
   *  the agent over the `control` data channel whenever the user changes
   *  it *or* the channel first opens. */
  const quality = ref<RcQuality>(readStoredQuality())
  /** rc.199 Ã¢ÂÂ the viewer "Priority" dial (per-session; persisted). Sent to the
   *  agent over the control DC on change and on channel open. Supersedes the
   *  old Quality dropdown in the UI (which only shadowed AIMD/REMB); the
   *  underlying `quality` ref + `rc:quality` sender are kept for back-compat. */
  const priority = ref<RcPriority>(readStoredPriority())
  /** loopback-TURN corp-relay (Phase 2; default ON since 2026-08-02). When on,
   *  `connect()` probes the local agent's loopback TURN and relays through it
   *  if present Ã¢ÂÂ bypasses the capped far-coturn relay on corp networks. */
  const localRelayEnabled = ref<boolean>(readStoredLocalRelay())
  /** Optional codec override. `null` = let the agent pick from the full
   *  intersection; `'h265'` = only advertise H.265 + H.264 fallback to
   *  the agent so AV1 can't win. Useful for A/B comparisons
   *  ("is HEVC actually better than H.264 on this link?"). Persisted
   *  to localStorage so the choice survives a page reload. */
  const preferredCodec = ref<RcPreferredCodec | null>(readStoredPreferredCodec())
  /** How the remote video is rendered inside the viewer stage. See
   *  `RcScaleMode`. Persisted per-browser in localStorage. */
  const scaleMode = ref<RcScaleMode>(readStoredScaleMode())
  /** Percent for `scaleMode === 'custom'`. Range 5-1000, clamped at
   *  read/write time. */
  const scaleCustomPercent = ref<number>(readStoredScalePct())
  /** Remote capture/encode resolution choice. Persisted per-agent
   *  (keyed on `agentId` after `connect()`). Starts at `{mode:'original'}`
   *  and narrows when `connect()` supplies the real agent id. */
  const resolution = ref<RcResolutionSetting>({ mode: 'original' })
  // Tracks the last agentId we loaded + persist under. Set in connect().
  let resolutionAgentId: string | null = null
  /** FR-119 P1 — the frame rate this viewer asks for (`rc:fps`), remembered per
   *  browser. Sent only to an agent advertising `fps-high`. */
  const frameRate = ref<FrameRate>(readStoredFrameRate())
  /** FR-119 P1 — the picker's options for the connected agent. P2b-3: a rate
   *  above the host screen's refresh rate is disabled, once the agent says
   *  what that is. */
  const frameRateChoices = computed(() =>
    frameRateOptions(agent?.value?.capabilities?.video, hostRefreshHzOf(videoInfo.value)),
  )
  /** Per-agent codec override bookkeeping Ã¢ÂÂ set in connect(), cleared in
   *  disconnect() so an idle post-session global pick can't silently write
   *  the last agent's override. */
  let codecAgentId: string | null = null
  let codecUserPickedThisSession = false
  /** The DC transport this session REQUESTED (agent-caps-gated), or null for
   *  the legacy RTP track. Set per connect(); gates the RTP-track WebCodecs
   *  transform machinery, whose "webcodecs path skipped" warnings are
   *  misleading noise on DC sessions (the track is a dormant placeholder
   *  there â the DC worker path IS WebCodecs; field 2026-07-28). */
  let sessionDcTransport: string | null = null
  /** FR-77 — the chroma format the current session's cell runs in, so a
   *  decode failure is remembered against the right cell (`hevc:yuv444`
   *  failing must not ban HEVC 4:2:0). Set where the request is built. */
  let sessionCellChroma: 'yuv420' | 'yuv444' = 'yuv420'
  /** FR-17 — true when THIS session negotiated per-chunk framing: the
   *  agent advertised `chunk-framing` in `AgentCaps.video` and we asked
   *  for it in `rc:session.request`. Read by `startVp9_444Path` /
   *  `startHevcPath` when they hand the worker its `init-canvas`, so the
   *  parse side can never be enabled without the request side having
   *  been sent — an unframed stream parsed as framed is garbage, not a
   *  degraded picture, so the two must move together. */
  let sessionChunkFraming = false
  /** FR-16 L4 — how THIS session times input to photon, if at all:
   *  `probe` when the knob `roomler-rc-bench=1` is set AND the agent
   *  advertised `bench` in `AgentCaps.video`; `target` when the knob says
   *  `target` (a `roomlerd probe-target` window on the host paints the
   *  answers). Resolved beside `sessionChunkFraming`, before any worker gets
   *  its `init-canvas`, which carries `sessionBench`. */
  let sessionBenchMode: BenchMode | null = null
  let sessionBench = false
  let benchProber: BenchProber | null = null
  let videoBench: VideoBenchSampler | null = null
  /** The element `attachInput` was given: the `<video>` the bench sampler
   *  reads on the plain RTP path lives inside it. */
  let benchSurface: HTMLElement | null = null
  const l4Uploader = createL4Uploader()
  // rc.190 (A1) Ã¢ÂÂ true once the USER changed resolution this session, so
  // connect()'s per-agent restore doesn't clobber a pre-connect pick.
  let resolutionUserPickedThisSession = false

  /** Viewer render path. `video` goes through `<video>` + the browser's
   *  jitter buffer; `webcodecs` uses the Worker + VideoDecoder + canvas
   *  path that bypasses it. Persisted per-browser; defaults to `video`
   *  so the feature stays opt-in while we bed it in. */
  const renderPath = ref<RcRenderPath>(readStoredRenderPath())
  /** Preferred video transport. `webrtc` is the legacy default; the
   *  user opts in to `data-channel-vp9-444` when they want crystal-
   *  clear 4:4:4 text rendering. The actual negotiation is done on
   *  the agent: this ref is only consulted at `connect()` time, the
   *  agent reads `preferred_transport` and intersects it with its
   *  own `AgentCaps.transports`. Persisted per-browser. */
  const videoTransport = ref<RcVideoTransport>(readStoredVideoTransport())
  /** Opt-in "receive host audio" preference (per-browser, persisted).
   *  When true `connect()` adds a `recvonly` audio transceiver AND sets
   *  `audio_enabled: true` on the request; the received Opus track is
   *  played through a dedicated `<audio>` sink (the `<video>` element
   *  stays `muted` since video may travel over the DataChannel/canvas
   *  path). Only takes effect on the next `connect()` Ã¢ÂÂ matching the
   *  video-transport toggles. Graceful no-op when the agent doesn't
   *  advertise `"opus"`. */
  const audioEnabled = ref<boolean>(readStoredAudioEnabled())
  /** The received host-audio track, wrapped in its OWN MediaStream so
   *  it never clobbers `remoteStream` (which the `<video>` element
   *  binds to). Set in `pc.ontrack` for `kind === 'audio'`; the view
   *  binds it to a hidden `<audio autoplay>` element. Null until an
   *  audio track arrives. */
  const remoteAudioStream = ref<MediaStream | null>(null)
  /** True when a received audio track could NOT be auto-played because
   *  the browser blocked autoplay-with-sound (no prior user gesture on
   *  the page). The view surfaces a one-click "unmute" affordance that
   *  calls `resumeAudioPlayback()`. Reset to false once playback
   *  succeeds or audio tears down. */
  const audioAutoplayBlocked = ref<boolean>(false)
  /** rc.62 Ã¢ÂÂ VP9 chroma preference (per-browser, persisted). When set
   *  to `'yuv420'` or `'yuv444'` the value is sent as `chroma_pref` in
   *  the `rc:session.request` payload; the agent's VP9-444 encoder
   *  uses it instead of its `ROOMLERD_VP9_CHROMA` env var. When
   *  `'auto'` (default), the field is omitted and the agent uses its
   *  own configured default. */
  const vp9Chroma = ref<Vp9ChromaPref>(readStoredVp9Chroma())
  /** Whether VP9 profile 1 (8-bit 4:4:4) decode is supported on this
   *  browser. Resolved asynchronously by `isVp9_444DecodeSupported()`
   *  in `connect()` (and re-checked once on first composable use, so
   *  the UI can disable the toolbar toggle when unsupported). The UI
   *  reads this; an unset/false value means the data-channel transport
   *  is unavailable regardless of the user's stored preference. */
  const vp9_444Supported = ref<boolean>(false)
  // Kick off the async probe immediately. We only need the answer at
  // connect() time so the await isn't latency-critical, but resolving
  // it eagerly lets the UI disable the toolbar toggle on browsers
  // that lack VP9 profile 1 support.
  void isVp9_444DecodeSupported().then((ok) => { vp9_444Supported.value = ok })
  /** rc.190 Ã¢ÂÂ whether WebCodecs AV1 decode is available here (dav1d SW
   *  ships in Chromium, so ~always true on Chrome). Gates the AV1
   *  toggle; the HW-vs-SW truth is `viewerDecodeHw` below. */
  const av1Supported = ref<boolean>(false)
  void isAv1DecodeSupported().then((ok) => { av1Supported.value = ok })
  /** rc.190 Ã¢ÂÂ whether THIS viewer decodes the active session's codec in
   *  hardware (MediaCapabilities `smooth && powerEfficient` at pick
   *  time). `null` = unknown / webrtc path. Surfaces the viewer half of
   *  the HWÃÂHW story in the stats HUD, next to the agent-side
   *  `hardware` flag from `rc:video-info`. */
  const viewerDecodeHw = ref<boolean | null>(null)
  /** Whether this browser actually supports the WebCodecs path. UI
   *  reads this to disable the toggle when the APIs aren't present
   *  (Firefox, Safari < 17, old Chromium). */
  const webcodecsSupported = ref<boolean>(isWebCodecsSupported())
  /** The `<canvas>` the view renders into when `renderPath === 'webcodecs'`
   *  and the session is active. The view writes this ref on mount; the
   *  composable reads it in `pc.ontrack` to transfer control to the
   *  worker. Null in `video` mode. */
  const webcodecsCanvasEl = ref<HTMLCanvasElement | null>(null)
  /** Unified intrinsic dimensions of the rendered remote frame. Driven
   *  by `<video>.onresize` in classic mode and by worker `first-frame`
   *  messages in webcodecs mode. The view reads this for `custom`/`original`
   *  scale styling + input coord math Ã¢ÂÂ one source of truth that works
   *  across both paths. */
  const mediaIntrinsicW = ref(0)
  const mediaIntrinsicH = ref(0)
  // WebCodecs runtime handles. Created on track-attach, destroyed in
  // teardown(). Tracked here rather than scoped inside ontrack so
  // teardown() can reliably stop the worker on disconnect.
  let webcodecsWorker: Worker | null = null
  /** `true` once the WebCodecs transform is successfully installed
   *  on the receiver AND we're committed to painting to the canvas.
   *  Stays `false` when we fall back (HEVC, missing API, worker
   *  ctor failure, transferControlToOffscreen throw). The VIEW
   *  reads this (not the `renderPath` preference) to decide which
   *  element to mount Ã¢ÂÂ so an HEVC session under renderPath='webcodecs'
   *  correctly renders the `<video>` rather than a permanent black
   *  canvas. */
  const webcodecsActive = ref(false)

  // P7 — FSR sharpening (see rc-fsr-render.ts). `sharpenMode` is the live
  // setting (persisted + posted to whichever DC worker is active);
  // `renderInfo` mirrors the worker's 1 s stats (active render path +
  // actual backing size) for the stats pill ("· FSR") and the diag HUD.
  const sharpenMode = ref<SharpenMode>(storedSharpenMode())
  const renderInfo = ref<{ mode: string; w: number; h: number } | null>(null)
  let vp9ViewportCleanup: (() => void) | null = null
  let hevcViewportCleanup: (() => void) | null = null

  function setSharpenMode(m: SharpenMode) {
    const mode = normalizeSharpenMode(m)
    sharpenMode.value = mode
    persistSharpenMode(mode)
    const worker = hevcWorker ?? vp9_444Worker
    if (worker) {
      try {
        worker.postMessage({ type: 'render-mode', sharpen: mode })
      } catch {
        /* worker torn down mid-change */
      }
    }
  }

  /** P7 — fold the worker stats' render fields into `renderInfo`. */
  function updateRenderInfo(m: { render?: string; renderW?: number; renderH?: number }) {
    if (typeof m.render === 'string') {
      renderInfo.value = {
        mode: m.render,
        w: typeof m.renderW === 'number' ? m.renderW : 0,
        h: typeof m.renderH === 'number' ? m.renderH : 0,
      }
    }
  }

  // Phase Y.3: VP9-444 over DataChannel pipeline. Independent of the
  // RTCRtpScriptTransform path above Ã¢ÂÂ uses its OWN worker
  // (rc-vp9-444-worker.ts) fed off `video-bytes` DC binary messages.
  let vp9_444Worker: Worker | null = null
  /** `true` once the worker has been spun up and the DC opened. The
   *  view (Y.4) reads this to swap a `<canvas>` in for the `<video>`
   *  element, mirroring how `webcodecsActive` drives the WebCodecs
   *  path. Stays `false` when the user didn't opt in OR the agent
   *  doesn't honour the transport (no DC ever arrives Ã¢ÂÂ flag never
   *  flips). */
  const vp9_444Active = ref(false)
  /** Number of decoded VP9-444 frames so far. Surfaced to the view
   *  for diagnostics and used by tests to assert end-to-end decode
   *  succeeded. */
  const vp9_444FramesDecoded = ref(0)
  /** Rolling-window stats from the VP9-444 worker (rc.35). Bitrate is
   *  delivered-bytes/sec at the SCTP-receive boundary (post-network,
   *  pre-decode), so it shows the actual link throughput including
   *  any AIMD-driven adjustments. width/height reflect the latest
   *  decoded VideoFrame dims. Updated every ~1 s by the worker;
   *  the view's HUD reads these directly. */
  const vp9_444Stats = ref<{
    bitrateBps: number
    fps: number
    width: number
    height: number
    bytesReceivedTotal: number
  }>({ bitrateBps: 0, fps: 0, width: 0, height: 0, bytesReceivedTotal: 0 })
  /** The visible `<canvas>` the view paints VP9-444 frames into. The
   *  view writes this on mount; the composable picks it up and
   *  posts `init-canvas` to the worker. Null until the view
   *  provides a canvas Ã¢ÂÂ Y.3 ships without view-side wiring, so
   *  bytes flow + decode happens against a synthetic OffscreenCanvas
   *  instead. */
  const vp9_444CanvasEl = ref<HTMLCanvasElement | null>(null)

  // rc.78 Ã¢ÂÂ HEVC over DataChannel pipeline (Option B). Sibling to the
  // VP9-444 pipeline above; shares the `video-bytes` DC label (the
  // agent emits HEVC OR VP9-444 there based on negotiated_transport,
  // never both). Independent worker because the codec string +
  // decoder configure differ, and we want a clean failure isolation
  // boundary if one path regresses.
  let hevcWorker: Worker | null = null
  /** Whether HEVC decode is supported on this browser. Probe runs
   *  once on composable construction (and re-checks in connect()).
   *  HEVC has NO software fallback in WebCodecs Ã¢ÂÂ Linux Chromium
   *  and corporate-policy boxes return false here, and the connect
   *  path falls back to VP9-444-DC or webrtc. */
  const hevcSupported = ref<boolean>(false)
  void isHevcDecodeSupported().then((ok) => {
    hevcSupported.value = ok
  })
  /** DC transports whose worker FAILED before decoding a single frame this
   *  page-lifetime — i.e. the pre-connect probe said yes and the real
   *  decoder said no (`isConfigSupported` can lie: Chrome 148 accepted
   *  vp09.01 then rejected the first frame; Edge accepts probes its
   *  enterprise policy later refuses). Without this memory the reconnect
   *  ladder re-ran the SAME rank, re-picked the SAME transport and went
   *  black forever — the probe result hadn't changed, only reality had.
   *  Consulted by connect() (auto-rank inputs AND the explicit picks, which
   *  fall through to their existing fallback chains). Deliberately never
   *  cleared: a decoder that rejected real bytes once will reject them
   *  after the next probe too; a page reload starts fresh.
   *  `Set<string>` (not RcVideoTransport): the vp9-worker ban site keys by
   *  `sessionDcTransport`, which is a plain string. */
  const failedDcTransports = new Set<string>()
  /** P7 — whether this browser decodes HEVC Rext 4:4:4 (narrow: Chrome ≥137
   *  + NV driver ≥572.16, or Intel Gen11+ ≥117). Gates the "HEVC · crisp
   *  text (4:4:4)" picker entry together with the agent's `hevc_chroma`. */
  const hevcRextSupported = ref<boolean>(false)
  void isHevcRextDecodeSupported().then((ok) => {
    hevcRextSupported.value = ok
  })
  /** FR-77 P3b — whether this browser's VideoDecoder accepts H.264 High 4:4:4 (software decode). */
  const h264High444Supported = ref<boolean>(false)
  void isH264High444DecodeSupported().then((codec) => {
    h264High444Supported.value = codec !== null
  })
  /** `true` once the HEVC worker has been spun up and the DC opened.
   *  Same semantics as `vp9_444Active`. */
  const hevcActive = ref(false)
  /** Number of decoded HEVC frames so far. */
  const hevcFramesDecoded = ref(0)
  /** Rolling-window stats from the HEVC worker. Same shape as the
   *  VP9-444 stats so the view's HUD code is shared. */
  const hevcStats = ref<{
    bitrateBps: number
    fps: number
    width: number
    height: number
    bytesReceivedTotal: number
  }>({ bitrateBps: 0, fps: 0, width: 0, height: 0, bytesReceivedTotal: 0 })
  /** The visible `<canvas>` the view paints HEVC frames into. View
   *  writes this on mount; composable posts `init-canvas` to the
   *  worker. Null until view-side wiring lands (rc.79+); rc.78 ships
   *  with synthetic OffscreenCanvas so bytes still flow + decode
   *  happens for verification. */
  const hevcCanvasEl = ref<HTMLCanvasElement | null>(null)

  /** P1 Ã¢ÂÂ latest per-hop diagnostics window from the active decode worker
   *  (null until the first stats window on a DC path). */
  const decodeDiag = ref<RcDecodeDiag | null>(null)

  let pc: RTCPeerConnection | null = null
  /** Data channels we open proactively (per docs ÃÂ§5). Labels match the
   *  agent's expected routing: input/control/clipboard/files. */
  const channels: Record<string, RTCDataChannel> = {}
  // #2638 - a display-match request made before the control channel opened,
  // sent from its `onopen` (see `sendDisplayMatch`).
  const heldDisplayMatch = new HeldRequest<{ width: number; height: number } | null>()
  const inputChannelOpen = ref(false)
  // Multi-user P3: the session's EFFECTIVE input grant, from
  // `rc:session.created.permissions`. `true` until a server says otherwise
  // (pre-P3 servers omit the field = as-requested). Reset on each connect.
  const inputGranted = ref(true)
  // The same, for CLIPBOARD: `false` = the channel was dropped
  // (`dropClipboardChannel`) and the view hides its clipboard controls.
  const clipboardGranted = ref(true)
  // FR-85 P3c — RECORD survives the hub only when this controller may record
  // AND the device's owner opted in. `recordRefused` is the server's reason
  // when it did not (`controller_not_allowed`, `device_not_opted_in`), so the
  // toolbar can explain instead of only hiding. Reset on each connect.
  const recordGranted = ref(false)
  const recordRefused = ref<string | null>(null)
  const recording = useRemoteRecording()
  // FR-99 P1c — PRIVACY survives the hub only on a device that serves privacy
  // mode (its owner allowed it), and never under break-glass. `privacyRefused`
  // is the server's reason when it did not. Asked for only when the device
  // serves it (`withPrivacyAsked`). Reset on each connect.
  const privacyGranted = ref(false)
  const privacyRefused = ref<string | null>(null)
  const privacy = usePrivacyMode()
  // FR-101 P2c — the features the session policy took out of this session
  // (`rc:session.created.features_refused`: clipboard, files, audio → the
  // reason), so each control can say why instead of failing on a click, and
  // clipboard auto-sync stands down. Reset on each connect.
  const featuresRefused = ref<Record<string, string>>({})

  // Pending clipboard:read requests. Keyed by `req_id` so interleaved
  // reads can resolve independently. The agent echoes the req_id back
  // on `clipboard:content` / `clipboard:error`; a 5 s timeout rejects
  // stale requests so the UI toast doesn't spin forever.
  const pendingClipboardReads = new Map<
    number,
    { resolve: (text: string) => void; reject: (err: Error) => void; timer: ReturnType<typeof setTimeout> }
  >()
  let nextClipboardReqId = 1

  // ---- Clipboard v2: auto-sync engine ----------------------------------
  // Bidirectional clipboard sync without the manual toolbar buttons.
  // Local Ã¢ÂÂ remote: focus/visibility/poll/paste triggers read the local
  // clipboard and push changes over the DC. Remote Ã¢ÂÂ local: the agent
  // pushes clipboard:event / img streams after clipboard:subscribe.
  // The echo gate (+ the agent's SelfMarks) breaks the infinite loop
  // both directions independently.
  const clipboardAutoSyncEnabled = ref(readStoredClipboardAutoSync())
  /** Latched true when clipboard-read permission is DENIED (not on
   *  transient focus races Ã¢ÂÂ see handleClipboardReadDenied). The view
   *  shows a one-shot snackbar + Settings hint; manual buttons keep
   *  working via their own gesture-anchored reads. */
  const clipboardSyncBlocked = ref(false)
  const clipboardEchoGate = createClipboardEchoGate()

  /** Write-acks: id Ã¢ÂÂ settle. Resolved by clipboard:write-ack,
   *  clipboard:error{id}, or the timeout Ã¢ÂÂ always resolves (void), the
   *  waiter just proceeds. */
  const pendingClipboardAcks = new Map<
    string,
    { onSettle: () => void; timer: ReturnType<typeof setTimeout> }
  >()
  function awaitClipboardAck(id: string, timeoutMs: number): Promise<void> {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        pendingClipboardAcks.delete(id)
        resolve()
      }, timeoutMs)
      pendingClipboardAcks.set(id, {
        onSettle: () => {
          clearTimeout(timer)
          pendingClipboardAcks.delete(id)
          resolve()
        },
        timer,
      })
    })
  }
  function settleClipboardAck(id: unknown) {
    if (typeof id !== 'string') return
    pendingClipboardAcks.get(id)?.onSettle()
  }

  /** Un-acked local-to-remote writes, keyed by content hash. The echo gate
   *  remembers a hash at SEND time, so a deferred Ctrl+V that short-circuits
   *  on `knows(hash)` could flush while the agent's OS write (ordered DC +
   *  worker-thread hop) was still in flight — the remote app then pasted the
   *  STALE clipboard. That is the exact race the ack gate was built for,
   *  re-opened through the gate's own memory (auto-sync ON made it MORE
   *  likely). Short-circuit lanes must await the outstanding write first. */
  const unackedClipboardWrites = new Map<string, Promise<void>>()
  function trackClipboardWrite(hash: string, id: string) {
    if (!supportsClipboardAck.value) return
    const p = awaitClipboardAck(id, CLIPBOARD_ACK_TIMEOUT_MS).then(() => {
      if (unackedClipboardWrites.get(hash) === p) unackedClipboardWrites.delete(hash)
    })
    unackedClipboardWrites.set(hash, p)
  }
  function awaitOutstandingClipboardWrite(hash: string): Promise<void> {
    return unackedClipboardWrites.get(hash) ?? Promise.resolve()
  }

  /** Rich reads (accept:["image","html"]) that may resolve as an
   *  image/html stream instead of clipboard:content. Keyed by the
   *  same req_id namespace as pendingClipboardReads. */
  const pendingClipboardRichReads = new Map<
    number,
    {
      resolve: (
        content:
          | { kind: 'image'; blob: Blob; w: number; h: number }
          | { kind: 'html'; html: string; text: string }
          | { kind: 'native'; rtf: Uint8Array<ArrayBuffer>; html: string; text: string },
      ) => void
      reject: (err: Error) => void
    }
  >()

  type RemoteClipContent =
    | { kind: 'text'; text: string }
    | { kind: 'image'; blob: Blob; w: number; h: number }
    | { kind: 'html'; html: string; text: string }
    | { kind: 'native'; rtf: Uint8Array<ArrayBuffer>; html: string; text: string }
  /** Latest remote change that arrived while this tab was unfocused
   *  (clipboard writes need document focus). Applied on refocus unless
   *  the operator copied something new locally in the meantime Ã¢ÂÂ
   *  local wins then (last-writer-wins approximation, no clocks). */
  let pendingRemoteApply: RemoteClipContent | null = null

  /** v2.2 Ã¢ÂÂ the full fidelity path is available only when the REMOTE
   *  agent speaks native AND THIS machine has a local bridge to reach
   *  its own RTF clipboard. */
  const canUseNativeClipboard = computed(
    () => supportsClipboardNative.value && localClipboardBridge.value === true,
  )

  /** Probe the local agent's clipboard bridge once (loopback, ~1.5 s
   *  timeout). A local enrolled agent with the clipboard feature
   *  answers; anything else (no agent, feature off, PNA-blocked)
   *  leaves the flag false and the viewer stays on the DC lanes. */
  async function probeLocalClipboardBridge(): Promise<void> {
    if (!supportsClipboardNative.value) {
      localClipboardBridge.value = false
      localClipboardBridgePort.value = null
      return
    }
    // Walk the candidate range: a host with several agents binds
    // distinct ports, and only the WINDOWS-native one carries the
    // `x-roomler-clipboard-native` header (Access-Control-Expose-
    // Headers'd for cross-origin reads). Gating on it means a WSL /
    // Linux agent answering earlier in the range is skipped and the
    // Windows agent found on the next port. First match wins.
    for (const port of LOCAL_RELAY_PROBE_PORTS) {
      const ctrl = new AbortController()
      const timer = setTimeout(() => ctrl.abort(), 1200)
      try {
        const res = await fetch(clipboardBridgeUrl(port), { method: 'GET', signal: ctrl.signal })
        const reachable = res.ok || res.status === 204
        if (reachable && res.headers.get('x-roomler-clipboard-native') === '1') {
          localClipboardBridge.value = true
          localClipboardBridgePort.value = port
          return
        }
        // Reachable but not native (a non-Windows agent) Ã¢ÂÂ keep walking.
      } catch {
        // Nothing on this port (connection refused = fast) Ã¢ÂÂ next.
      } finally {
        clearTimeout(timer)
      }
    }
    localClipboardBridge.value = false
    localClipboardBridgePort.value = null
  }

  /** Read the local machine's native clipboard (RTF + alternates) via
   *  the bridge. Null when the bridge is absent or holds no RTF. */
  async function readLocalNativeClipboard(): Promise<
    { rtf: Uint8Array<ArrayBuffer>; html: string; text: string } | null
  > {
    const port = localClipboardBridgePort.value
    if (localClipboardBridge.value !== true || port == null) return null
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), 5000)
    try {
      const res = await fetch(clipboardBridgeUrl(port), { method: 'GET', signal: ctrl.signal })
      if (res.status === 204 || !res.ok) return null
      return parseNativeClipPayload(await res.json())
    } catch {
      return null
    } finally {
      clearTimeout(timer)
    }
  }

  /** Write RTF + alternates to the local machine's clipboard via the
   *  bridge. Returns true on success. */
  async function writeLocalNativeClipboard(content: {
    rtf: Uint8Array<ArrayBuffer>
    html: string
    text: string
  }): Promise<boolean> {
    const port = localClipboardBridgePort.value
    if (localClipboardBridge.value !== true || port == null) return false
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), 8000)
    try {
      const res = await fetch(clipboardBridgeUrl(port), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          rtf: bytesToBase64(content.rtf),
          html: content.html,
          text: content.text,
        }),
        signal: ctrl.signal,
      })
      return res.ok || res.status === 204
    } catch {
      return false
    } finally {
      clearTimeout(timer)
    }
  }

  async function writeRemoteContentToLocalClipboard(content: RemoteClipContent): Promise<void> {
    try {
      if (content.kind === 'native') {
        // v2.2 Ã¢ÂÂ full fidelity: write RTF (embedded images) to the
        // local clipboard via the bridge. Fall back to the html lane
        // if the bridge write fails.
        const ok = await writeLocalNativeClipboard(content)
        if (ok) {
          clipboardEchoGate.recordApplied(hashClipboardBytes(content.rtf))
          if (content.text) clipboardEchoGate.recordPushed(hashClipboardText(content.text))
          return
        }
        if (content.html) {
          await writeRemoteContentToLocalClipboard({
            kind: 'html',
            html: content.html,
            text: content.text,
          })
        } else if (content.text) {
          await writeRemoteContentToLocalClipboard({ kind: 'text', text: content.text })
        }
        return
      }
      if (content.kind === 'text') {
        await globalThis.navigator.clipboard.writeText(content.text)
        clipboardEchoGate.recordApplied(hashClipboardText(content.text))
      } else if (content.kind === 'html') {
        // v2.1 Ã¢ÂÂ both formats in one ClipboardItem: rich-aware local
        // paste targets take the html, plain editors the text alt.
        await globalThis.navigator.clipboard.write([
          new ClipboardItem({
            'text/html': new Blob([content.html], { type: 'text/html' }),
            'text/plain': new Blob([content.text], { type: 'text/plain' }),
          }),
        ])
        // Read back Ã¢ÂÂ Chrome re-serializes CF_HTML on write; hash what
        // a later local read will actually see so the echo gate holds.
        try {
          const items = await globalThis.navigator.clipboard.read()
          for (const item of items) {
            if (item.types.includes('text/html')) {
              const backHtml = await (await item.getType('text/html')).text()
              const backText = item.types.includes('text/plain')
                ? await (await item.getType('text/plain')).text()
                : ''
              clipboardEchoGate.recordApplied(hashClipboardHtml(backHtml, backText))
              // The text alt may surface alone via readText-based
              // polling Ã¢ÂÂ record it too so it isn't re-pushed.
              if (backText) clipboardEchoGate.recordPushed(hashClipboardText(backText))
              break
            }
          }
        } catch {
          clipboardEchoGate.recordApplied(hashClipboardHtml(content.html, content.text))
        }
      } else {
        await globalThis.navigator.clipboard.write([
          new ClipboardItem({ 'image/png': content.blob }),
        ])
        // Chrome re-encodes PNGs on write Ã¢ÂÂ read back and hash what a
        // later local read will actually see, else the echo gate
        // false-negatives and we push the image straight back.
        try {
          const items = await globalThis.navigator.clipboard.read()
          for (const item of items) {
            if (item.types.includes('image/png')) {
              const back = await item.getType('image/png')
              clipboardEchoGate.recordApplied(
                hashClipboardBytes(new Uint8Array(await back.arrayBuffer())),
              )
              break
            }
          }
        } catch {
          /* best-effort Ã¢ÂÂ the agent-side seq/self-marks still hold */
        }
      }
    } catch (e) {
      // Focus lost between check and write, or permission denied Ã¢ÂÂ
      // drop; the next remote change re-pushes.
      console.debug('[rc] clipboard apply failed', e)
    }
  }

  function applyRemoteClipboard(content: RemoteClipContent) {
    if (!clipboardAutoSyncEnabled.value) return
    // FR-101 P2c — the session policy took the clipboard out of this session.
    if (featuresRefused.value.clipboard) return
    if (!globalThis.document.hasFocus()) {
      pendingRemoteApply = content // latest wins
      return
    }
    void writeRemoteContentToLocalClipboard(content)
  }

  function handleClipboardReadDenied(e: unknown) {
    // NotAllowedError also fires on focus races ("Document is not
    // focused" Ã¢ÂÂ DevTools focus, window switch mid-await). Only latch
    // the blocked state when the permission is truly denied.
    void (async () => {
      try {
        const status = await globalThis.navigator.permissions.query({
          name: 'clipboard-read' as PermissionName,
        })
        if (status.state === 'denied') clipboardSyncBlocked.value = true
      } catch {
        /* permissions API unavailable Ã¢ÂÂ stay optimistic, retry later */
      }
    })()
    console.debug('[rc] clipboard read blocked', e)
  }

  async function pngDimensions(blob: Blob): Promise<{ w: number; h: number } | null> {
    try {
      const bmp = await createImageBitmap(blob)
      const d = { w: bmp.width, h: bmp.height }
      bmp.close()
      return d
    } catch {
      return null
    }
  }

  /** v2.1 Ã¢ÂÂ stream pre-built rich frames (html or image) with SCTP
   *  backpressure. Returns false when the DC dies mid-stream. */
  async function sendRichFramesOverDc(
    ch: RTCDataChannel,
    built: { begin: string; frames: Uint8Array<ArrayBuffer>[]; end: string },
  ): Promise<boolean> {
    try {
      ch.send(built.begin)
      for (const frame of built.frames) {
        while (ch.bufferedAmount > 4 * 1024 * 1024) {
          await new Promise((r) => setTimeout(r, 20))
          if (ch.readyState !== 'open') return false
        }
        ch.send(frame)
      }
      ch.send(built.end)
      return true
    } catch {
      return false
    }
  }

  /** v2.2 Ã¢ÂÂ read the local machine's native RTF via the bridge and
   *  push it as a native transfer (full fidelity, embedded images).
   *  Returns true when HANDLED (pushed or recognized as an echo);
   *  false Ã¢ÂÂ the caller falls back to the html/text lanes. `textHash`
   *  is the readText hash that triggered the sync Ã¢ÂÂ recorded so later
   *  polls don't re-push the text alt. */
  async function pushLocalNativeToRemote(ch: RTCDataChannel, textHash: string): Promise<boolean> {
    const native = await readLocalNativeClipboard()
    if (!native) return false // no RTF locally Ã¢ÂÂ html/text fallback
    const rtfHash = hashClipboardBytes(native.rtf)
    if (!clipboardEchoGate.shouldPush(rtfHash)) {
      clipboardEchoGate.recordPushed(textHash)
      return true
    }
    const built = buildClipboardNativeFrames(native.rtf, native.html, native.text)
    if (!built) return false // oversized Ã¢ÂÂ html/text fallback
    if (!(await sendRichFramesOverDc(ch, built))) return false
    clipboardEchoGate.recordPushed(rtfHash)
    clipboardEchoGate.recordPushed(textHash)
    trackClipboardWrite(rtfHash, built.id)
    trackClipboardWrite(textHash, built.id)
    if (native.html) {
      const htmlHash = hashClipboardHtml(native.html, native.text)
      clipboardEchoGate.recordPushed(htmlHash)
      trackClipboardWrite(htmlHash, built.id)
    }
    return true
  }

  /** v2.1 Ã¢ÂÂ read the local clipboard's text/html (one clipboard.read())
   *  and push it as an html transfer. Returns true when the change was
   *  HANDLED (pushed, or recognized as an echo) Ã¢ÂÂ the caller then skips
   *  the plain-text fallback. `textHash` is the readText-derived hash
   *  that triggered the sync; recorded alongside the combined hash so
   *  later readText polls don't re-push the text alt. */
  async function pushLocalHtmlToRemote(ch: RTCDataChannel, textHash: string): Promise<boolean> {
    let items: ClipboardItems
    try {
      items = await globalThis.navigator.clipboard.read()
    } catch (e) {
      if (e instanceof DOMException && e.name === 'NotAllowedError') {
        handleClipboardReadDenied(e)
      }
      return false
    }
    for (const item of items) {
      if (!item.types.includes('text/html')) continue
      let html = ''
      let text = ''
      try {
        html = await (await item.getType('text/html')).text()
        if (item.types.includes('text/plain')) {
          text = await (await item.getType('text/plain')).text()
        }
      } catch {
        return false
      }
      if (!html) return false
      const combinedHash = hashClipboardHtml(html, text)
      if (!clipboardEchoGate.shouldPush(combinedHash)) {
        // Known rich content (we applied or pushed it) resurfacing via
        // a fresh readText hash Ã¢ÂÂ remember the alt so the caller and
        // future polls stay quiet.
        clipboardEchoGate.recordPushed(textHash)
        return true
      }
      const built = buildClipboardHtmlFrames(html, text)
      if (!built) return false // oversized html Ã¢ÂÂ plain-text fallback
      if (!(await sendRichFramesOverDc(ch, built))) return false
      clipboardEchoGate.recordPushed(combinedHash)
      clipboardEchoGate.recordPushed(textHash)
      trackClipboardWrite(combinedHash, built.id)
      trackClipboardWrite(textHash, built.id)
      return true
    }
    return false // no html on the clipboard Ã¢ÂÂ plain-text fallback
  }

  async function pushLocalImageToRemote(ch: RTCDataChannel): Promise<boolean> {
    let items: ClipboardItems
    try {
      items = await globalThis.navigator.clipboard.read()
    } catch (e) {
      // DataError = clipboard holds no readable data (e.g. files) Ã¢ÂÂ
      // a transient skip, NOT a permission problem.
      if (e instanceof DOMException && e.name === 'NotAllowedError') {
        handleClipboardReadDenied(e)
      }
      return false
    }
    for (const item of items) {
      if (!item.types.includes('image/png')) continue
      let blob: Blob
      try {
        blob = await item.getType('image/png')
      } catch {
        return false
      }
      if (blob.size === 0 || blob.size > CLIPBOARD_IMAGE_MAX_BYTES) return false
      const png = new Uint8Array(await blob.arrayBuffer())
      const hash = hashClipboardBytes(png)
      if (!clipboardEchoGate.shouldPush(hash)) return false
      const dims = await pngDimensions(blob)
      if (!dims) return false
      try {
        const { begin, frames, end } = buildClipboardImageFrames(png, dims.w, dims.h)
        ch.send(begin)
        for (const frame of frames) {
          while (ch.bufferedAmount > 4 * 1024 * 1024) {
            await new Promise((r) => setTimeout(r, 20))
            if (ch.readyState !== 'open') return false
          }
          ch.send(frame)
        }
        ch.send(end)
        clipboardEchoGate.recordPushed(hash)
        return true
      } catch {
        return false
      }
    }
    return false
  }

  let clipboardPushInFlight = false
  let clipboardSyncDirty = false
  let lastClipboardSyncAttempt = 0
  async function syncLocalClipboardToRemote(
    reason: 'focus' | 'visible' | 'poll' | 'paste-intent' | 'connect',
  ): Promise<void> {
    if (!clipboardAutoSyncEnabled.value || clipboardSyncBlocked.value) return
    if (phase.value !== 'connected') return
    // FR-101 P2c — the agent would refuse every push: the session policy took
    // the clipboard out of this session.
    if (featuresRefused.value.clipboard) return
    const ch = channels.clipboard
    if (!ch || ch.readyState !== 'open') return
    if (!globalThis.document.hasFocus()) return
    if (clipboardPushInFlight) {
      // focus + visibilitychange fire back-to-back on refocus; the second
      // trigger used to be silently dropped while the first was still
      // reading — mark dirty and re-run once the in-flight pass ends.
      clipboardSyncDirty = true
      return
    }
    const now = Date.now()
    if (now - lastClipboardSyncAttempt < CLIPBOARD_SYNC_MIN_INTERVAL_MS) return
    lastClipboardSyncAttempt = now
    clipboardPushInFlight = true
    try {
      // Focus-conflict rule: refocusing with a stashed remote change Ã¢ÂÂ
      // local wins ONLY if the operator copied something new while
      // away (its hash is unknown to the gate); else the stash applies.
      const stashed = pendingRemoteApply
      pendingRemoteApply = null
      let text = ''
      try {
        text = await globalThis.navigator.clipboard.readText()
      } catch (e) {
        handleClipboardReadDenied(e)
        return
      }
      if (normalizeClipboardText(text) !== '') {
        const hash = hashClipboardText(text)
        if (clipboardEchoGate.shouldPush(hash)) {
          // v2.2 Ã¢ÂÂ richest available: when both ends can do native and
          // this machine has a local bridge, ship RTF (embedded
          // images). One bridge GET per actual change, not per tick.
          if (canUseNativeClipboard.value && reason !== 'poll') {
            const handled = await pushLocalNativeToRemote(ch, hash)
            if (handled) return
          }
          // v2.1 Ã¢ÂÂ new content detected via the cheap readText. Prefer
          // the RICH form when the agent takes html: one clipboard.read()
          // per actual change (not per poll tick).
          if (supportsClipboardHtml.value) {
            const handled = await pushLocalHtmlToRemote(ch, hash)
            if (handled) return
          }
          try {
            // RAW text on the wire Ã¢ÂÂ see sendClipboardWriteOverDc.
            const { id } = sendClipboardWriteOverDc(ch, text)
            clipboardEchoGate.recordPushed(hash)
            trackClipboardWrite(hash, id)
          } catch {
            /* DC hiccup Ã¢ÂÂ the next trigger retries */
          }
          return
        }
      } else if (supportsClipboardImages.value && reason !== 'poll') {
        // Image push is event-driven only: polling clipboard.read()
        // every 2 s would fetch + hash up to 8 MiB per tick.
        const pushed = await pushLocalImageToRemote(ch)
        if (pushed) return
      }
      if (stashed) await writeRemoteContentToLocalClipboard(stashed)
    } finally {
      clipboardPushInFlight = false
      if (clipboardSyncDirty) {
        clipboardSyncDirty = false
        // Re-run after the throttle window — the dropped trigger may have
        // seen NEWER clipboard content than the pass that just finished.
        setTimeout(() => {
          void syncLocalClipboardToRemote(reason)
        }, CLIPBOARD_SYNC_MIN_INTERVAL_MS)
      }
    }
  }

  function sendClipboardSubscription(on: boolean) {
    const ch = channels.clipboard
    if (!ch || ch.readyState !== 'open' || !supportsClipboardEvents.value) return
    try {
      ch.send(
        JSON.stringify(
          on
            ? {
                t: 'clipboard:subscribe',
                events: [
                  'text',
                  ...(supportsClipboardImages.value ? ['image'] : []),
                  ...(supportsClipboardHtml.value ? ['html'] : []),
                  // Only ask for native events if we can actually apply
                  // them (local bridge present) Ã¢ÂÂ else the remote would
                  // ship megabytes of RTF we'd only downgrade to html.
                  ...(canUseNativeClipboard.value ? ['native'] : []),
                ],
              }
            : { t: 'clipboard:unsubscribe' },
        ),
      )
    } catch {
      /* DC closing */
    }
  }

  /** `clipboardSyncBlocked` used to be a PERMANENT latch — one transient
   *  'denied' (focus race, temporary policy) killed auto-sync for the rest
   *  of the page's life. Re-probe the permission on window focus and
   *  un-latch when it reports granted; no prompt is shown by query(). */
  async function maybeUnblockClipboardSync(): Promise<void> {
    if (!clipboardSyncBlocked.value) return
    try {
      const status = await globalThis.navigator.permissions.query({
        name: 'clipboard-read' as PermissionName,
      })
      if (status.state === 'granted') clipboardSyncBlocked.value = false
    } catch {
      /* Permissions API unavailable — stay blocked */
    }
  }

  function onWindowFocusClipboard() {
    void maybeUnblockClipboardSync().then(() => syncLocalClipboardToRemote('focus'))
  }
  function onVisibilityClipboard() {
    if (globalThis.document.visibilityState === 'visible') {
      void syncLocalClipboardToRemote('visible')
    }
  }
  let clipboardSyncPollTimer: ReturnType<typeof setInterval> | null = null
  let clipboardSyncTriggersOn = false
  function startClipboardSyncTriggers() {
    if (clipboardSyncTriggersOn) return
    clipboardSyncTriggersOn = true
    globalThis.window.addEventListener('focus', onWindowFocusClipboard)
    globalThis.document.addEventListener('visibilitychange', onVisibilityClipboard)
    clipboardSyncPollTimer = setInterval(() => {
      if (globalThis.document.hasFocus()) void syncLocalClipboardToRemote('poll')
    }, CLIPBOARD_SYNC_POLL_MS)
  }
  function stopClipboardSyncTriggers() {
    if (!clipboardSyncTriggersOn) return
    clipboardSyncTriggersOn = false
    globalThis.window.removeEventListener('focus', onWindowFocusClipboard)
    globalThis.document.removeEventListener('visibilitychange', onVisibilityClipboard)
    if (clipboardSyncPollTimer) {
      clearInterval(clipboardSyncPollTimer)
      clipboardSyncPollTimer = null
    }
  }

  function setClipboardAutoSyncEnabled(on: boolean) {
    clipboardAutoSyncEnabled.value = on
  }
  watch(clipboardAutoSyncEnabled, (on) => {
    persistClipboardAutoSync(on)
    if (on) {
      sendClipboardSubscription(true)
      if (channels.clipboard?.readyState === 'open') {
        startClipboardSyncTriggers()
        void syncLocalClipboardToRemote('focus')
      }
    } else {
      sendClipboardSubscription(false)
      stopClipboardSyncTriggers()
      pendingRemoteApply = null
    }
  })

  // ---- File-DC registry (shared across all `files` channel transfers) ----
  // The `files` DC carries multiple concurrent kinds of work in 0.3.0+:
  // single-file uploads, multi-file upload queues (Phase 1), single-file
  // downloads (Phase 2), folder downloads (Phase 4), and dir-list requests
  // (Phase 3). All of them are demuxed from a single persistent
  // `onmessage` listener attached at DC creation time (see channels.files
  // setup further down). Per-call listener-add was the pattern in 0.2.x;
  // it works for one transfer at a time but doesn't compose with
  // concurrent up + down or a queued multi-upload.
  //
  // Each entry tracks a state (`pending` Ã¢ÂÂ `settled`); only the first
  // transition wins, so a `files:cancel` racing a `files:complete` /
  // `files:eof` doesn't double-resolve the Promise.
  type UploadResolve = (result: { path: string; bytes: number }) => void
  type DownloadResolve = (result: { name: string; bytes: number }) => void
  // FileSystemWritableFileStream is the showSaveFilePicker writable
  // (Chrome / Edge / Safari 17+). Older TS lib targets miss the type;
  // we keep the structural shape we actually use to avoid a lib bump.
  type SaveWritable = {
    write: (data: Uint8Array | ArrayBuffer) => Promise<void>
    close: () => Promise<void>
    abort: (reason?: unknown) => Promise<void>
  }
  type DownloadEntry = {
    kind: 'download'
    status: 'pending' | 'settled'
    resolve: DownloadResolve
    reject: (err: Error) => void
    // Sink: either a streaming writable (Chrome) OR a Blob accumulator
    // (Firefox / Safari < 17). Decided at downloadFile() time and
    // populated when files:offer arrives.
    saveMode: 'stream' | 'blob' | 'pending'
    writable: SaveWritable | null
    blobs: BlobPart[]
    name: string
    suggestedName?: string
    bytesReceived: number
    expectedSize: number | null
    mime?: string
  }
  /**
   * Upload entry. rc.19 carries enough context to re-pump after a
   * DC drop:
   * - `bytesAcked` mirrors the agent's last `files:progress` so
   *   `files:resume` knows the safest offset to request.
   * - `file` / `relPath` / `destPath` survive the original
   *   closure-only state from rc.18's `uploadOne` so the resume
   *   loop can call `innerPump` again without rebuilding the
   *   call-site context.
   * - `status: 'pending-resume'` is the in-between state set by
   *   the DC-close handler when the agent has the resume cap;
   *   the wrapper transitions it back to `'pending'` after
   *   `files:resumed` lands.
   */
  type UploadEntry = {
    kind: 'upload'
    status: 'pending' | 'pending-resume' | 'settled'
    resolve: UploadResolve
    reject: (err: Error) => void
    bytesAcked: number
    file: File
    relPath?: string
    destPath?: string
  }
  type RegistryEntry = UploadEntry | DownloadEntry
  const filesRegistry = new Map<string, RegistryEntry>()

  /**
   * rc.19: awaiters for `files:resumed { id, accepted_offset }`
   * replies during the resume handshake window. Separate from
   * `filesRegistry` because the resume wrapper needs the
   * resumed reply BEFORE the entry transitions back to `'pending'`
   * Ã¢ÂÂ routing through `filesRegistry.get(id)` would race with the
   * close-handler's `'pending-resume'` patch. Shape mirrors the
   * `pendingDirRequests` pattern used for `files:dir-list`.
   */
  type ResumeWaiter = {
    resolve: (acceptedOffset: number) => void
    reject: (err: Error) => void
    timer: ReturnType<typeof setTimeout>
  }
  const pendingResumePromises = new Map<string, ResumeWaiter>()
  // The browser-side demux contract: while a download `files:offer` is
  // active, every binary frame on the DC belongs to that id. There can
  // only be one active outgoing transfer at a time (server enforces);
  // we mirror that here so binary chunks find the right writable.
  let activeDownloadId: string | null = null
  // Settle an entry exactly once. Returns true if THIS call won the
  // transition; false if the entry was already settled. The caller uses
  // the return value to skip duplicate resolve / reject.
  function settleEntry(id: string): RegistryEntry | null {
    const entry = filesRegistry.get(id)
    if (!entry || entry.status === 'settled') return null
    entry.status = 'settled'
    filesRegistry.delete(id)
    return entry
  }

  // Reactive list of in-flight + recently-finished file transfers. The
  // Transfers chip in RemoteControl.vue binds to this. Entries auto-prune
  // after 10 s in a terminal state so the panel doesn't grow unboundedly
  // over a long session.
  type TransferStatus =
    | 'queued'
    | 'running'
    /** rc.19: DC closed mid-upload but the agent has the resume cap;
     *  the wrapper is waiting for the WebRTC peer to reconnect so
     *  it can issue `files:resume`. Operator sees "Reconnecting N/6". */
    | 'reconnecting'
    | 'complete'
    | 'error'
    | 'cancelled'
  interface Transfer {
    id: string
    kind: 'upload' | 'download'
    name: string
    bytes: number
    total: number | null
    status: TransferStatus
    error?: string
  }
  const transfers = ref<Transfer[]>([])
  function pushTransfer(t: Transfer) {
    transfers.value = [...transfers.value, t]
  }
  function patchTransfer(id: string, patch: Partial<Transfer>) {
    transfers.value = transfers.value.map((t) => (t.id === id ? { ...t, ...patch } : t))
    if (patch.status === 'complete' || patch.status === 'error' || patch.status === 'cancelled') {
      // Auto-prune after 10 s in a terminal state. rc.19 'reconnecting'
      // is explicitly NOT terminal Ã¢ÂÂ the wrapper transitions out of it
      // either back to 'running' (resume accepted) or to 'error' (6
      // attempts exhausted), at which point this branch fires again.
      setTimeout(() => {
        transfers.value = transfers.value.filter((t) => t.id !== id)
      }, 10_000)
    }
  }

  // Stats polling: interval handle + last snapshot so each poll can
  // derive a delta bitrate. Reset in teardown() so a fresh connection
  // doesn't see a stale byte counter.
  let statsTimer: ReturnType<typeof setInterval> | null = null
  // rc.188 Ã¢ÂÂ viewer-rate feedback. The decode worker reports a CUMULATIVE
  // backlog-drop counter; we diff it per window to derive the per-window
  // `struggling` bit sent to the agent (see `sendDecodeStat`). Reset in
  // teardown so a fresh connection doesn't see a stale total.
  let lastBacklogDrops = 0
  // P6 Ã¢ÂÂ flow-control knobs + the sustained-window struggle fold. One bad
  // window no longer trips the agent's fps clamp (which costs ~20 s of lazy
  // recovery); the run must persist `struggleWindows` consecutive windows.
  const flowParams = storedFlowParams()
  const struggleWindow = new StruggleWindow(flowParams.struggleWindows)
  let statsPrevBytes = 0
  let statsPrevTsMs = 0

  // FR-1 P7 — agent clock sync for the HUD's end-to-end frame age. A probe
  // rides every stats tick (`rc:clock` on the control DC, ~60 B); the agent
  // echoes t0 + its process-epoch µs, we keep the lowest-RTT sample of the
  // last CLOCK_RING (both clocks are fixed-origin, so the offset is a
  // constant — min-RTT is purely about asymmetry error), and push the offset
  // to whichever decode worker is painting. Old agents never echo: the ring
  // stays empty and the HUD simply shows no age.
  const CLOCK_RING = 8
  let clockSamples: ClockSample[] = []
  let clockBest: ClockSample | null = null

  function sendClockProbe() {
    const ch = channels.control
    if (!ch || ch.readyState !== 'open') return
    try {
      ch.send(JSON.stringify({ t: 'rc:clock', t0: epochNowUs() }))
    } catch {
      /* channel closed between check and send — next tick retries */
    }
  }

  /** Post the current best offset to the active decode worker(s). Called
   *  on every new best sample AND from each worker's start path (the
   *  worker may be created after the offset is already known). */
  function pushClockOffset() {
    const msg = { type: 'clock-offset', offsetUs: clockBest?.offsetUs ?? null }
    try { hevcWorker?.postMessage(msg) } catch { /* worker torn down */ }
    try { vp9_444Worker?.postMessage(msg) } catch { /* worker torn down */ }
  }

  function handleClockEcho(t0: number, agentUs: number) {
    const s = clockSample(t0, epochNowUs(), agentUs)
    if (!s) return
    clockSamples.push(s)
    if (clockSamples.length > CLOCK_RING) clockSamples.shift()
    const best = bestClockSample(clockSamples)
    const changed = best !== null
      && (clockBest === null || best.offsetUs !== clockBest.offsetUs)
    clockBest = best
    if (changed) pushClockOffset()
  }

  function resetClockSync() {
    clockSamples = []
    clockBest = null
  }

  // Coalesce rapid mouse moves to one per animation frame (~60 Hz). Keys
  // and clicks are NOT coalesced Ã¢ÂÂ they're too meaningful to drop.
  let pendingMove: { x: number; y: number; mon: number } | null = null
  // FR-1 P6 — pointer cadence decoupled from rAF. The old
  // requestAnimationFrame coalescer tied mouse_move sends to the viewer's
  // compositor: a busy tab (heavy decode/FSR) slows rAF exactly when the
  // user is dragging, thinning the input stream the remote end needs most —
  // and even idle, rAF adds up to a frame (~16 ms) before the FIRST send.
  // Now: send immediately when the min-gap has passed, else one timer for
  // the remainder; latest-wins. 8 ms ≈ 125 Hz ceiling, ~60 B/msg — noise
  // even on a constrained relay. FR-98 C3: the gap is a knob for the field
  // A/B (`roomler-rc-input-gap`, `storedInputGapMs`); 8 unless set.
  const INPUT_MOVE_GAP_MS = storedInputGapMs()
  let moveTimer: ReturnType<typeof setTimeout> | null = null
  let lastMoveSentAt = 0

  function flushPendingMove() {
    moveTimer = null
    if (!pendingMove || !channels.input || channels.input.readyState !== 'open') return
    lastMoveSentAt = performance.now()
    sendInput({ t: 'mouse_move', ...pendingMove })
    pendingMove = null
  }

  /** Send now if the gap has passed, else arm one timer for the rest. */
  function schedulePendingMove() {
    if (moveTimer !== null) return
    const since = performance.now() - lastMoveSentAt
    if (since >= INPUT_MOVE_GAP_MS) {
      flushPendingMove()
    } else {
      moveTimer = setTimeout(flushPendingMove, INPUT_MOVE_GAP_MS - since)
    }
  }

  // FR-109 — relative mode. While the input surface holds Pointer Lock the
  // pointer belongs to the host app: moves are deltas, summed over the same
  // gap and sent as `mouse_rel` in whole counts (the accumulator keeps the
  // fraction). The view sets `relativeMouseAllowed` from the agent's caps
  // (`mouse-rel`), so an agent that cannot parse the frame never gets one.
  const relativeMouse = ref(false)
  const relativeMouseAllowed = ref(false)
  // FR-109 P3 — the auto-switch. The agent says `cursor:hide` when the host
  // hides its cursor (an app captured the pointer); the next click inside the
  // picture then enters relative mode, and the cursor coming back
  // (`cursor:pos`) leaves it, but only a lock the switch itself took.
  const relativeMouseAuto = ref(false)
  /** FR-111 P4b-2 — while a viewer dialog takes typing (the layout editor's
   *  names and labels), the keyboard does not reach the host: the window's
   *  key listener leaves every event to the page. Setting it lets go of
   *  what the keyboard holds on the host. */
  const keyboardPaused = ref(false)
  const hostCursorHidden = ref(false)
  /** This cursor channel has carried the host's pointer (`cursor:pos` or
   *  `cursor:shape`). A tracker that cannot see the pointer (Linux without DRM
   *  capture, macOS) sends one `cursor:hide` at the start and nothing more, so
   *  until then a hide does not switch. */
  let hostCursorTracked = false
  /** The person left an auto-entered lock while the cursor stayed hidden:
   *  no re-entry until it shows again. */
  let relativeAutoSuppressed = false
  /** `roomler-rc-relative-auto=off`, read when the input surface attaches. */
  let relativeAutoOff = false
  /** The click that entered relative mode is the gesture, not input: its
   *  button-up is swallowed too. */
  let swallowedButton: string | null = null
  const relAcc = createRelAccumulator()
  let relTimer: ReturnType<typeof setTimeout> | null = null
  let lastRelSentAt = 0
  /** The surface `attachInput` wired, which is what Pointer Lock locks. */
  let relativeSurface: HTMLElement | null = null

  // FR-111 P2 — how a finger drives the host: `direct` (the finger is the
  // pointer) or `trackpad` (it moves the pointer, which stays between
  // touches). Remembered per browser; `direct` until decision 1 says otherwise.
  // FR-111 decision 1 — with nothing remembered, a phone-sized screen starts in
  // trackpad mode.
  const touchMode = ref<TouchMode>(readTouchMode((() => {
    try {
      return globalThis.localStorage
    } catch {
      return null
    }
  })(), phoneSized(globalThis.screen)))
  function setTouchMode(m: TouchMode) {
    touchMode.value = m
    try {
      globalThis.localStorage.setItem(TOUCH_MODE_STORAGE_KEY, m)
    } catch {
      /* blocked site data: this tab only */
    }
  }

  // FR-111 P3 — the on-screen controls press through the attached stage,
  // which owns the held-input tracking and both pointer paths. The proxy is
  // stable for the overlay to hold; it drops presses while no stage is
  // attached.
  let controlsSink: ControlsSink | null = null
  const touchControlsSink: ControlsSink = {
    key: (code, down) => controlsSink?.key(code, down),
    button: (btn, down) => controlsSink?.button(btn, down),
    move: (dx, dy) => controlsSink?.move(dx, dy),
    begin: () => controlsSink?.begin(),
    end: () => controlsSink?.end(),
    width: () => controlsSink?.width() ?? 0,
  }

  function flushRel() {
    if (relTimer !== null) {
      clearTimeout(relTimer)
      relTimer = null
    }
    const d = relAcc.take()
    if (!d) return
    lastRelSentAt = performance.now()
    sendInput({ t: 'mouse_rel', dx: d.dx, dy: d.dy })
  }

  function scheduleRel() {
    if (relTimer !== null) return
    const since = performance.now() - lastRelSentAt
    if (since >= INPUT_MOVE_GAP_MS) {
      flushRel()
    } else {
      relTimer = setTimeout(flushRel, INPUT_MOVE_GAP_MS - since)
    }
  }

  /** FR-109 — enter relative mode: Pointer Lock on the input surface, asking
   *  for raw, unaccelerated deltas. Must run inside a user gesture (the
   *  toolbar control is one). A browser that rejects `unadjustedMovement`
   *  gets plain Pointer Lock. Resolves whether the lock was requested. */
  async function enterRelativeMouse(): Promise<boolean> {
    const el = relativeSurface
    if (!el || !relativeMouseAllowed.value || !inputGranted.value) return false
    if (globalThis.document?.pointerLockElement === el) return true
    type Lockable = { requestPointerLock(options?: { unadjustedMovement?: boolean }): Promise<void> | void }
    const lockable = el as unknown as Lockable
    try {
      await lockable.requestPointerLock({ unadjustedMovement: true })
    } catch {
      try {
        await lockable.requestPointerLock()
      } catch {
        return false
      }
    }
    return true
  }

  /** FR-109 P3 — the host's cursor is visible again (`cursor:pos` after a
   *  `cursor:hide`): an auto-entered lock goes, and the next hide may switch
   *  again. A lock the person took from the toolbar stays theirs. */
  function onHostCursorShown() {
    if (!hostCursorHidden.value) return
    hostCursorHidden.value = false
    relativeAutoSuppressed = false
    if (relativeMouse.value && relativeMouseAuto.value) exitRelativeMouse()
  }

  /** FR-109 — leave relative mode (Esc does it too, as the browser's rule). */
  function exitRelativeMouse() {
    const doc = globalThis.document
    if (doc && relativeSurface && doc.pointerLockElement === relativeSurface) doc.exitPointerLock()
  }

  /** FR-109 — the view's gate, from `AgentCaps.input` and its kill switch.
   *  Withdrawn mid-lock (an older agent after a reconnect), the lock goes. */
  function setRelativeMouseAllowed(allowed: boolean) {
    relativeMouseAllowed.value = allowed
    if (!allowed) exitRelativeMouse()
  }

  function sendInput(msg: Record<string, unknown>) {
    // Multi-user P3: a view-effective session (the server stripped INPUT
    // because another live session holds it) sends nothing - the agent's
    // input DC is in drop-only mode anyway; suppressing here saves the
    // wire and makes the state observable (`inputGranted` export).
    if (!inputGranted.value) return
    const ch = channels.input
    if (!ch || ch.readyState !== 'open') return
    // FR-101 P4b-2b — this input is activity: the device withdraws its idle
    // warning on its next look, and the countdown goes now, not seconds later.
    if (idleEndsAt.value !== null) idleEndsAt.value = null
    try {
      ch.send(JSON.stringify(msg))
    } catch {
      /* channel may have closed between the check and send Ã¢ÂÂ drop */
    }
  }

  /** FR-16 L4 — send one bench probe on the input channel. Same gates as
   *  `sendInput` (an INPUT-less session sends nothing), but it reports
   *  whether the probe left, so only a probe that did is timed. */
  function sendBenchProbe(probe: { t: 'probe'; seq: number }): boolean {
    if (!inputGranted.value) return false
    const ch = channels.input
    if (!ch || ch.readyState !== 'open') return false
    try {
      ch.send(JSON.stringify(probe))
      return true
    } catch {
      return false
    }
  }

  /** FR-16 L4, target mode — the probe is a real pointer move onto cell
   *  `seq` of the host's `roomlerd probe-target` window. Aimed with the
   *  agent's reported native size, since the window lives in the host's own
   *  pixels however the stream is scaled. Same gates as `sendInput`. */
  function sendBenchTargetMove(probe: { t: 'probe'; seq: number }): boolean {
    if (!inputGranted.value) return false
    const ch = channels.input
    if (!ch || ch.readyState !== 'open') return false
    const video = benchSurface?.querySelector('video') as HTMLVideoElement | null
    const monW = videoInfo.value?.native_w || mediaIntrinsicW.value || video?.videoWidth || 0
    const monH = videoInfo.value?.native_h || mediaIntrinsicH.value || video?.videoHeight || 0
    const p = probeTargetPointer(monW, monH, probe.seq)
    if (!p) return false
    try {
      ch.send(JSON.stringify({ t: 'mouse_move', x: p.x, y: p.y, mon: 0 }))
      return true
    } catch {
      return false
    }
  }

  /** FR-16 L4 — a sampler read probe `seq` off a frame painted at
   *  `paintedAt` (epoch ms). */
  function onBenchProbe(seq: unknown, paintedAt: unknown, path: BenchPath) {
    if (typeof seq !== 'number' || typeof paintedAt !== 'number') return
    benchProber?.onPainted(seq, paintedAt, path)
  }

  /** FR-16 L4 — start probing: called when the input channel opens, and a
   *  no-op unless this session resolved `sessionBench`. Every sampler is
   *  armed per probe; only the one painting frames can answer. */
  function startBench() {
    if (!sessionBench || benchProber) return
    videoBench = createVideoBenchSampler({
      findVideo: () => (benchSurface?.querySelector('video') as HTMLVideoElement | null) ?? null,
      onProbe: (seq, paintedAt) => onBenchProbe(seq, paintedAt, 'video'),
    })
    const target = sessionBenchMode === 'target'
    benchProber = createBenchProber({
      send: target ? sendBenchTargetMove : sendBenchProbe,
      maxSeq: target ? PROBE_TARGET.cells : undefined,
      arm: (seq) => {
        hevcWorker?.postMessage({ type: 'bench-arm', seq })
        vp9_444Worker?.postMessage({ type: 'bench-arm', seq })
        webcodecsWorker?.postMessage({ type: 'bench-arm', seq })
        videoBench?.arm(seq)
      },
      flush: (batch) => {
        console.info('[rc] bench', formatBenchLine(benchStats(batch.rtts, batch.lost), batch.paths))
        l4Uploader.send(batch, {
          tenantId: expectedOrgTid(null, location.pathname) ?? lastConnectArgs?.orgId ?? null,
          agentOrgId: lastConnectArgs?.orgId ?? null,
          agentId: lastConnectArgs?.agentId ?? null,
          sessionId: sessionId.value,
        })
      },
    })
    benchProber.start()
  }

  function stopBench() {
    benchProber?.stop()
    benchProber = null
    videoBench?.stop()
    videoBench = null
  }

  /** Type literal text on the remote host. Used by the on-screen
   *  mobile keyboard and the IME composition path: the agent's
   *  `enigo.text()` invokes the OS Unicode-typing API, so emoji /
   *  CJK / accented Latin all round-trip without any HID-code
   *  mapping on the browser side. Safe to call when the input
   *  channel isn't open Ã¢ÂÂ silent drop. */
  function sendKeyText(text: string) {
    if (!text) return
    sendInput({ t: 'key_text', text })
  }

  /** Send a HID key event. Used by the mobile keyboard's special-
   *  key toolbar (Esc/Tab/Enter/Backspace/arrows + modifier keys).
   *  Mirrors the wire shape of the regular physical-key path. Pass
   *  the same `code` / `down` / `mods` triple as `decideKeyAction`
   *  produces. Safe to call when the input channel isn't open.
   *
   *  `mods` bitfield: 0x01 = Ctrl, 0x02 = Shift, 0x04 = Alt,
   *  0x08 = Meta/Win Ã¢ÂÂ matches `kbdCodeToHid` callers throughout
   *  the codebase. */
  function sendKey(code: number, down: boolean, mods: number = 0) {
    sendInput({ t: 'key', code, down, mods })
  }

  /**
   * rc.23 Ã¢ÂÂ request a tail of the agent's log file over the control
   * DC. Sends `rc:logs-fetch { lines }` and awaits the matching
   * `rc:logs-fetch.reply`. Single-flight: a second call while one is
   * pending cancels the prior promise (the late reply is dropped).
   *
   * Returns the reply or rejects with a clear error when the control
   * DC isn't open / the timeout fires / agent is too old to support
   * the message. Newer agents reply within ~50 ms for the default
   * 500-line tail; the 8 s timeout is generous for slow disks.
   */
  // rc.23 hotfix #4 Ã¢ÂÂ default tail reduced 500 Ã¢ÂÂ 200 lines. The
  // reply JSON for 500 lines could reach ~50Ã¢ÂÂ60 KB, very close to
  // webrtc-rs's SCTP `max_message_size` default of 65536. 200 lines
  // Ã¢ÂÂ 25 KB, safe margin. Operator can still ask for up to 5000 via
  // the UI line-count selector Ã¢ÂÂ the agent clamps anyway.
  function fetchAgentLogs(lines = 200): Promise<RcLogsFetchReply> {
    return new Promise((resolve, reject) => {
      const ch = channels.control
      if (!ch || ch.readyState !== 'open') {
        reject(new Error('control DC not open Ã¢ÂÂ not connected to agent'))
        return
      }
      // Cancel any prior in-flight request Ã¢ÂÂ late reply is dropped.
      const prevResolver = pendingLogsResolver
      if (prevResolver !== null) {
        // Resolve the prior promise with a synthetic error so its
        // caller doesn't hang forever.
        prevResolver({ ok: false, error: 'superseded by a newer fetch' })
      }
      agentLogsLoading.value = true
      // `isActive` is the single source of truth for "this request is
      // still awaiting a reply." Avoids the rc.23-first-cut bug where
      // the timer compared `pendingLogsResolver === resolve` but the
      // pendingLogsResolver had been reassigned to a wrapper closure,
      // so the timer body's guard always failed and the spinner spun
      // forever when the agent didn't respond (old agent unaware of
      // `rc:logs-fetch`, or DC half-open after a peer drop).
      let isActive = true
      // rc.23 hotfix #2 Ã¢ÂÂ 30 s timeout (was 8 s). the field-test host field
      // report: log fetch timing out even on rc.23 agent. Agent's
      // file read might be ESET-intercepted (the agent's tracing
      // log is itself a file that ESET scans on read). 8 s gave too
      // little budget; 30 s matches the "operator clicks Refresh
      // and waits a beat" experience.
      const timer = setTimeout(() => {
        if (!isActive) return
        isActive = false
        pendingLogsResolver = null
        agentLogsLoading.value = false
        reject(
          new Error(
            'rc:logs-fetch timed out after 30 s Ã¢ÂÂ agent might be on rc.22 or older, or its log read is being held by the AV scanner'
          )
        )
      }, 30000)
      pendingLogsResolver = (reply) => {
        if (!isActive) return
        isActive = false
        clearTimeout(timer)
        pendingLogsResolver = null
        agentLogsLoading.value = false
        resolve(reply)
      }
      try {
        const payload = JSON.stringify({ t: 'rc:logs-fetch', lines })
        // rc.23 hotfix #4 Ã¢ÂÂ outbound trace so DevTools shows the
        // request actually went out. Paired with the inbound trace
        // on `channels.control.onmessage`, the field can verify
        // request-vs-reply round-trip status without an agent log.
        // eslint-disable-next-line no-console
        console.log('[rc:control] outbound:', payload)
        ch.send(payload)
      } catch (e) {
        if (!isActive) return
        isActive = false
        clearTimeout(timer)
        pendingLogsResolver = null
        agentLogsLoading.value = false
        reject(e instanceof Error ? e : new Error(String(e)))
      }
    })
  }

  // Ã¢ÂÂÃ¢ÂÂ Remote app selection & launch (virtual-desktop hosts) Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ
  // All three ride the control DC (same request/reply shape as
  // rc:logs-fetch), id-correlated via `pendingAppsRequests`. The 10 s
  // timeout doubles as the old-agent detector: an agent that predates
  // rc:apps.* never replies Ã¢ÂÂ `appsSupported` flips false Ã¢ÂÂ menu disables.
  function sendAppsRequest<T extends RcAppsListReply | RcAppsActionReply>(
    msg: Record<string, unknown> | null,
    onTimeout?: () => void,
  ): Promise<T> {
    const ch = channels.control
    if (!ch || ch.readyState !== 'open') {
      return Promise.reject(new Error('control DC not open Ã¢ÂÂ not connected to agent'))
    }
    if (!msg || typeof msg.id !== 'string') {
      return Promise.reject(new Error('malformed apps request'))
    }
    const id = msg.id
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        if (pendingAppsRequests.delete(id)) {
          onTimeout?.()
          if (appsSupported.value === null) appsSupported.value = false
          reject(new Error('apps request timed out (10 s) Ã¢ÂÂ agent may predate rc:apps.*'))
        }
      }, 10_000)
      pendingAppsRequests.set(id, {
        resolve: resolve as (r: RcAppsListReply | RcAppsActionReply) => void,
        reject,
        timer,
      })
      try {
        ch.send(JSON.stringify(msg))
      } catch (e) {
        clearTimeout(timer)
        pendingAppsRequests.delete(id)
        reject(e instanceof Error ? e : new Error(String(e)))
      }
    })
  }

  /** Fetch the remote desktop's window list + launchable apps. Populates
   *  `remoteWindows` / `launchableApps` / `appsSupported` via the
   *  control-DC onmessage arm; also resolves with the reply. */
  function refreshApps(): Promise<RcAppsListReply> {
    appsLoading.value = true
    return sendAppsRequest<RcAppsListReply>(appsListWireMessage(makeAppsReqId()), () => {
      appsLoading.value = false
    }).finally(() => {
      appsLoading.value = false
    })
  }
  /** Focus a window by its opaque id from the last list. For a detached
   *  tmux session (a `tmux:<name>` synthetic id) the agent re-attaches by
   *  spawning a fresh xterm. */
  function focusWindow(windowId: string): Promise<RcAppsActionReply> {
    return sendAppsRequest<RcAppsActionReply>(appsFocusWireMessage(makeAppsReqId(), windowId))
  }
  /** Launch a new allowlisted app by its key. */
  function launchApp(appKey: string): Promise<RcAppsActionReply> {
    return sendAppsRequest<RcAppsActionReply>(appsLaunchWireMessage(makeAppsReqId(), appKey))
  }

  /** Send a `rc:quality` preference over the control channel. Safe to
   *  call while the channel is closed Ã¢ÂÂ it's a no-op until open. Also
   *  sent automatically when the channel first opens so the agent
   *  learns the restored preference without user interaction. */
  /** P6 — ask the agent's InputArbiter for the exclusive-mode floor. The
   *  reply is the next `rc:control.state` broadcast (granted = we become
   *  the holder; an ACTIVE holder keeps it and state shows who). */
  function requestControl() {
    sendControl({ t: 'rc:control.request' })
  }

  /** FR-27 — the holder hands the floor to whoever is waiting, without making
   *  them wait out the idle timer. The agent validates both ends (only the
   *  current holder may grant, and only to the session that actually asked),
   *  so a stale click cannot hand control to whoever asked last. */
  function grantControl(session: string) {
    sendControl({ t: 'rc:control.grant', session })
  }

  /** FR-27 — the holder declines, or the requester withdraws. The agent
   *  accepts it from either, so one verb clears the chip on both toolbars. */
  function dismissControlRequest() {
    sendControl({ t: 'rc:control.dismiss' })
  }

  /** Fire-and-forget on the control DC. No-op while it is closed — every
   *  caller here is a UI affordance whose reply is the next
   *  `rc:control.state` broadcast, so a dropped send self-corrects. */
  function sendControl(msg: Record<string, unknown>) {
    const ch = channels.control
    if (!ch || ch.readyState !== 'open') return
    try {
      ch.send(JSON.stringify(msg))
    } catch {
      /* drop */
    }
  }

  /** FR-92 — ask the device to turn keep busy on (with these settings) or
   *  off. The device decides — its arbiter checks this session's INPUT
   *  grant, the floor and the org — and answers every viewer with
   *  `rc:keep-busy.state`; a refusal comes back to this viewer alone. */
  function setKeepBusy(req: KeepBusyRequest) {
    sendControl(keepBusySetMessage(req))
  }

  /** P6 — toggle the device's arbitration mode in-session (INPUT-granted
   *  sessions only; the arbiter enforces). */
  function setInputMode(mode: 'free' | 'exclusive') {
    const ch = channels.control
    if (!ch || ch.readyState !== 'open') return
    try {
      ch.send(JSON.stringify({ t: 'rc:control.mode', mode }))
    } catch {
      /* drop */
    }
  }

  function sendQualityPreference() {
    const ch = channels.control
    if (!ch || ch.readyState !== 'open') return
    try {
      ch.send(JSON.stringify({ t: 'rc:quality', quality: quality.value }))
    } catch {
      /* channel closed between check and send Ã¢ÂÂ drop */
    }
  }

  /** rc.130 Ã¢ÂÂ ask the agent to force an encoder keyframe (IDR). A decode
   *  worker fires this (its `request-keyframe` message) after it drops
   *  deltas to recover from a decode backlog and needs a fresh resync
   *  point. The agent min-gap-clamps it. No-op if the control channel
   *  isn't open. */
  function requestKeyframe() {
    // The worker fires this after dropping deltas on a decode backlog; the agent
    // forces a fresh IDR so the decoder can resync. The viewer's sustainable-rate
    // feedback (rc.188, `sendDecodeStat`) is what makes the agent slow down Ã¢ÂÂ
    // this stays purely as the resync trigger.
    const ch = channels.control
    if (!ch || ch.readyState !== 'open') return
    try {
      ch.send(JSON.stringify({ t: 'rc:keyframe' }))
    } catch {
      /* channel closed between check and send Ã¢ÂÂ drop */
    }
  }

  /** rc.188 Ã¢ÂÂ push the viewer's measured decode rate + a struggling bit to the
   *  agent over the control DC. Sent once per stats window from the active
   *  decode worker's `stats` message. No-op while the channel is closed. */
  function sendDecodeStat(
    fps: number,
    struggling: boolean,
    age?: { avgMs: number; minMs: number } | null,
    probeRttMs?: number | null,
    link?: { rxBps: number; queueMs: number | null } | null,
    arrival?: { avgMs: number } | null,
  ) {
    const ch = channels.control
    if (!ch || ch.readyState !== 'open') return
    try {
      ch.send(
        JSON.stringify(decodeStatWireMessage(fps, struggling, age, probeRttMs, link, arrival)),
      )
    } catch {
      /* channel closed between check and send Ã¢ÂÂ drop */
    }
  }

  /** rc.188 Ã¢ÂÂ fold one decode-worker `stats` message into the agent feedback.
   *  `framesDroppedBacklog` is a cumulative counter, so a positive delta since
   *  last window means the viewer dropped frames to a backlog THIS window; a
   *  decode queue > 1 means it's backing up even before it had to drop. Either
   *  is "struggling". */
  function handleDecoderStats(m: {
    fps?: number
    framesDroppedBacklog?: number
    decodeQueueSize?: number
    age?: HopWindow | null
    /** FR-70 M0 — the window's age at arrival (null until the probe locks). */
    arrival?: HopWindow | null
    /** FR-59 P3 — bytes/s the worker actually received this window. */
    bitrateBps?: number
    /** FR-59 P3 — ms the transit queue grew this window; `null`/absent =
     *  fewer than two frames arrived, which is no-signal, not stability. */
    queueMs?: number | null
  }) {
    const drops = typeof m.framesDroppedBacklog === 'number' ? m.framesDroppedBacklog : 0
    const delta = Math.max(0, drops - lastBacklogDrops)
    lastBacklogDrops = drops
    const queue = typeof m.decodeQueueSize === 'number' ? m.decodeQueueSize : 0
    // A window is "bad" when we dropped frames to a backlog, OR the queue is
    // deep enough that we're about to (the worker drops at queue > maxQueue).
    // P6 Ã¢ÂÂ the struggling bit needs a SUSTAINED run of bad windows (default
    // 2 consecutive; `roomler-rc-struggle-windows=1` restores the legacy
    // instantaneous rule). P1's field read showed a healthy viewer parks at
    // queue 0, so a single-window blip (a big IDR landing, a GPU hiccup) was
    // a false positive that cost ~20 s of lazily-recovered reduced fps.
    const bad = delta > 0 || queue > flowParams.struggleQueue
    // FR-15 — ride the window's paint age along. Present only once the
    // clock probe has locked and frames actually painted (n > 0); the
    // agent treats its absence as "no signal", not as a 0 ms age.
    const age = m.age && m.age.n > 0 ? { avgMs: m.age.avgMs, minMs: m.age.minMs } : null
    // FR-59 P3 — the link report. `bitrateBps` is the worker's own count of
    // bytes it RECEIVED this window (it already computed it for the stats
    // pill), and `queueMs` is how much the transit queue grew. Both come
    // from the worker's local clock, so unlike `age` they survive a link
    // whose congestion biases the clock probe.
    const link =
      typeof m.queueMs === 'number'
        ? { rxBps: typeof m.bitrateBps === 'number' ? m.bitrateBps : 0, queueMs: m.queueMs }
        : null
    // FR-70 M0 — the age at arrival, present under the same conditions as
    // `age` (probe locked, frames painted).
    const arrival = age && m.arrival && m.arrival.n > 0 ? { avgMs: m.arrival.avgMs } : null
    sendDecodeStat(
      typeof m.fps === 'number' ? m.fps : 0,
      struggleWindow.observe(bad),
      age,
      clockBest?.rttMs ?? null,
      link,
      arrival,
    )
  }

  /** Update the controller's quality preference, persist it, and push
   *  the new value to the agent. No-ops (other than the persist) if the
   *  control channel isn't open yet Ã¢ÂÂ the onopen handler will re-send. */
  function setQuality(q: RcQuality) {
    quality.value = q
    persistQuality(q)
    sendQualityPreference()
  }

  /** Force a specific codec for the next session. Pass `null` to clear
   *  the override. Takes effect on the next `connect()` Ã¢ÂÂ live sessions
   *  keep whatever SDP they negotiated at start. Persisted to
   *  localStorage so the preference survives a reload. */
  function setPreferredCodec(c: RcPreferredCodec | null) {
    preferredCodec.value = c
    persistPreferredCodec(c)
  }

  /** Update the stage render mode. Takes effect immediately Ã¢ÂÂ CSS
   *  bindings + input coordinate mapping both switch live. */
  function setScaleMode(m: RcScaleMode) {
    scaleMode.value = m
    persistScaleMode(m)
  }

  /** Update the custom-scale percent (clamped to [5, 1000]). Takes
   *  effect immediately even when `scaleMode !== 'custom'`; switching
   *  back to custom picks up the latest value. */
  function setScaleCustomPercent(n: number) {
    // One decimal: FR-74 P4 — exact 1:1 at 150 % display scaling is 66.7 %.
    const clamped = Math.round(Math.max(5, Math.min(1000, n)) * 10) / 10
    scaleCustomPercent.value = clamped
    persistScalePct(clamped)
  }

  /** Send the current resolution preference over the control DC.
   *  Safe to call while the channel is closed Ã¢ÂÂ no-op until open; the
   *  `channels.control.onopen` handler calls this automatically so a
   *  page reload re-emits the stored preference without user action. */
  function sendResolutionPreference() {
    const ch = channels.control
    if (!ch || ch.readyState !== 'open') return
    const msg = resolutionWireMessage(resolution.value)
    if (!msg) return
    try {
      ch.send(JSON.stringify(msg))
    } catch {
      /* channel closed between check and send Ã¢ÂÂ drop */
    }
  }

  /** rc.191 Ã¢ÂÂ send a display-match request over the control DC: the agent
   *  switches its display to the largest mode fitting `dims` (viewer stage
   *  in physical px) and restores on `null` / channel close. Held while
   *  the channel is not open yet, and sent from its `onopen` (#2638). */
  function sendDisplayMatch(dims: { width: number; height: number } | null) {
    const ch = channels.control
    if (!ch || ch.readyState !== 'open') {
      // #2638 - not open yet: `channels.control.onopen` sends it.
      heldDisplayMatch.hold(dims)
      return
    }
    heldDisplayMatch.clear()
    try {
      ch.send(JSON.stringify(displayMatchWireMessage(dims)))
    } catch {
      /* channel closed between check and send Ã¢ÂÂ drop */
    }
  }

  /** rc.227 Ã¢ÂÂ ask the agent to switch the HOST's active keyboard
   *  layout (the Settings picker). `hkl` must come from
   *  `remoteLayout.installed[].hkl`. No explicit ack: the agent's
   *  re-sampled `rc:layout` push updates `remoteLayout`, and a
   *  lost/refused switch visibly snaps the picker back. */
  function setRemoteLayout(hkl: string) {
    const ch = channels.control
    if (!ch || ch.readyState !== 'open') return
    const msg = layoutSetWireMessage(hkl)
    if (!msg) return
    try {
      ch.send(JSON.stringify(msg))
    } catch {
      /* channel closed between check and send Ã¢ÂÂ drop */
    }
  }

  /** Update the controller's remote-resolution preference and push to
   *  the agent. For `fit` + `custom`, `width`/`height` are required;
   *  for `original`, they're ignored. Persisted per-agent so the
   *  choice survives reloads without bleeding across machines. */
  function setResolution(next: RcResolutionSetting) {
    resolution.value = next
    // rc.190 (A1) Ã¢ÂÂ remember that the user picked THIS session. Before
    // this flag, a dropdown pick made BEFORE Connect was (a) never
    // persisted (`resolutionAgentId` is null until connect()) and then
    // (b) CLOBBERED by connect()'s readStoredResolution restore Ã¢ÂÂ the
    // field-reported "initial resolution selection doesn't work, I must
    // connect at original THEN change it" bug.
    resolutionUserPickedThisSession = true
    if (resolutionAgentId) persistResolution(resolutionAgentId, next)
    sendResolutionPreference()
  }

  /** FR-119 P1 — send the frame-rate pick over the control DC, to an agent that
   *  advertises `fps-high` only: an older one cannot parse `rc:fps`. No-op while
   *  the channel is closed; `channels.control.onopen` calls this, so a reload
   *  re-asks without a click. The answer comes back in `rc:video-info`. */
  function sendFrameRatePreference() {
    if (!agentOffersHighRefresh(agent?.value?.capabilities?.video)) return
    sendControl(fpsWireMessage(frameRate.value))
  }

  /** FR-119 P1 — the viewer picked a frame rate. */
  function setFrameRate(next: FrameRate) {
    frameRate.value = next
    persistFrameRate(next)
    sendFrameRatePreference()
  }

  /** FR-119 P1 — the agent's answer, from the latest `rc:video-info`; `null`
   *  from an agent without `fps-high`. */
  const frameRateAnswer = computed(() => frameRateAnswerOf(videoInfo.value))

  /** Switch render path. Only takes effect on the next `connect()` Ã¢ÂÂ
   *  switching mid-session would require tearing down the receiver
   *  transform and replacing the DOM element the video paints into,
   *  which is more disruption than "reconnect to apply". Persisted
   *  per-browser. If WebCodecs isn't supported on this browser and
   *  the caller asks for `webcodecs`, we clamp to `video` silently so
   *  a stored preference from a different browser doesn't brick the
   *  viewer. */
  function setRenderPath(p: RcRenderPath) {
    const next = p === 'webcodecs' && !webcodecsSupported.value ? 'video' : p
    renderPath.value = next
    persistRenderPath(next)
  }

  /** Switch video transport. Only takes effect on the next `connect()`
   *  Ã¢ÂÂ the choice is baked into the rc:session.request payload. If the
   *  caller asks for `data-channel-vp9-444` but `vp9_444Supported` is
   *  false (older browser, or the async probe hasn't resolved yet),
   *  we still persist the preference so the toggle reflects the user
   *  intent; the actual transport negotiation falls back to webrtc
   *  on the agent side when its caps don't include the field. */
  function setVideoTransport(t: RcVideoTransport) {
    videoTransport.value = t
    persistVideoTransport(t)
  }

  /** Toggle opt-in host-audio reception. Only takes effect on the next
   *  `connect()` Ã¢ÂÂ the choice is baked into the `recvonly` audio
   *  transceiver + the request's `audio_enabled` field, both fixed at
   *  offer time. Persisted per-browser. */
  function setAudioEnabled(on: boolean) {
    audioEnabled.value = on
    persistAudioEnabled(on)
  }

  /** Retry playback of the received host-audio stream after the browser
   *  blocked autoplay-with-sound. The view calls this from a user
   *  gesture (the "unmute" button click) so the browser's autoplay
   *  policy is satisfied. The actual `<audio>.play()` lives in the
   *  view; here we just clear the blocked flag so the view's watcher
   *  re-attempts. Idempotent + safe when no audio is active. */
  function resumeAudioPlayback() {
    audioAutoplayBlocked.value = false
  }

  /** rc.62 Ã¢ÂÂ switch VP9 chroma preference. Only takes effect on the
   *  next `connect()` Ã¢ÂÂ the choice is baked into the
   *  `rc:session.request.chroma_pref` field. Older agents that don't
   *  understand the field ignore it and fall back to their own
   *  `ROOMLERD_VP9_CHROMA` default (= no-op). */
  function setVp9Chroma(c: Vp9ChromaPref) {
    vp9Chroma.value = c
    persistVp9Chroma(c)
  }

  /** Send the current `rc:priority` dial over the control DC. Safe to call
   *  while closed Ã¢ÂÂ no-op until open; the control `onopen` handler calls it so
   *  a reload re-emits the stored dial without user action. */
  function sendPriorityPreference() {
    const ch = channels.control
    if (!ch || ch.readyState !== 'open') return
    try {
      ch.send(JSON.stringify(priorityWireMessage(priority.value)))
    } catch {
      /* channel closed between check and send Ã¢ÂÂ drop */
    }
  }

  /** Update the Priority dial, persist it, and push it to the agent. Unlike
   *  the codec/transport picks, this takes effect LIVE Ã¢ÂÂ the agent re-resolves
   *  the relay resolution cap on the next encoded frame. */
  function setPriority(p: RcPriority) {
    priority.value = p
    persistPriority(p)
    sendPriorityPreference()
  }

  /** Toggle the loopback-TURN corp-relay opt-in (Phase 2). Takes effect on the
   *  next `connect()`. */
  function setLocalRelayEnabled(on: boolean) {
    localRelayEnabled.value = on
    persistLocalRelay(on)
  }

  /** Probe the local enrolled agent's loopback TURN endpoint. Returns its
   *  descriptor, or `null` on any failure (no local agent, feature off,
   *  Private-Network-Access blocked, non-2xx, timeout) Ã¢ÂÂ all graceful, so a
   *  host WITHOUT a local agent silently keeps the normal coturn path. Loopback
   *  fetch is exempt from mixed-content blocking; the agent's endpoint must
   *  answer the PNA CORS preflight for HTTPSÃ¢ÂÂlocalhost on newer Chrome. */
  async function probeLocalRelay(): Promise<LocalRelayDescriptor | null> {
    // Walk the candidate range Ã¢ÂÂ with multiple agents on the host the
    // descriptor may be served on a fallback port. First valid
    // descriptor wins (any agent's local TURN works for the relay).
    for (const port of LOCAL_RELAY_PROBE_PORTS) {
      const ctl = new AbortController()
      const timer = setTimeout(() => ctl.abort(), 800)
      try {
        const res = await fetch(`http://127.0.0.1:${port}/rc-local-turn`, { signal: ctl.signal })
        if (res.ok) {
          const desc = parseLocalRelayDescriptor(await res.json())
          if (desc) return desc
        }
      } catch {
        // Nothing on this port Ã¢ÂÂ next.
      } finally {
        clearTimeout(timer)
      }
    }
    return null
  }

  /** The unified Codec picker as a computed over the four underlying refs.
   *  `get` derives the current choice; `set` applies the full tuple through
   *  the existing setters (so persistence + connect-time wiring are unchanged).
   *  Takes effect on the next `connect()`, like the transport/chroma refs it
   *  drives. Also records the pick per agent once `codecAgentId` is known
   *  ("auto" clears that agent's override). */
  const codecChoice = computed<RcCodecChoice>({
    get: () => settingsToCodecChoice(videoTransport.value, vp9Chroma.value),
    set: (choice) => {
      const s = codecChoiceToSettings(choice, { h264Rtp: storedH264Rtp() })
      setVideoTransport(s.videoTransport)
      setVp9Chroma(s.chroma)
      setPreferredCodec(s.preferredCodec)
      setRenderPath(s.renderPath)
      codecUserPickedThisSession = true
      if (codecAgentId) persistCodecChoice(codecAgentId, choice)
    },
  })

  /** Persist-free twin of the `codecChoice` setter, used ONLY by the
   *  connect-time per-agent restore: writes the four refs directly so a
   *  stored override for agent X never leaks into the four GLOBAL
   *  localStorage keys (which stay the cross-agent default). Mirrors
   *  `setRenderPath`'s webcodecs-support fallback. */
  function applyCodecChoiceSettings(choice: RcCodecChoice) {
    const s = codecChoiceToSettings(choice, { h264Rtp: storedH264Rtp() })
    videoTransport.value = s.videoTransport
    vp9Chroma.value = s.chroma
    preferredCodec.value = s.preferredCodec
    renderPath.value =
      s.renderPath === 'webcodecs' && !webcodecsSupported.value ? 'video' : s.renderPath
  }

  /** Install the receiver transform EAGERLY (at pc.ontrack time) so
   *  Chrome routes encoded frames to the worker from the very first
   *  RTP packet. The worker decodes into a null sink until a canvas
   *  arrives via `attachCanvasToWorker()`; once the canvas lands, it
   *  transfers control + the worker starts painting. Previously we
   *  waited for the canvas before installing the transform, which
   *  looked like a race Ã¢ÂÂ some Chrome builds seem to lock frames
   *  onto the default decoder when the transform is assigned after
   *  the track has already started producing. */
  function installWebCodecsTransform(receiver: RTCRtpReceiver): boolean {
    const g = globalThis as unknown as {
      RTCRtpScriptTransform?: new (worker: Worker, opts: unknown) => unknown
    }
    const TransformCtor = g.RTCRtpScriptTransform
    if (typeof TransformCtor !== 'function') return false
    // Chrome (Ã¢ÂÂ¤ 131 at least) installs RTCRtpScriptTransform on an
    // HEVC receiver without complaint but bypasses it Ã¢ÂÂ frames go
    // straight to the default decoder and our TransformStream never
    // sees them. Observed 2026-04-24 on Intel UHD + real HEVC track:
    // `receiver.getStats()` showed framesReceived + framesDecoded
    // climbing normally while the worker's `first-encoded-frame`
    // message never fired. Until Chrome closes that gap, auto-fall-
    // back to the `<video>` path for HEVC so the user sees video
    // instead of a black canvas.
    const sdpCodec = codecFromSdp(pc?.currentRemoteDescription?.sdp)
    const receiverCodec = shortCodecFromReceiver(receiver)
    const codec = sdpCodec ?? receiverCodec
    if (codec === 'h265') {
      console.warn(
        '[rc] webcodecs path skipped Ã¢ÂÂ Chrome does not forward HEVC frames to RTCRtpScriptTransform. Falling back to <video>. Use the Codec toolbar to force H.264 for a guaranteed WebCodecs path.',
      )
      return false
    }
    // rc.43 Ã¢ÂÂ Chrome 148+ regression: RTCRtpScriptTransform attaches +
    // configure() reports success but encoded frames are never delivered
    // to the transformer's readable; the worker's 3 s watchdog catches it
    // and tears down, but Chrome also holds frames off the default path
    // so the <video> fallback renders blank for 1-2 min. Pre-empt the
    // broken activation so the <video> path stays unobstructed from the
    // start.
    if (isChromeWithBrokenScriptTransform()) {
      console.warn(
        '[rc] webcodecs path skipped Ã¢ÂÂ Chrome 148+ regressed RTCRtpScriptTransform frame delivery. Falling back to <video>. See useRemoteControl.ts::isChromeWithBrokenScriptTransform for details.',
      )
      return false
    }
    let worker: Worker
    try {
      worker = new Worker(
        new URL('../workers/rc-webcodecs-worker.ts', import.meta.url),
        { type: 'module' },
      )
    } catch (err) {
      console.warn('[rc] worker construction failed', err)
      return false
    }
    worker.onmessage = (ev) => {
      const msg = ev.data as Record<string, unknown>
      if (!msg || typeof msg.type !== 'string') return
      if (msg.type === 'bench-probe') {
        onBenchProbe(msg.seq, msg.paintedAt, 'webcodecs')
        return
      }
      if (msg.type === 'first-frame' && typeof msg.width === 'number' && typeof msg.height === 'number') {
        mediaIntrinsicW.value = msg.width
        mediaIntrinsicH.value = msg.height
        markConnect('first_frame')
        logConnectTiming('first-frame')
        console.info('[rc] webcodecs first frame', msg.width, 'x', msg.height)
      } else if (msg.type === 'transform-active') {
        console.info('[rc] webcodecs transform active', msg)
      } else if (msg.type === 'first-encoded-frame' || msg.type === 'early-encoded-frame') {
        console.info('[rc] webcodecs encoded frame', msg)
      } else if (msg.type === 'reader-heartbeat') {
        console.info('[rc] webcodecs heartbeat', msg)
      } else if (msg.type === 'watchdog') {
        // Chrome's RTCRtpScriptTransform silently drops frames for
        // some codec/version combos (HEVC Ã¢ÂÂ¤ Chrome 131, also H.264
        // in some 2026-04-26 builds). The default decoder still gets
        // the frames via our pipeThrough Ã¢ÂÂ writable, so the
        // <video> element would render fine Ã¢ÂÂ we just need to swap
        // the DOM. Tear down the worker; webcodecsActive flips to
        // false; the view's `isWebCodecsRender` computed reverts;
        // Vue mounts <video> and the existing srcObject watcher
        // wires the stream. No reconnect needed.
        console.warn('[rc] webcodecs watchdog fired Ã¢ÂÂ auto-fallback to <video>', msg)
        stopWebCodecsPath()
      } else if (
        msg.type === 'decoder-error'
        || msg.type === 'decoder-configure-error'
        || msg.type === 'decode-error'
        || msg.type === 'reader-error'
        || msg.type === 'pipe-error'
      ) {
        // rc.43 Ã¢ÂÂ pre-rc.43 we only logged. Decoder errors after a
        // successful configure() (Chrome 148 VP9 profile-1 path,
        // mid-session codec change) would leave the canvas blank with
        // no recovery. Tear down so the view re-mounts <video> and the
        // standard RTP path takes over.
        console.warn('[rc] webcodecs worker error Ã¢ÂÂ auto-fallback to <video>', msg)
        stopWebCodecsPath()
      }
    }
    console.info('[rc] webcodecs path activating; codec:', codec, '(sdp:', sdpCodec, ' receiver:', receiverCodec, ')')
    try {
      ;(receiver as unknown as { transform: unknown }).transform = new TransformCtor(
        worker,
        { codec },
      )
    } catch (err) {
      console.warn('[rc] setting receiver.transform failed', err)
      worker.terminate()
      return false
    }
    webcodecsWorker = worker
    webcodecsActive.value = true
    // If the canvas is already mounted, attach it now; otherwise
    // the watcher picks it up when it lands.
    if (webcodecsCanvasEl.value) {
      attachCanvasToWorker(webcodecsCanvasEl.value)
    }
    // Kick a getStats diagnostic to confirm whether RTP is actually
    // flowing to this receiver Ã¢ÂÂ if bytesReceived rises but the
    // worker never posts `first-encoded-frame`, Chrome is dropping
    // frames before the transform.
    scheduleInboundRtpDiagnostic(receiver)
    return true
  }

  /** Hand an OffscreenCanvas to the worker so it can start painting.
   *  Returns false on transfer failure. Called immediately from
   *  `installWebCodecsTransform` when the canvas is already there,
   *  or later from the `webcodecsCanvasEl` watcher. */
  function attachCanvasToWorker(canvasEl: HTMLCanvasElement): boolean {
    if (!webcodecsWorker) return false
    let offscreen: OffscreenCanvas
    try {
      offscreen = canvasEl.transferControlToOffscreen()
    } catch (err) {
      console.warn('[rc] transferControlToOffscreen failed', err)
      return false
    }
    try {
      webcodecsWorker.postMessage(
        { type: 'init-canvas', canvas: offscreen, bench: sessionBench },
        [offscreen],
      )
      console.info('[rc] webcodecs: canvas attached to worker')
      return true
    } catch (err) {
      console.warn('[rc] worker init-canvas post failed', err)
      return false
    }
  }

  function scheduleInboundRtpDiagnostic(receiver: RTCRtpReceiver) {
    let ticks = 0
    const interval = setInterval(async () => {
      ticks += 1
      if (ticks > 5 || !webcodecsActive.value) {
        clearInterval(interval)
        return
      }
      try {
        const stats = await receiver.getStats()
        stats.forEach((r: { type?: string; bytesReceived?: number; framesReceived?: number; framesDecoded?: number }) => {
          if (r.type === 'inbound-rtp') {
            console.info('[rc] webcodecs diag inbound-rtp', {
              tick: ticks,
              bytesReceived: r.bytesReceived,
              framesReceived: r.framesReceived,
              framesDecoded: r.framesDecoded,
            })
          }
        })
      } catch { /* ignore */ }
    }, 1000)
  }

  function stopWebCodecsPath() {
    webcodecsActive.value = false
    if (!webcodecsWorker) return
    try { webcodecsWorker.postMessage({ type: 'close' }) } catch { /* ignore */ }
    try { webcodecsWorker.terminate() } catch { /* ignore */ }
    webcodecsWorker = null
  }

  /** Boot the VP9-444 worker, open the `video-bytes` DataChannel, and
   *  forward incoming binary messages to the worker. Called from
   *  `connect()` only when the browser opted in to
   *  `data-channel-vp9-444` AND VP9 profile 1 decode is supported.
   *  Idempotent Ã¢ÂÂ a second call while a worker exists is a no-op
   *  (wraps the existing channel + worker pair).
   *
   *  The worker self-decodes against an `OffscreenCanvas`. For Y.3
   *  the canvas is synthetic (created here, never displayed); Y.4
   *  hooks the view's `<canvas>` element via
   *  `vp9_444CanvasEl` + a `transferControlToOffscreen()` swap.
   *  Bytes still flow + frames still decode in the synthetic case,
   *  which is what e2e + integration tests assert against.
   *
   *  Returns the worker handle so tests can drive it directly.
   *
   *  rc.190 Ã¢ÂÂ `codecOverride` reuses this whole path for AV1-over-DC
   *  (`AV1_CODEC_STRING`): identical 13-byte wire framing, identical DC
   *  label, the worker's VideoDecoder just gets a different codec
   *  string. Only one DC video transport is active per session, so the
   *  shared worker/stats plumbing can't collide. */
  // Ã¢ÂÂÃ¢ÂÂ 2026-07-24 freeze triangulation (round 3) Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ
  // Field: 3-5 s video freezes with a SILENT console Ã¢ÂÂ the worker-side stall
  // detector needs chunks to arrive to run at all, so silence is ambiguous
  // between "bytes stopped arriving" (network/SCTP) and "the main thread was
  // blocked so nothing was forwarded" (jank). These two detectors split that:

  /** Network-side delivery-gap detector. `dc.onmessage` runs on the main
   *  thread as bytes come off SCTP; a multi-second silence here (logged once,
   *  on resume) means bytes were NOT arriving Ã¢ÂÂ network/SCTP layer. */
  let lastVideoDcMsgMs = 0
  function noteVideoDcDelivery() {
    const now = performance.now()
    if (lastVideoDcMsgMs > 0 && now - lastVideoDcMsgMs > 1500) {
      console.warn(
        '[rc] video DC delivery gap',
        Math.round(now - lastVideoDcMsgMs),
        'ms Ã¢ÂÂ no video bytes arrived from the network for this long',
      )
    }
    lastVideoDcMsgMs = now
  }

  /** Self-measuring main-thread jank detector. A 250 ms interval whose tick
   *  arrives late by >1.5 s means the main thread (which also forwards DC
   *  chunks to the worker) was blocked that long Ã¢ÂÂ the freeze is page jank,
   *  not network and not the decoder. */
  let jankTimer: ReturnType<typeof setInterval> | null = null
  let jankLastTickMs = 0
  function startJankDetector() {
    if (jankTimer) return
    jankLastTickMs = performance.now()
    jankTimer = setInterval(() => {
      const now = performance.now()
      const gap = now - jankLastTickMs
      if (gap > 1500) {
        console.warn(
          '[rc] MAIN-THREAD STALL ~',
          Math.round(gap),
          'ms Ã¢ÂÂ the page (and DCÃ¢ÂÂworker chunk forwarding) was blocked this long',
        )
      }
      jankLastTickMs = now
    }, 250)
    startLongTaskObserver()
  }
  function stopJankDetector() {
    if (jankTimer) {
      clearInterval(jankTimer)
      jankTimer = null
    }
    stopLongTaskObserver()
  }

  // P1 Ã¢ÂÂ main-thread long-task accounting. Counts blocking tasks Ã¢ÂÂ¥50 ms
  // while a DC path is active; snapshotted into `decodeDiag` on each worker
  // stats window so main-thread jank sits next to the worker's hop timings
  // (the number that decides whether the fps ceiling is main-thread-bound).
  let longTaskObserver: PerformanceObserver | null = null
  let longTaskCount = 0
  let longTaskMs = 0
  let longTaskWindowStartMs = 0
  function startLongTaskObserver() {
    if (longTaskObserver) return
    try {
      longTaskObserver = new PerformanceObserver((list) => {
        for (const e of list.getEntries()) {
          longTaskCount++
          longTaskMs += e.duration
        }
      })
      longTaskObserver.observe({ type: 'longtask', buffered: false })
      longTaskWindowStartMs = performance.now()
    } catch {
      longTaskObserver = null // 'longtask' unsupported Ã¢ÂÂ diag shows zeros
    }
  }
  function stopLongTaskObserver() {
    try {
      longTaskObserver?.disconnect()
    } catch {
      /* ignore */
    }
    longTaskObserver = null
    longTaskCount = 0
    longTaskMs = 0
    longTaskWindowStartMs = 0
  }
  function snapshotLongTasks(): { perSec: number; msPerSec: number } {
    const now = performance.now()
    const elapsedSec =
      longTaskWindowStartMs > 0 ? Math.max(0.2, (now - longTaskWindowStartMs) / 1000) : 1
    const perSec = Math.round((longTaskCount / elapsedSec) * 10) / 10
    const msPerSec = Math.round((longTaskMs / elapsedSec) * 10) / 10
    longTaskCount = 0
    longTaskMs = 0
    longTaskWindowStartMs = now
    return { perSec, msPerSec }
  }

  /** P1 Ã¢ÂÂ fold one worker stats window into `decodeDiag` for the diag HUD. */
  function updateDecodeDiag(m: {
    paint?: HopWindow
    fwd?: HopWindow
    decode?: HopWindow
    age?: HopWindow | null
    arrival?: HopWindow | null
    viewer?: HopWindow | null
    outGapMaxMs?: number
    decodeQueueSize?: number
    framesDroppedBacklog?: number
    ctxMode?: string
  }) {
    const lt = snapshotLongTasks()
    decodeDiag.value = {
      paint: m.paint ?? null,
      fwd: m.fwd ?? null,
      decode: m.decode ?? null,
      age: m.age ?? null,
      arrival: m.arrival ?? null,
      viewer: m.viewer ?? null,
      probeRttMs: clockBest?.rttMs ?? null,
      outGapMaxMs: typeof m.outGapMaxMs === 'number' ? m.outGapMaxMs : 0,
      queue: typeof m.decodeQueueSize === 'number' ? m.decodeQueueSize : 0,
      droppedTotal: typeof m.framesDroppedBacklog === 'number' ? m.framesDroppedBacklog : 0,
      ctxMode: typeof m.ctxMode === 'string' ? m.ctxMode : 'legacy',
      longTasksPerSec: lt.perSec,
      longTaskMsPerSec: lt.msPerSec,
    }
  }

  function startVp9_444Path(codecOverride?: string): Worker | null {
    if (vp9_444Worker) return vp9_444Worker
    if (!pc) return null
    let worker: Worker
    try {
      worker = new Worker(
        new URL('../workers/rc-vp9-444-worker.ts', import.meta.url),
        { type: 'module' },
      )
    } catch (err) {
      console.warn('[rc] vp9-444 worker construction failed', err)
      return null
    }
    worker.onmessage = (ev) => {
      const msg = ev.data as Record<string, unknown> | undefined
      if (!msg || typeof msg.type !== 'string') return
      if (msg.type === 'bench-probe') {
        onBenchProbe(msg.seq, msg.paintedAt, 'vp9-444')
        return
      }
      if (msg.type === 'request-keyframe') {
        // rc.130 Ã¢ÂÂ worker dropped deltas on a decode backlog; ask the agent
        // for a fresh IDR so it can resync.
        requestKeyframe()
        return
      }
      if (msg.type === 'first-frame'
        && typeof msg.width === 'number'
        && typeof msg.height === 'number') {
        mediaIntrinsicW.value = msg.width
        mediaIntrinsicH.value = msg.height
        vp9_444FramesDecoded.value = Math.max(vp9_444FramesDecoded.value, 1)
        markConnect('first_frame')
        logConnectTiming('first-frame')
        console.info('[rc] vp9-444 first frame', msg.width, 'x', msg.height)
      } else if (msg.type === 'decoder-configured') {
        // `pref` (round 3) = the hardwareAcceleration ACTUALLY passed to
        // configure() Ã¢ÂÂ proves whether the roomler-rc-decode-pref A/B took.
        // FR-80 — the worker's log prefix is a legacy name; `msg.codec` is
        // the truth (this worker decodes VP9, AV1 and H.264). The pill reads
        // it until the agent names its encoder.
        dcDecoderCodec.value = typeof msg.codec === 'string' ? msg.codec : null
        console.info('[rc] vp9-444 decoder configured', msg.codec, 'hwAccel:', msg.pref ?? 'no-preference')
      } else if (msg.type === 'decoder-error'
        || msg.type === 'decoder-configure-error'
        || msg.type === 'decode-error') {
        // rc.43 Ã¢ÂÂ Chrome 148 field repro: VideoDecoder.configure() with
        // vp09.01.10.08 (profile 1, 4:4:4 8-bit) reports success but the
        // first real frame errors out with "Unsupported configuration"
        // and the decoder closes; every subsequent frame logs
        // "Cannot call 'decode' on a closed codec" indefinitely. Pre-
        // rc.43 just logged the warn Ã¢ÂÂ the canvas stayed blank until the
        // user disconnected. Tear down so the view re-mounts <video> and
        // the standard RTP H.264 track (which the agent sends in parallel
        // to the DC path) renders normally.
        console.warn('[rc] vp9-444 worker', msg.type, msg.error, 'Ã¢ÂÂ auto-fallback to <video>')
        // Same ban-and-renegotiate as the HEVC handler: a pre-first-frame
        // failure means the probe lied (this worker serves the vp9-444,
        // av1 AND h264 DC transports - ban whichever THIS session
        // negotiated, `sessionDcTransport`). Post-first-frame errors stay
        // transient and keep today's behaviour.
        const vp9NeverDecoded = vp9_444FramesDecoded.value === 0
        const failedTransport = sessionDcTransport
        stopVp9_444Path()
        if (vp9NeverDecoded && failedTransport && failedTransport !== 'auto' && failedTransport !== 'webrtc') {
          failedDcTransports.add(failedTransport)
          // FR-77 — remembered per device × cell across page loads.
          const failedCodec = cellCodecOfTransport(failedTransport)
          if (codecAgentId && failedCodec) {
            rememberCellFailure(codecAgentId, failedCodec, sessionCellChroma, globalThis.navigator?.userAgent ?? '')
          }
          console.warn(`[rc] ${failedTransport} banned for this page (decoder failed before first frame) - reconnecting on the next-best transport`)
          if (lastConnectArgs) scheduleReconnect()
        }
      } else if (msg.type === 'frame-rejected') {
        console.warn('[rc] vp9-444 frame rejected', msg)
      } else if (msg.type === 'awaiting-keyframe') {
        // Round 3 Ã¢ÂÂ parity with the HEVC handler: these worker messages were
        // silently dropped on the VP9 path, hiding gate activity from the
        // console during field freezes.
        console.info('[rc] vp9-444 awaiting keyframe Ã¢ÂÂ dropped', msg.dropped, 'delta(s) while gated')
      } else if (msg.type === 'keyframe-acquired') {
        console.info('[rc] vp9-444 keyframe acquired (dropped', msg.droppedBefore, 'delta(s) before it)')
      } else if (msg.type === 'backlog-drop') {
        console.warn('[rc] vp9-444 backlog drop Ã¢ÂÂ decode queue', msg.queue, 'Ã¢ÂÂ gate re-armed, resync IDR requested (total dropped', msg.dropped, ')')
      } else if (msg.type === 'decode-stall') {
        // 2026-07-24 Ã¢ÂÂ frames are arriving but the decoder produced no
        // output for gapMs with work queued: a decoder/GPU-process stall,
        // NOT transport and NOT the resync gate. Field-diagnosis marker.
        console.warn('[rc] vp9-444 DECODE STALL Ã¢ÂÂ no decoder output for', msg.gapMs, 'ms; queue', msg.queue)
      } else if (msg.type === 'decode-stall-recovered') {
        console.warn('[rc] vp9-444 decode stall recovered after', msg.gapMs, 'ms')
      } else if (msg.type === 'render-fallback') {
        // P7 — GL unavailable/lost for good this session; the worker
        // reverted to the byte-identical 2D paint path.
        console.warn('[rc] vp9-444 FSR unavailable — 2D paint path:', msg.reason)
      } else if (msg.type === 'frame-decoded') {
        // Worker emits this for every decoded frame after the first.
        // Driven by the worker's `output` callback, used by tests +
        // view-side diagnostics.
        vp9_444FramesDecoded.value++
      } else if (msg.type === 'stats') {
        // rc.35 Ã¢ÂÂ rolling-window bitrate / fps / resolution from the
        // worker. Surfaces the actual DC-receive throughput so the
        // operator can confirm rc.33's AIMD-driven bitrate target
        // is pushing the link as expected.
        const m = msg as {
          bitrateBps?: number
          fps?: number
          width?: number
          height?: number
          bytesReceivedTotal?: number
          framesDroppedBacklog?: number
          decodeQueueSize?: number
          framesDecodedTotal?: number
          paint?: HopWindow
          fwd?: HopWindow
          decode?: HopWindow
          // FR-15 — end-to-end paint age window (null until the
          // rc:clock probe locks); rides the decodestat to the agent.
          age?: HopWindow | null
          outGapMaxMs?: number
          ctxMode?: string
          render?: string
          renderW?: number
          renderH?: number
        }
        updateRenderInfo(m)
        vp9_444Stats.value = {
          bitrateBps: typeof m.bitrateBps === 'number' ? m.bitrateBps : 0,
          fps: typeof m.fps === 'number' ? m.fps : 0,
          width: typeof m.width === 'number' ? m.width : 0,
          height: typeof m.height === 'number' ? m.height : 0,
          bytesReceivedTotal: typeof m.bytesReceivedTotal === 'number' ? m.bytesReceivedTotal : 0,
        }
        // P1 Ã¢ÂÂ the per-frame `frame-decoded` message is off by default; keep
        // the diagnostics counter monotonic from the 1 s window total.
        if (typeof m.framesDecodedTotal === 'number') {
          vp9_444FramesDecoded.value = Math.max(vp9_444FramesDecoded.value, m.framesDecodedTotal)
        }
        updateDecodeDiag(m)
        // rc.188 Ã¢ÂÂ feed the agent this viewer's real decode rate so it caps fps.
        handleDecoderStats(m)
      }
    }
    // rc.61 Ã¢ÂÂ pick the codec string based on the agent's advertised
    // chroma format. `'yuv420'` Ã¢ÂÂ VP9 profile 0 (`vp09.00.10.08`),
    // `'yuv444'` (default + pre-rc.61 agents) Ã¢ÂÂ profile 1
    // (`vp09.01.10.08`). Mismatch with the bitstream the agent
    // actually sends would leave the canvas blank.
    //
    // rc.62 Ã¢ÂÂ the user's `vp9Chroma` ref OVERRIDES the agent's
    // advertised default when it's not `'auto'`. The same value was
    // sent as `chroma_pref` in `rc:session.request`, so the agent
    // emits the format we picked.
    let effectiveChroma: string | undefined
    if (vp9Chroma.value === 'yuv420' || vp9Chroma.value === 'yuv444') {
      effectiveChroma = vp9Chroma.value
    } else {
      effectiveChroma = agent?.value?.capabilities?.vp9_chroma
    }
    // rc.190 Ã¢ÂÂ an explicit codec override (the AV1 path) wins over the
    // VP9 chroma-derived string.
    const workerCodec =
      codecOverride ?? (effectiveChroma === 'yuv420' ? 'vp09.00.10.08' : 'vp09.01.10.08')

    // Synthetic OffscreenCanvas Ã¢ÂÂ keeps the worker fully wired even
    // without a view-side canvas. Y.4 swaps in the visible canvas
    // via vp9_444CanvasEl watcher below.
    try {
      const synthetic = new OffscreenCanvas(2, 2)
      worker.postMessage(
        {
          type: 'init-canvas',
          canvas: synthetic,
          codec: workerCodec,
          decodePref: storedDecodePref(),
          ctxMode: storedCtxMode(),
          perFrameMsg: storedPerFrameMsg(),
          maxQueue: flowParams.maxQueue,
          // FR-17 — negotiated per session; see `sessionChunkFraming`.
          chunkFraming: sessionChunkFraming,
          // FR-16 L4 — resolved per session; see `sessionBench`.
          bench: sessionBench,
          // P7 — FSR knobs (sticky across the visible-canvas re-init).
          sharpen: sharpenMode.value,
          sharpness: storedSharpness(),
        },
        [synthetic],
      )
    } catch (err) {
      console.warn('[rc] vp9-444: synthetic OffscreenCanvas init failed', err)
      try { worker.terminate() } catch { /* ignore */ }
      return null
    }
    // Open the DC. Forward binary messages straight through to the
    // worker as ArrayBuffer chunks (transferred, not copied).
    let dc: RTCDataChannel
    try {
      // FR-17 stage B - unordered ONLY when this session negotiated
      // framing; `videoDcOptions` enforces that pairing.
      dc = pc.createDataChannel(
        VP9_444_DC_LABEL,
        videoDcOptions(sessionChunkFraming, storedUnorderedVideo()),
      )
    } catch (err) {
      console.warn('[rc] vp9-444 DC creation failed', err)
      try { worker.terminate() } catch { /* ignore */ }
      return null
    }
    dc.binaryType = 'arraybuffer'
    lastVideoDcMsgMs = 0 // fresh path Ã¢ÂÂ don't count the setup silence as a gap
    startJankDetector()
    dc.onmessage = (ev) => {
      if (!(ev.data instanceof ArrayBuffer)) return
      noteVideoDcDelivery()
      try {
        // P1 Ã¢ÂÂ sentAt stamps the mainÃ¢ÂÂworker forwarding hop (epoch-absolute).
        worker.postMessage(
          { type: 'chunk', bytes: ev.data, sentAt: performance.timeOrigin + performance.now() },
          [ev.data],
        )
      } catch (err) {
        console.warn('[rc] vp9-444 worker post failed', err)
      }
    }
    dc.onopen = () => {
      markConnect('dc_open')
      console.info('[rc] vp9-444 DC opened')
    }
    dc.onclose = () => {
      console.info('[rc] vp9-444 DC closed')
    }
    channels.videoBytes = dc
    vp9_444Worker = worker
    vp9_444Active.value = true
    // FR-1 P7 — the clock offset may already be locked (probe started with
    // the control DC); hand it to the fresh worker.
    pushClockOffset()
    return worker
  }

  function stopVp9_444Path() {
    vp9_444Active.value = false
    vp9_444FramesDecoded.value = 0
    // P7 — drop the viewport reporter + render-path mirror with the path.
    vp9ViewportCleanup?.()
    vp9ViewportCleanup = null
    renderInfo.value = null
    if (!vp9_444Worker) return
    try { vp9_444Worker.postMessage({ type: 'close' }) } catch { /* ignore */ }
    try { vp9_444Worker.terminate() } catch { /* ignore */ }
    vp9_444Worker = null
  }

  /** When the view mounts a real `<canvas>`, swap it in for the
   *  synthetic OffscreenCanvas the worker started with. The worker
   *  treats `init-canvas` as idempotent Ã¢ÂÂ second call replaces the
   *  paint target. */
  watch(vp9_444CanvasEl, (el) => {
    vp9ViewportCleanup?.()
    vp9ViewportCleanup = null
    if (!el || !vp9_444Worker) return
    try {
      const off = el.transferControlToOffscreen()
      vp9_444Worker.postMessage({ type: 'init-canvas', canvas: off }, [off])
      // P7 — start reporting the element box for the FSR sizing policy.
      vp9ViewportCleanup = startViewportReporter(el, vp9_444Worker)
    } catch (err) {
      console.warn('[rc] vp9-444: transferControlToOffscreen failed', err)
    }
  })

  /** rc.78 Ã¢ÂÂ boot the HEVC worker, open the `video-bytes` DataChannel,
   *  and forward incoming binary messages to the worker. Mirror of
   *  `startVp9_444Path` for the HEVC transport. Called from
   *  `connect()` only when the browser opted in to
   *  `data-channel-hevc` AND `hevcSupported` resolved true.
   *
   *  Returns the worker handle so tests can drive it directly. */
  function startHevcPath(codecOverride?: string): Worker | null {
    if (hevcWorker) return hevcWorker
    if (!pc) return null
    let worker: Worker
    try {
      worker = new Worker(
        new URL('../workers/rc-hevc-worker.ts', import.meta.url),
        { type: 'module' },
      )
    } catch (err) {
      console.warn('[rc] hevc worker construction failed', err)
      return null
    }
    worker.onmessage = (ev) => {
      const msg = ev.data as Record<string, unknown> | undefined
      if (!msg || typeof msg.type !== 'string') return
      if (msg.type === 'bench-probe') {
        onBenchProbe(msg.seq, msg.paintedAt, 'hevc')
        return
      }
      if (msg.type === 'request-keyframe') {
        // rc.130 Ã¢ÂÂ worker dropped deltas on a decode backlog; ask the agent
        // for a fresh IDR so it can resync.
        requestKeyframe()
        return
      }
      if (msg.type === 'first-frame'
        && typeof msg.width === 'number'
        && typeof msg.height === 'number') {
        mediaIntrinsicW.value = msg.width
        mediaIntrinsicH.value = msg.height
        hevcFramesDecoded.value = Math.max(hevcFramesDecoded.value, 1)
        markConnect('first_frame')
        logConnectTiming('first-frame')
        // rc.100 Ã¢ÂÂ the worker now reports the CODED size as width/height and
        // forwards coded/display/visibleRect for field diagnosis. Logging the
        // gap localises the NVDEC HEVC dim mismatch (DEVBOX: agent
        // encodes 2560ÃÂ1600 but display came out 1280ÃÂ720).
        console.info(
          '[rc] hevc first frame', msg.width, 'x', msg.height,
          '| coded', msg.coded, 'display', msg.display, 'visible', msg.visible,
          '| crop', msg.crop, 'rewrapped', msg.rewrapped,
        )
      } else if (msg.type === 'decoder-configured') {
        // `pref` (round 3) Ã¢ÂÂ see the vp9-444 handler.
        dcDecoderCodec.value = typeof msg.codec === 'string' ? msg.codec : null
        console.info('[rc] hevc decoder configured', msg.codec, 'hwAccel:', msg.pref ?? 'no-preference')
      } else if (msg.type === 'decoder-error'
        || msg.type === 'decoder-configure-error'
        || msg.type === 'decode-error') {
        // Mid-session HEVC HW driver hiccup OR the decoder
        // claimed support then rejected real bytes. Tear down so
        // the view re-mounts <video> and the standard RTP path
        // (which the agent sends in parallel) renders normally.
        console.warn('[rc] hevc worker', msg.type, msg.error, 'Ã¢ÂÂ auto-fallback to <video>')
        // A failure BEFORE the first decoded frame means the pre-connect
        // probe was wrong for this browser, and it will be wrong again on
        // the next rank (field: Edge, where MediaCapabilities says HEVC is
        // hardware-smooth while WebCodecs refuses hev1) - ban the transport
        // for this page and re-negotiate NOW instead of leaving a black
        // canvas for the watchdog to find ~10 s later (a DC session's
        // <video> has no parallel RTP samples, so this fallback renders
        // nothing). A post-first-frame error is a transient (driver
        // hiccup) - the same codec may work again on reconnect.
        const hevcNeverDecoded = hevcFramesDecoded.value === 0
        stopHevcPath()
        if (hevcNeverDecoded) {
          failedDcTransports.add('data-channel-hevc')
          // FR-77 — remembered per device × cell (a Rext failure bans only
          // the 4:4:4 cell; the 4:2:0 path is a different decoder profile).
          if (codecAgentId) {
            rememberCellFailure(codecAgentId, 'hevc', sessionCellChroma, globalThis.navigator?.userAgent ?? '')
          }
          console.warn('[rc] data-channel-hevc banned for this page (decoder failed before first frame) - reconnecting on the next-best transport')
          if (lastConnectArgs) scheduleReconnect()
        }
      } else if (msg.type === 'frame-rejected') {
        console.warn('[rc] hevc frame rejected', msg)
      } else if (msg.type === 'awaiting-keyframe') {
        // rc.103 Ã¢ÂÂ the leading-delta gate is dropping deltas while it waits
        // for the first IDR (async-encoder DC-open race). Expected for a
        // few frames right after "hevc DC opened"; a high/growing count
        // means the agent isn't shipping an IDR (check encoder forced-idr).
        console.info('[rc] hevc awaiting keyframe Ã¢ÂÂ dropped', msg.dropped, 'leading delta(s)')
      } else if (msg.type === 'keyframe-acquired') {
        console.info('[rc] hevc first keyframe acquired (dropped', msg.droppedBefore, 'leading delta(s))')
      } else if (msg.type === 'backlog-drop') {
        // Round 3 Ã¢ÂÂ was silently dropped; parity with the vp9-444 handler.
        console.warn('[rc] hevc backlog drop Ã¢ÂÂ decode queue', msg.queue, 'Ã¢ÂÂ gate re-armed, resync IDR requested (total dropped', msg.dropped, ')')
      } else if (msg.type === 'decode-stall') {
        // 2026-07-24 Ã¢ÂÂ see the vp9-444 handler: decoder/GPU-process stall
        // marker (frames arriving, work queued, no output for gapMs).
        console.warn('[rc] hevc DECODE STALL Ã¢ÂÂ no decoder output for', msg.gapMs, 'ms; queue', msg.queue)
      } else if (msg.type === 'decode-stall-recovered') {
        console.warn('[rc] hevc decode stall recovered after', msg.gapMs, 'ms')
      } else if (msg.type === 'render-fallback') {
        // P7 — GL unavailable/lost for good this session; the worker
        // reverted to the byte-identical 2D paint path.
        console.warn('[rc] hevc FSR unavailable — 2D paint path:', msg.reason)
      } else if (msg.type === 'frame-decoded') {
        hevcFramesDecoded.value++
      } else if (msg.type === 'stats') {
        const m = msg as {
          bitrateBps?: number
          fps?: number
          width?: number
          height?: number
          bytesReceivedTotal?: number
          framesDroppedBacklog?: number
          decodeQueueSize?: number
          framesDecodedTotal?: number
          paint?: HopWindow
          fwd?: HopWindow
          decode?: HopWindow
          // FR-15 — end-to-end paint age window (null until the
          // rc:clock probe locks); rides the decodestat to the agent.
          age?: HopWindow | null
          outGapMaxMs?: number
          ctxMode?: string
          render?: string
          renderW?: number
          renderH?: number
        }
        updateRenderInfo(m)
        hevcStats.value = {
          bitrateBps: typeof m.bitrateBps === 'number' ? m.bitrateBps : 0,
          fps: typeof m.fps === 'number' ? m.fps : 0,
          width: typeof m.width === 'number' ? m.width : 0,
          height: typeof m.height === 'number' ? m.height : 0,
          bytesReceivedTotal: typeof m.bytesReceivedTotal === 'number' ? m.bytesReceivedTotal : 0,
        }
        // P1 Ã¢ÂÂ see the vp9-444 handler.
        if (typeof m.framesDecodedTotal === 'number') {
          hevcFramesDecoded.value = Math.max(hevcFramesDecoded.value, m.framesDecodedTotal)
        }
        updateDecodeDiag(m)
        // rc.188 Ã¢ÂÂ feed the agent this viewer's real decode rate so it caps fps.
        handleDecoderStats(m)
      }
    }
    // Synthetic OffscreenCanvas Ã¢ÂÂ keeps the worker fully wired even
    // without a view-side canvas. rc.79+ swaps in the visible canvas
    // via hevcCanvasEl watcher below.
    try {
      const synthetic = new OffscreenCanvas(2, 2)
      worker.postMessage(
        {
          type: 'init-canvas',
          canvas: synthetic,
          // P7 — Rext 4:4:4 sessions override the Main-profile default
          // (hev1.4.10.L153.B0 vs hev1.1.6.L153.B0); undefined keeps it.
          codec: codecOverride,
          decodePref: storedDecodePref(),
          ctxMode: storedCtxMode(),
          perFrameMsg: storedPerFrameMsg(),
          maxQueue: flowParams.maxQueue,
          // FR-17 — negotiated per session; see `sessionChunkFraming`.
          chunkFraming: sessionChunkFraming,
          // FR-16 L4 — resolved per session; see `sessionBench`.
          bench: sessionBench,
          // P7 — FSR knobs (sticky across the visible-canvas re-init).
          sharpen: sharpenMode.value,
          sharpness: storedSharpness(),
        },
        [synthetic],
      )
    } catch (err) {
      console.warn('[rc] hevc: synthetic OffscreenCanvas init failed', err)
      try { worker.terminate() } catch { /* ignore */ }
      return null
    }
    // Open the same `video-bytes` DC the VP9-444 path uses Ã¢ÂÂ the
    // agent's `media_pump_hevc_dc` writes there based on the
    // negotiated_transport. Browser opens unconditionally; the
    // agent stays silent if it picked the WebRTC track instead.
    let dc: RTCDataChannel
    try {
      // FR-17 stage B - unordered ONLY when this session negotiated
      // framing; `videoDcOptions` enforces that pairing.
      dc = pc.createDataChannel(
        VP9_444_DC_LABEL,
        videoDcOptions(sessionChunkFraming, storedUnorderedVideo()),
      )
    } catch (err) {
      console.warn('[rc] hevc DC creation failed', err)
      try { worker.terminate() } catch { /* ignore */ }
      return null
    }
    dc.binaryType = 'arraybuffer'
    lastVideoDcMsgMs = 0 // fresh path Ã¢ÂÂ don't count the setup silence as a gap
    startJankDetector()
    dc.onmessage = (ev) => {
      if (!(ev.data instanceof ArrayBuffer)) return
      noteVideoDcDelivery()
      try {
        // P1 Ã¢ÂÂ sentAt stamps the mainÃ¢ÂÂworker forwarding hop (epoch-absolute).
        worker.postMessage(
          { type: 'chunk', bytes: ev.data, sentAt: performance.timeOrigin + performance.now() },
          [ev.data],
        )
      } catch (err) {
        console.warn('[rc] hevc worker post failed', err)
      }
    }
    dc.onopen = () => {
      markConnect('dc_open')
      console.info('[rc] hevc DC opened')
    }
    dc.onclose = () => {
      console.info('[rc] hevc DC closed')
    }
    channels.videoBytes = dc
    hevcWorker = worker
    hevcActive.value = true
    // FR-1 P7 — the clock offset may already be locked (probe started with
    // the control DC); hand it to the fresh worker.
    pushClockOffset()
    return worker
  }

  function stopHevcPath() {
    hevcActive.value = false
    hevcFramesDecoded.value = 0
    // P7 — drop the viewport reporter + render-path mirror with the path.
    hevcViewportCleanup?.()
    hevcViewportCleanup = null
    renderInfo.value = null
    if (!hevcWorker) return
    try { hevcWorker.postMessage({ type: 'close' }) } catch { /* ignore */ }
    try { hevcWorker.terminate() } catch { /* ignore */ }
    hevcWorker = null
  }

  watch(hevcCanvasEl, (el) => {
    hevcViewportCleanup?.()
    hevcViewportCleanup = null
    if (!el || !hevcWorker) return
    try {
      const off = el.transferControlToOffscreen()
      hevcWorker.postMessage({ type: 'init-canvas', canvas: off }, [off])
      // P7 — start reporting the element box for the FSR sizing policy.
      hevcViewportCleanup = startViewportReporter(el, hevcWorker)
    } catch (err) {
      console.warn('[rc] hevc: transferControlToOffscreen failed', err)
    }
  })

  // Late-canvas watcher. The transform is installed eagerly in
  // pc.ontrack, but the canvas is gated on phase === 'connected'
  // so it mounts after ontrack fires. When it mounts, hand the
  // OffscreenCanvas to the already-running worker so it can start
  // painting what it's been decoding.
  watch(webcodecsCanvasEl, (el) => {
    if (!el || !webcodecsWorker) return
    attachCanvasToWorker(el)
  })

  function startStatsPoll() {
    if (statsTimer !== null) return
    statsTimer = setInterval(async () => {
      if (!pc) return
      // FR-1 P7 — clock probe rides the stats cadence (no-op until the
      // control DC opens; old agents ignore the verb).
      sendClockProbe()
      try {
        const report = await pc.getStats()
        const snap = extractStatsSnapshot(report, statsPrevBytes, statsPrevTsMs)
        stats.value = snap.next
        statsPrevBytes = snap.bytes
        statsPrevTsMs = snap.tsMs
      } catch {
        /* getStats() can reject during teardown Ã¢ÂÂ just wait for next tick */
      }
    }, STATS_POLL_MS)
  }

  /**
   * Decode a `cursor:shape` payload into an `ImageBitmap` and stash
   * it in the cursor shape cache. Fire-and-forget: a failed decode
   * leaves the cache unchanged so the paint loop keeps drawing the
   * previous shape (visually: a brief cursor freeze, not a crash).
   */
  async function applyCursorShape(
    msg: Record<string, unknown>,
  ): Promise<void> {
    const id = Number(msg.id)
    const w = Number(msg.w)
    const h = Number(msg.h)
    const hx = Number(msg.hx)
    const hy = Number(msg.hy)
    const b64 = msg.bgra
    if (!Number.isFinite(id) || !Number.isFinite(w) || !Number.isFinite(h) || typeof b64 !== 'string') {
      return
    }
    // Skip if we already have this shape cached Ã¢ÂÂ agent should only
    // send it on change but defensive.
    if (cursor.value.shapes.has(id)) return
    try {
      const bgra = base64ToBytes(b64)
      if (bgra.length < w * h * 4) return
      // Swizzle BGRA Ã¢ÂÂ RGBA for ImageData. Done in-place on a copy
      // so the original buffer is reusable.
      const rgba = new Uint8ClampedArray(w * h * 4)
      for (let i = 0; i < w * h; i++) {
        rgba[i * 4 + 0] = bgra[i * 4 + 2]! // R
        rgba[i * 4 + 1] = bgra[i * 4 + 1]! // G
        rgba[i * 4 + 2] = bgra[i * 4 + 0]! // B
        rgba[i * 4 + 3] = bgra[i * 4 + 3]! // A
      }
      const imgData = new ImageData(rgba, w, h)
      const bitmap = await createImageBitmap(imgData)
      // Mutate the Map in place + replace the ref to trigger Vue
      // reactivity (shallowRef would be nicer; ref + new object
      // reference works today).
      const cssKw = typeof msg.css === 'string' ? msg.css : undefined
      const shapes = new Map(cursor.value.shapes)
      shapes.set(id, { bitmap, hotspotX: hx, hotspotY: hy, css: cssKw })
      cursor.value = { ...cursor.value, shapes }
    } catch {
      /* decode failed Ã¢ÂÂ skip this shape update */
    }
  }

  function stopStatsPoll() {
    if (statsTimer !== null) {
      clearInterval(statsTimer)
      statsTimer = null
    }
    statsPrevBytes = 0
    statsPrevTsMs = 0
    stats.value = { ...EMPTY_STATS }
  }

  /** Buffer ICE candidates that arrive before we've set a remote
   *  description, otherwise addIceCandidate throws. */
  const pendingRemoteIce: RTCIceCandidateInit[] = []
  let remoteDescriptionSet = false

  // Multi-user P3: THIS composable's unsubscribers. Registration is
  // multi-subscriber now (ws.ts Set-based registry), so teardown must
  // remove only OUR handlers — the old type-wide offRcMessage nuked a
  // sibling composable's live handlers (device modal over the RC page,
  // HMR double-mount).
  let rcUnsubs: Array<() => void> = []

  function installRcHandlers() {
    removeRcHandlers() // idempotent re-install (reconnect path)
    const on = (t: string, h: (msg: any) => void) => {
      rcUnsubs.push(ws.onRcMessage(t, h))
    }
    on('rc:session.created', (msg) => {
      // Only accept while we actually have a request in flight Ã¢ÂÂ a
      // late/stale create must not resurrect an abandoned attempt.
      // (2026-08-05 winhost-a wedge) ...but don't LEAK a rejected create:
      // the server holds a live session pinned to the agent until someone
      // terminates it (previously it survived until the next request's
      // orphan reap or the consent timeout).
      // #1045 — a create for the session we're ALREADY tracking is not a
      // ghost: it's the server re-affirming our live session (the coalesce
      // echo, where a duplicate request on this same socket is answered with
      // our existing id). Terminating on it would kill the session we're in.
      // #1631 — and while `requesting`, a create for ANOTHER agent is not
      // ours either (A's late create landing while B's request is in
      // flight). The decision table is `sessionCreatedAction`.
      const action = sessionCreatedAction(
        phase.value,
        msg,
        sessionId.value,
        lastConnectArgs?.agentId ?? null,
        externalMode,
      )
      if (action === 'ignore') return
      if (action === 'terminate') {
        console.warn(
          '[rc] rc:session.created',
          phase.value === 'requesting'
            ? `for agent ${String(msg.agent_id)} while requesting ${lastConnectArgs?.agentId}`
            : `outside an active request (phase ${phase.value})`,
          '- releasing the ghost session',
        )
        if (typeof msg.session_id === 'string' && msg.session_id) {
          ws.sendRaw({
            t: 'rc:terminate',
            session_id: msg.session_id,
            reason: 'controller_hangup',
          })
        }
        return
      }
      requestSent = false
      sessionId.value = msg.session_id
      // Multi-user P3: the server reports the EFFECTIVE grant, which the
      // single-INPUT-holder rule may have narrowed (another live session
      // already drives this host). Absent from pre-P3 servers = treat as
      // as-requested. `inputGranted=false` suppresses the input senders so
      // we never stream events the agent drops anyway.
      const perms = typeof msg.permissions === 'string' ? msg.permissions : null
      inputGranted.value = perms === null || perms.includes('INPUT')
      recordGranted.value = grantHoldsRecord(perms)
      recordRefused.value = typeof msg.record_refused === 'string' ? msg.record_refused : null
      // FR-85 P3c — the grant is known only now, so the `record` channel is
      // opened only now (see `openRecordChannel` for why never in connect()).
      const recordChannel = openRecordChannel(pc, channels, perms)
      if (recordChannel) recording.attach(recordChannel as unknown as RecordChannel)
      // FR-99 P1c — the same for privacy mode: the grant, the server's reason
      // when it stripped the bit, and the channel only on a grant holding it.
      privacyGranted.value = grantHoldsPrivacy(perms)
      privacyRefused.value = typeof msg.privacy_refused === 'string' ? msg.privacy_refused : null
      // FR-101 P2c — and what the session policy refused, each with why.
      featuresRefused.value = parseFeaturesRefused(msg.features_refused)
      const privacyChannel = openPrivacyChannel(pc, channels, perms)
      if (privacyChannel) privacy.attach(privacyChannel as unknown as PrivacyChannel)
      if (!inputGranted.value) {
        console.info(
          '[rc] session is VIEW-EFFECTIVE: another session already holds input on this host',
        )
      }
      clipboardGranted.value = grantAllowsClipboard(perms)
      if (!clipboardGranted.value && dropClipboardChannel(channels)) {
        console.info('[rc] no CLIPBOARD in the grant: the clipboard channel is closed')
      }
      markConnect('session_created')
      // FR-34 — a fresh attempt starts un-locked-known; the agent tells us
      // via rc:consent.pending if the host is locked.
      hostLocked.value = false
      phase.value = 'awaiting_consent'
      // Consent is human-paced on Prompt-mode devices; the SERVER owns
      // that timeout (consent_timeout). Ours only covers requesting/
      // negotiating.
      clearSignalingTimeout()
    })
    // FR-34 — the agent reports the host is LOCKED while this prompt is
    // pending, so the on-host panel is on the invisible secure desktop and
    // someone must unlock the machine to see + approve it. Advisory: it
    // never gates the flow (unlock + approve resolves it, 5-min window),
    // it only turns the wait into an instruction. Reuses `hostLocked` (the
    // same flag the connected session sets from rc:host_locked).
    on('rc:consent.pending', (msg) => {
      if (
        phase.value === 'awaiting_consent' &&
        msg.session_id === sessionId.value &&
        msg.host_locked === true
      ) {
        hostLocked.value = true
      }
    })
    // FR-52 P4e — the server refused the external session ask itself: the
    // login was already spent or expired, the device went away or is busy, or
    // an org gate closed since the login. It answers `rc:extauth.result`, not
    // `rc:error`, and nothing follows — so this is the end of the attempt.
    on('rc:extauth.result', (msg) => {
      if (!externalMode || phase.value !== 'requesting' || !externalAuth) return
      if (msg.attempt_id != null && msg.attempt_id !== externalAuth.attemptId) return
      if (msg.refused === undefined || msg.refused === null) return
      // FR-115 P3b — the slot count's refusal carries the server's own words
      // (who holds the slot, on which device); every other reason does not.
      failWith(
        msg.refused === 'session_limit' && typeof msg.message === 'string' && msg.message
          ? msg.message
          : friendlyExtauthRefusal(msg.refused, msg.retry_after_secs),
      )
    })
    on('rc:ready', async (msg) => {
      // (2026-08-05 winhost-a wedge) NEVER drop rc:ready silently: the server
      // is now in Negotiating and sends nothing further, so a dropped Ready
      // used to park the UI in 'awaiting_consent' forever. Stale-session
      // Readys are ignored; a Ready whose PeerConnection lost a race
      // against teardown re-enters through the ladder.
      const action = readyRecoveryAction(
        sessionGateAllows(msg.session_id, sessionId.value),
        !!pc,
        !!lastConnectArgs,
      )
      if (action === 'ignore') {
        console.warn('[rc] rc:ready for a stale session - ignoring', msg.session_id)
        return
      }
      if (action === 'reschedule') {
        console.warn('[rc] rc:ready arrived with no PeerConnection - retrying the attempt')
        scheduleReconnect()
        return
      }
      if (action === 'fail') {
        failWith('session setup raced teardown')
        return
      }
      const livePc = pc
      if (!livePc) return // unreachable: 'proceed' implies pc exists (TS narrowing only)
      markConnect('ready')
      phase.value = 'negotiating'
      armSignalingTimeout()
      try {
        const offer = await livePc.createOffer()
        await livePc.setLocalDescription(offer)
        const offerFrame: Record<string, unknown> = {
          t: 'rc:sdp.offer',
          session_id: msg.session_id,
          sdp: offer.sdp,
        }
        // FR-52 P4e — an external session's offer is SEALED: a MAC over this
        // browser's DTLS certificate, under the key only this page and the
        // device hold. The device refuses an external offer without it.
        if (externalMode) {
          if (!externalAuth) throw new Error(EXTERNAL_LOGIN_GONE)
          offerFrame.extauth_mac = await transportMac(
            externalAuth.appKey,
            'offer',
            sdpFingerprint(offer.sdp ?? ''),
          )
        }
        // FR-100 P2a — an in-org session asks the device to SIGN its answer:
        // a fresh nonce rides the offer, and what was asked is kept to judge
        // the answer by. An offer naming no single certificate asks nothing;
        // the device could not sign against it either.
        peerAuthAsked = null
        peerAuth.value = null
        const askedSid = typeof msg.session_id === 'string' ? msg.session_id : sessionId.value
        const offerFingerprint = peerAuthPlan ? singleFingerprint(offer.sdp ?? '') : null
        if (peerAuthPlan && askedSid && offerFingerprint !== null) {
          const nonce = newPeerAuthNonce()
          peerAuthAsked = { ...peerAuthPlan, sessionId: askedSid, nonce, offerFingerprint }
          // FR-100 P2b — and this browser signs the offer with its own key,
          // for the device to judge (P1c). A key store that hangs past 1.5 s
          // is not waited for: the offer then only asks.
          offerFrame.peer_auth = await offerAsk({
            nonce,
            sessionId: askedSid,
            agentId: peerAuthPlan.agentId,
            userId: peerAuthPlan.userId,
            offerFingerprint,
            pair: peerAuthKey ? await withinMs(peerAuthKey, 1500) : null,
          })
        }
        ws.sendRaw(offerFrame)
        markConnect('offer_sent')
      } catch (e) {
        failWith((e as Error).message || 'createOffer failed')
      }
    })
    on('rc:sdp.answer', async (msg) => {
      if (!pc) return
      if (!sessionGateAllows(msg.session_id, sessionId.value)) return
      // The peer this answer is for. Checking the answer awaits, and a
      // teardown (or a whole new attempt) can land meanwhile: an answer is
      // applied only to the peer that made the offer it answers.
      const answerPc = pc
      markConnect('answer')
      try {
        // FR-52 P4e — an external session's answer must carry the DEVICE's
        // seal over its own DTLS certificate, checked BEFORE the description
        // is applied: once applied, DTLS would pin whatever certificate the
        // answer named, and an answer that cannot prove the login's key may
        // have been written by whoever relays the signalling. No seal, no
        // session — and the server is told, so the device's slot frees.
        if (externalMode) {
          const sealed =
            externalAuth !== null &&
            typeof msg.extauth_mac === 'string' &&
            (await verifyTransportMac(
              externalAuth.appKey,
              'answer',
              sdpFingerprint(String(msg.sdp ?? '')),
              msg.extauth_mac,
            ))
          if (!sealed) {
            if (sessionId.value) {
              ws.sendRaw({
                t: 'rc:terminate',
                session_id: sessionId.value,
                reason: 'controller_hangup',
              })
            }
            failWith(EXTERNAL_ANSWER_UNSEALED)
            return
          }
        }
        // FR-100 P2a — when this page asked the device to sign its answer,
        // judge the signature BEFORE the description is applied, as the
        // external check above does: the key this browser pinned for the
        // device, signing over THIS session, is what makes the answer the
        // device's. A first key is pinned; another key, or a signature that
        // does not verify, ends the attempt here. Unsigned proceeds, and says
        // so: a pod from before the field existed drops it mid-roll.
        if (peerAuthAsked) {
          const asked = peerAuthAsked
          peerAuthAsked = null
          const pins = peerAuthPins()
          const pinned = pins.get(asked.userId, asked.agentId)
          const verdict = await judgePeerAuth({
            asked,
            sessionId: asked.sessionId,
            agentId: asked.agentId,
            userId: asked.userId,
            answerFingerprint: singleFingerprint(String(msg.sdp ?? '')),
            answerPeerAuth: msg.peer_auth,
            pinned,
          })
          const signedBy = 'key' in verdict ? verdict.key : null
          const judged: PeerAuthJudgement = {
            verdict,
            userId: asked.userId,
            agentId: asked.agentId,
            fingerprint: signedBy ? await peerAuthFingerprint(signedBy) : null,
            pinnedFingerprint: pinned ? await peerAuthFingerprint(pinned) : null,
          }
          if (pc !== answerPc) return // torn down while the signature was checked
          peerAuth.value = judged
          if (applyPeerAuthVerdict(verdict, pins, asked.userId, asked.agentId) === 'refuse') {
            console.warn('[rc] peer-auth: the device answer was refused:', verdict.kind)
            if (sessionId.value) {
              ws.sendRaw({
                t: 'rc:terminate',
                session_id: sessionId.value,
                reason: 'controller_hangup',
              })
            }
            failWith(
              verdict.kind === 'key-changed'
                ? peerAuthKeyChangedMessage(judged.pinnedFingerprint, judged.fingerprint)
                : PEER_AUTH_BAD_SIGNATURE,
            )
            return
          }
        }
        // Torn down while the seal or the signature was being checked.
        if (!pc || pc !== answerPc) return
        await pc.setRemoteDescription({ type: 'answer', sdp: msg.sdp })
        remoteDescriptionSet = true
        // Flush any ICE that arrived early.
        for (const c of pendingRemoteIce) {
          try {
            await pc.addIceCandidate(c)
          } catch {
            /* tolerate stale candidates */
          }
        }
        pendingRemoteIce.length = 0
      } catch (e) {
        failWith((e as Error).message || 'setRemoteDescription failed')
      }
    })
    on('rc:ice', async (msg) => {
      if (!pc || !msg.candidate) return
      if (!sessionGateAllows(msg.session_id, sessionId.value)) return
      const init = msg.candidate as RTCIceCandidateInit
      if (!remoteDescriptionSet) {
        pendingRemoteIce.push(init)
        return
      }
      try {
        await pc.addIceCandidate(init)
      } catch {
        /* ignore Ã¢ÂÂ happens on stale candidates during teardown */
      }
    })
    on('rc:terminate', (msg) => {
      // While the ladder timer is pending every terminate refers to a
      // session we already abandoned Ã¢ÂÂ ignore.
      if (phase.value === 'reconnecting') return
      if (!sessionGateAllows(msg.session_id, sessionId.value)) return
      // Involuntary endings (agent WS displacement Ã¢ÂÂ the classic
      // "host joined a VPN" symptom Ã¢ÂÂ or a transient agent error)
      // auto-re-create the session instead of dumping the operator
      // to a dead viewer. Deliberate endings stay terminal. And a session
      // this page already failed keeps its error (`terminateAction`).
      const action = terminateAction({
        phase: phase.value,
        retryable: isRetryableTerminateReason(msg.reason, msg.limit),
        canReplay: !!lastConnectArgs,
      })
      if (action === 'keep-error') return
      if (action === 'reconnect') {
        console.info('[rc] session ended (', msg.reason, ') Ã¢ÂÂ auto-reconnecting')
        // Server already ended the session Ã¢ÂÂ don't send a redundant
        // terminate for it.
        scheduleReconnect({ notifyServer: false })
        return
      }
      phase.value = 'closed'
      if (endedByHost(msg.reason)) {
        // FR-27 P10 - the person at the device ended it. Said as such (the
        // view renders `endedBy`), never as an error, and never retried on
        // its own: teardown() below closes the channels with the phase
        // already 'closed', so the control DC's onclose (the fast reconnect
        // path) stays quiet, and the ladder is left with nothing to replay.
        // Reconnect is the operator's explicit act from here, through
        // consent like any new session.
        console.info('[rc] session ended by the person at the device - not reconnecting')
        endedBy.value = 'host'
        cancelReconnect()
        lastConnectArgs = null
      }
      if (msg.reason) {
        // FR-27 - a non-nominal end gets a sentence, not the enum name. The
        // mapping returns null for every nominal reason, so the set of
        // reasons that surface is the set that has something to say.
        const friendly = friendlyEndReason(msg.reason, msg.limit)
        if (friendly) error.value = friendly
      }
      teardown()
    })
    on('rc:error', (msg) => {
      // PR-1 rehome: handled BEFORE the reconnecting-guard below. A
      // mid-ladder `agent_on_other_pod` is the live signal that our
      // socket keys to the wrong pod, not stale fallout from an
      // abandoned session. Server prose may name pod internals, so
      // diagnostics stay in the console, never in the UI.
      if (msg.code === 'agent_on_other_pod') {
        if (!sessionGateAllows(msg.session_id, sessionId.value)) return
        attemptErrorCode = msg.code
        if (!lastConnectArgs) {
          failWith(friendlyRcError(msg.code, msg.message))
          return
        }
        rehomeStreak += 1
        if (rehomeRetryDecision(rehomeStreak) === 'redial_retry') {
          const expected = expectedOrgTid(lastConnectArgs.orgId, location.pathname)
          if (expected) ws.setTenantAffinity(expected)
          console.info(
            `[rc] device homed on another pod; re-keying the socket and retrying (${rehomeStreak}/${RC_REHOME_MAX_REDIALS})`,
            msg.message,
          )
          notice.value = "Rerouting to your device's server..."
          ws.forceRedial()
        } else {
          // The dial key evidently is not the problem (a parked agent
          // still converging server-side). Stop cycling the socket but
          // keep the infinite ladder (rc.23: no terminal) with honest
          // copy in place of raw server prose.
          console.warn(
            `[rc] still cross-pod after ${RC_REHOME_MAX_REDIALS} redials; riding the ladder`,
            msg.message,
          )
          notice.value = 'Still reaching your device through the cluster. Retrying automatically...'
        }
        scheduleReconnect({ notifyServer: false })
        return
      }
      // Ladder pending Ã¢ÂÂ errors are stale fallout from the abandoned
      // session (e.g. session_not_found for our own hangup). Ignore.
      if (phase.value === 'reconnecting') return
      if (!sessionGateAllows(msg.session_id, sessionId.value)) return
      // #2251 - and once the server has ENDED this session, an error scoped to
      // it is fallout of frames in flight, never news: the end said why.
      if (isFalloutOfEndedSession(phase.value, msg.session_id, sessionId.value)) {
        console.info('[rc] rc:error (', msg.code, ') for a session already ended - ignoring')
        return
      }
      // #1045 — while `awaiting_consent` the SERVER owns the timeout and a
      // human is at the host prompt. An un-scoped transient here (an
      // agent_offline bounced by our own hangup for a PRIOR session while the
      // agent WS flaps) must NOT fire the reconnect ladder: that re-sends the
      // request on this same socket and, on a multi-viewer agent, spawns a
      // SECOND session — a second host prompt on a second surface (native busy
      // => companion). A genuine agent drop during consent arrives as a SCOPED
      // rc:terminate, handled above; ignore the un-scoped noise.
      if (!msg.session_id && phase.value === 'awaiting_consent') {
        console.info(
          '[rc] un-scoped transient rc:error (',
          msg.code,
          ') during awaiting_consent - ignoring (server owns the consent timeout)',
        )
        return
      }
      // FR-22 part 4 - from here on the error ACTS on the live attempt (it
      // retries it or fails it), so its code belongs in that attempt's
      // record. The ignored cases above never reach this line.
      attemptErrorCode = typeof msg.code === 'string' ? msg.code : 'unknown'
      // (2026-08-05 winhost-a wedge) An un-scoped transient (no session_id -
      // e.g. agent_offline bounced by our own hangup for the PREVIOUS
      // session while the agent's WS flaps) passes the gate and used to
      // failWith a LIVE attempt mid-flight. With an attempt in flight,
      // ride the ladder instead - never kill a live attempt on an
      // un-scoped transient code.
      if (!msg.session_id && sessionId.value && isRetryableRcErrorCode(msg.code) && lastConnectArgs) {
        console.info('[rc] un-scoped transient rc:error (', msg.code, ') during an active attempt - retrying')
        scheduleReconnect({ notifyServer: false })
        return
      }
      // Mid-ladder transients (agent_busy while the old slot frees,
      // agent_offline while the agent WS flaps back) advance the
      // ladder instead of killing it. First-connect errors still fail
      // fast Ã¢ÂÂ reconnectAttempt is 0 outside a reconnect cycle.
      if (isRetryableRcErrorCode(msg.code) && reconnectAttempt.value > 0 && lastConnectArgs) {
        console.info('[rc] transient signalling error (', msg.code, ') Ã¢ÂÂ retrying')
        scheduleReconnect({ notifyServer: false })
        return
      }
      failWith(friendlyRcError(msg.code, msg.message))
    })
  }

  function removeRcHandlers() {
    // P3: remove only THIS composable's subscriptions (see rcUnsubs).
    for (const un of rcUnsubs) un()
    rcUnsubs = []
  }

  function failWith(message: string) {
    error.value = message
    phase.value = 'error'
    cancelReconnect()
    logConnectTiming('closed')
    lastConnectArgs = null
    // #1631 - a request answered by a failing rc:error (or an attempt that
    // died before one went out) leaves nothing for the late-create
    // terminator to release. teardown() bumps `connectGen`, so a connect()
    // still in its pre-flight stops at its next check.
    requestSent = false
    // FR-52 P4e — a failed external session's login is spent either way.
    forgetExternalAuth()
    teardown()
  }

  /**
   * Cancel any pending reconnect timer and reset the attempt counter.
   * Called from `failWith` (terminal error), `disconnect` (user-
   * initiated teardown), and on every successful 'connected'
   * transition (so a stable session that later fails starts the
   * ladder from 250 ms again, not from where it left off).
   */
  function cancelReconnect(opts?: { keepAttempts?: boolean }) {
    if (reconnectTimer !== null) {
      clearTimeout(reconnectTimer)
      reconnectTimer = null
    }
    if (opts?.keepAttempts) return
    reconnectAttempt.value = 0
    deadAirStreak.value = 0
    rehomeStreak = 0
    notice.value = null
  }

  /**
   * Schedule the next reconnect attempt according to
   * `RC_RECONNECT_LADDER_MS`. Cancels any prior schedule (no
   * stacking). After `RC_RECONNECT_LADDER_MS.length` attempts have
   * elapsed without a 'connected' transition resetting the counter,
   * gives up and calls `failWith` so the operator sees the failure
   * instead of a hung "reconnecting" UI.
   *
   * The PC is torn down at schedule time (not retry time) so any
   * lingering ICE / track listeners don't fire on the dead PC while
   * the timer is pending.
   */
  function scheduleReconnect(opts?: { notifyServer?: boolean }) {
    // Replace any prior schedule.
    if (reconnectTimer !== null) {
      clearTimeout(reconnectTimer)
      reconnectTimer = null
    }
    // FR-52 P4e — every automatic retry funnels through here, and an EXTERNAL
    // session takes none: its login opened exactly one session, and another
    // costs the password again — retrying would only spend guesses on a
    // request the server would refuse (spec, open decision 10). The server is
    // still told, so the device's slot frees.
    if (externalMode) {
      if (opts?.notifyServer !== false && sessionId.value) {
        ws.sendRaw({
          t: 'rc:terminate',
          session_id: sessionId.value,
          reason: 'controller_hangup',
        })
      }
      failWith(EXTERNAL_SESSION_ENDED)
      return
    }
    // Without the original connect args we can't retry.
    if (!lastConnectArgs) {
      failWith('peer connection failed')
      return
    }
    // FR-22 part 4 - an attempt the ladder is advancing past without a
    // phase bound firing (a transient rc:error it rides, an ICE failure,
    // dead air before the first frame) had no record at all: its recorder
    // was replaced by the next beginAttempt(). Report it FIRST, while the
    // session id is still known. A recorder that already painted is a
    // drop, reported at first paint; logConnectTiming just releases it.
    if (connectTiming) logConnectTiming('retried')
    // Free the agent's session slot BEFORE retrying: the default
    // max_simultaneous_sessions is 1, and the agent only notices a
    // dead peer on its own timeout Ã¢ÂÂ without this hangup the fresh
    // request bounces off `agent_busy` for many seconds. Skipped
    // (notifyServer: false) when the trigger was the server ending
    // the session itself.
    if (opts?.notifyServer !== false && sessionId.value) {
      ws.sendRaw({
        t: 'rc:terminate',
        session_id: sessionId.value,
        reason: 'controller_hangup',
      })
    }
    sessionId.value = null
    const attemptIdx = reconnectAttempt.value
    // rc.23 Ã¢ÂÂ nextReconnectDelayMs always returns a positive delay
    // now; the loop only exits when the operator clicks Disconnect
    // (which sets lastConnectArgs = null and falls into the failWith
    // above) or the peer transitions back to 'connected'. Removes
    // the "budget exhausted" terminal that frustrated operators on
    // corporate AV-protected hosts where the agent gets killed and
    // restarted repeatedly during large uploads.
    // A cycle that reached `connected` and never saw a frame is DEAD AIR:
    // count it, and let the dead-air ladder raise the floor on the delay.
    // `Math.max` so a genuinely flapping-but-working session keeps the fast
    // ladder — only the frameless case is slowed.
    if (
      isDeadAir({
        mediaEverFlowed,
        connected: phase.value === 'connected',
        // P2d-2 — a session that ended while the agent said it waited for
        // the person at the screen was not dead air either.
        agentSaidNoPixels: mediaUnavailable.value !== null || mediaWaiting.value !== null,
      })
    ) {
      deadAirStreak.value += 1
    }
    const deadAir = deadAirDelayMs(deadAirStreak.value)
    const delay = Math.max(nextReconnectDelayMs(attemptIdx), deadAir)
    if (deadAir > 0) {
      console.warn(
        '[rc] no media on the last',
        deadAirStreak.value,
        'attempts — backing off',
        delay,
        'ms. The device likely has no usable network path to this browser.',
      )
      notice.value = `No video from this device after ${deadAirStreak.value} attempts — retrying every ${Math.round(delay / 1000)}s. Its network may be blocking the connection.`
    }
    reconnectAttempt.value = attemptIdx + 1
    phase.value = 'reconnecting'
    // FR-93 P5j — a computer going to sleep keeps saying so through the redial.
    const kept = waitKeptAcrossReconnect(mediaWaiting.value, Date.now())
    teardown()
    if (kept) mediaWaiting.value = kept
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null
      fireReconnectAttempt()
    }, delay)
  }

  /** The body of a ladder retry. Split out of the timer callback so
   *  the ws.status watcher can fast-path it the moment signalling
   *  comes back instead of sitting out the remaining backoff. */
  function fireReconnectAttempt() {
    const args = lastConnectArgs
    if (!args) return
    if (ws.status !== 'connected') {
      // Firing into a CONNECTING/closed socket silently drops the
      // request (sendRaw only warns) and costs the full signalling
      // timeout. Re-arm instead; the ws.status watcher fast-paths the
      // retry the moment the socket opens.
      scheduleReconnect({ notifyServer: false })
      return
    }
    // `connect()` resets phase / sessionId on entry; the early-
    // return guard for non-{idle,closed,error} states is OK
    // because we set 'reconnecting' which falls outside those.
    // We `await` via .catch so a synchronous throw inside connect
    // chains into another reconnect attempt instead of bubbling
    // unhandled.
    void connect(args.agentId, args.permissions, /* isReconnect */ true).catch(() => {
      scheduleReconnect()
    })
  }

  /**
   * Resolve true the moment the signalling socket reports 'connected',
   * or false after `timeoutMs`. Used by the rc pre-flight so the
   * session request never fires into a CONNECTING socket.
   */
  function waitForWsConnected(timeoutMs: number): Promise<boolean> {
    if (ws.status === 'connected') return Promise.resolve(true)
    return new Promise((resolve) => {
      let timer: ReturnType<typeof setTimeout> | null = null
      const stop = watch(
        () => ws.status,
        (s) => {
          if (s === 'connected') {
            if (timer !== null) clearTimeout(timer)
            stop()
            resolve(true)
          }
        },
      )
      timer = setTimeout(() => {
        stop()
        resolve(false)
      }, timeoutMs)
    })
  }

  // Signalling transport watch: the moment the WS comes back while a
  // ladder timer is pending, retry immediately Ã¢ÂÂ the backoff exists to
  // pace attempts against a dead server, not to penalise a recovered
  // one. (Attempts fired while the WS is down send into the void and
  // get re-laddered by the signalling timeout, so this also shortens
  // the worst case after a laptop wake.)
  watch(
    () => ws.status,
    (s) => {
      if (s === 'connected' && phase.value === 'reconnecting' && reconnectTimer !== null) {
        clearTimeout(reconnectTimer)
        reconnectTimer = null
        console.info('[rc] signalling restored Ã¢ÂÂ retrying immediately')
        fireReconnectAttempt()
      }
    },
  )

  function teardown() {
    // #1631 - invalidate any connect() still in its pre-flight (see
    // `connectGen`): the peer it would build belongs to a state that just
    // ended. Every teardown path - disconnect(), failWith(), a scoped
    // rc:terminate, the ladder - comes through here.
    connectGen += 1
    stopStatsPoll()
    stopMediaWatchdog()
    clearPcDisconnectedTimer()
    clearSignalingTimeout()
    stopJankDetector()
    lastBacklogDrops = 0
    struggleWindow.reset()
    // FR-1 P7 — clock sync is per-connection (a reconnect may land on a
    // restarted agent process with a fresh epoch).
    resetClockSync()
    // FR-16 L4 — flush the last batch while the session id still names it.
    stopBench()
    stopWebCodecsPath()
    stopVp9_444Path()
    stopHevcPath()
    for (const ch of Object.values(channels)) {
      try { ch.close() } catch { /* ignore */ }
    }
    for (const k of Object.keys(channels)) delete channels[k]
    if (pc) {
      try { pc.close() } catch { /* ignore */ }
      pc = null
    }
    remoteStream.value = null
    // Stop + drop the host-audio track so the <audio> sink goes silent
    // and the browser releases the decoder. The view's watcher clears
    // the element's srcObject when this flips to null.
    if (remoteAudioStream.value) {
      for (const t of remoteAudioStream.value.getTracks()) {
        try { t.stop() } catch { /* ignore */ }
      }
    }
    remoteAudioStream.value = null
    audioAutoplayBlocked.value = false
    hasMedia.value = false
    remoteDescriptionSet = false
    pendingRemoteIce.length = 0
    // FR-100 P2a — what the next attempt asks is decided afresh. The verdict
    // (`peerAuth`) stays: the error view reads it after a refusal.
    peerAuthPlan = null
    peerAuthAsked = null
    peerAuthKey = null
    cursor.value = { pos: null, shapes: new Map() }
    mediaIntrinsicW.value = 0
    mediaIntrinsicH.value = 0
    hostLocked.value = false
    hostLockedInput.value = 'suppressed'
    keepBusy.value = null
    displayMatchState.value = null
    currentDesktop.value = 'Default'
    videoInfo.value = null
    // FR-80 — a host whose permission was restored must not keep showing
    // yesterday's reason, and the pill must not carry the last session's
    // codec into one that has not named its own yet.
    mediaUnavailable.value = null
    audioUnavailable.value = null
    mediaWaiting.value = null
    inputReach.value = null
    idleEndsAt.value = null
    dcDecoderCodec.value = null
    remoteLayout.value = null
    localClipboardBridge.value = null
    localClipboardBridgePort.value = null
  }

  // Phase 5 Ã¢ÂÂ admin break-glass reason for the NEXT `connect()`. The UI sets it
  // (via a confirm dialog) before a forced session; `connect` reads it into the
  // `rc:session.request` and clears it. The server ignores it unless the caller
  // is a validated `ADMINISTRATOR`.
  const overrideReason = ref('')

  async function connect(
    agentId: string,
    // Multi-user P3: FILES is requested explicitly now that the agent
    // ENFORCES it (it was always implicitly granted under the legacy
    // triple; the server grandfathers exactly that legacy request).
    // FR-85 P3c: RECORD is always asked for. The server strips it, with a
    // reason, unless this controller may record and the device opted in, so
    // asking costs nothing and the answer is what enables the Record button.
    permissions = 'VIEW | INPUT | CLIPBOARD | FILES | RECORD',
    isReconnect = false,
    // The agent's org (tenant hex). Placement-critical: the session
    // request must originate from the pod this org hashes to, and the
    // page URL alone is wrong for cross-org device modals. Optional;
    // falls back to the URL inside expectedOrgTid().
    orgId?: string,
  ) {
    // The reconnect path is allowed to drive `connect` while phase ==
    // 'reconnecting'; user-initiated calls must still be blocked from
    // re-entering an active session.
    if (
      phase.value !== 'idle'
      && phase.value !== 'closed'
      && phase.value !== 'error'
      && !(isReconnect && phase.value === 'reconnecting')
    ) {
      return // already active
    }
    // FR-52 P4e — an external viewer starts only from a login in hand.
    if (externalMode && !externalAuth) {
      failWith(EXTERNAL_LOGIN_GONE)
      return
    }
    // #1631 - this attempt's generation, re-checked after every suspension
    // below. Taken AFTER the guard: a call rejected above must not touch it,
    // the attempt it would have displaced is still the live one.
    const gen = ++connectGen
    // Capture the original call so a later 'failed' can replay it.
    // Don't clobber on an isReconnect call Ã¢ÂÂ that path already has
    // the right args from the original user click.
    if (!isReconnect) {
      lastConnectArgs = { agentId, permissions, orgId }
      // FR-27 P10 - a fresh request is the operator's answer to "the person
      // at the device ended it"; the notice has done its job.
      endedBy.value = null
      // New user-initiated connect - a later retry in THIS cycle must not
      // inherit "the session worked once" from the previous one.
      sessionEverPainted = false
      // Fresh user-initiated connect Ã¢ÂÂ reset reconnect state.
      cancelReconnect()
    }
    error.value = null
    sessionId.value = null
    // FR-22 - the clock starts HERE, not at `rc:session.request`.
    // Everything between this point and the request is a wait the
    // operator experiences: re-keying and redialling the signalling
    // socket (up to RC_PREFLIGHT_WS_WAIT_MS on its own), an HTTP fetch
    // for TURN credentials, the local-relay probe and the browser's
    // codec-capability probes. Starting at the request measured none of
    // it, so a connect that spent its whole wait in the pre-flight
    // reported a small TTFF and was reported as healthy - which is
    // exactly the case that reproduced with no snackbar.
    connectTiming = beginAttempt(reconnectAttempt.value + 1, sessionEverPainted)
    attemptErrorCode = null
    armVisibilityTiming()
    // Per-ATTEMPT, not per-user-connect: each retry has to earn "media
    // flowed" again, otherwise one good session would excuse every frameless
    // one that followed it.
    mediaEverFlowed = false
    inputGranted.value = true // until rc:session.created reports otherwise
    clipboardGranted.value = true // likewise
    // FR-85 P3c — a recording is granted per session, never carried over.
    recordGranted.value = false
    recordRefused.value = null
    // FR-99 P1c — and so is privacy mode; the last session's channel is gone.
    privacyGranted.value = false
    privacyRefused.value = null
    privacy.detach()
    // FR-101 P2c — each session is told its own refusals.
    featuresRefused.value = {}
    // P6 — fresh session, fresh multi-user state.
    controlState.value = null
    peerCursors.value = {}
    phase.value = 'requesting'

    // PR-1 rc pre-flight: rc is pod-local, so the request must go out
    // on a socket keyed to the agent's org. A live socket dialed with
    // a different key (deep-link race before the org resolved, an org
    // switch under lazy affinity, a cross-org device modal) re-keys +
    // redials FIRST; then wait for OPEN, because sendRaw into a
    // CONNECTING socket is silently dropped and costs the full
    // signalling timeout.
    const expectedOrg = expectedOrgTid(
      isReconnect ? lastConnectArgs?.orgId : orgId,
      location.pathname,
    )
    if (expectedOrg) {
      ws.setTenantAffinity(expectedOrg)
      if (ws.getDialedTid() !== expectedOrg && ws.status !== 'disconnected') {
        console.info('[rc] pre-flight: re-keying the signalling socket to the device org')
        ws.forceRedial()
      }
    }
    if (ws.status !== 'connected') {
      const ready = await waitForWsConnected(RC_PREFLIGHT_WS_WAIT_MS)
      if (!ready) {
        console.warn('[rc] pre-flight: signalling socket not ready; proceeding (ladder will retry)')
      }
    }
    // #1631 - torn down while we waited for the socket (the operator picked
    // another device, or hung up). Nothing below may run for a dead attempt.
    if (gen !== connectGen) return
    markConnect('ws_ready')

    // Restore the per-agent resolution preference. This has to live
    // here (not at composable-init) because `useRemoteControl()` runs
    // before the route params resolve on some mount paths, and we
    // don't want a stale value from a different agent leaking in.
    resolutionAgentId = agentId
    if (resolutionUserPickedThisSession) {
      // rc.190 (A1) Ã¢ÂÂ the user picked a resolution BEFORE connecting (the
      // dropdown next to Connect). Keep it, and persist it now that we
      // finally know which agent it belongs to. Pre-fix this line
      // unconditionally overwrote the pick with the stored value
      // ('original' by old default) Ã¢ÂÂ the "initial resolution selection
      // in the dropdown doesn't work" field bug.
      persistResolution(agentId, resolution.value)
    } else {
      resolution.value = readStoredResolution(agentId)
    }

    // Per-agent codec override Ã¢ÂÂ same shape as the resolution block above,
    // including its rc.190 guard: a pick made BEFORE connect wins over the
    // stored override (and is persisted now that the agent is known); the
    // restore path is persist-FREE so agent X's override never rewrites the
    // global default other agents inherit.
    codecAgentId = agentId
    switch (
      codecConnectAction(codecUserPickedThisSession, readStoredCodecChoice(agentId))
    ) {
      case 'persist-pick':
        persistCodecChoice(agentId, codecChoice.value)
        break
      case 'apply-stored':
        applyCodecChoiceSettings(readStoredCodecChoice(agentId) as RcCodecChoice)
        break
      case 'none':
        break
    }

    // Inspect what video codecs this browser can decode so the agent
    // can pick the best intersection with its own AgentCaps.codecs
    // (Phase 2 negotiation, 2B.2). Filtered to the codecs we'd ever
    // negotiate: H.264 universal, H.265 + AV1 = bandwidth wins,
    // VP9 = WebRTC-mandatory, VP8 = legacy. Browsers without
    // RTCRtpReceiver.getCapabilities (older Safari/Firefox) get an
    // empty list and the agent falls back to H.264-only.
    const allBrowserCaps = inspectBrowserVideoCodecs()
    const browserCaps = filterCapsByPreference(allBrowserCaps, preferredCodec.value)
    if (allBrowserCaps.length > 0) {
      // Surface both lists in the console Ã¢ÂÂ useful when debugging
      // "why didn't H.265 negotiate" on a session. Shown as the raw
      // browser list Ã¢ÂÂ© forced preference Ã¢ÂÂ sent list.
      console.info(
        '[rc] browser codecs:',
        allBrowserCaps.join(', '),
        preferredCodec.value ? `(forced ${preferredCodec.value})` : '',
        'Ã¢ÂÂ sending to agent:',
        browserCaps.join(', '),
      )
    }

    // Pull TURN creds before creating the PC so the first gather uses them.
    // FR-115 P4b — charged to the device's org; an external session names
    // neither id (its device is a connect code here), so it stays uncharged.
    let iceServers: IceServer[] = []
    try {
      const creds = await api.get<TurnCredsResponse>(
        externalMode || sharedMode
          ? '/turn/credentials'
          : turnCredsPath(agentId, expectedOrgTid(orgId, location.pathname)),
      )
      iceServers = creds.ice_servers
    } catch {
      // Fall back to a public STUN if the server has none configured.
      iceServers = defaultStunServers()
    }
    if (gen !== connectGen) return // #1631 - torn down during the TURN fetch
    markConnect('turn_ready')

    // loopback-TURN corp-relay (Phase 2): if opted-in AND this host runs a
    // local enrolled agent serving a loopback TURN, prepend it as an ICE server
    // (loopback is never firewall-blocked, unlike this corp browser's direct/
    // coturn UDP) and forward its descriptor to the server (below) so the REMOTE
    // agent relays through it too. Graceful no-op on any host without one.
    let localRelay: LocalRelayDescriptor | null = null
    // FR-52 P4e — never for an external session: its frame cannot carry a
    // relay descriptor (F4), and a relay on THIS host's mesh could not reach a
    // device in someone else's organization anyway.
    if (localRelayEnabled.value && !externalMode && !sharedMode) {
      localRelay = await probeLocalRelay()
      if (localRelay) {
        iceServers = [localRelayIceServer(localRelay), ...iceServers]
        console.info(
          '[rc] local-relay TURN discovered on this host Ã¢ÂÂ relaying via local agent overlay',
          localRelay.overlay_ip,
        )
      }
    }
    // #1631 - the last suspension before the peer exists. A disconnect()
    // during any wait above must never leave a peer that nothing will close
    // (its ICE sockets outlive the composable - see the socket-leak note in
    // docs/tunnels.md), nor send a request on behalf of a torn-down state.
    if (gen !== connectGen) return

    pc = new RTCPeerConnection({
      iceServers: iceServers as RTCIceServer[],
      bundlePolicy: 'max-bundle',
    })
    // e2e hook (FR-61): the live PC, so specs can assert framesDecoded via
    // getStats() instead of settling for currentTime heuristics — the hook
    // remote-session-smoke.spec.ts documents wishing it had.
    ;(window as unknown as Record<string, unknown>).__roomler_remote_pc = pc

    pc.ontrack = (ev) => {
      // Opt-in host audio arrives on its own m=audio section. Route it
      // to a SEPARATE stream + sink so it never clobbers `remoteStream`
      // (bound to the <video> element) and never rides through the
      // muted <video> / DataChannel-canvas video path. The view binds
      // `remoteAudioStream` to a hidden <audio autoplay> element; if
      // the browser blocks autoplay-with-sound we flip
      // `audioAutoplayBlocked` so the view can offer a one-click unmute.
      // Return early Ã¢ÂÂ none of the video/WebCodecs plumbing below
      // applies to an audio track.
      if (ev.track.kind === 'audio') {
        remoteAudioStream.value = new MediaStream([ev.track])
        hasMedia.value = true
        return
      }
      // Replace rather than append. addTrack accumulates across ICE
      // restarts / renegotiations, leaving dead tracks attached to the
      // MediaStream; the <video> element would render the wrong one.
      // Current agent doesn't renegotiate, but if it ever does this
      // would regress silently Ã¢ÂÂ replacement is idempotent for the
      // single-track case we have today.
      remoteStream.value = new MediaStream([ev.track])
      hasMedia.value = true
      // Try the WebCodecs bypass first when the user opted in AND the
      // browser supports it. If the canvas hasn't mounted yet (common
      // Ã¢ÂÂ ontrack fires in 'negotiating' while the canvas is gated on
      // 'connected'), stash the receiver; the watcher on
      // webcodecsCanvasEl below picks it up as soon as the canvas
      // mounts.
      // DC sessions: the video track is a dormant placeholder (frames ride
      // the data channel into the DC worker — already WebCodecs); skip the
      // RTP-track transform machinery SILENTLY so its 'webcodecs path
      // skipped' warnings stop crying wolf. Rare legacy combo (explicit DC
      // pick vs an old agent that silently falls back to RTP) renders via
      // <video> — video still plays, only the canvas bypass is skipped.
      const wantsWebCodecs =
        sessionDcTransport == null
        && renderPath.value === 'webcodecs'
        && webcodecsSupported.value
        && ev.track.kind === 'video'
      if (wantsWebCodecs) {
        // Hint the default receiver path toward low-latency so the
        // brief window before the transform lands doesn't buffer.
        try {
          const receiver = ev.receiver as RTCRtpReceiver & {
            jitterBufferTarget?: number | null
            playoutDelayHint?: number | null
          }
          receiver.jitterBufferTarget = 0
          receiver.playoutDelayHint = 0
        } catch { /* best-effort */ }
        // Install the transform EAGERLY Ã¢ÂÂ canvas is attached later
        // when it mounts. This gets Chrome's RTP pipeline routing
        // frames to our worker from the first packet; waiting for
        // the canvas mount (phase === 'connected') meant the default
        // decoder locked in first on some Chrome builds and the
        // transform stopped receiving anything.
        if (installWebCodecsTransform(ev.receiver)) {
          return
        }
        // Install failed (no RTCRtpScriptTransform, worker throw,
        // etc.) Ã¢ÂÂ fall through to classic <video> path.
      }
      // Tell the browser we care about latency, not playback smoothness.
      // Chromium enforces a soft ~80 ms floor regardless, but asking
      // for zero still shaves ~30-50 ms off the previous 50 ms setting
      // because the jitter-buffer overhead is both the floor AND the
      // requested target. See
      // https://www.w3.org/TR/webrtc-extensions/#dom-rtcrtpreceiver-jitterbuffertarget
      try {
        const receiver = ev.receiver as RTCRtpReceiver & {
          jitterBufferTarget?: number | null
          playoutDelayHint?: number | null
        }
        receiver.jitterBufferTarget = 0
        // Firefox + non-standard Chromium hint Ã¢ÂÂ belt-and-braces with
        // jitterBufferTarget. Same intent: "decode + display as fast
        // as possible; I'd rather see stutter than lag."
        receiver.playoutDelayHint = 0
      } catch {
        // Best-effort Ã¢ÂÂ browser will use its own adaptive default.
      }
      // contentHint tells the compositor this is motion (not detail),
      // which switches Chrome's <video> internal smoothing off and
      // discourages re-buffering on minor frame timing irregularity.
      try {
        (ev.track as MediaStreamTrack & { contentHint?: string }).contentHint = 'motion'
      } catch {
        /* ignore */
      }
    }

    pc.onicecandidate = (ev) => {
      if (!sessionId.value) return
      // Note: null candidate signals end-of-gather Ã¢ÂÂ skip it.
      if (!ev.candidate) return
      ws.sendRaw({
        t: 'rc:ice',
        session_id: sessionId.value,
        candidate: ev.candidate.toJSON(),
      })
    }

    pc.onconnectionstatechange = () => {
      // Snapshot the state up front: failWith() below nulls `pc` as part
      // of teardown, so re-reading `pc.connectionState` on the next branch
      // would throw TypeError.
      const state = pc?.connectionState
      if (!state) return
      if (state === 'connected') {
        markConnect('pc_connected')
        phase.value = 'connected'
        // FR-93 P5j — a session that connects is a computer that woke.
        if (isKeptSleepNotice(mediaWaiting.value, Date.now())) mediaWaiting.value = null
        // Stand down the pending retry timer, but KEEP the attempt counters:
        // reaching `connected` is not proof the session works. A pair with no
        // usable ICE candidate connects every time and then sits in dead air
        // until the media watchdog kills it, so resetting here made the ladder
        // restart at 250 ms forever (winhost-a: 388 sessions/24 h). The media
        // watchdog clears both counters the moment a frame actually arrives,
        // which still gives a long-lived session that drops at hour 5 its
        // 250 ms first retry — that session had media.
        cancelReconnect({ keepAttempts: true })
        // A recovered ICE flap lands back here Ã¢ÂÂ stand down the
        // sustained-'disconnected' fuse and the negotiation timeout,
        // and start watching media progress.
        clearPcDisconnectedTimer()
        clearSignalingTimeout()
        startMediaWatchdog()
      } else if (state === 'disconnected') {
        // Transient ICE flaps recover on their own within ~1-2 s; a
        // host that jumped onto a VPN never does. Arm a one-shot
        // fuse instead of ignoring the state outright (the pre-S3
        // behaviour, which left the viewer frozen at "connected"
        // until the much slower media watchdog / agent timeout).
        if (pcDisconnectedTimer === null) {
          pcDisconnectedTimer = setTimeout(() => {
            pcDisconnectedTimer = null
            if (pc?.connectionState === 'disconnected') {
              console.warn('[rc] peer sat in \'disconnected\' past grace Ã¢ÂÂ re-creating session')
              scheduleReconnect()
            }
          }, RC_PC_DISCONNECTED_GRACE_MS)
        }
      } else if (state === 'failed') {
        // M3 hand-off / desktop transition / network blip. Replace
        // the previous immediate-failWith with the auto-reconnect
        // ladder so the operator doesn't have to F5 + reconnect
        // every time the host briefly goes dark.
        scheduleReconnect()
      } else if (state === 'closed' && phase.value !== 'error' && phase.value !== 'closed' && phase.value !== 'reconnecting') {
        // Clean up the data channels + stream too; otherwise they leak
        // when the PC closes without a prior disconnect() (e.g. the
        // server-side session terminates first).
        phase.value = 'closed'
        teardown()
      }
    }

    // Declare we want to *receive* video from the agent. Without this line
    // the offer has no m=video section, so the agent's answer can't include
    // one either Ã¢ÂÂ ontrack never fires and hasMedia stays false. See the
    // peer-side mirror in agents/roomlerd/src/peer.rs (add_track).
    pc.addTransceiver('video', { direction: 'recvonly' })

    // Opt-in host audio: declare a recvonly audio transceiver so the
    // offer carries an m=audio section the agent can answer with its
    // Opus track. Only when the user asked for it Ã¢ÂÂ otherwise no audio
    // m-line is offered and the agent adds no audio track (mirrors the
    // `audio_enabled` request flag). The agent still gates on its own
    // `AgentCaps.audio` advertising `"opus"`, so this is a safe no-op
    // against agents without the audio feature.
    if (audioEnabled.value) {
      pc.addTransceiver('audio', { direction: 'recvonly' })
    }

    // Create the four data channels up front per architecture doc ÃÂ§5.
    // Reliability profiles match the doc: unreliable+unordered for input,
    // reliable+ordered for everything else.
    channels.input = pc.createDataChannel('input', {
      ordered: false,
      maxRetransmits: 0,
    })
    channels.control = pc.createDataChannel('control', { ordered: true })
    // #2638 - a request held for an earlier session's channel never carries
    // over into this one.
    heldDisplayMatch.clear()
    // Cursor channel: reliable + ordered because a dropped `cursor:
    // shape` message would leave the browser unable to render the
    // current cursor. Position-only updates would also be fine
    // unordered, but muxing both on one channel means we use the
    // stricter policy.
    channels.cursor = pc.createDataChannel('cursor', { ordered: true })
    channels.clipboard = pc.createDataChannel('clipboard', { ordered: true })
    // v2 Ã¢ÂÂ the clipboard DC carries binary PNG frames; without an
    // explicit binaryType some browsers deliver Blobs (the files DC
    // defends both, the video DCs pin arraybuffer Ã¢ÂÂ same here).
    channels.clipboard.binaryType = 'arraybuffer'
    channels.clipboard.onopen = () => {
      if (clipboardAutoSyncEnabled.value) {
        // v2.2 Ã¢ÂÂ probe the local bridge FIRST (it decides whether we
        // ask the remote for native events), then subscribe + start
        // the localÃ¢ÂÂremote triggers. The probe is a ~1.5 s loopback
        // fetch; subscribing after it means the `native` event opt-in
        // reflects real availability. Re-fires on the fresh DC after a
        // reconnect.
        void probeLocalClipboardBridge().finally(() => {
          if (channels.clipboard?.readyState !== 'open') return
          sendClipboardSubscription(true)
          startClipboardSyncTriggers()
          void syncLocalClipboardToRemote('connect')
        })
      }
    }
    channels.clipboard.onclose = () => {
      stopClipboardSyncTriggers()
    }
    channels.files = pc.createDataChannel('files', { ordered: true })
    // FR-85 P3c — NOT the `record` channel: no grant has been seen yet (the
    // session request goes out below). `rc:session.created` opens it
    // (`openRecordChannel`).

    // Persistent listener on the `files` DC. Demuxes every control
    // message by id and dispatches to the registry entry that owns
    // the transfer. Single attach point: replaces the per-call
    // addEventListener pattern from 0.2.x. See `filesRegistry` doc
    // comment for the lifecycle contract.
    //
    // String frames are JSON control messages (files:offer, eof,
    // complete, error, progress, accepted, dir-list, dir-error).
    // Binary frames are download chunks routed to the
    // `activeDownloadId`'s registry entry per the demux contract
    // (one active outgoing transfer at a time).
    channels.files.onmessage = (ev) => {
      if (typeof ev.data !== 'string') {
        // Binary frame Ã¢ÂÂ route to the active download's writable
        // or Blob accumulator. If no active download, drop (would
        // be a protocol violation; agent shouldn't send binaries
        // without a preceding files:offer).
        if (!activeDownloadId) return
        const entry = filesRegistry.get(activeDownloadId)
        if (!entry || entry.kind !== 'download' || entry.status === 'settled') return
        // ev.data may be ArrayBuffer or Blob depending on the DC's
        // binaryType. webrtc-rs DCs default to ArrayBuffer.
        const data = ev.data as ArrayBuffer | Blob
        if (data instanceof ArrayBuffer) {
          appendDownloadChunk(entry, data)
        } else if (data instanceof Blob) {
          // Async path; we don't await Ã¢ÂÂ entries are kept in arrival
          // order via the same await chain.
          void data.arrayBuffer().then((buf) => appendDownloadChunk(entry, buf))
        }
        return
      }
      let msg: {
        t?: string
        id?: string
        req_id?: string
        name?: string
        size?: number | null
        mime?: string
        path?: string
        parent?: string | null
        entries?: DirEntry[]
        bytes?: number
        message?: string
        /** rc.19 files:resumed reply Ã¢ÂÂ server-authoritative offset
         *  the browser should re-pump from. */
        accepted_offset?: number
      }
      try {
        msg = JSON.parse(ev.data)
      } catch {
        return
      }
      const id = typeof msg.id === 'string' ? msg.id : ''
      // Directory listing replies are demuxed by req_id, not id.
      if (msg.t === 'files:dir-list') {
        const reqId = typeof msg.req_id === 'string' ? msg.req_id : ''
        const pending = settleDirRequest(reqId)
        if (pending) {
          pending.resolve({
            path: String(msg.path ?? ''),
            parent: typeof msg.parent === 'string' ? msg.parent : null,
            entries: Array.isArray(msg.entries) ? msg.entries : [],
          })
        }
        return
      } else if (msg.t === 'files:dir-error') {
        const reqId = typeof msg.req_id === 'string' ? msg.req_id : ''
        const pending = settleDirRequest(reqId)
        if (pending) {
          pending.reject(new Error(String(msg.message ?? 'agent dir error')))
        }
        return
      }
      if (msg.t === 'files:complete') {
        const entry = settleEntry(id)
        if (entry?.kind === 'upload') {
          patchTransfer(id, { status: 'complete', bytes: Number(msg.bytes ?? 0) })
          entry.resolve({ path: String(msg.path ?? ''), bytes: Number(msg.bytes ?? 0) })
        }
      } else if (msg.t === 'files:error') {
        const errMsg = String(msg.message ?? 'agent error')
        // rc.19: if a resume handshake is waiting on this id, route
        // the error THERE first. The wrapper falls back to a fresh
        // `files:begin` with a new id (see uploadOneResumable).
        // The original upload entry stays in `filesRegistry` so the
        // wrapper can rebind it.
        const waiter = pendingResumePromises.get(id)
        if (waiter) {
          clearTimeout(waiter.timer)
          pendingResumePromises.delete(id)
          waiter.reject(new Error(errMsg))
          return
        }
        // Errors can land for either an upload OR a download.
        const entry = settleEntry(id)
        if (!entry) return
        patchTransfer(id, { status: 'error', error: errMsg })
        if (entry.kind === 'upload') {
          entry.reject(new Error(errMsg))
        } else {
          // Download error: abort writable so Chrome auto-deletes
          // any partial file in the user's chosen save location.
          if (id === activeDownloadId) activeDownloadId = null
          if (entry.writable) {
            void entry.writable.abort(errMsg).catch(() => {})
          }
          entry.reject(new Error(errMsg))
        }
      } else if (msg.t === 'files:progress') {
        const bytes = Number(msg.bytes ?? 0)
        patchTransfer(id, { status: 'running', bytes })
        // rc.19: each progress envelope is a durable-bytes ack
        // (agent calls sync_data per 1 MiB before emitting).
        // Update the upload entry so a future resume request
        // claims the right offset.
        const entry = filesRegistry.get(id)
        if (entry?.kind === 'upload') {
          entry.bytesAcked = bytes
        }
      } else if (msg.t === 'files:resumed') {
        // rc.19: agent Ã¢ÂÂ browser reply confirming the byte offset
        // from which to re-pump. Routed via pendingResumePromises
        // (NOT filesRegistry) Ã¢ÂÂ the entry is currently in
        // 'pending-resume' state and we hand control back to the
        // resume wrapper via this waiter.
        const waiter = pendingResumePromises.get(id)
        if (waiter) {
          clearTimeout(waiter.timer)
          pendingResumePromises.delete(id)
          waiter.resolve(Number(msg.accepted_offset ?? 0))
        }
      } else if (msg.t === 'files:accepted') {
        patchTransfer(id, { status: 'running' })
      } else if (msg.t === 'files:offer') {
        const entry = filesRegistry.get(id)
        if (!entry || entry.kind !== 'download' || entry.status === 'settled') return
        entry.name = String(msg.name ?? entry.suggestedName ?? 'download.bin')
        entry.expectedSize = typeof msg.size === 'number' ? msg.size : null
        entry.mime = typeof msg.mime === 'string' ? msg.mime : undefined
        activeDownloadId = id
        patchTransfer(id, {
          status: 'running',
          name: entry.name,
          total: entry.expectedSize,
        })
        // Resolve the save-mode: prefer streaming when the browser
        // supports showSaveFilePicker AND the caller didn't preselect
        // a Blob path. The picker MUST have been opened by the
        // caller (a synchronous user gesture is required); by the
        // time files:offer arrives we already have the writable in
        // entry.writable if the picker resolved.
        if (entry.saveMode === 'pending') {
          // No picker was set up; fall back to Blob accumulator.
          entry.saveMode = 'blob'
        }
      } else if (msg.t === 'files:eof') {
        const entry = filesRegistry.get(id)
        if (!entry || entry.kind !== 'download' || entry.status === 'settled') return
        const totalBytes = Number(msg.bytes ?? entry.bytesReceived)
        if (id === activeDownloadId) activeDownloadId = null
        // Finalize: close the writable (Chrome streaming) or trigger
        // the anchor download (Blob fallback).
        void finalizeDownload(entry, totalBytes).then(
          () => {
            const settled = settleEntry(id)
            if (settled?.kind === 'download') {
              patchTransfer(id, { status: 'complete', bytes: totalBytes })
              settled.resolve({ name: entry.name, bytes: totalBytes })
            }
          },
          (err: unknown) => {
            const settled = settleEntry(id)
            if (settled?.kind === 'download') {
              const errMsg = err instanceof Error ? err.message : String(err)
              patchTransfer(id, { status: 'error', error: errMsg })
              settled.reject(new Error(errMsg))
            }
          }
        )
      }
    }
    // DC close handler. Pre-rc.19: every pending transfer is
    // settled with "channel closed" and the operator has to manually
    // retry. rc.19: when the agent has the resume cap, UPLOAD
    // entries are deferred to 'pending-resume' state so the
    // `uploadOneResumable` wrapper can issue `files:resume` after
    // the WebRTC peer reconnects (handled by `scheduleReconnect`).
    // Downloads still fail-fast Ã¢ÂÂ host Ã¢ÂÂ browser resume is future
    // work.
    channels.files.onclose = () => {
      activeDownloadId = null
      // Reject any in-flight resume handshakes Ã¢ÂÂ the new DC will
      // get a fresh waiter.
      for (const [id, w] of Array.from(pendingResumePromises.entries())) {
        clearTimeout(w.timer)
        pendingResumePromises.delete(id)
        w.reject(new Error('files channel closed mid-resume'))
      }
      const errMsg = 'files channel closed'
      for (const id of Array.from(filesRegistry.keys())) {
        const entry = filesRegistry.get(id)
        if (!entry || entry.status === 'settled') continue
        if (entry.kind === 'upload' && supportsResume.value) {
          // Defer settle Ã¢ÂÂ the uploadOneResumable wrapper is awaiting
          // the next `phase === 'connected'` and will issue
          // `files:resume`. Transition to 'pending-resume' so a
          // late files:complete on a stale DC can't double-settle.
          entry.status = 'pending-resume'
          patchTransfer(id, { status: 'reconnecting', error: 'waiting for reconnect' })
          continue
        }
        const settled = settleEntry(id)
        if (!settled) continue
        patchTransfer(id, { status: 'error', error: errMsg })
        if (settled.kind === 'upload') {
          settled.reject(new Error(errMsg))
        } else if (settled.kind === 'download') {
          if (settled.writable) {
            void settled.writable.abort(errMsg).catch(() => {})
          }
          settled.reject(new Error(errMsg))
        }
      }
    }

    // Subscribe to the clipboard DC. Agent -> browser messages are
    // `clipboard:content` (single-envelope reply to a read),
    // `clipboard:content-chunk` (rc.44+ chunked reply, multiple
    // envelopes carrying the same `req_id` until `last: true`), and
    // `clipboard:error` (read or write failure). Pending-read promises
    // are keyed by the req_id we stamp on outbound `clipboard:read`
    // messages so interleaved reads resolve independently.
    const pendingClipboardReadChunks = new Map<number, string>()
    // v2 Ã¢ÂÂ chunked change-event reassembly (keyed by event_id) and the
    // inbound agentÃ¢ÂÂbrowser rich stream (image OR html Ã¢ÂÂ one at a
    // time; the agent serializes them). A 15 s inactivity timer drops
    // half streams.
    const pendingClipboardEventChunks = new Map<string, string>()
    let inboundClipRich: {
      id: string
      kind: 'image' | 'html' | 'native'
      w: number
      h: number
      rtfBytes: number
      htmlBytes: number
      declared: number
      chunks: BlobPart[]
      received: number
      reqId: number | null
      timer: ReturnType<typeof setTimeout>
    } | null = null
    const dropInboundClipRich = () => {
      if (inboundClipRich) {
        clearTimeout(inboundClipRich.timer)
        inboundClipRich = null
      }
    }
    const armInboundClipRichTimer = () => {
      if (!inboundClipRich) return
      clearTimeout(inboundClipRich.timer)
      inboundClipRich.timer = setTimeout(() => {
        console.debug('[rc] clipboard rich stream timed out; dropping')
        dropInboundClipRich()
      }, 15_000)
    }
    /** Resolve a completed rich stream: answer to a rich read (req_id)
     *  or unsolicited change event Ã¢ÂÂ apply locally. */
    const finishInboundClipRich = (content: RemoteClipContent, reqId: number | null) => {
      if (reqId != null && content.kind !== 'text') {
        const rich = pendingClipboardRichReads.get(reqId)
        if (rich) {
          pendingClipboardRichReads.delete(reqId)
          const textPending = pendingClipboardReads.get(reqId)
          if (textPending) {
            clearTimeout(textPending.timer)
            pendingClipboardReads.delete(reqId)
          }
          rich.resolve(content)
          return
        }
      }
      applyRemoteClipboard(content)
    }
    channels.clipboard.onmessage = (ev) => {
      if (typeof ev.data !== 'string') {
        // v2 Ã¢ÂÂ binary frame for the announced inbound rich stream.
        if (!inboundClipRich) return
        const data = ev.data as ArrayBuffer | Blob
        const size = data instanceof Blob ? data.size : data.byteLength
        if (inboundClipRich.received + size > inboundClipRich.declared) {
          console.debug('[rc] clipboard rich stream overflowed declared bytes; dropping')
          dropInboundClipRich()
          return
        }
        inboundClipRich.chunks.push(data)
        inboundClipRich.received += size
        armInboundClipRichTimer()
        return
      }
      let msg: {
        t?: string
        req_id?: number | null
        id?: string
        text?: string
        message?: string
        last?: boolean
        kind?: string
        event_id?: string
        seq?: number
        w?: number
        h?: number
        bytes?: number
        html_bytes?: number
        text_bytes?: number
        rtf_bytes?: number
      }
      try {
        msg = JSON.parse(ev.data)
      } catch {
        return
      }
      if (msg.t === 'clipboard:write-ack') {
        settleClipboardAck(msg.id)
        return
      }
      if (msg.t === 'clipboard:event') {
        if (msg.kind === 'text' && typeof msg.text === 'string') {
          applyRemoteClipboard({ kind: 'text', text: msg.text })
        }
        return
      }
      if (msg.t === 'clipboard:event-chunk') {
        const eventId = typeof msg.event_id === 'string' ? msg.event_id : null
        if (eventId == null) return
        const chunk = typeof msg.text === 'string' ? msg.text : ''
        const acc = (pendingClipboardEventChunks.get(eventId) ?? '') + chunk
        if (acc.length > CLIPBOARD_MAX_BYTES) {
          pendingClipboardEventChunks.delete(eventId)
          return
        }
        if (msg.last === true) {
          pendingClipboardEventChunks.delete(eventId)
          applyRemoteClipboard({ kind: 'text', text: acc })
        } else {
          pendingClipboardEventChunks.set(eventId, acc)
        }
        return
      }
      if (msg.t === 'clipboard:img-begin') {
        const declared = typeof msg.bytes === 'number' ? msg.bytes : 0
        if (
          typeof msg.id !== 'string' ||
          declared <= 0 ||
          declared > CLIPBOARD_IMAGE_MAX_BYTES
        ) {
          return
        }
        dropInboundClipRich()
        inboundClipRich = {
          id: msg.id,
          kind: 'image',
          w: typeof msg.w === 'number' ? msg.w : 0,
          h: typeof msg.h === 'number' ? msg.h : 0,
          rtfBytes: 0,
          htmlBytes: 0,
          declared,
          chunks: [],
          received: 0,
          reqId: typeof msg.req_id === 'number' ? msg.req_id : null,
          timer: setTimeout(() => dropInboundClipRich(), 15_000),
        }
        return
      }
      if (msg.t === 'clipboard:html-begin') {
        const htmlBytes = typeof msg.html_bytes === 'number' ? msg.html_bytes : 0
        const textBytes = typeof msg.text_bytes === 'number' ? msg.text_bytes : 0
        const declared = htmlBytes + textBytes
        if (
          typeof msg.id !== 'string' ||
          htmlBytes <= 0 ||
          declared > CLIPBOARD_HTML_MAX_BYTES
        ) {
          return
        }
        dropInboundClipRich()
        inboundClipRich = {
          id: msg.id,
          kind: 'html',
          w: 0,
          h: 0,
          rtfBytes: 0,
          htmlBytes,
          declared,
          chunks: [],
          received: 0,
          reqId: typeof msg.req_id === 'number' ? msg.req_id : null,
          timer: setTimeout(() => dropInboundClipRich(), 15_000),
        }
        return
      }
      if (msg.t === 'clipboard:native-begin') {
        const rtfBytes = typeof msg.rtf_bytes === 'number' ? msg.rtf_bytes : 0
        const htmlBytes = typeof msg.html_bytes === 'number' ? msg.html_bytes : 0
        const textBytes = typeof msg.text_bytes === 'number' ? msg.text_bytes : 0
        const declared = rtfBytes + htmlBytes + textBytes
        // All three lengths must be non-negative and the rtf+html split
        // must fall inside the declared total, else the native-end
        // reassembly would mis-slice on a malformed/hostile header.
        if (
          typeof msg.id !== 'string' ||
          rtfBytes <= 0 ||
          htmlBytes < 0 ||
          textBytes < 0 ||
          rtfBytes + htmlBytes > declared ||
          declared > CLIPBOARD_NATIVE_MAX_BYTES
        ) {
          return
        }
        dropInboundClipRich()
        inboundClipRich = {
          id: msg.id,
          kind: 'native',
          w: 0,
          h: 0,
          rtfBytes,
          htmlBytes,
          declared,
          chunks: [],
          received: 0,
          reqId: typeof msg.req_id === 'number' ? msg.req_id : null,
          timer: setTimeout(() => dropInboundClipRich(), 15_000),
        }
        return
      }
      if (
        msg.t === 'clipboard:img-end' ||
        msg.t === 'clipboard:html-end' ||
        msg.t === 'clipboard:native-end'
      ) {
        if (!inboundClipRich || inboundClipRich.id !== msg.id) return
        const rich = inboundClipRich
        clearTimeout(rich.timer)
        inboundClipRich = null
        if (rich.received !== rich.declared) {
          console.debug('[rc] clipboard rich stream incomplete; dropping')
          return
        }
        if (rich.kind === 'image') {
          const blob = new Blob(rich.chunks, { type: 'image/png' })
          finishInboundClipRich({ kind: 'image', blob, w: rich.w, h: rich.h }, rich.reqId)
        } else if (rich.kind === 'html') {
          // html Ã¢ÂÂ decode the combined bytes and split at the declared
          // html length (both halves are UTF-8 strings).
          void new Blob(rich.chunks).arrayBuffer().then((buf) => {
            const bytes = new Uint8Array(buf)
            const dec = new TextDecoder('utf-8')
            const html = dec.decode(bytes.subarray(0, rich.htmlBytes))
            const text = dec.decode(bytes.subarray(rich.htmlBytes))
            finishInboundClipRich({ kind: 'html', html, text }, rich.reqId)
          })
        } else {
          // native Ã¢ÂÂ split rtf ++ html ++ text at the declared lengths
          // (rtf is raw bytes; html/text are UTF-8 strings).
          void new Blob(rich.chunks).arrayBuffer().then((buf) => {
            const bytes = new Uint8Array(buf) as Uint8Array<ArrayBuffer>
            const dec = new TextDecoder('utf-8')
            const rtf = bytes.slice(0, rich.rtfBytes) as Uint8Array<ArrayBuffer>
            const html = dec.decode(bytes.subarray(rich.rtfBytes, rich.rtfBytes + rich.htmlBytes))
            const text = dec.decode(bytes.subarray(rich.rtfBytes + rich.htmlBytes))
            finishInboundClipRich({ kind: 'native', rtf, html, text }, rich.reqId)
          })
        }
        return
      }
      if (msg.t === 'clipboard:content') {
        const reqId = typeof msg.req_id === 'number' ? msg.req_id : null
        if (reqId == null) return
        const pending = pendingClipboardReads.get(reqId)
        if (!pending) return
        clearTimeout(pending.timer)
        pendingClipboardReads.delete(reqId)
        pendingClipboardReadChunks.delete(reqId)
        pending.resolve(typeof msg.text === 'string' ? msg.text : '')
      } else if (msg.t === 'clipboard:content-chunk') {
        // rc.44 Ã¢ÂÂ chunked read reply. The agent splits long clipboard
        // text into multiple envelopes, each carrying the same
        // `req_id`. Accumulate by req_id; resolve on `last: true`.
        const reqId = typeof msg.req_id === 'number' ? msg.req_id : null
        if (reqId == null) return
        const pending = pendingClipboardReads.get(reqId)
        if (!pending) return
        const chunk = typeof msg.text === 'string' ? msg.text : ''
        const acc = (pendingClipboardReadChunks.get(reqId) ?? '') + chunk
        // Defensive cap: don't let a buggy / malicious agent OOM us
        // by streaming endless chunks. The .length here is UTF-16
        // code-unit count, which is Ã¢ÂÂ¤ the UTF-8 byte length for any
        // input Ã¢ÂÂ so capping at CLIPBOARD_MAX_BYTES is conservative.
        if (acc.length > CLIPBOARD_MAX_BYTES) {
          clearTimeout(pending.timer)
          pendingClipboardReads.delete(reqId)
          pendingClipboardReadChunks.delete(reqId)
          pending.reject(
            new Error(`clipboard:content-chunk stream exceeded ${CLIPBOARD_MAX_BYTES}B cap`),
          )
          return
        }
        pendingClipboardReadChunks.set(reqId, acc)
        if (msg.last === true) {
          clearTimeout(pending.timer)
          pendingClipboardReads.delete(reqId)
          pendingClipboardReadChunks.delete(reqId)
          pending.resolve(acc)
        }
      } else if (msg.t === 'clipboard:error') {
        // v2 Ã¢ÂÂ a failed id-stamped write settles its ack waiter (the
        // deferred Ctrl+V flushes; pasting the old content beats
        // hanging the keystroke on a write that will never land).
        settleClipboardAck(msg.id)
        const reqId = typeof msg.req_id === 'number' ? msg.req_id : null
        if (reqId == null) return
        const rich = pendingClipboardRichReads.get(reqId)
        if (rich) {
          pendingClipboardRichReads.delete(reqId)
          rich.reject(new Error(msg.message || 'agent clipboard error'))
        }
        const pending = pendingClipboardReads.get(reqId)
        if (!pending) return
        clearTimeout(pending.timer)
        pendingClipboardReads.delete(reqId)
        pendingClipboardReadChunks.delete(reqId)
        pending.reject(new Error(msg.message || 'agent clipboard error'))
      }
    }

    // Subscribe to the cursor DC. The agent pumps `cursor:pos` /
    // `cursor:shape` / `cursor:hide` at ~30 Hz; decode shape bitmaps
    // eagerly so the paint loop is a zero-copy `drawImage`.
    // FR-109 P3 — a new cursor channel knows nothing yet about a hidden cursor,
    // nor whether this host's tracker sees a pointer at all.
    hostCursorHidden.value = false
    hostCursorTracked = false
    channels.cursor.onmessage = (ev) => {
      if (typeof ev.data !== 'string') return
      let msg: { t?: string } & Record<string, unknown>
      try {
        msg = JSON.parse(ev.data)
      } catch {
        return
      }
      if (msg.t === 'cursor:pos') {
        const id = Number(msg.id)
        const x = Number(msg.x)
        const y = Number(msg.y)
        if (Number.isFinite(id) && Number.isFinite(x) && Number.isFinite(y)) {
          cursor.value = { ...cursor.value, pos: { id, x, y } }
        }
        hostCursorTracked = true
        onHostCursorShown()
      } else if (msg.t === 'cursor:peer') {
        // P6 — another session's pointer (ghost cursor), name-tagged,
        // normalized 0..1 per monitor, throttled agent-side to ~30 Hz.
        const sid = typeof msg.sid === 'string' ? msg.sid : ''
        const x = Number(msg.x)
        const y = Number(msg.y)
        if (sid && Number.isFinite(x) && Number.isFinite(y)) {
          peerCursors.value = {
            ...peerCursors.value,
            [sid]: {
              name: typeof msg.name === 'string' ? msg.name : '',
              x,
              y,
              mon: Number.isFinite(Number(msg.mon)) ? Number(msg.mon) : 0,
              ts: Date.now(),
            },
          }
        }
      } else if (msg.t === 'cursor:shape') {
        hostCursorTracked = true
        void applyCursorShape(msg)
      } else if (msg.t === 'cursor:hide') {
        cursor.value = { ...cursor.value, pos: null }
        hostCursorHidden.value = true
      }
    }

    installRcHandlers()

    // Flag the first open so the input pump can start queuing. FR-16 L4:
    // the bench probe rides this channel, so it starts and stops with it.
    channels.input.onopen = () => {
      inputChannelOpen.value = true
      startBench()
    }
    channels.input.onclose = () => {
      inputChannelOpen.value = false
      stopBench()
    }

    // Re-send the restored quality preference as soon as the control
    // channel opens Ã¢ÂÂ otherwise the agent would stay at its default
    // after a page reload that had set a non-default preference.
    channels.control.onopen = () => {
      sendQualityPreference()
      sendResolutionPreference()
      // #2638 - the display-match request the session made before this
      // channel opened (the per-connect re-send of the stored preference).
      const dm = heldDisplayMatch.take()
      if (dm) sendDisplayMatch(dm.value)
      // rc.199 Ã¢ÂÂ re-emit the stored Priority dial so a reloaded session
      // restores the operator's sharpness/smoothness choice without a click.
      sendPriorityPreference()
      // FR-119 P1 — re-ask for the stored frame rate (agents with fps-high only).
      sendFrameRatePreference()
    }
    // The control DC closing while the session still reports
    // 'connected' means the transport died under us (SCTP teardown
    // races pc.connectionState by seconds in Chrome). Every other
    // exit path Ã¢ÂÂ disconnect(), failWith(), scheduleReconnect() Ã¢ÂÂ
    // moves `phase` off 'connected' BEFORE teardown closes the
    // channels, so this only fires on genuine mid-session death.
    channels.control.onclose = () => {
      if (phase.value === 'connected') {
        console.warn('[rc] control channel closed mid-session Ã¢ÂÂ re-creating session')
        scheduleReconnect()
      }
    }
    // Agent Ã¢ÂÂ browser control messages. Recognised:
    //   - `rc:host_locked` (boolean) Ã¢ÂÂ the agent flips this on/off
    //     as `lock_state.rs` observes desktop transitions (0.2.3+).
    //   - `rc:desktop_changed` (string name) Ã¢ÂÂ the SYSTEM-context
    //     worker emits this after every `try_change_desktop`
    //     Switched, so the viewer shows e.g. "On Winlogon" while
    //     the operator drives the lock screen (0.3.0+).
    // Other variants (rc:dpi-change, rc:cursor-shape) layer on the
    // same parse-by-`t` switch. Unknown `t` values are dropped
    // silently; older agents emitted nothing here, so backward-
    // compat is automatic.
    channels.control.onmessage = (ev) => {
      // rc.23 hotfix Ã¢ÂÂ trace every inbound control envelope to the
      // browser console so the field can see, via DevTools, exactly
      // which messages the agent is sending. Helps diagnose
      // "rc:logs-fetch.reply never arrived" reports without requiring
      // an agent log fetch (which itself depends on the round-trip
      // working). Truncated to first 200 chars so a huge logs
      // payload doesn't blow up the console.
      //
      // Uses `console.log` (not debug) intentionally Ã¢ÂÂ Chrome
      // DevTools' default level filter hides `debug` and the field
      // report 2026-05-13 was "no console logs at all" because of
      // that filter, not because the messages were absent.
      if (typeof ev.data === 'string') {
        // eslint-disable-next-line no-console
        console.log(
          '[rc:control] inbound:',
          ev.data.length > 200 ? ev.data.slice(0, 200) + 'Ã¢ÂÂ¦' : ev.data
        )
      }
      const parsed = parseControlInbound(ev.data)
      if (parsed?.kind === 'host_locked') {
        hostLocked.value = parsed.locked
        hostLockedInput.value = parsed.input
      } else if (parsed?.kind === 'keep_busy') {
        keepBusy.value = parsed.state
      } else if (parsed?.kind === 'display_match') {
        displayMatchState.value = parsed.state
      } else if (parsed?.kind === 'clock_echo') {
        // FR-1 P7 — clock probe round trip complete; fold the sample.
        handleClockEcho(parsed.t0, parsed.agentUs)
      } else if (parsed?.kind === 'desktop_changed') {
        currentDesktop.value = parsed.name
      } else if (parsed?.kind === 'layout') {
        // rc.227 Ã¢ÂÂ keyboard-layout snapshot; drives the toolbar chip
        // + the Settings picker. Old agents never send it Ã¢ÂÂ the ref
        // stays null and the UI self-hides.
        remoteLayout.value = {
          activeHkl: parsed.activeHkl,
          activeTag: parsed.activeTag,
          installed: parsed.installed,
        }
      } else if (parsed?.kind === 'video_info') {
        // rc.87 Ã¢ÂÂ the agent told us its real encoder. Drives the
        // honest stats badge (replaces the hardcoded "VP9 4:4:4 SW").
        videoInfo.value = parsed.info
        console.info('[rc] video-info', parsed.info)
      } else if (parsed?.kind === 'media_unavailable') {
        // FR-80 — the host cannot capture. Surfaced on the canvas, because
        // the alternative the operator had was a black rectangle and a
        // stall that names nothing.
        mediaUnavailable.value = parsed.reason
        // FR-93 P2d-2 — a wait that ended without an answer ends here: this
        // message says why, and replaces the "waiting" notice on the canvas.
        mediaWaiting.value = null
        console.warn(
          `[rc] the host cannot capture its screen (${parsed.reason.code}) — ${parsed.reason.hint}`,
          parsed.reason.detail,
        )
        // FR-93 — this arrived over the control channel, so the path to the
        // device works: earlier frameless attempts were not a network
        // problem, and a notice saying they were must not sit over the reason.
        deadAirStreak.value = 0
        reconnectAttempt.value = 0
        notice.value = null
      } else if (parsed?.kind === 'audio_unavailable') {
        // FR-97 P3c-1 — the host sends no sound this session, and says why.
        // The view puts it on the audio control and says it once.
        audioUnavailable.value = parsed.reason
        console.warn(
          `[rc] the host sends no sound (${parsed.reason.code}) — ${parsed.reason.hint}`,
          parsed.reason.detail,
        )
      } else if (parsed?.kind === 'media_waiting') {
        // FR-93 P2d-2 — the host is asking the person at its screen to share
        // it. The deadline is set HERE, on this browser's clock.
        mediaWaiting.value = {
          for: parsed.for,
          deadlineMs: Date.now() + parsed.waitsMs,
          hint: parsed.hint,
        }
        mediaWaitingSinceMs = Date.now()
        console.info(
          `[rc] the host is waiting for the person at the screen (${parsed.for}), up to ${Math.round(parsed.waitsMs / 1000)} s`,
        )
        // Like FR-80's notice, this came over the control channel, so the
        // path to the device works: earlier frameless attempts were not a
        // network problem.
        deadAirStreak.value = 0
        reconnectAttempt.value = 0
        notice.value = null
      } else if (parsed?.kind === 'idle') {
        // FR-101 P4b-2b — the device's idle limit: a countdown on this
        // browser's clock, or its withdrawal (there was activity).
        idleEndsAt.value = parsed.endsInMs === null ? null : Date.now() + parsed.endsInMs
      } else if (parsed?.kind === 'input_reach') {
        // FR-93 P1 — the mouse and keyboard will not reach the whole desktop.
        // Said on screen, because the alternative was input that went nowhere
        // with nothing anywhere saying so.
        inputReach.value = parsed.reach
        console.warn(`[rc] input reaches ${parsed.reach.reach} of this desktop — ${parsed.reach.reason}`)
      } else if (parsed?.kind === 'control_state') {
        // P6 - arbiter state: participants rail + exclusive floor. Prune
        // ghost cursors of sessions that left.
        controlState.value = parsed.state
        const live = new Set(parsed.state.participants.map((p) => p.session))
        const next: Record<string, PeerCursor> = {}
        for (const [sid, pc] of Object.entries(peerCursors.value)) {
          if (live.has(sid)) next[sid] = pc
        }
        peerCursors.value = next
      } else if (parsed?.kind === 'logs_fetch_reply') {
        agentLogs.value = parsed.reply
        agentLogsLoading.value = false
        const resolve = pendingLogsResolver
        pendingLogsResolver = null
        if (resolve) resolve(parsed.reply)
      } else if (parsed?.kind === 'logs_fetch_start') {
        // rc.24 streamed reply: collect into the accumulator until
        // the matching `end` envelope arrives. `path` + `truncated`
        // are carried on `start`; lines accumulate from chunks.
        streamingLogsAcc = {
          ok: true,
          path: parsed.path,
          lines: [],
          truncated: parsed.truncated,
        }
      } else if (parsed?.kind === 'logs_fetch_chunk') {
        if (streamingLogsAcc && streamingLogsAcc.lines) {
          streamingLogsAcc.lines.push(...parsed.lines)
        }
      } else if (parsed?.kind === 'logs_fetch_end') {
        const reply = streamingLogsAcc ?? { ok: false, error: 'no start envelope' }
        streamingLogsAcc = null
        agentLogs.value = reply
        agentLogsLoading.value = false
        const resolve = pendingLogsResolver
        pendingLogsResolver = null
        if (resolve) resolve(reply)
      } else if (parsed?.kind === 'apps_list_reply') {
        // Update the reactive refs even when the agent didn't echo the id
        // (id-null tolerance, like the streamed logs path); only the
        // promise resolution is skipped in that case.
        appsLoading.value = false
        appsSupported.value = parsed.reply.supported
        appsCoverage.value = parsed.reply.coverage ?? null
        if (parsed.reply.ok) {
          remoteWindows.value = parsed.reply.windows
          launchableApps.value = parsed.reply.launchable
          // FR-56 AC10 — `supported: false` is a REFUSAL, not a quiet desktop.
          // Until this the arm cleared the error here and the dialog read
          // "No windows reported" — the calm reading — for every host with no
          // desktop to manage. The agent now says why; an agent that does not
          // is named as such rather than papered over.
          appsError.value = parsed.reply.supported
            ? null
            : (parsed.reply.unavailable?.reason ?? APPS_UNAVAILABLE_NO_REASON)
        } else {
          appsError.value = parsed.reply.error ?? 'apps list failed'
        }
        if (parsed.id) settleAppsRequest(parsed.id)?.resolve(parsed.reply)
      } else if (parsed?.kind === 'apps_focus_reply') {
        if (parsed.id) settleAppsRequest(parsed.id)?.resolve(parsed.reply)
      } else if (parsed?.kind === 'apps_launch_reply') {
        if (parsed.id) settleAppsRequest(parsed.id)?.resolve(parsed.reply)
      }
    }

    // Begin polling getStats() on a 500 ms cadence so the UI can show
    // live bitrate/fps/codec. Runs unconditionally while `pc` exists;
    // teardown() stops + clears it.
    startStatsPoll()

    // Resolve VP9-444 decode support before sending the request so
    // we only advertise `data-channel-vp9-444` when the browser can
    // actually decode it. The eager probe in the composable ctor
    // has likely already resolved by now, but await once more in
    // case `connect()` runs on first paint. Falling back silently
    // to webrtc when the user opted in but the browser lacks
    // support keeps the UX boring rather than broken.
    sessionDcTransport = null
    let preferredTransport: RcVideoTransport | null = null
    // rc.186 Ã¢ÂÂ set to 'yuv420' when we fall back from software-HEVC to VP9
    // so the fallback lands on VP9 profile 0 (hardware-decoded), overriding
    // the user's chroma choice for the fallback session only.
    let chromaOverride: string | null = null
    // P2 Ã¢ÂÂ the avc1 codec string the H.264-DC worker should configure with
    // (probe-ladder result); null when H.264-DC isn't in play.
    let h264DcCodec: string | null = null
    // P7 — true when the hevc-444 pick passed BOTH Rext gates (browser
    // probe + agent hevc_chroma); drives the worker codec override + the
    // chroma_pref field.
    let hevcRextPick = false
    // FR-77 P3b — the H.264 High 4:4:4 pick (both gates passed).
    let h264_444Pick = false
    viewerDecodeHw.value = null
    // FR-77 — cells whose decoder failed on real bytes for THIS device in
    // this browser build stay out of every rank and pick, across page loads
    // (the page-scoped `failedDcTransports` alone re-picked a proven-bad
    // decoder on the next visit). A 4:2:0 failure bans the transport; a
    // 4:4:4 failure only bans the 4:4:4 cell, since 4:2:0 on the same codec
    // is a different decoder path.
    const remembered = codecAgentId
      ? rememberedCellFailures(codecAgentId, globalThis.navigator?.userAgent ?? '')
      : new Set<string>()
    if (remembered.has('av1:yuv420')) failedDcTransports.add('data-channel-av1')
    if (remembered.has('hevc:yuv420')) failedDcTransports.add('data-channel-hevc')
    if (remembered.has('h264:yuv420')) failedDcTransports.add('data-channel-h264')
    if (remembered.has('vp9:yuv420')) failedDcTransports.add('data-channel-vp9-444')
    const hevc444Remembered = remembered.has('hevc:yuv444')
    const vp9_444Remembered = remembered.has('vp9:yuv444')
    const h264_444Remembered = remembered.has('h264:yuv444')
    if (videoTransport.value === 'auto') {
      // rc.190 (A3) Ã¢ÂÂ HWÃÂHW auto-rank. A codec is only smooth when it's
      // hardware on BOTH ends (field: VP9 is SW-encoded on non-Intel
      // hosts; HEVC/AV1 can be SW-decoded on weak viewers). Cross the
      // agent's advertised encoders with this browser's MediaCapabilities
      // and pick the best pair; explicit user picks skip this entirely.
      const caps = agent?.value?.capabilities
      const [av1Hw, hevcHw, hevcDec, vp9Hw, vp9Dec, h264Hw, h264Codec, hevcRext, h264High444, vp9Dec420] = await Promise.all([
        probeAv1Hw(),
        probeHevcHw(),
        probeHevcDec(),
        probeVp9Hw(),
        probeVp9_444(),
        probeH264Hw(),
        probeH264Dc(),
        probeHevcRext(),
        probeH264High444(),
        probeVp9_420(),
      ])
      vp9_444Supported.value = vp9Dec
      hevcSupported.value = hevcDec
      hevcRextSupported.value = hevcRext
      h264High444Supported.value = h264High444 !== null
      // FR-77 — the agent's HEVC 4:4:4 cell, read through the one derivation
      // (new `video_cells` or the legacy `hevc_chroma`), never optimistic.
      const agentHevc444 = cellsFromCaps(caps).some(
        (c) => c.codec === 'hevc' && c.chroma.includes('yuv444'),
      )
      // FR-77 P3b — the H.264 4:4:4 cell (NVENC High 4:4:4) and a HARDWARE
      // VP9 4:4:4 cell (vp9_qsv profile 1), for the explicit-4:4:4 rungs.
      const cellsNow = cellsFromCaps(caps)
      const agentH264_444 = cellsNow.some((c) => c.codec === 'h264' && c.chroma.includes('yuv444'))
      const agentVp9Hw444 = cellsNow.some((c) => c.codec === 'vp9' && c.hw && c.chroma.includes('yuv444'))
      const pick = pickAutoTransport({
        chromaPref: vp9_444Remembered && vp9Chroma.value !== 'yuv420' ? 'auto' : vp9Chroma.value,
        agentHevc444: agentHevc444 && !hevc444Remembered,
        viewerHevcRext: hevcRext && !hevc444Remembered,
        agentH264_444: agentH264_444 && !h264_444Remembered,
        viewerH264High444: h264High444 !== null && !h264_444Remembered,
        agentVp9Hw444: agentVp9Hw444 && !vp9_444Remembered,
        agentTransports: caps?.transports ?? [],
        agentHwEncoders: caps?.hw_encoders ?? [],
        viewerAv1Hw: av1Hw && !failedDcTransports.has('data-channel-av1'),
        viewerHevcHw: hevcHw && !failedDcTransports.has('data-channel-hevc'),
        // The WebCodecs config probe — the contract the worker configures
        // against; MC (`hevcHw` above) alone diverges on Edge.
        viewerHevcDecodable: hevcDec,
        viewerVp9Hw: vp9Hw && !failedDcTransports.has('data-channel-vp9-444'),
        viewerVp9Decodable: vp9Dec && !failedDcTransports.has('data-channel-vp9-444'),
        // #2231 — profile 0 alone (Firefox) takes the VP9 DataChannel at 4:2:0
        // when the RTP track has no H.264 for it.
        viewerVp9_420Decodable: vp9Dec420 && !failedDcTransports.has('data-channel-vp9-444'),
        viewerRtpH264: allBrowserCaps.length === 0 || allBrowserCaps.includes('h264'),
        // P2Ã¢ÂÂ H.264-DC needs both the HW-smooth verdict AND an accepted
        // Annex-B avc1 config (the worker configures with the latter).
        viewerH264Hw: h264Hw && h264Codec !== null
          && !failedDcTransports.has('data-channel-h264'),
        // Sharper can upgrade the SW VP9 rung to full chroma - see the
        // chroma note on `pickAutoTransport`.
        priority: priority.value,
      })
      preferredTransport = pick.transport
      chromaOverride = pick.chromaOverride
      if (pick.transport === 'data-channel-h264') {
        // FR-77 P3b — the High 4:4:4 pick configures the worker with the
        // High 4:4:4 string and sends chroma_pref yuv444.
        h264_444Pick = pick.chromaOverride === 'yuv444'
        h264DcCodec = h264_444Pick ? h264High444 : h264Codec
      }
      // FR-77 — the rank picked the HEVC Rext cell: the request carries
      // chroma_pref yuv444 exactly as an explicit hevc-444 pick would.
      if (pick.transport === 'data-channel-hevc' && pick.chromaOverride === 'yuv444') {
        hevcRextPick = true
      }
      viewerDecodeHw.value =
        pick.transport === 'data-channel-av1'
          ? av1Hw
          : pick.transport === 'data-channel-hevc'
            ? hevcHw
            : pick.transport === 'data-channel-vp9-444'
              ? // Profile 1 has no fixed-function decode anywhere - claiming
                // `dec HW` on a 4:4:4 pick would make the badge lie, which is
                // the exact thing rc.87's real-encoder plumbing exists to stop.
                pick.chromaOverride === 'yuv444'
                ? false
                : vp9Hw
              : pick.transport === 'data-channel-h264'
                ? (h264_444Pick ? false : h264Hw)
                : null
      console.info(`[rc] auto transport Ã¢ÂÂ ${pick.transport ?? 'webrtc'} (${pick.reason})`)
    } else if (videoTransport.value === 'data-channel-h264') {
      // P2 Ã¢ÂÂ explicit H.264 pick. Prefer the DC + WebCodecs pipeline when
      // BOTH ends support it: the agent must advertise the transport (old
      // agents don't Ã¢ÂÂ the legacy RTP track + <video> is exactly what they
      // will send), and this browser must accept a description-less
      // Annex-B avc1 config (probe ladder). On either miss we stay on the
      // RTP path silently Ã¢ÂÂ same behaviour as before P2.
      const h264Caps = agent?.value?.capabilities
      const agentHasH264Dc = (h264Caps?.transports ?? []).includes('data-channel-h264')
      const codec = agentHasH264Dc ? await probeH264Dc() : null
      if (agentHasH264Dc && codec && !failedDcTransports.has('data-channel-h264')) {
        preferredTransport = 'data-channel-h264'
        h264DcCodec = codec
        viewerDecodeHw.value = await probeH264Hw()
        // FR-77 P3b — explicit 4:4:4 (or Sharper on chroma Auto) on H.264:
        // High 4:4:4 Predictive when this browser's VideoDecoder accepts the
        // string AND the agent opened the cell. Either missing → the normal
        // 4:2:0 session, said so in the console.
        if (
          resolveChroma(vp9Chroma.value, priority.value, true) === 'yuv444'
          && !h264_444Remembered
        ) {
          const high444 = await probeH264High444()
          h264High444Supported.value = high444 !== null
          const agent444 = cellsFromCaps(h264Caps).some(
            (c) => c.codec === 'h264' && c.chroma.includes('yuv444'),
          )
          if (high444 && agent444) {
            h264DcCodec = high444
            h264_444Pick = true
            viewerDecodeHw.value = false
          } else {
            console.info(
              high444
                ? '[rc] H.264 4:4:4 dropped — the agent has no H.264 4:4:4 cell (non-NVENC host / older agent). Running H.264 4:2:0.'
                : '[rc] H.264 4:4:4 dropped — this browser lacks WebCodecs High 4:4:4 decode. Running H.264 4:2:0.',
            )
          }
        }
      } else if (failedDcTransports.has('data-channel-h264')) {
        console.info(
          '[rc] data-channel-h264 dropped Ã¢ÂÂ its decoder failed on real bytes earlier this page. Falling back to the RTP track.',
        )
      } else {
        console.info(
          agentHasH264Dc
            ? '[rc] data-channel-h264 dropped Ã¢ÂÂ WebCodecs Annex-B avc1 decode unsupported here. Falling back to the RTP track.'
            : '[rc] data-channel-h264 not advertised by this agent Ã¢ÂÂ using the legacy RTP track.',
        )
      }
    } else if (videoTransport.value === 'data-channel-av1') {
      // rc.190 Ã¢ÂÂ explicit AV1 pick. Chromium always has dav1d SW decode,
      // so gate only on decodability; the badge surfaces HW vs SW truth.
      const decodable = av1Supported.value || (await probeAv1Dec())
      av1Supported.value = decodable
      if (decodable && !failedDcTransports.has('data-channel-av1')) {
        preferredTransport = 'data-channel-av1'
        viewerDecodeHw.value = await isAv1HwDecodeSupported()
      } else if (failedDcTransports.has('data-channel-av1')) {
        console.info(
          '[rc] data-channel-av1 dropped Ã¢ÂÂ its decoder failed on real bytes earlier this page. Falling back to webrtc.',
        )
      } else {
        console.info(
          '[rc] preferred_transport=data-channel-av1 dropped Ã¢ÂÂ WebCodecs AV1 decode unsupported here. Falling back to webrtc.',
        )
      }
    } else if (videoTransport.value === 'data-channel-vp9-444') {
      const supported = vp9_444Supported.value || (await probeVp9_444())
      vp9_444Supported.value = supported
      // #2231 — profile 0 only (Firefox): the DataChannel still runs, at 4:2:0.
      const profile0Only = !supported && (await probeVp9_420())
      if ((supported || profile0Only) && !failedDcTransports.has('data-channel-vp9-444')) {
        preferredTransport = 'data-channel-vp9-444'
        viewerDecodeHw.value = await isVp9HwDecodeSupported()
        // FR-77 — chroma "Auto" on an explicit VP9 pick follows the Priority
        // dial (it used to send nothing, which the agent reads as profile 1);
        // a remembered profile-1 decode failure pins 4:2:0, and so does a
        // browser that decodes only profile 0.
        if (vp9_444Remembered || profile0Only) {
          chromaOverride = 'yuv420'
        } else if (vp9Chroma.value === 'auto') {
          chromaOverride = resolveChroma('auto', priority.value, true)
        }
        if ((chromaOverride ?? vp9Chroma.value) === 'yuv444') {
          // Profile 1 has no fixed-function decode anywhere.
          viewerDecodeHw.value = false
        }
      } else if (failedDcTransports.has('data-channel-vp9-444')) {
        console.info(
          '[rc] data-channel-vp9-444 dropped Ã¢ÂÂ its decoder failed on real bytes earlier this page. Falling back to webrtc.',
        )
      } else {
        console.info(
          '[rc] preferred_transport=data-channel-vp9-444 dropped Ã¢ÂÂ VideoDecoder.isConfigSupported(vp09.01.10.08) returned false. Falling back to webrtc.',
        )
      }
    } else if (videoTransport.value === 'data-channel-hevc') {
      // rc.78 Ã¢ÂÂ HEVC over DataChannel (Option B). rc.186 Ã¢ÂÂ require
      // HARDWARE + real-time-smooth decode, not just "decodable":
      // `isConfigSupported` returns true even for software / too-slow HEVC,
      // and a weak iGPU then hangs at 1080p+/40fps (field: Iris Xe backs up
      // Ã¢ÂÂ keyframe spiral Ã¢ÂÂ 1-2 s hang, while VP9 4:2:0 is smooth on the
      // same device). `isHevcHwDecodeSupported()` gates on MediaCapabilities
      // `smooth` + `powerEfficient`. On failure we fall back to VP9 4:2:0
      // (profile 0 = universal fixed-function HW decode) Ã¢ÂÂ NOT VP9-444
      // (profile 1), which is ALSO software-decoded and would hang too.
      const decodable = hevcSupported.value || (await probeHevcDec())
      hevcSupported.value = decodable
      const hwSmooth = decodable
        && !failedDcTransports.has('data-channel-hevc')
        && (await probeHevcHw())
      if (hwSmooth) {
        preferredTransport = 'data-channel-hevc'
        viewerDecodeHw.value = true
        // P7 — the hevc-444 pick (chroma yuv444 on the HEVC transport):
        // honour it only when BOTH ends do Rext — this browser's probe AND
        // the agent's advertised hevc_chroma. Either missing → silently run
        // the normal 4:2:0 HEVC session (no chroma_pref sent).
        // FR-77 — chroma "Auto" on an explicit HEVC pick follows the Priority
        // dial (Sharper ⇒ try Rext); a remembered Rext decode failure keeps
        // the session on 4:2:0 without re-trying the broken cell.
        if (
          resolveChroma(vp9Chroma.value, priority.value, true) === 'yuv444'
          && !hevc444Remembered
        ) {
          const rext = hevcRextSupported.value || (await probeHevcRext())
          hevcRextSupported.value = rext
          const agentRext = cellsFromCaps(agent?.value?.capabilities).some(
            (c) => c.codec === 'hevc' && c.chroma.includes('yuv444'),
          )
          if (rext && agentRext) {
            hevcRextPick = true
          } else {
            console.info(
              rext
                ? '[rc] HEVC 4:4:4 dropped — agent does not advertise hevc_chroma yuv444 (non-nvenc host / older agent). Running HEVC 4:2:0.'
                : '[rc] HEVC 4:4:4 dropped — this browser lacks WebCodecs Rext decode (Chrome ≥137 + NV driver ≥572.16, or Intel Gen11+). Running HEVC 4:2:0.',
            )
          }
        }
      } else {
        const profile1 = vp9_444Supported.value || (await probeVp9_444())
        vp9_444Supported.value = profile1
        // #2231 — this fallback always runs at 4:2:0, so profile 0 is enough.
        const vp9Ok = profile1 || (await probeVp9_420())
        const fallback = vp9Ok && !failedDcTransports.has('data-channel-vp9-444')
        if (fallback) {
          console.info(
            decodable
              ? '[rc] data-channel-hevc dropped Ã¢ÂÂ HEVC decode is software / not real-time-smooth here (MediaCapabilities.smooth/powerEfficient). Falling back to VP9 4:2:0 (hardware).'
              : '[rc] data-channel-hevc dropped Ã¢ÂÂ HEVC decode unsupported. Falling back to VP9 4:2:0.',
          )
          preferredTransport = 'data-channel-vp9-444'
          // Force 4:2:0 (VP9 profile 0, hardware-decoded); 4:4:4 (profile 1)
          // would be software again and defeat the fallback.
          chromaOverride = 'yuv420'
          viewerDecodeHw.value = await isVp9HwDecodeSupported()
        } else {
          console.info(
            '[rc] data-channel-hevc dropped + VP9 also unsupported. Falling back to webrtc.',
          )
        }
      }
    }

    // #1631 - the decode probes above suspend too. Nothing else does between
    // here and the request send, so this one check guards both the DC/worker
    // start (which would otherwise open a channel on a NEWER attempt's peer,
    // `pc` being shared) and the `rc:session.request` itself.
    if (gen !== connectGen) return

    // FR-17 — per-chunk framing is negotiated, never assumed: only when
    // the agent advertised `chunk-framing` AND this session actually uses
    // a DataChannel transport (the RTP track has no chunks to frame).
    // Resolved HERE, immediately before the worker starts, because the
    // `init-canvas` below carries it — the parse side must not be armed
    // ahead of the request side.
    sessionChunkFraming =
      preferredTransport !== null
      && (agent?.value?.capabilities?.video ?? []).includes('chunk-framing')
    // FR-16 L4 — the same rule for the bench probe: on only when the agent
    // will answer it, decided before any worker is told.
    sessionBenchMode = benchSessionMode(storedBenchMode(), agent?.value?.capabilities?.video)
    sessionBench = sessionBenchMode !== null
    if (sessionBenchMode === 'probe') {
      console.info('[rc] bench mode: the agent advertised `bench`; probing once the input channel opens (FR-16 L4)')
    } else if (sessionBenchMode === 'target') {
      console.info('[rc] bench mode: target — probing with pointer moves onto the host\'s `roomlerd probe-target` window (FR-16 L4)')
    }

    // Everything above this point - the local-relay probe and the
    // browser's MediaCapabilities decode probes - runs before a single
    // byte goes to the server, and on a cold profile the probes are not
    // free.
    markConnect('probes_ready')

    // If we're advertising the data-channel transport, open the DC +
    // worker NOW so the channel lands in the SDP offer. The agent
    // will only actually pump bytes through it when its caps include
    // the same transport, so opening it speculatively is harmless on
    // older agents (they ignore the channel entirely).
    if (preferredTransport === 'data-channel-vp9-444') {
      // rc.190 Ã¢ÂÂ when the pick forced 4:2:0 (auto-rank / HEVC fallback),
      // configure the worker for profile 0 explicitly so the codec
      // string matches the bitstream the agent will emit, instead of
      // deriving from the user's chroma pref (which may say 4:4:4).
      startVp9_444Path(chromaOverride === 'yuv420' ? 'vp09.00.10.08' : undefined)
    } else if (preferredTransport === 'data-channel-hevc') {
      // P7 — the Rext pick reconfigures the worker's VideoDecoder with the
      // Rext codec string (same Annex-B no-description contract; only the
      // profile fields differ).
      startHevcPath(hevcRextPick ? HEVC_REXT_CODEC_STRING : undefined)
    } else if (preferredTransport === 'data-channel-av1') {
      // rc.190 Ã¢ÂÂ AV1 rides the SAME wire format + worker as VP9-over-DC
      // (13-byte length-prefix framing; the worker's VideoDecoder just
      // gets the AV1 codec string). No separate worker file needed.
      startVp9_444Path(AV1_CODEC_STRING)
    } else if (preferredTransport === 'data-channel-h264') {
      // P2 Ã¢ÂÂ H.264 rides the same worker via the avc1 codec override
      // (the AV1 precedent). The probe ladder already picked the codec
      // string this browser accepts.
      startVp9_444Path(h264DcCodec ?? H264_DC_CODEC_CANDIDATES[0])
    }

    // Kick off the rc:* handshake. browser_caps lets the agent pick
    // the best codec on its end (Phase 2 commit 2B.2 wires the
    // intersection logic + SDP munging on the agent side).
    // preferred_transport (Phase Y.3) hints which transport the
    // browser would like to use; the agent honours it only if its
    // own AgentCaps.transports contains the same entry, otherwise
    // falls back to the legacy WebRTC video track silently.
    // FR-99 P1c — PRIVACY is asked for only when THIS device serves it: the
    // page's agent, and only if it is the one being asked (a device switch
    // can race the request).
    const askedCaps = agent?.value?.id === agentId ? agent.value.capabilities : undefined
    // FR-52 P4e — an EXTERNAL session asks with its own frame: the device by
    // connect code and the verified login it spends — never an agent id, and
    // with no `local_relay` or `override_reason` to carry (F4). Everything
    // after this point (transport, chroma, framing, audio) means the same in
    // both frames. An outsider's page reads no device row, so it has no caps
    // to ask PRIVACY on, and an outsider is never granted it anyway (FR-52
    // decision 13: the server strips it, and so does the device). Its grant
    // is what it asked, under the org's ceiling.
    const requestPayload: Record<string, unknown> =
      externalMode && externalAuth
        ? {
            t: 'rc:extauth.session',
            connect_code: externalAuth.connectCode,
            attempt_id: externalAuth.attemptId,
            permissions,
            browser_caps: browserCaps,
            // FR-115 P3b — whose session slots it takes, when chosen.
            ...(externalAuth.chargeOrg ? { charge_org: externalAuth.chargeOrg } : {}),
          }
        : {
            t: 'rc:session.request',
            agent_id: agentId,
            permissions: sharedMode ? permissions : withPrivacyAsked(permissions, askedCaps),
            ...(sharedMode ? { share_grant_id: opts?.shareGrantId?.() } : {}),
            browser_caps: browserCaps,
          }
    // loopback-TURN corp-relay (Phase 2): forward the probed descriptor so the
    // Hub adds `turn:{overlay_ip}:{turn_port}` to the REMOTE agent's ICE servers
    // Ã¢ÂÂ it reaches that TURN over the overlay (WFP-permitted). Absent Ã¢ÂÂ the Hub
    // pushes nothing extra, so old servers/agents are unaffected.
    if (localRelay) {
      requestPayload.local_relay = localRelay
    }
    sessionDcTransport = preferredTransport
    // FR-77 — which chroma cell this session runs in (mirrors the chroma_pref
    // logic below; an unstated VP9 chroma is profile 1 on the agent).
    sessionCellChroma =
      preferredTransport === 'data-channel-vp9-444'
        ? (chromaOverride ?? (vp9Chroma.value !== 'auto' ? vp9Chroma.value : 'yuv444')) === 'yuv444'
          ? 'yuv444'
          : 'yuv420'
        : preferredTransport === 'data-channel-hevc' && hevcRextPick
          ? 'yuv444'
          : preferredTransport === 'data-channel-h264' && h264_444Pick
            ? 'yuv444'
            : 'yuv420'
    if (preferredTransport) {
      requestPayload.preferred_transport = preferredTransport
      // rc.62 Ã¢ÂÂ chroma_pref is only meaningful on the
      // data-channel-vp9-444 transport (rc.190 narrowed the send to it Ã¢ÂÂ
      // HEVC/AV1 sessions are 4:2:0 by construction and ignore it). Omit
      // when the user picks `'auto'` (= let agent decide via its env
      // var). rc.186 Ã¢ÂÂ a `chromaOverride` (from the software-HEVC Ã¢ÂÂ VP9
      // 4:2:0 fallback OR the rc.190 auto-rank) wins unconditionally so
      // the pick lands on the hardware-decoded profile 0 even if the
      // user left chroma on 'auto' or '4:4:4'.
      if (preferredTransport === 'data-channel-vp9-444') {
        if (chromaOverride) {
          requestPayload.chroma_pref = chromaOverride
        } else if (vp9Chroma.value !== 'auto') {
          requestPayload.chroma_pref = vp9Chroma.value
        }
      }
      // P7 — the HEVC transport now honours chroma_pref too (Rext 4:4:4 via
      // hevc_nvenc). Sent ONLY when both ends passed the Rext gate above;
      // older agents ignore the field entirely.
      if (preferredTransport === 'data-channel-hevc' && hevcRextPick) {
        requestPayload.chroma_pref = 'yuv444'
      }
      // FR-77 P3b — the H.264 transport honours chroma_pref too (High 4:4:4
      // via h264_nvenc); sent only when both gates passed above.
      if (preferredTransport === 'data-channel-h264' && h264_444Pick) {
        requestPayload.chroma_pref = 'yuv444'
      }
      // FR-17 — ask the agent to prefix every `video-bytes` message with
      // {frame_seq, chunk_idx, chunk_count}. Sent only when the agent's
      // caps say it understands the field; a pre-FR-17 agent would ignore
      // it via `#[serde(default)]` anyway, but not sending it keeps the
      // request wire identical for the fleet that can't use it.
      if (sessionChunkFraming) {
        requestPayload.chunk_framing = true
      }
    }
    // Opt-in host audio Ã¢ÂÂ `audio_enabled: true` (omitted when off so
    // pre-audio agents/servers keep the silent-by-default behaviour via
    // `#[serde(default)]`). Field name locked by a unit test on
    // `audioRequestFields`.
    Object.assign(requestPayload, audioRequestFields(sharedMode ? false : audioEnabled.value))
    // Phase 5 Ã¢ÂÂ admin break-glass. A non-empty reason asks the server to skip
    // consent; it's honoured ONLY if the server validates the caller as an
    // ADMINISTRATOR who isn't the owner (a non-admin's value is ignored). One-
    // shot: cleared after send so a later normal Connect isn't a silent force.
    if (overrideReason.value.trim() && !externalMode && !sharedMode) {
      requestPayload.override_reason = overrideReason.value.trim()
    }
    // #1631 - a request we abandoned to this same agent may still be
    // answered, and that answer is now OURS: the hub coalesces a same-socket,
    // same-agent request onto the live session. Stop the terminator first.
    abandonedRequests.disarm(agentId)
    // FR-100 P2a — whether this attempt's offer asks the device to sign its
    // answer, decided for the agent this request names. P2b — and, when it
    // asks, this browser's key starts loading now, while consent runs.
    peerAuthPlan = planPeerAuth(agentId)
    peerAuthKey = peerAuthPlan
      ? controllerKeyFor(peerAuthPlan.userId, indexedDbKeyBackend())
      : null
    ws.sendRaw(requestPayload)
    requestSent = true
    markConnect('request_sent')
    overrideReason.value = ''
    // Abandon-and-retry if the server never answers the request (WS
    // died mid-send, pod restart, ...). Cleared by rc:session.created.
    armSignalingTimeout()
  }

  /**
   * FR-52 P4e — start an EXTERNAL session on `auth`, the login the `/connect`
   * page just completed. Only on an instance created with `{ external: true }`.
   *
   * The login is spent by this one session: when it ends, its key is zeroed
   * and another session needs the password again. System audio rides the
   * grant (`AUDIO`) for an outsider, so asking for it is asking for the bit.
   */
  async function connectExternal(auth: ExternalSessionAuth) {
    if (!externalMode) throw new Error('connectExternal on a viewer that is not external')
    if (phase.value !== 'idle' && phase.value !== 'closed' && phase.value !== 'error') return
    forgetExternalAuth()
    externalAuth = auth
    const permissions = `VIEW | INPUT | CLIPBOARD | FILES${audioEnabled.value ? ' | AUDIO' : ''}`
    return connect(`ext:${auth.connectCode}`, permissions, false, undefined)
  }

  function disconnect() {
    // #1631 - read BEFORE the resets below. A request that went out and was
    // never answered (still `requesting`, or `reconnecting` after its
    // timeout) will be answered by a create this composable no longer sees
    // once removeRcHandlers() runs; the module-level registry releases it.
    const abandonedAgentId =
      (phase.value === 'requesting' || phase.value === 'reconnecting')
      && requestSent
      && !sessionId.value
        ? (lastConnectArgs?.agentId ?? null)
        : null
    requestSent = false
    // Operator-initiated teardown must override any pending
    // reconnect timer; otherwise a reconnect could fire after the
    // user already dismissed the viewer, racing the WS rc:terminate
    // we just sent.
    cancelReconnect()
    // FR-22 - an attempt the operator cancelled mid-connect still has a
    // story: which step it was waiting on when they gave up is the same
    // evidence a timeout would have produced.
    logConnectTiming('closed')
    lastConnectArgs = null
    // FR-52 P4e — the operator hung up: the login's key goes with the session.
    forgetExternalAuth()
    // End of this agent's session: later picker changes are global-only
    // until the next connect() names an agent again.
    codecAgentId = null
    codecUserPickedThisSession = false
    if (sessionId.value && pc) {
      ws.sendRaw({
        t: 'rc:terminate',
        session_id: sessionId.value,
        reason: 'controller_hangup',
      })
    }
    if (abandonedAgentId !== null) abandonedRequests.arm(abandonedAgentId)
    phase.value = 'closed'
    teardown()
    removeRcHandlers()
  }

  onBeforeUnmount(() => {
    disconnect()
    // FR-22 part 4 - disconnect() released the recorder and its listener,
    // but a view that unmounts with no attempt live never armed one; this
    // is the belt for the DC-never-opened class below.
    disarmVisibilityTiming()
    // Defensive Ã¢ÂÂ disconnect() closes the DC which stops the triggers
    // via onclose, but a DC that never opened has no onclose to fire.
    stopClipboardSyncTriggers()
  })

  /**
   * Attach mouse/keyboard/wheel listeners to a surface element (typically
   * the video container). Coordinates sent to the agent are normalised in
   * `[0,1]` per the architecture doc ÃÂ§6, so the agent can resolve them
   * against its current resolution.
   *
   * `options.onFilesPasted` is called when the operator hits Ctrl+V over
   * the viewer with files in their OS clipboard. The composable defers
   * the Ctrl+V keystroke until the `paste` event fires (a fraction of a
   * millisecond later) and decides: files Ã¢ÂÂ call onFilesPasted, no
   * keystroke forwarded; text Ã¢ÂÂ mirror to host clipboard via existing
   * `setAgentClipboard` + emit deferred Ctrl+V; empty Ã¢ÂÂ emit deferred
   * Ctrl+V as a fallback.
   *
   * Returns a detach function the caller should invoke before unmounting.
   */
  function attachInput(
    surface: HTMLElement,
    options?: {
      onFilesPasted?: (files: File[]) => void
      /** Element to focus on pointerenter to steal focus from left-
       *  panel nav-drawer items / page buttons. Should have
       *  `tabindex="-1"` so it doesn't enter the Tab order but
       *  accepts programmatic `.focus()`. Field bug rc.17: clicking a
       *  Dashboard / Rooms / Files nav item then connecting to the
       *  viewer left that `<v-list-item>` focused; the first Enter /
       *  Space pressed over the viewer fired Vuetify's keyboard-
       *  activation `@click` and navigated away. */
      focusAnchor?: HTMLElement
      /** Called after a Ctrl+C-over-viewer auto-mirror attempt.
       *  `ok === true`  Ã¢ÂÂ text written to `navigator.clipboard` OK.
       *  `ok === false` Ã¢ÂÂ browser refused `writeText` (no permission /
       *  no user-gesture chain); caller shows a snackbar with the
       *  text + a manual Copy button so the operator can still get
       *  the content. */
      onClipboardMirrored?: (text: string, ok: boolean) => void
      /** FR-111 — a two-finger pinch on the stage: zoom the viewer's own
       *  picture by `factor` around the client point (`cx`, `cy`). Nothing is
       *  sent to the host. */
      onPinchZoom?: (factor: number, cx: number, cy: number) => void
      /** FR-111 decision 4 — two fingers moving together in direct mode, by
       *  (`dx`, `dy`) px (positive scrolls down/right). The view returns true
       *  when it consumed them, panning a picture larger than the stage; only
       *  otherwise do they scroll the host. */
      onTwoFingerScroll?: (dx: number, dy: number) => boolean
    }
  ): () => void {
    // Locate the <video> once, fall back gracefully if the layout changes.
    const findVideo = () =>
      (surface.querySelector('video') as HTMLVideoElement | null) ??
      (surface.firstElementChild as HTMLVideoElement | null)
    const clamp01 = (n: number) => Math.min(Math.max(n, 0), 1)
    // FR-16 L4 — the bench sampler finds the `<video>` in here.
    benchSurface = surface
    // FR-109 — and Pointer Lock locks it.
    relativeSurface = surface
    // FR-109 P3 — the auto-switch's kill switch, read once per attach.
    try {
      relativeAutoOff = relativeAutoSwitchedOff(globalThis.localStorage)
    } catch {
      relativeAutoOff = false
    }
    relativeAutoSuppressed = false
    swallowedButton = null

    /**
     * Returns [0,1]-normalised coordinates relative to the *visible video
     * content* Ã¢ÂÂ not the outer .video-frame. The `<video>` uses
     * `object-fit: contain`, which letterboxes the stream when the display
     * aspect ratio differs from the source (e.g. 2560x1600 viewport showing
     * a 3840x2160 agent). Without this correction, clicks land at the wrong
     * pixel on the remote, and clicks in the letterbox bars get clamped to
     * the edge instead of being ignored.
     */
    // rc.57 Ã¢ÂÂ mouse-offset diagnostic counter. Logs the first 50
    // pointer-derived normalisation calls of THIS session at INFO
    // level so we can verify that the browser-side intrinsic dims
    // (videoElement.videoWidth/Height after the agent's auto-downscale
    // rebuild) match what the agent expects. The Crystal-Clear-OFF
    // H.264 path on WINHOST-A still mis-positions and we suspect a
    // race between the SDP-advertised native dims (1920ÃÂ1200) and
    // the actual first frame (1280ÃÂ800 post-downscale) Ã¢ÂÂ this log
    // captures intrinsicW/H + renderRect + computed norm so a single
    // session reproduces the bug AND surfaces the root cause.
    //
    // Counter is closure-scoped to `attachInput`, so it naturally
    // resets per-session (each remote-control mount is a new
    // attachInput call). NO process-global state.
    const MOUSE_OFFSET_DIAG_LIMIT = 50
    let mouseOffsetDiagCount = 0

    function normalisedXY(
      ev: PointerEvent | MouseEvent | WheelEvent,
    ): { x: number; y: number; insideVideo: boolean } {
      const video = findVideo()
      // VP9-444 mode: the `<video>` is hidden + unfed (the agent's
      // pump routed encoded frames to the `video-bytes` DC instead of
      // the WebRTC track), so `video.videoWidth` is 0. The visible
      // surface is the `<canvas>` painted by rc-vp9-444-worker, and
      // its intrinsic dimensions (the agent's encode resolution) are
      // already cached in `mediaIntrinsicW/H` from the worker's
      // `first-frame` message. Use that instead Ã¢ÂÂ without it the
      // letterbox math hits divide-by-zero and every pointer event
      // gets mapped to NaN, dropping all clicks/moves silently.
      // Same shape applies to the WebCodecs render path (the canvas
      // there also reports via `first-frame`), but in that path the
      // `<video>` is also fed the RTP track so videoWidth is non-zero
      // anyway Ã¢ÂÂ falling through to the canvas path is harmless.
      // rc.95 Ã¢ÂÂ HEVC-over-DC is a canvas path too (rc-hevc-worker reports
      // dims via `first-frame` Ã¢ÂÂ mediaIntrinsicW/H). It was MISSING here,
      // so HEVC sessions mapped input against the now-hidden `<video>`'s
      // videoWidth=0 (the sibling of the RemoteControl.vue `<video>`
      // v-show omission that black-screened HEVC). Include it.
      const useCanvasDims =
        vp9_444Active.value || webcodecsActive.value || hevcActive.value
      const intrinsicW = useCanvasDims
        ? mediaIntrinsicW.value
        : (video?.videoWidth ?? 0)
      const intrinsicH = useCanvasDims
        ? mediaIntrinsicH.value
        : (video?.videoHeight ?? 0)
      // In `original` / `custom` scale modes the surface element is
      // sized to its own intrinsic pixels (ÃÂ custom scale) Ã¢ÂÂ there's
      // no letterboxing inside it, so map directly against its
      // bounding rect. In `adaptive` mode the element fills the stage
      // and `object-fit: contain` letterboxes internally, so we need
      // the stage rect + aspect-ratio math.
      //
      // Pick the live render surface for the direct-bounding-rect
      // path: video in legacy mode, canvas in VP9-444 / WebCodecs
      // modes. (The `<video>` is `display: none` in the latter two,
      // so getBoundingClientRect() would report a zero rect.)
      const renderEl: HTMLElement | null = useCanvasDims
        ? (surface.querySelector('canvas.remote-video') as HTMLElement | null)
        : video

      let result: { x: number; y: number; insideVideo: boolean }
      let path: 'direct' | 'letterbox'
      let renderRect: DOMRect | null = null
      let frameRect: DOMRect | null = null

      if (scaleMode.value !== 'adaptive' && renderEl) {
        renderRect = renderEl.getBoundingClientRect()
        result = directVideoNormalise(
          ev.clientX, ev.clientY,
          { left: renderRect.left, top: renderRect.top, width: renderRect.width, height: renderRect.height },
        )
        path = 'direct'
      } else {
        frameRect = surface.getBoundingClientRect()
        result = letterboxedNormalise(
          ev.clientX, ev.clientY,
          { left: frameRect.left, top: frameRect.top, width: frameRect.width, height: frameRect.height },
          intrinsicW, intrinsicH,
        )
        path = 'letterbox'
      }

      // rc.57 Ã¢ÂÂ diagnostic dump (first 50 events of this session). Search
      // browser console for `[rc] mouse-offset diag` to triage misposition
      // reports. Compare `intrinsicW/H` against the agent log's reported
      // capture width/height; mismatch identifies the auto-downscale race.
      if (mouseOffsetDiagCount < MOUSE_OFFSET_DIAG_LIMIT) {
        const seq = mouseOffsetDiagCount++
        // rc.101 Ã¢ÂÂ log the canvas's ACTUAL rendered rect. `renderRect` is
        // only computed in the direct (non-letterbox) path; in adaptive
        // letterbox mode it's null. If `canvasRectW/H` reads the backing-
        // store size (e.g. 2560ÃÂ1600) instead of the frame size, the canvas
        // isn't constrained to its container Ã¢ÂÂ CSS sizing bug (the rc.101
        // overflow symptom on NEO16). When constrained it should equal the
        // frame box (object-fit letterboxes the bitmap inside it).
        const elRect = renderEl?.getBoundingClientRect() ?? null
        console.info('[rc] mouse-offset diag', {
          seq,
          path,
          scaleMode: scaleMode.value,
          useCanvasDims,
          videoWidth: video?.videoWidth ?? 0,
          videoHeight: video?.videoHeight ?? 0,
          mediaIntrinsicW: mediaIntrinsicW.value,
          mediaIntrinsicH: mediaIntrinsicH.value,
          intrinsicW,
          intrinsicH,
          vp9_444Active: vp9_444Active.value,
          webcodecsActive: webcodecsActive.value,
          hevcActive: hevcActive.value,
          renderElTag: renderEl?.tagName ?? null,
          renderRectW: renderRect?.width ?? null,
          renderRectH: renderRect?.height ?? null,
          canvasRectW: elRect ? Math.round(elRect.width) : null,
          canvasRectH: elRect ? Math.round(elRect.height) : null,
          frameRectW: frameRect?.width ?? null,
          frameRectH: frameRect?.height ?? null,
          clientX: Math.round(ev.clientX),
          clientY: Math.round(ev.clientY),
          computedX: Number(result.x.toFixed(4)),
          computedY: Number(result.y.toFixed(4)),
          insideVideo: result.insideVideo,
        })
      }

      return result
    }

    function onPointerMove(ev: PointerEvent) {
      // FR-111 — a finger's moves are the recognizer's to read.
      if (isGestureTouch(ev)) {
        touchStep('move', ev)
        return
      }
      // FR-109 — under Pointer Lock the position is frozen and only the
      // deltas mean anything; they go out as `mouse_rel` at the input gap.
      if (relativeMouse.value) {
        relAcc.add(ev.movementX, ev.movementY)
        scheduleRel()
        return
      }
      const { x, y, insideVideo } = normalisedXY(ev)
      if (!insideVideo) return
      // FR-93 — every synthetic button-up reuses this (`releaseHeldInputs` on
      // blur or a hidden tab, and a drag that ends outside the picture), so it
      // must follow the POINTER. Updated on press and release only, it held
      // the press point: on the FR-93 lab a tab closed mid-drag let go at
      // (0.5,0.5) after the drag had reached (0.6,0.6), and the host's cursor
      // snapped back to where the drag began.
      lastPointerNorm = { x, y }
      pendingMove = { x, y, mon: 0 }
      schedulePendingMove()
    }

    // Cancel any RAF-queued mouse_move so it can't fire *after* a click
    // and overwrite whatever move the user does next. Without this, a
    // fast click-then-drag can register a stale mouse_move at the click
    // coords between the button event and the subsequent moves.
    function cancelPendingMove() {
      if (moveTimer !== null) {
        clearTimeout(moveTimer)
        moveTimer = null
      }
      pendingMove = null
    }

    function onPointerDown(ev: PointerEvent) {
      ev.preventDefault()
      // FR-111 — a finger presses nothing yet: the recognizer decides what it
      // is (a tap, a drag, a long press, half of a two-finger gesture). One
      // landing outside the picture starts nothing, as a mouse press there
      // does, but a second finger during a gesture still counts.
      if (isGestureTouch(ev)) {
        // In trackpad mode the whole stage is the pad, letterbox included.
        const pad = touchMode.value === 'trackpad'
        if (!pad && !normalisedXY(ev).insideVideo && !touchActive()) return
        if (!touchActive()) {
          touchWheel.reset()
          padPointer = null
        }
        try { surface.setPointerCapture(ev.pointerId) } catch { /* noop */ }
        touchStep('down', ev)
        return
      }
      // FR-109 — relative mode presses where the host's pointer is. The
      // motion gathered so far goes first, so the press lands after it.
      if (relativeMouse.value) {
        flushRel()
        const btn = browserButton(ev.button)
        sendInput(relativeButtonMessage(btn, true))
        heldInputs.button(btn, true)
        pointerPresses.press(ev.pointerId, btn)
        return
      }
      const { x, y, insideVideo } = normalisedXY(ev)
      if (!insideVideo) return
      // FR-109 P3 — the host hid its cursor (an app captured the pointer):
      // this click enters relative mode. It is the gesture Pointer Lock needs,
      // not input: forwarded, an absolute press would first jump the captured
      // pointer to where the click happened.
      if (shouldAutoEnterRelative({
        allowed: relativeMouseAllowed.value,
        autoOff: relativeAutoOff,
        cursorHidden: hostCursorHidden.value,
        cursorTracked: hostCursorTracked,
        hostLocked: hostLocked.value,
        suppressed: relativeAutoSuppressed,
        relativeActive: relativeMouse.value,
        inputGranted: inputGranted.value,
      })) {
        swallowedButton = browserButton(ev.button)
        relativeMouseAuto.value = true
        void enterRelativeMouse().then((ok) => {
          if (!ok) relativeMouseAuto.value = false
        })
        return
      }
      cancelPendingMove()
      surface.setPointerCapture(ev.pointerId)
      lastPointerNorm = { x, y }
      sendInput({ t: 'mouse_button', btn: browserButton(ev.button), down: true, x, y, mon: 0 })
      heldInputs.button(browserButton(ev.button), true)
      pointerPresses.press(ev.pointerId, browserButton(ev.button))
    }

    function onPointerUp(ev: PointerEvent) {
      if (isGestureTouch(ev)) {
        try { surface.releasePointerCapture(ev.pointerId) } catch { /* noop */ }
        touchStep('up', ev)
        return
      }
      pointerPresses.end(ev.pointerId)
      // FR-109 P3 — the button-up of the click that entered relative mode.
      if (swallowedButton !== null && browserButton(ev.button) === swallowedButton) {
        swallowedButton = null
        return
      }
      if (relativeMouse.value) {
        flushRel()
        const btn = browserButton(ev.button)
        sendInput(relativeButtonMessage(btn, false))
        heldInputs.button(btn, false)
        return
      }
      try { surface.releasePointerCapture(ev.pointerId) } catch { /* noop */ }
      const { x, y, insideVideo } = normalisedXY(ev)
      cancelPendingMove()
      // A press we forwarded MUST get its release even when the pointer
      // ended outside the video (drag past the edge used to leave the
      // host's mouse button physically stuck down). Use the last inside
      // position for the up when the current one is out of bounds; a
      // stray up for a never-pressed button is harmless on the host.
      const btn = browserButton(ev.button)
      const ux = insideVideo ? x : lastPointerNorm.x
      const uy = insideVideo ? y : lastPointerNorm.y
      if (insideVideo) lastPointerNorm = { x, y }
      sendInput({ t: 'mouse_button', btn, down: false, x: ux, y: uy, mon: 0 })
      heldInputs.button(btn, false)
    }

    // FR-111 — a browser that takes a pointer over (a touch drag read as a pan
    // or a zoom, a system gesture) ends it with `pointercancel` and never sends
    // `pointerup`. The press is already on the host, so it must still be let
    // go, or the host's button stays down and the next touch's moves become a
    // drag (P0 measured exactly that). A cancel's position is not worth
    // trusting: release at the last point the pointer reached.
    function onPointerCancel(ev: PointerEvent) {
      if (isGestureTouch(ev)) {
        touchCancel(ev.pointerId)
        return
      }
      const btn = pointerPresses.end(ev.pointerId)
      if (btn === undefined) return
      if (relativeMouse.value) {
        flushRel()
      } else {
        try { surface.releasePointerCapture(ev.pointerId) } catch { /* noop */ }
        cancelPendingMove()
      }
      sendInput(releaseForCancelledPointer(btn, relativeMouse.value, lastPointerNorm))
      heldInputs.button(btn, false)
    }

    // #2367 — the agent turns a pixel wheel into 100 px steps and rounds every
    // frame on its own, so the few-pixel frames of a precision trackpad or a
    // high-resolution wheel scrolled nothing (10 × 20 px reached the host as
    // no wheel at all). Pixel-mode events are gathered and sent as whole steps,
    // like FR-111's touch scroll; a pause drops the carry, so a stopped scroll
    // leaves nothing behind for the next one.
    const pixelWheel = createWheelSteps()
    let pixelWheelIdle: ReturnType<typeof setTimeout> | null = null
    function onWheel(ev: WheelEvent) {
      ev.preventDefault()
      // Browser uses positive Y for down; agent does the same.
      if (ev.deltaMode !== 0) {
        sendInput({
          t: 'mouse_wheel',
          dx: ev.deltaX,
          dy: ev.deltaY,
          mode: ev.deltaMode === 1 ? 'line' : 'page',
        })
        return
      }
      const step = pixelWheel.add(ev.deltaX, ev.deltaY)
      if (step) sendInput({ t: 'mouse_wheel', dx: step.dx, dy: step.dy, mode: 'pixel' })
      if (pixelWheelIdle !== null) clearTimeout(pixelWheelIdle)
      pixelWheelIdle = setTimeout(() => {
        pixelWheelIdle = null
        pixelWheel.reset()
      }, WHEEL_CARRY_IDLE_MS)
    }

    // Track whether the pointer is currently over the remote-viewer
    // surface. When true, browser-eaten shortcuts like Ctrl+A / Ctrl+C
    // are intercepted locally (preventDefault) and forwarded to the
    // remote only. When false, the controller keeps normal browser UX
    // (Ctrl+T opens a new tab, Ctrl+F triggers find, etc.).
    let pointerInside = false
    function onPointerEnter() {
      pointerInside = true
      // rc.18: steal focus from whatever the operator clicked last
      // (typically a left-panel nav-drawer item) so Enter / Space /
      // Arrow keys pressed over the viewer DON'T fire the focused
      // element's `@click` keyboard-activation handler. Two-step:
      // blur the active element + focus our anchor. Anchor has
      // tabindex="-1" so it accepts programmatic focus without
      // entering Tab order.
      if (options?.focusAnchor) {
        const active = document.activeElement
        if (active instanceof HTMLElement && active !== options.focusAnchor) {
          active.blur()
        }
        try {
          options.focusAnchor.focus({ preventScroll: true })
        } catch {
          /* old browsers without `preventScroll`: blurring above is
             enough to fix the immediate bug; the focus call is
             defence-in-depth */
        }
      } else if (document.activeElement instanceof HTMLElement) {
        // No anchor given by caller Ã¢ÂÂ just blur. Active element ends
        // up on <body>; harmless.
        document.activeElement.blur()
      }
    }
    function onPointerLeave() { pointerInside = false }

    // Phase 5 (file-DC v2) Ã¢ÂÂ deferred Ctrl+V over viewer.
    //
    // When the operator hits Ctrl+V with the pointer over the viewer,
    // we don't immediately forward the keystroke. The browser fires
    // a `paste` event microseconds later; we use that to decide:
    //   - Files in clipboard  Ã¢ÂÂ upload them; the remote app does
    //     NOT receive a Ctrl+V keystroke (that wasn't the operator's
    //     intent Ã¢ÂÂ they meant "upload these files").
    //   - Text in clipboard   Ã¢ÂÂ mirror to the host clipboard via
    //     the existing `clipboard:write` + emit the deferred Ctrl+V
    //     so the remote app's paste sees the right text.
    //   - Empty clipboard     Ã¢ÂÂ emit the deferred Ctrl+V as a normal
    //     keystroke (operator intent unclear; preserve current
    //     behaviour).
    //
    // 50 ms timeout fallback: some browsers don't fire `paste` if
    // the clipboard is empty / denied. After 50 ms with the keystroke
    // still pending, flush it as a normal Ctrl+V. 50 ms is below the
    // human keystroke-perception threshold but well above paste-event
    // scheduling.
    //
    // The keyup is also intercepted while a deferral is active so we
    // don't emit a stray V-up against an un-down'd V on the agent.
    let pendingCtrlV: { mods: number; timer: ReturnType<typeof setTimeout> | null } | null = null
    const KEY_V_HID = 0x19

    // Every HID key / pointer button we press on the host is recorded here
    // and force-released when this window loses focus (alt-tab, minimize,
    // OS-level steal) — see createHeldInputTracker for the stuck-Alt story.
    const heldInputs = createHeldInputTracker()
    // FR-111 — which button each pointer pressed on the host, so a pointer the
    // browser cancels (a touch drag it took over as a pan) still lets go of
    // exactly that button, and one that pressed nothing releases nothing.
    const pointerPresses = createPointerPressTracker()
    // Last normalized pointer position inside the picture — synthetic
    // button-ups reuse it so releasing a stuck drag doesn't teleport the host
    // cursor. ⚠️ Every pointer MOVE updates it (onPointerMove), not only a
    // press: a press-only value is exactly the teleport this exists to avoid.
    let lastPointerNorm = { x: 0.5, y: 0.5 }

    // FR-111 P1 — a finger goes through the gesture recognizer (direct mode:
    // tap, drag, long press, two-finger tap / scroll, pinch); a mouse or a pen
    // keeps the paths above. `roomler-rc-touch=legacy` sends a finger down the
    // mouse's path, as before FR-111.
    const touchGestures = createDirectGestures()
    // A two-finger scroll's pixels, let out as whole agent wheel steps: the
    // agent rounds every frame on its own, so a few pixels each would scroll
    // nothing (the field showed exactly that).
    const touchWheel = createWheelSteps()
    const touchGesturesOn = stageTouchAction((() => {
      try {
        return globalThis.localStorage
      } catch {
        return null
      }
    })()) === 'none'
    let longPressTimer: ReturnType<typeof setTimeout> | null = null
    function isGestureTouch(ev: PointerEvent): boolean {
      return touchGesturesOn && ev.pointerType === 'touch' && !relativeMouse.value
    }
    function touchSample(ev: PointerEvent): TouchSample {
      const { x, y } = normalisedXY(ev)
      return {
        id: ev.pointerId,
        px: ev.clientX,
        py: ev.clientY,
        nx: Math.min(1, Math.max(0, x)),
        ny: Math.min(1, Math.max(0, y)),
        t: performance.now(),
      }
    }
    function runGestures(actions: GestureAction[]) {
      for (const a of actions) {
        switch (a.kind) {
          case 'press':
            cancelPendingMove()
            lastPointerNorm = { x: a.x, y: a.y }
            sendInput({ t: 'mouse_button', btn: a.btn, down: true, x: a.x, y: a.y, mon: 0 })
            heldInputs.button(a.btn, true)
            break
          case 'move':
            lastPointerNorm = { x: a.x, y: a.y }
            pendingMove = { x: a.x, y: a.y, mon: 0 }
            schedulePendingMove()
            break
          case 'release':
            cancelPendingMove()
            sendInput({ t: 'mouse_button', btn: a.btn, down: false, x: a.x, y: a.y, mon: 0 })
            heldInputs.button(a.btn, false)
            break
          case 'wheel': {
            // FR-111 decision 4 — a picture zoomed past the stage is panned by
            // the two fingers; the host scrolls only when it fits.
            if (options?.onTwoFingerScroll?.(a.dx, a.dy)) break
            const step = touchWheel.add(a.dx, a.dy)
            if (step) sendInput({ t: 'mouse_wheel', dx: step.dx, dy: step.dy, mode: 'pixel' })
            break
          }
          case 'zoom':
            options?.onPinchZoom?.(a.factor, a.cx, a.cy)
            break
        }
      }
      armTouchTimer()
    }

    // FR-111 P2 — trackpad mode. The finger moves the host's pointer; its
    // travel is measured in the picture's own normalised space, so letterbox
    // and zoom are already accounted for.
    const trackpad = createTrackpadGestures()
    /** For an agent without `mouse-rel`: where the host's pointer is, seeded
     *  from the last `cursor:pos` when a gesture starts, then moved by the
     *  finger. */
    let padPointer: { x: number; y: number } | null = null
    function hostPointerNorm(): { x: number; y: number } {
      const pos = cursor.value.pos
      const w = mediaIntrinsicW.value
      const h = mediaIntrinsicH.value
      if (pos && w > 0 && h > 0) return { x: clamp01(pos.x / w), y: clamp01(pos.y / h) }
      return { ...lastPointerNorm }
    }
    /** A finger's travel in CSS pixels, as a share of the picture. */
    function padTravel(dx: number, dy: number): { x: number; y: number } {
      const r = surface.getBoundingClientRect()
      const cx = r.left + r.width / 2
      const cy = r.top + r.height / 2
      const a = normalisedXY({ clientX: cx, clientY: cy } as MouseEvent)
      const b = normalisedXY({ clientX: cx + dx, clientY: cy + dy } as MouseEvent)
      return { x: b.x - a.x, y: b.y - a.y }
    }
    function runTrackpad(actions: TrackpadAction[]) {
      // An agent that takes `mouse_rel` (FR-109) gets the travel as motion and
      // presses where its pointer is; an older one gets absolute moves from
      // the pointer's last known position.
      const rel = relativeMouseAllowed.value
      for (const a of actions) {
        switch (a.kind) {
          case 'pointer': {
            const t = padTravel(a.dx, a.dy)
            if (rel) {
              relAcc.add(t.x * mediaIntrinsicW.value, t.y * mediaIntrinsicH.value)
              scheduleRel()
            } else {
              const p = padPointer ?? hostPointerNorm()
              padPointer = { x: clamp01(p.x + t.x), y: clamp01(p.y + t.y) }
              lastPointerNorm = { ...padPointer }
              pendingMove = { x: padPointer.x, y: padPointer.y, mon: 0 }
              schedulePendingMove()
            }
            break
          }
          case 'press':
          case 'release': {
            const down = a.kind === 'press'
            if (rel) {
              flushRel()
              sendInput(relativeButtonMessage(a.btn, down))
            } else {
              const p = padPointer ?? hostPointerNorm()
              cancelPendingMove()
              sendInput({ t: 'mouse_button', btn: a.btn, down, x: p.x, y: p.y, mon: 0 })
            }
            heldInputs.button(a.btn, down)
            break
          }
          case 'wheel': {
            const step = touchWheel.add(a.dx, a.dy)
            if (step) sendInput({ t: 'mouse_wheel', dx: step.dx, dy: step.dy, mode: 'pixel' })
            break
          }
          case 'zoom':
            options?.onPinchZoom?.(a.factor, a.cx, a.cy)
            break
        }
      }
      armTouchTimer()
    }

    /** Re-arm the long-press / hold timer for whatever the current mode's
     *  recognizer waits on now. */
    function armTouchTimer() {
      if (longPressTimer !== null) {
        clearTimeout(longPressTimer)
        longPressTimer = null
      }
      const pad = touchMode.value === 'trackpad'
      const due = pad ? trackpad.deadline() : touchGestures.deadline()
      if (due !== null) {
        longPressTimer = setTimeout(() => {
          longPressTimer = null
          if (pad) runTrackpad(trackpad.tick(performance.now()))
          else runGestures(touchGestures.tick(performance.now()))
        }, Math.max(0, due - performance.now()) + 5)
      }
    }

    // FR-111 P3 — the on-screen controls' presses. A key goes out as the
    // keyboard's frame would (Ctrl as Cmd on a Mac host, FR-13); a mouse
    // button and the stick take the trackpad's two paths. What they hold is
    // tracked like any other press, so a blur or a detach lets go of it, and
    // a release for something already let go is dropped.
    const controlKeys = new Map<number, number>() // the usage pressed → the usage sent
    const controlBtns = new Set<MouseBtn>()
    const stageControls: ControlsSink = {
      key(code, down) {
        if (down === controlKeys.has(code)) return
        let sent = code
        if (down) {
          if (hostIsMac.value && ctrlAsCmd.value && (code === 0xe0 || code === 0xe4)) sent = 0xe3
          controlKeys.set(code, sent)
        } else {
          sent = controlKeys.get(code) ?? code
          controlKeys.delete(code)
        }
        heldInputs.key(sent, down)
        sendInput({ t: 'key', code: sent, down, mods: modsOf(controlKeys.values()) })
      },
      button(btn, down) {
        if (down === controlBtns.has(btn)) return
        if (down) controlBtns.add(btn)
        else controlBtns.delete(btn)
        if (relativeMouseAllowed.value) {
          flushRel()
          sendInput(relativeButtonMessage(btn, down))
        } else {
          const p = padPointer ?? hostPointerNorm()
          cancelPendingMove()
          sendInput({ t: 'mouse_button', btn, down, x: p.x, y: p.y, mon: 0 })
        }
        heldInputs.button(btn, down)
      },
      move(dx, dy) {
        if (relativeMouseAllowed.value) {
          relAcc.add(dx, dy)
          scheduleRel()
          return
        }
        const w = mediaIntrinsicW.value
        const h = mediaIntrinsicH.value
        if (w <= 0 || h <= 0) return
        const p = padPointer ?? hostPointerNorm()
        padPointer = { x: clamp01(p.x + dx / w), y: clamp01(p.y + dy / h) }
        lastPointerNorm = { ...padPointer }
        pendingMove = { x: padPointer.x, y: padPointer.y, mon: 0 }
        schedulePendingMove()
      },
      begin() {
        padPointer = null
      },
      end() {
        padPointer = null
      },
      width: () => mediaIntrinsicW.value,
    }
    controlsSink = stageControls

    /** One touch event, to the current mode's recognizer. */
    function touchStep(kind: 'down' | 'move' | 'up', ev: PointerEvent) {
      const p = touchSample(ev)
      if (touchMode.value === 'trackpad') runTrackpad(trackpad[kind](p))
      else runGestures(touchGestures[kind](p))
    }
    function touchCancel(id: number) {
      if (touchMode.value === 'trackpad') runTrackpad(trackpad.cancel(id))
      else runGestures(touchGestures.cancel(id))
    }
    function touchActive(): boolean {
      return touchMode.value === 'trackpad' ? trackpad.active() : touchGestures.active()
    }

    function releaseHeldInputs() {
      // A pending Ctrl+V deferral must not fire its 50 ms fallback AFTER
      // focus already left this window (it would paste at the host while
      // the operator is working in a local app).
      if (pendingCtrlV?.timer) clearTimeout(pendingCtrlV.timer)
      pendingCtrlV = null
      const held = heldInputs.releaseAll()
      // FR-111 P3 — this lets go of the on-screen controls' presses too, so
      // the overlay's own release later is a duplicate and is dropped.
      controlKeys.clear()
      controlBtns.clear()
      for (const btn of held.buttons) {
        // FR-109 — in relative mode there is no position to go back to: the
        // host app owns the cursor, so let go where it is.
        sendInput(relativeMouse.value
          ? relativeButtonMessage(btn, false)
          : {
              t: 'mouse_button',
              btn,
              down: false,
              x: lastPointerNorm.x,
              y: lastPointerNorm.y,
              mon: 0,
            })
      }
      for (const code of held.keys) {
        sendInput({ t: 'key', code, down: false, mods: 0 })
      }
    }

    function flushPendingCtrlV() {
      if (!pendingCtrlV) return
      const mods = pendingCtrlV.mods
      if (pendingCtrlV.timer) clearTimeout(pendingCtrlV.timer)
      pendingCtrlV = null
      sendInput({ t: 'key', code: KEY_V_HID, down: true, mods })
      sendInput({ t: 'key', code: KEY_V_HID, down: false, mods })
    }

    function isCtrlVOverViewer(ev: KeyboardEvent): boolean {
      // Locked fullscreen counts as "over the viewer": pointerInside
      // is driven by pointerenter/leave on the surface and can be
      // stale right after entering fullscreen via the toolbar button
      // (which sits OUTSIDE the fullscreen target). Without this, the
      // locked-mode preventDefault-everything policy would suppress
      // the paste event and degrade Ctrl+V to a stale-clipboard flush.
      if (!pointerInside && !keyboardLockActive.value) return false
      if (ev.code !== 'KeyV') return false
      if (!(ev.ctrlKey || ev.metaKey)) return false
      // If focus is in an INPUT / TEXTAREA / contenteditable element,
      // the operator is editing a page text field Ã¢ÂÂ let the native
      // paste flow happen there; don't intercept.
      const target = ev.target as Element | null
      if (target) {
        const tag = target.tagName
        if (tag === 'INPUT' || tag === 'TEXTAREA') return false
        const editable = (target as HTMLElement).isContentEditable
        if (editable) return false
      }
      return true
    }

    /** Ctrl+C over viewer (rc.18 P5). Mirrors the Ctrl+V helper's
     *  carve-out for page-text-field focus so the operator's normal
     *  copy-from-form-field doesn't get hijacked. */
    function isCtrlCOverViewer(ev: KeyboardEvent): boolean {
      // Same locked-fullscreen carve-out as isCtrlVOverViewer.
      if (!pointerInside && !keyboardLockActive.value) return false
      if (ev.code !== 'KeyC') return false
      if (!(ev.ctrlKey || ev.metaKey)) return false
      const target = ev.target as Element | null
      if (target) {
        const tag = target.tagName
        if (tag === 'INPUT' || tag === 'TEXTAREA') return false
        const editable = (target as HTMLElement).isContentEditable
        if (editable) return false
      }
      return true
    }

    /** Schedule a 25 ms-delayed read of the host's clipboard + mirror
     *  to the browser's `navigator.clipboard`. 25 ms is enough for
     *  the remote app to finish its copy (well under human perception)
     *  and avoids a race with the agent's Ctrl+C HID handling.
     *
     *  On failure (DC closed, agent doesn't reply within 5 s, or
     *  `writeText` is refused by the browser's user-gesture policy)
     *  the caller's `onClipboardMirrored(text, false)` fires so the
     *  parent component can surface a snackbar with a manual Copy
     *  button Ã¢ÂÂ keeps the operator's intent reachable.
     */
    function scheduleClipboardMirror() {
      // v2 Ã¢ÂÂ when change events are flowing, the agent pushes the
      // fresh copy the instant its clipboard changes; the delayed
      // read-back mirror is redundant (and its writeText would fight
      // the event's own apply).
      if (
        clipboardAutoSyncEnabled.value &&
        supportsClipboardEvents.value &&
        !clipboardSyncBlocked.value
      ) {
        return
      }
      const delayMs = 25
      setTimeout(() => {
        // Fire-and-forget. We deliberately don't await in the
        // keydown handler Ã¢ÂÂ the host needs to process Ctrl+C before
        // its clipboard reflects the copy.
        getAgentClipboard()
          .then(async (text: string) => {
            if (!text) return // remote clipboard was empty; no-op
            let ok = false
            try {
              await navigator.clipboard.writeText(text)
              ok = true
            } catch {
              // Browser denied (no user-gesture chain, no permission,
              // or no clipboard-write API in this context). The
              // callback exposes the text for a fallback path.
              ok = false
            }
            options?.onClipboardMirrored?.(text, ok)
          })
          .catch(() => {
            // Agent didn't respond, DC closed, etc. Ã¢ÂÂ silent drop;
            // the operator's local clipboard stays unchanged, same
            // as pre-rc.18 behaviour.
          })
      }, delayMs)
    }

    function onKey(ev: KeyboardEvent, down: boolean) {
      // FR-111 P4b-2 — a dialog is taking the typing: leave the event to it,
      // untouched (no preventDefault, no stopPropagation).
      if (keyboardPaused.value) return
      // Ctrl+Alt+End (RDP convention) / literal Ctrl+Alt+Del Ã¢ÂÂ
      // canonical SAS sequence via sendCtrlAltDel(). Swallow BOTH key
      // directions so no stray End/Delete HID events reach the host;
      // `ev.repeat` guard fires the SAS exactly once per held chord.
      // Gated on driving intent: pointer over the viewer OR locked
      // fullscreen (where pointerInside can be stale until the first
      // boundary event). Must run BEFORE the Ctrl+V deferral Ã¢ÂÂ the
      // chords are disjoint but the ordering keeps this hot path
      // first-match.
      if (
        isRemoteSasChord(ev, (k) => ev.getModifierState(k)) &&
        (pointerInside || keyboardLockActive.value)
      ) {
        ev.preventDefault()
        ev.stopPropagation()
        if (down && !ev.repeat) sendCtrlAltDel()
        return
      }

      // Ctrl+V deferral path. Keep preventDefault on keydown so the
      // subsequent `paste` event fires (and so the browser doesn't
      // run a default for the V key). Skip the normal sendInput path
      // Ã¢ÂÂ flushPendingCtrlV / paste handler will emit the keystroke
      // if the clipboard didn't have files.
      if (isCtrlVOverViewer(ev)) {
        // CRITICAL: do NOT call ev.preventDefault() on this keydown.
        // Per HTML spec, preventDefault on a keydown that would
        // trigger paste suppresses the subsequent `paste` event
        // entirely Ã¢ÂÂ `clipboardData` is never delivered to our
        // listener and the deferred-keystroke design degenerates
        // into "always flush as plain Ctrl+V" (rc.12-rc.15 bug).
        // Field repro rc.15 2026-05-07: Ctrl+V never uploads files.
        //
        // Instead: stash pendingCtrlV (skip the sendInput keystroke
        // forwarding) and let the browser's natural paste pipeline
        // fire. The window-level `paste` listener decides Ã¢ÂÂ files Ã¢ÂÂ
        // upload, text Ã¢ÂÂ clipboard:write + flush keystroke, empty
        // clipboard Ã¢ÂÂ 50 ms timer flushes as normal Ctrl+V.
        //
        // Keystroke forwarding is suppressed by the `return` below
        // (we exit before `sendInput`); the host won't see Ctrl+V
        // until the paste handler explicitly flushes it.
        if (down) {
          if (pendingCtrlV?.timer) clearTimeout(pendingCtrlV.timer)
          const mods =
            (ev.ctrlKey ? 1 : 0) |
            (ev.shiftKey ? 2 : 0) |
            (ev.altKey ? 4 : 0) |
            (ev.metaKey ? 8 : 0)
          const timer = setTimeout(() => {
            // Paste didn't fire (empty clipboard / browser denied
            // the read) Ã¢ÂÂ flush as a normal Ctrl+V keystroke so
            // the operator's chord still reaches the remote app.
            flushPendingCtrlV()
          }, 50)
          pendingCtrlV = { mods, timer }
        }
        // rc.18: stop propagation so a focused nav-drawer item
        // doesn't ALSO see the Ctrl+V and trigger its own
        // keyboard-activation. Capture-phase keydown means we run
        // before the focused element's bubble-phase handlers.
        if (pointerInside || keyboardLockActive.value) ev.stopPropagation()
        // keyup with a pending deferral: don't emit a stray V-up.
        // The flush path emits both down + up together.
        return
      }

      const action = decideKeyAction(ev, down, (k) => ev.getModifierState(k))
      if (action.kind === 'drop') return
      if (shouldPreventDefault(ev, pointerInside, keyboardLockActive.value)) ev.preventDefault()
      // rc.18: stop propagation when pointer is over viewer so a
      // focused page button / nav-drawer item doesn't ALSO see this
      // keystroke and fire its own keyboard-activation `@click`. The
      // capture-phase registration of this listener (see below) means
      // stopPropagation here cuts the bubble path before any focused
      // descendant runs its handler. Locked fullscreen counts too.
      if (pointerInside || keyboardLockActive.value) ev.stopPropagation()
      if (action.kind === 'text') {
        sendInput({ t: 'key_text', text: action.text })
      } else {
        // FR-13 (#789): on a mac host, rewrite Ctrl→Cmd (0xe0/0xe4→0xe3)
        // unless the operator disabled translation. The held tracker
        // records the SUBSTITUTED code so focus-loss release matches what
        // the host believes is down.
        const code = translateModifierForHost(
          action.code,
          action.down,
          hostIsMac.value && ctrlAsCmd.value,
          ctrlSubState,
        )
        sendInput({ t: 'key', code, down: action.down, mods: action.mods })
        heldInputs.key(code, action.down)
      }
      // rc.18: after a Ctrl+C-over-viewer is forwarded to the host,
      // schedule the auto-mirror of the host's clipboard back to the
      // browser. Only fire on `down` (Ctrl+C produces a down event;
      // we don't want to fire twice on up). Carve-outs (focus inside
      // INPUT/TEXTAREA/contenteditable) live in isCtrlCOverViewer.
      if (down && isCtrlCOverViewer(ev)) {
        scheduleClipboardMirror()
      }
    }

    function onPaste(ev: ClipboardEvent) {
      // Only respond if we deferred a Ctrl+V keystroke. Native paste
      // events that come from elsewhere (e.g. an editable field
      // outside the deferral path) keep their default handling.
      if (!pendingCtrlV) return
      const dt = ev.clipboardData
      if (!dt) {
        flushPendingCtrlV()
        return
      }

      // Files take precedence Ã¢ÂÂ operator intent is "upload these".
      if (dt.files && dt.files.length > 0 && options?.onFilesPasted) {
        ev.preventDefault()
        if (pendingCtrlV.timer) clearTimeout(pendingCtrlV.timer)
        pendingCtrlV = null
        const files: File[] = []
        for (let i = 0; i < dt.files.length; i++) files.push(dt.files[i])
        options.onFilesPasted(files)
        return
      }

      // Text path: mirror to host clipboard so the remote app's
      // paste sees the right content, then emit the Ctrl+V keystroke.
      const text = dt.getData('text') ?? ''
      // v2.1 Ã¢ÂÂ rich paste: the paste event exposes text/html
      // SYNCHRONOUSLY (no clipboard.read() needed). When the agent
      // takes html, ship both formats so the remote app pastes
      // formatting (tables, bold, web images), ack-gated like text.
      const html = dt.getData('text/html') ?? ''
      // v2.2 Ã¢ÂÂ full fidelity via the local bridge: read the machine's
      // RTF (embedded images the paste event can't carry) and ship it,
      // ack-gated. Only when both ends support native AND a local
      // bridge is present; else fall through to html/text.
      if (html && canUseNativeClipboard.value) {
        const ch = channels.clipboard
        if (ch && ch.readyState === 'open') {
          if (pendingCtrlV?.timer) {
            clearTimeout(pendingCtrlV.timer)
            pendingCtrlV.timer = null
          }
          void (async () => {
            let sent = false
            const native = await readLocalNativeClipboard()
            if (native) {
              const rtfHash = hashClipboardBytes(native.rtf)
              if (clipboardEchoGate.knows(rtfHash)) {
                // Auto-sync already delivered this content — but the gate
                // records at SEND time, so its write-ack may still be
                // outstanding; flushing before the OS write lands pastes
                // the STALE clipboard (the race the ack gate exists for).
                await awaitOutstandingClipboardWrite(rtfHash)
                flushPendingCtrlV()
                return
              }
              const built = buildClipboardNativeFrames(native.rtf, native.html, native.text)
              if (built && (await sendRichFramesOverDc(ch, built))) {
                clipboardEchoGate.recordPushed(rtfHash)
                if (text) clipboardEchoGate.recordPushed(hashClipboardText(text))
                if (supportsClipboardAck.value) {
                  await awaitClipboardAck(built.id, CLIPBOARD_ACK_TIMEOUT_MS)
                }
                sent = true
              }
            }
            // Bridge had no RTF / oversized / failed Ã¢ÂÂ html fallback
            // (still ack-gated) so the paste isn't downgraded to text.
            if (!sent && supportsClipboardHtml.value) {
              const built = buildClipboardHtmlFrames(html, text)
              if (built && (await sendRichFramesOverDc(ch, built))) {
                clipboardEchoGate.recordPushed(hashClipboardHtml(html, text))
                if (text) clipboardEchoGate.recordPushed(hashClipboardText(text))
                if (supportsClipboardAck.value) {
                  await awaitClipboardAck(built.id, CLIPBOARD_ACK_TIMEOUT_MS)
                }
              }
            }
            flushPendingCtrlV()
          })()
          return
        }
      }
      if (html && supportsClipboardHtml.value) {
        const ch = channels.clipboard
        if (ch && ch.readyState === 'open') {
          const combinedHash = hashClipboardHtml(html, text)
          if (clipboardEchoGate.knows(combinedHash)) {
            // Known content, but its write-ack may still be outstanding
            // (gate records at SEND time) — hold the flush until it lands.
            // Park the 50 ms fallback: the awaited path owns the flush now.
            if (pendingCtrlV?.timer) {
              clearTimeout(pendingCtrlV.timer)
              pendingCtrlV.timer = null
            }
            void awaitOutstandingClipboardWrite(combinedHash).then(() => flushPendingCtrlV())
            return
          }
          const built = buildClipboardHtmlFrames(html, text)
          if (built) {
            if (pendingCtrlV?.timer) {
              clearTimeout(pendingCtrlV.timer)
              pendingCtrlV.timer = null
            }
            void (async () => {
              const ok = await sendRichFramesOverDc(ch, built)
              if (ok) {
                clipboardEchoGate.recordPushed(combinedHash)
                if (text) clipboardEchoGate.recordPushed(hashClipboardText(text))
                if (supportsClipboardAck.value) {
                  await awaitClipboardAck(built.id, CLIPBOARD_ACK_TIMEOUT_MS)
                }
              }
              flushPendingCtrlV()
            })()
            return
          }
          // Oversized html Ã¢ÂÂ fall through to the plain-text path.
        }
      }
      if (text) {
        const ch = channels.clipboard
        if (ch && ch.readyState === 'open') {
          const hash = hashClipboardText(text)
          if (clipboardEchoGate.knows(hash)) {
            // The gate records at SEND time, so the auto-sync write-ack may
            // still be outstanding; flushing early pastes the STALE
            // clipboard. Park the 50 ms fallback — the awaited path owns
            // the flush now.
            if (pendingCtrlV?.timer) {
              clearTimeout(pendingCtrlV.timer)
              pendingCtrlV.timer = null
            }
            void awaitOutstandingClipboardWrite(hash).then(() => flushPendingCtrlV())
            return
          }
          try {
            // rc.44 Ã¢ÂÂ `sendClipboardWriteOverDc` picks the legacy
            // single-envelope shape for Ã¢ÂÂ¤12 KB texts (back-compat
            // with older agents) or splits into `clipboard:write-chunk`
            // envelopes for larger texts to stay under the SCTP
            // `max_message_size` ceiling.
            const { id } = sendClipboardWriteOverDc(ch, text)
            clipboardEchoGate.recordPushed(hash)
            trackClipboardWrite(hash, id)
            if (supportsClipboardAck.value) {
              // v2 Ã¢ÂÂ flush the deferred keystroke only after the agent
              // confirms the OS clipboard write. Without this gate the
              // keystroke (unordered input DC) routinely beat the
              // write (ordered clipboard DC + worker-thread hop) and
              // the remote app pasted the STALE clipboard Ã¢ÂÂ the field
              // -reported multiline corruption. The 50 ms empty-
              // clipboard timer must not fire in between: the ack
              // path owns the flush now.
              if (pendingCtrlV?.timer) {
                clearTimeout(pendingCtrlV.timer)
                pendingCtrlV.timer = null
              }
              void awaitClipboardAck(id, CLIPBOARD_ACK_TIMEOUT_MS).then(() =>
                flushPendingCtrlV(),
              )
              return
            }
          } catch {
            /* dropped Ã¢ÂÂ host clipboard stays unchanged but we still
               forward the keystroke; remote app pastes whatever was
               there before. */
          }
        }
      }
      flushPendingCtrlV()
    }

    const onKeyDown = (e: KeyboardEvent) => onKey(e, true)
    const onKeyUp = (e: KeyboardEvent) => onKey(e, false)
    // Alt-tab / minimize / OS steal: the matching keyups will never arrive —
    // release everything we're holding on the host NOW. Registered even
    // under Keyboard Lock (see createHeldInputTracker's doc).
    const onWindowBlurInput = () => releaseHeldInputs()
    const onVisibilityInput = () => {
      if (globalThis.document.visibilityState === 'hidden') releaseHeldInputs()
    }
    // FR-109 — Pointer Lock came or went: the control, Esc, a lost focus.
    // Leaving it sends the motion still gathered and lets go of any held
    // button where the pointer is, before moves turn absolute again (an
    // absolute button-up would throw the host's cursor to the old position).
    const onPointerLockChange = () => {
      const locked = globalThis.document.pointerLockElement === surface
      if (locked === relativeMouse.value) return
      if (!locked) {
        flushRel()
        relAcc.reset()
        for (const btn of heldInputs.releaseButtons()) {
          sendInput(relativeButtonMessage(btn, false))
        }
        // FR-109 P3 — the person left an auto-entered lock while the cursor
        // is still hidden (Esc): no re-entry on the next click until the
        // cursor shows again, or a hidden cursor would trap them.
        if (relativeMouseAuto.value) {
          relativeMouseAuto.value = false
          if (hostCursorHidden.value) relativeAutoSuppressed = true
        }
      }
      relativeMouse.value = locked
    }

    // Disable the OS-native context menu so right-click forwards cleanly.
    function onContextMenu(ev: MouseEvent) { ev.preventDefault() }

    surface.addEventListener('pointermove', onPointerMove)
    // FR-1 P6 — where supported (Chromium), also sample at device rate:
    // pointerrawupdate fires between rAF-aligned pointermoves, so the
    // 8 ms coalescer always has the FRESHEST position even when the main
    // thread is busy compositing. Duplicate events are harmless
    // (latest-wins into pendingMove).
    if ('onpointerrawupdate' in surface) {
      surface.addEventListener(
        'pointerrawupdate',
        onPointerMove as EventListener,
      )
    }
    surface.addEventListener('pointerdown', onPointerDown)
    surface.addEventListener('pointerup', onPointerUp)
    surface.addEventListener('pointercancel', onPointerCancel)
    surface.addEventListener('pointerenter', onPointerEnter)
    surface.addEventListener('pointerleave', onPointerLeave)
    surface.addEventListener('wheel', onWheel, { passive: false })
    surface.addEventListener('contextmenu', onContextMenu)
    // Paste handler must be on `window` (or a focusable surface) Ã¢ÂÂ
    // attaching to `surface` only fires when surface itself is the
    // event target, which doesn't happen for keyboard-driven paste.
    // Window-level listener with our own pendingCtrlV gating means
    // we only intercept paste events that follow a deferred Ctrl+V.
    window.addEventListener('paste', onPaste)
    window.addEventListener('blur', onWindowBlurInput)
    document.addEventListener('visibilitychange', onVisibilityInput)
    document.addEventListener('pointerlockchange', onPointerLockChange)
    // rc.18: register on CAPTURE phase so we run BEFORE any focused
    // element's bubble-phase handlers. Combined with the per-handler
    // `stopPropagation` when pointer is inside, this stops a focused
    // nav-drawer item from receiving Enter/Space/etc. while the
    // operator is driving the remote. Outside the viewer the
    // stopPropagation is gated off, so normal browser shortcuts
    // (Tab navigation, Esc closing dialogs) still work.
    window.addEventListener('keydown', onKeyDown, { capture: true })
    window.addEventListener('keyup', onKeyUp, { capture: true })
    // FR-111 P4b-2 — pausing the keyboard lets go of what it holds on the
    // host: the key-ups of a chord held at that moment will go to the dialog.
    const stopPauseWatch = watch(keyboardPaused, (paused) => {
      if (paused) releaseHeldInputs()
    })

    return () => {
      stopPauseWatch()
      if (benchSurface === surface) benchSurface = null
      surface.removeEventListener('pointermove', onPointerMove)
      if ('onpointerrawupdate' in surface) {
        surface.removeEventListener(
          'pointerrawupdate',
          onPointerMove as EventListener,
        )
      }
      surface.removeEventListener('pointerdown', onPointerDown)
      surface.removeEventListener('pointerup', onPointerUp)
      surface.removeEventListener('pointercancel', onPointerCancel)
      surface.removeEventListener('pointerenter', onPointerEnter)
      surface.removeEventListener('pointerleave', onPointerLeave)
      surface.removeEventListener('wheel', onWheel)
      surface.removeEventListener('contextmenu', onContextMenu)
      window.removeEventListener('paste', onPaste)
      if (longPressTimer !== null) clearTimeout(longPressTimer)
      if (pixelWheelIdle !== null) clearTimeout(pixelWheelIdle)
      // Release anything still held on the host BEFORE the channels close
      // (detach mid-chord must not leave a stuck modifier behind).
      releaseHeldInputs()
      if (controlsSink === stageControls) controlsSink = null
      window.removeEventListener('blur', onWindowBlurInput)
      document.removeEventListener('visibilitychange', onVisibilityInput)
      // FR-109 — the surface is going: so is its lock, and relative mode.
      document.removeEventListener('pointerlockchange', onPointerLockChange)
      exitRelativeMouse()
      if (relTimer !== null) {
        clearTimeout(relTimer)
        relTimer = null
      }
      relAcc.reset()
      relativeMouse.value = false
      relativeMouseAuto.value = false
      relativeAutoSuppressed = false
      swallowedButton = null
      if (relativeSurface === surface) relativeSurface = null
      // Same `capture: true` as the add Ã¢ÂÂ required for matching.
      window.removeEventListener('keydown', onKeyDown, { capture: true })
      window.removeEventListener('keyup', onKeyUp, { capture: true })
      // Drop any in-flight deferral; otherwise its 50 ms timer would
      // fire after teardown and call sendInput on a closed channel.
      if (pendingCtrlV?.timer) clearTimeout(pendingCtrlV.timer)
      pendingCtrlV = null
      if (moveTimer !== null) {
        clearTimeout(moveTimer)
        moveTimer = null
      }
      // A disconnect while fullscreen must not leave the Keyboard
      // Lock dangling (the stage may stay fullscreen briefly).
      disableKeyboardLock()
    }
  }

  /** Send the browser's clipboard text to the agent's OS clipboard.
   *  Fire-and-forget. Requires user gesture Ã¢ÂÂ `navigator.clipboard.
   *  readText()` throws in non-gesture contexts. Call from a button
   *  click handler. Resolves to `true` on best-effort send, `false`
   *  if the clipboard DC isn't open or reading the browser clipboard
   *  was blocked (e.g. permissions denied). */
  async function sendClipboardToAgent(): Promise<boolean> {
    const ch = channels.clipboard
    if (!ch || ch.readyState !== 'open') return false
    let text: string
    try {
      text = await globalThis.navigator.clipboard.readText()
    } catch {
      return false
    }
    try {
      // rc.44 Ã¢ÂÂ chunks large payloads to avoid SCTP `ErrChunk`.
      const { id } = sendClipboardWriteOverDc(ch, text)
      clipboardEchoGate.recordPushed(hashClipboardText(text))
      // v2 Ã¢ÂÂ wait for the agent's write-ack so the button's success
      // toast reflects the OS clipboard actually being written (1 s
      // timeout fallback keeps old agents on the fire-and-forget
      // semantics).
      if (supportsClipboardAck.value) {
        await awaitClipboardAck(id, CLIPBOARD_ACK_TIMEOUT_MS)
      }
      return true
    } catch {
      return false
    }
  }

  /** Request the agent's current clipboard text. Rejects with a
   *  timeout after 5 seconds if the agent doesn't reply. Call from a
   *  button click handler so the subsequent `navigator.clipboard.
   *  writeText()` has user-gesture permission. Resolves with the
   *  text; the caller is responsible for writing it to the browser
   *  clipboard (this lets the caller show a preview / paste into a
   *  specific field instead of always overwriting). */
  function getAgentClipboard(): Promise<string> {
    const ch = channels.clipboard
    if (!ch || ch.readyState !== 'open') {
      return Promise.reject(new Error('clipboard channel not open'))
    }
    const reqId = nextClipboardReqId++
    const msg = JSON.stringify({ t: 'clipboard:read', req_id: reqId })
    return new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => {
        pendingClipboardReads.delete(reqId)
        reject(new Error('agent did not respond to clipboard:read within 5s'))
      }, 5000)
      pendingClipboardReads.set(reqId, { resolve, reject, timer })
      try {
        ch.send(msg)
      } catch (e) {
        clearTimeout(timer)
        pendingClipboardReads.delete(reqId)
        reject(e instanceof Error ? e : new Error(String(e)))
      }
    })
  }

  /** v2 Ã¢ÂÂ rich clipboard read: like [`getAgentClipboard`] but also
   *  accepts an IMAGE or HTML reply when the host clipboard holds one
   *  and the agent advertises the matching cap. Resolves with a tagged
   *  union; `{kind:'text', text:''}` means the host clipboard is
   *  empty. Falls back to the text-only read against old agents. */
  async function getAgentClipboardRich(): Promise<
    | { kind: 'text'; text: string }
    | { kind: 'image'; blob: Blob; w: number; h: number }
    | { kind: 'html'; html: string; text: string }
    | { kind: 'native'; rtf: Uint8Array<ArrayBuffer>; html: string; text: string }
  > {
    const accept = [
      'text',
      ...(supportsClipboardImages.value ? ['image'] : []),
      ...(supportsClipboardHtml.value ? ['html'] : []),
      ...(canUseNativeClipboard.value ? ['native'] : []),
    ]
    if (accept.length === 1) {
      const text = await getAgentClipboard()
      return { kind: 'text', text }
    }
    const ch = channels.clipboard
    if (!ch || ch.readyState !== 'open') {
      throw new Error('clipboard channel not open')
    }
    const reqId = nextClipboardReqId++
    return new Promise((resolve, reject) => {
      // 15 s (vs the text read's 5 s): an 8 MiB PNG at a constrained
      // relay can legitimately take a while.
      const timer = setTimeout(() => {
        cleanup()
        reject(new Error('agent did not respond to clipboard:read within 15s'))
      }, 15_000)
      function cleanup() {
        clearTimeout(timer)
        pendingClipboardReads.delete(reqId)
        pendingClipboardRichReads.delete(reqId)
      }
      pendingClipboardReads.set(reqId, {
        resolve: (text) => {
          cleanup()
          resolve({ kind: 'text', text })
        },
        reject: (e) => {
          cleanup()
          reject(e)
        },
        timer,
      })
      pendingClipboardRichReads.set(reqId, {
        resolve: (content) => {
          cleanup()
          resolve(content)
        },
        reject: (e) => {
          cleanup()
          reject(e)
        },
      })
      try {
        ch.send(JSON.stringify({ t: 'clipboard:read', req_id: reqId, accept }))
      } catch (e) {
        cleanup()
        reject(e instanceof Error ? e : new Error(String(e)))
      }
    })
  }

  /** Upload a single `File` to the remote host's Downloads folder via
   *  the `files` data channel. Chunks at 64 KiB with backpressure on
   *  the SCTP buffer. Resolves with the final path + byte count
   *  reported by the agent. Rejects on agent error or DC close.
   *
   *  Internal Ã¢ÂÂ the public surface is `uploadFiles(files)` (queue) and
   *  the back-compat `uploadFile(file)` shim. Reads agent replies via
   *  the persistent `files` DC listener registered at channel-create
   *  time (see `filesRegistry`). */
  /**
   * Sentinel "DC closed mid-upload" error. The resume wrapper
   * catches THIS specifically and retries; any other Error
   * propagates straight to the caller.
   */
  const CHANNEL_CLOSED_TAG = '__rc19_channel_closed__'
  function makeChannelClosedError(file: File, offset: number): Error {
    const pct = file.size === 0 ? 100 : Math.round((offset / file.size) * 100)
    const err = new Error(
      `files channel closed mid-upload at ${pct}% (${offset}/${file.size} bytes). ` +
        `Most likely the remote agent restarted (auto-update / crash / network drop).`
    )
    ;(err as Error & { [k: string]: unknown })[CHANNEL_CLOSED_TAG] = true
    return err
  }
  function isChannelClosedError(e: unknown): boolean {
    return !!(e && typeof e === 'object' && (e as Record<string, unknown>)[CHANNEL_CLOSED_TAG])
  }

  /**
   * Inner pump Ã¢ÂÂ sends raw chunks from `file.slice(startOffset)` over
   * the LIVE `channels.files` DC (re-read every invocation, NOT
   * captured at construction). Throws a channel-closed sentinel when
   * the DC dies; caller handles retry via `uploadOneResumable`.
   * Sends the terminal `files:end` envelope on success.
   *
   * Used by both the first attempt (after `files:begin`) and every
   * resume attempt (after `files:resumed`).
   */
  async function innerPump(file: File, startOffset: number, id: string): Promise<void> {
    // rc.23 hotfix #3 (the field-test host 2026-05-13): 64 KiB sat exactly at
    // webrtc-rs's SCTP `max_message_size` default (65536), so any
    // 64-KiB outbound chunk that landed AT the boundary triggered
    // `failed to handle_inbound: ErrChunk` warnings + silent drop on
    // the agent side. Sub-32-KiB files succeeded (single chunk fits
    // comfortably), 1 MiB files failed (16 chunks each at the
    // boundary). Drop to 16 KiB Ã¢ÂÂ 4ÃÂ margin, well within both SCTP
    // implementations' guaranteed-unfragmented size + matches what
    // RustDesk + most browser-based file-transfer libraries use.
    // The trade-off is ~3ÃÂ more send() calls per MB, but each
    // call is sub-microsecond and the SCTP layer pipelines them.
    const CHUNK = 16 * 1024
    let offset = startOffset
    // Cancellation: `cancelUpload(id)` settles the registry entry
    // locally; the pump checks status between chunks and exits.
    const isCancelled = () => {
      const e = filesRegistry.get(id)
      return !e || e.status === 'settled'
    }
    while (offset < file.size) {
      if (isCancelled()) return
      // P0-3 fix: re-read live channel every loop iteration. After a
      // DC drop + reconnect, `channels.files` is a NEW
      // RTCDataChannel; the stale capture would throw "DataChannel
      // is not opened" indefinitely.
      const ch = channels.files
      if (!ch || ch.readyState !== 'open') {
        throw makeChannelClosedError(file, offset)
      }
      // Back off when the sctp buffer fills up so the browser
      // doesn't OOM on huge files.
      while (ch.bufferedAmount > 4 * 1024 * 1024) {
        if (ch.readyState !== 'open') {
          throw makeChannelClosedError(file, offset)
        }
        if (isCancelled()) return
        await new Promise((r) => setTimeout(r, 20))
      }
      const end = Math.min(offset + CHUNK, file.size)
      const slice = file.slice(offset, end)
      const buf = await slice.arrayBuffer()
      // Re-read after the await Ã¢ÂÂ readyState can flip during the
      // ArrayBuffer materialisation.
      const ch2 = channels.files
      if (!ch2 || ch2.readyState !== 'open') {
        throw makeChannelClosedError(file, offset)
      }
      if (isCancelled()) return
      try {
        ch2.send(buf)
      } catch {
        throw makeChannelClosedError(file, offset)
      }
      offset = end
      patchTransfer(id, { status: 'running', bytes: offset })
    }
    if (isCancelled()) return
    const ch = channels.files
    if (!ch || ch.readyState !== 'open') {
      throw makeChannelClosedError(file, offset)
    }
    try {
      ch.send(JSON.stringify({ t: 'files:end', id }))
    } catch {
      throw makeChannelClosedError(file, offset)
    }
  }

  /**
   * Wait until the WebRTC peer is back in `connected` phase OR the
   * reconnect ladder gives up (phase transitions to 'error' or
   * 'closed'). Resolves true on connected, false on terminal.
   * Cancelled by `onBeforeUnmount` via the same `stop` registry as
   * the rest of the composable.
   */
  function waitForConnected(timeoutMs: number = 30_000): Promise<boolean> {
    if (phase.value === 'connected') return Promise.resolve(true)
    // rc.23 Ã¢ÂÂ pass `Number.POSITIVE_INFINITY` to wait indefinitely
    // for the next 'connected' transition. `setTimeout(fn, Infinity)`
    // is implementation-defined (most engines clamp to ~2^31-1 ms
    // Ã¢ÂÂ 25 days) so we just skip the timer instead. The settle path
    // is the phase watcher below Ã¢ÂÂ phases 'closed' / 'error' / 'idle'
    // still resolve false so the caller can detect operator-cancel.
    return new Promise((resolve) => {
      const wantTimer = Number.isFinite(timeoutMs)
      const timer = wantTimer
        ? setTimeout(() => {
            stop()
            resolve(false)
          }, timeoutMs)
        : null
      const stop = watch(
        phase,
        (p) => {
          if (p === 'connected') {
            if (timer !== null) clearTimeout(timer)
            stop()
            resolve(true)
          } else if (p === 'closed' || p === 'error' || p === 'idle') {
            if (timer !== null) clearTimeout(timer)
            stop()
            resolve(false)
          }
        },
        { immediate: false }
      )
    })
  }

  /**
   * rc.23 hotfix Ã¢ÂÂ wait for `channels.files` to be open. Necessary
   * companion to {@link waitForConnected} for the resume loop:
   * `phase = 'connected'` only means the WebRTC PeerConnection is
   * up, not that the file DC has re-opened. When the agent drops
   * the file DC mid-transfer but keeps the peer alive (some failure
   * modes do this), `runOnce` throws "channel closed" synchronously,
   * `waitForConnected` returns true immediately, the loop re-enters,
   * throws again Ã¢ÂÂ tight async loop that burns CPU and freezes the
   * tab. Field repro on the field-test host 2026-05-12 (CV.pdf upload + rc.23
   * web on rc.23 agent Ã¢ÂÂ tab had to be killed).
   *
   * `pollIntervalMs` defaults to 250 Ã¢ÂÂ cheap; the DC opens once per
   * resume cycle so we don't pay a steady cost. `timeoutMs` defaults
   * to `Number.POSITIVE_INFINITY` so the loop matches the parent
   * "DC always stays open" contract; finite caps are useful only
   * when an outer caller wants to bail.
   */
  function waitForFilesChannel(
    timeoutMs: number = Number.POSITIVE_INFINITY,
    pollIntervalMs: number = 250
  ): Promise<boolean> {
    if (channels.files && channels.files.readyState === 'open') {
      return Promise.resolve(true)
    }
    return new Promise((resolve) => {
      const wantTimer = Number.isFinite(timeoutMs)
      let settled = false
      const finish = (ok: boolean) => {
        if (settled) return
        settled = true
        if (timer !== null) clearTimeout(timer)
        clearInterval(poll)
        resolve(ok)
      }
      const timer = wantTimer ? setTimeout(() => finish(false), timeoutMs) : null
      const poll = setInterval(() => {
        if (channels.files && channels.files.readyState === 'open') {
          finish(true)
          return
        }
        // Operator-disconnect / fatal error terminates the wait.
        if (phase.value === 'closed' || phase.value === 'error' || phase.value === 'idle') {
          finish(false)
        }
      }, pollIntervalMs)
    })
  }

  /**
   * rc.19 P5: resume-capable wrapper around `innerPump`. First
   * attempt sends `files:begin`; subsequent attempts send
   * `files:resume { id, offset: entry.bytesAcked }` and re-pump
   * from the agent's accepted offset. Up to 6 attempts (matches
   * RC_RECONNECT_LADDER_MS.length); on exhaustion sends
   * `files:cancel` so the agent cleans its staging dir immediately.
   *
   * Pre-rc.19 behaviour preserved for non-resume agents: the
   * `supportsResume.value === false` branch falls through to a
   * single fresh-begin attempt with the original fail-fast error.
   */
  function uploadOne(
    file: File,
    relPath?: string,
    destPath?: string
  ): Promise<{ path: string; bytes: number }> {
    const initialCh = channels.files
    if (!initialCh || initialCh.readyState !== 'open') {
      return Promise.reject(new Error('files channel not open'))
    }
    const id = `up-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`

    return new Promise((resolve, reject) => {
      const entry: UploadEntry = {
        kind: 'upload',
        status: 'pending',
        resolve,
        reject,
        bytesAcked: 0,
        file,
        relPath,
        destPath,
      }
      filesRegistry.set(id, entry)
      pushTransfer({
        id,
        kind: 'upload',
        // Show the relative path in the Transfers panel for folder
        // uploads so the operator can tell `file.txt` (root) apart
        // from `MyFolder/sub/file.txt` (deep).
        name: relPath ?? file.name,
        bytes: 0,
        total: file.size,
        status: 'queued',
      })

      // Local error Ã¢ÂÂ settle the registry entry ourselves and reject.
      // (Agent-side errors arrive via the persistent listener.)
      const localFail = (err: Error) => {
        const settled = settleEntry(id)
        if (settled) {
          patchTransfer(id, { status: 'error', error: err.message })
          settled.reject(err)
        }
      }

      function sendBegin(ch: RTCDataChannel): boolean {
        try {
          if (ch.readyState !== 'open') {
            throw new Error('files channel closed before files:begin could be sent')
          }
          // Folder-upload extension (file-DC v2.1) + path-targeted
          // upload extension (v2.2). Old agents ignore unknown JSON
          // fields and use `name` as the basename.
          const beginMsg: Record<string, unknown> = {
            t: 'files:begin',
            id,
            name: file.name,
            size: file.size,
            mime: file.type || undefined,
          }
          if (relPath) beginMsg.rel_path = relPath
          if (destPath) beginMsg.dest_path = destPath
          ch.send(JSON.stringify(beginMsg))
          return true
        } catch (e) {
          localFail(e instanceof Error ? e : new Error(String(e)))
          return false
        }
      }

      // rc.19: send `files:resume { id, offset }` and await the
      // matching `files:resumed { id, accepted_offset }` (or
      // `files:error` Ã¢ÂÂ reject the waiter, wrapper falls back to a
      // fresh `files:begin` with a NEW id). 10 s timeout Ã¢ÂÂ way more
      // than the agent's local lookup + truncate + reopen.
      function sendResume(ch: RTCDataChannel, offset: number): Promise<number> {
        return new Promise<number>((resolveResume, rejectResume) => {
          const timer = setTimeout(() => {
            pendingResumePromises.delete(id)
            rejectResume(new Error('files:resumed timeout'))
          }, 10_000)
          pendingResumePromises.set(id, {
            resolve: resolveResume,
            reject: rejectResume,
            timer,
          })
          try {
            if (ch.readyState !== 'open') {
              throw new Error('files channel closed before files:resume could be sent')
            }
            ch.send(JSON.stringify({ t: 'files:resume', id, offset }))
          } catch (e) {
            clearTimeout(timer)
            pendingResumePromises.delete(id)
            rejectResume(e instanceof Error ? e : new Error(String(e)))
          }
        })
      }

      function sendCancelBestEffort(): void {
        const ch = channels.files
        if (!ch || ch.readyState !== 'open') return
        try {
          ch.send(JSON.stringify({ t: 'files:cancel', id }))
        } catch {
          /* DC closed between check and send Ã¢ÂÂ agent's 24h sweep cleans the partial */
        }
      }

      // rc.23 Ã¢ÂÂ infinite retry. The DC effectively stays "open" from
      // the operator's POV: every drop triggers a resume on the next
      // 'connected' transition; the loop only exits when the operator
      // cancels via Cancel button (which settles the registry entry)
      // or files:complete arrives. `MAX_ATTEMPTS` retained as a label
      // for log lines + UI "attempt N/MAX" rendering, but tied to
      // `Number.POSITIVE_INFINITY` so the budget check below is a
      // no-op. Was 6; rolled forward on the field-test host field repro where
      // ESET caused the agent to be killed repeatedly during 14 MB
      // uploads and the 6-attempt cap surfaced "exhausted" before
      // the DC could reconnect.
      const MAX_ATTEMPTS = Number.POSITIVE_INFINITY
      let attempt = 0

      const runOnce = async (): Promise<void> => {
        // Bail if the operator cancelled or a fatal error already
        // settled the registry entry.
        const e = filesRegistry.get(id)
        if (!e || e.status === 'settled') return

        let startOffset = 0
        const ch = channels.files
        if (!ch || ch.readyState !== 'open') {
          throw makeChannelClosedError(file, e.kind === 'upload' ? e.bytesAcked : 0)
        }

        if (attempt === 0) {
          // First attempt Ã¢ÂÂ fresh begin.
          if (!sendBegin(ch)) return
          // Transition the entry back to 'pending' (it might have been
          // 'pending-resume' if this is a fresh-id fallback after a
          // resume error).
          if (e.kind === 'upload') e.status = 'pending'
          patchTransfer(id, { status: 'running' })
        } else {
          // Resume attempt. supportsResume is already guaranteed
          // true by the catch-block guard below.
          patchTransfer(id, {
            status: 'reconnecting',
            error: `attempt ${attempt + 1}`,
          })
          // Transition back to 'pending' so files:complete settles
          // through the normal path.
          if (e.kind === 'upload') e.status = 'pending'
          const requested = e.kind === 'upload' ? e.bytesAcked : 0
          const accepted = await sendResume(ch, requested)
          startOffset = accepted
          if (e.kind === 'upload') e.bytesAcked = accepted
          patchTransfer(id, { status: 'running', bytes: startOffset })
        }
        await innerPump(file, startOffset, id)
        // files:end is sent by innerPump on success; the listener
        // resolves the outer promise on files:complete.
      }

      const runResumable = async (): Promise<void> => {
        while (attempt < MAX_ATTEMPTS) {
          try {
            await runOnce()
            return // success Ã¢ÂÂ listener resolves via files:complete
          } catch (err) {
            const e = filesRegistry.get(id)
            if (!e || e.status === 'settled') return // settled by listener
            const canRetry = supportsResume.value && isChannelClosedError(err)
            if (!canRetry) {
              localFail(err instanceof Error ? err : new Error(String(err)))
              return
            }
            // Channel closed mid-flight with resume cap Ã¢ÂÂ wait for
            // reconnect and retry.
            patchTransfer(id, {
              status: 'reconnecting',
              error: `attempt ${attempt + 1}`,
            })
            // rc.23 Ã¢ÂÂ wait forever for the peer to come back. The
            // resume loop is the operator's "DC stays open" promise;
            // legacy 30 s timeout could fire while the agent was
            // being installer-restarted by msiexec (5-90 s window
            // observed during auto-update on the field-test host). Outer
            // settle-check at the top of `runOnce` handles the
            // operator-cancel path.
            const e2 = filesRegistry.get(id)
            if (!e2 || e2.status === 'settled') return
            // rc.23 hotfix Ã¢ÂÂ bound the retry rate to prevent a tight
            // async loop when the file DC is closed but the peer is
            // still 'connected'. Without this delay, `runOnce` throws
            // "channel closed" synchronously, `waitForConnected`
            // returns true immediately (phase already 'connected'),
            // we retry, throw again Ã¢ÂÂ thousands of iterations per
            // second pin a CPU core and freeze the browser tab. Field
            // repro on the field-test host 2026-05-12 (CV.pdf upload). Backstop
            // delay also gives the agent breathing room to reopen
            // the DC before we ping it again.
            const backoffMs =
              attempt < RC_RECONNECT_LADDER_MS.length
                ? RC_RECONNECT_LADDER_MS[attempt]
                : RC_RECONNECT_STEADY_MS
            await new Promise((r) => setTimeout(r, backoffMs))
            // Re-check settled after the sleep Ã¢ÂÂ operator may have
            // cancelled while we were waiting.
            const e3 = filesRegistry.get(id)
            if (!e3 || e3.status === 'settled') return
            // Block until 'connected' fires; the watch handler that
            // resolves waitForConnected fires unconditionally on the
            // peer-level 'connected' transition.
            const connected = await waitForConnected(Number.POSITIVE_INFINITY)
            if (!connected) {
              // waitForConnected only returns false on timeout. With
              // an infinite timeout the only way out is the settle
              // check above; surface a defensive error if we somehow
              // get here.
              localFail(new Error('reconnect wait returned without connecting (defensive)'))
              return
            }
            // rc.23 hotfix Ã¢ÂÂ also wait for the file DC to re-open.
            // `phase === 'connected'` is necessary but not sufficient:
            // if the agent dropped just the file DC, the peer never
            // transitions, and `runOnce` would throw on entry without
            // the DC ready. waitForFilesChannel polls every 250 ms
            // for `channels.files.readyState === 'open'`.
            const fileChanOpen = await waitForFilesChannel(Number.POSITIVE_INFINITY)
            if (!fileChanOpen) {
              localFail(new Error('file channel did not re-open (operator disconnect?)'))
              return
            }
            attempt += 1
          }
        }
        // MAX_ATTEMPTS is Infinity in rc.23 Ã¢ÂÂ this is unreachable but
        // kept as a defensive surface so a future regression flips
        // MAX_ATTEMPTS without leaving the loop able to silently exit.
        sendCancelBestEffort()
        localFail(new Error('resumable upload exited the infinite-retry loop unexpectedly'))
      }

      void runResumable()
    })
  }

  /** Public single-file upload Ã¢ÂÂ back-compat shim retained so existing
   *  E2E tests + 0.2.x call sites keep working. New code should call
   *  `uploadFiles([file])` directly. */
  function uploadFile(file: File): Promise<{ path: string; bytes: number }> {
    return uploadOne(file)
  }

  // --------------------------------------------------------------
  // Downloads (host Ã¢ÂÂ browser) Ã¢ÂÂ Phase 2 of file-DC v2.

  // Hard cap on the Blob fallback path (no showSaveFilePicker) so a
  // misbehaving server can't OOM the tab by streaming gigabytes of
  // chunks into memory. Single-file downloads come with size up-front
  // (in files:offer); we can refuse early. Folder zips (Phase 4) ride
  // a Chrome-only path that bypasses this entirely.
  const DOWNLOAD_BLOB_HARD_CAP = 2 * 1024 * 1024 * 1024 // 2 GiB

  /** Append one binary chunk to a download entry's sink. Tracks total
   *  bytes for the Transfers panel + enforces the Blob-fallback hard
   *  cap so a wedged stream doesn't OOM the tab. */
  function appendDownloadChunk(entry: DownloadEntry, buf: ArrayBuffer) {
    if (entry.status === 'settled') return
    entry.bytesReceived += buf.byteLength
    patchTransfer(entry === filesRegistry.get(activeDownloadId ?? '') ? (activeDownloadId as string) : '', {
      status: 'running',
      bytes: entry.bytesReceived,
    })
    if (entry.saveMode === 'stream' && entry.writable) {
      // Chrome streaming path: write directly to the user-chosen
      // file. Errors propagate via files:error from the agent or
      // via the writable's own promise (handled in finalizeDownload).
      void entry.writable.write(buf).catch(() => {
        // Swallow; the writable's close()/abort() in finalize will
        // surface the underlying error.
      })
    } else if (entry.saveMode === 'blob') {
      if (entry.bytesReceived > DOWNLOAD_BLOB_HARD_CAP) {
        // Sentinel: settle now with an error and drop the buffer.
        // Send a cancel to the agent so it stops sending bytes.
        const id = activeDownloadId
        if (id) {
          const ch = channels.files
          if (ch && ch.readyState === 'open') {
            try { ch.send(JSON.stringify({ t: 'files:cancel', id })) } catch { /* dropped */ }
          }
          const settled = settleEntry(id)
          if (settled?.kind === 'download') {
            const msg = `download exceeds ${Math.round(DOWNLOAD_BLOB_HARD_CAP / (1024 * 1024 * 1024))} GiB browser-memory cap (use Chrome for streaming downloads)`
            patchTransfer(id, { status: 'error', error: msg })
            settled.reject(new Error(msg))
          }
          activeDownloadId = null
        }
        return
      }
      entry.blobs.push(buf)
    }
  }

  /** Close the writable (Chrome streaming) OR concatenate the Blob
   *  parts and trigger an `<a download>` click (Firefox/Safari
   *  fallback). Resolves once the bytes are durable. */
  async function finalizeDownload(entry: DownloadEntry, totalBytes: number): Promise<void> {
    if (entry.saveMode === 'stream' && entry.writable) {
      await entry.writable.close()
      return
    }
    if (entry.saveMode === 'blob') {
      const blob = new Blob(entry.blobs, { type: entry.mime || 'application/octet-stream' })
      const url = URL.createObjectURL(blob)
      try {
        const a = document.createElement('a')
        a.href = url
        a.download = entry.suggestedName || entry.name || 'download.bin'
        a.style.display = 'none'
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
      } finally {
        // Schedule the URL revoke after the browser has had a tick
        // to start the download.
        setTimeout(() => URL.revokeObjectURL(url), 1_000)
      }
      // Free the chunks regardless of success.
      entry.blobs = []
      // Sanity: don't surface a totalBytes mismatch as an error here;
      // the agent already locked the count via files:eof.
      void totalBytes
      return
    }
    // 'pending' should never reach here (files:offer flips it to
    // 'blob' as a fallback); guard anyway.
    throw new Error('download finalised in unexpected save mode')
  }

  /** Download a single file from the host to the browser's local
   *  filesystem. `path` is the absolute host path (subject to the
   *  agent's denylist). `suggestedName` overrides the filename in the
   *  save dialog / anchor download. Returns the agent-reported byte
   *  count on success.
   *
   *  Implementation strategy:
   *  - Chrome / Edge / Safari 17+: opens `showSaveFilePicker` BEFORE
   *    sending the request (browsers require a user-gesture chain),
   *    streams chunks directly into the chosen file.
   *  - Firefox / Safari < 17: accumulates chunks in an in-memory
   *    Blob and triggers an `<a download>` click on completion.
   *    Capped at 2 GiB to prevent OOM.
   */
  async function downloadFile(
    path: string,
    suggestedName?: string
  ): Promise<{ name: string; bytes: number }> {
    const ch = channels.files
    if (!ch || ch.readyState !== 'open') {
      throw new Error('files channel not open')
    }
    const id = `dl-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`
    const fallbackName = suggestedName ?? path.split(/[\\/]/).pop() ?? 'download.bin'

    // Try to open showSaveFilePicker FIRST (before any await past the
    // user gesture) Ã¢ÂÂ browsers require this. If unavailable, fall
    // back to the Blob path; if the user cancels the picker, throw.
    let writable: SaveWritable | null = null
    let saveMode: DownloadEntry['saveMode'] = 'pending'
    type ShowSaveFilePicker = (options?: {
      suggestedName?: string
      types?: { description?: string; accept: Record<string, string[]> }[]
    }) => Promise<{
      createWritable: () => Promise<SaveWritable>
    }>
    const showSavePicker = (window as unknown as { showSaveFilePicker?: ShowSaveFilePicker })
      .showSaveFilePicker
    if (typeof showSavePicker === 'function') {
      try {
        const handle = await showSavePicker({ suggestedName: fallbackName })
        writable = await handle.createWritable()
        saveMode = 'stream'
      } catch (e) {
        // User cancelled or picker errored Ã¢ÂÂ propagate as user-facing
        // error so the UI can show "Download cancelled".
        throw e instanceof Error ? e : new Error(String(e))
      }
    } else {
      saveMode = 'blob'
    }

    return new Promise<{ name: string; bytes: number }>((resolve, reject) => {
      const entry: DownloadEntry = {
        kind: 'download',
        status: 'pending',
        resolve,
        reject,
        saveMode,
        writable,
        blobs: [],
        name: fallbackName,
        suggestedName: fallbackName,
        bytesReceived: 0,
        expectedSize: null,
      }
      filesRegistry.set(id, entry)
      pushTransfer({
        id,
        kind: 'download',
        name: fallbackName,
        bytes: 0,
        total: null,
        status: 'queued',
      })
      try {
        ch.send(JSON.stringify({ t: 'files:get', id, path }))
      } catch (e) {
        const settled = settleEntry(id)
        if (settled?.kind === 'download') {
          const msg = e instanceof Error ? e.message : String(e)
          patchTransfer(id, { status: 'error', error: msg })
          if (writable) void writable.abort(msg).catch(() => {})
          settled.reject(new Error(msg))
        }
      }
    })
  }

  /** Download an entire folder from the host as a streaming zip.
   *  Same `files:offer` Ã¢ÂÂ binary chunks Ã¢ÂÂ `files:eof` envelope as
   *  `downloadFile`, but the agent zips on the fly with no temp
   *  disk and `size` arrives as `null` (unknown until end-of-stream).
   *
   *  **Refused on browsers without `showSaveFilePicker`** (Firefox,
   *  Safari < 17, older mobile). Folder zips don't have an upfront
   *  size, so the Blob fallback would risk OOMing on a large folder.
   *  Operators on those browsers see a clear toast asking them to
   *  use Chrome/Edge; download-individual-files still works. */
  async function downloadFolder(
    path: string,
    suggestedName?: string
  ): Promise<{ name: string; bytes: number }> {
    const ch = channels.files
    if (!ch || ch.readyState !== 'open') {
      throw new Error('files channel not open')
    }
    type ShowSaveFilePicker = (options?: {
      suggestedName?: string
      types?: { description?: string; accept: Record<string, string[]> }[]
    }) => Promise<{
      createWritable: () => Promise<SaveWritable>
    }>
    const showSavePicker = (window as unknown as { showSaveFilePicker?: ShowSaveFilePicker })
      .showSaveFilePicker
    if (typeof showSavePicker !== 'function') {
      throw new Error(
        'Folder downloads require Chrome / Edge (need streaming disk writes Ã¢ÂÂ Firefox / Safari fallback would OOM on large zips)'
      )
    }
    const id = `dlf-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`
    const folderBase = path.split(/[\\/]/).filter(Boolean).pop() ?? 'folder'
    const fallbackName = suggestedName ?? `${folderBase}.zip`

    let writable: SaveWritable | null = null
    try {
      const handle = await showSavePicker({
        suggestedName: fallbackName,
        types: [
          {
            description: 'ZIP archive',
            accept: { 'application/zip': ['.zip'] },
          },
        ],
      })
      writable = await handle.createWritable()
    } catch (e) {
      throw e instanceof Error ? e : new Error(String(e))
    }

    return new Promise<{ name: string; bytes: number }>((resolve, reject) => {
      const entry: DownloadEntry = {
        kind: 'download',
        status: 'pending',
        resolve,
        reject,
        saveMode: 'stream',
        writable,
        blobs: [],
        name: fallbackName,
        suggestedName: fallbackName,
        bytesReceived: 0,
        expectedSize: null,
      }
      filesRegistry.set(id, entry)
      pushTransfer({
        id,
        kind: 'download',
        name: fallbackName,
        bytes: 0,
        total: null,
        status: 'queued',
      })
      try {
        ch.send(JSON.stringify({ t: 'files:get-folder', id, path, format: 'zip' }))
      } catch (e) {
        const settled = settleEntry(id)
        if (settled?.kind === 'download') {
          const msg = e instanceof Error ? e.message : String(e)
          patchTransfer(id, { status: 'error', error: msg })
          if (writable) void writable.abort(msg).catch(() => {})
          settled.reject(new Error(msg))
        }
      }
    })
  }

  /** Ask the agent to cancel an in-flight download. Best-effort: the
   *  agent flips its AtomicBool and the next chunk-loop iteration
   *  exits. The Promise rejects via the resulting `files:error`. */
  function cancelDownload(id: string): void {
    const ch = channels.files
    if (!ch || ch.readyState !== 'open') return
    try {
      ch.send(JSON.stringify({ t: 'files:cancel', id }))
    } catch {
      /* dropped */
    }
  }

  /** Cancel an in-flight upload. Settles the registry entry locally
   *  (rejects the Promise + flags the Transfer panel row as
   *  cancelled). The browser-side `pump()` loop checks `readyState`
   *  + the entry status before each chunk send, so by settling here
   *  the next iteration short-circuits and stops sending bytes. The
   *  agent will see the DC stay open with no more chunks; eventually
   *  its existing short-transfer-on-end logic / DC-close cleanup
   *  handles the half-uploaded file (left on disk under Downloads/
   *  for the operator to delete or resume manually).
   *
   *  Symmetric with `cancelDownload` so the Transfers panel can
   *  render a single "Cancel" affordance regardless of direction. */
  function cancelUpload(id: string): void {
    const entry = filesRegistry.get(id)
    if (!entry || entry.kind !== 'upload' || entry.status === 'settled') return
    const settled = settleEntry(id)
    if (settled?.kind === 'upload') {
      patchTransfer(id, { status: 'cancelled', error: 'cancelled by operator' })
      settled.reject(new Error('cancelled by operator'))
    }
  }

  /** Cancel a transfer regardless of direction. Convenience for the
   *  Transfers panel UI which doesn't need to know upload vs
   *  download Ã¢ÂÂ it just calls `cancelTransfer(id)` per row. */
  function cancelTransfer(id: string): void {
    const entry = filesRegistry.get(id)
    if (!entry) return
    if (entry.kind === 'upload') cancelUpload(id)
    else cancelDownload(id)
  }

  // --------------------------------------------------------------
  // Directory listing (Phase 3 of file-DC v2).
  //
  // Request/response keyed by req_id, like the clipboard:read flow.
  // 5 s timeout rejects stale requests so the drawer doesn't spin
  // forever if the host is unreachable or the agent lacks the new
  // capability (old 0.2.x agents will simply not reply).

  type DirEntry = {
    name: string
    is_dir: boolean
    size: number | null
    mtime_unix: number | null
  }
  type DirListing = {
    path: string
    parent: string | null
    entries: DirEntry[]
  }
  const pendingDirRequests = new Map<
    string,
    { resolve: (l: DirListing) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> }
  >()
  function settleDirRequest(reqId: string): {
    resolve: (l: DirListing) => void
    reject: (e: Error) => void
  } | null {
    const p = pendingDirRequests.get(reqId)
    if (!p) return null
    clearTimeout(p.timer)
    pendingDirRequests.delete(reqId)
    return { resolve: p.resolve, reject: p.reject }
  }

  /** List a directory on the host. `path` is the absolute host path;
   *  empty string / "~" / "/" enumerates roots (logical drives on
   *  Windows; "/" on Unix). Resolves with the listing or rejects on
   *  timeout / dir-error. */
  function listDir(path: string): Promise<DirListing> {
    const ch = channels.files
    if (!ch || ch.readyState !== 'open') {
      return Promise.reject(new Error('files channel not open'))
    }
    const reqId = `ls-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`
    return new Promise<DirListing>((resolve, reject) => {
      const timer = setTimeout(() => {
        if (pendingDirRequests.has(reqId)) {
          pendingDirRequests.delete(reqId)
          reject(new Error('list_dir timed out (5 s) Ã¢ÂÂ host may not support remote browse'))
        }
      }, 5_000)
      pendingDirRequests.set(reqId, { resolve, reject, timer })
      try {
        ch.send(JSON.stringify({ t: 'files:dir', req_id: reqId, path }))
      } catch (e) {
        clearTimeout(timer)
        pendingDirRequests.delete(reqId)
        reject(e instanceof Error ? e : new Error(String(e)))
      }
    })
  }

  /** Upload multiple files sequentially. Each file is queued through
   *  `uploadOne`; the queue continues on individual failures so a
   *  bad file doesn't sink the rest. Resolves with one result per
   *  input file (in order) carrying either the agent-reported path +
   *  bytes (success) or an error message (failure).
   *
   *  Accepts either bare `File` items (flat upload Ã¢ÂÂ file lands in
   *  Downloads/) or `{ file, relPath }` pairs (folder upload Ã¢ÂÂ agent
   *  recreates the directory structure under Downloads/<root>/).
   *  Mixing is allowed Ã¢ÂÂ useful when a drag&drop event has both
   *  individual files and one or more folders. */
  type UploadResult =
    | { ok: true; name: string; path: string; bytes: number }
    | { ok: false; name: string; error: string }
  // `relPath` carries the folder-upload structure (file-DC v2.1).
  // `destPath` is the path-targeted upload root (file-DC v2.2) Ã¢ÂÂ when
  // set, the file lands under `<destPath>/`. The two stack: a folder
  // dropped onto a host directory recreates the source structure
  // under that target dir.
  type UploadInput =
    | File
    | { file: File; relPath?: string; destPath?: string }
  async function uploadFiles(
    items: UploadInput[],
    options?: { destPath?: string }
  ): Promise<UploadResult[]> {
    const results: UploadResult[] = []
    for (const it of items) {
      const f: File = it instanceof File ? it : it.file
      const relPath: string | undefined = it instanceof File ? undefined : it.relPath
      // Per-item destPath wins; falls back to the call-level option.
      const destPath: string | undefined =
        (it instanceof File ? undefined : it.destPath) ?? options?.destPath
      const reportName = relPath ?? f.name
      try {
        const r = await uploadOne(f, relPath, destPath)
        results.push({ ok: true, name: reportName, path: r.path, bytes: r.bytes })
      } catch (e) {
        results.push({
          ok: false,
          name: reportName,
          error: e instanceof Error ? e.message : String(e),
        })
      }
    }
    return results
  }

  /** Recursively walk a `FileSystemEntry` (from
   *  `dataTransfer.items[i].webkitGetAsEntry()`) into a flat list of
   *  `{ file, relPath }` pairs ready for `uploadFiles`. The relative
   *  path uses forward slashes (matches what the agent expects on
   *  the wire). Skips dotfiles and symlinks for safety; caps the
   *  walk at 5000 files / 32 levels of depth to refuse pathological
   *  inputs (huge `node_modules` etc.) before they swamp the queue.
   *
   *  Returns `null` on entries that aren't directories (caller
   *  should treat as a single file via `entry.file()`). */
  type FolderWalkEntry = { file: File; relPath: string }
  async function walkFolderEntry(
    entry: FileSystemEntry,
    rootName: string
  ): Promise<FolderWalkEntry[]> {
    const out: FolderWalkEntry[] = []
    const MAX_FILES = 5000
    const MAX_DEPTH = 32
    type Pending = { entry: FileSystemEntry; relParent: string; depth: number }
    const queue: Pending[] = [{ entry, relParent: rootName, depth: 0 }]
    while (queue.length > 0) {
      const { entry: cur, relParent, depth } = queue.shift() as Pending
      if (depth > MAX_DEPTH) continue
      if (cur.name.startsWith('.')) continue // skip dotfiles / dotdirs
      if (cur.isFile) {
        const fileEntry = cur as FileSystemFileEntry
        const f: File = await new Promise((resolve, reject) =>
          fileEntry.file(resolve, reject)
        )
        out.push({ file: f, relPath: `${relParent}/${cur.name}` })
        if (out.length >= MAX_FILES) break
      } else if (cur.isDirectory) {
        const dirEntry = cur as FileSystemDirectoryEntry
        const reader = dirEntry.createReader()
        // readEntries pages Ã¢ÂÂ keep calling until it returns an empty array.
        let batch: FileSystemEntry[] = []
        do {
          batch = await new Promise<FileSystemEntry[]>((resolve, reject) =>
            reader.readEntries(resolve, reject)
          )
          for (const child of batch) {
            queue.push({
              entry: child,
              relParent: `${relParent}/${cur.name}`,
              depth: depth + 1,
            })
          }
        } while (batch.length > 0)
      }
    }
    return out
  }

  /** Send Ctrl+Alt+Del to the remote. The browser can't capture this
   *  key combo (the OS intercepts first), so callers typically wire
   *  this to a dedicated toolbar button. FR-97 P4a: to an agent that
   *  sends Windows' secure attention sequence, one `sas` frame, which
   *  the lock and sign-in screens answer; to any other, the three keys
   *  in the native order (`ctrlAltDelFrames`). */
  function sendCtrlAltDel() {
    const ch = channels.input
    if (!ch || ch.readyState !== 'open') return
    for (const frame of ctrlAltDelFrames(agent?.value?.capabilities?.input)) {
      try { ch.send(JSON.stringify(frame)) } catch { /* dropped */ }
    }
  }

  return {
    phase,
    error,
    notice,
    /** FR-27 P10 - `'host'` when the person at the device ended the last session. */
    endedBy,
    sessionId,
    overrideReason,
    remoteStream,
    hasMedia,
    inputChannelOpen,
    inputGranted,
    clipboardGranted,
    recordGranted,
    recordRefused,
    recording,
    privacyGranted,
    privacyRefused,
    privacy,
    featuresRefused,
    /** FR-100 P2a — the verdict on the last answer this page asked a device to sign. */
    peerAuth,
    trustPeerAuthKey,
    stats,
    quality,
    setQuality,
    cursor,
    connect,
    connectExternal,
    disconnect,
    /**
     * Current auto-reconnect attempt counter. 0 = not reconnecting;
     * 1..N = pending the Nth attempt's timer (or the Nth retry's
     * connect() call is in flight). The viewer can render
     * "Reconnecting (N/{RC_RECONNECT_LADDER_MS.length})..." while
     * `phase === 'reconnecting'`.
     */
    reconnectAttempt,
    lastTtffMs,
    /**
     * S3 Ã¢ÂÂ sub-connected health. Non-null while `phase ===
     * 'connected'` but something is off: 'transport_unstable' (pc
     * left 'connected'), 'media_stalled' (keyframe probe
     * outstanding), 'signalling_offline' (WS down; media may still
     * flow P2P). The viewer renders a warning chip from this instead
     * of a dishonest solid-green "connected".
     */
    degraded,
    /**
     * Whether the host has signalled (via the `rc:host_locked`
     * control-DC message) that its input desktop has transitioned
     * to `winsta0\Winlogon`. Used by the viewer to render an
     * explicit "Host locked" badge alongside the video stream's
     * padlock overlay frame.
     */
    hostLocked,
    /** FR-97 P3b — what the lock screen does with input: the chip says it. */
    hostLockedInput,
    keepBusy,
    setKeepBusy,
    /** FR-108 — the device's answer to the latest display-match request. */
    displayMatchState,
    /** FR-109 — relative mode: true while the stage holds Pointer Lock. */
    relativeMouse,
    /** FR-109 P3 — the lock was taken by the auto-switch (the host hid its
     *  cursor), not from the toolbar. */
    relativeMouseAuto,
    /** FR-111 P4b-2 — set while a viewer dialog takes typing. */
    keyboardPaused,
    enterRelativeMouse,
    exitRelativeMouse,
    setRelativeMouseAllowed,
    touchMode,
    setTouchMode,
    /** FR-111 P3 — where the on-screen controls press. */
    touchControlsSink,
    /** rc.87 Ã¢ÂÂ real encoder info from the agent (`rc:video-info`).
     *  Null on the legacy track / libvpx paths (no message); the
     *  badge falls back to a selection-derived label then. */
    videoInfo,
    mediaUnavailable,
    // FR-97 P3c-1 — why this session's audio track carries no sound, or null.
    audioUnavailable,
    mediaWaiting,
    inputReach,
    // FR-101 P4b-2b — the device's idle countdown (epoch ms, or null).
    idleEndsAt,
    dcDecoderCodec,
    // P6 — multi-user: arbiter state, ghost cursors, floor control.
    controlState,
    peerCursors,
    requestControl,
    grantControl,
    dismissControlRequest,
    setInputMode,
    /**
     * Name of the input desktop the agent is currently bound to,
     * as reported by the SYSTEM-context worker via the
     * `rc:desktop_changed` control-DC message. `'Default'` is the
     * normal interactive desktop; `'Winlogon'` / `'Screen-saver'`
     * are secure desktops. Older agents never emit the message and
     * the ref stays at `'Default'`, which keeps the viewer
     * rendering only the existing `hostLocked` chip.
     */
    currentDesktop,
    /**
     * rc.23 Ã¢ÂÂ diagnostic surface. `agentLogs` holds the last
     * `rc:logs-fetch.reply` (null until first fetch); the UI renders
     * `lines` in a scrolling pre-block. `agentLogsLoading` flips
     * true while a request is in flight (drives a spinner).
     * `fetchAgentLogs(linesCount)` triggers a new request Ã¢ÂÂ operator
     * calls this from a toolbar button or auto-fetches when the log
     * dialog opens.
     */
    agentLogs,
    agentLogsLoading,
    fetchAgentLogs,
    // rc.NEXT Ã¢ÂÂ remote app selection & launch (virtual-desktop hosts).
    remoteWindows,
    launchableApps,
    appsCoverage,
    appsSupported,
    appsLoading,
    appsError,
    refreshApps,
    focusWindow,
    launchApp,
    attachInput,
    /** Wire `key_text` over the input DC (used by mobile keyboard +
     *  IME composition path). See [`sendKeyText`] for the full
     *  contract. */
    sendKeyText,
    /** Wire a HID `key` event over the input DC (used by mobile
     *  keyboard's special-key toolbar). See [`sendKey`] for the
     *  bitfield encoding. */
    sendKey,
    /** Keyboard Lock (locked fullscreen): flag + engage/release.
     *  The view calls enable on fullscreenchange-enter (never awaited
     *  inline) and disable on exit/unmount. */
    keyboardLockActive,
    enableKeyboardLock,
    disableKeyboardLock,
    /** FR-13 (#789): mac-host Ctrl→Cmd translation — flag + the
     *  per-session toggle the toolbar renders for mac hosts only. */
    hostIsMac,
    ctrlAsCmd,
    /** rc.227 Ã¢ÂÂ remote keyboard-layout state (null on old agents /
     *  non-Windows hosts) + the manual switch sender. */
    remoteLayout,
    setRemoteLayout,
    sendClipboardToAgent,
    getAgentClipboard,
    /** v2 Ã¢ÂÂ text-or-image read (falls back to text-only on old
     *  agents). The Get-clipboard button uses this when the agent
     *  advertises the `images` cap. */
    getAgentClipboardRich,
    /** v2 Ã¢ÂÂ clipboard auto-sync toggle (persisted; default ON) +
     *  the permission-blocked latch the view surfaces as a snackbar. */
    clipboardAutoSyncEnabled,
    setClipboardAutoSyncEnabled,
    clipboardSyncBlocked,
    supportsClipboardEvents,
    supportsClipboardImages,
    supportsClipboardHtml,
    /** v2.2 Ã¢ÂÂ remote agent speaks RTF, and whether this machine has a
     *  local bridge to reach its own RTF clipboard (the WordÃ¢ÂÂWord
     *  full-fidelity path). `canUseNativeClipboard` = both true. */
    supportsClipboardNative,
    localClipboardBridge,
    canUseNativeClipboard,
    /** v2.2 Ã¢ÂÂ write a native (RTF) payload to THIS machine's clipboard
     *  via the local bridge. Used by the manual Get button so the view
     *  doesn't need bridge access. Returns true on success. */
    writeLocalNativeClipboard,
    sendCtrlAltDel,
    uploadFile,
    uploadFiles,
    walkFolderEntry,
    downloadFile,
    downloadFolder,
    cancelDownload,
    cancelUpload,
    cancelTransfer,
    listDir,
    transfers,
    preferredCodec,
    setPreferredCodec,
    scaleMode,
    scaleCustomPercent,
    setScaleMode,
    setScaleCustomPercent,
    resolution,
    setResolution,
    /** FR-119 P1 — the frame-rate pick, its options, and the agent's answer. */
    frameRate,
    frameRateChoices,
    frameRateAnswer,
    setFrameRate,
    renderPath,
    setRenderPath,
    webcodecsSupported,
    webcodecsActive,
    webcodecsCanvasEl,
    mediaIntrinsicW,
    mediaIntrinsicH,
    videoTransport,
    setVideoTransport,
    /** rc.190 Ã¢ÂÂ WebCodecs AV1 decode availability (gates the AV1 toggle). */
    av1Supported,
    /** rc.191 Ã¢ÂÂ display-match sender (agent switches its display mode to
     *  fit the viewer's stage; null restores). View owns the toggle. */
    sendDisplayMatch,
    /** rc.190 Ã¢ÂÂ whether this viewer HW-decodes the active session's codec
     *  (null = unknown / webrtc). The viewer half of the HWÃÂHW badge. */
    viewerDecodeHw,
    /** Opt-in "receive host audio" flag (per-browser, persisted).
     *  Drives the recvonly audio transceiver + `audio_enabled` request
     *  field. Takes effect on next Connect. */
    audioEnabled,
    setAudioEnabled,
    /** The received host-audio stream (own MediaStream). View binds it
     *  to a hidden <audio autoplay> sink. Null until an Opus track
     *  arrives. */
    remoteAudioStream,
    /** True when autoplay-with-sound was blocked; view shows a one-
     *  click unmute affordance that calls `resumeAudioPlayback`. */
    audioAutoplayBlocked,
    resumeAudioPlayback,
    /** rc.62 Ã¢ÂÂ user's VP9 chroma preference ('auto' | 'yuv420' |
     *  'yuv444'). Drives the `chroma_pref` field of
     *  `rc:session.request` AND the vp9-444 worker's codec string
     *  selection. */
    vp9Chroma,
    setVp9Chroma,
    /** rc.199 Ã¢ÂÂ the viewer "Priority" dial + its setter (live; sent over the
     *  control DC). Balanced / Sharper (relay-cap override) / Smoother. */
    priority,
    setPriority,
    /** P7 — FSR sharpening mode ('auto' | 'on' | 'off') + its setter (live;
     *  posted to the active DC video worker) and the worker-reported active
     *  render path + backing size (for the "· FSR" pill / diag HUD). */
    sharpenMode,
    setSharpenMode,
    renderInfo,
    /** rc.199 — the unified Codec picker (computed over transport+chroma+
     *  preferredCodec+renderPath). Read for the picker's value; assign to
     *  apply a choice. Replaces the 4 transport toggles + 2 dropdowns. */
    codecChoice,
    /** loopback-TURN corp-relay opt-in (Phase 2, default OFF) + its setter.
     *  When on, `connect()` probes the local agent's loopback TURN and relays
     *  through it Ã¢ÂÂ bypasses the capped far-coturn relay on corp networks. */
    localRelayEnabled,
    setLocalRelayEnabled,
    vp9_444Supported,
    vp9_444Active,
    vp9_444FramesDecoded,
    vp9_444Stats,
    vp9_444CanvasEl,
    /** P7 — whether this browser decodes HEVC Rext 4:4:4 (gates the
     *  "HEVC · crisp text (4:4:4)" picker entry with the agent's
     *  hevc_chroma caps). */
    hevcRextSupported,
    h264High444Supported,
    /** rc.78 — HEVC over DataChannel (Option B). Same shape as the
     *  VP9-444 fields above; view can branch on which is active to
     *  decide which canvas/HUD to render. */
    hevcSupported,
    hevcActive,
    hevcFramesDecoded,
    hevcStats,
    hevcCanvasEl,
    /** P1 Ã¢ÂÂ per-hop pipeline diagnostics for the diag HUD
     *  (localStorage roomler-rc-diag-hud=1). */
    decodeDiag,
  }
}

/** Small base64 Ã¢ÂÂ Uint8Array helper. atob + TextDecoder would work
 *  but base64 decodes to a binary string that atob(str).charCodeAt(i)
 *  handles correctly; use the direct loop. Exported for tests. */
export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/**
 * Inspect the browser's `RTCRtpReceiver.getCapabilities('video')` and
 * return the subset of codec mime types we care about for negotiation,
 * stripped to short names ("h264", "h265", "av1", "vp9", "vp8").
 *
 * Returns an empty array on browsers that don't expose
 * `getCapabilities` (older Safari/iOS) Ã¢ÂÂ the agent then falls back to
 * H.264-only. Each codec is reported once even if the browser
 * advertises multiple profile-level-id variants of it.
 *
 * Exported standalone so vitest can verify the filter without standing
 * up the full composable + WS store.
 */
export function inspectBrowserVideoCodecs(): string[] {
  // Static method. Older Safari may not have it.
  const getCaps = (
    globalThis as unknown as { RTCRtpReceiver?: { getCapabilities?: (k: string) => { codecs?: Array<{ mimeType?: string }> } | null } }
  ).RTCRtpReceiver?.getCapabilities
  if (typeof getCaps !== 'function') return []
  const caps = getCaps('video')
  if (!caps || !Array.isArray(caps.codecs)) return []
  // Codec mime types are case-insensitive per RFC 6381 ("video/H264").
  const seen = new Set<string>()
  for (const c of caps.codecs) {
    const mime = (c.mimeType || '').toLowerCase()
    if (!mime.startsWith('video/')) continue
    const name = mime.slice('video/'.length)
    // Filter to the codecs the agent's negotiation cares about.
    // RTX (retransmission), red (FEC), ulpfec, flexfec are RTP
    // mechanism codecs Ã¢ÂÂ not what we'd negotiate as the primary
    // video codec.
    if (['h264', 'h265', 'av1', 'vp9', 'vp8'].includes(name)) {
      seen.add(name)
    }
  }
  return Array.from(seen)
}

/**
 * Pure helper: extract a live-stats snapshot from an `RTCStatsReport`.
 *
 * Given the previous `bytesReceived` total and its wall-clock timestamp,
 * computes the delta bitrate over the interval and returns it along with
 * the new cumulative counters so the caller can feed them back on the
 * next poll. Extracted as a pure function so the bitrate/fps/codec
 * derivation can be unit-tested without a real PeerConnection.
 *
 * Bitrate is 0 on the first call (prevTsMs === 0): we need two
 * snapshots to derive a rate. `codec` comes from matching the
 * `inbound-rtp.codecId` against a `codec.id` in the same report.
 */
export function extractStatsSnapshot(
  report: RTCStatsReport,
  prevBytes: number,
  prevTsMs: number,
): { next: RcStats; bytes: number; tsMs: number } {
  let bytes = 0
  let tsMs = 0
  let fps = 0
  let codecId = ''
  const codecMap = new Map<string, string>()

  report.forEach((raw) => {
    // RTCStatsReport is typed loosely Ã¢ÂÂ narrow via `type`.
    const s = raw as { type?: string } & Record<string, unknown>
    if (s.type === 'inbound-rtp' && (s as { kind?: string }).kind === 'video') {
      bytes = typeof s.bytesReceived === 'number' ? s.bytesReceived : 0
      tsMs = typeof s.timestamp === 'number' ? s.timestamp : 0
      fps = typeof s.framesPerSecond === 'number' ? s.framesPerSecond : 0
      codecId = typeof s.codecId === 'string' ? s.codecId : ''
    } else if (s.type === 'codec') {
      const id = typeof s.id === 'string' ? s.id : ''
      const mime = typeof s.mimeType === 'string' ? s.mimeType : ''
      if (id) codecMap.set(id, mime)
    }
  })

  // mimeType shape: "video/H264" Ã¢ÂÂ strip the prefix for display.
  const mime = codecMap.get(codecId) || ''
  const codec = mime.replace(/^video\//i, '')

  let bitrate_bps = 0
  if (prevTsMs > 0 && tsMs > prevTsMs) {
    const dtSec = (tsMs - prevTsMs) / 1000
    bitrate_bps = Math.max(0, Math.round(((bytes - prevBytes) * 8) / dtSec))
  }

  return {
    next: { bitrate_bps, fps: Math.round(fps * 10) / 10, codec },
    bytes,
    tsMs,
  }
}

/**
 * Map a browser `MouseEvent.button` (0/1/2/3/4) to the agent's enum.
 */
function browserButton(n: number): 'left' | 'right' | 'middle' | 'back' | 'forward' {
  switch (n) {
    case 0: return 'left'
    case 1: return 'middle'
    case 2: return 'right'
    case 3: return 'back'
    case 4: return 'forward'
    default: return 'left'
  }
}

/** Decide whether to `preventDefault` on a keyboard event in the remote
 *  viewer. Three categories:
 *
 *  1. Unconditionally: `Tab` (would otherwise move focus out of the
 *     video and away from our key listeners) and plain `Backspace`
 *     (some browsers map to back-navigation on pages without a form).
 *
 *  2. Only when the pointer is over the video: common Ctrl/Cmd-shortcuts
 *     that the local browser would otherwise intercept (Ctrl+A select
 *     all, Ctrl+C/V/X clipboard, Ctrl+Z/Y undo/redo, Ctrl+F find,
 *     Ctrl+S save, Ctrl+P print, Ctrl+R reload). Outside the video
 *     the controller keeps normal browser UX Ã¢ÂÂ Ctrl+T to open a tab,
 *     Ctrl+W to close it, etc. Ã¢ÂÂ when NOT keyboard-locked.
 *
 *  3. Locked fullscreen (`keyboardLocked` Ã¢ÂÂ the Keyboard Lock API is
 *     active): suppress the local default for EVERY forwarded key so
 *     Alt+Tab / Win / Ctrl+W / Ctrl+T / F-keys act on the REMOTE.
 *     Escape is safe to suppress here Ã¢ÂÂ exiting fullscreen under
 *     Keyboard Lock is the browser's press-AND-HOLD gesture, which
 *     preventDefault cannot cancel; short Esc taps forward cleanly.
 *     IME events never reach this decision (`decideKeyAction` drops
 *     them first in `onKey`).
 *
 *  Ctrl+Alt+Del is reserved by the OS and cannot be intercepted by the
 *  browser Ã¢ÂÂ it's exposed via the dedicated toolbar button plus the
 *  RDP-convention Ctrl+Alt+End chord (see [`isRemoteSasChord`]).
 *  Exported so unit tests can lock the policy. */
export function shouldPreventDefault(
  ev: KeyboardEvent,
  pointerInside: boolean,
  keyboardLocked = false,
): boolean {
  if (keyboardLocked) return true
  if (ev.code === 'Tab') return true
  if (ev.code === 'Backspace' && !ev.ctrlKey && !ev.altKey && !ev.metaKey) return true
  if (!pointerInside) return false
  const cmd = ev.ctrlKey || ev.metaKey
  if (!cmd) return false
  // Keys the local browser would intercept; prevent so they only
  // forward to the remote.
  switch (ev.code) {
    case 'KeyA': case 'KeyC': case 'KeyV': case 'KeyX':
    case 'KeyZ': case 'KeyY':
    case 'KeyF': case 'KeyS': case 'KeyP': case 'KeyR':
      return true
    default:
      return false
  }
}

/** RDP-convention secure-attention chord: Ctrl+Alt+End sends
 *  Ctrl+Alt+Del to the remote (the literal chord is OS-reserved and
 *  never reaches the page on Windows viewers; on Linux/macOS viewers
 *  it CAN arrive, so accept it too). AltGraph carve-out: German and
 *  other AltGr layouts report ctrlKey+altKey while typing Ã¢ÂÂ AltGr+End
 *  must not fire a SAS. Meta excluded so Win+Ctrl+Alt combos don't
 *  trigger. Exported for the spec's chord matrix. */
export function isRemoteSasChord(
  ev: Pick<KeyboardEvent, 'code' | 'ctrlKey' | 'altKey' | 'metaKey'>,
  getModifierState: (key: string) => boolean = () => false,
): boolean {
  if (!ev.ctrlKey || !ev.altKey || ev.metaKey) return false
  if (getModifierState('AltGraph')) return false
  return ev.code === 'End' || ev.code === 'Delete'
}

/** Structural shape of the (Chromium-only) Keyboard Lock API Ã¢ÂÂ
 *  lib.dom.d.ts doesn't ship it. */
type KeyboardLockApi = {
  lock?: (keyCodes?: string[]) => Promise<void>
  unlock?: () => void
}

/** Feature-detect `navigator.keyboard.lock` (Chromium in a secure
 *  context). Firefox/Safari return false and the viewer degrades to
 *  the pointer-inside preventDefault policy. Injectable nav for
 *  tests. */
export function isKeyboardLockSupported(
  nav: { keyboard?: KeyboardLockApi } | undefined = typeof navigator === 'undefined'
    ? undefined
    : (navigator as Navigator & { keyboard?: KeyboardLockApi }),
): boolean {
  return !!nav?.keyboard && typeof nav.keyboard.lock === 'function'
}

/**
 * Translate `KeyboardEvent.code` (physical-key string, e.g. "KeyA",
 * "ArrowLeft") to a USB HID usage code on the Keyboard/Keypad page.
 *
 * The agent's enigo backend maps these back to OS-native scan codes,
 * which is what makes remote typing layout-independent.
 */
function kbdCodeToHid(code: string): number | null {
  // Letter row.
  if (code.startsWith('Key') && code.length === 4) {
    const ch = code.charCodeAt(3) - 'A'.charCodeAt(0)
    if (ch >= 0 && ch <= 25) return 0x04 + ch // a..z Ã¢ÂÂ 0x04..0x1d
  }
  // Digit row.
  if (code.startsWith('Digit') && code.length === 6) {
    const d = code.charCodeAt(5) - '0'.charCodeAt(0)
    // HID: 1..9 Ã¢ÂÂ 0x1e..0x26, 0 Ã¢ÂÂ 0x27
    if (d === 0) return 0x27
    if (d >= 1 && d <= 9) return 0x1e + d - 1
  }
  if (code === 'Enter') return 0x28
  if (code === 'Escape') return 0x29
  if (code === 'Backspace') return 0x2a
  if (code === 'Tab') return 0x2b
  if (code === 'Space') return 0x2c
  if (code === 'ArrowRight') return 0x4f
  if (code === 'ArrowLeft') return 0x50
  if (code === 'ArrowDown') return 0x51
  if (code === 'ArrowUp') return 0x52
  if (code === 'Home') return 0x4a
  if (code === 'End') return 0x4d
  if (code === 'PageUp') return 0x4b
  if (code === 'PageDown') return 0x4e
  if (code === 'Insert') return 0x49
  if (code === 'Delete') return 0x4c
  if (code === 'ControlLeft') return 0xe0
  if (code === 'ShiftLeft') return 0xe1
  if (code === 'AltLeft') return 0xe2
  if (code === 'MetaLeft') return 0xe3
  if (code === 'ControlRight') return 0xe4
  if (code === 'ShiftRight') return 0xe5
  if (code === 'AltRight') return 0xe6
  if (code === 'MetaRight') return 0xe7
  // Punctuation row. HID usages from "Keyboard/Keypad" Page (0x07).
  // These mostly reach the agent via KeyText now (printable + no
  // chord Ã¢ÂÂ see onKey), but we still need HID codes for the chord
  // path: e.g. Ctrl+, in some IDEs binds to "settings", which only
  // works if we forward the keypress with the chord modifier rather
  // than typing a literal ','. Without these mappings, those chords
  // were silently dropped pre-fix.
  if (code === 'Backquote') return 0x35
  if (code === 'Minus') return 0x2d
  if (code === 'Equal') return 0x2e
  if (code === 'BracketLeft') return 0x2f
  if (code === 'BracketRight') return 0x30
  if (code === 'Backslash') return 0x31
  if (code === 'Semicolon') return 0x33
  if (code === 'Quote') return 0x34
  if (code === 'Comma') return 0x36
  if (code === 'Period') return 0x37
  if (code === 'Slash') return 0x38
  if (code === 'IntlBackslash') return 0x64
  // Lock + system keys.
  if (code === 'CapsLock') return 0x39
  if (code === 'NumLock') return 0x53
  if (code === 'ScrollLock') return 0x47
  if (code === 'PrintScreen') return 0x46
  if (code === 'Pause') return 0x48
  if (code === 'ContextMenu') return 0x65
  // Numeric keypad (HID 0x53..0x63). agent's hid_to_key currently
  // falls through to Key::Other(code) for these; works enough that
  // chords with NumLock-off arrows make it through.
  if (code === 'NumpadDivide') return 0x54
  if (code === 'NumpadMultiply') return 0x55
  if (code === 'NumpadSubtract') return 0x56
  if (code === 'NumpadAdd') return 0x57
  if (code === 'NumpadEnter') return 0x58
  if (code === 'NumpadDecimal') return 0x63
  if (code.startsWith('Numpad') && code.length === 7) {
    const d = code.charCodeAt(6) - '0'.charCodeAt(0)
    // HID Numpad 1..9 Ã¢ÂÂ 0x59..0x61, Numpad 0 Ã¢ÂÂ 0x62.
    if (d === 0) return 0x62
    if (d >= 1 && d <= 9) return 0x59 + d - 1
  }
  // F1..F12
  if (code.startsWith('F') && code.length >= 2 && code.length <= 3) {
    const n = parseInt(code.slice(1), 10)
    if (n >= 1 && n <= 12) return 0x3a + n - 1
  }
  return null
}

/**
 * Pure helper: given a pointer clientX/clientY, the .video-frame bounding
 * rect, and the `<video>` element's intrinsic videoWidth/videoHeight,
 * return [0,1]-normalised coordinates relative to the *visible video
 * content* (accounting for the letterbox that `object-fit: contain`
 * produces when viewer and agent aspect ratios differ) plus a boolean
 * indicating whether the pointer is inside the visible region.
 *
 * Extracted so the math is unit-testable without a DOM.
 */
export function letterboxedNormalise(
  clientX: number,
  clientY: number,
  frame: { left: number; top: number; width: number; height: number },
  videoWidth: number,
  videoHeight: number,
): { x: number; y: number; insideVideo: boolean } {
  const clamp01 = (n: number) => Math.min(Math.max(n, 0), 1)

  if (!videoWidth || !videoHeight || !frame.width || !frame.height) {
    // No aspect ratio yet Ã¢ÂÂ fall back to frame-relative coords.
    const x = (clientX - frame.left) / Math.max(frame.width, 1)
    const y = (clientY - frame.top) / Math.max(frame.height, 1)
    return { x: clamp01(x), y: clamp01(y), insideVideo: true }
  }

  const videoAR = videoWidth / videoHeight
  const frameAR = frame.width / frame.height
  let visibleW: number, visibleH: number, offsetX: number, offsetY: number
  if (videoAR > frameAR) {
    visibleW = frame.width
    visibleH = frame.width / videoAR
    offsetX = 0
    offsetY = (frame.height - visibleH) / 2
  } else {
    visibleW = frame.height * videoAR
    visibleH = frame.height
    offsetX = (frame.width - visibleW) / 2
    offsetY = 0
  }

  const localX = clientX - frame.left - offsetX
  const localY = clientY - frame.top - offsetY
  const insideVideo =
    localX >= 0 && localX <= visibleW && localY >= 0 && localY <= visibleH
  return {
    x: clamp01(localX / Math.max(visibleW, 1)),
    y: clamp01(localY / Math.max(visibleH, 1)),
    insideVideo,
  }
}

/**
 * Pure helper for `original` / `custom` scale modes where the `<video>`
 * element is rendered without letterboxing Ã¢ÂÂ at its intrinsic size or
 * with a uniform CSS scale. Coordinates map directly against the
 * video element's bounding rect (which already includes scroll
 * offset and the custom CSS scale), normalised to `[0,1]` relative to
 * that rect.
 *
 * Unlike `letterboxedNormalise` this doesn't need to know the
 * intrinsic `videoWidth/videoHeight` Ã¢ÂÂ the bounding rect already
 * reflects the rendered size after scroll + scale, so a point at
 * normalised `(0.5, 0.5)` is always the middle of the remote frame.
 */
export function directVideoNormalise(
  clientX: number,
  clientY: number,
  videoRect: { left: number; top: number; width: number; height: number },
): { x: number; y: number; insideVideo: boolean } {
  const clamp01 = (n: number) => Math.min(Math.max(n, 0), 1)
  if (!videoRect.width || !videoRect.height) {
    return { x: 0, y: 0, insideVideo: false }
  }
  const localX = clientX - videoRect.left
  const localY = clientY - videoRect.top
  const insideVideo =
    localX >= 0 && localX <= videoRect.width &&
    localY >= 0 && localY <= videoRect.height
  return {
    x: clamp01(localX / videoRect.width),
    y: clamp01(localY / videoRect.height),
    insideVideo,
  }
}

/**
 * Outcome of routing a `KeyboardEvent` to either the layout-agnostic
 * `KeyText` path or the existing HID `Key` path. Pure function so the
 * decision tree is unit-testable without standing up the full
 * composable.
 *
 * `text`  Ã¢ÂÂ printable single character with no real-chord modifiers
 *           active. Forwarded to the agent as
 *           `InputMsg::KeyText { text }` Ã¢ÂÂ `enigo.text` Ã¢ÂÂ VK_PACKET on
 *           Windows. Layout-agnostic on the remote.
 * `key`   Ã¢ÂÂ chord, named key (Enter/F1/ArrowUp), Tab, or any printable
 *           release that already had its keydown emitted as `text`.
 *           Forwarded as `InputMsg::Key { code, down, mods }`.
 * `drop`  Ã¢ÂÂ IME composition events, printable keyup whose keydown was
 *           already a `text` (the agent press+releases atomically),
 *           and unmapped codes.
 */
export type KeyDecision =
  | { kind: 'text'; text: string }
  | { kind: 'key'; code: number; down: boolean; mods: number }
  | { kind: 'drop' }

/**
 * Decide which wire-format message (if any) to emit for a browser
 * `KeyboardEvent`. Encapsulates:
 *   - IME composition guard (drop)
 *   - AltGr-aware "real chord" classification
 *   - Printable single-char Ã¢ÂÂ `KeyText` (layout-agnostic)
 *   - Tab carve-out (stays HID for focus traversal)
 *   - Suppress keyup for printable+nochord (matched keydown was atomic)
 *   - Fallback to HID via `kbdCodeToHid`
 *
 * Exported for vitest. The `getModifierState` parameter is split out
 * so tests can drive `AltGraph` without needing a real DOM event
 * (KeyboardEventInit doesn't accept getModifierState in jsdom).
 */
export function decideKeyAction(
  ev: Pick<
    KeyboardEvent,
    'key' | 'code' | 'ctrlKey' | 'altKey' | 'metaKey' | 'shiftKey' | 'isComposing' | 'keyCode'
  >,
  down: boolean,
  getModifierState: (key: string) => boolean = () => false,
): KeyDecision {
  // IME composition: drop. Forwarding would double-type when the
  // matching `compositionend` text flows through.
  if (ev.isComposing || ev.keyCode === 229) return { kind: 'drop' }

  const altGr = getModifierState('AltGraph')
  const realChord =
    (ev.ctrlKey && !altGr) || (ev.altKey && !altGr) || ev.metaKey
  // Tab is excluded from the printable path on purpose: many remote
  // apps gate focus traversal on WM_KEYDOWN(VK_TAB) and wouldn't pick
  // up a U+0009 typed via VK_PACKET.
  const isPrintableSingleChar =
    !realChord && ev.key.length === 1 && ev.key !== '\t'

  if (down && isPrintableSingleChar) {
    return { kind: 'text', text: ev.key }
  }
  if (!down && isPrintableSingleChar) {
    // KeyText is press+release atomic on the agent Ã¢ÂÂ no release event.
    return { kind: 'drop' }
  }

  const code = kbdCodeToHid(ev.code)
  if (code === null) return { kind: 'drop' }
  const mods =
    (ev.ctrlKey ? 1 : 0) | (ev.shiftKey ? 2 : 0) | (ev.altKey ? 4 : 0) | (ev.metaKey ? 8 : 0)
  return { kind: 'key', code, down, mods }
}

/**
 * FR-13 (#789): wholesale Ctrl→Cmd substitution for macOS hosts.
 *
 * A Windows/Linux viewer's Ctrl chords reach a mac host as literal
 * Control — which is SIGINT in a terminal and Emacs bindings in Cocoa
 * text views, never copy/paste. macOS's primary modifier is Command, so
 * when enabled the LEFT/RIGHT CONTROL usages (0xe0/0xe4) are rewritten
 * to LeftGui (0xe3 — `Key::Meta` → kVK_Command on the agent, mapped
 * since 0.1.x, so every deployed agent understands it). This is the
 * same trade RustDesk/CRD/Parsec ship as "translate mode": Ctrl+C in a
 * remote mac Terminal becomes Cmd+C (copy) — the per-session toggle
 * restores literal Ctrl for terminal work.
 *
 * The release half is keyed on what was actually SENT, not on the
 * toggle's current value — flipping the toggle mid-hold must release
 * the key the host believes is down, or Cmd sticks.
 */
export function translateModifierForHost(
  code: number,
  down: boolean,
  enabled: boolean,
  state: { ctrlHeldAsCmd: boolean },
): number {
  if (code !== 0xe0 && code !== 0xe4) return code
  if (down) {
    if (!enabled) return code
    state.ctrlHeldAsCmd = true
    return 0xe3
  }
  if (state.ctrlHeldAsCmd) {
    state.ctrlHeldAsCmd = false
    return 0xe3
  }
  return code
}

export { browserButton, kbdCodeToHid }
