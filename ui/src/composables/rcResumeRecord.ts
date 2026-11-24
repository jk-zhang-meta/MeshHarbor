// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-130 P1c (#3604) — `rc.resume`: one record per hold, filed on the road
 * FR-22's `rc.connect` takes (`POST /api/log/browser`, `agent_logs` with
 * source `browser`).
 *
 * A resumed session writes no `rc.connect` record, because no attempt starts.
 * Before this, a session that rode out a roll would leave nothing to read it
 * by, and a session that did not left only its redial's attempts, under a new
 * session's id. This is AC2's instrument: `gap_ms` is the picture's gap across
 * the cut, read from the frames the page painted (`workers/rc-paint-gap.ts`).
 *
 * | Field | What it holds |
 * |---|---|
 * | `v` | {@link RC_RESUME_RECORD_VERSION} |
 * | `outcome` | `resumed` (the server answered the claim), `ended` (a terminate, the device's `rc:ended`, a transport signal, a hangup), `expired` (the page's own deadline) |
 * | `reason` | an `ended` hold's reason token; absent otherwise |
 * | `gap_ms` | from the last frame painted before the cut to the first after it; `null` when nothing was painted before it |
 * | `gap_open` | no frame was painted after the cut by the time of the record: `gap_ms` is then a lower bound |
 * | `ws_down_ms` | how long the page's own socket was down inside the hold |
 * | `held_ms` | from the cut to the outcome |
 * | `hidden` | the tab was hidden at the cut or at the end: a `<video>` path paints nothing then |
 * | `agent_id`, `agent_org_id` | as `rc.connect` carries them |
 *
 * ⚠️ Best effort, as `rc.connect` is (`rcConnectTimingUpload.ts`): a
 * fire-and-forget POST that never throws, never retries and bypasses
 * `api/client.ts`, capped per minute below the API's governor. Timing
 * metadata only: ids by shape, numbers, booleans and a reason token.
 */
import { RC_CONNECT_UPLOAD_PATH, type RcConnectExtJsonDate } from './rcConnectTimingUpload'
import type { RcHoldOutcome } from './rcSessionHold'

export const RC_RESUME_LOG_TARGET = 'rc.resume'
/** Bump when `fields` changes shape, so a miner can tell records apart. */
export const RC_RESUME_RECORD_VERSION = 1
/** A hold happens a few times a roll at most; this only bounds a flap. */
export const RC_RESUME_UPLOAD_MAX_PER_MIN = 12

const OBJECT_ID_HEX = /^[0-9a-f]{24}$/
/** The server's end reasons are snake_case tokens (`agent_disconnect`, …), and
 *  so are the page's own (`transport`). Anything else is recorded as `other`. */
const REASON = /^[a-z0-9_]{1,64}$/

export interface RcResumeRecordInput {
  /** The page's org, where the person's membership opened the page. */
  tenantId: string | null
  /** The device's org, kept when it is not the page's. */
  agentOrgId?: string | null
  agentId: string | null
  /** The held session: the batch is filed under it. */
  sessionId: string | null
  outcome: RcHoldOutcome
  reason?: string | null
  heldMs: number
  wsDownMs: number
  gapMs: number | null
  gapOpen: boolean
  hidden: boolean
}

export interface RcResumeRecordFields {
  v: typeof RC_RESUME_RECORD_VERSION
  outcome: RcHoldOutcome
  reason?: string
  gap_ms: number | null
  gap_open: boolean
  ws_down_ms: number
  held_ms: number
  hidden: boolean
  agent_id: string | null
  agent_org_id?: string
}

export interface RcResumeLogLine {
  ts: RcConnectExtJsonDate
  level: 'INFO' | 'WARN'
  target: typeof RC_RESUME_LOG_TARGET
  msg: string
  fields: RcResumeRecordFields
}

/** The body `POST /api/log/browser` takes (`BrowserLogBatchPayload`). */
export interface RcResumeUploadBody {
  tenant_id: string
  source: 'browser'
  session_id?: string
  lines: [RcResumeLogLine]
}

function hexOrNull(v: string | null | undefined): string | null {
  return v && OBJECT_ID_HEX.test(v) ? v : null
}

function wholeMs(v: number): number {
  return Number.isFinite(v) ? Math.max(0, Math.round(v)) : 0
}

/** The record for one hold; `null` when there is no tenant to file it under. */
export function buildResumeRecordUpload(input: RcResumeRecordInput, nowMs: number): RcResumeUploadBody | null {
  const tenantId = hexOrNull(input.tenantId)
  if (!tenantId) return null
  const gapMs = input.gapMs === null || !Number.isFinite(input.gapMs) ? null : wholeMs(input.gapMs)
  const fields: RcResumeRecordFields = {
    v: RC_RESUME_RECORD_VERSION,
    outcome: input.outcome,
    gap_ms: gapMs,
    gap_open: input.gapOpen,
    ws_down_ms: wholeMs(input.wsDownMs),
    held_ms: wholeMs(input.heldMs),
    hidden: input.hidden,
    agent_id: hexOrNull(input.agentId),
  }
  if (input.outcome === 'ended' && input.reason) {
    fields.reason = REASON.test(input.reason) ? input.reason : 'other'
  }
  const agentOrg = hexOrNull(input.agentOrgId)
  if (agentOrg && agentOrg !== tenantId) fields.agent_org_id = agentOrg
  const gapWords =
    gapMs === null
      ? 'no picture before the cut'
      : input.gapOpen
        ? `picture gap at least ${gapMs} ms (no frame painted after the cut)`
        : `picture gap ${gapMs} ms`
  const how = fields.reason ? `${input.outcome} (${fields.reason})` : input.outcome
  const line: RcResumeLogLine = {
    ts: { $date: { $numberLong: String(Math.round(nowMs)) } },
    // A resumed session is the point; anything else is a warning, as the
    // console says it.
    level: input.outcome === 'resumed' ? 'INFO' : 'WARN',
    target: RC_RESUME_LOG_TARGET,
    msg: `held ${fields.held_ms} ms, ${how}: ${gapWords}, socket down ${fields.ws_down_ms} ms`,
    fields,
  }
  const sessionId = hexOrNull(input.sessionId)
  return {
    tenant_id: tenantId,
    source: 'browser',
    ...(sessionId ? { session_id: sessionId } : {}),
    lines: [line],
  }
}

export interface RcResumeRecordUploader {
  /** Post one hold's record. Never throws, never rejects, never blocks. */
  send(input: RcResumeRecordInput): void
  /** Records handed to `fetch` so far. */
  sentCount(): number
}

export interface RcResumeUploaderDeps {
  fetch?: (input: string, init: RequestInit) => Promise<unknown>
  now?: () => number
  maxPerMinute?: number
}

/** One per viewer composable, as `createConnectTimingUploader` is. */
export function createResumeRecordUploader(deps: RcResumeUploaderDeps = {}): RcResumeRecordUploader {
  const now = deps.now ?? (() => Date.now())
  const maxPerMinute = deps.maxPerMinute ?? RC_RESUME_UPLOAD_MAX_PER_MIN
  const sentAt: number[] = []
  let sent = 0

  function underCap(nowMs: number): boolean {
    for (;;) {
      const oldest = sentAt[0]
      if (oldest === undefined || nowMs - oldest < 60_000) break
      sentAt.shift()
    }
    if (sentAt.length >= maxPerMinute) return false
    sentAt.push(nowMs)
    return true
  }

  return {
    send(input) {
      try {
        const nowMs = now()
        const body = buildResumeRecordUpload(input, nowMs)
        if (!body) return
        if (!underCap(nowMs)) return
        const init: RequestInit = {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
          // The record of a hold the person ended by closing the tab is the one
          // most likely to be lost without it.
          keepalive: true,
          credentials: 'same-origin',
        }
        const p = deps.fetch
          ? deps.fetch(RC_CONNECT_UPLOAD_PATH, init)
          : typeof globalThis.fetch === 'function'
            ? globalThis.fetch(RC_CONNECT_UPLOAD_PATH, init)
            : null
        if (!p) return
        sent += 1
        void Promise.resolve(p).then(
          () => undefined,
          () => undefined,
        )
      } catch {
        /* never let a diagnostic reach the session */
      }
    },
    sentCount() {
      return sent
    },
  }
}
