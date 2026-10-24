// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { appPath } from '@/utils/deployment'
/**
 * FR-22 part 4 — persist each connect attempt's marks.
 *
 * Parts 1–3b put the eleven connect marks in the console and the verdict in
 * a snackbar. Both live exactly as long as the tab does. The 2026-09-25 field
 * read found what that costs: the server records three of the eleven marks
 * (`remote_audit`), every stall it could see had aged past the pod-log and
 * `agent_logs` windows, and a stall in `requesting` leaves no server row at
 * all — so the phase a stall died in, the one fact the marks exist to
 * capture, was recorded nowhere. `agent_logs` held ZERO browser rows because
 * the `/api/log/browser` route had never been given a caller.
 *
 * This is that caller. One record per attempt, posted when the attempt ends
 * — first paint, a phase bound firing, the operator cancelling, or the ladder
 * advancing past it — into `agent_logs` as a `browser`-source batch with one
 * line, `target: "rc.connect"`, so a stall's phase is mineable server-side
 * within the same 7-day window as the agent's own logs.
 *
 * ⚠️ Best effort, by construction. Nothing here may touch the session: the
 * POST is fire-and-forget, every failure (network, 401, 403, 429, 5xx) is
 * swallowed, and it deliberately bypasses `api/client.ts`, whose 401 handler
 * would try a token refresh and log the operator out, and whose 429/5xx
 * handlers raise a snackbar. A diagnostic must never become the incident.
 *
 * ⚠️ Timing metadata only. The `msg` is the same per-step line the console
 * prints (mark names and millisecond deltas) and `fields` carries ids,
 * booleans and numbers. No URL, no token, no message text, no hostname —
 * the record is about WHEN, never about WHAT.
 *
 * ⚠️ Rate-capped below the API's per-IP governor (60 req/min). One attempt
 * produces one POST, never a retry, and a flapping ladder that abandons an
 * attempt every few seconds is capped by `RC_CONNECT_UPLOAD_MAX_PER_MIN` —
 * dropping a record is the right failure, since a diagnostic that throttles
 * the API it shares with the session would be measuring its own damage.
 */
import {
  RC_CONNECT_MARKS,
  firstMissingMark,
  formatConnectTiming,
  type RcConnectMark,
  type RcConnectTiming,
} from './rcConnectTiming'

/** How the attempt ended. `abandoned` = the phase bound fired
 *  (`signalingTimeoutFor`); `closed` = the operator hung up, the view
 *  unmounted or a terminal `rc:error` failed it; `retried` = the ladder
 *  advanced past it for another reason (a transient `rc:error` it rides,
 *  an ICE failure, dead air before the first frame). Before part 4 a
 *  `retried` attempt was replaced by the next recorder without a trace. */
export type RcConnectOutcome = 'first_frame' | 'abandoned' | 'closed' | 'retried'

export interface RcConnectUploadContext {
  /** The tenant the row is filed under — the PAGE's org, where the user's
   *  membership is what let them open the page. The route rejects a tenant
   *  the caller is not a member of, and on a cross-org session (FR-52) that
   *  can be the device's org. */
  tenantId: string | null
  /** The device's org when it is not the page's. Kept in `fields` so a
   *  cross-org record still says whose device it was. */
  agentOrgId?: string | null
  agentId: string | null
  /** Known from `rc:session.created` onward. Absent on a `requesting` stall
   *  — which is the point: that absence is the phase. */
  sessionId: string | null
  outcome: RcConnectOutcome
  /** The `rc:error` code that ended the attempt, when one did. Separates
   *  "the server refused" from "nobody answered", which look identical in
   *  the marks (both stop at the same missing step). */
  errorCode?: string | null
}

export const RC_CONNECT_LOG_TARGET = 'rc.connect'
/** Bump when `fields` changes shape, so a miner can tell records apart. */
export const RC_CONNECT_RECORD_VERSION = 1
export const RC_CONNECT_UPLOAD_PATH = appPath('/api/log/browser')
/** Well under the governor's 60/min per IP, and above anything the ladder
 *  can legitimately produce (its fastest steady state is one attempt per
 *  `RC_REQUEST_TIMEOUT_MS`, i.e. 15/min, and those are the records worth
 *  having; anything faster is a flap the first dozen already describe). */
export const RC_CONNECT_UPLOAD_MAX_PER_MIN = 12

const OBJECT_ID_HEX = /^[0-9a-f]{24}$/
/** The server's `rc:error` codes are snake_case tokens (`agent_offline`,
 *  `consent_denied`, …; `error_code()` in `crates/modules/remote/src/controller.rs`).
 *  Anything else that arrives in that slot is recorded as `other`: the
 *  record is timing metadata by SHAPE, not by trust in whoever filled the
 *  field, and a free-text code is the one place a URL or a token could ride in. */
const ERROR_CODE = /^[a-z0-9_]{1,64}$/

/** Canonical extended-JSON date — the shape `bson::DateTime` round-trips
 *  through `serde_json`, and the one the ingest route is locked to accept
 *  (`crates/modules/fleet/src/agent_log.rs`, `browser_connect_timing_record_parses`). */
export interface RcConnectExtJsonDate {
  $date: { $numberLong: string }
}

export interface RcConnectRecordFields {
  v: typeof RC_CONNECT_RECORD_VERSION
  outcome: RcConnectOutcome
  attempt: number
  after_drop: boolean
  hidden: boolean
  /** The first wait that never completed; `null` when the attempt painted. */
  stalled_at: RcConnectMark | null
  /** `marks.first_frame` when reached — the number AC4 needs a distribution of. */
  ttff_ms: number | null
  agent_id: string | null
  agent_org_id?: string
  error_code?: string
  /** Absolute ms from the attempt's start, in wait order; an unreached mark
   *  is ABSENT, never zero. The per-step deltas are in `msg`. */
  marks: Partial<Record<RcConnectMark, number>>
}

export interface RcConnectLogLine {
  ts: RcConnectExtJsonDate
  level: 'INFO' | 'WARN'
  target: typeof RC_CONNECT_LOG_TARGET
  msg: string
  fields: RcConnectRecordFields
}

/** The body `POST /api/log/browser` takes (`BrowserLogBatchPayload`). */
export interface RcConnectUploadBody {
  tenant_id: string
  source: 'browser'
  session_id?: string
  lines: [RcConnectLogLine]
}

function hexOrNull(v: string | null | undefined): string | null {
  return v && OBJECT_ID_HEX.test(v) ? v : null
}

/**
 * Build the record for one finished attempt. Pure; `null` when there is no
 * tenant to file it under (nothing else is worth guessing about).
 *
 * The marks are copied in wait order and only when reached, so the record's
 * missing keys ARE the finding, the same way the console line's `<name>:—`
 * is — a miner asking "which step did the stalls die in" reads `stalled_at`
 * and never has to reconstruct it.
 */
export function buildConnectTimingUpload(
  t: RcConnectTiming,
  ctx: RcConnectUploadContext,
  nowMs: number = Date.now(),
): RcConnectUploadBody | null {
  const tenantId = hexOrNull(ctx.tenantId)
  if (!tenantId) return null
  const marks: Partial<Record<RcConnectMark, number>> = {}
  for (const m of RC_CONNECT_MARKS) {
    const at = t.marks[m]
    if (typeof at === 'number' && Number.isFinite(at)) marks[m] = Math.round(at)
  }
  const fields: RcConnectRecordFields = {
    v: RC_CONNECT_RECORD_VERSION,
    outcome: ctx.outcome,
    attempt: t.attempt,
    after_drop: t.afterDrop,
    hidden: t.hidden === true,
    stalled_at: firstMissingMark(t),
    ttff_ms: marks.first_frame ?? null,
    agent_id: hexOrNull(ctx.agentId),
    marks,
  }
  const agentOrg = hexOrNull(ctx.agentOrgId)
  if (agentOrg && agentOrg !== tenantId) fields.agent_org_id = agentOrg
  if (ctx.errorCode) fields.error_code = ERROR_CODE.test(ctx.errorCode) ? ctx.errorCode : 'other'
  const line: RcConnectLogLine = {
    ts: { $date: { $numberLong: String(Math.round(nowMs)) } },
    // An attempt that painted is information; one that did not is a warning
    // — the same split the console makes, so a level filter on either side
    // selects the same rows.
    level: ctx.outcome === 'first_frame' ? 'INFO' : 'WARN',
    target: RC_CONNECT_LOG_TARGET,
    msg: formatConnectTiming(t),
    fields,
  }
  const sessionId = hexOrNull(ctx.sessionId)
  return {
    tenant_id: tenantId,
    source: 'browser',
    ...(sessionId ? { session_id: sessionId } : {}),
    lines: [line],
  }
}

export interface RcConnectTimingUploader {
  /** Post one attempt's record. Never throws, never rejects, never blocks. */
  send(t: RcConnectTiming, ctx: RcConnectUploadContext): void
  /** Records handed to `fetch` so far — for tests and the console. */
  sentCount(): number
}

export interface RcConnectUploaderDeps {
  /** Injected for tests. Defaults to the global `fetch` at call time. */
  fetch?: (input: string, init: RequestInit) => Promise<unknown>
  now?: () => number
  maxPerMinute?: number
}

/**
 * The fire-and-forget uploader. One instance per viewer composable.
 *
 * `keepalive: true` lets the POST outlive the page: the `closed` record of
 * an attempt the operator abandoned by closing the tab is otherwise the one
 * most likely to be lost, and it is also the one that says how long they
 * waited before giving up. `credentials: 'same-origin'` names what the
 * browser does anyway — the session cookie is the only credential, so a
 * signed-out tab gets a 401 that is swallowed like every other failure.
 */
export function createConnectTimingUploader(
  deps: RcConnectUploaderDeps = {},
): RcConnectTimingUploader {
  const now = deps.now ?? (() => Date.now())
  const maxPerMinute = deps.maxPerMinute ?? RC_CONNECT_UPLOAD_MAX_PER_MIN
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
    send(t, ctx) {
      try {
        const nowMs = now()
        const body = buildConnectTimingUpload(t, ctx, nowMs)
        if (!body) return
        if (!underCap(nowMs)) return
        const init: RequestInit = {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
          keepalive: true,
          credentials: 'same-origin',
        }
        // Call the global unbound-free: `fetch` must be invoked as a plain
        // function of the global, not through a copied reference with a
        // foreign `this`, or some engines throw "Illegal invocation".
        const p = deps.fetch
          ? deps.fetch(RC_CONNECT_UPLOAD_PATH, init)
          : typeof globalThis.fetch === 'function'
            ? globalThis.fetch(RC_CONNECT_UPLOAD_PATH, init)
            : null
        if (!p) return
        sent += 1
        // Swallow BOTH settlements. A rejected promise with no handler is an
        // unhandled-rejection console error on some browsers, which is the
        // closest thing to "affecting the session" a background POST can do.
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
