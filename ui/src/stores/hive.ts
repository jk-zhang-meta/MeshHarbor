// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api, ApiError } from '@/api/client'

/**
 * FR-90 — agent sessions: the server's RECORD of each, never what is in one.
 * The transcript lives on the device that runs the session and reaches the
 * browser over a viewer peer (`composables/useHiveViewer.ts`).
 */

/** Mirrors the Rust `SessionStatus` (snake_case). */
export type HiveSessionStatus =
  | 'starting'
  | 'idle'
  | 'running'
  | 'awaiting_approval'
  | 'stopping'
  | 'ended'
  | 'refused'
  | 'lost'

/** `SessionView` — `crates/modules/hive/src/model.rs`. */
export interface HiveSession {
  id: string
  owner_id: string
  /** P1c — who besides the owner drives it; absent from an older server. */
  drivers?: string[]
  title: string
  /** The session's secret chat room (P0d-1); absent on an older record. */
  room_id?: string
  harness: string
  harness_session: string
  device_id: string
  device_name: string
  folder: string
  /** The local account the device runs it as — the device's claim. */
  account?: string
  status: HiveSessionStatus
  fence: number
  refusal?: string
  end_reason?: string
  detail?: string
  created_at: string
  updated_at: string
  accepted_at?: string
  ended_at?: string
  /** P1j — `adopted`: a terminal session its owner adopted, read-only (it
   *  runs in the terminal). Absent from an older server: started. */
  origin?: 'started' | 'adopted'
  /** P2c-2b — where its copies are. Absent: placed nowhere (the server
   *  copies nothing, or an older record). */
  replicaset?: HiveReplicaset
  /** P2e-3 — the move in flight. Absent: none. */
  promotion?: HivePromotion
  /** P2f-4b — an adopted session asked to become a managed one: when, and
   *  the word its device refused it with, if it did. Absent: never asked. */
  from_terminal?: { at: string; refused?: string }
}

/** `ReplicasetView` — `crates/modules/hive/src/model.rs`. */
export interface HiveReplicaset {
  policy_revision: number
  min: number
  max: number
  restricted_tags: string[]
  members: HiveReplicaMember[]
  /** Why it holds fewer than `min` copies: `adopted` · `restricted` · `no_device`. */
  short?: string
  placed_at: string
}

/** One copy: `role` is `primary` · `owner` · `archive` · `teleport`; `state`
 *  `pending` · `joined` · `refused` · `leaving` (a newer word is shown as is). */
export interface HiveReplicaMember {
  device_id: string
  role: string
  state: string
  refusal?: string
  answered_at?: string
  /** Where its copy ends, as it last said: the device's claim. */
  tip?: { fence: number; seq: number; hash: string; checkpoint_seq?: number; at: string }
  /** P2j-1 — how much of the session's chain its copy holds, as a `seq`: the
   *  rule a move is decided by, so the freshest holds the most. Absent
   *  without a tip, and from a server before P2j-1. */
  holds?: number
}

/** `PurgeView` (P2g-2) — a purge of a session from every device that held
 *  it: each device `pending` until it answers, then `done`, or `closed`
 *  (`closed`: `device_removed` · `holds_nothing`); its two parts, the
 *  daemon's `store` and the `account`'s, are each `done` · `not_there` ·
 *  `failed` (a newer word is shown as is). */
export interface HivePurge {
  id: string
  session_id: string
  /** `owner`, or `retention` for one the server's sweep issued. */
  reason: string
  at: string
  done_at?: string
  devices: Array<{
    device_id: string
    state: string
    store?: string
    account?: string
    detail?: string
    answered_at?: string
    closed?: string
  }>
}

/** `DELETE …/session/{sid}`: `purging` (sent to every device that held it),
 *  `purged` (every device answered, or none could be asked) or `refused`
 *  (`no_permission` · `in_progress`). `forks` counts the sessions forked
 *  from it, which keep its conversation up to their fork. */
export interface HivePurgeResult {
  outcome: 'purging' | 'purged' | 'refused'
  reason?: string
  message?: string
  purge?: HivePurge
  forks?: number
}

/** `PromotionView` — a move in flight, step by step. */
export interface HivePromotion {
  id: string
  to: string
  to_name: string
  folder: string
  from: string
  from_fence: number
  by: string
  /** `preparing` · `joining` · `draining` · `syncing` · `moving`. */
  state: string
  started_at: string
  deadline: string
  teleport: boolean
  fork: boolean
}

/** `POST …/promote`: `promoting` (the member is ready, the primary drains),
 *  `pending` (the member has not answered yet) or `refused`, in the words of
 *  the gate that said no; `POST …/teleport` says `teleporting` in place of
 *  `promoting`. Always 200 for a well-formed request. */
export interface HivePromoteResult {
  outcome: 'promoting' | 'teleporting' | 'pending' | 'refused'
  reason?: string
  message?: string
  session: HiveSession
}

/** `POST …/hive/session` — always 200 for a well-formed request. A fork's
 *  answer is a start's too, or (P2f-3c) `joining` while a device with no
 *  copy takes one first. */
export interface HiveStartResult {
  outcome: 'accepted' | 'refused' | 'pending' | 'joining'
  reason?: string
  message?: string
  session?: HiveSession
}

export interface HiveStopResult {
  outcome: 'stopping' | 'queued' | 'ended'
  session: HiveSession
}

/** P1c — someone's part in a session: its owner, a driver (prompts it and
 *  answers its approvals), or a reader (reads it and talks in its room). */
export type HiveRole = 'owner' | 'driver' | 'reader'

export interface HiveParticipant {
  user_id: string
  display_name: string
  role: HiveRole
}

/** `GET/PUT/DELETE …/hive/session/{id}/participant[/{user}]`. */
export interface HiveParticipants {
  items: HiveParticipant[]
  /** Only the owner changes who takes part. */
  may_manage: boolean
}

interface ListResponse {
  items: HiveSession[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

/**
 * P1e — core memory: facts people keep for the org's agent sessions. A session
 * gets a frozen snapshot of them when it starts — and only on a device whose
 * owner turned on `hive_core_memory`, because Claude Code reads them as the
 * user's own instructions.
 */
export type BrainScope = 'org' | 'user' | 'device'
export type FactKind = 'preference' | 'convention' | 'path' | 'gotcha' | 'decision' | 'warning'
export const FACT_KINDS: FactKind[] = ['convention', 'preference', 'path', 'gotcha', 'decision', 'warning']
/** The longest fact, in characters (`MAX_FACT_CHARS`, `brain.rs`). */
export const MAX_FACT_CHARS = 500

/** `FactView` — `crates/modules/hive/src/brain.rs`. */
export interface BrainFact {
  id: string
  scope: BrainScope
  owner_id?: string
  text: string
  kind: FactKind
  version: number
  created_by: string
  created_at: string
  updated_by: string
  updated_at: string
}

export interface BrainBudget {
  scope: BrainScope
  owner_id?: string
  used: number
  budget: number
}

/** `GET …/hive/brain`. */
export interface BrainView {
  brain_rev: number
  facts: BrainFact[]
  budgets: BrainBudget[]
}

/** P2c-2a — who holds a session's copies (`ReplicasetRules`,
 *  `crates/modules/hive/src/policy.rs`). */
export interface ReplicasetRules {
  /** The session's own device and `min - 1` more copies. */
  min: number
  max: number
  /** Every archive replica the rules allow joins. */
  archive: boolean
  /** Who joins after the archive replicas, in order (`owner_devices`). */
  prefer: string[]
  /** A session on a device carrying one of these is copied only to devices
   *  carrying it too. */
  restricted_tags: string[]
}

/** P2c-2a — `PolicyView`: an organization's replica policy. */
export interface HivePolicy {
  replicaset: ReplicasetRules
  /** Days an ended session is kept; 0 keeps it for ever. */
  retention_days: number
  /** The devices an administrator designated archive replicas. */
  archive_devices: string[]
  /** A write names the revision it was made from. */
  revision: number
  /** Nothing written yet: these are the defaults. */
  is_default: boolean
  updated_by?: string
  updated_at?: string
}

/** P2h-2 — the capability word a device advertises while it offers itself as
 *  an archive replica (its owner turned `hive_archive` on). Matched by
 *  equality, as every `rpc` word is. */
export const HIVE_ARCHIVE_CAP = 'hive-archive'

/** P2j-4 — the most copies of a session a policy asks for, its own device's
 *  among them, and the longest it keeps an ended session, in days: the
 *  server's `MAX_MEMBERS` and `MAX_RETENTION_DAYS`, which it enforces. */
export const HIVE_MAX_MEMBERS = 8
export const HIVE_MAX_RETENTION_DAYS = 3650

/** P2j-4 — the one word `prefer` names today: the session owner's own
 *  devices, after the archive replicas. */
export const HIVE_PREFER_OWNER_DEVICES = 'owner_devices'

/** A session that can still change. */
/** P1j — a terminal session adopted on its device: nobody drives it here. */
export function isAdopted(s?: Pick<HiveSession, 'origin'> | null): boolean {
  return s?.origin === 'adopted'
}

/** P2j-5 — an adopted session its terminal ended (`exited`): the one the
 *  server makes a managed session (P2f-4b). One stopped from MeshHarbor, whose
 *  terminal went on after it, and one ended any other way, are not. */
export function mayBecomeManaged(s?: Pick<HiveSession, 'origin' | 'status' | 'end_reason'> | null): boolean {
  return !!s && s.origin === 'adopted' && s.status === 'ended' && s.end_reason === 'exited'
}

/** P2j-5 — asked to become a managed session, and its device has not
 *  answered: the server's own `managing()`. A refusal makes the record the
 *  adopted session it was again, its word kept on `from_terminal`. */
export function isBecomingManaged(s?: Pick<HiveSession, 'status' | 'accepted_at' | 'from_terminal'> | null): boolean {
  return !!s && s.status === 'starting' && !s.accepted_at && !!s.from_terminal && !s.from_terminal.refused
}

export function isLive(s: Pick<HiveSession, 'status'>): boolean {
  return !['ended', 'refused', 'lost'].includes(s.status)
}

export const useHiveStore = defineStore('hive', () => {
  const sessions = ref<HiveSession[]>([])
  const total = ref(0)
  const loading = ref(false)
  const error = ref<string | null>(null)
  let fetchSeq = 0

  function base(tenantId: string): string {
    return `/tenant/${tenantId}/hive/session`
  }

  /** The caller's own sessions, newest first. */
  async function fetchSessions(tenantId: string, page = 1, perPage = 50): Promise<void> {
    const seq = ++fetchSeq
    loading.value = true
    error.value = null
    try {
      const res = await api.get<ListResponse>(`${base(tenantId)}?page=${page}&per_page=${perPage}`)
      if (seq !== fetchSeq) return
      sessions.value = res.items
      total.value = res.total
    } catch (e) {
      if (seq !== fetchSeq) return
      error.value = (e as Error).message
    } finally {
      if (seq === fetchSeq) loading.value = false
    }
  }

  function upsert(s: HiveSession): void {
    const i = sessions.value.findIndex((x) => x.id === s.id)
    if (i >= 0) sessions.value[i] = s
    else sessions.value = [s, ...sessions.value]
  }

  async function fetchSession(tenantId: string, sessionId: string): Promise<HiveSession> {
    const s = await api.get<HiveSession>(`${base(tenantId)}/${sessionId}`)
    upsert(s)
    return s
  }

  /** Start a session on a device. The answer is the device's own words. */
  async function start(
    tenantId: string,
    body: { device_id: string; folder: string; title?: string },
  ): Promise<HiveStartResult> {
    const res = await api.post<HiveStartResult>(base(tenantId), body)
    if (res.session) upsert(res.session)
    return res
  }

  /** P2j-1 — the owner moves a running session to a member that holds a
   *  copy (P2e-3). The answer's record replaces the one held. */
  async function promote(
    tenantId: string,
    sessionId: string,
    body: { device_id: string; folder?: string },
  ): Promise<HivePromoteResult> {
    const res = await api.post<HivePromoteResult>(`${base(tenantId)}/${sessionId}/promote`, body)
    if (res.session) upsert(res.session)
    return res
  }

  /** P2j-2 — the owner moves a running session to a device that holds no
   *  copy of it (P2f-1): it takes one while the session still runs. */
  async function teleport(
    tenantId: string,
    sessionId: string,
    body: { device_id: string; folder?: string },
  ): Promise<HivePromoteResult> {
    const res = await api.post<HivePromoteResult>(`${base(tenantId)}/${sessionId}/teleport`, body)
    if (res.session) upsert(res.session)
    return res
  }

  /** P2j-2 — the owner makes a new session from this one's conversation
   *  (P2f-3), in a folder of its own. The answer's record is the FORK's,
   *  with its own room; the session it forks is not changed. */
  function fork(
    tenantId: string,
    sessionId: string,
    body: { device_id: string; folder: string; title?: string },
  ): Promise<HiveStartResult> {
    return api.post<HiveStartResult>(`${base(tenantId)}/${sessionId}/fork`, body)
  }

  /** P2j-5 — the owner makes their ended terminal session a managed one, on
   *  the device that adopted it (P2f-4b): the SAME record, answered as a
   *  start is. Its folder is sent only when it is not its terminal's. A
   *  refused answer carries the record as it is. */
  async function manage(tenantId: string, sessionId: string, folder?: string): Promise<HiveStartResult> {
    const res = await api.post<HiveStartResult>(`${base(tenantId)}/${sessionId}/manage`, folder ? { folder } : {})
    if (res.session) upsert(res.session)
    return res
  }

  /** P2j-3 — the owner purges the session from every device that held it
   *  (P2g-2). Once it is purging, the record is its tombstone, read by
   *  nobody: it leaves the list. */
  async function purge(tenantId: string, sessionId: string): Promise<HivePurgeResult> {
    const res = await api.delete<HivePurgeResult>(`${base(tenantId)}/${sessionId}`)
    if (res.outcome !== 'refused') sessions.value = sessions.value.filter((s) => s.id !== sessionId)
    return res
  }

  /** P2j-3 — how a purge of the owner's session goes, device by device. */
  function fetchPurge(tenantId: string, sessionId: string): Promise<HivePurge> {
    return api.get<HivePurge>(`${base(tenantId)}/${sessionId}/purge`)
  }

  async function stop(tenantId: string, sessionId: string): Promise<HiveStopResult> {
    const res = await api.post<HiveStopResult>(`${base(tenantId)}/${sessionId}/stop`, {})
    upsert(res.session)
    return res
  }

  /** P1c — who takes part in a session; anyone who may read it may ask. */
  function fetchParticipants(tenantId: string, sessionId: string): Promise<HiveParticipants> {
    return api.get<HiveParticipants>(`${base(tenantId)}/${sessionId}/participant`)
  }

  /** P1c — the owner names someone a driver or a reader. A driver needs
   *  "Run agent sessions" (HIVE_RUN): the server says so with a 403. */
  function setParticipant(
    tenantId: string,
    sessionId: string,
    userId: string,
    role: Exclude<HiveRole, 'owner'>,
  ): Promise<HiveParticipants> {
    return api.put<HiveParticipants>(`${base(tenantId)}/${sessionId}/participant/${userId}`, { role })
  }

  /** P1c — the owner takes someone out: out of the room, driving nothing. */
  function removeParticipant(tenantId: string, sessionId: string, userId: string): Promise<HiveParticipants> {
    return api.delete<HiveParticipants>(`${base(tenantId)}/${sessionId}/participant/${userId}`)
  }

  /** P1g — whether agent sessions serve each organization, as the server
   *  answered (`GET …/hive`); absent until it has. */
  const served = ref<Record<string, boolean>>({})
  /** P2h-2 — and whether their sessions are copied there at all (the
   *  server's `hive.replicaset`), from the same answer. A server before it
   *  says nothing of it, which reads as no. */
  const copied = ref<Record<string, boolean>>({})
  /** P2i-3 — and whether its members can search the copies there: copies on,
   *  and an archive replica that searches is online (`search`, P2i-2). A
   *  server before it says nothing of it, which reads as no. */
  const searchable = ref<Record<string, boolean>>({})
  const servedAsks = new Map<string, Promise<boolean>>()
  const searchAsks = new Map<string, Promise<boolean>>()

  /** Keep one `GET …/hive` answer: `null` is a `404`, served nowhere. */
  function keepAnswer(tenantId: string, r: { enabled?: boolean; replicaset?: boolean; search?: boolean } | null): boolean {
    const on = r?.enabled === true
    const copies = on && r?.replicaset === true
    copied.value = { ...copied.value, [tenantId]: copies }
    searchable.value = { ...searchable.value, [tenantId]: copies && r?.search === true }
    served.value = { ...served.value, [tenantId]: on }
    return on
  }

  /**
   * P1g — ask once per organization. `200` is served and `404` is not, both
   * kept; anything else is no answer — not served for now, and asked again
   * next time — because the module is hidden everywhere until the server
   * names it.
   */
  function checkServed(tenantId: string): Promise<boolean> {
    if (tenantId in served.value) return Promise.resolve(served.value[tenantId])
    const asked = servedAsks.get(tenantId)
    if (asked) return asked
    const ask = api
      .get<{ enabled?: boolean; replicaset?: boolean; search?: boolean }>(`/tenant/${tenantId}/hive`)
      .then((r) => keepAnswer(tenantId, r))
      .catch((e: unknown) => {
        if (e instanceof ApiError && e.status === 404) {
          keepAnswer(tenantId, null)
        } else {
          console.warn('[hive] could not ask whether agent sessions serve this organization', e)
        }
        return false
      })
      .finally(() => servedAsks.delete(tenantId))
    servedAsks.set(tenantId, ask)
    return ask
  }

  /**
   * P2i-3 — whether the organization's copies can be searched NOW, asked
   * again at every call: archive replicas come and go, so the sessions page
   * asks each time it opens. No answer keeps what was known; the open
   * decides anyway.
   */
  function checkSearchable(tenantId: string): Promise<boolean> {
    const asked = searchAsks.get(tenantId)
    if (asked) return asked
    const ask = api
      .get<{ enabled?: boolean; replicaset?: boolean; search?: boolean }>(`/tenant/${tenantId}/hive`)
      .then((r) => {
        keepAnswer(tenantId, r)
        return searchable.value[tenantId] === true
      })
      .catch((e: unknown) => {
        if (e instanceof ApiError && e.status === 404) keepAnswer(tenantId, null)
        else console.warn('[hive] could not ask whether this organization can be searched', e)
        return searchable.value[tenantId] === true
      })
      .finally(() => searchAsks.delete(tenantId))
    searchAsks.set(tenantId, ask)
    return ask
  }

  function brainBase(tenantId: string): string {
    return `/tenant/${tenantId}/hive/brain`
  }

  /** P1e — the facts the caller may read: the org's, their own, and with
   *  `deviceId` that device's, each scope with its budget. */
  function fetchBrain(tenantId: string, deviceId?: string): Promise<BrainView> {
    const q = deviceId ? `?device_id=${encodeURIComponent(deviceId)}` : ''
    return api.get<BrainView>(`${brainBase(tenantId)}${q}`)
  }

  /** P1e — keep a fact. A 403 (who may write which scope) and a 409
   *  (`over_budget`, with the numbers) come back in the server's words. */
  function keepFact(
    tenantId: string,
    body: { scope: BrainScope; owner_id?: string; text: string; kind?: FactKind },
  ): Promise<BrainFact> {
    return api.post<BrainFact>(brainBase(tenantId), body)
  }

  /** P1e — change a fact at the version read; a stale one is a 409. */
  function editFact(
    tenantId: string,
    factId: string,
    body: { text: string; kind?: FactKind; version: number },
  ): Promise<BrainFact> {
    return api.put<BrainFact>(`${brainBase(tenantId)}/${factId}`, body)
  }

  /** P1e — archive a fact: out of every future session's memory and out of
   *  its budget, kept as a record. */
  function archiveFact(tenantId: string, factId: string): Promise<{ archived: boolean }> {
    return api.delete<{ archived: boolean }>(`${brainBase(tenantId)}/${factId}`)
  }

  /** P2h-2 — the organization's replica policy, for any of its members: the
   *  defaults until an administrator writes one. `404` while the server
   *  copies no sessions. */
  function fetchPolicy(tenantId: string): Promise<HivePolicy> {
    return api.get<HivePolicy>(`/tenant/${tenantId}/hive/policy`)
  }

  /** P2h-2 — an administrator writes the WHOLE policy, from the revision
   *  read: one changed since is a `409` (read it again), and a device that
   *  cannot be an archive replica a `400`, both in the server's words. */
  function putPolicy(
    tenantId: string,
    body: Pick<HivePolicy, 'replicaset' | 'retention_days' | 'archive_devices' | 'revision'>,
  ): Promise<HivePolicy> {
    return api.put<HivePolicy>(`/tenant/${tenantId}/hive/policy`, body)
  }

  return {
    sessions,
    total,
    loading,
    error,
    fetchSessions,
    fetchSession,
    start,
    stop,
    promote,
    teleport,
    fork,
    manage,
    purge,
    fetchPurge,
    upsert,
    fetchParticipants,
    setParticipant,
    removeParticipant,
    served,
    copied,
    searchable,
    checkServed,
    checkSearchable,
    fetchBrain,
    keepFact,
    editFact,
    archiveFact,
    fetchPolicy,
    putPolicy,
  }
})
