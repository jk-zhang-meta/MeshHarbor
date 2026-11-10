// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-90 P1g — whether agent sessions serve an organization: asked once, the
// server's answer kept; no answer is not an answer.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

const hoisted = vi.hoisted(() => {
  class ApiError extends Error {
    constructor(
      public status: number,
      public data: unknown,
    ) {
      super(`API error ${status}`)
    }
  }
  return { get: vi.fn(), del: vi.fn(), post: vi.fn(), ApiError }
})
vi.mock('@/api/client', () => ({
  api: { get: hoisted.get, delete: hoisted.del, post: hoisted.post },
  ApiError: hoisted.ApiError,
}))

import { isAdopted, isBecomingManaged, mayBecomeManaged, useHiveStore } from '@/stores/hive'

beforeEach(() => {
  setActivePinia(createPinia())
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

afterEach(() => {
  vi.clearAllMocks()
  vi.restoreAllMocks()
})

describe('hive store — the organizations agent sessions serve (FR-90 P1g)', () => {
  it('asks once per organization and keeps a yes', async () => {
    hoisted.get.mockResolvedValue({ enabled: true })
    const hive = useHiveStore()
    const [a, b] = await Promise.all([hive.checkServed('t1'), hive.checkServed('t1')])
    expect([a, b]).toEqual([true, true])
    expect(await hive.checkServed('t1')).toBe(true)
    expect(hoisted.get).toHaveBeenCalledTimes(1)
    expect(hoisted.get).toHaveBeenCalledWith('/tenant/t1/hive')
    expect(hive.served).toEqual({ t1: true })
  })

  it('keeps a 404 as not served', async () => {
    hoisted.get.mockRejectedValue(new hoisted.ApiError(404, { error: 'not_found' }))
    const hive = useHiveStore()
    expect(await hive.checkServed('t2')).toBe(false)
    expect(await hive.checkServed('t2')).toBe(false)
    expect(hoisted.get).toHaveBeenCalledTimes(1)
    expect(hive.served).toEqual({ t2: false })
  })

  it('treats no answer as not served for now, and asks again', async () => {
    hoisted.get.mockRejectedValueOnce(new hoisted.ApiError(500, null)).mockResolvedValueOnce({ enabled: true })
    const hive = useHiveStore()
    expect(await hive.checkServed('t3')).toBe(false)
    expect(hive.served).toEqual({})
    expect(await hive.checkServed('t3')).toBe(true)
    expect(hoisted.get).toHaveBeenCalledTimes(2)
  })

  it('tells an adopted session (P1j) from a started one, an older server included', () => {
    expect(isAdopted({ origin: 'adopted' })).toBe(true)
    expect(isAdopted({ origin: 'started' })).toBe(false)
    expect(isAdopted({})).toBe(false)
    expect(isAdopted(undefined)).toBe(false)
  })

  // FR-90 P2h-2 — the same answer says whether sessions are copied there at
  // all; a server before it says nothing, which is no.
  it('keeps whether sessions are copied there, from the same answer', async () => {
    hoisted.get
      .mockResolvedValueOnce({ enabled: true, replicaset: true })
      .mockResolvedValueOnce({ enabled: true, replicaset: false })
      .mockResolvedValueOnce({ enabled: true })
      .mockRejectedValueOnce(new hoisted.ApiError(404, { error: 'not_found' }))
    const hive = useHiveStore()
    for (const tid of ['c1', 'c2', 'c3', 'c4']) await hive.checkServed(tid)
    expect(hive.copied).toEqual({ c1: true, c2: false, c3: false, c4: false })
    expect(hive.served).toEqual({ c1: true, c2: true, c3: true, c4: false })
  })

  // FR-90 P2i-3 — and whether its copies can be searched: only with copies
  // on; a server before P2i-2 says nothing, which is no.
  it('keeps whether the copies can be searched, from the same answer', async () => {
    hoisted.get
      .mockResolvedValueOnce({ enabled: true, replicaset: true, search: true })
      .mockResolvedValueOnce({ enabled: true, replicaset: true })
      .mockResolvedValueOnce({ enabled: true, replicaset: false, search: true })
      .mockResolvedValueOnce({ enabled: false, replicaset: true, search: true })
      .mockRejectedValueOnce(new hoisted.ApiError(404, { error: 'not_found' }))
    const hive = useHiveStore()
    for (const tid of ['s1', 's2', 's3', 's4', 's5']) await hive.checkServed(tid)
    expect(hive.searchable, 'only with copies on, in an organization served').toEqual({
      s1: true,
      s2: false,
      s3: false,
      s4: false,
      s5: false,
    })
  })

  it('asks again whether the copies can be searched at every call, and keeps what it knew on no answer', async () => {
    hoisted.get
      .mockResolvedValueOnce({ enabled: true, replicaset: true, search: false })
      .mockResolvedValueOnce({ enabled: true, replicaset: true, search: true })
      .mockRejectedValueOnce(new hoisted.ApiError(503, null))
      .mockRejectedValueOnce(new hoisted.ApiError(404, { error: 'not_found' }))
    const hive = useHiveStore()
    // One ask for two callers at once.
    const [a, b] = await Promise.all([hive.checkSearchable('t'), hive.checkSearchable('t')])
    expect([a, b]).toEqual([false, false])
    expect(hoisted.get).toHaveBeenCalledTimes(1)
    // An archive replica came online since.
    expect(await hive.checkSearchable('t'), 'asked again: an archive replica came online').toBe(true)
    expect(hive.searchable).toEqual({ t: true })
    expect(hive.served).toEqual({ t: true })
    // No answer is not an answer.
    expect(await hive.checkSearchable('t'), 'no answer keeps what it knew').toBe(true)
    // A 404 is: served nowhere, searched nowhere.
    expect(await hive.checkSearchable('t')).toBe(false)
    expect(hive.served).toEqual({ t: false })
    expect(hoisted.get).toHaveBeenCalledTimes(4)
    expect(hoisted.get).toHaveBeenLastCalledWith('/tenant/t/hive')
  })

  // FR-90 P2j-3 — a purged session's record is its tombstone, read by nobody:
  // it leaves the list; one whose purge was refused stays.
  it('takes a purged session out of the list, and keeps one whose purge was refused', async () => {
    hoisted.del
      .mockResolvedValueOnce({ outcome: 'refused', reason: 'in_progress', message: 'it is being moved' })
      .mockResolvedValueOnce({ outcome: 'purging', forks: 0 })
    const hive = useHiveStore()
    hive.upsert({
      id: 's1',
      owner_id: 'u1',
      title: 't',
      harness: 'claude-code',
      harness_session: 'h',
      device_id: 'd',
      device_name: 'laptop',
      folder: '/w',
      status: 'ended',
      fence: 1,
      created_at: '',
      updated_at: '',
    })
    await hive.purge('t', 's1')
    expect(hive.sessions.map((s) => s.id), 'a refusal deletes nothing').toEqual(['s1'])
    await hive.purge('t', 's1')
    expect(hoisted.del).toHaveBeenLastCalledWith('/tenant/t/hive/session/s1')
    expect(hive.sessions, 'gone once it purges').toEqual([])
  })

  // FR-90 P2j-5 — an ended terminal session made a managed one: the same
  // record, its answer's kept; a folder only when one is named.
  it("asks for a managed session, and keeps the answer's record", async () => {
    const adopted = {
      id: 's1',
      owner_id: 'u1',
      title: 't',
      harness: 'claude-code',
      harness_session: 'h',
      device_id: 'd',
      device_name: 'laptop',
      folder: '/w',
      status: 'ended' as const,
      origin: 'adopted' as const,
      end_reason: 'exited',
      fence: 1,
      created_at: '',
      updated_at: '',
    }
    hoisted.post
      .mockResolvedValueOnce({ outcome: 'pending', session: { ...adopted, origin: undefined, status: 'starting' } })
      .mockResolvedValueOnce({ outcome: 'refused', reason: 'not_adopted' })
    const hive = useHiveStore()
    hive.upsert(adopted)
    await hive.manage('t', 's1')
    expect(hoisted.post.mock.calls[0], 'no folder named, none sent').toStrictEqual([
      '/tenant/t/hive/session/s1/manage',
      {},
    ])
    expect(hive.sessions[0].status, "the answer's record kept").toBe('starting')
    await hive.manage('t', 's1', '/w2')
    expect(hoisted.post.mock.calls[1]).toEqual(['/tenant/t/hive/session/s1/manage', { folder: '/w2' }])
    expect(hive.sessions[0].status, 'an answer without a record changes nothing').toBe('starting')
  })

  it('tells a session that may become a managed one, and one becoming it', () => {
    const s = { origin: 'adopted' as const, status: 'ended' as const, end_reason: 'exited' }
    expect(mayBecomeManaged(s), 'its terminal ended it').toBe(true)
    expect(mayBecomeManaged({ ...s, end_reason: 'stopped' }), 'stopped from MeshHarbor').toBe(false)
    expect(mayBecomeManaged({ ...s, status: 'running' }), 'still running').toBe(false)
    expect(mayBecomeManaged({ ...s, origin: 'started' }), 'a started session').toBe(false)
    expect(mayBecomeManaged(null)).toBe(false)
    const asked = { status: 'starting' as const, from_terminal: { at: 'now' } }
    expect(isBecomingManaged(asked), 'asked, not answered').toBe(true)
    expect(isBecomingManaged({ ...asked, accepted_at: 'now' }), 'its device took it').toBe(false)
    expect(isBecomingManaged({ ...asked, from_terminal: { at: 'now', refused: 'folder_taken' } }), 'refused').toBe(false)
    expect(isBecomingManaged({ status: 'starting' as const }), 'a start that is no asking').toBe(false)
  })
})
