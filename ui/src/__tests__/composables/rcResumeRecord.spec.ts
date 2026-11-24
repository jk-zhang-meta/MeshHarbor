// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-130 P1c (#3604) — `rc.resume`, the record a held session writes: one per
// hold, on the road `rc.connect` takes (`/api/log/browser`, FR-22 part 4). It
// is AC2's instrument: `gap_ms` is the picture's gap across the cut.
import { describe, expect, it, vi } from 'vitest'
import {
  RC_RESUME_LOG_TARGET,
  RC_RESUME_RECORD_VERSION,
  RC_RESUME_UPLOAD_MAX_PER_MIN,
  buildResumeRecordUpload,
  createResumeRecordUploader,
  type RcResumeRecordInput,
} from '@/composables/rcResumeRecord'
import { RC_CONNECT_UPLOAD_PATH } from '@/composables/rcConnectTimingUpload'

const TENANT = '69f0000000000000000000a1'
const SESSION = '69f0000000000000000000b2'
const AGENT = '69f0000000000000000000c3'
const OTHER_ORG = '69f0000000000000000000d4'

function input(over: Partial<RcResumeRecordInput> = {}): RcResumeRecordInput {
  return {
    tenantId: TENANT,
    agentOrgId: TENANT,
    agentId: AGENT,
    sessionId: SESSION,
    outcome: 'resumed',
    reason: null,
    heldMs: 3_400.4,
    wsDownMs: 3_000.2,
    gapMs: 33.3,
    gapOpen: false,
    hidden: false,
    ...over,
  }
}

describe('rc.resume — the record a held session writes', () => {
  it('is one browser-source line filed under the page\'s org and the held session', () => {
    const body = buildResumeRecordUpload(input(), 1_800_000_000_000)!
    expect(body.tenant_id).toBe(TENANT)
    expect(body.source).toBe('browser')
    expect(body.session_id).toBe(SESSION)
    expect(body.lines).toHaveLength(1)
    const line = body.lines[0]
    expect(line.target).toBe(RC_RESUME_LOG_TARGET)
    expect(RC_RESUME_LOG_TARGET).toBe('rc.resume')
    expect(line.ts).toEqual({ $date: { $numberLong: '1800000000000' } })
    expect(line.level).toBe('INFO')
  })

  it('carries v, outcome, gap_ms, ws_down_ms and how long it held, in whole ms', () => {
    const f = buildResumeRecordUpload(input(), 1)!.lines[0].fields
    expect(f).toEqual({
      v: RC_RESUME_RECORD_VERSION,
      outcome: 'resumed',
      gap_ms: 33,
      gap_open: false,
      ws_down_ms: 3_000,
      held_ms: 3_400,
      hidden: false,
      agent_id: AGENT,
    })
    expect(RC_RESUME_RECORD_VERSION).toBe(1)
  })

  it('an end says why, in the server\'s or the device\'s own token; anything else is "other"', () => {
    const ended = buildResumeRecordUpload(input({ outcome: 'ended', reason: 'admin_terminated' }), 1)!
    expect(ended.lines[0].fields.reason).toBe('admin_terminated')
    expect(ended.lines[0].level).toBe('WARN')
    const odd = buildResumeRecordUpload(input({ outcome: 'ended', reason: 'https://x/?token=1' }), 1)!
    expect(odd.lines[0].fields.reason).toBe('other')
    const expired = buildResumeRecordUpload(input({ outcome: 'expired' }), 1)!
    expect(expired.lines[0].fields.reason).toBeUndefined()
    expect(expired.lines[0].level).toBe('WARN')
  })

  it('a gap with no frame after the cut is a lower bound, and says so; none at all is null', () => {
    const open = buildResumeRecordUpload(input({ gapMs: 65_040, gapOpen: true }), 1)!
    expect(open.lines[0].fields.gap_ms).toBe(65_040)
    expect(open.lines[0].fields.gap_open).toBe(true)
    expect(open.lines[0].msg).toContain('no frame painted after the cut')
    const none = buildResumeRecordUpload(input({ gapMs: null, gapOpen: true }), 1)!
    expect(none.lines[0].fields.gap_ms).toBeNull()
  })

  it('names the device\'s org only when it is not the page\'s', () => {
    const cross = buildResumeRecordUpload(input({ agentOrgId: OTHER_ORG }), 1)!
    expect(cross.lines[0].fields.agent_org_id).toBe(OTHER_ORG)
    const same = buildResumeRecordUpload(input(), 1)!
    expect(same.lines[0].fields.agent_org_id).toBeUndefined()
  })

  it('no tenant to file it under: no record', () => {
    expect(buildResumeRecordUpload(input({ tenantId: null }), 1)).toBeNull()
    expect(buildResumeRecordUpload(input({ tenantId: 'x' }), 1)).toBeNull()
  })

  it('the line reads like the console', () => {
    const line = buildResumeRecordUpload(input(), 1)!.lines[0]
    expect(line.msg).toBe('held 3400 ms, resumed: picture gap 33 ms, socket down 3000 ms')
  })
})

describe('createResumeRecordUploader — best effort, like rc.connect', () => {
  it('posts to /api/log/browser, keepalive, same-origin, and never throws', async () => {
    const fetch = vi.fn(async () => ({}))
    const up = createResumeRecordUploader({ fetch, now: () => 1 })
    up.send(input())
    expect(fetch).toHaveBeenCalledTimes(1)
    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toBe(RC_CONNECT_UPLOAD_PATH)
    expect(init.method).toBe('POST')
    expect(init.keepalive).toBe(true)
    expect(init.credentials).toBe('same-origin')
    expect(JSON.parse(String(init.body)).lines[0].target).toBe('rc.resume')
    const failing = createResumeRecordUploader({
      fetch: () => Promise.reject(new Error('offline')),
      now: () => 1,
    })
    expect(() => failing.send(input())).not.toThrow()
    const throwing = createResumeRecordUploader({
      fetch: () => {
        throw new Error('sync')
      },
      now: () => 1,
    })
    expect(() => throwing.send(input())).not.toThrow()
  })

  it('is capped per minute, below the API governor', () => {
    let now = 0
    const fetch = vi.fn(async () => ({}))
    const up = createResumeRecordUploader({ fetch, now: () => now })
    for (let i = 0; i < RC_RESUME_UPLOAD_MAX_PER_MIN + 5; i += 1) up.send(input())
    expect(fetch).toHaveBeenCalledTimes(RC_RESUME_UPLOAD_MAX_PER_MIN)
    now = 60_001
    up.send(input())
    expect(fetch).toHaveBeenCalledTimes(RC_RESUME_UPLOAD_MAX_PER_MIN + 1)
    expect(up.sentCount()).toBe(RC_RESUME_UPLOAD_MAX_PER_MIN + 1)
  })
})
