// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'

vi.mock('@/api/client', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
}))

import { useAgentStore, type Agent } from '@/stores/agents'
import { useTenantStore } from '@/stores/tenant'
import { api } from '@/api/client'

const mockApi = vi.mocked(api)

const TENANT_ID = 'ten_1'

/**
 * FR-82 — the three org-switch fetches are gated on `MANAGE_TENANT` in the
 * store, so a test that wants one to FIRE has to say who is asking. Seeding
 * `myPermissionsTenantId` short-circuits `ensureMyMembership`, so the gate
 * costs no `/member/me` round-trip and cannot consume a mocked response
 * meant for the request under test.
 */
function asOwner() {
  const t = useTenantStore()
  t.isOwner = true
  t.myPermissions = 0
  t.myPermissionsTenantId = TENANT_ID
}

/** A member with a real mask that simply lacks `MANAGE_TENANT`. */
function asMemberWithoutManageTenant() {
  const t = useTenantStore()
  t.isOwner = false
  // MANAGE_AGENTS | REMOTE_CONTROL — the exact mask the field report's user
  // held: enough for the Devices nav to appear, not enough for org settings.
  t.myPermissions = (1 << 24) | (1 << 25)
  t.myPermissionsTenantId = TENANT_ID
}

function mkAgent(over: Partial<Agent> = {}): Agent {
  return {
    id: 'a1',
    tenant_id: TENANT_ID,
    owner_user_id: 'u1',
    name: 'Laptop',
    machine_id: 'mach-1',
    os: 'linux',
    agent_version: '0.1.0',
    status: 'offline',
    is_online: false,
    last_seen_at: '2026-04-17T09:00:00Z',
    access_policy: {
      consent_mode: 'prompt',
      allowed_role_ids: [],
      allowed_user_ids: [],
      auto_terminate_idle_minutes: null,
    },
    ...over,
  }
}

describe('useAgentStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  it('starts empty', () => {
    const s = useAgentStore()
    expect(s.agents).toEqual([])
    expect(s.total).toBe(0)
    expect(s.loading).toBe(false)
    expect(s.error).toBeNull()
  })

  it('fetchAgents populates list', async () => {
    mockApi.get.mockResolvedValueOnce({
      items: [mkAgent({ id: 'a1' }), mkAgent({ id: 'a2', name: 'Desktop' })],
      total: 2,
      page: 1,
      per_page: 25,
      total_pages: 1,
    })
    const s = useAgentStore()
    await s.fetchAgents(TENANT_ID)
    // per_page=100 (the server cap): without it the server defaulted to 25
    // and every consumer saw a silently truncated fleet.
    expect(mockApi.get).toHaveBeenCalledWith(`/tenant/${TENANT_ID}/agent?per_page=100`)
    expect(s.agents).toHaveLength(2)
    expect(s.total).toBe(2)
  })

  it('fetchAgents stores error and clears list on failure', async () => {
    mockApi.get.mockRejectedValueOnce(new Error('network'))
    const s = useAgentStore()
    await s.fetchAgents(TENANT_ID)
    expect(s.error).toBe('network')
    expect(s.agents).toEqual([])
    expect(s.total).toBe(0)
  })

  it('issueEnrollmentToken POSTs to correct path', async () => {
    const tok = {
      enrollment_token: 'jwt.here',
      expires_in: 600,
      jti: 'abc',
    }
    mockApi.post.mockResolvedValueOnce(tok)
    const s = useAgentStore()
    const out = await s.issueEnrollmentToken(TENANT_ID)
    expect(mockApi.post).toHaveBeenCalledWith(`/tenant/${TENANT_ID}/agent/enroll-token`)
    expect(out).toEqual(tok)
  })

  it('rename updates local row on success', async () => {
    mockApi.put.mockResolvedValueOnce({ updated: true })
    const s = useAgentStore()
    s.agents = [mkAgent({ id: 'a1', name: 'Old' })]
    await s.rename(TENANT_ID, 'a1', 'New')
    expect(mockApi.put).toHaveBeenCalledWith(`/tenant/${TENANT_ID}/agent/a1`, { name: 'New' })
    expect(s.agents[0]!.name).toBe('New')
  })

  it('triggerUpdate POSTs the per-agent update path and returns delivered', async () => {
    const store = useAgentStore()
    mockApi.post.mockResolvedValueOnce({ agent_id: 'a1', delivered: true })

    const delivered = await store.triggerUpdate(TENANT_ID, 'a1')

    expect(mockApi.post).toHaveBeenCalledWith(`/tenant/${TENANT_ID}/agent/a1/update`, {})
    expect(delivered).toBe(true)
  })

  it('rotateOverlayKey POSTs the overlay-key rotate path and returns the dispatch', async () => {
    const store = useAgentStore()
    mockApi.post.mockResolvedValueOnce({
      agent_id: 'a1',
      request_id: 'r1',
      dispatch: 'queued',
      delivered: false,
    })

    const res = await store.rotateOverlayKey(TENANT_ID, 'a1')

    expect(mockApi.post).toHaveBeenCalledWith(
      `/tenant/${TENANT_ID}/agent/a1/overlay-key/rotate`,
      {},
    )
    expect(res.request_id).toBe('r1')
    expect(res.dispatch).toBe('queued')
    expect(res.delivered).toBe(false)
  })

  it('triggerUpdateAll POSTs the bulk update path and returns counts', async () => {
    const store = useAgentStore()
    mockApi.post.mockResolvedValueOnce({ requested: 3, delivered: 2, results: [] })

    const res = await store.triggerUpdateAll(TENANT_ID)

    expect(mockApi.post).toHaveBeenCalledWith(`/tenant/${TENANT_ID}/agent/update`, {})
    expect(res.requested).toBe(3)
    expect(res.delivered).toBe(2)
  })

  it('deleteAgent removes from list and decrements total', async () => {
    mockApi.delete.mockResolvedValueOnce({ deleted: true })
    const s = useAgentStore()
    s.agents = [mkAgent({ id: 'a1' }), mkAgent({ id: 'a2' })]
    s.total = 2
    await s.deleteAgent(TENANT_ID, 'a1')
    expect(mockApi.delete).toHaveBeenCalledWith(`/tenant/${TENANT_ID}/agent/a1`)
    expect(s.agents.map((a) => a.id)).toEqual(['a2'])
    expect(s.total).toBe(1)
  })

  it('updateAccessPolicy merges into local row', async () => {
    mockApi.put.mockResolvedValueOnce({ updated: true })
    const s = useAgentStore()
    s.agents = [mkAgent({ id: 'a1' })]
    const policy = {
      consent_mode: 'auto' as const,
      allowed_role_ids: ['r1'],
      allowed_user_ids: [],
      auto_terminate_idle_minutes: 30,
      // FR-99 P3b — the device row's lock ask rides the same PUT.
      lock_on_end: 'always' as const,
    }
    await s.updateAccessPolicy(TENANT_ID, 'a1', policy)
    expect(mockApi.put).toHaveBeenCalledWith(`/tenant/${TENANT_ID}/agent/a1`, {
      access_policy: policy,
    })
    expect(s.agents[0]!.access_policy).toEqual(policy)
  })

  it('updateRoutes PUTs routes and patches local row', async () => {
    mockApi.put.mockResolvedValueOnce({ updated: true })
    const s = useAgentStore()
    s.agents = [mkAgent({ id: 'a1' })]
    const routes = ['10.66.24.0/24', '192.168.1.0/24']
    await s.updateRoutes(TENANT_ID, 'a1', routes)
    expect(mockApi.put).toHaveBeenCalledWith(`/tenant/${TENANT_ID}/agent/a1`, { routes })
    expect(s.agents[0]!.routes).toEqual(routes)
  })

  // ─── Task 9 Phase 3: crash-report fetch ────────────────────────

  it('fetchCrashes GETs the tenant-scoped per-agent endpoint and unwraps items', async () => {
    mockApi.get.mockResolvedValueOnce({
      items: [
        {
          id: 'cr1',
          reportedAt: '2026-05-17T12:00:00Z',
          crashedAtUnix: 1779192000,
          reason: 'panic',
          summary: 'index out of bounds',
          logTail: 'line 1\nline 2',
          agentVersion: '0.3.0-rc.35',
          os: 'windows',
          hostname: 'the field-test host',
          pid: 4567,
        },
      ],
    })
    const s = useAgentStore()
    const out = await s.fetchCrashes(TENANT_ID, 'a1')
    expect(mockApi.get).toHaveBeenCalledWith(`/tenant/${TENANT_ID}/agent/a1/crash`)
    expect(out).toHaveLength(1)
    expect(out[0]!.reason).toBe('panic')
    expect(out[0]!.summary).toBe('index out of bounds')
  })

  it('fetchCrashes propagates errors (callers handle locally, not in store)', async () => {
    mockApi.get.mockRejectedValueOnce(new Error('403 forbidden'))
    const s = useAgentStore()
    await expect(s.fetchCrashes(TENANT_ID, 'a1')).rejects.toThrow('403 forbidden')
    // Store-level state (agents.error/loading) is NOT mutated by
    // fetchCrashes; the modal holds its own local loading + error
    // state.
    expect(s.error).toBeNull()
    expect(s.loading).toBe(false)
  })

  // ── Fleet RPC ──────────────────────────────────────────────────────

  it('an agent with no exec_policy is treated as closed, not permissive', () => {
    // Every device that existed before the feature deserialises without the
    // field. Reading that as anything but "off" would retroactively open the
    // whole fleet the moment the org switch is flipped.
    const a = mkAgent()
    expect(a.exec_policy).toBeUndefined()
    expect(a.exec_policy?.mode ?? 'off').toBe('off')
  })

  it('execOnAgent posts the command and returns the result verbatim', async () => {
    mockApi.post.mockResolvedValueOnce({
      request_id: 'req1',
      agent_id: 'a1',
      agent_name: 'Laptop',
      exit_code: 0,
      stdout: 'uid=0(root)',
      stderr: '',
      truncated: false,
      duration_ms: 12,
      error: null,
    })
    const s = useAgentStore()
    const out = await s.execOnAgent(TENANT_ID, 'a1', { command: 'id', timeout_ms: 5000 })
    expect(mockApi.post).toHaveBeenCalledWith(`/tenant/${TENANT_ID}/agent/a1/exec`, {
      command: 'id',
      timeout_ms: 5000,
    })
    expect(out.exit_code).toBe(0)
    expect(out.stdout).toBe('uid=0(root)')
  })

  it('a policy refusal RESOLVES with an error, it does not reject', async () => {
    // The server answers 200 with `error` set for every gate refusal, so the
    // UI renders one shape and never has to guess whether a rejection was a
    // policy decision or a network failure.
    mockApi.post.mockResolvedValueOnce({
      request_id: 'req2',
      agent_id: 'a1',
      agent_name: 'Laptop',
      exit_code: null,
      stdout: '',
      stderr: '',
      truncated: false,
      duration_ms: 0,
      error: 'remote execution is not enabled on this device',
    })
    const s = useAgentStore()
    const out = await s.execOnAgent(TENANT_ID, 'a1', { command: 'id' })
    expect(out.error).toContain('not enabled on this device')
    // The distinction the whole result shape exists to preserve.
    expect(out.exit_code).toBeNull()
  })

  it('execOnFleet unwraps the results array', async () => {
    mockApi.post.mockResolvedValueOnce({
      results: [
        { request_id: 'r1', agent_id: 'a1', agent_name: 'A', exit_code: 0, stdout: 'x', stderr: '', truncated: false, duration_ms: 3, error: null },
        { request_id: 'r2', agent_id: 'a2', agent_name: 'B', exit_code: null, stdout: '', stderr: '', truncated: false, duration_ms: 0, error: 'device is offline' },
      ],
    })
    const s = useAgentStore()
    const out = await s.execOnFleet(TENANT_ID, ['a1', 'a2'], { command: 'id' })
    expect(mockApi.post).toHaveBeenCalledWith(`/tenant/${TENANT_ID}/agent/exec`, {
      agent_ids: ['a1', 'a2'],
      command: 'id',
    })
    expect(out).toHaveLength(2)
    expect(out[1]!.error).toBe('device is offline')
  })

  it('updateExecPolicy PUTs and patches the local agent', async () => {
    mockApi.put.mockResolvedValueOnce({})
    const s = useAgentStore()
    s.agents = [mkAgent({ id: 'a1' })]
    const policy = {
      mode: 'on' as const,
      can_originate: false,
      allowed_user_ids: [],
      allowed_role_ids: [],
      consent_mode: 'auto' as const,
      shells: [],
    }
    await s.updateExecPolicy(TENANT_ID, 'a1', policy)
    expect(mockApi.put).toHaveBeenCalledWith(`/tenant/${TENANT_ID}/agent/a1/exec-policy`, policy)
    expect(s.agents[0]!.exec_policy?.mode).toBe('on')
  })

  it('a 403 on the org switch leaves it UNKNOWN, not "off"', async () => {
    // "You are not an admin" and "the org has it switched off" are different
    // facts. Collapsing the former into the latter would have the console
    // tell a non-admin something false about their org.
    mockApi.get.mockRejectedValueOnce(new Error('403 forbidden'))
    asOwner()
    const s = useAgentStore()
    await s.fetchOrgExecEnabled(TENANT_ID)
    expect(s.orgExecEnabled).toBeNull()
  })

  it('fetchOrgExecEnabled stores the flag', async () => {
    mockApi.get.mockResolvedValueOnce({ remote_exec_enabled: true })
    asOwner()
    const s = useAgentStore()
    await s.fetchOrgExecEnabled(TENANT_ID)
    expect(s.orgExecEnabled).toBe(true)
    // A server from before FR-94 never names it: unknown, never "off".
    expect(s.orgExecRequireSystem).toBeNull()
  })

  it('FR-94: require-SYSTEM carries the kill-switch it holds, and only then', async () => {
    // The server reads `remote_exec_enabled` as required on every PUT, so this
    // must send the value it already holds — and refuse to guess one.
    const s = useAgentStore()
    await expect(s.setOrgExecRequireSystem(TENANT_ID, true)).rejects.toThrow()
    expect(mockApi.put).not.toHaveBeenCalled()

    mockApi.get.mockResolvedValueOnce({ remote_exec_enabled: true, exec_require_system: false })
    asOwner()
    await s.fetchOrgExecEnabled(TENANT_ID)
    expect(s.orgExecRequireSystem).toBe(false)
    mockApi.put.mockResolvedValueOnce({ remote_exec_enabled: true, exec_require_system: true })
    await s.setOrgExecRequireSystem(TENANT_ID, true)
    expect(mockApi.put).toHaveBeenCalledWith(`/tenant/${TENANT_ID}/exec-settings`, {
      remote_exec_enabled: true,
      exec_require_system: true,
    })
    expect(s.orgExecRequireSystem).toBe(true)
  })

  it('FR-94: flipping the kill-switch never names require-SYSTEM', async () => {
    // Absent means "leave it alone" server-side; sending a value here would
    // reset an org's choice every time someone toggled exec.
    mockApi.put.mockResolvedValueOnce({ remote_exec_enabled: false, exec_require_system: true })
    const s = useAgentStore()
    await s.setOrgExecEnabled(TENANT_ID, false)
    expect(mockApi.put).toHaveBeenCalledWith(`/tenant/${TENANT_ID}/exec-settings`, {
      remote_exec_enabled: false,
    })
    expect(s.orgExecRequireSystem).toBe(true)
  })

  it('FR-94: unanchorDevice deletes the anchor and clears it on the row', async () => {
    mockApi.delete.mockResolvedValueOnce({ ok: true, was_anchored: true })
    const s = useAgentStore()
    s.agents = [mkAgent({ id: 'a1', exec_anchor: { anchored_at: 'x', anchored_by: 'u' } })]
    await s.unanchorDevice(TENANT_ID, 'a1')
    expect(mockApi.delete).toHaveBeenCalledWith(`/tenant/${TENANT_ID}/agent/a1/exec-anchor`)
    expect(s.agents[0]!.exec_anchor).toBeNull()
  })

  it('fetchExecAudit passes the narrowing filters through', async () => {
    mockApi.get.mockResolvedValueOnce({ items: [], total: 0 })
    const s = useAgentStore()
    await s.fetchExecAudit(TENANT_ID, { agentId: 'a1', perPage: 25 })
    const url = mockApi.get.mock.calls.at(-1)![0] as string
    expect(url).toContain(`/tenant/${TENANT_ID}/exec-audit?`)
    expect(url).toContain('agent_id=a1')
    expect(url).toContain('per_page=25')
  })

  // ── MeshHarbor SSH ────────────────────────────────────────────────────

  it('an agent with no ssh_policy is treated as closed, not permissive', () => {
    // Same rule as exec: a device that predates the feature, or whose API
    // body omits the field, must read as OFF. Defaulting the other way would
    // silently open every legacy device the moment the UI shipped.
    const a = mkAgent()
    expect(a.ssh_policy).toBeUndefined()
    expect(a.ssh_policy?.mode ?? 'off').toBe('off')
  })

  it('updateSshPolicy hits the ssh route and updates the row in place', async () => {
    mockApi.put.mockResolvedValueOnce({})
    const s = useAgentStore()
    s.agents = [mkAgent({ id: 'a1' })]
    const policy = {
      mode: 'on' as const,
      can_originate: false,
      allowed_user_ids: [],
      allowed_role_ids: [],
      account_mode: 'console_user' as const,
      account: null,
      consent_mode: null,
    }
    await s.updateSshPolicy(TENANT_ID, 'a1', policy)
    expect(mockApi.put).toHaveBeenCalledWith(`/tenant/${TENANT_ID}/agent/a1/ssh-policy`, policy)
    expect(s.agents[0]!.ssh_policy?.mode).toBe('on')
    // The exec policy is a different gate and must not be touched by this.
    expect(s.agents[0]!.exec_policy).toBeUndefined()
  })

  it('a rejected ssh-policy save PROPAGATES instead of reporting success', async () => {
    // The server refuses a prompt policy for an agent that would ignore it
    // (pre-P5d). Swallowing that would leave an admin believing a prompt is
    // enforced when nothing would ever ask — the exact lie P5d closed.
    mockApi.put.mockRejectedValueOnce(new Error('agent would ignore consent_mode'))
    const s = useAgentStore()
    s.agents = [mkAgent({ id: 'a1' })]
    await expect(
      s.updateSshPolicy(TENANT_ID, 'a1', {
        mode: 'on',
        can_originate: false,
        allowed_user_ids: [],
        allowed_role_ids: [],
        account_mode: 'console_user',
        account: null,
        consent_mode: 'prompt',
      }),
    ).rejects.toThrow()
    expect(s.agents[0]!.ssh_policy).toBeUndefined()
  })

  it('the ssh org switch is separate from the exec one', async () => {
    // Two independent decisions server-side; the store must not let one
    // fetch populate the other's flag.
    mockApi.get.mockResolvedValueOnce({ remote_ssh_enabled: true })
    asOwner()
    const s = useAgentStore()
    await s.fetchOrgSshEnabled(TENANT_ID)
    expect(s.orgSshEnabled).toBe(true)
    expect(s.orgExecEnabled).toBeNull()
    expect(mockApi.get.mock.calls.at(-1)![0]).toBe(`/tenant/${TENANT_ID}/ssh-settings`)
  })

  it('FR-92: the keep-busy org switch is a DENY, read and set on its own route', async () => {
    mockApi.get.mockResolvedValueOnce({ keep_busy_denied: false })
    asOwner()
    const s = useAgentStore()
    await s.fetchOrgKeepBusyDenied(TENANT_ID)
    expect(s.orgKeepBusyDenied).toBe(false)
    expect(s.orgSshEnabled).toBeNull()
    expect(mockApi.get.mock.calls.at(-1)![0]).toBe(`/tenant/${TENANT_ID}/keep-busy-settings`)
    mockApi.put.mockResolvedValueOnce({ keep_busy_denied: true })
    await s.setOrgKeepBusyDenied(TENANT_ID, true)
    expect(mockApi.put.mock.calls.at(-1)).toEqual([
      `/tenant/${TENANT_ID}/keep-busy-settings`,
      { keep_busy_denied: true },
    ])
    expect(s.orgKeepBusyDenied).toBe(true)
  })

  it('FR-92 P8: the admin read carries the default pattern, and a pattern-only PUT touches nothing else', async () => {
    mockApi.get.mockResolvedValueOnce({ keep_busy_denied: false, keep_busy_default_pattern: 'heart' })
    asOwner()
    const s = useAgentStore()
    await s.fetchOrgKeepBusyDenied(TENANT_ID)
    expect(s.orgKeepBusyDenied).toBe(false)
    expect(s.orgKeepBusyDefaultPattern).toBe('heart')

    mockApi.put.mockResolvedValueOnce({ keep_busy_denied: false, keep_busy_default_pattern: 'wave' })
    await s.setOrgKeepBusyDefaultPattern(TENANT_ID, 'wave')
    expect(mockApi.put.mock.calls.at(-1)).toEqual([
      `/tenant/${TENANT_ID}/keep-busy-settings`,
      { keep_busy_default_pattern: 'wave' },
    ])
    expect(s.orgKeepBusyDefaultPattern).toBe('wave')
    expect(s.orgKeepBusyDenied).toBe(false)

    // `null` clears it to the product default, and that is what is sent.
    mockApi.put.mockResolvedValueOnce({ keep_busy_denied: false, keep_busy_default_pattern: null })
    await s.setOrgKeepBusyDefaultPattern(TENANT_ID, null)
    expect(mockApi.put.mock.calls.at(-1)![1]).toEqual({ keep_busy_default_pattern: null })
    expect(s.orgKeepBusyDefaultPattern).toBeNull()
  })

  it('FR-101 P2: the org session policy is read and set on its own route, one feature at a time', async () => {
    mockApi.get.mockResolvedValueOnce({ clipboard: 'on', files: 'off', audio: 'on' })
    asOwner()
    const s = useAgentStore()
    await s.fetchOrgRcSessionPolicy(TENANT_ID)
    expect(mockApi.get.mock.calls.at(-1)![0]).toBe(`/tenant/${TENANT_ID}/rc-session-policy`)
    expect(s.orgRcSessionPolicy).toEqual({ clipboard: 'on', files: 'off', audio: 'on' })

    // A change names only its feature: the route leaves the others alone.
    mockApi.put.mockResolvedValueOnce({ clipboard: 'ask', files: 'off', audio: 'on' })
    await s.setOrgRcSessionPolicy(TENANT_ID, { clipboard: 'ask' })
    expect(mockApi.put.mock.calls.at(-1)).toEqual([
      `/tenant/${TENANT_ID}/rc-session-policy`,
      { clipboard: 'ask' },
    ])
    expect(s.orgRcSessionPolicy).toEqual({ clipboard: 'ask', files: 'off', audio: 'on' })
  })

  it('FR-101 P2: a member who cannot manage org settings reads no policy and sends nothing', async () => {
    asMemberWithoutManageTenant()
    const s = useAgentStore()
    const before = mockApi.get.mock.calls.length
    await s.fetchOrgRcSessionPolicy(TENANT_ID)
    expect(s.orgRcSessionPolicy).toBeNull()
    expect(mockApi.get.mock.calls.length).toBe(before)
    // A refused read leaves it unknown too.
    asOwner()
    mockApi.get.mockRejectedValueOnce(new Error('403 forbidden'))
    await s.fetchOrgRcSessionPolicy(TENANT_ID)
    expect(s.orgRcSessionPolicy).toBeNull()
  })

  it("FR-92 P8: a viewer's read of the default is ungated and never throws — circle for anything but a known word", async () => {
    // A plain member: the route is readable by any member, so no gate.
    asMemberWithoutManageTenant()
    const s = useAgentStore()
    mockApi.get.mockResolvedValueOnce({ keep_busy_denied: false, keep_busy_default_pattern: 'subtle' })
    expect(await s.fetchKeepBusyDefaultPattern(TENANT_ID)).toBe('subtle')
    expect(mockApi.get.mock.calls.at(-1)![0]).toBe(`/tenant/${TENANT_ID}/keep-busy-settings`)
    // Unset = the product default.
    mockApi.get.mockResolvedValueOnce({ keep_busy_denied: false, keep_busy_default_pattern: null })
    expect(await s.fetchKeepBusyDefaultPattern(TENANT_ID)).toBe('circle')
    // A word this viewer cannot draw (a newer server) = circle, never a crash.
    mockApi.get.mockResolvedValueOnce({ keep_busy_denied: false, keep_busy_default_pattern: 'hexagon' })
    expect(await s.fetchKeepBusyDefaultPattern(TENANT_ID)).toBe('circle')
    // A refusal or a network failure = circle; nothing thrown, nothing logged out.
    mockApi.get.mockRejectedValueOnce(new Error('403 forbidden'))
    expect(await s.fetchKeepBusyDefaultPattern(TENANT_ID)).toBe('circle')
  })

  it('FR-92 P7: the history is asked for newest first — by device, and by the cursor', async () => {
    const s = useAgentStore()
    mockApi.get.mockResolvedValueOnce([])
    await s.fetchKeepBusyHistory(TENANT_ID)
    expect(mockApi.get.mock.calls.at(-1)![0]).toBe(`/tenant/${TENANT_ID}/keep-busy-history?limit=50`)
    mockApi.get.mockResolvedValueOnce([])
    await s.fetchKeepBusyHistory(TENANT_ID, { agentId: 'a1', before: '2026-10-11T12:00:00Z', limit: 20 })
    expect(mockApi.get.mock.calls.at(-1)![0]).toBe(
      `/tenant/${TENANT_ID}/keep-busy-history?agent_id=a1&before=2026-10-11T12%3A00%3A00Z&limit=20`,
    )
  })

  it('a 403 on the ssh org switch leaves it UNKNOWN, not "off"', async () => {
    mockApi.get.mockRejectedValueOnce(new Error('403 forbidden'))
    asOwner()
    const s = useAgentStore()
    await s.fetchOrgSshEnabled(TENANT_ID)
    expect(s.orgSshEnabled).toBeNull()
  })

  // ── FR-82 — the org switches are never asked for without the bit ───
  //
  // The field bug, 2026-09-08: the Devices page mounts EnrollKeysSection
  // unconditionally, that card fetched `ephemeral-key-settings` on mount,
  // and the route needs MANAGE_TENANT — which `DEFAULT_ADMIN` deliberately
  // withholds. Every non-owner who opened the page collected a 403, and the
  // api client turned that into a logout. The client no longer does; this
  // makes sure the request is not sent in the first place.

  it.each([
    ['exec', 'fetchOrgExecEnabled', 'orgExecEnabled'],
    ['ssh', 'fetchOrgSshEnabled', 'orgSshEnabled'],
    ['keep-busy', 'fetchOrgKeepBusyDenied', 'orgKeepBusyDenied'],
    ['ephemeral-keys', 'fetchOrgEphemeralKeysEnabled', 'orgEphemeralKeysEnabled'],
  ] as const)(
    'the %s org switch is NOT fetched without MANAGE_TENANT',
    async (_label, method, flag) => {
      asMemberWithoutManageTenant()
      const s = useAgentStore()
      await s[method](TENANT_ID)
      expect(mockApi.get).not.toHaveBeenCalled()
      // ⚠️ And it stays UNKNOWN, never `false`: "you may not read this
      // switch" is not "your org has it off", and the console renders the
      // two differently.
      expect(s[flag]).toBeNull()
    },
  )

  it('an unknown mask blocks the org switches rather than guessing', async () => {
    // Fail-closed on `null`, unlike the fleet NAV predicate. The membership
    // fetch is awaited, so `null` here means it FAILED — and firing a
    // request whose authorization is unknown is how the original bug ran.
    const t = useTenantStore()
    t.isOwner = false
    t.myPermissions = null
    t.myPermissionsTenantId = TENANT_ID
    const s = useAgentStore()
    await s.fetchOrgEphemeralKeysEnabled(TENANT_ID)
    expect(mockApi.get).not.toHaveBeenCalled()
    expect(s.orgEphemeralKeysEnabled).toBeNull()
  })

  // ── FR-51 — ephemeral enrollment keys ──────────────────────────────

  // FR-52 — cross-org remote access. A THIRD org switch: exec and SSH decide
  // what a MEMBER may do, this decides whether a non-member may do anything.

  it('the external-access switch is a third independent flag on its own route', async () => {
    mockApi.get.mockResolvedValueOnce({ enabled: true, devices: [] })
    const s = useAgentStore()
    await s.fetchExternalAccess(TENANT_ID)
    expect(s.orgExternalAccessEnabled).toBe(true)
    // A fetch of one switch must never populate another's flag.
    expect(s.orgExecEnabled).toBeNull()
    expect(s.orgSshEnabled).toBeNull()
    expect(mockApi.get.mock.calls.at(-1)![0]).toBe(`/tenant/${TENANT_ID}/external-access`)
  })

  it('a 403 on external access leaves it UNKNOWN, not off', async () => {
    // "Not an admin" is not "disabled". Claiming the org is off would send
    // someone hunting through per-device settings for a switch that is fine.
    mockApi.get.mockRejectedValueOnce(new Error('403 forbidden'))
    const s = useAgentStore()
    await s.fetchExternalAccess(TENANT_ID)
    expect(s.orgExternalAccessEnabled).toBeNull()
    expect(s.externalDevices).toEqual([])
  })

  it('rotating a connect code REPLACES the stored one', async () => {
    // Rotation is the revocation story for a leaked code, so a store that kept
    // the old value would show an admin an address that no longer works.
    mockApi.get.mockResolvedValueOnce({
      enabled: true,
      devices: [
        {
          id: 'a1',
          name: 'Laptop',
          status: 'online',
          connect_code: 'AAAA-BBBB-CCCC',
          connect_code_rotated_at: '2026-09-01T09:00:00Z',
          max_permissions: 'VIEW | INPUT',
          expires_at: null,
          supported: true,
        },
      ],
    })
    const s = useAgentStore()
    await s.fetchExternalAccess(TENANT_ID)
    expect(s.externalDevices[0]!.connect_code).toBe('AAAA-BBBB-CCCC')

    mockApi.post.mockResolvedValueOnce({
      connect_code: 'K7Q2-9XM4-TB3F',
      rotated_at: '2026-09-01T10:00:00Z',
    })
    const next = await s.rotateConnectCode(TENANT_ID, 'a1')
    expect(next).toBe('K7Q2-9XM4-TB3F')
    expect(s.externalDevices[0]!.connect_code).toBe('K7Q2-9XM4-TB3F')
    expect(mockApi.post.mock.calls.at(-1)![0]).toBe(
      `/tenant/${TENANT_ID}/agent/a1/connect-code`,
    )
  })

  it('saving an external-access policy writes it back onto the agent row', async () => {
    // The dialog PUTs the WHOLE shape, so the store must keep the saved policy
    // — a stale row would reopen the dialog on the old ceiling and the next
    // save would silently widen what an outsider may do.
    mockApi.get.mockResolvedValueOnce({ items: [mkAgent({ id: 'a1' })], total: 1 })
    const s = useAgentStore()
    await s.fetchAgents(TENANT_ID)
    expect(s.agents[0]!.external_access_policy).toBeUndefined()

    mockApi.put.mockResolvedValueOnce({})
    await s.updateExternalAccessPolicy(TENANT_ID, 'a1', {
      approved: true,
      max_permissions: 'VIEW',
      expires_at: null,
    })
    expect(s.agents[0]!.external_access_policy).toEqual({
      approved: true,
      max_permissions: 'VIEW',
      expires_at: null,
    })
    expect(mockApi.put.mock.calls.at(-1)![0]).toBe(
      `/tenant/${TENANT_ID}/agent/a1/external-access-policy`,
    )
  })

  it('the ephemeral-keys org switch is its own flag and its own route', async () => {
    mockApi.get.mockResolvedValueOnce({ ephemeral_keys_enabled: true })
    asOwner()
    const s = useAgentStore()
    await s.fetchOrgEphemeralKeysEnabled(TENANT_ID)
    expect(s.orgEphemeralKeysEnabled).toBe(true)
    // The other two switches must stay untouched — three separate grants.
    expect(s.orgExecEnabled).toBeNull()
    expect(s.orgSshEnabled).toBeNull()
    expect(mockApi.get.mock.calls.at(-1)![0]).toBe(`/tenant/${TENANT_ID}/ephemeral-key-settings`)
  })

  it('a 403 on the ephemeral-keys switch leaves it UNKNOWN, not "off"', async () => {
    mockApi.get.mockRejectedValueOnce(new Error('403 forbidden'))
    asOwner()
    const s = useAgentStore()
    await s.fetchOrgEphemeralKeysEnabled(TENANT_ID)
    expect(s.orgEphemeralKeysEnabled).toBeNull()
  })

  it('FR-101 P4b: the maximum session length is read and set on its own route; null is no limit', async () => {
    mockApi.get.mockResolvedValueOnce({ max_secs: null })
    asOwner()
    const s = useAgentStore()
    expect(s.orgRcMaxSessionSecs).toBeUndefined()
    await s.fetchOrgRcSessionLimits(TENANT_ID)
    expect(mockApi.get.mock.calls.at(-1)![0]).toBe(`/tenant/${TENANT_ID}/rc-session-limits`)
    expect(s.orgRcMaxSessionSecs).toBeNull()

    mockApi.put.mockResolvedValueOnce({ max_secs: 7200 })
    await s.setOrgRcMaxSessionSecs(TENANT_ID, 7200)
    expect(mockApi.put.mock.calls.at(-1)).toEqual([
      `/tenant/${TENANT_ID}/rc-session-limits`,
      { max_secs: 7200 },
    ])
    expect(s.orgRcMaxSessionSecs).toBe(7200)

    // Clearing sends null, never an absent field.
    mockApi.put.mockResolvedValueOnce({ max_secs: null })
    await s.setOrgRcMaxSessionSecs(TENANT_ID, null)
    expect(mockApi.put.mock.calls.at(-1)![1]).toEqual({ max_secs: null })
    expect(s.orgRcMaxSessionSecs).toBeNull()
  })

  it('FR-101 P4b-2: the idle limit rides the same route, naming only itself', async () => {
    // A server from before P4b-2 sends no idle field: no idle limit.
    mockApi.get.mockResolvedValueOnce({ max_secs: 3600 })
    asOwner()
    const s = useAgentStore()
    expect(s.orgRcIdleSecs).toBeUndefined()
    await s.fetchOrgRcSessionLimits(TENANT_ID)
    expect(s.orgRcIdleSecs).toBeNull()
    expect(s.orgRcMaxSessionSecs).toBe(3600)

    mockApi.put.mockResolvedValueOnce({ max_secs: 3600, idle_secs: 900 })
    await s.setOrgRcIdleSecs(TENANT_ID, 900)
    // The body names the idle limit alone, so the maximum length stays.
    expect(mockApi.put.mock.calls.at(-1)).toEqual([
      `/tenant/${TENANT_ID}/rc-session-limits`,
      { idle_secs: 900 },
    ])
    expect(s.orgRcIdleSecs).toBe(900)
    expect(s.orgRcMaxSessionSecs).toBe(3600)

    mockApi.put.mockResolvedValueOnce({ max_secs: 3600, idle_secs: null })
    await s.setOrgRcIdleSecs(TENANT_ID, null)
    expect(mockApi.put.mock.calls.at(-1)![1]).toEqual({ idle_secs: null })
    expect(s.orgRcIdleSecs).toBeNull()
  })

  it('FR-101 P4b: a member who cannot manage org settings reads no limit and sends nothing', async () => {
    asMemberWithoutManageTenant()
    const s = useAgentStore()
    const before = mockApi.get.mock.calls.length
    await s.fetchOrgRcSessionLimits(TENANT_ID)
    expect(s.orgRcMaxSessionSecs).toBeUndefined()
    expect(mockApi.get.mock.calls.length).toBe(before)
  })

  it('mintEnrollKey POSTs the enroll-key path and hands back the one-time key', async () => {
    mockApi.post.mockResolvedValueOnce({
      key: 'jwt.shown.once',
      id: 'k1',
      jti: 'j1',
      label: 'ci',
      max_uses: 100,
      expires_at: '2026-10-01T00:00:00Z',
    })
    const s = useAgentStore()
    const resp = await s.mintEnrollKey(TENANT_ID, { label: 'ci' })
    expect(mockApi.post.mock.calls.at(-1)![0]).toBe(`/tenant/${TENANT_ID}/agent/enroll-key`)
    expect(resp.key).toBe('jwt.shown.once')
  })

  it('listEnrollKeys GETs the list (which never carries the secret)', async () => {
    mockApi.get.mockResolvedValueOnce({
      items: [{ id: 'k1', jti: 'j1', label: 'ci', created_by: 'u1', max_uses: 100, uses: 3, expires_at: '2026-10-01T00:00:00Z', created_at: '2026-09-01T00:00:00Z' }],
    })
    const s = useAgentStore()
    const rows = await s.listEnrollKeys(TENANT_ID)
    expect(mockApi.get.mock.calls.at(-1)![0]).toBe(`/tenant/${TENANT_ID}/agent/enroll-key`)
    expect(rows).toHaveLength(1)
    expect(Object.keys(rows[0]!)).not.toContain('key')
  })

  it('revokeEnrollKey DELETEs by key id', async () => {
    mockApi.delete.mockResolvedValueOnce({})
    const s = useAgentStore()
    await s.revokeEnrollKey(TENANT_ID, 'k1')
    expect(mockApi.delete.mock.calls.at(-1)![0]).toBe(`/tenant/${TENANT_ID}/agent/enroll-key/k1`)
  })

  it('fetchSshAudit passes the narrowing filters through', async () => {
    mockApi.get.mockResolvedValueOnce({ items: [], total: 0 })
    const s = useAgentStore()
    await s.fetchSshAudit(TENANT_ID, { userId: 'u9', perPage: 25 })
    const url = mockApi.get.mock.calls.at(-1)![0] as string
    expect(url).toContain(`/tenant/${TENANT_ID}/ssh-audit?`)
    expect(url).toContain('user_id=u9')
    expect(url).toContain('per_page=25')
  })

  it('fetchSshActivity hits its OWN route, not the audit one', async () => {
    // The two logs mean different things — the server's decision vs the
    // device's claim about itself — and are deliberately separate
    // collections. Pointing this at `ssh-audit` would silently present
    // unverified device reports as authoritative.
    mockApi.get.mockResolvedValueOnce({ items: [], total: 0 })
    const s = useAgentStore()
    await s.fetchSshActivity(TENANT_ID)
    const url = mockApi.get.mock.calls.at(-1)![0] as string
    expect(url).toContain(`/tenant/${TENANT_ID}/ssh-activity?`)
    expect(url).not.toContain('ssh-audit')
  })

  it('fetchSshActivity can narrow to one session via grant_id', async () => {
    // The join from an audit decision row to what followed it.
    mockApi.get.mockResolvedValueOnce({ items: [], total: 0 })
    const s = useAgentStore()
    await s.fetchSshActivity(TENANT_ID, { grantId: 'g-7', agentId: 'a1' })
    const url = mockApi.get.mock.calls.at(-1)![0] as string
    expect(url).toContain('grant_id=g-7')
    expect(url).toContain('agent_id=a1')
  })

  it('an activity row with allowed:false survives the round trip', async () => {
    // A refused forward is the row an operator most wants to find. If
    // `allowed` were dropped or defaulted, a denial would render as an
    // ordinary action.
    mockApi.get.mockResolvedValueOnce({
      items: [
        {
          id: 'r1',
          agent_id: 'a1',
          caller: 'ssh:Someone@100.65.4.2:1',
          kind: 'forward',
          detail: '10.0.0.5:5432',
          allowed: false,
          at: '2026-08-23T00:00:00Z',
        },
      ],
      total: 1,
    })
    const s = useAgentStore()
    const res = await s.fetchSshActivity(TENANT_ID)
    expect(res.items[0]!.allowed).toBe(false)
    expect(res.items[0]!.kind).toBe('forward')
    expect(res.items[0]!.detail).toBe('10.0.0.5:5432')
  })

  // ── Remote config (docs/remote-config.md) ──────────────────────────

  it('updateDesiredConfig sends only the keys under management', async () => {
    // `undefined` means "leave the device alone" and must NOT be sent as a
    // value. A body that asserted every key would silently turn SSH off on a
    // device whose admin only meant to touch exec.
    mockApi.put.mockResolvedValueOnce({
      revision: 1,
      desired: { revision: 1, exec_enabled: true },
    })
    const s = useAgentStore()
    s.agents = [mkAgent()]
    await s.updateDesiredConfig(TENANT_ID, 'a1', { exec_enabled: true })

    const [url, body] = mockApi.put.mock.calls.at(-1)!
    expect(url).toBe(`/tenant/${TENANT_ID}/agent/a1/desired-config`)
    expect(body).toEqual({ exec_enabled: true })
    expect('ssh_enabled' in (body as object)).toBe(false)
  })

  it('FR-119 — updateDesiredConfig carries the frame-rate denylist as given', async () => {
    mockApi.put.mockResolvedValueOnce({
      revision: 2,
      desired: { revision: 2, fps_deny: 'hevc_qsv:120' },
    })
    const s = useAgentStore()
    s.agents = [mkAgent()]
    await s.updateDesiredConfig(TENANT_ID, 'a1', { fps_deny: 'hevc_qsv:120' })

    const [, body] = mockApi.put.mock.calls.at(-1)!
    expect(body).toEqual({ fps_deny: 'hevc_qsv:120' })
  })

  it('a saved request is optimistically PENDING, never applied', async () => {
    // The device has not spoken yet. Writing anything but `pending` would put
    // an answer on screen that no device has given — the exact lie the
    // report-back mechanism exists to prevent.
    mockApi.put.mockResolvedValueOnce({
      revision: 4,
      desired: { revision: 4, exec_enabled: true },
    })
    const s = useAgentStore()
    s.agents = [mkAgent()]
    await s.updateDesiredConfig(TENANT_ID, 'a1', { exec_enabled: true })

    expect(s.agents[0]!.remote_config!.state).toBe('pending')
    expect(s.agents[0]!.remote_config!.report).toBeUndefined()
    expect(s.agents[0]!.remote_config!.desired.exec_enabled).toBe(true)
  })

  it('a device with no remote_config is simply unmanaged', () => {
    // Absent means nobody has requested anything — NOT "everything is off".
    expect(mkAgent().remote_config).toBeUndefined()
  })

  it('a refusal keeps its reason, because the reason IS the next action', async () => {
    // `not_opted_in` (go set a key on the host) and `not_primary` (ask the
    // other org) need completely different responses. Collapsing them into
    // "refused" would leave an operator with nothing to do.
    mockApi.get.mockResolvedValueOnce({
      items: [
        mkAgent({
          remote_config: {
            desired: { revision: 2, exec_enabled: true },
            report: {
              revision: 2,
              outcome: 'not_primary',
              live: [],
              needs_restart: [],
              reported_at: '2026-08-24T00:00:00Z',
            },
            state: 'refused',
          },
        }),
      ],
      total: 1,
      page: 1,
      per_page: 20,
      total_pages: 1,
    })
    const s = useAgentStore()
    await s.fetchAgents(TENANT_ID)
    expect(s.agents[0]!.remote_config!.state).toBe('refused')
    expect(s.agents[0]!.remote_config!.report!.outcome).toBe('not_primary')
  })

  it('needs_restart is never reported as applied', async () => {
    // The keys in that list are written to disk and not in force. Reading it
    // as "applied" tells an operator SSH is open while the device refuses
    // every session.
    mockApi.get.mockResolvedValueOnce({
      items: [
        mkAgent({
          remote_config: {
            desired: { revision: 3, ssh_enabled: true },
            report: {
              revision: 3,
              outcome: 'applied',
              live: [],
              needs_restart: ['ssh_enabled'],
              reported_at: '2026-08-24T00:00:00Z',
            },
            state: 'needs_restart',
          },
        }),
      ],
      total: 1,
      page: 1,
      per_page: 20,
      total_pages: 1,
    })
    const s = useAgentStore()
    await s.fetchAgents(TENANT_ID)
    const rc = s.agents[0]!.remote_config!
    // The device said "applied"; the SERVER resolved that to `needs_restart`
    // because of the key list. The state is the thing to render.
    expect(rc.report!.outcome).toBe('applied')
    expect(rc.state).toBe('needs_restart')
  })
})
