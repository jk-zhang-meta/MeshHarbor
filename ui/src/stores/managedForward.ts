// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api, ApiError } from '@/api/client'

// Matches `crates/modules/network/src/managed_forward.rs` and the responses in
// `crates/modules/network/src/routes/managed_forward.rs` (MeshHarbor #20).
// A forward keeps v039's layers apart: `desired` is what the administrator
// asked for, `applied` the ingress node's own ack for THIS revision, and
// `verified` its next inventory showing the forward in effect.

export type L4 = 'tcp' | 'udp'
export type NatMode = 'masquerade' | 'preserve_source'
export type Backend = 'userspace' | 'nft'
export type Desired = 'enabled' | 'disabled'

export interface ForwardSpec {
  name: string
  ingress_agent_id: string
  bind_addr: string
  port: number
  proto: L4
  /** Who may connect, as CIDRs. Never empty. */
  sources: string[]
  dest_agent_id?: string | null
  dest_addr: string
  dest_port: number
  nat: NatMode
  backend: Backend
  desired: Desired
  /** Required to bind a wildcard address. */
  public_listener?: boolean
  expires_at_ms?: number | null
}

export type Verdict = 'pass' | 'fail' | 'unknown' | 'warn'

export interface Check {
  name: string
  verdict: Verdict
  detail: string
}

export interface Plan {
  /** Every check passed (a `warn` passes). */
  ok: boolean
  checks: Check[]
  backend: Backend
}

export interface ForwardStatus {
  desired: Desired
  applied: 'applied' | 'failed' | 'pending' | 'not_applied'
  error?: string
  verified: 'verified' | 'drift' | 'unverified'
}

export interface ForwardView {
  id: string
  revision: number
  spec: ForwardSpec
  status: ForwardStatus
  created_at: string
  updated_at: string
}

/** What a mutation came to: stored, refused by its plan, or a stale revision. */
export type MutationResult =
  | { kind: 'ok'; forward: ForwardView; plan: Plan }
  | { kind: 'refused'; plan: Plan }
  | { kind: 'conflict'; message: string }
  | { kind: 'error'; message: string }

export function verdictColor(v: Verdict): string {
  switch (v) {
    case 'pass':
      return 'success'
    case 'warn':
      return 'warning'
    default:
      return 'error'
  }
}

export function appliedColor(a: ForwardStatus['applied']): string {
  switch (a) {
    case 'applied':
      return 'success'
    case 'failed':
      return 'error'
    case 'pending':
      return 'warning'
    default:
      return 'grey'
  }
}

export function verifiedColor(v: ForwardStatus['verified']): string {
  return v === 'verified' ? 'success' : v === 'drift' ? 'error' : 'grey'
}

/** `addr:port`, bracketing an IPv6 address. */
export function endpoint(addr: string, port: number): string {
  return addr.includes(':') ? `[${addr}]:${port}` : `${addr}:${port}`
}

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

/** A 422 carries the refusing plan; a 409 means someone changed it first. */
function settle(e: unknown): MutationResult {
  if (e instanceof ApiError) {
    const plan = (e.data as { plan?: Plan } | null)?.plan
    if (e.status === 422 && plan) return { kind: 'refused', plan }
    if (e.status === 409) return { kind: 'conflict', message: e.message }
  }
  return { kind: 'error', message: message(e) }
}

export const useManagedForwardStore = defineStore('managedForward', () => {
  const items = ref<ForwardView[]>([])
  const loading = ref(false)
  const error = ref<string | null>(null)

  const base = (tenantId: string) => `/tenant/${tenantId}/managed-forward`

  // Fetches swallow into `error` (stores/role.ts convention).
  async function fetchList(tenantId: string) {
    loading.value = true
    error.value = null
    try {
      const res = await api.get<{ items: ForwardView[] }>(base(tenantId))
      items.value = res.items
    } catch (e) {
      error.value = message(e)
    } finally {
      loading.value = false
    }
  }

  /** The dry run: nothing is stored and no node is touched. */
  async function plan(tenantId: string, spec: ForwardSpec): Promise<Plan | null> {
    try {
      return await api.post<Plan>(`${base(tenantId)}/plan`, spec)
    } catch (e) {
      error.value = message(e)
      return null
    }
  }

  function upsert(f: ForwardView) {
    const i = items.value.findIndex((x) => x.id === f.id)
    if (i >= 0) items.value[i] = f
    else items.value.push(f)
  }

  async function create(tenantId: string, spec: ForwardSpec): Promise<MutationResult> {
    try {
      const r = await api.post<{ forward: ForwardView; plan: Plan }>(base(tenantId), spec)
      upsert(r.forward)
      return { kind: 'ok', forward: r.forward, plan: r.plan }
    } catch (e) {
      return settle(e)
    }
  }

  /** Update against the revision the caller read; a stale one reloads. */
  async function update(tenantId: string, cur: ForwardView, spec: ForwardSpec): Promise<MutationResult> {
    try {
      const r = await api.put<{ forward: ForwardView; plan: Plan }>(`${base(tenantId)}/${cur.id}`, {
        expected_revision: cur.revision,
        spec,
      })
      upsert(r.forward)
      return { kind: 'ok', forward: r.forward, plan: r.plan }
    } catch (e) {
      const out = settle(e)
      if (out.kind === 'conflict') await fetchList(tenantId)
      return out
    }
  }

  function setDesired(tenantId: string, cur: ForwardView, desired: Desired) {
    return update(tenantId, cur, { ...cur.spec, desired })
  }

  async function remove(tenantId: string, cur: ForwardView): Promise<MutationResult | null> {
    try {
      await api.delete(`${base(tenantId)}/${cur.id}?expected_revision=${cur.revision}`)
      items.value = items.value.filter((x) => x.id !== cur.id)
      return null
    } catch (e) {
      const out = settle(e)
      if (out.kind === 'conflict') await fetchList(tenantId)
      return out
    }
  }

  return { items, loading, error, fetchList, plan, create, update, setDesired, remove }
})
