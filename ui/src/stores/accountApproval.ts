// SPDX-License-Identifier: AGPL-3.0-only
import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import { api } from '@/api/client'

export type ApprovalState = 'pending' | 'approved' | 'rejected' | 'suspended' | 'legacy_unreviewed'
export type ApprovalDecision = 'approved' | 'rejected' | 'suspended'
export type ApprovalTab = 'pending' | ApprovalDecision
export interface ApprovalAccount {
  user_id: string
  username: string
  email: string
  state: ApprovalState
  revision: number
  email_verified: boolean
}
interface ApprovalAccess { enabled: boolean; is_owner: boolean }
interface ApprovalPage { items: ApprovalAccount[]; total: number; page: number }

/** Display permission only. The server separately authenticates every queue/review. */
export const useAccountApprovalStore = defineStore('accountApproval', () => {
  const access = ref<ApprovalAccess | null>(null)
  const userId = ref<string | null>(null)
  const accessLoading = ref(false)
  const loading = ref(false)
  const reviewing = ref(false)
  const error = ref<string | null>(null)
  const items = ref<ApprovalAccount[]>([])
  const total = ref(0)
  const page = ref(1)
  const perPage = 20
  const tab = ref<ApprovalTab>('pending')
  const isOwner = computed(() => access.value?.enabled === true && access.value.is_owner === true)
  const pageCount = computed(() => Math.max(1, Math.ceil(total.value / perPage)))
  let generation = 0
  let queueRequest = 0

  function reset() {
    generation++
    queueRequest++
    access.value = null
    userId.value = null
    accessLoading.value = false
    loading.value = false
    reviewing.value = false
    error.value = null
    items.value = []
    total.value = 0
    page.value = 1
    tab.value = 'pending'
  }

  async function loadAccess(id: string | null): Promise<boolean> {
    if (!id) { reset(); return false }
    if (userId.value !== id) { reset(); userId.value = id }
    const attempt = ++generation
    accessLoading.value = true
    error.value = null
    // Clear the previous positive answer while the authoritative refresh runs.
    access.value = null
    items.value = []
    try {
      const result = await api.get<ApprovalAccess>('/auth/approval/access')
      if (attempt !== generation || userId.value !== id) return false
      access.value = { enabled: result.enabled === true, is_owner: result.is_owner === true }
      return isOwner.value
    } catch (e) {
      if (attempt === generation) error.value = (e as Error).message || 'Could not verify approval access.'
      return false
    } finally {
      if (attempt === generation) accessLoading.value = false
    }
  }

  async function loadQueue(): Promise<boolean> {
    if (!isOwner.value) return false
    const accountGeneration = generation
    const request = ++queueRequest
    loading.value = true
    items.value = []
    try {
      const params = new URLSearchParams({ page: String(page.value), per_page: String(perPage) })
      // Pending review includes legacy-unreviewed accounts through the backend default.
      if (tab.value !== 'pending') params.set('state', tab.value)
      const result = await api.get<ApprovalPage>(`/auth/approval?${params}`)
      if (accountGeneration !== generation || request !== queueRequest || !isOwner.value) return false
      total.value = result.total
      if (page.value > pageCount.value) { page.value = pageCount.value; return await loadQueue() }
      items.value = result.items
      return true
    } catch (e) {
      if (accountGeneration !== generation || request !== queueRequest) return false
      error.value = (e as Error).message || 'Could not load accounts.'
      if ([401, 403, 404].includes((e as { status?: number }).status ?? 0)) access.value = null
      return false
    } finally {
      if (request === queueRequest) loading.value = false
    }
  }

  async function selectTab(value: ApprovalTab) {
    tab.value = value
    page.value = 1
    error.value = null
    await loadQueue()
  }

  async function setPage(value: number) {
    page.value = Math.max(1, Math.min(value, pageCount.value))
    error.value = null
    await loadQueue()
  }

  async function review(account: ApprovalAccount, state: ApprovalDecision): Promise<'applied' | 'conflict' | 'failed'> {
    if (!isOwner.value || reviewing.value || loading.value) return 'failed'
    const attempt = generation
    reviewing.value = true
    error.value = null
    try {
      await api.post<ApprovalAccount>(`/auth/approval/${encodeURIComponent(account.user_id)}`, {
        state, expected_revision: account.revision,
      })
      if (attempt !== generation) return 'failed'
      // No optimistic privilege changes: reload only after the server's success.
      await loadQueue()
      if (attempt !== generation) return 'failed'
      return 'applied'
    } catch (e) {
      if (attempt !== generation) return 'failed'
      if ((e as { status?: number }).status === 409) {
        const refreshed = await loadQueue()
        if (attempt !== generation) return 'failed'
        error.value = refreshed
          ? 'This account changed. The list has been reloaded; review its current state before trying again.'
          : 'This account changed and the reload failed. Refresh successfully before reviewing it again.'
        return 'conflict'
      }
      error.value = (e as Error).message || 'The review was not applied.'
      if ([401, 403, 404].includes((e as { status?: number }).status ?? 0)) {
        access.value = null
        items.value = []
      }
      return 'failed'
    } finally {
      if (attempt === generation) reviewing.value = false
    }
  }

  return { access, userId, accessLoading, loading, reviewing, error, items, total, page,
    perPage, tab, isOwner, pageCount, reset, loadAccess, loadQueue, selectTab, setPage, review }
})
