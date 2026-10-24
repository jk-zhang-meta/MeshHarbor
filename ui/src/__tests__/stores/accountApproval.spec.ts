// SPDX-License-Identifier: AGPL-3.0-only
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { api } from '@/api/client'
import { useAccountApprovalStore, type ApprovalAccount } from '@/stores/accountApproval'
vi.mock('@/api/client', () => ({ api: { get: vi.fn(), post: vi.fn() } }))
const row: ApprovalAccount = { user_id: 'account-1', username: 'alice', email: 'alice@example.test', state: 'approved', revision: 7, email_verified: true }
const page = (items = [{ ...row }]) => ({ items, total: items.length, page: 1 })
async function owner() {
  vi.mocked(api.get).mockResolvedValueOnce({ enabled: true, is_owner: true })
  const store = useAccountApprovalStore()
  await store.loadAccess('owner-id')
  return store
}
beforeEach(() => { setActivePinia(createPinia()); vi.clearAllMocks() })
describe('central account approval authority and reviews', () => {
  it('uses the server owner flag and includes legacy accounts in pending review', async () => {
    const store = await owner()
    vi.mocked(api.get).mockResolvedValueOnce(page())
    await store.loadQueue()
    expect(store.isOwner).toBe(true)
    expect(api.get).toHaveBeenLastCalledWith('/auth/approval?page=1&per_page=20')
    expect(store.items[0]?.username).toBe('alice')
  })
  it('does not infer ownership from an owner-looking user ID and never loads a nonowner queue', async () => {
    vi.mocked(api.get).mockResolvedValueOnce({ enabled: true, is_owner: false })
    const store = useAccountApprovalStore()
    await store.loadAccess('owner')
    await store.loadQueue()
    expect(store.isOwner).toBe(false)
    expect(api.get).toHaveBeenCalledTimes(1)
  })
  it('uses an explicit state filter for approved/rejected/suspended tabs', async () => {
    const store = await owner()
    vi.mocked(api.get).mockResolvedValue(page())
    for (const state of ['approved', 'rejected', 'suspended'] as const) {
      await store.selectTab(state)
      expect(api.get).toHaveBeenLastCalledWith(`/auth/approval?page=1&per_page=20&state=${state}`)
    }
  })
  it('sends the precise revocation body and does not optimistically change admission', async () => {
    const store = await owner()
    vi.mocked(api.get).mockResolvedValue(page())
    await store.loadQueue()
    let resolvePost!: (value: unknown) => void
    vi.mocked(api.post).mockImplementationOnce(() => new Promise((resolve) => { resolvePost = resolve }))
    const task = store.review(row, 'suspended')
    expect(api.post).toHaveBeenCalledWith('/auth/approval/account-1', { state: 'suspended', expected_revision: 7 })
    expect(store.items[0]?.state).toBe('approved')
    resolvePost({ ...row, state: 'suspended', revision: 8 })
    expect(await task).toBe('applied')
    expect(api.get).toHaveBeenCalledTimes(3)
  })
  it('on 409 reloads current state without retrying or claiming privilege changed', async () => {
    const store = await owner()
    vi.mocked(api.post).mockRejectedValueOnce(Object.assign(new Error('changed'), { status: 409 }))
    vi.mocked(api.get).mockResolvedValueOnce(page([{ ...row, revision: 8 }]))
    expect(await store.review(row, 'suspended')).toBe('conflict')
    expect(store.items[0]?.state).toBe('approved')
    expect(store.items[0]?.revision).toBe(8)
    expect(store.error).toContain('review its current state')
    expect(api.post).toHaveBeenCalledTimes(1)
  })
  it('does not claim a conflicting account was reloaded when the refresh fails', async () => {
    const store = await owner()
    vi.mocked(api.post).mockRejectedValueOnce(Object.assign(new Error('changed'), { status: 409 }))
    vi.mocked(api.get).mockRejectedValueOnce(new Error('offline'))
    expect(await store.review(row, 'suspended')).toBe('conflict')
    expect(store.items).toEqual([])
    expect(store.error).toContain('reload failed')
  })
  it('does not return an old successful review after logout while its reload is pending', async () => {
    const store = await owner()
    vi.mocked(api.post).mockResolvedValueOnce({ ...row, state: 'suspended', revision: 8 })
    let finishReload!: (value: unknown) => void
    vi.mocked(api.get).mockImplementationOnce(() => new Promise((resolve) => { finishReload = resolve }))
    const task = store.review(row, 'suspended')
    await vi.waitFor(() => expect(finishReload).toBeTypeOf('function'))
    store.reset()
    finishReload(page([{ ...row, state: 'suspended', revision: 8 }]))
    expect(await task).toBe('failed')
    expect(store.userId).toBeNull()
    expect(store.items).toEqual([])
    expect(store.error).toBeNull()
    expect(store.reviewing).toBe(false)
  })
  it('does not write an old conflict error after identity changes while its reload is pending', async () => {
    const store = await owner()
    vi.mocked(api.post).mockRejectedValueOnce(Object.assign(new Error('changed'), { status: 409 }))
    let finishReload!: (value: unknown) => void
    vi.mocked(api.get).mockImplementationOnce(() => new Promise((resolve) => { finishReload = resolve }))
    const task = store.review(row, 'suspended')
    await vi.waitFor(() => expect(finishReload).toBeTypeOf('function'))
    store.reset()
    vi.mocked(api.get).mockResolvedValueOnce({ enabled: true, is_owner: false })
    await store.loadAccess('new-user')
    finishReload(page([{ ...row, revision: 8 }]))
    expect(await task).toBe('failed')
    expect(store.userId).toBe('new-user')
    expect(store.isOwner).toBe(false)
    expect(store.items).toEqual([])
    expect(store.error).toBeNull()
    expect(store.reviewing).toBe(false)
  })
  it('reset clears owner data and ignores an old in-flight access result after user change', async () => {
    const store = useAccountApprovalStore()
    let resolveOld!: (value: unknown) => void
    vi.mocked(api.get).mockImplementationOnce(() => new Promise((resolve) => { resolveOld = resolve }))
    const old = store.loadAccess('previous-owner')
    store.reset()
    vi.mocked(api.get).mockResolvedValueOnce({ enabled: true, is_owner: false })
    await store.loadAccess('new-user')
    resolveOld({ enabled: true, is_owner: true })
    await old
    expect(store.userId).toBe('new-user')
    expect(store.isOwner).toBe(false)
    expect(store.items).toEqual([])
  })
})
