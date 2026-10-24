// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'

// Mock router
vi.mock('@/plugins/router', () => ({
  default: { push: vi.fn() },
}))

// Mock push composable
vi.mock('@/composables/usePush', () => ({
  subscribePush: vi.fn(() => Promise.resolve()),
  unsubscribePush: vi.fn(() => Promise.resolve()),
}))

// Mock API client
vi.mock('@/api/client', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
}))

import { useAuthStore } from '@/stores/auth'
import { api } from '@/api/client'
import router from '@/plugins/router'
import { subscribePush, unsubscribePush } from '@/composables/usePush'
import { readTourProgress, hasSeenTour } from '@/composables/useTutorialProgress'

const mockApi = vi.mocked(api)
const mockRouter = vi.mocked(router)

/** The non-credential hint the store uses to render before `/auth/me`. */
const SIGNED_IN = 'roomler-signed-in'

const USER = { id: '1', email: 'test@test.com', username: 'testuser', display_name: 'Test' }

describe('useAuthStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    vi.clearAllMocks()
  })

  describe('initial state', () => {
    it('should start with no user and not authenticated', () => {
      const store = useAuthStore()
      expect(store.user).toBeNull()
      expect(store.isAuthenticated).toBe(false)
      expect(store.loading).toBe(false)
      expect(store.error).toBeNull()
    })

    it('should pick up the signed-in HINT from localStorage on creation', () => {
      // A hint, not a credential: it renders the app shell instead of the
      // login form on a hard refresh. The session itself is an HttpOnly
      // cookie this code cannot read, and the server decides.
      localStorage.setItem(SIGNED_IN, '1')
      const store = useAuthStore()
      expect(store.isAuthenticated).toBe(true)
    })
  })

  describe('login', () => {
    it('signs in WITHOUT putting any token in localStorage', async () => {
      // The point of the whole change. The session arrived as a Set-Cookie on
      // this same response; anything stored here is readable by an XSS.
      mockApi.post.mockResolvedValueOnce({
        access_token: 'server-still-returns-this',
        refresh_token: 'and-this',
        user: USER,
      })

      const store = useAuthStore()
      await store.login('testuser', 'password123')

      expect(mockApi.post).toHaveBeenCalledWith('/auth/login', {
        username: 'testuser',
        password: 'password123',
      })
      expect(store.user).toEqual(USER)
      expect(store.isAuthenticated).toBe(true)
      expect(subscribePush).toHaveBeenCalled()

      expect(localStorage.getItem('access_token')).toBeNull()
      expect(localStorage.getItem('refresh_token')).toBeNull()
      expect(localStorage.getItem(SIGNED_IN)).toBe('1')
    })

    it('surfaces the error and stays signed out on failure', async () => {
      mockApi.post.mockRejectedValueOnce(new Error('Invalid credentials'))
      const store = useAuthStore()
      await expect(store.login('u', 'bad')).rejects.toThrow('Invalid credentials')
      expect(store.error).toBe('Invalid credentials')
      expect(store.isAuthenticated).toBe(false)
      expect(localStorage.getItem(SIGNED_IN)).toBeNull()
    })
  })

  describe('logout', () => {
    it('ASKS THE SERVER to end the session, then clears locally', async () => {
      // ⚠️ The POST is the load-bearing part and it used to be missing: the
      // old logout cleared localStorage and navigated, which only looked like
      // a logout because the SPA then had no token to send. The session COOKIE
      // survived and the server accepted it for its full 7 days.
      mockApi.post.mockResolvedValueOnce({ access_token: 'tok', user: USER })
      const store = useAuthStore()
      await store.login('u', 'p')

      mockApi.post.mockResolvedValueOnce({})
      await store.logout()

      expect(mockApi.post).toHaveBeenCalledWith('/auth/logout', {})
      expect(store.user).toBeNull()
      expect(store.isAuthenticated).toBe(false)
      expect(localStorage.getItem(SIGNED_IN)).toBeNull()
      expect(unsubscribePush).toHaveBeenCalled()
      expect(mockRouter.push).toHaveBeenCalledWith({ name: 'login' })
    })

    it('still clears locally when the server call fails', async () => {
      // Offline or server down: do not trap the user inside a session they
      // asked to leave.
      localStorage.setItem(SIGNED_IN, '1')
      const store = useAuthStore()
      mockApi.post.mockRejectedValueOnce(new Error('network'))

      await store.logout()

      expect(store.isAuthenticated).toBe(false)
      expect(localStorage.getItem(SIGNED_IN)).toBeNull()
      expect(mockRouter.push).toHaveBeenCalledWith({ name: 'login' })
    })
  })

  describe('fetchMe', () => {
    it('should fetch user from API and set user', async () => {
      localStorage.setItem(SIGNED_IN, '1')
      const mockUser = { id: '2', email: 'me@test.com', username: 'me', display_name: 'Me' }
      mockApi.get.mockResolvedValueOnce(mockUser)

      const store = useAuthStore()
      await store.fetchMe()

      expect(mockApi.get).toHaveBeenCalledWith('/auth/me')
      expect(store.user).toEqual(mockUser)
      expect(subscribePush).toHaveBeenCalled()
    })

    it('should not call the API when this browser has no session hint', async () => {
      const store = useAuthStore()
      await store.fetchMe()
      expect(mockApi.get).not.toHaveBeenCalled()
    })

    it('logs out when the server disagrees with the hint', async () => {
      // The hint is only a hint. The server is the authority, and a stale hint
      // must not leave the app rendering a signed-in shell. The mock plays the
      // real api client: a refused session is a 401 whose refresh was refused,
      // and the client clears the hint before it throws (#1788).
      localStorage.setItem(SIGNED_IN, '1')
      mockApi.get.mockImplementationOnce(async () => {
        localStorage.removeItem(SIGNED_IN)
        throw new Error('Unauthorized')
      })
      mockApi.post.mockResolvedValueOnce({})

      const store = useAuthStore()
      await store.fetchMe()

      expect(mockApi.post).toHaveBeenCalledWith('/auth/logout', {})
      expect(store.user).toBeNull()
      expect(store.isAuthenticated).toBe(false)
      expect(mockRouter.push).toHaveBeenCalledWith({ name: 'login' })
    })

    // #1788, part 2 — measured: with the rate limit spent, `/auth/me` answered
    // 429 and fetchMe signed the user out FOR REAL (`POST /auth/logout` 200).
    // A throttled, failed or unreachable server has not refused anything.
    it('keeps the session when /auth/me fails without a refusal (429, 5xx, unreachable): the client left the hint alone', async () => {
      localStorage.setItem(SIGNED_IN, '1')
      mockApi.get.mockRejectedValueOnce(new Error('no verdict'))

      const store = useAuthStore()
      await store.fetchMe()

      expect(mockApi.post).not.toHaveBeenCalledWith('/auth/logout', {})
      expect(store.isAuthenticated).toBe(true)
      expect(localStorage.getItem(SIGNED_IN)).toBe('1')
      expect(mockRouter.push).not.toHaveBeenCalled()
    })
  })

  describe('a session that arrived as a cookie (the OAuth callback)', () => {
    it('adoptCookieSession signs in a store created signed OUT, and loads the user', async () => {
      // After a logout the hint is gone when the page loads, so the store is
      // created signed out. Writing only the hint (what the callback did)
      // left this false, and `fetchMe` returned before asking the server.
      mockApi.get.mockResolvedValueOnce(USER)
      const store = useAuthStore()
      expect(store.isAuthenticated).toBe(false)

      await store.adoptCookieSession()

      expect(store.isAuthenticated).toBe(true)
      expect(mockApi.get).toHaveBeenCalledWith('/auth/me')
      expect(store.user).toEqual(USER)
      expect(localStorage.getItem(SIGNED_IN)).toBe('1')
    })

    it('forgetLocalSession signs out locally, without a server call or a navigation', () => {
      localStorage.setItem(SIGNED_IN, '1')
      const store = useAuthStore()
      expect(store.isAuthenticated).toBe(true)

      store.forgetLocalSession()

      expect(store.isAuthenticated).toBe(false)
      expect(store.user).toBeNull()
      expect(localStorage.getItem(SIGNED_IN)).toBeNull()
      expect(mockApi.post).not.toHaveBeenCalled()
      expect(mockRouter.push).not.toHaveBeenCalled()
    })
  })

  describe('register', () => {
    it('signs in on the auto-verified path without storing a token', async () => {
      const mockUser = { id: '3', email: 'new@test.com', username: 'newuser', display_name: 'New' }
      mockApi.post.mockResolvedValueOnce({ access_token: 'reg-token', user: mockUser })

      const store = useAuthStore()
      const result = await store.register('new@test.com', 'newuser', 'pass', 'New')

      expect(mockApi.post).toHaveBeenCalledWith('/auth/register', {
        email: 'new@test.com',
        username: 'newuser',
        password: 'pass',
        display_name: 'New',
      })
      expect(store.user).toEqual(mockUser)
      expect(store.isAuthenticated).toBe(true)
      expect(localStorage.getItem('access_token')).toBeNull()
      expect(result).toEqual({ access_token: 'reg-token', user: mockUser })
    })

    it('does NOT sign in when registration needs email activation', async () => {
      // Production returns `{ message }` only — the account exists but is not
      // usable yet, so claiming a session would render an app shell whose
      // every request 401s.
      mockApi.post.mockResolvedValueOnce({ message: 'check your email' })

      const store = useAuthStore()
      await store.register('new@test.com', 'newuser', 'pass', 'New')

      expect(store.isAuthenticated).toBe(false)
      expect(store.user).toBeNull()
      expect(localStorage.getItem(SIGNED_IN)).toBeNull()
    })

    it('should include invite_code when provided', async () => {
      mockApi.post.mockResolvedValueOnce({
        access_token: 'tok',
        user: { id: '1', email: '', username: '', display_name: '' },
      })

      const store = useAuthStore()
      await store.register('e@e.com', 'u', 'p', 'D', 'invite-123')

      expect(mockApi.post).toHaveBeenCalledWith('/auth/register', {
        email: 'e@e.com',
        username: 'u',
        password: 'p',
        display_name: 'D',
        invite_code: 'invite-123',
      })
    })

    // FR-88 (#1790) §3a — attribution travels once, with the account.
    it('sends the attribution object when there is one', async () => {
      mockApi.post.mockResolvedValueOnce({ message: 'check your email' })
      const store = useAuthStore()
      await store.register('e@e.com', 'u', 'p', 'D', undefined, { source: 'youtube', campaign: 'c1', self_reported: 'friend' })

      expect(mockApi.post).toHaveBeenCalledWith('/auth/register', {
        email: 'e@e.com',
        username: 'u',
        password: 'p',
        display_name: 'D',
        attribution: { source: 'youtube', campaign: 'c1', self_reported: 'friend' },
      })
    })

    it('omits the attribution key when there is nothing to say — never `{}`', async () => {
      mockApi.post.mockResolvedValue({ message: 'check your email' })
      const store = useAuthStore()
      await store.register('e@e.com', 'u', 'p', 'D', undefined, undefined)
      await store.register('e@e.com', 'u', 'p', 'D', undefined, {})

      for (const [, body] of mockApi.post.mock.calls) {
        expect(body).not.toHaveProperty('attribution')
      }
    })
  })

  // FR-12 P3, field-caught on prod. The seed lived in
  // `AppLayout.maybeAutoOpenTour`, which bails on the tutorial route and runs
  // at most once per load -- so a browser with no local state showed
  // `0/8 done` for an account the server said had finished a chapter. Signing
  // in IS the event, so the store is where it belongs, and a store test is
  // what would have caught it.
  describe('tutorial state follows the account (FR-12 P3)', () => {
    const WITH_TUTORIAL = {
      ...USER,
      tutorial: { done: ['acl', 'devices'], seen_at: '2026-09-01T10:00:00Z' },
    }

    it('seeds this browser from the account on fetchMe', async () => {
      localStorage.setItem(SIGNED_IN, '1')
      mockApi.get.mockResolvedValueOnce(WITH_TUTORIAL)

      const store = useAuthStore()
      await store.fetchMe()

      expect(readTourProgress(USER.id).sort()).toEqual(['acl', 'devices'])
      expect(hasSeenTour(USER.id)).toBe(true)
    })

    it('seeds on login too -- a fresh browser signs IN, it does not fetchMe', async () => {
      mockApi.post.mockResolvedValueOnce({ user: WITH_TUTORIAL })

      const store = useAuthStore()
      await store.login('testuser', 'pw')

      expect(readTourProgress(USER.id).sort()).toEqual(['acl', 'devices'])
    })

    it('an account with no tutorial state leaves the browser alone', async () => {
      localStorage.setItem(SIGNED_IN, '1')
      mockApi.get.mockResolvedValueOnce(USER)

      const store = useAuthStore()
      await store.fetchMe()

      expect(readTourProgress(USER.id)).toEqual([])
      expect(hasSeenTour(USER.id)).toBe(false)
    })
  })
})

// The owner display permission must not survive an account boundary.
describe('account approval permission follows the signed-in account', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    vi.clearAllMocks()
  })
  async function signedInOwner() {
    const { useAccountApprovalStore } = await import('@/stores/accountApproval')
    const auth = useAuthStore()
    auth.user = USER
    const approval = useAccountApprovalStore()
    mockApi.get.mockResolvedValueOnce({ enabled: true, is_owner: true })
    await approval.loadAccess(USER.id)
    expect(approval.isOwner).toBe(true)
    return { auth, approval }
  }
  it('clears owner state immediately when logout starts, before the network response', async () => {
    const { auth, approval } = await signedInOwner()
    let finish!: (value: unknown) => void
    mockApi.post.mockImplementationOnce(() => new Promise((resolve) => { finish = resolve }))
    const task = auth.logout()
    expect(approval.isOwner).toBe(false)
    expect(approval.items).toEqual([])
    finish({})
    await task
  })
  it('clears owner state when the locally refused session is forgotten', async () => {
    const { auth, approval } = await signedInOwner()
    auth.forgetLocalSession()
    expect(approval.isOwner).toBe(false)
    expect(approval.userId).toBeNull()
  })
  it('clears old owner permission when login adopts another user', async () => {
    const { auth, approval } = await signedInOwner()
    mockApi.post.mockResolvedValueOnce({ user: { ...USER, id: 'another-user' } })
    await auth.login('another-user', 'password')
    expect(approval.isOwner).toBe(false)
    expect(approval.userId).toBeNull()
  })
})
