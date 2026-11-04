// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

// Mock router. `currentRoute` is read by the api client's tenant-eviction
// guard, so it has to exist or the 403 branch throws instead of navigating.
vi.mock('@/plugins/router', () => ({
  default: { push: vi.fn(), currentRoute: { value: { name: 'devices' } } },
}))

// Mock snackbar
const mockShowError = vi.fn()
vi.mock('@/composables/useSnackbar', () => ({
  useSnackbar: () => ({ showError: mockShowError }),
}))

import { api, ApiError } from '@/api/client'
import router from '@/plugins/router'

const mockRouter = vi.mocked(router)

describe('api client', () => {
  let mockFetch: ReturnType<typeof vi.fn>

  beforeEach(() => {
    localStorage.clear()
    vi.clearAllMocks()

    mockFetch = vi.fn()
    globalThis.fetch = mockFetch as typeof globalThis.fetch
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  function mockJsonResponse(status: number, data: unknown, ok?: boolean) {
    return {
      ok: ok ?? (status >= 200 && status < 300),
      status,
      headers: { get: (name: string) => name === 'content-type' ? 'application/json' : null },
      json: () => Promise.resolve(data),
      blob: () => Promise.resolve(new Blob()),
    }
  }

  describe('auth: the cookie carries the session, not a header', () => {
    it('sends NO Authorization header, even with a stale token in localStorage', async () => {
      // The client no longer reads a token at all. `BASE_URL` is `/api`, so
      // every call is same-origin and the browser attaches the HttpOnly
      // session cookie itself — which the server has always accepted.
      // A leftover token from an older version must not resurrect the header.
      localStorage.setItem('access_token', 'stale-token-from-an-old-version')
      mockFetch.mockResolvedValueOnce(mockJsonResponse(200, { ok: true }))

      await api.get('/test')

      const [, init] = mockFetch.mock.calls[0]
      const headers = (init as { headers: Record<string, string> }).headers
      expect(headers.Authorization).toBeUndefined()
    })

    it('should not include Authorization header when no token', async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse(200, { ok: true }))

      await api.get('/test')

      const headers = mockFetch.mock.calls[0][1].headers
      expect(headers.Authorization).toBeUndefined()
    })
  })

  describe('request methods', () => {
    beforeEach(() => {
      mockFetch.mockResolvedValue(mockJsonResponse(200, { data: 'test' }))
    })

    it('api.get should use GET method', async () => {
      await api.get('/resource')
      expect(mockFetch).toHaveBeenCalledWith('/api/resource', expect.objectContaining({ method: 'GET' }))
    })

    it('api.post should use POST method and send JSON body', async () => {
      await api.post('/resource', { name: 'test' })
      expect(mockFetch).toHaveBeenCalledWith('/api/resource', expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ name: 'test' }),
        headers: expect.objectContaining({ 'Content-Type': 'application/json' }),
      }))
    })

    it('api.put should use PUT method', async () => {
      await api.put('/resource', { name: 'updated' })
      expect(mockFetch).toHaveBeenCalledWith('/api/resource', expect.objectContaining({
        method: 'PUT',
        body: JSON.stringify({ name: 'updated' }),
      }))
    })

    it('api.delete should use DELETE method', async () => {
      await api.delete('/resource')
      expect(mockFetch).toHaveBeenCalledWith('/api/resource', expect.objectContaining({ method: 'DELETE' }))
    })

    it('api.upload should send FormData without Content-Type header', async () => {
      const form = new FormData()
      form.append('file', new Blob(), 'test.txt')

      await api.upload('/upload', form)

      const callArgs = mockFetch.mock.calls[0][1]
      expect(callArgs.method).toBe('POST')
      expect(callArgs.body).toBe(form)
      expect(callArgs.headers['Content-Type']).toBeUndefined()
    })
  })

  describe('response handling', () => {
    it('should parse JSON responses', async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse(200, { name: 'test' }))
      const result = await api.get<{ name: string }>('/test')
      expect(result).toEqual({ name: 'test' })
    })

    it('should return blob for non-JSON responses', async () => {
      const mockBlob = new Blob(['data'])
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: { get: () => 'application/octet-stream' },
        blob: () => Promise.resolve(mockBlob),
      })

      const result = await api.get('/file')
      expect(result).toBe(mockBlob)
    })
  })

  describe('error handling', () => {
    it('should throw ApiError on non-ok response', async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse(400, { error: 'Bad request' }, false))

      await expect(api.get('/test')).rejects.toThrow(ApiError)
    })

    it('should include status and data on ApiError', async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse(422, { error: 'Validation failed' }, false))

      try {
        await api.get('/test')
        expect.unreachable('Should have thrown')
      } catch (err) {
        expect(err).toBeInstanceOf(ApiError)
        expect((err as ApiError).status).toBe(422)
        expect((err as ApiError).data).toEqual({ error: 'Validation failed' })
      }
    })

    it('should redirect to login on 401 for non-auth paths', async () => {
      localStorage.setItem('meshharbor-signed-in', '1')
      // The refresh's answer is stated: before #1788 this test left it
      // unmocked, and the refresh that then THREW counted as a rejection.
      mockFetch
        .mockResolvedValueOnce(mockJsonResponse(401, {}, false)) // original request
        .mockResolvedValueOnce(mockJsonResponse(401, {}, false)) // refresh rejected

      await expect(api.get('/tenant/123/room')).rejects.toThrow()

      expect(localStorage.getItem('meshharbor-signed-in')).toBeNull()
      expect(mockRouter.push).toHaveBeenCalledWith({ name: 'login' })
    })

    // FR-82 — the field bug this replaced a passing test with. The Devices
    // page mounts a card that GETs `ephemeral-key-settings` (MANAGE_TENANT),
    // a bit `DEFAULT_ADMIN` deliberately withholds, so opening the page
    // logged out every non-owner in the org. The old rule made that the
    // CORRECT behaviour, which is why nothing caught it.
    it('a permission 403 on a GET does NOT end the session', async () => {
      localStorage.setItem('meshharbor-signed-in', '1')
      mockFetch.mockResolvedValueOnce(
        mockJsonResponse(
          403,
          { error: 'forbidden', message: 'Missing MANAGE_TENANT permission' },
          false,
        ),
      )

      await expect(api.get('/tenant/123/ephemeral-key-settings')).rejects.toThrow(
        'Missing MANAGE_TENANT permission',
      )

      expect(localStorage.getItem('meshharbor-signed-in')).toBe('1')
      expect(mockRouter.push).not.toHaveBeenCalled()
    })

    // The default direction is the point: a 403 the server did not classify
    // does NOTHING but throw. That is what keeps a newly-added
    // permission-gated route inert here without anyone remembering it.
    it('an UNCLASSIFIED 403 neither logs out nor navigates', async () => {
      localStorage.setItem('meshharbor-signed-in', '1')
      mockFetch.mockResolvedValueOnce(mockJsonResponse(403, {}, false))

      await expect(api.get('/tenant/123/room')).rejects.toThrow()

      expect(localStorage.getItem('meshharbor-signed-in')).toBe('1')
      expect(mockRouter.push).not.toHaveBeenCalled()
    })

    // The one 403 that HAS a navigation — and it is out of the tenant, not
    // out of the session: the credential is fine and the user is still in
    // every other org they belong to.
    it('a not_a_member 403 leaves the tenant and KEEPS the session', async () => {
      localStorage.setItem('meshharbor-signed-in', '1')
      mockFetch.mockResolvedValueOnce(
        mockJsonResponse(403, { error: 'not_a_member', message: 'Not a member' }, false),
      )

      await expect(api.get('/tenant/123/device')).rejects.toThrow('Not a member')

      expect(localStorage.getItem('meshharbor-signed-in')).toBe('1')
      expect(mockRouter.push).toHaveBeenCalledWith({ name: 'dashboard' })
    })

    // A 403 on a MUTATION is a policy verdict on a perfectly valid session —
    // e.g. the role editor refusing to grant a permission the caller does not
    // hold. Logging the user out would make a deliberate, expected refusal
    // look like a crash, and would swallow the explanation with it.
    it.each(['post', 'put', 'delete'] as const)(
      'should NOT log out or redirect on a 403 %s',
      async (verb) => {
        localStorage.setItem('meshharbor-signed-in', '1')
        mockFetch.mockResolvedValueOnce(
          mockJsonResponse(
            403,
            {
              error: 'forbidden',
              message: 'Cannot grant permissions you do not hold: EXEC_DEVICE',
            },
            false,
          ),
        )

        await expect(api[verb]('/tenant/123/role')).rejects.toThrow(
          'Cannot grant permissions you do not hold: EXEC_DEVICE',
        )

        expect(localStorage.getItem('meshharbor-signed-in')).toBe('1')
        expect(mockRouter.push).not.toHaveBeenCalled()
      },
    )

    it('surfaces the server message as the error message', async () => {
      // Call sites render `(e as Error).message` straight into a form error,
      // so a generic "API error 403" would hide the server's explanation.
      mockFetch.mockResolvedValueOnce(
        mockJsonResponse(409, { error: 'conflict', message: 'Role name taken' }, false),
      )

      await expect(api.post('/tenant/123/role', {})).rejects.toThrow('Role name taken')
    })

    it('falls back to the status when the body carries no message', async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse(409, {}, false))

      await expect(api.post('/tenant/123/role', {})).rejects.toThrow('API error 409')
    })

    // Regression guard for the 2026-07-28 prod incident: `/api` was rate
    // limited hard enough that ordinary use drew 429s, and a throttled
    // session was being logged out and bounced to a login page that was
    // itself throttled.
    it('should NOT log out or redirect on 429', async () => {
      localStorage.setItem('meshharbor-signed-in', '1')
      mockFetch.mockResolvedValueOnce(mockJsonResponse(429, {}, false))

      await expect(api.get('/tenant/123/room')).rejects.toThrow()

      expect(localStorage.getItem('meshharbor-signed-in')).toBe('1')
      expect(mockRouter.push).not.toHaveBeenCalled()
    })

    it('should surface the server message on 429 when there is one', async () => {
      mockFetch.mockResolvedValueOnce(
        mockJsonResponse(429, { error: 'too_many_requests', message: 'Try again in 6s.' }, false),
      )

      await expect(api.post('/auth/login', {})).rejects.toThrow()

      expect(mockShowError).toHaveBeenCalledWith('Try again in 6s.')
    })

    it('should fall back to Retry-After on a 429 with no message', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        headers: {
          get: (name: string) =>
            name === 'content-type' ? 'application/json' : name === 'retry-after' ? '12' : null,
        },
        json: () => Promise.resolve({}),
        blob: () => Promise.resolve(new Blob()),
      })

      await expect(api.get('/test')).rejects.toThrow()

      expect(mockShowError).toHaveBeenCalledWith('Too many requests. Try again in 12s.')
    })

    // A throttled refresh says nothing about session validity, so the
    // session must survive it — otherwise being rate limited logs you out.
    it('should keep the session when the token refresh is throttled', async () => {
      localStorage.setItem('meshharbor-signed-in', '1')
      mockFetch
        .mockResolvedValueOnce(mockJsonResponse(401, {}, false)) // original request
        .mockResolvedValueOnce(mockJsonResponse(429, {}, false)) // refresh throttled

      await expect(api.get('/tenant/123/room')).rejects.toThrow()

      expect(localStorage.getItem('meshharbor-signed-in')).toBe('1')
      expect(mockRouter.push).not.toHaveBeenCalled()
    })

    // ...but a genuine rejection still logs out, so the fix above doesn't
    // strand a dead session.
    it('should still log out when the token refresh is rejected', async () => {
      localStorage.setItem('meshharbor-signed-in', '1')
      mockFetch
        .mockResolvedValueOnce(mockJsonResponse(401, {}, false)) // original request
        .mockResolvedValueOnce(mockJsonResponse(401, {}, false)) // refresh rejected

      await expect(api.get('/tenant/123/room')).rejects.toThrow()

      expect(localStorage.getItem('meshharbor-signed-in')).toBeNull()
      expect(mockRouter.push).toHaveBeenCalledWith({ name: 'login' })
    })

    // #1788 — only a REJECTION ends the session. Found by FR-87's e2e on the
    // hosted images: after a successful refresh, a retry that met a spent rate
    // limit logged the user out; so did a refresh the next navigation cut short.
    describe('#1788: not every refresh problem is a rejection', () => {
      const signedIn = () => localStorage.getItem('meshharbor-signed-in')
      beforeEach(() => localStorage.setItem('meshharbor-signed-in', '1'))

      it('retries once after a successful refresh and returns the answer', async () => {
        mockFetch
          .mockResolvedValueOnce(mockJsonResponse(401, {}, false)) // original request
          .mockResolvedValueOnce(mockJsonResponse(200, {})) // refresh
          .mockResolvedValueOnce(mockJsonResponse(200, { rooms: [] })) // retry

        await expect(api.get('/tenant/123/room')).resolves.toEqual({ rooms: [] })
        expect(signedIn()).toBe('1')
      })

      it('a THROTTLED retry after a successful refresh keeps the session, as a 429', async () => {
        mockFetch
          .mockResolvedValueOnce(mockJsonResponse(401, {}, false))
          .mockResolvedValueOnce(mockJsonResponse(200, {})) // refresh: the session is fine
          .mockResolvedValueOnce(mockJsonResponse(429, { message: 'Try again in 3s.' }, false))

        const err = await api.get('/tenant/123/room').catch((e: unknown) => e)
        expect((err as ApiError).status).toBe(429) // the retry's answer, not the stale 401
        expect(mockShowError).toHaveBeenCalledWith('Try again in 3s.')
        expect(signedIn()).toBe('1')
        expect(mockRouter.push).not.toHaveBeenCalled()
      })

      it('a retry answered 403 after a successful refresh keeps the session', async () => {
        mockFetch
          .mockResolvedValueOnce(mockJsonResponse(401, {}, false))
          .mockResolvedValueOnce(mockJsonResponse(200, {}))
          .mockResolvedValueOnce(mockJsonResponse(403, { error: 'forbidden' }, false))

        const err = await api.get('/tenant/123/room').catch((e: unknown) => e)
        expect((err as ApiError).status).toBe(403)
        expect(signedIn()).toBe('1')
        expect(mockRouter.push).not.toHaveBeenCalled()
      })

      it('a retry STILL refused (401) right after a refresh ends the session, without refreshing again', async () => {
        mockFetch
          .mockResolvedValueOnce(mockJsonResponse(401, {}, false))
          .mockResolvedValueOnce(mockJsonResponse(200, {}))
          .mockResolvedValueOnce(mockJsonResponse(401, {}, false))

        await expect(api.get('/tenant/123/room')).rejects.toThrow()
        expect(mockFetch).toHaveBeenCalledTimes(3) // one refresh, one retry: no loop
        expect(signedIn()).toBeNull()
        expect(mockRouter.push).toHaveBeenCalledWith({ name: 'login' })
      })

      it.each([
        ['a network error', () => Promise.reject(new TypeError('Failed to fetch'))],
        ['a request cancelled by a navigation', () => Promise.reject(new DOMException('The user aborted a request.', 'AbortError'))],
        ['a 503 from the refresh endpoint', () => Promise.resolve(mockJsonResponse(503, {}, false))],
      ])('%s during the refresh keeps the session', async (_, refresh) => {
        mockFetch.mockResolvedValueOnce(mockJsonResponse(401, {}, false)).mockImplementationOnce(refresh)

        const err = await api.get('/tenant/123/room').catch((e: unknown) => e)
        expect((err as ApiError).status).toBe(401)
        expect(signedIn()).toBe('1')
        expect(mockRouter.push).not.toHaveBeenCalled()
        expect(mockShowError).toHaveBeenCalledWith('Could not reach the server. Please try again.')
      })

      it('a refresh answered 403 is a rejection too', async () => {
        mockFetch
          .mockResolvedValueOnce(mockJsonResponse(401, {}, false))
          .mockResolvedValueOnce(mockJsonResponse(403, {}, false))

        await expect(api.get('/tenant/123/room')).rejects.toThrow()
        expect(signedIn()).toBeNull()
        expect(mockRouter.push).toHaveBeenCalledWith({ name: 'login' })
      })
    })

    it('should NOT redirect on 401 for auth paths', async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse(401, { error: 'Invalid credentials' }, false))

      await expect(api.post('/auth/login', {})).rejects.toThrow()

      expect(mockRouter.push).not.toHaveBeenCalled()
    })

    it('should NOT redirect on 401 for refresh path', async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse(401, {}, false))

      await expect(api.post('/auth/refresh', {})).rejects.toThrow()

      expect(mockRouter.push).not.toHaveBeenCalled()
    })

    it('should NOT redirect on 401 for oauth paths', async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse(401, {}, false))

      await expect(api.get('/oauth/google')).rejects.toThrow()

      expect(mockRouter.push).not.toHaveBeenCalled()
    })

    it('should show snackbar on 500 errors', async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse(500, { error: 'Internal server error' }, false))

      await expect(api.get('/test')).rejects.toThrow()

      expect(mockShowError).toHaveBeenCalledWith('Internal server error')
    })

    it('should show generic message when 500 response has no error field', async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse(500, {}, false))

      await expect(api.get('/test')).rejects.toThrow()

      expect(mockShowError).toHaveBeenCalledWith('Server error (500)')
    })

    it('should show message field if error field is missing on 500', async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse(502, { message: 'Bad gateway' }, false))

      await expect(api.get('/test')).rejects.toThrow()

      expect(mockShowError).toHaveBeenCalledWith('Bad gateway')
    })

    it('should not show snackbar for 4xx errors', async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse(400, { error: 'Bad request' }, false))

      await expect(api.get('/test')).rejects.toThrow()

      expect(mockShowError).not.toHaveBeenCalled()
    })
  })

  describe('base URL', () => {
    it('should prepend /api to all paths', async () => {
      mockFetch.mockResolvedValueOnce(mockJsonResponse(200, {}))

      await api.get('/tenant/123')

      expect(mockFetch).toHaveBeenCalledWith('/api/tenant/123', expect.anything())
    })
  })
})
