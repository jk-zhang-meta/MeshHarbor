// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { appPath } from '@/utils/deployment'
import router from '@/plugins/router'
import { useSnackbar } from '@/composables/useSnackbar'
import { clearSignedIn } from '@/api/session'

const BASE_URL = appPath('/api')

const AUTH_PATHS = ['/auth/login', '/auth/register', '/auth/refresh', '/oauth/']

interface RequestOptions {
  method?: string
  body?: unknown
  headers?: Record<string, string>
}

class ApiError extends Error {
  constructor(
    public status: number,
    public data: unknown,
  ) {
    // Prefer the server's explanation. Every ApiError variant serialises as
    // `{error, message}` (crates/api/src/error.rs), and call sites almost
    // universally render `(e as Error).message` straight into a form error —
    // so without this the user sees "API error 403" where the server took the
    // trouble to say WHICH permission it refused.
    super((data as Record<string, string> | null)?.message || `API error ${status}`)
  }
}

/**
 * End the session locally after the server has rejected it.
 *
 * Only clears the local hint — the cookie is `HttpOnly`, so the SERVER has to
 * expire it, which is what `/auth/logout` is for. This path is the involuntary
 * one (the credential was already refused), so there is nothing left to revoke.
 */
function endSessionLocally(): void {
  clearSignedIn()
  router.push({ name: 'login' })
}

/**
 * Leave the tenant in the URL, keeping the session.
 *
 * FR-82 — the answer to the ONE case the old "any GET 403 ⇒ log out" rule
 * was defending: membership revoked, or a tenant switched underneath, so
 * every read in this org 403s and the page would otherwise sit there broken.
 * That is a tenant-scope problem, not an authentication one — the credential
 * is fine and the user is still signed in to every OTHER org they belong to,
 * so the correct destination is the org picker, not `/login`.
 *
 * Guarded against a redundant push: several in-flight requests for the same
 * dead tenant all land here, and the dashboard is not tenant-scoped, so
 * arriving once is enough to stop the traffic that got us here.
 */
function leaveTenant(): void {
  if (router.currentRoute.value.name === 'dashboard') return
  // Say why. An unexplained bounce to the org picker is the same confusion
  // the old logout caused, one screen further in — and this is the one case
  // where the user genuinely needs to know something changed.
  const { showError } = useSnackbar()
  showError('You are no longer a member of that organisation.')
  router.push({ name: 'dashboard' })
}

/**
 * Turn a 429 into something a user can act on. The server sends `Retry-After`
 * in seconds; without it we can only say "too many requests".
 */
export function rateLimitMessage(resp: Response, data: unknown): string {
  const serverMessage = (data as Record<string, string> | null)?.message
  if (serverMessage) return serverMessage

  const retryAfter = Number(resp.headers.get('retry-after'))
  return Number.isFinite(retryAfter) && retryAfter > 0
    ? `Too many requests. Try again in ${retryAfter}s.`
    : 'Too many requests. Please wait a moment and try again.'
}

/**
 * Only a REJECTION ends the session. `failed` is the server saying no: the
 * refresh endpoint answers a missing, expired or invalid refresh cookie with
 * a 401. `throttled` (a 429) and `unknown` (a network error, a request the
 * browser cancelled because the page is navigating away, a 5xx) say nothing
 * about whether the session is still valid, so they keep it. The next request
 * that needs the session asks again, and a dead one is rejected then.
 *
 * #1788: the network error and the cancelled request both used to count as
 * `failed`. A refresh cut short by a navigation cleared the signed-in hint,
 * and the next page showed a still-valid session the landing page.
 */
export type RefreshOutcome = 'ok' | 'failed' | 'throttled' | 'unknown'

let refreshPromise: Promise<RefreshOutcome> | null = null

async function tryRefreshToken(): Promise<RefreshOutcome> {
  // Deduplicate concurrent refresh attempts
  if (refreshPromise) return refreshPromise
  refreshPromise = doRefresh()
  const result = await refreshPromise
  refreshPromise = null
  return result
}

async function doRefresh(): Promise<RefreshOutcome> {
  // No token to send and none to keep: the refresh credential is an HttpOnly
  // cookie scoped to this exact endpoint, so the browser attaches it and the
  // response replaces it. An empty body is the whole request.
  try {
    const resp = await fetch(`${BASE_URL}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    })
    // The new access token arrives as a Set-Cookie; the body copy is ignored.
    if (resp.ok) return 'ok'
    if (resp.status === 401 || resp.status === 403) return 'failed'
    if (resp.status === 429) return 'throttled'
    return 'unknown'
  } catch {
    // A network error, or the fetch the browser aborts when the page unloads.
    return 'unknown'
  }
}

/** `retried`: this call is the one retry after a successful refresh. */
async function request<T>(path: string, options: RequestOptions = {}, retried = false): Promise<T> {
  const { method = 'GET', body, headers = {} } = options

  // No Authorization header. `BASE_URL` is `/api`, so every call here is
  // same-origin and the browser attaches the `access_token` cookie itself —
  // which the server has always accepted. Reading a token in JS to put it back
  // on the request bought nothing except a credential sitting in localStorage
  // for an XSS to find.
  const fetchHeaders: Record<string, string> = {
    ...headers,
  }

  if (body && !(body instanceof FormData)) {
    fetchHeaders['Content-Type'] = 'application/json'
  }

  const resp = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: fetchHeaders,
    body: body instanceof FormData ? body : body ? JSON.stringify(body) : undefined,
  })

  if (!resp.ok) {
    const data = await resp.json().catch(() => ({}))

    if (resp.status === 429) {
      // Being throttled says nothing about the session, so never treat it
      // as an auth failure — the 401 branch below would log the user out
      // and bounce them to a login page that is itself throttled.
      const { showError } = useSnackbar()
      showError(rateLimitMessage(resp, data))
      throw new ApiError(resp.status, data)
    }

    if (
      resp.status === 401 &&
      !AUTH_PATHS.some((p) => path.startsWith(p))
    ) {
      if (retried) {
        // The session was refreshed a moment ago and this request is STILL
        // refused: the credential really is dead.
        endSessionLocally()
      } else {
        const outcome = await tryRefreshToken()
        // Retry through this same function. Nothing to re-attach: the refresh
        // response replaced the session cookie, so the retry carries the new
        // one. And the retry's own failure is handled as what it is (a 429
        // as a 429, a 403 as a 403), not as a failed session. #1788: a retry
        // throttled right after a SUCCESSFUL refresh used to log the user out.
        if (outcome === 'ok') return request<T>(path, options, true)
        if (outcome === 'failed') {
          endSessionLocally()
        } else {
          // Keep the session: we never learned whether it was still valid.
          const { showError } = useSnackbar()
          showError(
            outcome === 'throttled'
              ? 'Too many requests. Please wait a moment and try again.'
              : 'Could not reach the server. Please try again.',
          )
        }
      }
    }

    // ── 403 ────────────────────────────────────────────────────────────
    //
    // A 403 NEVER ends the session, on any method. It is an authorization
    // verdict on a credential the server just accepted — the opposite of a
    // 401 — and treating the two alike is what turned "you may not read this
    // one thing" into "you are logged out".
    //
    // FR-82, field 2026-09-08: the Devices page mounts a card that fetches
    // `/tenant/{id}/ephemeral-key-settings`, which needs MANAGE_TENANT. Every
    // non-OWNER in the org — including its admins, since DEFAULT_ADMIN
    // deliberately excludes that bit — was logged out by opening the page.
    // The store had a `catch` that carefully left the switch `null`; it never
    // ran on the branch that mattered, because the logout fired one layer
    // below it, before the throw. Three fail-closed nav predicates in
    // `utils/permissions.ts` exist only to route around this rule, and each
    // was written after the same bug in a different corner (analytics,
    // invites, now enrollment keys). The rule was the defect.
    //
    // The only 403 with a navigation is the one that says you are not in this
    // tenant at all, and the SERVER says which it is (`ApiError::NotAMember`
    // ⇒ `error: "not_a_member"`) rather than the client guessing from a
    // message string — `chat`'s "Not a member of this room" is a 403 with the
    // same shape and must not evict anyone from their org.
    //
    // ⚠️ Default direction matters more than either branch: an UNCLASSIFIED
    // 403 does nothing but throw. That is what makes a newly-added
    // permission-gated route inert here by construction, instead of
    // dangerous until someone remembers to add a predicate for it.
    if (resp.status === 403 && !AUTH_PATHS.some((p) => path.startsWith(p))) {
      if ((data as Record<string, string> | null)?.error === 'not_a_member') {
        leaveTenant()
      }
    }

    if (resp.status >= 500) {
      const msg = (data as Record<string, string>)?.error || (data as Record<string, string>)?.message || `Server error (${resp.status})`
      const { showError } = useSnackbar()
      showError(msg)
    }

    throw new ApiError(resp.status, data)
  }

  const contentType = resp.headers.get('content-type') || ''
  if (contentType.includes('application/json')) {
    return resp.json() as Promise<T>
  }
  return resp.blob() as unknown as Promise<T>
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) => request<T>(path, { method: 'POST', body }),
  put: <T>(path: string, body?: unknown) => request<T>(path, { method: 'PUT', body }),
  delete: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
  upload: <T>(path: string, formData: FormData) =>
    request<T>(path, { method: 'POST', body: formData }),
}

export { ApiError }
