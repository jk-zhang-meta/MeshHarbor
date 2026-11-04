// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * Whether this browser believes it has a session — and nothing more.
 *
 * ## This is a HINT, not a credential
 *
 * The credential is an `HttpOnly` cookie that JavaScript cannot read, which is
 * the entire point: script that runs on this page cannot steal it. What script
 * still needs is a synchronous answer to "should I render the app or the login
 * page", so a hard refresh on a protected route does not flash the login form
 * while `/auth/me` is in flight.
 *
 * So this flag grants nothing. Setting it by hand in devtools gets you an app
 * shell whose every request 401s. The server is the only thing that decides.
 *
 * ## Why it is not the token
 *
 * Until this landed the SPA kept the access token (7 days) AND the refresh
 * token (30 days) in `localStorage`, where any XSS could read them — and the
 * refresh token re-mints access tokens, so that one was a month of durable
 * account access that survived a password change and a logout. Those are gone;
 * [`clearLegacyTokens`] removes what earlier versions left behind.
 */
const SIGNED_IN = 'meshharbor-signed-in'

/** Keys earlier versions used to store real credentials in. */
const LEGACY_TOKEN_KEYS = ['access_token', 'refresh_token']

export function markSignedIn(): void {
  try {
    localStorage.setItem(SIGNED_IN, '1')
  } catch {
    // Private mode / storage disabled. The app still works; a hard refresh
    // just has to wait for `/auth/me` before it knows what to render.
  }
}

export function clearSignedIn(): void {
  try {
    localStorage.removeItem(SIGNED_IN)
    clearLegacyTokens()
  } catch {
    /* see markSignedIn */
  }
}

export function looksSignedIn(): boolean {
  try {
    return localStorage.getItem(SIGNED_IN) === '1'
  } catch {
    return false
  }
}

/**
 * Delete the tokens earlier versions stored.
 *
 * Called once at boot, not only on logout: a user who never signs out again
 * would otherwise keep a valid 30-day refresh token in `localStorage` for the
 * rest of its life. Shipping the fix has to actually remove the thing.
 */
export function clearLegacyTokens(): void {
  try {
    for (const key of LEGACY_TOKEN_KEYS) localStorage.removeItem(key)
  } catch {
    /* see markSignedIn */
  }
}
