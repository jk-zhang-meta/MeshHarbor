// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { defineStore } from 'pinia'
import {
  seedTutorialFromServer,
  type ServerTutorialState,
} from '@/composables/useTutorialProgress'
import { ref, computed } from 'vue'
import { api } from '@/api/client'
import { useAccountApprovalStore } from '@/stores/accountApproval'
import router from '@/plugins/router'
import { subscribePush, unsubscribePush } from '@/composables/usePush'
import { markSignedIn, clearSignedIn, looksSignedIn } from '@/api/session'
import type { SignupAttribution } from '@/utils/attribution'

interface User {
  id: string
  email: string
  username: string
  display_name: string
  avatar?: string
  /** Platform-operator allowlist member (stats PR-4) — gates the
   *  Observability nav/view; the server re-checks every request. */
  is_platform_admin?: boolean
  /** FR-12 P3 — the account's tutorial state, so progress follows the person
   *  and not the browser profile. Absent against an older server. */
  tutorial?: ServerTutorialState
}

export const useAuthStore = defineStore('auth', () => {
  const user = ref<User | null>(null)

  /**
   * Everything that must happen the moment we learn who the caller is.
   *
   * FR-12 P3: the tutorial's server-side state is folded into THIS browser
   * here rather than in a view, because "we just learned who the user is" is
   * the actual event and any route can be the first one they land on. It sat
   * in `AppLayout.maybeAutoOpenTour` first, which was wrong twice over: that
   * function bails on the tutorial route itself and runs at most once per
   * load, and neither condition has anything to do with seeding. Field-caught
   * on prod - a browser with no local state showed `0/8 done` for an account
   * the server said had completed a chapter.
   */
  function adoptSession(u: User) {
    if (user.value?.id !== u.id) useAccountApprovalStore().reset()
    user.value = u
    seedTutorialFromServer(u.id, u.tutorial)
  }

  const loading = ref(false)
  const error = ref<string | null>(null)

  /**
   * Does this browser believe it is signed in?
   *
   * Seeded from the local hint so a hard refresh can render the app shell
   * without waiting for `/auth/me`, then corrected by the server: `fetchMe`
   * logs out if the session is not real. The credential itself is an HttpOnly
   * cookie this code cannot see — see `@/api/session`.
   */
  const signedIn = ref(looksSignedIn())
  const isAuthenticated = computed(() => signedIn.value)

  async function login(username: string, password: string) {
    loading.value = true
    error.value = null
    try {
      // The response still carries tokens; we deliberately ignore them. The
      // session arrived as Set-Cookie on this same response.
      const data = await api.post<{ user: User }>('/auth/login', {
        username,
        password,
      })
      adoptSession(data.user)
      signedIn.value = true
      markSignedIn()
      subscribePush().catch(() => {})
    } catch (e) {
      error.value = (e as Error).message
      throw e
    } finally {
      loading.value = false
    }
  }

  async function register(
    email: string,
    username: string,
    password: string,
    displayName: string,
    inviteCode?: string,
    attribution?: SignupAttribution,
  ) {
    loading.value = true
    error.value = null
    try {
      const body: Record<string, unknown> = {
        email,
        username,
        password,
        display_name: displayName,
      }
      if (inviteCode) body.invite_code = inviteCode
      // FR-88 §3a: where this account came from, sent once, with it. Absent
      // (not `{}`) when there is nothing to say.
      if (attribution && Object.keys(attribution).length > 0) body.attribution = attribution

      const data = await api.post<{
        access_token?: string
        user?: User
        invite_tenant?: { tenant_id: string; tenant_name: string; tenant_slug: string }
      }>('/auth/register', body)
      // Production registration returns no tokens and no user — the account
      // needs email activation first, so this is NOT a session yet. Only the
      // auto-verified path (e2e overlay) signs in, and it sets cookies.
      if (data.user) {
        adoptSession(data.user)
        signedIn.value = true
        markSignedIn()
        subscribePush().catch(() => {})
      }
      return data
    } catch (e) {
      error.value = (e as Error).message
      throw e
    } finally {
      loading.value = false
    }
  }

  /**
   * A session that arrived as a cookie outside `login()`: the OAuth callback,
   * whose redirect carried the Set-Cookie. The flag flips HERE, before
   * `fetchMe()`, which returns early while it is false. The callback used to
   * write only the local hint, which left this flag at the value it was
   * seeded with when the page loaded (`false` after a logout): `user` stayed
   * null and the app bar's user menu (`v-if="isAuthenticated"`) stayed hidden
   * until a reload re-seeded the flag from the hint.
   */
  async function adoptCookieSession() {
    signedIn.value = true
    markSignedIn()
    await fetchMe()
  }

  /**
   * Forget the session locally, without asking the server to expire it: for a
   * callback whose session the server just refused, so there is nothing to
   * expire, and whose error must stay on screen (`logout()` would navigate
   * away from it). The flag and the hint move together, as everywhere else in
   * this store.
   */
  function forgetLocalSession() {
    useAccountApprovalStore().reset()
    user.value = null
    signedIn.value = false
    clearSignedIn()
  }

  async function fetchMe() {
    if (!signedIn.value) return
    try {
      adoptSession(await api.get<User>('/auth/me'))
      subscribePush().catch(() => {})
    } catch {
      // Sign out only if the server REFUSED the session (#1788). The api
      // client makes that call, and clears the signed-in hint when it does:
      // a 401 whose refresh was refused. A 429, a 5xx or a network error
      // leaves the hint alone, because it says nothing about the session.
      // Logging out on one would ask the server to expire a perfectly valid
      // session: measured with a spent rate limit, `/auth/me` answered 429
      // and this line signed the user out for real.
      if (!looksSignedIn()) await logout()
    }
  }

  /**
   * Sign out.
   *
   * ⚠️ The `POST /auth/logout` call is the load-bearing part and it was
   * MISSING: this used to clear `localStorage` and navigate, which looked like
   * a logout only because the SPA then had no token to send. The session
   * COOKIE survived — and the server has always accepted it — so the session
   * was still live for its full 7 days. Now that the cookie IS the credential,
   * a logout that does not ask the server to expire it does not log anyone out.
   *
   * Best-effort: if the request fails (offline, server down) we still clear
   * locally rather than trapping the user in a session they asked to leave.
   */
  async function logout() {
    useAccountApprovalStore().reset()
    unsubscribePush().catch(() => {})
    try {
      await api.post('/auth/logout', {})
    } catch {
      /* clear locally regardless — see above */
    }
    user.value = null
    signedIn.value = false
    clearSignedIn()
    router.push({ name: 'login' })
  }

  return {
    user,
    loading,
    error,
    isAuthenticated,
    login,
    register,
    adoptCookieSession,
    forgetLocalSession,
    fetchMe,
    logout,
  }
})
