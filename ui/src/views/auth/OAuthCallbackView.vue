<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-container class="fill-height pa-2 pa-md-4 pa-xl-6" fluid>
    <v-row align="center" justify="center">
      <v-col cols="12" sm="6" class="text-center">
        <v-progress-circular v-if="!error" indeterminate color="primary" size="64" />
        <v-alert v-else type="error" class="mt-4">
          {{ error }}
          <template #append>
            <v-btn variant="text" to="/login">Back to login</v-btn>
          </template>
        </v-alert>
      </v-col>
    </v-row>
  </v-container>
</template>

<script setup lang="ts">
import { appPath } from '@/utils/deployment'
import { ref, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useWsStore } from '@/stores/ws'
import { isOAuthSignup, trackGoal } from '@/utils/goals'

const router = useRouter()
const route = useRoute()
const auth = useAuthStore()
const ws = useWsStore()
const error = ref('')

onMounted(async () => {
  // The token arrives in the URL FRAGMENT, which browsers never put on the
  // wire: it is not in the request line nginx logs, and not in `Referer`.
  // The query-string form is still accepted so a cached older SPA (or an
  // older API) keeps working through a deploy; drop it once both sides have
  // rolled and nothing emits `?token=` any more.
  // Nothing to read out of the URL and nothing to store: the session already
  // arrived, as a Set-Cookie on the redirect that landed us here. The token
  // this page used to lift out of the fragment went straight into
  // localStorage, which is exactly what cookie-only sessions exist to stop.
  //
  // The server still appends `#token=` for older cached bundles. We ignore the
  // value but still strip the fragment, so it does not linger in history or
  // get copy-pasted out of the address bar.
  //
  // FR-88 §3b: the one thing read from the URL first is whether this callback
  // CREATED the account (`signup=1`, set by the server).
  const createdAccount = isOAuthSignup(window.location.hash, window.location.search)
  window.history.replaceState({}, '', window.location.pathname)

  // Validate with a RAW fetch, outside the api client. Rationale: on a failed
  // sign-in `auth.fetchMe()` swallows the error (internal catch → logout) and
  // the api client's 401 handler navigates to /login — the user gets silently
  // bounced and this view's error alert never renders (e2e oauth.spec locks
  // the intended behaviour: show "Failed to complete OAuth login" here).
  // Same-origin, so the session cookie rides along by itself.
  const sessionOk = await fetch(appPath('/api/auth/me'))
    .then((r) => r.ok)
    .catch(() => false)
  if (!sessionOk) {
    error.value = 'Failed to complete OAuth login'
    auth.forgetLocalSession()
    return
  }

  // ⚠️ Only now, with the URL cleaned above: purestat sends `location.href`
  // with every event, and the fragment held the access token.
  if (createdAccount) trackGoal('signup')

  try {
    // Through the STORE, never the bare hint: the store was created when this
    // page loaded, signed out after a logout, and only its own flag is what
    // the app bar's user menu and `fetchMe()` read.
    await auth.adoptCookieSession()
    ws.connect()
    // S2: honor a protected deep-link stashed by the router guard
    // (parity with the password login path).
    const pendingRedirect = sessionStorage.getItem('pending_redirect')
    if (
      // Same-origin paths ONLY: `startsWith('/')` alone also admits the
      // protocol-relative `//evil.com` / `/\evil.com` open-redirect forms.
      pendingRedirect &&
      pendingRedirect.startsWith('/') &&
      !pendingRedirect.startsWith('//') &&
      !pendingRedirect.startsWith('/\\')
    ) {
      sessionStorage.removeItem('pending_redirect')
      router.push(pendingRedirect)
    } else {
      router.push({ name: 'dashboard' })
    }
  } catch {
    error.value = 'Failed to complete OAuth login'
    auth.forgetLocalSession()
  }
})
</script>
