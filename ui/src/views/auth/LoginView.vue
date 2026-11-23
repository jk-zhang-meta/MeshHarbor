<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <auth-shell>
        <div class="mh-auth-form">
          <img :src="brandMark" alt="" width="32" height="32" class="mh-auth-form__mark" />
          <h2 class="mh-auth-form__title">{{ $t('auth.login') }}</h2>
          <div class="mh-auth-form__sub" data-testid="product-name">{{ PRODUCT_TITLE }}</div>

          <v-form ref="formRef" @submit.prevent="handleLogin">
            <!-- Email is the account identity; passwords are never normalized. -->
            <v-text-field
              v-model="email"
              :label="$t('auth.email')"
              prepend-inner-icon="mdi-email"
              type="email"
              inputmode="email"
              :rules="[rules.required, rules.email]"
              autofocus
              autocomplete="username"
              autocapitalize="none"
              autocorrect="off"
              spellcheck="false"
            />
            <v-text-field
              v-model="password"
              :label="$t('auth.password')"
              prepend-inner-icon="mdi-lock"
              :type="showPassword ? 'text' : 'password'"
              :append-inner-icon="showPassword ? 'mdi-eye-off' : 'mdi-eye'"
              :rules="[rules.required]"
              autocomplete="current-password"
              @click:append-inner="showPassword = !showPassword"
            />

            <v-alert v-if="auth.error" type="error" density="compact" class="mb-4">
              {{ auth.error }}
            </v-alert>

            <v-btn
              type="submit"
              color="primary"
              block
              size="large"
              :loading="auth.loading"
            >
              {{ $t('auth.login') }}
            </v-btn>
          </v-form>

          <div class="mh-auth-form__or">
            <span>{{ $t('auth.orLoginWith') || 'Or login with' }}</span>
          </div>
          <div class="d-flex flex-wrap justify-center ga-2 pb-2">
            <v-btn
              v-for="p in oauthProviders"
              :key="p.name"
              @click="oauthLogin(p.name)"
              :color="p.color"
              variant="outlined"
              :size="xs ? 'default' : 'small'"
            >
              <v-icon start>{{ p.icon }}</v-icon>
              {{ p.label }}
            </v-btn>
          </div>

          <div class="mh-auth-form__alt">
            {{ $t('auth.noAccount') }}
            <router-link :to="{ path: '/register', query: onward }">{{ $t('auth.register') }}</router-link>
          </div>
        </div>
  </auth-shell>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useDisplay } from 'vuetify'
import AuthShell from '@/components/auth/AuthShell.vue'
import { useAuthStore } from '@/stores/auth'
import { useWsStore } from '@/stores/ws'
import { useValidation } from '@/composables/useValidation'
import { useBrand } from '@/composables/useBrand'
import { PRODUCT_TITLE } from '@/utils/product'
import { carriedQuery, signupAttribution, startOAuth, type Landing } from '@/utils/attribution'
import { markDeviceLoginOAuthRedirect } from '@/utils/deviceLoginPresence'

const auth = useAuthStore()
// Provider buttons are a real touch target on a phone (28 px at `small`).
const { xs } = useDisplay()
const ws = useWsStore()
const router = useRouter()
const route = useRoute()
const { rules } = useValidation()
const { mark: brandMark } = useBrand()

const formRef = ref()
const email = ref('')
const password = ref('')
const showPassword = ref(false)

const oauthProviders = [
  { name: 'google', label: 'Google', icon: 'mdi-google', color: '#DB4437' },
]

// FR-88 §3a — a provider "sign-in" creates the account when there is none, so
// these buttons carry the campaign exactly as the register view's do. The
// server attaches it only to an account it creates; a returning user's is
// ignored. Read from this page's URL, never stored.
function landing(): Landing {
  return { referrer: document.referrer, host: window.location.host, path: route.path }
}
function oauthLogin(provider: string) {
  markDeviceLoginOAuthRedirect()
  startOAuth(provider, signupAttribution(route.query, landing()))
}
/** The same keys on the link to the register page. */
const onward = computed(() => carriedQuery(route.query, landing()))

async function handleLogin() {
  const { valid } = await formRef.value.validate()
  if (!valid) return
  try {
    await auth.login(email.value, password.value)
    ws.connect()
    // Check for pending invite code
    const pendingInvite = (route.query.invite as string) || sessionStorage.getItem('pending_invite_code')
    // S2: a protected deep-link stashed by the router guard (e.g. the
    // desktop app's "View screen" remote URL) wins over the dashboard.
    const pendingRedirect = sessionStorage.getItem('pending_redirect')
    if (pendingInvite) {
      sessionStorage.removeItem('pending_invite_code')
      router.push({ name: 'invite', params: { code: pendingInvite } })
    } else if (
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
    // error handled by store
  }
}
</script>
