<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-container class="fill-height pa-2 pa-md-4 pa-xl-6" fluid>
    <v-row align="center" justify="center">
      <v-col cols="12" sm="8" md="4">
        <v-card class="pa-3 pa-md-4">
          <v-card-title class="text-center text-h5 mb-4">
            <img :src="brandMark" alt="" width="28" height="28" class="mr-2" style="vertical-align: middle" />
            {{ $t('auth.login') }}
          </v-card-title>

          <div class="text-center text-subtitle-1 mb-4" data-testid="product-name">{{ PRODUCT_TITLE }}</div>

          <v-form ref="formRef" @submit.prevent="handleLogin">
            <!-- No auto-capitalisation, no autocorrect: iOS capitalises the first
                 letter of a text field by default, and the server matches the
                 username exactly — "goran" typed on an iPhone arrived as
                 "Goran" and was refused as invalid credentials. -->
            <v-text-field
              v-model="username"
              :label="$t('auth.username')"
              prepend-inner-icon="mdi-account"
              :rules="[rules.required]"
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

          <v-divider class="my-4" />
          <v-card-text class="text-center pb-2">
            {{ $t('auth.orLoginWith') || 'Or login with' }}
          </v-card-text>
          <div class="d-flex flex-wrap justify-center ga-2 px-4 pb-4">
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

          <v-card-text class="text-center">
            {{ $t('auth.noAccount') }}
            <router-link :to="{ path: '/register', query: onward }">{{ $t('auth.register') }}</router-link>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useDisplay } from 'vuetify'
import { useAuthStore } from '@/stores/auth'
import { useWsStore } from '@/stores/ws'
import { useValidation } from '@/composables/useValidation'
import { useBrand } from '@/composables/useBrand'
import { PRODUCT_TITLE } from '@/utils/product'
import { carriedQuery, signupAttribution, startOAuth, type Landing } from '@/utils/attribution'

const auth = useAuthStore()
// Provider buttons are a real touch target on a phone (28 px at `small`).
const { xs } = useDisplay()
const ws = useWsStore()
const router = useRouter()
const route = useRoute()
const { rules } = useValidation()
const { mark: brandMark } = useBrand()

const formRef = ref()
const username = ref('')
const password = ref('')
const showPassword = ref(false)

const oauthProviders = [
  { name: 'google', label: 'Google', icon: 'mdi-google', color: '#DB4437' },
  { name: 'facebook', label: 'Facebook', icon: 'mdi-facebook', color: '#4267B2' },
  { name: 'github', label: 'GitHub', icon: 'mdi-github', color: '#333' },
  { name: 'linkedin', label: 'LinkedIn', icon: 'mdi-linkedin', color: '#0077B5' },
  { name: 'microsoft', label: 'Microsoft', icon: 'mdi-microsoft', color: '#00A4EF' },
]

// FR-88 §3a — a provider "sign-in" creates the account when there is none, so
// these buttons carry the campaign exactly as the register view's do. The
// server attaches it only to an account it creates; a returning user's is
// ignored. Read from this page's URL, never stored.
function landing(): Landing {
  return { referrer: document.referrer, host: window.location.host, path: route.path }
}
function oauthLogin(provider: string) {
  startOAuth(provider, signupAttribution(route.query, landing()))
}
/** The same keys on the link to the register page. */
const onward = computed(() => carriedQuery(route.query, landing()))

async function handleLogin() {
  const { valid } = await formRef.value.validate()
  if (!valid) return
  try {
    await auth.login(username.value, password.value)
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
