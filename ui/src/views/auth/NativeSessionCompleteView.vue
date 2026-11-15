<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<template>
  <v-container class="py-10" data-testid="native-session-complete">
    <v-card max-width="560" class="mx-auto pa-6">
      <template v-if="busy">
        <div class="d-flex align-center ga-3" role="status">
          <v-progress-circular indeterminate size="24" width="2" color="primary" />
          <span>{{ t('auth.nativeSession.completing') }}</span>
        </div>
      </template>
      <template v-else-if="error">
        <h1 class="text-h6 mb-3">{{ t('auth.nativeSession.failedTitle') }}</h1>
        <v-alert type="error" variant="tonal" class="mb-4" role="alert">
          {{ error }}
        </v-alert>
        <v-btn :to="{ name: 'login' }" color="primary" variant="flat">
          {{ t('auth.login') }}
        </v-btn>
      </template>
    </v-card>
  </v-container>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { useRoute, useRouter, type RouteLocationRaw } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { api } from '@/api/client'
import { useAuthStore, type User } from '@/stores/auth'
import { useWsStore } from '@/stores/ws'

interface HandoffTarget {
  purpose:
    | 'remote'
    | 'device_share_remote'
    | 'my_devices'
    | 'device_shares_sent'
    | 'device_shares_received'
    | 'dashboard'
  tenant_id?: string
  agent_id?: string
  share_id?: string
}

interface HandoffCompleteResponse {
  user: User
  target: HandoffTarget
}

const OID_RE = /^[0-9a-f]{24}$/i

function resolveFixedRoute(target: HandoffTarget | undefined | null): RouteLocationRaw | null {
  if (!target || typeof target.purpose !== 'string') return null
  switch (target.purpose) {
    case 'remote':
      if (
        !target.tenant_id ||
        !OID_RE.test(target.tenant_id) ||
        !target.agent_id ||
        !OID_RE.test(target.agent_id) ||
        target.share_id !== undefined
      ) {
        return null
      }
      return {
        path: `/tenant/${target.tenant_id}/agent/${target.agent_id}/remote`,
        query: { desktop: '1' },
      }
    case 'device_share_remote':
      if (
        !target.share_id ||
        !OID_RE.test(target.share_id) ||
        target.tenant_id !== undefined ||
        target.agent_id !== undefined
      ) {
        return null
      }
      return {
        path: `/device-shares/${target.share_id}/remote`,
        query: { desktop: '1' },
      }
    case 'my_devices':
      if (target.tenant_id || target.agent_id || target.share_id) return null
      return { path: '/my-devices', query: { desktop: '1' } }
    case 'device_shares_sent':
      if (target.tenant_id || target.agent_id || target.share_id) return null
      return { path: '/device-shares', query: { desktop: '1', direction: 'sent' } }
    case 'device_shares_received':
      if (target.tenant_id || target.agent_id || target.share_id) return null
      return { path: '/device-shares', query: { desktop: '1', direction: 'received' } }
    case 'dashboard':
      if (target.tenant_id || target.agent_id || target.share_id) return null
      return { path: '/', query: { desktop: '1' } }
    default:
      return null
  }
}

const route = useRoute()
const router = useRouter()
const { t } = useI18n()
const auth = useAuthStore()
const ws = useWsStore()

const busy = ref(true)
const error = ref('')
let alive = true

onUnmounted(() => {
  alive = false
})

onMounted(async () => {
  const handoffId = typeof route.query.handoff_id === 'string' ? route.query.handoff_id : ''
  if (!OID_RE.test(handoffId)) {
    auth.forgetLocalSession()
    ws.disconnect()
    busy.value = false
    error.value = t('auth.nativeSession.invalidHandoff')
    return
  }

  try {
    const res = await api.post<HandoffCompleteResponse>('/native/handoff/complete', {
      handoff_id: handoffId,
    })
    if (!alive) return
    const nextRoute = resolveFixedRoute(res?.target)
    if (
      !res?.user?.id ||
      typeof res.user.email !== 'string' ||
      res.user.email_verified !== true ||
      !nextRoute
    ) {
      throw new Error('invalid handoff response')
    }
    auth.completeNativeHandoff(res.user)
    ws.connect()
    await router.replace(nextRoute)
  } catch {
    if (!alive) return
    auth.forgetLocalSession()
    ws.disconnect()
    busy.value = false
    error.value = t('auth.nativeSession.failed')
  }
})
</script>
