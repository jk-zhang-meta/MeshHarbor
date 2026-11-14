<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Device login (`mh login`): approve a device that asked to join one of
     your organizations. The device's name and OS are its own claims; the
     address is what the server saw. -->
<template>
  <v-container data-testid="device-login" class="py-6">
    <v-card max-width="640" class="mx-auto pa-5">
      <h1 class="text-h5 mb-2">{{ t('deviceLogin.title') }}</h1>
      <p class="text-medium-emphasis mb-4">{{ t('deviceLogin.intro') }}</p>

      <v-alert v-if="error" type="error" class="mb-4" role="alert" data-testid="device-login-error">{{ error }}</v-alert>

      <v-alert v-if="done === 'approved'" type="success" data-testid="device-login-approved">
        {{ t('deviceLogin.approved') }}
      </v-alert>
      <v-alert v-else-if="done === 'denied'" type="info" data-testid="device-login-denied">
        {{ t('deviceLogin.denied') }}
      </v-alert>

      <template v-else>
        <v-text-field
          v-if="!preview"
          v-model="code"
          :label="t('deviceLogin.codeLabel')"
          placeholder="XXXXX-XXXXX"
          autocomplete="off"
          :spellcheck="false"
          :disabled="busy"
          data-testid="device-login-code"
          @keyup.enter="load"
        />
        <v-btn v-if="!preview" color="primary" :loading="busy" :disabled="!validCode" data-testid="device-login-lookup" @click="load">
          {{ t('deviceLogin.lookup') }}
        </v-btn>

        <section v-if="preview" aria-label="device" data-testid="device-login-preview">
          <v-list density="compact" class="mb-3">
            <v-list-item :title="preview.device.name" :subtitle="t('deviceLogin.device')" prepend-icon="mdi-laptop" />
            <v-list-item :title="osLabel" :subtitle="t('deviceLogin.os')" prepend-icon="mdi-monitor" />
            <v-list-item :title="preview.client" :subtitle="t('deviceLogin.from')" prepend-icon="mdi-map-marker" />
            <v-list-item :title="displayCode" :subtitle="t('deviceLogin.codeCheck')" prepend-icon="mdi-shield-key" />
          </v-list>
          <v-select
            v-model="tenantId"
            :items="tenantItems"
            :label="t('deviceLogin.org')"
            :disabled="busy"
            data-testid="device-login-org"
          />
          <p class="text-caption text-medium-emphasis mb-3">{{ t('deviceLogin.warning') }}</p>
          <div class="d-flex ga-2">
            <v-btn color="primary" :loading="busy" :disabled="!tenantId" data-testid="device-login-approve" @click="decide(true)">
              {{ t('deviceLogin.approve') }}
            </v-btn>
            <v-btn variant="text" :disabled="busy" data-testid="device-login-deny" @click="decide(false)">
              {{ t('deviceLogin.deny') }}
            </v-btn>
          </div>
        </section>
      </template>
    </v-card>
  </v-container>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { api, ApiError } from '@/api/client'
import { useTenantStore } from '@/stores/tenant'

interface Preview {
  device: { name: string; os: string }
  client: string
  requested_at_ms: number
  expires_at_ms: number
}

const { t } = useI18n()
const route = useRoute()
const tenants = useTenantStore()
const code = ref(typeof route.query.code === 'string' ? route.query.code : '')
const preview = ref<Preview | null>(null)
const tenantId = ref<string | null>(null)
const busy = ref(false)
const error = ref('')
const done = ref<'' | 'approved' | 'denied'>('')

// Same shape the server accepts: 10 consonants, the dash and case optional.
const normalized = computed(() => code.value.replace(/[\s-]/g, '').toUpperCase())
const validCode = computed(() => /^[BCDFGHJKLMNPQRSTVWXZ]{10}$/.test(normalized.value))
const displayCode = computed(() => `${normalized.value.slice(0, 5)}-${normalized.value.slice(5)}`)
const osLabel = computed(() => ({ windows: 'Windows', macos: 'macOS', linux: 'Linux' })[preview.value?.device.os ?? ''] ?? preview.value?.device.os ?? '')
const tenantItems = computed(() => tenants.tenants.map((x) => ({ title: x.name, value: x.id })))

async function load() {
  if (!validCode.value || busy.value) return
  busy.value = true
  error.value = ''
  try {
    if (!tenants.tenants.length) await tenants.fetchTenants()
    const p = await api.post<Preview>('/native/device-login/preview', { user_code: displayCode.value })
    if (!p || !p.device || typeof p.device.name !== 'string') throw new Error('bad preview')
    preview.value = p
    tenantId.value = tenants.current?.id ?? tenants.tenants[0]?.id ?? null
  } catch (e) {
    preview.value = null
    error.value = e instanceof ApiError && e.status === 404 ? t('deviceLogin.notFound') : t('deviceLogin.failed')
  } finally {
    busy.value = false
  }
}

async function decide(approve: boolean) {
  if (busy.value || !preview.value) return
  if (preview.value.expires_at_ms <= Date.now()) {
    preview.value = null
    error.value = t('deviceLogin.notFound')
    return
  }
  busy.value = true
  error.value = ''
  try {
    const r = await api.post<{ status: string }>('/native/device-login/decision', {
      user_code: displayCode.value,
      approve,
      tenant_id: approve ? tenantId.value : null,
    })
    if (r?.status !== (approve ? 'approved' : 'denied')) throw new Error('unexpected')
    done.value = approve ? 'approved' : 'denied'
    preview.value = null
  } catch (e) {
    error.value = e instanceof ApiError && e.status === 403 ? t('deviceLogin.noPermission') : t('deviceLogin.failed')
  } finally {
    busy.value = false
  }
}

onMounted(() => {
  if (validCode.value) void load()
})
</script>
