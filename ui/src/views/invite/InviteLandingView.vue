<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-container class="fill-height pa-2 pa-md-4 pa-xl-6" fluid>
    <v-row align="center" justify="center">
      <v-col cols="12" sm="8" md="5">
        <v-card class="pa-4 pa-md-6">
          <!-- Loading -->
          <div v-if="inviteStore.loading" class="text-center py-4 py-md-8">
            <v-progress-circular indeterminate color="primary" />
            <p class="mt-4 text-body-1">{{ t('mh.invite.loading') }}</p>
          </div>

          <!-- Error -->
          <div v-else-if="inviteStore.error" class="text-center py-4 py-md-8">
            <v-icon size="64" color="error">mdi-alert-circle</v-icon>
            <p class="mt-4 text-h6">{{ t('mh.invite.notFound') }}</p>
            <p class="text-body-2 text-medium-emphasis">
              {{ t('mh.invite.invalidLink') }}
            </p>
            <v-btn color="primary" to="/login" class="mt-4">{{ t('mh.invite.goLogin') }}</v-btn>
          </div>

          <!-- Invite info loaded -->
          <template v-else-if="info">
            <v-card-title class="text-center text-h5 mb-2">
              <v-icon color="primary" class="mr-2">mdi-account-plus</v-icon>
              {{ t('mh.invite.invited') }}
            </v-card-title>

            <v-card-subtitle class="text-center mb-4">
              <i18n-t keypath="mh.invite.join" tag="span" scope="global">
                <template #org><strong>{{ info.tenant_name }}</strong></template>
              </i18n-t>
            </v-card-subtitle>

            <v-card-text class="text-center text-body-1 mb-4">
              <v-icon size="20" class="mr-1">mdi-account</v-icon>
              <i18n-t keypath="mh.invite.invitedBy" tag="span" scope="global">
                <template #name><strong>{{ info.inviter_name }}</strong></template>
              </i18n-t>
            </v-card-text>

            <!-- Invalid invite -->
            <v-alert
              v-if="!info.is_valid"
              type="warning"
              variant="tonal"
              class="mb-4"
            >
              {{ t('mh.invite.noLongerValid', { status: info.status }) }}
            </v-alert>

            <!-- Already a member -->
            <template v-else-if="info.already_member">
              <v-alert type="info" variant="tonal" class="mb-4">
                {{ t('mh.invite.alreadyMember') }}
              </v-alert>
              <v-btn
                color="primary"
                block
                size="large"
                :to="tenantRoute"
              >
                {{ t('mh.invite.goTo', { org: info.tenant_name }) }}
              </v-btn>
            </template>

            <!-- Authenticated + valid: Accept button -->
            <template v-else-if="auth.isAuthenticated">
              <v-alert v-if="acceptError" type="error" density="compact" class="mb-4">
                {{ acceptError }}
              </v-alert>
              <v-btn
                color="primary"
                block
                size="large"
                :loading="accepting"
                @click="handleAccept"
              >
                {{ t('mh.invite.accept') }}
              </v-btn>
            </template>

            <!-- Not authenticated: Register / Login buttons -->
            <template v-else>
              <div class="d-flex flex-column ga-3">
                <v-btn
                  color="primary"
                  block
                  size="large"
                  :to="`/register?invite=${code}`"
                >
                  {{ t('mh.invite.registerJoin') }}
                </v-btn>
                <v-btn
                  variant="outlined"
                  block
                  size="large"
                  :to="`/login?invite=${code}`"
                >
                  {{ t('mh.invite.loginJoin') }}
                </v-btn>
              </div>
            </template>
          </template>
        </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useInviteStore } from '@/stores/invite'
import { useAuthStore } from '@/stores/auth'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const route = useRoute()
const router = useRouter()
const inviteStore = useInviteStore()
const auth = useAuthStore()

const code = computed(() => route.params.code as string)
const info = computed(() => inviteStore.inviteInfo)
const accepting = ref(false)
const acceptError = ref<string | null>(null)

const tenantRoute = computed(() => {
  // Route by tenant_id (the server now sends it); older servers without
  // the field fall back to the org picker at '/' — never the broken
  // `/tenant/` 404 this used to produce.
  const id = info.value?.tenant_id
  return id ? `/tenant/${id}` : '/'
})

async function handleAccept() {
  accepting.value = true
  acceptError.value = null
  try {
    const result = await inviteStore.acceptInvite(code.value)
    router.push(`/tenant/${result.tenant_id}`)
  } catch (e) {
    acceptError.value = (e as Error).message
  } finally {
    accepting.value = false
  }
}

onMounted(() => {
  // Store the invite code in sessionStorage for auth flow
  sessionStorage.setItem('pending_invite_code', code.value)
  inviteStore.fetchInviteInfo(code.value)
})
</script>
