<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-container fluid class="pa-2 pa-md-4 pa-xl-6">
    <h1 class="text-h5 text-md-h4 mb-2 mb-md-4">{{ $t('nav.dashboard') }}</h1>

    <!-- FR-58 P4 — one-time ask, only on POSITIVE evidence of "not
         subscribed" (a failed load must never prompt), per-user latch. -->
    <v-alert
      v-if="showNewsletterAsk"
      class="mb-4"
      color="primary"
      variant="tonal"
      density="comfortable"
    >
      <div class="d-flex flex-wrap align-center justify-space-between ga-3">
        <div>
          <div class="font-weight-bold">{{ tr('mh.news.getUpdates') }}</div>
          <div class="text-body-2">
            {{ tr('mh.news.blurbTo', { email: authStore.user?.email }) }}
          </div>
        </div>
        <div class="d-flex ga-2">
          <v-btn size="small" color="primary" :loading="nlBusy" @click="acceptNewsletter">
            {{ tr('mh.news.keepPosted') }}
          </v-btn>
          <v-btn size="small" variant="text" @click="dismissNewsletter">{{ tr('mh.news.noThanks') }}</v-btn>
        </div>
      </div>
    </v-alert>

    <v-row v-if="tenantStore.tenants.length === 0">
      <v-col cols="12" md="6">
        <v-card>
          <v-card-title>{{ tr('mh.dash.firstWorkspace') }}</v-card-title>
          <v-card-text>
            <v-form ref="formRef" @submit.prevent="handleCreate">
              <v-text-field v-model="name" :label="tr('mh.dash.workspaceName')" :rules="[rules.required]" @update:model-value="autoSlug" />
              <v-text-field v-model="slug" :label="tr('mh.dash.slug')" :hint="tr('mh.dash.slugHint')" :rules="[rules.required, rules.slug]" @update:model-value="slugTouched = true" />
              <v-btn type="submit" color="primary" class="mt-2">{{ tr('mh.dash.create') }}</v-btn>
            </v-form>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>

    <v-row v-else>
      <v-col v-for="t in tenantStore.tenants" :key="t.id" cols="12" sm="6" md="4">
        <v-card :to="`/tenant/${t.id}`" hover height="100%">
          <v-card-title>
            <v-icon class="mr-2">mdi-domain</v-icon>
            {{ t.name }}
          </v-card-title>
          <v-card-subtitle>{{ t.slug }}</v-card-subtitle>
          <v-card-text v-if="t.description">{{ t.description }}</v-card-text>
        </v-card>
      </v-col>
      <!-- Creating a SECOND org used to be impossible: the create form
           only rendered while you had zero tenants. height=100% on BOTH
           card kinds keeps this one the same height as the org cards. -->
      <v-col cols="12" sm="6" md="4">
        <v-card
          variant="outlined"
          hover
          height="100%"
          class="d-flex align-center justify-center"
          style="min-height: 96px; cursor: pointer"
          @click="showCreate = true"
        >
          <div class="text-center text-medium-emphasis">
            <v-icon size="28">mdi-plus</v-icon>
            <div>{{ tr('mh.dash.newOrg') }}</div>
          </div>
        </v-card>
      </v-col>
    </v-row>

    <v-dialog v-model="showCreate" max-width="420">
      <v-card>
        <v-card-title>{{ tr('mh.dash.newOrg') }}</v-card-title>
        <v-card-text>
          <v-form ref="formRef" @submit.prevent="handleCreate">
            <v-text-field v-model="name" :label="tr('mh.dash.name')" :rules="[rules.required]" @update:model-value="autoSlug" />
            <v-text-field v-model="slug" :label="tr('mh.dash.slug')" :hint="tr('mh.layout.orgSlugHint')" :rules="[rules.required, rules.slug]" @update:model-value="slugTouched = true" />
          </v-form>
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="showCreate = false">{{ tr('common.cancel') }}</v-btn>
          <v-btn color="primary" @click="handleCreate">{{ tr('mh.dash.create') }}</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </v-container>
</template>

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useTenantStore } from '@/stores/tenant'
import { useNewsletterPref } from '@/composables/useNewsletterPref'
import { useSnackbar } from '@/composables/useSnackbar'
import { useValidation } from '@/composables/useValidation'
import { useI18n } from 'vue-i18n'

const { t: tr } = useI18n()

const authStore = useAuthStore()
const tenantStore = useTenantStore()
const router = useRouter()
const { showSuccess, showError } = useSnackbar()
const { rules } = useValidation()

// ── FR-58 P4: the one-time newsletter ask ────────────────────────────────
const { subscribed: nlSubscribed, busy: nlBusy, load: nlLoad, set: nlSet } = useNewsletterPref()
// Until storage proves otherwise, behave as already-dismissed — unreadable
// storage must fail toward not annoying (the tutorial-latch house rule).
const nlDismissed = ref(true)
const askKey = () => `meshharbor:newsletter-ask:${authStore.user?.id ?? 'anon'}`
function readAskDismissed(): boolean {
  try {
    return localStorage.getItem(askKey()) !== null
  } catch {
    return true
  }
}
function latchAsk() {
  try {
    localStorage.setItem(askKey(), new Date().toISOString())
  } catch {
    // Worst case: asked again next visit.
  }
}
const showNewsletterAsk = computed(() => nlSubscribed.value === false && !nlDismissed.value)
async function acceptNewsletter() {
  if (await nlSet(true)) {
    showSuccess(tr('mh.news.subscribedToast'))
    latchAsk()
    nlDismissed.value = true
  } else {
    showError(tr('mh.news.subscribeFailed'))
  }
}
function dismissNewsletter() {
  latchAsk()
  nlDismissed.value = true
}

const formRef = ref()
const name = ref('')
const slug = ref('')
const showCreate = ref(false)
const slugTouched = ref(false)

function autoSlug() {
  if (!slugTouched.value) {
    slug.value = name.value
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
  }
}

async function handleCreate() {
  const { valid } = await formRef.value.validate()
  if (!valid) return
  try {
    const tenant = await tenantStore.createTenant(name.value, slug.value)
    showSuccess(tr('mh.dash.workspaceCreated'))
    router.push(`/tenant/${tenant.id}`)
  } catch (e) {
    const msg = e instanceof Error ? e.message : tr('mh.dash.createFailed')
    // tenants.slug is globally unique — put the dup-key case in words.
    showError(
      msg.includes('duplicate') || msg.includes('E11000')
        ? tr('mh.layout.slugTaken')
        : msg,
    )
  }
}

onMounted(() => {
  tenantStore.fetchTenants()
  nlDismissed.value = readAskDismissed()
  if (!nlDismissed.value) nlLoad()
})
</script>
