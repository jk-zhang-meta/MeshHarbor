<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-container max-width="600" class="pa-2 pa-md-4 pa-xl-6">
    <v-card flat>
      <v-card-title>{{ t('mh.profile.edit') }}</v-card-title>
      <v-card-text>
        <v-form @submit.prevent="save">
          <v-text-field
            v-model="form.display_name"
            :label="t('mh.profile.displayName')"
            :rules="[v => !!v || 'Required']"
            class="mb-3"
          />

          <v-textarea
            v-model="form.bio"
            :label="t('mh.profile.bio')"
            rows="3"
            counter="500"
            :rules="[v => !v || v.length <= 500 || 'Max 500 characters']"
            class="mb-3"
          />

          <v-text-field
            v-model="form.avatar"
            :label="t('mh.profile.avatar')"
            :hint="t('mh.profile.avatarHint')"
            class="mb-3"
          />

          <v-select
            v-model="form.locale"
            :items="locales"
            :label="t('mh.profile.language')"
            class="mb-3"
          />

          <v-select
            v-model="form.timezone"
            :items="timezones"
            :label="t('mh.profile.timezone')"
            class="mb-3"
          />

          <div class="d-flex ga-3">
            <v-btn variant="text" @click="router.back()">{{ t('common.cancel') }}</v-btn>
            <v-btn
              type="submit"
              color="primary"
              :loading="saving"
            >
              {{ t('mh.profile.save') }}
            </v-btn>
          </div>
        </v-form>

        <v-divider class="my-6" />

        <!-- FR-58 P4 — deliberately OUTSIDE the Save form: the toggle takes
             effect immediately (it writes the `subscribers` store, not the
             profile), and coupling it to Save would make "toggled but never
             saved" a silent no-op. Disabled until the state actually loaded —
             a switch rendered from a guess would invert someone's consent. -->
        <div class="d-flex align-center justify-space-between ga-4">
          <div>
            <div class="text-subtitle-2">{{ t('mh.news.productUpdates') }}</div>
            <div class="text-caption text-medium-emphasis">
              {{ t('mh.news.blurb') }}
            </div>
          </div>
          <v-switch
            :model-value="nlSubscribed === true"
            :loading="nlBusy"
            :disabled="nlSubscribed === null || nlBusy"
            color="primary"
            hide-details
            density="compact"
            :aria-label="t('mh.news.subscribeAria')"
            @update:model-value="toggleNewsletter"
          />
        </div>
      </v-card-text>
    </v-card>
  </v-container>
</template>

<script setup lang="ts">
import { reactive, ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useUserStore } from '@/stores/user'
import { useNewsletterPref } from '@/composables/useNewsletterPref'
import { useSnackbar } from '@/composables/useSnackbar'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const router = useRouter()
const authStore = useAuthStore()
const userStore = useUserStore()
const { subscribed: nlSubscribed, busy: nlBusy, load: nlLoad, set: nlSet } = useNewsletterPref()
const { showSuccess, showError } = useSnackbar()

async function toggleNewsletter(value: unknown) {
  const want = value === true
  if (await nlSet(want)) {
    showSuccess(want ? t('mh.news.subscribed') : t('mh.news.unsubscribed'))
  } else {
    showError(t('mh.news.prefFailed'))
  }
}

const saving = ref(false)
const form = reactive({
  display_name: '',
  bio: '',
  avatar: '',
  locale: 'en-US',
  timezone: 'UTC',
})

const locales = ['en-US', 'en-GB', 'de-DE', 'fr-FR', 'es-ES', 'mk-MK']
const timezones = [
  'UTC', 'America/New_York', 'America/Chicago', 'America/Los_Angeles',
  'Europe/London', 'Europe/Berlin', 'Europe/Paris', 'Europe/Skopje',
  'Asia/Tokyo', 'Asia/Shanghai', 'Australia/Sydney',
]

async function save() {
  saving.value = true
  try {
    await userStore.updateProfile({
      display_name: form.display_name || undefined,
      bio: form.bio || undefined,
      avatar: form.avatar || undefined,
      locale: form.locale || undefined,
      timezone: form.timezone || undefined,
    })
    showSuccess(t('mh.profile.saved'))
    router.back()
  } catch (e) {
    showError(e instanceof Error ? e.message : t('mh.profile.saveFailed'))
  } finally {
    saving.value = false
  }
}

onMounted(async () => {
  nlLoad()
  const userId = authStore.user?.id
  if (userId) {
    const profile = await userStore.fetchProfile(userId)
    if (profile) {
      form.display_name = profile.display_name
      form.bio = profile.bio || ''
      form.avatar = profile.avatar || ''
    }
  }
})
</script>
