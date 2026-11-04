<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-container max-width="600" class="pa-2 pa-md-4 pa-xl-6">
    <div v-if="userStore.loading" class="text-center pa-4 pa-md-6 pa-lg-8">
      <v-progress-circular indeterminate />
    </div>
    <v-card v-else-if="userStore.profile" flat>
      <div class="d-flex align-center pa-4 pa-md-6">
        <v-avatar size="80" color="primary" class="mr-4">
          <v-img v-if="userStore.profile.avatar" :src="userStore.profile.avatar" />
          <span v-else class="text-h4">{{ initial }}</span>
        </v-avatar>
        <div>
          <h2 class="text-h5">{{ userStore.profile.display_name }}</h2>
          <p class="text-medium-emphasis">@{{ userStore.profile.username }}</p>
          <v-chip
            size="small"
            :color="presenceColor"
            class="mt-1"
          >
            {{ ['online', 'idle', 'dnd', 'offline'].includes(userStore.profile.presence) ? t(`mh.profile.presence.${userStore.profile.presence}`) : userStore.profile.presence }}
          </v-chip>
        </div>
        <v-spacer />
        <v-btn
          v-if="isOwnProfile"
          variant="tonal"
          prepend-icon="mdi-pencil"
          :to="{ name: 'profile-edit' }"
        >
          Edit
        </v-btn>
      </div>

      <v-divider />

      <v-card-text>
        <div v-if="userStore.profile.bio" class="mb-4">
          <h3 class="text-subtitle-2 text-medium-emphasis mb-1">{{ t('mh.profile.bio') }}</h3>
          <p>{{ userStore.profile.bio }}</p>
        </div>

        <div>
          <h3 class="text-subtitle-2 text-medium-emphasis mb-1">{{ t('mh.profile.memberSince') }}</h3>
          <p>{{ formatDate(userStore.profile.created_at) }}</p>
        </div>
      </v-card-text>
    </v-card>
  </v-container>
</template>

<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useUserStore } from '@/stores/user'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const route = useRoute()
const authStore = useAuthStore()
const userStore = useUserStore()

const userId = computed(() => route.params.userId as string)
const isOwnProfile = computed(() => userId.value === authStore.user?.id)

const initial = computed(() => {
  const name = userStore.profile?.display_name || '?'
  return name.charAt(0).toUpperCase()
})

const presenceColor = computed(() => {
  switch (userStore.profile?.presence) {
    case 'online': return 'success'
    case 'idle': return 'warning'
    case 'dnd': return 'error'
    default: return undefined
  }
})

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  })
}

onMounted(() => {
  userStore.fetchProfile(userId.value)
})
</script>
