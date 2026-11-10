<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-container fluid class="pa-2 pa-md-4 pa-xl-6">
    <h1 class="text-h5 text-md-h4 mb-2">{{ $t('nav.explore') }}</h1>
    <p class="text-medium-emphasis mb-4">{{ t('mh.rooms.discover') }}</p>
    <v-text-field
      v-model="query"
      :label="$t('common.search')"
      prepend-inner-icon="mdi-magnify"
      clearable
      hide-details
      class="mb-4"
      @update:model-value="debounceSearch"
    />

    <v-row v-if="loading">
      <v-col cols="12" class="text-center pa-4 pa-md-6 pa-lg-8">
        <v-progress-circular indeterminate />
      </v-col>
    </v-row>

    <v-row v-else>
      <v-col v-for="room in results" :key="room.id" cols="12" sm="6" md="4">
        <v-card variant="outlined" class="fill-height d-flex flex-column">
          <v-card-title class="d-flex align-center">
            <v-icon class="mr-2" size="small" :color="room.is_open ? 'primary' : undefined">
              {{ room.is_open ? 'mdi-pound' : 'mdi-lock' }}
            </v-icon>
            <span class="text-truncate">{{ room.name }}</span>
          </v-card-title>

          <v-card-text class="flex-grow-1">
            <p v-if="room.topic?.value" class="text-body-2 mb-3">
              {{ room.topic.value }}
            </p>
            <p v-else class="text-body-2 text-medium-emphasis mb-3">
              {{ t('mh.rooms.noTopic') }}
            </p>

            <div class="d-flex align-center text-caption text-medium-emphasis">
              <v-icon size="x-small" class="mr-1">mdi-account-group</v-icon>
              {{ room.member_count }} {{ room.member_count === 1 ? 'member' : 'members' }}
              <template v-if="room.message_count > 0">
                <v-icon size="x-small" class="ml-3 mr-1">mdi-message-text</v-icon>
                {{ room.message_count }} messages
              </template>
            </div>
          </v-card-text>

          <v-card-actions>
            <v-spacer />
            <v-btn
              color="primary"
              variant="tonal"
              size="small"
              prepend-icon="mdi-login"
              @click="join(room.id)"
            >
              {{ $t('room.join') }}
            </v-btn>
          </v-card-actions>
        </v-card>
      </v-col>
    </v-row>

    <v-row v-if="results.length === 0 && !loading && searched">
      <v-col cols="12" class="text-center text-medium-emphasis pa-4 pa-md-6 pa-lg-8">
        <v-icon size="48" class="mb-2">mdi-magnify-close</v-icon>
        <p v-if="query">{{ t('mh.rooms.noMatch', { query }) }}</p>
        <p v-else>{{ t('mh.rooms.noOpen') }}</p>
      </v-col>
    </v-row>
  </v-container>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useRoomStore, type Room } from '@/stores/rooms'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const route = useRoute()
const router = useRouter()
const roomStore = useRoomStore()

const tenantId = computed(() => route.params.tenantId as string)
const query = ref('')
const results = ref<Room[]>([])
const loading = ref(false)
const searched = ref(false)
let searchTimeout: ReturnType<typeof setTimeout> | null = null

function debounceSearch() {
  if (searchTimeout) clearTimeout(searchTimeout)
  searchTimeout = setTimeout(() => doSearch(), 300)
}

async function doSearch() {
  loading.value = true
  searched.value = true
  try {
    results.value = await roomStore.explore(tenantId.value, query.value || '')
  } finally {
    loading.value = false
  }
}

async function join(roomId: string) {
  await roomStore.joinRoom(tenantId.value, roomId)
  router.push({ name: 'room-chat', params: { tenantId: tenantId.value, roomId } })
}

onMounted(() => {
  doSearch()
})
</script>
