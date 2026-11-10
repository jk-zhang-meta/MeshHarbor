<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-container fluid class="pa-2 pa-md-4 pa-xl-6">
    <div class="d-flex align-center mb-2 mb-md-4">
      <h1 class="text-h5 text-md-h4">{{ $t('nav.rooms') }}</h1>
      <v-spacer />
      <v-btn color="primary" prepend-icon="mdi-plus" @click="showCreate = true">
        {{ $t('room.create') }}
      </v-btn>
    </div>

    <v-card v-if="roomStore.loading">
      <v-card-text class="text-center">
        <v-progress-circular indeterminate />
      </v-card-text>
    </v-card>

    <v-card v-else-if="roomStore.rooms.length === 0" variant="outlined" class="text-center pa-4 pa-md-6 pa-lg-8">
      <v-icon size="48" color="medium-emphasis" class="mb-2">mdi-folder-open-outline</v-icon>
      <h2 class="text-h6 mb-2">{{ t('mh.rooms.empty') }}</h2>
      <p class="text-body-2 text-medium-emphasis mb-4">
        {{ t('mh.rooms.emptyBody') }}
      </p>
      <!-- FR-12 — the empty state is exactly where the tour helps. -->
      <v-btn
        size="small"
        variant="text"
        color="primary"
        prepend-icon="mdi-school-outline"
        :to="{ name: 'tutorial', params: { tenantId }, hash: '#rooms' }"
        class="mb-2"
      >
        {{ t('mh.rooms.walkThrough') }}
      </v-btn>
    </v-card>

    <v-list v-else>
      <template v-for="room in roomStore.rootRooms" :key="room.id">
        <room-tree-item :room="room" :tenant-id="tenantId" :depth="0" />
      </template>
    </v-list>

    <!-- Create room dialog -->
    <v-dialog v-model="showCreate" max-width="500">
      <v-card>
        <v-card-title>{{ $t('room.create') }}</v-card-title>
        <v-card-text>
          <v-form ref="formRef">
            <v-text-field v-model="newRoom.name" :label="$t('room.name')" :rules="[rules.required]" />
            <v-select
              v-model="newRoom.parent_id"
              :items="parentOptions"
              item-title="title"
              item-value="value"
              :label="$t('room.parent')"
              clearable
            />
            <v-checkbox v-model="newRoom.is_open" :label="$t('room.open')" />
            <v-checkbox v-model="newRoom.has_media" :label="$t('room.hasMedia')" />
          </v-form>
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn @click="showCreate = false">{{ $t('common.cancel') }}</v-btn>
          <v-btn color="primary" @click="createRoom">{{ $t('common.save') }}</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </v-container>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, reactive, provide } from 'vue'
import { useRoute } from 'vue-router'
import { useRoomStore } from '@/stores/rooms'
import { ApiError } from '@/api/client'
import { useSnackbar } from '@/composables/useSnackbar'
import { useValidation } from '@/composables/useValidation'
import RoomTreeItem from '@/components/rooms/RoomTreeItem.vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const route = useRoute()
const roomStore = useRoomStore()
const { showSuccess, showError } = useSnackbar()
const { rules } = useValidation()

const tenantId = computed(() => route.params.tenantId as string)
const showCreate = ref(false)

const newRoom = reactive({
  name: '',
  is_open: true,
  has_media: false,
  parent_id: null as string | null,
})
const formRef = ref()
const createError = ref<string | null>(null)

const parentOptions = computed(() => [
  { title: t('room.none'), value: null },
  ...roomStore.rooms.map(r => ({ title: r.name, value: r.id })),
])

function openCreateChild(parentId: string) {
  newRoom.parent_id = parentId
  showCreate.value = true
}

provide('createChildRoom', openCreateChild)

async function createRoom() {
  const { valid } = await formRef.value.validate()
  if (!valid) return
  try {
    await roomStore.createRoom(tenantId.value, {
      name: newRoom.name,
      is_open: newRoom.is_open,
      has_media: newRoom.has_media,
      parent_id: newRoom.parent_id ?? undefined,
    })
    showCreate.value = false
    newRoom.name = ''
    newRoom.is_open = true
    newRoom.has_media = false
    newRoom.parent_id = null
    showSuccess(t('mh.rooms.created'))
  } catch (e) {
    if (e instanceof ApiError && typeof (e.data as Record<string, unknown>)?.error === 'string') {
      showError((e.data as Record<string, string>).error)
    } else {
      showError((e as Error).message)
    }
  }
}

onMounted(() => {
  roomStore.fetchRooms(tenantId.value)
})
</script>
