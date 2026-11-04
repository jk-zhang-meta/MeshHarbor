<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <div>
    <v-list-item
      :to="`/tenant/${tenantId}/room/${room.id}`"
      :style="{ paddingLeft: `${depth * 24 + 16}px` }"
      density="compact"
    >
      <template #prepend>
        <v-icon size="small">
          {{ roomIcon }}
        </v-icon>
      </template>

      <v-list-item-title class="text-body-2">
        {{ room.name }}
      </v-list-item-title>

      <template #append>
        <v-badge
          v-if="room.conference_status === 'in_progress'"
          dot
          color="success"
          inline
          class="mr-1"
        />
        <v-chip v-if="(room.participant_count || 0) > 0 && room.conference_status === 'in_progress'" size="x-small" color="success" variant="tonal" class="mr-1">
          {{ room.participant_count }}
        </v-chip>
        <v-chip v-if="room.member_count > 0" size="x-small" variant="text">
          {{ room.member_count }}
        </v-chip>
        <v-menu>
          <template #activator="{ props: menuProps }">
            <v-btn icon="mdi-dots-vertical" size="x-small" variant="text" v-bind="menuProps" @click.prevent />
          </template>
          <v-list density="compact">
            <v-list-item prepend-icon="mdi-plus" @click="handleCreateChild">
              {{ $t('room.createChild') }}
            </v-list-item>
            <v-list-item v-if="room.has_media" prepend-icon="mdi-video" @click="handleStartCall">
              {{ $t('room.startCall') }}
            </v-list-item>
            <v-list-item prepend-icon="mdi-delete" class="text-error" @click="showDeleteConfirm = true">
              Delete
            </v-list-item>
          </v-list>
        </v-menu>
      </template>
    </v-list-item>

    <!-- Children -->
    <template v-if="children.length > 0">
      <room-tree-item
        v-for="child in children"
        :key="child.id"
        :room="child"
        :tenant-id="tenantId"
        :depth="depth + 1"
      />
    </template>
    <!-- Delete confirmation -->
    <v-dialog v-model="showDeleteConfirm" max-width="400">
      <v-card>
        <v-card-title class="text-h6">{{ t('mh.rooms.deleteTitle', { name: room.name }) }}</v-card-title>
        <v-card-text>{{ t('mh.rooms.deleteBody') }}</v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="showDeleteConfirm = false">{{ t('common.cancel') }}</v-btn>
          <v-btn color="error" variant="tonal" :loading="deleting" @click="handleDelete">{{ t('mh.common.delete') }}</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, inject } from 'vue'
import { useRouter } from 'vue-router'
import { useRoomStore, type Room } from '@/stores/rooms'
import { useSnackbar } from '@/composables/useSnackbar'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const props = defineProps<{
  room: Room
  tenantId: string
  depth: number
}>()

const router = useRouter()
const roomStore = useRoomStore()
const { showSuccess, showError } = useSnackbar()
const createChildRoom = inject<(parentId: string) => void>('createChildRoom')

const showDeleteConfirm = ref(false)
const deleting = ref(false)

const children = computed(() => roomStore.childrenOf(props.room.id))

const roomIcon = computed(() => {
  // The padlock renders from `visibility`, which the server ENFORCES — not
  // from `is_open`, which only means "listed in Explore". Rooms created
  // through the API default to `is_open: false`, so the old condition drew a
  // lock on most rooms in the org while every member could read them: a
  // padlock claiming a privacy that did not exist.
  if (props.room.visibility === 'secret') return 'mdi-eye-off'
  if (props.room.visibility === 'private') return 'mdi-lock'
  if (props.room.has_media) return 'mdi-video'
  if (props.room.parent_id === undefined) return 'mdi-folder'
  return 'mdi-pound'
})

function handleCreateChild() {
  createChildRoom?.(props.room.id)
}

function handleStartCall() {
  router.push({ name: 'room-call', params: { tenantId: props.tenantId, roomId: props.room.id } })
}

async function handleDelete() {
  deleting.value = true
  try {
    await roomStore.deleteRoom(props.tenantId, props.room.id)
    showDeleteConfirm.value = false
    showSuccess(`Room "${props.room.name}" deleted`)
  } catch (e) {
    showError((e as Error).message)
  } finally {
    deleting.value = false
  }
}
</script>
