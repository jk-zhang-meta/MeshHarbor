<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <div class="file-panel" data-testid="file-panel">
    <v-text-field
      v-model="search"
      placeholder="Search files..."
      density="compact"
      variant="outlined"
      hide-details
      prepend-inner-icon="mdi-magnify"
      class="mx-3 mt-3"
    >
      <template #append-inner>
        <v-btn icon="mdi-upload" variant="text" size="x-small" @click="triggerUpload" />
      </template>
    </v-text-field>

    <v-list density="compact" class="mt-2">
      <v-list-item v-if="roomStore.filesLoading" class="text-center">
        <v-progress-circular indeterminate size="24" />
      </v-list-item>

      <v-list-item
        v-for="file in filteredFiles"
        :key="file.id"
        class="px-2"
      >
        <template #prepend>
          <v-icon :icon="fileIcon(file.content_type)" size="small" class="mr-2" />
        </template>

        <v-list-item-title class="text-body-2 text-truncate">
          {{ file.filename }}
        </v-list-item-title>
        <v-list-item-subtitle class="text-caption">
          {{ formatSize(file.size) }} &middot; {{ formatDate(file.created_at) }}
        </v-list-item-subtitle>

        <template #append>
          <v-btn
            icon="mdi-download"
            variant="text"
            size="x-small"
            :href="appPath(`/api/tenant/${tenantId}/file/${file.id}/download`)"
            target="_blank"
          />
          <v-btn
            icon="mdi-delete-outline"
            variant="text"
            size="x-small"
            @click.stop="handleDelete(file.id)"
          />
        </template>
      </v-list-item>

      <v-list-item v-if="!roomStore.filesLoading && filteredFiles.length === 0">
        <v-list-item-title class="text-medium-emphasis">No files in this room</v-list-item-title>
      </v-list-item>
    </v-list>

    <!-- Hidden file input -->
    <input
      ref="fileInputRef"
      type="file"
      style="display: none"
      @change="handleFileSelected"
    />
  </div>
</template>

<script setup lang="ts">
import { appPath } from '@/utils/deployment'
import { ref, computed, onMounted, watch } from 'vue'
import { useRoomStore } from '@/stores/rooms'

const props = defineProps<{
  tenantId: string
  roomId: string
}>()

const roomStore = useRoomStore()
const search = ref('')
const fileInputRef = ref<HTMLInputElement | null>(null)

const filteredFiles = computed(() => {
  if (!search.value) return roomStore.roomFiles
  const q = search.value.toLowerCase()
  return roomStore.roomFiles.filter((f) =>
    f.filename.toLowerCase().includes(q),
  )
})

function fileIcon(contentType: string): string {
  if (contentType.startsWith('image/')) return 'mdi-image'
  if (contentType.includes('pdf')) return 'mdi-file-pdf-box'
  if (contentType.startsWith('audio/')) return 'mdi-music-note'
  if (contentType.startsWith('video/')) return 'mdi-video'
  return 'mdi-file'
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function formatDate(iso: string): string {
  const d = new Date(iso)
  return d.toLocaleDateString([], { month: 'short', day: 'numeric' })
}

function triggerUpload() {
  fileInputRef.value?.click()
}

async function handleFileSelected(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return

  try {
    await roomStore.uploadRoomFile(props.tenantId, props.roomId, file)
  } catch (err) {
    console.error('Failed to upload file:', err)
  }

  // Reset input
  input.value = ''
}

async function handleDelete(fileId: string) {
  try {
    await roomStore.deleteRoomFile(props.tenantId, fileId)
  } catch (err) {
    console.error('Failed to delete file:', err)
  }
}

async function fetchFiles() {
  if (!props.tenantId || !props.roomId) return
  await roomStore.fetchRoomFiles(props.tenantId, props.roomId)
}

watch(() => props.roomId, fetchFiles)
onMounted(fetchFiles)
</script>

<style scoped>
.file-panel {
  overflow-y: auto;
}
</style>
