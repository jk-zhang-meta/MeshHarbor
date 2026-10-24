<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <div class="files-panel d-flex flex-column">
    <v-toolbar density="compact" flat>
      <v-toolbar-title class="text-body-1">
        {{ $t('call.files') }}
      </v-toolbar-title>
      <v-spacer />
      <v-btn
        icon="mdi-upload"
        variant="text"
        size="small"
        aria-label="Upload a file"
        @click="triggerUpload"
      />
      <!-- Below 960 px the panel covers the video: this is the way back. -->
      <v-btn class="d-md-none" icon="mdi-close" variant="text" size="small" aria-label="Close files" @click="$emit('close')" />
    </v-toolbar>
    <v-divider />

    <div class="flex-grow-1 overflow-y-auto pa-2">
      <!-- Loading -->
      <div v-if="roomStore.filesLoading" class="text-center mt-4">
        <v-progress-circular indeterminate size="24" />
      </div>

      <!-- Empty state -->
      <div
        v-else-if="roomStore.roomFiles.length === 0"
        class="text-center text-medium-emphasis mt-4"
      >
        {{ $t('call.noFiles') }}
      </div>

      <!-- File list -->
      <v-list v-else density="compact" class="pa-0">
        <v-list-item
          v-for="file in roomStore.roomFiles"
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
              v-if="isAudio(file.content_type)"
              icon="mdi-play"
              variant="text"
              size="x-small"
              @click.stop="$emit('play', file)"
            />
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
      </v-list>
    </div>

    <!-- Hidden file input -->
    <input
      ref="fileInputRef"
      type="file"
      accept=".wav,.mp3,.ogg,.webm,.flac,.m4a"
      style="display: none"
      @change="handleFileSelected"
    />
  </div>
</template>

<script setup lang="ts">
import { appPath } from '@/utils/deployment'
import { ref } from 'vue'
import { useRoomStore, type FileEntry } from '@/stores/rooms'

const props = defineProps<{
  tenantId: string
  roomId: string
}>()

defineEmits<{
  play: [file: FileEntry]
  close: []
}>()

const roomStore = useRoomStore()
const fileInputRef = ref<HTMLInputElement | null>(null)

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

function isAudio(contentType: string): boolean {
  return contentType.startsWith('audio/')
}

function fileIcon(contentType: string): string {
  if (contentType.startsWith('audio/')) return 'mdi-music-note'
  if (contentType.startsWith('video/')) return 'mdi-video'
  if (contentType.startsWith('image/')) return 'mdi-image'
  if (contentType.includes('pdf')) return 'mdi-file-pdf-box'
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
</script>

<style scoped>
.files-panel {
  width: 320px;
  min-width: 280px;
  border-left: 1px solid rgba(var(--v-border-color), var(--v-border-opacity));
  background: rgb(var(--v-theme-surface));
}
/* Below 960 px: an overlay of the call's content area, like the chat panel. */
@media (max-width: 959.98px) {
  .files-panel {
    position: absolute;
    top: 0;
    right: 0;
    bottom: 0;
    width: 100%;
    min-width: 0;
    z-index: 5;
    border-left: 0;
  }
}
</style>
