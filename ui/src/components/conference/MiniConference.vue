<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <div class="mini-conference pa-2">
    <div class="d-flex align-center mb-2">
      <v-icon size="small" color="success" class="mr-1">mdi-phone</v-icon>
      <span class="text-caption text-truncate flex-grow-1">{{ conferenceStore.roomName }}</span>
      <v-btn
        icon="mdi-arrow-expand"
        size="x-small"
        variant="text"
        @click="returnToCall"
      >
        <v-tooltip activator="parent" location="top">{{ t('mh.conf.returnToCall') }}</v-tooltip>
      </v-btn>
    </div>

    <!-- Mini video grid (max 4 tiles) — click anywhere to return to call -->
    <div class="mini-grid mb-2" @click="returnToCall" style="cursor: pointer;">
      <!-- Local stream -->
      <div v-if="conferenceStore.localStream" class="mini-tile">
        <video
          ref="localVideoRef"
          autoplay
          muted
          playsinline
          class="mini-video"
        />
        <span class="mini-label">{{ t('mh.conf.you') }}</span>
      </div>

      <!-- Remote streams (up to 3) -->
      <div
        v-for="[key, remote] in visibleStreams"
        :key="key"
        class="mini-tile"
      >
        <video
          :ref="(el) => setRemoteVideoRef(key, el as HTMLVideoElement)"
          autoplay
          playsinline
          class="mini-video"
          :class="{ 'active-speaker': conferenceStore.activeSpeakerKey === key }"
        />
        <span class="mini-label">{{ participantName(remote.userId) }}</span>
      </div>
    </div>

    <!-- Controls -->
    <div class="d-flex justify-center ga-1">
      <v-btn
        :icon="conferenceStore.isMuted ? 'mdi-microphone-off' : 'mdi-microphone'"
        size="x-small"
        :color="conferenceStore.isMuted ? 'error' : undefined"
        variant="tonal"
        @click="conferenceStore.toggleMute()"
      />
      <v-btn
        :icon="conferenceStore.isVideoOn ? 'mdi-video' : 'mdi-video-off'"
        size="x-small"
        :color="!conferenceStore.isVideoOn ? 'error' : undefined"
        variant="tonal"
        @click="conferenceStore.toggleVideo()"
      />
      <v-btn
        icon="mdi-phone-hangup"
        size="x-small"
        color="error"
        variant="tonal"
        @click="handleHangup"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch, nextTick, onMounted } from 'vue'
import { useConferenceStore } from '@/stores/conference'
import { useRoomStore } from '@/stores/rooms'
import { useCallControls } from '@/composables/useCallControls'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const conferenceStore = useConferenceStore()
const roomStore = useRoomStore()

const localVideoRef = ref<HTMLVideoElement | null>(null)
const remoteVideoRefs = new Map<string, HTMLVideoElement>()

// Show at most 3 remote streams (camera only, skip screen shares)
const visibleStreams = computed(() => {
  const entries: [string, { userId: string; connectionId: string; stream: MediaStream; kind: string; source: string }][] = []
  for (const [key, remote] of conferenceStore.remoteStreams) {
    if (key.endsWith(':screen')) continue
    entries.push([key, remote])
    if (entries.length >= 3) break
  }
  return entries
})

function setRemoteVideoRef(key: string, el: HTMLVideoElement | null) {
  if (el) {
    remoteVideoRefs.set(key, el)
    const remote = conferenceStore.remoteStreams.get(key)
    if (remote) {
      el.srcObject = remote.stream
    }
  } else {
    remoteVideoRefs.delete(key)
  }
}

// One copy of return / hang up, shared with the phone's app-bar menu.
const { returnToCall, hangUp: handleHangup } = useCallControls()

/** A participant by name, as the call page labels them (its
 *  `getDisplayName`) — the tile used to show a 6-character user-id prefix. */
function participantName(userId: string): string {
  const p = roomStore.participants.find((x) => x.user_id === userId)
  return p?.display_name || userId.slice(0, 8)
}

// Attach local stream to video element
watch(
  () => conferenceStore.localStream,
  async (stream) => {
    await nextTick()
    if (localVideoRef.value && stream) {
      localVideoRef.value.srcObject = stream
    }
  },
  { immediate: true },
)

// Update remote video elements when streams change
watch(
  () => conferenceStore.remoteStreams.size,
  async () => {
    await nextTick()
    for (const [key, remote] of conferenceStore.remoteStreams) {
      const el = remoteVideoRefs.get(key)
      if (el && el.srcObject !== remote.stream) {
        el.srcObject = remote.stream
      }
    }
  },
)

onMounted(async () => {
  await nextTick()
  if (localVideoRef.value && conferenceStore.localStream) {
    localVideoRef.value.srcObject = conferenceStore.localStream
  }
})
</script>

<style scoped>
.mini-conference {
  border-top: 1px solid rgba(var(--v-border-color), var(--v-border-opacity));
  background: rgba(0, 0, 0, 0.1);
}

.mini-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 4px;
}

.mini-tile {
  position: relative;
  aspect-ratio: 4/3;
  background: #000;
  border-radius: 4px;
  overflow: hidden;
}

.mini-video {
  width: 100%;
  height: 100%;
  object-fit: cover;
}

.mini-video.active-speaker {
  outline: 2px solid rgb(var(--v-theme-success));
}

.mini-label {
  position: absolute;
  bottom: 2px;
  left: 4px;
  font-size: 10px;
  color: white;
  text-shadow: 0 0 3px black;
}
</style>
