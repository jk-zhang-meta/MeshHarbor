<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <div class="conference-root">
    <div class="conference-row">
      <div class="conference-main-col">
        <!-- Call header -->
        <v-toolbar density="compact" flat>
          <v-toolbar-title>
            {{ roomStore.current?.name || t('mh.conf.call') }}
          </v-toolbar-title>
          <v-spacer />
          <LayoutSwitcher
            v-if="joined"
            :prefs="layoutCtrl.prefs.value"
            @update:mode="layoutCtrl.setMode"
            @update:max-tiles="layoutCtrl.setMaxTiles"
            @update:hide-non-video="layoutCtrl.setHideNonVideo"
            @update:self-view-mode="layoutCtrl.setSelfViewMode"
          />
          <v-btn
            v-if="joined"
            :icon="showFiles ? 'mdi-folder' : 'mdi-folder-outline'"
            variant="text"
            :color="showFiles ? 'primary' : undefined"
            @click="toggleFiles"
          />
          <!-- Chat is room chat — usable before joining the call too
               (a refreshed /call page used to show no chat until re-join) -->
          <v-btn
            icon
            variant="text"
            :color="showChat ? 'primary' : undefined"
            :aria-label="chatDot ? 'Chat, new messages' : 'Chat'"
            data-testid="call-chat-toggle"
            @click="showChat = !showChat"
          >
            <v-badge :model-value="chatDot" dot color="error">
              <v-icon>{{ showChat ? 'mdi-message-text' : 'mdi-message-text-outline' }}</v-icon>
            </v-badge>
          </v-btn>
          <v-chip size="small" :color="statusColor">
            {{ ['in_progress', 'scheduled', 'ended'].includes(roomStore.current?.conference_status ?? '') ? t(`mh.conf.status.${roomStore.current?.conference_status}`) : roomStore.current?.conference_status }}
          </v-chip>
        </v-toolbar>

        <v-divider />

        <!-- Main content area. position-relative: below 960 px the chat and
             files panels overlay it instead of squeezing the video. -->
        <div class="flex-grow-1 d-flex overflow-hidden position-relative">
          <!-- Video grid -->
          <div class="flex-grow-1 d-flex align-center justify-center bg-black position-relative">
            <!-- Pre-join state -->
            <div v-if="!joined" class="text-center text-white">
              <v-icon size="64" class="mb-4">mdi-video</v-icon>
              <div class="text-h5">{{ t('mh.conf.ready') }}</div>
              <div class="mt-4" style="width: 300px; max-width: 100%; margin: 0 auto;">
                <v-select
                  v-model="conferenceStore.selectedAudioDeviceId"
                  :items="audioInputs"
                  item-title="label"
                  item-value="deviceId"
                  :label="t('mh.conf.microphone')"
                  density="compact"
                  variant="outlined"
                  class="mb-2"
                  hide-details
                  theme="dark"
                />
                <v-select
                  v-model="conferenceStore.selectedVideoDeviceId"
                  :items="videoInputs"
                  item-title="label"
                  item-value="deviceId"
                  :label="t('mh.conf.camera')"
                  density="compact"
                  variant="outlined"
                  class="mb-2"
                  hide-details
                  theme="dark"
                />
              </div>
              <v-btn
                color="primary"
                size="large"
                class="mt-4"
                :loading="joining"
                @click="handleJoin"
              >
                {{ $t('call.join') }}
              </v-btn>
            </div>

            <!-- Active call: dynamic layout -->
            <component
              v-else
              :is="layoutComponent"
              v-bind="layoutProps"
              @toggle-pin="handleTogglePin"
              @request-pip="handlePiP"
              @spotlight="handleSpotlight"
            />

          </div>

          <!-- Files panel -->
          <ConferenceFilesPanel
            v-if="joined && showFiles"
            :tenant-id="tenantId"
            :room-id="roomId"
            @play="handlePlayFile"
            @close="showFiles = false"
          />

          <!-- Chat panel (unified with room messages; available pre-join) -->
          <div
            v-if="showChat"
            class="chat-panel d-flex flex-column"
          >
            <v-toolbar density="compact" flat>
              <v-toolbar-title class="text-body-1">
                {{ $t('call.chat') }}
              </v-toolbar-title>
              <v-spacer />
              <!-- Below 960 px the panel covers the video: this is the way back. -->
              <v-btn class="d-md-none" icon="mdi-close" size="small" :aria-label="t('mh.conf.closeChat')" @click="showChat = false" />
            </v-toolbar>
            <v-divider />

            <!-- Messages list using shared messageStore -->
            <div ref="chatListRef" class="flex-grow-1 overflow-y-auto pa-3">
              <div
                v-if="messageStore.messages.length === 0"
                class="text-center text-medium-emphasis mt-4"
              >
                {{ $t('call.noChatMessages') }}
              </div>
              <div
                v-for="msg in messageStore.messages"
                :key="msg.id"
                class="mb-2"
              >
                <MessageBubble
                  :message="msg"
                  :editable="msg.author_id === currentUserId"
                  compact
                  @reply="handleReplyInChat(msg)"
                  @react="(emoji) => handleReact(msg.id, emoji)"
                  @edit="(content) => handleEdit(msg.id, content)"
                  @delete="handleDelete(msg.id)"
                />
              </div>
            </div>

            <v-divider />

            <!-- Chat input using MessageEditor -->
            <div class="pa-2">
              <MessageEditor
                ref="chatEditorRef"
                :placeholder="$t('call.chatPlaceholder')"
                :members="roomMembers"
                :tenant-id="tenantId"
                :room-id="roomId"
                @send="handleSendChat"
              />
            </div>
          </div>
        </div>

        <!-- Controls bar -->
        <v-toolbar v-if="joined" density="compact" color="grey-darken-4">
          <v-spacer />
          <v-btn
            :icon="conferenceStore.isMuted ? 'mdi-microphone-off' : 'mdi-microphone'"
            :color="conferenceStore.isMuted ? 'error' : undefined"
            @click="conferenceStore.toggleMute()"
          />
          <v-btn
            :icon="conferenceStore.isVideoOn ? 'mdi-video' : 'mdi-video-off'"
            :color="!conferenceStore.isVideoOn ? 'error' : undefined"
            @click="conferenceStore.toggleVideo()"
          />
          <!-- Only where the browser can share a screen: phone browsers have
               no getDisplayMedia, and the button answered a tap with "Screen
               share failed: navigator.mediaDevices.getDisplayMedia is not a
               function". -->
          <v-btn
            v-if="canScreenShare"
            :icon="conferenceStore.isScreenSharing ? 'mdi-monitor-off' : 'mdi-monitor-share'"
            :color="conferenceStore.isScreenSharing ? 'success' : undefined"
            @click="handleScreenShare"
          />
          <v-btn
            v-if="pip.isSupported.value"
            icon="mdi-picture-in-picture-bottom-right"
            :color="pip.isPiPActive.value ? 'primary' : undefined"
            @click="togglePiP"
          />
          <v-btn icon="mdi-phone-hangup" color="error" @click="handleLeave" />
          <v-spacer />
        </v-toolbar>
      </div>
    </div>

    <!-- Confirmation dialog for switching calls -->
    <v-dialog v-model="showSwitchDialog" max-width="400">
      <v-card>
        <v-card-title class="text-h6">{{ t('mh.conf.alreadyTitle') }}</v-card-title>
        <v-card-text>
          {{ t('mh.conf.alreadyBody', { room: conferenceStore.roomName }) }}
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="showSwitchDialog = false">{{ t('common.cancel') }}</v-btn>
          <v-btn color="primary" variant="tonal" @click="confirmSwitch">{{ t('mh.conf.switch') }}</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch, nextTick, type Component } from 'vue'
import { storeToRefs } from 'pinia'
import { useRoute, useRouter } from 'vue-router'
import { useDisplay } from 'vuetify'
import { useAuthStore } from '@/stores/auth'
import { useRoomStore } from '@/stores/rooms'
import { useMessageStore } from '@/stores/messages'
import { useWsStore } from '@/stores/ws'
import { useConferenceStore } from '@/stores/conference'
import { useSnackbar } from '@/composables/useSnackbar'
import { useAudioPlayback } from '@/composables/useAudioPlayback'
import { useConferenceLayout } from '@/composables/useConferenceLayout'
import { usePictureInPicture } from '@/composables/usePictureInPicture'
import LayoutSwitcher from '@/components/conference/LayoutSwitcher.vue'
import ConferenceFilesPanel from '@/components/conference/ConferenceFilesPanel.vue'
import MessageBubble from '@/components/chat/MessageBubble.vue'
import MessageEditor from '@/components/chat/MessageEditor.vue'
import type { MentionData } from '@/components/chat/MessageEditor.vue'
import type { MentionItem } from '@/components/chat/MentionList.vue'
import TiledLayout from '@/components/conference/layouts/TiledLayout.vue'
import SpotlightLayout from '@/components/conference/layouts/SpotlightLayout.vue'
import SidebarLayout from '@/components/conference/layouts/SidebarLayout.vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const route = useRoute()
const router = useRouter()
const authStore = useAuthStore()
const roomStore = useRoomStore()
const messageStore = useMessageStore()
const wsStore = useWsStore()
const conferenceStore = useConferenceStore()
const {
  localStream,
  isMuted: isMutedRef,
  audioLevels: audioLevelsRef,
  activeSpeakerKey: activeSpeakerKeyRef,
} = storeToRefs(conferenceStore)
const pip = usePictureInPicture()
const audioPlayback = useAudioPlayback()
const snackbar = useSnackbar()

const audioInputs = computed(() =>
  conferenceStore.availableDevices
    .filter((d) => d.kind === 'audioinput')
    .map((d, i) => ({ label: d.label || t('mh.conf.device', { n: i }), deviceId: d.deviceId }))
)
const videoInputs = computed(() =>
  conferenceStore.availableDevices
    .filter((d) => d.kind === 'videoinput')
    .map((d, i) => ({ label: d.label || t('mh.conf.device', { n: i }), deviceId: d.deviceId }))
)

const tenantId = computed(() => route.params.tenantId as string)
const roomId = computed(() => route.params.roomId as string)
const joined = ref(false)
const joining = ref(false)
const showChat = ref(false)
const showFiles = ref(false)
// FR-116 — below 960 px the chat and files panels overlay the video, so the
// chat starts closed there (it opened on every join, covering the call) and
// only one panel is open at a time.
const { smAndDown } = useDisplay()
const canScreenShare = typeof navigator !== 'undefined' && !!navigator.mediaDevices?.getDisplayMedia
// A closed chat — the phone's default now — still says when someone wrote: a
// dot on its button. The WS handler never bumps the unread count of the room
// you are in, so arrivals are noticed here (once the first load is in, which
// is not news); the server's count covers what came before the page opened.
const chatUnseen = ref(false)
let chatPrimed = false
const chatDot = computed(
  () => !showChat.value && (chatUnseen.value || (roomStore.unreadCounts[roomId.value] ?? 0) > 0),
)
watch(showChat, async (open) => {
  if (!open) return
  chatUnseen.value = false
  if (smAndDown.value) showFiles.value = false
  // The panel is v-if'd: one opened after the page loaded rendered at its
  // top, the OLDEST message — the scroll on mount and join found no list.
  await nextTick()
  scrollChatToBottom()
})
const showSwitchDialog = ref(false)
const chatEditorRef = ref<InstanceType<typeof MessageEditor> | null>(null)
const chatListRef = ref<HTMLElement | null>(null)
const roomMembers = ref<MentionItem[]>([])

const currentUserId = computed(() => authStore.user?.id)

async function fetchRoomMembers() {
  if (!tenantId.value || !roomId.value) return
  try {
    const members = await roomStore.fetchMembers(tenantId.value, roomId.value)
    roomMembers.value = members.map((m) => ({
      id: m.id,
      user_id: m.user_id,
      display_name: m.display_name,
      username: m.username,
    }))
  } catch {
    // members list not critical
  }
}

const localDisplayName = computed(() => authStore.user?.display_name ?? 'You')

function getDisplayName(userId: string): string {
  const participant = roomStore.participants.find((p) => p.user_id === userId)
  return participant?.display_name || userId.slice(0, 8)
}

const layoutCtrl = useConferenceLayout(
  localStream,
  conferenceStore.remoteStreams,
  isMutedRef,
  audioLevelsRef,
  activeSpeakerKeyRef,
  getDisplayName,
  localDisplayName,
  {
    video: conferenceStore.remoteVideoPaused,
    audio: conferenceStore.remoteAudioPaused,
    narrow: smAndDown,
  },
)

const layoutComponent = computed<Component>(() => {
  switch (layoutCtrl.layout.value.effectiveMode) {
    case 'spotlight': return SpotlightLayout
    case 'sidebar': return SidebarLayout
    default: return TiledLayout
  }
})

const layoutProps = computed(() => {
  const l = layoutCtrl.layout.value
  const selfP = layoutCtrl.selfParticipant.value
  const speakerKey = conferenceStore.activeSpeakerKey

  if (l.effectiveMode === 'tiled') {
    return {
      participants: l.primary,
      selfParticipant: l.selfViewFloating ? selfP : null,
      selfViewFloating: l.selfViewFloating,
      selfViewMode: layoutCtrl.prefs.value.selfViewMode,
      activeSpeakerKey: speakerKey,
    }
  }
  // spotlight or sidebar — `selfViewMode` used to be omitted here, which is
  // why "in grid (cropped/uncropped)" appeared dead: Auto resolves to one of
  // these two for screen shares and for any call of two people (FR-25).
  return {
    primary: l.primary,
    secondary: l.secondary,
    selfParticipant: l.selfViewFloating ? selfP : null,
    selfViewFloating: l.selfViewFloating,
    selfViewMode: layoutCtrl.prefs.value.selfViewMode,
    activeSpeakerKey: speakerKey,
  }
})

function handleTogglePin(streamKey: string) {
  layoutCtrl.togglePin(streamKey)
}

function handleSpotlight(streamKey: string) {
  layoutCtrl.toggleSpotlight(streamKey)
}

/**
 * FR-25 — the tile lookup depends on `data-stream-key`, which no layout was
 * passing, so this silently found nothing and PiP looked broken. The layouts
 * bind it now; a miss here is worth saying out loud rather than swallowing.
 */
async function handlePiP(streamKey: string) {
  const videoEl = document.querySelector(
    `video[data-stream-key="${streamKey}"]`,
  ) as HTMLVideoElement | null
  if (!videoEl) {
    snackbar.showError(t('mh.conf.notOnScreen'))
    return
  }
  const failure = await pip.requestPiP(videoEl)
  if (failure) snackbar.showError(failure)
}

function togglePiP() {
  if (pip.isPiPActive.value) {
    pip.exitPiP()
    return
  }
  // Prefer the speaker, then any remote, then yourself — a solo call used
  // to fall off the end of this and do nothing at all.
  const speakerKey = conferenceStore.activeSpeakerKey
  const firstRemote = conferenceStore.remoteStreams.keys().next().value as string | undefined
  handlePiP(speakerKey || firstRemote || 'local')
}

const statusColor = computed(() => {
  switch (roomStore.current?.conference_status) {
    case 'in_progress': return 'success'
    case 'scheduled': return 'info'
    case 'ended': return 'grey'
    default: return 'warning'
  }
})

function formatTime(iso: string): string {
  const d = new Date(iso)
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

function scrollChatToBottom() {
  if (chatListRef.value) {
    chatListRef.value.scrollTop = chatListRef.value.scrollHeight
  }
}

// Auto-scroll when new messages arrive
watch(
  () => messageStore.messages.length,
  async (n, o) => {
    // FR-116 — someone else wrote while the chat was closed: its dot.
    const last = messageStore.messages[n - 1]
    if (chatPrimed && !showChat.value && n > o && last && last.author_id !== currentUserId.value) {
      chatUnseen.value = true
    }
    await nextTick()
    scrollChatToBottom()
  },
)

async function handleSendChat(content: string, mentions?: MentionData, attachmentIds?: string[]) {
  if (!content && (!attachmentIds || attachmentIds.length === 0)) return
  try {
    await messageStore.sendMessage(tenantId.value, roomId.value, content, undefined, mentions, attachmentIds)
  } catch (err) {
    console.error('Failed to send chat message:', err)
  }
}

function handleReplyInChat(msg: { id: string; author_name: string; content: string }) {
  // Quote the message content as a reply
  const quote = msg.content.split('\n').map((l) => `> ${l}`).join('\n')
  const replyPrefix = `> **${msg.author_name}**:\n${quote}\n\n`
  chatEditorRef.value?.setContent(replyPrefix)
  chatEditorRef.value?.focus()
}

async function handleReact(messageId: string, emoji: string) {
  await messageStore.toggleReaction(tenantId.value, roomId.value, messageId, emoji)
}

async function handleEdit(messageId: string, content: string) {
  await messageStore.editMessage(tenantId.value, roomId.value, messageId, content)
}

async function handleDelete(messageId: string) {
  await messageStore.deleteMessage(tenantId.value, roomId.value, messageId)
}

async function confirmSwitch() {
  showSwitchDialog.value = false
  // Leave the current call first
  if (conferenceStore.tenantId && conferenceStore.roomId) {
    await roomStore.leaveCall(conferenceStore.tenantId, conferenceStore.roomId)
  }
  conferenceStore.leaveRoom()
  // Now join the new call
  await doJoin()
}

async function handleJoin() {
  if (joined.value || joining.value) return

  // If already in a different call, show confirmation dialog
  if (conferenceStore.isInCall && conferenceStore.roomId !== roomId.value) {
    showSwitchDialog.value = true
    return
  }

  // If returning to the same call, just show the full UI
  if (conferenceStore.isInCall && conferenceStore.roomId === roomId.value) {
    joined.value = true
    showChat.value = !smAndDown.value
    window.addEventListener('beforeunload', warnBeforeLeave)
    conferenceStore.startActiveSpeaker()
    wsStore.onMediaMessage('media:audio_playback', audioPlayback.handlePlaybackMessage)
    wsStore.onMediaMessage('media:room_closed', handleMediaRoomClosed)
    await messageStore.fetchMessages(tenantId.value, roomId.value).catch(() => {})
    await roomStore.fetchParticipants(tenantId.value, roomId.value)
    await nextTick()
    scrollChatToBottom()
    return
  }

  await doJoin()
}

// C-4 — the server folds a conference island when its pod loses the
// media-room claim (multi-pod rehome) and pushes media:room_closed with
// reason "rehomed": rejoin transparently — the fresh join lands on the
// surviving owner pod. Other reasons (call actually ended) keep today's
// behavior (room:call_ended drives the teardown).
let rehomeRejoining = false
async function handleMediaRoomClosed(data: { room_id?: string; reason?: string }) {
  if (data.reason !== 'rehomed' || data.room_id !== roomId.value) return
  if (rehomeRejoining || !joined.value) return
  rehomeRejoining = true
  try {
    conferenceStore.leaveRoom()
    joined.value = false
    await doJoin()
  } finally {
    rehomeRejoining = false
  }
}

async function doJoin() {
  joining.value = true
  try {
    await roomStore.startCall(tenantId.value, roomId.value)
    await roomStore.joinCall(tenantId.value, roomId.value)
    await roomStore.fetchRoom(tenantId.value, roomId.value)

    // Use conference store instead of composable
    const rName = roomStore.current?.name || 'Call'
    await conferenceStore.joinRoom(tenantId.value, roomId.value, rName)
    await conferenceStore.produceLocalMedia()
    await roomStore.fetchParticipants(tenantId.value, roomId.value)
    fetchRoomMembers()
    await messageStore.fetchMessages(tenantId.value, roomId.value).catch(() => {})

    joined.value = true
    showChat.value = !smAndDown.value
    window.addEventListener('beforeunload', warnBeforeLeave)

    // Scroll chat to latest message after joining
    await nextTick()
    scrollChatToBottom()

    conferenceStore.startActiveSpeaker()
    wsStore.onMediaMessage('media:audio_playback', audioPlayback.handlePlaybackMessage)
    wsStore.onMediaMessage('media:room_closed', handleMediaRoomClosed)
  } catch (err: unknown) {
    const error = err as Error
    if (error.name === 'NotAllowedError') {
      snackbar.showError(t('mh.conf.denied'))
    } else if (error.name === 'NotFoundError') {
      snackbar.showError(t('mh.conf.noDevice'))
    } else {
      snackbar.showError(t('mh.conf.joinFailed', { error: error.message }))
    }
  } finally {
    joining.value = false
  }
}

async function handleLeave() {
  // Remove beforeunload warning
  window.removeEventListener('beforeunload', warnBeforeLeave)

  // Stop active speaker (store-managed)
  conferenceStore.stopActiveSpeaker()

  // Exit PiP if active
  if (pip.isPiPActive.value) {
    await pip.exitPiP()
  }

  // Clean up audio playback
  audioPlayback.stopCurrentPlayback()
  wsStore.offMediaMessage('media:audio_playback')
  wsStore.offMediaMessage('media:room_closed')

  // Leave via conference store (tears down mediasoup)
  conferenceStore.leaveRoom()
  roomStore.clearRoomFiles()
  await roomStore.leaveCall(tenantId.value, roomId.value)
  joined.value = false
  showChat.value = false
  showFiles.value = false
  router.push(`/tenant/${tenantId.value}`)
}

function toggleFiles() {
  showFiles.value = !showFiles.value
  // One overlay at a time below 960 px (FR-116).
  if (showFiles.value && smAndDown.value) showChat.value = false
  if (showFiles.value) {
    roomStore.fetchRoomFiles(tenantId.value, roomId.value)
  }
}

function handlePlayFile(file: { id: string; url: string; filename: string }) {
  wsStore.send('media:play_audio', {
    room_id: roomId.value,
    file_id: file.id,
  })
}

async function handleScreenShare() {
  if (conferenceStore.isScreenSharing) {
    conferenceStore.stopScreenShare()
  } else {
    try {
      await conferenceStore.startScreenShare()
    } catch (err: unknown) {
      const error = err as Error
      if (error.name === 'AbortError' || error.name === 'NotAllowedError') {
        // User cancelled the screen share picker — do nothing
      } else {
        snackbar.showError(t('mh.conf.shareFailed', { error: error.message }))
      }
    }
  }
}

const warnBeforeLeave = (e: BeforeUnloadEvent) => {
  e.preventDefault()
}

// Auto-mark room messages read while the chat panel is visible. The call
// view has no scroll-observer like ChatView — an open panel means the user
// is reading; debounced so a burst of incoming messages is one API call.
// (Messages read here used to stay unread forever and produce stuck badges.)
let readAllTimer: ReturnType<typeof setTimeout> | null = null
function scheduleMarkAllRead() {
  if (!showChat.value) return
  if (readAllTimer) clearTimeout(readAllTimer)
  readAllTimer = setTimeout(() => {
    roomStore.markAllRead(tenantId.value, roomId.value)
  }, 1200)
}
watch(showChat, (open) => {
  if (open) scheduleMarkAllRead()
})
watch(
  () => messageStore.messages.length,
  () => scheduleMarkAllRead(),
)

onMounted(async () => {
  // Enumerate devices for pre-join selection
  conferenceStore.enumerateDevices()

  try {
    await roomStore.fetchRoom(tenantId.value, roomId.value)
  } catch {
    // Room not found
  }

  // Room chat is available pre-join too: a refreshed /call page used to
  // render no chat (and fetch none) until the user re-joined the call.
  showChat.value = !smAndDown.value
  fetchRoomMembers()
  await messageStore.fetchMessages(tenantId.value, roomId.value).catch(() => {})
  await nextTick()
  scrollChatToBottom()
  // From here a new message is news (the closed chat's dot, FR-116).
  chatPrimed = true

  // If already in call for this room (returned from mini-view), restore full view
  if (conferenceStore.isInCall && conferenceStore.roomId === roomId.value) {
    joined.value = true
    window.addEventListener('beforeunload', warnBeforeLeave)
    conferenceStore.startActiveSpeaker()
    wsStore.onMediaMessage('media:audio_playback', audioPlayback.handlePlaybackMessage)
    await roomStore.fetchParticipants(tenantId.value, roomId.value)
  }
})

onUnmounted(() => {
  window.removeEventListener('beforeunload', warnBeforeLeave)
  if (readAllTimer) clearTimeout(readAllTimer)
})
</script>

<style scoped>
.conference-root {
  display: flex;
  flex-direction: column;
  flex: 1 1 0;
  min-height: 0;
  overflow: hidden;
}
.conference-row {
  display: flex;
  flex: 1 1 0;
  min-height: 0;
  overflow: hidden;
}
.conference-main-col {
  display: flex;
  flex-direction: column;
  flex: 1 1 0;
  min-height: 0;
  min-width: 0;
  overflow: hidden;
}
.chat-panel {
  width: 320px;
  min-width: 280px;
  min-height: 0;
  border-left: 1px solid rgba(var(--v-border-color), var(--v-border-opacity));
  background: rgb(var(--v-theme-surface));
}
/* A 320 px column beside the video squeezed it to nothing on a phone (and
   pushed the chat's own editor off the edge): below 960 px it overlays the
   call's content area instead. */
@media (max-width: 959.98px) {
  .chat-panel {
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
