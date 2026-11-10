<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <div :class="['message-bubble', { 'message-bubble--compact': compact, 'message-bubble--unread': unread }]">
    <div class="d-flex align-start">
      <v-avatar size="32" color="primary" class="mr-2 mt-1" v-if="!compact">
        <span class="text-caption">{{ authorInitial }}</span>
      </v-avatar>

      <!-- min-width: 0 lets a long unbroken string (a link, a hash) wrap
           inside the bubble instead of widening the whole message list. -->
      <div class="flex-grow-1" style="min-width: 0">
        <div class="d-flex align-center mb-1">
          <router-link
            v-if="message.author_id"
            :to="{ name: 'profile', params: { userId: message.author_id } }"
            class="text-subtitle-2 font-weight-bold mr-2 text-decoration-none"
            style="color: inherit;"
          >
            {{ message.author_name || 'Unknown' }}
          </router-link>
          <span v-else class="text-subtitle-2 font-weight-bold mr-2">
            {{ message.author_name || 'Unknown' }}
          </span>
          <span class="text-caption text-medium-emphasis">
            {{ formatTime(message.created_at) }}
          </span>
          <span v-if="message.is_edited" class="text-caption text-medium-emphasis ml-1">
            (edited)
          </span>
          <v-spacer />
          <!-- Mouse: the row of actions, shown on hover or keyboard focus —
               and inert while hidden (it used to take taps at opacity 0, so a
               tap near a name could pin a message for the whole room). -->
          <div v-if="!editing" class="message-actions">
            <v-btn icon="mdi-emoticon-outline" size="x-small" variant="text" :aria-label="t('mh.chat.react')" @click="showEmojiPicker = true" />
            <v-btn icon="mdi-reply" size="x-small" variant="text" :aria-label="t('mh.chat.replyInThread')" @click="$emit('reply')" />
            <v-btn
              v-if="editable"
              icon="mdi-pencil"
              size="x-small"
              variant="text"
              :aria-label="t('mh.chat.editMessage')"
              @click="startEditing"
            />
            <v-btn
              v-if="editable"
              icon="mdi-delete"
              size="x-small"
              variant="text"
              color="error"
              :aria-label="t('mh.chat.deleteMessage')"
              @click="showDeleteConfirm = true"
            />
            <v-btn
              :icon="message.is_pinned ? 'mdi-pin-off' : 'mdi-pin'"
              size="x-small"
              variant="text"
              :aria-label="message.is_pinned ? 'Unpin message' : 'Pin message'"
              @click="$emit('pin')"
            />
          </div>
          <!-- Touch: no hover, so the same actions sit behind one ⋮. -->
          <v-menu v-if="!editing" location="bottom end">
            <template #activator="{ props: menuProps }">
              <v-btn
                v-bind="menuProps"
                class="message-actions-touch"
                icon="mdi-dots-vertical"
                size="small"
                variant="text"
                :aria-label="t('mh.chat.actions')"
              />
            </template>
            <v-list density="compact" min-width="200">
              <v-list-item prepend-icon="mdi-emoticon-outline" :title="t('mh.chat.reactShort')" @click="showEmojiPicker = true" />
              <v-list-item prepend-icon="mdi-reply" :title="t('mh.chat.replyInThread')" @click="$emit('reply')" />
              <v-list-item v-if="editable" prepend-icon="mdi-pencil" :title="t('mh.common.edit')" @click="startEditing" />
              <v-list-item
                :prepend-icon="message.is_pinned ? 'mdi-pin-off' : 'mdi-pin'"
                :title="message.is_pinned ? 'Unpin' : 'Pin'"
                @click="$emit('pin')"
              />
              <v-list-item
                v-if="editable"
                prepend-icon="mdi-delete"
                :title="t('mh.common.delete')"
                base-color="error"
                @click="showDeleteConfirm = true"
              />
            </v-list>
          </v-menu>
        </div>

        <!-- Edit mode -->
        <div v-if="editing">
          <message-editor
            ref="editEditorRef"
            :initial-content="message.content"
            :placeholder="t('mh.chat.editPlaceholder')"
            @send="saveEdit"
          />
          <div class="d-flex ga-1 mt-1">
            <v-btn size="x-small" variant="text" @click="cancelEdit">
              {{ t('common.cancel') }} <span class="text-caption ml-1">(Esc)</span>
            </v-btn>
          </div>
        </div>

        <!-- Normal display -->
        <div v-else class="text-body-2 message-content" v-html="renderedContent" />

        <!-- FR-90 P3-4e-3 — a vault approval card: its answer, under its text. -->
        <vault-approval-card
          v-if="tenantId && message.binding?.module === 'vault'"
          :tenant-id="tenantId"
          :approval-id="message.binding.ref"
          :stamp="message.updated_at"
          class="mt-2"
        />

        <!-- Attachments -->
        <div v-if="message.attachments && message.attachments.length > 0" class="mt-2 d-flex flex-wrap ga-2">
          <template v-for="att in message.attachments" :key="att.file_id">
            <v-img
              v-if="att.content_type.startsWith('image/')"
              :src="att.url"
              :alt="att.filename"
              max-width="300"
              max-height="200"
              rounded
              class="cursor-pointer"
              @click="openAttachment(att.url)"
            />
            <v-chip
              v-else
              variant="tonal"
              prepend-icon="mdi-file"
              :href="att.url"
              target="_blank"
            >
              {{ att.filename }}
              <span class="text-caption ml-1">({{ formatFileSize(att.size) }})</span>
            </v-chip>
          </template>
        </div>

        <!-- Reactions -->
        <div v-if="message.reaction_summary.length > 0" class="d-flex flex-wrap ga-1 mt-1">
          <v-chip
            v-for="r in message.reaction_summary"
            :key="r.emoji"
            size="small"
            variant="tonal"
            @click="$emit('react', r.emoji)"
          >
            {{ r.emoji }} {{ r.count }}
          </v-chip>
        </div>

        <!-- Thread indicator -->
        <div
          v-if="message.is_thread_root"
          class="mt-1 text-caption text-primary cursor-pointer d-flex align-center ga-2"
          @click="$emit('reply')"
        >
          <v-icon size="14">mdi-comment-outline</v-icon>
          <span v-if="message.reply_count">{{ t(message.reply_count === 1 ? 'mh.chat.replyOne' : 'mh.chat.replyMany', { n: message.reply_count }) }}</span>
          <span v-else>{{ t('mh.chat.viewThread') }}</span>
          <span v-if="message.last_reply_at" class="text-medium-emphasis">{{ formatRelativeTime(message.last_reply_at) }}</span>
        </div>
      </div>
    </div>

    <!-- Emoji picker for reactions -->
    <emoji-picker
      v-model="showEmojiPicker"
      @select="(emoji: string) => { $emit('react', emoji); showEmojiPicker = false }"
    />

    <!-- Delete confirmation dialog -->
    <v-dialog v-model="showDeleteConfirm" max-width="360">
      <v-card>
        <v-card-title class="text-h6">{{ t('mh.chat.deleteTitle') }}</v-card-title>
        <v-card-text>{{ t('mh.chat.cannotUndo') }}</v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="showDeleteConfirm = false">{{ t('common.cancel') }}</v-btn>
          <v-btn color="error" variant="tonal" @click="confirmDelete">{{ t('mh.common.delete') }}</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, nextTick, onMounted, onBeforeUnmount } from 'vue'
import { renderMarkdown } from '@/composables/useMarkdown'
import EmojiPicker from '@/components/chat/EmojiPicker.vue'
import MessageEditor from '@/components/chat/MessageEditor.vue'
import VaultApprovalCard from '@/components/vault/VaultApprovalCard.vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

interface Reaction {
  emoji: string
  count: number
}

interface Attachment {
  file_id: string
  filename: string
  content_type: string
  size: number
  url: string
  thumbnail_url?: string
}

interface Message {
  id: string
  author_id: string
  author_name: string
  content: string
  is_pinned: boolean
  is_edited: boolean
  is_thread_root: boolean
  reply_count?: number
  last_reply_at?: string
  reaction_summary: Reaction[]
  attachments: Attachment[]
  created_at: string
  updated_at: string
  /** FR-90 — the module a message belongs to, which chat stores and never
   *  reads: `vault` for an approval card (P3-4e). */
  binding?: { module: string; ref: string }
}

const props = defineProps<{
  message: Message
  compact?: boolean
  editable?: boolean
  unread?: boolean
  /** FR-90 P3-4e-3 — the room's organization, for a vault card's answer. */
  tenantId?: string
}>()

const emit = defineEmits<{
  reply: []
  react: [emoji: string]
  pin: []
  edit: [content: string]
  delete: []
}>()

const showEmojiPicker = ref(false)
const showDeleteConfirm = ref(false)
const editing = ref(false)
const editEditorRef = ref<InstanceType<typeof MessageEditor> | null>(null)

const renderedContent = computed(() => renderMarkdown(props.message.content))

const authorInitial = computed(() =>
  (props.message.author_name || '?').charAt(0).toUpperCase(),
)

function formatTime(iso: string): string {
  const d = new Date(iso)
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
}

function formatRelativeTime(iso: string): string {
  const now = Date.now()
  const then = new Date(iso).getTime()
  const diffMs = now - then
  const diffSec = Math.floor(diffMs / 1000)
  if (diffSec < 60) return t('mh.ago.now')
  const diffMin = Math.floor(diffSec / 60)
  if (diffMin < 60) return t('mh.ago.m', { n: diffMin })
  const diffHr = Math.floor(diffMin / 60)
  if (diffHr < 24) return t('mh.ago.h', { n: diffHr })
  const diffDay = Math.floor(diffHr / 24)
  return t('mh.ago.d', { n: diffDay })
}

function startEditing() {
  editing.value = true
  nextTick(() => {
    editEditorRef.value?.focus()
  })
}

function cancelEdit() {
  editing.value = false
}

function saveEdit(content: string) {
  if (content && content !== props.message.content) {
    emit('edit', content)
  }
  editing.value = false
}

function openAttachment(url: string) {
  window.open(url, '_blank')
}

function confirmDelete() {
  showDeleteConfirm.value = false
  emit('delete')
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function handleKeydown(e: KeyboardEvent) {
  if (e.key === 'Escape' && editing.value) {
    cancelEdit()
  }
}

onMounted(() => {
  document.addEventListener('keydown', handleKeydown)
})

onBeforeUnmount(() => {
  document.removeEventListener('keydown', handleKeydown)
})
</script>

<style scoped>
.message-bubble {
  padding: 4px 8px;
  border-radius: 4px;
}
.message-bubble--unread {
  border-left: 3px solid #FF9800;
  background: rgba(255, 152, 0, 0.05);
}
.message-bubble:hover {
  background: rgba(255, 255, 255, 0.04);
}
.message-actions {
  opacity: 0;
  pointer-events: none;
  transition: opacity 0.15s;
}
.message-bubble:hover .message-actions,
.message-actions:focus-within {
  opacity: 1;
  pointer-events: auto;
}
.message-actions-touch {
  display: none;
}
/* A touch screen has no hover: the row could never be seen, only hit. */
@media (hover: none) {
  .message-actions {
    display: none;
  }
  .message-actions-touch {
    display: inline-flex;
  }
}
.message-content {
  overflow-wrap: anywhere;
}

/* Markdown content styles */
.message-content :deep(p) {
  margin: 0 0 4px;
}
.message-content :deep(p:last-child) {
  margin-bottom: 0;
}
.message-content :deep(code) {
  background: rgba(var(--v-theme-on-surface), 0.08);
  border-radius: 3px;
  padding: 1px 4px;
  font-size: 0.85em;
}
.message-content :deep(pre) {
  background: rgba(var(--v-theme-on-surface), 0.08);
  border-radius: 4px;
  padding: 8px 12px;
  overflow-x: auto;
  margin: 4px 0;
}
.message-content :deep(pre code) {
  background: none;
  padding: 0;
}
.message-content :deep(blockquote) {
  border-left: 3px solid rgba(var(--v-theme-primary), 0.5);
  padding-left: 12px;
  margin: 4px 0;
  opacity: 0.85;
}
.message-content :deep(a) {
  color: rgb(var(--v-theme-primary));
  text-decoration: none;
}
.message-content :deep(a:hover) {
  text-decoration: underline;
}
.message-content :deep(ul),
.message-content :deep(ol) {
  margin: 4px 0;
  padding-left: 24px;
}
.message-content :deep(img) {
  max-width: 100%;
  max-height: 300px;
  border-radius: 4px;
}
.message-content :deep(hr) {
  border: none;
  border-top: 1px solid rgba(var(--v-theme-on-surface), 0.12);
  margin: 8px 0;
}
.message-content :deep(.mention) {
  color: rgb(var(--v-theme-primary));
  background: rgba(var(--v-theme-primary), 0.1);
  border-radius: 4px;
  padding: 1px 4px;
  font-weight: 500;
}
</style>
