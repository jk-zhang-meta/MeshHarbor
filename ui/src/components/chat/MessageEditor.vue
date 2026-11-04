<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <div
    class="message-editor"
    :class="{ 'message-editor--dragover': isDragging }"
    @dragover.prevent="isDragging = true"
    @dragenter.prevent="isDragging = true"
    @dragleave.prevent="isDragging = false"
    @drop.prevent="handleDrop"
  >
    <div class="editor-toolbar d-flex align-center ga-1 px-2 py-1">
      <v-btn
        size="x-small"
        variant="text"
        :color="mode === 'rich' ? 'primary' : undefined"
        @click="toggleMode"
      >
        <v-icon>{{ mode === 'rich' ? 'mdi-format-letter-case' : 'mdi-format-text' }}</v-icon>
        <v-tooltip activator="parent" location="top">
          {{ mode === 'minimal' ? 'Rich text mode' : 'Minimal mode' }}
        </v-tooltip>
      </v-btn>

      <v-divider vertical class="mx-1" />

      <!-- The formatting buttons scroll on their own: in one no-wrap row they
           needed ~596 px, and on a phone attach, emoji, GIF and Send were cut
           off past the editor's edge, with no other way to send on a soft
           keyboard. -->
      <div class="editor-format d-flex align-center ga-1">
      <template v-if="mode === 'rich'">
        <v-btn
          icon="mdi-format-bold"
          size="x-small"
          variant="text"
          :color="editor?.isActive('bold') ? 'primary' : undefined"
          @click="editor?.chain().focus().toggleBold().run()"
        />
        <v-btn
          icon="mdi-format-italic"
          size="x-small"
          variant="text"
          :color="editor?.isActive('italic') ? 'primary' : undefined"
          @click="editor?.chain().focus().toggleItalic().run()"
        />
        <v-btn
          icon="mdi-format-underline"
          size="x-small"
          variant="text"
          :color="editor?.isActive('underline') ? 'primary' : undefined"
          @click="editor?.chain().focus().toggleUnderline().run()"
        />
        <v-btn
          icon="mdi-format-strikethrough"
          size="x-small"
          variant="text"
          :color="editor?.isActive('strike') ? 'primary' : undefined"
          @click="editor?.chain().focus().toggleStrike().run()"
        />

        <v-divider vertical class="mx-1" />

        <v-btn
          icon="mdi-code-tags"
          size="x-small"
          variant="text"
          :color="editor?.isActive('code') ? 'primary' : undefined"
          @click="editor?.chain().focus().toggleCode().run()"
        />
        <v-btn
          icon="mdi-code-braces"
          size="x-small"
          variant="text"
          :color="editor?.isActive('codeBlock') ? 'primary' : undefined"
          @click="editor?.chain().focus().toggleCodeBlock().run()"
        />

        <v-divider vertical class="mx-1" />

        <v-btn
          icon="mdi-format-list-bulleted"
          size="x-small"
          variant="text"
          :color="editor?.isActive('bulletList') ? 'primary' : undefined"
          @click="editor?.chain().focus().toggleBulletList().run()"
        />
        <v-btn
          icon="mdi-format-list-numbered"
          size="x-small"
          variant="text"
          :color="editor?.isActive('orderedList') ? 'primary' : undefined"
          @click="editor?.chain().focus().toggleOrderedList().run()"
        />
        <v-btn
          icon="mdi-format-quote-close"
          size="x-small"
          variant="text"
          :color="editor?.isActive('blockquote') ? 'primary' : undefined"
          @click="editor?.chain().focus().toggleBlockquote().run()"
        />

        <v-divider vertical class="mx-1" />

        <v-btn
          icon="mdi-link"
          size="x-small"
          variant="text"
          :color="editor?.isActive('link') ? 'primary' : undefined"
          @click="toggleLink"
        />
      </template>
      </div>

      <v-spacer />

      <div class="d-flex align-center ga-1 flex-shrink-0">
      <v-btn
        icon="mdi-paperclip"
        size="x-small"
        variant="text"
        @click="triggerFileInput"
      />
      <v-btn
        icon="mdi-emoticon-outline"
        size="x-small"
        variant="text"
        @click="$emit('open-emoji-picker')"
      />
      <!-- `mdi-gif` is not in the bundled @mdi/font (7.x), so this button drew
           nothing at any width. -->
      <v-btn
        icon="mdi-file-gif-box"
        size="x-small"
        variant="text"
        aria-label="GIF"
        @click="$emit('open-giphy-picker')"
      />
      <!-- In both modes: minimal mode sends on Enter, but a phone's keyboard
           is no place to learn that, and rich mode needs Ctrl+Enter, which a
           soft keyboard does not have. -->
      <v-btn
        icon="mdi-send"
        size="x-small"
        variant="text"
        color="primary"
        :aria-label="t('mh.chat.send')"
        @click="handleSend"
      >
        <!-- Explicit: a v-btn renders its default slot INSTEAD of its `icon`,
             and the tooltip below is slot content — so this button used to
             draw no icon at all. -->
        <v-icon>mdi-send</v-icon>
        <v-tooltip activator="parent" location="top">
          {{ mode === 'rich' ? 'Send (Ctrl+Enter)' : 'Send (Enter)' }}
        </v-tooltip>
      </v-btn>
      </div>
    </div>

    <editor-content :editor="editor" class="editor-content" />

    <!-- Hidden file input for attachments -->
    <input
      ref="fileInputRef"
      type="file"
      multiple
      style="display: none"
      @change="handleFileSelect"
    />
  </div>
</template>

<script setup lang="ts">
import { onBeforeUnmount, watch, ref as vueRef } from 'vue'
import { useEditor, EditorContent, VueRenderer } from '@tiptap/vue-3'
import StarterKit from '@tiptap/starter-kit'
import Placeholder from '@tiptap/extension-placeholder'
import Link from '@tiptap/extension-link'
import Underline from '@tiptap/extension-underline'
import Image from '@tiptap/extension-image'
import Mention from '@tiptap/extension-mention'
import { Markdown } from 'tiptap-markdown'
import tippy, { type Instance as TippyInstance } from 'tippy.js'
import MentionList from './MentionList.vue'
import type { MentionItem } from './MentionList.vue'
import { api } from '@/api/client'
import { useSnackbar } from '@/composables/useSnackbar'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const { showError } = useSnackbar()

type EditorMode = 'minimal' | 'rich'

const props = withDefaults(
  defineProps<{
    placeholder?: string
    initialContent?: string
    members?: MentionItem[]
    tenantId?: string
    roomId?: string
  }>(),
  {
    initialContent: '',
    members: () => [],
    tenantId: '',
    roomId: '',
  },
)

export interface MentionData {
  users: string[]
  everyone: boolean
  here: boolean
}

const emit = defineEmits<{
  send: [content: string, mentions: MentionData, attachmentIds: string[]]
  'open-emoji-picker': []
  'open-giphy-picker': []
}>()

const mode = vueRef<EditorMode>(
  (localStorage.getItem('meshharbor-editor-mode') as EditorMode) || 'minimal',
)
// Ensure default is persisted
if (!localStorage.getItem('meshharbor-editor-mode')) {
  localStorage.setItem('meshharbor-editor-mode', 'minimal')
}
const pendingAttachmentIds = vueRef<string[]>([])
const fileInputRef = vueRef<HTMLInputElement | null>(null)
const isDragging = vueRef(false)

function toggleMode() {
  mode.value = mode.value === 'minimal' ? 'rich' : 'minimal'
  localStorage.setItem('meshharbor-editor-mode', mode.value)
}

function triggerFileInput() {
  fileInputRef.value?.click()
}

async function handleFileSelect(event: Event) {
  const input = event.target as HTMLInputElement
  const files = input.files
  if (!files || !props.tenantId) return

  for (const file of Array.from(files)) {
    const formData = new FormData()
    formData.append('file', file)
    if (props.roomId) formData.append('room_id', props.roomId)

    try {
      const result = await api.upload<{ id: string; filename: string; url: string }>(
        `/tenant/${props.tenantId}/file/upload`,
        formData,
      )
      pendingAttachmentIds.value.push(result.id)

      // Insert image or file reference into editor
      if (file.type.startsWith('image/')) {
        editor.value?.chain().focus().setImage({ src: result.url, alt: file.name }).run()
      } else {
        editor.value?.chain().focus().insertContent(`[${file.name}](${result.url})`).run()
      }
    } catch (err) {
      console.error('File upload failed:', err)
      showError(t('mh.chat.uploadFailed'))
    }
  }

  // Reset input
  input.value = ''
}

async function handleDrop(event: DragEvent) {
  isDragging.value = false
  const files = event.dataTransfer?.files
  if (!files || files.length === 0 || !props.tenantId) return

  for (const file of Array.from(files)) {
    const formData = new FormData()
    formData.append('file', file)
    if (props.roomId) formData.append('room_id', props.roomId)

    try {
      const result = await api.upload<{ id: string; filename: string; url: string }>(
        `/tenant/${props.tenantId}/file/upload`,
        formData,
      )
      pendingAttachmentIds.value.push(result.id)

      if (file.type.startsWith('image/')) {
        editor.value?.chain().focus().setImage({ src: result.url, alt: file.name }).run()
      } else {
        editor.value?.chain().focus().insertContent(`[${file.name}](${result.url})`).run()
      }
    } catch (err) {
      console.error('File upload failed:', err)
      showError(t('mh.chat.uploadFailed'))
    }
  }
}

const mentionItems = vueRef<MentionItem[]>([])
const isMentionOpen = vueRef(false)

const editor = useEditor({
  content: props.initialContent,
  extensions: [
    StarterKit.configure({
      // Prevent duplicate extensions — tiptap-markdown may register its own
    }),
    Placeholder.configure({ placeholder: props.placeholder ?? t('mh.chat.writePlaceholder') }),
    Link.configure({ openOnClick: false, autolink: true }),
    Underline,
    Image.configure({ inline: true, allowBase64: false }),
    Markdown.configure({ html: false, transformPastedText: true }),
    Mention.configure({
      HTMLAttributes: {
        class: 'mention',
      },
      suggestion: {
        items: ({ query }: { query: string }) => {
          const q = query.toLowerCase()
          const specialItems: MentionItem[] = [
            { id: '__everyone__', display_name: 'everyone' },
            { id: '__here__', display_name: 'here' },
          ]
          const all = [...specialItems, ...props.members]
          if (!q) return all.slice(0, 10)
          return all
            .filter((item) =>
              (item.display_name || '').toLowerCase().includes(q) ||
              (item.username || '').toLowerCase().includes(q),
            )
            .slice(0, 10)
        },
        // TipTap's SuggestionProps generics don't cleanly intersect
        // with VueRenderer's internal `editor: any`, so the render
        // object is typed loosely (any) and we narrow inside each
        // handler. Shipped this way since the feature landed — the
        // runtime shape is correct, only the static types disagree.
        render: (): any => {
          let component: VueRenderer
          let popup: TippyInstance[]

          return {
            onStart: (renderProps: Record<string, unknown>) => {
              isMentionOpen.value = true
              component = new VueRenderer(MentionList, {
                props: renderProps,
                editor: renderProps.editor as never,
              })

              if (!renderProps.clientRect) return

              popup = tippy('body', {
                getReferenceClientRect: renderProps.clientRect as () => DOMRect,
                appendTo: () => document.body,
                content: component.element ?? undefined,
                showOnCreate: true,
                interactive: true,
                trigger: 'manual',
                placement: 'bottom-start',
              })
            },
            onUpdate(renderProps: Record<string, unknown>) {
              component?.updateProps(renderProps)
              if (renderProps.clientRect) {
                popup?.[0]?.setProps({
                  getReferenceClientRect: renderProps.clientRect as () => DOMRect,
                })
              }
            },
            onKeyDown(renderProps: { event: KeyboardEvent }) {
              if (renderProps.event.key === 'Escape') {
                popup?.[0]?.hide()
                return true
              }
              return (component?.ref as unknown as { onKeyDown: (props: { event: KeyboardEvent }) => boolean })?.onKeyDown(renderProps)
            },
            onExit() {
              isMentionOpen.value = false
              popup?.[0]?.destroy()
              component?.destroy()
            },
          }
        },
      },
    }),
  ],
  editorProps: {
    // A phone's return key reads "send" where Enter sends (minimal mode).
    attributes: () => ({ enterkeyhint: mode.value === 'minimal' ? 'send' : 'enter' }),
    handleKeyDown(_view, event) {
      // In minimal mode: Enter sends, Shift+Enter inserts newline
      if (mode.value === 'minimal' && event.key === 'Enter' && !event.shiftKey) {
        // When mention popup is open, let the mention plugin handle Enter
        if (isMentionOpen.value) return false
        event.preventDefault()
        handleSend()
        return true
      }
      // Rich mode: Ctrl+Enter or Cmd+Enter sends
      if (mode.value === 'rich' && event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
        event.preventDefault()
        handleSend()
        return true
      }
      return false
    },
  },
})

watch(
  () => props.initialContent,
  (val) => {
    if (editor.value && val !== getMarkdown()) {
      editor.value.commands.setContent(val)
    }
  },
)

watch(
  () => props.members,
  (val) => { mentionItems.value = val },
  { immediate: true },
)

/**
 * Custom markdown serializer that walks the TipTap JSON tree.
 * tiptap-markdown silently skips mention nodes (atom: true leaf nodes),
 * so we serialize manually to ensure @[label](id) format.
 */
function getMarkdown(): string {
  if (!editor.value) return ''
  const json = editor.value.getJSON()
  return serializeNode(json).trim()
}

function serializeNode(node: Record<string, unknown>): string {
  const type = node.type as string
  const attrs = (node.attrs || {}) as Record<string, unknown>
  const children = (node.content || []) as Record<string, unknown>[]

  switch (type) {
    case 'doc':
      return children.map(serializeNode).join('')

    case 'paragraph': {
      const inner = children.map(serializeNode).join('')
      return inner + '\n'
    }

    case 'text': {
      let text = (node.text as string) || ''
      const marks = (node.marks || []) as { type: string; attrs?: Record<string, unknown> }[]
      for (const mark of marks) {
        switch (mark.type) {
          case 'bold': text = `**${text}**`; break
          case 'italic': text = `*${text}*`; break
          case 'strike': text = `~~${text}~~`; break
          case 'code': text = `\`${text}\``; break
          case 'link': text = `[${text}](${mark.attrs?.href || ''})`; break
        }
      }
      return text
    }

    case 'mention': {
      const label = (attrs.label as string) || (attrs.id as string) || ''
      const id = (attrs.id as string) || ''
      return `@[${label}](${id})`
    }

    case 'hardBreak':
      return '\n'

    case 'heading': {
      const level = (attrs.level as number) || 1
      const inner = children.map(serializeNode).join('')
      return '#'.repeat(level) + ' ' + inner + '\n'
    }

    case 'blockquote': {
      const inner = children.map(serializeNode).join('')
      return inner.split('\n').filter(Boolean).map((l) => `> ${l}`).join('\n') + '\n'
    }

    case 'codeBlock': {
      const inner = children.map(serializeNode).join('')
      const lang = (attrs.language as string) || ''
      return '```' + lang + '\n' + inner + '```\n'
    }

    case 'bulletList':
      return children.map((child) => {
        const inner = serializeNode(child).trim()
        return `- ${inner}\n`
      }).join('')

    case 'orderedList':
      return children.map((child, i) => {
        const inner = serializeNode(child).trim()
        return `${i + 1}. ${inner}\n`
      }).join('')

    case 'listItem': {
      return children.map(serializeNode).join('').trim()
    }

    case 'horizontalRule':
      return '---\n'

    case 'image': {
      const src = (attrs.src as string) || ''
      const alt = (attrs.alt as string) || ''
      return `![${alt}](${src})`
    }

    default:
      // Fallback: serialize children
      return children.map(serializeNode).join('')
  }
}

function extractMentions(): MentionData {
  const result: MentionData = { users: [], everyone: false, here: false }
  if (!editor.value) return result

  const json = editor.value.getJSON()
  function walk(node: Record<string, unknown>) {
    if (node.type === 'mention' && node.attrs) {
      const attrs = node.attrs as { id?: string }
      if (attrs.id === '__everyone__') {
        result.everyone = true
      } else if (attrs.id === '__here__') {
        result.here = true
      } else if (attrs.id && !result.users.includes(attrs.id)) {
        result.users.push(attrs.id)
      }
    }
    if (Array.isArray(node.content)) {
      for (const child of node.content) {
        walk(child as Record<string, unknown>)
      }
    }
  }
  walk(json as Record<string, unknown>)
  return result
}

function handleSend() {
  const content = getMarkdown().trim()
  if (!content && pendingAttachmentIds.value.length === 0) return
  const mentions = extractMentions()
  emit('send', content || '', mentions, [...pendingAttachmentIds.value])
  pendingAttachmentIds.value = []
  editor.value?.commands.clearContent(true)
}

function toggleLink() {
  if (!editor.value) return
  if (editor.value.isActive('link')) {
    editor.value.chain().focus().unsetLink().run()
  } else {
    const url = window.prompt('URL')
    if (url) {
      editor.value.chain().focus().setLink({ href: url }).run()
    }
  }
}

function insertContent(text: string) {
  editor.value?.chain().focus().insertContent(text).run()
}

function setContent(markdown: string) {
  editor.value?.commands.setContent(markdown)
}

function focus() {
  editor.value?.commands.focus()
}

defineExpose({ insertContent, setContent, focus })

onBeforeUnmount(() => {
  editor.value?.destroy()
})
</script>

<style scoped>
.message-editor {
  border: 1px solid rgba(var(--v-theme-on-surface), 0.2);
  border-radius: 8px;
  overflow: hidden;
  transition: border-color 0.15s;
}
.message-editor--dragover {
  border-color: rgb(var(--v-theme-primary));
  background: rgba(var(--v-theme-primary), 0.04);
}
.editor-toolbar {
  border-bottom: 1px solid rgba(var(--v-theme-on-surface), 0.08);
  background: rgba(var(--v-theme-on-surface), 0.02);
}
.editor-format {
  min-width: 0;
  overflow-x: auto;
  scrollbar-width: none;
}
.editor-format::-webkit-scrollbar {
  display: none;
}
.editor-content {
  min-height: 40px;
  max-height: 200px;
  overflow-y: auto;
  padding: 8px 12px;
}
.editor-content :deep(.tiptap) {
  outline: none;
  min-height: 24px;
}
.editor-content :deep(.tiptap p.is-editor-empty:first-child::before) {
  content: attr(data-placeholder);
  float: left;
  color: rgba(var(--v-theme-on-surface), 0.35);
  pointer-events: none;
  height: 0;
}
.editor-content :deep(.tiptap p) {
  margin: 0;
}
.editor-content :deep(.tiptap code) {
  background: rgba(var(--v-theme-on-surface), 0.08);
  border-radius: 3px;
  padding: 1px 4px;
  font-size: 0.85em;
}
.editor-content :deep(.tiptap pre) {
  background: rgba(var(--v-theme-on-surface), 0.08);
  border-radius: 4px;
  padding: 8px 12px;
  margin: 4px 0;
}
.editor-content :deep(.tiptap blockquote) {
  border-left: 3px solid rgba(var(--v-theme-primary), 0.5);
  padding-left: 12px;
  margin: 4px 0;
}
.editor-content :deep(.mention) {
  color: rgb(var(--v-theme-primary));
  background: rgba(var(--v-theme-primary), 0.1);
  border-radius: 4px;
  padding: 1px 4px;
  font-weight: 500;
}
</style>
