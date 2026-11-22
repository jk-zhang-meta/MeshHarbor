<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  FR-126 P2 — the meeting whiteboard (Excalidraw). Opening it asks the meeting for the board as
  it is (`media:whiteboard_join`); every edit here goes out as the changed elements, at most
  every 100 ms; the meeting's edits come in through `applyRemote`, which the meeting view calls.
-->
<template>
  <div
    class="whiteboard-panel"
    data-testid="whiteboard"
    :data-state="state"
    :data-element-count="count"
  >
    <div v-if="state === 'loading'" class="wb-overlay">
      <v-progress-circular indeterminate color="primary" />
    </div>
    <div v-else-if="state === 'failed'" class="wb-overlay text-center">
      <div class="mb-3">{{ t('mh.conf.whiteboardFailed') }}</div>
      <v-btn variant="tonal" color="primary" @click="start">{{ t('mh.conf.whiteboardRetry') }}</v-btn>
    </div>
    <div ref="host" class="wb-host" />
  </div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useTheme } from 'vuetify'
import { useWsStore } from '@/stores/ws'
import { BoardSync, liveCount, type BoardElement } from '@/whiteboard/sync'
import type { BoardHandle } from '@/whiteboard/mountExcalidraw'

const props = defineProps<{ roomId: string }>()
const { t, locale } = useI18n()
const theme = useTheme()
const ws = useWsStore()

const host = ref<HTMLElement | null>(null)
const state = ref<'loading' | 'ready' | 'failed'>('loading')
const count = ref(0)

// One message stays far below the server's 512 KiB cap.
const BATCH = 300
const sync = new BoardSync()
let handle: BoardHandle | null = null
let early: (readonly unknown[])[] = []
let pending: readonly unknown[] | null = null
let timer: ReturnType<typeof setTimeout> | null = null
let alive = true

function flush() {
  timer = null
  if (!pending) return
  const out = sync.outgoing(pending as readonly BoardElement[])
  pending = null
  for (let i = 0; i < out.length; i += BATCH) {
    ws.send('media:whiteboard_update', { room_id: props.roomId, elements: out.slice(i, i + BATCH) })
  }
}

function onChange(elements: readonly unknown[]) {
  count.value = liveCount(elements as readonly BoardElement[])
  pending = elements
  if (!timer) timer = setTimeout(flush, 100)
}

/** Elements from the meeting. Before the board is up they wait, and are applied after it. */
function applyRemote(elements: readonly unknown[]) {
  sync.received(elements as readonly BoardElement[])
  if (!handle) {
    early.push(elements)
    return
  }
  handle.applyRemote(elements)
  count.value = liveCount(handle.elements() as readonly BoardElement[])
}

async function start() {
  state.value = 'loading'
  try {
    const scenePromise = ws.waitForMessage('media:whiteboard_scene', 10000)
    ws.send('media:whiteboard_join', { room_id: props.roomId })
    const scene = (await scenePromise) as { elements?: unknown[] }
    const elements = scene?.elements ?? []
    if (import.meta.env.PROD) {
      ;(window as unknown as { EXCALIDRAW_ASSET_PATH?: string }).EXCALIDRAW_ASSET_PATH =
        `${import.meta.env.BASE_URL}excalidraw-assets/`
    }
    const { mountExcalidraw } = await import('@/whiteboard/mountExcalidraw')
    if (!alive || !host.value) return
    sync.received(elements as BoardElement[])
    handle?.destroy()
    handle = mountExcalidraw(host.value, {
      initialElements: elements,
      langCode: String(locale.value).startsWith('zh') ? 'zh-CN' : 'en',
      theme: theme.global.current.value.dark ? 'dark' : 'light',
      onChange,
    })
    for (const q of early.splice(0)) handle.applyRemote(q)
    count.value = liveCount(elements as BoardElement[])
    state.value = 'ready'
  } catch (e) {
    console.warn('[whiteboard] could not open', e)
    if (alive) state.value = 'failed'
  }
}

onMounted(start)
onUnmounted(() => {
  alive = false
  if (timer) clearTimeout(timer)
  flush()
  handle?.destroy()
  handle = null
  early = []
})

defineExpose({ applyRemote })
</script>

<style scoped>
.whiteboard-panel {
  position: relative;
  flex: 1 1 auto;
  min-width: 0;
  height: 100%;
  background: #fff;
}
.wb-host {
  position: absolute;
  inset: 0;
}
.wb-overlay {
  position: absolute;
  inset: 0;
  z-index: 2;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  background: rgba(255, 255, 255, 0.9);
  color: #333;
}
</style>
