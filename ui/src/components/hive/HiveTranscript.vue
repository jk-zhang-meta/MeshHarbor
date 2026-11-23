<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  FR-90 P0d-3 — an agent session's transcript, read from the device over a
  viewer peer, with the "ask the agent" composer for a viewer that may drive.
  The room's own composer is "message the room": ordinary chat, which never
  reaches the agent. Who drives is the owner's call (P1c, `HiveParticipants`).

  Assistant text is markdown through the SAME pipeline as chat messages
  (`renderMarkdown`: markdown-it, then DOMPurify — the one XSS boundary for
  message content). Everything else — prompts, tool inputs, tool output — is
  data rendered by text interpolation, never an HTML string.
-->
<template>
  <div class="hive-transcript d-flex flex-column">
    <!-- FR-120 P2 — the header wraps: at 360 px its chips, Copies, Manage,
         People and Reconnect overflowed one row and were clipped. -->
    <div class="d-flex align-center flex-wrap px-3 py-2 ga-2">
      <v-chip size="small" :color="statusColor" variant="tonal" data-testid="hive-viewer-status">
        {{ $t(`hive.viewer.status.${statusKey}`) }}
      </v-chip>
      <v-chip v-if="viewer.runState.value" size="small" variant="outlined">
        {{ $t(`hive.state.${viewer.runState.value}`, viewer.runState.value) }}
      </v-chip>
      <span v-if="viewer.reason.value" class="text-caption text-medium-emphasis text-truncate">
        {{ viewer.reason.value }}
      </span>
      <v-spacer />
      <hive-copies v-if="tenantId" :tenant-id="tenantId" :session-id="sessionId" />
      <hive-manage v-if="tenantId" :tenant-id="tenantId" :session-id="sessionId" />
      <hive-participants v-if="tenantId" :tenant-id="tenantId" :session-id="sessionId" :adopted="adopted" />
      <v-btn
        v-if="viewer.status.value === 'closed' || viewer.status.value === 'refused'"
        size="small"
        variant="text"
        prepend-icon="mdi-refresh"
        @click="viewer.open(sessionId)"
      >
        {{ $t('hive.viewer.reconnect') }}
      </v-btn>
    </div>
    <v-divider />

    <div ref="listRef" class="flex-grow-1 overflow-y-auto pa-3" style="min-height: 0" @scroll="onScroll">
      <div v-if="viewer.hasEarlier.value" class="text-center mb-2">
        <v-btn size="small" variant="text" @click="viewer.loadEarlier()">{{ $t('hive.viewer.loadEarlier') }}</v-btn>
      </div>
      <div
        v-if="viewer.status.value === 'open' && viewer.events.value.length === 0"
        class="text-center text-medium-emphasis pa-6"
      >
        {{ $t('hive.viewer.empty') }}
      </div>
      <div v-for="e in visible" :key="e.seq" class="hive-event mb-2" :data-kind="e.event.kind">
        <template v-if="e.event.kind === 'user_message'">
          <div class="text-caption text-medium-emphasis">
            {{ asText(e.event.author) || (adopted ? $t('hive.viewer.inTerminal') : $t('hive.viewer.someone')) }}
          </div>
          <div class="hive-prompt pa-2 rounded">{{ asText(e.event.text) }}</div>
        </template>
        <!-- eslint-disable-next-line vue/no-v-html -- renderMarkdown is the sanitising boundary -->
        <div v-else-if="e.event.kind === 'assistant_text'" class="hive-assistant" v-html="renderMarkdown(asText(e.event.text))" />
        <details v-else-if="e.event.kind === 'thinking'" class="text-medium-emphasis">
          <summary class="text-caption">{{ $t('hive.viewer.thinking') }}</summary>
          <div class="hive-pre">{{ asText(e.event.summary) }}</div>
        </details>
        <!-- FR-90 P1f — a call by its tool, its result folded under it. -->
        <hive-tool-call
          v-else-if="e.event.kind === 'tool_use'"
          :name="asText(e.event.name)"
          :input="e.event.input"
          :result="resultOf(e.event.id)"
        />
        <!-- A result on its own: after the approval that let its call run,
             or with its call before the loaded window. -->
        <hive-tool-result
          v-else-if="e.event.kind === 'tool_result'"
          :name="callName(e.event.tool_use_id)"
          :result="{ ok: e.event.ok !== false, output: asText(e.event.output), truncated: e.event.truncated === true }"
        />
        <div v-else-if="e.event.kind === 'turn'" class="text-caption text-medium-emphasis hive-turn">
          {{ turnLine(e.event) }}
        </div>
        <div v-else-if="e.event.kind === 'session_init'" class="text-caption text-medium-emphasis">
          {{ $t('hive.viewer.started', { model: asText(e.event.model) || '—', cwd: asText(e.event.cwd) || '—' }) }}
        </div>
        <div v-else-if="e.event.kind === 'note'" class="text-caption text-medium-emphasis">{{ asText(e.event.text) }}</div>
        <!-- FR-90 P1a — a tool call waiting for a driver. The input is the
             model's: text, never markup. -->
        <div
          v-else-if="e.event.kind === 'approval_requested'"
          class="hive-approval pa-2 rounded"
          :data-approval="asText(e.event.id)"
          data-testid="hive-approval"
        >
          <div class="text-body-2 font-weight-medium">
            <v-icon size="small" color="warning">mdi-shield-key</v-icon>
            {{ $t('hive.viewer.approval.asks', { tool: asText(e.event.tool_name) }) }}
          </div>
          <hive-tool-input class="mt-1" :name="asText(e.event.tool_name)" :input="e.event.input" />
          <template v-if="isOpen(e.event.id)">
            <div v-if="viewer.mayAnswer.value" class="d-flex flex-wrap align-center ga-2 mt-2">
              <v-btn
                size="small"
                color="success"
                variant="flat"
                prepend-icon="mdi-check"
                :loading="answering === asText(e.event.id)"
                :disabled="answering !== null"
                data-testid="hive-approve"
                @click="answer(asText(e.event.id), 'allow')"
              >
                {{ $t('hive.viewer.approval.allow') }}
              </v-btn>
              <v-btn
                size="small"
                color="error"
                variant="tonal"
                prepend-icon="mdi-close"
                :disabled="answering !== null"
                data-testid="hive-deny"
                @click="answer(asText(e.event.id), 'deny')"
              >
                {{ $t('hive.viewer.approval.deny') }}
              </v-btn>
              <v-text-field
                v-model="denyNote"
                :placeholder="$t('hive.viewer.approval.denyPlaceholder')"
                density="compact"
                variant="outlined"
                hide-details
                class="hive-deny-note"
                data-testid="hive-deny-note"
              />
            </div>
            <div v-else class="text-caption text-medium-emphasis mt-1">{{ $t('hive.viewer.approval.waiting') }}</div>
          </template>
          <div v-else-if="!resolvedIds.has(asText(e.event.id))" class="text-caption text-medium-emphasis mt-1">
            {{ $t('hive.viewer.approval.unanswered') }}
          </div>
          <div v-if="answerError && answerErrorFor === asText(e.event.id)" class="text-caption text-error mt-1">
            {{ answerError }}
          </div>
        </div>
        <div
          v-else-if="e.event.kind === 'approval_resolved'"
          class="text-caption hive-approval-end"
          data-testid="hive-approval-end"
        >
          {{ resolvedLine(e.event) }}
        </div>
        <div v-else-if="e.event.kind === 'compaction'" class="text-caption text-medium-emphasis">
          {{ $t('hive.viewer.compacted') }}
        </div>
        <div v-else-if="e.event.kind === 'checkpoint'" class="text-caption text-medium-emphasis hive-checkpoint">
          {{ checkpointLine(e.event) }}
        </div>
        <div v-else class="text-caption text-medium-emphasis">
          {{ $t('hive.viewer.unknownKind', { kind: asText(e.event.kind) }) }}
        </div>
      </div>
    </div>

    <template v-if="viewer.mayPrompt.value && viewer.status.value === 'open'">
      <v-divider />
      <div class="pa-2 d-flex align-end ga-2">
        <v-textarea
          v-model="draft"
          :placeholder="$t('hive.viewer.askPlaceholder')"
          auto-grow
          rows="1"
          max-rows="8"
          hide-details
          density="compact"
          variant="outlined"
          data-testid="hive-ask"
          @keydown.enter.exact.prevent="ask"
        />
        <v-btn color="primary" :loading="asking" :disabled="!draft.trim()" icon="mdi-send" @click="ask" />
      </div>
      <div v-if="askError" class="px-3 pb-2 text-caption text-error">{{ askError }}</div>
    </template>
    <div
      v-else-if="viewer.status.value === 'open' && !viewer.mayPrompt.value"
      class="px-3 py-2 text-caption text-medium-emphasis"
      data-testid="hive-read-only"
    >
      <!-- P1c-2 — the server named us a driver, the device does not let us
           act as its account: say so, in the device's words. -->
      <template v-if="adopted">{{ $t('hive.viewer.adoptedReadOnly') }}</template>
      <!-- P2d-5 — a member's copy, served while the device running the
           session cannot: read only, for drivers too. -->
      <template v-else-if="viewer.copy.value">{{ $t('hive.viewer.copyReadOnly') }}</template>
      <template v-else-if="viewer.drivingRefused.value">
        {{ $t('hive.viewer.drivingRefused', { why: viewer.drivingRefused.value }) }}
      </template>
      <template v-else>{{ $t('hive.viewer.readOnly') }}</template>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { renderMarkdown } from '@/composables/useMarkdown'
import { useHiveViewer, withoutRepeatedInits } from '@/composables/useHiveViewer'
import HiveParticipants from '@/components/hive/HiveParticipants.vue'
import HiveCopies from '@/components/hive/HiveCopies.vue'
import HiveManage from '@/components/hive/HiveManage.vue'
import HiveToolCall from '@/components/hive/HiveToolCall.vue'
import HiveToolInput from '@/components/hive/HiveToolInput.vue'
import HiveToolResult from '@/components/hive/HiveToolResult.vue'

const props = withDefaults(
  defineProps<{
    sessionId: string
    tenantId?: string
    /** P1f-2 — how many events the transcript keeps while it follows the newest. */
    keep?: number
    /** P1j — a terminal session adopted on its device: read-only here. */
    adopted?: boolean
  }>(),
  { tenantId: undefined, keep: 1000, adopted: false },
)
const { t } = useI18n()
const viewer = useHiveViewer()
const shown = computed(() => withoutRepeatedInits(viewer.events.value))

// P1f — tool calls and their results, matched by the call's id. A call an
// approval names is drawn by its approval card (the input the answer applies
// to), and its result after the answer; any other call has its result drawn
// under it. A result whose call is not among the events shown stands alone.
type ToolResult = { ok: boolean; output: string; truncated?: boolean }
const tools = computed(() => {
  const names = new Map<string, string>()
  const results = new Map<string, ToolResult>()
  const approved = new Set<string>()
  for (const e of viewer.events.value) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const ev = e.event as any
    if (ev.kind === 'tool_use') names.set(asText(ev.id), asText(ev.name))
    else if (ev.kind === 'tool_result') {
      results.set(asText(ev.tool_use_id), { ok: ev.ok !== false, output: asText(ev.output), truncated: ev.truncated === true })
    } else if (ev.kind === 'approval_requested' && ev.tool_use_id) approved.add(asText(ev.tool_use_id))
  }
  return { names, results, approved }
})
const visible = computed(() => {
  const { approved } = tools.value
  const drawn = new Set<string>()
  for (const e of shown.value) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const id = asText((e.event as any).id)
    if (e.event.kind === 'tool_use' && !approved.has(id)) drawn.add(id)
  }
  return shown.value.filter((e) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const ev = e.event as any
    if (ev.kind === 'tool_use') return !approved.has(asText(ev.id))
    if (ev.kind === 'tool_result') return !drawn.has(asText(ev.tool_use_id))
    return true
  })
})

function resultOf(id: unknown): ToolResult | null {
  return tools.value.results.get(asText(id)) ?? null
}

/** The tool a result came from; empty when its call is not loaded. */
function callName(id: unknown): string {
  return tools.value.names.get(asText(id)) ?? ''
}

const listRef = ref<HTMLElement | null>(null)
const nearBottom = ref(true)
const draft = ref('')
const asking = ref(false)
const askError = ref<string | null>(null)
// P1a — approvals.
const answering = ref<string | null>(null)
const answerError = ref<string | null>(null)
const answerErrorFor = ref<string | null>(null)
const denyNote = ref('')

/** Approvals the transcript already records an end for. */
const resolvedIds = computed(() => {
  const ids = new Set<string>()
  for (const e of viewer.events.value) {
    if (e.event.kind === 'approval_resolved') ids.add(asText((e.event as { id?: unknown }).id))
  }
  return ids
})

function isOpen(id: unknown): boolean {
  return viewer.pendingApprovals.value.includes(asText(id))
}

async function answer(id: string, decision: 'allow' | 'deny'): Promise<void> {
  if (answering.value) return
  answering.value = id
  answerError.value = null
  const note = decision === 'deny' ? denyNote.value.trim() || undefined : undefined
  const res = await viewer.answer(id, decision, note)
  answering.value = null
  if (res.ok) {
    denyNote.value = ''
  } else {
    answerError.value = res.error ?? t('hive.viewer.approval.failed')
    answerErrorFor.value = id
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function resolvedLine(e: any): string {
  const by = asText(e.by) || t('hive.viewer.someone')
  switch (e.outcome) {
    case 'allowed':
      return `✅ ${t('hive.viewer.approval.allowed', { by })}`
    case 'denied':
      return e.message
        ? `⛔ ${t('hive.viewer.approval.deniedWith', { by, message: asText(e.message) })}`
        : `⛔ ${t('hive.viewer.approval.denied', { by })}`
    case 'expired':
      return `⌛ ${t('hive.viewer.approval.expired')}`
    case 'withdrawn':
      return `⏹ ${t('hive.viewer.approval.withdrawn')}`
    default:
      return t('hive.viewer.approval.other', { outcome: asText(e.outcome) })
  }
}

/**
 * FR-90 P2b — what a checkpoint kept for the session's replicas: how many of
 * its files changed, and the folder (committed, unchanged, or not taken, and
 * why). No file's content is ever in the event.
 */
function checkpointLine(e: any): string {
  const files: Array<{ chunks?: unknown[] }> = Array.isArray(e.files) ? e.files : []
  const changed = files.filter((f) => Array.isArray(f.chunks) && f.chunks.length > 0).length
  const head = `💾 ${t('hive.viewer.checkpoint', { n: asText(e.n), changed, files: files.length })}`
  const skipped: Array<{ path?: unknown; why?: unknown }> = Array.isArray(e.skipped) ? e.skipped : []
  const folderSkipped = skipped.find((s) => s.path === 'the workspace')
  if (e.workspace && typeof e.workspace === 'object') {
    const pack = (e.workspace as { pack?: unknown[] }).pack
    const committed = Array.isArray(pack) && pack.length > 0
    return `${head}; ${t(committed ? 'hive.viewer.checkpointFolderCommitted' : 'hive.viewer.checkpointFolderSame')}`
  }
  if (folderSkipped) {
    return `${head}; ${t('hive.viewer.checkpointFolderSkipped', { why: asText(folderSkipped.why) })}`
  }
  return head
}

// FR-90 P2k-6 (F2) — an open view of a member's copy (P2d-5) is not the
// device live: the chip says so, as the read-only note below does.
const statusKey = computed(() =>
  viewer.status.value === 'open' && viewer.copy.value ? 'openCopy' : viewer.status.value,
)

const statusColor = computed(() => {
  switch (statusKey.value) {
    case 'open':
      return 'success'
    case 'openCopy':
      return 'info'
    case 'opening':
    case 'connecting':
      return 'info'
    case 'refused':
      return 'error'
    default:
      return undefined
  }
})

function asText(v: unknown): string {
  return typeof v === 'string' ? v : v == null ? '' : String(v)
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function turnLine(e: any): string {
  const parts = [e.ok === false ? t('hive.viewer.turnError') : t('hive.viewer.turnDone')]
  if (typeof e.duration_ms === 'number') parts.push(`${Math.round(e.duration_ms / 1000)} s`)
  if (typeof e.cost_usd === 'number' && Number.isFinite(e.cost_usd)) parts.push(`$${e.cost_usd.toFixed(2)}`)
  return parts.join(' · ')
}

function onScroll(): void {
  const el = listRef.value
  if (!el) return
  nearBottom.value = el.scrollHeight - el.scrollTop - el.clientHeight < 80
}

watch(
  () => viewer.events.value.length,
  async () => {
    if (!nearBottom.value) return
    // P1f-2 — following the newest, the page stays bounded: the oldest go
    // back to the device. Never while someone reads further up.
    viewer.trimEarlier(props.keep)
    await nextTick()
    const el = listRef.value
    if (el) el.scrollTop = el.scrollHeight
  },
)

async function ask(): Promise<void> {
  const text = draft.value.trim()
  if (!text || asking.value) return
  asking.value = true
  askError.value = null
  const res = await viewer.prompt(text)
  asking.value = false
  if (res.ok) {
    draft.value = ''
    nearBottom.value = true
  } else {
    askError.value = res.error ?? t('hive.viewer.askFailed')
  }
}

onMounted(() => viewer.open(props.sessionId))
watch(
  () => props.sessionId,
  (id) => id && viewer.open(id),
)
</script>

<style scoped>
.hive-transcript {
  height: 100%;
  min-height: 0;
}
.hive-assistant :deep(ol),
.hive-assistant :deep(ul) {
  padding-left: 1.5rem;
}
.hive-prompt {
  white-space: pre-wrap;
  word-break: break-word;
  background: rgba(var(--v-theme-primary), 0.08);
}
.hive-pre {
  white-space: pre-wrap;
  word-break: break-word;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.8rem;
  max-height: 24rem;
  overflow: auto;
  margin: 0;
  padding: 0.5rem;
  border-radius: 4px;
  background: rgba(var(--v-theme-on-surface), 0.05);
}
.hive-error {
  border-left: 3px solid rgb(var(--v-theme-error));
}
.hive-turn {
  border-top: 1px dashed rgba(var(--v-theme-on-surface), 0.2);
  padding-top: 0.25rem;
}
.hive-approval {
  border: 1px solid rgba(var(--v-theme-warning), 0.6);
  background: rgba(var(--v-theme-warning), 0.06);
}
.hive-approval-end {
  padding-left: 0.5rem;
}
.hive-deny-note {
  min-width: 12rem;
  flex: 1 1 12rem;
}
</style>
