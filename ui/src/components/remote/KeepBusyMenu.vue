<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  FR-92 — the viewer's Keep busy menu.

  The device owns the state: this renders `rc:keep-busy.state` and asks for
  changes through `set`. The form remembers the last choices per device in
  localStorage for convenience only — it is never re-sent on connect, so a
  reconnecting tab cannot undo the host's Stop or another controller's
  choice.
-->
<template>
  <v-menu :close-on-content-click="false" location="bottom end">
    <template #activator="{ props: menuProps }">
      <v-chip
        v-if="state?.on"
        v-bind="menuProps"
        size="small"
        :color="state.phase === 'running' ? 'primary' : undefined"
        variant="flat"
        class="mr-2"
        prepend-icon="mdi-cursor-default-gesture"
        :title="statusLine"
        data-testid="rc-keep-busy-chip"
      >
        {{ chipText }}
      </v-chip>
      <v-btn
        v-else
        v-bind="menuProps"
        icon
        variant="text"
        size="small"
        class="mr-1"
        aria-label="Keep busy"
        title="Keep busy"
        data-testid="rc-keep-busy-btn"
      >
        <v-icon>mdi-cursor-default-gesture-outline</v-icon>
      </v-btn>
    </template>
    <v-card min-width="340" max-width="420" data-testid="rc-keep-busy-menu">
      <v-card-title class="d-flex align-center text-subtitle-1">
        Keep busy
        <v-spacer />
        <v-switch
          :model-value="!!state?.on"
          :disabled="!canToggle"
          color="primary"
          density="compact"
          hide-details
          inset
          aria-label="Keep busy on or off"
          data-testid="rc-keep-busy-switch"
          @update:model-value="onToggle"
        />
      </v-card-title>
      <v-card-text>
        <p class="text-caption mb-2">
          Moves the pointer in a pattern so this computer stays active: no screensaver, idle
          lock or "Away". Anyone using the computer pauses it at once, and it resumes after
          they have been idle for a while. It stays on after you disconnect, until someone
          turns it off.
        </p>
        <p class="text-body-2 mb-2" data-testid="rc-keep-busy-status">{{ statusLine }}</p>
        <p v-if="refusal" class="text-caption text-error mb-2" data-testid="rc-keep-busy-refused">
          {{ refusal }}
        </p>
        <p v-if="!canControl" class="text-caption text-medium-emphasis mb-2">
          This session is view-only, so it can watch keep busy but not change it.
        </p>
        <p
          v-if="state?.warn.includes('focus_follows_mouse')"
          class="text-caption text-warning mb-2"
          data-testid="rc-keep-busy-warn-focus"
        >
          On this computer the keyboard focus follows the pointer. Choose Subtle to keep the
          focus where it is.
        </p>
        <div class="kb-grid mb-3" role="radiogroup" aria-label="Pattern">
          <button
            v-for="p in patterns"
            :key="p.id"
            type="button"
            role="radio"
            class="kb-tile"
            :class="{ 'kb-tile--on': p.id === form.pattern }"
            :aria-checked="p.id === form.pattern"
            :disabled="!canEdit"
            :title="p.label"
            :data-testid="`rc-keep-busy-pattern-${p.id}`"
            @click="choose({ pattern: p.id })"
          >
            <svg viewBox="0 0 48 48" width="36" height="36" aria-hidden="true">
              <path
                :d="previews[p.id]"
                fill="none"
                stroke="currentColor"
                stroke-width="1.6"
                stroke-linejoin="round"
              />
            </svg>
            <span class="kb-label">{{ p.label }}</span>
          </button>
        </div>
        <div class="d-flex align-center ga-3 mb-3 flex-wrap">
          <v-btn-toggle
            :model-value="form.speed"
            density="compact"
            mandatory
            divided
            :disabled="!canEdit"
            aria-label="Speed"
            @update:model-value="(v: KeepBusySpeed) => choose({ speed: v })"
          >
            <v-btn value="slow" size="small">Slow</v-btn>
            <v-btn value="normal" size="small">Normal</v-btn>
            <v-btn value="fast" size="small">Fast</v-btn>
          </v-btn-toggle>
          <v-btn-toggle
            :model-value="form.size"
            density="compact"
            mandatory
            divided
            :disabled="!canEdit"
            aria-label="Size"
            @update:model-value="(v: KeepBusySize) => choose({ size: v })"
          >
            <v-btn value="s" size="small">S</v-btn>
            <v-btn value="m" size="small">M</v-btn>
            <v-btn value="l" size="small">L</v-btn>
          </v-btn-toggle>
        </div>
        <div class="d-flex ga-3">
          <v-select
            :model-value="form.resumeAfterS"
            :items="resumeItems"
            label="Resume after"
            density="compact"
            hide-details
            :disabled="!canEdit"
            @update:model-value="(v: number) => choose({ resumeAfterS: v })"
          />
          <v-select
            :model-value="form.autoOffMin"
            :items="autoOffItems"
            label="Turn off after"
            density="compact"
            hide-details
            :disabled="!canEdit"
            @update:model-value="(v: number) => choose({ autoOffMin: v })"
          />
        </div>
      </v-card-text>
    </v-card>
  </v-menu>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import {
  KEEP_BUSY_AUTO_OFF_CHOICES,
  KEEP_BUSY_PATTERNS,
  KEEP_BUSY_RESUME_CHOICES,
  keepBusyRefusalText,
  keepBusyResumesInS,
  keepBusyStatusLine,
  patternLabel,
  patternPreviewPath,
  type KeepBusyPattern,
  type KeepBusyRequest,
  type KeepBusySize,
  type KeepBusySpeed,
  type KeepBusyState,
} from '@/composables/keepBusy'

const props = defineProps<{
  /** The device's state; `null` until the agent has said something. */
  state: KeepBusyState | null
  /** Does this session hold INPUT? (The device checks it anyway.) */
  canControl: boolean
  /** For the remembered form, per device. */
  agentId: string
  /** FR-92 P8 — the org's default pattern, once the viewer has read it.
   *  Pre-selected ONLY while nothing is remembered for this device and
   *  nothing is running: a person's own last choice wins, and what runs
   *  shows the device's pattern. `null`/absent = circle. */
  defaultPattern?: KeepBusyPattern | null
}>()

const emit = defineEmits<{ set: [req: KeepBusyRequest] }>()

interface Form {
  pattern: KeepBusyPattern
  speed: KeepBusySpeed
  size: KeepBusySize
  resumeAfterS: number
  autoOffMin: number
}

const STORAGE_PREFIX = 'meshharbor-rc-keep-busy.v1:'
const defaults: Form = { pattern: 'circle', speed: 'normal', size: 'm', resumeAfterS: 30, autoOffMin: 0 }

/** The remembered form for this device, or the defaults with the org's
 *  default pattern (when already known) in place of circle. */
function loadForm(): { form: Form; remembered: boolean } {
  try {
    const raw = globalThis.localStorage?.getItem(STORAGE_PREFIX + props.agentId)
    if (raw) return { form: { ...defaults, ...(JSON.parse(raw) as Partial<Form>) }, remembered: true }
  } catch {
    /* a private window or blocked storage: defaults */
  }
  return { form: { ...defaults, pattern: props.defaultPattern ?? defaults.pattern }, remembered: false }
}

const loaded = loadForm()
const form = reactive<Form>(loaded.form)
// True once this device has a remembered choice — from storage, or from a
// choice made in this visit. The org's default never overrides one.
let remembered = loaded.remembered

function saveForm() {
  try {
    globalThis.localStorage?.setItem(STORAGE_PREFIX + props.agentId, JSON.stringify(form))
  } catch {
    /* storage unavailable: the form still works for this visit */
  }
  remembered = true
}

// P8 — the org's default usually arrives after a fetch, once the menu
// exists. It fills the pattern only while nothing is remembered for this
// device and nothing is running.
watch(
  () => props.defaultPattern,
  (p) => {
    if (p && !remembered && !props.state?.on) form.pattern = p
  },
)

// While it is on, the form shows what the DEVICE is doing.
watch(
  () => props.state,
  (s) => {
    if (s?.on) {
      form.pattern = s.pattern
      form.speed = s.speed
      form.size = s.size
      form.resumeAfterS = s.resumeAfterS
    }
  },
  { immediate: true },
)

const patterns = KEEP_BUSY_PATTERNS
const previews = Object.fromEntries(
  KEEP_BUSY_PATTERNS.map((p) => [p.id, patternPreviewPath(p.id)]),
) as Record<KeepBusyPattern, string>

const resumeItems = KEEP_BUSY_RESUME_CHOICES.map((s) => ({
  title: s < 60 ? `${s} seconds` : `${s / 60} minute${s === 60 ? '' : 's'}`,
  value: s,
}))
const autoOffItems = KEEP_BUSY_AUTO_OFF_CHOICES.map((m) => ({
  title: m === 0 ? 'Never' : m < 60 ? `${m} minutes` : `${m / 60} hour${m === 60 ? '' : 's'}`,
  value: m,
}))

// A ticking clock for the pause countdown.
const now = ref(Date.now())
let timer: ReturnType<typeof setInterval> | undefined
onMounted(() => {
  timer = setInterval(() => (now.value = Date.now()), 1000)
})
onBeforeUnmount(() => {
  if (timer) clearInterval(timer)
})

const canToggle = computed(() => props.canControl && props.state?.available !== false)
// Settings can be chosen while off (they are what "on" will use) and changed
// live while on — both need the right to control.
const canEdit = computed(() => props.canControl && props.state?.available !== false)

const statusLine = computed(() =>
  props.state ? keepBusyStatusLine(props.state, now.value) : 'Off.',
)
const refusal = computed(() => (props.state?.refused ? keepBusyRefusalText(props.state.refused) : null))

const chipText = computed(() => {
  const s = props.state
  if (!s?.on) return 'Keep busy'
  if (s.phase === 'running') return `Keep busy · ${patternLabel(s.pattern).toLowerCase()}`
  if (s.phase === 'paused') {
    const left = keepBusyResumesInS(s, now.value)
    return left ? `Keep busy · paused ${left}s` : 'Keep busy · paused'
  }
  if (s.phase === 'locked') return 'Keep busy · locked'
  return `Keep busy · ${s.phase}`
})

function request(on: boolean): KeepBusyRequest {
  return { on, ...form }
}

function onToggle(on: boolean | null) {
  emit('set', request(!!on))
}

function choose(change: Partial<Form>) {
  Object.assign(form, change)
  saveForm()
  // While on, a change applies at once; while off it waits for the switch.
  if (props.state?.on) emit('set', request(true))
}
</script>

<style scoped>
.kb-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(64px, 1fr));
  gap: 6px;
}
.kb-tile {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 2px;
  padding: 6px 2px;
  border: 1px solid rgba(var(--v-theme-on-surface), 0.12);
  border-radius: 8px;
  background: transparent;
  color: rgb(var(--v-theme-on-surface));
  cursor: pointer;
}
.kb-tile:disabled {
  cursor: default;
  opacity: 0.5;
}
.kb-tile--on {
  border-color: rgb(var(--v-theme-primary));
  color: rgb(var(--v-theme-primary));
  background: rgba(var(--v-theme-primary), 0.08);
}
.kb-label {
  font-size: 11px;
  line-height: 1.2;
}
</style>
