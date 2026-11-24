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
        :aria-label="t('keepBusy.menu.title')"
        :title="t('keepBusy.menu.title')"
        data-testid="rc-keep-busy-btn"
      >
        <v-icon>mdi-cursor-default-gesture-outline</v-icon>
      </v-btn>
    </template>
    <v-card min-width="340" max-width="420" data-testid="rc-keep-busy-menu">
      <v-card-title class="d-flex align-center text-subtitle-1">
        {{ t('keepBusy.menu.title') }}
        <v-spacer />
        <v-switch
          :model-value="!!state?.on"
          :disabled="!canToggle"
          color="primary"
          density="compact"
          hide-details
          inset
          :aria-label="t('keepBusy.menu.switch')"
          data-testid="rc-keep-busy-switch"
          @update:model-value="onToggle"
        />
      </v-card-title>
      <v-card-text>
        <p class="text-caption mb-2">
          {{ t('keepBusy.menu.intro') }}
        </p>
        <p class="text-body-2 mb-2" data-testid="rc-keep-busy-status">{{ statusLine }}</p>
        <p v-if="refusal" class="text-caption text-error mb-2" data-testid="rc-keep-busy-refused">
          {{ refusal }}
        </p>
        <p v-if="!canControl" class="text-caption text-medium-emphasis mb-2">
          {{ t('keepBusy.menu.viewOnly') }}
        </p>
        <p
          v-if="state?.warn.includes('focus_follows_mouse')"
          class="text-caption text-warning mb-2"
          data-testid="rc-keep-busy-warn-focus"
        >
          {{ t('keepBusy.menu.focusFollows') }}
        </p>
        <div class="kb-grid mb-3" role="radiogroup" :aria-label="t('keepBusy.menu.pattern')">
          <button
            v-for="p in patterns"
            :key="p.id"
            type="button"
            role="radio"
            class="kb-tile"
            :class="{ 'kb-tile--on': p.id === form.pattern }"
            :aria-checked="p.id === form.pattern"
            :disabled="!canEdit"
            :title="patternLabel(p.id)"
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
            <span class="kb-label">{{ patternLabel(p.id) }}</span>
          </button>
        </div>
        <div class="d-flex align-center ga-3 mb-3 flex-wrap">
          <v-btn-toggle
            :model-value="form.speed"
            density="compact"
            mandatory
            divided
            :disabled="!canEdit"
            :aria-label="t('keepBusy.menu.speed')"
            @update:model-value="(v: KeepBusySpeed) => choose({ speed: v })"
          >
            <v-btn value="slow" size="small">{{ t('keepBusy.menu.slow') }}</v-btn>
            <v-btn value="normal" size="small">{{ t('keepBusy.menu.normal') }}</v-btn>
            <v-btn value="fast" size="small">{{ t('keepBusy.menu.fast') }}</v-btn>
          </v-btn-toggle>
          <v-btn-toggle
            :model-value="form.size"
            density="compact"
            mandatory
            divided
            :disabled="!canEdit"
            :aria-label="t('keepBusy.menu.size')"
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
            :label="t('keepBusy.menu.resumeAfter')"
            density="compact"
            hide-details
            :disabled="!canEdit"
            @update:model-value="(v: number) => choose({ resumeAfterS: v })"
          />
          <v-select
            :model-value="form.autoOffMin"
            :items="autoOffItems"
            :label="t('keepBusy.menu.turnOffAfter')"
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
import { useI18n } from 'vue-i18n'
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

const { t } = useI18n()
const resumeItems = computed(() =>
  KEEP_BUSY_RESUME_CHOICES.map((s) => ({
    title: s < 60 ? t('keepBusy.dur.seconds', s) : t('keepBusy.dur.minutes', s / 60),
    value: s,
  })),
)
const autoOffItems = computed(() =>
  KEEP_BUSY_AUTO_OFF_CHOICES.map((m) => ({
    title: m === 0 ? t('keepBusy.dur.never') : m < 60 ? t('keepBusy.dur.minutes', m) : t('keepBusy.dur.hours', m / 60),
    value: m,
  })),
)

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
  props.state ? keepBusyStatusLine(props.state, now.value) : t('keepBusy.status.off'),
)
const refusal = computed(() => (props.state?.refused ? keepBusyRefusalText(props.state.refused) : null))

const chipText = computed(() => {
  const s = props.state
  if (!s?.on) return t('keepBusy.menu.title')
  if (s.phase === 'running') return t('keepBusy.chip.running', { pattern: patternLabel(s.pattern).toLowerCase() })
  if (s.phase === 'paused') {
    const left = keepBusyResumesInS(s, now.value)
    return left ? t('keepBusy.chip.pausedFor', { s: left }) : t('keepBusy.chip.paused')
  }
  if (s.phase === 'locked') return t('keepBusy.chip.locked')
  return t('keepBusy.chip.other', { phase: s.phase })
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
