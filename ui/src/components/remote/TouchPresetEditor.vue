<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  FR-111 P4b-2 — the layout editor. Lists the built-ins, a member's own
  layouts in this browser, and the org's. A built-in is only ever copied; an
  org layout is changed only by someone who may publish (MANAGE_TENANT, open
  decision 5). A draft is checked against the server's own rules
  (`validatePreset`) before it is saved anywhere, and the live preview runs it
  on a sink that sends nothing.
-->
<template>
  <v-card class="tpe" data-testid="rc-tpe">
    <v-card-title class="d-flex align-center">
      <span>{{ t('remote.viewer.tpe.title') }}</span>
      <v-spacer />
      <v-btn icon variant="text" size="small" :aria-label="t('remote.viewer.common.close')" data-testid="rc-tpe-close" @click="emit('close')">
        <v-icon>mdi-close</v-icon>
      </v-btn>
    </v-card-title>
    <v-card-text class="tpe-body">
      <div class="tpe-list">
        <v-btn block variant="tonal" size="small" class="mb-2" data-testid="rc-tpe-new" @click="startNew">
          {{ t('remote.viewer.tpe.new') }}
        </v-btn>
        <v-list density="compact" nav>
          <v-list-subheader>{{ t('remote.viewer.tpe.builtin') }}</v-list-subheader>
          <v-list-item
            v-for="p in builtins"
            :key="p.id"
            :title="presetName(p)"
            :active="current?.id === p.id"
            :data-testid="`rc-tpe-item-${p.id}`"
            @click="select(p, 'builtin')"
          />
          <template v-if="mine.length">
            <v-list-subheader>{{ t('remote.viewer.touch.thisBrowser') }}</v-list-subheader>
            <v-list-item
              v-for="p in mine"
              :key="p.id"
              :title="p.name"
              :active="current?.id === p.id"
              :data-testid="`rc-tpe-item-${p.id}`"
              @click="select(p, 'mine')"
            />
          </template>
          <template v-if="org.length">
            <v-list-subheader>{{ t('remote.viewer.touch.yourOrg') }}</v-list-subheader>
            <v-list-item
              v-for="p in org"
              :key="p.id"
              :title="p.name"
              :active="current?.id === p.id"
              :data-testid="`rc-tpe-item-${p.id}`"
              @click="select(p, 'org')"
            />
          </template>
        </v-list>
      </div>

      <div v-if="draft" class="tpe-edit">
        <v-alert v-if="readOnly" density="compact" type="info" variant="tonal" class="mb-2" data-testid="rc-tpe-readonly">
          {{ source === 'builtin' ? t('remote.viewer.tpe.builtinReadOnly') : t('remote.viewer.tpe.orgReadOnly') }}
          <template #append>
            <v-btn size="small" variant="text" data-testid="rc-tpe-copy" @click="copyCurrent">{{ t('remote.viewer.tpe.copy') }}</v-btn>
          </template>
        </v-alert>
        <fieldset class="tpe-fields" :disabled="readOnly">
          <v-text-field
            v-model="draft.name"
            :label="t('remote.viewer.tpe.name')"
            density="compact"
            variant="outlined"
            :maxlength="LIMITS.name"
            hide-details="auto"
            data-testid="rc-tpe-name"
          />

          <div v-for="(c, ci) in draft.controls" :key="c.id" class="tpe-control" :data-testid="`rc-tpe-control-${ci}`">
            <div class="d-flex align-center mb-1">
              <strong class="text-body-2">{{ c.kind === 'row' ? t('remote.viewer.tpe.buttons') : c.kind === 'dpad' ? t('remote.viewer.tpe.dpad') : t('remote.viewer.tpe.stick') }}</strong>
              <v-spacer />
              <v-btn size="x-small" variant="text" :data-testid="`rc-tpe-remove-${ci}`" @click="removeControl(ci)">
                {{ t('remote.viewer.tpe.remove') }}
              </v-btn>
            </div>

            <!-- Where it sits: an edge per direction, or centred. -->
            <div class="tpe-place">
              <span class="text-caption">{{ t('remote.viewer.tpe.across') }}</span>
              <v-btn-toggle
                :model-value="hEdge(c.at)"
                density="compact"
                mandatory
                @update:model-value="setH(c, $event)"
              >
                <v-btn value="left" size="x-small">{{ t('remote.viewer.tpe.left') }}</v-btn>
                <v-btn value="center" size="x-small">{{ t('remote.viewer.tpe.centre') }}</v-btn>
                <v-btn value="right" size="x-small">{{ t('remote.viewer.tpe.right') }}</v-btn>
              </v-btn-toggle>
              <input
                v-if="hEdge(c.at) !== 'center'"
                class="tpe-num"
                type="number"
                min="0"
                :max="LIMITS.placePx"
                :value="hEdge(c.at) === 'left' ? c.at.left : c.at.right"
                :aria-label="t('remote.viewer.tpe.edgePx')"
                @change="setHPx(c, $event)"
              />
              <span class="text-caption ml-2">{{ t('remote.viewer.tpe.down') }}</span>
              <v-btn-toggle
                :model-value="vEdge(c.at)"
                density="compact"
                mandatory
                @update:model-value="setV(c, $event)"
              >
                <v-btn value="top" size="x-small">{{ t('remote.viewer.tpe.top') }}</v-btn>
                <v-btn value="center" size="x-small">{{ t('remote.viewer.tpe.centre') }}</v-btn>
                <v-btn value="bottom" size="x-small">{{ t('remote.viewer.tpe.bottom') }}</v-btn>
              </v-btn-toggle>
              <input
                v-if="vEdge(c.at) !== 'center'"
                class="tpe-num"
                type="number"
                min="0"
                :max="LIMITS.placePx"
                :value="vEdge(c.at) === 'top' ? c.at.top : c.at.bottom"
                :aria-label="t('remote.viewer.tpe.edgePx')"
                @change="setVPx(c, $event)"
              />
            </div>

            <template v-if="c.kind === 'row'">
              <label class="text-caption d-flex align-center">
                <input type="checkbox" :checked="c.dir === 'column'" @change="c.dir = ($event.target as HTMLInputElement).checked ? 'column' : undefined" />
                <span class="ml-1">{{ t('remote.viewer.tpe.stack') }}</span>
              </label>
              <div v-for="(b, bi) in c.buttons" :key="b.id" class="tpe-button">
                <input
                  v-model="b.label"
                  class="tpe-text"
                  :maxlength="LIMITS.label"
                  :aria-label="t('remote.viewer.tpe.buttonLabel')"
                  :data-testid="`rc-tpe-btn-label-${ci}-${bi}`"
                />
                <v-btn-toggle
                  :model-value="b.action.kind"
                  density="compact"
                  mandatory
                  :data-testid="`rc-tpe-btn-kind-${ci}-${bi}`"
                  @update:model-value="setActionKind(b, $event)"
                >
                  <v-btn value="keys" size="x-small" :data-testid="`rc-tpe-btn-kind-${ci}-${bi}-keys`">{{ t('remote.viewer.tpe.keys') }}</v-btn>
                  <v-btn value="mouse" size="x-small" :data-testid="`rc-tpe-btn-kind-${ci}-${bi}-mouse`">{{ t('remote.viewer.tpe.mouse') }}</v-btn>
                  <v-btn value="macro" size="x-small" :data-testid="`rc-tpe-btn-kind-${ci}-${bi}-macro`">{{ t('remote.viewer.tpe.macro') }}</v-btn>
                </v-btn-toggle>
                <template v-if="b.action.kind === 'keys'">
                  <v-btn
                    size="x-small"
                    variant="outlined"
                    :data-testid="`rc-tpe-capture-${ci}-${bi}`"
                    @click="captureChord(`${ci}/${bi}`, b)"
                  >
                    {{ capturing?.id === `${ci}/${bi}` ? t('remote.viewer.tpe.pressKeys') : chordName(b.action.keys) || t('remote.viewer.tpe.setKeys') }}
                  </v-btn>
                </template>
                <template v-else-if="b.action.kind === 'mouse'">
                  <v-btn-toggle v-model="b.action.btn" density="compact" mandatory>
                    <v-btn value="left" size="x-small">{{ t('remote.viewer.tpe.left') }}</v-btn>
                    <v-btn value="right" size="x-small">{{ t('remote.viewer.tpe.right') }}</v-btn>
                    <v-btn value="middle" size="x-small">{{ t('remote.viewer.tpe.middle') }}</v-btn>
                  </v-btn-toggle>
                </template>
                <v-btn size="x-small" variant="text" :data-testid="`rc-tpe-btn-remove-${ci}-${bi}`" @click="c.buttons.splice(bi, 1)">
                  <v-icon size="small">mdi-delete-outline</v-icon>
                </v-btn>
                <!-- A macro's steps: a key or a mouse button, pressed, released or tapped, then a wait. -->
                <div v-if="b.action.kind === 'macro'" class="tpe-steps">
                  <div v-for="(s, si) in b.action.steps" :key="si" class="tpe-step" :data-testid="`rc-tpe-step-${ci}-${bi}-${si}`">
                    <v-btn-toggle v-model="s.op" density="compact" mandatory>
                      <v-btn value="press" size="x-small">{{ t('remote.viewer.tpe.press') }}</v-btn>
                      <v-btn value="release" size="x-small">{{ t('remote.viewer.tpe.release') }}</v-btn>
                      <v-btn value="tap" size="x-small">{{ t('remote.viewer.tpe.tap') }}</v-btn>
                    </v-btn-toggle>
                    <v-btn
                      size="x-small"
                      variant="outlined"
                      :data-testid="`rc-tpe-step-target-${ci}-${bi}-${si}`"
                      @click="captureStep(`${ci}/${bi}/${si}`, s)"
                    >
                      {{ capturing?.id === `${ci}/${bi}/${si}` ? t('remote.viewer.tpe.pressAKey') : stepTarget(s) }}
                    </v-btn>
                    <v-btn-toggle
                      :model-value="s.btn ?? null"
                      density="compact"
                      @update:model-value="setStepButton(s, $event)"
                    >
                      <v-btn value="left" size="x-small" :title="t('remote.viewer.tpe.leftMouse')">L</v-btn>
                      <v-btn value="right" size="x-small" :title="t('remote.viewer.tpe.rightMouse')">R</v-btn>
                    </v-btn-toggle>
                    <input
                      class="tpe-num"
                      type="number"
                      min="0"
                      :max="LIMITS.stepWaitMs"
                      step="50"
                      :value="s.wait_ms ?? 0"
                      :aria-label="t('remote.viewer.tpe.wait')"
                      :title="t('remote.viewer.tpe.wait')"
                      @change="s.wait_ms = clampInt(($event.target as HTMLInputElement).value, 0, LIMITS.stepWaitMs)"
                    />
                    <v-btn size="x-small" variant="text" @click="b.action.steps.splice(si, 1)">
                      <v-icon size="small">mdi-close</v-icon>
                    </v-btn>
                  </div>
                  <v-btn
                    size="x-small"
                    variant="text"
                    :data-testid="`rc-tpe-step-add-${ci}-${bi}`"
                    @click="b.action.steps.push({ op: 'tap', key: 0x2c, wait_ms: 0 })"
                  >
                    {{ t('remote.viewer.tpe.addStep') }}
                  </v-btn>
                </div>
              </div>
              <v-btn size="x-small" variant="text" :data-testid="`rc-tpe-btn-add-${ci}`" @click="c.buttons.push(newButton(draft!.controls, c.id))">
                {{ t('remote.viewer.tpe.addButton') }}
              </v-btn>
            </template>

            <template v-else>
              <div class="tpe-place">
                <input v-model="c.label" class="tpe-text" :maxlength="LIMITS.label" :aria-label="t('remote.viewer.tpe.label')" />
                <span class="text-caption">{{ t('remote.viewer.tpe.size') }}</span>
                <input
                  class="tpe-num"
                  type="number"
                  :min="LIMITS.sizeMin"
                  :max="LIMITS.sizeMax"
                  :value="c.size"
                  :aria-label="t('remote.viewer.tpe.sizePx')"
                  @change="c.size = clampInt(($event.target as HTMLInputElement).value, LIMITS.sizeMin, LIMITS.sizeMax)"
                />
                <template v-if="c.kind === 'stick'">
                  <span class="text-caption">{{ t('remote.viewer.tpe.speed') }}</span>
                  <input
                    class="tpe-num"
                    type="number"
                    :min="LIMITS.speedMin"
                    :max="LIMITS.speedMax"
                    step="0.1"
                    :value="c.speed"
                    :aria-label="t('remote.viewer.tpe.speed')"
                    @change="c.speed = clampNum(($event.target as HTMLInputElement).value, LIMITS.speedMin, LIMITS.speedMax)"
                  />
                </template>
              </div>
              <div v-if="c.kind === 'dpad'" class="tpe-place">
                <v-btn
                  v-for="dir in (['up', 'down', 'left', 'right'] as const)"
                  :key="dir"
                  size="x-small"
                  variant="outlined"
                  :data-testid="`rc-tpe-pad-${ci}-${dir}`"
                  @click="capturePad(`${ci}/${dir}`, c, dir)"
                >
                  {{ t(`remote.viewer.tpe.dir.${dir}`) }}: {{ capturing?.id === `${ci}/${dir}` ? '…' : keyName(c[dir]) }}
                </v-btn>
              </div>
            </template>
          </div>

          <div class="d-flex flex-wrap mt-2" style="gap: 4px">
            <v-btn size="small" variant="tonal" data-testid="rc-tpe-add-row" @click="addControl('row')">{{ t('remote.viewer.tpe.addRow') }}</v-btn>
            <v-btn size="small" variant="tonal" data-testid="rc-tpe-add-dpad" @click="addControl('dpad')">{{ t('remote.viewer.tpe.addDpad') }}</v-btn>
            <v-btn size="small" variant="tonal" data-testid="rc-tpe-add-stick" @click="addControl('stick')">{{ t('remote.viewer.tpe.addStick') }}</v-btn>
          </div>
        </fieldset>

        <div v-if="capturing" class="tpe-capturing" data-testid="rc-tpe-capturing">
          {{ capturing.single ? t('remote.viewer.tpe.captureOne') : t('remote.viewer.tpe.captureMany', { n: LIMITS.chordKeys }) }}
          <v-btn size="x-small" variant="text" data-testid="rc-tpe-capture-done" @click="capturing = null">{{ t('remote.viewer.tpe.done') }}</v-btn>
        </div>

        <v-alert v-if="problem" density="compact" type="warning" variant="tonal" class="mt-2" data-testid="rc-tpe-error">
          {{ problem }}
        </v-alert>

        <div class="tpe-preview" data-testid="rc-tpe-preview" :aria-label="t('remote.viewer.tpe.preview')">
          <TouchControls :preset="draft" :sink="previewSink" :ctrl-is-cmd="ctrlIsCmd" />
        </div>
      </div>
    </v-card-text>
    <v-card-actions v-if="draft" class="flex-wrap">
      <v-btn
        v-if="source === 'mine'"
        color="error"
        variant="text"
        size="small"
        data-testid="rc-tpe-delete"
        @click="deleteCurrent"
      >
        {{ t('remote.viewer.tpe.delete') }}
      </v-btn>
      <v-btn
        v-else-if="source === 'org' && canPublish"
        color="error"
        variant="text"
        size="small"
        :loading="busy"
        data-testid="rc-tpe-delete"
        @click="deleteCurrent"
      >
        {{ t('remote.viewer.tpe.deleteOrg') }}
      </v-btn>
      <v-spacer />
      <v-btn
        variant="text"
        size="small"
        :disabled="readOnly || !!verdict"
        data-testid="rc-tpe-save-mine"
        @click="saveMine"
      >
        {{ t('remote.viewer.tpe.saveMine') }}
      </v-btn>
      <v-btn
        v-if="canPublish"
        color="primary"
        variant="tonal"
        size="small"
        :disabled="readOnly || !!verdict"
        :loading="busy"
        data-testid="rc-tpe-publish"
        @click="publishCurrent"
      >
        {{ source === 'org' ? t('remote.viewer.tpe.saveOrg') : t('remote.viewer.tpe.publish') }}
      </v-btn>
    </v-card-actions>
  </v-card>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import TouchControls from '@/components/remote/TouchControls.vue'
import {
  ORG_PRESET_PREFIX,
  builtinPresetNameKey,
  type ButtonControl,
  type ControlPlace,
  type ControlsSink,
  type DpadControl,
  type MacroStep,
  type TouchControl,
  type TouchPreset,
} from '@/composables/touchControls'
import {
  chordName,
  copyForEdit,
  describeRefusal,
  keyName,
  LIMITS,
  MINE_PRESET_PREFIX,
  newButton,
  newDpad,
  newMineId,
  newRow,
  newStick,
  touchKeyOk,
  validatePreset,
} from '@/composables/touchPresetEdit'
import { kbdCodeToHid } from '@/composables/useRemoteControl'

type Source = 'builtin' | 'mine' | 'org' | 'new'

const props = defineProps<{
  builtins: readonly TouchPreset[]
  mine: readonly TouchPreset[]
  org: readonly TouchPreset[]
  /** May publish to the org (MANAGE_TENANT). */
  canPublish: boolean
  /** Store an org layout: `serverId` null creates one. Resolves to `null`, or
   *  the refusal code the server answered. */
  publish: (preset: { name: string; controls: TouchControl[] }, serverId: string | null) => Promise<string | null>
  deleteOrg: (serverId: string) => Promise<string | null>
  ctrlIsCmd?: boolean
}>()

const { t } = useI18n()
/** FR-131 P3 — a built-in's name in the reader's language; one someone named, as written. */
function presetName(p: TouchPreset): string {
  const k = builtinPresetNameKey(p)
  return k ? t(k) : p.name
}
const emit = defineEmits<{
  (e: 'close'): void
  (e: 'save-mine', preset: TouchPreset): void
  (e: 'delete-mine', id: string): void
}>()

const current = ref<TouchPreset | null>(null)
const source = ref<Source>('new')
const draft = ref<TouchPreset | null>(null)
const busy = ref(false)
const serverProblem = ref<string | null>(null)

const readOnly = computed(() => source.value === 'builtin' || (source.value === 'org' && !props.canPublish))
/** The server's verdict on the draft, here. */
const verdict = computed(() => (draft.value ? validatePreset(draft.value) : null))
const problem = computed(() => (serverProblem.value ? describeRefusal(serverProblem.value) : verdict.value ? describeRefusal(verdict.value) : null))

/** The preview presses nothing. */
const previewSink: ControlsSink = {
  key: () => {},
  button: () => {},
  move: () => {},
  begin: () => {},
  end: () => {},
  width: () => 1000,
}

function clone(p: TouchPreset): TouchPreset {
  return { id: p.id, name: p.name, controls: JSON.parse(JSON.stringify(p.controls)) }
}

function select(p: TouchPreset, from: Source) {
  capturing.value = null
  serverProblem.value = null
  current.value = p
  source.value = from
  draft.value = clone(p)
}

function startNew() {
  const controls: TouchControl[] = []
  controls.push(newRow(controls))
  select({ id: newMineId(), name: t('remote.viewer.tpe.myLayout'), controls }, 'new')
  current.value = null
}

function copyCurrent() {
  if (!draft.value) return
  const name = t('remote.viewer.tpe.copyOf', { name: presetName(draft.value) })
  select(copyForEdit(draft.value, name), 'new')
  current.value = null
}

function addControl(kind: 'row' | 'dpad' | 'stick') {
  const d = draft.value
  if (!d) return
  d.controls.push(kind === 'row' ? newRow(d.controls) : kind === 'dpad' ? newDpad(d.controls) : newStick(d.controls))
}

function removeControl(i: number) {
  draft.value?.controls.splice(i, 1)
}

function setActionKind(b: ButtonControl, kind: unknown) {
  if (kind === 'keys') b.action = { kind: 'keys', keys: [0x2c] }
  else if (kind === 'mouse') b.action = { kind: 'mouse', btn: 'left' }
  else if (kind === 'macro') b.action = { kind: 'macro', steps: [{ op: 'tap', key: 0x2c, wait_ms: 0 }] }
}

function stepTarget(s: MacroStep): string {
  return s.btn ? t(`remote.viewer.tpe.mouseBtn.${s.btn}`) : s.key !== undefined ? keyName(s.key) : t('remote.viewer.tpe.setAKey')
}

function setStepButton(s: MacroStep, btn: unknown) {
  if (btn === 'left' || btn === 'right') {
    s.btn = btn
    delete s.key
  } else if (s.btn) {
    delete s.btn
    s.key = 0x2c
  }
}

// ── where a control sits ───────────────────────────────────────────────

function hEdge(at: ControlPlace): 'left' | 'center' | 'right' {
  return at.left !== undefined ? 'left' : at.right !== undefined ? 'right' : 'center'
}
function vEdge(at: ControlPlace): 'top' | 'center' | 'bottom' {
  return at.top !== undefined ? 'top' : at.bottom !== undefined ? 'bottom' : 'center'
}
function setH(c: TouchControl, edge: unknown) {
  const px = c.at.left ?? c.at.right ?? 16
  delete c.at.left
  delete c.at.right
  if (edge === 'left') c.at.left = px
  else if (edge === 'right') c.at.right = px
}
function setV(c: TouchControl, edge: unknown) {
  const px = c.at.top ?? c.at.bottom ?? 16
  delete c.at.top
  delete c.at.bottom
  if (edge === 'top') c.at.top = px
  else if (edge === 'bottom') c.at.bottom = px
}
function setHPx(c: TouchControl, ev: Event) {
  const px = clampInt((ev.target as HTMLInputElement).value, 0, LIMITS.placePx)
  if (c.at.left !== undefined) c.at.left = px
  else if (c.at.right !== undefined) c.at.right = px
}
function setVPx(c: TouchControl, ev: Event) {
  const px = clampInt((ev.target as HTMLInputElement).value, 0, LIMITS.placePx)
  if (c.at.top !== undefined) c.at.top = px
  else if (c.at.bottom !== undefined) c.at.bottom = px
}

function clampInt(v: string, lo: number, hi: number): number {
  const n = Math.round(Number(v))
  return Number.isFinite(n) ? Math.min(Math.max(n, lo), hi) : lo
}
function clampNum(v: string, lo: number, hi: number): number {
  const n = Number(v)
  return Number.isFinite(n) ? Math.min(Math.max(n, lo), hi) : lo
}

// ── capturing keys from the keyboard ───────────────────────────────────
//
// The viewer's own keyboard forwarding is paused while the editor is open
// (`keyboardPaused`), so a key pressed here never reaches the host.

interface Capture {
  id: string
  single: boolean
  keys: number[]
  set: (keys: number[]) => void
}
const capturing = ref<Capture | null>(null)

function captureChord(id: string, b: ButtonControl) {
  capturing.value = {
    id,
    single: false,
    keys: [],
    set: (keys) => {
      if (b.action.kind === 'keys') b.action.keys = keys
    },
  }
}
function captureStep(id: string, s: MacroStep) {
  capturing.value = {
    id,
    single: true,
    keys: [],
    set: ([k]) => {
      delete s.btn
      s.key = k
    },
  }
}
function capturePad(id: string, c: DpadControl, dir: 'up' | 'down' | 'left' | 'right') {
  capturing.value = {
    id,
    single: true,
    keys: [],
    set: ([k]) => {
      c[dir] = k
    },
  }
}

function onCaptureKey(ev: KeyboardEvent) {
  const c = capturing.value
  if (!c) return
  ev.preventDefault()
  ev.stopPropagation()
  if (ev.repeat) return
  const code = kbdCodeToHid(ev.code)
  if (code === null || !touchKeyOk(code)) return
  if (c.single) {
    c.set([code])
    capturing.value = null
    return
  }
  if (!c.keys.includes(code) && c.keys.length < LIMITS.chordKeys) {
    c.keys.push(code)
    c.set([...c.keys])
  }
}

onMounted(() => window.addEventListener('keydown', onCaptureKey, { capture: true }))
onBeforeUnmount(() => window.removeEventListener('keydown', onCaptureKey, { capture: true }))

// ── saving ─────────────────────────────────────────────────────────────

function serverIdOf(id: string): string | null {
  return id.startsWith(ORG_PRESET_PREFIX) ? id.slice(ORG_PRESET_PREFIX.length) : null
}

function saveMine() {
  const d = draft.value
  if (!d || verdict.value) return
  const id = source.value === 'mine' && d.id.startsWith(MINE_PRESET_PREFIX) ? d.id : newMineId()
  const saved: TouchPreset = { id, name: d.name.trim(), controls: JSON.parse(JSON.stringify(d.controls)) }
  emit('save-mine', saved)
  select(saved, 'mine')
}

async function publishCurrent() {
  const d = draft.value
  if (!d || verdict.value || !props.canPublish) return
  busy.value = true
  serverProblem.value = null
  try {
    const code = await props.publish(
      { name: d.name.trim(), controls: JSON.parse(JSON.stringify(d.controls)) },
      source.value === 'org' ? serverIdOf(d.id) : null,
    )
    if (code) serverProblem.value = code
  } finally {
    busy.value = false
  }
}

async function deleteCurrent() {
  const d = draft.value
  if (!d) return
  if (source.value === 'mine') {
    emit('delete-mine', d.id)
    draft.value = null
    current.value = null
    return
  }
  const sid = serverIdOf(d.id)
  if (source.value !== 'org' || !props.canPublish || !sid) return
  busy.value = true
  serverProblem.value = null
  try {
    const code = await props.deleteOrg(sid)
    if (code) serverProblem.value = code
    else {
      draft.value = null
      current.value = null
    }
  } finally {
    busy.value = false
  }
}

defineExpose({ startNew, select })
</script>

<style scoped>
.tpe-body {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}
.tpe-list {
  flex: 0 0 200px;
  max-width: 100%;
}
.tpe-edit {
  flex: 1 1 320px;
  min-width: 0;
}
.tpe-fields {
  border: 0;
  margin: 0;
  padding: 0;
  min-width: 0;
}
.tpe-control {
  border: 1px solid rgba(var(--v-border-color), var(--v-border-opacity));
  border-radius: 6px;
  padding: 6px 8px;
  margin-top: 8px;
}
.tpe-place,
.tpe-button,
.tpe-step {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 4px;
  margin-top: 4px;
}
.tpe-steps {
  flex-basis: 100%;
  padding-left: 12px;
}
.tpe-num {
  width: 64px;
  border: 1px solid rgba(var(--v-border-color), var(--v-border-opacity));
  border-radius: 4px;
  padding: 0 4px;
  color: inherit;
  background: transparent;
}
.tpe-text {
  width: 96px;
  border: 1px solid rgba(var(--v-border-color), var(--v-border-opacity));
  border-radius: 4px;
  padding: 0 4px;
  color: inherit;
  background: transparent;
}
.tpe-capturing {
  margin-top: 8px;
  font-size: 0.85rem;
}
.tpe-preview {
  position: relative;
  width: 100%;
  max-width: 420px;
  height: 260px;
  margin-top: 8px;
  border-radius: 6px;
  overflow: hidden;
  background: repeating-linear-gradient(45deg, rgba(128, 128, 128, 0.12) 0 8px, transparent 8px 16px);
}
</style>
