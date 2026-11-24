<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  FR-111 P3 — on-screen controls over the stage: rows of buttons, a d-pad and
  a mouse stick, laid out by a preset. A touch on a control stays with it
  (pointer capture) and never reaches the stage's own gestures; a touch
  anywhere else falls through to the stage as before. What the controls press
  goes to `sink`, the attached stage's entry point.
-->
<template>
  <div
    ref="root"
    class="touch-controls"
    data-testid="rc-touch-controls"
    :data-preset="preset.id"
    :style="{ transform: `translate(${scrollX ?? 0}px, ${scrollY ?? 0}px)` }"
  >
    <template v-for="c in controls" :key="c.id">
      <div
        v-if="c.kind === 'row'"
        class="tc-row"
        :class="{ 'tc-column': c.dir === 'column' }"
        :style="placeStyle(c.at)"
      >
        <button
          v-for="b in c.buttons"
          :key="b.id"
          type="button"
          class="tc-btn"
          :class="{ 'tc-held': lit.has(`${c.id}/${b.id}`) || macroLit.has(`${c.id}/${b.id}`) }"
          :data-testid="`rc-tc-${c.id}-${b.id}`"
          :aria-label="controlLabel(b.label, !!ctrlIsCmd)"
          @pointerdown.stop.prevent="onButtonDown($event, c, b)"
          @pointermove.stop
          @pointerrawupdate.stop
          @pointerup.stop.prevent="onUp($event)"
          @pointercancel.stop="onUp($event)"
          @lostpointercapture.stop="onUp($event)"
          @contextmenu.stop.prevent
        >
          {{ controlLabel(b.label, !!ctrlIsCmd) }}
        </button>
      </div>
      <div
        v-else-if="c.kind === 'dpad'"
        class="tc-pad"
        role="button"
        :aria-label="c.label"
        :data-testid="`rc-tc-${c.id}`"
        :style="{ ...placeStyle(c.at), width: `${c.size}px`, height: `${c.size}px` }"
        @pointerdown.stop.prevent="onPadDown($event, c)"
        @pointermove.stop="onMove($event)"
        @pointerrawupdate.stop
        @pointerup.stop.prevent="onUp($event)"
        @pointercancel.stop="onUp($event)"
        @lostpointercapture.stop="onUp($event)"
        @contextmenu.stop.prevent
      >
        <span
          v-for="arm in arms(c)"
          :key="arm.dir"
          class="tc-arm"
          :class="[`tc-arm-${arm.dir}`, { 'tc-held': (padKeys.get(c.id) ?? []).includes(arm.code) }]"
        >{{ hidLabel(arm.code) }}</span>
      </div>
      <div
        v-else
        class="tc-pad"
        role="button"
        :aria-label="c.label"
        :data-testid="`rc-tc-${c.id}`"
        :style="{ ...placeStyle(c.at), width: `${c.size}px`, height: `${c.size}px` }"
        @pointerdown.stop.prevent="onStickDown($event, c)"
        @pointermove.stop="onMove($event)"
        @pointerrawupdate.stop
        @pointerup.stop.prevent="onUp($event)"
        @pointercancel.stop="onUp($event)"
        @lostpointercapture.stop="onUp($event)"
        @contextmenu.stop.prevent
      >
        <span class="tc-stick-label">{{ c.label }}</span>
        <span class="tc-knob" :class="{ 'tc-held': knobs.has(c.id) }" :style="knobStyle(c)" />
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import {
  controlLabel,
  createControlsDriver,
  fitControls,
  hidLabel,
  placeStyle,
  type ButtonControl,
  type ControlsSink,
  type DpadControl,
  type RowControl,
  type StickControl,
  type TouchPreset,
} from '@/composables/touchControls'

const props = defineProps<{
  preset: TouchPreset
  sink: ControlsSink
  /** The stage's scroll offsets: the overlay stays over the part of the
   *  stage on screen while a zoomed picture scrolls under it. */
  scrollX?: number
  scrollY?: number
  /** A Mac host whose viewer sends Ctrl as Cmd (FR-13). */
  ctrlIsCmd?: boolean
}>()

const driver = createControlsDriver(props.sink)

/** FR-125 P2 — the overlay's own height (the stage's), and the preset fitted
 *  to it: a stage with room renders the preset as designed. */
const root = ref<HTMLElement | null>(null)
const stageHeight = ref(0)
const controls = computed(() => fitControls(props.preset.controls, stageHeight.value))
let resizeObserver: ResizeObserver | null = null

/** What is lit: `control/button` for a held button. */
const lit = reactive(new Set<string>())
/** FR-111 P4 — a macro button stays lit while its macro plays, which it does
 *  after the finger lifts too. */
const macroLit = reactive(new Set<string>())
/** The keys each d-pad holds now. */
const padKeys = reactive(new Map<string, number[]>())
/** Each held stick's push, as a share of its radius. */
const knobs = reactive(new Map<string, { nx: number; ny: number }>())

interface Finger {
  control: string
  /** The lit button, for a button. */
  button?: string
  kind: 'button' | 'dpad' | 'stick'
  cx: number
  cy: number
  r: number
}
const fingers = new Map<number, Finger>()

function arms(c: DpadControl) {
  return [
    { dir: 'up', code: c.up },
    { dir: 'down', code: c.down },
    { dir: 'left', code: c.left },
    { dir: 'right', code: c.right },
  ]
}

function knobStyle(c: StickControl): Record<string, string> {
  const k = knobs.get(c.id)
  if (!k) return {}
  const m = Math.hypot(k.nx, k.ny)
  const s = m > 1 ? 1 / m : 1
  const travel = (c.size / 2) * 0.6
  return { transform: `translate(${k.nx * s * travel}px, ${k.ny * s * travel}px)` }
}

function capture(ev: PointerEvent) {
  try {
    ;(ev.currentTarget as Element).setPointerCapture(ev.pointerId)
  } catch {
    /* a synthetic event in a test, or a pointer already gone */
  }
}

function geometry(ev: PointerEvent): { cx: number; cy: number; r: number } {
  const rect = (ev.currentTarget as Element).getBoundingClientRect()
  return { cx: rect.left + rect.width / 2, cy: rect.top + rect.height / 2, r: Math.max(rect.width / 2, 1) }
}

function offset(f: Finger, ev: PointerEvent): { nx: number; ny: number } {
  return { nx: (ev.clientX - f.cx) / f.r, ny: (ev.clientY - f.cy) / f.r }
}

function onButtonDown(ev: PointerEvent, c: RowControl, b: ButtonControl) {
  if (fingers.has(ev.pointerId)) return
  capture(ev)
  const key = `${c.id}/${b.id}`
  fingers.set(ev.pointerId, { control: c.id, button: key, kind: 'button', cx: 0, cy: 0, r: 1 })
  lit.add(key)
  driver.pressButton(ev.pointerId, b)
  if (b.action.kind === 'macro' && driver.playing(b.id)) watchMacro(key, b.id)
}

function watchMacro(key: string, buttonId: string) {
  if (macroLit.has(key)) return
  macroLit.add(key)
  const check = () => {
    if (driver.playing(buttonId)) requestAnimationFrame(check)
    else macroLit.delete(key)
  }
  requestAnimationFrame(check)
}

function onPadDown(ev: PointerEvent, c: DpadControl) {
  if (fingers.has(ev.pointerId)) return
  capture(ev)
  const f: Finger = { control: c.id, kind: 'dpad', ...geometry(ev) }
  fingers.set(ev.pointerId, f)
  const o = offset(f, ev)
  driver.pressDpad(ev.pointerId, c, o.nx, o.ny)
  padKeys.set(c.id, driver.keysOf(ev.pointerId))
}

let raf: number | null = null
function loop(now: number) {
  raf = null
  if (driver.tick(now)) raf = requestAnimationFrame(loop)
}

function onStickDown(ev: PointerEvent, c: StickControl) {
  if (fingers.has(ev.pointerId)) return
  capture(ev)
  const f: Finger = { control: c.id, kind: 'stick', ...geometry(ev) }
  fingers.set(ev.pointerId, f)
  const o = offset(f, ev)
  driver.pressStick(ev.pointerId, c, o.nx, o.ny, performance.now())
  knobs.set(c.id, o)
  if (raf === null) raf = requestAnimationFrame(loop)
}

function onMove(ev: PointerEvent) {
  const f = fingers.get(ev.pointerId)
  if (!f || f.kind === 'button') return
  const o = offset(f, ev)
  driver.move(ev.pointerId, o.nx, o.ny)
  if (f.kind === 'dpad') padKeys.set(f.control, driver.keysOf(ev.pointerId))
  else knobs.set(f.control, o)
}

function forget(id: number) {
  const f = fingers.get(id)
  if (!f) return
  fingers.delete(id)
  if (f.button) lit.delete(f.button)
  if (f.kind === 'dpad') padKeys.delete(f.control)
  if (f.kind === 'stick') knobs.delete(f.control)
}

function onUp(ev: PointerEvent) {
  driver.release(ev.pointerId)
  forget(ev.pointerId)
}

function releaseAll() {
  driver.releaseAll()
  macroLit.clear()
  for (const id of [...fingers.keys()]) forget(id)
  if (raf !== null) {
    cancelAnimationFrame(raf)
    raf = null
  }
}

function onVisibility() {
  if (document.visibilityState === 'hidden') releaseAll()
}

// A new preset starts with nothing held.
watch(() => props.preset.id, releaseAll)

onMounted(() => {
  window.addEventListener('blur', releaseAll)
  document.addEventListener('visibilitychange', onVisibility)
  if (root.value) {
    stageHeight.value = root.value.clientHeight
    if (typeof ResizeObserver !== 'undefined') {
      resizeObserver = new ResizeObserver(() => {
        if (root.value) stageHeight.value = root.value.clientHeight
      })
      resizeObserver.observe(root.value)
    }
  }
})
onBeforeUnmount(() => {
  window.removeEventListener('blur', releaseAll)
  document.removeEventListener('visibilitychange', onVisibility)
  resizeObserver?.disconnect()
  releaseAll()
})
</script>

<style scoped>
.touch-controls {
  position: absolute;
  left: 0;
  top: 0;
  width: 100%;
  height: 100%;
  pointer-events: none;
  z-index: 20;
}
.tc-row {
  position: absolute;
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 6px;
  max-width: calc(100% - 24px);
}
.tc-row.tc-column {
  flex-direction: column;
  flex-wrap: nowrap;
}
.tc-btn,
.tc-pad {
  pointer-events: auto;
  touch-action: none;
  user-select: none;
  -webkit-user-select: none;
  -webkit-touch-callout: none;
  color: #fff;
  background: rgba(20, 20, 20, 0.5);
  border: 1px solid rgba(255, 255, 255, 0.35);
}
.tc-btn {
  min-width: 48px;
  height: 44px;
  padding: 0 10px;
  border-radius: 10px;
  font: 600 13px/1 system-ui, sans-serif;
}
.tc-held {
  background: rgba(33, 150, 243, 0.75);
  border-color: #90caf9;
}
.tc-pad {
  position: absolute;
  border-radius: 50%;
}
.tc-arm {
  position: absolute;
  width: 34%;
  height: 34%;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 10px;
  font: 700 15px/1 system-ui, sans-serif;
  color: rgba(255, 255, 255, 0.9);
}
.tc-arm.tc-held {
  border: 1px solid #90caf9;
}
.tc-arm-up {
  top: 4%;
  left: 33%;
}
.tc-arm-down {
  bottom: 4%;
  left: 33%;
}
.tc-arm-left {
  left: 4%;
  top: 33%;
}
.tc-arm-right {
  right: 4%;
  top: 33%;
}
.tc-stick-label {
  position: absolute;
  bottom: 8%;
  width: 100%;
  text-align: center;
  font: 500 11px/1 system-ui, sans-serif;
  opacity: 0.7;
}
.tc-knob {
  position: absolute;
  left: 30%;
  top: 30%;
  width: 40%;
  height: 40%;
  border-radius: 50%;
  background: rgba(255, 255, 255, 0.35);
  border: 1px solid rgba(255, 255, 255, 0.6);
}
</style>
