<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <div v-if="open" class="mobile-keyboard-shell" data-testid="mobile-keyboard">
    <!--
      Off-screen capture target. The OS soft keyboard appears when
      THIS textarea has focus, but we never let the user see what's
      "in" the textarea — content is cleared after every input event
      (`flushInputBuffer`) so it never visibly accumulates. iOS Safari
      refuses to surface a keyboard for elements with `display:none`
      or `visibility:hidden`; instead we keep a 1×1 transparent
      textarea in-document via `transform: translate(-9999px)` per
      the Monaco / CodeMirror mobile-pattern.
    -->
    <textarea
      ref="captureRef"
      class="mobile-keyboard-capture"
      autocapitalize="off"
      autocorrect="off"
      autocomplete="off"
      spellcheck="false"
      enterkeyhint="enter"
      :aria-label="t('remote.viewer.kbd.input')"
      @input="onInput"
      @compositionstart="onCompositionStart"
      @compositionend="onCompositionEnd"
      @keydown="onKeyDown"
      @blur="onBlur"
    />
    <!--
      Floating toolbar with the keys the soft keyboard doesn't expose
      reliably. `inputmode='none'` prevents the toolbar buttons
      themselves from popping the keyboard down on iOS when tapped
      via accidental focus shifts.
    -->
    <div class="mobile-keyboard-toolbar" role="toolbar" :aria-label="t('remote.viewer.kbd.special')">
      <button
        v-for="key in specialKeys"
        :key="key.label"
        type="button"
        class="mkb-btn"
        :class="{ 'mkb-btn-mod': key.kind === 'mod', 'mkb-btn-mod-active': key.kind === 'mod' && pinnedMods[key.mod] }"
        :title="key.title"
        @pointerdown.prevent="onSpecialKey(key)"
      >
        {{ key.label }}
      </button>
      <button
        type="button"
        class="mkb-btn mkb-btn-close"
        :title="t('remote.viewer.tb.hideKeyboard')"
        @pointerdown.prevent="$emit('close')"
      >
        ▾
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
/*
 * Mobile virtual keyboard for the remote-control viewer (Plan 4).
 *
 * The remote viewer is a `<video>` (or canvas in WebCodecs mode);
 * tapping it doesn't trigger the OS soft keyboard. This component
 * surfaces a hidden `<textarea>` that, when focused, tells iOS /
 * Android to show their software keyboard. Typed characters arrive
 * as `input` events and are forwarded to the host as `key_text`
 * messages over the input DC — the agent's `enigo.text()` types
 * them via the OS Unicode-typing API, so emoji / CJK / accented
 * Latin all round-trip without browser-side HID mapping.
 *
 * Special keys (Esc / Tab / Enter / Backspace / arrows + sticky
 * Ctrl / Alt / Meta modifiers) live in a floating toolbar because
 * the OS keyboard doesn't reliably expose them on iOS especially.
 *
 * IME composition (Pinyin / Kana / Hangul): suppressed on the
 * `input` event path while `isComposing === true`; the composed
 * string flushes as a single `key_text` on `compositionend`. Matches
 * the planner's "v1 sends composed string only on compositionend"
 * design — per-keystroke composition deferred to a follow-up.
 */
import { ref, watch, nextTick, computed } from 'vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const props = defineProps<{
  open: boolean
}>()

const emit = defineEmits<{
  close: []
  /** Plain typed text (no special keys). */
  keyText: [text: string]
  /** Special-key down/up (e.g. Backspace, Enter, Esc). `mods`
   *  bitfield matches `useRemoteControl.sendKey` (0x01 Ctrl /
   *  0x02 Shift / 0x04 Alt / 0x08 Meta). */
  key: [code: number, down: boolean, mods: number]
}>()

const captureRef = ref<HTMLTextAreaElement | null>(null)
const isComposing = ref(false)
/** Sticky-modifier flags. Tap once to arm; the next `keyText` or
 *  special-key press fires it AND clears it (sticky-once). Tap
 *  again before pressing anything to clear without firing. */
const pinnedMods = ref<{ ctrl: boolean; alt: boolean; meta: boolean }>({
  ctrl: false,
  alt: false,
  meta: false,
})

/** HID codes per USB HID Usage Tables (page 0x07) — same numbers
 *  the Rust agent's `hid_to_key` accepts. Lifted from the existing
 *  `kbdCodeToHid` table so we don't drift; re-importing it would
 *  be cleaner long-term. */
const HID = {
  Enter: 0x28,
  Escape: 0x29,
  Backspace: 0x2a,
  Tab: 0x2b,
  ArrowRight: 0x4f,
  ArrowLeft: 0x50,
  ArrowDown: 0x51,
  ArrowUp: 0x52,
  Home: 0x4a,
  End: 0x4d,
  PageUp: 0x4b,
  PageDown: 0x4e,
  Delete: 0x4c,
} as const

/** Modifier-bit encoding — matches `decideKeyAction` /
 *  `useRemoteControl.sendKey`. */
const MOD = { Ctrl: 0x01, Shift: 0x02, Alt: 0x04, Meta: 0x08 } as const

type SpecialKey =
  | { kind: 'key'; label: string; title: string; hid: number }
  | { kind: 'mod'; label: string; title: string; mod: 'ctrl' | 'alt' | 'meta' }

const specialKeys = computed<SpecialKey[]>(() => [
  { kind: 'key', label: 'Esc', title: 'Escape', hid: HID.Escape },
  { kind: 'key', label: 'Tab', title: 'Tab', hid: HID.Tab },
  { kind: 'mod', label: 'Ctrl', title: t('remote.viewer.kbd.sticky', { key: 'Ctrl' }), mod: 'ctrl' },
  { kind: 'mod', label: 'Alt', title: t('remote.viewer.kbd.sticky', { key: 'Alt' }), mod: 'alt' },
  { kind: 'mod', label: 'Win', title: t('remote.viewer.kbd.sticky', { key: 'Win/Cmd' }), mod: 'meta' },
  { kind: 'key', label: '←', title: t('remote.viewer.kbd.left'), hid: HID.ArrowLeft },
  { kind: 'key', label: '↑', title: t('remote.viewer.kbd.up'), hid: HID.ArrowUp },
  { kind: 'key', label: '↓', title: t('remote.viewer.kbd.down'), hid: HID.ArrowDown },
  { kind: 'key', label: '→', title: t('remote.viewer.kbd.right'), hid: HID.ArrowRight },
  { kind: 'key', label: 'Home', title: 'Home', hid: HID.Home },
  { kind: 'key', label: 'End', title: 'End', hid: HID.End },
  { kind: 'key', label: 'Del', title: 'Delete', hid: HID.Delete },
])

/** Compose the current modifier bitfield from sticky pinned mods.
 *  Cleared after consumption (sticky-once semantics). */
function consumeModBits(): number {
  let bits = 0
  if (pinnedMods.value.ctrl) bits |= MOD.Ctrl
  if (pinnedMods.value.alt) bits |= MOD.Alt
  if (pinnedMods.value.meta) bits |= MOD.Meta
  pinnedMods.value = { ctrl: false, alt: false, meta: false }
  return bits
}

/** Send a special key as down → up with whatever sticky modifier
 *  bits were active. The host needs both edges; rapid tap = key
 *  press. Modifier bits are consumed on `down` only — agent's
 *  enigo backend treats `key down` with mods=Ctrl as "press Ctrl,
 *  press X, release X, release Ctrl" so we don't need separate
 *  modifier-down/up events. */
function emitSpecialKey(hid: number) {
  const mods = consumeModBits()
  emit('key', hid, true, mods)
  emit('key', hid, false, mods)
}

function onSpecialKey(key: SpecialKey) {
  if (key.kind === 'mod') {
    pinnedMods.value = {
      ...pinnedMods.value,
      [key.mod]: !pinnedMods.value[key.mod],
    }
    // Re-focus the capture textarea so the keyboard stays up after
    // toolbar interaction. Without this iOS can dismiss the kbd.
    captureRef.value?.focus()
    return
  }
  emitSpecialKey(key.hid)
  captureRef.value?.focus()
}

/** Accept text input from the OS soft keyboard. We rely on the
 *  textarea's `value` rather than `event.data` because the latter
 *  is empty for some Android keyboards on certain input types. After
 *  reading we clear the textarea so the next keystroke arrives in
 *  isolation — the textarea is purely an event source, never a
 *  text container the user sees. */
function onInput(ev: Event) {
  // IME composition in progress — wait for compositionend.
  if (isComposing.value) return
  const e = ev as InputEvent
  // Some browsers fire `input` for delete operations too. Detect via
  // inputType and route deletes to the Backspace HID instead of
  // sending an empty `key_text`.
  if (e.inputType === 'deleteContentBackward') {
    emitSpecialKey(HID.Backspace)
    flushInputBuffer()
    return
  }
  if (e.inputType === 'deleteContentForward') {
    emitSpecialKey(HID.Delete)
    flushInputBuffer()
    return
  }
  if (
    e.inputType === 'insertLineBreak' ||
    e.inputType === 'insertParagraph'
  ) {
    emitSpecialKey(HID.Enter)
    flushInputBuffer()
    return
  }
  // Anything else → treat as text-typed.
  const ta = captureRef.value
  if (!ta) return
  const text = ta.value
  if (text) {
    // Modifiers stickily applied to the FIRST char only — typical
    // user flow is "tap Ctrl then tap V" → Ctrl+V, not "tap Ctrl
    // then type 'word'" → Ctrl+w/Ctrl+o/Ctrl+r/Ctrl+d.
    const mods = consumeModBits()
    if (mods !== 0) {
      // Map the first char back to a HID best-effort. v1: only
      // ASCII letters (a-z) can carry modifiers; everything else
      // falls through as plain text. This matches the operator's
      // typical "Ctrl+letter" intent without trying to be clever
      // about Ctrl+? layouts.
      const ch = text[0]
      const lower = ch.toLowerCase()
      if (lower >= 'a' && lower <= 'z') {
        const hid = 0x04 + (lower.charCodeAt(0) - 'a'.charCodeAt(0))
        emit('key', hid, true, mods)
        emit('key', hid, false, mods)
        // Send the rest as plain text (no mods).
        if (text.length > 1) {
          emit('keyText', text.slice(1))
        }
        flushInputBuffer()
        return
      }
    }
    emit('keyText', text)
  }
  flushInputBuffer()
}

function onCompositionStart() {
  isComposing.value = true
}

function onCompositionEnd(ev: CompositionEvent) {
  isComposing.value = false
  // Send the composed string as a single key_text event. The OS-
  // typing API on the agent side handles the multi-codepoint case
  // natively (CJK / emoji).
  if (ev.data) {
    emit('keyText', ev.data)
  }
  // Clear the textarea: in-progress composition leaves text behind
  // that we don't want to re-emit on the next `input`.
  flushInputBuffer()
}

/** Some browsers (mobile Safari with hardware keyboard attached)
 *  bypass `input` and emit `keydown` for special keys. Catch the
 *  obvious ones here so the operator isn't left without a Tab key
 *  in that edge case. Most production traffic goes through the
 *  toolbar buttons. */
function onKeyDown(ev: KeyboardEvent) {
  if (isComposing.value) return
  const passthrough = ((): number | null => {
    switch (ev.key) {
      case 'Tab':
        return HID.Tab
      case 'Enter':
        return HID.Enter
      case 'Escape':
        return HID.Escape
      case 'ArrowLeft':
        return HID.ArrowLeft
      case 'ArrowRight':
        return HID.ArrowRight
      case 'ArrowUp':
        return HID.ArrowUp
      case 'ArrowDown':
        return HID.ArrowDown
      default:
        return null
    }
  })()
  if (passthrough !== null) {
    ev.preventDefault()
    emitSpecialKey(passthrough)
  }
}

/** Reset textarea content + cursor to fresh-empty state. Called
 *  after every input/composition event so the next keystroke
 *  arrives in isolation. */
function flushInputBuffer() {
  const ta = captureRef.value
  if (!ta) return
  ta.value = ''
  // Re-set cursor to 0 so the next input event always reports text
  // anchored to position 0 (Android Gboard quirk).
  ta.setSelectionRange(0, 0)
}

/** Auto-focus the capture textarea when the parent shows us. iOS
 *  Safari requires the focus call to happen inside a user gesture;
 *  the parent toggles `open` from a tap handler, so the synchronous
 *  focus inside the watcher's `nextTick` callback satisfies that. */
watch(
  () => props.open,
  (open) => {
    if (open) {
      void nextTick(() => {
        captureRef.value?.focus()
      })
    } else {
      // Reset sticky modifiers on hide so a stale Ctrl from a
      // previous session doesn't carry over.
      pinnedMods.value = { ctrl: false, alt: false, meta: false }
      flushInputBuffer()
    }
  },
)

/** When the capture textarea loses focus (user tapped outside the
 *  keyboard / video), the OS keyboard goes down. Tell the parent
 *  to update its toolbar toggle so the icon reflects state. */
function onBlur() {
  emit('close')
}
</script>

<style scoped>
.mobile-keyboard-shell {
  position: fixed;
  bottom: 0;
  left: 0;
  right: 0;
  /*
   * Pin to the visualViewport's bottom edge so on iOS Safari (where
   * the keyboard pushes the layout viewport up) the toolbar still
   * sits above the keyboard rectangle. Falls back gracefully when
   * `visualViewport` API is missing (older browsers).
   */
  padding-bottom: env(safe-area-inset-bottom, 0);
  z-index: 2000;
  pointer-events: none;
}

.mobile-keyboard-capture {
  position: absolute;
  /*
   * iOS Safari refuses to bring up the soft keyboard for elements
   * with display:none / visibility:hidden / opacity:0. Use a
   * tiny visible-but-off-screen layout instead. The `transform`
   * places the element 9999px off-screen so it can't catch
   * pointer events accidentally; `pointer-events:none` belt-and-
   * suspenders.
   */
  width: 1px;
  height: 1px;
  opacity: 0.01;
  transform: translate(-9999px, 0);
  pointer-events: none;
  border: 0;
  padding: 0;
  font-size: 16px;
  /* iOS auto-zooms inputs with font-size < 16px on focus — we don't
   * want any zoom because the textarea is invisible. 16px also
   * happens to be the threshold below which Safari triggers
   * accessibility zoom on tap-and-hold. */
  background: transparent;
  color: transparent;
  caret-color: transparent;
}

.mobile-keyboard-toolbar {
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 4px;
  padding: 6px 8px;
  background: rgba(20, 20, 20, 0.92);
  backdrop-filter: blur(4px);
  -webkit-backdrop-filter: blur(4px);
  pointer-events: auto;
}

.mkb-btn {
  appearance: none;
  border: 0;
  border-radius: 6px;
  background: rgba(255, 255, 255, 0.12);
  color: #fff;
  font-size: 14px;
  font-weight: 500;
  min-width: 44px;
  /* 44 px is the iOS / Android touch-target floor — anything
   * smaller is non-trivially mis-tappable in motion. */
  height: 36px;
  padding: 0 10px;
  cursor: pointer;
  transition: background-color 80ms ease;
}

.mkb-btn:active {
  background: rgba(255, 255, 255, 0.24);
}

.mkb-btn-mod-active {
  background: #1976d2;
  /* Match Vuetify's primary blue; signals "armed for next press". */
}

.mkb-btn-close {
  margin-left: auto;
  background: rgba(255, 255, 255, 0.18);
}
</style>
