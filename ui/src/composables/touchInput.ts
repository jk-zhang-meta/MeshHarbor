// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
// FR-111 — touch on the stage: the pieces that need no DOM, so they can be
// tested as plain functions. The wiring (the stage's listeners, its
// `touch-action`) lives in useRemoteControl.ts and RemoteControl.vue.

/** Viewer-side kill switch: `localStorage['meshharbor-rc-touch'] = 'legacy'` gives
 *  the stage back to the browser's own touch handling (pan and zoom over the
 *  picture), as before FR-111. */
export const TOUCH_STORAGE_KEY = 'meshharbor-rc-touch'

/** The stage's `touch-action`. `none` hands every touch on the picture to the
 *  viewer: without it a touch browser takes a drag over as a pan, ends the
 *  pointer with `pointercancel`, and the press already forwarded to the host
 *  is never let go (FR-111 P0, §8 row 1). Storage that throws (a private
 *  window, blocked site data) reads as "not switched off". */
export function stageTouchAction(storage: Pick<Storage, 'getItem'> | null | undefined): 'none' | 'auto' {
  try {
    return storage?.getItem(TOUCH_STORAGE_KEY) === 'legacy' ? 'auto' : 'none'
  } catch {
    return 'none'
  }
}

/** Which button each pointer pressed on the host, so the end of that pointer
 *  (`pointerup`, or a `pointercancel` that never brings one) releases exactly
 *  what it pressed, and a pointer that pressed nothing releases nothing. */
export interface PointerPressTracker {
  press(pointerId: number, btn: string): void
  /** The button this pointer pressed, forgotten as it is returned; `undefined`
   *  when it pressed nothing (or was already released). */
  end(pointerId: number): string | undefined
  size(): number
}

export function createPointerPressTracker(): PointerPressTracker {
  const pressed = new Map<number, string>()
  return {
    press(pointerId: number, btn: string) {
      pressed.set(pointerId, btn)
    },
    end(pointerId: number) {
      const btn = pressed.get(pointerId)
      pressed.delete(pointerId)
      return btn
    },
    size() {
      return pressed.size
    },
  }
}

/** The frame that lets go of a cancelled pointer's press. A cancel carries no
 *  position worth trusting, so absolute mode releases at the last position the
 *  pointer reached; relative mode (FR-109) releases where the host's pointer
 *  is, with `mouse_release`, as every relative release does. */
export function releaseForCancelledPointer(
  btn: string,
  relative: boolean,
  last: { x: number; y: number },
):
  | { t: 'mouse_release'; btn: string }
  | { t: 'mouse_button'; btn: string; down: false; x: number; y: number; mon: 0 } {
  if (relative) return { t: 'mouse_release', btn }
  return { t: 'mouse_button', btn, down: false, x: last.x, y: last.y, mon: 0 }
}

/** FR-111 P2 — how a finger drives the host: `direct` (the finger is the
 *  pointer, today's) or `trackpad` (the screen is a laptop's trackpad). */
export type TouchMode = 'direct' | 'trackpad'

/** Where this browser remembers the touch mode. */
export const TOUCH_MODE_STORAGE_KEY = 'meshharbor-rc-touch-mode'

/** A screen whose shorter side is under this many CSS px is a phone's. */
export const PHONE_SHORT_SIDE_PX = 600

/** FR-111 decision 1 — is this a phone-sized screen? Read from the screen, not
 *  the window, so a small desktop window is not a phone. */
export function phoneSized(screen: { width: number; height: number } | null | undefined): boolean {
  if (!screen) return false
  const short = Math.min(screen.width, screen.height)
  return Number.isFinite(short) && short > 0 && short < PHONE_SHORT_SIDE_PX
}

/** The touch mode: the remembered word when it is exactly `trackpad` or
 *  `direct` (the toolbar's choice). With nothing remembered, FR-111 decision 1
 *  (operator, 2026-10-17): `trackpad` on a phone-sized screen, `direct` on a
 *  larger one. Storage that throws counts as nothing remembered. */
export function readTouchMode(storage: Pick<Storage, 'getItem'> | null | undefined, phone = false): TouchMode {
  let remembered: string | null = null
  try {
    remembered = storage?.getItem(TOUCH_MODE_STORAGE_KEY) ?? null
  } catch {
    remembered = null
  }
  if (remembered === 'trackpad' || remembered === 'direct') return remembered
  return phone ? 'trackpad' : 'direct'
}

/** FR-111 decision 4 — does the picture overflow the stage? Then two fingers
 *  moving together pan it, and the host scrolls only once it fits. A pixel of
 *  slack absorbs rounding in the layout. */
export function pictureOverflows(stage: {
  scrollWidth: number
  clientWidth: number
  scrollHeight: number
  clientHeight: number
}): boolean {
  return stage.scrollWidth > stage.clientWidth + 1 || stage.scrollHeight > stage.clientHeight + 1
}
