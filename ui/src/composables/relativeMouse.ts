// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
// FR-109 — relative mouse: the pieces of Pointer Lock mode that need no DOM,
// so they can be tested as plain functions. The wiring (requestPointerLock,
// the input pump) lives in useRemoteControl.ts.

/** The agent's word for "I inject relative motion" in `AgentCaps.input`.
 *  Matched by equality, never as a prefix: an unknown word is ignored. */
export const MOUSE_REL_CAP = 'mouse-rel'

/** Viewer-side kill switch: `localStorage['meshharbor-rc-relative-mouse'] = 'off'`
 *  hides the relative-mouse control, whatever the agent advertises. */
export const RELATIVE_MOUSE_STORAGE_KEY = 'meshharbor-rc-relative-mouse'

/** Does this agent take `mouse_rel` / `mouse_press`? Only one that says so:
 *  an older agent cannot parse either frame. */
export function agentSupportsRelativeMouse(input: readonly string[] | null | undefined): boolean {
  return Array.isArray(input) && input.includes(MOUSE_REL_CAP)
}

/** The viewer's kill switch, read where the control is offered. Storage that
 *  throws (a private window, blocked site data) reads as "not switched off". */
export function relativeMouseSwitchedOff(storage: Pick<Storage, 'getItem'> | null | undefined): boolean {
  try {
    return storage?.getItem(RELATIVE_MOUSE_STORAGE_KEY) === 'off'
  } catch {
    return false
  }
}

/** Sums Pointer Lock deltas between sends. `take()` hands out whole counts
 *  and keeps the fraction for the next send, so slow motion (a high-DPI
 *  mouse reports fractional `movementX`) is never rounded away. */
export interface RelAccumulator {
  add(dx: number, dy: number): void
  /** The whole counts gathered so far, or `null` when there is nothing to
   *  send yet. */
  take(): { dx: number; dy: number } | null
  reset(): void
}

export function createRelAccumulator(): RelAccumulator {
  let x = 0
  let y = 0
  return {
    add(dx, dy) {
      if (Number.isFinite(dx)) x += dx
      if (Number.isFinite(dy)) y += dy
    },
    take() {
      const dx = Math.trunc(x)
      const dy = Math.trunc(y)
      if (dx === 0 && dy === 0) return null
      x -= dx
      y -= dy
      return { dx, dy }
    },
    reset() {
      x = 0
      y = 0
    },
  }
}

/** FR-109 P3 — viewer-side kill switch for the auto-switch alone:
 *  `localStorage['meshharbor-rc-relative-auto'] = 'off'` keeps relative mode
 *  manual (the toolbar control still works). */
export const RELATIVE_AUTO_STORAGE_KEY = 'meshharbor-rc-relative-auto'

export function relativeAutoSwitchedOff(storage: Pick<Storage, 'getItem'> | null | undefined): boolean {
  try {
    return storage?.getItem(RELATIVE_AUTO_STORAGE_KEY) === 'off'
  } catch {
    return false
  }
}

/** What the auto-switch decides on, read at the moment of a click inside the
 *  picture. */
export interface AutoEnterState {
  /** The agent advertises `mouse-rel` and the viewer has not switched it off. */
  allowed: boolean
  /** `meshharbor-rc-relative-auto` is `off`. */
  autoOff: boolean
  /** The agent said `cursor:hide` and no `cursor:pos` has come since. */
  cursorHidden: boolean
  /** The agent has reported the host's pointer on this channel (a `cursor:pos`
   *  or `cursor:shape`). A tracker that cannot see the pointer (Linux without
   *  DRM capture, macOS) sends one `cursor:hide` at the start and nothing
   *  after it, so a hide means "an app hid the cursor" only after this. */
  cursorTracked: boolean
  /** The host's input desktop is the lock screen (`rc:host_locked`). */
  hostLocked: boolean
  /** The person left relative mode while the cursor stayed hidden: no
   *  re-entry until the cursor shows again. */
  suppressed: boolean
  relativeActive: boolean
  inputGranted: boolean
}

/** FR-109 P3 — should this click enter relative mode by itself? Only when the
 *  host has hidden its cursor (an app captured the pointer) and every other
 *  gate agrees. ⚠️ The lock screen hides the cursor too, so a locked host never
 *  switches; once the person has left with Esc, a still-hidden cursor does not
 *  pull them back in on the next click; and a host that never reported a
 *  pointer (whose only cursor message is that first `cursor:hide`) never
 *  switches, or its first click would take the pointer. */
export function shouldAutoEnterRelative(s: AutoEnterState): boolean {
  return s.allowed && !s.autoOff && s.cursorHidden && s.cursorTracked && !s.hostLocked
    && !s.suppressed && !s.relativeActive && s.inputGranted
}

/** A button in relative mode presses and lets go WHERE THE POINTER IS:
 *  `mouse_button` carries a position every backend moves to first, and in
 *  Pointer Lock the viewer has none to send (the host app owns the cursor). */
export function relativeButtonMessage(btn: string, down: boolean): Record<string, unknown> {
  return down ? { t: 'mouse_press', btn } : { t: 'mouse_release', btn }
}
