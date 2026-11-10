// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-111 P4b-2 — the layout editor's pure half:
 *
 * - a member's own presets, kept in this browser (open decision 6, built to
 *   its recommendation): no server, no permission;
 * - the drafts the editor shapes, with unique ids;
 * - the server's own limits (`TouchPresetRequest::validate` in
 *   `remote_control`), so a draft is refused here with the code the server
 *   would answer, before it is saved anywhere.
 *
 * No DOM, so vitest drives it directly.
 */
import { MINE_PRESET_PREFIX } from './touchControls'
import type { ButtonControl, ControlPlace, MacroStep, TouchControl, TouchPreset } from './touchControls'

/** A member's own preset is offered under `mine:<id>`, beside the built-ins
 *  and the org's `org:` presets (defined beside them, in touchControls). */
export { MINE_PRESET_PREFIX }

/** Per user, in this browser. */
export const MY_PRESETS_STORAGE_PREFIX = 'meshharbor-rc-touch-presets:'

/** The server's limits, kept in lockstep with `TouchPresetRequest`. */
export const LIMITS = {
  name: 48,
  label: 16,
  id: 32,
  controls: 24,
  rowButtons: 12,
  chordKeys: 4,
  macroSteps: 32,
  stepWaitMs: 5000,
  macroMs: 30000,
  placePx: 4000,
  sizeMin: 48,
  sizeMax: 400,
  speedMin: 0.05,
  speedMax: 5,
  /** How many presets a member keeps in one browser (the org's cap). */
  mine: 50,
} as const

/** A HID usage the keyboard path can send: the Keyboard/Keypad page's keys and
 *  its eight modifiers, as the server allows. */
export function touchKeyOk(k: unknown): boolean {
  return Number.isInteger(k) && (((k as number) >= 0x04 && (k as number) <= 0xa4) || ((k as number) >= 0xe0 && (k as number) <= 0xe7))
}

function textOk(s: unknown, max: number): boolean {
  if (typeof s !== 'string') return false
  // eslint-disable-next-line no-control-regex
  return [...s].length <= max && !/[\u0000-\u001f\u007f-\u009f]/.test(s)
}

function placeOk(at: ControlPlace | undefined): string | null {
  if (!at || typeof at !== 'object') return 'place_invalid'
  if ((at.left !== undefined && at.right !== undefined) || (at.top !== undefined && at.bottom !== undefined)) {
    return 'place_both_edges'
  }
  for (const v of [at.left, at.right, at.top, at.bottom]) {
    if (v === undefined) continue
    if (typeof v !== 'number' || !Number.isFinite(v) || v < 0 || v > LIMITS.placePx) return 'place_invalid'
  }
  return null
}

function stepOk(s: MacroStep): string | null {
  const hasKey = s.key !== undefined
  const hasBtn = s.btn !== undefined
  if (hasKey === hasBtn) return 'step_key_or_button'
  if (hasKey && !touchKeyOk(s.key)) return 'key_invalid'
  if (hasBtn && !['left', 'right', 'middle'].includes(s.btn as string)) return 'step_key_or_button'
  if (!['press', 'release', 'tap'].includes(s.op)) return 'step_key_or_button'
  const w = s.wait_ms ?? 0
  if (!Number.isInteger(w) || w < 0 || w > LIMITS.stepWaitMs) return 'step_wait'
  return null
}

function buttonOk(b: ButtonControl): string | null {
  if (!textOk(b.label, LIMITS.label) || b.label.trim() === '') return 'label_invalid'
  const a = b.action
  if (a.kind === 'keys') {
    if (a.keys.length === 0 || a.keys.length > LIMITS.chordKeys) return 'chord_keys'
    if (!a.keys.every(touchKeyOk)) return 'key_invalid'
  } else if (a.kind === 'macro') {
    if (a.steps.length === 0 || a.steps.length > LIMITS.macroSteps) return 'macro_steps'
    let total = 0
    for (const s of a.steps) {
      const bad = stepOk(s)
      if (bad) return bad
      total += s.wait_ms ?? 0
    }
    if (total > LIMITS.macroMs) return 'macro_too_long'
  } else if (!['left', 'right', 'middle'].includes(a.btn)) {
    return 'label_invalid'
  }
  return null
}

/** The server's verdict on a draft, here: `null` when it would be stored, or
 *  the refusal code it would answer (the same codes). */
export function validatePreset(p: { name: string; controls: TouchControl[] }): string | null {
  const name = (p.name ?? '').trim()
  if (name === '') return 'name_empty'
  if (!textOk(name, LIMITS.name)) return 'name_invalid'
  if (!Array.isArray(p.controls) || p.controls.length === 0) return 'no_controls'
  if (p.controls.length > LIMITS.controls) return 'too_many_controls'
  const ids = new Set<string>()
  const id = (s: string): string | null => {
    if (!s || !textOk(s, LIMITS.id)) return 'id_invalid'
    if (ids.has(s)) return 'id_duplicate'
    ids.add(s)
    return null
  }
  for (const c of p.controls) {
    const bad = id(c.id) ?? placeOk(c.at)
    if (bad) return bad
    if (c.kind === 'row') {
      if (c.buttons.length === 0 || c.buttons.length > LIMITS.rowButtons) return 'row_buttons'
      for (const b of c.buttons) {
        const bb = id(b.id) ?? buttonOk(b)
        if (bb) return bb
      }
    } else {
      if (!textOk(c.label, LIMITS.label) || c.label.trim() === '') return 'label_invalid'
      if (!Number.isInteger(c.size) || c.size < LIMITS.sizeMin || c.size > LIMITS.sizeMax) return 'size_invalid'
      if (c.kind === 'dpad') {
        if (![c.up, c.down, c.left, c.right].every(touchKeyOk)) return 'key_invalid'
      } else if (!Number.isFinite(c.speed) || c.speed < LIMITS.speedMin || c.speed > LIMITS.speedMax) {
        return 'speed_invalid'
      }
    }
  }
  return null
}

/** What the editor says for a refusal code, the server's or its own. */
export function describeRefusal(code: string): string {
  switch (code) {
    case 'name_empty':
      return 'Give the layout a name.'
    case 'name_invalid':
      return `A name is at most ${LIMITS.name} characters, on one line.`
    case 'no_controls':
      return 'Add at least one control.'
    case 'too_many_controls':
      return `A layout has at most ${LIMITS.controls} controls.`
    case 'id_invalid':
    case 'id_duplicate':
      return 'Two controls share an id; remove one and add it again.'
    case 'label_invalid':
      return `Every control and button needs a label of at most ${LIMITS.label} characters.`
    case 'row_buttons':
      return `A row has between 1 and ${LIMITS.rowButtons} buttons.`
    case 'chord_keys':
      return `A key button presses between 1 and ${LIMITS.chordKeys} keys.`
    case 'key_invalid':
      return 'A key cannot be sent from the keyboard; capture it again.'
    case 'size_invalid':
      return `A size is between ${LIMITS.sizeMin} and ${LIMITS.sizeMax} pixels.`
    case 'speed_invalid':
      return `A stick's speed is between ${LIMITS.speedMin} and ${LIMITS.speedMax}.`
    case 'place_both_edges':
      return 'Place a control from one edge per direction, not both.'
    case 'place_invalid':
      return `An edge distance is between 0 and ${LIMITS.placePx} pixels.`
    case 'macro_steps':
      return `A macro has between 1 and ${LIMITS.macroSteps} steps.`
    case 'step_key_or_button':
      return 'Each macro step presses either a key or a mouse button.'
    case 'step_wait':
      return `A wait is at most ${LIMITS.stepWaitMs / 1000} s.`
    case 'macro_too_long':
      return `A macro lasts at most ${LIMITS.macroMs / 1000} s in all.`
    case 'name_taken':
      return 'The organization already has a layout of that name.'
    case 'too_many_presets':
      return `The organization keeps at most ${LIMITS.mine} layouts.`
    case 'invalid_json':
      return 'The server did not take the layout. Reload the page, then try again.'
    default:
      return 'The layout could not be saved.'
  }
}

const NAMED_KEYS: Record<number, string> = {
  0x28: 'Enter',
  0x29: 'Esc',
  0x2a: 'Backspace',
  0x2b: 'Tab',
  0x2c: 'Space',
  0x2d: '-',
  0x2e: '=',
  0x2f: '[',
  0x30: ']',
  0x31: '\\',
  0x33: ';',
  0x34: "'",
  0x35: '`',
  0x36: ',',
  0x37: '.',
  0x38: '/',
  0x39: 'Caps Lock',
  0x46: 'Print Screen',
  0x48: 'Pause',
  0x49: 'Insert',
  0x4a: 'Home',
  0x4b: 'Page Up',
  0x4c: 'Delete',
  0x4d: 'End',
  0x4e: 'Page Down',
  0x4f: '→',
  0x50: '←',
  0x51: '↓',
  0x52: '↑',
  0xe0: 'Ctrl',
  0xe1: 'Shift',
  0xe2: 'Alt',
  0xe3: 'Meta',
  0xe4: 'Right Ctrl',
  0xe5: 'Right Shift',
  0xe6: 'Right Alt',
  0xe7: 'Right Meta',
}

/** What the editor shows for a HID usage: the key's name, or its code. */
export function keyName(code: number): string {
  if (code >= 0x04 && code <= 0x1d) return String.fromCharCode(65 + code - 0x04)
  if (code >= 0x1e && code <= 0x26) return String(code - 0x1d)
  if (code === 0x27) return '0'
  if (code >= 0x3a && code <= 0x45) return `F${code - 0x39}`
  if (code >= 0x68 && code <= 0x73) return `F${code - 0x68 + 13}`
  return NAMED_KEYS[code] ?? `0x${code.toString(16)}`
}

/** A chord as the editor shows it: `Ctrl + C`. */
export function chordName(keys: readonly number[]): string {
  return keys.map(keyName).join(' + ')
}

/** A fresh `mine:` id. */
export function newMineId(rand: () => number = Math.random): string {
  return MINE_PRESET_PREFIX + Math.floor(rand() * 2 ** 48).toString(36)
}

/** A member's own presets, from this browser: only entries that are presets
 *  the server would take, each under a `mine:` id; anything else (a hand
 *  edit, a newer build's shape, storage that throws) is left out. */
export function readMyPresets(storage: Pick<Storage, 'getItem'> | null | undefined, userId: string): TouchPreset[] {
  try {
    const raw = storage?.getItem(MY_PRESETS_STORAGE_PREFIX + userId)
    if (!raw) return []
    const items: unknown = JSON.parse(raw)
    if (!Array.isArray(items)) return []
    const out: TouchPreset[] = []
    for (const it of items.slice(0, LIMITS.mine)) {
      const p = it as Partial<TouchPreset>
      if (typeof p?.id !== 'string' || !p.id.startsWith(MINE_PRESET_PREFIX)) continue
      if (typeof p.name !== 'string' || !Array.isArray(p.controls)) continue
      if (validatePreset({ name: p.name, controls: p.controls }) !== null) continue
      if (out.some((o) => o.id === p.id)) continue
      out.push({ id: p.id, name: p.name.trim(), controls: p.controls })
    }
    return out
  } catch {
    return []
  }
}

/** Keep a member's own presets in this browser; `false` when storage refuses
 *  (blocked site data, a full quota). */
export function writeMyPresets(
  storage: Pick<Storage, 'setItem'> | null | undefined,
  userId: string,
  presets: readonly TouchPreset[],
): boolean {
  try {
    if (!storage) return false
    storage.setItem(MY_PRESETS_STORAGE_PREFIX + userId, JSON.stringify(presets.slice(0, LIMITS.mine)))
    return true
  } catch {
    return false
  }
}

/** A deep copy to edit, under a new `mine:` id. A built-in or an org preset is
 *  only ever copied, never changed in place. */
export function copyForEdit(p: TouchPreset, name = p.name, rand: () => number = Math.random): TouchPreset {
  return { id: newMineId(rand), name: [...name].slice(0, LIMITS.name).join(''), controls: JSON.parse(JSON.stringify(p.controls)) }
}

/** An id no control or button in `controls` uses yet. */
export function freeId(controls: readonly TouchControl[], stem: string): string {
  const taken = new Set<string>()
  for (const c of controls) {
    taken.add(c.id)
    if (c.kind === 'row') for (const b of c.buttons) taken.add(b.id)
  }
  for (let i = 1; ; i++) {
    const id = `${stem}${i}`
    if (!taken.has(id)) return id
  }
}

/** New controls, placed where a thumb finds them. */
export function newRow(controls: readonly TouchControl[]): TouchControl {
  const id = freeId(controls, 'row')
  return {
    kind: 'row',
    id,
    at: { bottom: 12 },
    buttons: [{ id: `${id}-b1`, label: 'Esc', action: { kind: 'keys', keys: [0x29] } }],
  }
}

export function newDpad(controls: readonly TouchControl[]): TouchControl {
  return {
    kind: 'dpad',
    id: freeId(controls, 'pad'),
    label: 'Move',
    at: { left: 16, bottom: 16 },
    size: 150,
    up: 0x52,
    down: 0x51,
    left: 0x50,
    right: 0x4f,
  }
}

export function newStick(controls: readonly TouchControl[]): TouchControl {
  return { kind: 'stick', id: freeId(controls, 'stick'), label: 'Mouse', at: { right: 16, bottom: 16 }, size: 150, speed: 1 }
}

/** A new button for a row, with an id the preset does not use yet. */
export function newButton(controls: readonly TouchControl[], rowId: string): ButtonControl {
  return { id: freeId(controls, `${rowId}-b`), label: 'Key', action: { kind: 'keys', keys: [0x2c] } }
}
