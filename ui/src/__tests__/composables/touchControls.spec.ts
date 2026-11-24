// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, expect, it } from 'vitest'
import {
  BUILTIN_PRESETS,
  CONTROLS_STORAGE_PREFIX,
  controlLabel,
  createControlsDriver,
  dpadKeys,
  fitControls,
  HID,
  TC_BUTTON_GAP,
  TC_BUTTON_HEIGHT,
  TC_PAD_MIN,
  hidLabel,
  MACRO_STEP_MAX_MS,
  modsOf,
  ORG_PRESET_PREFIX,
  orgPresets,
  placeStyle,
  presetById,
  readControlsPreset,
  stickVelocity,
  type ButtonControl,
  type ControlsSink,
  type DpadControl,
  type DriverTimers,
  type MouseBtn,
  type StickControl,
} from '@/composables/touchControls'
import { kbdCodeToHid } from '@/composables/useRemoteControl'

type Sent =
  | { k: number; down: boolean }
  | { b: MouseBtn; down: boolean }
  | { dx: number; dy: number }
  | { begin: true }
  | { end: true }

function recordingSink(width = 1280): { sink: ControlsSink; sent: Sent[] } {
  const sent: Sent[] = []
  return {
    sent,
    sink: {
      key: (k, down) => sent.push({ k, down }),
      button: (b, down) => sent.push({ b, down }),
      move: (dx, dy) => sent.push({ dx, dy }),
      begin: () => sent.push({ begin: true }),
      end: () => sent.push({ end: true }),
      width: () => width,
    },
  }
}

const wasd: DpadControl = {
  kind: 'dpad',
  id: 'move',
  label: 'W A S D',
  at: {},
  size: 150,
  up: HID.KeyW,
  down: HID.KeyS,
  left: HID.KeyA,
  right: HID.KeyD,
}
const look: StickControl = { kind: 'stick', id: 'look', label: 'look', at: {}, size: 150, speed: 1 }
const copy: ButtonControl = { id: 'copy', label: 'Ctrl+C', action: { kind: 'keys', keys: [HID.ControlLeft, HID.KeyC] } }
const ctrl: ButtonControl = { id: 'ctrl', label: 'Ctrl', action: { kind: 'keys', keys: [HID.ControlLeft] } }
const fire: ButtonControl = { id: 'fire', label: 'Fire', action: { kind: 'mouse', btn: 'left' } }

describe('FR-111 P3 presets', () => {
  it('names every key by the HID usage the keyboard path sends for it', () => {
    for (const [name, code] of Object.entries(HID)) {
      expect(kbdCodeToHid(name), name).toBe(code)
    }
  })

  it('ships the office row, arrows and WASD with mouse look, each control and button with its own id', () => {
    expect(BUILTIN_PRESETS.map((p) => p.id)).toEqual(['office', 'arrows', 'wasd'])
    const codes = new Set<number>(Object.values(HID))
    for (const p of BUILTIN_PRESETS) {
      expect(p.name.length).toBeGreaterThan(0)
      const ids = p.controls.map((c) => c.id)
      expect(new Set(ids).size, p.id).toBe(ids.length)
      for (const c of p.controls) {
        if (c.kind !== 'row') continue
        const bids = c.buttons.map((b) => b.id)
        expect(new Set(bids).size, `${p.id}/${c.id}`).toBe(bids.length)
        for (const b of c.buttons) {
          if (b.action.kind === 'keys') {
            expect(b.action.keys.length).toBeGreaterThan(0)
            for (const k of b.action.keys) expect(codes.has(k), `${p.id}/${b.id}`).toBe(true)
          }
        }
      }
    }
  })
})

describe('FR-111 P3 readControlsPreset', () => {
  const store = (m: Record<string, string>): Pick<Storage, 'getItem'> => ({
    getItem: (k: string) => m[k] ?? null,
  })

  it('is off unless this browser chose a preset for this device', () => {
    expect(readControlsPreset(store({}), 'dev1')).toBeNull()
    expect(readControlsPreset(null, 'dev1')).toBeNull()
    const s = store({ [CONTROLS_STORAGE_PREFIX + 'dev1']: 'wasd' })
    expect(readControlsPreset(s, 'dev1')).toBe('wasd')
    expect(readControlsPreset(s, 'dev2')).toBeNull()
  })

  it('reads an id this build does not know, or storage that throws, as off', () => {
    expect(readControlsPreset(store({ [CONTROLS_STORAGE_PREFIX + 'dev1']: 'racing' }), 'dev1')).toBeNull()
    expect(readControlsPreset({ getItem: () => { throw new Error('SecurityError') } }, 'dev1')).toBeNull()
  })
})

describe('FR-111 P3 placeStyle and hidLabel', () => {
  it('places a control by its edges and centres an axis with none', () => {
    expect(placeStyle({ left: 16, bottom: 16 })).toEqual({ left: '16px', bottom: '16px' })
    expect(placeStyle({ bottom: 12 })).toEqual({ bottom: '12px', left: '50%', transform: 'translate(-50%, 0)' })
    expect(placeStyle({})).toEqual({ left: '50%', top: '50%', transform: 'translate(-50%, -50%)' })
  })

  it('labels a d-pad arm with its letter or its arrow', () => {
    expect([HID.KeyW, HID.KeyA, HID.KeyS, HID.KeyD].map(hidLabel)).toEqual(['W', 'A', 'S', 'D'])
    expect([HID.ArrowUp, HID.ArrowDown, HID.ArrowLeft, HID.ArrowRight].map(hidLabel)).toEqual(['▲', '▼', '◀', '▶'])
    expect(hidLabel(HID.Space)).toBe('')
  })
})

describe('FR-111 P3 controlLabel', () => {
  it('shows Cmd for a Ctrl chord on a Mac host that turns Ctrl into Cmd', () => {
    expect(controlLabel('Ctrl+C', true)).toBe('⌘C')
    expect(controlLabel('Ctrl+C', false)).toBe('Ctrl+C')
    expect(controlLabel('Alt+Tab', true)).toBe('Alt+Tab')
    expect(controlLabel('Ctrl', true)).toBe('Ctrl')
  })
})

describe('FR-111 P3 dpadKeys', () => {
  it('holds nothing near the centre', () => {
    expect(dpadKeys(wasd, 0, 0)).toEqual([])
    expect(dpadKeys(wasd, 0.2, 0)).toEqual([])
  })

  it('holds one key along an axis and two on a diagonal', () => {
    expect(dpadKeys(wasd, 0, -1)).toEqual([HID.KeyW])
    expect(dpadKeys(wasd, 0, 1)).toEqual([HID.KeyS])
    expect(dpadKeys(wasd, -1, 0)).toEqual([HID.KeyA])
    expect(dpadKeys(wasd, 1, 0)).toEqual([HID.KeyD])
    // 10° below right is still right; 45° is the diagonal.
    const deg = (d: number) => [Math.cos((d * Math.PI) / 180), Math.sin((d * Math.PI) / 180)] as const
    expect(dpadKeys(wasd, ...deg(10))).toEqual([HID.KeyD])
    expect(dpadKeys(wasd, ...deg(45))).toEqual([HID.KeyS, HID.KeyD])
    expect(dpadKeys(wasd, ...deg(-135))).toEqual([HID.KeyW, HID.KeyA])
  })
})

describe('FR-111 P3 stickVelocity', () => {
  it('moves nothing inside the deadzone and a picture a second at full push', () => {
    expect(stickVelocity(0.1, 0, 1, 1280)).toEqual({ vx: 0, vy: 0 })
    const full = stickVelocity(1, 0, 1, 1280)
    expect(full.vx).toBeCloseTo(1280)
    expect(full.vy).toBeCloseTo(0)
    // Past the rim it stays at full speed.
    expect(stickVelocity(0, -2, 1, 1280).vy).toBeCloseTo(-1280)
  })

  it('grows with the square of the push, so a small push is precise', () => {
    const half = stickVelocity(0.575, 0, 1, 1000) // halfway between the deadzone and the rim
    expect(half.vx).toBeCloseTo(250)
  })
})

describe('FR-111 P3 modsOf', () => {
  it('reads the modifier bits from the held usages', () => {
    expect(modsOf([])).toBe(0)
    expect(modsOf([0xe0, 0x06])).toBe(1)
    expect(modsOf([0xe1, 0xe6])).toBe(2 | 4)
    expect(modsOf([0xe3])).toBe(8)
  })
})

describe('FR-111 P3 createControlsDriver', () => {
  it('a chord presses in order and releases in reverse', () => {
    const { sink, sent } = recordingSink()
    const d = createControlsDriver(sink)
    d.pressButton(1, copy)
    d.release(1)
    expect(sent).toEqual([
      { k: HID.ControlLeft, down: true },
      { k: HID.KeyC, down: true },
      { k: HID.KeyC, down: false },
      { k: HID.ControlLeft, down: false },
    ])
    expect(d.active()).toBe(false)
  })

  it('two fingers holding one key press it once and release it after the last', () => {
    const { sink, sent } = recordingSink()
    const d = createControlsDriver(sink)
    d.pressButton(1, ctrl)
    d.pressButton(2, copy)
    d.release(1)
    expect(sent).toEqual([
      { k: HID.ControlLeft, down: true },
      { k: HID.KeyC, down: true },
    ])
    d.release(2)
    expect(sent.slice(2)).toEqual([
      { k: HID.KeyC, down: false },
      { k: HID.ControlLeft, down: false },
    ])
  })

  it('a finger sliding round the d-pad lets go of the old key before it presses the new one', () => {
    const { sink, sent } = recordingSink()
    const d = createControlsDriver(sink)
    d.pressDpad(1, wasd, 0, -1) // up
    d.move(1, 0.7, -0.7) // up-right
    expect(d.keysOf(1)).toEqual([HID.KeyW, HID.KeyD])
    d.move(1, 1, 0) // right
    d.move(1, 0, 0) // back to the centre
    d.release(1)
    expect(sent).toEqual([
      { k: HID.KeyW, down: true },
      { k: HID.KeyD, down: true },
      { k: HID.KeyW, down: false },
      { k: HID.KeyD, down: false },
    ])
  })

  it('a mouse button holds the button', () => {
    const { sink, sent } = recordingSink()
    const d = createControlsDriver(sink)
    d.pressButton(3, fire)
    d.release(3)
    expect(sent).toEqual([
      { b: 'left', down: true },
      { b: 'left', down: false },
    ])
  })

  it('a held stick moves the pointer every tick, and stops when it is let go', () => {
    const { sink, sent } = recordingSink(1000)
    const d = createControlsDriver(sink)
    d.pressStick(4, look, 1, 0, 1000)
    expect(sent).toEqual([{ begin: true }])
    expect(d.tick(1100)).toBe(true) // 100 ms at full push: a tenth of the picture
    const m = sent[1] as { dx: number; dy: number }
    expect(m.dx).toBeCloseTo(100)
    expect(m.dy).toBeCloseTo(0)
    d.move(4, 0.05, 0) // inside the deadzone
    expect(d.tick(1200)).toBe(true)
    expect(sent.length).toBe(2)
    d.release(4)
    expect(sent[2]).toEqual({ end: true })
    expect(d.tick(1300)).toBe(false)
    expect(sent.length).toBe(3)
  })

  it('two sticks begin once and end only when the last one lets go', () => {
    const { sink, sent } = recordingSink(1000)
    const d = createControlsDriver(sink)
    d.pressStick(4, look, 0, 0, 0)
    d.pressStick(5, look, 0, 0, 0)
    d.release(4)
    expect(sent).toEqual([{ begin: true }])
    d.release(5)
    expect(sent).toEqual([{ begin: true }, { end: true }])
  })

  it('a stall between ticks never throws the pointer: one tick moves at most 100 ms', () => {
    const { sink, sent } = recordingSink(1000)
    const d = createControlsDriver(sink)
    d.pressStick(4, look, 1, 0, 0)
    d.tick(5000)
    expect((sent[1] as { dx: number }).dx).toBeCloseTo(100)
  })

  it('releaseAll lets go of every finger, and ignores a second press by the same finger', () => {
    const { sink, sent } = recordingSink()
    const d = createControlsDriver(sink)
    d.pressButton(1, copy)
    d.pressButton(1, fire) // the same finger: ignored
    d.pressDpad(2, wasd, -1, 0)
    d.move(9, 1, 0) // a finger the driver never saw: ignored
    d.releaseAll()
    expect(sent).toEqual([
      { k: HID.ControlLeft, down: true },
      { k: HID.KeyC, down: true },
      { k: HID.KeyA, down: true },
      { k: HID.KeyA, down: false },
      { k: HID.KeyC, down: false },
      { k: HID.ControlLeft, down: false },
    ])
    expect(d.active()).toBe(false)
  })
})

/** Timers the test steps by hand: each `set` queues, `run` fires the next. */
function fakeTimers() {
  const queue: Array<{ fn: () => void; ms: number; live: boolean }> = []
  return {
    waits: () => queue.map((q) => q.ms),
    pending: () => queue.filter((q) => q.live).length,
    timers: {
      set: (fn: () => void, ms: number) => {
        const t = { fn, ms, live: true }
        queue.push(t)
        return t
      },
      clear: (h: unknown) => {
        ;(h as { live: boolean }).live = false
      },
    } satisfies DriverTimers,
    /** Fire every live timer, oldest first, until none is left. */
    drain() {
      for (let guard = 0; guard < 100; guard++) {
        const t = queue.find((q) => q.live)
        if (!t) return
        t.live = false
        t.fn()
      }
    },
  }
}

const pasteTwice: ButtonControl = {
  id: 'paste2',
  label: 'Paste x2',
  action: {
    kind: 'macro',
    steps: [
      { op: 'press', key: HID.ControlLeft },
      { op: 'tap', key: HID.KeyV, wait_ms: 120 },
      { op: 'tap', key: HID.KeyV },
      { op: 'release', key: HID.ControlLeft },
    ],
  },
}

describe('FR-111 P4 macros', () => {
  it('plays its steps in order, a tap as a press and a release, with the waits between', () => {
    const { sink, sent } = recordingSink()
    const t = fakeTimers()
    const d = createControlsDriver(sink, t.timers)
    d.pressButton(1, pasteTwice)
    expect(sent).toEqual([{ k: HID.ControlLeft, down: true }])
    expect(d.playing('paste2')).toBe(true)
    t.drain()
    expect(sent).toEqual([
      { k: HID.ControlLeft, down: true },
      { k: HID.KeyV, down: true },
      { k: HID.KeyV, down: false },
      { k: HID.KeyV, down: true },
      { k: HID.KeyV, down: false },
      { k: HID.ControlLeft, down: false },
    ])
    expect(t.waits()).toEqual([0, 120, 0, 0])
    expect(d.playing('paste2')).toBe(false)
  })

  it('plays to its end after the finger lifts, and ignores a press while it plays', () => {
    const { sink, sent } = recordingSink()
    const t = fakeTimers()
    const d = createControlsDriver(sink, t.timers)
    d.pressButton(1, pasteTwice)
    d.release(1)
    d.pressButton(2, pasteTwice) // still playing: ignored
    d.release(2)
    expect(d.active()).toBe(true)
    t.drain()
    expect(sent.filter((s) => 'k' in s && s.k === HID.KeyV && s.down)).toHaveLength(2)
    expect(d.active()).toBe(false)
    // Once it has finished, a press plays it again.
    d.pressButton(3, pasteTwice)
    t.drain()
    expect(sent.filter((s) => 'k' in s && s.k === HID.KeyV && s.down)).toHaveLength(4)
  })

  it('releaseAll stops it and lets go of what it holds', () => {
    const { sink, sent } = recordingSink()
    const t = fakeTimers()
    const d = createControlsDriver(sink, t.timers)
    d.pressButton(1, pasteTwice)
    d.releaseAll()
    expect(sent).toEqual([
      { k: HID.ControlLeft, down: true },
      { k: HID.ControlLeft, down: false },
    ])
    expect(t.pending()).toBe(0)
    t.drain() // a cleared step never runs
    expect(sent).toHaveLength(2)
    expect(d.playing('paste2')).toBe(false)
  })

  it('releases only what it pressed, and lets go of a press with no release at its end', () => {
    const { sink, sent } = recordingSink()
    const t = fakeTimers()
    const d = createControlsDriver(sink, t.timers)
    d.pressButton(1, ctrl) // another finger holds Ctrl
    const odd: ButtonControl = {
      id: 'odd',
      label: 'Odd',
      action: {
        kind: 'macro',
        steps: [
          { op: 'release', key: HID.ControlLeft }, // not this macro's: ignored
          { op: 'press', key: HID.ShiftLeft }, // never released by a step
          { op: 'tap', btn: 'right', wait_ms: 50 },
        ],
      },
    }
    d.pressButton(2, odd)
    t.drain()
    expect(sent).toEqual([
      { k: HID.ControlLeft, down: true },
      { k: HID.ShiftLeft, down: true },
      { b: 'right', down: true },
      { b: 'right', down: false },
      { k: HID.ShiftLeft, down: false },
    ])
    // The other finger's Ctrl is still down until that finger lifts.
    d.release(1)
    expect(sent[sent.length - 1]).toEqual({ k: HID.ControlLeft, down: false })
  })

  it('never waits longer than a step may, whatever a stored row says', () => {
    const { sink } = recordingSink()
    const t = fakeTimers()
    const d = createControlsDriver(sink, t.timers)
    d.pressButton(1, {
      id: 'slow',
      label: 'Slow',
      action: { kind: 'macro', steps: [{ op: 'tap', key: HID.KeyA, wait_ms: 60_000 }] },
    })
    expect(t.waits()).toEqual([MACRO_STEP_MAX_MS])
  })
})

describe('FR-111 P4 the org presets', () => {
  it('offers the server rows under org ids, and leaves out a row that is not a preset', () => {
    const got = orgPresets([
      { id: 'a1', name: 'Game pad', controls: [], updated_at: 'x' },
      { id: 7, name: 'bad id', controls: [] },
      { name: 'no id', controls: [] },
      { id: 'b2', name: 'no controls' },
      null,
    ])
    expect(got).toEqual([{ id: `${ORG_PRESET_PREFIX}a1`, name: 'Game pad', controls: [] }])
    expect(orgPresets({ items: [] })).toEqual([])
  })

  it('finds an org preset beside the built-ins, and a built-in id always means the built-in', () => {
    const org = orgPresets([{ id: 'a1', name: 'Game pad', controls: [] }])
    expect(presetById(`${ORG_PRESET_PREFIX}a1`, org)?.name).toBe('Game pad')
    expect(presetById(`${ORG_PRESET_PREFIX}a1`)).toBeNull()
    expect(presetById(BUILTIN_PRESETS[0].id, [{ id: BUILTIN_PRESETS[0].id, name: 'impostor', controls: [] }])).toBe(
      BUILTIN_PRESETS[0],
    )
  })

  it('remembers an org preset id until the list arrives', () => {
    const store = new Map([[`${CONTROLS_STORAGE_PREFIX}dev1`, `${ORG_PRESET_PREFIX}a1`]])
    const storage = { getItem: (k: string) => store.get(k) ?? null }
    expect(readControlsPreset(storage, 'dev1')).toBe(`${ORG_PRESET_PREFIX}a1`)
    store.set(`${CONTROLS_STORAGE_PREFIX}dev1`, ORG_PRESET_PREFIX)
    expect(readControlsPreset(storage, 'dev1')).toBeNull()
  })
})

describe('fitControls — a preset on a stage shorter than it was designed for (FR-125 P2)', () => {
  const wasd = presetById('wasd')!.controls
  const arrows = presetById('arrows')!.controls
  const column = (n: number) => n * TC_BUTTON_HEIGHT + (n - 1) * TC_BUTTON_GAP

  it('the arithmetic FR-125 §2.2 measured: WASD needs a 326 px stage, Arrows 260', () => {
    const act = wasd.find((c) => c.id === 'act')!
    const keys = arrows.find((c) => c.id === 'keys')!
    expect(act.kind === 'row' && act.at.bottom! + column(act.buttons.length)).toBe(326)
    expect(keys.kind === 'row' && keys.at.bottom! + column(keys.buttons.length)).toBe(260)
  })

  it('a stage with room gets the same array back: the preset renders as designed', () => {
    for (const p of BUILTIN_PRESETS) {
      expect(fitControls(p.controls, 412)).toBe(p.controls)
      expect(fitControls(p.controls, 900)).toBe(p.controls)
    }
  })

  it('no stage height yet (not measured): unchanged', () => {
    expect(fitControls(wasd, 0)).toBe(wasd)
  })

  it("the smallest phone page held sideways (304 px): WASD's Fire / Aim / Jump column becomes a row at its corner", () => {
    const fitted = fitControls(wasd, 304)
    expect(fitted).not.toBe(wasd)
    const act = fitted.find((c) => c.id === 'act')!
    expect(act.kind === 'row' && act.dir).toBe('row')
    expect(act.kind === 'row' && act.at).toEqual({ right: 16, bottom: 182 })
    // Nothing else moved: the d-pad and the stick fit (16 + 150 = 166 ≤ 304).
    for (const id of ['move', 'look', 'keys']) {
      expect(fitted.find((c) => c.id === id)).toBe(wasd.find((c) => c.id === id))
    }
  })

  it('a 250 px stage: Arrows\' five keys become a row; the 150 px d-pad still fits', () => {
    const fitted = fitControls(arrows, 250)
    const keys = fitted.find((c) => c.id === 'keys')!
    expect(keys.kind === 'row' && keys.dir).toBe('row')
    const pad = fitted.find((c) => c.id === 'arrows')!
    expect(pad.kind === 'dpad' && pad.size).toBe(150)
  })

  it('a stage too short for a 150 px pad: it shrinks to fit, never below the floor', () => {
    const at150 = fitControls(wasd, 150)
    const move = at150.find((c) => c.id === 'move')!
    // Anchored 16 px from the bottom, kept 8 px from the top: 150 − 16 − 8.
    expect(move.kind === 'dpad' && move.size).toBe(126)
    const at80 = fitControls(wasd, 80)
    const look = at80.find((c) => c.id === 'look')!
    expect(look.kind === 'stick' && look.size).toBe(TC_PAD_MIN)
  })

  it('the office row never changes: one row of buttons fits any phone page', () => {
    const office = presetById('office')!.controls
    expect(fitControls(office, 120)).toBe(office)
  })
})
