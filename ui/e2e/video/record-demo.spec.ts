// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * The product demo: real machines, one browser tab, each desktop full screen.
 *
 * For each device in `E2E_DEMO_DEVICES` (display names, in order) the take
 * opens its remote page with the sidebar collapsed, presses Connect, waits for
 * the desktop to paint, and enters the viewer's fullscreen, so the machine
 * fills the frame. `scripts/record-demo.sh` cuts the result into the README
 * MP4 and GIF; captions and the title cards are added there, not here.
 *
 * ⚠️ The capture is the DevTools screencast, NOT Playwright's `video` option.
 * Playwright encodes its video at a fixed ~1 Mbit/s VP8, which turns a remote
 * desktop's text into mush at any size worth showing; the screencast hands
 * over every composited frame as a JPEG at the quality we ask for, with its
 * timestamp, and the cut is encoded once, at the end, from those.
 *
 * ⚠️ NOTHING may touch page JS while the screencast films a painting stream:
 * `evaluate`, `boundingBox` and every locator query hang rather than answer —
 * four takes of the earlier demo were lost to checks that could never return
 * while the desktop streamed perfectly. With the screencast PAUSED they answer
 * at once (2026-10-06, every query of the record probe), so it is the capture
 * that starves them, not the page. Geometry is taken BEFORE Connect or inside a
 * pause; otherwise it is CDP input only, and even input then waits ~100 ms per
 * event (see `drag`). That is why "connected" is read from the screencast (a
 * painted desktop is a far heavier JPEG than the connecting page) rather than
 * asked of the page.
 *
 * ⚠️ The fullscreen button exists only once the session is connected, and
 * until then the SAME spot holds Disconnect. Clicking there on a guess would
 * end the session it was meant to show, so the click happens only after the
 * paint is seen; a device that never paints is filmed in the page instead.
 *
 * ⚠️ Nothing filmed may name the org or the fleet. The device list, the
 * dashboard and the network pages all do (machine names, MagicDNS names, other
 * people's devices), so the take never visits them: it goes straight to each
 * device's own page, where the header shows only its name (relabelled, see
 * LABELS), the OS and the version.
 */
import { test, expect, type CDPSession, type Page } from '@playwright/test'
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, writeFile, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'

/**
 * `E2E_DEMO_LOCKCHECK` (`record-demo.sh` passes `MESHHARBOR_DEMO_LOCKCHECK`): `mh exec`
 * selectors with their OS, one per device in filming order — `"laptop-17:win,office-mac:mac"`.
 * Each device is checked right before it is FILMED, not just when the take starts: managed
 * laptops lock after a few idle minutes, and the second machine of a take sat idle while the
 * first was filmed (2026-10-07: two takes refused in a row as one laptop then the other locked).
 */
const LOCKCHECK = (process.env.E2E_DEMO_LOCKCHECK || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean)

/** Whether the device's screen is signed in now, by `mh exec`. Anything unclear is "no". */
function signedIn(check: string): { ok: boolean; why: string } {
  const i = check.lastIndexOf(':')
  const [sel, os] = [check.slice(0, i), check.slice(i + 1)]
  const cmd = os === 'win' ? 'tasklist /FI "IMAGENAME eq LogonUI.exe" /NH' : os === 'mac' ? 'ioreg -n Root -d1 -a' : ''
  if (!cmd) return { ok: false, why: `"${check}" needs :win or :mac` }
  let out: string
  try {
    out = execFileSync('meshharbor', ['exec', sel, cmd], { encoding: 'utf8', timeout: 60_000 })
  } catch (e) {
    return { ok: false, why: `could not check ${sel}: ${(e as Error).message.split('\n')[0]}` }
  }
  if (os === 'win') {
    // The process name and the INFO prefix alone: "nothing found" is localized.
    if (out.includes('LogonUI.exe')) return { ok: false, why: `${sel} is at its lock screen` }
    return out.trimStart().startsWith('INFO') ? { ok: true, why: '' } : { ok: false, why: `${sel} answered: ${out.slice(0, 80)}` }
  }
  if (/CGSSessionScreenIsLocked<\/key>\s*<true\/>/.test(out)) return { ok: false, why: `${sel} is locked` }
  return /kCGSessionLoginDoneKey<\/key>\s*<true\/>/.test(out)
    ? { ok: true, why: '' }
    : { ok: false, why: `${sel} has no signed-in console session` }
}

const USERNAME = process.env.E2E_USERNAME || ''
const PASSWORD = process.env.E2E_PASSWORD || ''
/**
 * A saved browser session (`record-demo.sh --login`), so a take needs no password.
 *
 * With `E2E_SAVE_STATE=1` the run only signs in and writes the session to this path. Without it,
 * the take starts from that session and never sees the login form. ⚠️ The file holds the
 * account's cookies: it lives in the user's home, outside every repository, like the
 * credentials file it replaces.
 */
const STATE = process.env.E2E_STORAGE_STATE || ''
const SAVE_STATE = process.env.E2E_SAVE_STATE === '1'
const TENANT_ID = process.env.E2E_TENANT_ID || ''
const DEVICES = (process.env.E2E_DEMO_DEVICES || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean)
/**
 * Where the frames and the manifest go.
 *
 * ⚠️ Keep it OUTSIDE `e2e/video/output`: Playwright empties its outputDir at
 * the start of every run, so a take kept there is gone the moment anything
 * else runs. `record-demo.sh` points this at the user's Videos folder.
 */
const OUT = resolve(process.env.E2E_DEMO_OUT || 'e2e/video/output/take')
/**
 * The name each device shows ON SCREEN, one per device, `|`-separated.
 *
 * ⚠️ A display name is how the owner tells machines apart, which is exactly
 * why it does not belong in a public video: "Anna's work laptop" says whose
 * machine it is and where. The take rewrites the name in the agent API
 * responses the PAGE receives,
 * so the app renders the label through its own code, in its own font, on every
 * re-render; nothing on the server changes, and the harness's own lookup
 * (`page.request`, which page routes do not touch) still finds the device by
 * its real name.
 */
const LABELS = (process.env.E2E_DEMO_LABELS || '').split('|').map((s) => s.trim())

/**
 * An optional closing scene (`E2E_DEMO_NETWORK=1`): the dashboard's Network card, the mesh the
 * desktops sit on.
 *
 * ⚠️ The dashboard names the org and the whole fleet, so this scene changes what the PAGE is told,
 * the way LABELS does. The mesh payload is rewritten: each filmed device under its label, every
 * other device as "device N", and no address, relay home or relay name. Its center is
 * "meshharbor.itachi.fans". The pointer stays off the graph, because a hover tooltip would show more. The
 * card's box goes into the manifest (`mark.box`), and the cut films that box and nothing else of
 * the page.
 */
const NETWORK = process.env.E2E_DEMO_NETWORK === '1'
const NETWORK_MS = Number(process.env.E2E_DEMO_NETWORK_MS || 9000)
/**
 * An optional record scene (FR-85's remote recording, filmed): on each device, once its desktop
 * paints, Record → Start, a window dragged across the remote desktop, Stop, then Download, with
 * the downloaded file kept beside the take as `rec-<label>.mp4`. It replaces fullscreen and the
 * glide, because the Record menu lives in the page's toolbar.
 *
 * `E2E_DEMO_RECORD` is JSON: `{"ui": {"record": [x, y], "start": [x, y], "stop": [x, y],
 * "download": [x, y]}, "drag": [[[x1, y1], [x2, y2]], …]}`, page coordinates, `drag` one pair per
 * device in filming order (null skips it). `ui` may instead be an array, one per device: the menu
 * is not the same height everywhere (a Mac adds a line saying why computer audio is unavailable).
 * The device lists recordings newest first and the page re-lists them on Stop, so the new file is
 * always the first row. ⚠️ Every position is MEASURED on a probe's frames,
 * because nothing may query the page while a stream paints (see the header): the menu's buttons
 * are clicked as input events only.
 *
 * `E2E_DEMO_RECORD_PROBE=1` is that probe: Record, then Start, Stop and Download, each found by
 * its `data-testid` with a short timeout (a query that hangs is abandoned, never awaited), every
 * box it gets logged, and the frames kept, so the coordinates come from one of the two.
 */
type RecordUi = { record: [number, number]; start: [number, number]; stop: [number, number]; download: [number, number] }
const RECORD: null | {
  ui?: RecordUi | RecordUi[]
  drag?: Array<null | [[number, number], [number, number]]>
  /**
   * Per device: click `at` (an editor's text) and type `text` there, before the drag; `clear`
   * empties the editor first (select all, delete) so a re-take does not type after the last one.
   */
  type?: Array<null | { at: [number, number]; text: string; clear?: boolean }>
} = process.env.E2E_DEMO_RECORD ? JSON.parse(process.env.E2E_DEMO_RECORD) : null
const RECORD_PROBE = process.env.E2E_DEMO_RECORD_PROBE === '1'
/**
 * An optional scripted scene (`E2E_DEMO_STEPS`): after the desktop paints, a list of input steps
 * on the remote desktop, for a task the record scene does not cover (an app's own editor, say).
 * JSON, one list per device in filming order (null skips it):
 *
 *   {"fullscreen": true}  {"click": [x, y]}  {"dbl": [x, y]}  {"wheel": [x, y, dy]}
 *   {"move": [x, y], "steps": 12}  {"drag": [[x1, y1], [x2, y2]], "ms": 1400}
 *   {"key": "Meta+Shift+G"}  {"type": "text"}  {"wait": 1500}  {"mark": "name"}
 *
 * The steps start in the page; `fullscreen` switches the viewer to full screen, and the positions
 * after it are full-screen ones. The keys reach the remote through the viewer, once a click on the
 * desktop has given it focus. `move` is a pure pointer move, no button, no scroll: what a host's
 * "rest the pointer at the top edge" reveal (FR-27 P9) needs, which `wheel` with a zero delta only
 * imitated. ⚠️ Every position is measured on an earlier run's frames, as for the
 * record scene: a run that stops early is how the next position is found.
 *
 * ⚠️ A step that seems to do nothing is not proof its position is wrong. Twice in ~25 Mac runs
 * (2026-10-06) a session stalled — the stream froze ("video stalled" in the pills) and input
 * stopped reaching the device — and the first of those was blamed on "the top edge of full
 * screen" until a measured run moved the pointer to y = 2, 8, 20 and 40 there without a miss.
 * Re-run it, and read the pills, before moving the position.
 */
type Step =
  | { fullscreen: true }
  | { wheel: [number, number, number] }
  | { move: [number, number]; steps?: number }
  | { click: [number, number] }
  | { dbl: [number, number] }
  | { drag: [[number, number], [number, number]]; ms?: number }
  | { key: string }
  | { type: string }
  | { wait: number }
  | { mark: string }
const STEPS: null | Array<null | Step[]> = process.env.E2E_DEMO_STEPS ? JSON.parse(process.env.E2E_DEMO_STEPS) : null
/**
 * How long one drag takes, and one typed character. A drag is a demo of how fast the remote
 * desktop answers, so it is quick: a slow, eased glide read as a slow remote desktop (the operator,
 * 2026-10-06), and typing shows the latency better than any pointer can.
 */
const DRAG_MS = Number(process.env.E2E_DEMO_DRAG_MS || 450)
const TYPE_MS = Number(process.env.E2E_DEMO_TYPE_MS || 70)
/** Where the probe clicks Record before anything is measured: the toolbar icon left of Disconnect. */
const RECORD_BTN_GUESS: [number, number] = [1680, 72]
/** The frame the cut is made at. 1080p is what YouTube and the MP4 want. */
const W = 1920
const H = 1080

/** How long each desktop is held full screen. */
const DWELL_MS = Number(process.env.E2E_DEMO_DWELL_MS || 7000)
/** Longest wait for a desktop to paint after Connect. */
const PAINT_BUDGET_MS = Number(process.env.E2E_DEMO_PAINT_BUDGET_MS || 45_000)

test.use({
  video: 'off',
  viewport: { width: W, height: H },
  deviceScaleFactor: 1,
  ...(STATE && !SAVE_STATE ? { storageState: STATE } : {}),
})

type Frame = { file: string; t: number; bytes: number }
type Mark = { device: string; what: string; t: number; box?: { x: number; y: number; width: number; height: number } }

/** Every composited frame, as a JPEG on disk with its swap timestamp. */
class Capture {
  readonly frames: Frame[] = []
  private n = 0

  constructor(
    readonly cdp: CDPSession,
    private readonly dir: string,
  ) {}

  async start() {
    this.cdp.on('Page.screencastFrame', (ev) => {
      const file = `f${String(this.n++).padStart(6, '0')}.jpg`
      const buf = Buffer.from(ev.data, 'base64')
      writeFile(join(this.dir, file), buf, () => {})
      this.frames.push({ file, t: ev.metadata.timestamp ?? Date.now() / 1000, bytes: buf.length })
      // Unacked, the screencast stops after a few frames.
      this.cdp.send('Page.screencastFrameAck', { sessionId: ev.sessionId }).catch(() => {})
    })
    await this.resume()
  }

  async stop() {
    await this.pause()
  }

  /**
   * The record probe pauses the frames while it measures, in case the screencast is what keeps a
   * query from answering; `boxWithin` still gives up after its timeout. The listener stays, so
   * `resume` only restarts the frames.
   */
  async pause() {
    await this.cdp.send('Page.stopScreencast').catch(() => {})
  }

  async resume() {
    await this.cdp.send('Page.startScreencast', {
      format: 'jpeg',
      quality: 92,
      maxWidth: W,
      maxHeight: H,
      everyNthFrame: 1,
    })
  }

  /** Median JPEG size of the frames since `sinceT` (seconds), or of the last frame. */
  baseline(sinceT: number): number {
    const recent = this.frames.filter((f) => f.t >= sinceT).map((f) => f.bytes)
    const pool = recent.length ? recent : this.frames.slice(-1).map((f) => f.bytes)
    if (!pool.length) return 0
    pool.sort((a, b) => a - b)
    return pool[Math.floor(pool.length / 2)]
  }

  /**
   * Resolve once a desktop has painted: several consecutive frames far heavier
   * than the page was before Connect. False when the budget runs out.
   */
  async waitForPaint(baseline: number, sinceT: number, budgetMs: number): Promise<boolean> {
    const threshold = baseline * 1.6 + 40_000
    const deadline = Date.now() + budgetMs
    while (Date.now() < deadline) {
      const after = this.frames.filter((f) => f.t > sinceT)
      let run = 0
      for (const f of after) {
        run = f.bytes > threshold ? run + 1 : 0
        if (run >= 4) return true
      }
      await new Promise((r) => setTimeout(r, 150))
    }
    return false
  }
}

/**
 * Suppress transient toasts for the whole take. They appear DURING a stream —
 * "Connected in 9.1 s, slower than usual", the clipboard-permission prompt —
 * which is exactly when the page cannot be asked to dismiss them, so they are
 * hidden by CSS installed before the app's own JS runs, on every navigation.
 */
async function suppressToasts(page: Page) {
  await page.addInitScript(() => {
    const install = () => {
      const s = document.createElement('style')
      s.textContent =
        '.v-snackbar,.v-snackbar__wrapper,.kb-lock-toast,.kb-lock-pill{display:none !important}'
      ;(document.head || document.documentElement).appendChild(s)
    }
    if (document.head) install()
    else document.addEventListener('DOMContentLoaded', install, { once: true })
  })
}

/** Rail mode is not persisted, so every full page load needs it again. */
async function collapseSidebar(page: Page) {
  const btn = page.getByRole('button', { name: 'Collapse sidebar' })
  if (await btn.isVisible().catch(() => false)) await btn.click()
}

/** A slow, deliberate glide — reads as a hand on a mouse, not a teleport. */
async function glide(page: Page, points: Array<[number, number]>, stepsPer = 40, pauseMs = 320) {
  for (const [x, y] of points) {
    await page.mouse.move(x, y, { steps: stepsPer })
    await page.waitForTimeout(pauseMs)
  }
}

type Box = { x: number; y: number; width: number; height: number }

/**
 * A locator's box, or null after `ms`. While a stream paints, a page query may never answer; the
 * race abandons it instead of awaiting it, so the probe always moves on.
 */
async function boxWithin(page: Page, selector: string, ms: number): Promise<Box | null> {
  const timeout = new Promise<null>((r) => setTimeout(() => r(null), ms))
  const box = page.locator(selector).first().boundingBox().catch(() => null)
  return Promise.race([box, timeout])
}

const centre = (b: Box): [number, number] => [b.x + b.width / 2, b.y + b.height / 2]

/**
 * Drag from `a` to `b` over about `ms`, eased, so a window visibly follows on the remote desktop.
 *
 * ⚠️ The moves go out on the raw DevTools session, paced by the clock and NOT awaited one by one.
 * While the screencast runs, the browser takes ~100 ms to acknowledge each input event, so
 * awaited moves (Playwright's `mouse.move`) reached the device at ~8 a second, and a 1.4 s drag
 * took the device 6–8 s (2026-10-06, seen in its own recording). The press, the moves and the
 * release all use the raw session, because Playwright's `mouse.up` would release where IT last
 * put the pointer, the drag's start.
 */
async function drag(page: Page, cdp: CDPSession, a: [number, number], b: [number, number], ms = DRAG_MS) {
  await page.mouse.move(a[0], a[1], { steps: 4 })
  await page.waitForTimeout(200)
  const send = (type: 'mousePressed' | 'mouseMoved' | 'mouseReleased', x: number, y: number, buttons: number) =>
    cdp.send('Input.dispatchMouseEvent', { type, x, y, button: 'left', buttons, clickCount: type === 'mouseMoved' ? 0 : 1 })
  await send('mousePressed', a[0], a[1], 1)
  await page.waitForTimeout(80)
  const n = Math.max(6, Math.round(ms / 30))
  const t0 = Date.now()
  const acks: Array<Promise<unknown>> = []
  for (let i = 1; i <= n; i++) {
    const t = i / n
    const e = t < 0.5 ? 2 * t * t : 1 - (2 - 2 * t) ** 2 / 2
    acks.push(send('mouseMoved', a[0] + (b[0] - a[0]) * e, a[1] + (b[1] - a[1]) * e, 1).catch(() => {}))
    await page.waitForTimeout(ms / n)
  }
  await Promise.all(acks)
  console.log(`  drag: ${n} moves sent over ${ms} ms, all acknowledged after ${Date.now() - t0} ms`)
  await page.waitForTimeout(120)
  await send('mouseReleased', b[0], b[1], 0)
  // Playwright's own idea of the pointer, for the next move it makes.
  await page.mouse.move(b[0], b[1])
}

/**
 * Type `text` on the remote at a typist's pace, the same way `drag` moves: raw DevTools key
 * events, paced by the clock and not awaited one by one, so the browser's ~100 ms per input event
 * while the screencast runs does not turn into ~100 ms per character on screen. A printable key
 * reaches the device as text (`key_text`), not as a key code, so the device's keyboard layout
 * (the German laptops) does not change what appears.
 */
async function typeText(page: Page, cdp: CDPSession, text: string, msPerChar = TYPE_MS) {
  const t0 = Date.now()
  const acks: Array<Promise<unknown>> = []
  for (const ch of text) {
    acks.push(cdp.send('Input.dispatchKeyEvent', { type: 'keyDown', key: ch, text: ch, unmodifiedText: ch }).catch(() => {}))
    acks.push(cdp.send('Input.dispatchKeyEvent', { type: 'keyUp', key: ch }).catch(() => {}))
    await page.waitForTimeout(msPerChar)
  }
  await Promise.all(acks)
  console.log(`  type: ${text.length} characters sent at ${msPerChar} ms each, acknowledged after ${Date.now() - t0} ms`)
}

/**
 * The record scene on one connected device: Record → Start, the window drag, Stop, Download.
 * In probe mode each button is located by its `data-testid` (logged), falling back to the
 * configured position; otherwise only configured positions are clicked.
 */
async function recordScene(
  page: Page,
  label: string,
  index: number,
  out: string,
  mark: (device: string, what: string) => void,
  cap: Capture,
) {
  const ui = Array.isArray(RECORD?.ui) ? RECORD.ui[index] : RECORD?.ui
  const at = async (selector: string, fallback: [number, number] | undefined): Promise<[number, number] | null> => {
    if (RECORD_PROBE) {
      await cap.pause()
      const b = await boxWithin(page, selector, 4000)
      await cap.resume()
      console.log(`  probe ${selector}: ${b ? JSON.stringify(b) : 'no answer'}`)
      if (b) return centre(b)
    }
    return fallback ?? null
  }
  const openMenu = async () => {
    const p = (await at('[data-testid="rc-record-btn"]', ui?.record)) ?? RECORD_BTN_GUESS
    await page.mouse.click(p[0], p[1])
    await page.waitForTimeout(1500)
  }

  await page.waitForTimeout(1500)
  await openMenu()
  mark(label, 'record-menu')
  const start = await at('[data-testid="rc-record-start"]', ui?.start)
  if (!start) {
    console.log(`  ${label}: no Start position, nothing recorded`)
    await page.keyboard.press('Escape')
    return
  }
  await page.mouse.click(start[0], start[1])
  mark(label, 'record-start')
  await page.waitForTimeout(2500) // the device's banner comes up before its first frame
  await page.keyboard.press('Escape') // the menu, so the pointer reaches the desktop
  await page.waitForTimeout(800)

  // ⚠️ Once more, right before any typing. The connect already moved the pointer over the
  // stream, which resets the device's idle timer; if it is still signed in NOW it will not lock
  // during the next minute. If it locked between the pre-take check and that pointer move
  // (2026-10-07: a laptop locked seconds after passing the check), typing would go into its
  // password field — so nothing is typed or dragged.
  const lockCheck = LOCKCHECK[index]
  const inputOk = !lockCheck || signedIn(lockCheck).ok
  if (!inputOk) {
    console.log(`  ${label}: screen locked before typing — no typing, no drag`)
    mark(label, 'input-skipped-locked')
  }
  const typing = inputOk ? RECORD?.type?.[index] : undefined
  if (typing) {
    // Focus the editor's text with a click, then type: the latency a person feels.
    await page.mouse.click(typing.at[0], typing.at[1])
    await page.waitForTimeout(400)
    if (typing.clear) {
      // Select all + delete: a re-take starts from an empty editor, not from the last take's
      // text. The viewer sends Ctrl as Cmd to a Mac.
      await page.keyboard.press('Control+a')
      await page.waitForTimeout(250)
      await page.keyboard.press('Backspace')
      await page.waitForTimeout(400)
    }
    mark(label, 'type')
    await typeText(page, cap.cdp, typing.text)
    await page.waitForTimeout(700)
  }
  const pair = inputOk ? RECORD?.drag?.[index] : undefined
  if (pair) {
    mark(label, 'drag')
    await drag(page, cap.cdp, pair[0], pair[1])
    await page.waitForTimeout(700)
    await drag(page, cap.cdp, pair[1], pair[0])
  }
  await page.waitForTimeout(1500)

  await openMenu()
  const stop = await at('[data-testid="rc-record-stop"]', ui?.stop)
  if (stop) {
    await page.mouse.click(stop[0], stop[1])
    mark(label, 'record-stop')
  } else {
    console.log(`  ${label}: no Stop position; leaving the page stops it`)
  }
  await page.waitForTimeout(3500) // the device finalizes the file and lists it

  if (RECORD_PROBE) {
    await page.keyboard.press('Escape')
    await page.waitForTimeout(600)
    await openMenu()
  }
  // The list's own buttons, `Download <name>`; `rc-record-download` is the progress box. Scoped
  // to the menu, so a Download button anywhere else on the page is never the one measured.
  const dl = await at('[data-testid="rc-record-menu"] button[aria-label^="Download "]', ui?.download)
  if (dl) {
    const wait = page.waitForEvent('download', { timeout: 180_000 }).catch(() => null)
    await page.mouse.click(dl[0], dl[1])
    mark(label, 'download')
    const d = await wait
    if (d) {
      const file = join(out, `rec-${label.replace(/[^A-Za-z0-9]+/g, '-')}.mp4`)
      await d.saveAs(file)
      mark(label, 'downloaded')
      console.log(`  ${label}: saved ${file}`)
    } else {
      console.log(`  ${label}: no download arrived`)
    }
  }
  await page.keyboard.press('Escape')
  await page.waitForTimeout(1000)
}

/** The scripted scene's steps, in order, as CDP input only (see `STEPS`). */
async function stepsScene(
  page: Page,
  label: string,
  steps: Step[],
  mark: (device: string, what: string) => void,
  cap: Capture,
  fullscreenBtn: [number, number],
) {
  for (const s of steps) {
    if ('fullscreen' in s) {
      await page.mouse.click(fullscreenBtn[0], fullscreenBtn[1])
      mark(label, 'fullscreen')
      await page.waitForTimeout(1200)
    } else if ('wheel' in s) {
      await page.mouse.move(s.wheel[0], s.wheel[1])
      await page.mouse.wheel(0, s.wheel[2])
    } else if ('move' in s) await page.mouse.move(s.move[0], s.move[1], { steps: s.steps ?? 12 })
    else if ('click' in s) await page.mouse.click(s.click[0], s.click[1])
    else if ('dbl' in s) await page.mouse.dblclick(s.dbl[0], s.dbl[1])
    else if ('drag' in s) await drag(page, cap.cdp, s.drag[0], s.drag[1], s.ms)
    else if ('key' in s) await page.keyboard.press(s.key)
    else if ('type' in s) await page.keyboard.type(s.type, { delay: 60 })
    else if ('wait' in s) await page.waitForTimeout(s.wait)
    else if ('mark' in s) mark(label, s.mark)
    // A beat between steps, so each one reads on screen.
    await page.waitForTimeout(350)
  }
}

test.describe('MeshHarbor demo recording', () => {
  test('record the product demo', async ({ page }) => {
    test.setTimeout(900_000)

    const useState = Boolean(STATE) && !SAVE_STATE
    if (useState) {
      expect(existsSync(STATE), `no saved session at ${STATE}: run record-demo.sh --login first`).toBeTruthy()
    } else {
      expect(USERNAME, 'E2E_USERNAME is required').not.toBe('')
      expect(PASSWORD, 'E2E_PASSWORD is required').not.toBe('')
    }
    if (!SAVE_STATE) {
      expect(TENANT_ID, 'E2E_TENANT_ID is required').not.toBe('')
      expect(DEVICES.length, 'E2E_DEMO_DEVICES is required (display names, comma-separated)').toBeGreaterThan(0)
    }

    await suppressToasts(page)
    // The site's own analytics would count every take as a visit.
    await page.route('https://purestat.ai/**', (r) => r.abort())
    if (RECORD || RECORD_PROBE) {
      // The in-memory download path: no native save dialog, and the file is kept only when its
      // SHA-256 matches the device's (docs/recording.md §10, the viewer).
      await page.addInitScript(() => {
        ;(window as unknown as { showSaveFilePicker?: unknown }).showSaveFilePicker = undefined
      })
    }
    if (!useState) {
      await page.goto('/login')
      await page.waitForLoadState('networkidle')
      const user = page.locator('input').first()
      await user.click()
      await user.pressSequentially(USERNAME, { delay: 25 })
      const pass = page.locator('input[type="password"]')
      await pass.click()
      await pass.pressSequentially(PASSWORD, { delay: 25 })
      await page.getByRole('button', { name: /sign in|log in|login/i }).click()
      await page.waitForTimeout(3000)
    }
    if (SAVE_STATE) {
      expect(STATE, 'E2E_STORAGE_STATE names the file to save the session to').not.toBe('')
      expect(page.url(), 'still on the login page: the sign-in failed').not.toContain('/login')
      await page.context().storageState({ path: STATE })
      console.log(`  session saved to ${STATE}`)
      // What a take can film: each org this account is in, with its devices by display name.
      const orgs = await (await page.request.get('/api/tenant')).json().catch(() => [])
      for (const o of Array.isArray(orgs) ? orgs : []) {
        const r = await page.request.get(`/api/tenant/${o.id}/agent?per_page=100`)
        const b = r.ok() ? await r.json() : {}
        const list: Array<Record<string, unknown>> = b.items ?? (Array.isArray(b) ? b : [])
        console.log(`  org ${o.id} (${list.length} devices)`)
        for (const a of list) {
          console.log(`    ${a.is_online ? 'online ' : 'offline'}  ${String(a.os ?? '').padEnd(8)} ${a.display_name ?? a.name}`)
        }
      }
      return
    }
    if (useState) {
      // The saved session signs the page in through the app's own refresh; give it a page load.
      await page.goto('/')
      await page.waitForLoadState('networkidle')
    }

    const framesDir = join(OUT, 'frames')
    mkdirSync(framesDir, { recursive: true })

    // Resolve each device by display name, and refuse an offline one now: a
    // take that films a spinner is a wasted run that reports success.
    const res = await page.request.get(`/api/tenant/${TENANT_ID}/agent?per_page=100`)
    expect(
      res.ok(),
      `agent list failed: ${res.status()}` + (res.status() === 401 && useState ? ' (the saved session expired: run record-demo.sh --login again)' : ''),
    ).toBeTruthy()
    const body = await res.json()
    const agents: Array<Record<string, unknown>> = body.items ?? body ?? []
    const shots = DEVICES.map((name, i) => {
      const a = agents.find((x) => String(x.display_name ?? x.name ?? '') === name)
      expect(a, `no device with display name "${name}" in this org`).toBeTruthy()
      expect(a?.is_online, `"${name}" is offline`).toBeTruthy()
      // `shown` is what the take and its manifest call the device: the label
      // when one is given, so the real name never lands in the take folder.
      return { name, shown: LABELS[i] || name, id: String(a?.id), os: String(a?.os ?? '') }
    })

    const label = new Map(shots.map((s, i) => [s.id, LABELS[i] || '']).filter(([, l]) => l))
    if (label.size) {
      const relabel = (a: Record<string, unknown>) => {
        const l = label.get(String(a?.id))
        // Both names: the header shows the machine name beside the display
        // name whenever the viewer's preference says so.
        if (l) Object.assign(a, { display_name: l, name: l })
      }
      await page.route(
        (url) => url.pathname.startsWith(`/api/tenant/${TENANT_ID}/agent`),
        async (route) => {
          const path = new URL(route.request().url()).pathname
          const list = path === `/api/tenant/${TENANT_ID}/agent`
          if (route.request().method() !== 'GET' || !(list || /\/agent\/[0-9a-f]{24}$/.test(path))) {
            return route.continue()
          }
          const resp = await route.fetch()
          const json = await resp.json().catch(() => null)
          if (!json) return route.fulfill({ response: resp })
          if (list) for (const a of json.items ?? json ?? []) relabel(a)
          else relabel(json)
          await route.fulfill({ response: resp, json })
        },
      )
    }

    if (NETWORK) {
      const shownById = new Map(shots.map((s) => [s.id, s.shown]))
      await page.route(
        (url) => url.pathname === `/api/tenant/${TENANT_ID}/stats/mesh`,
        async (route) => {
          const resp = await route.fetch()
          const json = await resp.json().catch(() => null)
          if (!json) return route.fulfill({ response: resp })
          // One name per device across nodes and agents: its label, or the next "device N".
          let k = 0
          const anon = new Map<string, string>()
          const nameFor = (agentId: string | undefined, key: string) => {
            if (agentId && shownById.has(agentId)) return shownById.get(agentId)!
            if (!anon.has(key)) anon.set(key, `device ${++k}`)
            return anon.get(key)!
          }
          for (const a of json.agents ?? []) {
            const n = nameFor(String(a.id), String(a.id))
            Object.assign(a, { name: n, display_name: n, relay_home: null })
          }
          for (const n of json.nodes ?? []) {
            const key = n.agent_id_hex ? String(n.agent_id_hex) : String(n.id)
            Object.assign(n, { name: nameFor(n.agent_id_hex ? String(n.agent_id_hex) : undefined, key), relay_home: null })
            delete n.overlay_ip
          }
          for (const e of json.edges ?? []) for (const end of e.ends ?? []) delete end.relay
          if (json.center) json.center.name = 'meshharbor.itachi.fans'
          await route.fulfill({ response: resp, json })
        },
      )
    }

    const cdp = await page.context().newCDPSession(page)
    const cap = new Capture(cdp, framesDir)
    const marks: Mark[] = []
    const mark = (device: string, what: string) => {
      marks.push({ device, what, t: Date.now() / 1000 })
      console.log(`  ${device.padEnd(14)} ${what}`)
    }
    await cap.start()

    for (const shot of shots) {
      // Right before THIS device is filmed (see `LOCKCHECK`): a locked screen is skipped, and
      // never typed into or filmed.
      const check = LOCKCHECK[shots.indexOf(shot)]
      if (check) {
        const s = signedIn(check)
        if (!s.ok) {
          console.log(`  ${shot.shown}: SKIPPED, not filmed — ${s.why}`)
          mark(shot.shown, 'skipped-locked')
          continue
        }
      }
      await page.goto(`/tenant/${TENANT_ID}/agent/${shot.id}/remote`)
      await page.waitForLoadState('networkidle')
      await collapseSidebar(page)
      const connect = page.getByRole('button', { name: /^connect$/i }).first()
      await connect.waitFor({ state: 'visible', timeout: 15_000 })
      const box = await connect.boundingBox()
      expect(box, 'Connect has no box').toBeTruthy()
      // Park the pointer in the empty stage, away from any hover state.
      await page.mouse.move(W * 0.55, H * 0.6)
      await page.waitForTimeout(1500)
      mark(shot.shown, 'ready')

      const before = Date.now() / 1000
      const baseline = cap.baseline(before - 1.5)
      await connect.click()
      mark(shot.shown, 'connect')

      // ── from here: no page queries, CDP input only ─────────────────────────
      // ⚠️ A connected session can stream a BLACK screen: a laptop whose
      // display has gone to sleep sends black frames at a few kbit/s until
      // something wakes it, and waiting for a paint without touching the
      // mouse then waits forever (the first take did exactly that, 45 s of
      // "connected · 12 kbps" over a black stage). So the wait nudges the
      // pointer a few pixels in the middle of the stage: before the session
      // is up that goes nowhere, after it the host wakes.
      let painted = false
      const deadline = Date.now() + PAINT_BUDGET_MS
      for (let k = 0; !painted && Date.now() < deadline; k++) {
        await page.mouse.move(W * 0.55 + (k % 2 ? 8 : -8), H * 0.6, { steps: 4 })
        painted = await cap.waitForPaint(baseline, before + 0.2, 2500)
      }
      mark(shot.shown, painted ? 'painted' : 'no-paint')
      if (!painted) {
        await page.waitForTimeout(2000)
        mark(shot.shown, 'end')
        continue
      }
      if (RECORD || RECORD_PROBE) {
        await recordScene(page, shot.shown, shots.indexOf(shot), OUT, mark, cap)
        mark(shot.shown, 'end')
        continue
      }
      const steps = STEPS?.[shots.indexOf(shot)]
      if (steps) {
        await page.waitForTimeout(1200)
        await stepsScene(page, shot.shown, steps, mark, cap, [box!.x + box!.width - 20, box!.y + box!.height / 2])
        await page.waitForTimeout(1500)
        mark(shot.shown, 'end')
        continue
      }
      await page.waitForTimeout(1800) // the desktop, still inside the page
      // Fullscreen is the LAST toolbar button once connected; before Connect
      // that end of the toolbar was Connect's own right edge.
      await page.mouse.click(box!.x + box!.width - 20, box!.y + box!.height / 2)
      mark(shot.shown, 'fullscreen')
      await page.waitForTimeout(1200)

      // A slow pass through the middle of the screen: no clicks, no typing,
      // nothing near a taskbar, a dock or a hot corner.
      mark(shot.shown, 'glide')
      await glide(page, [
        [W * 0.42, H * 0.42],
        [W * 0.58, H * 0.36],
        [W * 0.62, H * 0.55],
        [W * 0.46, H * 0.6],
        [W * 0.5, H * 0.48],
      ])
      await page.waitForTimeout(Math.max(0, DWELL_MS - 4000))
      mark(shot.shown, 'end')
    }

    if (NETWORK) {
      // The page is not streaming here, so locators answer again.
      await page.goto(`/tenant/${TENANT_ID}`)
      await page.waitForLoadState('networkidle')
      await collapseSidebar(page)
      const card = page.locator('.mesh-wrap').first()
      await card.waitFor({ state: 'visible', timeout: 20_000 })
      await card.scrollIntoViewIfNeeded()
      await page.mouse.move(8, H - 8) // off the graph: a hover tooltip shows more than a name
      await page.waitForTimeout(600)
      const box = await card.boundingBox()
      expect(box, 'the Network card has no box').toBeTruthy()
      marks.push({ device: 'network', what: 'network', t: Date.now() / 1000, box: box! })
      console.log(`  ${'network'.padEnd(14)} network ${JSON.stringify(box)}`)
      await page.waitForTimeout(NETWORK_MS)
      mark('network', 'end')
    }

    await cap.stop()
    await page.goto('about:blank')
    writeFileSync(
      join(OUT, 'take.json'),
      JSON.stringify({ viewport: { width: W, height: H }, devices: shots.map((s) => ({ name: s.shown, os: s.os })), marks, frames: cap.frames }, null, 1),
    )
    console.log(`\n  ${cap.frames.length} frames → ${framesDir}`)
    expect(marks.filter((m) => m.what === 'painted').length, 'no device painted').toBeGreaterThan(0)
  })
})
