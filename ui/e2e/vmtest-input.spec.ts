/**
 * FR-93 (#1972) — the viewer's INPUT, end to end, on the FR-93 Wayland lab.
 *
 * A real browser drives the real remote-desktop page against the real server,
 * exactly as `vmtest-remote.spec.ts` does, and this spec SENDS input and says
 * what it sent: one `[vmtest-input] sent {…}` line per action. It decides
 * nothing about the host, because the browser cannot see it. The harness
 * (meshharbor-deploy `vmtest/lab/measure/viewer-input.sh`) reads what ARRIVED
 * from the lab guest's probe app, a fullscreen native Wayland client that logs
 * every pointer, button, scroll and key event, and from the shell's own state.
 *
 * `E2E_INPUT_PLAN` picks what to send:
 *   - `points` (AC4): the pointer to three known points, a click, a wheel
 *     notch down, typed ASCII, and a letter typed under a held Shift.
 *   - `close-mid-drag`: press, drag, then CLOSE THE PAGE. The page's own
 *     unload path (`releaseHeldInputs`, on blur / tab hidden) lets go of the
 *     button it holds. Measured 2026-10-11: it let go at the PRESS point, so
 *     the host cursor snapped back from where the drag had reached.
 *   - `crash-mid-drag` (#1945): press, drag, then CRASH THE RENDERER (CDP
 *     `Page.crash`), so no page code runs at all. A browser that crashes or
 *     loses its tab mid-drag. Only the agent can let go then: its arbiter
 *     releases what the closing session held, and that release must not move
 *     the pointer. One that moved first landed in the top-left pixel, GNOME's
 *     Activities hot corner.
 *
 *   - `cursor` (AC5): is the host's pointer visible in the viewer? The PERSON
 *     at the screen moves it (the harness, over QMP, outside every meshharbor
 *     input path), so this answers even where remote input reaches nothing.
 *     The harness signals each position with a marker file in the shared
 *     `/work`. At each one the spec reports what the picture shows there, and
 *     whether the viewer's own cursor overlay (painted from the agent's
 *     `cursor` channel) sits there.
 *
 * Coordinates are normalised to the remote picture, as on the wire. The spec
 * finds the picture on the page (the largest live `<canvas>` or `<video>`,
 * letterboxed with `object-fit: contain`), so a target of (0.25, 0.25) is a
 * quarter of the way into the HOST's screen, whatever the viewport.
 *
 * Env: E2E_BASE_URL, E2E_API_URL, E2E_VMTEST_TENANT_ID, E2E_VMTEST_EMAIL,
 * E2E_VMTEST_PASSWORD, E2E_AGENT_NAME (all required; the spec skips
 * otherwise), E2E_INPUT_PLAN (`points` by default).
 */
import * as fs from 'node:fs'
import { test, expect, type Page } from '@playwright/test'

const API_URL = process.env.E2E_API_URL || ''
const BASE_URL = process.env.E2E_BASE_URL || ''
const TENANT_ID = process.env.E2E_VMTEST_TENANT_ID || ''
const EMAIL = process.env.E2E_VMTEST_EMAIL || ''
const PASSWORD = process.env.E2E_VMTEST_PASSWORD || ''
const AGENT_NAME = process.env.E2E_AGENT_NAME || ''
const PLAN = process.env.E2E_INPUT_PLAN || 'points'

/** The named agent's id once it reports online. Exact-name match only, as in
 *  `vmtest-remote.spec.ts` (parallel VMs must never cross-match). */
async function findNamedOnlineAgent(token: string): Promise<string | null> {
  for (let i = 0; i < 24; i++) {
    // Every page: the listing returns 25 rows unless asked for more (100 at most), and a long-lived lab device
    // drops off the first page as the org fills with cells.
    for (let page = 1, pages = 1; page <= pages; page++) {
      const resp = await fetch(`${API_URL}/api/tenant/${TENANT_ID}/agent?per_page=100&page=${page}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) break
      const body = (await resp.json()) as {
        total_pages?: number
        items?: Array<{
          id: string
          machine_name?: string
          name?: string
          display_name?: string
          is_online: boolean
        }>
      }
      pages = body.total_pages ?? 1
      const hit = body.items?.find(
        (a) =>
          a.is_online &&
          (a.machine_name === AGENT_NAME || a.name === AGENT_NAME || a.display_name === AGENT_NAME),
      )
      if (hit) return hit.id
    }
    await new Promise((r) => setTimeout(r, 5000))
  }
  return null
}

type Picture = { x: number; y: number; w: number; h: number; srcW: number; srcH: number }

/** Where the remote picture is drawn on the page: the largest `<canvas>` or
 *  `<video>` that has decoded dimensions, with `object-fit: contain`'s
 *  letterbox applied. `null` until a frame has been decoded. */
async function picture(page: Page): Promise<Picture | null> {
  return await page.evaluate(() => {
    const els = [
      ...Array.from(document.querySelectorAll('video')),
      ...Array.from(document.querySelectorAll('canvas')),
    ]
    let best: { r: DOMRect; srcW: number; srcH: number } | null = null
    for (const el of els) {
      const r = el.getBoundingClientRect()
      const srcW = el instanceof HTMLVideoElement ? el.videoWidth : el.width
      const srcH = el instanceof HTMLVideoElement ? el.videoHeight : el.height
      if (!srcW || !srcH || r.width < 50 || r.height < 50) continue
      // 300×150 is a canvas nobody has drawn into yet (the HTML default), not
      // a decoded picture. Measured: one run aimed at one, and every target
      // missed. A real remote screen is far larger.
      if (srcW < 320 || srcH < 200) continue
      if (!best || r.width * r.height > best.r.width * best.r.height) best = { r, srcW, srcH }
    }
    if (!best) return null
    const { r, srcW, srcH } = best
    const scale = Math.min(r.width / srcW, r.height / srcH)
    const w = srcW * scale
    const h = srcH * scale
    return { x: r.left + (r.width - w) / 2, y: r.top + (r.height - h) / 2, w, h, srcW, srcH }
  })
}

/** AC5 — what the remote picture shows near each target: the count of
 *  ACHROMATIC dark and bright pixels in a 48 px box from 8 px up-left of the
 *  point (an arrow's hotspot is its tip). GNOME's arrow is black with a white
 *  outline; the probe's own background is flat grey and its pointer crosshair
 *  pure red, so neither counts. Read at the picture's native size. */
async function cursorPixels(
  page: Page,
  targets: Array<[number, number]>,
): Promise<Array<{ dark: number; bright: number }> | null> {
  return await page.evaluate((targets) => {
    const els = [
      ...Array.from(document.querySelectorAll('video')),
      ...Array.from(document.querySelectorAll('canvas')),
    ]
    let best: { el: HTMLVideoElement | HTMLCanvasElement; w: number; h: number; area: number } | null = null
    for (const el of els) {
      const r = el.getBoundingClientRect()
      const w = el instanceof HTMLVideoElement ? el.videoWidth : el.width
      const h = el instanceof HTMLVideoElement ? el.videoHeight : el.height
      if (w < 320 || h < 200) continue
      if (!best || r.width * r.height > best.area) best = { el, w, h, area: r.width * r.height }
    }
    if (!best) return null
    const c = document.createElement('canvas')
    c.width = best.w
    c.height = best.h
    const g = c.getContext('2d', { willReadFrequently: true })
    if (!g) return null
    g.drawImage(best.el, 0, 0, best.w, best.h)
    return targets.map(([fx, fy]) => {
      const x0 = Math.max(0, Math.round(fx * best.w) - 8)
      const y0 = Math.max(0, Math.round(fy * best.h) - 8)
      const d = g.getImageData(x0, y0, Math.min(48, best.w - x0), Math.min(48, best.h - y0)).data
      let dark = 0
      let bright = 0
      for (let i = 0; i < d.length; i += 4) {
        const hi = Math.max(d[i], d[i + 1], d[i + 2])
        const lo = Math.min(d[i], d[i + 1], d[i + 2])
        if (hi - lo < 30 && hi < 70) dark++
        else if (hi - lo < 30 && lo > 200) bright++
      }
      return { dark, bright }
    })
  }, targets)
}

/** AC5 — where the viewer's own cursor overlay is, normalised to the picture:
 *  the `.remote-cursor-canvas` painted from the agent's `cursor` channel.
 *  `null` when the viewer shows none. */
async function cursorOverlay(page: Page, p: Picture): Promise<{ fx: number; fy: number } | null> {
  return await page.evaluate((p) => {
    const el = document.querySelector('.remote-cursor-canvas')
    if (!el) return null
    const r = el.getBoundingClientRect()
    if (r.width === 0 || r.height === 0) return null
    return { fx: (r.left - p.x) / p.w, fy: (r.top - p.y) / p.h }
  }, p)
}

/** One line per action, for the harness to compare against the probe's log.
 *  `wall` is seconds since the epoch, like the probe's own field. */
function sent(kind: string, fields: Record<string, unknown> = {}): void {
  console.log(`[vmtest-input] sent ${JSON.stringify({ kind, wall: Date.now() / 1000, ...fields })}`)
}

const pause = (page: Page, ms: number) => page.waitForTimeout(ms)

test.describe('vmtest viewer input (named agent)', () => {
  test.skip(
    !API_URL || !BASE_URL || !TENANT_ID || !EMAIL || !PASSWORD || !AGENT_NAME,
    'vmtest env not set (E2E_BASE_URL/E2E_API_URL/E2E_VMTEST_TENANT_ID/E2E_VMTEST_EMAIL/E2E_VMTEST_PASSWORD/E2E_AGENT_NAME)',
  )
  test.setTimeout(4 * 60 * 1000)

  test(`the viewer's input reaches the host (${PLAN})`, async ({ page, context }) => {
    // Analytics must never count a test session (FR-102).
    await context.route('https://purestat.ai/**', (r) => r.abort())
    // Cookie-only sessions (#680/#690): log in through the context so the
    // HttpOnly cookie lands in this context's jar — see vmtest-remote.spec.ts.
    const loginResp = await context.request.post(`${API_URL}/api/auth/login`, {
      data: { email: EMAIL, password: PASSWORD },
    })
    expect(loginResp.ok(), `browser login failed: ${loginResp.status()}`).toBeTruthy()
    const token = ((await loginResp.json()) as { access_token: string }).access_token
    await context.addInitScript(() => {
      try {
        window.localStorage.setItem('meshharbor-signed-in', '1')
      } catch {
        /* storage blocked: the cookie still authenticates */
      }
    })
    const agentId = await findNamedOnlineAgent(token)
    expect(agentId, `agent "${AGENT_NAME}" never reported online in tenant ${TENANT_ID}`).toBeTruthy()

    await page.goto(`${BASE_URL}/tenant/${TENANT_ID}/agent/${agentId}/remote`)
    await page.getByRole('button', { name: /^connect$/i }).first().click({ timeout: 30_000 })
    await expect(page.locator('text=/^connected$/i').first()).toBeVisible({ timeout: 90_000 })

    // The same picture, at the same place, on two reads 500 ms apart: a
    // stream still settling its size or layout is not one to aim at.
    let pic: Picture | null = null
    await expect
      .poll(
        async () => {
          const a = await picture(page)
          await pause(page, 500)
          const b = await picture(page)
          pic = b
          return a !== null && b !== null && JSON.stringify(a) === JSON.stringify(b)
        },
        { timeout: 60_000, message: 'no decoded remote picture settled' },
      )
      .toBe(true)
    const p = pic as unknown as Picture
    console.log(`[vmtest-input] picture ${JSON.stringify(p)}`)
    const at = (fx: number, fy: number) => ({ x: p.x + fx * p.w, y: p.y + fy * p.h })
    const moveTo = async (fx: number, fy: number) => {
      const t = at(fx, fy)
      // ONE jump, not a glide: each target should be one motion on the host.
      await page.mouse.move(t.x, t.y, { steps: 1 })
      sent('move', { fx, fy, px: Math.round(fx * p.srcW), py: Math.round(fy * p.srcH) })
    }

    if (PLAN === 'cursor') {
      // AC5 — the harness moves the host's pointer to each target and touches
      // `/work/cursor-at-<n>`. The spec samples a second and a half later, so
      // a frame with the pointer in its new place has arrived.
      const targets: Array<[number, number]> = [
        [0.3, 0.6],
        [0.7, 0.6],
      ]
      sent('cursor-ready', { targets })
      for (let n = 0; n < targets.length; n++) {
        const marker = `/work/cursor-at-${n}`
        await expect
          .poll(() => fs.existsSync(marker), {
            timeout: 90_000,
            message: `the harness never placed the pointer (${marker})`,
          })
          .toBe(true)
        await pause(page, 1_500)
        sent('cursor-sample', {
          n,
          regions: await cursorPixels(page, targets),
          overlay: await cursorOverlay(page, p),
        })
      }
      sent('done')
      return
    }

    if (PLAN === 'close-mid-drag' || PLAN === 'crash-mid-drag') {
      await moveTo(0.5, 0.5)
      await pause(page, 1_000)
      await page.mouse.down()
      sent('press', { fx: 0.5, fy: 0.5 })
      for (const f of [0.52, 0.54, 0.56, 0.58, 0.6]) {
        await moveTo(f, f)
        await pause(page, 150)
      }
      await pause(page, 1_500)
      // The viewer vanishes with the button still held: no mouse-up from the
      // test. What happens to that button is the event under test.
      sent('vanish', { how: PLAN, held_at_fx: 0.6, held_at_fy: 0.6 })
      if (PLAN === 'crash-mid-drag') {
        // A crashed renderer runs no unload, blur or visibility handler, so
        // the page cannot let go. Its sockets die with it, and only the
        // agent's arbiter is left to release the button.
        page.on('crash', () => sent('crashed'))
        const cdp = await context.newCDPSession(page)
        // NOT awaited: the crash kills the target that would answer, so the
        // call never settles. Measured: awaited, every attempt sat out the
        // 4-minute test timeout after a crash that took 240 ms. Wait for the
        // page's own crash event instead.
        void cdp.send('Page.crash').catch(() => {})
        await page.waitForEvent('crash', { timeout: 15_000 }).catch(() => {})
      } else {
        await page.close()
      }
      return
    }

    // `points` — AC4: three points, a click, a wheel notch, ASCII, Shift+A.
    for (const [fx, fy] of [
      [0.25, 0.25],
      [0.75, 0.25],
      [0.5, 0.75],
    ]) {
      await moveTo(fx, fy)
      await pause(page, 1_500)
    }
    const c = at(0.5, 0.75)
    await page.mouse.click(c.x, c.y)
    sent('click', { fx: 0.5, fy: 0.75 })
    await pause(page, 1_000)
    await page.mouse.wheel(0, 120)
    sent('wheel', { dy: 120 })
    await pause(page, 1_000)
    await page.keyboard.type('hello 123', { delay: 80 })
    sent('type', { text: 'hello 123' })
    await pause(page, 1_000)
    await page.keyboard.down('Shift')
    await page.keyboard.press('KeyA')
    await page.keyboard.up('Shift')
    sent('shifted', { text: 'A' })
    await pause(page, 1_500)
    sent('done')
  })
})
