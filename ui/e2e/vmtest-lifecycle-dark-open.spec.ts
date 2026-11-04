/**
 * FR-93 P5 — LAB ONLY: the lifecycle oracle (AC7) for a session OPENED during an event (`LC_PRE`): it says
 * `[lc] ready` once connected, without waiting for a picture first. Otherwise vmtest-lifecycle.spec.ts, line
 * for line. Driven by meshharbor-deploy's `vmtest/lab/lifecycle/run.sh`; skipped without the vmtest env.
 * ONE viewer session to the named agent,
 * held while the harness drives lifecycle events from outside the guest (QMP keys, loginctl, gdbus) and dates
 * each one. Every 500 ms this logs what a person at the viewer would see: whether the session says connected,
 * a checksum and the lit share of the picture (64×40), the "cannot capture" overlay's words, any
 * reconnect / waiting status line, and the input-reach warning's words. `[lc] ready` tells the harness the picture is up; the harness ends the hold
 * by touching /work/lc-stop. The verdict lines this log up against the harness's event log.
 */
import * as fs from 'node:fs'
import { test, expect, type Page } from '@playwright/test'

const API_URL = process.env.E2E_API_URL || ''
const BASE_URL = process.env.E2E_BASE_URL || ''
const TENANT_ID = process.env.E2E_VMTEST_TENANT_ID || ''
const EMAIL = process.env.E2E_VMTEST_EMAIL || ''
const PASSWORD = process.env.E2E_VMTEST_PASSWORD || ''
const AGENT_NAME = process.env.E2E_AGENT_NAME || ''
/** The longest hold; the harness normally stops it sooner. */
const HOLD_S = 900

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
        items?: Array<{ id: string; machine_name?: string; name?: string; display_name?: string; is_online: boolean }>
      }
      pages = body.total_pages ?? 1
      const hit = body.items?.find(
        (a) => a.is_online && (a.machine_name === AGENT_NAME || a.name === AGENT_NAME || a.display_name === AGENT_NAME),
      )
      if (hit) return hit.id
    }
    await new Promise((r) => setTimeout(r, 5000))
  }
  return null
}

/** A checksum and the lit share of the largest live picture, scaled to 64×40, and an 8×5 grey thumbnail (each
 *  cell the mean of an 8×8 block) for the verdict to tell a new screen from a clock tick. */
async function picture(page: Page): Promise<{ sum: number | null; lit: number | null; g?: number[] }> {
  return await page.evaluate(() => {
    const els = [...Array.from(document.querySelectorAll('video')), ...Array.from(document.querySelectorAll('canvas'))]
    let best: HTMLVideoElement | HTMLCanvasElement | null = null
    let area = 0
    for (const el of els) {
      const w = el instanceof HTMLVideoElement ? el.videoWidth : el.width
      const h = el instanceof HTMLVideoElement ? el.videoHeight : el.height
      if (w < 320 || h < 200) continue
      if (w * h > area) {
        area = w * h
        best = el
      }
    }
    if (!best) return { sum: null, lit: null }
    const c = document.createElement('canvas')
    c.width = 64
    c.height = 40
    const ctx = c.getContext('2d')
    if (!ctx) return { sum: null, lit: null }
    try {
      ctx.drawImage(best, 0, 0, 64, 40)
      const d = ctx.getImageData(0, 0, 64, 40).data
      let s = 0
      let lit = 0
      const g = new Array<number>(40).fill(0)
      for (let i = 0; i < d.length; i += 4) {
        s = (s * 31 + d[i] + d[i + 1] * 3 + d[i + 2] * 7) >>> 0
        if (d[i] + d[i + 1] + d[i + 2] > 30) lit++
        const px = (i / 4) % 64
        const py = Math.floor(i / 4 / 64)
        g[Math.floor(py / 8) * 8 + Math.floor(px / 8)] += (d[i] + d[i + 1] + d[i + 2]) / 3
      }
      return { sum: s, lit: lit / (64 * 40), g: g.map((v) => Math.round(v / 64)) }
    } catch {
      return { sum: null, lit: null }
    }
  })
}

/** The viewer's own status words a person would read, if any. */
const STATUS = /(Reconnecting[^.\n]*|Connection lost[^.\n]*|No video from this device[^.\n]*|waiting for the person[^.\n]*|The person at this computer[^.\n]*|agent (is )?offline[^.\n]*|disconnected[^.\n]*|This computer's display[^.\n]*|waiting for the display[^.\n]*)/i

type Read = { wall: number; counter: number | null; why: string; w: number; h: number; lit?: number }

async function readProbe(page: import('@playwright/test').Page): Promise<Read> {
  return await page.evaluate(() => {
    const wall = Date.now()
    let src: HTMLVideoElement | HTMLCanvasElement | null = null
    let W = 0
    let H = 0
    const v = document.querySelector('video') as HTMLVideoElement | null
    if (v && v.videoWidth > 0) {
      src = v
      W = v.videoWidth
      H = v.videoHeight
    } else {
      const c = (Array.from(document.querySelectorAll('canvas')) as HTMLCanvasElement[])
        .filter((x) => x.width > 100 && x.height > 100)
        .sort((a, b) => b.width * b.height - a.width * a.height)[0]
      if (c) {
        src = c
        W = c.width
        H = c.height
      }
    }
    if (!src) return { wall, counter: null, why: 'no frame source', w: 0, h: 0 }
    const cv = document.createElement('canvas')
    cv.width = W
    cv.height = H
    const ctx = cv.getContext('2d', { willReadFrequently: true })!
    ctx.drawImage(src, 0, 0, W, H)
    const all = ctx.getImageData(0, 0, W, H).data
    let litN = 0
    for (let i = 0; i < all.length; i += 4 * 97) if (0.2126 * all[i] + 0.7152 * all[i + 1] + 0.0722 * all[i + 2] > 40) litN++
    const lit = litN / (all.length / (4 * 97))
    const px = (x: number, y: number) => {
      const i = (Math.round(y) * W + Math.round(x)) * 4
      return [all[i], all[i + 1], all[i + 2]]
    }
    const red = ([r, g, b]: number[]) => r > 160 && g < 100 && b < 100
    const blue = ([r, g, b]: number[]) => b > 160 && r < 100 && g < 100
    // The red marker: the first red RUN at least 2 % of the frame wide, row-major, in the top-left half. The
    // marker is 4 % wide; the probe's own pointer crosshair, also red, is 2 px thick and must not match.
    let fx = -1
    let fy = -1
    const minRun = Math.max(6, Math.floor(W * 0.02))
    outer: for (let y = 0; y < H * 0.5; y += 2) {
      let x = 0
      while (x < W * 0.5) {
        if (!red(px(x, y))) {
          x += 2
          continue
        }
        let e = x
        while (e < W - 1 && red(px(e + 1, y))) e++
        if (e - x + 1 >= minRun) {
          fx = x
          fy = y
          break outer
        }
        x = e + 2
      }
    }
    if (fx < 0) return { wall, counter: null, why: 'no red marker', w: W, h: H, lit }
    // Measure it: its horizontal extent a few pixels into it, then its vertical extent through that centre.
    const ym = Math.min(H - 1, fy + 6)
    let xl = fx
    while (xl > 0 && red(px(xl - 1, ym))) xl--
    let xr = fx
    while (xr < W - 1 && red(px(xr + 1, ym))) xr++
    const cx = (xl + xr) / 2
    let yt = ym
    while (yt > 0 && red(px(cx, yt - 1))) yt--
    let yb = ym
    while (yb < H - 1 && red(px(cx, yb + 1))) yb++
    const cy = (yt + yb) / 2
    const s = Math.min(xr - xl + 1, yb - yt + 1)
    if (s < 6) return { wall, counter: null, why: `marker too small (${s} px)`, w: W, h: H, lit }
    const p = 1.2 * s
    if (!blue(px(cx, cy + p))) return { wall, counter: null, why: 'no blue marker below the red', w: W, h: H, lit }
    // Each data cell by a patch average around its centre (a third of the cell), luma over mid-grey = 1.
    const bitAt = (row: number, col: number) => {
      const x0 = cx + col * p
      const y0 = cy + row * p
      const r = Math.max(1, Math.floor(s / 6))
      let sum = 0
      let n = 0
      for (let dy = -r; dy <= r; dy++)
        for (let dx = -r; dx <= r; dx++) {
          const [R, G, B] = px(x0 + dx, y0 + dy)
          sum += 0.2126 * R + 0.7152 * G + 0.0722 * B
          n++
        }
      return sum / n > 128 ? 1 : 0
    }
    let word = 0
    for (let row = 0; row < 2; row++) for (let col = 1; col <= 10; col++) word = (word << 1) | bitAt(row, col)
    const counter = word >> 4
    const check = word & 0xf
    const nib = ((counter >> 12) + ((counter >> 8) & 0xf) + ((counter >> 4) & 0xf) + (counter & 0xf)) & 0xf
    if (nib !== check) return { wall, counter: null, why: `check ${check} != ${nib} (word ${word})`, w: W, h: H, lit }
    return { wall, counter, why: 'ok', w: W, h: H, lit }
  })
}

test.describe('vmtest lifecycle (named agent)', () => {
  test.describe.configure({ retries: 0 })
  test.skip(!API_URL || !BASE_URL || !TENANT_ID || !EMAIL || !PASSWORD || !AGENT_NAME, 'vmtest env not set')

  test('one session opened while the display is off', async ({ page, context }) => {
    // Analytics must never count a test session (FR-102).
    await context.route('https://purestat.ai/**', (r) => r.abort())
    test.setTimeout((HOLD_S + 240) * 1000)
    const loginResp = await context.request.post(`${API_URL}/api/auth/login`, { data: { email: EMAIL, password: PASSWORD } })
    expect(loginResp.ok(), `browser login failed: ${loginResp.status()}`).toBeTruthy()
    const token = ((await loginResp.json()) as { access_token: string }).access_token
    await context.addInitScript(() => {
      try {
        window.localStorage.setItem('meshharbor-signed-in', '1')
      } catch {
        /* the cookie still authenticates */
      }
    })
    const agentId = await findNamedOnlineAgent(token)
    expect(agentId, `agent "${AGENT_NAME}" never reported online`).toBeTruthy()
    await page.goto(`${BASE_URL}/tenant/${TENANT_ID}/agent/${agentId}/remote`)
    await page.getByRole('button', { name: /^connect$/i }).first().click({ timeout: 30_000 })
    await expect(page.locator('text=/^connected$/i').first()).toBeVisible({ timeout: 90_000 })
    console.log(`[lc] ready ${JSON.stringify({ wall: Date.now() / 1000 })}`)

    const overlay = page.locator('.no-media-overlay').first()
    const reachBanner = page.getByTestId('rc-input-reach').first()
    const end = Date.now() + HOLD_S * 1000
    while (Date.now() < end && !fs.existsSync('/work/lc-stop')) {
      if (fs.existsSync('/work/lc-move')) {
        fs.unlinkSync('/work/lc-move')
        const box = await page.locator('.video-frame').first().boundingBox()
        if (box) {
          await page.mouse.move(box.x + box.width * 0.5, box.y + box.height * 0.5)
          await page.mouse.move(box.x + box.width * 0.56, box.y + box.height * 0.56, { steps: 6 })
        }
        console.log(`[lc] viewer-move ${JSON.stringify({ wall: Date.now() / 1000, box: !!box })}`)
      }
      const p = await picture(page)
      const pr = await readProbe(page)
      const connected = await page.locator('text=/^connected$/i').first().isVisible().catch(() => false)
      const ov = (await overlay.isVisible().catch(() => false))
        ? ((await overlay.innerText().catch(() => '')) || '').replace(/\s+/g, ' ').slice(0, 240)
        : ''
      const body = ((await page.locator('body').innerText().catch(() => '')) || '').replace(/\s+/g, ' ')
      const status = (body.match(STATUS)?.[0] || '').slice(0, 160)
      // FR-93 P1a — the input-reach warning, if the viewer shows one (AC11's kill switch shows none).
      const reach = (await reachBanner.isVisible().catch(() => false))
        ? ((await reachBanner.innerText().catch(() => '')) || '').replace(/\s+/g, ' ').slice(0, 160)
        : ''
      console.log(`[lc] ${JSON.stringify({ wall: Date.now() / 1000, connected, sum: p.sum, lit: p.lit, g: p.g, counter: pr.counter, w: pr.w, h: pr.h, overlay: ov, status, reach })}`)
      await page.waitForTimeout(500)
    }
    console.log(`[lc] done ${JSON.stringify({ wall: Date.now() / 1000 })}`)
  })
})
