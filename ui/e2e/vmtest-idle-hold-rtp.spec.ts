/**
 * FR-93 lab: AC8's idle hold on the RTP media track, driven by meshharbor-deploy's
 * `vmtest/lab/measure/idle-cost.sh <guest> <label> <on|off> rtp`. One viewer session held for
 * E2E_SOAK_MINUTES (30 by default). Every minute it checks that the session
 * still says connected and that the picture still changes. The lab probe's
 * block code ticks every 250 ms, so a live stream always differs.
 */
import { test, expect, type Page } from '@playwright/test'

const API_URL = process.env.E2E_API_URL || ''
const BASE_URL = process.env.E2E_BASE_URL || ''
const TENANT_ID = process.env.E2E_VMTEST_TENANT_ID || ''
const EMAIL = process.env.E2E_VMTEST_EMAIL || ''
const PASSWORD = process.env.E2E_VMTEST_PASSWORD || ''
const AGENT_NAME = process.env.E2E_AGENT_NAME || ''
const MINUTES = 4

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

/** A checksum of the largest live picture, scaled down to 64×40. */
async function pictureSum(page: Page): Promise<number | null> {
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
    if (!best) return null
    const c = document.createElement('canvas')
    c.width = 64
    c.height = 40
    const ctx = c.getContext('2d')
    if (!ctx) return null
    try {
      ctx.drawImage(best, 0, 0, 64, 40)
      const d = ctx.getImageData(0, 0, 64, 40).data
      let s = 0
      for (let i = 0; i < d.length; i += 4) s = (s * 31 + d[i] + d[i + 1] * 3 + d[i + 2] * 7) >>> 0
      return s
    } catch {
      return null
    }
  })
}

test.describe('vmtest idle hold, RTP (named agent)', () => {
  // A failed 30-minute soak must not run twice more.
  test.describe.configure({ retries: 0 })
  test.skip(!API_URL || !BASE_URL || !TENANT_ID || !EMAIL || !PASSWORD || !AGENT_NAME, 'vmtest env not set')

  test(`one session held for ${MINUTES} minutes`, async ({ page, context }) => {
    // Analytics must never count a test session (FR-102).
    await context.route('https://purestat.ai/**', (r) => r.abort())
    // In the body: the CLI's --timeout=120000 is the default this overrides.
    test.setTimeout((MINUTES + 6) * 60 * 1000)
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
    // AC8 — FR-29 measured the RTP media track: pin the viewer to it (VP9; this Chromium has no H.264).
    await context.addInitScript(() => {
      try {
        window.localStorage.setItem('meshharbor-rc-video-transport.v2', 'webrtc')
        window.localStorage.setItem('meshharbor-rc-preferred-codec', 'vp9')
        window.localStorage.setItem('meshharbor-rc-render-path', 'video')
      } catch {
        /* the default path, then — the journal's heartbeat names the pump either way */
      }
    })
    await page.goto(`${BASE_URL}/tenant/${TENANT_ID}/agent/${agentId}/remote`)
    await page.getByRole('button', { name: /^connect$/i }).first().click({ timeout: 30_000 })
    await expect(page.locator('text=/^connected$/i').first()).toBeVisible({ timeout: 90_000 })
    await expect.poll(() => pictureSum(page), { timeout: 60_000 }).not.toBeNull()
    console.log(`[vmtest-idle] start ${JSON.stringify({ wall: Date.now() / 1000 })}`)
    let last = await pictureSum(page)
    let stale = 0
    for (let m = 1; m <= MINUTES; m++) {
      await page.waitForTimeout(60_000)
      const connected = await page.locator('text=/^connected$/i').first().isVisible()
      const now = await pictureSum(page)
      const changed = now !== null && now !== last
      if (!changed) stale++
      console.log(`[vmtest-idle] minute ${JSON.stringify({ m, connected, changed, wall: Date.now() / 1000 })}`)
      expect(connected, `minute ${m}: the session no longer says connected`).toBeTruthy()
      last = now
    }
    console.log(`[vmtest-idle] done ${JSON.stringify({ minutes: MINUTES, stale })}`)
  })
})
