/**
 * FR-61 (vmtest) — the remote-desktop check for the throwaway-OS install &
 * verify matrix (docs/fr/FR-61-vmtest-matrix.md, #1199).
 *
 * remote-session-smoke.spec.ts discovers "the first online agent", which is
 * correct for the single-agent agent-e2e harness and WRONG for vmtest: a
 * matrix run keeps several throwaway VMs alive in the same org, so this spec
 * selects the agent by EXACT name (`E2E_AGENT_NAME`) and never falls back.
 *
 * Driven by meshharbor-deploy/vmtest/playwright/run-rd-check.sh from mars
 * against the real server. Asserts, in order:
 *   1. the named agent reports online in the org listing (polls — the VM
 *      enrolled seconds ago),
 *   2. the viewer connects (phase chip "connected"),
 *   3. FRAMES FLOW, twice, via two independent oracles that together cover
 *      every media path:
 *        - `__meshharbor_remote_pc` → getStats `framesDecoded` (the RTP track
 *          path; the hook remote-session-smoke documents wishing it had),
 *        - `__meshharbor_remote_stats` → the composable's live fps/bitrate (the
 *          DataChannel pump paths, where inbound-rtp stats are silent).
 *      While sampling, the mouse wiggles over the surface so input-capable
 *      cells produce real motion; input-less cells are still covered by the
 *      idle keepalive re-encode (FR-38), which keeps fps > 0 on a static
 *      desktop.
 *   4. the picture has CONTENT — some of it is lit (#1719: steps 1–3 all
 *      passed on a uniformly black stream). A lane whose desktop is dark by
 *      design opts out with `E2E_RD_EXPECT_CONTENT=0`; every lane saves the
 *      viewer screenshot `rd-surface.png` either way.
 *
 * Env (all required; spec skips otherwise): E2E_BASE_URL, E2E_API_URL,
 * E2E_VMTEST_TENANT_ID, E2E_VMTEST_EMAIL, E2E_VMTEST_PASSWORD, E2E_AGENT_NAME.
 */
import { test, expect, type Page } from '@playwright/test'

const API_URL = process.env.E2E_API_URL || ''
const BASE_URL = process.env.E2E_BASE_URL || ''
const TENANT_ID = process.env.E2E_VMTEST_TENANT_ID || ''
const EMAIL = process.env.E2E_VMTEST_EMAIL || ''
const PASSWORD = process.env.E2E_VMTEST_PASSWORD || ''
const AGENT_NAME = process.env.E2E_AGENT_NAME || ''

/** The named agent's id once it reports online. Polls up to ~2 min — the VM
 *  enrolled moments before this spec started. Exact-name match only. */
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

/** Path-agnostic media progress: max(framesDecoded across inbound-rtp video)
 *  and the composable's live fps. Either strictly advancing proves a live
 *  stream. */
async function mediaProgress(page: Page): Promise<{ frames: number; fps: number }> {
  return await page.evaluate(async () => {
    const w = window as unknown as Record<string, unknown>
    const pc = w.__meshharbor_remote_pc as RTCPeerConnection | undefined
    let frames = -1
    if (pc) {
      const stats = await pc.getStats()
      stats.forEach((r) => {
        const rep = r as unknown as { type?: string; kind?: string; framesDecoded?: number }
        if (rep.type === 'inbound-rtp' && rep.kind === 'video' && rep.framesDecoded !== undefined) {
          frames = Math.max(frames, rep.framesDecoded)
        }
      })
    }
    const statsRef = w.__meshharbor_remote_stats as { value?: { fps?: number } } | undefined
    const fps = statsRef?.value?.fps ?? -1
    return { frames, fps }
  })
}

/** A signature of whatever surface is actually painting — `<video>` for the
 *  RTP path, the largest `<canvas>` for the DataChannel paths (VP9-444 /
 *  HEVC-over-DC, what a SW-encode agent negotiates, which has NO <video> and
 *  NO inbound-rtp at all). 'none' = nothing live yet. */
async function surfaceSig(page: Page): Promise<string> {
  return await page.evaluate(() => {
    const v = document.querySelector('video') as HTMLVideoElement | null
    if (v && v.videoWidth > 0) return 'v:' + v.currentTime
    const c = (Array.from(document.querySelectorAll('canvas')) as HTMLCanvasElement[])
      .filter((x) => x.width > 100 && x.height > 100)
      .sort((a, b) => b.width * b.height - a.width * a.height)[0]
    if (!c) return 'none'
    try {
      const s = document.createElement('canvas')
      s.width = 32
      s.height = 20
      s.getContext('2d')!.drawImage(c, 0, 0, 32, 20)
      return 'c:' + s.toDataURL().slice(-96)
    } catch {
      return 'tainted'
    }
  })
}

/** The fps the VIEWER ITSELF reports, from its own live stats pill. The pill
 *  renders `v-if="metrics.fps"`, and those metrics are fed by the real pump on
 *  EVERY transport — so a non-zero reading is direct evidence that frames are
 *  arriving, including on a DataChannel path where inbound-rtp is silent.
 *  Read from rendered text rather than a class, so a restyle cannot silently
 *  turn this oracle off. 0 = the viewer is not reporting frames. */
async function viewerFps(page: Page): Promise<number> {
  return await page.evaluate(() => {
    const m = (document.body.innerText || '').match(/(\d+(?:\.\d+)?)\s*fps/i)
    return m ? Number(m[1]) : 0
  })
}

/** Ground truth for ANY transport, in two independent forms:
 *   1. the viewer's own fps readout is non-zero at both ends of a 3 s window —
 *      the ONLY workable signal on a STATIC desktop, where a live stream is
 *      re-encoded by the idle keepalive and successive frames are pixel-
 *      identical (measured 2026-09-04: a healthy 28 fps VP9-444 stream failed a
 *      pixel-change proof because the guest was just sitting at its wallpaper);
 *   2. failing that, the painted surface CHANGES across the window.
 *  A dead stream reports no fps and paints nothing, so it still fails. */
async function proveStreamLive(page: Page): Promise<void> {
  const f0 = await viewerFps(page)
  if (f0 > 0) {
    await wiggle(page)
    await page.waitForTimeout(3_000)
    const f1 = await viewerFps(page)
    expect(f1, `viewer fps fell to 0 over 3s (was ${f0}) — stream stalled`).toBeGreaterThan(0)
    return
  }
  await proveSurfaceLive(page)
}

/** Pixel-change proof: a live surface appears and its pixels CHANGE across a
 *  3 s window while the pointer wiggles. Used when the viewer reports no fps. */
async function proveSurfaceLive(page: Page): Promise<void> {
  await expect
    .poll(
      async () => {
        await wiggle(page)
        return await surfaceSig(page)
      },
      { timeout: 60_000, message: 'no live remote surface (video/canvas) appeared' },
    )
    .not.toBe('none')
  const s0 = await surfaceSig(page)
  await wiggle(page)
  await page.waitForTimeout(3_000)
  const s1 = await surfaceSig(page)
  expect(s0, 'remote surface pixels unreadable (tainted)').not.toBe('tainted')
  expect(
    s1 !== s0,
    `remote surface static over 3s — stream frozen or not painting (${s0.slice(0, 24)} → ${s1.slice(0, 24)})`,
  ).toBe(true)
}

/** Wiggle the pointer over the remote surface so input-capable agents
 *  produce real motion (and the input path gets a free smoke). Best-effort:
 *  a cell whose agent cannot inject still passes via keepalive frames. */
async function wiggle(page: Page): Promise<void> {
  const surface = page.locator('video, canvas').first()
  try {
    const box = await surface.boundingBox()
    if (!box) return
    for (let i = 0; i < 6; i++) {
      await page.mouse.move(
        box.x + box.width * (0.3 + 0.07 * i),
        box.y + box.height * (0.4 + 0.05 * (i % 3)),
        { steps: 4 },
      )
      await page.waitForTimeout(120)
    }
  } catch {
    /* surface not interactable — keepalive frames carry the check */
  }
}

/** #1719 — CONTENT, not only motion. Every oracle above proves LIVENESS
 *  (frames decode, time advances, the viewer reports fps), and all of them
 *  passed on a stream that was uniformly BLACK: the Ubuntu cells are GNOME
 *  Wayland sessions, and a capture that falls through to XShm reads
 *  Xwayland's empty root. A remote desktop that shows nothing is the one
 *  failure this check exists to catch.
 *
 *  Default ON. A lane whose captured desktop is legitimately dark sets
 *  `E2E_RD_EXPECT_CONTENT=0` — the ARM cells, whose Xvfb virtual desktop has
 *  a black root by design — and is checked for liveness only; the
 *  measurement is still logged and the screenshot still saved, so the
 *  difference stays visible. */
const EXPECT_CONTENT = process.env.E2E_RD_EXPECT_CONTENT !== '0'
/** Share of sampled pixels that must be brighter than luma 40 (of 255). A
 *  black stream measures 0 %; a desktop with a wallpaper measures tens of
 *  percent, so 1 % separates them with a wide margin either side. */
const MIN_LIT = 0.01

type Content = { lit: number; spread: number } | 'none' | 'tainted'

/** Sample whatever surface is painting — the `<video>` on the RTP path, the
 *  largest `<canvas>` on the DataChannel paths, the same choice
 *  `surfaceSig` makes — at 64×40 and measure how much of it is lit. */
async function surfaceContent(page: Page): Promise<Content> {
  return await page.evaluate(() => {
    let src: HTMLVideoElement | HTMLCanvasElement | null = null
    const v = document.querySelector('video') as HTMLVideoElement | null
    if (v && v.videoWidth > 0) src = v
    else
      src =
        (Array.from(document.querySelectorAll('canvas')) as HTMLCanvasElement[])
          .filter((x) => x.width > 100 && x.height > 100)
          .sort((a, b) => b.width * b.height - a.width * a.height)[0] ?? null
    if (!src) return 'none'
    try {
      const s = document.createElement('canvas')
      s.width = 64
      s.height = 40
      const ctx = s.getContext('2d', { willReadFrequently: true })!
      ctx.drawImage(src, 0, 0, 64, 40)
      const d = ctx.getImageData(0, 0, 64, 40).data
      let lit = 0
      let min = 255
      let max = 0
      for (let i = 0; i < d.length; i += 4) {
        const y = 0.2126 * d[i] + 0.7152 * d[i + 1] + 0.0722 * d[i + 2]
        if (y > 40) lit++
        if (y < min) min = y
        if (y > max) max = y
      }
      return { lit: lit / (d.length / 4), spread: max - min }
    } catch {
      return 'tainted'
    }
  })
}

/** The picture must have SOMETHING in it. Polls for 20 s — the first frames
 *  of a stream can legitimately be dark while the encoder settles — and always
 *  saves a screenshot of the viewer to the test output (`rd-surface.png`),
 *  which `run-rd-check.sh` keeps with the cell, so a pass is inspectable too. */
async function proveContent(page: Page): Promise<void> {
  let last: Content = 'none'
  const deadline = Date.now() + 20_000
  while (Date.now() < deadline) {
    await wiggle(page)
    last = await surfaceContent(page)
    if (typeof last !== 'string' && last.lit >= MIN_LIT) break
    await page.waitForTimeout(1_000)
  }
  const shot = test.info().outputPath('rd-surface.png')
  await page.screenshot({ path: shot }).catch(() => undefined)
  const desc =
    typeof last === 'string'
      ? last
      : `lit=${(last.lit * 100).toFixed(1)}% spread=${last.spread.toFixed(0)}`
  console.log(`[vmtest-remote] content: ${desc}${EXPECT_CONTENT ? '' : ' (not asserted on this lane)'}`)
  if (!EXPECT_CONTENT) return
  expect(last, 'remote surface pixels unreadable (tainted)').not.toBe('tainted')
  expect(
    typeof last !== 'string' && last.lit >= MIN_LIT,
    `the remote picture is BLACK (${desc}): frames flow but show nothing — on a Wayland ` +
      'guest that is the XShm fallback reading the empty Xwayland root (#1719); the ' +
      "guest's own screen is in the cell's desktop-*.ppm",
  ).toBe(true)
}

test.describe('vmtest remote-desktop check (named agent)', () => {
  test.skip(
    !API_URL || !BASE_URL || !TENANT_ID || !EMAIL || !PASSWORD || !AGENT_NAME,
    'vmtest env not set (E2E_BASE_URL/E2E_API_URL/E2E_VMTEST_TENANT_ID/E2E_VMTEST_EMAIL/E2E_VMTEST_PASSWORD/E2E_AGENT_NAME)',
  )
  test.setTimeout(5 * 60 * 1000)

  test('named throwaway agent streams decoded, advancing frames', async ({ page, context }) => {
    // Analytics must never count a test session (FR-102).
    await context.route('https://purestat.ai/**', (r) => r.abort())
    // Sessions are COOKIE-ONLY since #680/#690 — seeding localStorage
    // access/refresh tokens does NOTHING and the SPA shows the login form.
    // Log in through the context's request API so the HttpOnly session cookie
    // lands in the jar shared with this context's pages, and set the
    // `meshharbor-signed-in` hint so the SPA renders its shell and refreshes via
    // the cookie instead of bouncing to /login.
    const loginResp = await context.request.post(`${API_URL}/api/auth/login`, {
      data: { email: EMAIL, password: PASSWORD },
    })
    expect(loginResp.ok(), `browser login failed: ${loginResp.status()}`).toBeTruthy()
    const token = ((await loginResp.json()) as { access_token: string }).access_token
    await context.addInitScript(() => {
      try {
        window.localStorage.setItem('meshharbor-signed-in', '1')
      } catch {
        /* private mode / storage blocked — the cookie still authenticates */
      }
    })

    const agentId = await findNamedOnlineAgent(token)
    expect(agentId, `agent "${AGENT_NAME}" never reported online in tenant ${TENANT_ID}`).toBeTruthy()

    const consoleErrors: string[] = []
    page.on('console', (msg) => {
      if (msg.type() === 'error') consoleErrors.push(msg.text())
    })

    await page.goto(`${BASE_URL}/tenant/${TENANT_ID}/agent/${agentId}/remote`)
    await expect(page.getByRole('button', { name: /^connect$/i }).first()).toBeVisible({
      timeout: 30_000,
    })
    await page.getByRole('button', { name: /^connect$/i }).first().click()

    await expect(page.locator('text=/^connected$/i').first()).toBeVisible({ timeout: 90_000 })

    const hooks = await page.evaluate(() => {
      const w = window as unknown as Record<string, unknown>
      return { pc: !!w.__meshharbor_remote_pc, stats: !!w.__meshharbor_remote_stats }
    })
    if (!hooks.pc && !hooks.stats) {
      // Viewer build predates the FR-61 hooks (e.g. prod not yet redeployed).
      // Degrade to a TRANSPORT-AGNOSTIC surface oracle: the RTP path paints a
      // <video> (advancing currentTime), the DataChannel paths (VP9-444 /
      // HEVC-over-DC — what a SW-encode agent actually negotiates) paint a
      // <canvas> via WebCodecs with NO <video> at all. Sample whichever surface
      // is live and require it to CHANGE across a 3 s window while the pointer
      // wiggles — a frozen or absent stream fails, a live one passes on any
      // transport. The hooks strengthen this automatically once they ship.
      console.warn('[vmtest-remote] FR-61 hooks absent -- using the surface pixel-change fallback')
      await proveStreamLive(page)
      await proveContent(page)
      return
    }

    // ── first frames: prefer the counters, but NEVER fail on them alone ────
    // ⚠️ Both counters are RTP-shaped: `getStats` has no inbound-rtp video and
    // `__meshharbor_remote_stats` is the RTP stats ref, so BOTH read zero on the
    // DataChannel transports even while the viewer paints a perfect stream.
    // Measured 2026-09-04: every Ubuntu cell "failed" RD while the toolbar read
    // `VP9 4:4:4 SW (libvpx) · direct · 28 fps · 9.1 Mbps` and the screenshot
    // showed the live desktop. Counters are an optimisation; the SURFACE is
    // ground truth — fall through to it rather than calling a working product
    // broken.
    const gateDeadline = Date.now() + 60_000
    let countersLive = false
    while (Date.now() < gateDeadline) {
      await wiggle(page)
      const p = await mediaProgress(page)
      if (p.frames > 0 || p.fps > 0) {
        countersLive = true
        break
      }
      // The viewer already reporting fps means frames ARE arriving on a
      // transport the RTP counters cannot see — stop waiting out the 60 s and
      // let proveStreamLive do the (transport-agnostic) liveness proof.
      if ((await viewerFps(page)) > 0) break
      await page.waitForTimeout(1_000)
    }
    if (!countersLive) {
      console.warn(
        '[vmtest-remote] RTP counters flat (DataChannel transport?) — proving liveness on the SURFACE',
      )
      await proveStreamLive(page)
      await proveContent(page)
      return
    }

    // ── liveness: progress across a 3 s window (not one painted frame) ─────
    const s0 = await mediaProgress(page)
    await wiggle(page)
    await page.waitForTimeout(3_000)
    const s1 = await mediaProgress(page)
    const advanced =
      (s1.frames > s0.frames && s1.frames > 0) || (s0.fps > 0 && s1.fps > 0)
    expect(
      advanced,
      `stream froze (framesDecoded ${s0.frames} → ${s1.frames}, fps ${s0.fps} → ${s1.fps})`,
    ).toBe(true)
    await proveContent(page)

    if (consoleErrors.length > 0) {
      console.warn(`[vmtest-remote] ${consoleErrors.length} console errors:`)
      for (const line of consoleErrors.slice(0, 10)) console.warn('  ', line)
    }
  })
})
