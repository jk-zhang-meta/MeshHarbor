// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-75 (#1447) — the `collab` pillar check for the self-host **profile**
 * matrix (docs/fr/FR-75-selfhost-profile-matrix.md).
 *
 * Runs INSIDE the server VM against `http://localhost:8080`, because a call is
 * only measurable there: RTP does not survive a port-forward, a LAN URL is not
 * a secure context (so `navigator.mediaDevices` is `undefined`), and
 * `MESHHARBOR__APP__FRONTEND_URL` must EQUAL the browser's Origin or the
 * cookie-authenticated `/ws` upgrade is refused 403. The prod e2e lane solved
 * the same three problems the same way, with an in-pod sidecar.
 *
 * ⚠️ WHY THIS EXISTS ALONGSIDE `conference-multi.spec.ts`: that spec proves the
 * JOIN FLOW and deliberately swallows its tile assertion
 * (`.catch(() => {})` — "in headless environments remote tiles may not
 * render"). That is the exact shape of the 2026-08-26 RTC-range incident,
 * where signalling was flawless — join, transports, producers, consumers all
 * green — and ZERO media arrived, for weeks, with nothing logged. So this spec
 * asserts DECODED FRAMES ADVANCING ON BOTH SIDES and fails if they do not.
 *
 * The oracle is the `<video>` element itself — `getVideoPlaybackQuality()
 * .totalVideoFrames` — not `getStats`. Two reasons: mediasoup-client owns the
 * RTCPeerConnections and the app exposes no debug hook for them, and a frame
 * counted by the element is a frame the compositor could actually paint, which
 * is the product claim. `currentTime` advancing is the corroborating signal.
 *
 * Env: E2E_BASE_URL, E2E_API_URL (both required; the spec skips otherwise).
 * Skips itself against a server that does not mount `conference`, so it is
 * inert on `remote`/`mesh`/`access` rather than falsely red.
 */
import { test, expect, type BrowserContext, type Page } from '@playwright/test'
import {
  uniqueUser,
  registerUserViaApi,
  createTenantViaApi,
  createRoomViaApi,
  addTenantMemberViaApi,
  joinRoomViaApi,
  startCallViaApi,
  sendMessageViaApi,
  loginViaUi,
} from './fixtures/test-helpers'

const API_URL = process.env.E2E_API_URL || ''
const BASE_URL = process.env.E2E_BASE_URL || ''

/** What this server actually mounts. Unauthenticated by design (FR-69 D10). */
async function serverModules(): Promise<string[]> {
  const resp = await fetch(`${API_URL}/api/capabilities`)
  if (!resp.ok) throw new Error(`capabilities: ${resp.status}`)
  return ((await resp.json()) as { modules: string[] }).modules
}

/**
 * Decoded-frame progress across every `<video>` on the page that is actually
 * playing something. Returns the best (max) counter, because the local
 * self-view is also a `<video>` and we care that SOME video is decoding — the
 * remote-tile-count assertion below is what makes it the peer's.
 */
async function videoProgress(page: Page): Promise<{ frames: number; time: number; videos: number }> {
  return await page.evaluate(() => {
    let frames = 0
    let time = 0
    let videos = 0
    for (const v of Array.from(document.querySelectorAll('video'))) {
      const el = v as HTMLVideoElement & {
        getVideoPlaybackQuality?: () => { totalVideoFrames: number }
        webkitDecodedFrameCount?: number
      }
      if (!el.srcObject) continue
      videos++
      const q = el.getVideoPlaybackQuality?.()
      const f = q ? q.totalVideoFrames : (el.webkitDecodedFrameCount ?? 0)
      if (f > frames) frames = f
      if (el.currentTime > time) time = el.currentTime
    }
    return { frames, time, videos }
  })
}

/**
 * A REMOTE track is arriving: at least one `<video>` whose MediaStream carries
 * a live video track that this page did not produce. `muted` is the tell the
 * app sets on its own self-view; rather than rely on that styling choice, count
 * streams whose track ids differ from every locally-captured track.
 */
async function remoteVideoTracks(page: Page): Promise<number> {
  return await page.evaluate(() => {
    const w = window as unknown as { __selfhost_local_track_ids?: string[] }
    const local = new Set(w.__selfhost_local_track_ids ?? [])
    let n = 0
    for (const v of Array.from(document.querySelectorAll('video'))) {
      const s = (v as HTMLVideoElement).srcObject as MediaStream | null
      if (!s) continue
      for (const t of s.getVideoTracks()) {
        if (t.readyState === 'live' && !local.has(t.id)) n++
      }
    }
    return n
  })
}

/** Record the ids of tracks this page captured, so remote ones are tellable. */
async function trackLocalCaptures(context: BrowserContext): Promise<void> {
  await context.addInitScript(() => {
    const w = window as unknown as { __selfhost_local_track_ids: string[] }
    w.__selfhost_local_track_ids = []
    const md = navigator.mediaDevices
    if (!md?.getUserMedia) return
    const orig = md.getUserMedia.bind(md)
    md.getUserMedia = async (c?: MediaStreamConstraints) => {
      const s = await orig(c)
      for (const t of s.getTracks()) w.__selfhost_local_track_ids.push(t.id)
      return s
    }
  })
}

/** Join the call in the UI and wait for the local tile to render. */
async function joinCallInUi(page: Page, tenantId: string, roomId: string): Promise<void> {
  await page.goto(`${BASE_URL}/tenant/${tenantId}/room/${roomId}/call`)
  const join = page.getByRole('button', { name: /join/i }).first()
  await expect(join, 'call page never offered a Join button').toBeVisible({ timeout: 30_000 })
  await join.click()
  await expect(page.getByText('You').first(), 'own tile never rendered after Join').toBeVisible({
    timeout: 30_000,
  })
}

test.describe('FR-75 collab pillar — chat and a call that carries media', () => {
  test.skip(!API_URL || !BASE_URL, 'set E2E_BASE_URL and E2E_API_URL')
  test.setTimeout(6 * 60 * 1000)

  let owner: ReturnType<typeof uniqueUser>
  let peer: ReturnType<typeof uniqueUser>
  let ownerToken = ''
  let peerToken = ''
  let tenantId = ''
  let roomId = ''

  test.beforeEach(async () => {
    const mods = await serverModules()
    test.skip(
      !mods.includes('chat') || !mods.includes('conference'),
      `server mounts [${mods.join(' ')}] — no chat/conference to exercise`,
    )

    owner = uniqueUser()
    peer = uniqueUser()
    const o = await registerUserViaApi(owner)
    ownerToken = o.access_token
    const p = await registerUserViaApi(peer)
    peerToken = p.access_token

    const tenant = await createTenantViaApi(ownerToken, 'FR75 Collab', `fr75-${Date.now()}`)
    tenantId = tenant.id
    await addTenantMemberViaApi(ownerToken, tenantId, p.user.id)

    const room = await createRoomViaApi(ownerToken, tenantId, 'FR75 Room')
    roomId = room.id
    // ⚠️ Tenant membership is NOT room membership. The `/ws` fan-out targets
    // ROOM members, so without this join the peer's page opens, subscribes to
    // nothing, and the realtime assertion fails 30 s later with "element not
    // found" — which reads as a broken socket rather than a missing join.
    await joinRoomViaApi(peerToken, tenantId, roomId)
  })

  test('two users exchange chat in realtime', async ({ browser }) => {
    const ctx = await browser.newContext()
    const page = await ctx.newPage()
    try {
      await loginViaUi(page, peer.username, peer.password)
      await page.goto(`${BASE_URL}/tenant/${tenantId}/room/${roomId}`)

      // The message is sent by the OTHER user, through the API, AFTER this
      // page is open — so seeing it proves the `/ws` fan-out, not a reload.
      const body = `fr75-realtime-${Date.now()}`
      await expect(page.locator('body')).toBeVisible()
      await page.waitForTimeout(2_000)
      await sendMessageViaApi(ownerToken, tenantId, roomId, body)

      await expect(
        page.getByText(body).first(),
        'message sent by the peer never arrived over /ws',
      ).toBeVisible({ timeout: 30_000 })
    } finally {
      await page.close()
      await ctx.close()
    }
  })

  test('a two-party call decodes advancing frames on BOTH sides', async ({ browser }) => {
    await startCallViaApi(ownerToken, tenantId, roomId)

    const ctx1 = await browser.newContext({ permissions: ['camera', 'microphone'] })
    const ctx2 = await browser.newContext({ permissions: ['camera', 'microphone'] })
    await trackLocalCaptures(ctx1)
    await trackLocalCaptures(ctx2)
    const page1 = await ctx1.newPage()
    const page2 = await ctx2.newPage()

    const trouble: string[] = []
    for (const [tag, p] of [
      ['owner', page1],
      ['peer', page2],
    ] as const) {
      p.on('console', (m) => {
        if (m.type() === 'error') trouble.push(`${tag} console.error: ${m.text()}`)
      })
    }

    try {
      await loginViaUi(page1, owner.username, owner.password)
      await loginViaUi(page2, peer.username, peer.password)

      await joinCallInUi(page1, tenantId, roomId)
      await joinCallInUi(page2, tenantId, roomId)

      // ── each side must actually RECEIVE the other's track ────────────────
      for (const [tag, p] of [
        ['owner', page1],
        ['peer', page2],
      ] as const) {
        await expect
          .poll(async () => await remoteVideoTracks(p), {
            timeout: 90_000,
            message: `${tag} never received a remote video track — signalling may be green while no media arrives (the 2026-08-26 RTC-range shape)`,
          })
          .toBeGreaterThan(0)
      }

      // ── and those frames must ADVANCE, not merely exist ──────────────────
      // One painted frame proves a keyframe arrived; a stream is a stream only
      // if the counter keeps moving.
      const before = await Promise.all([videoProgress(page1), videoProgress(page2)])
      await page1.waitForTimeout(5_000)
      const after = await Promise.all([videoProgress(page1), videoProgress(page2)])

      for (const [i, tag] of [
        [0, 'owner'],
        [1, 'peer'],
      ] as const) {
        const b = before[i]
        const a = after[i]
        expect(
          a.frames > b.frames || a.time > b.time,
          `${tag}: video did not advance over 5s (frames ${b.frames} → ${a.frames}, ` +
            `currentTime ${b.time.toFixed(2)} → ${a.time.toFixed(2)}, ${a.videos} video elements) — ` +
            `mediasoup signalling can be perfect while no RTP arrives; check ANNOUNCED_IP and the RTC port range`,
        ).toBe(true)
      }

      if (trouble.length) {
        console.warn(`[fr75-collab] ${trouble.length} console errors during the call:`)
        for (const t of trouble.slice(0, 10)) console.warn('  ', t)
      }
    } finally {
      await page1.close()
      await page2.close()
      await ctx1.close()
      await ctx2.close()
    }
  })
})
