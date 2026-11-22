// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-126 — two people in a meeting see and hear each other: FRAMES, not tiles.
//
// `conference-multi.spec.ts` counts tiles and passes on a server whose SFU announces an address
// nobody can reach (FR-126 E11). This test reads the WebRTC stats of every peer connection a page
// opens and requires decoded video frames and received audio bytes on BOTH sides, within the
// deadline. `E2E_FORCE_RELAY=1` makes every connection relay-only (TURN), the path a browser
// behind a symmetric NAT or a UDP-blocking firewall takes.
//
// Point it at a server with open registration (auto-verify, no owner approval):
//   E2E_BASE_URL=http://localhost:18082/meshharbor/ E2E_API_URL=http://localhost:18082/meshharbor \
//   bunx playwright test e2e/conference-media.spec.ts
// A base URL with a path needs the trailing slash; navigation below is relative to it.
import { test, expect, type Browser, type Page } from '@playwright/test'
import {
  uniqueUser,
  registerUserViaApi,
  createTenantViaApi,
  createRoomViaApi,
  startCallViaApi,
  addTenantMemberViaApi,
} from './fixtures/test-helpers'

const FORCE_RELAY = process.env.E2E_FORCE_RELAY === '1'
// `E2E_TCP_ONLY=1` drops the server's UDP candidates, the path a browser on a UDP-blocking
// network takes straight to the SFU's TCP listener.
const TCP_ONLY = process.env.E2E_TCP_ONLY === '1'
// `E2E_EXTRA_CHROME_ARGS` (a JSON array) adds browser flags, e.g.
// `["--host-resolver-rules=MAP turn.example 127.0.0.1"]` to reach a TURN port the test machine's
// own network blocks, through a forward.
const EXTRA_ARGS: string[] = JSON.parse(process.env.E2E_EXTRA_CHROME_ARGS || '[]')
if (EXTRA_ARGS.length) {
  test.use({
    launchOptions: {
      args: ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream', ...EXTRA_ARGS],
    },
  })
}
const MODE = FORCE_RELAY ? ' (relay only)' : TCP_ONLY ? ' (TCP only)' : ''

/** Collect every RTCPeerConnection the page creates; force relay or TCP when asked. */
function instrument({ forceRelay, tcpOnly }: { forceRelay: boolean; tcpOnly: boolean }) {
  const Native = window.RTCPeerConnection
  const pcs: RTCPeerConnection[] = []
  const iceErrors: string[] = []
  const iceUrls: string[] = []
  const w = window as unknown as { __pcs: RTCPeerConnection[]; __iceErrors: string[]; __iceUrls: string[] }
  w.__iceUrls = iceUrls
  w.__pcs = pcs
  w.__iceErrors = iceErrors
  class Recorded extends Native {
    constructor(config?: RTCConfiguration) {
      super(forceRelay ? { ...config, iceTransportPolicy: 'relay' } : config)
      pcs.push(this)
      iceUrls.push((config?.iceServers ?? []).flatMap((x) => (Array.isArray(x.urls) ? x.urls : [x.urls])).join(' ') || '(none)')
      if (tcpOnly) {
        const set = this.setRemoteDescription.bind(this)
        this.setRemoteDescription = (d: RTCSessionDescriptionInit) =>
          set({ ...d, sdp: d.sdp?.split('\r\n').filter((l) => !/^a=candidate:\S+ \d+ udp /i.test(l)).join('\r\n') })
      }
      this.addEventListener('icecandidateerror', (e) => {
        const err = e as RTCPeerConnectionIceErrorEvent
        if (iceErrors.length < 12) iceErrors.push(`${err.url} ${err.errorCode} ${err.errorText}`)
      })
    }
  }
  window.RTCPeerConnection = Recorded as typeof RTCPeerConnection
}

interface MediaStats {
  framesDecoded: number
  audioBytes: number
  candidates: string[]
  ice: string[]
  iceErrors: string[]
  iceUrls: string[]
}

async function mediaStats(page: Page): Promise<MediaStats> {
  return page.evaluate(async () => {
    const w = window as unknown as { __pcs?: RTCPeerConnection[]; __iceErrors?: string[]; __iceUrls?: string[] }
    const pcs = w.__pcs ?? []
    let framesDecoded = 0
    let audioBytes = 0
    const candidates: string[] = []
    const ice = pcs.map((pc) => pc.iceConnectionState)
    for (const pc of pcs) {
      if (pc.connectionState === 'closed') continue
      const stats = await pc.getStats()
      const byId = new Map<string, Record<string, unknown>>()
      stats.forEach((s) => byId.set(s.id, s as unknown as Record<string, unknown>))
      stats.forEach((s) => {
        const r = s as unknown as Record<string, unknown>
        if (r.type === 'inbound-rtp' && r.kind === 'video') framesDecoded += Number(r.framesDecoded ?? 0)
        if (r.type === 'inbound-rtp' && r.kind === 'audio') audioBytes += Number(r.bytesReceived ?? 0)
        if (r.type === 'candidate-pair' && r.state === 'succeeded' && r.nominated) {
          const local = byId.get(String(r.localCandidateId))
          const remote = byId.get(String(r.remoteCandidateId))
          candidates.push(`${local?.candidateType}/${local?.protocol} -> ${remote?.candidateType}/${remote?.protocol}`)
        }
      })
    }
    return { framesDecoded, audioBytes, candidates, ice, iceErrors: w.__iceErrors ?? [], iceUrls: w.__iceUrls ?? [] }
  })
}

async function signIn(browser: Browser, user: ReturnType<typeof uniqueUser>): Promise<Page> {
  const ctx = await browser.newContext({ permissions: ['camera', 'microphone'] })
  await ctx.addInitScript(instrument, { forceRelay: FORCE_RELAY, tcpOnly: TCP_ONLY })
  const page = await ctx.newPage()
  await page.goto('login')
  await page.locator('input').first().fill(user.email)
  await page.locator('input[type="password"]').fill(user.password)
  await page.getByRole('button', { name: /login/i }).click()
  await page.waitForURL((u) => !u.pathname.endsWith('/login'), { timeout: 15000 })
  return page
}

test.describe('FR-126 meeting media', () => {
  test(`two participants exchange video frames and audio${MODE}`, async ({ browser }) => {
    test.setTimeout(120_000)
    const owner = uniqueUser()
    const peer = uniqueUser()
    const ownerReg = await registerUserViaApi(owner)
    const peerReg = await registerUserViaApi(peer)
    const tenant = await createTenantViaApi(ownerReg.access_token, 'FR-126 media', `fr126-${Date.now()}`)
    await addTenantMemberViaApi(ownerReg.access_token, tenant.id, peerReg.user.id)
    const room = await createRoomViaApi(ownerReg.access_token, tenant.id, 'FR-126 media')
    await startCallViaApi(ownerReg.access_token, tenant.id, room.id)

    const pages = [await signIn(browser, owner), await signIn(browser, peer)]
    for (const page of pages) {
      await page.goto(`tenant/${tenant.id}/room/${room.id}/call`)
      const join = page.getByRole('button', { name: /join/i })
      await expect(join).toBeVisible({ timeout: 15000 })
      await join.click()
      await expect(page.getByText('You')).toBeVisible({ timeout: 15000 })
    }

    // Both sides must DECODE the other's video and RECEIVE its audio, not just render a tile.
    const deadline = Date.now() + 45_000
    let last: MediaStats[] = []
    while (Date.now() < deadline) {
      last = await Promise.all(pages.map(mediaStats))
      if (last.every((s) => s.framesDecoded >= 30 && s.audioBytes > 2000)) break
      await pages[0].waitForTimeout(1000)
    }
    console.log(`FR-126 media: ${JSON.stringify(last)}`)
    for (const [i, s] of last.entries()) {
      expect(s.framesDecoded, `participant ${i} decoded video frames`).toBeGreaterThanOrEqual(30)
      expect(s.audioBytes, `participant ${i} received audio bytes`).toBeGreaterThan(2000)
      if (FORCE_RELAY) {
        for (const c of s.candidates) expect(c, `participant ${i} rides the relay`).toMatch(/^relay\//)
      }
      if (TCP_ONLY) {
        for (const c of s.candidates) expect(c, `participant ${i} rides TCP`).toMatch(/-> host\/tcp$/)
      }
    }
  })
})
