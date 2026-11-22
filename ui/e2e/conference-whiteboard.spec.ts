// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-126 P2 — the meeting whiteboard, through real browsers and the real server: a rectangle one
// participant draws appears on the other's board within a second, and someone who joins the
// meeting later opens the board as it is.
//
// Point it at a server with open registration (auto-verify, no owner approval), like
// `conference-media.spec.ts`:
//   E2E_BASE_URL=http://localhost:18082/meshharbor/ E2E_API_URL=http://localhost:18082/meshharbor \
//   bunx playwright test e2e/conference-whiteboard.spec.ts
import { test, expect, type Browser, type Page } from '@playwright/test'
import {
  uniqueUser,
  registerUserViaApi,
  createTenantViaApi,
  createRoomViaApi,
  startCallViaApi,
  addTenantMemberViaApi,
} from './fixtures/test-helpers'

async function inMeeting(
  browser: Browser,
  user: ReturnType<typeof uniqueUser>,
  tenantId: string,
  roomId: string,
): Promise<Page> {
  const ctx = await browser.newContext({ permissions: ['camera', 'microphone'] })
  const page = await ctx.newPage()
  await page.goto('login')
  await page.locator('input').first().fill(user.email)
  await page.locator('input[type="password"]').fill(user.password)
  await page.getByRole('button', { name: /login/i }).click()
  await page.waitForURL((u) => !u.pathname.endsWith('/login'), { timeout: 15000 })
  await page.goto(`tenant/${tenantId}/room/${roomId}/call`)
  const join = page.getByRole('button', { name: /join/i })
  await expect(join).toBeVisible({ timeout: 15000 })
  await join.click()
  await expect(page.getByText('You')).toBeVisible({ timeout: 15000 })
  return page
}

async function openBoard(page: Page) {
  await page.getByTestId('call-whiteboard-toggle').click()
  await expect(page.getByTestId('whiteboard')).toHaveAttribute('data-state', 'ready', { timeout: 30000 })
  // Excalidraw is up when its toolbar is.
  await expect(page.getByTestId('toolbar-rectangle')).toBeAttached({ timeout: 30000 })
}

const count = (page: Page) => page.getByTestId('whiteboard').getAttribute('data-element-count')

test.describe('FR-126 meeting whiteboard', () => {
  test('a stroke reaches the other participant, and a late joiner sees the board', async ({ browser }) => {
    test.setTimeout(180_000)
    const [owner, peer, late] = [uniqueUser(), uniqueUser(), uniqueUser()]
    const ownerReg = await registerUserViaApi(owner)
    const peerReg = await registerUserViaApi(peer)
    const lateReg = await registerUserViaApi(late)
    const tenant = await createTenantViaApi(ownerReg.access_token, 'FR-126 board', `fr126wb-${Date.now()}`)
    await addTenantMemberViaApi(ownerReg.access_token, tenant.id, peerReg.user.id)
    await addTenantMemberViaApi(ownerReg.access_token, tenant.id, lateReg.user.id)
    const room = await createRoomViaApi(ownerReg.access_token, tenant.id, 'FR-126 board')
    await startCallViaApi(ownerReg.access_token, tenant.id, room.id)

    const a = await inMeeting(browser, owner, tenant.id, room.id)
    const b = await inMeeting(browser, peer, tenant.id, room.id)
    await openBoard(a)
    await openBoard(b)
    expect(await count(a)).toBe('0')
    expect(await count(b)).toBe('0')

    // Draw a rectangle on A's board: pick the tool, drag inside the canvas.
    // The test id sits on the tool's radio input, which Excalidraw keeps visually hidden.
    await a.getByTestId('toolbar-rectangle').click({ force: true })
    const box = await a.getByTestId('whiteboard').boundingBox()
    if (!box) throw new Error('no whiteboard box')
    const x = box.x + box.width * 0.35
    const y = box.y + box.height * 0.4
    // The shape reaches B while A is still dragging, so the clock starts at the pointer-down
    // and B is watched during the stroke, every 25 ms.
    await a.mouse.move(x, y)
    const strokeAt = Date.now()
    const seenOnB = (async () => {
      while (Date.now() - strokeAt < 5000) {
        if ((await count(b)) === '1') return Date.now() - strokeAt
        await b.waitForTimeout(25)
      }
      return Number.POSITIVE_INFINITY
    })()
    await a.mouse.down()
    await a.mouse.move(x + 160, y + 100, { steps: 8 })
    await a.mouse.up()
    const latencyMs = await seenOnB
    expect(await count(a)).toBe('1')
    await expect.poll(() => count(b), { timeout: 5000 }).toBe('1')
    console.log(`FR-126 whiteboard: the stroke appeared on the other board ${latencyMs} ms after it began`)
    expect(latencyMs, 'stroke latency').toBeLessThan(1000)

    // A late joiner opens the board as it is.
    const c = await inMeeting(browser, late, tenant.id, room.id)
    await openBoard(c)
    await expect.poll(() => count(c), { timeout: 10000 }).toBe('1')
  })
})
