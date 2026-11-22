// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-126 P3 — meeting recording through real browsers and the real server: one participant
// records, the other sees the indicator while it runs and not after; the recording lands in the
// room's files as WebM. With `E2E_RECORDING_OUT=<dir>` the file is also saved there, for
// `ffprobe` to show its streams.
//
//   E2E_BASE_URL=http://localhost:18082/meshharbor/ E2E_API_URL=http://localhost:18082/meshharbor \
//   bunx playwright test e2e/conference-recording.spec.ts
import { writeFileSync } from 'fs'
import { join } from 'path'
import { test, expect, type Browser, type Page } from '@playwright/test'
import {
  uniqueUser,
  registerUserViaApi,
  createTenantViaApi,
  createRoomViaApi,
  startCallViaApi,
  addTenantMemberViaApi,
} from './fixtures/test-helpers'

const API_URL = process.env.E2E_API_URL || 'http://localhost:5001'

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

test.describe('FR-126 meeting recording', () => {
  test('a recording shows to everyone while it runs and lands in the room files', async ({ browser }) => {
    test.setTimeout(180_000)
    const [owner, peer] = [uniqueUser(), uniqueUser()]
    const ownerReg = await registerUserViaApi(owner)
    const peerReg = await registerUserViaApi(peer)
    const tenant = await createTenantViaApi(ownerReg.access_token, 'FR-126 rec', `fr126rec-${Date.now()}`)
    await addTenantMemberViaApi(ownerReg.access_token, tenant.id, peerReg.user.id)
    const room = await createRoomViaApi(ownerReg.access_token, tenant.id, 'FR-126 rec')
    await startCallViaApi(ownerReg.access_token, tenant.id, room.id)

    const a = await inMeeting(browser, owner, tenant.id, room.id)
    const b = await inMeeting(browser, peer, tenant.id, room.id)
    // Both sides have each other's video before the recording starts.
    await expect(a.locator('video')).toHaveCount(2, { timeout: 30000 })

    await a.getByTestId('call-record-toggle').click()
    await expect(a.getByTestId('call-recording-indicator')).toBeVisible({ timeout: 10000 })
    await expect(b.getByTestId('call-recording-indicator')).toBeVisible({ timeout: 15000 })
    await a.waitForTimeout(8000)
    await a.getByTestId('call-record-toggle').click()
    await expect(b.getByTestId('call-recording-indicator')).toBeHidden({ timeout: 15000 })

    // The part lands in the room's files.
    const files = async () => {
      const r = await fetch(`${API_URL}/api/tenant/${tenant.id}/room/${room.id}/file`, {
        headers: { Authorization: `Bearer ${ownerReg.access_token}` },
      })
      const body = (await r.json()) as { items?: { id: string; filename: string; size: number; content_type: string }[] }
      return (body.items ?? []).filter((f) => f.filename.endsWith('.webm'))
    }
    await expect.poll(async () => (await files()).length, { timeout: 30000 }).toBe(1)
    const [file] = await files()
    console.log(`FR-126 recording: ${file.filename} ${file.size} bytes ${file.content_type}`)
    expect(file.size).toBeGreaterThan(50_000)
    expect(file.content_type).toBe('video/webm')

    const dl = await fetch(`${API_URL}/api/tenant/${tenant.id}/file/${file.id}/download`, {
      headers: { Authorization: `Bearer ${ownerReg.access_token}` },
    })
    expect(dl.ok).toBe(true)
    const bytes = Buffer.from(await dl.arrayBuffer())
    // EBML magic: a WebM/Matroska file.
    expect(bytes.subarray(0, 4).toString('hex')).toBe('1a45dfa3')
    if (process.env.E2E_RECORDING_OUT) writeFileSync(join(process.env.E2E_RECORDING_OUT, 'fr126-recording.webm'), bytes)
  })
})
