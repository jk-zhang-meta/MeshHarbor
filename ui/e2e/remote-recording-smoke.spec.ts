// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-85 P3c — pressing Record on a device that serves remote recording ends in
 * a VISIBLE outcome: the REC chip, or a refusal said in words. Never silence.
 *
 * Runs only against an agent whose caps advertise `record` (an image built
 * with the `recording` feature, and its owner's `record_remote_enabled` on).
 * The harness agents run as root with nobody at a console, so a recording
 * there is UNATTENDED (FR-85 P1f): made by the daemon into its own folder,
 * with no banner because there is nobody to show one to. `Dockerfile.agent-e2e`
 * carries `recording` from P1f on; a harness image built before it
 * advertises nothing and this spec skips. A refusal said in words is accepted
 * as a correct, visible outcome — a real recording is proven on real hosts in
 * the field matrix (FR-85 P6).
 */
import { test, expect } from '@playwright/test'
import { signInContext } from './fixtures/test-helpers'

const API_URL = process.env.E2E_API_URL || 'http://localhost:5001'
const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:5000'
const TENANT_ID = process.env.E2E_AGENT_E2E_TENANT_ID || ''
const ADMIN_EMAIL = process.env.E2E_AGENT_E2E_ADMIN_EMAIL || 'agent-e2e-admin@meshharbor.local'
const ADMIN_PASSWORD =
  process.env.E2E_AGENT_E2E_ADMIN_PASSWORD || 'agent-e2e-bootstrap-pw-2026'

type AgentRow = { id: string; is_online: boolean; capabilities?: { record?: string[] } }

async function adminLogin(): Promise<string> {
  const resp = await fetch(`${API_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD }),
  })
  if (!resp.ok) throw new Error(`admin login failed: ${resp.status}`)
  return ((await resp.json()) as { access_token: string }).access_token
}

test.describe('Remote recording — Record gives a visible answer (FR-85 P3c)', () => {
  test.skip(!TENANT_ID, 'E2E_AGENT_E2E_TENANT_ID must be set to the rebaked tenant_id.')
  test.setTimeout(3 * 60 * 1000)

  test('Record on a recording-capable device shows REC or a named refusal', async ({
    page,
    context,
  }) => {
    const token = await adminLogin()
    const resp = await fetch(`${API_URL}/api/tenant/${TENANT_ID}/agent`, {
      headers: { Authorization: `Bearer ${token}` },
    })
    const rows = ((await resp.json()) as { items?: AgentRow[] }).items ?? []
    const agent = rows.find((a) => a.is_online && (a.capabilities?.record ?? []).includes('remote'))
    test.skip(!agent, 'no online agent advertises the record capability')

    // Cookie-only sessions (#691): sign in through the context's jar.
    await signInContext(context, ADMIN_EMAIL, ADMIN_PASSWORD)
    await page.goto(`${BASE_URL}/tenant/${TENANT_ID}/agent/${agent!.id}/remote`)
    await page.getByRole('button', { name: /^connect$/i }).first().click({ timeout: 30_000 })
    await expect(page.locator('text=/^connected$/i').first()).toBeVisible({ timeout: 60_000 })

    await page.getByTestId('rc-record-btn').click({ timeout: 15_000 })
    await page.getByTestId('rc-record-start').click()

    const chip = page.getByTestId('rc-rec-chip')
    const reason = page.getByTestId('rc-record-reason')
    await expect(chip.or(reason)).toBeVisible({ timeout: 30_000 })
    if (await chip.isVisible()) {
      await page.getByTestId('rc-record-stop').click()
      await expect(chip).toHaveCount(0, { timeout: 60_000 })
    } else {
      // A refusal must name its reason in words, not a bare code.
      await expect(reason).toContainText(/Not recording: \S/)
      await expect(reason).not.toContainText(/_/)
    }
  })
})
