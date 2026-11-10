// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-85 P3c — the viewer tells a controller WHY it cannot record, against the
 * `agent-e2e` harness.
 *
 * The viewer always asks for RECORD. The server strips it unless the
 * controller may record AND the device advertises `remote`, which a device
 * does only while its owner has switched remote recording on. On a device
 * with a recorder whose owner has not (it advertises `available` alone), the
 * answer must be a disabled Record control whose title names the reason, and
 * never a Record button that can only fail. P3c-2: on a device with NO
 * recorder (it advertises nothing), there is nothing to allow or refuse, and
 * the toolbar shows no Record control at all.
 *
 * Skip-conditions mirror `remote-file-upload-smoke.spec.ts`: no seeded tenant,
 * or no online agent of the kind a test needs. An agent that DOES advertise
 * `remote` is `remote-recording-smoke.spec.ts`'s case.
 */
import { test, expect } from '@playwright/test'
import { signInContext } from './fixtures/test-helpers'

const API_URL = process.env.E2E_API_URL || 'http://localhost:5001'
const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:5000'
const TENANT_ID = process.env.E2E_AGENT_E2E_TENANT_ID || ''
const ADMIN_EMAIL = process.env.E2E_AGENT_E2E_ADMIN_EMAIL || 'agent-e2e-admin@meshharbor.local'
const ADMIN_PASSWORD =
  process.env.E2E_AGENT_E2E_ADMIN_PASSWORD || 'agent-e2e-bootstrap-pw-2026'

type AgentRow = { id: string; machine_name: string; is_online: boolean; capabilities?: { record?: string[] } }

async function adminLogin(): Promise<string> {
  const resp = await fetch(`${API_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD }),
  })
  if (!resp.ok) throw new Error(`admin login failed: ${resp.status}`)
  return ((await resp.json()) as { access_token: string }).access_token
}

async function onlineAgents(token: string): Promise<AgentRow[]> {
  for (let i = 0; i < 6; i++) {
    const resp = await fetch(`${API_URL}/api/tenant/${TENANT_ID}/agent`, {
      headers: { Authorization: `Bearer ${token}` },
    })
    if (!resp.ok) return []
    const body = (await resp.json()) as { items?: AgentRow[] }
    const online = (body.items ?? []).filter((a) => a.is_online)
    if (online.length) return online
    await new Promise((r) => setTimeout(r, 500))
  }
  return []
}

test.describe('Remote recording — a refusal is explained (FR-85 P3c)', () => {
  test.skip(!TENANT_ID, 'E2E_AGENT_E2E_TENANT_ID must be set to the rebaked tenant_id.')
  test.setTimeout(3 * 60 * 1000)

  test('a device that has not opted in shows a disabled Record control that says why', async ({
    page,
    context,
  }) => {
    const token = await adminLogin()
    const agent = (await onlineAgents(token)).find((a) => {
      const record = a.capabilities?.record ?? []
      return record.includes('available') && !record.includes('remote')
    })
    test.skip(!agent, 'no online agent with a recorder its owner has not opted in')

    await connectTo(page, context, agent!.id)
    const refused = page.getByTestId('rc-record-refused')
    await expect(refused).toBeVisible({ timeout: 15_000 })
    await expect(refused).toHaveAttribute('title', /owner hasn't allowed remote recording/)
    // No working Record button: nothing to press that could only fail.
    await expect(page.getByTestId('rc-record-btn')).toHaveCount(0)
  })

  test('a device with no recorder shows no Record control at all (P3c-2)', async ({
    page,
    context,
  }) => {
    const token = await adminLogin()
    const agent = (await onlineAgents(token)).find(
      (a) => (a.capabilities?.record ?? []).length === 0,
    )
    test.skip(!agent, 'no online agent without a recorder')

    await connectTo(page, context, agent!.id)
    // Give the toolbar the same 15 s the refusal gets to appear, then
    // require that it never did: no disabled control, no button.
    await page.waitForTimeout(15_000)
    await expect(page.getByTestId('rc-record-refused')).toHaveCount(0)
    await expect(page.getByTestId('rc-record-btn')).toHaveCount(0)
  })
})

async function connectTo(
  page: import('@playwright/test').Page,
  context: import('@playwright/test').BrowserContext,
  agentId: string,
) {
  // Cookie-only sessions (#691): sign in through the context's jar.
  await signInContext(context, ADMIN_EMAIL, ADMIN_PASSWORD)
  await page.goto(`${BASE_URL}/tenant/${TENANT_ID}/agent/${agentId}/remote`)
  await page.getByRole('button', { name: /^connect$/i }).first().click({ timeout: 30_000 })
  await expect(page.locator('text=/^connected$/i').first()).toBeVisible({ timeout: 60_000 })
}
