/**
 * #1631 — the remote view must follow the device picked in the left nav.
 *
 * Field symptom: Devices → A opened `/tenant/:tid/agent/A/remote`; clicking
 * B in the nav changed the URL to `/agent/B/remote` but the view stayed on
 * A — toolbar name, status, and Connect dialling A — until an unrelated
 * route was visited. Vue Router reused the mounted view across the param
 * change (AppLayout's bare `<router-view>`), and the viewer resolved its
 * device once in `onMounted`. The fix keys the routed view by `agentId`
 * (`KeyedRouterView`) and hardens the composable against the races a
 * mid-request switch exposes.
 *
 * Runs on the k8s e2e lane against the two `agent-e2e` replicas
 * (`scripts/e2e-k8s/AGENT-E2E.md`). Same skip conditions as
 * `remote-session-smoke.spec.ts`, plus "fewer than two online agents".
 *
 * **What it validates**:
 *  1. A's remote view connects (the smoke's happy path, as the baseline).
 *  2. Clicking B in the nav: the URL AND the toolbar name are B's, and no
 *     connected state is carried over — the view is a fresh mount that
 *     offers Connect again.
 *  3. Connect on B reaches "connected": the request dials B, not A.
 *  4. Back to A via the nav, Connect reaches "connected" again. A's session
 *     was released at the switch — the e2e agents run the default
 *     single-session limit, so a leaked session would answer `agent_busy`
 *     ("concurrent session limit") instead.
 */
import { test, expect, type Page } from '@playwright/test'

const API_URL = process.env.E2E_API_URL || 'http://localhost:5001'
const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:5000'
const TENANT_ID = process.env.E2E_AGENT_E2E_TENANT_ID || ''
const ADMIN_EMAIL = process.env.E2E_AGENT_E2E_ADMIN_EMAIL || 'agent-e2e-admin@meshharbor.local'
const ADMIN_PASSWORD =
  process.env.E2E_AGENT_E2E_ADMIN_PASSWORD || 'agent-e2e-bootstrap-pw-2026'

interface AgentRow {
  id: string
  name: string
  display_name?: string
  machine_name: string
  is_online: boolean
}

/**
 * The online enrolled agents of the tenant, name-sorted so the two replicas
 * come back in a stable order (`agent-e2e-0`, `agent-e2e-1`). Polls a few
 * times so a Pod mid-`rc:agent.hello` can settle before we declare the test
 * un-runnable.
 */
async function findOnlineAgents(token: string): Promise<AgentRow[]> {
  for (let i = 0; i < 6; i++) {
    const resp = await fetch(`${API_URL}/api/tenant/${TENANT_ID}/agent`, {
      headers: { Authorization: `Bearer ${token}` },
    })
    if (!resp.ok) return []
    const body = (await resp.json()) as { items?: AgentRow[] }
    const online = (body.items ?? []).filter((a) => a.is_online)
    if (online.length >= 2) {
      return online.sort((x, y) => x.name.localeCompare(y.name))
    }
    await new Promise((r) => setTimeout(r, 500))
  }
  return []
}

/** What the nav row and the viewer toolbar both render for a device. */
function shownName(a: AgentRow): string {
  return a.display_name || a.name
}

const connectButton = (page: Page) => page.getByRole('button', { name: /^connect$/i }).first()
const connectedChip = (page: Page) => page.locator('text=/^connected$/i').first()
const toolbarTitle = (page: Page) => page.locator('.rc-toolbar-primary .v-toolbar-title').first()
const navLinkTo = (page: Page, agentId: string) =>
  page.locator(`a[href="/tenant/${TENANT_ID}/agent/${agentId}/remote"]`).first()

async function connectAndWait(page: Page) {
  await expect(connectButton(page)).toBeVisible({ timeout: 30_000 })
  await connectButton(page).click()
  await expect(connectedChip(page)).toBeVisible({ timeout: 60_000 })
}

test.describe('Switching devices in the nav while on the remote view (#1631)', () => {
  test.skip(
    !TENANT_ID,
    'E2E_AGENT_E2E_TENANT_ID must be set to the rebaked tenant_id from the seed Job.'
  )
  // Three connects, each with room for the rc:* handshake + ICE to converge.
  test.setTimeout(5 * 60 * 1000)

  test('the view follows the picked device, and the previous device can be dialled again', async ({
    page,
    context,
  }) => {
    // -------- Log in: the session is an HttpOnly cookie, so log in through
    // the context's request API (the jar is shared with the page) and set the
    // `meshharbor-signed-in` hint the SPA renders its shell on. --------
    const loginResp = await context.request.post(`${API_URL}/api/auth/login`, {
      data: { email: ADMIN_EMAIL, password: ADMIN_PASSWORD },
    })
    expect(loginResp.ok(), `admin login failed: ${loginResp.status()}`).toBeTruthy()
    const token = ((await loginResp.json()) as { access_token: string }).access_token
    await context.addInitScript(() => {
      try {
        window.localStorage.setItem('meshharbor-signed-in', '1')
      } catch {
        /* private mode / storage blocked — the cookie still authenticates */
      }
    })

    // -------- Discover TWO online agents before we open the SPA --------
    const agents = await findOnlineAgents(token)
    test.skip(
      agents.length < 2,
      'fewer than two online enrolled agents — apply the agent-e2e overlay (2 replicas) first'
    )
    const [a, b] = agents as [AgentRow, AgentRow]

    const consoleErrors: string[] = []
    page.on('console', (msg) => {
      const t = msg.type()
      if (t === 'error' || t === 'warning') consoleErrors.push(`[${t}] ${msg.text()}`)
    })

    // -------- 1. A: open and connect (the baseline) --------
    await page.goto(`${BASE_URL}/tenant/${TENANT_ID}/agent/${a.id}/remote`)
    await expect(toolbarTitle(page)).toContainText(shownName(a), { timeout: 30_000 })
    await connectAndWait(page)

    // -------- 2. Pick B in the left nav (an in-app navigation, NOT a page
    // load — the reuse bug only exists across a router param change) --------
    const linkToB = navLinkTo(page, b.id)
    await linkToB.scrollIntoViewIfNeeded()
    await expect(linkToB, 'B is not in the nav — the Devices group should be open by default').toBeVisible({
      timeout: 10_000,
    })
    await linkToB.click()

    await expect(page).toHaveURL(new RegExp(`/tenant/${TENANT_ID}/agent/${b.id}/remote`))
    // The toolbar names B, not A: the view remounted for the new param.
    await expect(toolbarTitle(page)).toContainText(shownName(b), { timeout: 30_000 })
    // No connected state carried over from A's view: the chip is gone and
    // Connect is offered again (a re-pointed view would still show
    // "connected" here, with A's stream in it).
    await expect(connectedChip(page)).not.toBeVisible({ timeout: 30_000 })
    await expect(connectButton(page)).toBeVisible({ timeout: 30_000 })

    // -------- 3. Connect dials B --------
    await connectAndWait(page)
    await expect(toolbarTitle(page)).toContainText(shownName(b))

    // -------- 4. Back to A: its session was released at the switch, so
    // Connect succeeds rather than bouncing off the agent's session limit --------
    const linkToA = navLinkTo(page, a.id)
    await linkToA.scrollIntoViewIfNeeded()
    await expect(linkToA).toBeVisible({ timeout: 10_000 })
    await linkToA.click()
    await expect(page).toHaveURL(new RegExp(`/tenant/${TENANT_ID}/agent/${a.id}/remote`))
    await expect(toolbarTitle(page)).toContainText(shownName(a), { timeout: 30_000 })
    await expect(connectedChip(page)).not.toBeVisible({ timeout: 30_000 })

    await connectAndWait(page)
    // `friendlyRcError('agent_busy')` — the exact copy a leaked session
    // would surface. Asserted after the connect so a transient busy that
    // the ladder rode through still counts as a failure of the release.
    await expect(page.getByText('concurrent session limit')).toHaveCount(0)

    if (consoleErrors.length > 0) {
      console.warn(`[remote-switch-device] ${consoleErrors.length} console errors/warnings:`)
      for (const line of consoleErrors.slice(0, 20)) console.warn('  ', line)
    }
  })
})
