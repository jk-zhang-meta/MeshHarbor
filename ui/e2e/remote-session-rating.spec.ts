/**
 * FR-102 P9b — AC19: the post-session rating prompt appears at most once per
 * user per day and never after a session shorter than 30 s, and dismissing
 * it changes nothing else in the viewer. Against the Phase 1 `agent-e2e`
 * harness, the way `remote-session-smoke.spec.ts` is (the same
 * skip-conditions, the same login and discovery).
 *
 * Four sessions on one synthetic-frame agent:
 *
 *  1. a short one (a few seconds) → no prompt;
 *  2. a long one (≥ 30 s from the request) → the prompt; dismissing it posts
 *     nothing and leaves the viewer as it was (same URL, Connect usable);
 *  3. another long one, same browser, same day → no prompt (once a day);
 *  4. a long one in a FRESH context (fresh storage: another person's
 *     browser, or tomorrow) → the prompt; thumbs down + a chip + Send posts
 *     exactly one `POST …/feedback` answered 201, then the thanks line.
 *
 * Every purestat request is aborted before it leaves (a test run must never
 * reach the analytics plane). The prompt is read by its `data-testid`s, never
 * by `video, canvas`.
 *
 * Two targets. The `agent-e2e` harness: its single agent is "the first
 * online one". A named device on a real server — a vmtest guest, from mars,
 * the way `vmtest-remote.spec.ts` runs: set `E2E_AGENT_NAME` and the agent is
 * chosen by EXACT name, never "the first online" (the vmtest org also holds
 * the permanent anchor and other sessions' guests).
 *
 * ⚠️ Sessions are COOKIE-ONLY since #680/#690: each context signs in through
 * its own request API, so the HttpOnly session cookie lands in that
 * context's jar. Seeding `localStorage` tokens, as this spec first did, does
 * nothing and the viewer shows the login form.
 */
import { test, expect, type Page, type BrowserContext } from '@playwright/test'

const API_URL = process.env.E2E_API_URL || 'http://localhost:5001'
const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:5000'
const TENANT_ID = process.env.E2E_AGENT_E2E_TENANT_ID || ''
const ADMIN_EMAIL = process.env.E2E_AGENT_E2E_ADMIN_EMAIL || 'agent-e2e-admin@meshharbor.local'
const ADMIN_PASSWORD =
  process.env.E2E_AGENT_E2E_ADMIN_PASSWORD || 'agent-e2e-bootstrap-pw-2026'
/** When set, the agent is this device, matched exactly; empty = the first online. */
const AGENT_NAME = process.env.E2E_AGENT_NAME || ''

/** The viewer's threshold (`RATING_MIN_SESSION_MS`), measured from the request. */
const MIN_SESSION_MS = 30_000
/** Held past the threshold so the clock on either side cannot argue. */
const LONG_SESSION_HOLD_MS = MIN_SESSION_MS + 3_000
const SHORT_SESSION_HOLD_MS = 3_000

async function adminLogin(): Promise<string> {
  const resp = await fetch(`${API_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD }),
  })
  if (!resp.ok) {
    throw new Error(`admin login failed: ${resp.status} ${await resp.text().catch(() => '')}`)
  }
  const body = (await resp.json()) as { access_token: string }
  return body.access_token
}

/** The online agent to drive: the named one when `E2E_AGENT_NAME` is set
 *  (exact match on any of its names, never a fallback), else the first. */
async function findOnlineAgent(token: string): Promise<{ id: string } | null> {
  for (let i = 0; i < 24; i++) {
    const resp = await fetch(`${API_URL}/api/tenant/${TENANT_ID}/agent`, {
      headers: { Authorization: `Bearer ${token}` },
    })
    if (!resp.ok) return null
    const body = (await resp.json()) as {
      items?: Array<{
        id: string
        is_online: boolean
        machine_name?: string
        name?: string
        display_name?: string
      }>
    }
    const online = body.items?.find(
      (a) =>
        a.is_online &&
        (!AGENT_NAME ||
          a.machine_name === AGENT_NAME ||
          a.name === AGENT_NAME ||
          a.display_name === AGENT_NAME),
    )
    if (online) return online
    await new Promise((r) => setTimeout(r, AGENT_NAME ? 5_000 : 500))
  }
  return null
}

/** A context whose analytics requests never leave, signed in as the admin
 *  through its own cookie jar. */
async function signedInContext(context: BrowserContext): Promise<void> {
  await context.route('https://purestat.ai/**', (r) => r.abort())
  const login = await context.request.post(`${API_URL}/api/auth/login`, {
    data: { email: ADMIN_EMAIL, password: ADMIN_PASSWORD },
  })
  expect(login.ok(), `browser login failed: ${login.status()}`).toBeTruthy()
  // The hint that makes the SPA render its shell and refresh through the
  // cookie instead of bouncing to /login.
  await context.addInitScript(() => {
    try {
      window.localStorage.setItem('meshharbor-signed-in', '1')
    } catch {
      /* storage blocked — the cookie still authenticates */
    }
  })
}

/** Count every rating POST the page makes. */
function countFeedbackPosts(page: Page): { posts: number[] } {
  const seen = { posts: [] as number[] }
  page.on('response', (r) => {
    if (r.request().method() === 'POST' && /\/session\/[0-9a-f]{24}\/feedback$/.test(r.url())) {
      seen.posts.push(r.status())
    }
  })
  return seen
}

const connectButton = (page: Page) => page.getByRole('button', { name: /^connect$/i }).first()
const disconnectButton = (page: Page) => page.getByRole('button', { name: /^disconnect$/i }).first()
const prompt = (page: Page) => page.getByTestId('rc-rating')

/** Connect, wait for the session to be live, hold it, then Disconnect. */
async function runSession(page: Page, holdMs: number): Promise<void> {
  await expect(connectButton(page)).toBeVisible({ timeout: 30_000 })
  await expect(connectButton(page)).toBeEnabled({ timeout: 30_000 })
  await connectButton(page).click()
  await expect(page.locator('text=/^connected$/i').first()).toBeVisible({ timeout: 60_000 })
  await page.waitForTimeout(holdMs)
  await disconnectButton(page).click()
  // Back at rest: the Connect hint is the ended state's own text.
  await expect(connectButton(page)).toBeVisible({ timeout: 15_000 })
}

test.describe('AC19 — the post-session rating prompt', () => {
  test.skip(
    !TENANT_ID,
    'E2E_AGENT_E2E_TENANT_ID must be set to the rebaked tenant_id from the seed Job.'
  )
  // Four sessions, two of them held past 30 s, plus four handshakes.
  test.setTimeout(8 * 60 * 1000)

  test('never under 30 s, once a day, dismiss changes nothing, a rating posts once', async ({
    page,
    context,
    browser,
  }) => {
    const token = await adminLogin()
    const agent = await findOnlineAgent(token)
    // A named device that never came online is a failure, not a skip.
    if (AGENT_NAME) expect(agent, `agent "${AGENT_NAME}" never reported online`).toBeTruthy()
    test.skip(!agent, 'no online enrolled agent found — apply the agent-e2e overlay first')
    const remoteUrl = `${BASE_URL}/tenant/${TENANT_ID}/agent/${agent!.id}/remote`

    await signedInContext(context)
    const seen = countFeedbackPosts(page)
    await page.goto(remoteUrl)

    // 1. A short session: no prompt — the viewer measures from the request,
    //    and a few seconds of session is under the 30 s floor.
    await runSession(page, SHORT_SESSION_HOLD_MS)
    await expect(prompt(page)).toHaveCount(0)
    await page.waitForTimeout(2_000)
    await expect(prompt(page)).toHaveCount(0)

    // 2. A long session: the prompt, inline in the ended state. Dismissing
    //    it posts nothing and leaves the viewer exactly where it was.
    await runSession(page, LONG_SESSION_HOLD_MS)
    await expect(prompt(page)).toBeVisible({ timeout: 10_000 })
    // Exactly one prompt: the viewer mounts it in the closed ending and in
    // the error ending, two branches of one v-if chain (locked structurally
    // by `rcRatingMount.spec.ts`; live here for the closed ending).
    await expect(prompt(page)).toHaveCount(1)
    await expect(page.getByTestId('rc-rating-up')).toBeVisible()
    await expect(page.getByTestId('rc-rating-down')).toBeVisible()
    // Nothing in the prompt took the focus: the active element is the body
    // (or whatever the viewer left focused), never one of the prompt's buttons.
    const focusedInPrompt = await page.evaluate(
      () => !!document.activeElement?.closest('[data-testid="rc-rating"]'),
    )
    expect(focusedInPrompt, 'the prompt must not steal focus').toBe(false)
    const urlBefore = page.url()
    await page.getByTestId('rc-rating-dismiss').click()
    await expect(prompt(page)).toHaveCount(0)
    expect(page.url()).toBe(urlBefore)
    await expect(connectButton(page)).toBeEnabled()
    expect(seen.posts, 'a dismissal posts nothing').toEqual([])

    // 3. Another long session the same day, same browser: no prompt. The day
    //    was recorded when the prompt was SHOWN, so the dismissal counted.
    await runSession(page, LONG_SESSION_HOLD_MS)
    await expect(prompt(page)).toHaveCount(0)
    await page.waitForTimeout(3_000)
    await expect(prompt(page)).toHaveCount(0)
    expect(seen.posts).toEqual([])

    // 4. A fresh context — fresh storage, as another person's browser or the
    //    next day would be: the prompt again; a rating posts exactly once.
    const fresh = await browser.newContext()
    try {
      await signedInContext(fresh)
      const page2 = await fresh.newPage()
      const seen2 = countFeedbackPosts(page2)
      await page2.goto(remoteUrl)
      await runSession(page2, LONG_SESSION_HOLD_MS)
      await expect(prompt(page2)).toBeVisible({ timeout: 10_000 })
      await expect(prompt(page2)).toHaveCount(1)
      await page2.getByTestId('rc-rating-down').click()
      await expect(page2.getByTestId('rc-rating-reason-lag')).toBeVisible()
      await page2.getByTestId('rc-rating-reason-lag').click()
      const posted = page2.waitForResponse(
        (r) => r.request().method() === 'POST' && /\/feedback$/.test(r.url()),
        { timeout: 15_000 },
      )
      await page2.getByTestId('rc-rating-send').click()
      const resp = await posted
      expect(resp.status(), await resp.text().catch(() => '')).toBe(201)
      const body = (await resp.json()) as { rating: string; reasons: string[] }
      expect(body.rating).toBe('down')
      expect(body.reasons).toEqual(['lag'])
      await expect(page2.getByTestId('rc-rating-thanks')).toBeVisible()
      await page2.waitForTimeout(1_500)
      expect(seen2.posts, 'exactly one rating for the session').toEqual([201])
      // The viewer is still itself: Connect is there, nothing navigated.
      expect(page2.url()).toBe(remoteUrl)
      await expect(connectButton(page2)).toBeEnabled()
    } finally {
      await fresh.close()
    }
  })
})
