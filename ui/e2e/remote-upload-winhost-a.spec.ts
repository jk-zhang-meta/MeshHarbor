/**
 * E2E: upload a >1 MB file to a remote agent via the live
 * meshharbor.itachi.fans production deployment. Validates the rc.23 reconnect +
 * rc.22 staging fixes against a real ESET-protected corporate host
 * that was failing 14 MB uploads pre-rc.22.
 *
 * **Preconditions**:
 *  - `.cred` exists in the repo root, format: `username/password`
 *  - The target agent is online and registered. Tenant + agent IDs
 *    are taken from env vars (`E2E_TENANT_ID`, `E2E_AGENT_ID`) — no
 *    real identifiers are baked into this file.
 *  - The upload payload path is `E2E_UPLOAD_FILE` (>1 MB).
 *
 * **Run**:
 * ```bash
 * cd ui && \
 *   E2E_BASE_URL=https://meshharbor.itachi.fans \
 *   E2E_TENANT_ID=<hex24> E2E_AGENT_ID=<hex24> \
 *   E2E_UPLOAD_FILE=/path/to/payload.pdf \
 *   bunx playwright test remote-upload-winhost-a --headed --reporter=list
 * ```
 *
 * **Why headed**: WebRTC peer connections need a real Chrome
 * window; headless mode works but `--headed` lets us SEE the
 * Transfers panel update + Reconnecting badge so we can diagnose
 * failures interactively if the test stalls.
 */
import { test, expect, type Page } from '@playwright/test'
import * as fs from 'node:fs'
import * as path from 'node:path'

const REPO_ROOT = path.resolve(__dirname, '..', '..')
const CRED_PATH = path.join(REPO_ROOT, '.cred')
const UPLOAD_FILE = process.env.E2E_UPLOAD_FILE ?? ''
const TENANT_ID = process.env.E2E_TENANT_ID ?? ''
const AGENT_ID = process.env.E2E_AGENT_ID ?? ''
const REMOTE_URL = `/tenant/${TENANT_ID}/agent/${AGENT_ID}/remote`

/**
 * Read the `username/password` pair from `.cred`. Throws a clear
 * error if the file is missing — the test isn't runnable without
 * it.
 */
function readCred(): { username: string; password: string } {
  if (!fs.existsSync(CRED_PATH)) {
    throw new Error(
      `.cred missing at ${CRED_PATH}. ` +
        'Create it with format: username/password (one line).'
    )
  }
  const raw = fs.readFileSync(CRED_PATH, 'utf-8').trim()
  const slash = raw.indexOf('/')
  if (slash <= 0 || slash === raw.length - 1) {
    throw new Error(`.cred malformed; expected username/password, got: ${raw.length} chars`)
  }
  return {
    username: raw.slice(0, slash),
    password: raw.slice(slash + 1),
  }
}

/**
 * Login to meshharbor.itachi.fans via the UI. Returns when the URL is the
 * dashboard `/` — pre-condition for navigating to the agent's
 * remote view (which requires auth).
 */
async function login(page: Page, username: string, password: string) {
  await page.goto('/login')
  await page.locator('input').first().fill(username)
  await page.locator('input[type="password"]').fill(password)
  await page.getByRole('button', { name: /login/i }).click()
  // Allow up to 15 s for the production API; lands on dashboard.
  await expect(page).toHaveURL(/\/$/, { timeout: 15_000 })
}

test.describe('Remote upload to a field-test host', () => {
  test.skip(
    !process.env.E2E_BASE_URL || !process.env.E2E_BASE_URL.includes('meshharbor.itachi.fans'),
    'This spec targets PROD only. Set E2E_BASE_URL=https://meshharbor.itachi.fans to run.'
  )
  test.skip(
    !TENANT_ID || !AGENT_ID,
    'E2E_TENANT_ID and E2E_AGENT_ID must be set to the target agent.'
  )
  test.skip(
    !UPLOAD_FILE || !fs.existsSync(UPLOAD_FILE),
    `Upload file missing. Set E2E_UPLOAD_FILE to a >1 MB local path.`
  )

  // The whole test can take many minutes when the file is large
  // and the network is slow / ESET-protected. Generous timeout so
  // an infinite-reconnect loop on the browser side has room to
  // converge.
  test.setTimeout(15 * 60 * 1000)

  test('upload payload to the remote agent and wait for completion', async ({ page }) => {
    const { username, password } = readCred()

    // -------- Login --------
    await login(page, username, password)

    // -------- Navigate to the agent's remote view --------
    await page.goto(REMOTE_URL)
    // Wait for the agent header to render — title + Connect button.
    await expect(page.getByRole('button', { name: /^connect$/i })).toBeVisible({
      timeout: 30_000,
    })

    // Capture console logs from the browser context so a failure
    // surfaces what happened on the JS side (resume errors, DC
    // closures, etc.).
    const consoleLines: string[] = []
    page.on('console', (msg) => {
      if (msg.type() === 'error' || msg.type() === 'warning') {
        consoleLines.push(`[${msg.type()}] ${msg.text()}`)
      }
    })

    // -------- Click Connect --------
    await page.getByRole('button', { name: /^connect$/i }).click()

    // Phase chip transitions: idle → connecting → connected.
    // The chip text is rendered in lower-case ("connecting…",
    // "connected") inside a v-chip. Wait for "connected".
    await expect(
      page.locator('text=/^connected$/i').first()
    ).toBeVisible({ timeout: 60_000 })

    // -------- Upload via file input (browse path) --------
    // The file-DC v2 toolbar exposes a hidden <input type="file">
    // that the "Upload file" button proxies onto. Playwright's
    // setInputFiles works against it directly.
    const fileInput = page.locator('input[type="file"]').first()
    await fileInput.setInputFiles(UPLOAD_FILE)

    // -------- Wait for the Transfers panel to show our file --------
    // The Transfers panel renders one row per in-flight transfer,
    // with status pill: 'running' | 'reconnecting' | 'complete' |
    // 'error'. We expect a row labelled with the uploaded filename.
    const uploadName = path.basename(UPLOAD_FILE)
    const escapedName = uploadName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    const transferRow = page.locator(`text=/${escapedName}/i`).first()
    await expect(transferRow).toBeVisible({ timeout: 30_000 })

    // -------- Poll until complete (or test timeout) --------
    // rc.23 — there's no terminal "exhausted" state any more, so
    // the polling loop only exits on 'complete' or 'error'. With
    // infinite reconnect, an ESET interruption surfaces as
    // 'reconnecting (attempt N)' but the test keeps waiting.
    const completionDeadline = Date.now() + 12 * 60 * 1000 // 12 min
    let lastStatus = ''
    while (Date.now() < completionDeadline) {
      const completePill = page.locator('text=/complete/i').first()
      const errorPill = page.locator('text=/^error$/i').first()
      if (await completePill.isVisible().catch(() => false)) {
        lastStatus = 'complete'
        break
      }
      if (await errorPill.isVisible().catch(() => false)) {
        lastStatus = 'error'
        break
      }
      // Sample a status hint for the failure message.
      const statusEl = page.locator(
        ':is(text=/running/i, text=/reconnecting/i, text=/pending/i)'
      ).first()
      if (await statusEl.isVisible().catch(() => false)) {
        lastStatus = (await statusEl.textContent().catch(() => '')) ?? lastStatus
      }
      await page.waitForTimeout(2000)
    }

    if (lastStatus !== 'complete') {
      // Dump console log to surface the failure context.
      console.error('--- Browser console errors during upload ---')
      for (const line of consoleLines) console.error(line)
      console.error('--- End console errors ---')
      throw new Error(
        `Upload did not complete within 12 min. Last status: "${lastStatus}". ` +
          'Check the Transfers panel + agent log on the target host.'
      )
    }

    // -------- Success --------
    expect(lastStatus).toBe('complete')
  })
})
