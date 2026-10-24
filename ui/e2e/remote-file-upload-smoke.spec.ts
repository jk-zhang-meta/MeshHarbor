/** Real file-DC round trip: random upload -> remote task directory -> browser
 * download, with byte length, full byte equality and independent SHA-256 check.
 * The operator must pre-create E2E_AGENT_E2E_REMOTE_DIR inside the disposable
 * fixture, including a meshharbor-e2e-<task-id> path component. This test does not
 * create/delete arbitrary remote directories or use a human Downloads folder.
 */
import { test, expect, type Page } from '@playwright/test'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { connectFixture, fixtureConfigured, REMOTE_DIR } from './fixtures/remote-fixture'

test.use({ headless: true, acceptDownloads: true, trace: 'off' })

async function openFiles(page: Page) {
  await page.getByRole('button', { name: 'Open viewer settings', exact: true }).click()
  const settings = page.getByRole('dialog').filter({
    has: page.getByRole('tab', { name: 'Session', exact: true }),
  })
  await settings.getByRole('tab', { name: 'Session', exact: true }).click()
  await settings.getByTestId('rc-files-browse').click()
  const drawer = page.locator('.files-drawer')
  await expect(drawer).toBeVisible()
  const input = drawer.getByPlaceholder('Path (Enter to go)')
  // The first-open roots fetch must finish before submitting another navigation.
  // Count every accessible loader; Vuetify also mounts an aria-hidden field loader.
  await expect(input).toHaveValue(/.+/, { timeout: 20_000 })
  await expect(drawer.getByRole('progressbar')).toHaveCount(0, { timeout: 20_000 })
  await input.fill(REMOTE_DIR)
  await input.press('Enter')
  await expect(drawer.getByRole('progressbar')).toHaveCount(0, { timeout: 20_000 })
  await expect(drawer.locator('.text-error')).toHaveCount(0)
  // Canonical Windows paths may acquire a \\?\ prefix. Require the exact task
  // directory suffix instead of silently accepting a failed navigation/root.
  await expect.poll(async () => (await input.inputValue()).replace(/^\\\\\?\\/, '')
    .replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase(), { timeout: 20_000 })
    .toBe(REMOTE_DIR.replace(/^\\\\\?\\/, '').replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase())
  return drawer
}

test.describe('Remote file-DC byte-integrity smoke against the synthetic harness', () => {
  test.skip(!fixtureConfigured || !REMOTE_DIR, 'explicit fixture IDs and task-owned REMOTE_DIR required')
  test.setTimeout(4 * 60 * 1000)

  test('round-trip a random 1 MiB payload without changing a byte', async ({ page, context }, testInfo) => {
    const parts = REMOTE_DIR.split(/[\\/]/)
    expect(parts, 'REMOTE_DIR must not traverse parents').not.toContain('..')
    expect(parts.some((part) => /^meshharbor-e2e-[A-Za-z\d_-]{6,}$/.test(part)),
      'pre-create an explicitly task-owned meshharbor-e2e-<task-id> directory in the fixture').toBe(true)
    // Exercise the real supported Blob-download branch. Disabling the optional
    // native picker in this fresh page prevents an OS dialog/user-desktop effect;
    // this does NOT stub the DC, remote filesystem, or downloaded payload.
    await page.addInitScript(() => Object.defineProperty(window, 'showSaveFilePicker', {
      configurable: true, value: undefined,
    }))
    await connectFixture(page, context)
    const payload = randomBytes(1024 * 1024)
    const sha256 = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex')
    const name = `roundtrip-${randomUUID()}.bin`
    const source = testInfo.outputPath('source', name)
    const destination = testInfo.outputPath('download', name)
    await fs.mkdir(path.dirname(source), { recursive: true })
    await fs.mkdir(path.dirname(destination), { recursive: true })
    await fs.writeFile(source, payload, { flag: 'wx' })
    const drawer = await openFiles(page)
    await drawer.locator('input[type="file"]').setInputFiles(source)
    await drawer.locator('button[title="Close"]').click()
    await page.getByRole('button', { name: /transfer\(s\) in progress/i }).click()
    const transfer = page.locator('.transfer-row', { hasText: name }).first()
    await expect(transfer).toBeVisible({ timeout: 30_000 })
    await expect(transfer).toHaveClass(/transfer-(complete|error)\b/, { timeout: 120_000 })
    await expect(transfer).toHaveClass(/transfer-complete\b/)
    await page.keyboard.press('Escape')
    const files = await openFiles(page)
    const entry = files.locator('.v-list-item').filter({
      has: page.locator('.v-list-item-title', { hasText: name }),
    })
    await expect(entry).toHaveCount(1)
    const downloadEvent = page.waitForEvent('download', { timeout: 60_000 })
    await entry.locator(`button[title="Download ${name}"]`).click()
    const download = await downloadEvent
    expect(download.suggestedFilename()).toBe(name)
    await download.saveAs(destination)
    expect(await download.failure()).toBeNull()
    const returned = await fs.readFile(destination)
    expect(returned.length, 'download byte length').toBe(payload.length)
    expect(returned.equals(payload), 'full downloaded payload equality').toBe(true)
    const expectedSha256 = sha256(payload)
    const actualSha256 = sha256(returned)
    expect(actualSha256, 'download SHA-256').toBe(expectedSha256)
    await testInfo.attach('file-round-trip-integrity', {
      body: JSON.stringify({ name, remoteDir: REMOTE_DIR, bytes: returned.length,
        expectedSha256, actualSha256 }), contentType: 'application/json',
    })
    // Only task-owned output/remote fixture paths were written. Retain them for
    // failure forensics; the runner/fixture owner performs its bounded cleanup.
  })
})
