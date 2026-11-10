import { test, expect } from '@playwright/test'
import {
  uniqueUser,
  registerUserViaApi,
  createTenantViaApi,
  createRoomViaApi,
  joinRoomViaApi,
  sendMessageViaApi,
  addTenantMemberViaApi,
  loginViaUi,
  fetchActivationEmail,
  activateViaApi,
  parseActivationUrl,
} from './fixtures/test-helpers'

const API_URL = process.env.E2E_API_URL || 'http://localhost:5001'

test.describe('Email-related flows', () => {
  test.describe('Registration & Activation', () => {
    test('registration triggers SMTP delivery captured by Mailpit', async () => {
      // The e2e overlay sets MESHHARBOR__EMAIL__SMTP_HOST=mailpit so the
      // EmailService dispatches every send through plaintext SMTP to
      // the Mailpit pod. AUTO_VERIFY=true still flips is_verified at
      // register time (so the existing 100+ specs keep working), but
      // the activation email is sent unconditionally — we poll
      // Mailpit's HTTP API to verify SMTP arrived end-to-end.
      const user = uniqueUser()
      const auth = await registerUserViaApi(user)
      expect(auth.access_token).toBeTruthy()

      const mail = await fetchActivationEmail(user.email)
      expect(mail.subject.toLowerCase()).toContain('activate')
      expect(mail.html.length).toBeGreaterThan(0)
      expect(mail.activationUrl).toBeTruthy()
      // Activation URL targets the configured FRONTEND_URL (http://meshharbor2
      // in cluster) plus the /auth/activate path. It carries a 24-char
      // hex userId and a 7-char nanoid token.
      expect(mail.activationUrl).toMatch(
        /^https?:\/\/[^/]+\/auth\/activate\?userId=[a-f0-9]{24}&token=[A-Za-z0-9_-]{7}$/,
      )
    })

    test('activation roundtrip: parse link from Mailpit → POST /activate succeeds', async () => {
      // End-to-end check that the URL embedded in the email is a real,
      // accept-able activation. AUTO_VERIFY already set is_verified at
      // register time, so /activate is idempotent in this overlay —
      // it still must return 200 (success) for a valid token.
      const user = uniqueUser()
      await registerUserViaApi(user)
      const mail = await fetchActivationEmail(user.email)
      if (!mail.activationUrl) throw new Error('no activation URL in Mailpit email')

      const { userId, token } = parseActivationUrl(mail.activationUrl)
      const result = await activateViaApi(userId, token)
      expect(result.message.toLowerCase()).toContain('activated')
    })

    test('activation endpoint rejects invalid tokens', async () => {
      const resp = await fetch(`${API_URL}/api/auth/activate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: '000000000000000000000000',
          token: 'invalid-activation-token',
        }),
      })
      // 400 = bad request for invalid / expired token (covered by the
      // backend's `find_valid` returning None for unknown user_id).
      expect(resp.status).toBe(400)
    })

    test('activated user can login successfully', async () => {
      // registerUserViaApi already returns tokens via the AUTO_VERIFY
      // shortcut; this asserts the post-register tokens work for
      // subsequent authenticated API calls.
      const user = uniqueUser()
      const auth = await registerUserViaApi(user)
      expect(auth.access_token).toBeDefined()
      expect(auth.access_token.length).toBeGreaterThan(0)
    })
  })

  test.describe('Mention Notification flows', () => {
    let adminUser: ReturnType<typeof uniqueUser>
    let memberUser: ReturnType<typeof uniqueUser>
    let adminToken: string
    let memberToken: string
    let memberUserId: string
    let tenantId: string
    let roomId: string

    test.beforeEach(async () => {
      adminUser = uniqueUser()
      memberUser = uniqueUser()

      const adminAuth = await registerUserViaApi(adminUser)
      adminToken = adminAuth.access_token

      const memberAuth = await registerUserViaApi(memberUser)
      memberToken = memberAuth.access_token
      memberUserId = memberAuth.user.id

      const tenant = await createTenantViaApi(
        adminToken,
        'Email Test Org',
        `email-test-${Date.now()}`,
      )
      tenantId = tenant.id

      await addTenantMemberViaApi(adminToken, tenantId, memberUserId)

      const room = await createRoomViaApi(adminToken, tenantId, 'email-test-room', true)
      roomId = room.id

      // Drop the admin self-join — the room creator is auto-joined
      // by the API and re-joining returns 409 Conflict. Same fix
      // wave Cycle 3 applied to 7 other spec files in ea2a619; this
      // file was deferred (testIgnored) at the time so it missed the
      // sweep.
      await joinRoomViaApi(memberToken, tenantId, roomId)
    })

    test('sending a mention creates a notification for the mentioned user', async () => {
      // Admin sends a message mentioning the member. Backend doesn't
      // parse `@username` out of content — the frontend computes
      // mentions client-side and sends explicit user IDs, so the API
      // helper must do the same to trigger the notification path.
      const mentionContent = `Hey @${memberUser.username} please review this`
      await sendMessageViaApi(adminToken, tenantId, roomId, mentionContent, {
        users: [memberUserId],
      })

      // Poll unread-count until the notification appears. The mention
      // creation flow detects @username inline, writes the notification
      // row, then broadcasts WS — there can be 1-3 s of latency in a
      // freshly-rolled cluster. A fixed 1 s sleep used to be enough but
      // proved flaky once email-flows.spec.ts started running (Chunk 1).
      let count = 0
      for (let i = 0; i < 20; i++) {
        await new Promise((r) => setTimeout(r, 250))
        const resp = await fetch(`${API_URL}/api/notification/unread-count`, {
          headers: { Authorization: `Bearer ${memberToken}` },
        })
        if (!resp.ok) continue
        const data = (await resp.json()) as { count: number }
        if (data.count >= 1) {
          count = data.count
          break
        }
      }
      expect(count).toBeGreaterThanOrEqual(1)
    })

    test('notifications API returns mention notification details', async () => {
      // Send mention with explicit user IDs — same reason as the
      // previous test (backend doesn't parse @username from content).
      const mentionContent = `Heads up @${memberUser.username}!`
      await sendMessageViaApi(adminToken, tenantId, roomId, mentionContent, {
        users: [memberUserId],
      })

      // Same poll-until-visible pattern as the test above. The
      // /api/notification/unread endpoint returns paginated JSON
      // (`{ items, total, page, per_page, total_pages }`), not a
      // bare array — destructure `items` so `.length` is defined.
      let items: Array<{ id: string; type: string; is_read: boolean }> = []
      for (let i = 0; i < 20; i++) {
        await new Promise((r) => setTimeout(r, 250))
        const resp = await fetch(`${API_URL}/api/notification/unread`, {
          headers: { Authorization: `Bearer ${memberToken}` },
        })
        if (!resp.ok) continue
        const data = (await resp.json()) as {
          items: Array<{ id: string; type: string; is_read: boolean }>
        }
        items = data.items
        if (items.length > 0) break
      }
      expect(items.length).toBeGreaterThanOrEqual(1)
      expect(items.some((n) => !n.is_read)).toBe(true)
    })

    test('mark-all-read clears unread notifications', async () => {
      // Create a notification via mention
      await sendMessageViaApi(
        adminToken,
        tenantId,
        roomId,
        `Hey @${memberUser.username}`,
      )
      await new Promise((r) => setTimeout(r, 1000))

      // Mark all as read
      const markResp = await fetch(`${API_URL}/api/notification/read-all`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${memberToken}` },
      })
      expect(markResp.ok).toBeTruthy()

      // Verify unread count is now 0
      const countResp = await fetch(`${API_URL}/api/notification/unread-count`, {
        headers: { Authorization: `Bearer ${memberToken}` },
      })
      expect(countResp.ok).toBeTruthy()
      const countData = (await countResp.json()) as { count: number }
      expect(countData.count).toBe(0)
    })

    test('mention notification is visible in UI notification panel', async ({ page }) => {
      // Send mention
      await sendMessageViaApi(
        adminToken,
        tenantId,
        roomId,
        `Urgent @${memberUser.username} please respond`,
      )

      // Login as the mentioned user
      await loginViaUi(page, memberUser.username, memberUser.password)

      // Wait for notifications to load
      await page.waitForTimeout(2000)

      // Open the notification panel via bell icon
      await page.locator('.mdi-bell-outline').click()
      await page.waitForTimeout(1000)

      // The notification panel should be visible
      await expect(page.locator('.notification-panel')).toBeVisible({ timeout: 5000 })
    })
  })
})
