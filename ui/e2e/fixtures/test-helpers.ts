import { type BrowserContext, type Page, expect } from '@playwright/test'

const API_URL = process.env.E2E_API_URL || 'http://localhost:5001'
const MAILPIT_URL = process.env.E2E_MAILPIT_URL || 'http://localhost:8025'

let userCounter = 0

/** Generate a unique test user for each test */
export function uniqueUser() {
  userCounter++
  const id = `e2e_${Date.now()}_${userCounter}`
  return {
    email: `${id}@test.local`,
    username: id,
    displayName: `E2E User ${userCounter}`,
    password: 'TestPass123!',
  }
}

/** Register a user via the API and return credentials */
export async function registerUserViaApi(user: ReturnType<typeof uniqueUser>) {
  const resp = await fetch(`${API_URL}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: user.email,
      username: user.username,
      password: user.password,
      display_name: user.displayName,
    }),
  })
  if (!resp.ok) throw new Error(`Register failed: ${resp.status}`)
  return (await resp.json()) as { access_token: string; user: { id: string } }
}

/** Create a tenant via the API */
export async function createTenantViaApi(token: string, name: string, slug: string) {
  const resp = await fetch(`${API_URL}/api/tenant`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ name, slug }),
  })
  if (!resp.ok) throw new Error(`Create tenant failed: ${resp.status}`)
  return (await resp.json()) as { id: string; name: string; slug: string }
}

/** Create a room via the API */
export async function createRoomViaApi(
  token: string,
  tenantId: string,
  name: string,
  isOpen = true,
  options: { media_settings?: Record<string, unknown>; parent_id?: string } = {},
) {
  const resp = await fetch(`${API_URL}/api/tenant/${tenantId}/room`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ name, is_open: isOpen, ...options }),
  })
  if (!resp.ok) throw new Error(`Create room failed: ${resp.status}`)
  return (await resp.json()) as { id: string; name: string; path: string; has_media: boolean; parent_id?: string }
}

/** End a call in a room via the API */
export async function endCallViaApi(token: string, tenantId: string, roomId: string) {
  const resp = await fetch(`${API_URL}/api/tenant/${tenantId}/room/${roomId}/call/end`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!resp.ok) throw new Error(`End call failed: ${resp.status}`)
  return resp.json()
}

/** Login through the UI */
export async function loginViaUi(page: Page, username: string, password: string) {
  await page.goto('/login')
  await page.locator('input').first().fill(username)
  await page.locator('input[type="password"]').fill(password)
  await page.getByRole('button', { name: /login/i }).click()
  await expect(page).toHaveURL(/\/$/, { timeout: 5000 })
}

/**
 * Sign a browser context in through its OWN cookie jar, with no login form.
 *
 * Sessions are cookie-only since #691: an `access_token` seeded into
 * `localStorage` grants nothing, and the viewer shows the login form. Posting
 * the login through `context.request` lands the HttpOnly session cookie in
 * that context's jar. The `roomler-signed-in` hint makes the SPA render its
 * shell and refresh through the cookie instead of bouncing to /login. purestat
 * is aborted, so a test run never feeds the analytics a real visit feeds.
 */
export async function signInContext(context: BrowserContext, email: string, password: string) {
  await context.route('https://purestat.ai/**', (r) => r.abort())
  const login = await context.request.post(`${API_URL}/api/auth/login`, {
    data: { email, password },
  })
  expect(login.ok(), `browser login failed: ${login.status()}`).toBeTruthy()
  await context.addInitScript(() => {
    try {
      window.localStorage.setItem('roomler-signed-in', '1')
    } catch {
      /* storage blocked — the cookie still authenticates */
    }
  })
}

/** Join a room via the API */
export async function joinRoomViaApi(token: string, tenantId: string, roomId: string) {
  const resp = await fetch(`${API_URL}/api/tenant/${tenantId}/room/${roomId}/join`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!resp.ok) throw new Error(`Join room failed: ${resp.status}`)
  return resp.json()
}

/** Start a call in a room via the API */
export async function startCallViaApi(token: string, tenantId: string, roomId: string) {
  const resp = await fetch(`${API_URL}/api/tenant/${tenantId}/room/${roomId}/call/start`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!resp.ok) throw new Error(`Start call failed: ${resp.status}`)
  return resp.json()
}

/** Join a call in a room via the API */
export async function joinCallViaApi(token: string, tenantId: string, roomId: string) {
  const resp = await fetch(`${API_URL}/api/tenant/${tenantId}/room/${roomId}/call/join`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!resp.ok) throw new Error(`Join call failed: ${resp.status}`)
  return (await resp.json()) as { member_id: string; joined: boolean }
}

/** Send a message via the API. Optional `mentions` triggers the
 *  backend's notification creation path — without it the API does
 *  NOT parse `@username` out of `content` (the frontend computes
 *  mentions client-side and sends explicit user IDs). */
export async function sendMessageViaApi(
  token: string,
  tenantId: string,
  roomId: string,
  content: string,
  mentions?: { users?: string[]; everyone?: boolean; here?: boolean },
) {
  const body: Record<string, unknown> = { content }
  if (mentions) body.mentions = mentions
  const resp = await fetch(`${API_URL}/api/tenant/${tenantId}/room/${roomId}/message`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(body),
  })
  if (!resp.ok) throw new Error(`Send message failed: ${resp.status}`)
  return (await resp.json()) as { id: string; content: string; author_id: string }
}

/** Send a thread reply via the API */
export async function sendThreadReplyViaApi(
  token: string,
  tenantId: string,
  roomId: string,
  threadId: string,
  content: string,
) {
  const resp = await fetch(`${API_URL}/api/tenant/${tenantId}/room/${roomId}/message`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ content, thread_id: threadId }),
  })
  if (!resp.ok) throw new Error(`Send thread reply failed: ${resp.status}`)
  return (await resp.json()) as { id: string; content: string; thread_id: string }
}

/** Add a reaction to a message via the API */
export async function addReactionViaApi(
  token: string,
  tenantId: string,
  roomId: string,
  messageId: string,
  emoji: string,
) {
  const resp = await fetch(
    `${API_URL}/api/tenant/${tenantId}/room/${roomId}/message/${messageId}/reaction`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ emoji }),
    },
  )
  if (!resp.ok) throw new Error(`Add reaction failed: ${resp.status}`)
  return resp.json()
}

/** Remove a reaction from a message via the API */
export async function removeReactionViaApi(
  token: string,
  tenantId: string,
  roomId: string,
  messageId: string,
  emoji: string,
) {
  const resp = await fetch(
    `${API_URL}/api/tenant/${tenantId}/room/${roomId}/message/${messageId}/reaction/${encodeURIComponent(emoji)}`,
    {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    },
  )
  if (!resp.ok) throw new Error(`Remove reaction failed: ${resp.status}`)
  return resp.json()
}

/** Fetch messages in a room via the API */
export async function fetchMessagesViaApi(
  token: string,
  tenantId: string,
  roomId: string,
) {
  const resp = await fetch(`${API_URL}/api/tenant/${tenantId}/room/${roomId}/message`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!resp.ok) throw new Error(`Fetch messages failed: ${resp.status}`)
  return (await resp.json()) as {
    items: Array<{
      id: string
      content: string
      is_thread_root: boolean
      reply_count?: number
      reaction_summary: Array<{ emoji: string; count: number }>
    }>
  }
}

/** Add a user to a tenant via the API */
export async function addTenantMemberViaApi(
  token: string,
  tenantId: string,
  userId: string,
) {
  const resp = await fetch(`${API_URL}/api/tenant/${tenantId}/member`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ user_id: userId }),
  })
  if (!resp.ok) throw new Error(`Add tenant member failed: ${resp.status}`)
  return resp.json()
}

/** Create an invite via the API */
export async function createInviteViaApi(
  token: string,
  tenantId: string,
  options: { target_email?: string; max_uses?: number; expires_in_hours?: number } = {},
) {
  const resp = await fetch(`${API_URL}/api/tenant/${tenantId}/invite`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(options),
  })
  if (!resp.ok) throw new Error(`Create invite failed: ${resp.status}`)
  return (await resp.json()) as { id: string; code: string; status: string }
}

/** Accept an invite via the API */
export async function acceptInviteViaApi(token: string, code: string) {
  const resp = await fetch(`${API_URL}/api/invite/${code}/accept`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!resp.ok) throw new Error(`Accept invite failed: ${resp.status}`)
  return (await resp.json()) as { tenant_id: string; tenant_name: string; tenant_slug: string }
}

/** Revoke an invite via the API */
export async function revokeInviteViaApi(token: string, tenantId: string, inviteId: string) {
  const resp = await fetch(`${API_URL}/api/tenant/${tenantId}/invite/${inviteId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!resp.ok) throw new Error(`Revoke invite failed: ${resp.status}`)
  return resp.json()
}

/** Fetch room members via the API */
export async function fetchMembersViaApi(
  token: string,
  tenantId: string,
  roomId: string,
) {
  const resp = await fetch(`${API_URL}/api/tenant/${tenantId}/room/${roomId}/member`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!resp.ok) throw new Error(`Fetch members failed: ${resp.status}`)
  return (await resp.json()) as {
    items: Array<{
      id: string
      user_id: string
      display_name: string
      username: string
    }>
    total: number
  }
}

/**
 * Shape of one entry in Mailpit's `/api/v1/messages` listing —
 * we destructure just the fields we need. See
 * https://mailpit.axllent.org/docs/api-v1/ for the full schema.
 */
type MailpitListItem = {
  ID: string
  To: Array<{ Address: string }>
  Subject: string
  Created: string
}

/**
 * Poll Mailpit's HTTP API for an email delivered to `recipient`.
 * Returns the parsed Mailpit message once one arrives; throws if no
 * matching message lands within `timeoutMs` (default 15 s).
 *
 * Mailpit's `/api/v1/search?query=to:<email>` is exact-match on the
 * recipient address. We use it because the inbox may contain emails
 * from other concurrent tests in the same run.
 *
 * NOTE: requires the e2e overlay's roomler2 to have its EmailService
 * routed through SMTP → Mailpit (set via `MESHHARBOR__EMAIL__SMTP_HOST`
 * + `MESHHARBOR__EMAIL__SMTP_PORT` in `configmap-roomler2-config.yaml`).
 * Outside that overlay, this helper will time out.
 */
export async function fetchActivationEmail(
  recipient: string,
  timeoutMs = 15000,
): Promise<{ subject: string; html: string; text: string; activationUrl: string | null }> {
  const start = Date.now()
  const query = encodeURIComponent(`to:${recipient}`)
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const list = await fetch(`${MAILPIT_URL}/api/v1/search?query=${query}&limit=10`)
    if (list.ok) {
      const data = (await list.json()) as { messages: MailpitListItem[] }
      const match = data.messages.find(
        (m) => m.To.some((t) => t.Address.toLowerCase() === recipient.toLowerCase())
          && /activate/i.test(m.Subject),
      )
      if (match) {
        const full = await fetch(`${MAILPIT_URL}/api/v1/message/${match.ID}`)
        if (full.ok) {
          const body = (await full.json()) as { HTML: string; Text: string; Subject: string }
          // Activation URL lands in the HTML as
          //   <a href="<frontend_url>/auth/activate?userId=<hex>&token=<7-char-nanoid>">
          const m = /href="(https?:\/\/[^"]*\/auth\/activate\?userId=[a-f0-9]{24}&token=[^"]+)"/i.exec(
            body.HTML,
          )
          return {
            subject: body.Subject,
            html: body.HTML,
            text: body.Text,
            activationUrl: m ? m[1] : null,
          }
        }
      }
    }
    if (Date.now() - start > timeoutMs) {
      throw new Error(
        `Mailpit: no activation email for ${recipient} after ${timeoutMs}ms (last list status ${list.status})`,
      )
    }
    await new Promise((r) => setTimeout(r, 500))
  }
}

/**
 * POST the activation token to `/api/auth/activate` to complete the
 * email-link round-trip. Returns the success message.
 */
export async function activateViaApi(userId: string, token: string) {
  const resp = await fetch(`${API_URL}/api/auth/activate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_id: userId, token }),
  })
  if (!resp.ok) throw new Error(`Activate failed: ${resp.status}`)
  return (await resp.json()) as { message: string }
}

/**
 * Parse `userId` and `token` query params out of the activation URL
 * emitted by `auth::register` (format:
 * `<frontend>/auth/activate?userId=<oid>&token=<nanoid>`).
 */
export function parseActivationUrl(url: string): { userId: string; token: string } {
  const parsed = new URL(url)
  const userId = parsed.searchParams.get('userId')
  const token = parsed.searchParams.get('token')
  if (!userId || !token) {
    throw new Error(`Cannot parse activation URL: ${url}`)
  }
  return { userId, token }
}

/** Register through the UI */
export async function registerViaUi(
  page: Page,
  email: string,
  username: string,
  displayName: string,
  password: string,
) {
  await page.goto('/register')
  const inputs = page.locator('input')
  await inputs.nth(0).fill(email)
  await inputs.nth(1).fill(username)
  await inputs.nth(2).fill(displayName)
  await page.locator('input[type="password"]').fill(password)
  await page.getByRole('button', { name: /register/i }).click()
  await expect(page).toHaveURL(/\/$/, { timeout: 5000 })
}
