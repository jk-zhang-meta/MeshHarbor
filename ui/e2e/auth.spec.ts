import { test, expect } from '@playwright/test'
import { uniqueUser, registerUserViaApi, registerViaUi, loginViaUi } from './fixtures/test-helpers'

test.describe('Authentication', () => {
  test('register new user and redirect to dashboard', async ({ page }) => {
    const user = uniqueUser()
    await registerViaUi(page, user.email, user.username, user.displayName, user.password)
    await expect(page).toHaveURL('/')
  })

  test('login with valid credentials', async ({ page }) => {
    const user = uniqueUser()
    // Register via UI first
    await registerViaUi(page, user.email, user.username, user.displayName, user.password)
    // Logout by clearing storage
    await page.evaluate(() => localStorage.clear())
    await page.goto('/login')

    // Login
    await loginViaUi(page, user.username, user.password)
    await expect(page).toHaveURL('/')
  })

  test('login with wrong password shows error', async ({ page }) => {
    await page.goto('/login')
    await page.locator('input').first().fill('nonexistent')
    await page.locator('input[type="password"]').fill('wrongpass')
    await page.getByRole('button', { name: /login/i }).click()
    // Should stay on login page with error
    await expect(page).toHaveURL(/\/login/)
  })

  test('an unauthenticated visitor at / gets the product page, never the app', async ({ page }) => {
    const resp = await page.goto('/')
    // FR-87 P6: behind the production nginx, `/` without a session cookie IS
    // the static homepage (what every crawler reads). The vite dev server has
    // no nginx, so there the SPA's guard shows its /landing view instead.
    // Which of the two answered is read from the response, never assumed.
    const html = (await resp?.text()) ?? ''
    if (html.includes('class="home-hero__title"')) {
      await expect(page).toHaveURL(/\/$/)
      await expect(page.locator('h1.home-hero__title')).toBeVisible()
      await expect(page.getByRole('link', { name: 'Log in' })).toHaveAttribute('href', '/login')
    } else {
      await expect(page).toHaveURL(/\/landing/)
    }
    await expect(page.getByText(/create your first workspace/i)).toHaveCount(0)
  })

  test('a returning user whose session cookie lapsed lands back in the app (FR-87 P6)', async ({ page, context }) => {
    // The access cookie lives 7 days, the refresh cookie 30 — and the refresh
    // cookie is scoped to /api/auth/refresh, so nginx never sees it at `/`
    // and serves such a user the static homepage. Its home.js hands a browser
    // the SPA marked signed in to /login; the guest guard sends it on to the
    // dashboard, whose first 401 refreshes the session.
    const user = uniqueUser()
    await registerUserViaApi(user)
    await loginViaUi(page, user.username, user.password)
    const cookies = await context.cookies()
    expect(cookies.find((c) => c.name === 'refresh_token'), 'login set no refresh_token cookie').toBeTruthy()
    // Park the page first: `loginViaUi` returns while the dashboard still has
    // requests in flight, and one sent after the cookies change 401s, starts a
    // refresh, and the `goto` below aborts it. The app counts an aborted
    // refresh as a rejection and clears its hint, so the test would then
    // measure its own race rather than the hand-off (seen on both images).
    await page.goto('about:blank')
    await context.clearCookies()
    await context.addCookies(cookies.filter((c) => c.name !== 'access_token'))

    await page.goto('/')
    // `/` is also the static page's URL, and the dashboard's text is no proof
    // either: the app renders from the HINT, and an empty tenant list from a
    // 401 looks exactly like a new user's (measured: the text was up before
    // the refresh answered). Proof is a freshly minted session cookie that
    // the server accepts as this user.
    await expect(page.locator('h1.home-hero__title')).toHaveCount(0, { timeout: 15000 })
    await expect
      .poll(async () => (await context.cookies()).some((c) => c.name === 'access_token'), {
        message: 'the refresh minted no session',
        timeout: 15000,
      })
      .toBe(true)
    const me = await page.request.get('/api/auth/me')
    expect(me.status(), 'the new session cookie is not accepted').toBe(200)
    expect((await me.json()).username).toBe(user.username)
    await expect(page).toHaveURL(/\/$/)
    await expect(page.getByText(/create your first workspace/i)).toBeVisible()
  })

  test('a stale signed-in hint cannot loop: it ends on the login page, cleared', async ({ page }) => {
    // No cookies at all, but the SPA's hint says signed in: home.js hands the
    // browser to the app, the refresh 401s, and the SPA clears the hint and
    // shows its login page — which is where it must STAY.
    await page.goto('/login')
    await page.evaluate(() => localStorage.setItem('meshharbor-signed-in', '1'))
    await page.goto('/')
    await expect(page).toHaveURL(/\/login/, { timeout: 15000 })
    await expect(page.locator('input[type="password"]')).toBeVisible()
    expect(await page.evaluate(() => localStorage.getItem('meshharbor-signed-in'))).toBeNull()
    await expect(page).toHaveURL(/\/login/)
  })

  test('protected deep-link redirects to login, not landing (S2)', async ({ page }) => {
    // A real target (e.g. the desktop app's "View screen" remote URL)
    // must land on the sign-in form with the path stashed for
    // redirect-back — the landing page would strand the link.
    await page.goto('/tenant/000000000000000000000000/agent/000000000000000000000000/remote')
    await expect(page).toHaveURL(/\/login/)
    const stashed = await page.evaluate(() => sessionStorage.getItem('pending_redirect'))
    expect(stashed).toContain('/agent/000000000000000000000000/remote')
  })

  test('navigate between login and register', async ({ page }) => {
    await page.goto('/login')
    await page.getByRole('link', { name: /register/i }).click()
    await expect(page).toHaveURL(/\/register/)

    await page.getByRole('link', { name: /login/i }).click()
    await expect(page).toHaveURL(/\/login/)
  })

  test('an invalid session cookie keeps you out of the app', async ({ page, context }) => {
    const user = uniqueUser()
    await registerUserViaApi(user)

    // ⚠️ Rewritten for cookie-only sessions. The original set
    // `localStorage.access_token` and then tampered it — neither step
    // describes anything any more: the session cookie is HttpOnly since
    // #690/#691 precisely so that page script cannot read or forge it, which
    // is the property that made an XSS unable to walk off with 30 days of
    // re-mintable access. Tampering therefore has to happen through the
    // browser CONTEXT, which is also a truer model of a stolen-or-stale
    // cookie than a localStorage write ever was.
    await loginViaUi(page, user.username, user.password)

    const session = (await context.cookies()).find((c) => c.name === 'access_token')
    expect(session, 'login set no access_token cookie').toBeTruthy()

    await context.clearCookies()
    await context.addCookies([{ ...session!, value: 'expired.invalid.token' }])

    // Navigate to an authenticated route. The property under test is that a
    // bad cookie does NOT get you into the app — not which door you are shown.
    //
    // ⚠️ It can be either: the router guard sends an unauthenticated visitor to
    // /landing, while the 401 interceptor sends them to /login, and which wins
    // is a race. Asserting /login alone made this flaky (it failed on /landing
    // in the 2026-08-30 nightly and passed on retry), so assert the invariant.
    await page.goto('/')
    await expect(page).toHaveURL(/\/(login|landing)/, { timeout: 10000 })
    // And nothing authenticated rendered behind it.
    await expect(page.getByRole('link', { name: 'Rooms' })).toHaveCount(0)
  })

  test('nav menu hides profile/logout when unauthenticated', async ({ page }) => {
    await page.goto('/login')
    // On the login page, AppLayout is not rendered (guest route),
    // so avatar and logout should not be present
    await expect(page.getByText('Logout')).not.toBeVisible()
    await expect(page.getByText('Profile')).not.toBeVisible()
  })
})
