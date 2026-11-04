// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-87 (#1776) P6 — the static homepage nginx serves at `/` to every
 * request without a session cookie, and `home.js`, which enhances it.
 *
 * `home.js` is RUN here, against the rendered page, rather than grepped:
 * its first job (handing a returning user to the app) decides whether a
 * signed-in person sees their dashboard or a sign-up page, so the test that
 * guards it has to exercise the code path, and the key it reads is locked to
 * the one the SPA writes by calling the SPA's own `markSignedIn`.
 */
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { clearSignedIn, markSignedIn } from '../../src/api/session.ts'
import { enrollCommands } from '../../src/utils/enrollCommands.ts'
import { CAPABILITIES, FALLBACK_PLANS, HERO, PILLARS, annualLine } from '../../src/utils/landing.ts'
import { MAX_DESCRIPTION_CHARS, MAX_TITLE_CHARS, SITE_ORIGIN } from '../site.ts'
import { HOME_DESCRIPTION, HOME_TITLE, priceLabel, renderHome } from '../theme/home-layout.ts'
import type { ShellNav, SiteAssets } from '../theme/shell.ts'

const assets: SiteAssets = {
  css: '/docs/assets/docs.0123456789.css',
  js: '/docs/assets/docs.abcdefabcd.js',
  search: '/docs/assets/search.1111111111.js',
  osPreference: '/docs/assets/os-preference.2222222222.js',
  searchIndex: '/docs/assets/search-index.3333333333.json',
  blogCss: '/docs/assets/blog.4444444444.css',
  homeCss: '/docs/assets/home.5555555555.css',
  homeJs: '/docs/assets/home.6666666666.js',
}
const nav: ShellNav = { current: 'home', hasBlog: true }
const hero = { url: '/docs/assets/hero-mesh.7777777777.svg', width: 880, height: 560 }
const render = (n: ShellNav = nav) => renderHome({ assets, nav: n, hero })

const HOME_JS = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'theme', 'home.js'), 'utf8')

function jsonLd(html: string): Array<Record<string, unknown>> {
  const m = html.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/)
  expect(m, 'the homepage carries no JSON-LD').toBeTruthy()
  return (JSON.parse(m![1]!) as { '@graph': Array<Record<string, unknown>> })['@graph']
}

describe('the static homepage', () => {
  it('is the canonical root, with a title and description inside the search-result limits', () => {
    const html = render()
    expect(HOME_TITLE.length).toBeLessThanOrEqual(MAX_TITLE_CHARS)
    expect(HOME_DESCRIPTION.length).toBeLessThanOrEqual(MAX_DESCRIPTION_CHARS)
    expect(html).toContain(`<link rel="canonical" href="${SITE_ORIGIN}/">`)
    expect(html).toContain('<meta property="og:type" content="website">')
    expect(html).not.toContain('noindex')
  })

  it('has exactly one h1, and it is the hero', () => {
    const html = render()
    expect(html.match(/<h1[\s>]/g)).toHaveLength(1)
    expect(html).toContain(`<h1 class="home-hero__title">${HERO.titleLead}<br><span class="home-accent">${HERO.titleAccent}</span></h1>`)
  })

  it('describes the organization and the site, and claims no software rating it does not have', () => {
    const graph = jsonLd(render())
    expect(graph.map((n) => n['@type']).sort()).toEqual(['Organization', 'WebSite'])
    const site = graph.find((n) => n['@type'] === 'WebSite')!
    expect(site.url).toBe(`${SITE_ORIGIN}/`)
    expect((site.publisher as Record<string, unknown>)['@id']).toBe(`${SITE_ORIGIN}/#organization`)
    const org = graph.find((n) => n['@type'] === 'Organization')!
    expect(org.legalName).toBe('G ROX EOOD')
    // SoftwareApplication's rich result REQUIRES aggregateRating or review;
    // without real ones the markup is an error, and they are never invented.
    expect(JSON.stringify(graph)).not.toMatch(/SoftwareApplication|aggregateRating|SearchAction|G ROX LTD/)
  })

  it('loads home.js in <head> WITHOUT defer, so the hand-off runs before the page paints', () => {
    const html = render()
    const head = html.slice(0, html.indexOf('</head>'))
    expect(head).toContain(`<script src="${assets.homeJs}"></script>`)
    expect(head).toContain(`<link rel="stylesheet" href="${assets.homeCss}">`)
    // No blog furniture on this page, so no blog.css — even with the feed on.
    expect(head).toContain('<link rel="alternate" type="application/atom+xml"')
    expect(html).not.toContain(assets.blogCss!)
  })

  it('carries no inline script: the CSP (`script-src \'self\'`) would block it silently', () => {
    for (const tag of render().match(/<script\b[^>]*>/g)!) {
      expect(tag, tag).toMatch(/\ssrc="|type="application\/ld\+json"/)
    }
    // FR-88's carry script included, when the build publishes it.
    for (const tag of renderHome({ assets: { ...assets, attribution: '/docs/assets/attribution.9999999999.js' }, nav, hero }).match(/<script\b[^>]*>/g)!) {
      expect(tag, tag).toMatch(/\ssrc="|type="application\/ld\+json"/)
    }
  })

  it('renders every section, with in-page links that all resolve', () => {
    const html = render()
    const esc = (s: string) => s.replace(/&/g, '&amp;')
    for (const c of CAPABILITIES) expect(html).toContain(`<span class="chip">${esc(c)}</span>`)
    for (const p of PILLARS) {
      expect(html).toContain(`<h2 class="home-h2">${esc(p.title)}</h2>`)
      for (const f of p.features) expect(html).toContain(`<h3 class="home-card__title">${esc(f.title)}</h3>`)
    }
    const ids = new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]))
    const fragments = [...html.matchAll(/href="#([^"]+)"/g)].map((m) => m[1])
    expect(fragments).toEqual(expect.arrayContaining(['features', 'download', 'pricing', 'main']))
    for (const f of fragments) expect(ids, `href="#${f}" has no target`).toContain(f)
  })

  it('draws the hero art sized and eager: it is the largest thing above the fold', () => {
    expect(render()).toContain(
      `<img src="${hero.url}" alt="Laptops, servers and cloud machines joined in one encrypted mesh, reached from a browser tab" width="880" height="560" loading="eager" fetchpriority="high" decoding="async">`,
    )
  })

  it('shows the same install commands as every other surface (enrollCommands)', () => {
    const html = render()
    const oses = enrollCommands('agent', SITE_ORIGIN, null)
    expect(oses.length).toBeGreaterThanOrEqual(3)
    for (const os of oses) {
      const cmd = os.blocks.find((b) => !b.isDownload)!
      const escaped = cmd.command.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
      expect(html).toContain(`<pre class="home-cmd"><code>${escaped}</code></pre>`)
    }
  })

  it('ships the fallback price table, marked up for the live refresh', () => {
    const html = render()
    for (const plan of FALLBACK_PLANS) {
      const { amount, unit } = priceLabel(plan)
      expect(html).toContain(`data-plan="${plan.id}"`)
      expect(html).toContain(`<span class="home-plan__amount" data-price>${amount}</span> <span class="home-plan__unit" data-unit>${unit}</span>`)
    }
  })

  it('without JavaScript, points the newsletter at sign-up instead of showing a dead form', () => {
    const html = render()
    expect(html).toContain('<form class="home-news__form" data-subscribe hidden>')
    expect(html).toMatch(/<p class="home-news__nojs" data-nojs>[^<]*<a href="\/register">/)
  })

  it('has a topbar of its own: the brand is home, the sections are anchors, and there is a way in', () => {
    const html = render()
    const top = html.slice(html.indexOf('<header class="topbar">'), html.indexOf('</header>'))
    expect(top).toContain('<a class="brand" href="/"><span class="brand__mark">MeshHarbor</span></a>')
    expect(top).not.toContain('data-nav-toggle') // no docs sidebar to open
    expect(top).toContain('<a href="#features">Features</a>')
    expect(top).toContain('<a href="#pricing">Pricing</a>')
    expect(top).toContain('<a href="/login">Log in</a>')
    expect(top).toContain('<a href="/blog/">Blog</a>')
    expect(top).not.toContain('aria-current')
    // The kill switch: with no posts, no Blog link and no feed.
    const noBlog = render({ current: 'home', hasBlog: false })
    expect(noBlog).not.toContain('href="/blog/"')
    expect(noBlog).not.toContain('application/atom+xml')
  })
})

describe('priceLabel', () => {
  it('matches what the SPA shows', () => {
    const plan = (price_cents: number) => ({ id: 'x', name: 'X', price_cents, features: [] })
    expect(priceLabel(plan(0))).toEqual({ amount: '$0', unit: 'forever' })
    // FR-115 — per user per month; no euro figure until EUR is on sale.
    expect(priceLabel(plan(800))).toEqual({ amount: '$8', unit: 'per user / month' })
    expect(priceLabel(plan(1250))).toEqual({ amount: '$12.50', unit: 'per user / month' })
    // Once the plan lists an EUR price, the same number in both currencies.
    const withEur = (price_cents: number) => ({
      ...plan(price_cents),
      prices: [
        { interval: 'month' as const, currency: 'usd' as const, unit_amount: price_cents },
        { interval: 'month' as const, currency: 'eur' as const, unit_amount: price_cents },
      ],
    })
    expect(priceLabel(withEur(800))).toEqual({ amount: '$8', unit: '/ €8 per user / month' })
    expect(priceLabel(withEur(1250))).toEqual({ amount: '$12.50', unit: '/ €12.50 per user / month' })
  })
})

describe('annualLine', () => {
  it('names a paid plan’s yearly price, and never a free plan’s (prod, 2026-10-20)', () => {
    const yearly = (price_cents: number, unit_amount: number) => ({
      id: 'x',
      name: 'X',
      price_cents,
      features: [],
      prices: [{ interval: 'year' as const, currency: 'usd' as const, unit_amount }],
    })
    expect(annualLine(yearly(800, 8000))).toBe('or $80 per user per year (two months free)')
    expect(annualLine(yearly(0, 0))).toBeNull()
    expect(annualLine({ id: 'x', name: 'X', price_cents: 800, features: [] })).toBeNull()
  })
})

// ── home.js ────────────────────────────────────────────────────────────────

interface Run {
  doc: Document
  replace: ReturnType<typeof vi.fn>
  fetch: ReturnType<typeof vi.fn>
}

type Answer = { ok: boolean; status?: number; body?: unknown } | Error

/** Run home.js against a freshly rendered homepage. `answers` maps a URL to
 *  what `fetch` gives back for it; `win` adds to the fake `window` (FR-88:
 *  `purestat`), `prepare` edits the page first. */
function runHomeJs(
  answers: Record<string, Answer>,
  storage: Pick<Storage, 'getItem'> = window.localStorage,
  win: Record<string, unknown> = {},
  prepare: (doc: Document) => void = () => {},
): Run {
  const doc = new DOMParser().parseFromString(render(), 'text/html')
  prepare(doc)
  const replace = vi.fn()
  const fetch = vi.fn((url: string) => {
    const a = answers[url]
    if (!a) return Promise.reject(new Error(`unexpected fetch ${url}`))
    if (a instanceof Error) return Promise.reject(a)
    return Promise.resolve({ ok: a.ok, status: a.status ?? (a.ok ? 200 : 500), json: () => Promise.resolve(a.body) })
  })
  const fakeWindow = { localStorage: storage, location: { replace }, ...win }
  // The script names `window`, `document` and `fetch`; nothing else global.
  new Function('window', 'document', 'fetch', HOME_JS)(fakeWindow, doc, fetch)
  return { doc, replace, fetch }
}

const settle = () => new Promise((r) => setTimeout(r, 0))
const SAAS = { ok: true, body: { version: 'x', modules: ['chat', 'saas'] } }
const NO_SAAS = { ok: true, body: { version: 'x', modules: ['chat', 'remote'] } }
const PLANS_404 = { ok: false, status: 404 }

describe('home.js — the signed-in hand-off', () => {
  afterEach(() => clearSignedIn())

  it('sends a browser the SPA marked signed in to the app, before anything else runs', () => {
    markSignedIn() // the SPA's own writer: this locks the two keys together
    const run = runHomeJs({})
    expect(run.replace).toHaveBeenCalledWith('/login')
    expect(run.fetch).not.toHaveBeenCalled()
  })

  it('leaves everyone else on the page — a guest, and every crawler', () => {
    clearSignedIn()
    const run = runHomeJs({ '/api/capabilities': SAAS, '/api/stripe/plans': PLANS_404 })
    expect(run.replace).not.toHaveBeenCalled()
    expect(run.fetch).toHaveBeenCalledWith('/api/capabilities', { credentials: 'omit' })
  })

  it('stays on the page when storage is blocked', () => {
    const blocked = { getItem: () => { throw new Error('SecurityError') } }
    const run = runHomeJs({ '/api/capabilities': SAAS, '/api/stripe/plans': PLANS_404 }, blocked)
    expect(run.replace).not.toHaveBeenCalled()
  })

  it('ignores any value but "1", as the SPA does', () => {
    window.localStorage.setItem('meshharbor-signed-in', 'true')
    const run = runHomeJs({ '/api/capabilities': SAAS, '/api/stripe/plans': PLANS_404 })
    expect(run.replace).not.toHaveBeenCalled()
  })
})

describe('home.js — the newsletter', () => {
  const visible = (doc: Document, sel: string) => !(doc.querySelector(sel) as HTMLElement).hidden

  it('shows the form where the server mounts the list, and retires the no-JS note', async () => {
    const { doc } = runHomeJs({ '/api/capabilities': SAAS, '/api/stripe/plans': PLANS_404 })
    await settle()
    expect(visible(doc, '[data-subscribe]')).toBe(true)
    expect(visible(doc, '[data-nojs]')).toBe(false)
  })

  it('hides the whole block where the server has no list (no `saas`)', async () => {
    const { doc } = runHomeJs({ '/api/capabilities': NO_SAAS, '/api/stripe/plans': PLANS_404 })
    await settle()
    expect(visible(doc, '[data-news]')).toBe(false)
  })

  it.each([
    ['unreachable', new Error('offline')],
    ['answering 500', { ok: false, status: 500 }],
  ] as Array<[string, Answer]>)('fails OPEN with the capabilities endpoint %s: the server still decides', async (_, answer) => {
    const { doc } = runHomeJs({ '/api/capabilities': answer, '/api/stripe/plans': PLANS_404 })
    await settle()
    expect(visible(doc, '[data-subscribe]')).toBe(true)
  })

  it('posts the address with its source, and says only that a confirmation is on its way', async () => {
    const run = runHomeJs({ '/api/capabilities': SAAS, '/api/stripe/plans': PLANS_404, '/api/subscribe': { ok: true, status: 202 } })
    await settle()
    const form = run.doc.querySelector('[data-subscribe]') as HTMLFormElement
    ;(form.querySelector('input[type=email]') as HTMLInputElement).value = '  someone@example.com '
    form.dispatchEvent(new Event('submit', { cancelable: true }))
    await settle()
    const [, init] = run.fetch.mock.calls.find(([url]) => url === '/api/subscribe')!
    expect(init.method).toBe('POST')
    expect(JSON.parse(init.body)).toEqual({ email: 'someone@example.com', source: 'home' })
    expect(form.hidden).toBe(true)
    const status = run.doc.querySelector('[data-subscribe-status]') as HTMLElement
    expect(status.hidden).toBe(false)
    expect(status.textContent).toMatch(/confirmation/)
  })

  // FR-88 (#1790) — the goal and the campaign source.
  async function submit(run: Run) {
    await settle()
    const form = run.doc.querySelector('[data-subscribe]') as HTMLFormElement
    ;(form.querySelector('input[type=email]') as HTMLInputElement).value = 'someone@example.com'
    form.dispatchEvent(new Event('submit', { cancelable: true }))
    await settle()
    const call = run.fetch.mock.calls.find(([url]) => url === '/api/subscribe')
    return call ? JSON.parse(call[1].body) : undefined
  }

  it('fires the subscribe goal once, after the 202', async () => {
    const purestat = vi.fn()
    const run = runHomeJs({ '/api/capabilities': SAAS, '/api/stripe/plans': PLANS_404, '/api/subscribe': { ok: true, status: 202 } }, undefined, { purestat })
    await submit(run)
    expect(purestat).toHaveBeenCalledTimes(1)
    expect(purestat).toHaveBeenCalledWith('subscribe')
  })

  it('fires no goal when the request fails', async () => {
    const purestat = vi.fn()
    const run = runHomeJs({ '/api/capabilities': SAAS, '/api/stripe/plans': PLANS_404, '/api/subscribe': { ok: false, status: 503 } }, undefined, { purestat })
    await submit(run)
    expect(purestat).not.toHaveBeenCalled()
  })

  it('still confirms the subscription without purestat (the goal is a no-op)', async () => {
    const run = runHomeJs({ '/api/capabilities': SAAS, '/api/stripe/plans': PLANS_404, '/api/subscribe': { ok: true, status: 202 } })
    await submit(run)
    const status = run.doc.querySelector('[data-subscribe-status]') as HTMLElement
    expect(status.hidden).toBe(false)
    expect(status.textContent).toMatch(/confirmation/)
  })

  it('posts the campaign attribution.js found as the source, and `home` without one', async () => {
    const answers = { '/api/capabilities': SAAS, '/api/stripe/plans': PLANS_404, '/api/subscribe': { ok: true, status: 202 } }
    const tagged = runHomeJs(answers, undefined, {}, (doc) => doc.querySelector('[data-subscribe]')!.setAttribute('data-source', 'fr88-test'))
    expect((await submit(tagged)).source).toBe('fr88-test')
    expect((await submit(runHomeJs(answers))).source).toBe('home')
  })

  it('lets the visitor retry when the request fails', async () => {
    const run = runHomeJs({ '/api/capabilities': SAAS, '/api/stripe/plans': PLANS_404, '/api/subscribe': { ok: false, status: 503 } })
    await settle()
    const form = run.doc.querySelector('[data-subscribe]') as HTMLFormElement
    ;(form.querySelector('input[type=email]') as HTMLInputElement).value = 'someone@example.com'
    form.dispatchEvent(new Event('submit', { cancelable: true }))
    await settle()
    expect(form.hidden).toBe(false)
    expect((form.querySelector('button') as HTMLButtonElement).disabled).toBe(false)
    expect(run.doc.querySelector('[data-subscribe-status]')!.textContent).toMatch(/try again/)
  })
})

describe('home.js — live prices', () => {
  it('replaces the fallback with the server’s plans, keeping the tick marks', async () => {
    const plans = [{ id: 'pro', name: 'Pro', price_cents: 1250, features: ['Alpha', '<b>Beta</b>'] }]
    const { doc } = runHomeJs({ '/api/capabilities': SAAS, '/api/stripe/plans': { ok: true, body: plans } })
    await settle()
    const card = doc.querySelector('[data-plan="pro"]')!
    expect(card.querySelector('[data-price]')!.textContent).toBe('$12.50')
    // No EUR price from this server: no euro figure (FR-115).
    expect(card.querySelector('[data-unit]')!.textContent).toBe('per user / month')
    const items = [...card.querySelectorAll('[data-features] li')]
    expect(items.map((li) => li.textContent)).toEqual(['Alpha', '<b>Beta</b>']) // text, never markup
    expect(items.every((li) => li.querySelector('svg'))).toBe(true)
    // No annual price from this server: the yearly line stays hidden.
    expect((card.querySelector('[data-annual]') as HTMLElement).hidden).toBe(true)
  })

  it('shows the yearly line when the server sells annual (FR-115)', async () => {
    const plans = [
      {
        id: 'pro',
        name: 'Pro',
        price_cents: 800,
        features: ['Alpha'],
        prices: [
          { interval: 'month', currency: 'usd', unit_amount: 800 },
          { interval: 'year', currency: 'usd', unit_amount: 8000 },
          { interval: 'year', currency: 'eur', unit_amount: 8000 },
        ],
      },
    ]
    const { doc } = runHomeJs({ '/api/capabilities': SAAS, '/api/stripe/plans': { ok: true, body: plans } })
    await settle()
    const annual = doc.querySelector('[data-plan="pro"] [data-annual]') as HTMLElement
    expect(annual.hidden).toBe(false)
    expect(annual.textContent).toBe('or $80 / €80 per user per year (two months free)')
    // EUR on sale: the monthly label carries the euro figure too.
    expect(doc.querySelector('[data-plan="pro"] [data-unit]')!.textContent).toBe('/ €8 per user / month')
  })

  it('never offers the free plan by the year (prod, 2026-10-20: "or $0 per user per year")', async () => {
    const plans = [
      {
        id: 'free',
        name: 'Free',
        price_cents: 0,
        features: ['Alpha'],
        prices: [
          { interval: 'month', currency: 'usd', unit_amount: 0 },
          { interval: 'year', currency: 'usd', unit_amount: 0 },
        ],
      },
    ]
    const { doc } = runHomeJs({ '/api/capabilities': SAAS, '/api/stripe/plans': { ok: true, body: plans } })
    await settle()
    const annual = doc.querySelector('[data-plan="free"] [data-annual]') as HTMLElement
    expect(annual.hidden).toBe(true)
    expect(annual.textContent).toBe('')
    expect(doc.querySelector('[data-plan="free"] [data-unit]')!.textContent).toBe('forever')
  })

  it('keeps the fallback table when the answer is unusable', async () => {
    const before = new DOMParser().parseFromString(render(), 'text/html').querySelector('[data-plans]')!.innerHTML
    for (const body of [null, { plans: [] }, [{ id: 'pro', price_cents: '12' }], [{ id: 'pro"] , x[y="', price_cents: 5 }]]) {
      const { doc } = runHomeJs({ '/api/capabilities': SAAS, '/api/stripe/plans': { ok: true, body } })
      await settle()
      expect(doc.querySelector('[data-plans]')!.innerHTML).toBe(before)
    }
  })
})
