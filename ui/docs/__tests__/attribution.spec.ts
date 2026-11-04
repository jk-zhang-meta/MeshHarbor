// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-88 (#1790) §3a — `attribution.js`, the static pages' carry script.
 *
 * It is RUN here, against the pages the generator renders (the homepage, a
 * docs page, a blog post), rather than grepped: what matters is which hrefs
 * change on a real page, that nothing else does, and that no storage API is
 * touched on the way. The key list is locked to the register view's by
 * importing it from `ui/src/utils/attribution.ts`, and the script run is the
 * one the build publishes: `INSTALL_PAGES` written in (`theme/carry.ts`).
 */
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CARRIED_KEYS } from '../../src/utils/attribution.ts'
import { AUTHORS, BASE, INSTALL_PAGES } from '../site.ts'
import { renderPost } from '../theme/blog-layout.ts'
import { carryScript, INSTALL_PAGES_PLACEHOLDER, installPageErrors } from '../theme/carry.ts'
import { renderHome } from '../theme/home-layout.ts'
import { renderPage, type DocPage } from '../theme/layout.ts'
import type { Post } from '../theme/posts.ts'
import { createRenderer, renderMarkdown } from '../theme/render.ts'
import { renderBodyScripts, type SiteAssets } from '../theme/shell.ts'

const SOURCE = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'theme', 'attribution.js'), 'utf8')
/** What the build publishes. */
const SCRIPT = carryScript(SOURCE, INSTALL_PAGES)

const assets: SiteAssets = {
  css: '/docs/assets/docs.0123456789.css',
  js: '/docs/assets/docs.abcdefabcd.js',
  search: '/docs/assets/search.1111111111.js',
  osPreference: '/docs/assets/os-preference.2222222222.js',
  searchIndex: '/docs/assets/search-index.3333333333.json',
  blogCss: '/docs/assets/blog.4444444444.css',
  homeCss: '/docs/assets/home.5555555555.css',
  homeJs: '/docs/assets/home.6666666666.js',
  attribution: '/docs/assets/attribution.7777777777.js',
}

// ── the three kinds of page ───────────────────────────────────────────────

const homeHtml = () =>
  renderHome({ assets, nav: { current: 'home', hasBlog: true }, hero: { url: '/docs/assets/hero.8888888888.svg', width: 880, height: 560 } })

const md = createRenderer()
const docsBody = renderMarkdown(
  md,
  [
    '## Create an account',
    '',
    'Sign up at [meshharbor.itachi.fans](/register) and name the organization.',
    '',
    '## Enroll a machine',
    '',
    ':::enroll',
    ':::',
    '',
    'Read [the Windows guide](/docs/start/install/windows/), or [the FAQ](/docs/faq/),',
    'or jump back to [the first step](#create-an-account).',
    '',
    'The code is on [GitHub](https://github.com/jk-zhang-meta/MeshHarbor).',
  ].join('\n'),
  'test.md',
)

const docPage: DocPage = {
  slug: 'start/quickstart',
  url: '/docs/start/quickstart/',
  outFile: 'start/quickstart/index.html',
  title: 'Quickstart',
  description: 'Enroll a machine and open it in a browser tab.',
  tags: ['install'],
  order: 1,
  noindex: false,
  html: docsBody.html,
  headings: docsBody.headings,
  plain: '',
  faq: false,
  sourceFile: 'start/quickstart',
}
const docsHtml = () => renderPage({ nav: [], page: docPage, assets, site: { current: 'docs', hasBlog: true } }, new Set())

const post: Post = {
  slug: 'x',
  title: 'A post',
  description: 'A post.',
  date: '2026-09-25T22:45:13Z',
  authorKey: 'goran',
  author: AUTHORS.goran!,
  tags: ['remote-desktop'],
  hero: 'remote-desktop.svg',
  heroAlt: 'A browser tab',
  related: [],
  url: '/blog/x/',
  outFile: 'x/index.html',
  sourceFile: 'ui/blog/posts/x.md',
  heroImage: { url: '/docs/assets/remote-desktop.cfab9256a7.svg', width: 760, height: 400 },
  og: { url: 'https://meshharbor.itachi.fans/docs/assets/og.0123456789.png', width: 1200, height: 630, alt: 'A browser tab' },
  html: '<p>Built with <a href="https://github.com/jk-zhang-meta/MeshHarbor">MeshHarbor</a>.</p>',
  headings: [],
  plain: '',
  readingMinutes: 3,
}
const postHtml = () => renderPost({ assets, nav: { current: 'blog', hasBlog: true }, tagIndexed: new Set(), post, related: [] })

// ── the harness ───────────────────────────────────────────────────────────

/** Run attribution.js on `html`, as if it were served at `href` and reached
 *  from `referrer`. The script names `window` and `document`, nothing else. */
function run(html: string, href: string, referrer = '', script = SCRIPT): Document {
  const doc = new DOMParser().parseFromString(html, 'text/html')
  Object.defineProperty(doc, 'referrer', { value: referrer })
  new Function('window', 'document', script)({ location: { href } }, doc)
  return doc
}

const hrefs = (doc: Document) => [...doc.querySelectorAll('a[href]')].map((a) => a.getAttribute('href')!)

/** Every link whose href changed, as [before, after]. */
function changed(html: string, doc: Document): Array<[string, string]> {
  const before = hrefs(new DOMParser().parseFromString(html, 'text/html'))
  const after = hrefs(doc)
  expect(after).toHaveLength(before.length)
  return before.map((b, i) => [b, after[i]!] as [string, string]).filter(([b, a]) => b !== a)
}

/** The allowlist, stated independently of the script: sign-up, sign-in, the
 *  installer downloads, and the install pages — on this origin, and never the
 *  page itself (an in-page anchor must stay an in-page jump). */
const ALLOWED = [/^\/register$/, /^\/login$/, /^\/api\/setup\/(?:windows|linux|macos)$/]
function allowed(href: string, page: string): boolean {
  const here = new URL(page)
  const u = new URL(href, here)
  if (u.origin !== here.origin || u.pathname === here.pathname) return false
  return INSTALL_PAGES.includes(u.pathname) || ALLOWED.some((re) => re.test(u.pathname))
}

const CAMPAIGN = 'utm_source=youtube&utm_medium=video&utm_campaign=fr88-test'

// ── storage: carry, don't store ───────────────────────────────────────────

let spies: Array<ReturnType<typeof vi.spyOn>> = []
const idb = { open: vi.fn(), deleteDatabase: vi.fn() }

beforeEach(() => {
  spies = [
    vi.spyOn(Storage.prototype, 'setItem'),
    vi.spyOn(Storage.prototype, 'getItem'),
    vi.spyOn(Storage.prototype, 'removeItem'),
    vi.spyOn(Storage.prototype, 'clear'),
    vi.spyOn(Document.prototype, 'cookie', 'set'),
    vi.spyOn(Document.prototype, 'cookie', 'get'),
  ]
  vi.stubGlobal('indexedDB', idb)
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  idb.open.mockReset()
  idb.deleteDatabase.mockReset()
})

function expectNoStorage(): void {
  for (const s of spies) expect(s, 'a storage API was touched').not.toHaveBeenCalled()
  expect(idb.open).not.toHaveBeenCalled()
  expect(idb.deleteDatabase).not.toHaveBeenCalled()
}

describe('attribution.js — without a campaign', () => {
  it.each([
    ['the homepage', homeHtml, 'https://meshharbor.itachi.fans/'],
    ['a docs page', docsHtml, 'https://meshharbor.itachi.fans/docs/start/quickstart/'],
    ['a blog post', postHtml, 'https://meshharbor.itachi.fans/blog/x/'],
  ])('leaves every link on %s untouched', (_, html, url) => {
    // An external referrer and unrelated parameters are not a campaign.
    const doc = run(html(), `${url}?q=vpn&landing_path=/x&referrer_host=evil.example`, 'https://www.google.com/')
    expect(changed(html(), doc)).toEqual([])
    expect(doc.querySelector('form[data-subscribe]')?.hasAttribute('data-source') ?? false).toBe(false)
    expectNoStorage()
  })

  it('treats an empty campaign value as no campaign', () => {
    const doc = run(homeHtml(), 'https://meshharbor.itachi.fans/?utm_source=&ref=%20')
    expect(changed(homeHtml(), doc)).toEqual([])
  })
})

describe('attribution.js — with a campaign', () => {
  it.each([
    ['the homepage', homeHtml, 'https://meshharbor.itachi.fans/'],
    ['a docs page', docsHtml, 'https://meshharbor.itachi.fans/docs/start/quickstart/'],
    ['a blog post', postHtml, 'https://meshharbor.itachi.fans/blog/x/'],
  ])('rewrites exactly the allowlisted links on %s, and every one of them', (_, html, url) => {
    const doc = run(html(), `${url}?${CAMPAIGN}`, 'https://www.youtube.com/')
    const diff = changed(html(), doc)
    expect(diff.length).toBeGreaterThan(0)
    // Only allowlisted links changed…
    for (const [before] of diff) expect(allowed(before, url), `${before} is not a CTA`).toBe(true)
    // …and none was missed.
    const before = hrefs(new DOMParser().parseFromString(html(), 'text/html'))
    const after = hrefs(doc)
    const missed = before.filter((h, i) => allowed(h, url) && after[i] === h)
    expect(missed).toEqual([])
    expectNoStorage()
  })

  it('never turns an in-page jump into a reload, on a page that is itself a target', () => {
    // The quickstart is an install guide: its `#main` skip link and anything
    // else that resolves to the quickstart itself must keep its href.
    const url = 'https://meshharbor.itachi.fans/docs/start/quickstart/'
    const doc = run(docsHtml(), `${url}?${CAMPAIGN}`)
    expect(doc.querySelector('a.skip-link')!.getAttribute('href')).toBe('#main')
    // The table of contents, the heading permalinks and the prose's own jump.
    const jumps = [...doc.querySelectorAll('a[href^="#"]')].map((a) => a.getAttribute('href'))
    expect(jumps).toEqual(expect.arrayContaining(['#main', '#create-an-account', '#enroll-a-machine']))
    for (const [before] of changed(docsHtml(), doc)) {
      expect(new URL(before, url).pathname).not.toBe('/docs/start/quickstart/')
    }
  })

  it('carries the campaign and where the journey began onto the sign-up link', () => {
    const doc = run(homeHtml(), `https://meshharbor.itachi.fans/?${CAMPAIGN}&utm_content=desc&utm_term=rd&ref=x`, 'https://www.youtube.com/')
    const cta = doc.querySelector('a.btn.btn--primary.btn--lg')!.getAttribute('href')!
    const u = new URL(cta, 'https://meshharbor.itachi.fans')
    expect(u.pathname).toBe('/register')
    // In the register view's order, and nothing else: CARRIED_KEYS is the
    // SPA's list, so the two cannot drift.
    expect([...u.searchParams.keys()]).toEqual([...CARRIED_KEYS])
    expect(Object.fromEntries(u.searchParams)).toEqual({
      utm_source: 'youtube',
      utm_medium: 'video',
      utm_campaign: 'fr88-test',
      utm_content: 'desc',
      utm_term: 'rd',
      ref: 'x',
      referrer_host: 'www.youtube.com',
      landing_path: '/',
    })
  })

  it('keeps a site-relative href site-relative, and an absolute one absolute', () => {
    const doc = run(docsHtml(), `https://meshharbor.itachi.fans/docs/start/quickstart/?${CAMPAIGN}`)
    const all = hrefs(doc)
    expect(all.find((h) => h.startsWith('/register?'))).toBeDefined()
    // The :::enroll download buttons name the absolute origin.
    const download = all.find((h) => h.startsWith('https://meshharbor.itachi.fans/api/setup/windows'))!
    expect(new URL(download).searchParams.get('utm_campaign')).toBe('fr88-test')
  })

  it('carries onto this origin only: another origin’s download links keep their href', () => {
    const html = docsHtml()
    const doc = run(html, `http://localhost:5000/docs/start/quickstart/?${CAMPAIGN}`)
    const diff = changed(html, doc)
    expect(diff.some(([b]) => b.startsWith('https://meshharbor.itachi.fans/'))).toBe(false)
    expect(diff.some(([b]) => b === '/register')).toBe(true)
  })

  it('records the referrer as a HOST, and only when it is another site', () => {
    const at = (referrer: string) =>
      new URL(run(homeHtml(), `https://meshharbor.itachi.fans/?${CAMPAIGN}`, referrer).querySelector('a[href^="/register"]')!.getAttribute('href')!, 'https://meshharbor.itachi.fans')
        .searchParams
    expect(at('https://www.reddit.com/r/selfhosted/comments/abc/private-title/').get('referrer_host')).toBe('www.reddit.com')
    expect(at('https://meshharbor.itachi.fans/docs/').has('referrer_host')).toBe(false)
    expect(at('').has('referrer_host')).toBe(false)
  })

  it('passes on what an earlier page carried rather than re-deriving it', () => {
    // Second hop: the visitor came from the homepage (this site) by a carried
    // link; the first page's landing and referrer must survive.
    const doc = run(
      docsHtml(),
      `https://meshharbor.itachi.fans/docs/start/quickstart/?${CAMPAIGN}&referrer_host=www.youtube.com&landing_path=%2F`,
      'https://meshharbor.itachi.fans/?utm_source=youtube',
    )
    const u = new URL(doc.querySelector('a[href^="/register"]')!.getAttribute('href')!, 'https://meshharbor.itachi.fans')
    expect(u.searchParams.get('referrer_host')).toBe('www.youtube.com')
    expect(u.searchParams.get('landing_path')).toBe('/')
  })

  it('leaves a value a link names itself alone', () => {
    const html = '<!DOCTYPE html><html><body><a href="/register?utm_source=own#top">x</a></body></html>'
    const doc = run(html, `https://meshharbor.itachi.fans/docs/?${CAMPAIGN}`)
    const u = new URL(doc.querySelector('a')!.getAttribute('href')!, 'https://meshharbor.itachi.fans')
    expect(u.searchParams.get('utm_source')).toBe('own')
    expect(u.searchParams.get('utm_campaign')).toBe('fr88-test')
    expect(u.hash).toBe('#top')
  })

  it('caps every value at the 64 characters the server keeps', () => {
    const doc = run(homeHtml(), `https://meshharbor.itachi.fans/?utm_campaign=${'c'.repeat(300)}`)
    const u = new URL(doc.querySelector('a[href^="/register"]')!.getAttribute('href')!, 'https://meshharbor.itachi.fans')
    expect(u.searchParams.get('utm_campaign')).toBe('c'.repeat(64))
  })

  it('changes nothing but hrefs (and the newsletter source): no layout can shift', () => {
    const html = homeHtml()
    const strip = (s: string) => s.replace(/\shref="[^"]*"/g, ' href').replace(/\sdata-source="[^"]*"/g, '')
    const doc = run(html, `https://meshharbor.itachi.fans/?${CAMPAIGN}`, 'https://www.youtube.com/')
    const pristine = new DOMParser().parseFromString(html, 'text/html')
    expect(strip(doc.documentElement.outerHTML)).toBe(strip(pristine.documentElement.outerHTML))
  })

  it('hands the newsletter form the campaign as its source, cleaned as the server cleans it', () => {
    const src = (qs: string) => run(homeHtml(), `https://meshharbor.itachi.fans/?${qs}`).querySelector('form[data-subscribe]')!.getAttribute('data-source')
    expect(src(CAMPAIGN)).toBe('fr88-test')
    expect(src('utm_campaign=a%20b%3Cc%3E')).toBe('abc')
    expect(src(`utm_campaign=${'x'.repeat(40)}`)).toBe('x'.repeat(32))
    // A source without a campaign, or a campaign that cleans to nothing, leaves the form's own.
    expect(src('utm_source=youtube')).toBeNull()
    expect(src('utm_campaign=%F0%9F%8E%89')).toBeNull()
  })

  it('reads and writes no storage in its source at all', () => {
    // Belt and braces for the paths the runs above do not take. Comments are
    // stripped first: the header says what the script does NOT use.
    const code = SCRIPT.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')
    expect(code).not.toMatch(/localStorage|sessionStorage|indexedDB|cookie/i)
  })
})

describe('attribution.js — sign-in and the install pages', () => {
  const carriedTo = (doc: Document, path: string) =>
    [...doc.querySelectorAll('a[href]')]
      .map((a) => new URL(a.getAttribute('href')!, 'https://meshharbor.itachi.fans'))
      .filter((u) => u.pathname === path)

  it('carries onto the sign-in link: a provider "sign-in" creates the account when there is none', () => {
    const doc = run(homeHtml(), `https://meshharbor.itachi.fans/?${CAMPAIGN}`)
    const login = carriedTo(doc, '/login')
    expect(login.length).toBeGreaterThan(0)
    for (const u of login) expect(u.searchParams.get('utm_campaign')).toBe('fr88-test')
  })

  it('carries onto every install page a page links to, the docs home included', () => {
    const doc = run(homeHtml(), `https://meshharbor.itachi.fans/?${CAMPAIGN}`)
    for (const path of ['/docs/', '/docs/start/quickstart/']) {
      const links = carriedTo(doc, path)
      expect(links.length, path).toBeGreaterThan(0)
      for (const u of links) expect(u.searchParams.get('utm_source'), path).toBe('youtube')
    }
  })

  it('needs the build’s list: the unfilled source reaches no install page at all', () => {
    // The fixed targets still work; the install pages are the build's to write.
    const doc = run(homeHtml(), `https://meshharbor.itachi.fans/?${CAMPAIGN}`, '', SOURCE)
    expect(carriedTo(doc, '/register')[0]!.searchParams.get('utm_source')).toBe('youtube')
    for (const path of ['/docs/', '/docs/start/quickstart/']) {
      for (const u of carriedTo(doc, path)) expect(u.search, path).toBe('')
    }
  })
})

describe('carryScript — the build writes INSTALL_PAGES into the script', () => {
  it('replaces the placeholder with the list, and nothing else', () => {
    expect(SOURCE.split(INSTALL_PAGES_PLACEHOLDER)).toHaveLength(2)
    const filled = carryScript(SOURCE, ['/docs/', '/docs/x/'])
    expect(filled).toContain('var INSTALL_PAGES = ["/docs/","/docs/x/"]')
    expect(filled.replace('["/docs/","/docs/x/"]', INSTALL_PAGES_PLACEHOLDER)).toBe(SOURCE)
  })

  it('refuses a script without the placeholder, or with two: an empty list must not ship silently', () => {
    expect(() => carryScript('var INSTALL_PAGES = []', INSTALL_PAGES)).toThrow(/exactly once/)
    expect(() => carryScript(`${INSTALL_PAGES_PLACEHOLDER} ${INSTALL_PAGES_PLACEHOLDER}`, INSTALL_PAGES)).toThrow(/exactly once/)
  })
})

describe('installPageErrors — the build gate that keeps the lists together', () => {
  const block = (cmd: string) => renderMarkdown(md, ['```bash', cmd, '```'].join('\n'), 'x.md').html
  const install = block('curl -fsSL https://meshharbor.itachi.fans/api/setup/install.sh | sh -s -- --role daemon --token <t>')
  const pages = [
    { id: 'ui/docs/content/index.md', url: `${BASE}/`, html: install },
    { id: 'ui/docs/content/faq/index.md', url: `${BASE}/faq/`, html: block('meshharbor status') },
  ]

  it('passes when every page with an install command is listed', () => {
    expect(installPageErrors(pages, [`${BASE}/`])).toEqual([])
  })

  it('fails for a page that shows an install command but is not listed', () => {
    const errors = installPageErrors([...pages, { id: 'ui/docs/content/new.md', url: `${BASE}/new/`, html: install }], [`${BASE}/`])
    expect(errors).toHaveLength(1)
    expect(errors[0]).toMatch(/^ui\/docs\/content\/new\.md — shows an install command but \/docs\/new\/ is not in INSTALL_PAGES/)
  })

  it('fails for a listed page this site does not generate', () => {
    expect(installPageErrors(pages, [`${BASE}/`, `${BASE}/gone/`])).toEqual([
      'INSTALL_PAGES (ui/docs/site.ts) lists /docs/gone/, which is not a page this site generates',
    ])
  })

  it('allows a listed page without a command (the self-hosting guide installs the server)', () => {
    expect(installPageErrors(pages, [`${BASE}/`, `${BASE}/faq/`])).toEqual([])
  })
})

describe('the shell', () => {
  it('loads the carry script on every page, deferred and first-party', () => {
    for (const html of [homeHtml(), docsHtml(), postHtml()]) {
      expect(html).toContain(`<script src="${assets.attribution}" defer></script>`)
    }
  })

  it('loads nothing when the kill switch leaves it out', () => {
    const { attribution: _, ...without } = assets
    expect(renderBodyScripts(without)).not.toContain('attribution')
    expect(renderBodyScripts(without)).toBe(
      `<script src="${assets.js}" defer></script>\n<script src="${assets.search}" defer></script>`,
    )
  })
})
