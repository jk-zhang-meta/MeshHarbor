// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-102 (#2127) §3c — the static pages load purestat on the hosted site,
 * and nowhere else.
 *
 * Before this the shell wrote the tracker's tag into every page, so a
 * self-hosted copy of the docs, a fork and a `localhost` build all reported
 * to purestat.ai as `meshharbor.itachi.fans`. Now every page carries a same-origin
 * loader (`theme/analytics.js`) whose configuration rides on its own tag as
 * `data-*`, and the loader injects the tracker only where the SPA's rule
 * would. Three things are held here:
 *
 *   - the loader is RUN, against the same table of cases as the SPA's
 *     `shouldLoadAnalytics` (imported, so the two implementations of the one
 *     rule cannot drift), and touches no storage on the way;
 *   - every kind of page the generator renders — a docs page, the 404, a
 *     post, the blog index, the homepage, the link hub — carries the loader
 *     and NOT the tracker, with no inline script (the CSP forbids one);
 *   - the real build publishes the loader into the full tree AND the
 *     blog-only tree (FR-91's lane serves nothing from `/docs/assets/`).
 *
 * `ANALYTICS = null`, the kill switch, is `analytics-off.spec.ts`: it needs
 * the module mocked, which is per file.
 */
import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { ANALYTICS_DOMAIN, ANALYTICS_HOSTS, ANALYTICS_SRC, shouldLoadAnalytics, type Where } from '../../src/utils/analytics.ts'
import { CASES } from '../../src/__tests__/utils/analytics.cases.ts'
import { ANALYTICS, AUTHORS } from '../site.ts'
import { renderBlogIndex, renderPost } from '../theme/blog-layout.ts'
import { renderHome } from '../theme/home-layout.ts'
import { renderPage, type DocPage } from '../theme/layout.ts'
import { renderLinks } from '../theme/links-layout.ts'
import type { Post } from '../theme/posts.ts'
import { renderHead, type SiteAssets } from '../theme/shell.ts'

const HERE = dirname(fileURLToPath(import.meta.url))
const UI = join(HERE, '..', '..')
const LOADER = readFileSync(join(HERE, '..', 'theme', 'analytics.js'), 'utf8')

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
  analytics: '/docs/assets/analytics.8888888888.js',
}

/** The one tag the shell writes, on every page. */
const LOADER_TAG = `<script src="${assets.analytics}" defer data-src="https://purestat.ai/js/purestat.js" data-domain="meshharbor.itachi.fans" data-hosts="meshharbor.itachi.fans,www.meshharbor.itachi.fans"></script>`
// `\ssrc`, not `\bsrc`: the loader's own tag carries `data-src="https://purestat.ai/…"`.
const TRACKER_TAG = /<script\b[^>]*\ssrc="https:\/\/purestat\.ai/

// ── the loader, run ───────────────────────────────────────────────────────

const DEFAULT_ATTRS = { 'data-src': ANALYTICS_SRC, 'data-domain': ANALYTICS_DOMAIN, 'data-hosts': ANALYTICS_HOSTS.join(',') }

/** Run analytics.js as the browser would: as the script of a `<script>`
 *  element carrying `attrs`, on a page at `where`. The script names `window`
 *  and `document`, nothing else. */
function run(where: Where, attrs: Record<string, string> | null = DEFAULT_ATTRS): Document {
  const doc = new DOMParser().parseFromString('<!DOCTYPE html><html><head><title>x</title></head><body></body></html>', 'text/html')
  let me: HTMLScriptElement | null = null
  if (attrs) {
    me = doc.createElement('script')
    me.setAttribute('src', assets.analytics!)
    me.defer = true
    for (const [k, v] of Object.entries(attrs)) me.setAttribute(k, v)
    doc.head.appendChild(me)
  }
  Object.defineProperty(doc, 'currentScript', { value: me, configurable: true })
  const win = { location: { hostname: where.hostname, protocol: where.protocol }, navigator: { webdriver: where.webdriver } }
  new Function('window', 'document', LOADER)(win, doc)
  return doc
}

const trackers = (doc: Document) => [...doc.querySelectorAll('script[src^="https://purestat.ai/"]')]

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

describe('analytics.js — one rule, two implementations', () => {
  it.each(CASES)('answers as the SPA does on %s', (_, where, loads) => {
    const doc = run(where)
    expect(trackers(doc).length, 'the static loader disagrees with shouldLoadAnalytics').toBe(shouldLoadAnalytics(where) ? 1 : 0)
    expect(trackers(doc).length).toBe(loads ? 1 : 0)
    expectNoStorage()
  })

  it('injects exactly the tag the pages always carried, deferred, into <head>, when it loads', () => {
    const doc = run({ hostname: 'meshharbor.itachi.fans', protocol: 'https:', webdriver: false })
    const tag = trackers(doc)[0] as HTMLScriptElement
    expect(tag.parentElement).toBe(doc.head)
    expect(tag.defer).toBe(true)
    expect(tag.getAttribute('data-domain')).toBe('meshharbor.itachi.fans')
    expect(tag.getAttribute('src')).toBe('https://purestat.ai/js/purestat.js')
    expect(tag.getAttribute('type')).toBeNull()
    // Nothing else changed: the loader's own tag is still the only other script.
    expect(doc.querySelectorAll('script')).toHaveLength(2)
  })

  it('changes nothing on a page it does not load on', () => {
    const doc = run({ hostname: 'localhost', protocol: 'http:', webdriver: false })
    expect(doc.querySelectorAll('script')).toHaveLength(1)
    expect(doc.head.innerHTML).toContain('data-hosts=')
  })

  it('reads the allowlist from its own tag: a different list loads elsewhere, an empty one nowhere', () => {
    const fork: Where = { hostname: 'docs.example', protocol: 'https:', webdriver: false }
    expect(trackers(run(fork, { ...DEFAULT_ATTRS, 'data-hosts': 'docs.example,www.docs.example' }))).toHaveLength(1)
    expect(trackers(run(fork, { ...DEFAULT_ATTRS, 'data-hosts': 'www.docs.example' }))).toHaveLength(0)
    expect(trackers(run({ hostname: 'meshharbor.itachi.fans', protocol: 'https:', webdriver: false }, { ...DEFAULT_ATTRS, 'data-hosts': '' }))).toHaveLength(0)
    // An empty hostname (file:, about:) never matches an empty entry.
    expect(trackers(run({ hostname: '', protocol: 'https:', webdriver: false }, { ...DEFAULT_ATTRS, 'data-hosts': ',' }))).toHaveLength(0)
  })

  it('loads the tracker its tag names, for the site its tag names', () => {
    const doc = run({ hostname: 'meshharbor.itachi.fans', protocol: 'https:', webdriver: false }, { 'data-src': 'https://purestat.ai/js/other.js', 'data-domain': 'x.meshharbor.itachi.fans', 'data-hosts': 'meshharbor.itachi.fans' })
    const tag = trackers(doc)[0]!
    expect(tag.getAttribute('src')).toBe('https://purestat.ai/js/other.js')
    expect(tag.getAttribute('data-domain')).toBe('x.meshharbor.itachi.fans')
  })

  it('does nothing without its element, or with a tag missing the tracker or the site', () => {
    const hosted: Where = { hostname: 'meshharbor.itachi.fans', protocol: 'https:', webdriver: false }
    expect(trackers(run(hosted, null))).toHaveLength(0)
    const { 'data-src': _src, ...noSrc } = DEFAULT_ATTRS
    expect(trackers(run(hosted, noSrc))).toHaveLength(0)
    const { 'data-domain': _domain, ...noDomain } = DEFAULT_ATTRS
    expect(trackers(run(hosted, noDomain))).toHaveLength(0)
  })

  it('reads and writes no storage in its source at all', () => {
    const code = LOADER.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')
    expect(code).not.toMatch(/localStorage|sessionStorage|indexedDB|cookie/i)
  })
})

// ── the shell: every kind of page ─────────────────────────────────────────

const docPage: DocPage = {
  slug: 'start/quickstart',
  url: '/docs/start/quickstart/',
  outFile: 'start/quickstart/index.html',
  title: 'Quickstart',
  description: 'Enroll a machine and open it in a browser tab.',
  tags: ['install'],
  order: 1,
  noindex: false,
  html: '<p>Body.</p>',
  headings: [],
  plain: 'Body.',
  faq: false,
  sourceFile: 'start/quickstart',
}

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
  html: '<p>Body.</p>',
  headings: [],
  plain: '',
  readingMinutes: 3,
}

/** Every page kind, rendered on `a` (the build's assets, or a variation). */
const PAGES: ReadonlyArray<[string, (a: SiteAssets) => string]> = [
  ['a docs page', (a) => renderPage({ nav: [], page: docPage, assets: a, site: { current: 'docs', hasBlog: true } }, new Set())],
  ['the 404 page', (a) => renderPage({ nav: [], page: { ...docPage, slug: '404', url: '/docs/404.html', notFound: true, noindex: true, sourceFile: undefined }, assets: a }, new Set())],
  ['a blog post', (a) => renderPost({ assets: a, nav: { current: 'blog', hasBlog: true }, tagIndexed: new Set(), post, related: [] })],
  ['the blog index', (a) => renderBlogIndex({ assets: a, nav: { current: 'blog', hasBlog: true }, tagIndexed: new Set(), posts: [post], pageNo: 1, pages: 1 })],
  ['the homepage', (a) => renderHome({ assets: a, nav: { current: 'home', hasBlog: true }, hero: { url: '/docs/assets/hero.9999999999.svg', width: 880, height: 560 } })],
  ['the link hub', (a) => renderLinks({ assets: a, nav: { current: 'links', hasBlog: true } })],
]

describe('the shell', () => {
  it('builds the loader tag from ANALYTICS in site.ts, which is the SPA’s configuration', () => {
    expect(ANALYTICS).toEqual({ src: ANALYTICS_SRC, domain: ANALYTICS_DOMAIN, hosts: ANALYTICS_HOSTS })
    expect(ANALYTICS!.hosts).toEqual(['meshharbor.itachi.fans', 'www.meshharbor.itachi.fans'])
  })

  it.each(PAGES)('%s carries the loader once, in <head>, and never the tracker', (_, render) => {
    const html = render(assets)
    const head = html.slice(0, html.indexOf('</head>'))
    expect(head.split(LOADER_TAG)).toHaveLength(2)
    expect(html.split(LOADER_TAG)).toHaveLength(2)
    expect(html).not.toMatch(TRACKER_TAG)
    expect(html).not.toContain('purestat.js"></script>')
  })

  it.each(PAGES)('%s carries no inline script: the CSP would block it silently', (_, render) => {
    for (const tag of render(assets).match(/<script\b[^>]*>/g)!) {
      expect(tag, tag).toMatch(/\ssrc="|type="application\/ld\+json"/)
    }
  })

  it.each(PAGES)('%s carries neither when the build published no loader', (_, render) => {
    const { analytics: _a, ...without } = assets
    const html = render(without)
    expect(html).not.toContain('data-hosts=')
    expect(html).not.toMatch(TRACKER_TAG)
    expect(html.toLowerCase()).not.toContain('purestat')
  })

  it('escapes what it writes onto the tag', () => {
    const html = renderHead({
      title: 'x',
      description: 'x',
      noindex: true,
      og: { type: 'website', title: 'x' },
      assets: { ...assets, analytics: '/docs/assets/analytics.0000000000.js' },
    })
    expect(html).toContain('<script src="/docs/assets/analytics.0000000000.js" defer data-src="https://purestat.ai/js/purestat.js" data-domain="meshharbor.itachi.fans" data-hosts="meshharbor.itachi.fans,www.meshharbor.itachi.fans"></script>')
  })
})

// ── the real build: both trees ────────────────────────────────────────────

function build(args: string[]): { code: number | null; log: string } {
  const r = spawnSync('bun', ['docs/build.ts', ...args], { cwd: UI, encoding: 'utf8' })
  return { code: r.status, log: `${r.stdout ?? ''}${r.stderr ?? ''}${r.error ? String(r.error) : ''}` }
}

function files(dir: string): string[] {
  const out: string[] = []
  const walk = (d: string) => {
    for (const e of readdirSync(d)) {
      const p = join(d, e)
      if (statSync(p).isDirectory()) walk(p)
      else out.push(relative(dir, p).split('\\').join('/'))
    }
  }
  walk(dir)
  return out.sort()
}

describe('the build publishes the loader into both trees', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'fr102-'))
  const FULL = join(tmp, 'full')
  const LANE = join(tmp, 'lane')

  beforeAll(() => {
    const full = build(['--out', FULL])
    expect(full.code, full.log).toBe(0)
    const lane = build(['--blog-only', '--out', LANE])
    expect(lane.code, lane.log).toBe(0)
  })
  afterAll(() => rmSync(tmp, { recursive: true, force: true }))

  /** The loader every HTML file under `root` names, checked to exist there with the theme's bytes. */
  function loaderOf(root: string, assetBase: string): string {
    const html = files(root).filter((f) => f.endsWith('.html'))
    expect(html.length).toBeGreaterThan(0)
    const names = new Set<string>()
    for (const f of html) {
      const text = readFileSync(join(root, f), 'utf8')
      const m = text.match(new RegExp(`<script src="(${assetBase}/analytics\\.[0-9a-f]{10}\\.js)" defer data-src="https://purestat\\.ai/js/purestat\\.js" data-domain="meshharbor\\.itachi\\.fans" data-hosts="meshharbor\\.itachi\\.fans,www\\.meshharbor\\.itachi\\.fans"></script>`, 'g'))
      expect(m, `${f} does not carry the loader`).toHaveLength(1)
      names.add(m![0]!.match(/src="([^"]+)"/)![1]!)
      expect(text, `${f} carries the tracker itself`).not.toMatch(TRACKER_TAG)
    }
    expect(names.size).toBe(1)
    const url = [...names][0]!
    const file = join(root, url.replace(/^\//, ''))
    expect(existsSync(file), url).toBe(true)
    expect(readFileSync(file, 'utf8')).toBe(LOADER)
    return url
  }

  it('the full build: every page under /docs/, the homepage, the link hub and the blog name one /docs/assets/ loader', () => {
    const url = loaderOf(FULL, '/docs/assets')
    for (const f of ['docs/index.html', 'docs/404.html', 'home/index.html', 'links/index.html', 'blog/index.html']) {
      expect(readFileSync(join(FULL, f), 'utf8'), f).toContain(url)
    }
    const posts = files(join(FULL, 'blog')).filter((f) => /^[^/]+\/index\.html$/.test(f) && !f.startsWith('page/') && !f.startsWith('tags/'))
    expect(posts.length).toBeGreaterThan(0)
  })

  it('the blog-only build: the lane’s pages name a loader in the lane’s own /blog/assets/', () => {
    const url = loaderOf(LANE, '/blog/assets')
    expect(url.startsWith('/blog/assets/analytics.')).toBe(true)
    expect(files(LANE).some((f) => f.includes('/docs/'))).toBe(false)
  })
})
