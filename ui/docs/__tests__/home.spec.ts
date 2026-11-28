// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-87 (#1776) P6 — the static homepage nginx serves at `/` to every
 * request without a session cookie, and `home.js`, which enhances it.
 */
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { clearSignedIn, markSignedIn } from '../../src/api/session.ts'
import { enrollCommands } from '../../src/utils/enrollCommands.ts'
import { CAPABILITIES, HERO, PILLARS } from '../../src/utils/landing.ts'
import { MAX_DESCRIPTION_CHARS, MAX_TITLE_CHARS, SITE_ORIGIN } from '../site.ts'
import { HOME_DESCRIPTION, HOME_TITLE, renderHome } from '../theme/home-layout.ts'
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
    expect(JSON.stringify(graph)).not.toMatch(/SoftwareApplication|aggregateRating|SearchAction|G ROX LTD/)
  })

  it('loads home.js in <head> WITHOUT defer, so the hand-off runs before the page paints', () => {
    const html = render()
    const head = html.slice(0, html.indexOf('</head>'))
    expect(head).toContain(`<script src="${assets.homeJs}"></script>`)
    expect(head).toContain(`<link rel="stylesheet" href="${assets.homeCss}">`)
    expect(head).toContain('<link rel="alternate" type="application/atom+xml"')
    expect(html).not.toContain(assets.blogCss!)
  })

  it('carries no inline script: the CSP (`script-src \'self\'`) would block it silently', () => {
    for (const tag of render().match(/<script\b[^>]*>/g)!) {
      expect(tag, tag).toMatch(/\ssrc="|type="application\/ld\+json"/)
    }
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
    expect(fragments).toEqual(expect.arrayContaining(['features', 'download', 'main']))
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

  it('has a topbar of its own: the brand is home, the sections are anchors, and there is a way in', () => {
    const html = render()
    const top = html.slice(html.indexOf('<header class="topbar">'), html.indexOf('</header>'))
    expect(top).toContain('<a class="brand" href="/"><span class="brand__mark">MeshHarbor</span></a>')
    expect(top).not.toContain('data-nav-toggle')
    expect(top).toContain('<a href="#features">Features</a>')
    expect(top).toContain('<a href="#download">Download</a>')
    expect(top).toContain('<a href="/login">Log in</a>')
    expect(top).toContain('<a href="/blog/">Blog</a>')
    expect(top).not.toContain('aria-current')
    const noBlog = render({ current: 'home', hasBlog: false })
    expect(noBlog).not.toContain('href="/blog/"')
    expect(noBlog).not.toContain('application/atom+xml')
  })
})

function runHomeJs(storage: Pick<Storage, 'getItem'> = window.localStorage) {
  const doc = new DOMParser().parseFromString(render(), 'text/html')
  const replace = vi.fn()
  const fakeWindow = { localStorage: storage, location: { replace } }
  new Function('window', 'document', HOME_JS)(fakeWindow, doc)
  return { doc, replace }
}

describe('home.js — the signed-in hand-off', () => {
  afterEach(() => clearSignedIn())

  it('sends a browser the SPA marked signed in to the app, before anything else runs', () => {
    markSignedIn()
    const run = runHomeJs()
    expect(run.replace).toHaveBeenCalledWith('/login')
  })

  it('leaves everyone else on the page — a guest, and every crawler', () => {
    clearSignedIn()
    const run = runHomeJs()
    expect(run.replace).not.toHaveBeenCalled()
  })

  it('stays on the page when storage is blocked', () => {
    const blocked = { getItem: () => { throw new Error('SecurityError') } }
    const run = runHomeJs(blocked)
    expect(run.replace).not.toHaveBeenCalled()
  })

  it('ignores any value but "1", as the SPA does', () => {
    window.localStorage.setItem('meshharbor-signed-in', 'true')
    const run = runHomeJs()
    expect(run.replace).not.toHaveBeenCalled()
  })
})
