// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-87 (#1776) — what the page shell publishes, and what it must not.
 */
import { describe, expect, it } from 'vitest'
import { docsTitle, renderPage, type DocPage, type SiteAssets } from '../theme/layout.ts'

const assets: SiteAssets = {
  css: '/docs/assets/docs.0123456789.css',
  js: '/docs/assets/docs.abcdefabcd.js',
  search: '/docs/assets/search.1111111111.js',
  osPreference: '/docs/assets/os-preference.2222222222.js',
  searchIndex: '/docs/assets/search-index.3333333333.json',
}

const base: DocPage = {
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
const render = (page: Partial<DocPage>) => renderPage({ nav: [], page: { ...base, ...page }, assets }, new Set())

describe('dates', () => {
  it('publishes NO date when none is known — never the build date', () => {
    const html = render({ lastmod: undefined })
    expect(html).not.toContain('dateModified')
    expect(html).not.toContain('Last updated')
    expect(html).not.toContain(new Date().toISOString().slice(0, 10))
    // The edit link survives on its own.
    expect(html).toContain('Edit this page')
  })

  it('publishes a known date in the footer and the structured data', () => {
    const html = render({ lastmod: '2026-09-01' })
    expect(html).toContain('"dateModified":"2026-09-01"')
    expect(html).toContain('Last updated <time datetime="2026-09-01">2026-09-01</time>')
  })

  it("gives structured data git's full timestamp, and readers its date", () => {
    // Google's Rich Results Test flags a bare date as "invalid datetime …
    // missing a timezone" (measured on this page's markup, 2026-09-29).
    const html = render({ created: '2026-08-30T21:04:10+02:00', lastmod: '2026-09-01T14:02:11+02:00' })
    expect(html).toContain('"datePublished":"2026-08-30T21:04:10+02:00","dateModified":"2026-09-01T14:02:11+02:00"')
    expect(html).toContain('<meta property="article:modified_time" content="2026-09-01T14:02:11+02:00">')
    expect(html).toContain('Last updated <time datetime="2026-09-01T14:02:11+02:00">2026-09-01</time>')
  })
})

describe('assets', () => {
  it('names the hashed theme files and the hashed search index', () => {
    const html = render({})
    for (const url of Object.values(assets)) expect(html).toContain(url)
    expect(html).toContain(`data-search-index="${assets.searchIndex}"`)
    // No leftover plain names in the markup.
    expect(html).not.toMatch(/\/docs\/assets\/(docs|search|os-preference)\.(css|js)"/)
  })

  it('gives the hero its real size and loads it first', () => {
    const html = render({ hero: { url: '/docs/assets/tunnels.3e0a37ab4a.svg', width: 760, height: 400 }, heroAlt: 'A tunnel' })
    expect(html).toContain('src="/docs/assets/tunnels.3e0a37ab4a.svg" alt="A tunnel" width="760" height="400"')
    expect(html).toContain('fetchpriority="high"')
    expect(html).not.toContain('width="960"')
  })
})

describe('the 404 page', () => {
  it('declares no address and describes nothing to a crawler', () => {
    const html = render({ notFound: true, noindex: true, sourceFile: undefined, title: 'Page not found' })
    expect(html).not.toContain('rel="canonical"')
    expect(html).not.toContain('og:url')
    expect(html).not.toContain('application/ld+json')
    expect(html).toContain('<meta name="robots" content="noindex, follow">')
    expect(html).not.toContain('Edit this page')
  })

  it('leaves an ordinary page its canonical', () => {
    expect(render({})).toContain('<link rel="canonical" href="https://meshharbor.itachi.fans/docs/start/quickstart/">')
  })
})

// ── P3: the head ──────────────────────────────────────────────────────────

describe('the <title>', () => {
  const section = { dir: 'compare', title: 'How MeshHarbor compares', blurb: '', icon: 'compare', accent: 'coral' } as const
  const leaf = (title: string, extra: Partial<DocPage> = {}): DocPage => ({ ...base, slug: 'compare/x', url: '/docs/compare/x/', section, title, ...extra })

  it('keeps the section when everything fits', () => {
    expect(docsTitle(leaf('vs Tailscale'))).toBe('vs Tailscale · How MeshHarbor compares — MeshHarbor Docs')
  })

  it('drops the section, then the site name, to fit 60', () => {
    // 71 chars with the section — the kind of title FR-60 shipped, cut off in results.
    expect(docsTitle(leaf('MeshHarbor vs TeamViewer and AnyDesk'))).toBe('MeshHarbor vs TeamViewer and AnyDesk — MeshHarbor Docs')
    const long = 'A title that is fifty-five characters long, near enough'
    expect(docsTitle(leaf(long))).toBe(long)
  })

  it('returns null — a build error — when even the bare title is too long', () => {
    expect(docsTitle(leaf('x'.repeat(61)))).toBeNull()
  })

  it("uses the author's seoTitle verbatim", () => {
    expect(docsTitle(leaf('Anything', { seoTitle: 'TeamViewer alternative, self-hosted' }))).toBe('TeamViewer alternative, self-hosted')
  })

  it('fits the docs home', () => {
    expect(docsTitle({ ...base, slug: 'index', url: '/docs/' })!.length).toBeLessThanOrEqual(60)
  })
})

describe('the head', () => {
  it('marks a leaf an article and a listing a website', () => {
    expect(render({})).toContain('<meta property="og:type" content="article">')
    expect(render({ slug: 'index', url: '/docs/' })).toContain('<meta property="og:type" content="website">')
    expect(render({ slug: 'tags/windows', url: '/docs/tags/windows/', sourceFile: undefined })).toContain('content="website"')
  })

  it('carries article:* only on articles', () => {
    const leaf = render({ created: '2026-08-01', lastmod: '2026-09-01' })
    expect(leaf).toContain('<meta property="article:published_time" content="2026-08-01">')
    expect(leaf).toContain('<meta property="article:modified_time" content="2026-09-01">')
    expect(leaf).toContain('<meta property="article:tag" content="install">')
    expect(render({ slug: 'index', url: '/docs/' })).not.toContain('article:')
  })

  it('asks for large image previews, and describes the image it names', () => {
    const html = render({})
    expect(html).toContain('<meta name="robots" content="max-image-preview:large">')
    expect(html).toContain('<meta property="og:image:width" content="1280">')
    expect(html).toContain('<meta property="og:image:alt" content="')
  })

  it('loads the hosted-only analytics loader the build published, never the tracker itself (FR-102)', () => {
    const analytics = '/docs/assets/analytics.9999999999.js'
    const html = renderPage({ nav: [], page: base, assets: { ...assets, analytics } }, new Set())
    expect(html).toContain(`<script src="${analytics}" defer data-src="https://purestat.ai/js/purestat.js" data-domain="meshharbor.itachi.fans" data-hosts="meshharbor.itachi.fans,www.meshharbor.itachi.fans"></script>`)
    expect(html).not.toMatch(/<script[^>]*\ssrc="https:\/\/purestat\.ai/) // `\ssrc`: the loader carries data-src
    // Without a published loader (ANALYTICS = null), nothing at all.
    expect(render({})).not.toMatch(/<script[^>]*data-hosts=/)
    expect(render({}).toLowerCase()).not.toContain('purestat')
  })

  it('emits ONE graph, published by G ROX EOOD, never "G ROX LTD"', () => {
    const html = render({})
    expect(html.match(/application\/ld\+json/g)).toHaveLength(1)
    const json = JSON.parse(html.match(/<script type="application\/ld\+json">(.*?)<\/script>/)![1]!)
    expect(json['@context']).toBe('https://schema.org')
    const types = json['@graph'].map((n: { '@type': string }) => n['@type'])
    expect(types).toEqual(['Organization', 'TechArticle', 'BreadcrumbList'])
    expect(html).toContain('"legalName":"G ROX EOOD"')
    expect(html).not.toContain('G ROX LTD')
  })

  it('describes a listing as a CollectionPage, and drops a one-item breadcrumb', () => {
    const json = JSON.parse(render({ slug: 'index', url: '/docs/' }).match(/<script type="application\/ld\+json">(.*?)<\/script>/)![1]!)
    expect(json['@graph'].map((n: { '@type': string }) => n['@type'])).toEqual(['Organization', 'CollectionPage'])
  })
})

describe('the brand', () => {
  it('links the favicon set, each reused name versioned past the old icon cached `immutable` for a year', () => {
    const html = render({})
    expect(html).toContain('<link rel="icon" href="/favicon.ico?v=2" sizes="48x48">')
    expect(html).toContain('<link rel="icon" href="/favicon.svg?v=3" type="image/svg+xml">')
    expect(html).toContain('<link rel="apple-touch-icon" href="/apple-touch-icon.png?v=2">')
    expect(html).toContain('<link rel="manifest" href="/site.webmanifest">')
    expect(html).not.toContain('href="/favicon.svg"')
  })

  it('puts the logo in the top bar when the build published one, and the word when not', () => {
    const logo = '/docs/assets/meshharbor-logo.4444444444.svg'
    const withLogo = renderPage({ nav: [], page: base, assets: { ...assets, logo } }, new Set())
    const top = withLogo.slice(withLogo.indexOf('<header class="topbar">'), withLogo.indexOf('</header>'))
    expect(top).toContain(
      `<a class="brand" href="/docs/"><img class="brand__logo" src="${logo}" alt="MeshHarbor" width="113" height="32"><span class="brand__docs">Docs</span></a>`,
    )
    expect(top).not.toContain('brand__mark')
    expect(render({})).toContain('<span class="brand__mark">MeshHarbor</span>')
  })
})
