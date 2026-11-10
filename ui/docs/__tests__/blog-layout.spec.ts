// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-87 (#1776) — the blog's pages, and the kill switch in the shared chrome.
 */
import { describe, expect, it } from 'vitest'
import { AUTHORS } from '../site.ts'
import { formatDate, indexTitle, renderBlogIndex, renderPost, siteLabel } from '../theme/blog-layout.ts'
import type { Post } from '../theme/posts.ts'
import { DOCS_NAV, renderFooter, renderTopbar, type ShellNav, type SiteAssets } from '../theme/shell.ts'

const assets: SiteAssets = {
  css: '/docs/assets/docs.0123456789.css',
  js: '/docs/assets/docs.abcdefabcd.js',
  search: '/docs/assets/search.1111111111.js',
  osPreference: '/docs/assets/os-preference.2222222222.js',
  searchIndex: '/docs/assets/search-index.3333333333.json',
  blogCss: '/docs/assets/blog.4444444444.css',
}
const nav: ShellNav = { current: 'blog', hasBlog: true }

const post: Post = {
  slug: 'self-hosted-teamviewer-alternative',
  title: 'My wife’s swearing at TeamViewer made me build my own remote desktop tool',
  seoTitle: 'Self-hosted TeamViewer alternative: why I built MeshHarbor',
  subtitle: 'An open-source, self-hosted TeamViewer alternative',
  description: 'Why I built MeshHarbor.',
  date: '2026-09-25T22:45:13Z',
  updated: '2026-09-28T20:52:50Z',
  authorKey: 'goran',
  author: AUTHORS.goran!,
  tags: ['teamviewer', 'remote-desktop'],
  hero: 'remote-desktop.svg',
  heroAlt: 'A browser tab showing a remote desktop',
  ogImage: 'teamviewer-og.png',
  related: [],
  syndication: 'https://medium.com/@gjovanov/my-post',
  url: '/blog/self-hosted-teamviewer-alternative/',
  outFile: 'self-hosted-teamviewer-alternative/index.html',
  sourceFile: 'ui/blog/posts/self-hosted-teamviewer-alternative.md',
  heroImage: { url: '/docs/assets/remote-desktop.cfab9256a7.svg', width: 760, height: 400 },
  og: { url: 'https://meshharbor.itachi.fans/docs/assets/teamviewer-og.0123456789.png', width: 1200, height: 630, alt: 'A browser tab showing a remote desktop' },
  html: '<p>Body.</p>',
  headings: [],
  plain: 'Body.',
  readingMinutes: 9,
}
const render = (p: Partial<Post> = {}) =>
  renderPost({ assets, nav, tagIndexed: new Set(), post: { ...post, ...p }, related: [] })

describe('a post page', () => {
  it('is its own canonical, with its share image and article metadata', () => {
    const html = render()
    expect(html).toContain('<link rel="canonical" href="https://meshharbor.itachi.fans/blog/self-hosted-teamviewer-alternative/">')
    expect(html).toContain('<title>Self-hosted TeamViewer alternative: why I built MeshHarbor</title>')
    expect(html).toContain('<meta property="og:image" content="https://meshharbor.itachi.fans/docs/assets/teamviewer-og.0123456789.png">')
    expect(html).toContain('<meta property="og:image:width" content="1200">')
    expect(html).toContain('<meta property="article:author" content="https://github.com/gjovanov">')
    expect(html).toContain('<link rel="alternate" type="application/atom+xml" title="MeshHarbor blog" href="/blog/feed.xml">')
    expect(html).toContain(`<link rel="stylesheet" href="${assets.blogCss}">`)
  })

  it('names an off-site original as canonical when the post declares one', () => {
    expect(render({ canonical: 'https://example.com/original/' })).toContain('<link rel="canonical" href="https://example.com/original/">')
  })

  it('emits BlogPosting and a two-step breadcrumb under the one Organization', () => {
    const json = JSON.parse(render().match(/<script type="application\/ld\+json">(.*?)<\/script>/)![1]!)
    expect(json['@graph'].map((n: { '@type': string }) => n['@type'])).toEqual(['Organization', 'BlogPosting', 'BreadcrumbList'])
  })

  it('shows the byline, and "updated" only when the day differs', () => {
    expect(render()).toContain('25 September 2026</time> · updated <time datetime="2026-09-28T20:52:50Z">28 September 2026</time> · 9 min read')
    expect(render({ updated: '2026-09-25T23:10:00Z' })).not.toContain('updated <time')
  })

  it('credits the syndicated copy only when there is one', () => {
    expect(render()).toContain('Also published on <a href="https://medium.com/@gjovanov/my-post">Medium</a>.')
    expect(render({ syndication: undefined })).not.toContain('Also published on')
  })

  it('writes no author bio nobody wrote', () => {
    expect(render()).not.toContain('author-box__bio')
  })

  it('loads the hero first', () => {
    expect(render()).toMatch(/<figure class="hero"><img [^>]*width="760" height="400" loading="eager" fetchpriority="high"/)
  })

  it('renders no hero for a post without one, and still shares its image', () => {
    const html = render({ hero: undefined, heroAlt: undefined, heroImage: undefined })
    expect(html).not.toContain('class="hero"')
    expect(html).toContain('<meta property="og:image" content="https://meshharbor.itachi.fans/docs/assets/teamviewer-og.0123456789.png">')
  })
})

describe('the index', () => {
  it('fits its title, and links its neighbours on a middle page', () => {
    expect(indexTitle(1).length).toBeLessThanOrEqual(60)
    const html = renderBlogIndex({ assets, nav, tagIndexed: new Set(), posts: [post], pageNo: 2, pages: 3 })
    expect(html).toContain('<link rel="canonical" href="https://meshharbor.itachi.fans/blog/page/2/">')
    expect(html).toContain('<link rel="prev" href="/blog/">')
    expect(html).toContain('<link rel="next" href="/blog/page/3/">')
    expect(html).toContain('"@type":"Blog"')
  })
})

describe('dates and labels', () => {
  it('formats the date AS WRITTEN, with no time-zone arithmetic', () => {
    expect(formatDate('2026-09-25T22:45:13Z')).toBe('25 September 2026')
    expect(formatDate('2026-09-26T00:30:00+02:00')).toBe('26 September 2026')
  })

  it('names Medium by name', () => {
    expect(siteLabel('https://medium.com/@gjovanov/x')).toBe('Medium')
    expect(siteLabel('https://www.example.org/a')).toBe('example.org')
  })
})

describe('the kill switch in the shared chrome', () => {
  it('shows no Blog and no RSS until a post exists', () => {
    const chrome = renderTopbar(DOCS_NAV) + renderFooter(DOCS_NAV)
    expect(chrome).not.toContain('/blog/')
    expect(chrome).not.toContain('RSS')
  })

  it('shows both once one does, marking where the reader is', () => {
    const top = renderTopbar({ current: 'docs', hasBlog: true })
    expect(top).toContain('<a href="/docs/" aria-current="page">Docs</a>')
    expect(top).toContain('<a href="/blog/">Blog</a>')
    expect(renderFooter({ current: 'docs', hasBlog: true })).toContain('<a href="/blog/feed.xml">RSS feed</a>')
  })
})
