// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-102 (#2127) — the kill switch. `ANALYTICS = null` in `ui/docs/site.ts`
 * has turned analytics off on the static pages since FR-87; with the loader
 * in the tracker's place it must still remove everything: no loader, no
 * tracker, nothing that names purestat. `site.ts` is a module constant, so
 * this runs with it mocked, in a file of its own (a `vi.mock` is per file).
 *
 * The build's half — not publishing `analytics.js` at all when `ANALYTICS`
 * is null — is a one-line conditional in `build.ts`; its OTHER half, the
 * shell, is what writes the tag, and this proves the shell writes none even
 * when handed a published loader.
 */
import { describe, expect, it, vi } from 'vitest'
import { AUTHORS } from '../site.ts'
import { renderBlogIndex, renderPost } from '../theme/blog-layout.ts'
import { renderHome } from '../theme/home-layout.ts'
import { renderPage, type DocPage } from '../theme/layout.ts'
import { renderLinks } from '../theme/links-layout.ts'
import type { Post } from '../theme/posts.ts'
import type { SiteAssets } from '../theme/shell.ts'

vi.mock('../site.ts', async (importOriginal) => ({ ...(await importOriginal<typeof import('../site.ts')>()), ANALYTICS: null }))

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
  // Handed a loader anyway: the shell must still write nothing.
  analytics: '/docs/assets/analytics.8888888888.js',
}

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

const PAGES: ReadonlyArray<[string, () => string]> = [
  ['a docs page', () => renderPage({ nav: [], page: docPage, assets, site: { current: 'docs', hasBlog: true } }, new Set())],
  ['the 404 page', () => renderPage({ nav: [], page: { ...docPage, slug: '404', url: '/docs/404.html', notFound: true, noindex: true, sourceFile: undefined }, assets }, new Set())],
  ['a blog post', () => renderPost({ assets, nav: { current: 'blog', hasBlog: true }, tagIndexed: new Set(), post, related: [] })],
  ['the blog index', () => renderBlogIndex({ assets, nav: { current: 'blog', hasBlog: true }, tagIndexed: new Set(), posts: [post], pageNo: 1, pages: 1 })],
  ['the homepage', () => renderHome({ assets, nav: { current: 'home', hasBlog: true }, hero: { url: '/docs/assets/hero.9999999999.svg', width: 880, height: 560 } })],
  ['the link hub', () => renderLinks({ assets, nav: { current: 'links', hasBlog: true } })],
]

describe('ANALYTICS = null', () => {
  it.each(PAGES)('%s carries no loader, no tracker and no mention of purestat', (_, render) => {
    const html = render()
    expect(html).not.toContain(assets.analytics!)
    expect(html).not.toContain('data-hosts=')
    expect(html).not.toMatch(/<script\b[^>]*\ssrc="https:\/\/purestat\.ai/)
    expect(html.toLowerCase()).not.toContain('purestat')
    // The page's other scripts are untouched by the switch.
    expect(html).toContain(`<script src="${assets.js}" defer></script>`)
    expect(html).toContain(`<script src="${assets.attribution}" defer></script>`)
  })
})
