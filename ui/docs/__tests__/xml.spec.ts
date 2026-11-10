// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-87 (#1776) — the sitemap index, its urlsets, robots.txt.
 */
import { describe, expect, it } from 'vitest'
import { atomFeed, feedHtml, newest, robotsTxt, sitemapChildren, sitemapIndex, urlset, xmlEscape, type FeedInput } from '../theme/xml.ts'

/** Parsed by a real XML parser (jsdom's), so "well-formed" is checked, not assumed. */
function parseXml(xml: string): Document {
  const doc = new DOMParser().parseFromString(xml, 'application/xml')
  const err = doc.getElementsByTagName('parsererror')[0]
  if (err) throw new Error(`not well-formed: ${err.textContent}`)
  return doc
}

const FEED: FeedInput = {
  id: 'https://meshharbor.itachi.fans/blog/',
  selfUrl: 'https://meshharbor.itachi.fans/blog/feed.xml',
  htmlUrl: 'https://meshharbor.itachi.fans/blog/',
  title: 'MeshHarbor blog',
  subtitle: 'Posts & notes',
  updated: '2026-09-28T20:52:50Z',
  entries: [
    {
      id: 'https://meshharbor.itachi.fans/blog/a/',
      url: 'https://meshharbor.itachi.fans/blog/a/',
      title: 'Wife’s swearing & <TeamViewer>',
      summary: 'Why "MeshHarbor" exists',
      contentHtml: '<p>A <a href="https://meshharbor.itachi.fans/docs/">link</a> &amp; <code>&lt;tag&gt;</code></p>',
      published: '2026-09-25T22:45:13Z',
      updated: '2026-09-28T20:52:50Z',
      author: { name: 'Goran Jovanov', uri: 'https://github.com/gjovanov' },
      tags: ['teamviewer', 'remote-desktop'],
    },
  ],
}

describe('atomFeed', () => {
  it('is well-formed Atom, with the entry and its full content intact', () => {
    const doc = parseXml(atomFeed(FEED))
    expect(doc.documentElement.namespaceURI).toBe('http://www.w3.org/2005/Atom')
    const entry = doc.getElementsByTagName('entry')[0]!
    expect(entry.getElementsByTagName('title')[0]!.textContent).toBe('Wife’s swearing & <TeamViewer>')
    const content = entry.getElementsByTagName('content')[0]!
    expect(content.getAttribute('type')).toBe('html')
    // The HTML survives the round trip exactly: escaped once, decoded once.
    expect(content.textContent).toBe(FEED.entries[0]!.contentHtml)
    expect([...entry.getElementsByTagName('category')].map((c) => c.getAttribute('term'))).toEqual(['teamviewer', 'remote-desktop'])
  })

  it('names itself and the page it mirrors', () => {
    const doc = parseXml(atomFeed(FEED))
    const links = [...doc.documentElement.children].filter((n) => n.tagName === 'link')
    expect(links.map((l) => `${l.getAttribute('rel')} ${l.getAttribute('href')}`)).toEqual([
      'self https://meshharbor.itachi.fans/blog/feed.xml',
      'alternate https://meshharbor.itachi.fans/blog/',
    ])
  })
})

describe('feedHtml', () => {
  it('makes site links and images absolute, and leaves other URLs alone', () => {
    const out = feedHtml('<a href="/docs/x/">x</a><img src="/docs/assets/a.png"><a href="//cdn.example/y">y</a><a href="https://e.com/">e</a>', 'https://meshharbor.itachi.fans')
    expect(out).toContain('href="https://meshharbor.itachi.fans/docs/x/"')
    expect(out).toContain('src="https://meshharbor.itachi.fans/docs/assets/a.png"')
    expect(out).toContain('href="//cdn.example/y"')
    expect(out).toContain('href="https://e.com/"')
  })

  it("drops the page's own chrome: permalinks, copy buttons, icons", () => {
    const out = feedHtml(
      '<h2 id="a">A<a class="heading-anchor" href="#a"><svg viewBox="0 0 1 1"></svg></a></h2>' +
        '<div class="code-head"><button class="code-copy" type="button"><svg></svg></button></div>',
      'https://meshharbor.itachi.fans',
    )
    expect(out).toBe('<h2 id="a">A</h2><div class="code-head"></div>')
  })
})

describe('urlset', () => {
  it('writes lastmod when known and OMITS it when not — never a stand-in date', () => {
    const xml = urlset([{ loc: 'https://meshharbor.itachi.fans/docs/', lastmod: '2026-09-01' }, { loc: 'https://meshharbor.itachi.fans/docs/tags/x/' }])
    expect(xml).toContain('<loc>https://meshharbor.itachi.fans/docs/</loc>\n    <lastmod>2026-09-01</lastmod>')
    expect(xml).toContain('<loc>https://meshharbor.itachi.fans/docs/tags/x/</loc>\n  </url>')
    expect(xml.match(/<lastmod>/g)).toHaveLength(1)
  })

  it('is well-formed: the declaration, the namespace, escaped text', () => {
    const xml = urlset([{ loc: 'https://meshharbor.itachi.fans/a?b=1&c=2' }])
    expect(xml.startsWith('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">')).toBe(true)
    expect(xml).toContain('a?b=1&amp;c=2')
    expect(xml.trimEnd().endsWith('</urlset>')).toBe(true)
  })
})

describe('sitemapIndex', () => {
  it('points at each collection, dated by its newest page', () => {
    const docs = [{ loc: 'x', lastmod: '2026-09-01' }, { loc: 'y', lastmod: '2026-09-20' }, { loc: 'z' }]
    const xml = sitemapIndex([{ loc: 'https://meshharbor.itachi.fans/sitemap-docs.xml', lastmod: newest(docs) }])
    expect(xml).toContain('<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">')
    expect(xml).toContain('<sitemap>\n    <loc>https://meshharbor.itachi.fans/sitemap-docs.xml</loc>\n    <lastmod>2026-09-20</lastmod>')
  })

  it('leaves a child undated when none of its pages is dated', () => {
    expect(newest([{ loc: 'x' }, { loc: 'y' }])).toBeUndefined()
  })
})

// FR-91 (#1880): with the blog lane on, the image no longer knows the blog's
// newest date, so the index lists the blog child UNDATED and unconditionally.
describe('sitemapChildren', () => {
  const O = 'https://meshharbor.itachi.fans'
  const docs = [{ loc: `${O}/`, lastmod: '2026-10-01' }, { loc: `${O}/docs/`, lastmod: '2026-10-05' }]
  const blog = [{ loc: `${O}/blog/`, lastmod: '2026-09-29' }]

  it('lane off, no posts: the docs child only (what the site was before the blog)', () => {
    expect(sitemapChildren(O, docs, [], { hasBlog: false, blogLane: false })).toEqual([
      { loc: `${O}/sitemap-docs.xml`, lastmod: '2026-10-05' },
    ])
  })

  it('lane off, with posts: the blog child dated by its newest post (FR-87, unchanged)', () => {
    expect(sitemapChildren(O, docs, blog, { hasBlog: true, blogLane: false })).toEqual([
      { loc: `${O}/sitemap-docs.xml`, lastmod: '2026-10-05' },
      { loc: `${O}/sitemap-blog.xml`, lastmod: '2026-09-29' },
    ])
  })

  it('lane on: the blog child is listed WITHOUT a lastmod, posts or not', () => {
    for (const hasBlog of [true, false]) {
      const children = sitemapChildren(O, docs, hasBlog ? blog : [], { hasBlog, blogLane: true })
      expect(children).toEqual([{ loc: `${O}/sitemap-docs.xml`, lastmod: '2026-10-05' }, { loc: `${O}/sitemap-blog.xml` }])
      expect(sitemapIndex(children)).toContain('<loc>https://meshharbor.itachi.fans/sitemap-blog.xml</loc>\n  </sitemap>')
    }
  })
})

describe('robots.txt', () => {
  it('names the sitemap index and keeps the app out', () => {
    const txt = robotsTxt('https://meshharbor.itachi.fans')
    expect(txt).toContain('Sitemap: https://meshharbor.itachi.fans/sitemap.xml')
    expect(txt).toContain('Disallow: /tenant/')
    expect(txt).not.toMatch(/Disallow: \/(docs|blog)/)
  })
})

describe('xmlEscape', () => {
  it('escapes the five XML specials', () => {
    expect(xmlEscape(`<a href="x">'&'</a>`)).toBe('&lt;a href=&quot;x&quot;&gt;&apos;&amp;&apos;&lt;/a&gt;')
  })
})
