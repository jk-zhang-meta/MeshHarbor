// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-87 (#1776) — the JSON-LD builders.
 */
import { describe, expect, it } from 'vitest'
import { AUTHORS, ORG } from '../site.ts'
import {
  blog,
  BLOG_ID,
  blogPosting,
  breadcrumbList,
  collectionPage,
  graph,
  jsonLdScript,
  organization,
  techArticle,
} from '../theme/structured.ts'

describe('the blog (P4)', () => {
  const post = {
    url: 'https://meshharbor.itachi.fans/blog/a/',
    headline: 'A',
    description: 'd',
    datePublished: '2026-09-25T22:45:13Z',
    dateModified: '2026-09-28T20:52:50Z',
    image: { url: 'https://meshharbor.itachi.fans/docs/assets/a.0123456789.png', width: 1200, height: 630 },
    author: AUTHORS.goran!,
    keywords: ['teamviewer'],
  }

  it('credits a PERSON as author and the Organization as publisher', () => {
    const p = blogPosting(post)
    expect(p.author).toEqual({ '@type': 'Person', name: 'Goran Jovanov', url: 'https://github.com/gjovanov', sameAs: AUTHORS.goran!.sameAs })
    expect((p.publisher as { '@id': string })['@id']).toBe(ORG.id)
  })

  it('carries the share image with its size, both dates, and the blog it belongs to', () => {
    expect(blogPosting(post)).toMatchObject({
      '@type': 'BlogPosting',
      image: { '@type': 'ImageObject', width: 1200, height: 630 },
      datePublished: '2026-09-25T22:45:13Z',
      dateModified: '2026-09-28T20:52:50Z',
      isPartOf: { '@type': 'Blog', '@id': BLOG_ID },
    })
  })

  it('names a syndicated copy as the same work, and only when there is one', () => {
    expect(blogPosting({ ...post, sameAs: ['https://medium.com/@gjovanov/a'] }).sameAs).toEqual(['https://medium.com/@gjovanov/a'])
    expect('sameAs' in blogPosting(post)).toBe(false)
  })

  it('lists the posts on the blog index', () => {
    const b = blog({ url: 'https://meshharbor.itachi.fans/blog/', description: 'x', posts: [{ url: post.url, headline: 'A', datePublished: post.datePublished }] })
    expect(b).toMatchObject({ '@type': 'Blog', '@id': BLOG_ID, blogPost: [{ '@type': 'BlogPosting', headline: 'A' }] })
  })
})

describe('the publisher', () => {
  it('is ONE Organization with the legal name every other record uses', () => {
    const org = organization()
    expect(org['@id']).toBe('https://meshharbor.itachi.fans/#organization')
    expect(org.legalName).toBe('G ROX EOOD')
    expect(JSON.stringify(org)).not.toContain('LTD')
  })

  it('is what every article points at, by @id', () => {
    const a = techArticle({ url: 'https://meshharbor.itachi.fans/docs/x/', headline: 'X', description: 'd', image: 'https://meshharbor.itachi.fans/i.png', keywords: [] })
    expect((a.author as { '@id': string })['@id']).toBe(ORG.id)
    expect((a.publisher as { '@id': string })['@id']).toBe(ORG.id)
  })
})

describe('techArticle', () => {
  const base = { url: 'https://meshharbor.itachi.fans/docs/x/', headline: 'X', description: 'd', image: 'https://meshharbor.itachi.fans/i.png', keywords: ['a', 'b'] }

  it('carries the dates it knows and omits the ones it does not', () => {
    expect(techArticle({ ...base, datePublished: '2026-09-01', dateModified: '2026-09-02' })).toMatchObject({
      datePublished: '2026-09-01',
      dateModified: '2026-09-02',
    })
    const undated = techArticle(base)
    expect('datePublished' in undated).toBe(false)
    expect('dateModified' in undated).toBe(false)
  })

  it('names its own page as the main entity', () => {
    expect(techArticle(base)).toMatchObject({ mainEntityOfPage: base.url, '@id': `${base.url}#article`, keywords: 'a, b' })
  })
})

describe('the rest', () => {
  it('numbers breadcrumbs from 1 with absolute URLs', () => {
    const b = breadcrumbList([{ name: 'Docs', url: '/docs/' }, { name: 'Compare', url: '/docs/compare/' }])
    expect(b.itemListElement).toEqual([
      { '@type': 'ListItem', position: 1, name: 'Docs', item: 'https://meshharbor.itachi.fans/docs/' },
      { '@type': 'ListItem', position: 2, name: 'Compare', item: 'https://meshharbor.itachi.fans/docs/compare/' },
    ])
  })

  it('describes a listing as a CollectionPage, not an article', () => {
    expect(collectionPage({ url: 'u', name: 'n', description: 'd' })['@type']).toBe('CollectionPage')
  })

  it('wraps a page in one graph', () => {
    expect(graph([organization()])).toEqual({ '@context': 'https://schema.org', '@graph': [organization()] })
  })

  it('cannot be closed early by a `</script>` inside the data', () => {
    const html = jsonLdScript({ headline: 'a </script><script>alert(1)</script>' })
    expect(html.match(/<\/script>/g)).toHaveLength(1)
    expect(html).toContain('\\u003c/script>')
  })
})
