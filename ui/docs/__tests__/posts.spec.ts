// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-87 (#1776) — what a blog post must declare. Each gate is tripped here
 * by the front-matter that should trip it, next to a post that passes.
 */
import { describe, expect, it } from 'vitest'
import { parseFrontmatter } from '../theme/frontmatter.ts'
import {
  docsBacklinks,
  indexPageUrl,
  paginate,
  readingMinutes,
  readPostMeta,
  sortPosts,
} from '../theme/posts.ts'

const NOW = new Date('2026-09-29T12:00:00Z')

const VALID = [
  'title: My wife’s swearing at TeamViewer made me build my own remote desktop tool',
  'seoTitle: Self-hosted TeamViewer alternative: why I built MeshHarbor',
  'subtitle: An open-source, self-hosted TeamViewer alternative',
  'description: Why I built MeshHarbor, an open-source TeamViewer alternative with remote desktop from any browser tab.',
  'date: 2026-09-25T22:45:13Z',
  'author: goran',
  'tags: [teamviewer, remote-desktop]',
  'hero: remote-desktop.svg',
  'heroAlt: A browser tab showing a remote desktop',
  'ogImage: teamviewer-og.png',
  'related: [/docs/compare/teamviewer/]',
  'syndication: https://medium.com/@gjovanov/x',
]

function meta(lines: string[], slug = 'self-hosted-teamviewer-alternative') {
  const { data } = parseFrontmatter(`---\n${lines.join('\n')}\n---\nBody.\n`, 'p.md')
  return readPostMeta(data, slug, 'p.md', NOW)
}
const without = (key: string) => VALID.filter((l) => !l.startsWith(`${key}:`))
const replace = (key: string, value: string) => [...without(key), `${key}: ${value}`]

describe('readPostMeta', () => {
  it('accepts a complete post', () => {
    const r = meta(VALID)
    expect(r.errors).toEqual([])
    expect(r.meta).toMatchObject({ slug: 'self-hosted-teamviewer-alternative', author: { name: 'Goran Jovanov' }, tags: ['teamviewer', 'remote-desktop'] })
  })

  it.each(['title', 'description', 'date', 'author', 'tags'])('requires `%s`', (key) => {
    expect(meta(without(key)).errors.join('\n')).toContain(`\`${key}\` is required`)
  })

  it('requires alt text for a hero', () => {
    expect(meta(without('heroAlt')).errors.join('\n')).toContain('`heroAlt` is required')
  })

  it('always needs a RASTER share image', () => {
    // An SVG hero is not one…
    expect(meta(without('ogImage')).errors.join('\n')).toMatch(/not a raster image.*ogImage/)
    // …a PNG hero is…
    expect(meta([...without('ogImage').filter((l) => !l.startsWith('hero:')), 'hero: hero.png']).errors).toEqual([])
    // …and ogImage cannot be an SVG either.
    expect(meta(replace('ogImage', 'card.svg')).errors.join('\n')).toMatch(/must be a PNG, JPEG, WebP or GIF/)
  })

  it('takes a post with no hero — its first image stays in the text — given a share image and its alt', () => {
    const noHero = VALID.filter((l) => !l.startsWith('hero:') && !l.startsWith('heroAlt:'))
    expect(meta(noHero).errors.join('\n')).toMatch(/`ogImageAlt` is required/)
    expect(meta([...noHero, 'ogImageAlt: A browser tab showing a remote desktop']).errors).toEqual([])
    expect(meta(noHero.filter((l) => !l.startsWith('ogImage:'))).errors.join('\n')).toMatch(/no hero needs `ogImage:`/)
  })

  it('has no drafts: `draft` is refused with the reason', () => {
    expect(meta([...VALID, 'draft: true']).errors.join('\n')).toMatch(/IS published.*promo repo/)
  })

  it('refuses an unknown key', () => {
    expect(meta([...VALID, 'heroalt: typo']).errors.join('\n')).toContain('unknown frontmatter key `heroalt`')
  })

  it('refuses a bare date, a future date, and an update before the post', () => {
    expect(meta(replace('date', '2026-09-25')).errors.join('\n')).toMatch(/ISO 8601 timestamp/)
    expect(meta(replace('date', '2026-10-01T00:00:00Z')).errors.join('\n')).toMatch(/in the future.*no scheduling/)
    expect(meta([...VALID, 'updated: 2026-09-20T00:00:00Z']).errors.join('\n')).toMatch(/`updated` .* is before `date`/)
    expect(meta([...VALID, 'updated: 2026-09-28T20:52:50Z']).errors).toEqual([])
  })

  it('refuses an author nobody declared', () => {
    expect(meta(replace('author', 'nobody')).errors.join('\n')).toMatch(/author "nobody" is not in AUTHORS/)
  })

  it('caps seoTitle at 60 and description at 160', () => {
    expect(meta(replace('seoTitle', 'x'.repeat(61))).errors.join('\n')).toMatch(/seoTitle.*61 chars/)
    expect(meta(replace('description', 'x'.repeat(161))).errors.join('\n')).toMatch(/description.*161 chars/)
  })

  it('wants related pages site-absolute, and copies and canonicals off-site over https', () => {
    expect(meta(replace('related', '[docs/compare/]')).errors.join('\n')).toMatch(/site-absolute/)
    expect(meta(replace('syndication', 'http://medium.com/x')).errors.join('\n')).toMatch(/https:\/\//)
    expect(meta([...VALID, 'canonical: https://meshharbor.itachi.fans/blog/x/']).errors.join('\n')).toMatch(/its own canonical/)
    expect(meta([...VALID, 'canonical: https://example.com/original/']).errors).toEqual([])
  })

  it('refuses a file name that cannot be a URL', () => {
    expect(meta(VALID, 'My Post').errors.join('\n')).toMatch(/kebab-case/)
  })

  it('reports every problem in one pass', () => {
    // draft, description, author, tags, the bare date, the missing share image
    expect(meta(['title: T', 'draft: true', 'date: 2026-09-25']).errors.length).toBeGreaterThanOrEqual(6)
  })

  // FR-91: a post that shows an install command declares it, and joins
  // INSTALL_PAGES for the build (build.ts). Absent means no; only a real
  // boolean is accepted, so `installCopy: yes` cannot silently mean false.
  it('reads `installCopy` as a boolean, false when absent', () => {
    expect(meta(VALID).meta?.installCopy).toBe(false)
    expect(meta([...VALID, 'installCopy: true']).meta?.installCopy).toBe(true)
    expect(meta([...VALID, 'installCopy: false']).meta?.installCopy).toBe(false)
    expect(meta([...VALID, 'installCopy: "yes"']).errors.join('\n')).toMatch(/`installCopy` must be `true` or `false`/)
  })
})

describe('ordering and paging', () => {
  it('sorts newest first by INSTANT, not by string', () => {
    // 00:30 at +02:00 on the 26th is 22:30 UTC on the 25th — before 22:45.
    const posts = sortPosts([
      { slug: 'a', date: '2026-09-26T00:30:00+02:00' },
      { slug: 'b', date: '2026-09-25T22:45:13Z' },
    ])
    expect(posts.map((p) => p.slug)).toEqual(['b', 'a'])
  })

  it('pages by ten, with page 1 at /blog/', () => {
    expect(paginate(Array.from({ length: 23 }, (_, i) => i), 10).map((p) => p.length)).toEqual([10, 10, 3])
    expect(paginate([], 10)).toEqual([[]])
    expect(indexPageUrl(1)).toBe('/blog/')
    expect(indexPageUrl(2)).toBe('/blog/page/2/')
  })

  it('estimates reading time from words, never below a minute', () => {
    expect(readingMinutes('word '.repeat(460))).toBe(2)
    expect(readingMinutes('a few words')).toBe(1)
  })
})

describe('docsBacklinks', () => {
  it('maps each docs page to the posts that link it, by body link or `related`', () => {
    const post = {
      html: '<a href="/docs/a/">a</a><a href="/docs/b#x">b</a><a href="/docs/assets/x.png">file</a><a href="/blog/other/">post</a>',
      related: ['/docs/c/'],
    }
    const map = docsBacklinks([post], '/docs')
    expect([...map.keys()].sort()).toEqual(['/docs/a/', '/docs/b/', '/docs/c/'])
    expect(map.get('/docs/a/')).toEqual([post])
  })
})
