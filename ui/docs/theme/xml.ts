// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-87 (#1776) — the site-root files a crawler reads first: the sitemap
 * index, its urlsets, and robots.txt.
 *
 * `/sitemap.xml` is an INDEX over one urlset per collection
 * (`sitemap-docs.xml`, and `sitemap-blog.xml` once a post exists), so
 * Search Console reports indexing per collection instead of as one number.
 *
 * FR-60's sitemap also listed five SPA routes (`/landing`, `/pricing`,
 * `/privacy`, `/terms`, `/imprint`) whose served canonical is `/`. Asking a
 * crawler to index a URL that names another URL as its canonical is a
 * contradiction Search Console reports as "Duplicate, submitted URL not
 * selected as canonical". They are gone.
 */

export interface UrlEntry {
  /** Absolute URL. */
  loc: string
  /** `YYYY-MM-DD`, or absent when unknown — never the build date. */
  lastmod?: string
}

export function xmlEscape(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
}

function entry(tag: 'url' | 'sitemap', u: UrlEntry): string {
  return (
    `  <${tag}>\n    <loc>${xmlEscape(u.loc)}</loc>\n` +
    (u.lastmod ? `    <lastmod>${u.lastmod}</lastmod>\n` : '') +
    `  </${tag}>`
  )
}

const HEADER = `<?xml version="1.0" encoding="UTF-8"?>\n`
const NS = 'http://www.sitemaps.org/schemas/sitemap/0.9'

export function urlset(urls: UrlEntry[]): string {
  return `${HEADER}<urlset xmlns="${NS}">\n${urls.map((u) => entry('url', u)).join('\n')}\n</urlset>\n`
}

/** A child's `lastmod` is its newest page's, and absent when none is dated. */
export function newest(urls: UrlEntry[]): string | undefined {
  return urls.reduce<string | undefined>((max, u) => (u.lastmod && (!max || u.lastmod > max) ? u.lastmod : max), undefined)
}

/**
 * The index's children: the docs urlset always, dated by its newest page; the
 * blog's once a post exists, dated the same way.
 *
 * FR-91: with the blog lane on (`BLOG_LANE`), the blog is published without
 * this image, so the image cannot know the blog's newest date. The child is
 * then listed unconditionally and WITHOUT a `lastmod`: a stale date teaches a
 * crawler to distrust the field, and none is honest.
 */
export function sitemapChildren(
  origin: string,
  docsUrls: UrlEntry[],
  blogUrls: UrlEntry[],
  opts: { hasBlog: boolean; blogLane: boolean },
): UrlEntry[] {
  const children: UrlEntry[] = [{ loc: `${origin}/sitemap-docs.xml`, lastmod: newest(docsUrls) }]
  if (opts.blogLane) children.push({ loc: `${origin}/sitemap-blog.xml` })
  else if (opts.hasBlog) children.push({ loc: `${origin}/sitemap-blog.xml`, lastmod: newest(blogUrls) })
  return children
}

export function sitemapIndex(children: UrlEntry[]): string {
  return `${HEADER}<sitemapindex xmlns="${NS}">\n${children.map((c) => entry('sitemap', c)).join('\n')}\n</sitemapindex>\n`
}

// ── the Atom feed (FR-87 P4) ─────────────────────────────────────────────

export interface FeedEntry {
  /** Permanent: the post's absolute URL, which never changes once published. */
  id: string
  url: string
  title: string
  summary: string
  /** Full post HTML, already made feed-safe by `feedHtml`. */
  contentHtml: string
  /** RFC 3339 timestamps. */
  published: string
  updated: string
  author: { name: string; uri?: string }
  tags: string[]
}

export interface FeedInput {
  id: string
  /** The feed's own URL (`rel="self"`). */
  selfUrl: string
  /** The HTML page it mirrors (`rel="alternate"`). */
  htmlUrl: string
  title: string
  subtitle: string
  updated: string
  entries: FeedEntry[]
}

/** Atom 1.0 with full content. Every entry names its author, so the feed
 *  itself need not (RFC 4287 §4.1.1). */
export function atomFeed(f: FeedInput): string {
  const e = xmlEscape
  const entries = f.entries.map(
    (x) =>
      `  <entry>\n` +
      `    <id>${e(x.id)}</id>\n` +
      `    <title>${e(x.title)}</title>\n` +
      `    <link rel="alternate" type="text/html" href="${e(x.url)}"/>\n` +
      `    <published>${x.published}</published>\n` +
      `    <updated>${x.updated}</updated>\n` +
      `    <author><name>${e(x.author.name)}</name>${x.author.uri ? `<uri>${e(x.author.uri)}</uri>` : ''}</author>\n` +
      x.tags.map((t) => `    <category term="${e(t)}"/>\n`).join('') +
      `    <summary>${e(x.summary)}</summary>\n` +
      `    <content type="html">${e(x.contentHtml)}</content>\n` +
      `  </entry>`,
  )
  return (
    `<?xml version="1.0" encoding="utf-8"?>\n` +
    `<feed xmlns="http://www.w3.org/2005/Atom" xml:lang="en">\n` +
    `  <id>${e(f.id)}</id>\n` +
    `  <title>${e(f.title)}</title>\n` +
    `  <subtitle>${e(f.subtitle)}</subtitle>\n` +
    `  <link rel="self" type="application/atom+xml" href="${e(f.selfUrl)}"/>\n` +
    `  <link rel="alternate" type="text/html" href="${e(f.htmlUrl)}"/>\n` +
    `  <updated>${f.updated}</updated>\n` +
    entries.map((x) => `${x}\n`).join('') +
    `</feed>\n`
  )
}

/**
 * A post's HTML as a feed reader should get it: links and images absolute
 * (a reader resolves nothing against our origin), and the page's own chrome
 * gone — heading permalinks, copy buttons and inline icons mean nothing
 * outside the page and render as clutter.
 */
export function feedHtml(html: string, origin: string): string {
  return html
    .replace(/<a class="heading-anchor"[^>]*>[\s\S]*?<\/a>/g, '')
    .replace(/<button class="code-copy"[^>]*>[\s\S]*?<\/button>/g, '')
    .replace(/<svg\b[\s\S]*?<\/svg>/g, '')
    .replace(/\b(href|src)="\/(?!\/)/g, `$1="${origin}/`)
}

export function robotsTxt(origin: string): string {
  return (
    `# MeshHarbor — ${origin}\n` +
    `User-agent: *\n` +
    `Allow: /\n` +
    `# The application itself is behind auth and client-rendered; there is\n` +
    `# nothing there for a crawler, and tenant ids should not be enumerated.\n` +
    `Disallow: /tenant/\n` +
    `Disallow: /oauth/\n` +
    `Disallow: /consent/\n` +
    `Disallow: /invite/\n` +
    `\n` +
    `Sitemap: ${origin}/sitemap.xml\n`
  )
}
