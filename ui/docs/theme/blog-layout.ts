// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-87 (#1776) — the blog's pages: a post, the index (and its later pages)
 * and a tag listing, on the same shell as the docs.
 *
 * A post is written to be READ, so the page is one column with the table of
 * contents beside it, and no docs sidebar: the reader arrived from a search
 * result or a link, not from the docs' navigation.
 */
import { BASE, BLOG_BASE, BLOG_DESCRIPTION, BLOG_TITLE, SITE_ORIGIN } from '../site.ts'
import { icon } from './icons.ts'
import { indexPageUrl, lastTouched, type Post } from './posts.ts'
import { escapeHtml, type Heading } from './render.ts'
import {
  fitTitle,
  FEED_URL,
  renderBodyScripts,
  renderFooter,
  renderHead,
  renderSearchDialog,
  renderTopbar,
  type OgImage,
  type ShellNav,
  type SiteAssets,
} from './shell.ts'
import { blog, blogPosting, breadcrumbList, graph, organization, type Crumb } from './structured.ts'

export interface BlogCtx {
  assets: SiteAssets
  nav: ShellNav
  /** Tags with a listing page (at MIN_POSTS_PER_TAG_INDEX or more posts). */
  tagIndexed: Set<string>
  /** The share image of a listing page (index, tag). Absent = the site's
   *  default under `/docs/assets/`; FR-91's blog-only build names its own copy
   *  under `/blog/assets/`, so the lane never depends on the image's assets. */
  ogImage?: OgImage
}

const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December']

/** `2026-09-25T22:45:13Z` → `25 September 2026`, from the date AS WRITTEN:
 *  no locale data and no time-zone arithmetic, so every build agrees. */
export function formatDate(iso: string): string {
  const [y, m, d] = iso.slice(0, 10).split('-')
  return `${Number(d)} ${MONTHS[Number(m) - 1]} ${y}`
}

/** `https://medium.com/@x/y` → `Medium`. */
export function siteLabel(url: string): string {
  const host = new URL(url).hostname.replace(/^www\./, '')
  if (host === 'medium.com' || host.endsWith('.medium.com')) return 'Medium'
  if (host === 'github.com') return 'GitHub'
  return host
}

export function postTitle(post: Post): string {
  return post.seoTitle ?? fitTitle([`${post.title} — ${BLOG_TITLE}`, post.title]) ?? post.title
}

function crumbsHtml(crumbs: Crumb[]): string {
  return `<nav class="crumbs" aria-label="Breadcrumb"><ol>${crumbs
    .map((t, i) =>
      i === crumbs.length - 1
        ? `<li aria-current="page">${escapeHtml(t.name)}</li>`
        : `<li><a href="${t.url}">${escapeHtml(t.name)}</a>${icon('chevronRight', { size: 14, cls: 'crumbs__sep' })}</li>`,
    )
    .join('')}</ol></nav>`
}

function tocHtml(headings: Heading[]): string {
  const items = headings.filter((h) => h.level === 2 || h.level === 3)
  if (items.length < 2) return ''
  return (
    `<nav class="toc" aria-label="In this post"><p class="toc__head">In this post</p><ul>` +
    items.map((h) => `<li class="toc__item toc__item--h${h.level}"><a href="#${h.slug}">${escapeHtml(h.text)}</a></li>`).join('') +
    `</ul></nav>`
  )
}

function chips(tags: string[], tagIndexed: Set<string>): string {
  return (
    `<ul class="chips" aria-label="Tags">` +
    tags
      .map((t) =>
        tagIndexed.has(t)
          ? `<li><a class="chip chip--link" href="${BLOG_BASE}/tags/${encodeURIComponent(t)}/">${escapeHtml(t)}</a></li>`
          : `<li><span class="chip">${escapeHtml(t)}</span></li>`,
      )
      .join('') +
    `</ul>`
  )
}

function byline(post: Post): string {
  const parts = [
    `<a href="${escapeHtml(post.author.url)}" rel="author">${escapeHtml(post.author.name)}</a>`,
    `<time datetime="${post.date}">${formatDate(post.date)}</time>`,
  ]
  // "Updated" only when the day differs: a same-day fix is not news.
  if (post.updated && post.updated.slice(0, 10) !== post.date.slice(0, 10)) {
    parts.push(`updated <time datetime="${post.updated}">${formatDate(post.updated)}</time>`)
  }
  parts.push(`${post.readingMinutes} min read`)
  return `<p class="post-byline">${parts.join(' · ')}</p>`
}

function authorBox(post: Post): string {
  const links = post.author.sameAs
    .map((u) => `<a href="${escapeHtml(u)}" rel="me noopener" target="_blank">${escapeHtml(siteLabel(u))}</a>`)
    .join(' · ')
  return (
    `<aside class="author-box" aria-label="About the author">` +
    `<p class="author-box__name">Written by <a href="${escapeHtml(post.author.url)}" rel="author">${escapeHtml(post.author.name)}</a></p>` +
    (post.author.bio ? `<p class="author-box__bio">${escapeHtml(post.author.bio)}</p>` : '') +
    (links ? `<p class="author-box__links">${links}</p>` : '') +
    `</aside>`
  )
}

export interface RelatedPage {
  url: string
  title: string
  description: string
}

function relatedDocs(related: RelatedPage[]): string {
  if (related.length === 0) return ''
  return (
    `<aside class="related-docs" aria-labelledby="related-docs"><h2 class="related-docs__head" id="related-docs">Related in the docs</h2>` +
    `<div class="section-grid">${related
      .map(
        (r) =>
          `<a class="section-card" href="${r.url}"><h3 class="section-card__title">${escapeHtml(r.title)}</h3>` +
          `<p class="section-card__blurb">${escapeHtml(r.description)}</p></a>`,
      )
      .join('')}</div></aside>`
  )
}

const CTA =
  `<aside class="post-cta" aria-label="Try MeshHarbor">` +
  `<p class="post-cta__title">Run it yourself</p>` +
  `<p>MeshHarbor is open source: host it on your own server with Docker Compose, or start on the hosted version.</p>` +
  `<p class="post-cta__actions"><a class="btn btn--primary" href="${BASE}/start/self-hosting/">Self-host MeshHarbor</a> ` +
  `<a class="btn btn--tonal" href="/register">Get started free</a></p></aside>`

function postPager(newer?: Post, older?: Post): string {
  if (!newer && !older) return ''
  const left = newer
    ? `<a class="pager__link pager__link--prev" href="${newer.url}">${icon('arrowLeft', { size: 18 })}<span><span class="pager__dir">Newer</span><span class="pager__title">${escapeHtml(newer.title)}</span></span></a>`
    : '<span></span>'
  const right = older
    ? `<a class="pager__link pager__link--next" href="${older.url}"><span><span class="pager__dir">Older</span><span class="pager__title">${escapeHtml(older.title)}</span></span>${icon('arrowRight', { size: 18 })}</a>`
    : '<span></span>'
  return `<nav class="pager" aria-label="More posts">${left}${right}</nav>`
}

function page(head: string, ctx: BlogCtx, main: string, toc = ''): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
${head}
</head>
<body>
<a class="skip-link" href="#main">Skip to content</a>

${renderTopbar(ctx.nav, ctx.assets.logo)}

<div class="layout layout--blog">
  <main id="main" class="content content--blog">
${main}
  </main>

  <aside class="toc-rail">${toc}</aside>
</div>

${renderFooter(ctx.nav)}

${renderSearchDialog(ctx.assets, ctx.nav)}

${renderBodyScripts(ctx.assets)}
</body>
</html>
`
}

export interface PostCtx extends BlogCtx {
  post: Post
  newer?: Post
  older?: Post
  related: RelatedPage[]
}

export function renderPost(ctx: PostCtx): string {
  const { post } = ctx
  const self = `${SITE_ORIGIN}${post.url}`
  const crumbs: Crumb[] = [
    { name: 'Blog', url: `${BLOG_BASE}/` },
    { name: post.title, url: post.url },
  ]
  const modified = lastTouched(post)
  const head = renderHead({
    title: postTitle(post),
    description: post.description,
    // A post whose original lives elsewhere names it; one published here is
    // its own canonical (and the syndicated copy points back at it).
    canonical: post.canonical ?? self,
    noindex: false,
    og: { type: 'article', title: post.title, image: post.og },
    article: { published: post.date, modified, tags: post.tags, author: post.author.url },
    jsonLd: graph([
      organization(),
      blogPosting({
        url: self,
        headline: post.title,
        description: post.description,
        datePublished: post.date,
        dateModified: modified,
        image: post.og,
        author: post.author,
        keywords: post.tags,
        sameAs: post.syndication ? [post.syndication] : undefined,
      }),
      breadcrumbList(crumbs),
    ]),
    assets: ctx.assets,
    feed: true,
  })

  const hero = post.heroImage
    ? `<figure class="hero"><img src="${escapeHtml(post.heroImage.url)}" alt="${escapeHtml(post.heroAlt ?? '')}" ` +
      `width="${post.heroImage.width}" height="${post.heroImage.height}" loading="eager" fetchpriority="high" decoding="async"></figure>`
    : ''
  const syndication = post.syndication
    ? `<p class="post-syndication">Also published on <a href="${escapeHtml(post.syndication)}">${escapeHtml(siteLabel(post.syndication))}</a>.</p>`
    : ''

  const main = `    ${crumbsHtml(crumbs)}
    <article class="post">
      <header class="post-head">
        <h1 class="page-title">${escapeHtml(post.title)}</h1>
        ${post.subtitle ? `<p class="post-dek">${escapeHtml(post.subtitle)}</p>` : ''}
        ${byline(post)}
        ${chips(post.tags, ctx.tagIndexed)}
      </header>
      ${hero}
      <div class="prose">
${post.html}
      </div>
      ${syndication}
      ${authorBox(post)}
      ${relatedDocs(ctx.related)}
      ${CTA}
      ${postPager(ctx.newer, ctx.older)}
    </article>`
  return page(head, ctx, main, tocHtml(post.headings))
}

function postCard(post: Post): string {
  return (
    `<li class="post-card"><a href="${post.url}">` +
    `<h2 class="post-card__title">${escapeHtml(post.title)}</h2>` +
    `<p class="post-card__dek">${escapeHtml(post.subtitle ?? post.description)}</p>` +
    `<p class="post-card__meta"><time datetime="${post.date}">${formatDate(post.date)}</time> · ${post.readingMinutes} min read</p>` +
    `</a></li>`
  )
}

export interface IndexCtx extends BlogCtx {
  posts: Post[]
  /** 1-based. */
  pageNo: number
  pages: number
}

/** The whole `<title>` of index page N; page 1 carries the keywords. */
export function indexTitle(pageNo: number): string {
  return pageNo <= 1 ? `${BLOG_TITLE} — remote desktop, mesh network, self-hosting` : `${BLOG_TITLE} — page ${pageNo}`
}

export function renderBlogIndex(ctx: IndexCtx): string {
  const url = indexPageUrl(ctx.pageNo)
  const self = `${SITE_ORIGIN}${url}`
  const prevUrl = ctx.pageNo > 1 ? indexPageUrl(ctx.pageNo - 1) : undefined
  const nextUrl = ctx.pageNo < ctx.pages ? indexPageUrl(ctx.pageNo + 1) : undefined
  const head = renderHead({
    title: indexTitle(ctx.pageNo),
    description: BLOG_DESCRIPTION,
    canonical: self,
    noindex: false,
    og: { type: 'website', title: BLOG_TITLE, image: ctx.ogImage },
    jsonLd: graph([
      organization(),
      blog({
        url: `${SITE_ORIGIN}${BLOG_BASE}/`,
        description: BLOG_DESCRIPTION,
        posts: ctx.posts.map((p) => ({ url: `${SITE_ORIGIN}${p.url}`, headline: p.title, datePublished: p.date })),
      }),
    ]),
    assets: ctx.assets,
    feed: true,
    prevUrl,
    nextUrl,
  })
  const pager =
    ctx.pages > 1
      ? `<nav class="blog-pages" aria-label="Pages">` +
        (prevUrl ? `<a href="${prevUrl}">${icon('arrowLeft', { size: 16 })} Newer posts</a>` : '<span></span>') +
        `<span>Page ${ctx.pageNo} of ${ctx.pages}</span>` +
        (nextUrl ? `<a href="${nextUrl}">Older posts ${icon('arrowRight', { size: 16 })}</a>` : '<span></span>') +
        `</nav>`
      : ''
  const main = `    <h1 class="page-title">${escapeHtml(BLOG_TITLE)}</h1>
    <p class="page-lead">${escapeHtml(BLOG_DESCRIPTION)}</p>
    <p class="feed-link"><a href="${FEED_URL}">Subscribe with RSS</a></p>
    <ol class="post-list">${ctx.posts.map(postCard).join('')}</ol>
    ${pager}`
  return page(head, ctx, main)
}

export interface TagCtx extends BlogCtx {
  tag: string
  posts: Post[]
}

export function renderBlogTag(ctx: TagCtx): string {
  const url = `${BLOG_BASE}/tags/${encodeURIComponent(ctx.tag)}/`
  const crumbs: Crumb[] = [
    { name: 'Blog', url: `${BLOG_BASE}/` },
    { name: ctx.tag, url },
  ]
  const head = renderHead({
    title: fitTitle([`Posts tagged “${ctx.tag}” — ${BLOG_TITLE}`, `Posts tagged “${ctx.tag}”`]) ?? ctx.tag,
    description: `Every post on the ${BLOG_TITLE} tagged “${ctx.tag}”.`,
    canonical: `${SITE_ORIGIN}${url}`,
    noindex: false,
    og: { type: 'website', title: `Posts tagged “${ctx.tag}”`, image: ctx.ogImage },
    jsonLd: graph([organization(), breadcrumbList(crumbs)]),
    assets: ctx.assets,
    feed: true,
  })
  const main = `    ${crumbsHtml(crumbs)}
    <h1 class="page-title">Posts tagged “${escapeHtml(ctx.tag)}”</h1>
    <ol class="post-list">${ctx.posts.map(postCard).join('')}</ol>`
  return page(head, ctx, main)
}
