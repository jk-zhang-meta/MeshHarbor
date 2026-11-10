// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-60 (#1165) — the documentation page: sidebar, content, table of
 * contents, on the shared shell (`shell.ts`, FR-87).
 *
 * Everything a crawler reads is emitted statically, per page: a unique
 * <title> that fits, a real <meta name="description">, an ABSOLUTE
 * canonical, OG/Twitter tags and JSON-LD. The SPA next door has none of these
 * — one `<title>MeshHarbor</title>` for every public route — which is the gap
 * FR-60 exists to close.
 */
import { BASE, SITE_ORIGIN, SITE_TITLE_SUFFIX, type SectionDef } from '../site.ts'
import { icon } from './icons.ts'
import { escapeHtml, type Heading, type PageVideo, type ResolvedImage } from './render.ts'
import {
  DEFAULT_OG_IMAGE,
  DOCS_NAV,
  fitTitle,
  renderBodyScripts,
  renderFooter,
  renderHead,
  renderSearchDialog,
  renderTopbar,
  type OgImage,
  type ShellNav,
  type SiteAssets,
} from './shell.ts'
import { breadcrumbList, collectionPage, graph, organization, techArticle, videoObject, type Crumb } from './structured.ts'

export type { SiteAssets } from './shell.ts'

export interface DocPage {
  /** Path under content/, without extension: `start/install/windows`. */
  slug: string
  /** Site-absolute URL with a trailing slash: `/docs/start/install/windows/`. */
  url: string
  /** Output path relative to the docs root. */
  outFile: string
  section?: SectionDef
  title: string
  /** The whole `<title>`, when the author set one (≤ MAX_TITLE_CHARS). */
  seoTitle?: string
  description: string
  tags: string[]
  order: number
  hero?: ResolvedImage
  heroAlt?: string
  noindex: boolean
  /** Rendered body HTML. */
  html: string
  headings: Heading[]
  /** FR-88 P3: the `:::video` embeds, for the page's VideoObject nodes. */
  videos?: PageVideo[]
  /** Body as plain text, for the search index. */
  plain: string
  /** Emit FAQPage structured data from this page's h2s. */
  faq: boolean
  /** When the content last changed — an ISO 8601 timestamp from git, or the
   *  front-matter `updated` (a date or a timestamp) — else the dates
   *  manifest. UNDEFINED when none of them knows, and then no date is
   *  published at all — never the build date (FR-87). */
  lastmod?: string
  /** When the source file first appeared in git, when known (a timestamp). */
  created?: string
  /** The 404 page: no canonical, no structured data, never indexed. */
  notFound?: boolean
  /** Path under `content/` this page was authored from, without extension.
   *  Absent for GENERATED pages — tag indexes, and a section index nobody
   *  wrote. Those must not offer "Edit this page": the link would point at
   *  a file that does not exist, which is a 404 shipped on 32 pages. */
  sourceFile?: string
}

export interface NavSection {
  section: SectionDef
  pages: DocPage[]
}

export interface LayoutCtx {
  nav: NavSection[]
  page: DocPage
  assets: SiteAssets
  /** The site-wide chrome; defaults to docs with no blog. */
  site?: ShellNav
  /** Posts that link to this page (FR-87): shown as "On the blog". */
  onTheBlog?: Array<{ url: string; title: string }>
  prev?: DocPage
  next?: DocPage
  /** The page's share image. Absent = the site's default under `/docs/assets/`;
   *  FR-91's blog lane renders its 404 page with its own copy. */
  ogImage?: OgImage
}

function onTheBlogHtml(posts: Array<{ url: string; title: string }> | undefined): string {
  if (!posts?.length) return ''
  return (
    `<aside class="on-the-blog" aria-label="On the blog"><p class="on-the-blog__head">On the blog</p><ul>` +
    posts.map((p) => `<li><a href="${p.url}">${escapeHtml(p.title)}</a></li>`).join('') +
    `</ul></aside>`
  )
}

/** A page whose content is a list of other pages: it is a `website`, not an
 *  `article`, to Open Graph, and a CollectionPage to schema.org. */
export function isListing(page: DocPage): boolean {
  return (
    page.slug === 'index' ||
    page.slug.startsWith('tags/') ||
    (page.section !== undefined && page.url === `${BASE}/${page.section.dir}/`)
  )
}

/**
 * The `<title>`: the author's `seoTitle` verbatim, else the first default
 * that fits — with the section, without it, then the bare title. Null when
 * even the bare title is too long; the build turns that into an error that
 * asks for a `seoTitle` (FR-87: 8 of 65 titles ran 62–71 chars before).
 */
export function docsTitle(page: DocPage): string | null {
  if (page.seoTitle) return page.seoTitle
  if (page.slug === 'index') return fitTitle([`${SITE_TITLE_SUFFIX} — remote desktop, mesh network, chat & video`])
  const leafOfSection = page.section && !isListing(page)
  return fitTitle([
    ...(leafOfSection ? [`${page.title} · ${page.section!.title} — ${SITE_TITLE_SUFFIX}`] : []),
    `${page.title} — ${SITE_TITLE_SUFFIX}`,
    page.title,
  ])
}

function trail(page: DocPage): Crumb[] {
  const crumbs: Crumb[] = [{ name: 'Docs', url: `${BASE}/` }]
  if (page.section) crumbs.push({ name: page.section.title, url: `${BASE}/${page.section.dir}/` })
  const isSectionIndex = page.section && page.url === `${BASE}/${page.section.dir}/`
  if (!isSectionIndex && page.slug !== 'index') crumbs.push({ name: page.title, url: page.url })
  return crumbs
}

function breadcrumbHtml(crumbs: Crumb[]): string {
  if (crumbs.length <= 1) return ''
  return `<nav class="crumbs" aria-label="Breadcrumb"><ol>${crumbs
    .map((t, i) =>
      i === crumbs.length - 1
        ? `<li aria-current="page">${escapeHtml(t.name)}</li>`
        : `<li><a href="${t.url}">${escapeHtml(t.name)}</a>${icon('chevronRight', { size: 14, cls: 'crumbs__sep' })}</li>`,
    )
    .join('')}</ol></nav>`
}

function sidebar(nav: NavSection[], current: DocPage): string {
  const groups = nav
    .map(({ section, pages }) => {
      const open = current.section?.dir === section.dir
      const items = pages
        .map(
          (p) =>
            `<li><a href="${p.url}"${p.url === current.url ? ' class="is-active" aria-current="page"' : ''}>${escapeHtml(p.title)}</a></li>`,
        )
        .join('')
      return (
        `<details class="side-group"${open ? ' open' : ''}>` +
        `<summary><span class="side-group__icon side-group__icon--${section.accent}">${icon(section.icon, { size: 17 })}</span>` +
        `<span class="side-group__title">${escapeHtml(section.title)}</span>${icon('chevronDown', { size: 15, cls: 'side-group__chev' })}</summary>` +
        `<ul>${items}</ul></details>`
      )
    })
    .join('')
  return `<nav class="sidebar__nav" aria-label="Documentation sections">${groups}</nav>`
}

function tocHtml(headings: Heading[]): string {
  const items = headings.filter((h) => h.level === 2 || h.level === 3)
  if (items.length < 2) return ''
  return (
    `<nav class="toc" aria-label="On this page"><p class="toc__head">On this page</p><ul>` +
    items
      .map(
        (h) =>
          `<li class="toc__item toc__item--h${h.level}"><a href="#${h.slug}">${escapeHtml(h.text)}</a></li>`,
      )
      .join('') +
    `</ul></nav>`
  )
}

function tagChips(page: DocPage, tags: string[], tagIndexed: Set<string>): string {
  // A tag index's only tag is itself; rendering the chip there is a
  // self-link and adds nothing.
  if (tags.length === 0 || page.slug.startsWith('tags/')) return ''
  return (
    `<ul class="chips" aria-label="Tags">` +
    tags
      .map((t) => {
        const label = escapeHtml(t)
        return tagIndexed.has(t)
          ? `<li><a class="chip chip--link" href="${BASE}/tags/${encodeURIComponent(t)}/">${label}</a></li>`
          : `<li><span class="chip">${label}</span></li>`
      })
      .join('') +
    `</ul>`
  )
}

function pager(prev?: DocPage, next?: DocPage): string {
  if (!prev && !next) return ''
  const left = prev
    ? `<a class="pager__link pager__link--prev" href="${prev.url}">${icon('arrowLeft', { size: 18 })}<span><span class="pager__dir">Previous</span><span class="pager__title">${escapeHtml(prev.title)}</span></span></a>`
    : '<span></span>'
  const right = next
    ? `<a class="pager__link pager__link--next" href="${next.url}"><span><span class="pager__dir">Next</span><span class="pager__title">${escapeHtml(next.title)}</span></span>${icon('arrowRight', { size: 18 })}</a>`
    : '<span></span>'
  return `<nav class="pager" aria-label="Pagination">${left}${right}</nav>`
}

function faqJsonLd(page: DocPage): Record<string, unknown> | null {
  if (!page.faq) return null
  // Questions are the h2s; the answer is the plain text that follows one,
  // up to the next h2. Built from the SAME heading list the TOC uses, so
  // the structured data cannot describe a page shape that is not there.
  const qs = page.headings.filter((h) => h.level === 2)
  if (qs.length === 0) return null
  const entries: unknown[] = []
  for (const [i, q] of qs.entries()) {
    const start = page.plain.indexOf(q.text)
    if (start === -1) continue
    const nextQ = qs[i + 1]
    const end = nextQ ? page.plain.indexOf(nextQ.text, start + q.text.length) : page.plain.length
    const answer = page.plain
      .slice(start + q.text.length, end === -1 ? page.plain.length : end)
      .trim()
    if (!answer) continue
    entries.push({
      '@type': 'Question',
      name: q.text,
      acceptedAnswer: { '@type': 'Answer', text: answer.slice(0, 1200) },
    })
  }
  if (entries.length === 0) return null
  return { '@type': 'FAQPage', mainEntity: entries }
}

/** One graph per page: the Organization, what the page is, where it sits. */
function structuredData(page: DocPage, canonical: string, crumbs: Crumb[]): Record<string, unknown> {
  const nodes: Array<Record<string, unknown>> = [organization()]
  if (isListing(page)) {
    nodes.push(collectionPage({ url: canonical, name: page.title, description: page.description }))
  } else {
    nodes.push(
      techArticle({
        url: canonical,
        headline: page.title,
        description: page.description,
        datePublished: page.created,
        dateModified: page.lastmod,
        image: DEFAULT_OG_IMAGE.url,
        keywords: page.tags,
      }),
    )
  }
  // A one-item trail (the docs home) is not a breadcrumb.
  if (crumbs.length > 1) nodes.push(breadcrumbList(crumbs))
  const faq = faqJsonLd(page)
  if (faq) nodes.push(faq)
  // FR-88 P3: one VideoObject per embedded video that has a published poster
  // (Google requires a thumbnail; a page built without the image hook has none).
  for (const { video, poster } of page.videos ?? []) {
    if (poster) nodes.push(videoObject({ ...video, thumbnailUrl: `${SITE_ORIGIN}${poster.url}` }))
  }
  return graph(nodes)
}

/** "Last updated … · Edit this page", each part only when it is true: no
 *  date when none is known, no edit link on a page no file produces. */
function pageMeta(page: DocPage): string {
  const parts: string[] = []
  if (page.lastmod) parts.push(`Last updated <time datetime="${page.lastmod}">${page.lastmod.slice(0, 10)}</time>`)
  if (page.sourceFile) {
    parts.push(
      `<a href="https://github.com/jk-zhang-meta/MeshHarbor/edit/master/ui/docs/content/${page.sourceFile}.md" target="_blank" rel="noopener noreferrer">Edit this page</a>`,
    )
  }
  return parts.length ? `<p class="page-meta">\n      ${parts.join(' ·\n      ')}\n    </p>` : ''
}

export function renderPage(ctx: LayoutCtx, tagIndexed: Set<string>): string {
  const { page, nav, prev, next, assets } = ctx
  const site = ctx.site ?? DOCS_NAV
  const crumbs = trail(page)
  const canonical = `${SITE_ORIGIN}${page.url}`
  const listing = isListing(page)
  // The 404 page answers for every missing URL, so it has no address of its
  // own to declare, and nothing in it is a thing to describe to a crawler.
  const head = renderHead({
    title: docsTitle(page) ?? page.title,
    description: page.description,
    canonical: page.notFound ? undefined : canonical,
    noindex: page.noindex,
    og: { type: listing || page.notFound ? 'website' : 'article', title: page.title, image: ctx.ogImage },
    article: listing || page.notFound ? undefined : { published: page.created, modified: page.lastmod, tags: page.tags },
    jsonLd: page.notFound ? undefined : structuredData(page, canonical, crumbs),
    assets,
    feed: site.hasBlog,
  })

  // The hero's REAL size (FR-87), read from the file: FR-60 hard-coded
  // 960×420 for heroes that are 760×400 or 600×540, reserving the wrong box.
  // It is the first thing in view, so it loads first rather than lazily.
  const hero = page.hero
    ? `<figure class="hero"><img src="${escapeHtml(page.hero.url)}" alt="${escapeHtml(page.heroAlt ?? page.title)}" width="${page.hero.width}" height="${page.hero.height}" loading="eager" fetchpriority="high" decoding="async"></figure>`
    : ''

  const toc = tocHtml(page.headings)

  return `<!DOCTYPE html>
<html lang="en">
<head>
${head}
</head>
<body>
<a class="skip-link" href="#main">Skip to content</a>

${renderTopbar(site, assets.logo)}

<div class="layout">
  <aside class="sidebar" data-nav>
    ${sidebar(nav, page)}
  </aside>

  <main id="main" class="content">
    ${breadcrumbHtml(crumbs)}
    <h1 class="page-title">${escapeHtml(page.title)}</h1>
    <p class="page-lead">${escapeHtml(page.description)}</p>
    ${tagChips(page, page.tags, tagIndexed)}
    ${hero}
    <div class="prose">
${page.html}
    </div>
    ${onTheBlogHtml(ctx.onTheBlog)}${pager(prev, next)}
    ${pageMeta(page)}
  </main>

  ${toc ? `<aside class="toc-rail">${toc}</aside>` : '<aside class="toc-rail"></aside>'}
</div>

${renderFooter(site)}

${renderSearchDialog(assets, site)}

${renderBodyScripts(assets)}
</body>
</html>
`
}
