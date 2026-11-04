// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-60 (#1165) — the static documentation generator.
 *
 *   bun docs/build.ts            (from ui/, after `vite build`)
 *
 * Ordering matters: `vite build` empties `dist/`, so this MUST run after
 * it. It writes `dist/docs/**` plus `dist/sitemap.xml` and
 * `dist/robots.txt` at the site root.
 *
 * Everything below that can be a BUILD GATE is one. A docs site whose own
 * navigation 404s costs more SEO than the site earns, so a dangling
 * internal link fails the build rather than logging a warning nobody
 * reads. Same for a missing description (a search engine invents the
 * snippet), a duplicate slug (two pages competing for one URL), and a
 * search index that outgrew its budget (a page-load cost nobody decided
 * to spend).
 *
 * FR-87 (#1776) added honest dates (`dates.ts`: an unknown date is omitted,
 * never the build date), content-hashed asset names (`theme/assets.ts`),
 * images with their real size (`theme/images.ts`), and the 404 page nginx
 * serves for any missing `/docs/` URL.
 */
import { gzipSync } from 'node:zlib'
import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { basename, dirname, join, relative, resolve, sep } from 'node:path'
import { resolveDates } from './dates.ts'
import { ATTRIBUTION_ENABLED } from '../src/utils/attribution.ts'
import { FEATURED_VIDEO_ID, videoById } from '../src/utils/videos.ts'
import {
  ANALYTICS,
  BASE,
  BLOG_BASE,
  BLOG_DESCRIPTION,
  BLOG_LANE,
  BLOG_TITLE,
  DOCS_FRONTMATTER_KEYS,
  INSTALL_PAGES,
  LEGACY_UNHASHED_ASSETS,
  MAX_DESCRIPTION_CHARS,
  MAX_TITLE_CHARS,
  MIN_OG_IMAGE_WIDTH,
  MIN_PAGES_PER_TAG_INDEX,
  MIN_POSTS_PER_TAG_INDEX,
  OG_IMAGE_META,
  POSTS_PER_PAGE,
  SEARCH_INDEX_MAX_GZIP_BYTES,
  SECTIONS,
  SITE_ORIGIN,
  sectionByDir,
} from './site.ts'
import { AssetEmitter } from './theme/assets.ts'
import { renderBlogIndex, renderBlogTag, renderPost } from './theme/blog-layout.ts'
import { carryScript, installPageErrors } from './theme/carry.ts'
import { renderHome } from './theme/home-layout.ts'
import { LINKS_URL, renderLinks } from './theme/links-layout.ts'
import {
  optionalBoolean,
  optionalNumber,
  optionalString,
  parseFrontmatter,
  requireString,
  requireStringArray,
  unknownKeys,
  type Frontmatter,
} from './theme/frontmatter.ts'
import { imageSize, MAX_IMAGE_BYTES } from './theme/images.ts'
import { checkLinks } from './theme/links.ts'
import { createRenderer, escapeHtml, renderMarkdown, type ResolvedImage } from './theme/render.ts'
import { docsTitle, renderPage, type DocPage, type NavSection, type SiteAssets } from './theme/layout.ts'
import {
  docsBacklinks,
  indexPageUrl,
  lastTouched,
  paginate,
  postUrl,
  readingMinutes,
  readPostMeta,
  sortPosts,
  type Post,
} from './theme/posts.ts'
import { FEED_URL, fitTitle, type OgImage, type ShellNav } from './theme/shell.ts'
import { atomFeed, feedHtml, robotsTxt, sitemapChildren, sitemapIndex, urlset, type UrlEntry } from './theme/xml.ts'

// ── invocation (FR-91) ──────────────────────────────────────────────────
// `bun docs/build.ts` builds the whole static site into ui/dist, exactly as it
// always has. Three flags exist for the blog's own publishing lane, which puts
// a post live without rebuilding the server image:
//   --blog-only       every gate runs as usual, but ONLY the blog is written:
//                     /blog/** (with its own /blog/assets/ and /blog/404.html),
//                     the feed and /sitemap-blog.xml. Nothing under /docs/.
//   --out <dir>       the output root instead of ui/dist.
//   --blog-dir <dir>  posts from <dir>/posts and their assets from <dir>/assets
//                     instead of ui/blog (a publisher's staging copy).

interface Invocation {
  blogOnly: boolean
  out?: string
  blogDir?: string
}

function parseInvocation(argv: string[]): Invocation {
  const inv: Invocation = { blogOnly: false }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!
    if (a === '--blog-only') inv.blogOnly = true
    else if (a === '--out' || a === '--blog-dir') {
      const v = argv[++i]
      if (!v || v.startsWith('--')) {
        console.error(`[docs] ${a} needs a directory`)
        process.exit(2)
      }
      if (a === '--out') inv.out = v
      else inv.blogDir = v
    } else {
      console.error(`[docs] unknown argument "${a}". Known: --blog-only, --out <dir>, --blog-dir <dir>`)
      process.exit(2)
    }
  }
  return inv
}

const INVOCATION = parseInvocation(process.argv.slice(2))
const BLOG_ONLY = INVOCATION.blogOnly

const DOCS_ROOT = dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'))
const UI_ROOT = resolve(DOCS_ROOT, '..')
const REPO_ROOT = resolve(UI_ROOT, '..')
const CONTENT_DIR = join(DOCS_ROOT, 'content')
const THEME_DIR = join(DOCS_ROOT, 'theme')
const DIST = INVOCATION.out ? resolve(INVOCATION.out) : join(UI_ROOT, 'dist')
const OUT = join(DIST, 'docs')
const OUT_ASSETS = join(OUT, 'assets')
// FR-87 P4: the blog. Published posts only; drafts live in the private promo repo.
const BLOG_DIR = INVOCATION.blogDir ? resolve(INVOCATION.blogDir) : join(UI_ROOT, 'blog')
const POSTS_DIR = join(BLOG_DIR, 'posts')
const OUT_BLOG = join(DIST, 'blog')
const OUT_BLOG_ASSETS = join(OUT_BLOG, 'assets')

/**
 * Where a frontmatter `hero:` / inline image name is looked up, in order.
 * Reusing the tutorial's artwork is the point — it is the same product.
 *
 * ⚠️ EVERY path must be inside `ui/`. The Dockerfile's UI stage is
 * `COPY ui/ .` and nothing else, so an asset resolved from the repo root
 * exists on a dev box and is ABSENT in the production image. The repo's
 * `docs/assets/` used to be searched here; it is deliberately gone,
 * because a hero added from there would build green locally and fail — or
 * worse, 404 — in the image. Put shared artwork in `ui/docs/assets/`.
 */
const ASSET_SEARCH_PATHS = [
  join(DOCS_ROOT, 'assets'),
  join(UI_ROOT, 'src', 'assets', 'tutorial'),
]
/** A post looks in the blog's own assets first, then the shared artwork. */
const BLOG_ASSET_SEARCH_PATHS = [join(BLOG_DIR, 'assets'), ...ASSET_SEARCH_PATHS]

const errors: string[] = []
function fail(msg: string): void {
  errors.push(msg)
}

// ── content discovery ───────────────────────────────────────────────────

function walk(dir: string, out: string[] = []): string[] {
  if (!existsSync(dir)) return out
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) walk(full, out)
    else if (entry.endsWith('.md')) out.push(full)
  }
  return out
}

// ── dates (FR-87) ───────────────────────────────────────────────────────
// FR-60 fell back to the build date here, calling it "when these bytes were
// made". Crawlers read `lastmod` as when the CONTENT changed, and production
// never had git, so every page claimed to change on every deploy.

const dates = resolveDates()
/** `2026-09-01`, or a full ISO 8601 timestamp with its offset. */
const FRONT_MATTER_DATE = /^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:\d{2}))?$/
/** Only for refusing a future date; never published. */
const NOW_DAY = new Date().toISOString().slice(0, 10)

/** A front-matter date: `YYYY-MM-DD` or an ISO timestamp, real, and not in
 *  the future. A bare date is valid schema.org, but Google prefers a time
 *  with a zone, so a git date (always a full timestamp) is the better one. */
function frontMatterDate(data: Frontmatter, key: string, rel: string): string | undefined {
  const v = optionalString(data, key)
  if (v === undefined) return undefined
  if (!FRONT_MATTER_DATE.test(v) || Number.isNaN(Date.parse(v))) {
    fail(`${rel} — \`${key}: ${v}\` is neither YYYY-MM-DD nor an ISO 8601 timestamp with its offset`)
    return undefined
  }
  if (v.slice(0, 10) > NOW_DAY) {
    fail(`${rel} — \`${key}: ${v}\` is in the future`)
    return undefined
  }
  return v
}

function toSlug(file: string): string {
  return relative(CONTENT_DIR, file).split(sep).join('/').replace(/\.md$/, '')
}

function slugToUrl(slug: string): string {
  if (slug === 'index') return `${BASE}/`
  const trimmed = slug.replace(/\/index$/, '')
  return `${BASE}/${trimmed}/`
}

// ── assets ──────────────────────────────────────────────────────────────

const assets = new AssetEmitter(OUT_ASSETS, `${BASE}/assets`, LEGACY_UNHASHED_ASSETS)
/**
 * FR-91: the blog lane's own assets. A `--blog-only` tree is served by a
 * separate server, so every file one of its pages loads must be in that tree:
 * nothing it references may live under the image's `/docs/assets/`, whose
 * hashed names change with every image. The full build never uses this
 * emitter, so its output is what it always was.
 */
const blogAssets = new AssetEmitter(OUT_BLOG_ASSETS, `${BLOG_BASE}/assets`, false)
/** Where a post's images are published: the shared docs assets in the full
 *  build, the blog's own in a `--blog-only` build. */
const postAssets = BLOG_ONLY ? blogAssets : assets

function findAsset(name: string, where: string, paths: string[]): string | null {
  const bare = name.replace(/^.*\//, '')
  for (const dir of paths) {
    const candidate = join(dir, bare)
    if (existsSync(candidate)) return candidate
  }
  fail(
    `${where} — asset "${name}" not found. Looked in:\n` +
      paths.map((d) => `      ${relative(REPO_ROOT, d).split(sep).join('/')}`).join('\n'),
  )
  return null
}

/** A hero or markdown image: found, size-checked, measured, and published
 *  under its hashed name. Null after reporting why it cannot be. */
function publishImage(name: string, where: string, paths = ASSET_SEARCH_PATHS, emitter = assets): ResolvedImage | null {
  const file = findAsset(name, where, paths)
  if (!file) return null
  const bytes = readFileSync(file)
  if (bytes.length > MAX_IMAGE_BYTES) {
    fail(
      `${where} — image "${name}" is ${(bytes.length / 1048576).toFixed(1)} MB; the limit is ` +
        `${MAX_IMAGE_BYTES / 1048576} MB. The site serves images as they are, so resize or recompress it.`,
    )
    return null
  }
  try {
    return { url: emitter.publishFile(file), ...imageSize(bytes) }
  } catch (err) {
    fail(`${where} — image "${name}": ${err instanceof Error ? err.message : String(err)}`)
    return null
  }
}

// ── plain text + per-section excerpts ───────────────────────────────────

function stripTags(html: string): string {
  return html
    .replace(/<pre[\s\S]*?<\/pre>/g, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#\d+;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}

interface IndexRecord {
  p: number
  h: string
  a: string
  x: string
  g: string[]
}

/** Split rendered HTML at h2 boundaries so search results deep-link to the
 *  right part of a long page instead of dumping the reader at the top. */
function sectionChunks(page: { html: string; description: string }): Array<{ heading: string; anchor: string; text: string }> {
  const parts: Array<{ heading: string; anchor: string; text: string }> = []
  const re = /<h2[^>]*\bid="([^"]+)"[^>]*>([\s\S]*?)<\/h2>/g
  const marks: Array<{ idx: number; end: number; slug: string; text: string }> = []
  let m: RegExpExecArray | null
  while ((m = re.exec(page.html)) !== null) {
    marks.push({ idx: m.index, end: re.lastIndex, slug: m[1]!, text: stripTags(m[2]!) })
  }

  const intro = stripTags(page.html.slice(0, marks.length ? marks[0]!.idx : page.html.length))
  parts.push({ heading: '', anchor: '', text: `${page.description} ${intro}`.trim() })

  for (const [i, mk] of marks.entries()) {
    const end = marks[i + 1]?.idx ?? page.html.length
    parts.push({ heading: mk.text, anchor: mk.slug, text: stripTags(page.html.slice(mk.end, end)) })
  }
  return parts
}

// ── page loading ────────────────────────────────────────────────────────

const md = createRenderer()

function loadPage(file: string): DocPage {
  const rel = relative(REPO_ROOT, file).split(sep).join('/')
  const raw = readFileSync(file, 'utf8')
  const { data, body } = parseFrontmatter(raw, rel)

  const slug = toSlug(file)
  const title = requireString(data, 'title', rel)
  const description = requireString(data, 'description', rel)
  const tags = requireStringArray(data, 'tags', rel)

  for (const key of unknownKeys(data, DOCS_FRONTMATTER_KEYS)) {
    fail(`${rel} — unknown frontmatter key \`${key}\`. Known: ${DOCS_FRONTMATTER_KEYS.join(', ')}`)
  }

  if (description.length > MAX_DESCRIPTION_CHARS) {
    fail(
      `${rel} — frontmatter \`description\` is ${description.length} chars; ` +
        `the limit is ${MAX_DESCRIPTION_CHARS} (longer is silently truncated in search results)`,
    )
  }

  const seoTitle = optionalString(data, 'seoTitle')
  if (seoTitle && seoTitle.length > MAX_TITLE_CHARS) {
    fail(
      `${rel} — frontmatter \`seoTitle\` is ${seoTitle.length} chars; the limit is ${MAX_TITLE_CHARS} ` +
        `(search results cut a longer title off)`,
    )
  }

  const sectionDir = slug.includes('/') ? slug.split('/')[0]! : undefined
  const section = sectionDir ? sectionByDir(sectionDir) : undefined
  if (sectionDir && !section) {
    fail(`${rel} — directory "${sectionDir}" is not a declared section in ui/docs/site.ts`)
  }

  const { html, headings, videos } = renderMarkdown(md, body, rel, {
    resolveImage: (src) => publishImage(src, rel),
    fail,
  })
  const heroName = optionalString(data, 'hero')
  const git = dates.files.get(rel)

  const page: DocPage = {
    slug,
    url: slugToUrl(slug),
    outFile: slug === 'index' ? 'index.html' : `${slug.replace(/\/index$/, '')}/index.html`,
    section,
    title,
    seoTitle,
    description,
    tags,
    order: optionalNumber(data, 'order') ?? 999,
    hero: heroName ? (publishImage(heroName, rel) ?? undefined) : undefined,
    heroAlt: optionalString(data, 'heroAlt'),
    noindex: optionalBoolean(data, 'noindex') ?? false,
    html,
    headings,
    videos,
    plain: '',
    faq: optionalBoolean(data, 'faq') ?? false,
    // front-matter `updated` > git > manifest > nothing. `updated` exists for
    // the commit that touched every page without changing what one says.
    lastmod: frontMatterDate(data, 'updated', rel) ?? git?.modified,
    created: git?.created,
    sourceFile: slug,
  }
  page.plain = stripTags(html)
  return page
}

// ── generated pages (section indexes, tag indexes) ──────────────────────

/** @param level `2` when the grid sits directly under the page's `<h1>`,
 *  `3` under the "In this section" `<h2>` an authored index gets. */
function sectionIndexBody(pages: DocPage[], level: 2 | 3): string {
  const cards = pages
    .map(
      (p) =>
        `<a class="section-card" href="${p.url}">` +
        `<h${level} class="section-card__title">${escapeHtml(p.title)}</h${level}>` +
        `<p class="section-card__blurb">${escapeHtml(p.description)}</p></a>`,
    )
    .join('')
  return `<div class="section-grid">${cards}</div>`
}

function makeSectionIndex(
  section: (typeof SECTIONS)[number],
  pages: DocPage[],
  authored: DocPage | undefined,
): DocPage {
  if (authored) {
    // Authored prose stays first; the generated listing is appended, so a
    // new page in the section shows up without anyone editing an index.
    const listing = sectionIndexBody(pages, 3)
    authored.html = `${authored.html}\n<h2 id="in-this-section">In this section</h2>\n${listing}`
    authored.headings = [
      ...authored.headings,
      { level: 2, text: 'In this section', slug: 'in-this-section' },
    ]
    authored.plain = stripTags(authored.html)
    return authored
  }
  const listing = sectionIndexBody(pages, 2)
  // No `lastmod`: no file produces this page, so git has no date for it, and
  // the build date is not one (FR-87).
  return {
    slug: `${section.dir}/index`,
    url: `${BASE}/${section.dir}/`,
    outFile: `${section.dir}/index.html`,
    section,
    title: section.title,
    description: section.blurb,
    tags: [section.dir],
    order: -1,
    noindex: false,
    html: listing,
    headings: [],
    plain: stripTags(listing),
    faq: false,
  }
}

function makeTagIndex(tag: string, pages: DocPage[]): DocPage {
  const cards = pages
    .map(
      (p) =>
        `<a class="section-card" href="${p.url}">` +
        `<h2 class="section-card__title">${escapeHtml(p.title)}</h2>` +
        `<p class="section-card__blurb">${escapeHtml(p.description)}</p>` +
        `<span class="section-card__count">${escapeHtml(p.section?.title ?? 'Docs')}</span></a>`,
    )
    .join('')
  const html = `<div class="section-grid">${cards}</div>`
  return {
    slug: `tags/${tag}`,
    url: `${BASE}/tags/${encodeURIComponent(tag)}/`,
    outFile: `tags/${tag}/index.html`,
    section: undefined,
    title: `${tag}`,
    description: `Every MeshHarbor documentation page tagged “${tag}”.`,
    tags: [tag],
    order: 999,
    noindex: false,
    html,
    headings: [],
    plain: stripTags(html),
    faq: false,
  }
}

/** Served by nginx for any missing `/docs/` (and `/blog/`) URL — FR-87 P1's
 *  `error_page 404`. Every link in it is site-absolute, because it answers
 *  at whatever depth the missing URL had. */
function makeNotFoundPage(nav: NavSection[]): DocPage {
  const sections = nav
    .map(({ section }) => `<li><a href="${BASE}/${section.dir}/">${escapeHtml(section.title)}</a></li>`)
    .join('')
  const html =
    `<p>Nothing is published at this address. The page may have moved, or the link that brought you here may be wrong.</p>\n` +
    `<p><button class="btn btn--primary" type="button" data-search-open>Search the documentation</button></p>\n` +
    `<p>Or start from a section:</p>\n<ul><li><a href="${BASE}/">Documentation home</a></li>${sections}</ul>`
  return {
    slug: '404',
    url: `${BASE}/404.html`,
    outFile: '404.html',
    title: 'Page not found',
    description: 'This page does not exist. Search the documentation, or start from one of its sections.',
    tags: [],
    order: 999,
    noindex: true,
    notFound: true,
    html,
    headings: [],
    plain: '',
    faq: false,
  }
}

// ── the blog (FR-87 P4) ─────────────────────────────────────────────────

/** A post, rendered and checked; null after reporting why it cannot be. */
function loadPost(file: string, now: Date): Post | null {
  const rel = relative(REPO_ROOT, file).split(sep).join('/')
  const { data, body } = parseFrontmatter(readFileSync(file, 'utf8'), rel)
  const slug = basename(file, '.md')
  const { meta, errors: metaErrors } = readPostMeta(data, slug, rel, now)
  for (const e of metaErrors) fail(e)
  if (!meta) return null

  const { html, headings } = renderMarkdown(md, body, rel, {
    resolveImage: (src) => publishImage(src, rel, BLOG_ASSET_SEARCH_PATHS, postAssets),
    fail,
  })
  const heroImage = meta.hero ? publishImage(meta.hero, rel, BLOG_ASSET_SEARCH_PATHS, postAssets) : undefined
  if (heroImage === null) return null

  // The share image: `ogImage`, else the hero when it is raster. That one of
  // them exists and is raster is `readPostMeta`'s contract; its WIDTH needs
  // the file, so it is checked here.
  const ogName = meta.ogImage ?? meta.hero!
  const og = ogName === meta.hero ? heroImage : publishImage(ogName, rel, BLOG_ASSET_SEARCH_PATHS, postAssets)
  if (!og) return null
  if (og.width < MIN_OG_IMAGE_WIDTH) {
    fail(`${rel} — the share image "${ogName}" is ${og.width} px wide; Google and social platforms want at least ${MIN_OG_IMAGE_WIDTH}`)
    return null
  }

  const plain = stripTags(html)
  return {
    ...meta,
    url: postUrl(slug),
    outFile: `${slug}/index.html`,
    sourceFile: rel,
    heroImage,
    og: { url: `${SITE_ORIGIN}${og.url}`, width: og.width, height: og.height, alt: (meta.ogImageAlt ?? meta.heroAlt)! },
    html,
    headings,
    plain,
    readingMinutes: readingMinutes(plain),
  }
}

// ── output ──────────────────────────────────────────────────────────────

function write(file: string, contents: string | Buffer): void {
  mkdirSync(dirname(file), { recursive: true })
  writeFileSync(file, contents)
}

/** The docs pages a crawler is asked to index: not the noindexed, not the
 *  tag listings (see the note where this is written). */
function docsUrlEntries(pages: DocPage[]): UrlEntry[] {
  // The date part: what `git log -1 --format=%cs` prints for the file, which
  // is what the public-site smoke compares the sitemap against.
  return pages.filter((p) => !p.noindex).map((p) => ({ loc: `${SITE_ORIGIN}${p.url}`, lastmod: p.lastmod?.slice(0, 10) }))
}

// ── main ────────────────────────────────────────────────────────────────

function main(): void {
  const t0 = Date.now()

  if (!existsSync(CONTENT_DIR)) {
    console.error(`[docs] no content directory at ${CONTENT_DIR}`)
    process.exit(1)
  }

  const files = walk(CONTENT_DIR).sort()

  // Collect per-file failures instead of throwing on the first one. With
  // ~65 pages, aborting on file 3 means one build run per mistake — and a
  // raw stack trace where the other gates print an actionable list.
  const loaded: DocPage[] = []
  for (const file of files) {
    try {
      loaded.push(loadPage(file))
    } catch (err) {
      fail(err instanceof Error ? err.message : String(err))
    }
  }

  // Duplicate URLs: two files competing for one address.
  const seen = new Map<string, string>()
  for (const p of loaded) {
    const prev = seen.get(p.url)
    if (prev) fail(`duplicate URL ${p.url} — produced by both ${prev}.md and ${p.slug}.md`)
    seen.set(p.url, p.slug)
  }

  // Assemble sections. A section index is generated when nobody authored
  // one, so adding a page never requires editing an index by hand.
  const home = loaded.find((p) => p.slug === 'index')
  if (!home) fail('ui/docs/content/index.md is required (it is the /docs/ landing page)')

  const nav: NavSection[] = []
  const allPages: DocPage[] = home ? [home] : []

  for (const section of SECTIONS) {
    const own = loaded.filter((p) => p.slug.startsWith(`${section.dir}/`))
    const authoredIndex = own.find((p) => p.slug === `${section.dir}/index`)
    const leaves = own
      .filter((p) => p !== authoredIndex)
      .sort((a, b) => a.order - b.order || a.title.localeCompare(b.title))
    if (leaves.length === 0 && !authoredIndex) continue

    const index = makeSectionIndex(section, leaves, authoredIndex)
    nav.push({ section, pages: leaves })
    allPages.push(index, ...leaves)
  }

  // Pages in a directory that is not a declared section were already
  // reported by loadPage; carry them so their errors are not the only trace.
  for (const p of loaded) {
    if (!allPages.includes(p)) allPages.push(p)
  }

  // Tag indexes, above the doorway-page threshold only.
  const byTag = new Map<string, DocPage[]>()
  for (const p of allPages) {
    for (const t of p.tags) {
      if (!byTag.has(t)) byTag.set(t, [])
      byTag.get(t)!.push(p)
    }
  }
  const tagIndexed = new Set<string>()
  const tagPages: DocPage[] = []
  for (const [tag, pages] of [...byTag.entries()].sort()) {
    if (pages.length < MIN_PAGES_PER_TAG_INDEX) continue
    tagIndexed.add(tag)
    tagPages.push(makeTagIndex(tag, pages))
  }
  const renderable = [...allPages, ...tagPages]

  // Errors name the file an author would open; a generated page, its URL.
  const idOf = (p: DocPage) => (p.sourceFile ? `ui/docs/content/${p.sourceFile}.md` : p.url)

  // A title that does not fit even bare is cut off in every search result.
  for (const p of renderable) {
    if (docsTitle(p) === null) {
      fail(
        `${idOf(p)} — title "${p.title}" is ${p.title.length} chars, ` +
          `over ${MAX_TITLE_CHARS} even without the section and site name; add a \`seoTitle\``,
      )
    }
  }

  // ── the blog (FR-87 P4). No posts ⇒ no /blog output, no Blog links, no
  // feed, no sitemap entry: the site is exactly what it was without one.
  const now = new Date()
  const postFiles = existsSync(POSTS_DIR)
    ? readdirSync(POSTS_DIR)
        .filter((f) => f.endsWith('.md'))
        .sort()
        .map((f) => join(POSTS_DIR, f))
    : []
  const posts = sortPosts(
    postFiles
      .map((f) => {
        try {
          return loadPost(f, now)
        } catch (err) {
          fail(err instanceof Error ? err.message : String(err))
          return null
        }
      })
      .filter((p): p is Post => p !== null),
  )
  const hasBlog = posts.length > 0
  for (const p of posts) {
    if (!p.seoTitle && fitTitle([`${p.title} — ${BLOG_TITLE}`, p.title]) === null) {
      fail(`${p.sourceFile} — title "${p.title}" is ${p.title.length} chars, over ${MAX_TITLE_CHARS}; add a \`seoTitle\` (the H1 keeps the full title)`)
    }
  }
  const postsByTag = new Map<string, Post[]>()
  for (const p of posts) for (const t of p.tags) postsByTag.set(t, [...(postsByTag.get(t) ?? []), p])
  const blogTagIndexed = new Set([...postsByTag].filter(([, ps]) => ps.length >= MIN_POSTS_PER_TAG_INDEX).map(([t]) => t))

  const linkPages = [
    ...renderable.map((p) => ({
      id: idOf(p),
      url: p.url,
      html: p.html,
      anchors: new Set(p.headings.map((h) => h.slug)),
    })),
    ...posts.map((p) => ({ id: p.sourceFile, url: p.url, html: p.html, anchors: new Set(p.headings.map((h) => h.slug)) })),
    // The blog's generated listings are link targets too (no body to check).
    ...(hasBlog
      ? [
          ...paginate(posts, POSTS_PER_PAGE).map((_, i) => indexPageUrl(i + 1)),
          ...[...blogTagIndexed].map((t) => `${BLOG_BASE}/tags/${encodeURIComponent(t)}/`),
        ].map((url) => ({ id: url, url, html: '', anchors: new Set<string>() }))
      : []),
  ]
  // Other internal links point at the SPA (/register, /login …); this
  // generator does not own those routes, so it cannot verify them.
  const owns = (path: string) => path.startsWith(`${BASE}/`) || path.startsWith(`${BLOG_BASE}/`)
  const linkErrors = checkLinks(linkPages, owns)
  for (const e of linkErrors) fail(e)

  // The static homepage's art, resolved with every other image so a missing
  // file is reported with the rest (P6).
  const homeHero = publishImage('hero-mesh.svg', 'ui/docs/theme/home-layout.ts')
  // FR-88 P3: the homepage's video, a build error when the manifest lost it.
  const homeVideo = videoById(FEATURED_VIDEO_ID)
  if (!homeVideo) fail(`ui/src/utils/videos.ts — FEATURED_VIDEO_ID "${FEATURED_VIDEO_ID}" is not in VIDEOS`)
  const homeVideoPoster = homeVideo ? publishImage(homeVideo.poster, 'ui/src/utils/videos.ts') : null

  // A post's `related:` pages are listed as cards, so each must exist.
  const pagesByUrl = new Map<string, { url: string; title: string; description: string }>(
    [...renderable, ...posts].map((p) => [p.url, { url: p.url, title: p.title, description: p.description }]),
  )
  for (const p of posts) {
    for (const r of p.related) {
      const url = r.endsWith('/') ? r : `${r}/`
      if (!pagesByUrl.has(url)) fail(`${p.sourceFile} — related "${r}" is not a page this site generates`)
    }
  }

  // FR-88: a page that shows an install command is an install page, and a
  // campaign is carried to every install page. One list (`INSTALL_PAGES`),
  // checked here against what the pages actually show.
  const rendered = [
    ...renderable.map((p) => ({ id: idOf(p), url: p.url, html: p.html })),
    ...posts.map((p) => ({ id: p.sourceFile, url: p.url, html: p.html })),
  ]
  // FR-91: a post that declares `installCopy` is an install page for this
  // build. Without the key, a post that shows an install command still fails.
  const installPages = [...INSTALL_PAGES, ...posts.filter((p) => p.installCopy).map((p) => p.url)]
  for (const e of installPageErrors(rendered, installPages)) fail(e)

  if (errors.length) {
    console.error(`\n[docs] BUILD FAILED — ${errors.length} problem(s):\n`)
    for (const e of errors) console.error(`  • ${e}`)
    console.error('')
    process.exit(1)
  }

  // ── emit ──────────────────────────────────────────────────────────────
  // FR-91: a blog-only build clears and writes `/blog/` alone. It never
  // touches `/docs/`, the homepage, the link hub or the site-root files; their
  // gates belong to the image build that publishes them.
  if (BLOG_ONLY) {
    if (!hasBlog) {
      console.error(`\n[docs] BUILD FAILED — --blog-only, but ${relative(REPO_ROOT, POSTS_DIR) || POSTS_DIR} has no posts.\n`)
      process.exit(1)
    }
    rmSync(OUT_BLOG, { recursive: true, force: true })
  } else {
    rmSync(OUT, { recursive: true, force: true })
    mkdirSync(OUT_ASSETS, { recursive: true })
  }

  // Search index. Built BEFORE the pages are rendered: its name is
  // content-hashed, and every page carries that name.
  //
  // ⚠️ Tag indexes are excluded. Their entire content is the titles and
  // descriptions of pages that are already in the index, so including them
  // would return the same page twice for one query — once as itself and
  // once as a tag listing that merely mentions it. The `tag:` filter in
  // `search.js` is the better answer to "everything about windows", and it
  // works off the real pages.
  const idxPages: Array<{ u: string; t: string; s: string }> = []
  const records: IndexRecord[] = []
  for (const page of allPages) {
    if (page.noindex) continue
    const pi = idxPages.length
    idxPages.push({ u: page.url, t: page.title, s: page.section?.title ?? 'Docs' })
    for (const chunk of sectionChunks(page)) {
      if (!chunk.text && !chunk.heading) continue
      records.push({
        p: pi,
        h: chunk.heading,
        a: chunk.anchor,
        x: chunk.text.slice(0, 420),
        g: page.tags,
      })
    }
  }
  // Posts join the same index, grouped under "Blog" in the results.
  for (const post of posts) {
    const pi = idxPages.length
    idxPages.push({ u: post.url, t: post.title, s: 'Blog' })
    for (const chunk of sectionChunks(post)) {
      if (!chunk.text && !chunk.heading) continue
      records.push({ p: pi, h: chunk.heading, a: chunk.anchor, x: chunk.text.slice(0, 420), g: post.tags })
    }
  }
  const indexJson = JSON.stringify({ p: idxPages, r: records })
  const gz = gzipSync(Buffer.from(indexJson)).length
  if (gz > SEARCH_INDEX_MAX_GZIP_BYTES) {
    console.error(
      `\n[docs] BUILD FAILED — search index is ${(gz / 1024).toFixed(1)} KB gzipped, ` +
        `over the ${(SEARCH_INDEX_MAX_GZIP_BYTES / 1024).toFixed(0)} KB budget.\n` +
        `        Raise SEARCH_INDEX_MAX_GZIP_BYTES in ui/docs/site.ts deliberately, ` +
        `or shrink the per-record excerpt.\n`,
    )
    process.exit(1)
  }

  // The theme's files go where the pages that load them will be served from:
  // `/docs/assets/` in the full build, `/blog/assets/` in a blog-only one.
  const emitter = BLOG_ONLY ? blogAssets : assets
  const siteAssets: SiteAssets = {
    css: emitter.publishFile(join(THEME_DIR, 'docs.css')),
    js: emitter.publishFile(join(THEME_DIR, 'docs.js')),
    search: emitter.publishFile(join(THEME_DIR, 'search.js')),
    osPreference: emitter.publishFile(join(THEME_DIR, 'os-preference.js')),
    searchIndex: emitter.publishBytes('search-index.json', indexJson),
    // Published only with a post, so a site without one ships the same bytes.
    blogCss: hasBlog ? emitter.publishFile(join(THEME_DIR, 'blog.css')) : undefined,
    // The homepage is not part of the blog lane.
    homeCss: BLOG_ONLY ? undefined : assets.publishFile(join(THEME_DIR, 'home.css')),
    homeJs: BLOG_ONLY ? undefined : assets.publishFile(join(THEME_DIR, 'home.js')),
    // FR-88: the carry script, on every page, with the install pages written
    // in; the SPA's kill switch drops it.
    attribution: ATTRIBUTION_ENABLED
      ? emitter.publishBytes('attribution.js', carryScript(readFileSync(join(THEME_DIR, 'attribution.js'), 'utf8'), installPages))
      : undefined,
    // FR-102: the hosted-only analytics loader, on every page of whichever
    // tree is being written (`/blog/assets/` in a blog-only build, so the lane
    // depends on nothing under the image's `/docs/assets/`). `ANALYTICS = null`
    // drops it, and with it every trace of the tracker.
    analytics: ANALYTICS ? emitter.publishFile(join(THEME_DIR, 'analytics.js')) : undefined,
    // The top bar's logo, from the SPA's own copy, so the two never drift.
    logo: emitter.publishFile(join(UI_ROOT, 'src', 'assets', 'brand', 'meshharbor-logo.svg')),
  }

  const site: ShellNav = { current: 'docs', hasBlog }
  if (!BLOG_ONLY) {
    // Reading order for prev/next is the sidebar order: sections in declared
    // order, pages within them in `order` then title.
    const flow: DocPage[] = [
      ...(home ? [home] : []),
      ...nav.flatMap(({ section, pages }) => {
        const idx = allPages.find((p) => p.url === `${BASE}/${section.dir}/`)
        return idx ? [idx, ...pages] : pages
      }),
    ]

    const backlinks = docsBacklinks(posts, BASE)
    for (const page of renderable) {
      const i = flow.indexOf(page)
      const html = renderPage(
        {
          nav,
          page,
          assets: siteAssets,
          site,
          onTheBlog: backlinks.get(page.url)?.map((p) => ({ url: p.url, title: p.title })),
          prev: i > 0 ? flow[i - 1] : undefined,
          next: i >= 0 && i < flow.length - 1 ? flow[i + 1] : undefined,
        },
        tagIndexed,
      )
      write(join(OUT, page.outFile), html)
    }
    write(join(OUT, '404.html'), renderPage({ nav, page: makeNotFoundPage(nav), assets: siteAssets, site }, tagIndexed))

    // The static homepage (P6): nginx serves it at `/` to a request without the
    // session cookie, and `/home/` itself is internal (files/nginx-pod.conf).
    const homeHtml = renderHome({
      assets: siteAssets,
      nav: { current: 'home', hasBlog },
      hero: homeHero!,
      video: homeVideo && homeVideoPoster ? { video: homeVideo, poster: homeVideoPoster } : undefined,
    })
    const homeLinks = checkLinks(
      [...linkPages, { id: 'the static homepage', url: '/', html: homeHtml, anchors: new Set([...homeHtml.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]!)) }],
      owns,
    ).filter((e) => e.startsWith('the static homepage'))
    if (homeLinks.length) {
      console.error(`\n[docs] BUILD FAILED — the homepage links nowhere:\n${homeLinks.map((e) => `  • ${e}`).join('\n')}\n`)
      process.exit(1)
    }
    write(join(DIST, 'home', 'index.html'), homeHtml)

    // FR-88 P2: the link hub, which nginx serves at `/links/` and each channel's
    // short path redirects to. Held to the homepage's gate: a hub whose links go
    // nowhere is the one page a visitor from a profile sees.
    const linksHtml = renderLinks({ assets: siteAssets, nav: { current: 'links', hasBlog } })
    const hubLinks = checkLinks(
      [...linkPages, { id: 'the link hub', url: LINKS_URL, html: linksHtml, anchors: new Set([...linksHtml.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]!)) }],
      owns,
    ).filter((e) => e.startsWith('the link hub'))
    if (hubLinks.length) {
      console.error(`\n[docs] BUILD FAILED — the link hub links nowhere:\n${hubLinks.map((e) => `  • ${e}`).join('\n')}\n`)
      process.exit(1)
    }
    write(join(DIST, 'links', 'index.html'), linksHtml)
  }

  // The blog. Cleared first, so a post removed since the last build does
  // not survive as a stale page (a blog-only build cleared it above).
  if (!BLOG_ONLY) rmSync(OUT_BLOG, { recursive: true, force: true })
  // FR-91: a blog-only tree names its own copy of the site's share card, so
  // a listing page never points into the image's `/docs/assets/`. Absent in
  // the full build, where the default is that same card's /docs/ URL.
  const blogOgImage: OgImage | undefined = BLOG_ONLY
    ? { url: `${SITE_ORIGIN}${BLOG_BASE}/assets/social-preview.png?v=2`, ...OG_IMAGE_META }
    : undefined
  const blogUrls: UrlEntry[] = []
  if (hasBlog) {
    const ctx = { assets: siteAssets, nav: { current: 'blog', hasBlog } as ShellNav, tagIndexed: blogTagIndexed, ogImage: blogOgImage }
    for (const [i, post] of posts.entries()) {
      const related = post.related.map((r) => pagesByUrl.get(r.endsWith('/') ? r : `${r}/`)!).filter(Boolean)
      write(join(OUT_BLOG, post.outFile), renderPost({ ...ctx, post, newer: posts[i - 1], older: posts[i + 1], related }))
    }
    const pages = paginate(posts, POSTS_PER_PAGE)
    for (const [i, pagePosts] of pages.entries()) {
      const out = i === 0 ? join(OUT_BLOG, 'index.html') : join(OUT_BLOG, 'page', String(i + 1), 'index.html')
      write(out, renderBlogIndex({ ...ctx, posts: pagePosts, pageNo: i + 1, pages: pages.length }))
    }
    for (const tag of blogTagIndexed) {
      write(join(OUT_BLOG, 'tags', tag, 'index.html'), renderBlogTag({ ...ctx, tag, posts: postsByTag.get(tag)! }))
    }

    const newestPost = posts.map(lastTouched).sort((a, b) => Date.parse(b) - Date.parse(a))[0]!
    write(
      join(OUT_BLOG, 'feed.xml'),
      atomFeed({
        id: `${SITE_ORIGIN}${BLOG_BASE}/`,
        selfUrl: `${SITE_ORIGIN}${FEED_URL}`,
        htmlUrl: `${SITE_ORIGIN}${BLOG_BASE}/`,
        title: BLOG_TITLE,
        subtitle: BLOG_DESCRIPTION,
        updated: newestPost,
        entries: posts.map((p) => ({
          id: `${SITE_ORIGIN}${p.url}`,
          url: `${SITE_ORIGIN}${p.url}`,
          title: p.title,
          summary: p.description,
          contentHtml: feedHtml(p.html, SITE_ORIGIN),
          published: p.date,
          updated: lastTouched(p),
          author: { name: p.author.name, uri: p.author.url },
          tags: p.tags,
        })),
      }),
    )

    blogUrls.push({ loc: `${SITE_ORIGIN}${BLOG_BASE}/`, lastmod: newestPost.slice(0, 10) })
    for (const p of posts) blogUrls.push({ loc: `${SITE_ORIGIN}${p.url}`, lastmod: lastTouched(p).slice(0, 10) })
  }

  // FR-91: the blog lane's server answers a missing `/blog/` URL with its own
  // copy of the docs 404 (`error_page 404 /blog/404.html` in
  // files/nginx-blog.conf); the image's `/docs/404.html` is not in its tree.
  if (BLOG_ONLY) {
    write(join(OUT_BLOG, '404.html'), renderPage({ nav, page: makeNotFoundPage(nav), assets: siteAssets, site, ogImage: blogOgImage }, tagIndexed))
  }

  // Every hashed file planned above — theme, search index, heroes, images.
  emitter.flush()

  // ⚠️ The OG image must live INSIDE `ui/`. The Docker UI stage is
  // `COPY ui/ .` and nothing else, so a card read from the repo's
  // `docs/assets/` exists on a dev box and is ABSENT in the image — every
  // page's `og:image` would 404 in production while looking perfect
  // locally. Same class as the `@types/node` optional-peer divergence.
  //
  // A gate rather than a warning, for the same reason as the other gates:
  // this URL is referenced by all 96 pages, and a warning in a Docker build
  // log is precisely the thing nobody reads.
  const social = join(DOCS_ROOT, 'assets', 'social-preview.png')
  if (!existsSync(social)) {
    console.error(
      `\n[docs] BUILD FAILED — the Open Graph image is missing:\n` +
        `        ${relative(REPO_ROOT, social)}\n` +
        `        Every page references it as og:image, and it MUST live under ui/ —\n` +
        `        the Docker UI stage copies ui/ and nothing else.\n`,
    )
    process.exit(1)
  }
  cpSync(social, join(BLOG_ONLY ? OUT_BLOG_ASSETS : OUT_ASSETS, 'social-preview.png'))

  if (BLOG_ONLY) {
    // The blog's urlset is the lane's; the index, the docs urlset and
    // robots.txt stay the image's (they are served at the site root by it).
    write(join(DIST, 'sitemap-blog.xml'), urlset(blogUrls))
    console.log(
      `[docs] blog only · ${posts.length} blog post${posts.length === 1 ? '' : 's'} · ${records.length} search records · ` +
        `index ${(gz / 1024).toFixed(1)} KB gz · ${blogAssets.names().length} assets → ${DIST} · ${Date.now() - t0} ms`,
    )
    return
  }

  // Site-root SEO files.
  //
  // ⚠️ The sitemap lists DOCUMENTATION pages, not tag indexes. A sitemap is
  // what we actively ask a crawler to index, and tag pages exist for
  // readers navigating by chip — their content is other pages' titles. At
  // 31 tag pages against 65 real ones, promoting them would make a third of
  // what we submit thin listing pages, which is how a tag system reads as
  // doorway pages. They stay crawlable via their links; they are just not
  // advertised.
  //
  // FR-87: `/sitemap.xml` is an INDEX, one child per collection, so Search
  // Console reports each on its own. The blog adds `sitemap-blog.xml`.
  // `/` leads the docs sitemap (P6): it is static HTML now, but undated, as
  // no single source file is its content.
  const docsUrls = [{ loc: `${SITE_ORIGIN}/` }, ...docsUrlEntries(allPages)]
  write(join(DIST, 'sitemap-docs.xml'), urlset(docsUrls))
  rmSync(join(DIST, 'sitemap-blog.xml'), { force: true })
  if (hasBlog) write(join(DIST, 'sitemap-blog.xml'), urlset(blogUrls))
  // FR-91: with `BLOG_LANE` on, the blog child is listed undated and always.
  write(join(DIST, 'sitemap.xml'), sitemapIndex(sitemapChildren(SITE_ORIGIN, docsUrls, blogUrls, { hasBlog, blogLane: BLOG_LANE })))
  write(join(DIST, 'robots.txt'), robotsTxt(SITE_ORIGIN))

  const ms = Date.now() - t0
  // The date source is in the log because its absence is otherwise silent:
  // an image built without the manifest looks perfect and publishes no dates.
  const dated = allPages.filter((p) => p.lastmod).length
  const dateNote =
    dates.source === 'none'
      ? `dates: none (${dates.note})`
      : `dates: ${dates.source}, ${dated} of ${allPages.length} pages`
  console.log(
    `[docs] ${renderable.length} pages · ${posts.length} blog post${posts.length === 1 ? '' : 's'} · ${records.length} search records · ` +
      `index ${(gz / 1024).toFixed(1)} KB gz · ${tagPages.length} tag indexes · ` +
      `${assets.names().length} assets · ${dateNote} · ${ms} ms`,
  )
}

main()
