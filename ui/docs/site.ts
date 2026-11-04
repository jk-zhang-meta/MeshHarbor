// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-60 (#1165) — site-wide configuration for the static docs generator.
 *
 * The nav is NOT a hand-maintained list of pages. Sections are declared
 * here (order, title, blurb, icon); the pages inside them are DISCOVERED
 * by scanning `content/<section>/**\/*.md`. That is deliberate: a nav
 * entry pointing at a page nobody wrote is the single most common way a
 * docs site 404s its own navigation, and it cannot happen if the nav is
 * derived from the files that exist.
 */
import { ANALYTICS_DOMAIN, ANALYTICS_HOSTS, ANALYTICS_SRC } from '../src/utils/analytics.ts'

/** Absolute origin. Canonicals, OG URLs and the sitemap are absolute — a
 *  relative canonical is legal but silently useless when a crawler reaches
 *  the page through any other host (a preview deploy, a staging origin). */
export const SITE_ORIGIN = 'https://meshharbor.itachi.fans'

/** Everything is served under this path prefix by nginx. */
export const BASE = '/docs'

export const SITE_NAME = 'MeshHarbor'
export const SITE_TITLE_SUFFIX = 'MeshHarbor Docs'

/** Social card. Lives in the repo already (`docs/assets/social-preview.png`)
 *  and is copied into the output by the build. It is final artwork from the
 *  brand kit, as is the repo root's copy GitHub shows, not a render.
 *  ⚠️ The ONE asset that keeps a stable, unhashed name (FR-87): the SPA's
 *  `ui/index.html` names it as its own og:image. */
export const OG_IMAGE = `${BASE}/assets/social-preview.png?v=2`

/**
 * FR-87 (#1776) P2: when true, also publish every hashed asset under its old,
 * plain name (`docs.css`, `search.js`, the heroes), so HTML a browser cached
 * before P1 made pages revalidate keeps loading its styles and scripts.
 * Off since 2026-10-04: hashed names went live on 2026-09-29, and pre-P1 HTML
 * (no `Cache-Control`, so heuristic caching of about 2.8 days) has aged out.
 */
export const LEGACY_UNHASHED_ASSETS = false

/** Hard ceiling on the search index. Above this the build FAILS rather
 *  than shipping a page-load cost nobody decided to spend. */
export const SEARCH_INDEX_MAX_GZIP_BYTES = 150 * 1024

/** A `<meta name="description">` past this is truncated in results, so a
 *  longer one is a silent defect. Build gate, not a lint. */
export const MAX_DESCRIPTION_CHARS = 160

/** FR-87 (#1776): a `<title>` past this is cut off in search results. The
 *  default drops " · section", then " — MeshHarbor Docs", to fit; a title that
 *  still does not fit must say so with a `seoTitle`, which is a build error
 *  over this length. Measured before: 8 of 65 docs titles ran 62–71. */
export const MAX_TITLE_CHARS = 60

/** Every front-matter key a docs page may use. Anything else FAILS the build
 *  (FR-87): a misspelt `heroalt:` or `seo_title:` otherwise vanishes without
 *  a trace, and the page ships without the thing its author asked for. */
export const DOCS_FRONTMATTER_KEYS = [
  'title',
  'description',
  'tags',
  'order',
  'hero',
  'heroAlt',
  'noindex',
  'faq',
  'updated',
  'seoTitle',
] as const

export const REPO_URL = 'https://github.com/jk-zhang-meta/MeshHarbor'

/**
 * FR-88 (#1790) P2: MeshHarbor's own channel profiles, the ONE list of them.
 *
 * - `/links/` lists them, and `ORG.sameAs` names them to search engines.
 * - Each has a short path that nginx answers with a 302 to `/links/`
 *   (`shortPathLocation`, in `files/nginx-pod.conf`). It is for the places a
 *   link cannot carry a campaign: a profile bio, a URL said out loud.
 *   `docs/__tests__/links-page.spec.ts` checks the nginx locations against
 *   this list, both ways, and checks that no SPA route shares a short path.
 */
export const CHANNELS = [
  { id: 'youtube', name: 'YouTube', handle: '@MeshHarbor', url: 'https://www.youtube.com/@MeshHarbor', short: '/yt' },
  { id: 'tiktok', name: 'TikTok', handle: '@meshharbor.itachi.fans', url: 'https://www.tiktok.com/@meshharbor.itachi.fans', short: '/tt' },
  // X took Instagram's place on 2026-10-11, after Instagram disabled the account.
  // A channel leaves this list together with its short path, so `/ig` is gone.
  { id: 'x', name: 'X', handle: '@meshharbor', url: 'https://x.com/meshharbor', short: '/x' },
  // The page has no @username yet, so this is its numeric address.
  { id: 'facebook', name: 'Facebook', handle: 'MeshHarbor', url: 'https://www.facebook.com/profile.php?id=100044550434196', short: '/fb' },
] as const

export type Channel = (typeof CHANNELS)[number]

/**
 * Where a channel's short path sends a visitor: `/links/`, with the channel as
 * the source and the values every profile link of the program carries
 * (`utm_medium=bio`, `utm_campaign=profile`, as in a profile's own website
 * field). A visit through a bio is then one source, whichever way it came.
 */
export function shortPathLocation(channel: Pick<Channel, 'id'>): string {
  return `/links/?utm_source=${channel.id}&utm_medium=bio&utm_campaign=profile`
}

/**
 * The one Organization every page's structured data points at (FR-87). FR-60
 * wrote `author: "G ROX LTD"` while every other record — the imprint, the
 * licence headers — says G ROX EOOD: two names for one publisher is how a
 * knowledge panel ends up split, or wrong. `sameAs` names the repository and
 * the channel profiles (FR-88 P2), for the same reason.
 */
export const ORG = {
  id: `${SITE_ORIGIN}/#organization`,
  name: SITE_NAME,
  legalName: 'G ROX EOOD',
  url: `${SITE_ORIGIN}/`,
  logo: `${SITE_ORIGIN}/logo.svg?v=2`,
  sameAs: [REPO_URL, ...CHANNELS.map((c) => c.url)],
} as const

/** The social card's real size and alt text, for `og:image:*`. Measured from
 *  the file (1280×640); `images.spec.ts` locks it. The alt says what the card
 *  shows: the logo and its one line. */
export const OG_IMAGE_META = {
  width: 1280,
  height: 640,
  alt: 'The MeshHarbor logo, with the line: remote desktop, private mesh network, chat & video',
} as const

// ── the blog (FR-87 P4) ─────────────────────────────────────────────────

/** Posts are `ui/blog/posts/<slug>.md`, served under this prefix. */
export const BLOG_BASE = '/blog'
export const BLOG_TITLE = 'MeshHarbor blog'
export const BLOG_DESCRIPTION =
  'Why MeshHarbor exists and how it is built: remote desktop from a browser tab, a private mesh network and team collaboration on one open-source agent.'
export const POSTS_PER_PAGE = 10
/** As with docs tags: a tag page below this is a doorway page, not a page. */
export const MIN_POSTS_PER_TAG_INDEX = 3
/** Social platforms and Google want a raster share image at least this wide. */
export const MIN_OG_IMAGE_WIDTH = 1200
export const WORDS_PER_MINUTE = 230

/**
 * Every front-matter key a post may use; anything else fails the build.
 * There is deliberately no `draft`: a file in `ui/blog/posts/` IS published,
 * and unpublished copy stays in the private promo repo (FR-39's rule that
 * post copy does not live in this public repo).
 */
export const BLOG_FRONTMATTER_KEYS = [
  'title',
  'seoTitle',
  'subtitle',
  'description',
  'date',
  'updated',
  'author',
  'tags',
  'hero',
  'heroAlt',
  'ogImage',
  'ogImageAlt',
  'related',
  'syndication',
  'canonical',
  // FR-91: a post that shows an install command joins `INSTALL_PAGES` for the
  // build, so the install-page gate passes and the carry reaches its links.
  'installCopy',
] as const

/**
 * FR-91 (#1880): the blog is served by its own lane (`meshharbor-blog`, routed at
 * the edge for `/blog/` and `/sitemap-blog.xml`) and published without this
 * image. While true, the sitemap index lists `sitemap-blog.xml` WITHOUT a
 * `lastmod` and whether or not this image has posts: the image cannot know the
 * blog's newest date, and a stale one is worse than none. Flip it in the same
 * change that routes the edge, never before.
 */
export const BLOG_LANE = false

export interface Author {
  name: string
  /** A page about the author: what `author.url` in the structured data names. */
  url: string
  sameAs: string[]
  /** Written by the author, never generated. The author box omits it until then. */
  bio?: string
}

/** Keyed by a post's `author:`. */
export const AUTHORS: Record<string, Author> = {
  goran: {
    name: 'Goran Jovanov',
    url: 'https://github.com/gjovanov',
    sameAs: ['https://github.com/gjovanov', 'https://medium.com/@gjovanov'],
  },
}

/**
 * First-party analytics on the static pages: the same tracker, the same site
 * and the same host allowlist as the SPA (`ui/src/utils/analytics.ts`, which
 * has no imports so the build can read it), which the pod CSP already allows
 * (`script-src https://purestat.ai`). FR-60's pages loaded none, so organic
 * search traffic — the reason FR-87 exists — was unmeasured.
 *
 * FR-102 (#2127): the shell no longer writes the tracker's tag. It writes a
 * same-origin loader (`theme/analytics.js`, content-hashed like every other
 * theme file) carrying these values as `data-*` attributes, and the loader
 * injects the tracker only on an allowlisted hostname over https, never
 * under a WebDriver — so a self-hosted copy of these pages, a fork and a
 * `localhost` build make no request to purestat.ai. `null` turns it off: no
 * loader, no tag.
 */
export const ANALYTICS: { src: string; domain: string; hosts: readonly string[] } | null = {
  src: ANALYTICS_SRC,
  domain: ANALYTICS_DOMAIN,
  hosts: ANALYTICS_HOSTS,
}

/**
 * FR-88 (#1790): the install pages, the ONE list of them.
 *
 * - A campaign on a page's URL is carried onto links to these
 *   (`theme/attribution.js`, which the build fills from this list).
 * - Their install and enroll commands are the ones whose copy counts toward
 *   purestat's `install-copy` goal.
 *
 * The build FAILS when a page shows an install command (`isInstallCommand` in
 * `theme/render.ts`) but is not listed here, or when an entry is not a page
 * this site generates, so the two cannot drift. The self-hosting guide is
 * listed on purpose: it installs the server, and has no agent command to copy.
 */
export const INSTALL_PAGES: readonly string[] = [
  `${BASE}/`,
  `${BASE}/start/quickstart/`,
  `${BASE}/start/install/windows/`,
  `${BASE}/start/install/macos/`,
  `${BASE}/start/install/linux/`,
  `${BASE}/start/tunnel-cli/`,
  `${BASE}/start/self-hosting/`,
  `${BASE}/network/ephemeral-nodes/`,
  `${BASE}/reference/cli/`,
]

/**
 * A tag index page is only generated at or above this many pages. Below it,
 * a wall of one-link pages reads to a crawler as doorway pages — a penalty,
 * not an optimisation.
 *
 * ⚠️ Tag pages are NAVIGATION, not content: they are deliberately kept out
 * of `sitemap.xml` and out of the search index (see `build.ts`). Their whole
 * body is other pages' titles, so promoting them would submit a third of the
 * site as thin listings and return every page twice in search.
 */
export const MIN_PAGES_PER_TAG_INDEX = 3

export interface SectionDef {
  /** Directory under `content/`, and the first URL segment. */
  dir: string
  title: string
  /** One line, shown on the home page card and in the sidebar header. */
  blurb: string
  /** Key into ICONS (`theme/icons.ts`). */
  icon: string
  /** Accent colour for the section's card and heading rule. */
  accent: 'teal' | 'coral' | 'deep'
}

/**
 * Section order IS the sidebar order and the sitemap order. Reading order
 * follows the product's own pivot (#490): remote access first, the private
 * network second, collaboration as the included bonus — then the
 * cross-cutting material, then reference.
 */
export const SECTIONS: SectionDef[] = [
  {
    dir: 'start',
    title: 'Get started',
    blurb: 'Install MeshHarbor on Windows, macOS or Linux and reach your first device',
    icon: 'flag',
    accent: 'teal',
  },
  {
    dir: 'remote-desktop',
    title: 'Remote desktop',
    blurb: 'Use any of your machines from a browser tab',
    icon: 'monitor',
    accent: 'coral',
  },
  {
    dir: 'network',
    title: 'Private network',
    blurb: 'A WireGuard-style mesh, tunnels, exit nodes and SSH',
    icon: 'network',
    accent: 'teal',
  },
  {
    dir: 'collaboration',
    title: 'Chat & video',
    blurb: 'Rooms, threaded chat, HD calls and file sharing',
    icon: 'video',
    accent: 'deep',
  },
  {
    dir: 'architecture',
    title: 'Architecture',
    blurb: 'How the control plane and the three data planes fit together',
    icon: 'blueprint',
    accent: 'coral',
  },
  {
    dir: 'security',
    title: 'Security & access control',
    blurb: 'What the server can and cannot see, and who may reach what',
    icon: 'shield',
    accent: 'teal',
  },
  {
    dir: 'troubleshooting',
    title: 'Troubleshooting',
    blurb: 'When a device is offline, a screen is black, or a call has no media',
    icon: 'wrench',
    accent: 'coral',
  },
  {
    dir: 'reference',
    title: 'Reference',
    blurb: 'CLI, configuration keys, ports and the HTTP API',
    icon: 'book',
    accent: 'deep',
  },
  {
    dir: 'faq',
    title: 'FAQ',
    blurb: 'Short answers to the questions people actually ask',
    icon: 'help',
    accent: 'teal',
  },
  {
    dir: 'compare',
    title: 'How MeshHarbor compares',
    blurb: 'Against Tailscale, RustDesk, TeamViewer, MeshCentral and NetBird',
    icon: 'compare',
    accent: 'coral',
  },
]

export function sectionByDir(dir: string): SectionDef | undefined {
  return SECTIONS.find((s) => s.dir === dir)
}
