# FR-87: A blog at meshharbor.itachi.fans/blog, a crawlable homepage, and a site Google can index

**Issue:** [#1776](https://github.com/jk-zhang-meta/MeshHarbor/issues/1776) · **Status:** **closed
2026-09-30**, all 14 criteria field-verified. P1–P7 live since 2026-09-29. Follow-ups, none
blocking: `LEGACY_UNHASHED_ASSETS` turned off on 2026-10-04 (live with the next promote), and
Search Console reviews at +3/+14/+28 days · **Owner:** web / public site · **Builds on:**
[FR-60](FR-60-public-docs-site.md) (the static docs generator)

## 1. Goal

Make meshharbor.itachi.fans a site that Google can read and that earns its own search traffic.

1. **A blog at `/blog/`**: static, SEO-complete pages built by the same in-repo generator as
   `/docs`. The first post is the operator's Medium article
   ([*My wife's swearing at TeamViewer made me build my own remote desktop tool with extras*](https://medium.com/@gjovanov/my-wifes-swearing-at-teamviewer-made-me-build-my-own-remote-desktop-tool-with-extras-e48f1f7c5e35)),
   republished at `/blog/self-hosted-teamviewer-alternative/`. **The blog is the canonical
   copy**; Medium's canonical link points at it (operator decision, 2026-09-29).
2. **A crawlable homepage.** `/` serves guests and crawlers static HTML, and serves the SPA to
   signed-in users exactly as today (operator decision, 2026-09-29).
3. **The docs' SEO defects fixed** (§2).
4. **Indexing:** a Search Console domain property, the sitemap submitted, per-URL indexing
   requests, Bing Webmaster Tools and IndexNow.

## 2. Evidence: the failing baselines (measured 2026-09-28, production)

Each row is also an acceptance criterion's "shown failing" run.

| Probe | Today | Cause |
|---|---|---|
| `/sitemap.xml` `<lastmod>` | **70 of 70 URLs show the build date**; the content last changed 2026-09-01 | `build.ts:99-122` reads `git log` and falls back to today. `.git` is excluded by `.dockerignore:4` and CI checks out at depth 1. The same value feeds JSON-LD `dateModified` and the "Last updated" footer |
| `/docs/assets/docs.css`, `search.js` | unhashed names served `Cache-Control: public, immutable` for a year, **without CSP** | the regex location `nginx-pod.conf:64-69` takes precedence over `location /docs/` (`:92-94`) and declares `add_header`, which drops the inherited security headers |
| `curl -sI https://meshharbor.itachi.fans/docs` | `301 Location: http://meshharbor.itachi.fans/docs/`, a **scheme downgrade** | absolute redirect built from the pod's `:80` listener behind the TLS edge |
| `/blog/`, `/this-does-not-exist` | **200** with the SPA shell (soft 404) | SPA fallback `nginx-pod.conf:97-99` |
| `/docs/start/install/windows` (no slash) | 200, duplicate of the slash form | `try_files $uri $uri/index.html` serves both |
| `/` | a client-rendered shell: an empty `<div id="app">` for any crawler that doesn't run JS | `/` is `meta.auth` (`ui/src/plugins/router.ts:119`); guests are redirected to `/landing` client-side (`:345`) |
| sitemap | lists `/landing /pricing /privacy /terms /imprint` (`site.ts:150`), all of which declare canonical `/` (`ui/index.html:24`) | contradictory signals |
| docs JSON-LD | author `"G ROX LTD"` (`layout.ts:221`), but the legal name everywhere else is G ROX EOOD; no `datePublished`, `image` or `mainEntityOfPage`; the `WebSite`/`SoftwareApplication` markup spec'd by FR-60 was never built (`LayoutCtx.extraJsonLd` is never passed, `build.ts:515-523`) | — |
| docs `<title>` | up to 71 chars (e.g. `/docs/compare/teamviewer/`) | the template `layout.ts:204-209` always appends " · section — MeshHarbor Docs" |
| docs pages | **no analytics**, so organic traffic isn't measured | purestat loads only in the SPA (`ui/index.html:42`) |
| `render.ts:194` | card title opens `<h2>` and closes `</h3>` | missed in FR-60's heading pass |
| Search Console | no verified property for meshharbor.itachi.fans on the operator's day-to-day Google account | — |

**What already works, and must keep working:**
- canonical, OG and Twitter tags, and inline JSON-LD on every docs page (the CSP allows data
  blocks);
- `robots.txt` (`Allow: /`, app paths disallowed);
- security headers on HTML identical to `/` (FR-60 AC6);
- the build gates.

## 3. Keyword targets (Google Keyword Planner, US, English, Sep 2025 – Aug 2026)

| Cluster | Monthly searches | Target page |
|---|---|---|
| teamviewer alternative (+ ~20 variants: alternative to teamviewer, teamviewer alternative free, teamviewer competitors, apps/software like teamviewer…) | 1K–10K (variants 100–1K) | the post: the story / "why" angle |
| self hosted / open source teamviewer alternative | 10–100 | the post (title tag, slug, dek) |
| unattended remote access (+ software, teamviewer / anydesk unattended access) | 100–1K; top-of-page bids €8–27 | `/docs/remote-desktop/unattended-access/`, linked from the post |
| remote desktop from browser, web browser remote desktop, teamviewer from browser, rdp browser | 100–1K, **+900% over 3 months** | `/docs/remote-desktop/`, linked from the post |
| teamviewer competitors, anydesk alternative | 100–1K | `/docs/compare/teamviewer/` |
| rustdesk alternative(s) | 100–1K | `/docs/compare/rustdesk/` |
| tailscale alternative, self hosted tailscale, netbird vs tailscale | 100–1K (bids to €46) | `/docs/compare/tailscale/` now; the mesh post later |

The post and each compare page target different angles of the same topic and link to each
other with different anchor text, so they don't compete for one query.

## 4. Design

### 4a. One generator, two collections plus a homepage

`ui/docs/build.ts` stays the only site writer. It gains a **blog collection**
(`ui/blog/posts/*.md`, assets in `ui/blog/assets/`) and a **homepage template**. They share the
`<head>`, sitemaps, robots, search index, link checker and a new asset pipeline. The build
command (`bun run build`, `ui/package.json:9`), the Dockerfile and the CI invocation
(`ci.yml:2035-2065`) stay as they are, and **no dependency is added**. A separate blog builder
was rejected: it would mean two writers of `dist/sitemap.xml` and a link checker that can't see
a `/blog` → `/docs` link.

New modules under `ui/docs/`:

| Module | Purpose |
|---|---|
| `dates.ts` | git → dates manifest |
| `theme/shell.ts` | shared `<head>`, topbar (Docs \| Blog), footer |
| `theme/structured.ts` | JSON-LD builders |
| `theme/xml.ts` | sitemap index, feed, robots |
| `theme/assets.ts` | content-hashed names, planned at load and written after the output is cleared |
| `theme/images.ts` | dimensions (the image rule itself is in `render.ts`) |
| `theme/links.ts` | the link checker, testable |
| `theme/posts.ts` | post schema, sorting, pagination |
| `theme/blog-layout.ts` | blog page renderers |
| `theme/home-layout.ts` | the homepage renderer |
| `theme/home.js` | the homepage's progressive enhancement |

`ui/src/utils/landing.ts` (planned as `plans.ts`; P6 moved all the landing copy into it, not
only the plan table) is a zero-import module shared by `LandingView.vue` and the homepage,
following the `enrollCommands.ts` pattern.

### 4b. Dates: a git manifest, a front-matter override, and no date when unknown

- **Manifest generation:** `bun ui/docs/dates.ts --write` runs one `git log` over the content
  and writes a deterministic `ui/docs/content-dates.json`, keyed by path with `created` and
  `modified`: committer **timestamps** with their offset (`%cI`, manifest version 2). P2 stored
  bare dates (`%cs`); P3 found in the Rich Results Test that Google flags a bare date in
  `datePublished`/`dateModified` as "invalid datetime … missing a timezone". The sitemap and the
  "Last updated" line use the date part, which equals `%cs`. It runs on `hosted-image.yml`, which already checks out full history (`:76`),
  before the Docker build, so `COPY ui/ .` carries the file in (the build context is a path, so
  untracked files are sent). The runner gets bun from `oven-sh/setup-bun`, pinned to 1.3.12 as
  in `ci.yml`, and `dates.ts` imports `node:*` only, so no install is needed. The CLI **refuses**
  on a shallow clone, because a depth-1 clone's one commit "touches" every file. The file is
  gitignored. The break-glass build-host path runs the same command (`ship-it` §4).
- **Docs resolution order:** front-matter `updated` → live git (only when the clone isn't
  shallow) → manifest → **undefined**.
- **Blog dates** come only from front-matter (`date`, `updated`), because they are editorial.
- **An undefined date is omitted** (no `<lastmod>`, no `dateModified`, no "Last updated"
  line), never replaced by the build date. A build path without the manifest, such as a
  self-host or break-glass build, shows no dates instead of wrong ones. Generated section and
  tag indexes have no source file, so they are undated too.

### 4c. Assets

- Every emitted asset gets a **content-hashed name**, `name.<sha256:10>.ext`, so the one-year
  `immutable` cache is correct. The unhashed copies (`LEGACY_UNHASHED_ASSETS` in `site.ts`) are
  emitted for one more release, so that cached HTML can still load them. They were meant to go
  in the first phase after P2's promote, but P2 rolled with P1–P5 on 2026-09-29 and P6 is
  ready the same day. Pre-P1 HTML carried no `Cache-Control`, so a browser may still hold it
  under heuristic caching (about 2.8 days). The flag is therefore turned off in the first
  release on or after **2026-10-03**, not in P6. It was turned off on 2026-10-04, and reaches
  production with the next promote.
- `social-preview.png` keeps its stable name, because `ui/index.html` points at it.
- **Inline markdown images** get a markdown-it rule that emits `width`/`height` read from the
  file itself (PNG, GIF, JPEG, WebP and SVG parsed by hand, no dependency),
  `loading="lazy"` and `decoding="async"`. An image alone in a paragraph becomes a
  `<figure>`/`<figcaption>`.
- **Build errors:** empty alt text, a remote or `data:` `src`, a raw `<img>`, a file over 3 MB,
  or a format the reader can't size. The raw-`<img>` check reads the **authored** source,
  because after the pre-pass every container is raw HTML, including an OS tab that holds a
  legal markdown image.
- Heroes get their real dimensions, replacing the hard-coded 960×420 at `layout.ts:236`.

### 4d. `<head>` and structured data

P3 builds this in `theme/shell.ts` (the shared `<head>`, top bar, footer, search dialog and
scripts), `theme/structured.ts` and `theme/xml.ts`.

- `og:type` is `website` on listings and `article` on leaves.
- `article:published_time`, `article:modified_time`, `article:author` and `article:tag`
  (docs leaves carry all but `article:author`, which needs a person's profile: the blog's).
- `max-image-preview:large` on every indexable page; `noindex, follow` on the rest.
- `og:image` with its width, height and alt text. Per-post `og:image`: the hero, at least
  1200 px wide at ~1.91:1. Docs keep the social card, because their heroes are SVG, which
  social platforms don't render.
- A `seoTitle` front-matter key, capped at 60 chars by a build gate. The default template drops
  " · section", then " — MeshHarbor Docs", to fit 60, and a title too long even bare is a build
  error asking for a `seoTitle`. Before P3, 8 of 65 titles ran 62–71 chars; after, 0 of 96.
- One Organization entity (`@id https://meshharbor.itachi.fans/#organization`, name "MeshHarbor", legalName
  "G ROX EOOD"), a node of every page's single `@graph`, which every author and publisher
  references.
- **Types by page:**
  - `BlogPosting` + `BreadcrumbList` on posts;
  - `Blog` on the blog index;
  - `TechArticle` + `BreadcrumbList` on docs pages, now with `datePublished`, `image` and
    `mainEntityOfPage`; `CollectionPage` on the docs home and on section and tag indexes, which
    are lists, not articles; a one-item breadcrumb is dropped;
  - `WebSite` + `Organization` on the homepage (`structured.ts` `website()`). The sitelinks
    SearchAction is not built: Google retired it in 2024. **Nor is `SoftwareApplication`**,
    which this spec first listed: its rich result requires `aggregateRating` or `review`, a
    page without them reports the markup as an error, and ratings are never invented. A unit
    test (`home.spec.ts`) fails if either type appears.
- `/sitemap.xml` becomes a **sitemap index** pointing at `sitemap-docs.xml` (which includes
  `/`) and `sitemap-blog.xml`, so Search Console reports each separately. The SPA routes are
  dropped.
- Front-matter becomes **strict**: an unknown key is an error.
- purestat analytics is added to the static pages (the CSP already allows it); setting
  `ANALYTICS = null` turns it off.

### 4e. The blog

P4 builds this in `theme/posts.ts` (the post contract, pure and tested), `theme/blog-layout.ts`,
`theme/blog.css`, and the feed in `theme/xml.ts`. The author's guide is `ui/blog/README.md`.

- **Posts** live at `/blog/<slug>/`. They require `title`, `description` (≤160), `date`,
  `author` (a key in `AUTHORS`) and `tags`. `date` and `updated` are full ISO timestamps (the
  Atom feed needs the time and zone, and Google flags a bare date).
- **Optional keys:** `seoTitle`, `subtitle`, `updated`, `hero` + `heroAlt`, `ogImage` +
  `ogImageAlt`, `related` (link-checked internal URLs), `syndication` (the Medium copy) and
  `canonical` (off-site only). The hero is optional because the first post showed why: its
  first image sits mid-text after "What it looks like today:", so moving it up would leave that
  sentence pointing at nothing, and repeating it would show it twice.
- **The share image** must be raster and at least 1200 px wide, and every post has one. A
  raster hero is its own share image; an SVG hero (crisp and a few KB on the page, but no
  social platform renders an SVG card), or no hero, needs `ogImage`. A post's images are looked up in `ui/blog/assets/` first, then the
  shared docs artwork, and published hashed under `/docs/assets/` with everything else.
- **Drafts:** there is no `draft` key, and a future `date` is a build error. A file in
  `ui/blog/posts/` counts as published, and drafts stay in the private promo repo, per
  FR-39's rule on post copy.
- **Listing and tags:** the index is newest first, 10 per page (`/blog/page/N/`). Tag pages
  appear at ≥3 posts and stay out of the sitemap, as in docs.
- **Feed:** an Atom 1.0 feed at `/blog/feed.xml` with full content, advertised by
  `<link rel="alternate">` on every page once one post exists.
- **Post page:**
  - dek (subtitle), author, published and updated `<time>`, reading time;
  - hero with `fetchpriority="high"`;
  - TOC;
  - "Also published on Medium";
  - an author box (with a bio the operator writes);
  - related docs, previous/next, and a self-host call to action.
- **Search and linking:** posts join the site search. A docs page linked from a post shows an
  "On the blog" backlink. The topbar and footer gain Blog and RSS links.
- **Kill switch:** an empty `ui/blog/posts/` produces no `/blog` output, links, feed or sitemap
  entries. Measured: with no posts, P4's `dist/docs`, sitemaps and robots.txt are
  byte-identical to P3's. The blog's styles live in their own `blog.css`, published and linked
  only once a post exists, so the docs' stylesheet (and every docs page) is unchanged.

### 4f. nginx (`files/nginx-pod.conf`)

```nginx
absolute_redirect off;                               # Location: /docs/ — never http://
location /docs/ { expires -1; error_page 404 /docs/404.html; }
location /blog/ { expires -1; error_page 404 /docs/404.html; }
location = /blog/feed.xml { types { } default_type application/atom+xml; expires -1; }
map $cookie_access_token $root_doc { "" /home/index.html; default /index.html; }   # http level
location = / { expires -1; try_files $root_doc =404; }
location ^~ /home/ { internal; }                     # one URL for the homepage: /
location = /landing { return 301 /; }
location = /pricing { return 301 /#pricing; }
```

- **`expires` only, never `add_header`, in these locations.** `expires` is inherited
  separately from `add_header`, so the server-level CSP, HSTS, XFO, XCTO, Referrer-Policy and
  Permissions-Policy survive. The smoke test proves it with a header diff against `/`.
- **No `try_files` in `/docs/` or `/blog/`.** nginx's static handler then answers a
  slashless directory with a 301 to the slash form, which `absolute_redirect off` keeps
  relative, and a missing file with a real 404. FR-60's `try_files $uri $uri/index.html =404`
  is what made `/docs/start` a 200 duplicate: its `$uri/index.html` test matches the file, so
  nothing ever redirects. (This section's first draft, `try_files $uri $uri/ =404`, does 301,
  measured in `nginx:stable`; it adds nothing, so P1 ships without it.)
- **The session cookie decides the homepage.** The session is the HttpOnly `access_token`
  cookie (`crates/api/src/routes/auth.rs:247`). No cookie (guests and every crawler) gets the
  static homepage; a cookie gets the SPA, whose router behaves as today. A cookie the server
  refuses gets the SPA, which sends the visitor to login on its first 401.
- **`try_files` serves the chosen file inside `location = /`**, so `expires -1` applies to both
  branches, the server's security headers survive on both, and `internal` on `/home/` does not
  block it. Without `internal`, `/home/` would be a second URL for the homepage.
- ⚠️ **The access cookie is not the whole session.** It lives 7 days; the refresh cookie lives
  30, but it is scoped to `Path=/api/auth/refresh` (`auth.rs:427`), so nginx never sees it at
  `/`. A returning user between day 7 and day 30 has no cookie nginx can read, and is served
  the static page by a site that could still sign them in silently. §4g's hand-off closes that
  gap.

### 4g. The homepage

`home-layout.ts` renders `dist/home/index.html` from `LandingView.vue`'s sections: hero, trust,
the three pillars, "Set up a device in minutes", pricing, and the call to action. The copy and
the fallback plan table live in `ui/src/utils/landing.ts`, a zero-import module (the
`enrollCommands.ts` pattern) that both `LandingView.vue` and the generator import, so the two
pages cannot drift. The install commands come from `enrollCommands.ts`, like every other place
they appear. The SPA's Material icons map to the docs' inline SVGs, and an unmapped icon fails
the build.

- **Progressive enhancement:** `home.js`, an external script (the CSP forbids inline ones).
  - **The signed-in hand-off** (§4f's gap). `home.js` loads in `<head>` without `defer`, so it
    runs before the page paints. When the SPA's localStorage hint (`meshharbor-signed-in`, written
    by `ui/src/api/session.ts`) says signed in, it replaces the page with `/login`. It must not
    use `/`, which would serve this page again: still no cookie. The SPA's guest guard sends a
    signed-in visitor on to the dashboard, whose first 401 refreshes the session. If the
    refresh fails, the SPA clears the hint and shows its login page, so a stale hint cannot
    loop. A crawler has no localStorage and stays on the page.
  - **The newsletter form** shows where the server mounts the list (`saas` in
    `/api/capabilities`, failing open as the SPA does) and posts to `/api/subscribe` with
    `source: "home"`.
  - **Live prices** from `/api/stripe/plans`, written as text, never markup.
  - Without JavaScript, the page stays complete and the form's place links to sign-up.
- **The router is unchanged.** This spec first had a signed-out visitor at the root, and a
  logout, navigate fully to `/`. That was dropped because it can loop. The SPA only runs at `/`
  when the request carried a cookie, so for a cookie the server refuses (a stale or foreign
  token), a full navigation to `/` returns the SPA again, every time. The existing client-side
  push to `/landing` cannot loop. Logout already expires both cookies on the server and pushes
  `/login`, so the next `/` is the static page anyway. `LandingView` keeps working for in-app
  navigation.

### 4h. Indexing

**Operator only**, because they involve the Google account or DNS. The agent can drive steps
1–4 in the browser, with the operator's go-ahead, if the Workspace account is signed in.

1. **Search Console:** Add property → **Domain `meshharbor.itachi.fans`** → Verify. A
   `google-site-verification` TXT record already exists on the domain.
2. **Sitemaps:** submit `https://meshharbor.itachi.fans/sitemap.xml` and expect "Success" for both child
   sitemaps.
3. **URL Inspection:** Request indexing for `/`, `/blog/`, the post, `/docs/`, and the
   teamviewer, rustdesk and tailscale compare pages. The quota is about 10 a day.
4. **Medium:** Story settings → Advanced Settings → Customize Canonical Link → the blog URL,
   the same day the post is live.
5. **Bing Webmaster Tools:** Import from Search Console.
6. **Review** at +3, +14 and +28 days: Pages by sitemap, Performance queries, Enhancements
   (Article, Breadcrumbs), Core Web Vitals.

**Agent:**
- **IndexNow:** a key file in `ui/public/`, and a POST of new or changed URLs after the
  health watch in `promote.yml`, gated on `vars.INDEXNOW_ENABLED`. Failure only warns, and no
  server code is involved. As built (P7), `scripts/indexnow.sh` does three things:
  - **`snapshot`** reads every child of the *served* `/sitemap.xml` into `loc⇥lastmod`. It
    runs before the bump and again after the health watch, when both pods serve the new
    image.
  - **`changed`** is the difference: the URLs that are new, or carry another `lastmod`. The
    lastmods come from git (P2), so a theme-only roll re-dates nothing and submits nothing,
    and an undated URL (`/`, generated listings) is submitted once, when it first appears. No
    baseline means nothing is submitted, never everything.
  - **`submit`** first fetches `/<key>.txt` from the site and refuses when it is not exactly
    the key; a missing file would otherwise answer with the SPA shell, and every engine would
    reject the POST. It then posts to `api.indexnow.org` (200/202 accepted; 403, 422 and 429
    named in the warning). The key's single source is the file name: the promote job
    sparse-checks-out `scripts/indexnow.sh` and `ui/public/*.txt`, nothing else. The smoke
    also checks the file is served as committed.
- **Validation:** Rich Results Test and Schema Markup Validator in the browser, the W3C Feed
  Validator, and PageSpeed Insights (mobile and desktop) through its API.
- **What not to expect or use:**
  - FAQ rich results, which have been limited to government and health sites since 2023;
  - a `SoftwareApplication` rich result, which needs ratings, and ratings are never invented;
  - the retired sitemap ping endpoint, and the Indexing API (job and livestream pages only).

## 5. Phases

| P | What | Kill switch |
|---|---|---|
| P0 | claim (issue #1776, spec, ledger row); baselines (§2); **FR-60 close-out**: tick its criteria from the #1165 evidence, run its missing Rich Results check, write `docs/public-site.md` v1 | docs only |
| P1 | nginx (§4f, without the homepage map), plus header-diff and redirect assertions in the `hosted-image.yml` smoke | revert the hunk |
| P2 | dates (§4b), hashed assets and the image pipeline (§4c), the search index URL read from a `data-` attribute, the `</h2>` fix, real hero dimensions | missing manifest ⇒ no dates |
| P3 | `<head>` and structured data, strict front-matter, `seoTitle`, sitemap index, analytics (§4d) | `ANALYTICS = null` |
| P4 | the blog engine (§4e) | empty `ui/blog/posts/` |
| P5 | the post; keyword-tuned `seoTitle`/`description` on the target docs pages (§3); Medium canonical | delete the post |
| P6 | the homepage (§4g) and its nginx branch | remove the `map` and `location = /` |
| P7 | indexing (§4h) | `vars.INDEXNOW_ENABLED` |
| P8 | docs: `docs/public-site.md` with mermaid diagrams (build flow, date resolution, nginx routing incl. the cookie branch, post authoring and the private-draft rule), a `docs/README.md` row, the field log | — |

**Deploy order:**
- P1 goes live before P2, so HTML is no-cache before any asset is hashed. The unhashed copies
  cover the overlap as well.
- P1's real 404s ship before `/blog`.
- P6's `map` ships in the same image as `dist/home/`.

## 6. Acceptance criteria

- [x] **AC1:** the build emits `dist/blog/{index.html,<slug>/,feed.xml}`, `dist/home/index.html`
  and `sitemap{,-docs,-blog}.xml`, with no change to `package.json`, `bun.lock` or the
  Dockerfile. *(P6 build: all seven files. `git diff 8eb895751^ -- ui/package.json ui/bun.lock
  Dockerfile`, the claim's parent to the P6 tree: empty. CI's docs step now fails without
  `dist/home/index.html`, or without `/` in `sitemap-docs.xml`.)*
- [x] **AC2:** every new gate is shown failing, then passing: missing alt, unknown key, `draft`,
  future `date`, `updated` < `date`, hero narrower than 1200 px, `seoTitle` over 60, a dead
  blog→docs link. *(Real builds on throwaway pages, #1780 and #1781: all eight, plus a remote
  image, a raw `<img>`, a missing file, a future `updated`, dead anchors and a dead `related`.)*
- [x] **AC3:** with no posts there is no `/blog` output and no Blog link. *(#1781: `dist/docs`,
  both sitemaps and robots.txt byte-identical to P3's, `diff -r`.)*
- [x] **AC4:** production `<lastmod>` equals `git log -1 --format=%cs` for 5 sampled docs files
  (baseline: 70/70 show the build date). *(All 65, not 5: the smoke at the deployed commit,
  §9.)*
- [x] **AC5:** the Rich Results Test reports 0 errors on the post (Article + Breadcrumbs), one
  docs page, and `/`. *(The post and `/docs/compare/teamviewer/`: Article + Breadcrumbs, no
  issues. `/`, after the P6 roll: crawled, 0 errors, "No items detected", because WebSite and
  Organization are not rich-result types; the Schema Markup Validator reads them with 0 errors
  and 0 warnings. §9.)*
- [x] **AC6:** the security headers are identical on `/` (SPA), the static homepage, a docs
  page and a blog page, and HTML is `no-cache`. *(Production at `dfb78e151`: 9 headers on
  `/docs/`, a leaf and `/blog/` equal to `/`'s; `/` identical with and without the session
  cookie; `no-cache` on `/`, `/docs/` and the post.)*
- [x] **AC7:** `/blog/nonexistent/` and `/docs/nonexistent/` return 404; `/docs`, `/blog` and a
  slashless docs path return 301 with a relative Location (baseline: `http://` downgrade and
  soft 404s). *(Production, §9.)*
- [x] **AC8:** `/blog/feed.xml` is served as `application/atom+xml` and the W3C validator
  accepts it. *("This is a valid Atom 1.0 feed", no recommendations.)*
- [x] **AC9:** every `/docs/assets` and `/blog/assets` URL in production HTML is content-hashed,
  and every image carries `width`/`height`. *(Production: `/docs/`, a quickstart page and the
  post — 11 asset URLs on the post, all hashed and loading, 5 of 5 images sized.)*
- [x] **AC10:** Lighthouse SEO scores 100 on `/`, `/blog/`, the post and two docs pages; other
  scores are recorded as measured. *(All five at 100 in every category; `/` measured on
  production after the P6 roll: LCP 1.7 s, CLS 0.)*
- [x] **AC11:** `curl /` without a cookie returns the static homepage (its H1 and JSON-LD); with
  `Cookie: access_token=x` it returns the SPA shell. `/landing` 301s to `/`. A signed-in user
  still lands on the dashboard (Playwright e2e green). *(The production smoke at `dfb78e151`;
  a signed-in browser loads the app straight from `/`, no redirect, and renders the dashboard;
  `auth.spec.ts` 10/10 on the P6 image and on production's, and exactly the two hand-off
  specs fail with the hand-off removed. §9.)*
- [x] **AC12:** Search Console shows the sitemap as "Success"; the post reports "URL is on
  Google" within 14 days of the request; Medium's page source carries a canonical link to the
  blog. *(All on day 0: the sitemap index reads Success; the post was indexed before any
  request, with the Google-selected canonical the blog URL itself, not Medium's.)*
- [x] **AC13:** Bing Webmaster Tools is verified, the first IndexNow POST returns 200/202, and
  purestat records `/blog/` visits. *(IndexNow: the first live POST, from the P6/P7 promote,
  returned **202** for `https://meshharbor.itachi.fans/`. Bing: the site was imported from Search Console,
  so its verification carried over, and the sitemap index was submitted ("successfully
  submitted for processing"). purestat, today: `/blog/` 3 and the post 3, among the top ten
  pages. §9.)*
- [x] **AC14:** docs updated or created with mermaid diagrams (`docs/public-site.md`) and indexed
  in `docs/README.md`. *(`docs/public-site.md` covers P1–P7: the build, dates, nginx routing
  with the cookie branch, the smoke, and the promote-time IndexNow flow, all diagrammed; its
  `docs/README.md` row lists them.)*

## 7. Open decisions

- **Author pages:** deferred until there are ≥3 posts. Until then `author.url` points to
  GitHub.
- **Demo media:** the GIF (2.2 MB, lazy-loaded) ships now; switching to an MP4 `<video>`
  (`media-src 'self'` allows it) is a follow-up.
- **Whether `/privacy`, `/terms` and `/imprint` also become static pages.** They stay SPA
  routes here and simply leave the sitemap.

## 8. Out of scope

- The text of future posts, including the mesh article.
- Translations.
- Comments.
- A public newsletter archive: FR-58's open question, which could later live on this blog.
- AMP.
- Paid search.

## 9. Field-verification log

| Date | Build | What | Result |
|---|---|---|---|
| 2026-09-28 | production (pre-FR) | the §2 baselines | all failing as listed; recorded as the "shown failing" runs |
| 2026-09-29 | production (pre-P1) | `scripts/public-site-smoke.sh https://meshharbor.itachi.fans . HEAD` | **FAIL**, 10 checks: `/docs` → `http://`; `/docs/start` 200; nginx's bare 404; `/blog/…` 200 (soft 404); no Cache-Control; feed `text/html`; 5 unhashed theme/hero files on each of two pages; **65 of 65** sitemap `lastmod`s = 2026-09-28 (the build) against git's 2026-09-01 |
| 2026-09-29 | P1 image, CI ([run 36558431414](https://github.com/jk-zhang-meta/MeshHarbor/actions/runs/36558431414)) | the P1 checks | pass, 7 security headers compared on `/docs/` and `/docs/start/` |
| 2026-09-29 | P2 build in `nginx:stable` + `files/nginx-pod.conf` | the smoke with `.`, three builds | **no git, no manifest**: `lastmod` check FAILS (every entry undated), as it must. **With dates**: all 11 pass, 65 of 65 `lastmod` = git |
| 2026-09-29 | P2 image, CI ([run 36561581485](https://github.com/jk-zhang-meta/MeshHarbor/actions/runs/36561581485)) | the real image path | runner `[dates] 65 files`; Docker (no `.git`) `dates: manifest, 65 of 65 pages`; smoke all 11 pass, `lastmod == git` for 65 pages |
| 2026-09-29 | P3 markup, Rich Results Test (code mode, the TeamViewer compare page) | AC5, before deploy | first run: Article + Breadcrumbs valid, **4 non-critical issues** (bare dates: "invalid datetime", "missing a timezone"); after the `%cI` fix: valid, **no issues** |
| 2026-09-29 | **production, `hosted-20260929-69fcf0a`** (P1–P5; promoted from `hosted-20260928-9834060`; 0 of 60 health probes failed during the roll) | `scripts/public-site-smoke.sh https://meshharbor.itachi.fans . 0d06c1d7f` | **all 12 pass**, the same script that failed 10 that morning: relative 301s; the site's 404 page on `/docs/…` and `/blog/…`; no-cache HTML; 9 security headers == `/` on `/docs/`, a leaf and `/blog/`; feed `application/atom+xml`; hashed, loading assets and sized images; **`lastmod` == git for all 65 docs pages** |
| 2026-09-29 | production | the rest of AC6/AC7/AC9 | the post: 9 security headers == `/`, `no-cache`; `/blog` and a slashless post → 301, relative; 11 asset URLs hashed and loading, 5 of 5 images sized, the share image 200 `image/png`; `/sitemap.xml` indexes `sitemap-docs.xml` + `sitemap-blog.xml` |
| 2026-09-29 | production | AC5, Rich Results Test (URL mode) | the post: **Article + Breadcrumbs, 2 valid, no issues**; `/docs/compare/teamviewer/`: **Article + Breadcrumbs, 2 valid, no issues**. `/` is owed (P6) |
| 2026-09-29 | production | AC8, W3C Feed Validator | "This is a valid Atom 1.0 feed", no recommendations |
| 2026-09-29 | production | AC10, Lighthouse 12.8.2 (mobile) | `/blog/`, the post, `/docs/compare/teamviewer/`, `/docs/remote-desktop/unattended-access/`: **Performance, Accessibility, Best Practices, SEO all 100**; LCP 0.9 / 1.7 / 1.0 / 0.9 s; CLS 0.000 on all four. `/` is owed (P6). (The PageSpeed Insights API was not usable: its keyless daily quota is shared and exhausted) |
| 2026-09-29 | Medium | AC12 (the Medium half) | the three approved typo fixes live on the public story (verified on the page, after a first "Save and publish" that silently did nothing); the story's `<link rel="canonical">` → `https://meshharbor.itachi.fans/blog/self-hosted-teamviewer-alternative/`. Search Console is owed (P7) |
| 2026-09-29 | the fleet, after the roll | counts only | devices 18 / 12 online / 5 offline, identical to before; peers 13 direct, 5 offline, 1 DERP, 1 upgrading (before: 13 / 5 / 2 DERP); this host's 7 tunnel flows all on `quic-v1`. No remote-desktop session was run: nothing in this roll touches that path |
| 2026-09-29 | **production (pre-P6)**, `hosted-20260929-69fcf0a` | `scripts/public-site-smoke.sh https://meshharbor.itachi.fans . 0d06c1d7f`, with P6's checks | **FAIL, 6 checks**; the 14 P1–P5 checks still pass. `/` without a cookie is the SPA shell; `/` has no `Cache-Control`; `/home/` is 200; `/landing` and `/pricing` are 200, not 301; `/` names no hashed assets. The cookie branch passes only trivially, because today the SPA answers `/` either way |
| 2026-09-29 | P6 build in `nginx:stable` + P6's `files/nginx-pod.conf` | the same smoke | **all 20 pass**: the static homepage without a cookie, the SPA with one, the same security headers on both, `no-cache`, `/home/` 404, `/landing` → `/`, `/pricing` → `/#pricing`, and `/`'s 8 assets hashed and loading |
| 2026-09-29 | the same, negative controls on a second container (a scratch copy of the conf; each mutation shown applied inside the container and passing `nginx -t`) | 8 mutations | each turns its named checks red, and the unmutated conf passes on the same container: the map's values swapped; the map keyed on `refresh_token`; `internal` dropped (`/home/` 200); `expires` dropped; **`add_header Cache-Control` in place of `expires`, which strips every security header from both branches**; `absolute_redirect on`; `/pricing` without its fragment; the `/landing` block removed |
| 2026-09-29 | `ui/docs/__tests__/home.spec.ts` (24 tests), negative controls | 6 mutations of `home.js` | each turns exactly its test red: the hint key drifting from `session.ts`'s; no `return` after the hand-off; a hand-off to `/` (the loop); the newsletter failing closed; features written as markup; the subscription dropping `source`. The first run also caught a real defect: the homepage description was 161 characters, one over the limit the build enforces on every docs page, and nothing checked the homepage's |
| 2026-09-29 | `scripts/indexnow.sh`, locally | `snapshot` · `changed` · `submit` | production's sitemaps (67 URLs) against the P6 build's (68): `changed` is exactly `https://meshharbor.itachi.fans/`; identical snapshots → nothing; no baseline → a warning and nothing. `submit` against a stand-in endpoint: the key file not served (the SPA shell answered) → refused, nothing posted; accepted → 3 URLs (a duplicate and a foreign host dropped; a quote and a backslash JSON-escaped, the body parsed as JSON); 422 and an unreachable endpoint → a warning and a non-zero exit, which the promote step's `continue-on-error` absorbs |
| 2026-09-29 | the smoke's key-file check (P7) | served · removed · production | the P6 build with the key file: ✓; without it: ✗ ("engines would reject every submission"); **production: ✗**, together with P6's six. (A first production run also failed `/docs`'s Location once, on a slow link from this host, the only such failure in six runs; the rerun, 49 s, passed it, and no promote had run in between) |
| 2026-09-29 | `ui/e2e/auth.spec.ts` against the hosted images on this box: each image's own nginx + API, a throwaway Mongo and Redis, and the e2e overlay's settings (`AUTH__AUTO_VERIFY`, rate limit 1000/s, burst 5000) | AC11's e2e half, before the roll | P6 (`hosted-20260929-db55edd`): **10/10, and 30/30 with `--repeat-each=3`**. Production's image (`69fcf0a`): 10/10, so no regression; there the unauthenticated-visitor spec takes its `/landing` branch. The P6 image with the hand-off removed from its served `home.<hash>.js` (the marker verified in the served file): **exactly the two hand-off specs fail** |
| 2026-09-29 | the same, first runs | two wrong turns, recorded | (1) Without the lane's limits, the fifth spec met a general `/api` bucket (burst 60, 1/s) that the four specs before it had spent. The refresh returned 200, its retries got 429, and the app ended the session anyway. (2) With the limits, the new spec still failed, **on both images**. `loginViaUi` returns while the dashboard still has requests in flight; one sent after the test changed the cookies got a 401 and started a refresh, and the test's own `goto` aborted it. The app counts an aborted refresh as a rejection, so it cleared its hint. The spec now parks on `about:blank` before touching cookies. It also waits for a fresh cookie that `/api/auth/me` accepts, instead of dashboard text, which renders from the hint alone. Both app behaviours predate P6 and are filed as #1788 |
| 2026-09-29 | **the P6/P7 roll**: `hosted-20260929-69fcf0a` → `hosted-20260929-c6c2934` ([promote run 36626148679](https://github.com/jk-zhang-meta/MeshHarbor/actions/runs/36626148679)); `INDEXNOW_ENABLED` set first (operator's go-ahead) | the roll and AC13's IndexNow half | 0 of 60 health probes failed. IndexNow: 67 URLs before the bump, 68 after, `changed` = exactly `https://meshharbor.itachi.fans/`, **HTTP 202**, the first live submission |
| 2026-09-29 | **production, `dfb78e151`** | `scripts/public-site-smoke.sh https://meshharbor.itachi.fans . dfb78e151` | **all 21 pass**: the same run failed P6's six checks and the key-file check before the roll. The first post-roll run failed `/landing`'s Location once, as `/docs`'s had that afternoon. The check read the status and the Location from two requests, and the second one blipped; six direct probes all answered 301 `Location: /`. The script now reads both from one response, and the eight nginx negative controls still turn red with it |
| 2026-09-29 | production `/` | AC5 and AC10, the homepage | Rich Results Test: crawled, 0 errors, "No items detected" (WebSite and Organization aren't rich-result types). Schema Markup Validator: WebSite, with its Organization publisher, **0 errors, 0 warnings**. Lighthouse 12.8.2 (mobile): **100 / 100 / 100 / 100**, LCP 1.7 s, CLS 0 |
| 2026-09-29 | production, a signed-in browser | AC11's signed-in half | `/` loads the app straight from `/` (navigation entry `/`, no redirect: the session cookie branch), and the dashboard renders; checked by DOM, not screenshot, and the tab closed at once |
| 2026-09-29 | **Search Console**, the Workspace account (the operator signed in; the agent never saw a credential) | AC12 | Domain property `sc-domain:meshharbor.itachi.fans` **auto-verified** by the existing DNS record. Sitemap index submitted: "Couldn't fetch" at first, **Success** minutes later (every sitemap answers 200 to a Googlebot user agent). The post: **"URL is on Google"**, indexed, last crawl 20:24Z, referred from `/blog/`, **Google-selected canonical = the blog URL**, not Medium's. `/`, `/blog/`, `/docs/` and the three compare pages were also on Google. Indexing requested for `/` (the static page is new), `/docs/` (last crawled 09-27) and the three compare pages (titles changed in P5): 5 of the ~10 a day |
| 2026-09-29 | the fleet, after the roll | counts only | devices 17 / 12 online / 5 not, identical to before the roll; peers 14 direct, 1 relay, 5 offline; this host's 7 tunnel flows all on `quic-v1` |
| 2026-09-30 | **Bing Webmaster Tools**, signed in by the operator | AC13's Bing half | "Import from Google Search Console" with the operator's go-ahead: Google's consent screen asked for exactly "View Search Console data for your verified sites" (`webmasters.readonly`). 1 site found, imported with the Administrator role, so verification carried over. Sitemap index submitted: "successfully submitted for processing", 1 known sitemap. Bing's IndexNow page for the new site stays at its introduction until the import's data lands (up to 48 h) |
| 2026-09-30 | **purestat**, the operator's dashboard | AC13's purestat half | Today: `/blog/` 3 and `/blog/self-hosted-teamviewer-alternative/` 3, plus `/docs/reference/ports-and-firewall/` 3 and `/docs/compare/teamviewer/` 2, all among the top ten pages. The static pages' analytics (P3) work. Three findings for purestat itself: the pages list stops at ten; `localhost` shows as a source (local test runs of pages that load the script get counted); and app paths carry tenant and device ids. Planned in the purestat repository, not here |

## 10. Related

- [FR-60](FR-60-public-docs-site.md): the generator this extends. P0 closes it out.
- [FR-58](FR-58-newsletter-sending.md): the newsletter and its hero images, versioned
  `ui/public/newsletter-img/*-vN.png`.
- [FR-39](FR-39-launch-readiness.md): post copy stays private until published; prerendering
  was out of scope there, and P6 does it here.
- [FR-73](FR-73-image-build-on-github.md): the hosted-image and promote pipeline P1, P2 and P7
  change.
