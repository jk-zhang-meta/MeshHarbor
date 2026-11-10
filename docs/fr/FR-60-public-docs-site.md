# FR-60: Public documentation site at meshharbor.itachi.fans/docs

**Issue:** [#1165](https://github.com/jk-zhang-meta/MeshHarbor/issues/1165) ·
**Status:** proposed · **Owner:** web/docs

## Goal

Ship `https://meshharbor.itachi.fans/docs` — a **static, searchable, individually-indexable**
documentation site that onboards a visitor **per operating system** and showcases
all three pillars (remote desktop · private mesh · conferencing & chat) in the
visual language of `/landing` and the in-app tutorial.

The bar is not "docs exist". It is: **a stranger who has never heard of MeshHarbor
can arrive from a search engine, understand what it is, install it on their own
OS, and reach their first device — without an account and without reading Rust.**

## 1. Field evidence — what a visitor and a crawler get today

MeshHarbor is three products on one daemon across Windows, macOS and Linux, and
**there is no public documentation site at all**. What exists instead:

| Surface | What it is | Why it does not serve a visitor |
|---|---|---|
| `meshharbor.itachi.fans/landing` | Marketing page | Sells the product, teaches nothing |
| `meshharbor.itachi.fans/tenant/{id}/tutorial` | 8-chapter in-app tour (FR-12 #788) | **Behind auth** — invisible to a crawler and to anyone still evaluating |
| `docs/*.md` (39 files) | Engineering design docs | Right depth, wrong audience and wrong voice — and carries fleet host names, incident narratives and internal landmine notes that must not become a marketing surface |

Four gaps measured while scoping, each closed by this FR:

1. **No `robots.txt` and no `sitemap.xml` exist anywhere in the repo.**
   `find . -name 'robots.txt' -o -name 'sitemap*'` returns empty. A site with no
   sitemap is not forbidden from being indexed; it is just slower and shallower
   about it, and every page has to be found by link-walking a client-rendered SPA.

2. **`ui/index.html` carries no SEO metadata at all** — `<title>MeshHarbor</title>`
   and nothing else. No description, no canonical, no Open Graph. Every public
   route (`/landing`, `/pricing`, `/privacy`, `/terms`, `/imprint`) shares that
   one title, and a link shared to Slack or X renders with no card.

3. **No FAQ page and no troubleshooting doc exist in the repo.**
   `grep -rlniE '^#+ .*(FAQ|troublesh)'` over `docs/*.md` returns nothing for
   either. Both are net-new writing — and both are what a stuck user actually
   types into a search box.

4. The two reference sites this was modelled against both solve exactly this:
   **Tailscale** organises around four task buckets (*get started → manage your
   tailnet → expand your tailnet → resources and reference*), and **RustDesk**
   opens with a *"which RustDesk path should you choose?"* decision table over
   Client / Server OSS / Server Pro / Development, then goes deep on per-OS
   install (`.deb` / `.rpm` / `pacman` / `zypper` / nix / AppImage).

This FR continues **FR-39 (#951)**, which measured that the product is unfindable
and shipped repo metadata, comparison docs and a self-host path — but no docs site.

## 2. Key design

### 2a. An in-repo static generator, not a second toolchain

Content and generator live at **`ui/docs/`**; output lands in `ui/dist/docs/`.

```
ui/
├── docs/
│   ├── content/**/*.md      Markdown + YAML frontmatter (the prose)
│   ├── theme/
│   │   ├── layout.ts        page shell, <head>, nav, breadcrumbs, JSON-LD
│   │   ├── render.ts        markdown-it config + containers/directives
│   │   ├── docs.css         design tokens + components
│   │   ├── search.js        ~4 KB, no deps, same-origin
│   │   └── os-tabs.js       ~1 KB, cross-page OS persistence
│   ├── assets/*.svg         heroes + diagrams
│   └── build.ts             md -> html + search index + sitemap + robots
└── dist/docs/**             build output
```

Four reasons this shape, each checked against the tree rather than assumed:

- **`markdown-it@14` and `dompurify` are already `ui` dependencies**
  (`ui/package.json`), so the renderer costs no new dependency.
- **The Dockerfile is untouched.** Stage 2 is `COPY ui/ .`, stage 3 is
  `COPY --from=ui-builder /app/ui/dist /var/www/meshharbor`. A top-level
  `docs-site/` would have needed a new build stage, a new COPY and a
  `.dockerignore` entry; `ui/docs/` needs none of them.
- **`vite build` empties `dist/`**, so `bun docs/build.ts` must run *after* it.
  It also writes `sitemap.xml` and `robots.txt` into `dist/` root, which is why
  those two are this FR's job and not a separate chore.
- **No Vue runtime on a docs page.** Output is HTML + one stylesheet + ~5 KB of
  JS. LCP is a ranking signal; shipping a SPA framework to render static prose
  spends it for nothing.

⚠️ `ui/tsconfig.json` `include` is `src/**/*` only, so `docs/**/*.ts` must be
added to it — otherwise `vue-tsc --noEmit` never type-checks the generator and a
broken build script ships silently.

### 2b. The volatile facts are generated from code

Docs rot where they restate something the code owns. The install commands are the
worst offender, so they are not written by hand at all: a
`::: enroll windows|macos|linux :::` directive expands at build time from
**`ui/src/utils/enrollCommands.ts`** — a **pure module with zero imports**,
already locked by `ui/src/__tests__/utils/enrollCommands.spec.ts` and already the
single source for the landing page and the in-app enrollment dialog. A flag or
binary rename therefore fails a unit test instead of shipping stale docs.

The build **fails**, not warns, on:

| Condition | Why a gate and not a lint |
|---|---|
| Missing `title` / `description` / `tags` | A page with no description gets a search-engine-invented snippet |
| `description` over 160 chars | Silently truncated in results |
| Duplicate slug | Two pages compete for one URL |
| Internal link resolving to no generated page | **A docs site whose own nav 404s costs more SEO than the site earns** |

### 2c. Search that needs no security-header change

`build.ts` emits `search-index.json` — one record per **section**, not per page,
carrying `{url, page title, heading, tags, excerpt}`. `search.js` (~4 KB, no
deps) does prefix + tag scoring, `/` to focus, arrow-key navigation, grouped
results and a `tag:` filter. The index is fetched lazily on first focus, so it
costs nothing on page load, and the build fails if it exceeds 150 KB gzipped —
growth is then a decision rather than a silent regression.

**Pagefind was rejected deliberately.** It is the better ranker at scale, but it
is WASM, and the pod CSP is `script-src 'self'` with no `wasm-unsafe-eval`
(`files/nginx-pod.conf`). Adopting it means widening a security header to ship a
docs feature. This design works under the CSP exactly as it stands.

⚠️ `application/ld+json` is a **data block**, not an executable script, so
`script-src 'self'` does not block the JSON-LD. That is asserted here and
**verified in the browser console during P1** — not taken on faith.

### 2d. One nginx location, and the `add_header` footgun

```nginx
location /docs/ {
    try_files $uri $uri/index.html =404;
}
```

**No `add_header` and no `expires` inside that block.** nginx inherits
`add_header` from the parent level *only if the current level declares none*, so
a single `add_header Cache-Control` there would silently drop CSP, HSTS,
X-Frame-Options, X-Content-Type-Options, Referrer-Policy and Permissions-Policy
for every docs page.

⚠️ This is not hypothetical. The existing `location ~* \.(js|css|woff2?|…)$`
block in the same file declares `add_header Cache-Control "public, immutable"`
and therefore **already drops all seven server-level security headers for every
static asset today**. Recorded here because it is the proof the footgun is live
in this exact file, and because the check for it (AC6) is cheap and falsifiable.

The front reverse proxy needs no change: `/docs` rides the same host, and both
pods serve byte-identical static copies, so the tenant-affinity hash is
irrelevant for it.

### 2e. Information architecture (~50 pages)

`/docs/` opens with a **"which path are you on?"** decision table — RustDesk's
best idea — over three pillar cards and the landing page's capability chip strip.

```
/docs                      home · decision table · pillar cards · chips
├── /start             9   what-is-meshharbor · quickstart · install/{windows,macos,linux}
│                          · tunnel-cli · enrollment · verify-your-install · self-hosting
├── /remote-desktop    7   overview · first-session · unattended-access · consent
│                          · codecs-and-performance · files-and-clipboard · per-os-permissions
├── /network          10   overview · addresses-and-magicdns · how-devices-connect
│                          · subnet-routers · exit-nodes · tunnels · socks5 · ssh
│                          · multi-org · ephemeral-nodes
├── /collaboration     4   rooms-and-chat · video-conferencing · files · notifications
├── /architecture      4   system-overview · the-agent · connection-cascade · what-the-server-sees
├── /security          7   security-model · users-roles-permissions · overlay-acls
│                          · device-policies · consent-and-audit · signed-releases · self-host-hardening
├── /troubleshooting   6   device-offline · cannot-connect · black-screen · calls-no-media
│                          · install-problems-per-os · collecting-diagnostics
├── /reference         4   cli · configuration · ports-and-firewall · api
├── /faq               1   FAQPage JSON-LD
├── /compare           5   tailscale · rustdesk · teamviewer · meshcentral · netbird
└── /tags/<tag>            generated at >=3 pages; thin ones noindex
```

Tailscale's four buckets map onto `start → security/collaboration →
remote-desktop/network → reference`; RustDesk's per-OS install depth maps onto
the three `start/install/*` pages plus OS tabs wherever a command differs.

### 2f. Visual language — reuse, do not reinvent

Every page composes from blocks that already ship, so the docs read as the same
product as `/landing` and the tutorial:

| Block | Mirrors |
|---|---|
| H1 + **tag chips** | landing capability strip (`LandingView.vue:41-47`) |
| Hero SVG on a light panel | tutorial hero (`TutorialView.vue`) |
| Badge cards (icon avatar + bold lead-in) | tutorial `badges` |
| Numbered / icon step lists with copyable code | tutorial `steps` |
| Feature cards | landing pillar cards |
| Callouts `:::note :::tip :::warning :::danger` | new; coral for danger |
| **OS tabs** | new — **CSS-only** (`input[type=radio]` + `:checked ~`), so they work with JS off and under the CSP; `os-tabs.js` only adds cross-page persistence |

Artwork is reused from `ui/src/assets/tutorial/*.svg` (8 heroes + 7 step
graphics) and `docs/assets/*.svg`. Bold is used the way the tutorial uses it —
marking the load-bearing noun in a sentence, not decoration.

**Colour tokens** come from `lightTheme` (`ui/src/plugins/vuetify.ts:13-24`):
teal `#009688`, coral `#ef5350`.

### 2g. Tags

Frontmatter `tags:` render as the chip strip under the H1, link to generated
`/docs/tags/<tag>/` indexes, and seed the search filter. A tag index is generated
only at **>=3 pages**, and thin ones carry `noindex` — otherwise a wall of
one-link tag pages reads to a crawler as doorway pages, which is a penalty, not
an optimisation.

### 2h. SEO plumbing

Per page: unique `<title>` (`{page} · {section} — MeshHarbor Docs`), frontmatter
`description`, absolute `<link rel="canonical">`, Open Graph + Twitter card
(image from `docs/assets/social-preview.png`), exactly one `<h1>`, stable
heading anchors with permalinks, prev/next and related links.

JSON-LD: `TechArticle` + `BreadcrumbList` per page; `FAQPage` on `/docs/faq`;
`SoftwareApplication` + `WebSite`/`SearchAction` on `/docs`.

Site-wide, emitted into `ui/dist/` root: `sitemap.xml` (docs pages plus the
public SPA routes, `lastmod` from git) and `robots.txt` (allow, `Sitemap:` line,
`Disallow: /tenant/`). `ui/index.html` gains description + OG/Twitter so the
marketing routes stop being title-only, and the Dockerfile's
`org.opencontainers.image.documentation` label repoints at `https://meshharbor.itachi.fans/docs`.

### 2i. What this deliberately does NOT do

**`docs/*.md` is not republished.** That tree stays the engineering record and is
*linked out to* for depth. It names fleet hosts, replays incidents and carries
operator landmines; rendering it onto a marketing domain would publish all of
that, in a voice written for whoever maintains the daemon. The docs site is a
separate, user-facing content set with a different audience on purpose — and the
facts that would otherwise drift between the two are generated from code (§2b).

## 3. Phases

| # | Phase | Contents | Kill switch |
|---|---|---|---|
| P1 | Engine + theme + SEO plumbing | `build.ts`, theme, search, OS tabs, sitemap/robots, nginx location, `ui/index.html` meta, tsconfig include, link checker, vitest specs, ~6 real pages | Drop the `location /docs/` block, or do not run `bun docs/build.ts` |
| P2 | Getting started | 9 pages, all three OSes, `enrollCommands` wired | Additive content only |
| P3 | Pillars | remote-desktop (7) + network (10) + collaboration (4) | Additive content only |
| P4 | Architecture + Security | 4 + 7 pages, new diagrams | Additive content only |
| P5 | Troubleshooting + Reference + FAQ | 6 + 4 + 1 pages, all net-new | Additive content only |
| P6 | Compare + tags + audit | 5 comparison pages, tag indexes, SEO pass, field verification | Additive content only |

Every phase is additive static output; nothing outside `dist/docs` reads it.

## 4. Acceptance criteria

Evidence for AC1–AC8 and AC10 is the field result on #1165 (2026-09-01/02, three deploys);
the boxes were never walked back to until FR-87's close-out.

- [x] **AC1** — `cd ui && bun run build` emits `dist/docs/**`, `dist/sitemap.xml`, `dist/robots.txt`; `Dockerfile` is unchanged. *(#1165 result: 70 sitemap URLs.)*
- [x] **AC2** — The link checker is shown to **FAIL** on a deliberately broken internal link and to pass when restored; likewise a missing frontmatter `description`. *(#1165 result, plus the OG-image gate.)*
- [x] **AC3** — Every page emits a unique `<title>`, `<meta name="description">`, absolute canonical, OG/Twitter tags, and valid `TechArticle` + `BreadcrumbList` JSON-LD; `/docs/faq` emits valid `FAQPage`. *(#1165 result: FAQPage with 21 Q&A pairs.)*
- [x] **AC4** — Search returns results and keyboard-navigates; tags filter; index <=150 KB gzipped, with the build failing above it. *(#1165 result: 59.4 KB gz.)*
- [x] **AC5** — OS tabs work **with JavaScript disabled**, and persist across pages with JS on. *(#1165 result: CSS `:checked` baseline.)*
- [x] **AC6** — `curl -sI https://meshharbor.itachi.fans/docs/start/install/windows/` returns the **same** CSP, HSTS and X-Frame-Options headers as `curl -sI https://meshharbor.itachi.fans/`. *(#1165 result; and since FR-87 P1 on every image, by `scripts/public-site-smoke.sh`.)*
- [x] **AC7** — Each of Windows, macOS and Linux has a complete install path, verified against the served installers rather than against memory. *(#1165 result.)*
- [x] **AC8** — All three pillars plus architecture, security & access control, troubleshooting and FAQ are present and non-stub. *(#1165 result: 65 authored pages across 10 sections.)*
- [x] **AC9** — Field: `/docs/`, `/robots.txt` and `/sitemap.xml` all 200 on production; Google Rich Results validates the FAQ page and one doc page. *(200s: #1165 result. Validation, run at FR-87's close-out on 2026-09-29 against production: `/docs/compare/teamviewer/` Article + Breadcrumbs, 2 valid, no issues; `/docs/faq/` Breadcrumbs valid, and its FAQPage 0 errors / 0 warnings in the Schema Markup Validator. The Rich Results Test does not list FAQPage for this site: Google has limited FAQ rich results to government and health sites since 2023.)*
- [x] **AC10** — Lighthouse SEO **and** Performance recorded for three sampled pages — **including any number that misses its bar**, recorded rather than reworded. *(#1165 result: seven page shapes, SEO/A11y/BP 100, Performance 100 on six and 98 on `/docs/compare/tailscale/`.)*
- [x] **AC11** — Docs: [`docs/public-site.md`](../public-site.md) describes the generator in the house style (mermaid, tables, `file:line` anchors) with a row in `docs/README.md`. *(Added at close-out: the docs-before-close rule of 2026-09-05 postdates this spec. Landed with FR-87's close-out PR.)*

## 5. Open decisions

- **Light-only for v1.** `LandingView.vue` wraps itself in
  `<v-theme-provider theme="light">`, and every hero SVG is a light-palette
  artwork that the tutorial already paints on a fixed light panel in both themes
  rather than forking per theme. The palette ships as CSS custom properties, so
  dark mode later is one token block plus a decision about the artwork.
- Whether `/docs/compare/*` is published on the marketing domain or stays
  GitHub-only. Planned as published — it is the highest-intent SEO in the tree.
- Whether the CLI and configuration reference pages are hand-written now and
  generated from clap / `config_surface` later.

## 6. Out of scope

- Localisation. English only; no `hreflang`.
- Republishing `docs/*.md` (see §2i).
- Versioned docs (`/docs/v0.4/…`).
- Dark mode (see §5).

## 7. Number note — claimed 58, **renumbered twice, landed at 60**

Three number events in one session. Recorded in full because the arc is the
strongest evidence the ledger has for its own central rule, and because it kept
happening for exactly the reason the rule names.

**First, at claim time**, `FR-57` was carried by **two** open issues —
[#1161](https://github.com/jk-zhang-meta/MeshHarbor/issues/1161) and
[#1163](https://github.com/jk-zhang-meta/MeshHarbor/issues/1163) — neither of which
had reached this ledger. Taking a number already contested by two in-flight
claims would have manufactured a three-way collision rather than resolving one,
so this claimed **FR-58** and left 57 to settle between them.

**Then FR-58 was taken anyway.** While this work was on a branch, master
absorbed nine commits, among them
[#1170](https://github.com/jk-zhang-meta/MeshHarbor/issues/1170) — *newsletter
sending* — carrying a `FR-58` ledger row and `docs/fr/FR-58-newsletter-sending.md`.

⚠️ **The LEDGER arbitrated, and it moved this claim rather than theirs, even
though this issue id is LOWER** (#1165 vs #1170). The lower-issue-id repair rule
applies only when two claims have **both landed on master**. This one had not:
it existed on a branch, which is invisible to every other session, exactly as a
memory file would be. A claim that never reached master moves — the same
resolution FR-50 recorded when #1086 took its number mid-flight.

**Then FR-59 was taken too** — while the FR-58 → FR-59 repair was being made,
master gained [#1163](https://github.com/jk-zhang-meta/MeshHarbor/issues/1163)
(*slow-link latency priority*), which had itself just renumbered off FR-57 for
the same reason. So this renumbered again, to **FR-60**.

⚠️ **A near-miss worth recording.** Resolving the ledger conflict by line index
was wrong, and the next rebase would have made it dangerous: `git diff
origin/master HEAD -- docs/fr/README.md` was read specifically to check whether
the resolution had clobbered anyone, and it appeared to have deleted master's
FR-59 row. It had not — master had gained that row *after* the rebase — but the
resolution technique could not have told the difference. **Resolve a shared
append-only table by re-appending onto the other side's version, never by line
number**, and diff against master afterwards. That check is cheap and it is the
only thing that distinguishes a merge from a silent revert.

So: renumbered **FR-58 → FR-59 → FR-60** — spec filename, title, ledger row, and
all 22 in-body and in-code references each time, verified mechanically as 20
insertions against 20 deletions so the sweep touched FR references and nothing
else. Never into a vacated number, and nothing already settled was disturbed.

🔑 The lesson this adds to the ledger's own: **the claim protocol only protects
you once the row is on master.** Pushing a branch is not claiming. On a long
piece of work, land the spec-and-row commit early rather than carrying it
alongside the implementation.

## 8. Field-verification log

The full record is the result comment on #1165 (2026-09-01/02, three deploys, seven page
shapes in Lighthouse). The close-out on 2026-09-29, after FR-87 P1–P5 reached production:

| Date | What | Result |
|---|---|---|
| 2026-09-29 | Rich Results Test, `/docs/compare/teamviewer/` | Article + Breadcrumbs, 2 valid, no issues |
| 2026-09-29 | Rich Results Test + Schema Markup Validator, `/docs/faq/` | Breadcrumbs valid; FAQPage 0 errors, 0 warnings (not listed by the Rich Results Test: FAQ rich results are government/health only since 2023) |
| 2026-09-29 | `scripts/public-site-smoke.sh` (FR-87) against production | all 12 checks pass, incl. header equality (AC6) on every page family |
