// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-87 (#1776) P6 — the static homepage, written to `dist/home/index.html`
 * and served at `/` to every visitor without a session cookie: guests, and
 * every crawler.
 *
 * The copy is the SPA landing page's, from `ui/src/utils/landing.ts`, so the
 * two cannot drift; the install commands come from `enrollCommands.ts`, like
 * every other place they appear.
 */
import { installCards } from '../../src/utils/enrollCommands.ts'
import {
  CAPABILITIES,
  CTA,
  DOWNLOAD,
  HERO,
  PILLARS,
  VIDEO_TOUR,
} from '../../src/utils/landing.ts'
import type { SiteVideo } from '../../src/utils/videos.ts'
import { BASE, SITE_ORIGIN } from '../site.ts'
import { icon, OS_ICON } from './icons.ts'
import { escapeHtml, type ResolvedImage } from './render.ts'
import { videoFacade } from './video.ts'
import {
  renderBodyScripts,
  renderFooter,
  renderHead,
  renderSearchDialog,
  renderTopbar,
  type ShellNav,
  type SiteAssets,
} from './shell.ts'
import { graph, organization, videoObject, website } from './structured.ts'

export const HOME_TITLE = 'MeshHarbor — remote desktop & private mesh network'
export const HOME_DESCRIPTION =
  'Remote desktop in a browser tab and a private WireGuard-style mesh between your machines. Self-hostable, end-to-end encrypted.'

/** The SPA's Material icons, drawn on this page with the docs' inline SVGs.
 *  An icon the map does not know FAILS the build, like an unknown icon
 *  name does: a copy edit must not ship a card with an empty corner. */
const ICON: Record<string, string> = {
  'mdi-monitor-eye': 'monitor',
  'mdi-shield-lock-outline': 'shield',
  'mdi-monitor-multiple': 'monitor',
  'mdi-lan': 'network',
  'mdi-router-network': 'network',
  'mdi-dns-outline': 'link',
}

function iconFor(mdi: string): string {
  const name = ICON[mdi]
  if (!name) throw new Error(`home: no inline icon for "${mdi}" — map it in ui/docs/theme/home-layout.ts`)
  return icon(name, { size: 30 })
}

export interface HomeCtx {
  assets: SiteAssets
  nav: ShellNav
  hero: ResolvedImage
  /** FR-88 P3: the featured video and its published poster; no section without it. */
  video?: { video: SiteVideo; poster: ResolvedImage }
}

export function renderHome(ctx: HomeCtx): string {
  const head = renderHead({
    title: HOME_TITLE,
    description: HOME_DESCRIPTION,
    canonical: `${SITE_ORIGIN}/`,
    noindex: false,
    og: { type: 'website', title: HOME_TITLE },
    jsonLd: graph([
      organization(),
      website(),
      ...(ctx.video ? [videoObject({ ...ctx.video.video, thumbnailUrl: `${SITE_ORIGIN}${ctx.video.poster.url}` })] : []),
    ]),
    assets: ctx.assets,
    feed: ctx.nav.hasBlog,
    blogStyles: false,
    styles: ctx.assets.homeCss ? [ctx.assets.homeCss] : [],
    headScripts: ctx.assets.homeJs ? [ctx.assets.homeJs] : [],
  })

  const pillars = PILLARS.map(
    (pillar) =>
      `<div class="home-pillar"><h2 class="home-h2">${escapeHtml(pillar.title)}</h2>` +
      `<p class="home-sub">${escapeHtml(pillar.subtitle)}</p><div class="home-cards">` +
      pillar.features
        .map(
          (f) =>
            `<div class="home-card"><span class="home-card__icon" style="color:${escapeHtml(f.color)}">${iconFor(f.icon)}</span>` +
            `<h3 class="home-card__title">${escapeHtml(f.title)}</h3><p class="home-card__text">${escapeHtml(f.description)}</p></div>`,
        )
        .join('') +
      `</div></div>`,
  ).join('')

  const downloads = installCards(SITE_ORIGIN)
    .map(
      (card) =>
        `<div class="home-card home-card--os"><h3 class="home-card__title home-os">${icon(OS_ICON[card.os]!, { size: 22 })}<span>${escapeHtml(card.title)}</span></h3>` +
        (card.wizardUrl
          ? `<p><a class="btn btn--tonal" href="${escapeHtml(card.wizardUrl)}">${icon('download', { size: 17 })}<span>MeshHarbor Setup</span></a></p>`
          : '') +
        `<p class="home-muted">${card.wizardUrl ? 'Or from a terminal:' : 'From a terminal:'}</p><pre class="home-cmd"><code>${escapeHtml(card.command)}</code></pre>` +
        `</div>`,
    )
    .join('')

  const main = `<main id="main" class="home">
  <section class="home-hero">
    <div class="home-wrap home-hero__grid">
      <div class="home-hero__copy">
        <h1 class="home-hero__title">${escapeHtml(HERO.titleLead)}<br><span class="home-accent">${escapeHtml(HERO.titleAccent)}</span></h1>
        <p class="home-hero__lead">${escapeHtml(HERO.lead)}</p>
        <p class="home-actions"><a class="btn btn--primary btn--lg" href="/register">Start free</a><a class="btn btn--tonal btn--lg" href="#download">Download</a></p>
      </div>
      <figure class="home-hero__art"><img src="${escapeHtml(ctx.hero.url)}" alt="Laptops, servers and cloud machines joined in one encrypted mesh, reached from a browser tab" width="${ctx.hero.width}" height="${ctx.hero.height}" loading="eager" fetchpriority="high" decoding="async"></figure>
    </div>
  </section>

  <section class="home-caps" aria-label="What MeshHarbor does">
    <ul class="chips home-wrap">${CAPABILITIES.map((c) => `<li><span class="chip">${escapeHtml(c)}</span></li>`).join('')}</ul>
  </section>
${
  ctx.video
    ? `
  <section id="video" class="home-section home-video">
    <div class="home-wrap home-video__inner">
      <h2 class="home-h2">${escapeHtml(VIDEO_TOUR.title)}</h2>
      <p class="home-sub">${escapeHtml(VIDEO_TOUR.lead)}</p>
      ${videoFacade(ctx.video.video, ctx.video.poster)}
    </div>
  </section>
`
    : ''
}
  <section id="features" class="home-section">
    <div class="home-wrap">${pillars}</div>
  </section>

  <section id="download" class="home-section home-section--soft">
    <div class="home-wrap">
      <h2 class="home-h2">${escapeHtml(DOWNLOAD.title)}</h2>
      <p class="home-sub">${escapeHtml(DOWNLOAD.lead)}</p>
      <div class="home-cards">${downloads}</div>
      <p class="home-more"><a href="${BASE}/start/quickstart/">The complete getting-started guide for every platform</a></p>
    </div>
  </section>

  <section class="home-cta">
    <div class="home-wrap home-cta__inner">
      <h2 class="home-h2">${escapeHtml(CTA.title)}</h2>
      <p class="home-cta__lead">${escapeHtml(CTA.lead)}</p>
      <p><a class="btn btn--light btn--lg" href="/register">${escapeHtml(CTA.button)}</a></p>
    </div>
  </section>
</main>`

  return `<!DOCTYPE html>
<html lang="en">
<head>
${head}
</head>
<body class="home-body">
<a class="skip-link" href="#main">Skip to content</a>

${renderTopbar(ctx.nav, ctx.assets.logo)}

${main}

${renderFooter(ctx.nav)}

${renderSearchDialog(ctx.assets, ctx.nav)}

${renderBodyScripts(ctx.assets)}
</body>
</html>
`
}
