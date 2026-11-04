// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-87 (#1776) P6 — the static homepage, written to `dist/home/index.html`
 * and served at `/` to every visitor without a session cookie: guests, and
 * every crawler. Before this, `/` was the SPA shell, one empty
 * `<div id="app">` to anything that does not run the app.
 *
 * The copy is the SPA landing page's, from `ui/src/utils/landing.ts`, so the
 * two cannot drift; the install commands come from `enrollCommands.ts`, like
 * every other place they appear.
 *
 * Progressive enhancement lives in `home.js`: the signed-in hand-off, the
 * newsletter form, and live prices. Without JavaScript the page is complete:
 * every section renders, and the newsletter block points at sign-up.
 */
import { installCards } from '../../src/utils/enrollCommands.ts'
import {
  CAPABILITIES,
  CTA,
  DOWNLOAD,
  FALLBACK_PLANS,
  HERO,
  PILLARS,
  PRICING,
  VIDEO_TOUR,
  annualLine,
  type Plan,
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

export const HOME_TITLE = 'MeshHarbor — remote desktop, private mesh network, chat & video'
export const HOME_DESCRIPTION =
  'Remote desktop in a browser tab and a private WireGuard-style mesh between your machines, team chat and video included. Self-hostable, end-to-end encrypted.'

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
  'mdi-pound': 'chat',
  'mdi-video-outline': 'video',
  'mdi-file-document-outline': 'file',
}

function iconFor(mdi: string): string {
  const name = ICON[mdi]
  if (!name) throw new Error(`home: no inline icon for "${mdi}" — map it in ui/docs/theme/home-layout.ts`)
  return icon(name, { size: 30 })
}

/** FR-115 — per user per month, the same number in USD and EUR; the euro
 * figure only once the plan lists an EUR price, i.e. once EUR is on sale
 * (`stripe.currencies`). `home.js` renders the identical label from the live
 * plans. */
export function priceLabel(plan: Plan): { amount: string; unit: string } {
  const dollars = plan.price_cents / 100
  const n = Number.isInteger(dollars) ? `${dollars}` : dollars.toFixed(2)
  if (plan.price_cents <= 0) return { amount: `$${n}`, unit: 'forever' }
  const eur = (plan.prices || []).some((p) => p.currency === 'eur')
  return { amount: `$${n}`, unit: eur ? `/ €${n} per user / month` : 'per user / month' }
}

function planCard(plan: Plan): string {
  const featured = plan.id === 'pro'
  const { amount, unit } = priceLabel(plan)
  const annual = annualLine(plan)
  return (
    `<div class="home-plan${featured ? ' home-plan--featured' : ''}" data-plan="${escapeHtml(plan.id)}">` +
    (featured ? `<p class="home-plan__badge">Most popular</p>` : '') +
    `<h3 class="home-plan__name">${escapeHtml(plan.name)}</h3>` +
    `<p class="home-plan__price"><span class="home-plan__amount" data-price>${amount}</span> <span class="home-plan__unit" data-unit>${unit}</span></p>` +
    `<p class="home-plan__annual" data-annual${annual ? '' : ' hidden'}>${escapeHtml(annual ?? '')}</p>` +
    `<ul class="home-plan__features" data-features>${plan.features.map((f) => `<li>${icon('check', { size: 16 })}<span>${escapeHtml(f)}</span></li>`).join('')}</ul>` +
    `<a class="btn ${featured ? 'btn--primary' : 'btn--tonal'} home-plan__cta" href="/register">${plan.price_cents === 0 ? 'Get started free' : 'Start now'}</a>` +
    `</div>`
  )
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
    // Runs before the body renders: a returning user whose 7-day session
    // cookie lapsed (so nginx sent this page) but whose refresh cookie is
    // alive is handed to the app instead of shown a sign-up page.
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

  // The wizard only where it installs the agent (FR-97 D5), as the SPA's copy.
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

  <section id="pricing" class="home-section">
    <div class="home-wrap">
      <h2 class="home-h2">${escapeHtml(PRICING.title)}</h2>
      <p class="home-sub">${escapeHtml(PRICING.lead)}</p>
      <div class="home-plans" data-plans>${FALLBACK_PLANS.map(planCard).join('')}</div>
    </div>
  </section>

  <section class="home-cta">
    <div class="home-wrap home-cta__inner">
      <h2 class="home-h2">${escapeHtml(CTA.title)}</h2>
      <p class="home-cta__lead">${escapeHtml(CTA.lead)}</p>
      <p><a class="btn btn--light btn--lg" href="/register">${escapeHtml(CTA.button)}</a></p>
      <div class="home-news" data-news>
        <p>Not ready to sign up? Get an email when something notable ships.</p>
        <form class="home-news__form" data-subscribe hidden>
          <label class="sr-only" for="news-email">Your email address</label>
          <input id="news-email" type="email" name="email" autocomplete="email" required placeholder="you@example.com">
          <button class="btn btn--light" type="submit">Keep me posted</button>
        </form>
        <p class="home-news__status" data-subscribe-status role="status" hidden></p>
        <p class="home-news__nojs" data-nojs>The mailing list needs JavaScript; <a href="/register">a free account</a> gets the same news.</p>
        <p class="home-news__fine">Product updates only, and never more than monthly. One-click unsubscribe in every email. We do not share your address. <a href="/privacy">Privacy Policy</a></p>
      </div>
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
