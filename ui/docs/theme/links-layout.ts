// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-88 (#1790) P2 — the link hub, written to `dist/links/index.html` and
 * served at `/links/`. It is where a link goes that cannot carry a campaign
 * itself: a profile bio, a URL said out loud in a video. Each channel's short
 * path (`/yt`, `/tt`, `/x`, `/fb`) is a 302 to here WITH one
 * (`shortPathLocation` in `site.ts`), and `attribution.js` carries it on to
 * sign-up and the install pages, as on every other static page.
 *
 * `noindex`: the page repeats what the homepage says, for people who arrive
 * from a profile, so it is not something to rank. Its links stay followed.
 */
import { enrollCommands } from '../../src/utils/enrollCommands.ts'
import { BASE, BLOG_BASE, CHANNELS, REPO_URL, SITE_ORIGIN } from '../site.ts'
import { HOME_DESCRIPTION } from './home-layout.ts'
import { icon } from './icons.ts'
import { escapeHtml } from './render.ts'
import {
  renderBodyScripts,
  renderFooter,
  renderHead,
  renderSearchDialog,
  renderTopbar,
  type ShellNav,
  type SiteAssets,
} from './shell.ts'
import { graph, organization } from './structured.ts'

export const LINKS_URL = '/links/'
export const LINKS_TITLE = 'MeshHarbor: start here'
export const LINKS_DESCRIPTION =
  'Start free, install the agent, read the docs, or follow MeshHarbor on YouTube, TikTok, X and Facebook.'

export interface LinksCtx {
  assets: SiteAssets
  nav: ShellNav
}

function action(href: string, label: string, opts: { primary?: boolean; icon?: string; external?: boolean } = {}): string {
  const ext = opts.external ? ' target="_blank" rel="noopener noreferrer"' : ''
  const glyph = opts.icon ? icon(opts.icon, { size: 18 }) : ''
  return `<li><a class="btn ${opts.primary ? 'btn--primary' : 'btn--tonal'} btn--lg links-btn" href="${escapeHtml(href)}"${ext}>${glyph}<span>${escapeHtml(label)}</span></a></li>`
}

export function renderLinks(ctx: LinksCtx): string {
  const head = renderHead({
    title: LINKS_TITLE,
    description: LINKS_DESCRIPTION,
    canonical: `${SITE_ORIGIN}${LINKS_URL}`,
    noindex: true,
    og: { type: 'website', title: LINKS_TITLE },
    jsonLd: graph([organization()]),
    assets: ctx.assets,
    feed: ctx.nav.hasBlog,
    blogStyles: false,
    styles: ctx.assets.homeCss ? [ctx.assets.homeCss] : [],
  })

  // The platforms the agent installs on, from the list the install pages and
  // the homepage's download cards are built from.
  const titles = enrollCommands('agent', SITE_ORIGIN, null).map((os) => os.title)
  const platforms = titles.length > 1 ? `${titles.slice(0, -1).join(', ')} and ${titles[titles.length - 1]}` : titles.join('')

  const actions = [
    action('/register', 'Start free', { primary: true }),
    action(`${BASE}/start/quickstart/`, 'Install the agent', { icon: 'download' }),
    action(`${BASE}/`, 'Read the docs', { icon: 'book' }),
    ctx.nav.hasBlog ? action(`${BLOG_BASE}/`, 'Read the blog', { icon: 'book' }) : '',
    action(REPO_URL, 'Source code on GitHub', { icon: 'external', external: true }),
  ].join('')

  const channels = CHANNELS.map(
    (c) =>
      `<li><a class="links-channel" href="${escapeHtml(c.url)}" target="_blank" rel="noopener noreferrer me">` +
      `<span class="links-channel__name">${escapeHtml(c.name)}</span><span class="links-channel__handle">${escapeHtml(c.handle)}</span>${icon('external', { size: 16 })}</a></li>`,
  ).join('')

  const main = `<main id="main" class="home links">
  <section class="home-hero links-hero">
    <div class="home-wrap links-wrap">
      <h1 class="links-title">MeshHarbor</h1>
      <p class="links-lead">${escapeHtml(HOME_DESCRIPTION)}</p>
      <ul class="links-actions">${actions}</ul>
      <p class="links-note">The agent runs on ${escapeHtml(platforms)}. The code is open source.</p>
      <h2 class="links-h2">Follow MeshHarbor</h2>
      <ul class="links-channels">${channels}</ul>
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
