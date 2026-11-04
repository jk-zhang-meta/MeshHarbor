// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-102 (#2127) §3c — analytics loads on the hosted site, and nowhere else.
 *
 * Until this, `ui/index.html` carried purestat's tag outright, so every
 * self-hosted install, every fork and every `localhost` dev or test run
 * beaconed to purestat.ai as `meshharbor.itachi.fans`: measured over 90 days, 42 % of
 * the site's events came from loopback and private hosts or other domains.
 * It also contradicted `LICENSING.md`'s promise that a self-hosted deployment
 * sends no telemetry.
 *
 * One rule, in two places — this module for the SPA, and
 * `ui/docs/theme/analytics.js` for the generated pages, which is plain
 * JavaScript and cannot import it (`ui/docs/__tests__/analytics.spec.ts`
 * holds the two to the same answers). The tracker is injected only when ALL
 * of these hold:
 *   1. `location.hostname` is one of `ANALYTICS_HOSTS`, exactly — no
 *      subdomain, no fork, no preview origin, no loopback;
 *   2. the page is `https:` (the hosted site is never served plain);
 *   3. `navigator.webdriver` is not true (Playwright, Selenium: a test run
 *      is not a visit).
 * Otherwise nothing is injected and no request is made.
 *
 * The loader reads and writes NO cookie and NO storage. It decides from the
 * URL and the navigator alone, as FR-88's carry does: carry, don't store.
 *
 * Zero imports, like `attribution.ts`: `ui/docs/site.ts` reads these values
 * at build time and writes them onto the static pages' loader tag.
 */

/** The tracker, as the hosted site has always loaded it. */
export const ANALYTICS_SRC = 'https://purestat.ai/js/purestat.js'

/** The purestat site the events belong to. */
export const ANALYTICS_DOMAIN = 'meshharbor.itachi.fans'

/**
 * Where the tracker may load. Exact hostnames: `app.meshharbor.itachi.fans` is not on
 * it, nor a fork, a staging origin, a self-hosted install or `localhost`,
 * and that is the point. An empty list loads it nowhere — the SPA's kill
 * switch; the static site's is `ANALYTICS = null` in `ui/docs/site.ts`.
 */
export const ANALYTICS_HOSTS: readonly string[] = ['meshharbor.itachi.fans', 'www.meshharbor.itachi.fans']

/** What the decision reads: `location.hostname`, `location.protocol` and
 *  `navigator.webdriver`. */
export interface Where {
  hostname: string
  protocol: string
  webdriver?: boolean
}

/** The rule. Pure, so a test can state every case. */
export function shouldLoadAnalytics(where: Where, hosts: readonly string[] = ANALYTICS_HOSTS): boolean {
  if (where.protocol !== 'https:') return false
  if (where.webdriver === true) return false
  return hosts.includes(where.hostname)
}

/**
 * Injects `<script defer data-domain="…" src="…">` into `<head>` when the
 * rule allows it, and returns whether it did. Never throws: analytics must
 * not be able to break the app it measures.
 *
 * purestat's script reads its `data-domain` through `document.currentScript`,
 * which the browser sets for a dynamically inserted classic script as it
 * does for one written into the HTML, so injection changes nothing for it.
 */
export function loadAnalytics(doc: Document = document, where?: Where): boolean {
  try {
    const w = where ?? { hostname: doc.location.hostname, protocol: doc.location.protocol, webdriver: navigator.webdriver }
    if (!shouldLoadAnalytics(w)) return false
    const tag = doc.createElement('script')
    tag.defer = true
    tag.setAttribute('data-domain', ANALYTICS_DOMAIN)
    tag.src = ANALYTICS_SRC
    doc.head.appendChild(tag)
    return true
  } catch {
    return false
  }
}
