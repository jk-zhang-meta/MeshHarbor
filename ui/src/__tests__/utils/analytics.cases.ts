// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-102 (#2127) — every case the analytics rule has to answer, with the
 * answer. ONE table for the two implementations of the one rule: the SPA's
 * `shouldLoadAnalytics` (`utils/analytics.spec.ts`) and the static pages'
 * plain-JS loader (`docs/__tests__/analytics.spec.ts`), so the two cannot
 * drift. Not a spec itself: a spec imported by another spec would register
 * its tests twice.
 *
 * The three that load are the hosted site's two hostnames over https, with
 * or without a `navigator.webdriver` value; everything else makes no request.
 */
import type { Where } from '@/utils/analytics'

export const CASES: ReadonlyArray<[name: string, where: Where, loads: boolean]> = [
  ['the hosted site', { hostname: 'meshharbor.itachi.fans', protocol: 'https:', webdriver: false }, true],
  ['the www hostname', { hostname: 'www.meshharbor.itachi.fans', protocol: 'https:', webdriver: false }, true],
  ['a browser that does not say whether it is driven', { hostname: 'meshharbor.itachi.fans', protocol: 'https:' }, true],
  ['localhost', { hostname: 'localhost', protocol: 'http:', webdriver: false }, false],
  ['localhost over https', { hostname: 'localhost', protocol: 'https:', webdriver: false }, false],
  ['127.0.0.1', { hostname: '127.0.0.1', protocol: 'http:', webdriver: false }, false],
  ['[::1]', { hostname: '[::1]', protocol: 'http:', webdriver: false }, false],
  ['a private host', { hostname: '192.168.1.20', protocol: 'https:', webdriver: false }, false],
  ["a fork's domain", { hostname: 'deskler.example', protocol: 'https:', webdriver: false }, false],
  ['a subdomain of the hosted site', { hostname: 'app.meshharbor.itachi.fans', protocol: 'https:', webdriver: false }, false],
  ['a look-alike with the hostname as a prefix', { hostname: 'meshharbor.itachi.fans.evil.example', protocol: 'https:', webdriver: false }, false],
  ['a look-alike with the hostname as a suffix', { hostname: 'notmeshharbor.itachi.fans', protocol: 'https:', webdriver: false }, false],
  ['the hosted site over plain http', { hostname: 'meshharbor.itachi.fans', protocol: 'http:', webdriver: false }, false],
  ['a file: URL', { hostname: '', protocol: 'file:', webdriver: false }, false],
  ['a WebDriver (Playwright) on the hosted site', { hostname: 'meshharbor.itachi.fans', protocol: 'https:', webdriver: true }, false],
]
