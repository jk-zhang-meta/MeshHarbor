/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 G ROX EOOD
 *
 * FR-102 (#2127) §3c — the static pages' analytics loader: the tracker loads
 * on the hosted site, and nowhere else.
 *
 * The shell used to write purestat's tag into every page, so a self-hosted
 * copy of the docs, a fork and a `localhost` build all reported to
 * purestat.ai as `meshharbor.itachi.fans`. This script takes the tag's place. It is
 * first-party and same-origin, so the CSP (`script-src 'self'
 * https://purestat.ai`) needs no change, and it carries no inline code: its
 * configuration rides on its OWN `<script>` element as `data-*` attributes,
 * which the build fills from `ANALYTICS` in ui/docs/site.ts:
 *
 *   <script src="/docs/assets/analytics.<hash>.js" defer
 *           data-src="https://purestat.ai/js/purestat.js"
 *           data-domain="meshharbor.itachi.fans" data-hosts="meshharbor.itachi.fans,www.meshharbor.itachi.fans">
 *
 * It injects `<script defer data-domain=… src=…>` only when ALL hold — the
 * page's hostname is one of `data-hosts` exactly, the page is `https:`, and
 * `navigator.webdriver` is not true — and otherwise does nothing at all.
 *
 * ⚠️ The SAME rule as the SPA's `ui/src/utils/analytics.ts`, which this file
 * cannot import (it is plain JavaScript served to browsers);
 * `docs/__tests__/analytics.spec.ts` holds the two to the same answers.
 *
 * NOTHING is read from or written to the visitor's device: no cookie, no
 * localStorage, no sessionStorage, no IndexedDB (FR-88's rule).
 */
;(function () {
  'use strict'

  // `document.currentScript` is this element while a classic script runs,
  // deferred or not. Without one (a module, an eval) there is nothing to read.
  var me = document.currentScript
  if (!me || !me.getAttribute) return
  var src = me.getAttribute('data-src')
  var domain = me.getAttribute('data-domain')
  var hosts = (me.getAttribute('data-hosts') || '').split(',')
  if (!src || !domain) return

  var loc = window.location
  if (!loc || loc.protocol !== 'https:') return
  if (window.navigator && window.navigator.webdriver === true) return
  var allowed = false
  for (var i = 0; i < hosts.length; i++) {
    if (hosts[i] && hosts[i] === loc.hostname) allowed = true
  }
  if (!allowed) return

  var tag = document.createElement('script')
  tag.defer = true
  tag.setAttribute('data-domain', domain)
  tag.src = src
  ;(document.head || document.documentElement).appendChild(tag)
})()
