/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 G ROX EOOD
 *
 * FR-87 (#1776) P6 — the static homepage's progressive enhancement. Loaded
 * in <head> WITHOUT `defer`, because its job has to run before the page paints.
 *
 * THE SIGNED-IN HAND-OFF: nginx sends this page to any request without the
 * `access_token` cookie. When localStorage says the user is signed in
 * (`SIGNED_IN` in `ui/src/api/session.ts`, locked equal by `home.spec.ts`),
 * hand them straight to `/login` so the SPA refreshes the session silently.
 */
;(function () {
  'use strict'

  var SIGNED_IN = 'meshharbor-signed-in'
  try {
    if (window.localStorage.getItem(SIGNED_IN) === '1') {
      // `/login`, not `/`: `/` would serve this page again (still no cookie).
      // The SPA's guest guard sends a signed-in visitor on to the dashboard.
      window.location.replace('/login')
      return
    }
  } catch (e) {
    /* storage blocked: stay on the static page */
  }
})()
