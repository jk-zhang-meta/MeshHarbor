/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 G ROX EOOD
 *
 * FR-87 (#1776) P6 — the static homepage's progressive enhancement. Loaded
 * in <head> WITHOUT `defer`, because its first job has to run before the
 * page paints.
 *
 * 1. THE SIGNED-IN HAND-OFF. nginx sends this page to any request without
 *    the `access_token` cookie. That cookie lives 7 days; the refresh cookie
 *    lives 30, but it is scoped to `/api/auth/refresh`, so nginx never sees
 *    it at `/`. A returning user between day 7 and day 30 would therefore be
 *    shown the sign-up page by a site that could still sign them in
 *    silently. The SPA's own "I think I am signed in" hint is in
 *    localStorage (`SIGNED_IN` in `ui/src/api/session.ts`, locked equal to
 *    the key below by `home.spec.ts`); when it says yes, the app gets the
 *    visitor — it refreshes the session, or, if that fails, clears the hint
 *    and shows its login page, so a stale hint cannot loop. A crawler has
 *    no localStorage and stays here.
 * 2. The newsletter form, where the server mounts the list (`saas`).
 * 3. Live prices from `/api/stripe/plans`, the single source of truth; the
 *    page ships the fallback table from `ui/src/utils/landing.ts`.
 * 4. FR-88 (#1790): the `subscribe` goal after the newsletter's 202, and the
 *    campaign as the form's `source` when `attribution.js` found one on the
 *    URL (it sets `data-source`; without it the source stays `home`).
 *
 * With JavaScript off the page is complete; only the form is replaced by a
 * pointer to sign-up.
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

  function ready(fn) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn)
    else fn()
  }

  // A purestat goal (FR-88 §3b). A no-op without the script (`ANALYTICS =
  // null`, blocked, not loaded yet), and it never throws.
  function goal(name) {
    try {
      if (typeof window.purestat === 'function') window.purestat(name)
    } catch (e) {
      /* analytics must never break the page */
    }
  }

  function initNewsletter() {
    var block = document.querySelector('[data-news]')
    var form = document.querySelector('[data-subscribe]')
    var status = document.querySelector('[data-subscribe-status]')
    var nojs = document.querySelector('[data-nojs]')
    if (!block || !form || !status) return

    function show() {
      form.hidden = false
      if (nojs) nojs.hidden = true
    }

    // The list is a `saas` feature. Fail OPEN, as the SPA does: if the
    // capabilities answer does not arrive, the form shows, and the server
    // still decides.
    fetch('/api/capabilities', { credentials: 'omit' })
      .then(function (r) {
        return r.ok ? r.json() : null
      })
      .then(function (caps) {
        if (caps && Array.isArray(caps.modules) && caps.modules.indexOf('saas') === -1) block.hidden = true
        else show()
      })
      .catch(show)

    form.addEventListener('submit', function (ev) {
      ev.preventDefault()
      var input = form.querySelector('input[type=email]')
      var button = form.querySelector('button')
      var email = (input.value || '').trim()
      if (!email) return
      button.disabled = true
      // The server answers 202 for every outcome, so this cannot and does
      // not say "already subscribed": that would leak list membership.
      fetch('/api/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ email: email, source: form.getAttribute('data-source') || 'home' }),
      })
        .then(function (r) {
          if (!r.ok) throw new Error('HTTP ' + r.status)
          form.hidden = true
          status.textContent = 'Thanks — check your inbox for a confirmation link.'
          status.hidden = false
          goal('subscribe')
        })
        .catch(function () {
          status.textContent = 'Could not reach the server. Please try again.'
          status.hidden = false
          button.disabled = false
        })
    })
  }

  function initPrices() {
    var box = document.querySelector('[data-plans]')
    if (!box) return
    fetch('/api/stripe/plans', { credentials: 'omit' })
      .then(function (r) {
        return r.ok ? r.json() : null
      })
      .then(function (plans) {
        if (!Array.isArray(plans)) return
        plans.forEach(function (p) {
          if (!p || typeof p.id !== 'string' || typeof p.price_cents !== 'number') return
          var card = box.querySelector('[data-plan="' + p.id.replace(/[^a-z0-9_-]/gi, '') + '"]')
          if (!card) return
          // FR-115 — the label `priceLabel` (home-layout.ts) renders: per
          // user per month, the euro figure only once EUR is on sale; and the
          // yearly line when the server sells annual.
          var dollars = p.price_cents / 100
          var n = dollars % 1 === 0 ? String(dollars) : dollars.toFixed(2)
          var prices = Array.isArray(p.prices) ? p.prices : []
          var eur = prices.some(function (x) { return x && x.currency === 'eur' })
          card.querySelector('[data-price]').textContent = '$' + n
          card.querySelector('[data-unit]').textContent =
            p.price_cents > 0 ? (eur ? '/ €' + n + ' per user / month' : 'per user / month') : 'forever'
          var annualEl = card.querySelector('[data-annual]')
          if (annualEl) {
            // `annualLine` (landing.ts): a free plan never says "or $0 per user per year".
            var yUsd = p.price_cents > 0 && prices.filter(function (x) { return x && x.interval === 'year' && x.currency === 'usd' })[0]
            var yEur = prices.filter(function (x) { return x && x.interval === 'year' && x.currency === 'eur' })[0]
            if (yUsd && typeof yUsd.unit_amount === 'number') {
              annualEl.textContent =
                'or $' + yUsd.unit_amount / 100 +
                (yEur && typeof yEur.unit_amount === 'number' ? ' / €' + yEur.unit_amount / 100 : '') +
                ' per user per year (two months free)'
              annualEl.hidden = false
            } else {
              annualEl.textContent = ''
              annualEl.hidden = true
            }
          }
          var list = card.querySelector('[data-features]')
          var first = list && list.querySelector('li')
          if (!Array.isArray(p.features) || !first) return
          var tick = first.querySelector('svg')
          list.textContent = ''
          p.features.forEach(function (f) {
            var li = document.createElement('li')
            if (tick) li.appendChild(tick.cloneNode(true))
            var span = document.createElement('span')
            span.textContent = String(f)
            li.appendChild(span)
            list.appendChild(li)
          })
        })
      })
      .catch(function () {
        /* the fallback table stays */
      })
  }

  ready(function () {
    initNewsletter()
    initPrices()
  })
})()
